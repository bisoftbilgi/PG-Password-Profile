//! Authentication-event ring with transaction-aware claim/acknowledge
//! semantics.
//!
//! # What changed and why
//! The original ring was destructive in two directions:
//!
//! * `dequeue()` advanced `tail` immediately, before the worker's database
//!   transaction ran. If that transaction then aborted, the event was already
//!   gone and a failed login was never counted.
//! * `enqueue()` on a full ring advanced `tail` and overwrote the oldest event,
//!   silently discarding brute-force evidence -- including an event the worker
//!   had already claimed.
//!
//! Both are removed. A consumer now *claims* the tail entry (copying it out
//! without moving `tail`), processes it in a database transaction, and the
//! `XACT_EVENT_COMMIT` callback acknowledges the claim. Only acknowledgement
//! advances `tail`, so an aborted transaction leaves the same event at the tail
//! for retry. A full ring refuses the new event and records it, rather than
//! destroying an old one.
//!
//! # Durability boundary
//! The ring is the bounded in-memory accelerator; [`crate::auth_journal`] is
//! authoritative. Every event is fsynced to that journal before it is offered
//! to the ring, so a postmaster crash or restart may destroy this shared-memory
//! copy without losing the event.
//!
//! # Lock discipline
//! `AUTH_EVENT_LWLOCK` serializes journal append/rotation with the matching ring
//! update. It is therefore allowed to contain file I/O, but never SPI, SQL,
//! logging, database locks, cache mutation or error raising. The lock is an
//! LWLock, so a slow fsync sleeps waiters instead of recreating the former raw
//! spinlock failure mode.
//!
//! That is not sufficient on its own. This ring is also written from inside
//! [`crate::expiry_cache::try_consume_grace`], which holds
//! `EXPIRY_CACHE_LWLOCK` across the call, so a warning emitted after *this*
//! module's own guard is dropped would still run under the caller's lock. An
//! earlier revision did exactly that.
//!
//! The primitive that nested callers use is therefore
//! [`enqueue_encoded_silent`], which writes the journal and shared memory but
//! never logs or raises. Deciding *whether* to warn is done in shared memory
//! (rate-limited across every backend), so the caller can release every lock it
//! holds before emitting the warning.
//! [`enqueue`] is the convenience wrapper for callers that hold no other lock:
//! it does the same thing and logs after its own guard is dropped.

use crate::{
    auth_journal::{self, EventId},
    encode_username, LwLockGuard, LwLockMode, AUTH_EVENT_LWLOCK, LOCK_USERNAME_BYTES,
};
use pgrx::pg_sys;
use std::ptr;

/// Number of slots in the ring. One slot is always left empty to distinguish
/// "full" from "empty", so the usable capacity is `RING_SLOTS - 1`.
const RING_SLOTS: usize = crate::AUTH_EVENT_RING_SIZE;

/// Events the ring can actually hold.
pub(crate) const USABLE_CAPACITY: u32 = (RING_SLOTS - 1) as u32;

#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct SharedAuthEvent {
    /// Stable identity shared by the durable journal and the RAM accelerator.
    pub(crate) event_id: [u8; 16],
    pub(crate) username: [u8; LOCK_USERNAME_BYTES],
    pub(crate) timestamp: pg_sys::TimestampTz,
    /// Monotonically increasing per-ring sequence number, assigned at enqueue.
    ///
    /// This is what makes a claim token unforgeable against ABA: a slot can be
    /// reused after wraparound, but its sequence number never repeats within a
    /// shared-memory lifetime.
    pub(crate) seq: u64,
    /// Primitive discriminant, never a Rust enum.
    ///
    /// Shared memory can hold any byte pattern, and transmuting an out-of-range
    /// byte into a Rust enum is undefined behaviour. The value is stored raw and
    /// validated explicitly by [`EventKind::from_raw`]; an unrecognized kind
    /// marks the queue `Corrupt`, which pauses this extension's enforcement rather
    /// than acknowledging unknown data.
    pub(crate) kind: u8,
    /// Password generation (`password_expiry.last_changed`) for
    /// [`EVENT_KIND_GRACE_CONSUMED`]; `0` for the other kinds.
    pub(crate) generation: pg_sys::TimestampTz,
    /// Primitive bit set recording what the *authentication hook* decided at
    /// admission time, never a Rust type.
    ///
    /// The only bit defined today is [`EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS`].
    /// Capturing it in the event is what makes the worker independent of the
    /// live GUC: `password_profile.lockout_enforcement` can be toggled by
    /// SIGHUP while an event waits in the queue, and the event must be applied
    /// with the semantics it was created with. Validated by
    /// [`EventFlags::from_raw`]; an unknown bit marks the queue corrupt.
    pub(crate) flags: u8,
}

/// Native authentication failed.
pub(crate) const EVENT_KIND_FAILURE: u8 = 1;
/// Native authentication succeeded; clears inactive failed-attempt state.
pub(crate) const EVENT_KIND_SUCCESS: u8 = 2;
/// Native authentication succeeded and consumed one grace login. Carries the
/// exact password generation the grace was taken from.
pub(crate) const EVENT_KIND_GRACE_CONSUMED: u8 = 3;

/// The login this event describes also had `lockout_enforcement` on when it
/// was admitted, so failed-attempt state must be cleared in the same
/// transaction that persists the event.
pub(crate) const EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS: u8 = 0x01;

/// Every bit this build understands. Anything outside it is corruption.
const EVENT_FLAGS_KNOWN: u8 = EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS;

/// Validated event flags.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct EventFlags(u8);

impl EventFlags {
    pub(crate) const NONE: EventFlags = EventFlags(0);
    pub(crate) const CLEAR_LOGIN_ATTEMPTS: EventFlags = EventFlags(EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS);

    /// Validates a raw bit set. `None` means the queue is corrupt.
    ///
    /// Deliberately strict: an unknown bit means this event was written by
    /// something that does not agree with this build about what the event
    /// means, so it is never guessed at or masked away.
    #[inline]
    pub(crate) fn from_raw(raw: u8) -> Option<Self> {
        if raw & !EVENT_FLAGS_KNOWN != 0 {
            return None;
        }
        Some(EventFlags(raw))
    }

    #[inline]
    pub(crate) fn raw(self) -> u8 {
        self.0
    }

    /// True when this event must also clear failed-login state.
    #[inline]
    pub(crate) fn clear_login_attempts(self) -> bool {
        self.0 & EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS != 0
    }

    /// Chooses the flag set for a successful login from the enforcement state
    /// observed at admission time.
    #[inline]
    pub(crate) fn for_admission(lockout_active: bool) -> Self {
        if lockout_active {
            EventFlags::CLEAR_LOGIN_ATTEMPTS
        } else {
            EventFlags::NONE
        }
    }
}

/// Validated event kind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum EventKind {
    Failure,
    Success,
    GraceConsumed,
}

impl EventKind {
    /// Validates a raw discriminant. `None` means the queue is corrupt.
    #[inline]
    pub(crate) fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            EVENT_KIND_FAILURE => Some(EventKind::Failure),
            EVENT_KIND_SUCCESS => Some(EventKind::Success),
            EVENT_KIND_GRACE_CONSUMED => Some(EventKind::GraceConsumed),
            _ => None,
        }
    }
}

impl SharedAuthEvent {
    const EMPTY: SharedAuthEvent = SharedAuthEvent {
        event_id: [0; 16],
        username: [0; LOCK_USERNAME_BYTES],
        timestamp: 0,
        seq: 0,
        kind: EVENT_KIND_SUCCESS,
        generation: 0,
        flags: 0,
    };
}

/// Proof of which ring entry a consumer is processing.
///
/// Fixed-size and `Copy`, so it can be staged in backend-local transaction
/// state and validated inside a commit callback without any allocation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) struct ClaimToken {
    slot: u32,
    seq: u64,
}

/// Health of the auth-event queue, independent of lock-cache readiness.
///
/// `Overflowed` is a recoverable RAM-pressure signal: the worker keeps draining
/// from the durable journal. `Corrupt` is structural and requires the explicit
/// administrative recovery function.
///
/// `#[repr(i32)]` with explicit discriminants -- the raw value lives in shared
/// memory and is surfaced numerically through `get_lock_cache_stats()`.
#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum QueueState {
    /// Accepting and delivering events normally. The only state that permits
    /// ordinary lockout processing.
    Healthy = 0,
    /// At least one durable event did not fit in the ring. Producers keep
    /// journaling and the worker continues draining. The state returns to
    /// `Healthy` when the retained RAM copies are fully drained.
    Overflowed = 1,
    /// Claim/acknowledge token validation or a ring invariant failed.
    Corrupt = 2,
}

impl QueueState {
    /// Unknown raw values map to `Corrupt` -- the safest unavailable state,
    /// since only `Healthy` relaxes enforcement.
    #[inline]
    fn from_raw(raw: i32) -> Self {
        match raw {
            0 => QueueState::Healthy,
            1 => QueueState::Overflowed,
            _ => QueueState::Corrupt,
        }
    }
}

/// Result of offering an event to the ring.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) enum EnqueueOutcome {
    /// Accepted and visible to the consumer.
    Enqueued,
    /// The event is durable but the RAM accelerator was full or unavailable.
    /// The worker will read it from the journal; no evidence was lost.
    DurableOnly,
    /// The journal could not be durably written, shared memory is not
    /// initialized, or a unique event identifier could not be generated.
    Unavailable,
}

impl EnqueueOutcome {
    #[inline]
    pub(crate) fn is_durable(self) -> bool {
        matches!(self, EnqueueOutcome::Enqueued | EnqueueOutcome::DurableOnly)
    }
}

/// Result of acknowledging a claim.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) enum AckOutcome {
    /// Token matched the tail entry; `tail` advanced exactly once.
    Acknowledged,
    /// Token did not match the current tail (already acknowledged, or a stale /
    /// wrong-slot / wrong-sequence token). `tail` did not move.
    Stale,
    /// Ring indices are not usable at all.
    Corrupt,
}

#[repr(C)]
struct AuthEventRing {
    /// Next slot a producer will write. `head == tail` means empty.
    head: u32,
    /// Oldest unacknowledged slot. Advanced **only** by [`AuthEventRing::ack`].
    tail: u32,
    /// Next sequence number to assign.
    next_seq: u64,
    /// Saturating lifetime counters.
    accepted: u64,
    acknowledged: u64,
    rejected: u64,
    journaled: u64,
    durable_only: u64,
    journal_failures: u64,
    /// Raw [`QueueState`].
    state: i32,
    /// `GetCurrentTimestamp()` of the last queue-full warning any backend was
    /// cleared to emit. Shared so the rate limit is global rather than
    /// per-backend -- a per-backend limiter would be useless here, since a new
    /// connection is a new process.
    last_warned_at: pg_sys::TimestampTz,
    events: [SharedAuthEvent; RING_SLOTS],
}

/// Minimum spacing between repeat queue-full warnings, in microseconds.
const QUEUE_WARN_INTERVAL_US: i64 = 60_000_000;

/// Outcome of the pure enqueue step.
///
/// `should_warn` is decided *inside* the ring, under `AUTH_EVENT_LWLOCK`, so
/// the caller can release every lock it holds -- including a caller-level lock
/// such as `EXPIRY_CACHE_LWLOCK` -- and only then call
/// [`emit_queue_full_warning`]. It is true on the healthy-to-unhealthy
/// transition and, after that, at most once per [`QUEUE_WARN_INTERVAL_US`]
/// across all backends, because the timestamp lives in shared memory.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) struct EnqueueStep {
    pub(crate) outcome: EnqueueOutcome,
    pub(crate) should_warn: bool,
}

impl AuthEventRing {
    const fn new() -> Self {
        AuthEventRing {
            head: 0,
            tail: 0,
            next_seq: 1,
            accepted: 0,
            acknowledged: 0,
            rejected: 0,
            journaled: 0,
            durable_only: 0,
            journal_failures: 0,
            state: QueueState::Healthy as i32,
            last_warned_at: 0,
            events: [SharedAuthEvent::EMPTY; RING_SLOTS],
        }
    }

    /// True when both indices are in range. Every operation checks this before
    /// indexing, so corrupt shared state produces an unhealthy queue rather
    /// than an out-of-bounds panic.
    #[inline]
    fn indices_valid(&self) -> bool {
        (self.head as usize) < RING_SLOTS && (self.tail as usize) < RING_SLOTS
    }

    #[inline]
    fn advance(index: u32) -> u32 {
        // `index` is always validated `< RING_SLOTS` before this is used.
        (index + 1) % RING_SLOTS as u32
    }

    #[inline]
    fn depth(&self) -> u32 {
        if !self.indices_valid() {
            return 0;
        }
        (self.head + RING_SLOTS as u32 - self.tail) % RING_SLOTS as u32
    }

    #[inline]
    fn state(&self) -> QueueState {
        QueueState::from_raw(self.state)
    }

    /// Records a degraded state. Normal draining recovers `Overflowed`; this
    /// helper never downgrades `Corrupt`.
    #[inline]
    fn degrade_to(&mut self, new_state: QueueState) {
        if new_state != QueueState::Healthy {
            // Corrupt outranks Overflowed.
            if new_state == QueueState::Corrupt || self.state() == QueueState::Healthy {
                self.state = new_state as i32;
            }
        }
    }

    /// Offers an event. Never overwrites an existing entry and never moves
    /// `tail`, so a claimed-but-unacknowledged event cannot be destroyed by a
    /// producer.
    /// Decides whether the caller may emit a warning for this rejection.
    ///
    /// Always true for the healthy-to-unhealthy transition; after that at most
    /// once per [`QUEUE_WARN_INTERVAL_US`]. Only a timestamp comparison and one
    /// store -- no allocation, no formatting, no logging.
    #[inline]
    fn should_warn_now(&mut self, was_healthy: bool, now: i64) -> bool {
        if was_healthy
            || self.last_warned_at == 0
            || now.saturating_sub(self.last_warned_at) >= QUEUE_WARN_INTERVAL_US
        {
            self.last_warned_at = now;
            true
        } else {
            false
        }
    }

    fn try_enqueue(
        &mut self,
        event_id: [u8; 16],
        username: [u8; LOCK_USERNAME_BYTES],
        timestamp: i64,
        kind: u8,
        flags: u8,
        generation: pg_sys::TimestampTz,
    ) -> EnqueueStep {
        if !self.indices_valid() {
            self.degrade_to(QueueState::Corrupt);
            return EnqueueStep {
                outcome: EnqueueOutcome::Unavailable,
                should_warn: false,
            };
        }

        // Structural corruption is not recoverable by draining. Do not add
        // more data to a ring whose contents can no longer be trusted.
        if self.state() == QueueState::Corrupt {
            return EnqueueStep {
                outcome: EnqueueOutcome::Unavailable,
                should_warn: false,
            };
        }

        let next_head = Self::advance(self.head);
        if next_head == self.tail {
            // Full. Refuse rather than destroy the oldest event.
            let was_healthy = self.state() == QueueState::Healthy;
            self.rejected = self.rejected.saturating_add(1);
            self.durable_only = self.durable_only.saturating_add(1);
            self.degrade_to(QueueState::Overflowed);
            let should_warn = self.should_warn_now(was_healthy, timestamp);
            return EnqueueStep {
                outcome: EnqueueOutcome::DurableOnly,
                should_warn,
            };
        }

        // Sequence exhaustion. `next_seq` is what makes a claim token
        // unforgeable, so a saturating counter would hand out `u64::MAX`
        // repeatedly and let a stale token acknowledge a different event.
        // Fail closed instead: refuse the event and mark the queue corrupt.
        // (Unreachable in practice -- it would take 2^64 logins in one
        // shared-memory lifetime -- but the failure mode is silent token
        // collision, so it is checked rather than assumed.)
        if self.next_seq == u64::MAX {
            self.rejected = self.rejected.saturating_add(1);
            self.degrade_to(QueueState::Corrupt);
            return EnqueueStep {
                outcome: EnqueueOutcome::Unavailable,
                should_warn: false,
            };
        }

        let seq = self.next_seq;
        self.next_seq += 1;
        self.events[self.head as usize] = SharedAuthEvent {
            event_id,
            username,
            timestamp,
            seq,
            kind,
            generation,
            flags,
        };
        self.head = next_head;
        self.accepted = self.accepted.saturating_add(1);

        EnqueueStep {
            outcome: EnqueueOutcome::Enqueued,
            should_warn: false,
        }
    }

    /// Copies out the oldest unacknowledged event **without** advancing `tail`.
    ///
    /// Repeated calls before an acknowledgement return the identical event and
    /// token, which is what makes retry-the-same-event work.
    fn claim(&mut self) -> Option<(ClaimToken, SharedAuthEvent)> {
        if !self.indices_valid() {
            self.degrade_to(QueueState::Corrupt);
            return None;
        }
        if self.head == self.tail {
            return None;
        }
        let slot = self.tail;
        let event = self.events[slot as usize];
        Some((
            ClaimToken {
                slot,
                seq: event.seq,
            },
            event,
        ))
    }

    /// Advances `tail` past exactly the claimed entry, if the token still
    /// matches both its position and its sequence number.
    ///
    /// Validating both is what rejects a stale token after wraparound (ABA):
    /// the slot may be reused, but its sequence number cannot repeat.
    fn ack(&mut self, token: ClaimToken) -> AckOutcome {
        if !self.indices_valid() {
            self.degrade_to(QueueState::Corrupt);
            return AckOutcome::Corrupt;
        }
        if self.head == self.tail {
            // Nothing outstanding: a duplicate acknowledgement.
            return AckOutcome::Stale;
        }
        if token.slot != self.tail {
            return AckOutcome::Stale;
        }
        if (token.slot as usize) >= RING_SLOTS {
            self.degrade_to(QueueState::Corrupt);
            return AckOutcome::Corrupt;
        }
        if self.events[token.slot as usize].seq != token.seq {
            return AckOutcome::Stale;
        }

        self.tail = Self::advance(self.tail);
        self.acknowledged = self.acknowledged.saturating_add(1);
        if self.head == self.tail && self.state() == QueueState::Overflowed {
            self.state = QueueState::Healthy as i32;
        }
        AckOutcome::Acknowledged
    }
}

static mut AUTH_EVENT_RING: *mut AuthEventRing = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<AuthEventRing>()
}

pub(crate) unsafe fn init() {
    if !AUTH_EVENT_RING.is_null() {
        return;
    }

    let size = std::mem::size_of::<AuthEventRing>();
    let mut found = false;
    let ring_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_auth_event_ring".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut AuthEventRing;

    if ring_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize auth event ring");
    }

    if !found {
        ptr::write(ring_ptr, AuthEventRing::new());
        pgrx::log!(
            "password_profile: auth event ring allocated ({} bytes, usable capacity {})",
            size,
            USABLE_CAPACITY
        );
    } else {
        pgrx::log!("password_profile: auth event ring attached to existing segment");
    }

    AUTH_EVENT_RING = ring_ptr;
}

/// Current queue health. Short shared-lock read, allocation-free.
pub(crate) fn state() -> QueueState {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return QueueState::Corrupt;
        }
        let ring = &*AUTH_EVENT_RING;
        let raw = {
            let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Shared);
            ring.state
        };
        QueueState::from_raw(raw)
    }
}

/// Records that the queue can no longer be trusted.
///
/// Used by the commit callback when an acknowledgement fails validation (where
/// raising an error is not allowed, because the commit has already happened)
/// and by the worker when an event cannot be decoded. One primitive store under
/// a short exclusive lock.
pub(crate) fn mark_corrupt() {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return;
        }
        let ring = &mut *AUTH_EVENT_RING;
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        ring.degrade_to(QueueState::Corrupt);
    }
}

/// Offers an event to the ring **without logging anything**.
///
/// This is the primitive every caller ultimately uses. It fsyncs the journal
/// and updates the RAM ring under `AUTH_EVENT_LWLOCK`: no logging, error
/// raising, SPI, database lock or cache mutation occurs inside the section.
///
/// It is safe to call while another LWLock is held. `EnqueueStep::should_warn`
/// carries the *decision* to warn back out as a primitive `bool`, so the caller
/// can release every lock it holds and only then call
/// [`emit_queue_full_warning`].
///
/// # Lock order
/// Callers that already hold a cache lock must hold `EXPIRY_CACHE_LWLOCK`
/// (never `LOCK_CACHE_LWLOCK`), because the only nesting the extension permits
/// is `EXPIRY_CACHE_LWLOCK -> AUTH_EVENT_LWLOCK`. Nothing acquires
/// `EXPIRY_CACHE_LWLOCK` while holding `AUTH_EVENT_LWLOCK`.
pub(crate) fn enqueue_encoded_silent(
    username_bytes: &[u8; LOCK_USERNAME_BYTES],
    kind: u8,
    flags: EventFlags,
    generation: pg_sys::TimestampTz,
) -> EnqueueStep {
    let Some(event_id) = auth_journal::new_event_id() else {
        // No unique identity, so no event can be admitted as durable. Same
        // treatment as a failed append: durable recording is degraded.
        crate::worker_health::mark_durable_failure_now();
        return EnqueueStep {
            outcome: EnqueueOutcome::Unavailable,
            should_warn: false,
        };
    };
    enqueue_encoded_with_id_silent(username_bytes, kind, flags, generation, event_id)
}

fn enqueue_encoded_with_id_silent(
    username_bytes: &[u8; LOCK_USERNAME_BYTES],
    kind: u8,
    flags: EventFlags,
    generation: pg_sys::TimestampTz,
    event_id: EventId,
) -> EnqueueStep {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            crate::worker_health::mark_durable_failure_now();
            return EnqueueStep {
                outcome: EnqueueOutcome::Unavailable,
                should_warn: false,
            };
        }

        let now = pg_sys::GetCurrentTimestamp();
        let ring = &mut *AUTH_EVENT_RING;

        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        let event = SharedAuthEvent {
            event_id: event_id.0,
            username: *username_bytes,
            timestamp: now,
            seq: 0,
            kind,
            generation,
            flags: flags.raw(),
        };
        if auth_journal::append(&event).is_err() {
            ring.rejected = ring.rejected.saturating_add(1);
            ring.journal_failures = ring.journal_failures.saturating_add(1);
            // Publish the degradation while still holding the lock. This is a
            // single relaxed atomic store of a timestamp the caller already
            // computed: no allocation, no logging, no SPI, nothing that can
            // `longjmp`, so it cannot strand `AUTH_EVENT_LWLOCK` (or
            // `EXPIRY_CACHE_LWLOCK`, when the grace path is the caller).
            //
            // It is what pauses lockout and expiry enforcement cluster-wide
            // until the worker has rehydrated the caches from the authoritative
            // tables. Nothing here rejects the login.
            crate::worker_health::mark_durable_failure(now);
            return EnqueueStep {
                outcome: EnqueueOutcome::Unavailable,
                should_warn: ring.should_warn_now(false, now),
            };
        }
        ring.journaled = ring.journaled.saturating_add(1);
        let mut step = ring.try_enqueue(
            event_id.0,
            *username_bytes,
            now,
            kind,
            flags.raw(),
            generation,
        );
        if step.outcome == EnqueueOutcome::Unavailable {
            ring.durable_only = ring.durable_only.saturating_add(1);
            step.outcome = EnqueueOutcome::DurableOnly;
        }
        step
    }
}

/// Emits the queue-full warning.
///
/// Called only by ordinary hook/worker code, only when
/// [`EnqueueStep::should_warn`] was set, and only once **every** LWLock the
/// caller held has been released. Counts only -- never a username and never any
/// event content.
pub(crate) fn emit_queue_full_warning() {
    pgrx::warning!(
        "password_profile: auth event queue is full (usable capacity {}); the event is retained \
         in the durable journal while the worker drains the RAM ring. No authentication \
         event was lost and other users are not blocked.",
        USABLE_CAPACITY
    );
}

pub(crate) fn emit_journal_failure_warning() {
    pgrx::warning!(
        "password_profile: durable auth journal write failed; the authentication event was not \
         recorded. The login itself is decided by PostgreSQL alone and is not rejected for this \
         reason. Lockout and expiry enforcement are paused until the worker has rehydrated the \
         caches from the authoritative tables; see auth_event_durable_recording_degraded in \
         password_profile.get_lock_cache_stats()."
    );
}

/// Offers an event to the ring for a caller that holds no other LWLock.
///
/// Convenience wrapper over [`enqueue_encoded_silent`]: it drops this module's
/// own guard first and only then logs, which is correct **only** because the
/// caller holds nothing else. Nested callers must use the silent primitive.
pub(crate) fn enqueue(username: &str, kind: u8, flags: EventFlags) -> EnqueueOutcome {
    let step = enqueue_encoded_silent(&encode_username(username), kind, flags, 0);
    if step.should_warn {
        if step.outcome == EnqueueOutcome::Unavailable {
            emit_journal_failure_warning();
        } else {
            emit_queue_full_warning();
        }
    }
    step.outcome
}

/// Claims the oldest unacknowledged event without advancing `tail`.
pub(crate) fn claim() -> Option<(ClaimToken, SharedAuthEvent)> {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return None;
        }
        let ring = &mut *AUTH_EVENT_RING;
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        ring.claim()
    }
}

/// Claims the ring tail only when it is the RAM copy of this durable event.
/// A durable-only record legitimately has no matching claim.
pub(crate) fn matching_claim(event_id: &[u8; 16]) -> Option<ClaimToken> {
    let (token, event) = claim()?;
    (event.event_id == *event_id).then_some(token)
}

/// Rotates the active durable journal under the same lock producers use for
/// append + ring insertion, preserving one total event order.
pub(crate) fn rotate_journal() -> Result<Option<std::path::PathBuf>, auth_journal::JournalError> {
    unsafe {
        if AUTH_EVENT_LWLOCK.is_null() {
            return Err(auth_journal::JournalError::Corrupt(
                "auth event LWLock is unavailable",
            ));
        }
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        auth_journal::rotate()
    }
}

/// Verifies the durable journal and resets only the volatile accelerator.
/// Append, verification and reset share one lock, so no producer can cross the
/// recovery boundary.
pub(crate) fn recover_corrupt_ring() -> Result<bool, auth_journal::JournalError> {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return Err(auth_journal::JournalError::Corrupt(
                "auth event shared memory is unavailable",
            ));
        }
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        let ring = &mut *AUTH_EVENT_RING;
        if ring.state() != QueueState::Corrupt {
            return Ok(false);
        }
        auth_journal::verify_pending()?;
        *ring = AuthEventRing::new();
        Ok(true)
    }
}

/// Acknowledges a claim, advancing `tail` past exactly that entry.
///
/// Called only from the transaction commit callback, after PostgreSQL has
/// decided the commit. Allocation-free, log-free, error-free; the cache LWLock
/// must already have been released before this is called.
pub(crate) fn ack_claim(token: ClaimToken) -> AckOutcome {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return AckOutcome::Corrupt;
        }
        let ring = &mut *AUTH_EVENT_RING;
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Exclusive);
        let outcome = ring.ack(token);
        if outcome != AckOutcome::Acknowledged {
            // Cannot raise here -- the database commit already happened. Record
            // it as a primitive state and let ordinary worker code report it.
            ring.degrade_to(QueueState::Corrupt);
        }
        outcome
    }
}

/// Primitive queue counters, copied under one short shared-lock section.
///
/// All `String` construction happens in the caller, after the guard is dropped.
#[derive(Copy, Clone, Debug)]
pub(crate) struct QueueStats {
    pub(crate) usable_capacity: i64,
    pub(crate) depth: i64,
    /// 1 when the ring holds at least one unacknowledged event.
    ///
    /// This is deliberately *not* called "in flight": the ring does not record
    /// whether the worker has actually claimed the tail entry, only that one
    /// exists. Tracking a real claimed flag in shared memory would need a way
    /// to clear it if the worker died mid-claim, which cannot be detected here,
    /// so the honest, cheap signal is reported instead.
    pub(crate) has_pending: i64,
    pub(crate) accepted: i64,
    pub(crate) acknowledged: i64,
    pub(crate) rejected: i64,
    pub(crate) journaled: i64,
    pub(crate) durable_only: i64,
    pub(crate) journal_failures: i64,
    /// Normalized [`QueueState`] discriminant; unknown raw values report as
    /// `Corrupt`.
    pub(crate) state: i64,
    pub(crate) next_seq: i64,
}

pub(crate) fn stats() -> Option<QueueStats> {
    unsafe {
        if AUTH_EVENT_RING.is_null() || AUTH_EVENT_LWLOCK.is_null() {
            return None;
        }
        let ring = &*AUTH_EVENT_RING;
        let _guard = LwLockGuard::acquire(AUTH_EVENT_LWLOCK, LwLockMode::Shared);
        let depth = ring.depth();
        Some(QueueStats {
            usable_capacity: USABLE_CAPACITY as i64,
            depth: depth as i64,
            has_pending: i64::from(depth > 0),
            accepted: ring.accepted.min(i64::MAX as u64) as i64,
            acknowledged: ring.acknowledged.min(i64::MAX as u64) as i64,
            rejected: ring.rejected.min(i64::MAX as u64) as i64,
            journaled: ring.journaled.min(i64::MAX as u64) as i64,
            durable_only: ring.durable_only.min(i64::MAX as u64) as i64,
            journal_failures: ring.journal_failures.min(i64::MAX as u64) as i64,
            // Normalized, not raw: an unrecognized value is reported as
            // `Corrupt`, exactly as `QueueState::from_raw` treats it in the
            // authentication hook. Showing the raw number would present an
            // unsupported value as if it were a state operators can act on.
            state: QueueState::from_raw(ring.state) as i64,
            next_seq: ring.next_seq.min(i64::MAX as u64) as i64,
        })
    }
}

pub(crate) fn username_from_bytes(bytes: &[u8]) -> Option<String> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&bytes[..end])
        .ok()
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    //! Pure state-machine tests over a heap-allocated ring. No shared memory,
    //! no LWLock, no PostgreSQL.

    use super::*;

    fn ring() -> Box<AuthEventRing> {
        Box::new(AuthEventRing::new())
    }

    fn event_id(tag: u8) -> [u8; 16] {
        [tag; 16]
    }

    fn user(tag: u8) -> [u8; LOCK_USERNAME_BYTES] {
        let mut buf = [0u8; LOCK_USERNAME_BYTES];
        buf[0] = tag;
        buf
    }

    fn try_push(r: &mut AuthEventRing, tag: u8, is_failure: bool) -> EnqueueOutcome {
        let kind = if is_failure {
            EVENT_KIND_FAILURE
        } else {
            EVENT_KIND_SUCCESS
        };
        r.try_enqueue(event_id(tag), user(tag), 0, kind, 0, 0)
            .outcome
    }

    /// Enqueue that must succeed; keeps the ordering tests readable.
    fn push(r: &mut AuthEventRing, tag: u8, is_failure: bool) {
        assert_eq!(try_push(r, tag, is_failure), EnqueueOutcome::Enqueued);
    }

    #[test]
    fn claim_does_not_advance_tail() {
        let mut r = ring();
        assert_eq!(try_push(&mut r, 1, true), EnqueueOutcome::Enqueued);

        let tail_before = r.tail;
        let (t1, e1) = r.claim().unwrap();
        assert_eq!(r.tail, tail_before);
        assert_eq!(r.depth(), 1);

        // Claiming again before acknowledgement yields the identical token.
        let (t2, e2) = r.claim().unwrap();
        assert_eq!(t1, t2);
        assert_eq!(e1, e2);
        assert_eq!(r.tail, tail_before);
    }

    #[test]
    fn abort_leaves_the_same_event_claimable() {
        let mut r = ring();
        push(&mut r, 1, true);
        let (token, event) = r.claim().unwrap();

        // A transaction abort simply never calls ack.
        let (token_again, event_again) = r.claim().unwrap();
        assert_eq!(token, token_again);
        assert_eq!(event, event_again);
        assert_eq!(r.depth(), 1);
    }

    #[test]
    fn commit_ack_advances_tail_once_and_duplicate_ack_does_not() {
        let mut r = ring();
        push(&mut r, 1, true);
        let (token, _) = r.claim().unwrap();

        assert_eq!(r.ack(token), AckOutcome::Acknowledged);
        assert_eq!(r.depth(), 0);
        assert_eq!(r.acknowledged, 1);
        let tail_after = r.tail;

        // Case 4: acknowledging the same token again must not advance twice.
        assert_eq!(r.ack(token), AckOutcome::Stale);
        assert_eq!(r.tail, tail_after);
        assert_eq!(r.acknowledged, 1);
    }

    #[test]
    fn wrong_slot_token_is_rejected() {
        let mut r = ring();
        push(&mut r, 1, true);
        push(&mut r, 2, true);
        let (token, _) = r.claim().unwrap();

        let bogus = ClaimToken {
            slot: token.slot + 1,
            seq: token.seq,
        };
        assert_eq!(r.ack(bogus), AckOutcome::Stale);
        assert_eq!(r.depth(), 2);
    }

    #[test]
    fn wrong_sequence_token_is_rejected() {
        let mut r = ring();
        push(&mut r, 1, true);
        let (token, _) = r.claim().unwrap();

        let bogus = ClaimToken {
            slot: token.slot,
            seq: token.seq.wrapping_add(7),
        };
        assert_eq!(r.ack(bogus), AckOutcome::Stale);
        assert_eq!(r.depth(), 1);
        // The real token still works.
        assert_eq!(r.ack(token), AckOutcome::Acknowledged);
    }

    #[test]
    fn stale_token_after_wraparound_is_rejected() {
        // ABA: reuse the same slot a full lap later and confirm the old token
        // no longer acknowledges it.
        let mut r = ring();
        push(&mut r, 1, true);
        let (old_token, _) = r.claim().unwrap();
        assert_eq!(r.ack(old_token), AckOutcome::Acknowledged);

        for lap in 0..RING_SLOTS {
            assert_eq!(
                try_push(&mut r, (lap % 251) as u8 + 1, false),
                EnqueueOutcome::Enqueued
            );
            let (t, _) = r.claim().unwrap();
            assert_eq!(r.ack(t), AckOutcome::Acknowledged);
        }

        // Slot 0 is in use again with a different sequence number.
        push(&mut r, 9, true);
        let (fresh, _) = r.claim().unwrap();
        assert_eq!(fresh.slot, old_token.slot);
        assert_ne!(fresh.seq, old_token.seq);
        assert_eq!(r.ack(old_token), AckOutcome::Stale);
        assert_eq!(r.ack(fresh), AckOutcome::Acknowledged);
    }

    #[test]
    fn fifo_order_survives_wraparound() {
        let mut r = ring();
        let mut expected: u64 = 1;
        for round in 0..(RING_SLOTS * 2 + 5) {
            let tag = (round % 251) as u8 + 1;
            assert_eq!(
                try_push(&mut r, tag, round % 2 == 0),
                EnqueueOutcome::Enqueued
            );
            let (token, event) = r.claim().unwrap();
            assert_eq!(event.username, user(tag));
            assert_eq!(event.seq, expected);
            assert_eq!(r.ack(token), AckOutcome::Acknowledged);
            expected += 1;
        }
    }

    #[test]
    fn success_and_failure_events_keep_their_order() {
        let mut r = ring();
        push(&mut r, b'a', false);
        push(&mut r, b'b', true);

        let (t1, e1) = r.claim().unwrap();
        assert_eq!(e1.username, user(b'a'));
        assert_eq!(EventKind::from_raw(e1.kind), Some(EventKind::Success));
        assert_eq!(r.ack(t1), AckOutcome::Acknowledged);

        let (t2, e2) = r.claim().unwrap();
        assert_eq!(e2.username, user(b'b'));
        assert_eq!(EventKind::from_raw(e2.kind), Some(EventKind::Failure));
        assert_eq!(r.ack(t2), AckOutcome::Acknowledged);
    }

    #[test]
    fn producer_cannot_overwrite_an_unacknowledged_tail_event() {
        let mut r = ring();
        for i in 0..USABLE_CAPACITY {
            assert_eq!(
                try_push(&mut r, (i % 251) as u8 + 1, true),
                EnqueueOutcome::Enqueued
            );
        }
        let (token, claimed) = r.claim().unwrap();
        let tail_before = r.tail;

        // The ring is full: further offers are refused, not absorbed by
        // overwriting the oldest (claimed) entry.
        assert_eq!(try_push(&mut r, 200, true), EnqueueOutcome::DurableOnly);
        assert_eq!(r.tail, tail_before);

        let (token_again, claimed_again) = r.claim().unwrap();
        assert_eq!(token, token_again);
        assert_eq!(claimed, claimed_again);
    }

    #[test]
    fn full_queue_returns_full_counts_and_degrades() {
        let mut r = ring();
        for i in 0..USABLE_CAPACITY {
            push(&mut r, (i % 251) as u8 + 1, true);
        }
        assert_eq!(r.state(), QueueState::Healthy);
        assert_eq!(r.rejected, 0);

        // Non-zero timestamps: `should_warn_now` treats `last_warned_at == 0`
        // as "never warned", so the rate limit is only observable once a real
        // clock value has been stamped.
        let t0: i64 = 1_000_000_000;
        let step = r.try_enqueue(event_id(9), user(9), t0, EVENT_KIND_FAILURE, 0, 0);
        assert_eq!(step.outcome, EnqueueOutcome::DurableOnly);
        assert!(step.should_warn);
        assert_eq!(r.rejected, 1);
        assert_eq!(r.state(), QueueState::Overflowed);

        // A second rejection one second later counts but does not warn again.
        let step2 = r.try_enqueue(
            event_id(10),
            user(10),
            t0 + 1_000_000,
            EVENT_KIND_FAILURE,
            0,
            0,
        );
        assert_eq!(step2.outcome, EnqueueOutcome::DurableOnly);
        assert!(!step2.should_warn);
        assert_eq!(r.rejected, 2);

        // Once the interval has elapsed, exactly one more warning is allowed.
        let step3 = r.try_enqueue(
            event_id(11),
            user(11),
            t0 + QUEUE_WARN_INTERVAL_US,
            EVENT_KIND_FAILURE,
            0,
            0,
        );
        assert_eq!(step3.outcome, EnqueueOutcome::DurableOnly);
        assert!(step3.should_warn);
        let step4 = r.try_enqueue(
            event_id(12),
            user(12),
            t0 + QUEUE_WARN_INTERVAL_US + 1,
            EVENT_KIND_FAILURE,
            0,
            0,
        );
        assert!(!step4.should_warn);
        assert_eq!(r.rejected, 4);
    }

    #[test]
    fn unknown_event_flag_bits_are_rejected() {
        assert_eq!(EventFlags::from_raw(0), Some(EventFlags::NONE));
        assert_eq!(
            EventFlags::from_raw(EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS),
            Some(EventFlags::CLEAR_LOGIN_ATTEMPTS)
        );
        assert_eq!(EventFlags::from_raw(0x02), None);
        assert_eq!(EventFlags::from_raw(0xFF), None);
        assert_eq!(
            EventFlags::from_raw(EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS | 0x80),
            None
        );
    }

    #[test]
    fn admission_flags_capture_the_lockout_switch() {
        assert!(EventFlags::for_admission(true).clear_login_attempts());
        assert!(!EventFlags::for_admission(false).clear_login_attempts());
    }

    #[test]
    fn event_flags_round_trip_through_the_ring() {
        let mut r = ring();
        assert_eq!(
            r.try_enqueue(
                event_id(b'f'),
                user(b'f'),
                0,
                EVENT_KIND_GRACE_CONSUMED,
                EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS,
                7
            )
            .outcome,
            EnqueueOutcome::Enqueued
        );
        let (_, ev) = r.claim().unwrap();
        assert_eq!(ev.flags, EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS);
        assert!(EventFlags::from_raw(ev.flags)
            .unwrap()
            .clear_login_attempts());
    }

    #[test]
    fn draining_an_overflowed_queue_recovers_health() {
        let mut r = ring();
        for i in 0..USABLE_CAPACITY {
            push(&mut r, (i % 251) as u8 + 1, true);
        }
        assert_eq!(
            r.try_enqueue(event_id(9), user(9), 0, EVENT_KIND_FAILURE, 0, 0)
                .outcome,
            EnqueueOutcome::DurableOnly
        );
        assert_eq!(r.state(), QueueState::Overflowed);

        while let Some((token, _)) = r.claim() {
            assert_eq!(r.ack(token), AckOutcome::Acknowledged);
        }
        assert_eq!(r.depth(), 0);
        assert_eq!(r.state(), QueueState::Healthy);
    }

    #[test]
    fn corrupt_queue_rejects_new_events_without_full_warning() {
        let mut r = ring();
        r.degrade_to(QueueState::Corrupt);

        let step = r.try_enqueue(event_id(1), user(1), 10, EVENT_KIND_FAILURE, 0, 0);
        assert_eq!(step.outcome, EnqueueOutcome::Unavailable);
        assert!(!step.should_warn);
        assert_eq!(r.depth(), 0);
        assert_eq!(r.state(), QueueState::Corrupt);
    }

    #[test]
    fn failed_transaction_retry_receives_the_same_event_then_acks_it() {
        let mut r = ring();
        push(&mut r, b'x', true);
        push(&mut r, b'y', false);

        // Attempt 1: claim, transaction fails, no ack.
        let (t1, e1) = r.claim().unwrap();
        // Attempt 2: same claim comes back.
        let (t2, e2) = r.claim().unwrap();
        assert_eq!(t1, t2);
        assert_eq!(e1, e2);
        // Attempt 3 succeeds and acknowledges exactly that token.
        assert_eq!(r.ack(t2), AckOutcome::Acknowledged);
        assert_eq!(r.acknowledged, 1);

        // The next event is a different one, in order.
        let (t3, e3) = r.claim().unwrap();
        assert_ne!(t3, t2);
        assert_eq!(e3.username, user(b'y'));
        assert_eq!(r.ack(t3), AckOutcome::Acknowledged);
        assert!(r.claim().is_none());
    }

    #[test]
    fn corrupt_indices_are_handled_without_panicking() {
        let mut r = ring();
        push(&mut r, 1, true);
        let (token, _) = r.claim().unwrap();

        r.head = u32::MAX;
        assert!(!r.indices_valid());
        assert_eq!(r.depth(), 0);
        assert!(r.claim().is_none());
        assert_eq!(r.state(), QueueState::Corrupt);
        assert_eq!(r.ack(token), AckOutcome::Corrupt);
        assert_eq!(
            r.try_enqueue(event_id(2), user(2), 0, EVENT_KIND_FAILURE, 0, 0)
                .outcome,
            EnqueueOutcome::Unavailable
        );

        let mut r2 = ring();
        r2.tail = RING_SLOTS as u32 + 99;
        assert!(r2.claim().is_none());
        assert_eq!(r2.state(), QueueState::Corrupt);
    }

    #[test]
    fn sequence_exhaustion_fails_closed_instead_of_reusing() {
        let mut r = ring();
        r.next_seq = u64::MAX;

        let step = r.try_enqueue(event_id(1), user(1), 0, EVENT_KIND_FAILURE, 0, 0);
        assert_eq!(step.outcome, EnqueueOutcome::Unavailable);
        assert!(step.should_warn);
        assert_eq!(r.state(), QueueState::Corrupt);
        assert_eq!(r.rejected, 1);
        // Nothing was written and no sequence number was handed out twice.
        assert_eq!(r.depth(), 0);
        assert_eq!(r.next_seq, u64::MAX);
    }

    #[test]
    fn sequence_numbers_are_never_reused() {
        let mut r = ring();
        r.next_seq = u64::MAX - 2;

        push(&mut r, 1, true);
        let first = r.claim().unwrap().0;
        assert_eq!(r.ack(first), AckOutcome::Acknowledged);
        push(&mut r, 2, true);
        let second = r.claim().unwrap().0;
        assert_ne!(first.seq, second.seq);
        assert_eq!(r.ack(second), AckOutcome::Acknowledged);

        // The last usable sequence number is consumed, then the ring refuses
        // further writes rather than wrapping and reusing sequence numbers.
        assert_eq!(r.next_seq, u64::MAX);
        assert_eq!(
            r.try_enqueue(event_id(3), user(3), 0, EVENT_KIND_FAILURE, 0, 0)
                .outcome,
            EnqueueOutcome::Unavailable
        );
    }

    #[test]
    fn event_kind_validation_rejects_unknown_discriminants() {
        assert_eq!(
            EventKind::from_raw(EVENT_KIND_FAILURE),
            Some(EventKind::Failure)
        );
        assert_eq!(
            EventKind::from_raw(EVENT_KIND_SUCCESS),
            Some(EventKind::Success)
        );
        assert_eq!(
            EventKind::from_raw(EVENT_KIND_GRACE_CONSUMED),
            Some(EventKind::GraceConsumed)
        );
        assert_eq!(EventKind::from_raw(0), None);
        assert_eq!(EventKind::from_raw(4), None);
        assert_eq!(EventKind::from_raw(255), None);
    }

    #[test]
    fn grace_event_carries_its_generation() {
        let mut r = ring();
        let u = user(b'g');
        assert_eq!(
            r.try_enqueue(event_id(b'g'), u, 0, EVENT_KIND_GRACE_CONSUMED, 0, 424242)
                .outcome,
            EnqueueOutcome::Enqueued
        );
        let (_, ev) = r.claim().unwrap();
        assert_eq!(ev.kind, EVENT_KIND_GRACE_CONSUMED);
        assert_eq!(ev.generation, 424242);
    }

    #[test]
    fn unknown_raw_state_maps_to_corrupt() {
        assert_eq!(QueueState::from_raw(0), QueueState::Healthy);
        assert_eq!(QueueState::from_raw(1), QueueState::Overflowed);
        assert_eq!(QueueState::from_raw(2), QueueState::Corrupt);
        assert_eq!(QueueState::from_raw(-7), QueueState::Corrupt);
        assert_eq!(QueueState::from_raw(9999), QueueState::Corrupt);
    }

    #[test]
    fn corrupt_outranks_overflowed_and_is_not_downgraded() {
        let mut r = ring();
        r.degrade_to(QueueState::Overflowed);
        assert_eq!(r.state(), QueueState::Overflowed);
        r.degrade_to(QueueState::Corrupt);
        assert_eq!(r.state(), QueueState::Corrupt);
        r.degrade_to(QueueState::Overflowed);
        assert_eq!(r.state(), QueueState::Corrupt);
    }
}
