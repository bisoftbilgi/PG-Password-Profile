//! Shared-memory password-expiry cache.
//!
//! # Why a cache at all
//! `ClientAuthentication_hook` runs before a normal database connection exists,
//! so it cannot query `password_profile.password_expiry`. Expiry and grace
//! decisions must therefore be answered entirely from shared memory, hydrated
//! from the authoritative table by the background worker.
//!
//! # Password generation
//! Each entry carries the row's exact `last_changed` value as a *generation*.
//! Grace-consumption events carry it too, so an event queued against an old
//! password can never decrement the grace allowance of a password that has
//! since been changed: the worker compares generations and treats a mismatch as
//! stale. `last_changed` is written by the same statement that resets
//! `grace_logins_remaining`, so it changes exactly when the grace allowance is
//! reset, which is precisely the identity a generation needs.
//!
//! # Lock discipline
//! Every critical section here is bounded, allocation-free and log-free. The
//! only nesting permitted anywhere in the extension is
//! `EXPIRY_CACHE_LWLOCK -> AUTH_EVENT_LWLOCK`, taken by
//! [`try_consume_grace`] so that decrementing the cached grace count and
//! queueing its persistence event are one indivisible step. Nothing acquires
//! them in the reverse order.
//!
//! Because that nesting exists, [`try_consume_grace`] uses
//! [`crate::auth_event::enqueue_encoded_silent`], which performs only
//! fixed-size shared-memory work and never logs. An earlier revision called a
//! wrapper that logged after releasing `AUTH_EVENT_LWLOCK` but while
//! `EXPIRY_CACHE_LWLOCK` was still held -- exactly the "log while holding a
//! PostgreSQL lock" hazard this project exists to avoid. The decision to warn
//! now travels back out as a primitive `bool` in [`GraceResult`], and the
//! authentication hook emits it after **both** locks are released.

use crate::auth_event;
use crate::{
    encode_username, LwLockGuard, LwLockMode, EXPIRY_CACHE_LWLOCK, EXPIRY_CACHE_SIZE,
    LOCK_USERNAME_BYTES,
};
use pgrx::pg_sys;
use std::ptr;

/// One cached expiry row.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct ExpiryEntry {
    /// Fixed-size encoded username; `username[0] == 0` marks a free slot.
    pub(crate) username: [u8; LOCK_USERNAME_BYTES],
    /// Exact `must_change_by` from the authoritative row.
    pub(crate) must_change_by: pg_sys::TimestampTz,
    /// Exact `last_changed`, used as the password generation.
    pub(crate) generation: pg_sys::TimestampTz,
    /// Remaining grace logins, never negative.
    pub(crate) grace_remaining: i32,
    _pad: i32,
}

impl ExpiryEntry {
    const EMPTY: ExpiryEntry = ExpiryEntry {
        username: [0; LOCK_USERNAME_BYTES],
        must_change_by: 0,
        generation: 0,
        grace_remaining: 0,
        _pad: 0,
    };
}

/// Readiness of the expiry cache, mirroring the lock cache's state machine.
///
/// `#[repr(i32)]` with explicit discriminants: the raw value lives in shared
/// memory and is reported numerically through `get_lock_cache_stats()`.
#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ExpiryCacheState {
    /// Never hydrated, or hydration failed. Expiry enforcement stays disabled.
    NotReady = 0,
    /// Hydrated and complete; every expiry row is represented.
    Ready = 1,
    /// More expiry rows exist than the cache can hold. Coverage is incomplete,
    /// so expiry enforcement is temporarily disabled.
    Overflow = 2,
    /// The worker stopped after a failure it could not recover from.
    WorkerFailed = 3,
}

impl ExpiryCacheState {
    /// Unknown raw values map to `NotReady` -- the safe direction, since only
    /// `Ready` permits enforcement to consult the cache.
    #[inline]
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => ExpiryCacheState::Ready,
            2 => ExpiryCacheState::Overflow,
            3 => ExpiryCacheState::WorkerFailed,
            _ => ExpiryCacheState::NotReady,
        }
    }
}

/// What the cache says about a user's expiry, evaluated against a wall-clock
/// instant.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum ExpiryDecision {
    /// The cache is not usable; login-time expiry enforcement is unavailable.
    CacheUnavailable,
    /// No expiry row exists for this user -- nothing to enforce.
    NoRow,
    /// `must_change_by` is still in the future.
    NotExpired,
    /// Expired, but grace logins remain.
    ExpiredWithGrace,
    /// Expired with no grace left.
    ExpiredNoGrace,
}

/// Everything [`try_consume_grace`] decided, carried out of the locked region
/// as primitives.
///
/// `queue_warn` is the auth-event ring's own rate-limited decision that a
/// queue-full warning is due. It is returned rather than acted on, because
/// acting on it would mean logging while `EXPIRY_CACHE_LWLOCK` is held.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) struct GraceResult {
    pub(crate) outcome: GraceOutcome,
    pub(crate) queue_warn: bool,
}

/// Result of atomically consuming one grace login.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) enum GraceOutcome {
    /// One grace login was decremented and its persistence event queued.
    Consumed,
    /// The re-check under the lock found nothing to consume (row vanished, the
    /// password was changed, or it is no longer expired): allow the login.
    NotNeeded,
    /// Expired with no grace remaining: reject.
    NoGrace,
    /// The decrement could not be recorded (queue full/unhealthy, or cache not
    /// ready). This login must be rejected -- never admit an unrecorded grace
    /// login.
    Unavailable,
}

#[repr(C)]
pub(crate) struct ExpiryCache {
    pub(crate) entries: [ExpiryEntry; EXPIRY_CACHE_SIZE],
    /// Raw [`ExpiryCacheState`].
    pub(crate) state: i32,
    /// Rows seen by the last successful hydration.
    pub(crate) hydration_rows: i64,
    /// Rows the last hydration could not fit.
    pub(crate) hydration_overflow: i64,
}

pub(crate) static mut EXPIRY_CACHE: *mut ExpiryCache = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<ExpiryCache>()
}

/// # Safety
/// Must be called from `shmem_startup_hook`, after the named LWLock tranche has
/// been initialized.
pub(crate) unsafe fn init() {
    if !EXPIRY_CACHE.is_null() {
        return;
    }

    let size = std::mem::size_of::<ExpiryCache>();
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_expiry_cache".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut ExpiryCache;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize shared expiry cache");
    }

    if !found {
        for entry in (*cache_ptr).entries.iter_mut() {
            *entry = ExpiryEntry::EMPTY;
        }
        (*cache_ptr).hydration_rows = 0;
        (*cache_ptr).hydration_overflow = 0;
        // Never start Ready: an un-hydrated cache knows nothing about expiry.
        (*cache_ptr).state = ExpiryCacheState::NotReady as i32;
        pgrx::log!(
            "password_profile: expiry cache allocated ({} bytes, capacity {})",
            size,
            EXPIRY_CACHE_SIZE
        );
    } else {
        pgrx::log!("password_profile: expiry cache attached to existing segment");
    }

    EXPIRY_CACHE = cache_ptr;
}

/// Current cache state. Short shared-lock read, allocation-free.
pub(crate) fn state() -> ExpiryCacheState {
    unsafe {
        if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
            return ExpiryCacheState::NotReady;
        }
        let cache = &*EXPIRY_CACHE;
        let raw = {
            let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Shared);
            cache.state
        };
        ExpiryCacheState::from_raw(raw)
    }
}

/// Stores a state under a short exclusive section. One primitive write.
pub(crate) fn set_state(new_state: ExpiryCacheState) {
    unsafe {
        if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
            return;
        }
        let cache = &mut *EXPIRY_CACHE;
        let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Exclusive);
        cache.state = new_state as i32;
    }
}

/// Pure decision helper, shared by the cache lookup and the locked re-check so
/// the two can never disagree.
#[inline]
fn classify(entry: &ExpiryEntry, now: pg_sys::TimestampTz) -> ExpiryDecision {
    if entry.must_change_by > now {
        ExpiryDecision::NotExpired
    } else if entry.grace_remaining > 0 {
        ExpiryDecision::ExpiredWithGrace
    } else {
        ExpiryDecision::ExpiredNoGrace
    }
}

/// Answers the expiry question for `username` without changing anything.
///
/// Distinguishes "no expiry row for this user" ([`ExpiryDecision::NoRow`]) from
/// "cache not usable" ([`ExpiryDecision::CacheUnavailable`]): the first means
/// there is nothing to enforce, while the second pauses login-time expiry for
/// this request.
pub(crate) fn lookup(username: &str, now: pg_sys::TimestampTz) -> ExpiryDecision {
    unsafe {
        if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
            return ExpiryDecision::CacheUnavailable;
        }
        let encoded = encode_username(username);
        let cache = &*EXPIRY_CACHE;

        let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Shared);

        if ExpiryCacheState::from_raw(cache.state) != ExpiryCacheState::Ready {
            return ExpiryDecision::CacheUnavailable;
        }

        for entry in cache.entries.iter() {
            if entry.username[0] != 0 && entry.username == encoded {
                return classify(entry, now);
            }
        }
        ExpiryDecision::NoRow
    }
}

/// Atomically consumes one grace login and queues its persistence event.
///
/// # Atomicity
/// The exclusive expiry lock is held across the whole sequence, so two
/// concurrent logins cannot both observe the same last grace allowance. Under
/// that lock this re-reads the entry (the state may have changed since
/// [`lookup`]), queues the grace event first, and only decrements if the event
/// was actually accepted. A failed enqueue therefore leaves the grace count
/// untouched and returns [`GraceOutcome::Unavailable`], so the caller rejects
/// the connection instead of admitting an unrecorded grace login.
///
/// # Lock order and logging
/// `EXPIRY_CACHE_LWLOCK -> AUTH_EVENT_LWLOCK`. This is the only nesting of
/// these two locks in the extension, and nothing takes them the other way
/// round. Nothing in this function logs, allocates, formats, raises, sleeps or
/// calls SPI: the enqueue uses the silent primitive, and any warning the ring
/// decided is due is returned in [`GraceResult::queue_warn`] for the caller to
/// emit once both locks are released.
///
/// # Flags
/// `flags` records what the hook decided at admission time -- in particular
/// whether failed-login cleanup is required -- so the worker never has to
/// consult a GUC that may have been reloaded since.
pub(crate) fn try_consume_grace(
    username: &str,
    now: pg_sys::TimestampTz,
    flags: auth_event::EventFlags,
) -> GraceResult {
    unsafe {
        if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
            return GraceResult {
                outcome: GraceOutcome::Unavailable,
                queue_warn: false,
            };
        }
        let encoded = encode_username(username);
        let cache = &mut *EXPIRY_CACHE;

        let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Exclusive);

        if ExpiryCacheState::from_raw(cache.state) != ExpiryCacheState::Ready {
            return GraceResult {
                outcome: GraceOutcome::Unavailable,
                queue_warn: false,
            };
        }

        let mut found: Option<usize> = None;
        for (idx, entry) in cache.entries.iter().enumerate() {
            if entry.username[0] != 0 && entry.username == encoded {
                found = Some(idx);
                break;
            }
        }

        let idx = match found {
            Some(idx) => idx,
            // The row disappeared between the lookup and here: nothing to
            // consume, and no expiry to enforce.
            None => {
                return GraceResult {
                    outcome: GraceOutcome::NotNeeded,
                    queue_warn: false,
                }
            }
        };

        let outcome_without_queue = match classify(&cache.entries[idx], now) {
            ExpiryDecision::NotExpired => Some(GraceOutcome::NotNeeded),
            ExpiryDecision::ExpiredNoGrace => Some(GraceOutcome::NoGrace),
            ExpiryDecision::ExpiredWithGrace => None,
            // `classify` never returns these.
            ExpiryDecision::NoRow | ExpiryDecision::CacheUnavailable => {
                Some(GraceOutcome::Unavailable)
            }
        };
        if let Some(outcome) = outcome_without_queue {
            return GraceResult {
                outcome,
                queue_warn: false,
            };
        }

        let generation = cache.entries[idx].generation;

        // Queue first: if this fails nothing has been decremented yet, so the
        // caller can reject without having lost a grace login. The silent
        // primitive is mandatory here -- `EXPIRY_CACHE_LWLOCK` is still held.
        let step = auth_event::enqueue_encoded_silent(
            &encoded,
            auth_event::EVENT_KIND_GRACE_CONSUMED,
            flags,
            generation,
        );

        if !step.outcome.is_durable() {
            return GraceResult {
                outcome: GraceOutcome::Unavailable,
                queue_warn: step.should_warn,
            };
        }

        cache.entries[idx].grace_remaining -= 1;
        GraceResult {
            outcome: GraceOutcome::Consumed,
            queue_warn: step.should_warn,
        }
    }
}

/// Installs or refreshes one expiry entry.
///
/// Never evicts a live entry to make room: a full cache records
/// [`ExpiryCacheState::Overflow`] and refuses, because silently dropping an
/// entry would make an expired password look like it has no expiry row.
///
/// Called from the transaction commit callback, so it performs no allocation,
/// formatting, logging, SPI or error raising.
///
/// # Safety
/// Must not be called while any cache LWLock is already held.
pub(crate) unsafe fn set_entry(
    username_bytes: &[u8; LOCK_USERNAME_BYTES],
    must_change_by: pg_sys::TimestampTz,
    generation: pg_sys::TimestampTz,
    grace_remaining: i32,
) -> crate::lock_cache::CacheOpStatus {
    use crate::lock_cache::CacheOpStatus;

    if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() || username_bytes[0] == 0 {
        return CacheOpStatus::Overflowed;
    }
    let cache = &mut *EXPIRY_CACHE;
    let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Exclusive);

    if let Some(entry) = cache
        .entries
        .iter_mut()
        .find(|e| e.username[0] != 0 && e.username == *username_bytes)
    {
        entry.must_change_by = must_change_by;
        entry.generation = generation;
        entry.grace_remaining = grace_remaining.max(0);
        return CacheOpStatus::Applied;
    }

    if let Some(entry) = cache.entries.iter_mut().find(|e| e.username[0] == 0) {
        entry.username = *username_bytes;
        entry.must_change_by = must_change_by;
        entry.generation = generation;
        entry.grace_remaining = grace_remaining.max(0);
        return CacheOpStatus::Applied;
    }

    cache.state = ExpiryCacheState::Overflow as i32;
    CacheOpStatus::Overflowed
}

/// Removes one expiry entry, used when a password change disables expiry.
///
/// # Safety
/// Must not be called while any cache LWLock is already held.
pub(crate) unsafe fn clear_entry(
    username_bytes: &[u8; LOCK_USERNAME_BYTES],
) -> crate::lock_cache::CacheOpStatus {
    use crate::lock_cache::CacheOpStatus;

    if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
        return CacheOpStatus::Applied;
    }
    let cache = &mut *EXPIRY_CACHE;
    let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Exclusive);

    for entry in cache.entries.iter_mut() {
        if entry.username[0] != 0 && entry.username == *username_bytes {
            *entry = ExpiryEntry::EMPTY;
            break;
        }
    }
    CacheOpStatus::Applied
}

/// Replaces the whole cache from a hydration snapshot in one exclusive section.
///
/// Returns how many entries were installed. Everything expensive (SQL,
/// allocation, ordering) happened before this call.
///
/// # Safety
/// Caller must ensure shared memory is initialized.
pub(crate) unsafe fn apply_hydrated(
    prepared: &[ExpiryEntry],
    rows: i64,
    overflow: i64,
    new_state: ExpiryCacheState,
) -> i64 {
    if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
        return 0;
    }
    let cache = &mut *EXPIRY_CACHE;
    let mut loaded: i64 = 0;

    let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Exclusive);

    // Full replacement: rows deleted in the database, and anything left from a
    // previous worker lifetime, disappear here.
    for entry in cache.entries.iter_mut() {
        *entry = ExpiryEntry::EMPTY;
    }

    let mut slot = 0usize;
    for prepared_entry in prepared.iter() {
        if slot >= EXPIRY_CACHE_SIZE {
            break;
        }
        if prepared_entry.username[0] == 0 {
            continue;
        }
        cache.entries[slot] = *prepared_entry;
        slot += 1;
        loaded += 1;
    }

    cache.hydration_rows = rows;
    cache.hydration_overflow = overflow;
    cache.state = new_state as i32;

    loaded
}

/// Primitive counters copied under one short shared section. All `String`
/// construction happens in the caller.
#[derive(Copy, Clone, Debug)]
pub(crate) struct ExpiryStats {
    pub(crate) capacity: i64,
    pub(crate) used: i64,
    pub(crate) free: i64,
    pub(crate) hydration_rows: i64,
    pub(crate) hydration_overflow: i64,
    pub(crate) state: i64,
}

pub(crate) fn stats() -> Option<ExpiryStats> {
    unsafe {
        if EXPIRY_CACHE.is_null() || EXPIRY_CACHE_LWLOCK.is_null() {
            return None;
        }
        let cache = &*EXPIRY_CACHE;
        let _guard = LwLockGuard::acquire(EXPIRY_CACHE_LWLOCK, LwLockMode::Shared);
        let used = cache.entries.iter().filter(|e| e.username[0] != 0).count() as i64;
        Some(ExpiryStats {
            capacity: EXPIRY_CACHE_SIZE as i64,
            used,
            free: EXPIRY_CACHE_SIZE as i64 - used,
            hydration_rows: cache.hydration_rows,
            hydration_overflow: cache.hydration_overflow,
            // Normalized: an unrecognized stored value reports as NotReady.
            state: ExpiryCacheState::from_raw(cache.state) as i64,
        })
    }
}

/// Builds a prepared entry outside any lock. Used by hydration.
pub(crate) fn prepared_entry(
    username: &str,
    must_change_by: pg_sys::TimestampTz,
    generation: pg_sys::TimestampTz,
    grace_remaining: i32,
) -> ExpiryEntry {
    ExpiryEntry {
        username: encode_username(username),
        must_change_by,
        generation,
        grace_remaining: grace_remaining.max(0),
        _pad: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tag: u8, must_change_by: i64, generation: i64, grace: i32) -> ExpiryEntry {
        let mut username = [0u8; LOCK_USERNAME_BYTES];
        username[0] = tag;
        ExpiryEntry {
            username,
            must_change_by,
            generation,
            grace_remaining: grace,
            _pad: 0,
        }
    }

    const NOW: i64 = 1_000_000;

    #[test]
    fn classify_covers_every_state() {
        assert_eq!(
            classify(&entry(1, NOW + 1, 1, 0), NOW),
            ExpiryDecision::NotExpired
        );
        assert_eq!(
            classify(&entry(1, NOW - 1, 1, 2), NOW),
            ExpiryDecision::ExpiredWithGrace
        );
        assert_eq!(
            classify(&entry(1, NOW - 1, 1, 0), NOW),
            ExpiryDecision::ExpiredNoGrace
        );
        // Exactly at the boundary counts as expired: `must_change_by > now` is
        // the "still valid" test.
        assert_eq!(
            classify(&entry(1, NOW, 1, 0), NOW),
            ExpiryDecision::ExpiredNoGrace
        );
    }

    #[test]
    fn unknown_raw_state_maps_to_not_ready() {
        assert_eq!(ExpiryCacheState::from_raw(0), ExpiryCacheState::NotReady);
        assert_eq!(ExpiryCacheState::from_raw(1), ExpiryCacheState::Ready);
        assert_eq!(ExpiryCacheState::from_raw(2), ExpiryCacheState::Overflow);
        assert_eq!(
            ExpiryCacheState::from_raw(3),
            ExpiryCacheState::WorkerFailed
        );
        assert_eq!(ExpiryCacheState::from_raw(-5), ExpiryCacheState::NotReady);
        assert_eq!(ExpiryCacheState::from_raw(77), ExpiryCacheState::NotReady);
    }

    #[test]
    fn negative_grace_is_clamped_in_prepared_entries() {
        let e = prepared_entry("bob", NOW, NOW, -3);
        assert_eq!(e.grace_remaining, 0);
    }
}
