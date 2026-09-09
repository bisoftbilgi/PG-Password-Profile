//! Commit-time application of shared lock-cache changes.
//!
//! # Why this is its own module
//! Shared memory is not transactional. Before this, `record_failed_login` and
//! both clear paths wrote the cache *during* their transaction, so a rollback
//! (or a commit-time failure) left shared memory describing a database state
//! that never existed -- in the worst case a cleared cache entry for a user the
//! database still has locked.
//!
//! Fixing that needs backend-local staging plus PostgreSQL transaction and
//! subtransaction callbacks, with their own registration discipline, bounded
//! storage, savepoint re-parenting and two-phase-commit policy. That is a
//! self-contained concern with invariants of its own, and `src/lib.rs` is
//! already ~1700 lines, so it lives here rather than being interleaved with the
//! password-policy code.
//!
//! # Ordering guarantee this design relies on
//! Verified against PostgreSQL's `CommitTransaction()` (`src/backend/access/
//! transam/xact.c`) in the locally installed 15.19, 16.15, 17.11 and 18.6
//! source trees, which run, in order:
//!
//! ```text
//! RecordTransactionCommit()                      // commit is durable/decided
//! CallXactCallbacks(XACT_EVENT_COMMIT)           // <-- this module's callback
//! ResourceOwnerRelease(.., RESOURCE_RELEASE_BEFORE_LOCKS, ..)
//! ResourceOwnerRelease(.., RESOURCE_RELEASE_LOCKS, ..)
//!     -> ProcReleaseLocks(isCommit)
//!         -> LockReleaseAll(USER_LOCKMETHOD, false)   // advisory locks released
//! ```
//!
//! So the commit callback runs **after** the commit is durable and **before**
//! the per-user transaction advisory lock is released -- exactly the window in
//! which the cache may be updated without racing another writer for the same
//! username. `AbortTransaction()` likewise calls
//! `CallXactCallbacks(XACT_EVENT_ABORT)` before its `ResourceOwnerRelease`
//! sequence, which is what lets an abort discard staged work.
//!
//! # Callback discipline
//! The commit and abort callbacks perform no SPI, no allocation, no formatting,
//! no logging and raise no errors. They only copy fixed-size bytes and
//! primitives, under the cache LWLock where shared memory is touched. They
//! never acquire a database or advisory lock, so they cannot invert the global
//! lock order.

use crate::auth_event::{self, AckOutcome, ClaimToken};
use crate::expiry_cache;
use crate::lock_cache::{self, CacheDecision, CacheOpStatus};
use crate::LOCK_USERNAME_BYTES;
use pgrx::pg_sys;
use pgrx::prelude::*;
use std::ffi::c_void;
use std::sync::Once;

/// Maximum number of staged cache operations per transaction.
///
/// Bounded on purpose: an unbounded `Vec` would let one long-lived backend grow
/// without limit. One transaction realistically stages one operation (the
/// worker processes a single auth event per transaction); the headroom covers
/// several usernames and savepoint layers. Exceeding it is never a silent drop
/// -- see [`stage`].
const MAX_PENDING_OPS: usize = 16;

/// What a staged entry should do to the expiry cache on commit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ExpiryDecision {
    /// Leave the expiry cache alone (a lockout-only operation).
    None,
    /// Install/refresh this user's entry with the exact committed values.
    Set {
        must_change_by: pg_sys::TimestampTz,
        generation: pg_sys::TimestampTz,
        grace_remaining: i32,
    },
    /// Remove this user's entry -- expiry was disabled for the change.
    Clear,
}

/// A fixed-size, staged cache mutation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PendingEntry {
    username: [u8; LOCK_USERNAME_BYTES],
    /// `None` leaves the lock cache untouched -- used by expiry-only staging,
    /// so recording a password change cannot silently clear an account lockout.
    decision: Option<CacheDecision>,
    /// Expiry-cache side of the same staged operation. Kept in the same entry
    /// so savepoint re-parenting, duplicate collapsing and the bounded capacity
    /// cover both caches with one mechanism.
    expiry: ExpiryDecision,
    /// The subtransaction that staged this entry (or adopted it when a child
    /// savepoint committed). Used to discard it if that level aborts, and to
    /// re-parent it if that level commits.
    subid: pg_sys::SubTransactionId,
}

/// Backend-local staging area for the current transaction.
///
/// # Ordering invariant
/// Entries are kept in **chronological staging order**, and `apply_all` applies
/// them in that order, so "later entry wins". Every mutation below preserves
/// that order, which is what makes the applied decision for a username always
/// the chronologically latest surviving one.
///
/// All methods here are pure Rust over a fixed array: no PostgreSQL calls, no
/// allocation, no logging. That is deliberate -- it makes the savepoint
/// algebra unit-testable without a running server (see the tests at the bottom
/// of this file).
struct PendingState {
    entries: [Option<PendingEntry>; MAX_PENDING_OPS],
    len: usize,
    /// The auth-event claim this transaction will acknowledge on commit.
    ///
    /// At most one, because a single worker consumer holds at most one claim at
    /// a time. Staged here rather than acknowledged after
    /// `CommitTransactionCommand()` returns: doing it afterwards leaves a window
    /// where the database commit is durable but the event is still queued, so a
    /// crash in between would replay it and double-count the failure.
    ack: Option<PendingAck>,
}

/// A staged auth-event acknowledgement, scoped to the subtransaction that
/// staged it so savepoint rollback discards it like any other pending work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct PendingAck {
    token: ClaimToken,
    subid: pg_sys::SubTransactionId,
}

/// The staging area is full for this transaction.
///
/// Carries no message and allocates nothing; the caller turns it into an error
/// that aborts the surrounding transaction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct StageCapacityExceeded;

impl PendingState {
    const fn new() -> Self {
        PendingState {
            entries: [None; MAX_PENDING_OPS],
            len: 0,
            ack: None,
        }
    }

    /// Number of live entries, clamped so a corrupted length can never index
    /// out of bounds.
    #[inline]
    fn live(&self) -> usize {
        if self.len > MAX_PENDING_OPS {
            MAX_PENDING_OPS
        } else {
            self.len
        }
    }

    /// True when this transaction has staged no work at all -- neither a cache
    /// operation nor an acknowledgement. Used by the 2PC guard, which must
    /// consider a staged acknowledgement just as much "pending work" as a cache
    /// operation.
    #[inline]
    fn is_empty(&self) -> bool {
        self.live() == 0 && self.ack.is_none()
    }

    #[inline]
    fn reset(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.len = 0;
        self.ack = None;
    }

    /// Stages one decision.
    ///
    /// Looks **backwards** for the latest entry with the same
    /// `(username, subid)` and overwrites that one. Searching forwards was the
    /// original bug: after a committed child savepoint was re-parented, the
    /// oldest parent entry was overwritten while the newer, re-parented child
    /// entry stayed later in the array and therefore won at commit -- inverting
    /// chronological order.
    ///
    /// Entries staged by a *different* (nested) subtransaction are never
    /// overwritten, because aborting that level must restore the parent's
    /// earlier decision.
    fn stage_entry(
        &mut self,
        username: [u8; LOCK_USERNAME_BYTES],
        decision: Option<CacheDecision>,
        expiry: ExpiryDecision,
        subid: pg_sys::SubTransactionId,
    ) -> Result<(), StageCapacityExceeded> {
        let live = self.live();

        // Backwards: the chronologically latest matching entry wins.
        for idx in (0..live).rev() {
            if let Some(entry) = &mut self.entries[idx] {
                if entry.subid == subid && entry.username == username {
                    entry.decision = decision;
                    entry.expiry = expiry;
                    return Ok(());
                }
            }
        }

        if live >= MAX_PENDING_OPS {
            return Err(StageCapacityExceeded);
        }

        self.entries[live] = Some(PendingEntry {
            username,
            decision,
            expiry,
            subid,
        });
        self.len = live + 1;
        Ok(())
    }

    /// A savepoint rolled back: drop only what that level staged.
    ///
    /// Entries staged by outer levels -- including an earlier decision for the
    /// same username -- survive untouched and keep their relative order.
    fn on_sub_abort(&mut self, my_subid: pg_sys::SubTransactionId) {
        // An acknowledgement staged inside the aborted savepoint is discarded
        // with everything else that level staged, so the event stays claimable.
        if matches!(self.ack, Some(ack) if ack.subid == my_subid) {
            self.ack = None;
        }
        let live = self.live();
        let mut write = 0usize;
        for read in 0..live {
            let keep = matches!(&self.entries[read], Some(entry) if entry.subid != my_subid);
            if keep {
                self.entries[write] = self.entries[read];
                write += 1;
            }
        }
        for slot in self.entries.iter_mut().take(live).skip(write) {
            *slot = None;
        }
        self.len = write;
    }

    /// A savepoint committed: its entries are adopted by the parent level, then
    /// duplicates are collapsed.
    ///
    /// Collapsing after re-parenting is what keeps the array from filling up
    /// with historical duplicates and, together with the backwards search in
    /// [`PendingState::stage_entry`], keeps "latest wins" true no matter how
    /// the savepoints nest.
    fn on_sub_commit(
        &mut self,
        my_subid: pg_sys::SubTransactionId,
        parent_subid: pg_sys::SubTransactionId,
    ) {
        if let Some(ack) = &mut self.ack {
            if ack.subid == my_subid {
                ack.subid = parent_subid;
            }
        }
        let live = self.live();
        for slot in self.entries.iter_mut().take(live) {
            if let Some(entry) = slot {
                if entry.subid == my_subid {
                    entry.subid = parent_subid;
                }
            }
        }
        self.compact_duplicates();
    }

    /// Removes entries that a later entry with the same `(username, subid)`
    /// supersedes, keeping the chronologically latest one and preserving the
    /// relative order of everything that survives.
    ///
    /// Only same-`subid` duplicates are collapsed. Two entries for one username
    /// at *different* nesting levels must both survive, because aborting the
    /// inner level has to expose the outer decision again.
    fn compact_duplicates(&mut self) {
        let live = self.live();
        let mut write = 0usize;
        for read in 0..live {
            let keep = match &self.entries[read] {
                Some(entry) => {
                    let mut superseded = false;
                    for later in (read + 1)..live {
                        if let Some(other) = &self.entries[later] {
                            if other.subid == entry.subid && other.username == entry.username {
                                superseded = true;
                                break;
                            }
                        }
                    }
                    !superseded
                }
                None => false,
            };
            if keep {
                self.entries[write] = self.entries[read];
                write += 1;
            }
        }
        for slot in self.entries.iter_mut().take(live).skip(write) {
            *slot = None;
        }
        self.len = write;
    }

    /// The decision that would actually be applied for `username`, i.e. the
    /// chronologically latest surviving entry. Mirrors the apply loop exactly.
    ///
    /// Test-only: production code applies entries by iterating, rather than
    /// resolving one username at a time.
    #[cfg(test)]
    fn resolved(&self, username: &[u8; LOCK_USERNAME_BYTES]) -> Option<Option<CacheDecision>> {
        let live = self.live();
        let mut found = None;
        for slot in self.entries.iter().take(live) {
            if let Some(entry) = slot {
                if entry.username == *username {
                    found = Some(entry.decision);
                }
            }
        }
        found
    }
}

static mut PENDING: PendingState = PendingState::new();

static CALLBACKS_REGISTERED: Once = Once::new();

/// Registers the transaction and subtransaction callbacks exactly once.
///
/// Called from `_PG_init`, matching the initialization discipline already used
/// for the shmem and authentication hooks. Registration lives in backend-local
/// memory; when the library is preloaded, the postmaster's registration is
/// inherited by every forked backend.
///
/// # Safety
/// Must be called from `_PG_init`.
pub(crate) unsafe fn register_callbacks() {
    CALLBACKS_REGISTERED.call_once(|| {
        pg_sys::RegisterXactCallback(Some(xact_callback), std::ptr::null_mut());
        pg_sys::RegisterSubXactCallback(Some(subxact_callback), std::ptr::null_mut());
    });
}

/// Stages a cache operation for the current transaction instead of applying it
/// immediately.
///
/// # Capacity exhaustion is a local failure, not a global one
/// Returning `Err` here is enough: the caller propagates it, the surrounding
/// transaction is aborted, and `XACT_EVENT_ABORT` discards every staged entry.
/// A transaction that never committed has not damaged authoritative coverage,
/// so this deliberately does **not** touch `CacheState`. An earlier version
/// marked the shared cache `Overflow` here, which let one oversized transaction
/// refuse every otherwise-successful login cluster-wide until the worker
/// re-hydrated. `CacheState::Overflow` is now reserved for real incomplete
/// coverage: more committed active lockouts than the cache can hold, or a
/// committed insertion that could not fit.
///
/// Nothing is silently dropped: the operation is refused *and* its transaction
/// is refused with it.
pub(crate) fn stage(
    username_bytes: [u8; LOCK_USERNAME_BYTES],
    decision: CacheDecision,
) -> Result<(), Box<dyn std::error::Error>> {
    stage_inner(username_bytes, Some(decision), ExpiryDecision::None)
}

/// Stages an expiry-cache decision without touching the lock cache.
pub(crate) fn stage_expiry(
    username_bytes: [u8; LOCK_USERNAME_BYTES],
    expiry: ExpiryDecision,
) -> Result<(), Box<dyn std::error::Error>> {
    stage_inner(username_bytes, None, expiry)
}

/// Stages lock and expiry cache changes for the same role as one operation.
/// Used by the explicit role rename/remove maintenance helpers.
pub(crate) fn stage_combined(
    username_bytes: [u8; LOCK_USERNAME_BYTES],
    decision: CacheDecision,
    expiry: ExpiryDecision,
) -> Result<(), Box<dyn std::error::Error>> {
    stage_inner(username_bytes, Some(decision), expiry)
}

/// Stages a lock-cache decision together with an expiry-cache decision.
///
/// Both halves ride in one entry, so a rollback discards them together and a
/// savepoint commit re-parents them together.
fn stage_inner(
    username_bytes: [u8; LOCK_USERNAME_BYTES],
    decision: Option<CacheDecision>,
    expiry: ExpiryDecision,
) -> Result<(), Box<dyn std::error::Error>> {
    let subid = unsafe { pg_sys::GetCurrentSubTransactionId() };
    let pending = unsafe { &mut *std::ptr::addr_of_mut!(PENDING) };

    match pending.stage_entry(username_bytes, decision, expiry, subid) {
        Ok(()) => Ok(()),
        Err(StageCapacityExceeded) => Err(format!(
            "password_profile: more than {} pending lock cache operations in one transaction; \
             aborting the transaction rather than dropping a lockout update",
            MAX_PENDING_OPS
        )
        .into()),
    }
}

/// Stages the acknowledgement of an auth-event claim for the current
/// transaction.
///
/// The event is *not* removed here. `tail` advances only from the commit
/// callback, after PostgreSQL has decided the commit, so an abort at any point
/// leaves the same event at the tail for retry.
///
/// Only one claim can be outstanding for the single worker consumer; staging a
/// second one in the same transaction replaces the first, which cannot happen
/// in the current worker but is defined rather than left ambiguous.
pub(crate) fn stage_ack(token: ClaimToken) {
    let subid = unsafe { pg_sys::GetCurrentSubTransactionId() };
    let pending = unsafe { &mut *std::ptr::addr_of_mut!(PENDING) };
    pending.ack = Some(PendingAck { token, subid });
}

/// Applies every staged entry to shared memory, in staging order, so the
/// chronologically latest decision for a username is the one that lands.
///
/// Runs inside the commit callback: no SPI, no allocation, no formatting, no
/// logging, no error raising, and no database or advisory lock is taken. If an
/// insertion cannot fit, `lock_cache::set` records `CacheState::Overflow` under
/// the same LWLock it used for the attempt -- that *is* real incomplete
/// coverage, because the operation was committed.
#[inline]
unsafe fn apply_all() {
    let pending = &*std::ptr::addr_of!(PENDING);
    for slot in pending.entries.iter().take(pending.live()) {
        if let Some(entry) = slot {
            // Lock cache first. `lock_cache::set`/`clear` each take and
            // release LOCK_CACHE_LWLOCK internally, so no cache lock is held
            // when the expiry cache is touched below -- the two are never held
            // simultaneously.
            let _status: CacheOpStatus = match entry.decision {
                None => CacheOpStatus::Applied,
                Some(CacheDecision::SetLock(expires_at)) => {
                    lock_cache::set(&entry.username, expires_at)
                }
                Some(CacheDecision::ClearLock) => lock_cache::clear(&entry.username),
            };

            let _expiry_status: CacheOpStatus = match entry.expiry {
                ExpiryDecision::None => CacheOpStatus::Applied,
                ExpiryDecision::Set {
                    must_change_by,
                    generation,
                    grace_remaining,
                } => expiry_cache::set_entry(
                    &entry.username,
                    must_change_by,
                    generation,
                    grace_remaining,
                ),
                ExpiryDecision::Clear => expiry_cache::clear_entry(&entry.username),
            };
        }
    }
}

/// Transaction-level callback.
///
/// `#[pg_guard]` is the FFI containment for this C-called function; the commit
/// and abort bodies are written so they cannot panic in the first place (fixed
/// arrays, clamped lengths, primitive copies, no allocation).
#[pg_guard]
unsafe extern "C-unwind" fn xact_callback(event: pg_sys::XactEvent::Type, _arg: *mut c_void) {
    match event {
        // Commit is durable and advisory locks are still held: this is the
        // window the whole design depends on.
        pg_sys::XactEvent::XACT_EVENT_COMMIT | pg_sys::XactEvent::XACT_EVENT_PARALLEL_COMMIT => {
            // Strict order, and the two LWLocks are never held together:
            //   1. apply the committed cache operations -- each of
            //      `lock_cache::set`/`clear` takes and *releases* the cache
            //      LWLock internally before returning;
            //   2. therefore no cache LWLock is held here;
            //   3. acknowledge the auth-event claim under the ring LWLock;
            //   4. clear backend-local staging.
            apply_all();

            let pending = &*std::ptr::addr_of!(PENDING);
            if let Some(ack) = pending.ack {
                // `ack_claim` records `QueueState::Corrupt` itself if validation
                // fails. Raising an error here is not an option -- the commit
                // has already happened -- so the primitive state is the report
                // channel and ordinary worker code surfaces it afterwards.
                let _outcome: AckOutcome = auth_event::ack_claim(ack.token);
            }

            (*std::ptr::addr_of_mut!(PENDING)).reset();
        }

        // Rolled back: shared memory must look as if nothing happened, and no
        // staged entry may survive into the next transaction.
        pg_sys::XactEvent::XACT_EVENT_ABORT | pg_sys::XactEvent::XACT_EVENT_PARALLEL_ABORT => {
            (*std::ptr::addr_of_mut!(PENDING)).reset();
        }

        // Two-phase commit, handled by failing closed.
        //
        // Staged operations -- cache updates *and* a staged auth-event
        // acknowledgement -- live in backend-local memory and are NOT carried
        // into the prepared transaction's on-disk state, so they would simply
        // vanish at `COMMIT PREPARED`: a silently lost lockout update, and an
        // event that is either never acknowledged or acknowledged by the wrong
        // backend. Rather than approximate that, refuse the PREPARE.
        // `PendingState::is_empty` counts a staged acknowledgement as pending
        // work, so this covers both.
        //
        // PRE_PREPARE is the correct place to raise: in the 15.19/16.15/17.11/
        // 18.6 sources it is called at the very top of `PrepareTransaction()`
        // (line 42 of the function in 17.11), long before `HOLD_INTERRUPTS()`
        // (line 115), `s->state = TRANS_PREPARE` (line 121) and `EndPrepare()`
        // (line 169). An ERROR raised there therefore propagates normally and
        // PostgreSQL aborts the transaction through `AbortCurrentTransaction()`,
        // which fires `XACT_EVENT_ABORT` and clears the staging area below.
        // (Raising in XACT_EVENT_PREPARE, at line 202, would be too late.)
        // `pgrx::error!` is safe here because this function is `#[pg_guard]`ed.
        pg_sys::XactEvent::XACT_EVENT_PRE_PREPARE => {
            if !(*std::ptr::addr_of!(PENDING)).is_empty() {
                pgrx::error!(
                    "password_profile: PREPARE TRANSACTION is not supported while lock cache \
                     updates are pending; commit or roll back this transaction instead"
                );
            }
        }

        // Reached only if nothing was pending at PRE_PREPARE. A prepared
        // transaction is not committed yet, so never apply here -- just make
        // sure nothing is carried into the next transaction.
        pg_sys::XactEvent::XACT_EVENT_PREPARE => {
            (*std::ptr::addr_of_mut!(PENDING)).reset();
        }

        // PRE_COMMIT / PARALLEL_PRE_COMMIT: nothing to do. The cache is
        // deliberately not touched until the commit is decided.
        _ => {}
    }
}

/// Subtransaction (savepoint) callback.
#[pg_guard]
unsafe extern "C-unwind" fn subxact_callback(
    event: pg_sys::SubXactEvent::Type,
    my_subid: pg_sys::SubTransactionId,
    parent_subid: pg_sys::SubTransactionId,
    _arg: *mut c_void,
) {
    let pending = &mut *std::ptr::addr_of_mut!(PENDING);

    match event {
        pg_sys::SubXactEvent::SUBXACT_EVENT_ABORT_SUB => pending.on_sub_abort(my_subid),
        pg_sys::SubXactEvent::SUBXACT_EVENT_COMMIT_SUB => {
            pending.on_sub_commit(my_subid, parent_subid)
        }
        // START_SUB / PRE_COMMIT_SUB: nothing to do.
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    //! Pure unit tests for the savepoint algebra. These touch no PostgreSQL
    //! state: they drive [`PendingState`] directly with synthetic
    //! subtransaction ids, exactly as the callbacks would.

    use super::*;

    const TOP: pg_sys::SubTransactionId = 1;
    const CHILD: pg_sys::SubTransactionId = 2;
    const GRANDCHILD: pg_sys::SubTransactionId = 3;

    fn user(tag: u8) -> [u8; LOCK_USERNAME_BYTES] {
        let mut buf = [0u8; LOCK_USERNAME_BYTES];
        buf[0] = tag;
        buf
    }

    const T1: pg_sys::TimestampTz = 1_000_000;
    const T2: pg_sys::TimestampTz = 2_000_000;

    #[test]
    fn parent_set_child_clear_child_commit_parent_set() {
        // The sequence that was previously inverted: the re-parented child's
        // ClearLock used to stay later in the array and win.
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.on_sub_commit(CHILD, TOP);
        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T2)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::SetLock(T2))));
    }

    #[test]
    fn parent_set_child_clear_child_abort() {
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.on_sub_abort(CHILD);

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::SetLock(T1))));
    }

    #[test]
    fn parent_set_child_clear_child_commit() {
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.on_sub_commit(CHILD, TOP);

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::ClearLock)));
        // The duplicate was collapsed, freeing capacity.
        assert_eq!(st.live(), 1);
    }

    #[test]
    fn nested_commits_then_parent_clear() {
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T2)),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            GRANDCHILD,
        )
        .unwrap();
        st.on_sub_commit(GRANDCHILD, CHILD);
        st.on_sub_commit(CHILD, TOP);
        st.stage_entry(a, Some(CacheDecision::ClearLock), ExpiryDecision::None, TOP)
            .unwrap();

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::ClearLock)));
        assert_eq!(st.live(), 1);
    }

    #[test]
    fn nested_grandchild_abort_restores_child_decision() {
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T2)),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            GRANDCHILD,
        )
        .unwrap();
        st.on_sub_abort(GRANDCHILD);
        st.on_sub_commit(CHILD, TOP);

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::SetLock(T2))));
    }

    #[test]
    fn usernames_are_independent() {
        let mut st = PendingState::new();
        let a = user(b'a');
        let b = user(b'b');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(b, Some(CacheDecision::ClearLock), ExpiryDecision::None, TOP)
            .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::ClearLock),
            ExpiryDecision::None,
            CHILD,
        )
        .unwrap();
        st.on_sub_abort(CHILD);

        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::SetLock(T1))));
        assert_eq!(st.resolved(&b), Some(Some(CacheDecision::ClearLock)));
    }

    #[test]
    fn same_level_restage_overwrites_in_place() {
        let mut st = PendingState::new();
        let a = user(b'a');

        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.stage_entry(a, Some(CacheDecision::ClearLock), ExpiryDecision::None, TOP)
            .unwrap();
        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T2)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();

        assert_eq!(st.live(), 1);
        assert_eq!(st.resolved(&a), Some(Some(CacheDecision::SetLock(T2))));
    }

    #[test]
    fn capacity_is_bounded_and_refuses_rather_than_dropping() {
        let mut st = PendingState::new();
        for i in 0..MAX_PENDING_OPS {
            st.stage_entry(
                user(i as u8 + 1),
                Some(CacheDecision::ClearLock),
                ExpiryDecision::None,
                TOP,
            )
            .unwrap();
        }
        assert_eq!(st.live(), MAX_PENDING_OPS);
        assert_eq!(
            st.stage_entry(
                user(0xff),
                Some(CacheDecision::ClearLock),
                ExpiryDecision::None,
                TOP
            ),
            Err(StageCapacityExceeded)
        );
        // The refused operation was not stored, and nothing already staged was
        // evicted to make room.
        assert_eq!(st.live(), MAX_PENDING_OPS);
        assert_eq!(st.resolved(&user(0xff)), None);
    }

    #[test]
    fn reset_clears_everything() {
        let mut st = PendingState::new();
        let a = user(b'a');
        st.stage_entry(
            a,
            Some(CacheDecision::SetLock(T1)),
            ExpiryDecision::None,
            TOP,
        )
        .unwrap();
        st.reset();
        assert!(st.is_empty());
        assert_eq!(st.resolved(&a), None);
    }
}
