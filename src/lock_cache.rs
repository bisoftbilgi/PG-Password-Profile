use crate::auth_event;
use crate::sql::{int4_arg, spi_update, text_arg};
use crate::{
    encode_username, LwLockGuard, LwLockMode, LOCK_CACHE_LWLOCK, LOCK_CACHE_SIZE,
    LOCK_USERNAME_BYTES, MICROS_PER_SEC,
};
use pgrx::datum::TimestampWithTimeZone;
use pgrx::pg_sys;
use pgrx::spi::Spi;
use std::error::Error;
use std::ptr;

#[repr(C)]
pub(crate) struct LockEntry {
    pub(crate) username: [u8; LOCK_USERNAME_BYTES],
    pub(crate) expires_at: pg_sys::TimestampTz,
}

impl LockEntry {
    #[allow(dead_code)]
    pub(crate) const fn new() -> Self {
        LockEntry {
            username: [0; LOCK_USERNAME_BYTES],
            expires_at: 0,
        }
    }
}

#[repr(C)]
pub(crate) struct LockCache {
    pub(crate) entries: [LockEntry; LOCK_CACHE_SIZE],
    /// Active lockouts (`lockout_until > now()`) observed in the database by
    /// the most recent **successful** hydration.
    ///
    /// These three counters are a snapshot of the last successful hydration,
    /// not cumulative event counters: every successful hydration overwrites
    /// them, and a failed hydration attempt leaves them untouched.
    pub(crate) hydration_active_total: i64,
    /// Entries the most recent successful hydration installed in the cache.
    pub(crate) hydration_loaded: i64,
    /// Active lockouts the most recent successful hydration could not fit into
    /// the fixed `LOCK_CACHE_SIZE` slots.
    ///
    /// A non-zero value means lockout coverage is incomplete. It is paired with
    /// [`LockCache::state`] = [`CacheState::Overflow`], which temporarily
    /// disables lockout enforcement without blocking PostgreSQL authentication.
    pub(crate) hydration_overflow: i64,
    /// Readiness of the cache, as a raw `i32` so the shared-memory layout does
    /// not depend on Rust enum layout. Always read/written through
    /// [`CacheState`], and only under `LOCK_CACHE_LWLOCK`.
    pub(crate) state: i32,
}

/// Whether the shared cache can currently be trusted to represent every active
/// lockout in the control database.
///
/// `#[repr(i32)]` with explicit discriminants: the value is stored verbatim in
/// shared memory and surfaced numerically through `get_lock_cache_stats()`, so
/// the numbers are part of the operator-visible contract and must not drift.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CacheState {
    /// Initial state after shared-memory creation, and the state after any
    /// failed hydration: coverage is unknown and this feature stays disabled.
    NotReady = 0,
    /// Hydration completed and *every* active database lockout fits in shared
    /// memory. Committed state transitions may be applied and events consumed.
    Ready = 1,
    /// Active lockouts, or pending cache operations, exceeded bounded capacity.
    /// Complete coverage cannot be guaranteed, so this feature stays disabled.
    Overflow = 2,
    /// The background worker stopped after a handled internal or PostgreSQL
    /// failure; new auth events are not being processed reliably.
    WorkerFailed = 3,
}

impl CacheState {
    /// Maps the raw shared-memory `i32` back to a state. An unrecognized value
    /// (torn write, older binary) is treated as [`CacheState::NotReady`] --
    /// the safe direction, since only `Ready` permits enforcement to relax.
    #[inline]
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => CacheState::Ready,
            2 => CacheState::Overflow,
            3 => CacheState::WorkerFailed,
            _ => CacheState::NotReady,
        }
    }
}

/// Result of a single bounded cache mutation.
///
/// `Overflowed` means the operation could not be represented without evicting
/// an active lockout; the cache has been marked [`CacheState::Overflow`] and
/// the caller must treat coverage as incomplete rather than continuing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[must_use]
pub(crate) enum CacheOpStatus {
    Applied,
    Overflowed,
}

/// Reads the current cache state.
///
/// Allocation-free, log-free, and takes only a short shared LWLock. Called on
/// the per-connection authentication path, so it must stay this cheap. An
/// uninitialized cache reads as [`CacheState::NotReady`].
pub(crate) fn state() -> CacheState {
    unsafe {
        if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
            return CacheState::NotReady;
        }
        let cache = &*LOCK_CACHE;
        let raw = {
            let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Shared);
            cache.state
        };
        CacheState::from_raw(raw)
    }
}

/// Changes the cache state under one short exclusive LWLock section.
///
/// Stores a single primitive and does nothing else: no SPI, no allocation, no
/// formatting, no logging, nothing that can `longjmp`. Silently does nothing if
/// shared memory is not initialized -- callers already treat that as
/// [`CacheState::NotReady`].
pub(crate) fn set_state(new_state: CacheState) {
    unsafe {
        if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
            return;
        }
        let cache = &mut *LOCK_CACHE;
        let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Exclusive);
        cache.state = new_state as i32;
    }
}

/// The **one** place that turns an authoritative `lockout_until` into a cache
/// operation.
///
/// Hydration, failed-login processing and successful-login preservation all go
/// through this, so their notion of "active lockout" cannot drift apart. The
/// timestamp is PostgreSQL's own `TimestampTz` throughout: no text, no float
/// epoch, no rounding, and never an expiry later than the database value.
#[inline]
pub(crate) fn decision_for(
    lockout_until: Option<pg_sys::TimestampTz>,
    now: pg_sys::TimestampTz,
) -> CacheDecision {
    match lockout_until {
        Some(expires_at) if expires_at > now => CacheDecision::SetLock(expires_at),
        _ => CacheDecision::ClearLock,
    }
}

/// What the authoritative database state says the cache entry for one username
/// should become.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CacheDecision {
    /// Install/refresh the entry with this exact authoritative expiry.
    SetLock(pg_sys::TimestampTz),
    /// Remove the entry: the database holds no active lockout.
    ClearLock,
}

/// One cache entry fully prepared *outside* the cache LWLock: fixed-size
/// username bytes plus the authoritative `lockout_until` copied verbatim from
/// PostgreSQL's own `TimestampTz` (no text or floating-point round trip).
struct PreparedLockEntry {
    username: [u8; LOCK_USERNAME_BYTES],
    expires_at: pg_sys::TimestampTz,
}

/// Counters describing one successful hydration pass. See
/// [`LockCache::hydration_active_total`] for the "last successful pass"
/// semantics.
pub(crate) struct HydrationStats {
    pub(crate) active_total: i64,
    pub(crate) loaded: i64,
    pub(crate) overflow: i64,
}

pub(crate) static mut LOCK_CACHE: *mut LockCache = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<LockCache>()
}

pub(crate) unsafe fn init() {
    if !LOCK_CACHE.is_null() {
        return;
    }

    let size = std::mem::size_of::<LockCache>();
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_lock_cache".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut LockCache;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize shared lock cache");
    }

    if !found {
        for entry in (*cache_ptr).entries.iter_mut() {
            entry.username = [0; LOCK_USERNAME_BYTES];
            entry.expires_at = 0;
        }
        (*cache_ptr).hydration_active_total = 0;
        (*cache_ptr).hydration_loaded = 0;
        (*cache_ptr).hydration_overflow = 0;
        // A freshly allocated cache is empty and has never been hydrated, so it
        // starts NotReady. Never initialize to Ready: that would open a login
        // enforcement gap for the whole window before the worker hydrates.
        (*cache_ptr).state = CacheState::NotReady as i32;
        pgrx::log!(
            "password_profile: lock cache allocated ({} bytes)",
            std::mem::size_of::<LockCache>()
        );
    } else {
        pgrx::log!("password_profile: lock cache attached to existing segment");
    }

    LOCK_CACHE = cache_ptr;
}

/// Installs or refreshes one lockout entry.
///
/// # Bounded, never evicting an active lockout
/// If every slot is occupied by a *still active* lockout, this refuses to evict
/// one. Evicting would silently drop enforcement for whichever user lost its
/// slot; instead the cache is marked [`CacheState::Overflow`] and
/// [`CacheOpStatus::Overflowed`] is returned, which makes the login hook fail
/// closed and sends the worker back to hydration. Expired slots are still
/// reused freely.
///
/// # Where this runs
/// Only from the transaction commit callback and from hydration-adjacent code.
/// It therefore performs **no logging, allocation, formatting, SPI or error
/// raising** -- the previous version logged on every path, which is not legal
/// inside a commit callback.
///
/// # Safety
/// Must not be called while any cache LWLock is already held.
pub(crate) unsafe fn set(
    username_bytes: &[u8; LOCK_USERNAME_BYTES],
    expires_at: pg_sys::TimestampTz,
) -> CacheOpStatus {
    if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
        // No shared memory to update: coverage is unknown by definition.
        return CacheOpStatus::Overflowed;
    }

    let now = pg_sys::GetCurrentTimestamp();
    if expires_at <= now {
        // Already expired by the time we apply it -- nothing to represent.
        return CacheOpStatus::Applied;
    }
    if username_bytes[0] == 0 {
        return CacheOpStatus::Applied;
    }

    let cache = &mut *LOCK_CACHE;
    let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Exclusive);

    if let Some(entry) = cache
        .entries
        .iter_mut()
        .find(|e| e.username[0] != 0 && e.username == *username_bytes)
    {
        entry.expires_at = expires_at;
        return CacheOpStatus::Applied;
    }

    if let Some(entry) = cache
        .entries
        .iter_mut()
        .find(|e| e.username[0] == 0 || e.expires_at <= now)
    {
        entry.username = *username_bytes;
        entry.expires_at = expires_at;
        return CacheOpStatus::Applied;
    }

    // Every slot holds an active lockout. Do not evict: record the loss of
    // coverage instead. Same lock section, still only a primitive store.
    cache.state = CacheState::Overflow as i32;
    CacheOpStatus::Overflowed
}

/// Removes one lockout entry.
///
/// Takes pre-encoded fixed-size bytes so it can run inside the transaction
/// commit callback: no allocation, no logging, no SPI, no error raising.
///
/// # Safety
/// Must not be called while any cache LWLock is already held.
pub(crate) unsafe fn clear(username_bytes: &[u8; LOCK_USERNAME_BYTES]) -> CacheOpStatus {
    if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
        return CacheOpStatus::Applied;
    }
    let cache = &mut *LOCK_CACHE;

    {
        let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Exclusive);

        for entry in cache.entries.iter_mut() {
            if entry.username[0] != 0 && entry.username == *username_bytes {
                entry.username = [0; LOCK_USERNAME_BYTES];
                entry.expires_at = 0;
                break;
            }
        }
    }

    CacheOpStatus::Applied
}

/// Whole seconds still remaining on a lockout, rounded **up**, or `None` when
/// the lockout is not active.
///
/// # Why ceiling
/// The previous floor division `(expires_at - now) / MICROS_PER_SEC` returned
/// `0` for any lockout with 1..=999_999 microseconds left. Callers filter on
/// `> 0`, so those users were treated as unlocked and could authenticate up to
/// one second early. The authoritative decision is `expires_at > now`; the
/// second count is only what a human is shown, so it is rounded up and floored
/// at 1 to keep the two consistent.
///
/// This never lengthens the cached authoritative `TimestampTz` -- only the
/// human-facing number is rounded upward.
///
/// Overflow-safe: `expires_at` may legitimately be `TIMESTAMPTZ 'infinity'`
/// (`i64::MAX`), so the microseconds are divided before anything is added.
#[inline]
pub(crate) fn remaining_seconds_ceil(
    expires_at: pg_sys::TimestampTz,
    now: pg_sys::TimestampTz,
) -> Option<i64> {
    if expires_at <= now {
        return None;
    }
    // `expires_at > now`, so this subtraction is positive; and because `now` is
    // itself a valid TimestampTz it cannot overflow i64 in the other direction.
    let delta = expires_at - now;
    let whole = delta / MICROS_PER_SEC;
    let secs = if delta % MICROS_PER_SEC != 0 {
        whole.saturating_add(1)
    } else {
        whole
    };
    // Active but sub-second: still locked, reported as one second.
    Some(secs.max(1))
}

pub(crate) unsafe fn remaining_seconds(username: &str) -> Option<i64> {
    if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
        return None;
    }

    // CRITICAL: NO catch_unwind - conflicts with PostgreSQL signal handling!
    // Lock operations are panic-safe via RAII guard
    let encoded = encode_username(username);
    let cache = &*LOCK_CACHE;
    let now = pg_sys::GetCurrentTimestamp();
    let mut expires_at = None;

    {
        let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Shared);

        for entry in cache.entries.iter() {
            if entry.username[0] == 0 {
                continue;
            }
            if entry.username == encoded && entry.expires_at > now {
                expires_at = Some(entry.expires_at);
                break;
            }
        }
    }

    // Conversion happens outside the lock, and `remaining_seconds_ceil` never
    // turns an active lockout into `None`.
    let filtered = expires_at.and_then(|ts| remaining_seconds_ceil(ts, now));
    if filtered.is_none() {
        // This is the normal, expected outcome for every unlocked login and
        // fires on the per-connection hot path, so it stays at DEBUG1
        // (disabled by default) rather than flooding the LOG level.
        pgrx::debug1!(
            "password_profile: lock cache miss for {} (entry expired or not present)",
            username
        );
    }
    filtered
}

/// Reads the authoritative `lockout_until` for one username and derives the
/// cache decision from it.
///
/// This replaces the old `sync()`, which converted the remaining lockout
/// through `ROUND(EXTRACT(EPOCH FROM (lockout_until - now())))` -- text-free but
/// float-based and rounded to whole seconds, so the cached expiry could differ
/// from the authoritative value by up to half a second in either direction.
/// Here the `TIMESTAMPTZ` is carried out as PostgreSQL's own `TimestampTz` and
/// fed to the single [`decision_for`] helper, so hydration, failed-login
/// processing and successful-login preservation cannot drift apart.
///
/// Performs SPI only; it takes no cache LWLock and stages nothing itself.
pub(crate) fn decision_from_db(username: &str) -> Result<CacheDecision, Box<dyn Error>> {
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Err("lock cache decision skipped: no database context".into());
    }

    let lockout_until: Option<pg_sys::TimestampTz> =
        Spi::connect(|client| -> pgrx::spi::Result<Option<pg_sys::TimestampTz>> {
            // A scalar subquery always returns one outer row, so a user with
            // no login-attempt state maps cleanly to `None`.
            let table = client.select(
                "SELECT (SELECT lockout_until
                           FROM password_profile.login_attempts
                          WHERE username = $1)",
                None,
                &[text_arg(username)],
            )?;
            Ok(table
                .first()
                .get_one::<TimestampWithTimeZone>()?
                .map(|ts| ts.into_inner()))
        })?;

    Ok(decision_for(lockout_until, unsafe {
        pg_sys::GetCurrentTimestamp()
    }))
}

/// Rebuilds the shared lock cache from the authoritative
/// `password_profile.login_attempts` table.
///
/// # Where this may be called from
/// Only from inside a `BackgroundWorker::transaction(...)` body, itself wrapped
/// in the worker's PostgreSQL error boundary (`run_hydration_transaction`).
/// The `SHARE` table lock taken below is what keeps the snapshot stable until
/// the prepared entries have been copied into shared memory; it is released by
/// that transaction's commit, i.e. *after* the cache has been replaced, or by
/// the boundary's `AbortCurrentTransaction()` if a PostgreSQL `ERROR` is
/// raised. An `Err` returned from here means the transaction itself ran fine
/// and the cache was left untouched.
///
/// # Staging
/// 1. Read and prepare (SQL, SPI, `String`/`Vec` allocation, ordering done by
///    PostgreSQL) -- no cache LWLock is held here.
/// 2. Replace the cache contents in one short exclusive LWLock section that
///    only clears the fixed slots, copies already prepared fixed-size entries
///    and stores primitive counters.
///
/// The resulting lock order is always
/// `login_attempts table lock -> LOCK_CACHE_LWLOCK`; no SPI, allocation,
/// formatting, logging or error raising happens while the cache LWLock is
/// held. Logging (including the overflow warning) is left to the caller so it
/// happens after both the table lock and the LWLock are gone.
pub(crate) fn hydrate_from_db() -> Result<HydrationStats, Box<dyn Error>> {
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Err("lock cache hydration skipped: no database context".into());
    }

    unsafe {
        if LOCK_CACHE.is_null() || LOCK_CACHE_LWLOCK.is_null() {
            return Err("lock cache hydration skipped: shared cache not initialized".into());
        }
    }

    // ---- Stage 1: read the authoritative rows; no cache LWLock held ----
    let snapshot: Option<(i64, Vec<PreparedLockEntry>)> = Spi::connect_mut(
        |client| -> pgrx::spi::Result<Option<(i64, Vec<PreparedLockEntry>)>> {
            // `to_regclass` returns NULL rather than raising when the extension
            // schema does not exist in this database yet, so "not installed
            // yet" stays a retryable miss instead of a PostgreSQL ERROR.
            let installed = client
                .select(
                    "SELECT to_regclass('password_profile.login_attempts') IS NOT NULL",
                    Some(1),
                    &[],
                )?
                .first()
                .get_one::<bool>()?
                .unwrap_or(false);
            if !installed {
                return Ok(None);
            }

            // SHARE still allows concurrent readers but conflicts with ROW
            // EXCLUSIVE, so no session can INSERT/UPDATE/DELETE
            // `login_attempts` between the count, the bounded read and the
            // cache replacement: all three see one consistent snapshot.
            // Bounded wait: a session holding ACCESS EXCLUSIVE on this table
            // must not park the worker in an unbounded lock wait. The timeout
            // surfaces as an ordinary PostgreSQL ERROR, which the worker's
            // hydration boundary already turns into a retry with backoff.
            spi_update(client, "SET LOCAL lock_timeout = '5s'", &[])?;
            spi_update(
                client,
                "LOCK TABLE password_profile.login_attempts IN SHARE MODE",
                &[],
            )?;

            // An active lockout is defined purely by a future `lockout_until`.
            // `failed_login_max` is deliberately NOT used as a filter: per-user
            // thresholds may differ from the global GUC.
            let active_total = client
                .select(
                    "SELECT count(*)::bigint
                       FROM password_profile.login_attempts
                      WHERE lockout_until IS NOT NULL AND lockout_until > now()",
                    Some(1),
                    &[],
                )?
                .first()
                .get_one::<i64>()?
                .unwrap_or(0);

            // Deterministic bounded selection: furthest expiry first, username
            // as tie-breaker, never more rows than the fixed cache capacity.
            let rows = client.select(
                "SELECT username, lockout_until
                   FROM password_profile.login_attempts
                  WHERE lockout_until IS NOT NULL AND lockout_until > now()
                  ORDER BY lockout_until DESC, username ASC
                  LIMIT $1",
                Some(LOCK_CACHE_SIZE as _),
                &[int4_arg(LOCK_CACHE_SIZE as i32)],
            )?;

            let mut prepared: Vec<PreparedLockEntry> =
                Vec::with_capacity(rows.len().min(LOCK_CACHE_SIZE));
            for row in rows {
                let username = match row.get::<String>(1)? {
                    Some(name) if !name.is_empty() => name,
                    _ => continue,
                };
                // Typed `TimestampTz` straight from the datum: the expiry is
                // carried verbatim, never through locale-sensitive text or a
                // lossy float interval, so hydration can never invent a later
                // lockout than the authoritative database value.
                let expires_at = match row.get::<TimestampWithTimeZone>(2)? {
                    Some(ts) => ts.into_inner(),
                    None => continue,
                };
                prepared.push(PreparedLockEntry {
                    username: encode_username(&username),
                    expires_at,
                });
            }

            Ok(Some((active_total, prepared)))
        },
    )?;

    let (active_total, prepared) = match snapshot {
        Some(snapshot) => snapshot,
        None => {
            return Err(
                "lock cache hydration skipped: password_profile.login_attempts not available"
                    .into(),
            )
        }
    };

    // Overflow is purely capacity-driven: rows the `LIMIT` excluded. Keeping it
    // independent of `loaded` means an entry that merely expired between the
    // read and the apply is not miscounted as an overflow. Overflow is never
    // silent -- it is stored in the hydration statistics and warned about by
    // the worker -- but it is a real gap in coverage, not a fallback.
    let overflow = active_total.saturating_sub(prepared.len() as i64).max(0);

    // ---- Stage 2: replace the cache under one short exclusive section ----
    // The state is decided here and stored in the *same* exclusive section that
    // installs the entries, so the cache is never observable as Ready with a
    // half-written entry set. Only a hydration that fits every active lockout
    // becomes Ready; an overflowed one becomes Overflow and keeps logins
    // failing closed.
    let new_state = if overflow == 0 {
        CacheState::Ready
    } else {
        CacheState::Overflow
    };
    let loaded = unsafe { apply_hydrated_entries(&prepared, active_total, overflow, new_state) };

    Ok(HydrationStats {
        active_total,
        loaded,
        overflow,
    })
}

/// Copies already prepared entries into the shared cache under a single short
/// exclusive LWLock section, replacing whatever the cache held before.
///
/// Everything expensive has already happened by the time this runs: the
/// protected region only zeroes the fixed slots, copies fixed-size entries and
/// stores three primitive counters. It performs no allocation, no formatting,
/// no logging, no SPI and nothing that can `longjmp` past the RAII guard.
///
/// Returns how many entries were actually installed.
///
/// # Safety
/// `LOCK_CACHE` and `LOCK_CACHE_LWLOCK` must both be initialized (the caller
/// checks this).
unsafe fn apply_hydrated_entries(
    prepared: &[PreparedLockEntry],
    active_total: i64,
    overflow: i64,
    new_state: CacheState,
) -> i64 {
    let cache = &mut *LOCK_CACHE;
    // Wall-clock time, not the transaction snapshot's `now()`, so an entry that
    // expired between the read and this apply is dropped instead of installed.
    let now = pg_sys::GetCurrentTimestamp();
    let mut loaded: i64 = 0;

    let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Exclusive);

    // Full replacement, not an append: expired entries, entries no longer
    // active in the database, and anything left over from a previous worker or
    // postmaster lifetime all disappear here.
    for entry in cache.entries.iter_mut() {
        entry.username = [0; LOCK_USERNAME_BYTES];
        entry.expires_at = 0;
    }

    let mut slot = 0usize;
    for prepared_entry in prepared.iter() {
        if slot >= LOCK_CACHE_SIZE {
            break;
        }
        // Same authoritative rule as every other cache write: an entry that
        // expired between the read and this apply produces ClearLock, i.e. it
        // is simply not installed.
        if prepared_entry.username[0] == 0
            || decision_for(Some(prepared_entry.expires_at), now) == CacheDecision::ClearLock
        {
            continue;
        }
        cache.entries[slot].username = prepared_entry.username;
        cache.entries[slot].expires_at = prepared_entry.expires_at;
        slot += 1;
        loaded += 1;
    }

    cache.hydration_active_total = active_total;
    cache.hydration_loaded = loaded;
    cache.hydration_overflow = overflow;
    cache.state = new_state as i32;

    loaded
}

#[cfg(test)]
mod remaining_seconds_tests {
    //! Pure boundary tests: no shared memory, no PostgreSQL.
    use super::remaining_seconds_ceil;
    use crate::MICROS_PER_SEC;

    const NOW: i64 = 1_700_000_000_000_000;

    #[test]
    fn one_microsecond_remaining_is_still_locked() {
        assert_eq!(remaining_seconds_ceil(NOW + 1, NOW), Some(1));
    }

    #[test]
    fn just_under_one_second_is_still_locked() {
        assert_eq!(remaining_seconds_ceil(NOW + 999_999, NOW), Some(1));
    }

    #[test]
    fn exactly_one_second() {
        assert_eq!(remaining_seconds_ceil(NOW + MICROS_PER_SEC, NOW), Some(1));
    }

    #[test]
    fn just_over_one_second_rounds_up() {
        assert_eq!(
            remaining_seconds_ceil(NOW + MICROS_PER_SEC + 1, NOW),
            Some(2)
        );
    }

    #[test]
    fn expired_and_exactly_now_are_not_locked() {
        assert_eq!(remaining_seconds_ceil(NOW, NOW), None);
        assert_eq!(remaining_seconds_ceil(NOW - 1, NOW), None);
    }

    #[test]
    fn infinity_does_not_overflow() {
        assert!(remaining_seconds_ceil(i64::MAX, NOW).unwrap() > 0);
    }
}

/// Rebuilds the shared expiry cache from `password_profile.password_expiry`.
///
/// Same two-stage shape as [`hydrate_from_db`]: read and prepare with SPI under
/// a `SHARE` table lock (no cache LWLock held), then replace the cache in one
/// short exclusive section. Timestamps are carried as PostgreSQL's own
/// `TimestampTz` -- no text, no float epoch -- so `must_change_by` and the
/// `last_changed` generation are exact.
///
/// Only a hydration that fits every row becomes `Ready`; an overflow becomes
/// `Overflow` and keeps expiry enforcement failing closed.
pub(crate) fn hydrate_expiry_from_db() -> Result<(i64, i64, i64), Box<dyn Error>> {
    use crate::expiry_cache::{self, ExpiryCacheState, ExpiryEntry};

    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Err("expiry cache hydration skipped: no database context".into());
    }

    let snapshot: Option<(i64, Vec<ExpiryEntry>)> = Spi::connect_mut(
        |client| -> pgrx::spi::Result<Option<(i64, Vec<ExpiryEntry>)>> {
            let installed = client
                .select(
                    "SELECT to_regclass('password_profile.password_expiry') IS NOT NULL",
                    Some(1),
                    &[],
                )?
                .first()
                .get_one::<bool>()?
                .unwrap_or(false);
            if !installed {
                return Ok(None);
            }

            // Bounded wait: a session holding ACCESS EXCLUSIVE on this table
            // must not park the worker in an unbounded lock wait. The timeout
            // surfaces as an ordinary PostgreSQL ERROR, which the worker's
            // hydration boundary already turns into a retry with backoff.
            spi_update(client, "SET LOCAL lock_timeout = '5s'", &[])?;
            spi_update(
                client,
                "LOCK TABLE password_profile.password_expiry IN SHARE MODE",
                &[],
            )?;

            let total = client
                .select(
                    "SELECT count(*)::bigint FROM password_profile.password_expiry
                      WHERE must_change_by IS NOT NULL AND last_changed IS NOT NULL",
                    Some(1),
                    &[],
                )?
                .first()
                .get_one::<i64>()?
                .unwrap_or(0);

            // Deterministic bounded selection: soonest expiry first, username
            // as tie-breaker, never more rows than the fixed capacity.
            let rows = client.select(
                "SELECT username, must_change_by, last_changed, grace_logins_remaining
                   FROM password_profile.password_expiry
                  WHERE must_change_by IS NOT NULL AND last_changed IS NOT NULL
                  ORDER BY must_change_by ASC, username ASC
                  LIMIT $1",
                Some(crate::EXPIRY_CACHE_SIZE as _),
                &[int4_arg(crate::EXPIRY_CACHE_SIZE as i32)],
            )?;

            let mut prepared: Vec<ExpiryEntry> =
                Vec::with_capacity(rows.len().min(crate::EXPIRY_CACHE_SIZE));
            for row in rows {
                let Some(username) = row.get::<String>(1)?.filter(|u| !u.is_empty()) else {
                    continue;
                };
                let Some(must_change_by) = row.get::<TimestampWithTimeZone>(2)? else {
                    continue;
                };
                let Some(last_changed) = row.get::<TimestampWithTimeZone>(3)? else {
                    continue;
                };
                let grace = row.get::<i32>(4)?.unwrap_or(0);
                prepared.push(expiry_cache::prepared_entry(
                    &username,
                    must_change_by.into_inner(),
                    last_changed.into_inner(),
                    grace,
                ));
            }

            Ok(Some((total, prepared)))
        },
    )?;

    let (rows, prepared) =
        match snapshot {
            Some(v) => v,
            None => return Err(
                "expiry cache hydration skipped: password_profile.password_expiry not available"
                    .into(),
            ),
        };

    let overflow = rows.saturating_sub(prepared.len() as i64).max(0);
    let new_state = if overflow == 0 {
        ExpiryCacheState::Ready
    } else {
        ExpiryCacheState::Overflow
    };

    let loaded = unsafe { expiry_cache::apply_hydrated(&prepared, rows, overflow, new_state) };
    Ok((rows, loaded, overflow))
}

/// Rebuilds the shared bypass-exemption cache from `pg_db_role_setting`.
///
/// Returns `(rows, loaded, overflow)`.
///
/// # What counts as exempt
/// Only database-independent role settings (`ALTER ROLE ... SET`, stored with
/// `setdatabase = 0`) are considered. `ALTER ROLE ... IN DATABASE ... SET` is
/// deliberately *not* honored here: the authentication hook answers before
/// `MyDatabaseId` exists, so a per-database exemption could not be evaluated
/// consistently at the point it would have to take effect.
///
/// `ALTER ROLE ... SET` stores the value verbatim (`GUCArrayAdd` builds
/// `name=value` from the text the user wrote), so the standard boolean
/// spellings PostgreSQL accepts for a `bool` GUC are all matched, not just the
/// literal `true`.
///
/// # Snapshot discipline
/// The whole set is read in one statement inside the caller's transaction, then
/// installed into shared memory in one exclusive section. Nothing is read while
/// the cache lock is held, and no partial set is ever observable: the cache is
/// replaced wholesale, which is what makes `RESET` take effect.
pub(crate) fn refresh_bypass_cache() -> Result<(i64, i64, i64), Box<dyn Error>> {
    use crate::bypass_cache::{self, BypassCacheState};

    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Err("bypass cache refresh skipped: no database context".into());
    }

    // `pg_authid` is superuser-only; the worker connects without a user name,
    // so `InitializeSessionUserIdStandalone` gives it the bootstrap superuser.
    let snapshot: (i64, Vec<[u8; crate::LOCK_USERNAME_BYTES]>) = Spi::connect_mut(
        |client| -> pgrx::spi::Result<_> {
            // Both statements are built from the single predicate constant,
            // so the count and the selection can never disagree about who is
            // exempt. Formatting two short strings once per refresh is
            // negligible next to the query itself, and neither string
            // interpolates any user-supplied value.
            let count_sql = format!("SELECT count(*)::bigint {BYPASS_MATCH_SQL}");
            let select_sql =
                // `pg_authid.rolname` is `name`, not `text`; the cast is
                // required or the row read fails with a datum type mismatch.
                format!("SELECT a.rolname::text {BYPASS_MATCH_SQL} ORDER BY a.rolname ASC LIMIT $1");

            let total = client
                .select(count_sql.as_str(), Some(1), &[])?
                .first()
                .get_one::<i64>()?
                .unwrap_or(0);

            let rows = client.select(
                select_sql.as_str(),
                Some(crate::BYPASS_CACHE_SIZE as _),
                &[int4_arg(crate::BYPASS_CACHE_SIZE as i32)],
            )?;

            let mut prepared: Vec<[u8; crate::LOCK_USERNAME_BYTES]> =
                Vec::with_capacity(rows.len().min(crate::BYPASS_CACHE_SIZE));
            for row in rows {
                let Some(username) = row.get::<String>(1)?.filter(|u| !u.is_empty()) else {
                    continue;
                };
                prepared.push(bypass_cache::prepared_entry(&username));
            }

            Ok((total, prepared))
        },
    )?;

    let (rows, prepared) = snapshot;
    let overflow = rows.saturating_sub(prepared.len() as i64).max(0);
    let new_state = if overflow == 0 {
        BypassCacheState::Ready
    } else {
        BypassCacheState::Overflow
    };

    let loaded = unsafe { bypass_cache::apply_refreshed(&prepared, rows, overflow, new_state) };
    Ok((rows, loaded, overflow))
}

/// The exemption predicate, written once so the count and the selection can
/// never disagree about who is exempt.
const BYPASS_MATCH_SQL: &str = "
    FROM pg_catalog.pg_authid a
    JOIN pg_catalog.pg_db_role_setting s
      ON s.setrole = a.oid AND s.setdatabase = 0
   WHERE EXISTS (
             SELECT 1
               FROM unnest(s.setconfig) AS cfg
              WHERE lower(split_part(cfg, '=', 1))
                    = 'password_profile.bypass_password_profile'
                AND lower(substr(cfg, strpos(cfg, '=') + 1))
                    IN ('true', 'tru', 'tr', 't', 'yes', 'ye', 'y', 'on', '1')
         )";

pub(crate) fn collect_stats() -> Result<Vec<(String, i64, String)>, Box<dyn Error>> {
    let mut stats = Vec::new();

    // Only primitive numeric counters are computed while the lock is held;
    // all Vec/String construction happens afterward (Phase 4: no allocation
    // while protected).
    let cache_counts: Option<(i64, i64, i64, i64, i64, i64)> = unsafe {
        if !LOCK_CACHE.is_null() && !LOCK_CACHE_LWLOCK.is_null() {
            let cache = &*LOCK_CACHE;
            let now = pg_sys::GetCurrentTimestamp();
            let _guard = LwLockGuard::acquire(LOCK_CACHE_LWLOCK, LwLockMode::Shared);

            let active_count = cache
                .entries
                .iter()
                .filter(|e| e.username[0] != 0 && e.expires_at > now)
                .count() as i64;

            let used_count = cache.entries.iter().filter(|e| e.username[0] != 0).count() as i64;

            Some((
                active_count,
                used_count,
                cache.hydration_active_total,
                cache.hydration_loaded,
                cache.hydration_overflow,
                cache.state as i64,
            ))
        } else {
            None
        }
    };

    match cache_counts {
        Some((
            active_count,
            used_count,
            hydration_active_total,
            hydration_loaded,
            hydration_overflow,
            state_raw,
        )) => {
            stats.push((
                "lock_cache_total_size".to_string(),
                LOCK_CACHE_SIZE as i64,
                "Maximum number of lockout entries".to_string(),
            ));

            stats.push((
                "lock_cache_active_lockouts".to_string(),
                active_count,
                "Currently locked accounts (non-expired)".to_string(),
            ));

            stats.push((
                "lock_cache_used_slots".to_string(),
                used_count,
                "Total used cache slots (including expired)".to_string(),
            ));

            stats.push((
                "lock_cache_free_slots".to_string(),
                (LOCK_CACHE_SIZE as i64) - used_count,
                "Available cache slots for new lockouts".to_string(),
            ));

            stats.push((
                "lock_cache_utilization_pct".to_string(),
                (used_count * 100) / (LOCK_CACHE_SIZE as i64),
                "Cache utilization percentage".to_string(),
            ));

            // Snapshot of the most recent *successful* worker hydration, not
            // cumulative counters: each successful hydration overwrites them,
            // and a failed attempt leaves the previous values in place.
            stats.push((
                "lock_cache_hydration_active_total".to_string(),
                hydration_active_total,
                "Active DB lockouts seen by the last successful hydration".to_string(),
            ));

            stats.push((
                "lock_cache_hydration_loaded".to_string(),
                hydration_loaded,
                "Entries loaded into the cache by the last successful hydration".to_string(),
            ));

            stats.push((
                "lock_cache_hydration_overflow".to_string(),
                hydration_overflow,
                "Active DB lockouts that did not fit during the last successful hydration"
                    .to_string(),
            ));

            // Numeric readiness, matching `CacheState`'s explicit
            // discriminants. Only state 1 (Ready) lets the login hook consult
            // the cache; every other value pauses lockout enforcement.
            stats.push((
                "lock_cache_state".to_string(),
                // Normalized the same way the authentication hook reads it, so
                // an unrecognized stored value is reported as 0=NotReady rather
                // than shown as though it were a supported state.
                CacheState::from_raw(state_raw as i32) as i64,
                "Cache readiness (normalized; an unrecognized stored value reports as \
                 0=NotReady): 0=NotReady (never hydrated / hydration failed), \
                 1=Ready (complete coverage, enforcement active), \
                 2=Overflow (capacity exceeded; lockout enforcement paused), \
                 3=WorkerFailed (worker stopped; lockout enforcement paused)"
                    .to_string(),
            ));
        }
        None => {
            stats.push((
                "lock_cache_status".to_string(),
                0,
                "Lock cache not initialized".to_string(),
            ));
            stats.push((
                "lock_cache_state".to_string(),
                CacheState::NotReady as i64,
                "Cache readiness: 0=NotReady (shared memory not initialized)".to_string(),
            ));
        }
    }

    // Worker liveness. Deliberately reported separately from every cache
    // state: a cache reports the entries it holds, not whether anything is
    // still maintaining them. `worker_running = 0` with a `lock_cache_state`
    // of 1 was the exact blind spot that let a terminated worker look healthy,
    // and these rows are the numeric signal that closes it.
    match crate::worker_health::stats() {
        Some(w) => {
            stats.push((
                "worker_running".to_string(),
                w.running,
                "1 when the auth event consumer is initialized, attached to the control \
                 database and running; 0 when it is not, in which case no authentication event \
                 is being applied and lockout/expiry enforcement is paused. PostgreSQL native \
                 authentication is unaffected."
                    .to_string(),
            ));
            stats.push((
                "worker_stop_reason".to_string(),
                w.stop_reason,
                "Why the auth event consumer last stopped: 0=never stopped (never started, or \
                 still running), 1=a shutdown was requested (SIGTERM; also the normal path \
                 during a PostgreSQL shutdown), 2=an unhandled failure was contained at the \
                 worker's error boundary. A stopped worker is deregistered by PostgreSQL and \
                 returns only on the next server start."
                    .to_string(),
            ));
            stats.push((
                "worker_starts_total".to_string(),
                w.starts,
                "Times the worker reached a running state since shared memory was created"
                    .to_string(),
            ));
            stats.push((
                "worker_stops_total".to_string(),
                w.stops,
                "Times the worker stopped since shared memory was created".to_string(),
            ));
            stats.push((
                "auth_event_durable_recording_degraded".to_string(),
                w.durable_degraded,
                "1 when a durable auth-journal append (or the worker's journal reader) last \
                 failed and the caches have not been rehydrated since; lockout and expiry \
                 enforcement are paused while this is 1. It clears only after the failures stop \
                 and the worker completes a fresh hydration -- never merely because storage \
                 looks writable again."
                    .to_string(),
            ));
        }
        None => {
            stats.push((
                "worker_running".to_string(),
                0,
                "Worker health shared memory is not initialized; enforcement is paused".to_string(),
            ));
        }
    }

    if let Ok(Some(total_attempts)) = Spi::get_one::<i64>(
        "SELECT COUNT(*) FROM password_profile.login_attempts WHERE fail_count > 0",
    ) {
        stats.push((
            "db_users_with_failures".to_string(),
            total_attempts,
            "Users with recorded failed attempts".to_string(),
        ));
    }

    if let Ok(Some(active_lockouts)) = Spi::get_one::<i64>(
        "SELECT COUNT(*) FROM password_profile.login_attempts WHERE lockout_until > NOW()",
    ) {
        stats.push((
            "db_active_lockouts".to_string(),
            active_lockouts,
            "Users currently locked (database state)".to_string(),
        ));
    }

    // Expiry cache observability. Primitive counters are copied under one short
    // shared section by `expiry_cache::stats()`; every String below is built
    // after that guard is gone.
    match crate::expiry_cache::stats() {
        Some(x) => {
            stats.push((
                "expiry_cache_state".to_string(),
                x.state,
                "Expiry cache readiness (normalized; an unrecognized stored value reports as \
                 0=NotReady): 0=NotReady (never hydrated / hydration failed), \
                 1=Ready (complete coverage), \
                 2=Overflow (capacity exceeded; login-time expiry paused), \
                 3=WorkerFailed (worker stopped; login-time expiry paused). \
                 Expiry is active only when expiry_enforcement = on AND \
                 password_expiry_days > 0"
                    .to_string(),
            ));
            stats.push((
                "expiry_cache_capacity".to_string(),
                x.capacity,
                "Maximum number of cached password-expiry entries".to_string(),
            ));
            stats.push((
                "expiry_cache_used_entries".to_string(),
                x.used,
                "Expiry entries currently held in the cache".to_string(),
            ));
            stats.push((
                "expiry_cache_free_entries".to_string(),
                x.free,
                "Remaining expiry cache slots".to_string(),
            ));
            stats.push((
                "expiry_cache_hydration_rows".to_string(),
                x.hydration_rows,
                "Expiry rows seen in the database by the last successful hydration".to_string(),
            ));
            stats.push((
                "expiry_cache_hydration_overflow".to_string(),
                x.hydration_overflow,
                "Expiry rows that did not fit during the last hydration (coverage incomplete)"
                    .to_string(),
            ));
        }
        None => {
            stats.push((
                "expiry_cache_state".to_string(),
                crate::expiry_cache::ExpiryCacheState::NotReady as i64,
                "Expiry cache readiness: 0=NotReady (shared memory not initialized)".to_string(),
            ));
        }
    }

    // Auth-event queue observability. `auth_event::stats()` copies primitive
    // counters under one short shared LWLock section and returns a `Copy`
    // struct; every `String` below is built after that guard is gone. No
    // username, event content or password is exposed.
    match auth_event::stats() {
        Some(q) => {
            stats.push((
                "auth_event_queue_capacity".to_string(),
                q.usable_capacity,
                "Auth events the ring can hold (one slot reserved to separate full from empty)"
                    .to_string(),
            ));
            stats.push((
                "auth_event_queue_depth".to_string(),
                q.depth,
                "Auth events currently queued and not yet acknowledged".to_string(),
            ));
            stats.push((
                "auth_event_queue_has_pending".to_string(),
                q.has_pending,
                "1 when the ring holds at least one unacknowledged event, else 0. This is queue \
                 occupancy, not worker claim state: whether the worker has actually claimed the \
                 tail entry is not tracked in shared memory."
                    .to_string(),
            ));
            stats.push((
                "auth_event_queue_accepted_total".to_string(),
                q.accepted,
                "Auth events accepted into the ring since shared memory was created".to_string(),
            ));
            stats.push((
                "auth_event_queue_acknowledged_total".to_string(),
                q.acknowledged,
                "Auth events acknowledged after their database transaction committed".to_string(),
            ));
            stats.push((
                "auth_event_queue_rejected_total".to_string(),
                q.rejected,
                "Auth event attempts not accepted by the RAM ring; compare durable-only and journal-failure counters"
                    .to_string(),
            ));
            stats.push((
                "auth_event_journaled_total".to_string(),
                q.journaled,
                "Auth events durably fsynced before the authentication hook returned".to_string(),
            ));
            stats.push((
                "auth_event_durable_only_total".to_string(),
                q.durable_only,
                "Durable auth events processed without a RAM-ring slot".to_string(),
            ));
            stats.push((
                "auth_event_journal_failures_total".to_string(),
                q.journal_failures,
                "Auth events rejected because their durable journal append failed".to_string(),
            ));
            let journal = crate::auth_journal::stats();
            stats.push((
                "auth_event_journal_pending_records".to_string(),
                journal.pending_records,
                "Complete auth-event records currently awaiting durable journal cleanup"
                    .to_string(),
            ));
            stats.push((
                "auth_event_journal_pending_bytes".to_string(),
                journal.pending_bytes,
                "Bytes currently held by active and processing auth-event journal files"
                    .to_string(),
            ));
            stats.push((
                "auth_event_queue_next_seq".to_string(),
                q.next_seq,
                "Next auth event sequence number to be assigned".to_string(),
            ));
            stats.push((
                "auth_event_queue_state".to_string(),
                q.state,
                "Queue health (normalized; an unrecognized stored value reports as 2=Corrupt): \
                 0=Healthy (accepting events normally), \
                 1=Overflowed (RAM capacity was exceeded; durable events keep draining and the \
                 state returns to Healthy when the ring becomes empty), \
                 2=Corrupt (claim/acknowledge validation or a ring invariant failed)"
                    .to_string(),
            ));
        }
        None => {
            stats.push((
                "auth_event_queue_state".to_string(),
                auth_event::QueueState::Corrupt as i64,
                "Queue health: 2=Corrupt (auth event ring not initialized)".to_string(),
            ));
        }
    }

    match crate::bypass_cache::stats() {
        Some(b) => {
            stats.push((
                "bypass_cache_state".to_string(),
                b.state,
                "Bypass cache readiness (normalized; an unrecognized stored value reports as \
                 0=NotReady): 0=NotReady (never refreshed, or refresh failed), \
                 1=Ready (the exemption set is complete), 2=Overflow (capacity exceeded; \
                 exemptions temporarily unavailable), 3=WorkerFailed (worker stopped). \
                 Only Ready can grant an exemption; every other state applies normal policy."
                    .to_string(),
            ));
            stats.push((
                "bypass_cache_capacity".to_string(),
                b.capacity,
                "Maximum number of exempt roles the cache can hold".to_string(),
            ));
            stats.push((
                "bypass_cache_used_entries".to_string(),
                b.used,
                "Exempt roles currently held in the cache".to_string(),
            ));
            stats.push((
                "bypass_cache_refresh_rows".to_string(),
                b.rows,
                "Exempt roles seen in pg_db_role_setting by the last successful refresh"
                    .to_string(),
            ));
            stats.push((
                "bypass_cache_refresh_overflow".to_string(),
                b.overflow,
                "Exempt roles the last refresh could not fit (non-zero means Overflow)".to_string(),
            ));
        }
        None => {
            stats.push((
                "bypass_cache_state".to_string(),
                crate::bypass_cache::BypassCacheState::NotReady as i64,
                "Bypass cache readiness: 0=NotReady (shared memory not initialized)".to_string(),
            ));
        }
    }

    Ok(stats)
}
