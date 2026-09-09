//! Shared-memory cache of roles exempted by
//! `password_profile.bypass_password_profile`.
//!
//! # Why this is a cache and not a catalog lookup
//! The documented meaning of `bypass_password_profile = true` is that the role
//! is exempt from validation, history, expiry **and lockout** checks. The first
//! three are enforced from ordinary SQL functions, which can read the catalog
//! directly. The last two are enforced from `ClientAuthentication_hook`, which
//! cannot.
//!
//! The setting is stored by `ALTER ROLE ... SET` in `pg_db_role_setting`, and
//! that catalog cannot be read from this hook:
//!
//! * There is **no syscache** for it. `MAKE_SYSCACHE` appears in
//!   `src/include/catalog/pg_authid.h` (`AUTHNAME`, `AUTHOID`) but not once in
//!   `src/include/catalog/pg_db_role_setting.h`, in PostgreSQL 15.19, 16.15,
//!   17.11 or 18.6. The `SearchSysCache1(AUTHNAME, ...)` trick the shim already
//!   uses for user-existence has no equivalent here.
//! * It is not a nailed relation either. `RelationCacheInitializePhase2()`
//!   (`src/backend/utils/cache/relcache.c`) builds descriptors for exactly five
//!   critical shared catalogs -- `pg_database`, `pg_authid`, `pg_auth_members`,
//!   `pg_shseclabel`, `pg_subscription` (`NUM_CRITICAL_SHARED_RELS 5`).
//!   `pg_db_role_setting` is not among them, so opening it would have to build
//!   a relcache entry by scanning `pg_class` -- and at
//!   `PerformAuthentication()` time `MyDatabaseId` is still `InvalidOid`
//!   (`src/backend/utils/init/postinit.c` sets it well after the
//!   `PerformAuthentication(MyProcPort)` call).
//!
//! So the exemption is projected into shared memory by the background worker,
//! exactly like lockouts and expiry, and the hook answers from shared memory
//! only.
//!
//! # Refresh
//! `ALTER ROLE ... SET/RESET` on a global object emits no invalidation this
//! extension can subscribe to: there is no syscache to register a callback on
//! (`CacheRegisterSyscacheCallback` needs a cache id), and event triggers do not
//! fire for role-level commands. The worker therefore re-reads the exemption set
//! on a short fixed interval, inside its own read-committed transaction, so a
//! `SET` or `RESET` converges without a server restart and without any catalog
//! access in the hook. See [`crate::worker`].
//!
//! # Lock discipline
//! One dedicated LWLock, never nested with any other. Every critical section is
//! a bounded, allocation-free run of fixed-size comparisons. Nothing here logs,
//! allocates, formats, raises, sleeps or calls SPI while the lock is held.

use crate::{
    encode_username, LwLockGuard, LwLockMode, BYPASS_CACHE_LWLOCK, BYPASS_CACHE_SIZE,
    LOCK_USERNAME_BYTES,
};
use pgrx::pg_sys;
use std::ptr;

/// Readiness of the bypass cache, mirroring the other two state machines.
///
/// `#[repr(i32)]` with explicit discriminants: the raw value lives in shared
/// memory and is reported numerically by `get_lock_cache_stats()`.
#[repr(i32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum BypassCacheState {
    /// Never hydrated, or hydration failed.
    NotReady = 0,
    /// Hydrated and complete: every exempt role is represented.
    Ready = 1,
    /// More exempt roles exist than the cache can hold, so a role's absence no
    /// longer proves it is not exempt.
    Overflow = 2,
    /// The worker stopped after a failure it could not recover from.
    WorkerFailed = 3,
}

impl BypassCacheState {
    /// Unknown raw values map to `NotReady` -- the safe direction, since only
    /// `Ready` lets the hook trust the answer.
    #[inline]
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => BypassCacheState::Ready,
            2 => BypassCacheState::Overflow,
            3 => BypassCacheState::WorkerFailed,
            _ => BypassCacheState::NotReady,
        }
    }
}

/// What the cache says about one role.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum BypassDecision {
    /// The role is exempt: skip lockout, expiry and auth-event processing.
    Bypassed,
    /// The role is not exempt: enforce normally.
    NotBypassed,
    /// The cache cannot answer. The caller applies the normal policy instead
    /// of turning an exemption-cache problem into a connection outage.
    Unavailable,
}

#[repr(C)]
pub(crate) struct BypassCache {
    /// Encoded usernames; `[0] == 0` marks a free slot.
    pub(crate) entries: [[u8; LOCK_USERNAME_BYTES]; BYPASS_CACHE_SIZE],
    /// Raw [`BypassCacheState`].
    pub(crate) state: i32,
    /// Exempt roles seen by the last successful refresh.
    pub(crate) rows: i64,
    /// Exempt roles the last refresh could not fit.
    pub(crate) overflow: i64,
}

pub(crate) static mut BYPASS_CACHE: *mut BypassCache = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<BypassCache>()
}

/// # Safety
/// Must be called from `shmem_startup_hook`, after the named LWLock tranche has
/// been initialized.
pub(crate) unsafe fn init() {
    if !BYPASS_CACHE.is_null() {
        return;
    }

    let size = std::mem::size_of::<BypassCache>();
    let mut found = false;
    let cache_ptr = pg_sys::ShmemInitStruct(
        c"password_profile_bypass_cache".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut BypassCache;

    if cache_ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize shared bypass cache");
    }

    if !found {
        for entry in (*cache_ptr).entries.iter_mut() {
            *entry = [0; LOCK_USERNAME_BYTES];
        }
        (*cache_ptr).rows = 0;
        (*cache_ptr).overflow = 0;
        // Never start Ready: an un-hydrated cache knows nothing about
        // exemptions, and "not listed" would wrongly read as "not exempt".
        (*cache_ptr).state = BypassCacheState::NotReady as i32;
        pgrx::log!(
            "password_profile: bypass cache allocated ({} bytes, capacity {})",
            size,
            BYPASS_CACHE_SIZE
        );
    } else {
        pgrx::log!("password_profile: bypass cache attached to existing segment");
    }

    BYPASS_CACHE = cache_ptr;
}

/// Current cache state. Short shared-lock read, allocation-free.
pub(crate) fn state() -> BypassCacheState {
    unsafe {
        if BYPASS_CACHE.is_null() || BYPASS_CACHE_LWLOCK.is_null() {
            return BypassCacheState::NotReady;
        }
        let cache = &*BYPASS_CACHE;
        let raw = {
            let _guard = LwLockGuard::acquire(BYPASS_CACHE_LWLOCK, LwLockMode::Shared);
            cache.state
        };
        BypassCacheState::from_raw(raw)
    }
}

/// Stores a state under a short exclusive section. One primitive write.
pub(crate) fn set_state(new_state: BypassCacheState) {
    unsafe {
        if BYPASS_CACHE.is_null() || BYPASS_CACHE_LWLOCK.is_null() {
            return;
        }
        let cache = &mut *BYPASS_CACHE;
        let _guard = LwLockGuard::acquire(BYPASS_CACHE_LWLOCK, LwLockMode::Exclusive);
        cache.state = new_state as i32;
    }
}

/// Answers the exemption question for `username`.
///
/// Returns a primitive three-way result. Takes only this cache's own LWLock and
/// must be called while no other LWLock is held.
pub(crate) fn lookup(username: &str) -> BypassDecision {
    unsafe {
        if BYPASS_CACHE.is_null() || BYPASS_CACHE_LWLOCK.is_null() {
            return BypassDecision::Unavailable;
        }
        let encoded = encode_username(username);
        if encoded[0] == 0 {
            // A username this cache cannot represent cannot be proven exempt.
            return BypassDecision::Unavailable;
        }
        let cache = &*BYPASS_CACHE;

        let _guard = LwLockGuard::acquire(BYPASS_CACHE_LWLOCK, LwLockMode::Shared);

        if BypassCacheState::from_raw(cache.state) != BypassCacheState::Ready {
            return BypassDecision::Unavailable;
        }

        for entry in cache.entries.iter() {
            if entry[0] != 0 && *entry == encoded {
                return BypassDecision::Bypassed;
            }
        }
        BypassDecision::NotBypassed
    }
}

/// Replaces the whole cache from a refresh snapshot in one exclusive section.
///
/// Returns how many entries were installed. Everything expensive (SQL,
/// allocation, encoding) happened before this call.
///
/// # Safety
/// Caller must ensure shared memory is initialized and no other cache LWLock is
/// held.
pub(crate) unsafe fn apply_refreshed(
    prepared: &[[u8; LOCK_USERNAME_BYTES]],
    rows: i64,
    overflow: i64,
    new_state: BypassCacheState,
) -> i64 {
    if BYPASS_CACHE.is_null() || BYPASS_CACHE_LWLOCK.is_null() {
        return 0;
    }
    let cache = &mut *BYPASS_CACHE;
    let mut loaded: i64 = 0;

    let _guard = LwLockGuard::acquire(BYPASS_CACHE_LWLOCK, LwLockMode::Exclusive);

    // Full replacement: a role whose setting was RESET disappears here, which
    // is what makes `RESET` take effect.
    for entry in cache.entries.iter_mut() {
        *entry = [0; LOCK_USERNAME_BYTES];
    }

    let mut slot = 0usize;
    for prepared_entry in prepared.iter() {
        if slot >= BYPASS_CACHE_SIZE {
            break;
        }
        if prepared_entry[0] == 0 {
            continue;
        }
        cache.entries[slot] = *prepared_entry;
        slot += 1;
        loaded += 1;
    }

    cache.rows = rows;
    cache.overflow = overflow;
    cache.state = new_state as i32;

    loaded
}

/// Primitive counters copied under one short shared section. All `String`
/// construction happens in the caller.
#[derive(Copy, Clone, Debug)]
pub(crate) struct BypassStats {
    pub(crate) capacity: i64,
    pub(crate) used: i64,
    pub(crate) rows: i64,
    pub(crate) overflow: i64,
    pub(crate) state: i64,
}

pub(crate) fn stats() -> Option<BypassStats> {
    unsafe {
        if BYPASS_CACHE.is_null() || BYPASS_CACHE_LWLOCK.is_null() {
            return None;
        }
        let cache = &*BYPASS_CACHE;
        let _guard = LwLockGuard::acquire(BYPASS_CACHE_LWLOCK, LwLockMode::Shared);
        let used = cache.entries.iter().filter(|e| e[0] != 0).count() as i64;
        Some(BypassStats {
            capacity: BYPASS_CACHE_SIZE as i64,
            used,
            rows: cache.rows,
            overflow: cache.overflow,
            // Normalized: an unrecognized stored value reports as NotReady.
            state: BypassCacheState::from_raw(cache.state) as i64,
        })
    }
}

/// Encodes one role name outside any lock. Used by the worker's refresh.
pub(crate) fn prepared_entry(username: &str) -> [u8; LOCK_USERNAME_BYTES] {
    encode_username(username)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_raw_state_maps_to_not_ready() {
        assert_eq!(BypassCacheState::from_raw(0), BypassCacheState::NotReady);
        assert_eq!(BypassCacheState::from_raw(1), BypassCacheState::Ready);
        assert_eq!(BypassCacheState::from_raw(2), BypassCacheState::Overflow);
        assert_eq!(
            BypassCacheState::from_raw(3),
            BypassCacheState::WorkerFailed
        );
        assert_eq!(BypassCacheState::from_raw(-1), BypassCacheState::NotReady);
        assert_eq!(BypassCacheState::from_raw(99), BypassCacheState::NotReady);
    }

    #[test]
    fn prepared_entries_are_fixed_size_and_nul_padded() {
        let e = prepared_entry("maint");
        assert_eq!(&e[..5], b"maint");
        assert!(e[5..].iter().all(|&b| b == 0));
    }
}
