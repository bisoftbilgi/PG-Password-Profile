//! Truthful liveness and durable-recording health for the auth-event worker.
//!
//! # Why this exists
//! Before this module the only shared-memory evidence that login-time
//! enforcement was alive was the *cache state* of each cache. That is not the
//! same question. A cache reaches [`CacheState::Ready`](crate::lock_cache::CacheState::Ready)
//! when the worker hydrates it and stays there until something explicitly
//! changes it -- so a worker that exits cleanly (a direct `SIGTERM` to
//! `password_profile_auth_event_consumer`, which PostgreSQL answers by
//! *deregistering* the worker rather than restarting it) left every cache
//! reporting `Ready` while nothing was applying authentication events any more.
//! Failed logins were journaled and never counted, so three wrong passwords
//! followed by the right one were accepted while `get_lock_cache_stats()` still
//! reported a healthy system.
//!
//! Cache readiness and worker liveness are therefore recorded separately, and
//! the authentication hook requires *both* before it enforces anything.
//!
//! # Why atomics rather than a fifth LWLock
//! Every value here is a single machine word that is written by one process and
//! read by many. There is no multi-field invariant to protect, so an LWLock
//! would buy nothing and would add a lock that the authentication hook has to
//! take on every connection. Atomics also make [`mark_durable_failure`] legal
//! from inside the auth-event enqueue path, which already holds
//! `AUTH_EVENT_LWLOCK` (and sometimes `EXPIRY_CACHE_LWLOCK`): an atomic store
//! allocates nothing, logs nothing, runs no SPI and cannot `longjmp`, so it
//! cannot strand a lock.
//!
//! This struct lives in PostgreSQL-owned shared memory, is created once by the
//! postmaster in `shmem_startup_hook`, and is inherited by every child through
//! `fork`, so all processes address the same words.

use pgrx::pg_sys;
use std::ptr;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};

/// The worker has never run in the lifetime of this shared-memory segment.
pub(crate) const STOP_NEVER: u32 = 0;
/// The worker returned because a shutdown was requested (`SIGTERM`, which is
/// also what a normal fast shutdown sends). Not an incident on its own.
pub(crate) const STOP_SHUTDOWN: u32 = 1;
/// The worker's outermost guard contained a PostgreSQL `ERROR`, a pgrx
/// `ErrorReport` or a Rust panic. Always an incident.
pub(crate) const STOP_CONTAINED: u32 = 2;

/// How long durable recording must have been failure-free before the worker is
/// allowed to rehydrate and re-enable enforcement.
///
/// This is what keeps a persistently broken journal from turning every login
/// into a hydration transaction: while failures keep arriving the recorded
/// timestamp keeps advancing, the quiet period never elapses, and the worker
/// neither rehydrates nor logs. Enforcement resumes one hydration after the
/// storage problem actually stops.
pub(crate) const DURABLE_QUIET_PERIOD_US: i64 = 5_000_000;

/// Minimum spacing between "enforcement paused" warnings, cluster-wide.
///
/// The timestamp is claimed with a compare-and-exchange, so a login storm
/// against a degraded extension produces one line per interval in total, not
/// one per backend.
const WARN_INTERVAL_US: i64 = 60_000_000;

#[repr(C)]
pub(crate) struct WorkerHealth {
    /// 1 only while the worker has completed initialization *and* attached to
    /// the control database, and has not yet begun leaving.
    running: AtomicU32,
    /// One of the `STOP_*` constants above.
    stop_reason: AtomicU32,
    starts: AtomicU64,
    stops: AtomicU64,
    /// `TimestampTz` of the most recent durable-recording failure, or 0 when
    /// durable recording is healthy.
    durable_degraded_us: AtomicI64,
    /// `TimestampTz` of the last emitted "enforcement paused" warning.
    last_warn_us: AtomicI64,
    /// Which [`PausedReason`] that warning was about, so a *different* reason
    /// is reported at once instead of waiting out the previous one's window.
    last_warn_reason: AtomicU32,
}

pub(crate) static mut WORKER_HEALTH: *mut WorkerHealth = ptr::null_mut();

pub(crate) fn shared_memory_bytes() -> usize {
    std::mem::size_of::<WorkerHealth>()
}

/// # Safety
/// Must run from `shmem_startup_hook`, exactly like the caches.
pub(crate) unsafe fn init() {
    if !WORKER_HEALTH.is_null() {
        return;
    }

    let size = std::mem::size_of::<WorkerHealth>();
    let mut found = false;
    let ptr = pg_sys::ShmemInitStruct(
        c"password_profile_worker_health".as_ptr(),
        size,
        &mut found as *mut bool,
    ) as *mut WorkerHealth;

    if ptr.is_null() {
        pgrx::error!("password_profile: failed to initialize shared worker health");
    }

    if !found {
        // A fresh segment has never seen a worker. Never initialize `running`
        // to 1: that would claim enforcement coverage for the whole window
        // before the worker actually starts.
        let health = &*ptr;
        health.running.store(0, Ordering::Relaxed);
        health.stop_reason.store(STOP_NEVER, Ordering::Relaxed);
        health.starts.store(0, Ordering::Relaxed);
        health.stops.store(0, Ordering::Relaxed);
        health.durable_degraded_us.store(0, Ordering::Relaxed);
        health.last_warn_us.store(0, Ordering::Relaxed);
        health.last_warn_reason.store(u32::MAX, Ordering::Relaxed);
        pgrx::log!("password_profile: worker health allocated ({} bytes)", size);
    }

    WORKER_HEALTH = ptr;
}

fn health() -> Option<&'static WorkerHealth> {
    unsafe {
        let ptr = WORKER_HEALTH;
        if ptr.is_null() {
            None
        } else {
            Some(&*ptr)
        }
    }
}

/// Publishes that the worker is initialized and attached to the control
/// database, and is therefore about to maintain the caches.
///
/// Called once, after `attach_signal_handlers` and `connect_worker_to_spi` have
/// both returned. It deliberately does **not** claim that any cache is usable:
/// each cache publishes its own `Ready` only from a completed hydration.
pub(crate) fn mark_running() {
    if let Some(h) = health() {
        h.starts.fetch_add(1, Ordering::Relaxed);
        h.running.store(1, Ordering::Release);
    }
}

/// Publishes that the worker is no longer maintaining anything.
///
/// Called on **every** way out of the worker -- the shutdown return paths and
/// the outermost guard's contained-failure path alike -- before the process
/// leaves. PostgreSQL deregisters a background worker that returns cleanly, so
/// "stopped" means "stopped until the server is restarted".
pub(crate) fn mark_stopped(reason: u32) {
    if let Some(h) = health() {
        h.stop_reason.store(reason, Ordering::Relaxed);
        h.stops.fetch_add(1, Ordering::Relaxed);
        h.running.store(0, Ordering::Release);
    }
}

/// True only while a worker is actually running.
///
/// Read on the per-connection authentication path: one relaxed atomic load, no
/// lock, no allocation.
pub(crate) fn is_running() -> bool {
    health().is_some_and(|h| h.running.load(Ordering::Acquire) == 1)
}

/// Records that an authentication event could not be recorded durably.
///
/// Safe to call while `AUTH_EVENT_LWLOCK` (and `EXPIRY_CACHE_LWLOCK`) are held:
/// a single relaxed store, with the timestamp supplied by the caller so not
/// even an FFI call happens inside the locked section.
pub(crate) fn mark_durable_failure(now: pg_sys::TimestampTz) {
    if let Some(h) = health() {
        // Never store 0 -- that is the "healthy" sentinel.
        h.durable_degraded_us
            .store(if now == 0 { 1 } else { now }, Ordering::Relaxed);
    }
}

/// Same, for callers that hold no lock and have no timestamp at hand.
pub(crate) fn mark_durable_failure_now() {
    mark_durable_failure(unsafe { pg_sys::GetCurrentTimestamp() });
}

/// `Some(timestamp)` while durable recording is untrusted, `None` when healthy.
pub(crate) fn durable_degraded_since() -> Option<i64> {
    match health()?.durable_degraded_us.load(Ordering::Relaxed) {
        0 => None,
        ts => Some(ts),
    }
}

/// Clears the durable-recording failure marker, but only if no newer failure
/// has been recorded since `observed` was read.
///
/// The compare-and-exchange is the whole point: the worker reads the marker,
/// rehydrates every cache the enabled features need, and only then tries to
/// clear it. If a backend recorded a fresh failure during the hydration the
/// exchange fails and enforcement correctly stays paused, so the caches are
/// never announced healthy on the strength of a hydration that a later failure
/// already invalidated.
pub(crate) fn clear_durable_degraded(observed: i64) -> bool {
    health().is_some_and(|h| {
        h.durable_degraded_us
            .compare_exchange(observed, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    })
}

/// Claims the right to emit one "enforcement paused" warning.
///
/// Returns `true` for at most one caller per [`WARN_INTERVAL_US`] *per reason*,
/// across every backend and the worker, so a degraded extension under a login
/// storm cannot flood the log -- while a change of reason (the worker stopped,
/// then the queue went corrupt) is still reported immediately, because that is
/// new information rather than a repeat.
fn claim_warning_slot(now: pg_sys::TimestampTz, reason: u32) -> bool {
    let Some(h) = health() else {
        return false;
    };
    let last = h.last_warn_us.load(Ordering::Relaxed);
    let same_reason = h.last_warn_reason.load(Ordering::Relaxed) == reason;
    if same_reason && last != 0 && now.saturating_sub(last) < WARN_INTERVAL_US {
        return false;
    }
    if h.last_warn_us
        .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return false;
    }
    h.last_warn_reason.store(reason, Ordering::Relaxed);
    true
}

/// Why login-time enforcement is currently paused.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub(crate) enum PausedReason {
    /// No worker is running, so nothing applies authentication events.
    WorkerNotRunning,
    /// The auth-event queue is structurally corrupt.
    QueueCorrupt,
    /// A durable journal append failed, so cached coverage cannot be trusted.
    DurableRecording,
}

/// Emits the rate-controlled degraded-state `WARNING`.
///
/// # Call-site discipline
/// This allocates and formats, so it must only be called from ordinary hook or
/// worker code after **every** LWLock the caller held has been released. Every
/// call site in this extension is a single exit point that satisfies that.
///
/// Contains state names, numeric counters and a pointer to the monitoring
/// function only -- never a username, never a password, never event content.
pub(crate) fn warn_enforcement_paused(reason: PausedReason) {
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    if !claim_warning_slot(now, reason as u32) {
        return;
    }

    let (what, recovery) = match reason {
        PausedReason::WorkerNotRunning => (
            "the auth event consumer is not running, so no authentication event is being applied",
            "restart PostgreSQL to start a new worker (PostgreSQL deregisters a background \
             worker that has exited, so it does not come back on its own)",
        ),
        PausedReason::QueueCorrupt => (
            "the auth event queue is structurally corrupt",
            "inspect password_profile.get_lock_cache_stats(); preserve \
             <PGDATA>/password_profile_auth_events.* as evidence; then set \
             password_profile.lockout_enforcement=off and \
             password_profile.expiry_enforcement=off, reload, and call \
             password_profile.recover_auth_event_queue()",
        ),
        PausedReason::DurableRecording => (
            "a durable auth journal append failed, so cached lockout and expiry coverage can no \
             longer be trusted",
            "fix the storage problem under <PGDATA>; the worker rehydrates the caches from the \
             authoritative tables and resumes enforcement on its own once appends stop failing",
        ),
    };

    pgrx::warning!(
        "password_profile: login-time lockout and expiry enforcement are PAUSED because {}. \
         PostgreSQL native authentication is unaffected and still decides every login, so wrong \
         passwords are still rejected; this extension is simply not adding brute-force lockout \
         or password-expiry enforcement until it recovers. To restore protection: {}. Numeric \
         state is in password_profile.get_lock_cache_stats() (worker_running, \
         worker_stop_reason, auth_event_queue_state, auth_event_durable_recording_degraded, \
         lock_cache_state, expiry_cache_state).",
        what,
        recovery
    );
}

/// Primitive worker-health counters for the DBA statistics surface.
#[derive(Copy, Clone, Debug)]
pub(crate) struct WorkerHealthStats {
    pub(crate) running: i64,
    pub(crate) stop_reason: i64,
    pub(crate) starts: i64,
    pub(crate) stops: i64,
    pub(crate) durable_degraded: i64,
}

pub(crate) fn stats() -> Option<WorkerHealthStats> {
    let h = health()?;
    Some(WorkerHealthStats {
        running: i64::from(h.running.load(Ordering::Acquire)),
        stop_reason: i64::from(h.stop_reason.load(Ordering::Relaxed)),
        starts: h.starts.load(Ordering::Relaxed).min(i64::MAX as u64) as i64,
        stops: h.stops.load(Ordering::Relaxed).min(i64::MAX as u64) as i64,
        durable_degraded: i64::from(h.durable_degraded_us.load(Ordering::Relaxed) != 0),
    })
}
