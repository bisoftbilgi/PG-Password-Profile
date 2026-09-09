use crate::auth_event;
use crate::auth_event::{ClaimToken, EventFlags, EventKind, QueueState};
use crate::auth_journal::{self, JournalReader};
use crate::bypass_cache::{self, BypassCacheState};
use crate::clear_login_attempts_internal;
use crate::expiry_cache::{self, ExpiryCacheState};
use crate::lock_cache;
use crate::lock_cache::CacheState;
use crate::pending_cache_op;
use crate::record_failed_login;
use crate::sql::bytea_arg;
use crate::worker_health;
use pgrx::bgworkers::{BackgroundWorker, SignalWakeFlags};
use pgrx::pg_sys;
use pgrx::pg_sys::elog::PgLogLevel;
use pgrx::pg_sys::errcodes::PgSqlErrorCode;
use pgrx::pg_sys::panic::CaughtError;
use pgrx::pg_sys::pg_try::PgTryBuilder;
use std::time::{Duration, Instant};

fn insert_event_receipt(event_id: &[u8; 16]) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(pgrx::Spi::get_one_with_args::<bool>(
        "WITH inserted AS ( \
             INSERT INTO password_profile.auth_event_receipts (event_id) VALUES ($1) \
             ON CONFLICT (event_id) DO NOTHING RETURNING 1 \
         ) SELECT EXISTS (SELECT 1 FROM inserted)",
        &[bytea_arg(event_id)],
    )?
    .unwrap_or(false))
}

/// First backoff step between hydration attempts.
const HYDRATION_RETRY_MIN: Duration = Duration::from_millis(500);
/// Upper bound for the hydration backoff, so a long outage costs one wakeup
/// every 30s instead of a busy loop.
const HYDRATION_RETRY_MAX: Duration = Duration::from_secs(30);
/// Warn on the first failure and then only every Nth one, so a persistent
/// failure cannot flood the log.
const HYDRATION_WARN_EVERY: u32 = 10;
/// How often the exemption set is re-read from `pg_db_role_setting`.
///
/// `ALTER ROLE ... SET/RESET` on a role is a shared-object command: it fires no
/// event trigger, and `pg_db_role_setting` has no syscache to register an
/// invalidation callback on (see `bypass_cache`). Convergence is therefore
/// bounded by this interval rather than being event-driven, which is why it is
/// short. The refresh is one small read-committed transaction.
const BYPASS_REFRESH_INTERVAL: Duration = Duration::from_millis(1000);

/// Bound on how long any worker transaction waits for a heavyweight lock.
///
/// Hydration takes `LOCK TABLE ... IN SHARE MODE` and event processing updates
/// `login_attempts`, so a session holding `ACCESS EXCLUSIVE` on either table
/// would otherwise park the worker in an unbounded lock wait: no busy loop and
/// no log flood, but also no progress and no diagnosis. With a timeout the wait
/// ends as an ordinary, already-handled PostgreSQL `ERROR` -- the transaction is
/// rolled back, the durable event stays pending and is retried under the
/// existing bounded backoff, so nothing is dropped.
const WORKER_LOCK_TIMEOUT: &str = "SET LOCAL lock_timeout = '5s'";

/// Applies [`WORKER_LOCK_TIMEOUT`] to the transaction that is already open.
///
/// `SET LOCAL` is reverted by the surrounding commit or abort, so it cannot
/// leak into another transaction or into any other backend.
fn apply_worker_lock_timeout() -> Result<(), Box<dyn std::error::Error>> {
    pgrx::Spi::run(WORKER_LOCK_TIMEOUT)?;
    Ok(())
}

/// Which shared caches a unit of worker work is allowed to mark unavailable.
///
/// The worker must never degrade a cache an event does not touch. Marking the
/// expiry cache `WorkerFailed` because an unrelated failed-login event could
/// not commit destroys real state -- and restoring `Ready` afterwards would
/// then claim a coverage guarantee that was never re-established.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct AffectedCaches {
    lock: bool,
    expiry: bool,
}

impl AffectedCaches {
    /// What one event actually writes.
    ///
    /// A failure or success event touches `login_attempts` and the lock cache
    /// only. A grace event always touches the expiry state, and touches
    /// `login_attempts` only when the login was admitted with lockout
    /// enforcement on -- which is recorded in the event's own flags, not read
    /// from the current GUC.
    fn for_event(kind: EventKind, flags: EventFlags) -> Self {
        match kind {
            EventKind::Failure | EventKind::Success => AffectedCaches {
                lock: true,
                expiry: false,
            },
            EventKind::GraceConsumed => AffectedCaches {
                lock: flags.clear_login_attempts(),
                expiry: true,
            },
        }
    }
}

/// Which caches *this retry sequence* moved from `Ready` to `WorkerFailed`.
///
/// Only these may be restored to `Ready` on a later success. A cache that was
/// already `Overflow` or `NotReady` is never overwritten and never "restored",
/// because nothing here re-established its coverage.
#[derive(Copy, Clone, Default)]
struct DegradedByRetry {
    lock: bool,
    expiry: bool,
}

impl DegradedByRetry {
    /// Marks only the affected, currently healthy caches unavailable.
    ///
    /// The `== Ready` test is what prevents an existing `Overflow` or
    /// `NotReady` from being overwritten with `WorkerFailed`: those states
    /// carry information this failure did not produce and cannot repair.
    fn mark(&mut self, affects: AffectedCaches) {
        if affects.lock && !self.lock && lock_cache::state() == CacheState::Ready {
            lock_cache::set_state(CacheState::WorkerFailed);
            self.lock = true;
        }
        if affects.expiry && !self.expiry && expiry_cache::state() == ExpiryCacheState::Ready {
            expiry_cache::set_state(ExpiryCacheState::WorkerFailed);
            self.expiry = true;
        }
    }

    /// Restores `Ready` for exactly the caches this sequence degraded, and only
    /// if they are still in the `WorkerFailed` state this sequence put them in.
    ///
    /// If something else has since recorded `Overflow` (a committed insertion
    /// that did not fit), that state is left alone and reported, because it
    /// describes incomplete coverage that a successful event commit does not
    /// repair.
    fn restore(&mut self) -> bool {
        let mut still_incomplete = false;
        if self.lock {
            match lock_cache::state() {
                CacheState::WorkerFailed => lock_cache::set_state(CacheState::Ready),
                CacheState::Ready => {}
                _ => still_incomplete = true,
            }
            self.lock = false;
        }
        if self.expiry {
            match expiry_cache::state() {
                ExpiryCacheState::WorkerFailed => expiry_cache::set_state(ExpiryCacheState::Ready),
                ExpiryCacheState::Ready => {}
                _ => still_incomplete = true,
            }
            self.expiry = false;
        }
        still_incomplete
    }
}

/// Why one hydration attempt failed.
///
/// The two variants correspond to the two *recoverable* ways a hydration
/// attempt can end. A genuine Rust panic is deliberately **not** represented
/// here: it is rethrown rather than turned into a retry (see
/// [`run_hydration_transaction`]).
enum HydrationFailure {
    /// [`lock_cache::hydrate_from_db`] returned `Err`. The transaction ran and
    /// ended normally; this is a "not ready yet" answer (no database context,
    /// shared memory not initialized, schema not installed, SPI-level failure).
    Reported(Box<dyn std::error::Error>),
    /// A PostgreSQL `ERROR` was raised while starting, running, or committing
    /// the hydration transaction, and has since been rolled back. Carries only
    /// the SQLSTATE, which is `Copy` -- nothing is allocated in the catch
    /// handler.
    PostgresError(PgSqlErrorCode),
}

/// Runs exactly one hydration transaction behind a PostgreSQL-aware error
/// boundary, so that a recoverable PostgreSQL `ERROR` becomes a retryable
/// failure instead of unwinding out of the worker.
///
/// # Why the boundary is needed
/// `BackgroundWorker::transaction` (pgrx 0.16.1, `src/bgworkers.rs`) is:
///
/// ```text
/// SetCurrentStatementStartTimestamp(); StartTransactionCommand();
/// PushActiveSnapshot(GetTransactionSnapshot());
/// let result = PgTryBuilder::new(body).execute();   // <-- no catch handler
/// PopActiveSnapshot(); CommitTransactionCommand();
/// ```
///
/// `PgTryBuilder::execute` with no registered handler ends in
/// `root_cause.rethrow()`, so a PostgreSQL `ERROR` raised by `SPI_execute`, the
/// `LOCK TABLE`, a relation race, a query cancellation, or by
/// `StartTransactionCommand`/`CommitTransactionCommand` themselves is *rethrown*
/// rather than returned as `Err` -- and `PopActiveSnapshot` /
/// `CommitTransactionCommand` are skipped, leaving an un-aborted transaction.
///
/// Such an `ERROR` is catchable in Rust because pgrx protects **every**
/// bindgen-generated Postgres function with `pg_guard_ffi_boundary`
/// (`pgrx-pg-sys/src/submodules/ffi.rs`), whose `siglongjmp` path ends in
/// `panic_any(CaughtError::PostgresError(..))`. This function therefore catches
/// *outside* `BackgroundWorker::transaction`, restores a valid non-transaction
/// state, and hands the outer loop a small classification.
///
/// # Handler discipline
/// The catch handler runs before `PgTryBuilder::execute` calls
/// `FlushErrorState()` -- the same order PostgreSQL's own background-worker
/// recovery paths use (abort, then flush). It therefore does no logging, no
/// allocation, no SPI, no sleeping and takes no LWLock; it copies a `Copy`
/// SQLSTATE, aborts the transaction, and returns.
fn run_hydration_transaction() -> Result<lock_cache::HydrationStats, HydrationFailure> {
    PgTryBuilder::new(|| {
        BackgroundWorker::transaction(lock_cache::hydrate_from_db)
            .map_err(HydrationFailure::Reported)
    })
    // NOTE: `execute()` dispatches `others` *before* `rust`, so registering
    // `catch_rust_panic` in addition would be dead code -- the Rust-panic case
    // is handled by the fall-through arm below instead.
    .catch_others(|caught| match caught {
        // A PostgreSQL ERROR that pgrx trapped at the FFI boundary. Recoverable:
        // roll the transaction back and let the caller retry.
        CaughtError::PostgresError(ref report) if report.level() == PgLogLevel::ERROR => {
            let sqlerrcode = report.sql_error_code();

            // Called unconditionally and *not* guarded by `IsTransactionState()`:
            // that predicate is true only for `TRANS_INPROGRESS`, so it would
            // skip cleanup after an error raised during transaction start or
            // commit. `AbortCurrentTransaction()` carries the correct guard
            // internally (`TBLOCK_DEFAULT` + `TRANS_DEFAULT` is a no-op, and
            // `TRANS_START` is handled explicitly); it is exactly what
            // PostgreSQL's own `PostgresMain` error path calls.
            //
            // Its `AbortTransaction()`/`CleanupTransaction()` own the rest of
            // the cleanup -- snapshot stack (`AtEOXact_Snapshot`), portals,
            // resource owner, held LWLocks (`LWLockReleaseAll`) and the
            // `login_attempts` SHARE lock -- so no snapshot is popped by hand
            // here.
            unsafe {
                pg_sys::AbortCurrentTransaction();
            }

            Err(HydrationFailure::PostgresError(sqlerrcode))
        }

        // Everything else is rethrown, never downgraded into a retry:
        //   * `CaughtError::RustPanic` -- a genuine Rust bug, not a transient
        //     database condition; swallowing it would spin the retry loop
        //     forever on a deterministic failure.
        //   * `CaughtError::ErrorReport` -- a pgrx-generated Rust error
        //     (`pgrx::error!`); hydration never raises one, so it is a bug too.
        //   * Any report whose level is not `ERROR` -- FATAL and PANIC must not
        //     be caught or downgraded. (PostgreSQL does not `siglongjmp` for
        //     those, so they cannot reach here anyway; the check makes that
        //     explicit and keeps it true if that ever changes.)
        other => other.rethrow(),
    })
    .execute()
}

/// Rebuilds every shared cache from the authoritative tables, retrying with a
/// latch-aware bounded backoff until the caches the *enabled* features need are
/// complete, or the worker is asked to shut down.
///
/// Returns `true` when the worker may start consuming authentication events and
/// `false` when a shutdown was requested first. The auth-event queue is never
/// touched from here, so nothing is consumed before hydration.
///
/// # Independent switches
/// Every cache is always hydrated, so enabling a feature later finds its cache
/// already warm. Only the caches an enabled feature actually consults can
/// *block*:
///
/// | `lockout_enforcement` | `expiry_enforcement` | blocking requirement |
/// |---|---|---|
/// | on  | on  | lock cache and expiry cache |
/// | on  | off | lock cache only |
/// | off | on  | expiry cache only |
/// | off | off | neither |
///
/// The bypass cache is hydrated whenever either switch is on. If it is not
/// ready, the hook grants no exemptions and applies normal policy.
///
/// An earlier revision blocked unconditionally on the lock cache. With
/// `lockout_enforcement = off` and a lock cache that could not be hydrated, the
/// worker never reached the event loop, so grace events were never persisted
/// even though expiry enforcement was on and healthy. The symmetric defect on
/// the expiry side had the same effect on lockout events.
fn hydrate_caches_with_retry() -> bool {
    let mut retry_delay = HYDRATION_RETRY_MIN;
    let mut failures: u32 = 0;

    loop {
        // Read *before* the hydration transactions run, so a failure recorded
        // while they were running invalidates this attempt's clearance rather
        // than being erased by it. `clear_durable_degradation_if_quiet` does the
        // comparison with a compare-and-exchange.
        let degraded_since = worker_health::durable_degraded_since();

        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down (before hydration)");
            return false;
        }

        if BackgroundWorker::sighup_received() {
            unsafe {
                pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP);
            }
            pgrx::log!("password_profile: auth event consumer reloaded config (SIGHUP)");
        }

        // Read once per attempt, after the config file has been processed, so a
        // SIGHUP that enables a feature is honored on this very iteration.
        let need_lock = crate::lockout_enforcement_enabled();
        let need_expiry = crate::expiry_login_enforcement_active();
        let need_bypass = need_lock || need_expiry;

        // Every cache is hydrated on every attempt regardless of the switches:
        // hydration is what lets a later SIGHUP enable a feature without a
        // restart. All logging happens after each transaction has ended and
        // therefore outside every lock, snapshot and error-handling context.
        let lock_ok = hydrate_lock_cache_once(&mut failures, retry_delay);
        let expiry_ok = hydrate_expiry_cache_once(&mut failures, retry_delay);
        let bypass_ok = refresh_bypass_cache_once(&mut failures, retry_delay);

        if (!need_lock || lock_ok) && (!need_expiry || expiry_ok) && (!need_bypass || bypass_ok) {
            // Every cache an enabled feature consults has just been rebuilt
            // from the authoritative tables, so this is the only moment at
            // which a durable-recording degradation may be cleared. Doing it
            // here -- never in the hook, never on a bare "the journal works
            // again" observation -- is what guarantees enforcement is never
            // announced healthy before a successful hydration.
            clear_durable_degradation_if_quiet(degraded_since);
            return true;
        }

        // Latch-aware wait: honoring `wait_latch`'s return value is what lets a
        // SIGTERM received while we are still waiting for the database stop the
        // worker instead of spinning.
        if !BackgroundWorker::wait_latch(Some(retry_delay)) {
            pgrx::log!("password_profile: auth event consumer shutting down (during hydration)");
            return false;
        }
        retry_delay = (retry_delay * 2).min(HYDRATION_RETRY_MAX);
    }
}

/// Handles one journal I/O failure: pause enforcement truthfully, warn at a
/// bounded rate, and wait out a bounded exponential backoff.
///
/// # Why this is not a plain warn-and-retry
/// The three journal I/O sites used to warn unconditionally and retry every
/// 500 ms. A journal path that stays unusable -- the case Task 3 calls "worker
/// unable to read or rotate the journal" -- therefore produced two identical
/// WARNING lines per second for as long as the incident lasted (65 lines in 32
/// seconds in the first verification run), which buries the one message an
/// operator actually needs and can itself fill the log filesystem that the
/// journal lives on.
///
/// Now the delay grows to the same 30 s ceiling every other retry in this
/// worker uses, and only the first failure and every tenth after it are
/// logged. `wait_latch` still returns immediately on SIGTERM, so shutdown stays
/// prompt no matter how long the backoff has grown.
///
/// Returns `false` when a shutdown was observed while waiting.
fn handle_journal_io_failure(failures: &mut u32, what: &str, error: &std::io::Error) -> bool {
    // The worker cannot drain durable events, so cached coverage is no longer
    // provable. Pause enforcement truthfully instead of letting the caches keep
    // claiming Ready.
    worker_health::mark_durable_failure_now();

    *failures = failures.saturating_add(1);
    let delay = event_failure_backoff(*failures);
    if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
        pgrx::warning!(
            "password_profile: durable auth journal {} failed {} time(s), retrying in {} ms: {}. \
             Lockout and expiry enforcement are paused while the journal cannot be drained; \
             PostgreSQL native authentication is unaffected.",
            what,
            *failures,
            delay.as_millis(),
            error
        );
    }

    if !BackgroundWorker::wait_latch(Some(delay)) {
        pgrx::log!("password_profile: auth event consumer shutting down (journal backoff)");
        return false;
    }

    // Re-stamp after the wait. The backoff grows to 30 s, which is far longer
    // than the quiet period that allows enforcement to resume; without this the
    // marker set before the wait would already look "quiet" the instant the
    // wait ended, and the worker would rehydrate and announce healthy
    // enforcement in the one iteration between two failures of an incident that
    // never actually stopped. Stamping here keeps the marker young for as long
    // as this loop keeps failing.
    worker_health::mark_durable_failure_now();
    true
}

/// Re-enables durable recording after a journal failure, but only when the
/// failure has stopped and the caches have just been rehydrated.
///
/// Two conditions, both required:
///
/// * **quiet period** -- at least [`worker_health::DURABLE_QUIET_PERIOD_US`]
///   has passed since the last recorded failure. While storage keeps failing,
///   each new failure pushes the marker forward, so this never fires: no
///   hydration churn and no log flood for as long as the incident lasts.
/// * **compare-and-exchange** -- the marker is cleared only if it still holds
///   the value read before the hydration ran. A failure that arrived during the
///   hydration therefore keeps enforcement paused instead of being erased by a
///   snapshot that predates it.
fn clear_durable_degradation_if_quiet(observed: Option<i64>) {
    let Some(since) = observed else {
        return;
    };
    let now = unsafe { pg_sys::GetCurrentTimestamp() };
    if now.saturating_sub(since) < worker_health::DURABLE_QUIET_PERIOD_US {
        return;
    }
    if worker_health::clear_durable_degraded(since) {
        pgrx::log!(
            "password_profile: durable auth-event recording has been failure-free for {} ms and \
             every required cache has been rehydrated from the authoritative tables; lockout and \
             expiry enforcement are active again",
            worker_health::DURABLE_QUIET_PERIOD_US / 1000
        );
    }
}

/// One lock-cache hydration attempt. Returns `true` when the cache is complete.
fn hydrate_lock_cache_once(failures: &mut u32, retry_delay: Duration) -> bool {
    match run_hydration_transaction() {
        Ok(stats) if stats.overflow == 0 => {
            // `hydrate_from_db` already stored `CacheState::Ready` in the same
            // exclusive section that installed the entries, so the cache was
            // never observable as Ready with a partial entry set.
            pgrx::log!(
                "password_profile: lock cache hydrated and ready (active={}, loaded={}, \
                 overflow=0)",
                stats.active_total,
                stats.loaded
            );
            true
        }
        Ok(stats) => {
            // Capacity pressure disables only lockout enforcement. The worker
            // must still drain auth events so a cache limit cannot turn into a
            // cluster-wide connection outage.
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                // Counts only -- never a username.
                pgrx::warning!(
                    "password_profile: active lockouts exceed lock cache capacity (active={}, \
                     loaded={}, overflow={}, capacity={}); lockout enforcement is temporarily \
                     disabled, PostgreSQL native authentication remains available, and a server \
                     restart rechecks capacity after the active lockouts are reduced.",
                    stats.active_total,
                    stats.loaded,
                    stats.overflow,
                    crate::LOCK_CACHE_SIZE
                );
            }
            true
        }
        Err(failure) => {
            // Coverage is unknown. Leave/force the cache unavailable so the
            // login hook keeps failing closed, and never touch the queue.
            lock_cache::set_state(CacheState::NotReady);
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                warn_hydration_failure("lock cache", &failure, retry_delay);
            }
            false
        }
    }
}

/// One expiry-cache hydration attempt. Returns `true` when the cache is
/// complete.
fn hydrate_expiry_cache_once(failures: &mut u32, retry_delay: Duration) -> bool {
    match run_expiry_hydration_transaction() {
        Ok((rows, loaded, 0)) => {
            pgrx::log!(
                "password_profile: expiry cache hydrated and ready (rows={}, loaded={}, \
                 overflow=0)",
                rows,
                loaded
            );
            true
        }
        Ok((rows, loaded, overflow)) => {
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                pgrx::warning!(
                    "password_profile: expiry rows exceed expiry cache capacity (rows={}, \
                     loaded={}, overflow={}); login-time expiry enforcement is temporarily \
                     disabled while PostgreSQL native authentication and the worker remain \
                     available; currently configured active={} (switch={}, \
                     password_expiry_days={}).",
                    rows,
                    loaded,
                    overflow,
                    crate::expiry_login_enforcement_active(),
                    crate::expiry_enforcement_switch_on(),
                    crate::password_expiry_days()
                );
            }
            true
        }
        Err(failure) => {
            expiry_cache::set_state(ExpiryCacheState::NotReady);
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                warn_hydration_failure("expiry cache", &failure, retry_delay);
            }
            false
        }
    }
}

/// One bypass-exemption refresh. Returns `true` when the set is complete.
fn refresh_bypass_cache_once(failures: &mut u32, retry_delay: Duration) -> bool {
    match run_bypass_refresh_transaction() {
        Ok((rows, _loaded, 0)) => {
            pgrx::log!(
                "password_profile: bypass cache refreshed and ready (exempt_roles={})",
                rows
            );
            true
        }
        Ok((rows, loaded, overflow)) => {
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                pgrx::warning!(
                    "password_profile: exempt roles exceed bypass cache capacity (rows={}, \
                     loaded={}, overflow={}, capacity={}); uncached roles are treated as not \
                     exempt and PostgreSQL native authentication remains available.",
                    rows,
                    loaded,
                    overflow,
                    crate::BYPASS_CACHE_SIZE
                );
            }
            true
        }
        Err(failure) => {
            bypass_cache::set_state(BypassCacheState::NotReady);
            *failures = failures.saturating_add(1);
            if *failures == 1 || *failures % HYDRATION_WARN_EVERY == 0 {
                warn_hydration_failure("bypass cache", &failure, retry_delay);
            }
            false
        }
    }
}

/// One place that renders a hydration failure, so the three callers cannot
/// drift apart. Runs outside every transaction and every lock.
fn warn_hydration_failure(what: &str, failure: &HydrationFailure, retry_delay: Duration) {
    match failure {
        HydrationFailure::Reported(e) => pgrx::warning!(
            "password_profile: {} hydration failed, retrying in {} ms: {}",
            what,
            retry_delay.as_millis(),
            e
        ),
        HydrationFailure::PostgresError(sqlerrcode) => pgrx::warning!(
            "password_profile: {} hydration hit a PostgreSQL error ({:?}); the transaction was \
             rolled back, retrying in {} ms",
            what,
            sqlerrcode,
            retry_delay.as_millis()
        ),
    }
}

/// Outcome of one event-processing transaction.
///
/// Deliberately small: the PostgreSQL catch handler that produces
/// `PostgresError` may not allocate, so that variant carries only a `Copy`
/// SQLSTATE.
enum EventTxnOutcome {
    /// The body returned `Ok` and the transaction was committed. The commit
    /// callback has applied the staged cache operation.
    Committed,
    /// The body returned `Err`; the transaction was explicitly aborted, so the
    /// database change and the staged cache operation were both discarded.
    RolledBack(String),
    /// A PostgreSQL `ERROR` escaped the body; the transaction was aborted.
    PostgresError(PgSqlErrorCode),
}

/// Runs one auth event inside a transaction whose failure semantics are
/// actually correct.
///
/// # Why `BackgroundWorker::transaction` cannot be used here
/// In pgrx 0.16.1 (`src/bgworkers.rs`) it is:
///
/// ```text
/// StartTransactionCommand(); PushActiveSnapshot(GetTransactionSnapshot());
/// let result = PgTryBuilder::new(body).execute();
/// PopActiveSnapshot(); CommitTransactionCommand();
/// result
/// ```
///
/// `CommitTransactionCommand()` runs unconditionally, so a body that returns a
/// plain Rust `Err` is still **committed**. For an auth event that is a real
/// correctness hole: `record_failed_login` can commit its `login_attempts`
/// change and then fail at `pending_cache_op::stage`, committing the database
/// row while no cache operation was staged -- leaving the cache `Ready` but no
/// longer describing the database.
///
/// This function therefore drives the transaction itself so that `Err` takes
/// the abort path. `AbortCurrentTransaction()` fires `XACT_EVENT_ABORT` (see
/// `AbortTransaction()` in xact.c, which calls `CallXactCallbacks(
/// XACT_EVENT_ABORT)` before its `ResourceOwnerRelease` sequence), and that
/// callback discards every staged entry. No snapshot is popped by hand on the
/// abort path: `AbortTransaction`/`CleanupTransaction` own the snapshot stack.
fn run_event_transaction(
    event_id: &[u8; 16],
    username: &str,
    kind: EventKind,
    flags: EventFlags,
    generation: pgrx::pg_sys::TimestampTz,
    token: Option<ClaimToken>,
) -> EventTxnOutcome {
    PgTryBuilder::new(|| {
        unsafe {
            pg_sys::SetCurrentStatementStartTimestamp();
            pg_sys::StartTransactionCommand();
            pg_sys::PushActiveSnapshot(pg_sys::GetTransactionSnapshot());
        }

        // Cleanup intent comes from the event's own flags, never from the
        // current GUC. `password_profile.lockout_enforcement` is
        // `PGC_SIGHUP`-settable, so it can change while an event waits in the
        // queue; applying an event with semantics it was not created with would
        // either clear failed-login state for a login admitted while lockout
        // enforcement was off, or skip cleanup for one admitted while it was on.
        let body: Result<(), Box<dyn std::error::Error>> = apply_worker_lock_timeout()
            .and_then(|()| insert_event_receipt(event_id))
            .and_then(|is_new| {
                if !is_new {
                    // This exact journal record committed before a worker or
                    // postmaster crash. Its database effect must not run twice.
                    return Ok(());
                }
                match kind {
                    EventKind::Failure => record_failed_login(username).map(|_| ()),
                    EventKind::Success => {
                        if flags.clear_login_attempts() {
                            clear_login_attempts_internal(username, false)
                        } else {
                            Ok(())
                        }
                    }
                    EventKind::GraceConsumed => {
                        // Persist the decrement first; a grace login is also a
                        // successful login, so cleanup belongs to this same
                        // transaction.
                        crate::persist_grace_consumption(username, generation).and_then(|_| {
                            if flags.clear_login_attempts() {
                                clear_login_attempts_internal(username, false)
                            } else {
                                Ok(())
                            }
                        })
                    }
                }
            });

        // Stage the acknowledgement inside the transaction. It is applied by
        // the commit callback and discarded by the abort callback, so the event
        // is removed if and only if this transaction's database work commits.
        if body.is_ok() {
            if let Some(token) = token {
                pending_cache_op::stage_ack(token);
            }
        }

        match body {
            Ok(()) => {
                unsafe {
                    pg_sys::PopActiveSnapshot();
                    pg_sys::CommitTransactionCommand();
                }
                EventTxnOutcome::Committed
            }
            Err(e) => {
                // Force a real rollback. Formatting the message here is safe:
                // PostgreSQL's error state is not set on this path, and we are
                // not inside a catch handler or a commit callback.
                let detail = e.to_string();
                unsafe {
                    pg_sys::AbortCurrentTransaction();
                }
                EventTxnOutcome::RolledBack(detail)
            }
        }
    })
    .catch_others(|caught| {
        let (level, sqlerrcode) = match &caught {
            CaughtError::PostgresError(report)
            | CaughtError::ErrorReport(report)
            | CaughtError::RustPanic {
                ereport: report, ..
            } => (report.level(), report.sql_error_code()),
        };

        // FATAL/PANIC are never caught or downgraded to recoverable ERROR
        // handling. PostgreSQL does not siglongjmp for them, so this is
        // unreachable in practice; the check keeps the guarantee enforced.
        if level != PgLogLevel::ERROR {
            caught.rethrow();
        }

        // Minimum safe cleanup only: copy a Copy SQLSTATE and roll back. No
        // logging, no allocation, no SPI, no cache LWLock -- this runs before
        // PgTryBuilder calls FlushErrorState().
        unsafe {
            pg_sys::AbortCurrentTransaction();
        }

        EventTxnOutcome::PostgresError(sqlerrcode)
    })
    .execute()
}

/// Runs one expiry-cache hydration behind the same PostgreSQL error boundary as
/// the lock-cache hydration, so a recoverable `ERROR` becomes a retryable
/// failure rather than unwinding out of the worker.
fn run_expiry_hydration_transaction() -> Result<(i64, i64, i64), HydrationFailure> {
    PgTryBuilder::new(|| {
        BackgroundWorker::transaction(lock_cache::hydrate_expiry_from_db)
            .map_err(HydrationFailure::Reported)
    })
    .catch_others(|caught| {
        let (level, sqlerrcode) = match &caught {
            CaughtError::PostgresError(report)
            | CaughtError::ErrorReport(report)
            | CaughtError::RustPanic {
                ereport: report, ..
            } => (report.level(), report.sql_error_code()),
        };
        if level != PgLogLevel::ERROR {
            caught.rethrow();
        }
        unsafe {
            pg_sys::AbortCurrentTransaction();
        }
        Err(HydrationFailure::PostgresError(sqlerrcode))
    })
    .execute()
}

/// Runs one bypass-exemption refresh behind the same PostgreSQL error boundary
/// as the two hydrations, so a recoverable `ERROR` becomes a retryable failure
/// rather than unwinding out of the worker.
fn run_bypass_refresh_transaction() -> Result<(i64, i64, i64), HydrationFailure> {
    PgTryBuilder::new(|| {
        BackgroundWorker::transaction(lock_cache::refresh_bypass_cache)
            .map_err(HydrationFailure::Reported)
    })
    .catch_others(|caught| {
        let (level, sqlerrcode) = match &caught {
            CaughtError::PostgresError(report)
            | CaughtError::ErrorReport(report)
            | CaughtError::RustPanic {
                ereport: report, ..
            } => (report.level(), report.sql_error_code()),
        };
        if level != PgLogLevel::ERROR {
            caught.rethrow();
        }
        unsafe {
            pg_sys::AbortCurrentTransaction();
        }
        Err(HydrationFailure::PostgresError(sqlerrcode))
    })
    .execute()
}

/// Why the event-consumption loop stopped.
enum ConsumeOutcome {
    /// SIGTERM (or postmaster death) observed -- stop the worker.
    Shutdown,
    /// The cache left `Ready` (runtime overflow while applying a committed
    /// operation). Stop consuming and go back to hydration/reconciliation.
    NeedsRehydration,
    /// The auth-event queue is structurally corrupt: acknowledgement failed
    /// validation or an entry could not be decoded. Hydration cannot repair
    /// this, so the worker stays suspended and enforcement stays paused until an
    /// administrator recovers the queue.
    QueueUnhealthy(QueueState),
}

/// Replays durable authentication events while required caches stay usable and
/// the RAM queue is not structurally corrupt.
///
/// # Replay/retry loop
/// A failed transaction leaves `pending_event` unchanged, so the next
/// iteration retries the identical durable record. The receipt row and state
/// change commit together; replay after a crash therefore skips an already
/// applied effect instead of counting it twice.
///
/// Never entered before a complete hydration, so no event is processed against
/// an incomplete cache.
fn consume_events() -> ConsumeOutcome {
    let mut event_failures: u32 = 0;
    // Which caches *this* retry sequence degraded, so only those are restored.
    let mut degraded = DegradedByRetry::default();
    // Exemptions are re-read on a fixed interval; see BYPASS_REFRESH_INTERVAL.
    let mut last_bypass_refresh = Instant::now();
    let mut batch: Option<(std::path::PathBuf, JournalReader)> = None;
    let mut pending_event: Option<auth_event::SharedAuthEvent> = None;
    // Consecutive journal I/O failures, driving both the bounded backoff and
    // the log rate control in `handle_journal_io_failure`. Reset by any journal
    // operation that succeeds, so an isolated hiccup never inherits an earlier
    // incident's delay.
    let mut journal_io_failures: u32 = 0;

    loop {
        // `sigterm_received()` and `wait_latch()`'s return value both consume
        // the same one-shot SIGTERM flag, so a shutdown can only be observed
        // once by whichever check runs first. Checked at the top of every
        // iteration -- including between a failed attempt and its retry -- so a
        // SIGTERM before commit can never acknowledge the claimed event.
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down");
            return ConsumeOutcome::Shutdown;
        }

        // SIGHUP aldıysak (pg_reload_conf() veya kill -HUP) GUC'ları yeniden yükle.
        // Bu sayede failed_login_max gibi ayarlar restart gerektirmeden geçer.
        if BackgroundWorker::sighup_received() {
            unsafe {
                pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP);
            }
            pgrx::log!("password_profile: auth event consumer reloaded config (SIGHUP)");
        }

        // Overflow is drainable; only structural corruption suspends the
        // worker.
        let queue_state = auth_event::state();
        if queue_state == QueueState::Corrupt {
            return ConsumeOutcome::QueueUnhealthy(queue_state);
        }

        // Re-read the switches every iteration, *after* SIGHUP processing, so
        // enabling a feature takes effect here rather than leaving the worker
        // in a mode it entered while that feature was off.
        let need_lock = crate::lockout_enforcement_enabled();
        let need_expiry = crate::expiry_login_enforcement_active();
        let need_bypass = need_lock || need_expiry;

        // A cache that has not hydrated, or whose worker update failed, is
        // retried. Capacity overflow is deliberately non-blocking: the hook
        // disables that feature and the worker keeps draining.
        if need_lock
            && matches!(
                lock_cache::state(),
                CacheState::NotReady | CacheState::WorkerFailed
            )
            && !(degraded.lock && lock_cache::state() == CacheState::WorkerFailed)
        {
            pgrx::warning!(
                "password_profile: lock cache is no longer complete; suspending auth event \
                 consumption and returning to hydration. Lockout enforcement stays temporarily \
                 disabled while PostgreSQL native authentication remains available."
            );
            return ConsumeOutcome::NeedsRehydration;
        }
        if need_expiry
            && matches!(
                expiry_cache::state(),
                ExpiryCacheState::NotReady | ExpiryCacheState::WorkerFailed
            )
            && !(degraded.expiry && expiry_cache::state() == ExpiryCacheState::WorkerFailed)
        {
            pgrx::warning!(
                "password_profile: expiry cache is no longer complete; suspending auth event \
                 consumption and returning to hydration. Login-time expiry enforcement stays \
                 temporarily disabled while PostgreSQL native authentication remains available."
            );
            return ConsumeOutcome::NeedsRehydration;
        }
        if need_bypass
            && matches!(
                bypass_cache::state(),
                BypassCacheState::NotReady | BypassCacheState::WorkerFailed
            )
        {
            pgrx::warning!(
                "password_profile: bypass cache is no longer complete; suspending auth event \
                 consumption and returning to hydration. Roles are treated as not exempt while \
                 PostgreSQL native authentication remains available."
            );
            return ConsumeOutcome::NeedsRehydration;
        }

        // A durable-recording failure pauses enforcement cluster-wide, and only
        // a fresh hydration may lift that. Go back to hydration once the
        // failures have actually stopped for the quiet period.
        //
        // While storage keeps failing the marker keeps advancing -- backends
        // re-stamp it on every failed append and `handle_journal_io_failure`
        // re-stamps it after every backoff wait -- so this never fires during
        // an ongoing incident. That is what keeps a broken journal from turning
        // every login into a hydration transaction.
        if let Some(since) = worker_health::durable_degraded_since() {
            let now = unsafe { pg_sys::GetCurrentTimestamp() };
            if now.saturating_sub(since) >= worker_health::DURABLE_QUIET_PERIOD_US {
                return ConsumeOutcome::NeedsRehydration;
            }
        }

        // Exemption refresh. `ALTER ROLE ... SET/RESET` emits no invalidation
        // this extension can subscribe to, so the set is re-read on a fixed
        // interval. Deliberately between transactions -- never mid-event and
        // never while a claim is outstanding -- and it touches only the bypass
        // cache, so it can never disturb a retry sequence's recorded state.
        if last_bypass_refresh.elapsed() >= BYPASS_REFRESH_INTERVAL {
            last_bypass_refresh = Instant::now();
            if let Err(failure) = run_bypass_refresh_transaction() {
                // An exemption set we cannot prove current is not trusted;
                // normal policy applies until refresh succeeds.
                bypass_cache::set_state(BypassCacheState::NotReady);
                warn_hydration_failure("bypass cache", &failure, BYPASS_REFRESH_INTERVAL);
                if need_bypass {
                    return ConsumeOutcome::NeedsRehydration;
                }
            }
        }

        if batch.is_none() {
            match auth_event::rotate_journal() {
                Ok(Some(path)) => match JournalReader::open(&path) {
                    Ok(reader) => {
                        journal_io_failures = 0;
                        batch = Some((path, reader));
                    }
                    Err(auth_journal::JournalError::Corrupt(reason)) => {
                        pgrx::warning!(
                            "password_profile: durable auth journal is corrupt: {}",
                            reason
                        );
                        auth_event::mark_corrupt();
                        return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
                    }
                    Err(auth_journal::JournalError::Io(e)) => {
                        if !handle_journal_io_failure(&mut journal_io_failures, "open", &e) {
                            return ConsumeOutcome::Shutdown;
                        }
                        continue;
                    }
                },
                Ok(None) => {
                    if !BackgroundWorker::wait_latch(Some(Duration::from_millis(25))) {
                        pgrx::log!(
                            "password_profile: auth event consumer shutting down (idle wait)"
                        );
                        return ConsumeOutcome::Shutdown;
                    }
                    continue;
                }
                Err(auth_journal::JournalError::Corrupt(reason)) => {
                    pgrx::warning!(
                        "password_profile: durable auth journal is corrupt: {}",
                        reason
                    );
                    auth_event::mark_corrupt();
                    return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
                }
                Err(auth_journal::JournalError::Io(e)) => {
                    if !handle_journal_io_failure(&mut journal_io_failures, "rotation", &e) {
                        return ConsumeOutcome::Shutdown;
                    }
                    continue;
                }
            }
        }

        if pending_event.is_none() {
            let next = batch
                .as_mut()
                .expect("journal batch is present")
                .1
                .next_event();
            match next {
                Ok(Some(event)) => {
                    journal_io_failures = 0;
                    pending_event = Some(event);
                }
                Ok(None) => {
                    let (path, _) = batch.take().expect("journal batch is present");
                    match auth_journal::remove_processing(&path) {
                        Ok(()) => {
                            journal_io_failures = 0;
                            // No processing file remains, so every receipt now
                            // belongs to a durably deleted batch.
                            let cleanup = BackgroundWorker::transaction(|| {
                                pgrx::Spi::run("DELETE FROM password_profile.auth_event_receipts")
                            });
                            if let Err(e) = cleanup {
                                pgrx::warning!(
                                    "password_profile: processed auth-event receipts could not be cleaned: {}",
                                    e
                                );
                            }
                        }
                        Err(auth_journal::JournalError::Io(e)) => {
                            if !handle_journal_io_failure(&mut journal_io_failures, "cleanup", &e) {
                                return ConsumeOutcome::Shutdown;
                            }
                        }
                        Err(e) => {
                            pgrx::warning!(
                                "password_profile: processed auth journal could not be removed: {}",
                                e
                            );
                            if !BackgroundWorker::wait_latch(Some(HYDRATION_RETRY_MIN)) {
                                return ConsumeOutcome::Shutdown;
                            }
                        }
                    }
                    continue;
                }
                Err(auth_journal::JournalError::Corrupt(reason)) => {
                    pgrx::warning!(
                        "password_profile: durable auth journal is corrupt: {}",
                        reason
                    );
                    auth_event::mark_corrupt();
                    return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
                }
                Err(auth_journal::JournalError::Io(e)) => {
                    if !handle_journal_io_failure(&mut journal_io_failures, "read", &e) {
                        return ConsumeOutcome::Shutdown;
                    }
                    continue;
                }
            }
        }

        let event = pending_event.expect("pending journal event is present");
        let token = auth_event::matching_claim(&event.event_id);

        // NOTE: check_for_interrupts!() must NOT be called here (outside a transaction /
        // catch_unwind boundary). If CHECK_FOR_INTERRUPTS() fires an ereport(ERROR) it
        // converts to a Rust panic with no catcher, causing _URC_END_OF_STACK (error 5)
        // and SIGABRT. Interrupt checking happens naturally inside run_event_transaction().

        let Some(username) = auth_event::username_from_bytes(&event.username) else {
            // An entry we cannot decode must not be silently dropped, and
            // acknowledging it would advance past evidence we never processed.
            // Mark the queue corrupt, which pauses enforcement cluster-wide.
            auth_event::mark_corrupt();
            return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
        };

        // Validate the primitive discriminant explicitly. An unknown kind is a
        // corrupt queue, never something to acknowledge away.
        let Some(kind) = EventKind::from_raw(event.kind) else {
            auth_event::mark_corrupt();
            return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
        };

        // Same treatment for the flag bits: an unknown bit means this event was
        // written by something that does not agree with this build about what
        // the event means, so it is never masked away or guessed at.
        let Some(flags) = EventFlags::from_raw(event.flags) else {
            auth_event::mark_corrupt();
            return ConsumeOutcome::QueueUnhealthy(QueueState::Corrupt);
        };

        let affects = AffectedCaches::for_event(kind, flags);

        match run_event_transaction(
            &event.event_id,
            &username,
            kind,
            flags,
            event.generation,
            token,
        ) {
            EventTxnOutcome::Committed => {
                pending_event = None;
                // The commit callback applied the cache operation and then
                // acknowledged this exact token. If that acknowledgement failed
                // validation it recorded `Corrupt`, which the next iteration's
                // health check will surface.
                if event_failures > 0 {
                    // Restore only what this retry sequence degraded, and only
                    // if it is still in the state this sequence put it in.
                    let still_incomplete = degraded.restore();
                    pgrx::log!(
                        "password_profile: auth event committed after {} failed attempt(s); \
                         cache states this sequence degraded were restored",
                        event_failures
                    );
                    event_failures = 0;
                    if still_incomplete {
                        // Something else recorded incomplete coverage while we
                        // were retrying. A successful commit does not repair
                        // that, so reconcile instead of claiming Ready.
                        return ConsumeOutcome::NeedsRehydration;
                    }
                }
            }

            // Both failure paths rolled the transaction back, so the database,
            // caches, receipt and RAM acknowledgement are unchanged. Keep the
            // durable event pending and retry it.
            EventTxnOutcome::RolledBack(detail) => {
                pgrx::warning!(
                    "password_profile: auth event transaction rolled back: {}",
                    detail
                );
                if !suspend_and_backoff(&mut event_failures, affects, &mut degraded) {
                    return ConsumeOutcome::Shutdown;
                }
            }
            EventTxnOutcome::PostgresError(sqlerrcode) => {
                pgrx::warning!(
                    "password_profile: auth event transaction aborted by a PostgreSQL error \
                     ({:?})",
                    sqlerrcode
                );
                if !suspend_and_backoff(&mut event_failures, affects, &mut degraded) {
                    return ConsumeOutcome::Shutdown;
                }
            }
        }
    }
}

/// Marks the caches this event actually affects unavailable and waits out a
/// bounded, latch-aware backoff before the caller retries the *same*
/// unacknowledged claim.
///
/// Returns `false` when a shutdown was observed while waiting.
///
/// # Why only the affected caches
/// An earlier revision marked *both* caches `WorkerFailed` for every failure
/// and restored both on the next success. That destroyed unrelated state: an
/// expiry cache sitting at `Overflow` while expiry enforcement was off would be
/// overwritten with `WorkerFailed` by a failing lockout event and then set to
/// `Ready` when that event finally committed -- announcing complete expiry
/// coverage that had never been hydrated.
fn suspend_and_backoff(
    event_failures: &mut u32,
    affects: AffectedCaches,
    degraded: &mut DegradedByRetry,
) -> bool {
    // Coverage is not provably complete while an event is stuck unprocessed --
    // but only for the state that event writes.
    degraded.mark(affects);
    *event_failures = event_failures.saturating_add(1);

    let delay = event_failure_backoff(*event_failures);
    if *event_failures == 1 || *event_failures % HYDRATION_WARN_EVERY == 0 {
        pgrx::warning!(
            "password_profile: auth event processing failed {} time(s); the event is still \
             queued and will be retried in {} ms. Marked unavailable: lock cache={}, expiry \
             cache={}. The affected extension feature remains paused until the event is \
             processed and its cache is reconciled.",
            *event_failures,
            delay.as_millis(),
            degraded.lock,
            degraded.expiry
        );
    }

    if !BackgroundWorker::wait_latch(Some(delay)) {
        pgrx::log!("password_profile: auth event consumer shutting down (failure backoff)");
        return false;
    }
    true
}

/// The worker's actual body, including its own initialization.
///
/// Initialization lives here, not in the exported entry point, so that a
/// PostgreSQL `ERROR` or Rust panic from `attach_signal_handlers` or
/// `connect_worker_to_spi` is contained by the same outer guard as the main
/// loop rather than escaping the FFI boundary.
///
/// Alternates between hydration (which must reach complete `Ready`) and event
/// consumption (which stops the moment the cache is no longer complete or an
/// event cannot be processed).
fn auth_event_consumer_impl() {
    // `attach_signal_handlers` installs pgrx's own SIGTERM/SIGHUP handlers
    // (which set an internal flag and post the worker's latch) and already
    // calls `BackgroundWorkerUnblockSignals()` internally. Do NOT follow
    // this with `pqsignal(SIGTERM, None)` -- that resets SIGTERM back to
    // its default action (terminate the process), which is why the worker
    // used to die with "terminated by signal 15" on `pg_ctl restart -m
    // fast` instead of exiting through the loop below and triggering
    // abnormal-shutdown crash recovery. Do not unblock signals a second
    // time either; `attach_signal_handlers` already did it.
    BackgroundWorker::attach_signal_handlers(SignalWakeFlags::SIGHUP | SignalWakeFlags::SIGTERM);
    BackgroundWorker::connect_worker_to_spi(Some(crate::CONTROL_DATABASE_NAME), None);

    // Only now -- signal handlers installed and the control database attached
    // -- may this worker claim to be running. Anything that fails above raises
    // or panics before this line, so a worker that never got that far is never
    // published as running, and the authentication hook keeps enforcement
    // paused rather than trusting caches nobody maintains.
    //
    // This is not a claim that any cache is usable: each cache publishes its
    // own `Ready` only from a completed hydration, below.
    worker_health::mark_running();

    pgrx::log!("password_profile: auth event consumer worker started");

    loop {
        // Restore active lockouts from the authoritative table before a single
        // authentication event is dequeued. Shared memory is empty after a
        // postmaster restart and may hold stale entries after a worker restart
        // or a standby promotion, so the cache is rebuilt from the database
        // first -- and must fit entirely -- before consumption begins.
        if !hydrate_caches_with_retry() {
            return;
        }

        match consume_events() {
            ConsumeOutcome::Shutdown => return,
            ConsumeOutcome::NeedsRehydration => continue,
            // Only structural corruption reaches this arm. Ordinary overflow
            // remains drainable and recovers when retained events are empty.
            ConsumeOutcome::QueueUnhealthy(queue_state) => {
                if suspend_on_unhealthy_queue(queue_state) {
                    continue;
                }
                return;
            }
        }
    }
}

/// Latch-aware suspension for a corrupt auth-event queue.
///
/// Entered only when the queue is `Corrupt`. Hydration cannot repair structural
/// corruption, so this loop deliberately
/// performs **no** hydration and no event consumption. It exists only to keep
/// the worker alive and responsive -- returning would make PostgreSQL
/// deregister the worker permanently (see `auth_event_consumer_main`).
///
/// While suspended, the authentication hook pauses this extension's enforcement
/// and leaves PostgreSQL's own authentication result untouched, so the
/// administrator can still log in and run the recovery function. It no longer
/// refuses logins: doing so locked the operator out of the connection the
/// documented recovery needs.
///
/// Returns `true` after an administrator has verified the journal and reset the
/// ring, or `false` on SIGTERM/postmaster death.
fn suspend_on_unhealthy_queue(initial_state: QueueState) -> bool {
    let mut reports: u32 = 0;
    let mut last_reported = initial_state;

    loop {
        if BackgroundWorker::sigterm_received() {
            pgrx::log!("password_profile: auth event consumer shutting down (queue unhealthy)");
            return false;
        }

        // SIGHUP is still honored so an administrator can reload configuration
        // -- including turning `lockout_enforcement` off to recover access --
        // without restarting the server. Reloading changes nothing about the
        // queue; it is processed here only so the signal is not left pending.
        if BackgroundWorker::sighup_received() {
            unsafe {
                pg_sys::ProcessConfigFile(pg_sys::GucContext::PGC_SIGHUP);
            }
            pgrx::log!("password_profile: auth event consumer reloaded config (SIGHUP)");
        }

        // Cache states are deliberately left exactly as they are.
        //
        // The queue has its own authoritative `Corrupt` state, and
        // `client_auth_hook` checks it directly. Overwriting the lock, expiry
        // and bypass caches with `WorkerFailed` would add no safety, would make an
        // unrelated healthy cache look as though it had failed, and would
        // destroy the diagnostic an operator needs -- whether the caches were
        // complete when the queue went bad. Nothing here repairs or resets the
        // queue either.
        //
        // Re-read for diagnostics; report the first observation, any state
        // change, and then only every Nth
        // wakeup, so a long outage cannot flood the log.
        let current = auth_event::state();
        if current != QueueState::Corrupt {
            pgrx::log!(
                "password_profile: auth event queue recovered; worker is resuming hydration and journal replay"
            );
            return true;
        }
        reports = reports.saturating_add(1);
        if reports == 1 || current != last_reported || reports % HYDRATION_WARN_EVERY == 0 {
            // The cache states are read before the message is built; each read
            // takes and releases its own lock, so nothing is held while this
            // logs. State names and counts only -- never a username or any
            // event content.
            let lock_state = lock_cache::state();
            let expiry_state = expiry_cache::state();
            let bypass_state = bypass_cache::state();
            pgrx::warning!(
                "password_profile: auth event queue is {:?}; the worker is suspended and will \
                 not hydrate or consume events, because neither operation can repair structural \
                 corruption. Login-time lockout and expiry enforcement are PAUSED; PostgreSQL \
                 native authentication is unaffected and still decides every login, so valid \
                 credentials are accepted and wrong passwords are rejected throughout. Lockout \
                 enforcement = {}, expiry enforcement active = {}. Cache states are preserved as \
                 diagnostics and are NOT evidence that the system is healthy: lock cache {:?}, \
                 expiry cache {:?}, bypass cache {:?}. Recovery requires an administrator and is \
                 reachable over a normal connection: inspect \
                 password_profile.get_lock_cache_stats(); preserve \
                 <PGDATA>/password_profile_auth_events.* as evidence; turn both enforcement \
                 switches off and reload; then call \
                 password_profile.recover_auth_event_queue().",
                current,
                crate::lockout_enforcement_enabled(),
                crate::expiry_login_enforcement_active(),
                lock_state,
                expiry_state,
                bypass_state
            );
            last_reported = current;
        }

        // One wakeup every 30s, never a busy loop; `wait_latch` returning false
        // means SIGTERM or postmaster death, so shutdown is prompt.
        if !BackgroundWorker::wait_latch(Some(Duration::from_secs(1))) {
            pgrx::log!("password_profile: auth event consumer shutting down (queue unhealthy)");
            return false;
        }
    }
}

/// Bounded exponential backoff for repeated event-processing failures.
///
/// Caps at [`HYDRATION_RETRY_MAX`] so a deterministic failure costs one wakeup
/// every 30s instead of a hot loop, while `wait_latch` keeps SIGTERM immediate.
fn event_failure_backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    HYDRATION_RETRY_MIN
        .saturating_mul(1u32 << shift)
        .min(HYDRATION_RETRY_MAX)
}

/// Outcome of the outermost worker guard.
enum WorkerExit {
    /// The worker returned normally (shutdown requested).
    Normal,
    /// A PostgreSQL `ERROR`, a pgrx `ErrorReport`, or a Rust panic was contained
    /// at the boundary. Carries only a `Copy` SQLSTATE -- the handler allocates
    /// nothing.
    Contained(PgSqlErrorCode),
}

/// Exported background-worker entry point.
///
/// # Final containment boundary
/// This is the last frame before PostgreSQL's C `StartBackgroundWorker`. Nothing
/// may unwind past it: a Rust panic crossing `extern "C-unwind"` here is the
/// `_URC_END_OF_STACK`/SIGABRT failure class that takes the postmaster into
/// crash recovery. Worker *initialization* is inside the guard too, so an error
/// from `attach_signal_handlers` or `connect_worker_to_spi` is contained as
/// well.
///
/// Phase 2's hydration wrapper contains recoverable PostgreSQL `ERROR`s so they
/// can be retried, and deliberately rethrows Rust panics and pgrx
/// `ErrorReport`s -- correct there, because a deterministic bug must not become
/// an infinite retry. This guard is where those rethrows stop.
///
/// FATAL and PANIC are neither caught nor downgraded. PostgreSQL does not
/// `siglongjmp` for them (`errfinish` goes straight to `proc_exit`/`abort`), so
/// they cannot reach a catch handler; the explicit level check keeps that
/// guarantee visible and enforced if it ever changes.
///
/// # Why the failure state is set out here
/// The catch handler may only do minimum safe cleanup: it runs *before*
/// `PgTryBuilder::execute()` calls `FlushErrorState()`, so PostgreSQL is still
/// "inside" the error subsystem. Taking the cache LWLock or logging there would
/// be work done in that state. Both therefore happen below, after `execute()`
/// has returned and the error state has been flushed.
///
/// # Restart behaviour (from PostgreSQL source)
/// Returning from here reaches `proc_exit(0)` in `StartBackgroundWorker`
/// (bgworker.c). `CleanupBackgroundWorker` (postmaster.c) then takes the
/// `EXIT_STATUS_0` branch, which sets `rw_crashed_at = 0` **and**
/// `rw_terminate = true`; `ReportBackgroundWorkerExit` (bgworker.c) sees
/// `rw_terminate` and calls `ForgetBackgroundWorker`. A clean return therefore
/// **deregisters** the worker -- it is not restarted, `bgw_restart_time`
/// notwithstanding, until the whole server restarts. That is why recoverable
/// failures are handled by suspending in-process with a latch-aware backoff
/// instead of returning: returning would convert a transient failure into a
/// permanent feature outage.
#[no_mangle]
pub unsafe extern "C-unwind" fn auth_event_consumer_main(_arg: pg_sys::Datum) {
    let exit = PgTryBuilder::new(|| {
        auth_event_consumer_impl();
        WorkerExit::Normal
    })
    // `execute()` dispatches `others` before `rust`, so this one arm sees
    // PostgreSQL errors, pgrx ErrorReports and Rust panics alike.
    .catch_others(|caught| {
        let (level, sqlerrcode) = match &caught {
            CaughtError::PostgresError(report)
            | CaughtError::ErrorReport(report)
            | CaughtError::RustPanic {
                ereport: report, ..
            } => (report.level(), report.sql_error_code()),
        };

        // Never catch or downgrade FATAL/PANIC. Unreachable in practice.
        if level != PgLogLevel::ERROR {
            caught.rethrow();
        }

        // Minimum safe cleanup only. Unconditional on purpose:
        // `IsTransactionState()` is true only for TRANS_INPROGRESS and would
        // skip cleanup after an error during transaction start or commit, while
        // `AbortCurrentTransaction()` carries the correct guard internally and
        // is what PostgreSQL's own `PostgresMain` calls. Its
        // AbortTransaction/CleanupTransaction release the snapshot stack,
        // portals, the resource owner and every held LWLock, and fire
        // XACT_EVENT_ABORT so staged cache operations are discarded.
        //
        // Nothing else happens here: no logging, no formatting, no allocation,
        // no SPI, no cache LWLock.
        unsafe {
            pg_sys::AbortCurrentTransaction();
        }

        WorkerExit::Contained(sqlerrcode)
    })
    .execute();

    // Past this point `execute()` has returned and, on the caught path, it has
    // already called FlushErrorState(). Only now is it safe to take the cache
    // LWLock and to log.
    //
    // # Every exit is handled the same way, on purpose
    // An earlier revision did this only for `Contained`. A *clean* return --
    // which is what a direct `SIGTERM` to `password_profile_auth_event_consumer`
    // produces -- therefore left every cache reporting `Ready` while
    // PostgreSQL had already deregistered the worker (see the restart note
    // above: a clean return reaches `ForgetBackgroundWorker`, so the worker
    // does not come back until the server restarts). Nothing was applying
    // authentication events any more, yet the login hook still believed lockout
    // enforcement was active: three wrong passwords were journaled and never
    // counted, and the fourth, correct one was accepted, while
    // `get_lock_cache_stats()` reported a completely healthy system.
    //
    // Whichever way the worker leaves, nothing maintains these caches
    // afterwards, so the honest state is the same. Only `Ready` is overwritten:
    // an existing `Overflow`/`NotReady` describes something this exit did not
    // cause and cannot repair.
    let stop_reason = match exit {
        WorkerExit::Normal => worker_health::STOP_SHUTDOWN,
        WorkerExit::Contained(_) => worker_health::STOP_CONTAINED,
    };
    worker_health::mark_stopped(stop_reason);

    if lock_cache::state() == CacheState::Ready {
        lock_cache::set_state(CacheState::WorkerFailed);
    }
    if expiry_cache::state() == ExpiryCacheState::Ready {
        expiry_cache::set_state(ExpiryCacheState::WorkerFailed);
    }
    if bypass_cache::state() == BypassCacheState::Ready {
        bypass_cache::set_state(BypassCacheState::WorkerFailed);
    }

    match exit {
        // A shutdown request is also exactly what a normal fast shutdown sends,
        // so this path must not look like an incident: the state is recorded
        // and reported at LOG level, and no WARNING is emitted here. If the
        // server is in fact still running -- a direct SIGTERM to the worker
        // alone -- the next login that wanted enforcement raises the
        // rate-controlled WARNING from the authentication hook, where the
        // degradation actually matters and where a real fast shutdown produces
        // no logins at all.
        WorkerExit::Normal => {
            pgrx::log!(
                "password_profile: auth event consumer stopped after a shutdown request; \
                 lockout and expiry enforcement are paused and every cache that was Ready is \
                 now WorkerFailed. This is the normal path during a PostgreSQL shutdown. If the \
                 server is still running, PostgreSQL has deregistered this worker and will not \
                 restart it before the next server start; worker_running in \
                 password_profile.get_lock_cache_stats() reports 0 until then."
            );
        }
        WorkerExit::Contained(sqlerrcode) => {
            pgrx::warning!(
                "password_profile: auth event consumer stopped after an unhandled failure \
                 ({:?}); every cache that was Ready is now WorkerFailed. The worker is \
                 deregistered by PostgreSQL on a clean exit and will not restart on its own. \
                 Login-time lockout and expiry enforcement remain paused -- PostgreSQL native \
                 authentication is unaffected and still rejects wrong passwords -- until an \
                 administrator investigates and restarts the server.",
                sqlerrcode
            );
        }
    }

    pgrx::log!("password_profile: auth event consumer worker stopped");
}
