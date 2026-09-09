use bcrypt::{hash, verify};
use pgrx::bgworkers::BackgroundWorkerBuilder;
use pgrx::datum::TimestampWithTimeZone;
use pgrx::pg_sys;
use pgrx::pg_sys::errcodes::PgSqlErrorCode;
use pgrx::pg_sys::ffi::pg_guard_ffi_boundary;
use pgrx::prelude::*;
use siphasher::sip::SipHasher13;
use std::ffi::{CStr, CString};
use std::hash::Hasher;
use std::os::raw::c_int;
use std::ptr;
use std::sync::Once;
use std::time::Duration;

mod auth_event;
mod auth_journal;
mod blacklist;
mod bypass_cache;
mod expiry_cache;
mod lock_cache;
mod pending_cache_op;
mod sql;
mod structured_log;
mod worker;
mod worker_health;
use crate::sql::{int4_arg, text_arg};
pub use worker::auth_event_consumer_main;

::pgrx::pg_module_magic!();
pgrx::extension_sql_file!("../sql/password_profile_schema.sql");

// Privileges for everything this extension creates.
//
// PostgreSQL grants `EXECUTE` on every new function to `PUBLIC` by default, so a
// plain `CREATE EXTENSION` would let any role call the administrative,
// monitoring and file-reading functions below. These statements revoke that.
//
// `finalize` is pgrx's ordering mechanism for "SQL intended to go after all
// other generated SQL", so this runs during a fresh `CREATE EXTENSION` once all
// functions, the schema and the tables exist -- no manual post-install step.
//
// Every function is named with its exact identity signature and qualified with
// `@extschema@`, which PostgreSQL substitutes with the schema the extension was
// installed into. Nothing outside this extension is touched: a blanket
// `REVOKE ... ON ALL FUNCTIONS IN SCHEMA public` would strip privileges from
// unrelated applications sharing that schema.
//
// Revoking from `PUBLIC` does not affect the extension owner, and superusers
// bypass ACLs entirely, so both keep working. No roles are created here; a DBA
// grants selected functions explicitly.
pgrx::extension_sql!(
    r#"
REVOKE ALL ON FUNCTION @extschema@.add_to_blacklist(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.check_password(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.check_password_expiry(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.check_user_access(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.clear_login_attempts(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.get_lock_cache_stats() FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.get_password_stats(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.init_login_attempts_table() FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.is_user_locked(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.load_blacklist_from_file(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.record_failed_login(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.record_password_change(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.rename_role_state(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.remove_role_state(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.remove_from_blacklist(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION @extschema@.recover_auth_event_queue() FROM PUBLIC;

REVOKE ALL ON SCHEMA password_profile FROM PUBLIC;
REVOKE ALL ON TABLE password_profile.login_attempts FROM PUBLIC;
REVOKE ALL ON TABLE password_profile.password_history FROM PUBLIC;
REVOKE ALL ON TABLE password_profile.password_expiry FROM PUBLIC;
REVOKE ALL ON TABLE password_profile.blacklist FROM PUBLIC;
REVOKE ALL ON TABLE password_profile.auth_event_receipts FROM PUBLIC;
REVOKE ALL ON SEQUENCE password_profile.password_history_id_seq FROM PUBLIC;
"#,
    name = "password_profile_privileges",
    finalize
);

const LOCK_CACHE_SIZE: usize = 2048;
/// Capacity of the shared expiry cache. Overflow is explicit and observable
/// rather than being hidden by eviction.
const EXPIRY_CACHE_SIZE: usize = 2048;
/// Capacity of the shared bypass-exemption cache. `bypass_password_profile` is
/// an administrative exemption, so this is deliberately far larger than any
/// sane number of exempt roles; exceeding it records `Overflow` and grants no
/// exemptions until the complete set can be hydrated.
const BYPASS_CACHE_SIZE: usize = 1024;
const LOCK_USERNAME_BYTES: usize = 64;
const MICROS_PER_SEC: i64 = 1_000_000;
const AUTH_EVENT_RING_SIZE: usize = 1024;

/// Name of the single named LWLock tranche that backs both the lock cache
/// and the authentication event ring. A named tranche is requested during
/// `shmem_request_hook` and its locks are retrieved from PostgreSQL-owned
/// shared memory during `shmem_startup_hook` -- unlike the old
/// raw spinlock this extension used to carry, these locks put a waiting backend
/// to sleep instead of busy-spinning, so a stuck holder can no longer trip
/// PostgreSQL's stuck-spinlock detector and abort the process.
const LWLOCK_TRANCHE_NAME: &CStr = c"password_profile_locks";
const LWLOCK_TRANCHE_COUNT: c_int = 4;

/// Lock guarding [`lock_cache::LOCK_CACHE`]. Populated by
/// [`init_named_lwlock_tranche`]; null until then.
pub(crate) static mut LOCK_CACHE_LWLOCK: *mut pg_sys::LWLock = ptr::null_mut();
/// Lock guarding the auth event ring. Populated by
/// [`init_named_lwlock_tranche`]; null until then.
pub(crate) static mut AUTH_EVENT_LWLOCK: *mut pg_sys::LWLock = ptr::null_mut();
/// Lock guarding the shared expiry cache. Populated by
/// [`init_named_lwlock_tranche`]; null until then.
///
/// # Global lock order
/// There is exactly one nesting of LWLocks anywhere in this extension:
///
/// ```text
/// EXPIRY_CACHE_LWLOCK -> AUTH_EVENT_LWLOCK
/// ```
///
/// It exists in one function, [`expiry_cache::try_consume_grace`], so that
/// decrementing a cached grace login and queueing its persistence event are
/// indivisible. Nothing anywhere acquires `EXPIRY_CACHE_LWLOCK` while holding
/// `AUTH_EVENT_LWLOCK`, so the reverse order does not exist and the pair cannot
/// deadlock.
///
/// Every other LWLock section in the extension holds exactly one lock:
/// `LOCK_CACHE_LWLOCK` and `BYPASS_CACHE_LWLOCK` are never nested with anything,
/// in either direction, and `pending_cache_op::apply_all` deliberately applies
/// the lock cache and the expiry cache one after the other rather than holding
/// both.
///
/// Database-level locks order ahead of all of them:
/// `per-user advisory lock -> login_attempts row/table -> LOCK_CACHE_LWLOCK`.
/// No LWLock is ever held while SPI runs.
///
/// Nothing logs, allocates, formats, raises, sleeps or calls SPI while any of
/// these is held -- including transitively. Where a nested call would otherwise
/// want to warn (a full auth-event ring), the *decision* to warn is returned as
/// a primitive `bool` and the warning is emitted by ordinary hook or worker code
/// after every lock has been released.
pub(crate) static mut EXPIRY_CACHE_LWLOCK: *mut pg_sys::LWLock = ptr::null_mut();
/// Lock guarding the shared bypass-exemption cache. Populated by
/// [`init_named_lwlock_tranche`]; null until then. Never nested with any other
/// lock in either direction.
pub(crate) static mut BYPASS_CACHE_LWLOCK: *mut pg_sys::LWLock = ptr::null_mut();

pub(crate) enum LwLockMode {
    Shared,
    Exclusive,
}

/// RAII guard that acquires a named PostgreSQL LWLock on construction and
/// releases it on drop (normal Rust scope exit).
///
/// # Safety / longjmp hazard
/// Never call SPI, `pgrx::error!()`, `pgrx::warning!()`, or anything else that
/// can `longjmp` while a guard is live -- doing so skips the `Drop` impl and
/// leaves the lock held forever.
pub(crate) struct LwLockGuard {
    lock_ptr: *mut pg_sys::LWLock,
}

impl LwLockGuard {
    /// # Safety
    /// `lock_ptr` must be a non-null pointer to an LWLock obtained from the
    /// `password_profile_locks` named tranche after PostgreSQL has
    /// initialized it (i.e. after [`init_named_lwlock_tranche`] has run).
    pub(crate) unsafe fn acquire(lock_ptr: *mut pg_sys::LWLock, mode: LwLockMode) -> Self {
        let raw_mode = match mode {
            LwLockMode::Shared => pg_sys::LWLockMode::LW_SHARED,
            LwLockMode::Exclusive => pg_sys::LWLockMode::LW_EXCLUSIVE,
        };
        pg_sys::LWLockAcquire(lock_ptr, raw_mode);
        LwLockGuard { lock_ptr }
    }
}

impl Drop for LwLockGuard {
    fn drop(&mut self) {
        // Mirrors pgrx's own `PgLwLock` guard (pgrx-0.16.1/src/lwlock.rs,
        // `release_unless_elog_unwinding`): `LWLockAcquire` calls
        // `HOLD_INTERRUPTS()`, so `InterruptHoldoffCount > 0` here in the
        // normal case. If PostgreSQL's own error/interrupt handling has
        // already unwound through this lock (resetting the holdoff count to
        // zero as part of its cleanup), the lock has already been released
        // by that cleanup and calling `LWLockRelease` again here would
        // double-release it and corrupt PostgreSQL's per-process
        // `held_lwlocks` bookkeeping.
        unsafe {
            if pg_sys::InterruptHoldoffCount > 0 {
                pg_sys::LWLockRelease(self.lock_ptr);
            }
        }
    }
}

/// Reserves space for the named LWLock tranche. Must run from
/// `shmem_request_hook`, alongside `RequestAddinShmemSpace`.
unsafe fn request_named_lwlock_tranche() {
    pg_sys::RequestNamedLWLockTranche(LWLOCK_TRANCHE_NAME.as_ptr(), LWLOCK_TRANCHE_COUNT);
}

/// Retrieves the two locks PostgreSQL initialized for our named tranche and
/// makes them available to postmaster children (via fork) and the
/// background worker. Must run from `shmem_startup_hook`, after PostgreSQL
/// has initialized the tranche -- never initialize an LWLock manually
/// without a valid tranche.
unsafe fn init_named_lwlock_tranche() {
    let tranche = pg_sys::GetNamedLWLockTranche(LWLOCK_TRANCHE_NAME.as_ptr());
    if tranche.is_null() {
        pgrx::error!("password_profile: failed to retrieve named LWLock tranche");
    }
    LOCK_CACHE_LWLOCK = ptr::addr_of_mut!((*tranche.add(0)).lock);
    AUTH_EVENT_LWLOCK = ptr::addr_of_mut!((*tranche.add(1)).lock);
    EXPIRY_CACHE_LWLOCK = ptr::addr_of_mut!((*tranche.add(2)).lock);
    BYPASS_CACHE_LWLOCK = ptr::addr_of_mut!((*tranche.add(3)).lock);
}

/// The single authoritative control database for password_profile.
///
/// PostgreSQL roles are cluster-wide but `password_profile`'s policy, history
/// and lockout tables live in one database. The background worker connects here,
/// and this is where password history is recorded and enforced.
const CONTROL_DATABASE: &CStr = c"postgres";

/// The same control database as a Rust `str`, for the background worker's
/// `connect_worker_to_spi`. Kept beside [`CONTROL_DATABASE`] so the worker and
/// the password-check gate can never name different databases.
pub(crate) const CONTROL_DATABASE_NAME: &str = "postgres";

/// Fails closed unless the current backend is connected to [`CONTROL_DATABASE`].
///
/// Allowing `ALTER ROLE ... PASSWORD` from another database would silently
/// bypass history and blacklist enforcement -- the role change would take effect
/// cluster-wide while the history tables in `postgres` never saw it. Rather than
/// claim multi-database support, refuse the operation and say where to do it.
///
/// Uses `get_database_name(MyDatabaseId)`, a backend API, rather than any
/// cross-database SPI connection. Only reached from the password-check hook, so
/// ordinary queries in other databases are unaffected.
///
/// # Safety
/// Must be called from a backend with an established database context, inside a
/// `#[pg_guard]`ed hook (so `pgrx::error!` is contained correctly).
unsafe fn require_control_database() {
    let db_id = std::ptr::addr_of!(pg_sys::MyDatabaseId).read();
    if db_id == pg_sys::InvalidOid {
        pgrx::error!(
            "password_profile: password changes require a database connection; \
             connect to the \"{}\" database and retry",
            CONTROL_DATABASE.to_string_lossy()
        );
    }

    let name_ptr = pg_sys::get_database_name(db_id);
    if name_ptr.is_null() {
        pgrx::error!(
            "password_profile: could not determine the current database; \
             password changes must be performed while connected to \"{}\"",
            CONTROL_DATABASE.to_string_lossy()
        );
    }

    if CStr::from_ptr(name_ptr) != CONTROL_DATABASE {
        pgrx::error!(
            "password_profile: password changes must be performed while connected to the \"{}\" database",
            CONTROL_DATABASE.to_string_lossy()
        );
    }
}

static CLIENT_AUTH_HOOK_INIT: Once = Once::new();

type ClientAuthHookRaw = unsafe extern "C-unwind" fn(port: *mut pg_sys::Port, status: c_int);
static mut PREV_CLIENT_AUTH_HOOK: Option<ClientAuthHookRaw> = None;

static PASSWORD_MIN_LENGTH: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(8);
static REQUIRE_UPPERCASE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_LOWERCASE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_DIGIT: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static REQUIRE_SPECIAL: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);
static PREVENT_USERNAME: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(true);

static PASSWORD_HISTORY_COUNT: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(5);
static PASSWORD_REUSE_DAYS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(90);

static PASSWORD_EXPIRY_DAYS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(90);
static PASSWORD_GRACE_LOGINS: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(3);

static FAILED_LOGIN_MAX: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(3);
static LOCKOUT_MINUTES: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(2);

static BCRYPT_COST: pgrx::GucSetting<i32> = pgrx::GucSetting::<i32>::new(10);

static BYPASS_PASSWORD_PROFILE: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(false);

/// Master switch for brute-force counting and lockout enforcement.
///
/// Defaults to `true` and is `PGC_SIGHUP`, so only someone who can edit
/// `postgresql.conf` (or an equivalent) and reload can change it -- ordinary
/// users cannot. It also provides an explicit bootstrap/emergency path: on a
/// fresh install the cache is `NotReady` until the worker hydrates, so lockout
/// enforcement is temporarily paused. Turning this off keeps that feature
/// disabled until an administrator deliberately enables it again.
///
/// It gates *only* brute-force counting and lockout enforcement. Password
/// complexity, history, blacklist and expiry rules are unaffected, and native
/// authentication is untouched either way. It never turns itself on or off.
static LOCKOUT_ENFORCEMENT: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(true);

/// Master switch for login-time password-expiry and grace-login enforcement.
///
/// Independent of [`LOCKOUT_ENFORCEMENT`], which stays scoped to brute-force
/// counting and account lockout. Defaults to `true`, `PGC_SIGHUP`, so an
/// ordinary session cannot change it.
///
/// It gates *only* login-time expiry/grace enforcement. Password complexity,
/// blacklist and history validation, and PostgreSQL's own authentication, are
/// unaffected. It never repairs or resets an unhealthy cache.
static EXPIRY_ENFORCEMENT: pgrx::GucSetting<bool> = pgrx::GucSetting::<bool>::new(true);

unsafe fn register_password_check_hook() {
    static mut PREV_CHECK_PASSWORD_HOOK: pg_sys::check_password_hook_type = None;

    #[pg_guard]
    unsafe extern "C-unwind" fn password_check_hook(
        username: *const std::os::raw::c_char,
        shadow_pass: *const std::os::raw::c_char,
        password_type: pg_sys::PasswordType::Type,
        validuntil_time: pg_sys::Datum,
        validuntil_null: bool,
    ) {
        let username_str = if username.is_null() {
            "unknown"
        } else {
            CStr::from_ptr(username).to_str().unwrap_or("unknown")
        };

        let password_str = if shadow_pass.is_null() {
            ""
        } else {
            CStr::from_ptr(shadow_pass).to_str().unwrap_or("")
        };

        if !password_str.is_empty() && is_hash_like(password_str) {
            raise_password_change_error(
                "Password looks like a precomputed hash. Direct hash input is not allowed. Use plain text passwords only.",
            );
        }

        // Enforce the single-control-database contract before any password
        // history or blacklist SQL runs. Applies to every password change,
        // including pre-hashed ones, because those bypass history just as
        // effectively when made from the wrong database.
        require_control_database();

        // Only a plaintext, non-empty password is a candidate to validate and
        // record. `PASSWORD NULL`, an absent password and pre-hashed input
        // (already rejected above) never reach the recorder, so they cannot
        // create history.
        let outcome = if password_type == pg_sys::PasswordType::PASSWORD_TYPE_PLAINTEXT
            && !password_str.is_empty()
        {
            match validate_password(username_str, password_str) {
                Ok(outcome) => {
                    log_password_validation(username_str, None, true);
                    Some(outcome)
                }
                Err(e) => {
                    log_password_validation(username_str, Some(&e.to_string()), false);
                    raise_password_change_error(&e.to_string());
                }
            }
        } else {
            None
        };

        // Every validation hook runs before anything is persisted, so a veto
        // from a downstream hook leaves no history or expiry row behind.
        if let Some(prev_hook) = PREV_CHECK_PASSWORD_HOOK {
            pg_guard_ffi_boundary(|| {
                prev_hook(
                    username,
                    shadow_pass,
                    password_type,
                    validuntil_time,
                    validuntil_null,
                )
            });
        }

        // Record exactly once, after all validation has succeeded. A bypassed
        // role records nothing, preserving the existing bypass semantics.
        if outcome == Some(ValidationOutcome::Accepted) {
            if let Err(e) = record_password_change_internal(username_str, password_str) {
                // Never allow the role password to change without its history
                // row: reject instead. This aborts the CREATE/ALTER ROLE, so
                // the role change and any partial write roll back together.
                let detail = format!("Password change could not be recorded: {}", e);
                raise_password_change_error(&detail);
            }
        }
    }

    PREV_CHECK_PASSWORD_HOOK = pg_sys::check_password_hook;
    pg_sys::check_password_hook = Some(password_check_hook);
}

extern "C-unwind" {
    fn password_profile_port_username(port: *mut pg_sys::Port) -> *const std::os::raw::c_char;
    fn password_profile_register_client_auth_hook(
        hook: Option<ClientAuthHookRaw>,
    ) -> Option<ClientAuthHookRaw>;
    fn password_profile_raise_lockout_error(
        username: *const std::os::raw::c_char,
        remaining_seconds: c_int,
    );
    /// Raises `FATAL` (terminating only this backend) because the password has
    /// expired and no grace logins remain. Takes no arguments so no username or
    /// cache content can leak.
    fn password_profile_raise_expired_error(username: *const std::os::raw::c_char);
    fn password_profile_raise_password_change_error(reason: *const std::os::raw::c_char);
    fn password_profile_log_password_validation(
        username: *const std::os::raw::c_char,
        reason: *const std::os::raw::c_char,
        accepted: bool,
    );
    fn password_profile_user_exists(username: *const std::os::raw::c_char) -> c_int;
    fn password_profile_get_last_sqlstate(port: *mut pg_sys::Port, status: c_int) -> c_int;
}

fn raise_password_change_error(reason: &str) -> ! {
    let safe_reason = reason.replace('\0', "");
    let c_reason = CString::new(safe_reason)
        .unwrap_or_else(|_| CString::new("password policy validation failed").unwrap());
    unsafe {
        password_profile_raise_password_change_error(c_reason.as_ptr());
    }
    unreachable!("PostgreSQL ERROR unexpectedly returned")
}

fn log_password_validation(username: &str, reason: Option<&str>, accepted: bool) {
    let c_username = CString::new(username.replace('\0', ""))
        .unwrap_or_else(|_| CString::new("unknown").unwrap());
    let c_reason = reason.map(|value| {
        CString::new(value.replace('\0', ""))
            .unwrap_or_else(|_| CString::new("password policy validation failed").unwrap())
    });
    unsafe {
        password_profile_log_password_validation(
            c_username.as_ptr(),
            c_reason
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            accepted,
        );
    }
}

#[inline]
fn encode_username(username: &str) -> [u8; LOCK_USERNAME_BYTES] {
    let mut buf = [0u8; LOCK_USERNAME_BYTES];
    let bytes = username.as_bytes();
    let len = bytes.len().min(LOCK_USERNAME_BYTES.saturating_sub(1));
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

fn check_lockout_from_db(username: &str) -> Option<i64> {
    use pgrx::spi::Spi;

    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return None;
    }

    // Read the per-user or global failed_login_max so the DB fallback matches
    // the same threshold used when recording failures.  We fall back to the
    // global GUC; per-user overrides are best-effort here since we may not have
    // an SPI context deep enough to query pg_user safely.
    let max_fails = FAILED_LOGIN_MAX.get();

    // The authoritative `lockout_until` is read as a typed `TimestampTz` and
    // converted by the same ceiling helper the cache path uses. The previous
    // `ROUND(EXTRACT(EPOCH ...))` was both float-based and round-to-nearest, so
    // a lockout with under half a second left reported 0 and was treated as
    // unlocked -- the same under-enforcement the cache path had.
    let result = Spi::connect(|client| -> pgrx::spi::Result<Option<pg_sys::TimestampTz>> {
        let args = [text_arg(username), crate::sql::int4_arg(max_fails)];
        let table = client.select(
            "SELECT (SELECT lockout_until
                       FROM password_profile.login_attempts
                      WHERE username = $1
                        AND fail_count >= $2
                        AND lockout_until > now())",
            None,
            &args,
        )?;

        Ok(table
            .first()
            .get_one::<TimestampWithTimeZone>()?
            .map(|ts| ts.into_inner()))
    });

    match result {
        Ok(Some(expires_at)) => {
            lock_cache::remaining_seconds_ceil(expires_at, unsafe { pg_sys::GetCurrentTimestamp() })
        }
        Ok(None) => None,
        Err(e) => {
            pgrx::warning!("password_profile: DB lockout check failed: {:?}", e);
            None
        }
    }
}

/// Invokes the previously registered `ClientAuthentication_hook`, if any,
/// through the project's guarded FFI boundary. Every path that leaves
/// `client_auth_hook` normally goes through here exactly once.
#[inline]
unsafe fn call_prev_client_auth_hook(port: *mut pg_sys::Port, status: c_int) {
    if let Some(prev_hook) = PREV_CLIENT_AUTH_HOOK {
        pg_guard_ffi_boundary(|| prev_hook(port, status));
    }
}

/// Structural corruption of the auth-event queue.
///
/// This used to be the extension's "final safety stop": every authenticated
/// connection was refused with a FATAL while the queue was `Corrupt`. That is a
/// cluster-wide login outage produced by an extension-internal condition -- and
/// it locked the administrator out of the very connection needed to run
/// `password_profile.recover_auth_event_queue()`, because the recovery function
/// is reachable only through a login that the same stop was refusing. A single
/// corrupt 112-byte journal record was therefore enough to make a healthy
/// cluster unreachable except by editing `postgresql.conf` on disk.
///
/// It is now what every other unhealthy shared-memory condition already was:
/// a reason to *pause this extension's own enforcement*. PostgreSQL's native
/// authentication is untouched and still decides every login, so wrong
/// passwords stay rejected throughout.
fn auth_queue_corrupt() -> bool {
    auth_event::state() == auth_event::QueueState::Corrupt
}

/// Whether this extension may enforce anything at login time right now.
///
/// All three conditions are about the extension's *own* runtime state, and none
/// of them says anything about the credential PostgreSQL just verified:
///
/// * no worker is running, so nothing would ever apply a queued event;
/// * the auth-event queue is structurally corrupt;
/// * a durable journal append failed recently, so what the caches contain can
///   no longer be shown to match the authoritative tables.
///
/// When any of them holds, enforcement is paused rather than converted into a
/// rejection. Returns the reason so the single exit point can emit one
/// rate-controlled warning.
fn enforcement_pause_reason() -> Option<worker_health::PausedReason> {
    if !worker_health::is_running() {
        return Some(worker_health::PausedReason::WorkerNotRunning);
    }
    if auth_queue_corrupt() {
        return Some(worker_health::PausedReason::QueueCorrupt);
    }
    if worker_health::durable_degraded_since().is_some() {
        return Some(worker_health::PausedReason::DurableRecording);
    }
    None
}

#[pg_guard]
unsafe extern "C-unwind" fn client_auth_hook(port: *mut pg_sys::Port, status: c_int) {
    // While this instance is in recovery (standby), password_profile's
    // brute-force protection, account lockout and expiry enforcement are
    // disabled: no cache lookup, no lockout table query, no user-existence
    // check, no auth event, no timing jitter, no extension logging.
    // PostgreSQL's native authentication still accepts or rejects credentials
    // on its own, so a wrong password is still rejected. This check must stay
    // ahead of every extension-specific login-time action below.
    if pg_sys::RecoveryInProgress() {
        call_prev_client_auth_hook(port, status);
        return;
    }

    // Two independent switches. Lockout enforcement covers brute-force
    // counting and account lockout; expiry enforcement covers login-time
    // password expiry and grace logins. Either can be off without affecting the
    // other. Both are the explicit bootstrap/emergency paths and are never
    // enabled implicitly.
    //
    // Expiry enforcement is additionally gated on `password_expiry_days > 0`:
    // with expiry disabled by policy there is nothing to enforce, and the
    // expiry cache's health must not be able to refuse a connection. That
    // combined condition is `expiry_login_enforcement_active()`, and the
    // background worker uses the identical helper, so the two can no longer
    // disagree about whether the expiry cache matters.
    let lockout_active = LOCKOUT_ENFORCEMENT.get();
    let expiry_active = expiry_login_enforcement_active();

    if !lockout_active && !expiry_active {
        call_prev_client_auth_hook(port, status);
        return;
    }

    let username_ptr = password_profile_port_username(port);
    let username_str = if username_ptr.is_null() {
        None
    } else {
        CStr::from_ptr(username_ptr).to_str().ok()
    };

    // ---- Administrative exemption ---------------------------------------
    // `password_profile.bypass_password_profile = true` is documented to exempt
    // a role from validation, history, expiry *and* lockout. Answered purely
    // from shared memory: this hook may not touch the catalog, and the setting
    // lives in `pg_db_role_setting`, which has no syscache and is not a nailed
    // relation (see `bypass_cache`). Takes only the bypass cache's own LWLock,
    // which is released before this returns.
    let bypass = match username_str {
        Some(name) => bypass_cache::lookup(name),
        // No username to look up: nothing to exempt, and nothing below will
        // record anything for it either.
        None => bypass_cache::BypassDecision::NotBypassed,
    };

    // ---- Previous hook: exactly once, on every non-recovery path ---------
    // PostgreSQL calls this hook *after* it has already produced `status`, so
    // the previous hook is not password verification -- it is another
    // extension's authentication hook, and it is entitled to run for every
    // connection this one sees, including one this extension is about to
    // refuse. It is deliberately placed ahead of every queue insertion, grace
    // consumption and FATAL below: if an earlier-registered hook rejects the
    // connection it never returns, so no auth event is enqueued and no grace
    // login is consumed for a connection that was refused.
    //
    // The two early returns above are the only other call sites, and they are
    // mutually exclusive with this one, so every path calls it exactly once.
    call_prev_client_auth_hook(port, status);

    let authenticated = status == pg_sys::STATUS_OK as c_int;

    match bypass {
        // Exempt: skip lockout, expiry and auth-event processing entirely.
        // PostgreSQL's own authentication result stands untouched, so a wrong
        // password is still rejected by PostgreSQL.
        bypass_cache::BypassDecision::Bypassed => return,
        // If the exemption cache is incomplete, apply the normal policy. A
        // missing exemption must not turn into a cluster-wide login outage.
        bypass_cache::BypassDecision::Unavailable => {}
        bypass_cache::BypassDecision::NotBypassed => {}
    }

    let Some(username_str) = username_str else {
        return;
    };

    // ---- Extension health ------------------------------------------------
    // Every unhealthy condition below pauses only this extension's own
    // enforcement. None of them rejects a login: PostgreSQL has already decided
    // `status` from the credential itself, and an internal journal, queue or
    // worker problem is not evidence about that credential.
    let pause_reason = enforcement_pause_reason();
    let healthy = pause_reason.is_none();

    let lockout_runtime_active =
        lockout_active && healthy && lock_cache::state() == lock_cache::CacheState::Ready;
    let expiry_runtime_active =
        expiry_active && healthy && expiry_cache::state() == expiry_cache::ExpiryCacheState::Ready;

    // Set when an event could not be recorded after the health check passed --
    // the journal can fail or the queue can degrade in between. It suppresses
    // the *rest of this extension's* processing for this connection and drives
    // the warning at the single exit point; it never rejects the connection.
    let mut event_lost = false;
    // Set when the password is expired with no grace remaining.
    let mut password_expired = false;
    // The auth-event ring's own rate-limited decision that a queue-full warning
    // is due. Carried out of every locked region as a primitive and emitted at
    // the single exit point, never while a lock is held.
    let mut queue_warn = false;

    if !authenticated {
        // ---- Failed native authentication -------------------------------
        // Expiry is never evaluated here: a wrong password must not consume a
        // grace login and must not reveal expiry status.
        if lockout_runtime_active {
            let sqlstate = password_profile_get_last_sqlstate(port, status) as u32;
            if sqlstate == PgSqlErrorCode::ERRCODE_INVALID_PASSWORD as u32 {
                let user_exists = password_profile_user_exists(username_ptr);
                if user_exists == 1 {
                    // A failed login carries no cleanup intent: it must never
                    // clear failed-attempt state.
                    if !auth_event::enqueue(
                        username_str,
                        auth_event::EVENT_KIND_FAILURE,
                        auth_event::EventFlags::NONE,
                    )
                    .is_durable()
                    {
                        // The failure could not be recorded durably. The
                        // enqueue path has already published the
                        // durable-recording degradation in shared memory, which
                        // pauses lockout enforcement for everyone until the
                        // worker can prove the caches again.
                        //
                        // It deliberately does NOT contain this user. The
                        // previous revision installed a lock-cache entry for
                        // `lockout_minutes` here, which survived the storage
                        // problem it was reacting to and went on refusing a
                        // user whose PostgreSQL credentials were valid -- and,
                        // because a superuser's local `trust` connection also
                        // passes through this hook, it could lock the
                        // administrator out of their own cluster for the whole
                        // lockout window.
                        event_lost = true;
                    }
                } else if user_exists != 0 {
                    pgrx::warning!(
                        "password_profile: failed to verify user existence during auth failure"
                    );
                }
            }
        }
        // PostgreSQL rejects the connection on its own; nothing more to do
        // except report degraded state. Every LWLock taken above was released
        // inside the function that took it, so this may allocate and log.
        report_degraded(pause_reason, event_lost);
        return;
    }

    // Reveal no lockout state for a credential PostgreSQL already rejected.
    // The same generic authentication error is returned for wrong passwords
    // and unknown users; lockout is enforced only after native authentication
    // has succeeded.
    if lockout_runtime_active {
        let remaining_secs = lock_cache::remaining_seconds(username_str)
            .or_else(|| check_lockout_from_db(username_str));

        if let Some(seconds) = remaining_secs.filter(|seconds| *seconds > 0) {
            password_profile_raise_lockout_error(
                username_ptr,
                seconds.min(i32::MAX as i64) as c_int,
            );
            #[allow(unreachable_code)]
            return;
        }
    }

    // ---- Successful native authentication --------------------------------
    // Re-check health immediately before anything is recorded or admitted.
    // The check above ran before the previous hook; another backend can degrade
    // the queue or the journal while that hook is running, and a success event
    // enqueued after that point would be recorded against state this extension
    // can no longer vouch for.
    if !healthy || enforcement_pause_reason().is_some() {
        event_lost = true;
    }

    // Expiry is evaluated only now, so the outcome can never leak for a wrong
    // password.
    let mut grace_consumed = false;

    if !event_lost && expiry_runtime_active {
        let now = pg_sys::GetCurrentTimestamp();
        match expiry_cache::lookup(username_str, now) {
            // Nothing to enforce.
            expiry_cache::ExpiryDecision::NoRow | expiry_cache::ExpiryDecision::NotExpired => {}
            expiry_cache::ExpiryDecision::ExpiredNoGrace => password_expired = true,
            expiry_cache::ExpiryDecision::ExpiredWithGrace => {
                // Re-decided under the exclusive lock; the lookup above is only
                // a hint, so two concurrent logins cannot both take the last
                // grace login. The cleanup intent is captured in the event's
                // flags *now*, from the switch value this login was admitted
                // under, so a later SIGHUP cannot change how the worker applies
                // it.
                let result = expiry_cache::try_consume_grace(
                    username_str,
                    now,
                    auth_event::EventFlags::for_admission(lockout_runtime_active),
                );
                // Both LWLocks are released by now; the warning is emitted at
                // the single exit point below.
                queue_warn |= result.queue_warn;

                match result.outcome {
                    expiry_cache::GraceOutcome::Consumed => grace_consumed = true,
                    expiry_cache::GraceOutcome::NotNeeded => {}
                    expiry_cache::GraceOutcome::NoGrace => password_expired = true,
                    // The decrement could not be recorded. The grace login
                    // is not counted and expiry enforcement is paused for this
                    // connection rather than turned into a rejection: a journal
                    // that cannot be written is not evidence about this user's
                    // password. `event_lost` keeps the success event from being
                    // queued too, and drives the warning below.
                    expiry_cache::GraceOutcome::Unavailable => event_lost = true,
                }
            }
            // A concurrent cache degradation disables expiry for this login;
            // it does not block unrelated PostgreSQL access.
            expiry_cache::ExpiryDecision::CacheUnavailable => {}
        }
    }

    // A grace consumption already queued its own event, which carries the same
    // cleanup intent, so a second success event is unnecessary.
    //
    // `!event_lost && !password_expired` is essential, not an optimization:
    // this connection is about to be refused, and a success event would clear
    // its failed-login state for a login that was never admitted.
    if !event_lost && !password_expired && lockout_runtime_active && !grace_consumed {
        if !auth_event::enqueue(
            username_str,
            auth_event::EVENT_KIND_SUCCESS,
            auth_event::EventFlags::for_admission(lockout_runtime_active),
        )
        .is_durable()
        {
            // The success could not be recorded durably, so failed-attempt
            // cleanup for this user did not happen. That is a *pause*, not a
            // reason to refuse credentials PostgreSQL accepted: the enqueue
            // path has published the degradation, the worker rehydrates from
            // `login_attempts` once storage is healthy again, and the login
            // proceeds meanwhile.
            event_lost = true;
        }
    }

    // ---- Single exit point, after every lock has been released -----------
    // Logging first: these allocate and format, so they must not run before
    // every LWLock above has been dropped -- which it has, since each of them
    // is scoped inside the function that took it.
    if queue_warn {
        if event_lost {
            auth_event::emit_journal_failure_warning();
        } else {
            auth_event::emit_queue_full_warning();
        }
    }
    report_degraded(pause_reason, event_lost);

    // The only login this extension still refuses is one its *healthy* policy
    // refuses: an expired password with no grace login left. There is no
    // "internally unavailable" rejection any more -- an extension-internal
    // failure pauses enforcement instead of denying access, so a journal, queue
    // or worker problem can never become a cluster-wide login outage.
    if password_expired {
        password_profile_raise_expired_error(username_ptr);
    }
}

/// Emits the rate-controlled degraded-state warning, if anything is degraded.
///
/// Must be called only where every LWLock is released: it allocates and logs.
/// `event_lost` covers a degradation that appeared *after* the health gate was
/// read, which has no `PausedReason` of its own yet -- the shared marker set by
/// the enqueue path names it.
fn report_degraded(pause_reason: Option<worker_health::PausedReason>, event_lost: bool) {
    if let Some(reason) = pause_reason {
        worker_health::warn_enforcement_paused(reason);
    } else if event_lost {
        worker_health::warn_enforcement_paused(
            enforcement_pause_reason().unwrap_or(worker_health::PausedReason::DurableRecording),
        );
    }
}

fn register_client_auth_hook() {
    CLIENT_AUTH_HOOK_INIT.call_once(|| {
        unsafe {
            PREV_CLIENT_AUTH_HOOK =
                password_profile_register_client_auth_hook(Some(client_auth_hook));
        }
        pgrx::log!("ClientAuthentication_hook registered");
    });
}

#[no_mangle]
pub unsafe extern "C-unwind" fn _PG_init() {
    pgrx::warning!("password_profile_pure: _PG_init called - extension loading");

    static mut PREV_SHMEM_REQUEST_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_request_hook_impl() {
        if let Some(prev) = PREV_SHMEM_REQUEST_HOOK {
            prev();
        }
        pg_sys::RequestAddinShmemSpace(lock_cache::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(auth_event::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(expiry_cache::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(bypass_cache::shared_memory_bytes());
        pg_sys::RequestAddinShmemSpace(worker_health::shared_memory_bytes());
        request_named_lwlock_tranche();
    }

    PREV_SHMEM_REQUEST_HOOK = pg_sys::shmem_request_hook;
    pg_sys::shmem_request_hook = Some(shmem_request_hook_impl);

    static mut PREV_SHMEM_STARTUP_HOOK: Option<unsafe extern "C-unwind" fn()> = None;

    unsafe extern "C-unwind" fn shmem_startup_hook_impl() {
        if let Some(prev) = PREV_SHMEM_STARTUP_HOOK {
            prev();
        }
        init_named_lwlock_tranche();
        lock_cache::init();
        auth_event::init();
        expiry_cache::init();
        bypass_cache::init();
        // Worker liveness is separate shared state from cache readiness: a
        // cache can hold a complete, correct entry set while no worker exists
        // to maintain it. See `worker_health`.
        worker_health::init();
    }

    PREV_SHMEM_STARTUP_HOOK = pg_sys::shmem_startup_hook;
    pg_sys::shmem_startup_hook = Some(shmem_startup_hook_impl);

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.min_length",
        c"Minimum password length",
        c"Minimum characters required",
        &PASSWORD_MIN_LENGTH,
        1,
        128,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_uppercase",
        c"Require at least one uppercase letter",
        c"Password must contain A-Z",
        &REQUIRE_UPPERCASE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_lowercase",
        c"Require at least one lowercase letter",
        c"Password must contain a-z",
        &REQUIRE_LOWERCASE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_digit",
        c"Require at least one digit",
        c"Password must contain 0-9",
        &REQUIRE_DIGIT,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.require_special",
        c"Require at least one special character",
        c"Password must contain special chars",
        &REQUIRE_SPECIAL,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.prevent_username",
        c"Prevent password from containing username",
        c"Username cannot be part of password",
        &PREVENT_USERNAME,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_history_count",
        c"Number of previous passwords to check (0=disabled)",
        c"Prevent reuse of last N passwords. Set to 0 to disable history checking.",
        &PASSWORD_HISTORY_COUNT,
        0,
        24,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_reuse_days",
        c"Days before password can be reused (0=disabled)",
        c"Prevent reuse within time window. Set to 0 to disable time-based checking.",
        &PASSWORD_REUSE_DAYS,
        0,
        3650,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_expiry_days",
        c"Days before password expires (0=disabled)",
        c"Force password change after N days. Set to 0 to disable expiration.",
        &PASSWORD_EXPIRY_DAYS,
        0,
        3650,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.password_grace_logins",
        c"Grace logins after expiry",
        c"Number of logins allowed after expiry",
        &PASSWORD_GRACE_LOGINS,
        0,
        10,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.failed_login_max",
        c"Maximum failed login attempts",
        c"Lock account after this many failures",
        &FAILED_LOGIN_MAX,
        1,
        100,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.lockout_minutes",
        c"Account lockout duration (minutes)",
        c"Minutes to lock account after max failures. Must be at least 1 minute.",
        &LOCKOUT_MINUTES,
        1,
        1440,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_int_guc(
        c"password_profile.bcrypt_cost",
        c"bcrypt hashing cost factor (4-31, default 10)",
        c"Higher = more secure but slower. Cost 10 = ~70ms, Cost 12 = ~300ms, Cost 8 = ~20ms. Adjust based on hardware capabilities.",
        &BCRYPT_COST,
        4,
        31,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.lockout_enforcement",
        c"Enable password_profile brute-force counting and account lockout enforcement",
        c"When off, password_profile performs no login-time lockout processing and does not enqueue auth events; PostgreSQL native authentication, password complexity, history, blacklist and expiry rules are unaffected. Intended as an explicit bootstrap/emergency switch. Requires a configuration reload (SIGHUP); ordinary users cannot change it.",
        &LOCKOUT_ENFORCEMENT,
        pgrx::GucContext::Sighup,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.expiry_enforcement",
        c"Enable password_profile login-time password expiry and grace-login enforcement",
        c"When off, password_profile performs no login-time expiry or grace processing and expiry-cache health alone cannot refuse a connection. Password complexity, history, blacklist validation and PostgreSQL native authentication are unaffected, and account lockout is controlled separately by password_profile.lockout_enforcement. Requires a configuration reload (SIGHUP); ordinary users cannot change it.",
        &EXPIRY_ENFORCEMENT,
        pgrx::GucContext::Sighup,
        pgrx::GucFlags::default(),
    );

    pgrx::GucRegistry::define_bool_guc(
        c"password_profile.bypass_password_profile",
        c"Bypass all password profile checks for this user",
        c"Set to true to exempt a user from password validation, history, expiry, and lockout checks. Use with ALTER USER username SET password_profile.bypass_password_profile = true;",
        &BYPASS_PASSWORD_PROFILE,
        pgrx::GucContext::Suset,
        pgrx::GucFlags::default(),
    );

    BackgroundWorkerBuilder::new("password_profile_auth_event_consumer")
        .set_function("auth_event_consumer_main")
        .set_library("password_profile")
        .set_argument(None::<i32>.into_datum())
        .set_restart_time(Some(Duration::from_secs(1)))
        .enable_spi_access()
        .load();
    pgrx::info!("password_profile: auth event consumer background worker registered");

    pgrx::log!("password_profile: Registering hooks...");
    unsafe {
        register_password_check_hook();
        pgrx::log!("password_profile: Password check hook registered");
        // Registered exactly once, alongside the other hooks: shared-memory
        // cache updates are deferred to transaction commit from here on.
        pending_cache_op::register_callbacks();
        pgrx::log!("password_profile: Transaction callbacks registered");
    }
    register_client_auth_hook();

    pgrx::log!("password_profile initialized with all features");
}

fn is_hash_like(password: &str) -> bool {
    if password.is_empty() {
        return false;
    }

    let len = password.len();
    let lower = password.to_lowercase();

    if len == 35 && lower.starts_with("md5") {
        let hex_part = &password[3..];
        if hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }

    if (lower.starts_with("$2a$")
        || lower.starts_with("$2b$")
        || lower.starts_with("$2x$")
        || lower.starts_with("$2y$"))
        && len >= 20
    {
        return true;
    }

    if lower.starts_with("$argon2i$")
        || lower.starts_with("$argon2id$")
        || lower.starts_with("$argon2d$")
    {
        return true;
    }

    // 4. SCRAM-SHA-256 format: SCRAM-SHA-256$4096:salt$hash:proof
    if lower.starts_with("scram-sha-256$") {
        return true;
    }

    // 5. PBKDF2 formats: $pbkdf2-sha256$29000$...
    if lower.starts_with("$pbkdf2-") {
        return true;
    }

    // 6. Django/Werkzeug formats: pbkdf2:sha256:... or sha1$salt$hash
    if lower.starts_with("pbkdf2:") || lower.starts_with("sha1$") || lower.starts_with("sha256$") {
        return true;
    }

    // 7. SHA hex digests: SHA-1 (40 chars), SHA-256 (64 chars), SHA-512 (128 chars)
    if (len == 40 || len == 64 || len == 128) && password.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // 9. Generic $ delimited hash: starts with $, long, has >= 3 $ separators
    if password.starts_with('$') && len > 50 && password.matches('$').count() >= 3 {
        return true;
    }

    // 10. crypt(3) formats: $1$ (MD5), $5$ (SHA-256), $6$ (SHA-512)
    if (lower.starts_with("$1$") || lower.starts_with("$5$") || lower.starts_with("$6$"))
        && len > 20
    {
        return true;
    }

    false
}

/// Validation-only password check.
///
/// Performs every enabled policy check and has **no side effects**: it never
/// inserts, updates or deletes `password_profile.password_history` or
/// `password_profile.password_expiry`. Persistence is the exclusive job of
/// [`record_password_change_internal`].
///
/// Returns [`ValidationOutcome::Bypassed`] when the target role is exempt, so
/// the caller can skip recording for it.
fn validate_password(
    username: &str,
    password: &str,
) -> Result<ValidationOutcome, Box<dyn std::error::Error>> {
    // Check if user has bypass enabled (per-user setting)
    let bypass_args = [text_arg(username)];
    let bypass_enabled = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT EXISTS(
                SELECT 1
                FROM pg_user, unnest(useconfig) AS cfg
                WHERE usename = $1
                  AND cfg = 'password_profile.bypass_password_profile=true'
            )),
            false
        )",
        &bypass_args,
    )?
    .unwrap_or(false);

    if bypass_enabled {
        return Ok(ValidationOutcome::Bypassed);
    }

    if is_hash_like(password) {
        return Err(
            "Security violation: Password looks like a precomputed hash. \
             Plain text passwords cannot be in hash format (bcrypt, MD5, SCRAM, etc.)"
                .into(),
        );
    }

    let user_args = [text_arg(username)];

    let min_length = Spi::get_one_with_args::<i32>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::int
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.min_length=%'
             LIMIT 1),
            current_setting('password_profile.min_length', false)::int
        )",
        &user_args,
    )?
    .unwrap_or(PASSWORD_MIN_LENGTH.get());

    let require_uppercase = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::bool
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.require_uppercase=%'
             LIMIT 1),
            current_setting('password_profile.require_uppercase', false)::bool
        )",
        &user_args,
    )?
    .unwrap_or(REQUIRE_UPPERCASE.get());

    let require_lowercase = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::bool
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.require_lowercase=%'
             LIMIT 1),
            current_setting('password_profile.require_lowercase', false)::bool
        )",
        &user_args,
    )?
    .unwrap_or(REQUIRE_LOWERCASE.get());

    let require_digit = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::bool
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.require_digit=%'
             LIMIT 1),
            current_setting('password_profile.require_digit', false)::bool
        )",
        &user_args,
    )?
    .unwrap_or(REQUIRE_DIGIT.get());

    let require_special = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::bool
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.require_special=%'
             LIMIT 1),
            current_setting('password_profile.require_special', false)::bool
        )",
        &user_args,
    )?
    .unwrap_or(REQUIRE_SPECIAL.get());

    let prevent_username = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT split_part(config, '=', 2)::bool
             FROM pg_user, unnest(useconfig) AS config
             WHERE usename = $1 
               AND config LIKE 'password_profile.prevent_username=%'
             LIMIT 1),
            current_setting('password_profile.prevent_username', false)::bool
        )",
        &user_args,
    )?
    .unwrap_or(PREVENT_USERNAME.get());

    if password.len() < min_length as usize {
        return Err("Password too short".into());
    }

    if require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err("Password must contain at least one uppercase letter".into());
    }

    if require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err("Password must contain at least one lowercase letter".into());
    }

    if require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".into());
    }

    if require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one special character".into());
    }

    if prevent_username && !username.is_empty() {
        let pwd_lower = password.to_lowercase();
        let user_lower = username.to_lowercase();
        if pwd_lower.contains(&user_lower) {
            return Err("Password cannot contain username".into());
        }
    }

    // A failed lookup propagates instead of being read as "not blacklisted",
    // so an unreadable blacklist table rejects the password change rather than
    // silently accepting it.
    if blacklist::contains(password)? {
        return Err("Password is in blacklist (too common)".into());
    }

    if PASSWORD_HISTORY_COUNT.get() > 0 {
        let history_count = PASSWORD_HISTORY_COUNT.get();

        let args = [text_arg(username), int4_arg(history_count)];
        const HISTORY_QUERY: &str = "
            SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[])
            FROM (
                SELECT password_hash
                FROM password_profile.password_history
                WHERE username = $1
                ORDER BY changed_at DESC
                LIMIT $2
            ) t
        ";

        if let Some(hashes) = Spi::get_one_with_args::<Vec<String>>(HISTORY_QUERY, &args)? {
            for stored_hash in hashes {
                // Same bcrypt-or-legacy-MD5 comparison the recorder uses.
                if stored_hash_matches(password, &stored_hash) {
                    return Err(format!(
                        "Password was used recently. Cannot reuse last {} passwords.",
                        history_count
                    )
                    .into());
                }
            }
        }
    }

    if PASSWORD_REUSE_DAYS.get() > 0 {
        let reuse_days = PASSWORD_REUSE_DAYS.get();

        let args = [text_arg(username), int4_arg(reuse_days)];
        const REUSE_QUERY: &str = "
            SELECT COALESCE(array_agg(password_hash), ARRAY[]::text[])
            FROM password_profile.password_history
            WHERE username = $1
              AND changed_at > now() - ($2 || ' days')::interval
        ";

        if let Some(hashes) = Spi::get_one_with_args::<Vec<String>>(REUSE_QUERY, &args)? {
            for stored_hash in hashes {
                // bcrypt, or a legacy 32-char MD5 digest from older rows.
                if stored_hash_matches(password, &stored_hash) {
                    return Err(format!("Password was used within last {} days", reuse_days).into());
                }
            }
        }
    }

    const HOOK_EXISTS_QUERY: &str = "
        SELECT EXISTS(
            SELECT 1 FROM pg_proc p
            JOIN pg_namespace n ON p.pronamespace = n.oid
            WHERE n.nspname = 'password_profile'
              AND p.proname = 'custom_password_check'
        )
    ";

    if Spi::get_one::<bool>(HOOK_EXISTS_QUERY)?.unwrap_or(false) {
        let hook_args = [text_arg(username), text_arg(password)];
        let hook_query = "SELECT password_profile.custom_password_check($1, $2)";

        if let Some(msg) = Spi::get_one_with_args::<String>(hook_query, &hook_args)? {
            if !msg.is_empty() && msg != "OK" {
                return Err(msg.into());
            }
        }
    }

    Ok(ValidationOutcome::Accepted)
}

/// Validates `password` for `username` without changing anything.
///
/// Calling this repeatedly is safe: it never writes `password_history`,
/// `password_expiry` or the PostgreSQL role password. It previously inserted a
/// history row as a side effect, which polluted history with candidates that
/// were never actually set and made repeated calls behave differently from the
/// first.
#[pg_extern]
fn check_password(username: &str, password: &str) -> Result<String, Box<dyn std::error::Error>> {
    match validate_password(username, password)? {
        ValidationOutcome::Bypassed => Ok("Password accepted (bypassed)".to_string()),
        ValidationOutcome::Accepted => Ok("Password accepted".to_string()),
    }
}

#[pg_extern]
fn init_login_attempts_table() -> Result<String, Box<dyn std::error::Error>> {
    let complete = Spi::get_one::<bool>(
        "SELECT to_regclass('password_profile.login_attempts') IS NOT NULL
            AND to_regclass('password_profile.password_history') IS NOT NULL
            AND to_regclass('password_profile.password_expiry') IS NOT NULL
            AND to_regclass('password_profile.blacklist') IS NOT NULL",
    )?
    .unwrap_or(false);

    if !complete {
        return Err(
            "password_profile schema is incomplete; reinstall the extension instead of creating tables manually"
                .into(),
        );
    }

    Ok("Extension tables are already initialized".to_string())
}

// ====================================================================================
// Per-user serialization of `password_profile.login_attempts` transitions.
//
// `record_failed_login` and both modes of `clear_login_attempts_internal` decide
// what the authoritative row should look like and then push that decision into
// shared memory. Without serialization those decisions interleave: a successful
// login can read "no active lockout", a concurrent failure can then commit one,
// and the success path still applies its now-stale decision to the cache.
//
// The lock is a *transaction-scoped* advisory lock, so PostgreSQL releases it at
// commit or abort -- there is nothing to leak on an error path, and no session
// lock can outlive a backend that died mid-decision.
// ====================================================================================

/// Advisory-lock namespace (the first `pg_advisory_xact_lock` key) for
/// `login_attempts` serialization.
///
/// Using the two-argument form keeps password_profile out of the single-`bigint`
/// advisory space that applications commonly use, so an unrelated
/// `pg_advisory_xact_lock(n)` elsewhere can never collide with ours.
const LOGIN_ATTEMPT_LOCK_NAMESPACE: i32 = 0x7057_1EAF_u32 as i32;

/// Advisory-lock namespace for serializing password-history recording.
///
/// Deliberately different from [`LOGIN_ATTEMPT_LOCK_NAMESPACE`]: recording a
/// password change and counting a failed login are independent operations and
/// must not block each other, even for the same username.
const PASSWORD_HISTORY_LOCK_NAMESPACE: i32 = 0x7057_2D15_u32 as i32;

/// Fixed SipHash-1-3 seeds for deriving the per-username advisory key.
///
/// These must stay constant forever: every backend and the background worker
/// derive the key independently, so changing a seed would let two processes
/// serialize on different keys and silently lose mutual exclusion. The key is
/// not a secret, only an agreement.
const LOGIN_ATTEMPT_LOCK_K0: u64 = 0x7061_7373_776F_7264; // "password"
const LOGIN_ATTEMPT_LOCK_K1: u64 = 0x5F70_726F_6669_6C65; // "_profile"

/// The single statement every path uses to take a per-user lock, so the
/// key derivation and the lock mode cannot drift apart between namespaces.
const LOGIN_ATTEMPT_LOCK_SQL: &str = "SELECT pg_advisory_xact_lock($1, $2)";

/// Derives the per-username advisory key, shared by every namespace above.
///
/// Deterministic across backends and restarts. A hash collision serializes two
/// unrelated usernames against each other -- a small, bounded loss of
/// concurrency -- but can never produce incorrect state, because every holder
/// still re-reads the authoritative row for its own username under the lock.
fn username_advisory_key(username: &str) -> i32 {
    let mut hasher = SipHasher13::new_with_keys(LOGIN_ATTEMPT_LOCK_K0, LOGIN_ATTEMPT_LOCK_K1);
    hasher.write(username.as_bytes());
    hasher.finish() as u32 as i32
}

/// Serializes all `login_attempts` state transitions for `username` for the rest
/// of the current transaction.
///
/// Must be called *before* the authoritative row is read or modified, and always
/// before the shared cache LWLock is taken. It performs SPI, so it must never be
/// called while a cache LWLock is held -- the lock order is
/// `advisory lock -> login_attempts row/table -> LOCK_CACHE_LWLOCK`.
fn lock_login_attempts_for(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    Spi::run_with_args(
        LOGIN_ATTEMPT_LOCK_SQL,
        &[
            int4_arg(LOGIN_ATTEMPT_LOCK_NAMESPACE),
            int4_arg(username_advisory_key(username)),
        ],
    )?;
    Ok(())
}

/// Serializes password-history recording for `username` for the rest of the
/// current transaction.
///
/// Taken before the latest history row is read, so two concurrent recorders for
/// the same username cannot both decide "no matching latest entry" and each
/// insert a row. PostgreSQL releases it at commit or abort, so nothing leaks on
/// an error path. Different usernames hash to different keys and do not
/// serialize against each other.
fn lock_password_history_for(username: &str) -> Result<(), Box<dyn std::error::Error>> {
    Spi::run_with_args(
        LOGIN_ATTEMPT_LOCK_SQL,
        &[
            int4_arg(PASSWORD_HISTORY_LOCK_NAMESPACE),
            int4_arg(username_advisory_key(username)),
        ],
    )?;
    Ok(())
}

/// True when `stored` represents `password`.
///
/// The single place that compares a candidate against a stored history entry,
/// so validation and recording cannot disagree about what "the same password"
/// means. Accepts a bcrypt digest, or a legacy 32-character hex MD5 digest for
/// rows written by older versions.
fn stored_hash_matches(password: &str, stored: &str) -> bool {
    if verify(password, stored).unwrap_or(false) {
        return true;
    }

    if stored.len() == 32 && stored.chars().all(|c| c.is_ascii_hexdigit()) {
        let pwd_hash_md5 = format!("{:x}", md5::compute(password.as_bytes()));
        return stored == pwd_hash_md5;
    }

    false
}

/// Whether a password change should leave a history row at all.
///
/// Count-based history and time-based reuse both read
/// `password_profile.password_history`, so a row is required when *either* is
/// enabled. The previous code recorded only when `password_history_count > 0`,
/// which silently disabled `password_reuse_days` enforcement whenever
/// count-based history was turned off.
fn password_history_recording_enabled() -> bool {
    PASSWORD_HISTORY_COUNT.get() > 0 || PASSWORD_REUSE_DAYS.get() > 0
}

/// Outcome of validating a candidate password.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ValidationOutcome {
    /// Passed every enabled policy check.
    Accepted,
    /// The target role has `password_profile.bypass_password_profile = true`;
    /// no policy was evaluated and nothing may be recorded for it.
    Bypassed,
}

/// Whether brute-force counting and lockout enforcement are enabled.
pub(crate) fn lockout_enforcement_enabled() -> bool {
    LOCKOUT_ENFORCEMENT.get()
}

/// The single canonical definition of "login-time expiry enforcement is active".
///
/// Two settings have to agree before the expiry cache means anything:
/// `password_profile.expiry_enforcement` must be on **and**
/// `password_profile.password_expiry_days` must be greater than zero. With
/// `password_expiry_days = 0` no expiry row is written and nothing is enforced,
/// so the expiry cache's health is irrelevant.
///
/// Every place that decides whether expiry-cache health is *required* calls
/// this: the authentication hook, the worker's initial hydration gate, the
/// worker's event-consumption gate (which re-reads it after every SIGHUP), the
/// bypass-cache requirement, and the operational messages whose meaning depends
/// on it. An earlier revision let the hook and the worker disagree -- the hook
/// applied both conditions while the worker applied only the boolean -- so with
/// `expiry_enforcement = on`, `password_expiry_days = 0` and an unhealthy
/// expiry cache the worker blocked on a cache the hook was already ignoring,
/// and failed-login and lockout events stopped being processed.
pub(crate) fn expiry_login_enforcement_active() -> bool {
    EXPIRY_ENFORCEMENT.get() && PASSWORD_EXPIRY_DAYS.get() > 0
}

/// The configured `password_profile.password_expiry_days`, for reporting only.
pub(crate) fn password_expiry_days() -> i32 {
    PASSWORD_EXPIRY_DAYS.get()
}

/// The raw `password_profile.expiry_enforcement` switch, for reporting only.
///
/// Never use this to decide whether expiry-cache health is required -- that is
/// [`expiry_login_enforcement_active`]. This exists so an operator-facing
/// message can distinguish "the switch is off" from "the switch is on but
/// `password_expiry_days = 0`".
pub(crate) fn expiry_enforcement_switch_on() -> bool {
    EXPIRY_ENFORCEMENT.get()
}

/// Recovers a structurally corrupt in-memory auth queue without restarting
/// PostgreSQL. Pending events remain in the verified durable journal and are
/// replayed by the worker after it observes the reset.
#[pg_extern]
fn recover_auth_event_queue() -> Result<String, Box<dyn std::error::Error>> {
    if !unsafe { pg_sys::superuser() } {
        return Err(
            "permission denied: superuser is required to recover the auth event queue".into(),
        );
    }
    if unsafe { pg_sys::RecoveryInProgress() } {
        return Err("auth event queue recovery must be run on the writable primary".into());
    }
    if lockout_enforcement_enabled() || expiry_enforcement_switch_on() {
        return Err(
            "set password_profile.lockout_enforcement=off and password_profile.expiry_enforcement=off, reload the configuration, then retry"
                .into(),
        );
    }

    match auth_event::recover_corrupt_ring().map_err(|e| match e {
        // Corruption is never repaired here and the files are never deleted or
        // overwritten: they are the evidence. Say plainly what the operator has
        // to do, because the previous message left them with an error and no
        // next step.
        auth_journal::JournalError::Corrupt(reason) => Box::<dyn std::error::Error>::from(format!(
            "the durable auth event journal still contains a record that cannot be trusted \
             ({reason}); no reset was performed and nothing was deleted. Stop PostgreSQL, move \
             (do not delete) <PGDATA>/password_profile_auth_events.processing and \
             <PGDATA>/password_profile_auth_events.active aside for analysis, start PostgreSQL, \
             and retry. Authentication events recorded in those files will not be applied."
        )),
        other => Box::<dyn std::error::Error>::from(other.to_string()),
    })? {
        true => Ok(
            "Auth event queue recovered; keep both enforcement switches off until auth_event_queue_state is 0 and pending journal events have drained"
                .to_string(),
        ),
        false => Ok("Auth event queue is not corrupt; no reset was performed".to_string()),
    }
}

/// Persists one grace-login consumption that the authentication hook already
/// admitted.
///
/// # Stale generations
/// `generation` is the `last_changed` value the shared cache held when the
/// grace was taken. A password change rewrites `last_changed` and resets
/// `grace_logins_remaining` in the same statement, so a generation mismatch
/// means this event belongs to a password that no longer exists. Such an event
/// is acknowledged without touching the new row -- it must never decrement a
/// freshly reset allowance.
///
/// # Contradiction is not guessed away
/// If the generation still matches but the row says there is no grace left, the
/// authoritative table contradicts a decision the hook already admitted. That
/// is not silently acknowledged: the error propagates, the transaction rolls
/// back, the event stays claimable and the caller marks enforcement unhealthy.
fn persist_grace_consumption(
    username: &str,
    generation: pg_sys::TimestampTz,
) -> Result<(), Box<dyn std::error::Error>> {
    // Same per-user namespace the password recorder uses, so a concurrent
    // password change and a grace persistence cannot interleave.
    lock_password_history_for(username)?;

    // One row always, so a missing row is `None` rather than a zero-row error.
    let generation_ts = TimestampWithTimeZone::try_from(generation)
        .map_err(|e| format!("password_profile: invalid password generation: {e:?}"))?;

    let current = Spi::get_one_with_args::<i64>(
        "SELECT (SELECT CASE
                    WHEN last_changed IS DISTINCT FROM $2 THEN -1
                    ELSE grace_logins_remaining
                 END
                 FROM password_profile.password_expiry
                 WHERE username = $1)",
        &[text_arg(username), unsafe {
            pgrx::datum::DatumWithOid::new(generation_ts, pg_sys::TIMESTAMPTZOID)
        }],
    )?;

    match current {
        // Row gone, or the password was changed since: stale event, nothing to
        // do. Acknowledged by the caller's commit.
        None | Some(-1) => Ok(()),
        Some(remaining) if remaining > 0 => spi_run_expect_one_row(
            "UPDATE password_profile.password_expiry
                    SET grace_logins_remaining = grace_logins_remaining - 1
                  WHERE username = $1
                    AND last_changed = $2
                    AND grace_logins_remaining > 0",
            username,
            generation,
        ),
        Some(_) => Err(
            "password_profile: grace login was admitted but the authoritative row has none left; \
             refusing to acknowledge the event"
                .into(),
        ),
    }
}

/// Runs the grace decrement and verifies exactly one row changed.
fn spi_run_expect_one_row(
    sql: &str,
    username: &str,
    generation: pg_sys::TimestampTz,
) -> Result<(), Box<dyn std::error::Error>> {
    // Converted before the SPI closure so the closure's error type stays
    // `SpiError`; an out-of-range generation is a caller error, not an SPI one.
    let generation_ts = TimestampWithTimeZone::try_from(generation)
        .map_err(|e| format!("password_profile: invalid password generation: {e:?}"))?;
    let statement = format!("{sql} RETURNING username");

    let updated = Spi::connect_mut(|client| -> pgrx::spi::Result<usize> {
        Ok(client
            .update(
                statement.as_str(),
                None,
                &[text_arg(username), unsafe {
                    pgrx::datum::DatumWithOid::new(generation_ts, pg_sys::TIMESTAMPTZOID)
                }],
            )?
            .len())
    })?;

    if updated == 1 {
        Ok(())
    } else {
        Err(format!(
            "password_profile: grace decrement affected {updated} rows for one username; \
             refusing to acknowledge the event"
        )
        .into())
    }
}

/// Records a password change for `username` exactly once.
///
/// This is the **only** path that writes `password_profile.password_history` or
/// `password_profile.password_expiry`. Both the password hook and the public
/// `record_password_change()` go through it, which is what makes recording
/// single and idempotent.
///
/// # Idempotency
/// The latest history row is read under a transaction-scoped per-user advisory
/// lock. If it already represents this password, no second row is written and
/// no second bcrypt hash is computed. Expiry metadata is still refreshed,
/// because a repeated change is still a change of `last_changed`.
///
/// # Atomicity
/// Everything runs in the caller's transaction, so a rollback -- including a
/// savepoint rollback -- discards the history and expiry writes together with
/// the role change that caused them.
///
/// # Errors
/// bcrypt and SPI failures propagate. The caller must reject the password
/// change rather than allow a role password to be set without its history row.
///
/// Returns `true` when a new history row was inserted.
fn record_password_change_internal(
    username: &str,
    password: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Serialize with any concurrent recorder for this username before reading
    // the latest row, so the read-then-insert below cannot interleave.
    lock_password_history_for(username)?;

    let mut inserted = false;

    if password_history_recording_enabled() {
        // Scalar subquery, so the statement always returns exactly one row and
        // an absent history yields SQL NULL -> `Ok(None)`. A bare
        // `SELECT ... LIMIT 1` returns zero rows for a first-time password,
        // which pgrx surfaces as `SpiError::InvalidPosition` rather than `None`.
        let latest = Spi::get_one_with_args::<String>(
            "SELECT (SELECT password_hash
                       FROM password_profile.password_history
                      WHERE username = $1
                      ORDER BY changed_at DESC, id DESC
                      LIMIT 1)",
            &[text_arg(username)],
        )?;

        let already_recorded = latest
            .as_deref()
            .is_some_and(|stored| stored_hash_matches(password, stored));

        if !already_recorded {
            // Hashed exactly once, and only when a row is actually written.
            let cost = BCRYPT_COST.get().clamp(4, 31) as u32;
            let pwd_hash =
                hash(password, cost).map_err(|e| format!("Failed to hash password: {}", e))?;

            // Errors propagate: a role password must never be set without its
            // history row. The previous code discarded this error.
            Spi::run_with_args(
                "INSERT INTO password_profile.password_history (username, password_hash, changed_at)
                 VALUES ($1, $2, now())",
                &[text_arg(username), text_arg(&pwd_hash)],
            )?;
            inserted = true;
        }
    }

    let expiry_days = PASSWORD_EXPIRY_DAYS.get();
    let encoded = encode_username(username);

    if expiry_days > 0 {
        let grace_logins = PASSWORD_GRACE_LOGINS.get();

        // `RETURNING` gives the exact committed values back, so the cache is
        // staged from the authoritative row rather than from a second,
        // slightly later clock read. `last_changed` is the password
        // generation.
        //
        // # Why not `now()`
        // `now()` is the *transaction start* timestamp, which is not a usable
        // generation in two ways that both let a stale grace event decrement a
        // freshly reset allowance:
        //
        // * Two password changes in one transaction get the identical `now()`,
        //   so the second reset produces a generation equal to the first and a
        //   grace event queued against the first still matches.
        // * A transaction that began before another transaction's password
        //   change can commit after it and write an *older* `last_changed`,
        //   so a newer password ends up with an older generation.
        //
        // The generation is therefore computed in SQL as
        // `GREATEST(clock_timestamp(), previous last_changed + 1 microsecond)`.
        // `clock_timestamp()` is the real current time rather than the
        // transaction's, and the `GREATEST` floor makes the value strictly
        // greater than the previous one even when two changes land inside the
        // same microsecond. Correctness of the read depends on the per-user
        // advisory lock taken at the top of this function: no other transaction
        // can be writing this row while the statement runs, and a second change
        // in this transaction sees the first one's row through its own command
        // id. `must_change_by` is derived from that exact value -- not from a
        // separate clock read -- so the row is internally consistent.
        let written: Option<(TimestampWithTimeZone, TimestampWithTimeZone, i32)> =
            Spi::connect_mut(|client| -> pgrx::spi::Result<_> {
                let table = client.update(
                    "WITH gen AS (
                         SELECT GREATEST(
                                    clock_timestamp(),
                                    COALESCE(
                                        (SELECT last_changed
                                           FROM password_profile.password_expiry
                                          WHERE username = $1),
                                        '-infinity'::timestamptz
                                    ) + interval '1 microsecond'
                                ) AS ts
                     )
                     INSERT INTO password_profile.password_expiry
                         (username, last_changed, must_change_by, grace_logins_remaining)
                     SELECT $1, gen.ts, gen.ts + ($2 || ' days')::interval, $3 FROM gen
                     ON CONFLICT (username) DO UPDATE SET
                         last_changed = EXCLUDED.last_changed,
                         must_change_by = EXCLUDED.must_change_by,
                         grace_logins_remaining = EXCLUDED.grace_logins_remaining
                     RETURNING last_changed, must_change_by, grace_logins_remaining",
                    None,
                    &[
                        text_arg(username),
                        int4_arg(expiry_days),
                        int4_arg(grace_logins),
                    ],
                )?;
                let row = table.first();
                Ok(
                    match (
                        row.get::<TimestampWithTimeZone>(1)?,
                        row.get::<TimestampWithTimeZone>(2)?,
                        row.get::<i32>(3)?,
                    ) {
                        (Some(lc), Some(mcb), Some(g)) => Some((lc, mcb, g)),
                        _ => None,
                    },
                )
            })?;

        let Some((last_changed, must_change_by, grace)) = written else {
            return Err(
                "password_profile: password expiry row was not written; refusing the change".into(),
            );
        };

        // Staged, not applied: the expiry cache changes only when this
        // transaction commits, and a rollback -- including a savepoint
        // rollback -- leaves shared memory untouched.
        pending_cache_op::stage_expiry(
            encoded,
            pending_cache_op::ExpiryDecision::Set {
                must_change_by: must_change_by.into_inner(),
                generation: last_changed.into_inner(),
                grace_remaining: grace,
            },
        )?;
    } else {
        // Expiry disabled for this change: remove any stale metadata rather
        // than leaving a row that would still be enforced at login.
        Spi::run_with_args(
            "DELETE FROM password_profile.password_expiry WHERE username = $1",
            &[text_arg(username)],
        )?;
        pending_cache_op::stage_expiry(encoded, pending_cache_op::ExpiryDecision::Clear)?;
    }

    Ok(inserted)
}

/// What the automatic-clear path learned from the authoritative row, before any
/// interpretation.
struct ClearOutcome {
    /// Rows removed by the conditional (inactive/expired only) delete.
    deleted: usize,
    /// Rows still carrying `lockout_until > now()` afterwards.
    active: usize,
    /// The authoritative expiry of that row, carried as PostgreSQL's own
    /// `TimestampTz` -- never through text or a float epoch.
    active_until: Option<pg_sys::TimestampTz>,
}

#[pg_extern]
fn record_failed_login(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        return Ok("Skipped - no database context".to_string());
    }

    // Use Spi directly without connect_mut (already in SPI context when called from bg worker)
    let username_arg = [text_arg(username)];

    let is_super = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE((SELECT usesuper FROM pg_user WHERE usename = $1), false)",
        &username_arg,
    )?
    .unwrap_or(false);

    if is_super {
        return Ok("Superuser bypassed".to_string());
    }

    let bypass = Spi::get_one_with_args::<bool>(
        "SELECT COALESCE(
            (SELECT EXISTS(
                SELECT 1
                FROM pg_user, unnest(useconfig) AS cfg
                WHERE usename = $1
                  AND cfg = 'password_profile.bypass_password_profile=true'
            )),
            false
        )",
        &username_arg,
    )?
    .unwrap_or(false);

    if bypass {
        return Ok("Bypassed failed login tracking".to_string());
    }

    let lockout = Spi::get_one_with_args::<i32>(
        "SELECT COALESCE(
            (
                SELECT substring(cfg FROM 'password_profile\\.lockout_minutes=([0-9]+)')::int
                FROM unnest((SELECT useconfig FROM pg_user WHERE usename = $1)) AS cfg
                WHERE cfg LIKE 'password_profile.lockout_minutes=%'
            ),
            $2
        )",
        &[text_arg(username), int4_arg(LOCKOUT_MINUTES.get())],
    )?
    .unwrap_or(LOCKOUT_MINUTES.get());

    let max_fails_val = Spi::get_one_with_args::<i32>(
        "SELECT COALESCE(
            (
                SELECT substring(cfg FROM 'password_profile\\.failed_login_max=([0-9]+)')::int
                FROM unnest((SELECT useconfig FROM pg_user WHERE usename = $1)) AS cfg
                WHERE cfg LIKE 'password_profile.failed_login_max=%'
            ),
            $2
        )",
        &[text_arg(username), int4_arg(FAILED_LOGIN_MAX.get())],
    )?
    .unwrap_or(FAILED_LOGIN_MAX.get());

    // Serialize against the clear paths for this username before the first
    // modification of `login_attempts`. Everything above only read `pg_user`
    // configuration, so taking the lock here avoids locking for users that are
    // skipped as superusers or bypassed.
    lock_login_attempts_for(username)?;

    Spi::run_with_args(
        "UPDATE password_profile.login_attempts 
         SET fail_count = 0, lockout_until = NULL
         WHERE username = $1 AND lockout_until IS NOT NULL AND lockout_until <= now()",
        &username_arg,
    )?;

    Spi::run_with_args(
        "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail, lockout_until)
         VALUES ($1, 1, now(), NULL)
         ON CONFLICT (username) DO UPDATE SET
             fail_count = password_profile.login_attempts.fail_count + 1,
             last_fail = now(),
             lockout_until = CASE
                 WHEN password_profile.login_attempts.fail_count + 1 >= $2
                 THEN now() + ($3 || ' minutes')::interval
                 ELSE NULL
             END",
        &[text_arg(username), int4_arg(max_fails_val), int4_arg(lockout)],
    )?;

    // Derive the cache decision from the authoritative typed `lockout_until`
    // (no epoch rounding), then *stage* it. Shared memory is only touched by the
    // commit callback, still under the advisory lock taken above, so a rollback
    // of the statements above cannot leave a lockout in the cache that the
    // database never committed.
    //
    // The old `sync()` also deleted a row whose lockout had already expired.
    // That is unreachable from here: the reset `UPDATE` above already cleared
    // any expired lockout, and the `INSERT ... ON CONFLICT` either sets
    // `lockout_until = now() + interval` or leaves it NULL. A zero
    // `lockout_minutes` now leaves an immediately-expired row in place instead
    // of deleting it; the next failure's reset `UPDATE`, or an automatic clear,
    // removes it.
    let decision = lock_cache::decision_from_db(username)?;
    pending_cache_op::stage(encode_username(username), decision)?;

    Ok("Failed login recorded".to_string())
}
#[pg_extern]
fn clear_login_attempts(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Security check: Only superuser or the same user can clear attempts
    // Use single Spi::connect() to avoid nested SPI
    let current_user =
        Spi::get_one::<String>("SELECT current_user::text")?.ok_or("Failed to get current user")?;
    let is_superuser = Spi::get_one_with_args::<bool>(
        "SELECT usesuper FROM pg_user WHERE usename = $1",
        &[text_arg(&current_user)],
    )?
    .unwrap_or(false);

    if !is_superuser && current_user != username {
        return Err(format!(
            "Permission denied: Only superuser or user '{}' can clear their login attempts",
            username
        )
        .into());
    }

    clear_login_attempts_internal(username, true)?;
    Ok("Login attempts cleared".to_string())
}

/// Clears a user's failed-login state.
///
/// `force = true` is the administrative clear reached through the public
/// `clear_login_attempts()`: the row goes regardless of lockout state, and so
/// does the cache entry.
///
/// `force = false` is the automatic clear after a successful authentication.
/// The database is authoritative there: the cache entry may only be dropped
/// when the database agrees no active lockout remains. Previously this path
/// issued a conditional `DELETE` -- which correctly refuses to remove an active
/// lockout -- and then cleared the cache *unconditionally*, so a locked user
/// whose correct password arrived while the lockout was still live lost the
/// cache entry and could be admitted by the login hook.
///
/// Lock order: per-user transaction advisory lock -> `login_attempts` row ->
/// `LOCK_CACHE_LWLOCK`. All SPI finishes before the cache is touched, and
/// nothing fallible, allocating or logging is added after it.
fn clear_login_attempts_internal(
    username: &str,
    force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Serialize against `record_failed_login` and the other clear mode for this
    // username. Held for the rest of the transaction, released by PostgreSQL at
    // commit or abort.
    lock_login_attempts_for(username)?;

    if force {
        // Administrative clear: an active lockout is removed on purpose, so
        // there is no decision to make -- only a row-count sanity check.
        let deleted = Spi::connect_mut(|client| -> pgrx::spi::Result<usize> {
            Ok(client
                .update(
                    "DELETE FROM password_profile.login_attempts
                      WHERE username = $1
                     RETURNING username",
                    None,
                    &[text_arg(username)],
                )?
                .len())
        })?;

        if deleted > 1 {
            return Err(format!(
                "password_profile: forced clear affected {} login_attempts rows for one \
                 username; refusing to update the lock cache",
                deleted
            )
            .into());
        }

        // Staged, not applied: if this transaction rolls back, the row comes
        // back and the cache must still describe it.
        pending_cache_op::stage(
            encode_username(username),
            lock_cache::CacheDecision::ClearLock,
        )?;
        return Ok(());
    }

    // Automatic clear. One SPI connection, one transaction, so the delete and
    // the follow-up read agree with each other and with the advisory lock we
    // already hold.
    let outcome = Spi::connect_mut(|client| -> pgrx::spi::Result<ClearOutcome> {
        // Delete only an inactive or already-expired row. `RETURNING` turns
        // "affected zero rows" into a fact we can reason about instead of an
        // assumption -- zero rows means either "no row at all" or "still
        // locked", and those two demand opposite cache actions.
        let deleted = client
            .update(
                "DELETE FROM password_profile.login_attempts
                  WHERE username = $1
                    AND (lockout_until IS NULL OR lockout_until <= now())
                 RETURNING username",
                None,
                &[text_arg(username)],
            )?
            .len();

        if deleted > 0 {
            return Ok(ClearOutcome {
                deleted,
                active: 0,
                active_until: None,
            });
        }

        // Nothing was deleted. Ask the same transaction which of the two cases
        // this is. `FOR UPDATE` pins the row for the rest of the transaction,
        // and the typed `lockout_until` is carried out verbatim as a
        // `TimestampTz` -- no text, no float epoch arithmetic. The row limit of
        // 2 is deliberate: it lets an impossible duplicate be detected rather
        // than silently truncated.
        let rows = client.select(
            "SELECT lockout_until
               FROM password_profile.login_attempts
              WHERE username = $1 AND lockout_until > now()
              FOR UPDATE",
            Some(2),
            &[text_arg(username)],
        )?;

        let active = rows.len();
        let mut active_until = None;
        for row in rows {
            if let Some(ts) = row.get::<TimestampWithTimeZone>(1)? {
                active_until = Some(ts.into_inner());
            }
        }

        Ok(ClearOutcome {
            deleted,
            active,
            active_until,
        })
    })?;

    // `login_attempts.username` is the primary key, so a decision about one
    // username can never legitimately concern more than one deleted or one
    // current row. Anything else means the table is not what we think it is:
    // fail and leave the cache untouched rather than guess.
    let active_until = match (outcome.deleted, outcome.active, outcome.active_until) {
        // No row existed, or the inactive/expired row was removed.
        (0, 0, None) | (1, 0, None) => None,
        // The row survived the conditional delete because it is still locked.
        (0, 1, Some(expires_at)) => Some(expires_at),
        (deleted, active, _) => {
            return Err(format!(
                "password_profile: inconsistent login_attempts state for one username \
                 (deleted={}, active={}); refusing to update the lock cache",
                deleted, active
            )
            .into())
        }
    };

    // One shared helper decides, so this cannot drift from hydration or from
    // failed-login processing. The expiry is the exact authoritative
    // `TimestampTz`; an entry that expired between the read and here becomes
    // `ClearLock`.
    let decision = lock_cache::decision_for(active_until, unsafe { pg_sys::GetCurrentTimestamp() });

    // Staged, not applied: shared memory changes only once this transaction
    // commits, while the per-user advisory lock is still held.
    pending_cache_op::stage(encode_username(username), decision)?;

    Ok(())
}

fn expiry_decision_from_db(
    username: &str,
) -> Result<pending_cache_op::ExpiryDecision, Box<dyn std::error::Error>> {
    let row = Spi::connect(|client| -> pgrx::spi::Result<Option<_>> {
        // Scalar subqueries always return exactly one outer row. That keeps a
        // missing expiry row on the normal `None` path instead of asking pgrx
        // for the first tuple of an empty result set.
        let rows = client.select(
            "SELECT
                (SELECT must_change_by FROM password_profile.password_expiry WHERE username = $1),
                (SELECT last_changed FROM password_profile.password_expiry WHERE username = $1),
                (SELECT grace_logins_remaining FROM password_profile.password_expiry WHERE username = $1)",
            None,
            &[text_arg(username)],
        )?;
        let first = rows.first();
        Ok(
            match (
                first.get::<TimestampWithTimeZone>(1)?,
                first.get::<TimestampWithTimeZone>(2)?,
                first.get::<i32>(3)?,
            ) {
                (Some(must_change_by), Some(last_changed), Some(grace_remaining)) => Some((
                    must_change_by.into_inner(),
                    last_changed.into_inner(),
                    grace_remaining,
                )),
                _ => None,
            },
        )
    })?;

    Ok(match row {
        Some((must_change_by, generation, grace_remaining)) => {
            pending_cache_op::ExpiryDecision::Set {
                must_change_by,
                generation,
                grace_remaining,
            }
        }
        None => pending_cache_op::ExpiryDecision::Clear,
    })
}

fn lock_role_state_names(
    first: &str,
    second: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut names = vec![first];
    if let Some(second) = second.filter(|name| *name != first) {
        names.push(second);
    }
    names.sort_unstable();

    for name in &names {
        lock_login_attempts_for(name)?;
    }
    for name in &names {
        lock_password_history_for(name)?;
    }
    Ok(())
}

/// Moves password-profile state after a role rename.
///
/// Run in the same transaction, after PostgreSQL has renamed the role:
/// `BEGIN; ALTER ROLE old RENAME TO new; SELECT
/// password_profile.rename_role_state('old', 'new'); COMMIT;`
#[pg_extern]
fn rename_role_state(
    old_username: &str,
    new_username: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    unsafe { require_control_database() };
    if !unsafe { pg_sys::superuser() } {
        return Err("permission denied: superuser is required to move role state".into());
    }
    if old_username.is_empty() || new_username.is_empty() {
        return Err("role names must not be empty".into());
    }
    if old_username == new_username {
        return Ok("Role state unchanged".to_string());
    }

    let old_role_exists = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
        &[text_arg(old_username)],
    )?
    .unwrap_or(false);
    let new_role_exists = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
        &[text_arg(new_username)],
    )?
    .unwrap_or(false);
    if old_role_exists || !new_role_exists {
        return Err(
            "rename the PostgreSQL role first and call rename_role_state in the same transaction"
                .into(),
        );
    }

    lock_role_state_names(old_username, Some(new_username))?;

    let target_has_state = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS (SELECT 1 FROM password_profile.login_attempts WHERE username = $1)
             OR EXISTS (SELECT 1 FROM password_profile.password_history WHERE username = $1)
             OR EXISTS (SELECT 1 FROM password_profile.password_expiry WHERE username = $1)",
        &[text_arg(new_username)],
    )?
    .unwrap_or(false);
    if target_has_state {
        return Err("target role name already has password_profile state; remove it first".into());
    }

    for statement in [
        "UPDATE password_profile.login_attempts SET username = $2 WHERE username = $1",
        "UPDATE password_profile.password_history SET username = $2 WHERE username = $1",
        "UPDATE password_profile.password_expiry SET username = $2 WHERE username = $1",
    ] {
        Spi::run_with_args(statement, &[text_arg(old_username), text_arg(new_username)])?;
    }

    let new_lock = lock_cache::decision_from_db(new_username)?;
    let new_expiry = expiry_decision_from_db(new_username)?;
    pending_cache_op::stage_combined(
        encode_username(old_username),
        lock_cache::CacheDecision::ClearLock,
        pending_cache_op::ExpiryDecision::Clear,
    )?;
    pending_cache_op::stage_combined(encode_username(new_username), new_lock, new_expiry)?;

    Ok("Role state renamed".to_string())
}

/// Removes password-profile state after a role has been dropped.
#[pg_extern]
fn remove_role_state(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    unsafe { require_control_database() };
    if !unsafe { pg_sys::superuser() } {
        return Err("permission denied: superuser is required to remove role state".into());
    }
    if username.is_empty() {
        return Err("role name must not be empty".into());
    }
    if Spi::get_one_with_args::<bool>(
        "SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)",
        &[text_arg(username)],
    )?
    .unwrap_or(false)
    {
        return Err(
            "drop the PostgreSQL role first and call remove_role_state in the same transaction"
                .into(),
        );
    }

    lock_role_state_names(username, None)?;
    for statement in [
        "DELETE FROM password_profile.login_attempts WHERE username = $1",
        "DELETE FROM password_profile.password_history WHERE username = $1",
        "DELETE FROM password_profile.password_expiry WHERE username = $1",
    ] {
        Spi::run_with_args(statement, &[text_arg(username)])?;
    }

    pending_cache_op::stage_combined(
        encode_username(username),
        lock_cache::CacheDecision::ClearLock,
        pending_cache_op::ExpiryDecision::Clear,
    )?;

    Ok("Role state removed".to_string())
}

#[pg_extern]
fn is_user_locked(username: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let query = "
        SELECT 1 FROM password_profile.login_attempts 
        WHERE username = $1 AND lockout_until > now() LIMIT 1
    ";

    match Spi::get_one_with_args::<i32>(query, &[text_arg(username)]) {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(_) => Ok(false), // Table doesn't exist or other error
    }
}

#[pg_extern]
fn check_user_access(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // CRITICAL: Check database context before SPI operations
    let my_db_id = unsafe { std::ptr::addr_of!(pg_sys::MyDatabaseId).read() };
    if my_db_id == pg_sys::InvalidOid {
        pgrx::log!("password_profile: check_user_access skipped - no database context");
        return Ok("Access check skipped - no database context".to_string());
    }

    // First check lock cache (fast, no DB access needed)
    if let Some(seconds) = unsafe { lock_cache::remaining_seconds(username) } {
        if seconds > 0 {
            let minutes = seconds / 60;
            let secs = seconds % 60;
            return Err(format!(
                "Account locked! Please wait {} minute(s) and {} second(s). Too many failed login attempts.",
                minutes, secs
            )
            .into());
        }
    }

    // Check if locked and get remaining time
    let query = "
        SELECT EXTRACT(EPOCH FROM (lockout_until - now()))::int AS seconds_left
        FROM password_profile.login_attempts 
        WHERE username = $1 AND lockout_until > now()
    ";

    match Spi::get_one_with_args::<i32>(query, &[text_arg(username)]) {
        Ok(Some(seconds)) if seconds > 0 => {
            let minutes = seconds / 60;
            let secs = seconds % 60;
            Err(format!(
                "Account locked! Please wait {} minute(s) and {} second(s). Too many failed login attempts.",
                minutes, secs
            ).into())
        }
        _ => Ok("Access granted".to_string()),
    }
}

// Password history functions
/// Records password-change metadata for `username`.
///
/// Metadata only: this does **not** change the PostgreSQL role password. Use
/// `ALTER ROLE ... PASSWORD` for that, which records its own history through the
/// password hook.
///
/// Idempotent for the latest identical password: repeated calls do not create
/// repeated bcrypt rows. Expiry metadata is still refreshed on every call.
/// It shares one recording path with the hook, so the two can no longer produce
/// duplicate rows for the same change.
#[pg_extern]
fn record_password_change(
    username: &str,
    new_password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if record_password_change_internal(username, new_password)? {
        Ok("Password change recorded".to_string())
    } else {
        Ok("Password already recorded; expiry metadata refreshed".to_string())
    }
}

#[pg_extern]
fn check_password_expiry(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Reporting only: this never consumes a grace login. Login-time
    // consumption happens in the authentication hook against the shared cache.
    if PASSWORD_EXPIRY_DAYS.get() == 0 {
        return Ok("Password expiry disabled".to_string());
    }

    // Scalar subqueries again: exactly one row, NULL for "no expiry row". The
    // previous version used `match ... { _ => Ok("Password valid") }`, which
    // swallowed every SPI failure -- including a missing table or revoked
    // privilege -- and reported the password as valid. Real errors now
    // propagate.
    let row = Spi::connect(|client| -> pgrx::spi::Result<(Option<bool>, Option<i32>)> {
        let table = client.select(
            "SELECT
                 (SELECT must_change_by < now()
                    FROM password_profile.password_expiry WHERE username = $1),
                 (SELECT grace_logins_remaining
                    FROM password_profile.password_expiry WHERE username = $1)",
            Some(1),
            &[text_arg(username)],
        )?;
        let first = table.first();
        Ok((first.get::<bool>(1)?, first.get::<i32>(2)?))
    })?;

    match row {
        // No expiry row at all: nothing recorded for this user.
        (None, _) => Ok("No password expiry record".to_string()),
        (Some(false), _) => Ok("Password valid".to_string()),
        (Some(true), Some(grace)) if grace > 0 => {
            Err(format!("Password expired! {} grace login(s) remaining.", grace).into())
        }
        (Some(true), _) => Err("Password expired! No grace logins remaining.".into()),
    }
}

#[pg_extern]
fn add_to_blacklist(
    password: &str,
    reason: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    Spi::run_with_args(
        "INSERT INTO password_profile.blacklist (password, added_at, reason)
         VALUES ($1, now(), $2)
         ON CONFLICT (password) DO NOTHING",
        &[
            text_arg(password),
            text_arg(reason.unwrap_or("Admin added")),
        ],
    )?;
    Ok("Added to blacklist".to_string())
}

#[pg_extern]
fn remove_from_blacklist(password: &str) -> Result<String, Box<dyn std::error::Error>> {
    Spi::run_with_args(
        "DELETE FROM password_profile.blacklist WHERE password = $1",
        &[text_arg(password)],
    )?;
    Ok("Removed from blacklist".to_string())
}

#[pg_extern]
fn load_blacklist_from_file(file_path: Option<&str>) -> Result<String, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    // Defense in depth: this function reads a server-side file, so an ACL alone
    // is not enough -- a DBA who grants EXECUTE would otherwise hand out a
    // filesystem probe. `superuser()` is a backend C call against the current
    // role; it needs no SPI and cannot itself fail.
    //
    // The check runs before the path is resolved, before existence is tested
    // and before `File::open`, and every rejection returns the identical
    // message. A non-superuser therefore cannot distinguish an existing file
    // from a missing or unreadable one: previously the OS error was surfaced
    // verbatim ("No such file or directory" vs "Permission denied"), which
    // leaked filesystem layout.
    if !unsafe { pg_sys::superuser() } {
        return Err("permission denied: superuser is required to load a blacklist file".into());
    }

    // Default path: $PGDATA/../share/extension/password_profile_blacklist.txt
    let path = if let Some(p) = file_path {
        p.to_string()
    } else {
        // Try to get PGDATA
        let pgdata =
            std::env::var("PGDATA").unwrap_or_else(|_| "/var/lib/pgsql/16/data".to_string());
        format!("{}/password_profile_blacklist.txt", pgdata)
    };

    let file = File::open(&path)
        .map_err(|e| format!("Failed to open blacklist file '{}': {}", path, e))?;

    let reader = BufReader::new(file);
    let mut count = 0;
    let mut errors = 0;

    for line in reader.lines() {
        if let Ok(password) = line {
            let password = password.trim();
            if password.is_empty() || password.starts_with('#') {
                continue;
            }

            match Spi::run_with_args(
                "INSERT INTO password_profile.blacklist (password, reason)
                 VALUES ($1, 'Loaded from file')
                 ON CONFLICT (password) DO NOTHING",
                &[text_arg(password)],
            ) {
                Ok(_) => count += 1,
                Err(_) => errors += 1,
            }
        }
    }

    Ok(format!(
        "Loaded {} passwords from '{}' ({} errors)",
        count, path, errors
    ))
}

#[pg_extern]
fn get_password_stats(username: &str) -> Result<String, Box<dyn std::error::Error>> {
    // One statement, scalar subqueries, so it always returns exactly one row
    // whatever combination of rows exists. The previous version issued three
    // bare `SELECT ... WHERE username = $1` statements; each returned zero rows
    // when its table had no row for the user, and pgrx surfaces that as
    // `SpiError::InvalidPosition` ("SpiTupleTable positioned before the start
    // or after the end") rather than `None` -- so the function failed outright
    // for any user missing an expiry or login-attempts row.
    //
    // Genuine SPI or table errors still propagate: only SQL NULL means
    // "no data", never a caught error.
    let row = Spi::connect(
        |client| -> pgrx::spi::Result<(Option<i64>, Option<i32>, Option<i32>)> {
            let table = client.select(
                "SELECT
                     (SELECT count(*) FROM password_profile.password_history WHERE username = $1),
                     (SELECT (EXTRACT(EPOCH FROM (must_change_by - now()))::bigint / 86400)::int
                        FROM password_profile.password_expiry WHERE username = $1),
                     (SELECT fail_count
                        FROM password_profile.login_attempts WHERE username = $1)",
                Some(1),
                &[text_arg(username)],
            )?;
            let first = table.first();
            Ok((
                first.get::<i64>(1)?,
                first.get::<i32>(2)?,
                first.get::<i32>(3)?,
            ))
        },
    )?;

    let (history_count, days_until_expiry, failed_attempts) = row;

    Ok(format!(
        "Password History: {} changes | Days until expiry: {} | Failed attempts: {}",
        history_count.unwrap_or(0),
        days_until_expiry.map_or("N/A".to_string(), |d| d.to_string()),
        failed_attempts.unwrap_or(0)
    ))
}

// ====================================================================================
// Instrumentation & Monitoring Functions
// ====================================================================================

/// Returns runtime statistics about lock cache and authentication failures
/// Useful for ops monitoring and capacity planning
#[pg_extern]
fn get_lock_cache_stats() -> Result<
    TableIterator<
        'static,
        (
            name!(metric, String),
            name!(value, i64),
            name!(description, String),
        ),
    >,
    Box<dyn std::error::Error>,
> {
    let stats = lock_cache::collect_stats()?;
    Ok(TableIterator::new(stats.into_iter()))
}

#[cfg(test)]
mod tests {
    use pgrx::prelude::*;

    #[test]
    fn test_user_exists_real_user() {
        Spi::run("CREATE USER test_exists_user WITH PASSWORD 'test123'").ok();
        let username = std::ffi::CString::new("test_exists_user").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        assert_eq!(result, 1);
        Spi::run("DROP USER test_exists_user").ok();
    }

    #[test]
    fn test_user_exists_fake_user() {
        let username = std::ffi::CString::new("definitely_not_exists_99999").unwrap();
        let result = unsafe { crate::password_profile_user_exists(username.as_ptr()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_user_exists_null() {
        let result = unsafe { crate::password_profile_user_exists(std::ptr::null()) };
        assert_eq!(result, -1);
    }

    #[test]
    fn test_record_failed_login_basic() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_fail_user WITH PASSWORD 'test123'").ok();
        crate::record_failed_login("test_fail_user").unwrap();
        let count: Option<i32> = Spi::get_one(
            "SELECT fail_count FROM password_profile.login_attempts WHERE username = 'test_fail_user'",
        )
        .unwrap();
        assert!(count.unwrap_or(0) > 0);
        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'test_fail_user'")
            .ok();
        Spi::run("DROP USER test_fail_user").ok();
    }

    #[test]
    fn test_clear_login_attempts() {
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_clear_user WITH PASSWORD 'test123'").ok();
        Spi::run(
            "INSERT INTO password_profile.login_attempts (username, fail_count, last_fail) 
                    VALUES ('test_clear_user', 5, NOW())",
        )
        .ok();

        crate::clear_login_attempts("test_clear_user").unwrap();
        let count: Option<i32> = Spi::get_one(
            "SELECT COUNT(*) FROM password_profile.login_attempts WHERE username = 'test_clear_user'",
        )
        .unwrap();
        assert_eq!(count.unwrap(), 0);
        Spi::run("DROP USER test_clear_user").ok();
    }

    #[test]
    fn test_password_validation_weak() {
        Spi::run("SET password_profile.password_min_length = 8").ok();
        let result = Spi::run("CREATE USER test_weak WITH PASSWORD 'weak'");
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_hash_password() {
        let hash_attempts = vec![
            "md5c4ca4238a0b923820dcc509a6f75849b",
            "SCRAM-SHA-256$",
            "$2a$10$abcdefghijklmnopqrstuv",
        ];

        for attempt in hash_attempts {
            assert!(crate::is_hash_like(attempt));
        }
        assert!(!crate::is_hash_like("MyPassword123!"));
    }

    #[test]
    fn test_lock_cache_decision_populates_cache() {
        unsafe { crate::lock_cache::init() };
        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'lock_user_stats'")
            .ok();
        Spi::run(
            "INSERT INTO password_profile.login_attempts (username, fail_count, lockout_until)
                 VALUES ('lock_user_stats', 5, now() + interval '2 minutes')",
        )
        .ok();

        // The decision now comes from the authoritative typed timestamp, and
        // cache writes take pre-encoded fixed-size bytes so they are legal
        // inside a commit callback.
        let encoded = crate::encode_username("lock_user_stats");
        match crate::lock_cache::decision_from_db("lock_user_stats").unwrap() {
            crate::lock_cache::CacheDecision::SetLock(expires_at) => {
                let status = unsafe { crate::lock_cache::set(&encoded, expires_at) };
                assert_eq!(status, crate::lock_cache::CacheOpStatus::Applied);
            }
            crate::lock_cache::CacheDecision::ClearLock => {
                panic!("expected an active lockout decision")
            }
        }

        let remaining = unsafe { crate::lock_cache::remaining_seconds("lock_user_stats") };
        assert!(remaining.unwrap_or(0) > 0);

        Spi::run("DELETE FROM password_profile.login_attempts WHERE username = 'lock_user_stats'")
            .ok();
        let _ = unsafe { crate::lock_cache::clear(&encoded) };
    }

    #[test]
    fn test_record_failed_login_triggers_lockout() {
        Spi::run("SET password_profile.failed_login_max = 2").ok();
        Spi::run("SET password_profile.lockout_minutes = 1").ok();

        Spi::run("CREATE SCHEMA IF NOT EXISTS password_profile").ok();
        Spi::run(
            "CREATE TABLE IF NOT EXISTS password_profile.login_attempts (
                username TEXT PRIMARY KEY,
                fail_count INT DEFAULT 0,
                last_fail TIMESTAMPTZ,
                lockout_until TIMESTAMPTZ
            )",
        )
        .ok();

        Spi::run("CREATE USER test_lockout_user WITH PASSWORD 'test123'").ok();
        crate::record_failed_login("test_lockout_user").unwrap();
        crate::record_failed_login("test_lockout_user").unwrap();

        let locked: Option<bool> = Spi::get_one(
            "SELECT lockout_until > now() FROM password_profile.login_attempts
                 WHERE username = 'test_lockout_user'",
        )
        .unwrap();
        assert!(locked.unwrap_or(false));

        Spi::run(
            "DELETE FROM password_profile.login_attempts WHERE username = 'test_lockout_user'",
        )
        .ok();
        Spi::run("DROP USER test_lockout_user").ok();
        Spi::run("RESET password_profile.failed_login_max").ok();
        Spi::run("RESET password_profile.lockout_minutes").ok();
    }
}
