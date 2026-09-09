# password_profile

`password_profile` is a PostgreSQL extension that validates passwords during `CREATE ROLE` and
`ALTER ROLE`, checks new passwords against password history and a blacklist, counts failed native
authentication attempts, and locks accounts after a configurable number of failures. Failed and
successful login events are handed to a background worker through shared memory, and lockout
decisions at connection time are answered from a shared-memory cache rather than from SQL.

## Current status and compatibility

| Item | Value |
|---|---|
| Extension version | 1.0.0 |
| Build framework | pgrx 0.16.1 |
| Cargo build targets | PostgreSQL 13, 14, 15, 16, 17, 18 (`--features pg13` … `pg18`) |
| Runtime-tested | PostgreSQL 17.11 on Rocky Linux 9 only |
| Rust used for that testing | 1.88.0 |
| Control database | `postgres` (fixed) |

Cargo build targets exist for PostgreSQL 13 through 18, but only PostgreSQL 17.11 on Rocky Linux 9
has been exercised at runtime with the current changes. The other major versions are declared as
build targets but have not been validated in this test cycle; treat them as unverified.

The extension must be listed in `shared_preload_libraries`. It allocates shared memory, installs the
`ClientAuthentication` and `check_password` hooks, and registers a background worker, none of which
is possible without preloading. Installation requires superuser SQL access and operating-system
access to the server (file installation, `postgresql.conf` edits, service restarts).

This documentation does not claim the extension is production-ready. Sections below state the known
limitations directly.

## Behavior

### Password changes

Password validation runs from the `check_password` hook when a plaintext password is supplied to
`CREATE ROLE ... PASSWORD` or `ALTER ROLE ... PASSWORD`. Input that looks like a precomputed hash
(MD5, SCRAM, bcrypt and similar) is rejected, so a client cannot bypass policy by sending a
pre-hashed value.

Accepted plaintext is still hashed by PostgreSQL itself according to `password_encryption`. The
extension does not store or transmit the role password; it only validates it and, when password
history is enabled, stores a bcrypt hash of it in `password_profile.password_history`.

Password changes must be issued while connected to the `postgres` database. A password change
attempted from any other database is rejected with an error telling the caller to reconnect to
`postgres`. PostgreSQL roles are cluster-wide, but the policy and history tables live in one
database, so allowing changes elsewhere would bypass history enforcement.

The extension is installed only in `postgres`, which is the fixed control database. Do not run
`CREATE EXTENSION password_profile` in application databases. The authentication hooks are loaded
process-wide from `shared_preload_libraries` and apply to connections to any database.

### Login and lockout flow

PostgreSQL performs authentication first. `password_profile` does not replace, weaken or substitute
for PostgreSQL authentication — an incorrect password is always rejected by PostgreSQL itself.

After PostgreSQL decides, the `ClientAuthentication` hook runs. On a primary, with at least one
enforcement switch on, it does the following in this order:

1. It reads the connecting role's exemption from the shared bypass cache, then calls any previously
   registered `ClientAuthentication_hook` **exactly once** — before this extension queues an event,
   consumes a grace login or raises any error of its own. If that earlier hook rejects the
   connection it never returns, so nothing is recorded for a connection that was refused. An
   exempt role returns here: no lockout check, no expiry check, no event.
2. A failed password authentication (SQLSTATE `28P01`) for a role that exists, is not a superuser and
   is not bypassed is placed on a shared-memory event queue. The connection is still rejected by
   PostgreSQL.
3. A successful authentication is also queued, so that inactive failed-attempt state can be cleared.
   Cache readiness and queue health are re-checked immediately before that event is queued, because
   another backend can degrade them while the previous hook is running. A connection this extension
   has decided to refuse never queues a success event, so a refused login can never clear
   failed-login state.
4. The background worker consumes queued events and updates `password_profile.login_attempts` in a
   database transaction.
5. When `fail_count` reaches `failed_login_max`, the worker sets `lockout_until` to
   `now() + lockout_minutes`, and the lockout becomes visible in the shared cache.
6. While a lockout is active, the hook refuses the connection before PostgreSQL would otherwise
   accept it.

Each queued event records what the hook decided at the moment the login was admitted, including
whether failed-login cleanup is required. The worker applies that recorded decision rather than the
current value of `password_profile.lockout_enforcement`, so reloading that switch while an event is
still queued cannot change how the event is applied.

Expiry is evaluated only after PostgreSQL's authentication has *succeeded*, so a wrong password never
consumes a grace login and never reveals expiry status. An unexpired password, or one with no expiry
row, is allowed. An expired password with grace remaining consumes exactly one grace login — the
decrement and the queueing of its persistence event happen together under one exclusive lock, so
concurrent logins cannot take the same allowance twice — and the worker then persists the decrement
against the exact password generation it was taken from. An expired password with no grace remaining
is refused with a password-expired error.

Additional properties:

- A correct password does **not** clear an active lockout. The connection is refused and the lockout
  is left unchanged.
- A successful login clears only *inactive* failed-attempt state (no row, a `NULL` `lockout_until`,
  or an expired one).
- A failed attempt against a role that does not exist is not recorded, so the table cannot be used to
  enumerate roles.
- Superusers are skipped by the worker's failed-login path and are never locked out by it.
- A role with `password_profile.bypass_password_profile = true` is skipped as well.

### Degraded behavior

Ordinary cache or queue capacity pressure does not refuse every PostgreSQL login. Each feature is
enabled only while its own cache is `Ready`:

| Condition | Behavior |
|---|---|
| lock cache not `Ready` | brute-force counting and lockout enforcement pause |
| expiry cache not `Ready` | login-time expiry and grace enforcement pause |
| bypass cache not `Ready` | roles are treated as not exempt |
| auth-event queue `Overflowed` | retained events continue draining; enforcement stays active |
| auth-event queue `Corrupt` | brute-force and expiry enforcement pause until administrative recovery |
| durable journal append fails | brute-force and expiry enforcement pause until the worker rehydrates |
| the worker is not running | brute-force and expiry enforcement pause until PostgreSQL is restarted |
| a grace consumption cannot be queued | the grace count is not consumed and expiry enforcement pauses for that login |

No condition in this table refuses a login. PostgreSQL's native authentication decides every
connection on its own throughout, so a wrong password is still rejected and valid credentials are
still accepted while the extension is degraded. Every degraded condition emits a rate-controlled
`WARNING` and is reported numerically by `password_profile.get_lock_cache_stats()` (`worker_running`,
`worker_stop_reason`, `auth_event_queue_state`, `auth_event_durable_recording_degraded`,
`lock_cache_state`, `expiry_cache_state`).

"Login-time expiry enforcement is active" means `expiry_enforcement = on` **and**
`password_expiry_days > 0`. Both conditions are required, and the authentication hook and the
background worker evaluate the identical condition, so they cannot disagree about whether the expiry
cache matters. In particular, with `password_expiry_days = 0` nothing writes or reads an expiry row,
so an unhealthy expiry cache refuses no connection. An overflowed expiry cache does not stop the worker from processing
failed-login and lockout events — even when `expiry_enforcement` is left `on`.

With `lockout_enforcement = off`, lock-cache health has no effect. With login-time expiry enforcement
inactive, expiry-cache health has no effect. The two features remain independent.

Queue overflow is recoverable. The worker keeps consuming retained events and the queue returns to
`Healthy` after it drains. A failed-login or successful-login event that cannot be recorded durably
pauses brute-force and expiry enforcement cluster-wide until the worker has rehydrated the caches
from the authoritative tables; it does not quarantine the affected user and does not refuse any
login. Queue corruption suspends the worker and pauses the same two features, but it does not refuse
logins either -- an extension-internal failure is not evidence about a credential, and refusing
logins would also lock the administrator out of the connection the recovery procedure needs.

Login-time policy errors intentionally use one generic client response. The detailed reason is sent
only to the PostgreSQL server log:

```
FATAL:  password authentication failed
```

An incorrect password is always rejected normally by PostgreSQL. No extension-internal failure state
refuses an otherwise-valid login: the only logins this extension refuses are the two its healthy
policy refuses, an active lockout and an expired password with no grace logins left. Existing
sessions are not terminated. Recovery is therefore reachable over a normal connection; see
[Emergency recovery](#emergency-recovery).

### Standby behavior

The following was observed on a streaming replica built with `pg_basebackup` from a test primary:

- While the server is in recovery, `password_profile` brute-force counting and lockout enforcement
  are bypassed entirely. No cache lookup or auth event is performed.
- PostgreSQL native authentication still runs, so an incorrect password is rejected on the standby.
- A correct password is accepted on the standby **even if that role is locked on the primary**.
  Lockouts are not enforced on a standby.
- The background worker does not start while the server remains in recovery, because it requests a
  database connection and is therefore registered with `BgWorkerStart_RecoveryFinished`.
- Password expiry and grace-login enforcement are bypassed on a standby for the same reason: no
  login-time shared-memory enforcement runs during recovery, so an expired password can still log in
  there with the correct password.
- Extension tables cannot be written on the standby; the standby only replays the primary's changes.
- After promotion, the worker starts, hydrates the lock cache from `postgres`, and enforcement
  resumes on the promoted node.

Lockout state is not maintained independently on a standby. It is replicated table data plus a cache
that is only built after promotion. If standbys accept client connections, they are not rate-limited
by this extension.

## Known limitations

- The control database is fixed as `postgres` and is not configurable.
- Password expiry and grace logins are enforced at login from a shared-memory expiry cache. That
  cache is not durable: entries live only for one shared-memory lifetime and are rebuilt from
  `password_profile.password_expiry` when the worker hydrates.
- Expiry and grace enforcement is bypassed while the server is in recovery (see Standby behavior).
- `check_password_expiry()` remains a reporting function. It never consumes a grace login.
- The expiry cache holds 2048 entries. More expiry rows than that makes it `Overflow` and pauses
  login-time expiry enforcement; PostgreSQL native authentication remains available.
- Blacklist validation reads the `password_profile.blacklist` SQL table directly; there is no
  blacklist shared-memory cache.
- Login-time exemption (`bypass_password_profile`) is answered from a shared-memory cache holding
  1024 roles. More exempt roles than that makes it `Overflow`; uncached roles are treated as not
  exempt. The exemption set
  is re-read from `pg_db_role_setting` about once per second by the background worker, so an
  `ALTER ROLE ... SET` or `RESET` takes effect within roughly that interval without a server
  restart. It is not instantaneous: `ALTER ROLE` on a global object fires no event trigger, and
  `pg_db_role_setting` has no system cache to subscribe to (see [Bypassing a role](#bypassing-a-role)).
- Only database-independent role settings (`ALTER ROLE ... SET`) are honored for the login-time
  exemption. `ALTER ROLE ... IN DATABASE ... SET` is not, because the hook runs before the
  connecting database is known.
- The authentication-event queue is shared memory, not durable storage. Events that have not yet been
  committed by the worker are lost on a PostgreSQL restart or crash.
- The queue holds 1023 usable entries (one slot of the 1024-entry ring is reserved to distinguish
  full from empty).
- A queue overflow does not overwrite older events. The rejected username is temporarily contained,
  retained events continue draining, and the queue returns to `Healthy` when empty.
- The lock cache holds 2048 entries. It is a fixed-size linear-scan array. It is not O(1), not
  lock-free, not dynamically sized, and it does not use LRU eviction; when every slot holds an active
  lockout it refuses new entries and marks itself `Overflow` rather than evicting. Lockout
  enforcement pauses instead of refusing all PostgreSQL logins.
- Usernames can appear in normal PostgreSQL connection/audit logs. Login-policy failures use the same
  client-facing message as native password rejection and do not disclose whether the account is
  locked or the password is expired. Password-validation audit messages and password-hook errors
  suppress the attached SQL statement. PostgreSQL can still log password DDL independently when
  `log_statement` includes DDL or all statements; protect and configure server logs accordingly.
- Runtime testing has covered PostgreSQL 17 only.

## Installation on Rocky Linux 9 with PostgreSQL 17

### System packages

```bash
sudo dnf install -y dnf-plugins-core epel-release
sudo dnf config-manager --set-enabled crb

sudo dnf install -y \
  https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

sudo dnf -qy module disable postgresql

sudo dnf install -y \
  postgresql17 \
  postgresql17-server \
  postgresql17-devel \
  postgresql17-contrib \
  git \
  clang \
  openssl-devel \
  krb5-devel \
  pkgconf-pkg-config

sudo dnf group install -y "Development Tools"
```

`postgresql17-devel` is required: the build needs the server headers and `pg_config`.

For a host with no PostgreSQL cluster yet:

```bash
sudo /usr/pgsql-17/bin/postgresql-17-setup initdb
sudo systemctl enable --now postgresql-17
```

Do not run `initdb` against an existing initialized cluster. It will fail on a non-empty data
directory, and forcing it destroys the cluster.

### Rust and pgrx

Run these as the non-root user that will perform the build, not as `root`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo install --locked cargo-pgrx --version 0.16.1
cargo pgrx init --pg17 /usr/pgsql-17/bin/pg_config
```

Rust 1.88.0 was used for the recorded PostgreSQL 17 runtime validation. No minimum supported Rust
version has been established; older toolchains have not been tested.

`cargo pgrx init --pg17 <pg_config>` registers the existing PostgreSQL 17 installation with pgrx and
does not download or build its own PostgreSQL.

### Clone and build

```bash
git clone https://github.com/bisoftbilgi/PG-Password-Profile.git
cd PG-Password-Profile

export PG_CONFIG=/usr/pgsql-17/bin/pg_config

cargo pgrx package \
  --pg-config "$PG_CONFIG" \
  --no-default-features \
  --features pg17
```

`--no-default-features --features pg17` is required because the crate defaults to `pg16`.

Install the staged artifacts:

```bash
sudo cp -a \
  target/release/password_profile-pg17/usr/pgsql-17/. \
  /usr/pgsql-17/
```

This installs the shared library, the control file and the generated SQL script into the PostgreSQL
installation.

The build must target a compatible operating system, architecture, runtime libraries and PostgreSQL
major version. The resulting `.so` is not portable across arbitrary distributions, architectures or
PostgreSQL major versions. Build and test it for each target environment.

### Blacklist file

```bash
sudo install -o postgres -g postgres -m 0600 \
  blacklist.txt \
  /var/lib/pgsql/17/data/password_profile_blacklist.txt
```

The file is loaded later with an explicit path. Do not rely on path inference: when called without an
argument, `load_blacklist_from_file()` derives the path from the `PGDATA` environment variable of the
server process and falls back to a PostgreSQL 16 path, which is wrong on a PostgreSQL 17 host.

## Safe initial setup

This order keeps login-time features explicitly disabled until the control tables and caches are
ready. A non-ready cache no longer refuses PostgreSQL connections, but starting disabled makes the
installation state unambiguous.

Edit `postgresql.conf`. `shared_preload_libraries` is a comma-separated list — preserve any existing
entries:

```
shared_preload_libraries = 'existing_extension,password_profile'
password_profile.lockout_enforcement = off
password_profile.expiry_enforcement = off
```

If nothing else is preloaded:

```
shared_preload_libraries = 'password_profile'
password_profile.lockout_enforcement = off
password_profile.expiry_enforcement = off
```

Starting with both login-time switches off is recommended during installation, but a cache that has
not hydrated no longer refuses PostgreSQL connections. The corresponding extension feature remains
paused until its cache becomes `Ready`.

Note that `ALTER SYSTEM` writes to `postgresql.auto.conf`, which overrides `postgresql.conf`. If
`shared_preload_libraries` is already set there, change it there instead, or the edit will have no
effect.

Restart so the library is preloaded:

```bash
sudo systemctl restart postgresql-17
```

Create the extension in `postgres` only:

```bash
sudo -u postgres psql -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE EXTENSION password_profile;"
```

`CREATE EXTENSION` creates the `password_profile` schema and all tables. Calling
`init_login_attempts_table()` during normal setup is unnecessary.

Load the blacklist with an explicit path:

```bash
sudo -u postgres psql -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT password_profile.load_blacklist_from_file('/var/lib/pgsql/17/data/password_profile_blacklist.txt');"
```

With both enforcement switches still off, confirm that the extension exists and the worker is
running:

```sql
SELECT extname, extversion
FROM pg_extension
WHERE extname = 'password_profile';

SELECT pid, backend_type, state
FROM pg_stat_activity
WHERE backend_type = 'password_profile_auth_event_consumer';
```

Now enable the two features:

```
password_profile.lockout_enforcement = on
password_profile.expiry_enforcement = on
```

and reload — a restart is not needed, because these settings are `PGC_SIGHUP`:

```bash
sudo systemctl reload postgresql-17
```

Enabling a feature while its cache is not ready is safe. The authentication hook pauses that
extension feature and leaves PostgreSQL native authentication authoritative; the worker notices the
new setting, hydrates the required cache and only then does enforcement become active.

Wait for the worker to hydrate the caches, then verify the final state:

```sql
SELECT metric, value, description
FROM password_profile.get_lock_cache_stats()
WHERE metric IN ('lock_cache_state', 'expiry_cache_state', 'bypass_cache_state',
                 'auth_event_queue_state')
ORDER BY metric;
```

Expected before enabling enforcement:

- `lock_cache_state = 1` — Ready. The cache has been hydrated and holds every active lockout.
- `expiry_cache_state = 1` — Ready. The expiry cache holds every `password_expiry` row.
- `bypass_cache_state = 1` — Ready. The exemption set has been read.
- `auth_event_queue_state = 0` — Healthy.

Do not treat installation as complete until all four rows have those values. If either required
cache remains `0`, check the server log for `password_profile:` messages and leave the corresponding
feature disabled until the cause is corrected.

### Final verification

```sql
SHOW shared_preload_libraries;
SHOW password_profile.lockout_enforcement;

SELECT extname, extversion FROM pg_extension WHERE extname = 'password_profile';

SELECT pid, backend_type, state
FROM pg_stat_activity
WHERE backend_type LIKE 'password_profile%';

SELECT * FROM password_profile.get_lock_cache_stats();
```

The worker also appears in the process list as
`postgres: password_profile_auth_event_consumer`.

## Usage

### Create a protected login role

Connected to `postgres`:

```sql
CREATE ROLE testuser LOGIN PASSWORD 'CorrectHorse!42';
```

`CorrectHorse!42` is a documentation example. Do not reuse it.

The following password change is expected to **fail**, because `prevent_username` is enabled by
default and the password contains the role name:

```sql
ALTER ROLE testuser PASSWORD 'testuser';
```

```
ERROR:  Password validation failed: Password cannot contain username
```

### Configure a policy

All settings live under `password_profile.*`.

| Setting | Default | Range | Context | Meaning |
|---|---|---|---|---|
| `min_length` | 8 | 1–128 | superuser | Minimum password length |
| `require_uppercase` | off | — | superuser | Require A–Z |
| `require_lowercase` | off | — | superuser | Require a–z |
| `require_digit` | off | — | superuser | Require 0–9 |
| `require_special` | off | — | superuser | Require a special character |
| `prevent_username` | on | — | superuser | Reject passwords containing the role name |
| `password_history_count` | 5 | 0–24 | superuser | Previous passwords to compare against; `0` disables history |
| `password_reuse_days` | 90 | 0–3650 | superuser | Reuse window in days; `0` disables |
| `password_expiry_days` | 90 | 0–3650 | superuser | Expiry metadata written on password change; `0` disables |
| `password_grace_logins` | 3 | 0–10 | superuser | Grace-login count stored with expiry metadata |
| `failed_login_max` | 3 | 1–100 | superuser | Failures before lockout |
| `lockout_minutes` | 2 | 1–1440 | superuser | Lockout duration |
| `bcrypt_cost` | 10 | 4–31 | superuser | bcrypt cost for stored history hashes |
| `bypass_password_profile` | off | — | superuser | Exempt a role from validation, history, expiry and lockout; see [Bypassing a role](#bypassing-a-role) |
| `lockout_enforcement` | on | — | **sighup** | Master switch for login-time failed-attempt counting and lockout enforcement |
| `expiry_enforcement` | on | — | **sighup** | Master switch for login-time password-expiry and grace-login enforcement |

Context notes:

- Every setting except `lockout_enforcement` is `PGC_SUSET`: a superuser can change it in a session
  with `SET`, and it can be set globally in `postgresql.conf` or by `ALTER SYSTEM`. Ordinary users
  cannot change them. Global changes take effect on reload; a session `SET` applies immediately to
  that session.
- `lockout_enforcement` and `expiry_enforcement` are `PGC_SIGHUP`: they can only be changed in
  `postgresql.conf` (or `postgresql.auto.conf`) followed by a reload. Neither can be set per session,
  per role or per database. They are independent — turning one off leaves the other operational — and
  neither disables password complexity, history or blacklist validation, or PostgreSQL's own
  authentication.

Login-time expiry enforcement is active only when `expiry_enforcement = on`, `password_expiry_days >
0`, and the server is not in recovery. That combined condition — not the boolean alone — is what
decides everywhere whether expiry-cache health matters: in the authentication hook, in the worker's
initial hydration gate, in its event-consumption gate (re-evaluated after every reload), and in the
bypass-cache requirement. Setting `password_expiry_days = 0` while leaving `expiry_enforcement = on`
therefore fully disables login-time expiry: expiry-cache health neither refuses a connection nor
stops the worker from processing failed-login and lockout events. Raising `password_expiry_days`
above zero and reloading makes the worker hydrate the expiry cache before enforcement resumes.

The same holds in the other direction: with `lockout_enforcement = off`, lock-cache health neither
refuses a connection nor stops the worker from processing expiry and grace events.

Example global policy in `postgresql.conf`:

```
password_profile.min_length = 12
password_profile.require_uppercase = on
password_profile.require_lowercase = on
password_profile.require_digit = on
password_profile.require_special = on
password_profile.prevent_username = on
password_profile.password_history_count = 10
password_profile.password_reuse_days = 180
password_profile.failed_login_max = 5
password_profile.lockout_minutes = 15
password_profile.bcrypt_cost = 12
```

```bash
sudo systemctl reload postgresql-17
```

### Role-specific settings

Not every setting supports a per-role override. The implementation reads the *target role's*
`ALTER ROLE ... SET` value only where noted; elsewhere it uses the value active in the current
session (or the global value).

| Setting | Target-role override read? |
|---|---|
| `min_length` | Yes |
| `require_uppercase` | Yes |
| `require_lowercase` | Yes |
| `require_digit` | Yes |
| `require_special` | Yes |
| `prevent_username` | Yes |
| `failed_login_max` | Yes |
| `lockout_minutes` | Yes |
| `bypass_password_profile` | Yes |
| `password_history_count` | No — session/global value |
| `password_reuse_days` | No — session/global value |
| `password_expiry_days` | No — session/global value |
| `password_grace_logins` | No — session/global value |
| `bcrypt_cost` | No — session/global value |

For the supported settings, the override is read from `pg_user.useconfig` for the role being
validated or counted, so it applies even though the `ALTER ROLE ... PASSWORD` is executed by an
administrator in a different session:

```sql
ALTER ROLE appuser SET password_profile.min_length = 16;
ALTER ROLE appuser SET password_profile.failed_login_max = 10;
ALTER ROLE appuser SET password_profile.lockout_minutes = 30;
```

Settings marked "No" are read with the value active in the session performing the operation. Setting
them with `ALTER ROLE ... SET` on a target role has no effect on that role's password validation.
`ALTER DATABASE ... SET` is not consulted for any of these overrides.

#### Bypassing a role

```sql
-- Exempt a maintenance account from validation, history, expiry and lockout
ALTER ROLE maint SET password_profile.bypass_password_profile = true;

-- Put it back under policy
ALTER ROLE maint RESET password_profile.bypass_password_profile;
```

An exempt role is skipped by password validation and history recording, and at login time it is
skipped by lockout, expiry and grace enforcement as well: no cache lookup, no event is queued and no
grace login is consumed for it. PostgreSQL's own authentication is untouched, so an incorrect
password is still rejected.

Because `ClientAuthentication_hook` runs before a database connection exists, it cannot read the
catalog. The login-time exemption is therefore answered from a shared-memory cache that the
background worker rebuilds from `pg_db_role_setting` about once per second. Consequences worth
knowing:

- `SET` and `RESET` take effect within roughly that interval, without a server restart. They are not
  instantaneous. `ALTER ROLE` on a global object fires no event trigger, and `pg_db_role_setting` has
  no system cache an extension can subscribe to, so there is nothing to make this event-driven.
- Only `ALTER ROLE ... SET` (all databases) is honored at login time.
  `ALTER ROLE ... IN DATABASE ... SET` is not, because the hook runs before the connecting database
  is known.
- The standard boolean spellings PostgreSQL accepts (`true`, `on`, `yes`, `1`, `t`, and their unique
  prefixes) are all recognized. `ALTER ROLE ... SET` stores the value as written.
- If the exemption set cannot be read, roles are treated as not exempt until the next successful
  refresh. Watch `bypass_cache_state`.
- Superusers are not automatically exempt from this login-time path. They are skipped by the
  worker's failed-login recording, but the exemption itself is only what `bypass_password_profile`
  grants.

For emergency access, prepare one tightly controlled DBA login as the break-glass role and set this
role-level exemption before an incident. The role must still pass PostgreSQL's native password
authentication. The worker refreshes the exemption cache about once per second; verify
`bypass_cache_state = 1` and `bypass_cache_used_entries >= 1` after configuration. This role remains
able to connect while the auth-event queue is full or structurally corrupt, provided the bypass cache
is `Ready`. Since an extension-internal failure no longer refuses logins, this exemption is a
convenience for skipping enforcement entirely rather than a break-glass requirement.

### Test native rejection and lockout

Use a TCP connection so the test does not silently succeed through `peer` or `trust` authentication.
`pg_hba.conf` must use a password method for the host line, for example:

```
host    all    all    127.0.0.1/32    scram-sha-256
```

Reload after editing `pg_hba.conf`.

With `failed_login_max = 3` and `lockout_minutes = 2`:

```bash
# Attempts below the threshold: rejected by PostgreSQL, counted by the extension
PGPASSWORD='wrong-password' \
  psql -h 127.0.0.1 -U testuser -d postgres -c 'SELECT 1;'
```

```
psql: error: connection to server at "127.0.0.1", port 5432 failed:
FATAL:  password authentication failed for user "testuser"
```

Inspect the counter between attempts:

```sql
SELECT username, fail_count, lockout_until, lockout_until > now() AS active
FROM password_profile.login_attempts
WHERE username = 'testuser';
```

Do not build the check with `||` against `lockout_until`; concatenating a `NULL` yields `NULL` and
makes an existing row look absent.

After the third failure a lockout exists. A **correct** password is now refused by the extension, not
by PostgreSQL:

```bash
PGPASSWORD='CorrectHorse!42' \
  psql -h 127.0.0.1 -U testuser -d postgres -c 'SELECT 1;'
```

```
psql: error: connection to server at "127.0.0.1", port 5432 failed:
FATAL:  password authentication failed
```

The server log records that password_profile rejected an otherwise-valid login and includes the
remaining lock duration; the client does not receive the username, lockout state or duration.

The lockout is not extended or cleared by this attempt. Unlock administratively:

```sql
SELECT password_profile.clear_login_attempts('testuser');
```

The correct password then works again. The lockout also expires on its own after `lockout_minutes`.

`clear_login_attempts()` may be called by a superuser, or by the role clearing its own state. It
deletes the row and removes the shared-cache entry.

### Change a password

Connected to `postgres`:

```sql
ALTER ROLE testuser PASSWORD 'AnotherExample!73';
```

The change goes through the validation hook, which records the change exactly once. After every
validation hook has accepted the password, a single bcrypt hash is written to
`password_profile.password_history`, and — when `password_expiry_days > 0` — the
`password_profile.password_expiry` row is inserted or refreshed. A history row is written when
`password_history_count > 0` **or** `password_reuse_days > 0`, so time-based reuse checks keep
working when count-based history is disabled. If either write fails, the password change is rejected;
if the surrounding transaction rolls back, the history and expiry writes roll back with the role
change. A role with `bypass_password_profile = true` records nothing.

Changing a password with `password_expiry_days > 0` resets `last_changed`, `must_change_by` and
`grace_logins_remaining` in the same transaction as the role change, and the expiry cache is updated
from the values the database actually committed. The new password is immediately treated as
unexpired.

`last_changed` doubles as the password's *generation*, which is what lets a grace-consumption event
queued against a superseded password be recognized and discarded. It is therefore guaranteed to be
strictly greater than the row's previous value: the database computes it as
`GREATEST(clock_timestamp(), previous last_changed + 1 microsecond)` under the per-role advisory
lock, and derives `must_change_by` from that exact value. `now()` would not be usable here — it is
the transaction-start timestamp, so two changes in one transaction would share a generation, and a
long-running transaction could write a generation older than a change that committed after it
began. With `password_expiry_days = 0` the change removes any existing expiry row and its cache
entry instead. A rollback — including a savepoint rollback — leaves both the row and the cache
untouched.

`check_password(username, password)` is validation-only. It reports whether a candidate would be
accepted and writes nothing, so it can be called repeatedly without touching history, expiry or the
role password.

`record_password_change(username, password)` is a low-level metadata function that does **not**
change the PostgreSQL role password; use `ALTER ROLE ... PASSWORD` for that. It shares one recording
path with the hook and is idempotent for the latest identical password: repeated calls do not create
repeated bcrypt rows, though expiry metadata is refreshed each time. Use it to seed or repair
metadata — for example for roles created before the extension was installed.

### Renaming and dropping roles

Profile state is keyed by role name. Keep PostgreSQL role changes and profile state changes in the
same transaction:

```sql
BEGIN;
ALTER ROLE old_name RENAME TO new_name;
SELECT password_profile.rename_role_state('old_name', 'new_name');
COMMIT;
```

After dropping a role, remove its retained state before reusing the name:

```sql
BEGIN;
DROP ROLE old_name;
SELECT password_profile.remove_role_state('old_name');
COMMIT;
```

Both helpers require a superuser. They update the tables and shared caches only when the surrounding
transaction commits. They refuse an incorrect call order or a rename target that already has profile
state instead of merging unrelated histories.

### Blacklist management

```sql
-- Load the bundled file (explicit path)
SELECT password_profile.load_blacklist_from_file('/var/lib/pgsql/17/data/password_profile_blacklist.txt');

-- Add an entry with a reason
SELECT password_profile.add_to_blacklist('Sirket2024!', 'Company name pattern');

-- Remove an entry
SELECT password_profile.remove_from_blacklist('Sirket2024!');

-- Inspect without printing candidate passwords
SELECT count(*) AS entries FROM password_profile.blacklist;
SELECT reason, count(*) FROM password_profile.blacklist GROUP BY reason ORDER BY 2 DESC;
```

Blacklist entries are stored in plaintext in `password_profile.blacklist`, so restrict access to that
table and avoid selecting its `password` column into logs or reports.

Blacklist changes affect password *validation* only. They take effect on the next `CREATE ROLE` or
`ALTER ROLE` that supplies a plaintext password. They do not affect existing sessions, do not
invalidate a password already set, and are not consulted during login authentication.

## Monitoring and administration

The extension's SQL functions and state tables are created in the fixed `password_profile` schema.

| Object | Schema |
|---|---|
| `get_lock_cache_stats()`, `is_user_locked()`, `clear_login_attempts()`, `check_password()`, `check_password_expiry()`, `get_password_stats()`, `check_user_access()`, `record_failed_login()`, `record_password_change()`, `rename_role_state()`, `remove_role_state()`, `add_to_blacklist()`, `remove_from_blacklist()`, `load_blacklist_from_file()`, `init_login_attempts_table()` | `password_profile` |
| `login_attempts`, `password_history`, `password_expiry`, `blacklist` | `password_profile` |

### Privileges

`CREATE EXTENSION` revokes the PostgreSQL default `EXECUTE` grant to `PUBLIC` from every function
this extension creates, so no ordinary role can call them after a fresh installation. The
`password_profile` schema, its four tables and the `password_history_id_seq` sequence likewise carry
no direct `PUBLIC` privileges. The extension owner keeps full access and superusers bypass ACLs, so
both continue to work unchanged. No roles are created for you.

A DBA can grant individual functions explicitly, for example to a monitoring role:

```sql
GRANT USAGE ON SCHEMA password_profile TO monitoring_role;
GRANT SELECT ON TABLE password_profile.login_attempts TO monitoring_role;
GRANT EXECUTE ON FUNCTION password_profile.get_lock_cache_stats() TO monitoring_role;
GRANT EXECUTE ON FUNCTION password_profile.is_user_locked(text) TO monitoring_role;
```

Both monitoring functions read `password_profile.login_attempts` with the caller's privileges, so
the read-only table grant is required. Grant only what a role needs; never grant direct write access
to `password_profile.login_attempts`, because writing to it directly desynchronizes the shared cache.

Two functions deserve specific attention:

- `clear_login_attempts(text)` carries its own superuser-or-same-user check, but that check is only
  reached once a role can call the function at all. Self-service unlocking therefore requires an
  explicit `GRANT EXECUTE ON FUNCTION password_profile.clear_login_attempts(text) TO <role>;` first.
- `load_blacklist_from_file(text)` **always requires a superuser**, even if `EXECUTE` is granted. The
  check runs before the path is examined and before any file is opened, and every rejection returns
  the same generic error, so a non-superuser cannot use it to discover whether a server-side file
  exists.

```sql
-- Full runtime state
SELECT * FROM password_profile.get_lock_cache_stats();

-- Currently locked accounts (database state)
SELECT username, fail_count, lockout_until
FROM password_profile.login_attempts
WHERE lockout_until > now()
ORDER BY lockout_until;

-- Recent failed-attempt rows
SELECT username, fail_count, last_fail
FROM password_profile.login_attempts
ORDER BY last_fail DESC
LIMIT 20;

SELECT password_profile.is_user_locked('testuser');
SELECT password_profile.clear_login_attempts('testuser');
SELECT password_profile.check_password_expiry('testuser');
SELECT password_profile.get_password_stats('testuser');
```

`check_password_expiry()` distinguishes every state: `Password expiry disabled` when
`password_expiry_days = 0`, `No password expiry record` when the user has no row, `Password valid`
when unexpired, and an error naming the remaining grace logins (or their absence) when expired. A
genuine SPI failure — missing table, revoked privilege — propagates as an error rather than being
reported as valid. It reports stored state only; it never blocks a login and never decrements a
grace login, which happens in the authentication hook against the shared cache.

`get_password_stats()` returns one formatted line for any combination of present or missing rows:
missing history counts as `0`, a missing expiry row shows `N/A`, and missing login attempts count as
`0`. Genuine SPI failures propagate rather than being reported as absent data.

### `get_lock_cache_stats()` metrics

| Metric | Meaning |
|---|---|
| `lock_cache_total_size` | Fixed capacity, 2048 entries |
| `lock_cache_active_lockouts` | Non-expired entries currently cached |
| `lock_cache_used_slots` | Occupied slots, including expired ones |
| `lock_cache_free_slots` | Remaining slots |
| `lock_cache_utilization_pct` | Used slots as a percentage of capacity |
| `lock_cache_hydration_active_total` | Active lockouts seen by the last successful hydration |
| `lock_cache_hydration_loaded` | Entries installed by the last successful hydration |
| `lock_cache_hydration_overflow` | Active lockouts that did not fit during the last hydration |
| `lock_cache_state` | Cache readiness, see below |
| `db_users_with_failures` | Rows in `login_attempts` with `fail_count > 0` |
| `db_active_lockouts` | Rows with `lockout_until > now()` |
| `auth_event_queue_capacity` | 1023 usable entries |
| `auth_event_queue_depth` | Queued events not yet acknowledged |
| `auth_event_queue_has_pending` | `1` when the queue holds at least one unacknowledged event. This is queue occupancy, not worker claim state |
| `auth_event_queue_accepted_total` | Events accepted since shared memory was created |
| `auth_event_queue_acknowledged_total` | Events acknowledged after their transaction committed |
| `auth_event_queue_rejected_total` | Events not accepted by the RAM ring; use the next two counters to distinguish durable spill from journal failure |
| `auth_event_journaled_total` | Events fsynced to the durable journal before the authentication hook returned |
| `auth_event_durable_only_total` | Durable events accepted without a RAM-ring slot |
| `auth_event_journal_failures_total` | Events that could not be journaled; extension lockout and expiry enforcement pause until durable recording recovers, while PostgreSQL native authentication remains authoritative |
| `auth_event_journal_pending_records` | Complete records waiting in the active and processing journal files |
| `auth_event_journal_pending_bytes` | Total bytes currently held by both journal files |
| `auth_event_queue_next_seq` | Next event sequence number |
| `auth_event_queue_state` | Queue health, see below |
| `expiry_cache_state` | Expiry cache readiness, see below |
| `expiry_cache_capacity` | Fixed capacity, 2048 entries |
| `expiry_cache_used_entries` | Expiry entries currently cached |
| `expiry_cache_free_entries` | Remaining expiry cache slots |
| `expiry_cache_hydration_rows` | Expiry rows seen by the last successful hydration |
| `expiry_cache_hydration_overflow` | Expiry rows that did not fit (coverage incomplete) |
| `bypass_cache_state` | Bypass cache readiness, see below |
| `bypass_cache_capacity` | Fixed capacity, 1024 exempt roles |
| `bypass_cache_used_entries` | Exempt roles currently cached |
| `bypass_cache_refresh_rows` | Exempt roles seen by the last successful refresh |
| `bypass_cache_refresh_overflow` | Exempt roles that did not fit (coverage incomplete) |

`lock_cache_state`:

| Value | Name | Meaning |
|---|---|---|
| 0 | NotReady | Never hydrated, or hydration failed. Lockout enforcement is paused |
| 1 | Ready | Hydrated, complete coverage. Normal operation |
| 2 | Overflow | Active lockouts exceed the 2048-entry capacity. Lockout enforcement is paused |
| 3 | WorkerFailed | Worker stopped after a failure it could not recover from. Lockout enforcement is paused |

`auth_event_queue_state`:

| Value | Name | Meaning |
|---|---|---|
| 0 | Healthy | Accepting and delivering events normally |
| 1 | Overflowed | RAM capacity was exceeded; events remain durable, continue draining, and the state clears when the ring is empty |
| 2 | Corrupt | Claim/acknowledge validation or a queue invariant failed; brute-force and expiry enforcement pause, logins are not refused |

`expiry_cache_state`:

| Value | Name | Meaning |
|---|---|---|
| 0 | NotReady | Never hydrated, or hydration failed. Expiry enforcement is paused |
| 1 | Ready | Hydrated, every expiry row represented. Normal operation |
| 2 | Overflow | More expiry rows than the 2048-entry capacity. Expiry enforcement is paused |
| 3 | WorkerFailed | Worker stopped after a failure it could not recover from. Expiry enforcement is paused |

`bypass_cache_state`:

| Value | Name | Meaning |
|---|---|---|
| 0 | NotReady | Never refreshed, or the refresh failed. Roles are treated as not exempt |
| 1 | Ready | The exemption set is complete. Normal operation |
| 2 | Overflow | More exempt roles than the 1024-entry capacity. Uncached roles are treated as not exempt |
| 3 | WorkerFailed | Worker stopped. Roles are treated as not exempt |

All four state values are normalized when read: an unrecognized stored value is reported as the
safest state (`0` for the lock, expiry and bypass caches, `2` for the queue).

There is no SQL view of event contents. The bounded ring is in shared memory, while the authoritative
fixed-record journal is stored in `PGDATA` as `password_profile_auth_events.active` and, during replay,
`password_profile_auth_events.processing`. Both files are owned by the PostgreSQL operating-system
user with mode `0600`; they contain event identifiers, usernames and event metadata, never passwords.
The worker removes a batch only after every event transaction commits. The
`password_profile.auth_event_receipts` table prevents double counting if PostgreSQL crashes after a
transaction commits but before the batch file is removed.

Durability adds one synchronous storage write to each login event handled by the extension. Keep
`PGDATA` on reliable, low-latency storage and alert when `auth_event_journal_failures_total` increases
or `auth_event_journal_pending_records` keeps growing; either signal means the worker or storage path
needs attention.

### Do not edit `login_attempts` directly

Deleting rows from `password_profile.login_attempts` with plain SQL does not synchronize the shared
cache. The extension will keep enforcing the cached lockout until the next hydration, so the account
stays locked even though the table looks clean. Always unlock with:

```sql
SELECT password_profile.clear_login_attempts('username');
```

## Emergency recovery

Use this when the server log reports a corrupt password_profile auth-event queue, or
`auth_event_queue_state` is 2. Brute-force and expiry enforcement are paused while this lasts;
connections are **not** blocked, so this procedure is run over an ordinary connection. Queue overflow
and cache capacity pressure do not require it at all.

1. Inspect the server log for the cause:

   ```bash
   sudo grep -E 'password_profile' /var/lib/pgsql/17/data/log/*.log | tail -50
   ```

   Look for `auth event queue is Corrupt`, acknowledgement/invariant failures, or an unhandled worker
   failure. An `auth event queue is full` warning by itself is recoverable and the worker continues
   draining.

2. Disable both login-time switches in `postgresql.conf` (or `postgresql.auto.conf` if set there):

   ```
   password_profile.lockout_enforcement = off
   password_profile.expiry_enforcement = off
   ```

3. Reload:

   ```bash
   sudo systemctl reload postgresql-17
   ```

4. Connect and inspect:

   ```sql
   SELECT * FROM password_profile.get_lock_cache_stats();
   SELECT count(*) FROM password_profile.login_attempts WHERE lockout_until > now();
   ```

5. If `auth_event_queue_state = 2`, verify the durable journal and reset only the RAM queue:

   ```sql
   SELECT password_profile.recover_auth_event_queue();
   ```

   The function is superuser-only and refuses to run unless both enforcement switches are off. It
   does not discard pending events: the worker resumes, rehydrates the caches and replays the verified
   journal. If journal verification reports corruption, keep enforcement off, preserve the journal
   files and investigate; the function will not silently delete them.

6. Confirm recovery:

   ```sql
   SELECT metric, value FROM password_profile.get_lock_cache_stats()
   WHERE metric IN ('lock_cache_state', 'auth_event_queue_state');
   ```

   Wait for the worker to resume. Re-enable each feature only after its cache is `Ready`,
   `auth_event_queue_state = 0`, and `auth_event_journal_pending_records = 0`.

7. Re-enable enforcement and reload:

   ```
   password_profile.lockout_enforcement = on
   ```

   ```bash
   sudo systemctl reload postgresql-17
   ```

During this procedure, the two switches pause failed-attempt counting, lockout and login-time
expiry/grace enforcement. PostgreSQL native authentication continues unchanged, and password
validation, history and blacklist checks on `CREATE ROLE` / `ALTER ROLE` are unaffected.

### PostgreSQL will not start because the library is missing

If the shared library was removed, replaced with an incompatible build, or the PostgreSQL minor
version changed, startup fails with a message such as
`could not access file "password_profile": No such file or directory`.

Edit `postgresql.conf` (and `postgresql.auto.conf`) and remove **only** the `password_profile`
element from the list, preserving the others:

```
shared_preload_libraries = 'existing_extension'
```

Start PostgreSQL, restore or rebuild the extension files for the correct PostgreSQL version, add
`password_profile` back to the list, and restart.

## Upgrading

Do not use `DROP EXTENSION` followed by `CREATE EXTENSION` for a routine upgrade. Dropping the
extension removes its SQL objects and can remove the password history, blacklist, expiry and
lockout data stored in the control database.

Check the installed and available versions before changing any files:

```sql
SELECT name, installed_version, default_version
FROM pg_available_extensions
WHERE name = 'password_profile';
```

### Binary-only development updates

The current repository identifies the extension as version `1.0.0` and does not yet contain a
versioned SQL upgrade script. When testing a source change that does not alter tables, function
signatures or other SQL objects, keep the existing extension installed:

1. Set `password_profile.lockout_enforcement = off` and reload PostgreSQL.
2. Stop PostgreSQL.
3. Build and install the replacement extension files for the same PostgreSQL major version and
   target operating system.
4. Start PostgreSQL.
5. Confirm that the worker starts and that `lock_cache_state = 1` and
   `auth_event_queue_state = 0`.
6. Re-enable enforcement and reload PostgreSQL.

The database will continue to report extension version `1.0.0`, because replacing the shared
library does not change `pg_extension.extversion`. This is acceptable for a controlled development
build, but published releases should have distinct extension versions so operators can identify the
code that is installed.

Because `password_profile` is loaded through `shared_preload_libraries`, replacing the `.so` file
does not update the code already loaded by the running postmaster. A PostgreSQL restart is required
for every binary update. `ALTER EXTENSION ... UPDATE` updates SQL objects; it does not reload the
shared library.

### Versioned releases

An in-place SQL upgrade is available only when the new installation contains a complete upgrade
path from the installed version. For example, a `1.0.0` to `1.0.1` release must ship a file named:

```
password_profile--1.0.0--1.0.1.sql
```

The release must also set its new default version consistently in `Cargo.toml` and
`password_profile.control`. pgrx copies versioned SQL files into the PostgreSQL extension directory,
but it does not create the migration logic automatically. The upgrade script must preserve existing
data with operations such as `ALTER TABLE` and `CREATE OR REPLACE FUNCTION`; it must not drop and
recreate state tables.

Use a maintenance window for a versioned upgrade:

1. Take a tested backup or storage snapshot of the `postgres` control database.
2. Disable `password_profile.lockout_enforcement` and reload PostgreSQL.
3. Stop PostgreSQL and install the new extension artifacts.
4. Start PostgreSQL and run the upgrade in `postgres` as a superuser:

   ```sql
   ALTER EXTENSION password_profile UPDATE TO '1.0.1';
   ```

5. Restart PostgreSQL once more so the worker and shared-memory state are initialized against the
   upgraded schema.
6. Verify the installed version and runtime state:

   ```sql
   SELECT extversion
   FROM pg_extension
   WHERE extname = 'password_profile';

   SELECT metric, value
   FROM password_profile.get_lock_cache_stats()
   WHERE metric IN ('lock_cache_state', 'auth_event_queue_state')
   ORDER BY metric;
   ```

7. Re-enable enforcement only after the installed version is correct, `lock_cache_state = 1`, and
   `auth_event_queue_state = 0`, then reload PostgreSQL.

The new binary must be able to start safely against the previous schema long enough for
`ALTER EXTENSION ... UPDATE` to run. If a release cannot maintain that compatibility, it requires a
release-specific offline migration procedure and must not be installed with the generic sequence
above. PostgreSQL does not provide an automatic extension downgrade; after a SQL migration, rollback
requires a release-specific downgrade path or restoring the pre-upgrade backup.

## Safe removal

1. Disable enforcement and reload, so no connection is refused during removal:

   ```
   password_profile.lockout_enforcement = off
   ```

   ```bash
   sudo systemctl reload postgresql-17
   ```

2. Drop the extension in `postgres`:

   ```bash
   sudo -u postgres psql -d postgres -c "DROP EXTENSION password_profile;"
   ```

   This drops the extension's functions. The `password_profile` schema and its tables were created by
   the extension script and are dropped with it. The current release does not register those tables
   with `pg_extension_config_dump()`, so do not assume a normal logical dump will include their data.
   Before removal, explicitly export every state table that must be retained, or take and verify a
   physical backup or storage snapshot of the cluster.

3. Remove only `password_profile` from `shared_preload_libraries`, keeping every other entry.

4. Restart:

   ```bash
   sudo systemctl restart postgresql-17
   ```

5. Optionally remove the installed files from `/usr/pgsql-17/` and the blacklist file from the data
   directory.

Do not assume extension data survives `DROP EXTENSION`. Take a dump first if the history or
login-attempt data matters.

## Development checks

```bash
cargo +1.88.0 fmt --check
cargo +1.88.0 check --all-targets
git diff --check
```

These verify formatting, compilation and whitespace only. They do not exercise the authentication
hook, the background worker, restart and hydration, queue overflow, or standby and promotion
behavior. Those paths require a real PostgreSQL instance with the extension preloaded, a
password-based `pg_hba.conf` entry and, for replication testing, a second cluster. Compilation alone
is not evidence that runtime behavior is correct.

## License

See [LICENSE](LICENSE).
