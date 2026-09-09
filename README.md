# password_profile

`password_profile` is a PostgreSQL extension for password policy, password history, password expiry
and brute-force protection.

It provides:

- password complexity checks for `CREATE ROLE` and `ALTER ROLE`;
- password history and reuse-period checks;
- a password blacklist;
- password expiry with grace logins;
- failed-login counting and temporary account lockout;
- shared-memory login checks backed by a background worker and a durable event journal.

## Support

| Item | Value |
|---|---|
| Extension version | 1.0.0 |
| pgrx | 0.16.1 |
| Runtime-tested platform | PostgreSQL 17.11, Rocky Linux 9, x86-64 |
| Build targets | PostgreSQL 13–18 |
| Control database | `postgres` |

Only PostgreSQL 17 has completed runtime, restart, load and standby testing. PostgreSQL 13–16 and
18 are build targets but require their own runtime validation before production use.

The extension must be installed in the `postgres` database and listed in
`shared_preload_libraries`. Password changes must be performed while connected to `postgres`.

## Installation: Rocky Linux 9 and PostgreSQL 17

### Packages

```bash
sudo dnf install -y dnf-plugins-core epel-release
sudo dnf config-manager --set-enabled crb

sudo dnf install -y \
  https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

sudo dnf -qy module disable postgresql

sudo dnf install -y \
  postgresql17 postgresql17-server postgresql17-devel postgresql17-contrib \
  curl git clang openssl-devel krb5-devel policycoreutils pkgconf-pkg-config

sudo dnf group install -y "Development Tools"
```

Initialize PostgreSQL only on a new server:

```bash
sudo /usr/pgsql-17/bin/postgresql-17-setup initdb
sudo systemctl enable --now postgresql-17
```

Do not run `initdb` against an existing cluster.

### Rust and pgrx

Run as the non-root build user:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo install --locked cargo-pgrx --version 0.16.1
cargo pgrx init --pg17 /usr/pgsql-17/bin/pg_config
```

### Build and install

```bash
git clone https://github.com/bisoftbilgi/PG-Password-Profile.git
cd PG-Password-Profile

export PG_CONFIG=/usr/pgsql-17/bin/pg_config
cargo pgrx package \
  --pg-config "$PG_CONFIG" \
  --no-default-features \
  --features pg17
```

Install the generated files:

```bash
sudo install -o root -g root -m 0755 \
  target/release/password_profile-pg17/usr/pgsql-17/lib/password_profile.so \
  /usr/pgsql-17/lib/password_profile.so

sudo install -o root -g root -m 0644 \
  target/release/password_profile-pg17/usr/pgsql-17/share/extension/password_profile.control \
  /usr/pgsql-17/share/extension/password_profile.control

sudo install -o root -g root -m 0644 \
  target/release/password_profile-pg17/usr/pgsql-17/share/extension/password_profile--1.0.0.sql \
  /usr/pgsql-17/share/extension/password_profile--1.0.0.sql

sudo restorecon -v \
  /usr/pgsql-17/lib/password_profile.so \
  /usr/pgsql-17/share/extension/password_profile.control \
  /usr/pgsql-17/share/extension/password_profile--1.0.0.sql
```

Do not use `cp -a` from the build directory. It can preserve the build user's ownership and
`user_home_t` SELinux label.

Install the supplied blacklist:

```bash
sudo install -o postgres -g postgres -m 0600 \
  blacklist.txt \
  /var/lib/pgsql/17/data/password_profile_blacklist.txt
```

### Configure PostgreSQL

Preserve any existing entries in `shared_preload_libraries`. During initial installation, keep the
two login-time features disabled:

```conf
shared_preload_libraries = 'password_profile'
password_profile.lockout_enforcement = off
password_profile.expiry_enforcement = off
```

Restart and create the extension:

```bash
sudo systemctl restart postgresql-17

sudo -u postgres psql -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE EXTENSION password_profile;"

sudo -u postgres psql -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT password_profile.load_blacklist_from_file('/var/lib/pgsql/17/data/password_profile_blacklist.txt');"
```

Enable the features and reload:

```conf
password_profile.lockout_enforcement = on
password_profile.expiry_enforcement = on
```

```bash
sudo systemctl reload postgresql-17
```

Verify readiness:

```sql
SELECT metric, value
FROM password_profile.get_lock_cache_stats()
WHERE metric IN ('worker_running', 'lock_cache_state', 'expiry_cache_state',
                 'bypass_cache_state', 'auth_event_queue_state')
ORDER BY metric;
```

Expected values:

```text
worker_running         = 1
lock_cache_state       = 1
expiry_cache_state     = 1
bypass_cache_state     = 1
auth_event_queue_state = 0
```

A cache that is not ready pauses only the related extension feature; it does not reject valid
PostgreSQL credentials. Check the PostgreSQL log if these values do not become ready.

## Configuration

Settings are placed in `postgresql.conf`. Policy settings require a reload.

| Setting | Default | Meaning |
|---|---:|---|
| `password_profile.min_length` | 8 | Minimum password length |
| `password_profile.require_uppercase` | off | Require an uppercase letter |
| `password_profile.require_lowercase` | off | Require a lowercase letter |
| `password_profile.require_digit` | off | Require a digit |
| `password_profile.require_special` | off | Require a special character |
| `password_profile.prevent_username` | on | Reject passwords containing the role name |
| `password_profile.password_history_count` | 5 | Number of recent passwords checked |
| `password_profile.password_reuse_days` | 90 | Minimum reuse period; `0` disables it |
| `password_profile.password_expiry_days` | 90 | Password lifetime; `0` disables expiry |
| `password_profile.password_grace_logins` | 3 | Logins allowed after expiry |
| `password_profile.failed_login_max` | 3 | Failed attempts before lockout |
| `password_profile.lockout_minutes` | 2 | Lockout duration |
| `password_profile.bcrypt_cost` | 10 | bcrypt cost for history hashes |
| `password_profile.lockout_enforcement` | on | Enable failed-login counting and lockout |
| `password_profile.expiry_enforcement` | on | Enable login-time expiry checks |

Example:

```conf
password_profile.min_length = 12
password_profile.require_uppercase = on
password_profile.require_lowercase = on
password_profile.require_digit = on
password_profile.require_special = on
password_profile.failed_login_max = 3
password_profile.lockout_minutes = 5
```

```bash
sudo systemctl reload postgresql-17
```

## Usage

Run password changes from the `postgres` database:

```sql
CREATE ROLE app_user LOGIN PASSWORD 'CorrectHorse!42';
ALTER ROLE app_user PASSWORD 'AnotherStrong!43';
```

PostgreSQL always performs native authentication first. A wrong password is rejected normally. On a
primary, failed attempts for an existing non-superuser role are counted and the role is temporarily
locked after the configured threshold.

Check and clear a lockout:

```sql
SELECT password_profile.is_user_locked('app_user');
SELECT password_profile.clear_login_attempts('app_user');
```

Manage the blacklist:

```sql
SELECT password_profile.add_to_blacklist('ExampleBad!123', 'company policy');
SELECT password_profile.remove_from_blacklist('ExampleBad!123');
SELECT password_profile.load_blacklist_from_file('/absolute/path/blacklist.txt');
```

Exclude a maintenance role from password-profile rules:

```sql
ALTER ROLE maint SET password_profile.bypass_password_profile = true;
ALTER ROLE maint RESET password_profile.bypass_password_profile;
```

The bypass change becomes visible to login checks in about one second. It does not bypass
PostgreSQL's password authentication.

## Monitoring

```sql
SELECT * FROM password_profile.get_lock_cache_stats();

SELECT username, fail_count, last_fail, lockout_until
FROM password_profile.login_attempts
ORDER BY last_fail DESC;
```

Functions and tables are not granted to `PUBLIC`. A read-only monitoring role needs:

```sql
GRANT USAGE ON SCHEMA password_profile TO monitoring_role;
GRANT SELECT ON TABLE password_profile.login_attempts TO monitoring_role;
GRANT EXECUTE ON FUNCTION password_profile.get_lock_cache_stats() TO monitoring_role;
GRANT EXECUTE ON FUNCTION password_profile.is_user_locked(text) TO monitoring_role;
```

Do not grant direct write access to extension tables. Use the management functions so shared caches
remain consistent.

## Standby behavior

While PostgreSQL is in recovery:

- native PostgreSQL authentication continues normally;
- password complexity, history and blacklist rules still apply to password changes on the primary;
- failed-login counting and account lockout are disabled on the standby;
- password expiry and grace-login enforcement are disabled on the standby;
- extension tables remain read-only replicas of the primary.

After promotion, the worker starts, rebuilds its caches and enables protection when they are ready.

## Failure behavior

Authentication events are written to a durable journal before being accepted. If the RAM queue is
full, additional events remain in the journal and are processed later. A restart does not discard
accepted but uncommitted events.

If the worker, journal or a cache is unhealthy, the affected extension protection pauses and emits
a PostgreSQL warning. Native PostgreSQL authentication remains active, so an extension failure does
not lock every user out of the database.

Emergency switches:

```conf
password_profile.lockout_enforcement = off
password_profile.expiry_enforcement = off
```

Reload PostgreSQL after changing them. A stopped background worker requires a PostgreSQL restart.

## Important limitations

- The control database is fixed as `postgres`.
- Standby brute-force and expiry enforcement are intentionally disabled.
- Runtime testing currently covers PostgreSQL 17 on Rocky Linux 9 only.
- Login-time caches hold 2048 lock/expiry entries and 1024 bypass roles.
- PostgreSQL may log password DDL when `log_statement` includes DDL or all statements. Protect server
  logs and choose the logging policy accordingly.
- Versioned extension upgrade scripts are not provided yet. Do not drop and recreate the extension
  to deploy an update if its stored history or lockout data must be retained.

## Development checks

```bash
cargo +1.88.0 fmt --check
cargo +1.88.0 check --all-targets --no-default-features --features pg17
cargo +1.88.0 pgrx package \
  --pg-config /usr/pgsql-17/bin/pg_config \
  --no-default-features \
  --features pg17
git diff --check
```

Runtime validation must use a real PostgreSQL instance with the extension preloaded. Compilation
alone does not exercise authentication hooks, the worker, restart recovery or standby promotion.

## License

See [LICENSE](LICENSE).
