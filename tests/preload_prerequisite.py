#!/usr/bin/env python3
"""Integration test against isolated clusters, with package files installed first.

python3 tests/preload_prerequisite.py --pg-config /path/to/pg_config
Add --old-pg-config /path/to/older/pg_config to test a real pg_upgrade as well.
Uses trust auth on private Unix sockets, never a running application cluster.
"""

import argparse
import getpass
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(args, *, input_text=None, check=True, cwd=None, timeout=60):
    result = subprocess.run(
        [str(arg) for arg in args], input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=cwd, timeout=timeout,
    )
    if check and result.returncode:
        raise AssertionError(f"{args[0]} failed:\n{result.stdout}\n{result.stderr}")
    return result


class Cluster:
    def __init__(self, root, pg_config, port):
        self.root = root
        self.bin = Path(run([pg_config, "--bindir"]).stdout.strip())
        self.data = root / "data"
        self.socket = root / "socket"
        self.port = port
        self.running = False
        root.mkdir()
        self.socket.mkdir(mode=0o700)
        run([self.bin / "initdb", "-D", self.data, "--no-locale", "-E", "UTF8", "-A", "trust"])

    def start(self, *, binary_upgrade=False):
        options = (
            f"-p {self.port} -c listen_addresses='' "
            f"-c unix_socket_directories='{self.socket}' "
            "-c password_profile.lockout_enforcement=off "
            "-c password_profile.expiry_enforcement=off"
        )
        if binary_upgrade:
            options += " -b"
        run([self.bin / "pg_ctl", "-D", self.data, "-l", self.root / "postgresql.log", "-o", options, "-w", "start"])
        self.running = True

    def stop(self):
        if self.running:
            run([self.bin / "pg_ctl", "-D", self.data, "-m", "fast", "-w", "stop"])
            self.running = False

    def sql(self, statement, *, db="postgres", check=True):
        return run([
            self.bin / "psql", "-X", "-h", self.socket, "-p", self.port,
            "-U", getpass.getuser(), "-d", db, "-At", "-v", "ON_ERROR_STOP=1",
        ], input_text=statement, check=check)

    def value(self, statement, *, db="postgres"):
        return self.sql(statement, db=db).stdout.strip()


def verify_no_install(cluster, label):
    assert cluster.value("SELECT count(*) FROM pg_extension WHERE extname='password_profile'") == "0"
    assert cluster.value("SELECT count(*) FROM pg_namespace WHERE nspname='password_profile'") == "0"
    assert cluster.value("SELECT count(*) FROM pg_proc WHERE probin='$libdir/password_profile'") == "0"
    # The backend that loaded the rejected library must also stay usable.
    result = cluster.sql(
        "LOAD 'password_profile'; CREATE TEMP TABLE usability_probe(id int); "
        "INSERT INTO usability_probe VALUES (42); SELECT id FROM usability_probe; "
        "CREATE ROLE preload_weak_probe PASSWORD 'weak'; DROP ROLE preload_weak_probe;"
    )
    assert "42" in result.stdout
    print(f"PASS {label}: no extension, schema or functions; database and backend usable", flush=True)


def failed_install(cluster, label, *, before=""):
    result = cluster.sql(
        "\\set VERBOSITY verbose\n" + before + "CREATE EXTENSION password_profile;\n",
        check=False,
    )
    assert result.returncode != 0, result.stdout
    assert "55000" in result.stderr, result.stderr
    assert "shared_preload_libraries" in result.stderr
    assert "restart PostgreSQL" in result.stderr
    assert "retry CREATE EXTENSION" in result.stderr
    verify_no_install(cluster, label)


def wait_value(cluster, sql, expected, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cluster.value(sql) == expected:
            return
        time.sleep(0.1)
    raise AssertionError(f"Timed out waiting for {sql} == {expected}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pg-config", required=True)
    parser.add_argument("--old-pg-config")
    parser.add_argument("--port", type=int, default=28927)
    args = parser.parse_args()
    # Do not let client environment settings redirect a test to another server.
    for name in ("PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGOPTIONS", "PGSERVICE"):
        os.environ.pop(name, None)
    root = Path(tempfile.mkdtemp(prefix="pp-preload-"))
    print(f"Evidence: {root}", flush=True)
    clusters = []
    cluster = Cluster(root / "install", args.pg_config, args.port)
    clusters.append(cluster)
    try:
        cluster.start()
        failed_install(cluster, "without preload")
        failed_install(cluster, "late LOAD", before="LOAD 'password_profile';\n")

        # Function calls load the library too, but cannot establish preload.
        result = cluster.sql(
            "\\set ON_ERROR_STOP off\n\\set VERBOSITY verbose\n"
            "BEGIN;\nCREATE FUNCTION public.preload_probe() RETURNS void "
            "AS '$libdir/password_profile', 'password_profile_require_preload_wrapper' LANGUAGE c;\n"
            "SELECT public.preload_probe();\n\\echo function_sqlstate=:SQLSTATE\nROLLBACK;\n"
            "CREATE EXTENSION password_profile;\n\\echo install_sqlstate=:SQLSTATE\nSELECT 42;\n"
        )
        assert "function_sqlstate=55000" in result.stdout, result.stdout
        assert "install_sqlstate=55000" in result.stdout, result.stdout
        assert "42" in result.stdout
        verify_no_install(cluster, "late function call")

        # Pre-existing, installer-owned namespaces must not be removed on error.
        cluster.sql("CREATE SCHEMA password_profile; CREATE TABLE password_profile.keep_me(id int)")
        result = cluster.sql("\\set VERBOSITY verbose\nCREATE EXTENSION password_profile;", check=False)
        assert "55000" in result.stderr
        assert cluster.value("SELECT count(*) FROM pg_class WHERE relnamespace='password_profile'::regnamespace AND relkind='r'") == "1"
        assert cluster.value("SELECT count(*) FROM pg_proc WHERE pronamespace='password_profile'::regnamespace") == "0"
        cluster.sql("DROP TABLE password_profile.keep_me; DROP SCHEMA password_profile")
        print("PASS rejected install preserves a pre-existing schema and unrelated table", flush=True)

        cluster.sql("ALTER SYSTEM SET shared_preload_libraries='password_profile'; SELECT pg_reload_conf()")
        wait_value(cluster, "SELECT pending_restart FROM pg_settings WHERE name='shared_preload_libraries'", "t")
        assert cluster.value("SELECT setting FROM pg_file_settings WHERE name='shared_preload_libraries' ORDER BY seqno DESC LIMIT 1") == "password_profile"
        failed_install(cluster, "configured and reloaded without restart")

        cluster.stop()
        cluster.start()
        cluster.sql("CREATE EXTENSION password_profile")
        assert cluster.value("SELECT extversion FROM pg_extension WHERE extname='password_profile'") == "1.0.0"
        assert cluster.value("SELECT count(*) FROM pg_class WHERE relnamespace='password_profile'::regnamespace AND relkind='r'") == "5"
        assert "preloaded: policy hooks installed" in cluster.value("SELECT password_profile.password_profile_status()")
        assert cluster.value("SELECT value FROM password_profile.get_lock_cache_stats() WHERE metric='library_preloaded'") == "1"
        assert cluster.value("SELECT has_function_privilege('public', 'password_profile.password_profile_status()', 'EXECUTE')") == "f"
        assert cluster.value("SELECT has_function_privilege('public', 'password_profile.password_profile_require_preload()', 'EXECUTE')") == "f"
        result = cluster.sql("CREATE ROLE preload_weak_probe PASSWORD 'weak'", check=False)
        assert result.returncode != 0, "Password policy hook was not installed"
        print("PASS real restart: installation succeeds, policy hook enforces, helper/status ACLs revoked", flush=True)

        cluster.sql("ALTER SYSTEM RESET shared_preload_libraries; SELECT pg_reload_conf()")
        assert "preloaded:" in cluster.value("SELECT password_profile.password_profile_status()")
        print("PASS removing the setting by reload does not claim the running library was unloaded", flush=True)
        cluster.stop()
        cluster.start()
        result = cluster.sql("SELECT password_profile.password_profile_status(); LOAD 'password_profile'; SELECT password_profile.password_profile_status()")
        assert result.stdout.count("NOT ACTIVE") == 2
        assert "password policy, expiry and brute-force protection are not enforced" in result.stdout
        assert "NOT ACTIVE" in result.stderr
        assert cluster.value("SELECT value FROM password_profile.get_lock_cache_stats() WHERE metric='library_preloaded'") == "0"
        assert cluster.value("SELECT count(*) FROM pg_stat_activity WHERE backend_type='password_profile_auth_event_consumer'") == "0"
        assert cluster.value("SELECT count(*) FROM pg_extension WHERE extname='password_profile'") == "1"
        cluster.sql("CREATE ROLE preload_weak_probe PASSWORD 'weak'; DROP ROLE preload_weak_probe")
        print("PASS removed preload after restart: installed objects remain; status/metrics warn of inactive enforcement", flush=True)

        # pg_upgrade's LOAD/library compatibility checks without preload.
        cluster.stop()
        cluster.start(binary_upgrade=True)
        cluster.sql("LOAD 'password_profile'; SELECT password_profile.password_profile_require_preload()")
        assert "binary upgrade mode" in cluster.value("SELECT password_profile.password_profile_status()")
        assert cluster.value("SELECT count(*) FROM pg_stat_activity WHERE backend_type='password_profile_auth_event_consumer'") == "0"
        cluster.sql("SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('80001'::oid); CREATE ROLE preload_weak_probe PASSWORD 'weak'; DROP ROLE preload_weak_probe")
        cluster.sql("ALTER SYSTEM SET shared_preload_libraries='password_profile'")
        cluster.stop()
        cluster.start(binary_upgrade=True)
        cluster.sql("SELECT password_profile.password_profile_require_preload()")
        assert "binary upgrade mode" in cluster.value("SELECT password_profile.password_profile_status()")
        assert cluster.value("SELECT count(*) FROM pg_stat_activity WHERE backend_type='password_profile_auth_event_consumer'") == "0"
        cluster.sql("SELECT pg_catalog.binary_upgrade_set_next_pg_authid_oid('80001'::oid); CREATE ROLE preload_weak_probe PASSWORD 'weak'; DROP ROLE preload_weak_probe")
        print("PASS binary-upgrade mode with and without preload: library checks allowed, hooks/worker disabled", flush=True)
        cluster.stop()

        if args.old_pg_config:
            old = Cluster(root / "upgrade_old", args.old_pg_config, args.port + 1)
            new = Cluster(root / "upgrade_new", args.pg_config, args.port + 2)
            clusters += [old, new]
            old.start()
            old.sql("ALTER SYSTEM SET shared_preload_libraries='password_profile'")
            old.stop()
            old.start()
            old.sql("CREATE EXTENSION password_profile; INSERT INTO password_profile.blacklist(password,reason) VALUES ('upgrade_fixture','preload test')")
            old.sql("CREATE DATABASE upgrade_extra")
            old.stop()
            new.start()
            new.sql("ALTER SYSTEM SET shared_preload_libraries='password_profile'")
            new.stop()
            result = run([
                new.bin / "pg_upgrade", "--old-bindir", old.bin, "--new-bindir", new.bin,
                "--old-datadir", old.data, "--new-datadir", new.data,
                "--old-port", old.port, "--new-port", new.port,
                "--socketdir", root, "--username", getpass.getuser(),
            ], check=False, cwd=root, timeout=180)
            (root / "pg_upgrade.stdout").write_text(result.stdout)
            (root / "pg_upgrade.stderr").write_text(result.stderr)
            assert result.returncode == 0, result.stdout + result.stderr
            new.start()
            assert new.value("SELECT reason FROM password_profile.blacklist WHERE password='upgrade_fixture'") == "preload test"
            assert new.value("SELECT count(*) FROM pg_extension WHERE extname='password_profile'") == "1"
            assert "preloaded:" in new.value("SELECT password_profile.password_profile_status()")
            assert new.value("SELECT value FROM password_profile.get_lock_cache_stats() WHERE metric='library_preloaded'") == "1"
            assert new.value("SELECT count(*) FROM pg_database WHERE datname='upgrade_extra'") == "1"
            result = new.sql("CREATE ROLE preload_weak_probe PASSWORD 'weak'", check=False)
            assert result.returncode != 0
            print("PASS real pg_upgrade: extension/data/database retained; normal startup reenables password policy", flush=True)
        print("All preload prerequisite checks passed", flush=True)
    finally:
        for item in reversed(clusters):
            item.stop()


if __name__ == "__main__":
    main()
