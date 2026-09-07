#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CP09-01 SDK collector.

Every fixture below mirrors a real SDK response model, verified against
oci==2.185.1. The three cases that exist specifically because the model is
counter-intuitive:

  * a file system whose snapshot policy id appears only on the full FileSystem,
    never on the FileSystemSummary the list returns;
  * a PostgreSQL system whose policy is nested at management_policy.backup_policy;
  * a volume with no policy assignment at all, which is the one shape that
    legitimately earns a negative finding.

PYTHON FILES USED:
  cp09-01/cp09-01-backup-configuration.py   the collector under test
  lib/oci_audit_sdk.py                      loaded transitively by the collector
"""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
import tempfile
import types
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TENANCY = "ocid1.tenancy.oc1..cp09mock"
SHARED = "ocid1.compartment.oc1..sharedservices"

_spec = importlib.util.spec_from_file_location(
    "cp0901", ROOT / "cp09-01" / "cp09-01-backup-configuration.py")
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)


class Obj:
    """A generated SDK model: attributes, and None for anything unset."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __getattr__(self, name):
        return None


class Response:
    def __init__(self, data):
        self.data = data
        self.headers = {"opc-request-id": "mock-request-id"}
        self.status = 200


class ServiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = {"opc-request-id": "mock-denied"}


class Denials:
    volume_assignment = False


class BaseClient:
    def __init__(self, config, **kwargs):
        self.config = config


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kw):
        names = {TENANCY: "MockTenancy", SHARED: "Shared Services"}
        return Response(Obj(id=compartment_id, name=names.get(compartment_id, "?")))

    def list_compartments(self, compartment_id, **kw):
        return Response([Obj(id=SHARED, name="Shared Services",
                             lifecycle_state="ACTIVE")])

    def list_availability_domains(self, **kw):
        return Response([Obj(name="mock-AD-1")])


class BlockstorageClient(BaseClient):
    def list_volumes(self, **kw):
        return Response([
            Obj(id="ocid1.volume.oc1..protected", display_name="protected-volume",
                lifecycle_state="AVAILABLE"),
            Obj(id="ocid1.volume.oc1..bare", display_name="unprotected-volume",
                lifecycle_state="AVAILABLE"),
            # A terminating volume must not raise a corrective action.
            Obj(id="ocid1.volume.oc1..gone", display_name="terminating-volume",
                lifecycle_state="TERMINATING"),
        ])

    def list_boot_volumes(self, **kw):
        return Response([Obj(id="ocid1.bootvolume.oc1..b1",
                             display_name="boot-volume", lifecycle_state="AVAILABLE")])

    def get_volume_backup_policy_asset_assignment(self, asset_id, **kw):
        if Denials.volume_assignment:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "read backup policy assignment was denied")
        if asset_id.endswith("bare"):
            return Response([])          # explicit negative: no policy attached
        return Response([Obj(asset_id=asset_id, policy_id="ocid1.volumebackuppolicy.oc1..p1")])

    def get_volume_backup_policy(self, policy_id, **kw):
        return Response(Obj(
            id=policy_id, display_name="bronze-daily",
            schedules=[Obj(backup_type="INCREMENTAL", period="ONE_DAY",
                           retention_seconds=2592000, time_zone="UTC",
                           is_retention_lock_enabled=True,
                           is_prevent_deletion_enabled=True)]))


class FileStorageClient(BaseClient):
    def list_file_systems(self, **kw):
        # The summary deliberately carries NO filesystem_snapshot_policy_id --
        # that field exists only on the full FileSystem. A collector that trusts
        # the summary reports both of these as unprotected.
        return Response([
            Obj(id="ocid1.filesystem.oc1..fs1", display_name="protected-fs",
                lifecycle_state="ACTIVE"),
            Obj(id="ocid1.filesystem.oc1..fs2", display_name="unprotected-fs",
                lifecycle_state="ACTIVE"),
        ])

    def get_file_system(self, file_system_id, **kw):
        if file_system_id.endswith("fs2"):
            return Response(Obj(id=file_system_id, display_name="unprotected-fs",
                                lifecycle_state="ACTIVE"))
        return Response(Obj(
            id=file_system_id, display_name="protected-fs", lifecycle_state="ACTIVE",
            filesystem_snapshot_policy_id="ocid1.filesystemsnapshotpolicy.oc1..sp1"))

    def get_filesystem_snapshot_policy(self, filesystem_snapshot_policy_id, **kw):
        return Response(Obj(
            id=filesystem_snapshot_policy_id, display_name="daily-snapshots",
            lifecycle_state="ACTIVE",
            schedules=[Obj(period="DAILY", retention_duration_in_seconds=604800,
                           time_zone="UTC")]))


class ObjectStorageClient(BaseClient):
    def get_namespace(self, **kw):
        return Response("mocknamespace")

    def list_buckets(self, **kw):
        return Response([Obj(name="worm-bucket"), Obj(name="plain-bucket")])

    def get_bucket(self, namespace_name, bucket_name, **kw):
        return Response(Obj(
            id=f"ocid1.bucket.oc1..{bucket_name}", name=bucket_name,
            versioning="Enabled" if bucket_name == "worm-bucket" else "Disabled"))

    def list_retention_rules(self, namespace_name, bucket_name, **kw):
        if bucket_name != "worm-bucket":
            return Response([])
        return Response([Obj(id="rr1", display_name="seven-year",
                             duration=Obj(time_amount=7, time_unit="YEARS"),
                             time_rule_locked="2026-01-01T00:00:00Z")])


class DatabaseClient(BaseClient):
    def list_autonomous_databases(self, **kw):
        return Response([Obj(id="ocid1.autonomousdatabase.oc1..a1", db_name="ADBPROD",
                             lifecycle_state="AVAILABLE",
                             backup_retention_period_in_days=60,
                             is_backup_retention_locked=True,
                             long_term_backup_schedule=Obj(
                                 is_disabled=False, repeat_cadence="MONTHLY",
                                 retention_period_in_days=365)),
            # Silent: no backup_retention_period_in_days.
            Obj(id="ocid1.autonomousdatabase.oc1..a2", db_name="ADBSILENT",
                lifecycle_state="AVAILABLE"),
        ])

    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.dbsystem.oc1..base", display_name="base-db",
                             lifecycle_state="AVAILABLE")])

    def list_databases(self, **kw):
        return Response([
            Obj(id="ocid1.database.oc1..d1", db_name="BASEON",
                db_backup_config=Obj(
                    auto_backup_enabled=True, auto_backup_window="SLOT_TWO",
                    recovery_window_in_days=30,
                    backup_deletion_policy="DELETE_AFTER_RETENTION_PERIOD",
                    # vpc_user/vpc_password are present on the real model. If the
                    # collector ever reads them, the self-check fails.
                    backup_destination_details=[Obj(
                        type="OBJECT_STORE", remote_region="us-ashburn-1",
                        is_retention_lock_enabled=True,
                        vpc_user="svc_backup", vpc_password="hunter2")])),
            Obj(id="ocid1.database.oc1..d2", db_name="BASEOFF",
                db_backup_config=Obj(auto_backup_enabled=False)),
            # No db_backup_config at all: unknown, not "backups are off".
            Obj(id="ocid1.database.oc1..d3", db_name="BASESILENT"),
        ])


class MysqlDbSystemClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.mysqldbsystem.oc1..m1",
                             lifecycle_state="ACTIVE"),
                         Obj(id="ocid1.mysqldbsystem.oc1..m2",
                             lifecycle_state="ACTIVE")])

    def get_db_system(self, db_system_id, **kw):
        if db_system_id.endswith("m2"):
            # Silent: the response carries no backup_policy object.
            return Response(Obj(id=db_system_id, display_name="mysql-silent"))
        return Response(Obj(
            id="ocid1.mysqldbsystem.oc1..m1", display_name="mysql-prod",
            backup_policy=Obj(is_enabled=True, retention_in_days=35,
                              window_start_time="03:00", soft_delete="ENABLED",
                              pitr_policy=Obj(is_enabled=True),
                              copy_policies=[Obj(copy_to_region="us-ashburn-1",
                                                 backup_copy_retention_in_days=90)])))


class PostgresqlClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([
            Obj(id="ocid1.postgresqldbsystem.oc1..p1", lifecycle_state="ACTIVE"),
            Obj(id="ocid1.postgresqldbsystem.oc1..p2", lifecycle_state="ACTIVE"),
            Obj(id="ocid1.postgresqldbsystem.oc1..p3", lifecycle_state="ACTIVE"),
        ])

    def get_db_system(self, db_system_id, **kw):
        if db_system_id.endswith("p3"):
            # Silent: no management_policy object at all.
            return Response(Obj(id=db_system_id, display_name="pgsql-silent"))
        if db_system_id.endswith("p2"):
            # kind=NONE is an explicit negative and IS a finding.
            return Response(Obj(
                id=db_system_id, display_name="pgsql-nobackup",
                management_policy=Obj(backup_policy=Obj(kind="NONE"))))
        # The policy is nested. A flat read yields None and would report this
        # correctly-backed-up system as having no backup at all.
        return Response(Obj(
            id=db_system_id, display_name="pgsql-prod",
            management_policy=Obj(
                pitr_policy=Obj(is_enabled=True),
                backup_policy=Obj(kind="DAILY", retention_days=31,
                                  copy_policy=Obj(regions=["us-ashburn-1"])))))


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_all(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(list_call_get_all_results=list_all)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.core = types.SimpleNamespace(BlockstorageClient=BlockstorageClient)
    oci.file_storage = types.SimpleNamespace(FileStorageClient=FileStorageClient)
    oci.object_storage = types.SimpleNamespace(ObjectStorageClient=ObjectStorageClient)
    oci.database = types.SimpleNamespace(DatabaseClient=DatabaseClient)
    oci.mysql = types.SimpleNamespace(DbSystemClient=MysqlDbSystemClient)
    oci.psql = types.SimpleNamespace(PostgresqlClient=PostgresqlClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


def run(extra_args, tmp):
    argv = ["-r", "us-langley-1", "-o", str(tmp), "-c", SHARED,
            "--non-interactive", "--confirm-scope-ocid", SHARED,
            "--approve-scan", "YES"] + list(extra_args)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = MODULE.main(argv, oci_module=build_sdk())
    return rc, buffer.getvalue()


def read_csv(tmp, marker):
    matches = sorted(Path(tmp).rglob(f"*{marker}*.csv"))
    assert matches, f"no CSV matching {marker} under {tmp}"
    with open(matches[0], newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def one(rows, name):
    hits = [r for r in rows if r["resource_name"] == name]
    assert len(hits) == 1, f"expected exactly one {name} row, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_backup_posture_across_every_service():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        assert "RESULT   : COMPLETE" in out, out
        rows = read_csv(tmp, "backup_configuration_2")

        vol = one(rows, "protected-volume")
        assert vol["backup_configured"] == "YES"
        assert vol["finding"] == "OK-SCHEDULED-BACKUP"
        assert vol["backup_type"] == "INCREMENTAL"
        assert vol["frequency"] == "ONE_DAY"
        assert vol["retention"] == "30d", vol
        assert vol["retention_lock"] == "YES" and vol["deletion_protection"] == "YES"

        bare = one(rows, "unprotected-volume")
        assert bare["finding"] == "NO-BACKUP-CONFIGURED", bare

        # A terminating volume is not a finding.
        assert not [r for r in rows if r["resource_name"] == "terminating-volume"], rows

        # The FSS policy id lives only on the full FileSystem.
        fs = one(rows, "protected-fs")
        assert fs["finding"] == "OK-SCHEDULED-SNAPSHOT", fs
        assert fs["policy_name"] == "daily-snapshots"
        assert fs["retention"] == "7d", fs
        assert one(rows, "unprotected-fs")["finding"] == "NO-BACKUP-CONFIGURED"

        worm = one(rows, "worm-bucket")
        assert worm["finding"] == "OK-VERSIONED-WORM", worm
        assert "7YEARS" in worm["retention"], worm
        assert one(rows, "plain-bucket")["finding"] == "REVIEW-OBJECT-VERSIONING-DISABLED"

        adb = one(rows, "ADBPROD")
        assert adb["finding"] == "OK-AUTOMATIC-BACKUP"
        assert adb["retention"] == "60d" and adb["retention_lock"] == "YES"
        assert "long-term=MONTHLY" in adb["frequency"], adb

        on = one(rows, "BASEON")
        assert on["finding"] == "OK-AUTOMATIC-BACKUP"
        assert on["retention"] == "30d"
        assert "OBJECT_STORE@us-ashburn-1" in on["frequency"], on
        assert one(rows, "BASEOFF")["finding"] == "NO-BACKUP-CONFIGURED"
        # No config object is UNKNOWN, never a negative finding.
        assert one(rows, "BASESILENT")["finding"] == "UNKNOWN-BACKUP-CONFIG"

        my = one(rows, "mysql-prod")
        assert my["finding"] == "OK-AUTOMATIC-BACKUP"
        assert my["retention"] == "35d" and my["point_in_time_recovery"] == "ENABLED"
        assert "copy=us-ashburn-1=90d" in my["frequency"], my

        # The nested PostgreSQL policy must be found.
        pg = one(rows, "pgsql-prod")
        assert pg["finding"] == "OK-SCHEDULED-BACKUP", pg
        assert pg["retention"] == "31d" and pg["backup_type"] == "DAILY"
        assert one(rows, "pgsql-nobackup")["finding"] == "NO-BACKUP-CONFIGURED"

        # A response that does not establish backup posture is UNKNOWN on every
        # service, never NO-BACKUP-CONFIGURED. This is the rule the whole design
        # turns on, so it is asserted for each service that can go silent.
        for silent in ("BASESILENT", "ADBSILENT", "mysql-silent", "pgsql-silent"):
            row = one(rows, silent)
            assert row["finding"] == "UNKNOWN-BACKUP-CONFIG", (silent, row)
            assert row["backup_configured"] == "UNKNOWN", (silent, row)

        coverage = read_csv(tmp, "coverage")
        assert all(r["collection_status"] == "OK" for r in coverage), coverage


@check
def test_no_credential_field_reaches_evidence():
    """BackupDestinationDetails carries vpc_user/vpc_password on a normal read."""
    with tempfile.TemporaryDirectory() as tmp:
        run([], tmp)
        for path in Path(tmp).rglob("*.csv"):
            body = path.read_text(encoding="utf-8")
            for secret in ("hunter2", "svc_backup", "vpc_password", "vpc_user"):
                assert secret not in body, (path.name, secret)


@check
def test_denied_read_is_never_a_clean_negative():
    Denials.volume_assignment = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "volumes"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "backup_configuration_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
            # The critical property: a denial must not look like "no backup".
            assert not [r for r in rows if r["finding"] == "NO-BACKUP-CONFIGURED"], rows
            coverage = read_csv(tmp, "coverage")
            assert any(r["collection_status"] == "DENIED" for r in coverage), coverage
    finally:
        Denials.volume_assignment = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
    with tempfile.TemporaryDirectory() as tmp:
        for argv, why in (
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED], "missing --approve-scan"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "yes"], "lowercase"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--approve-scan", "YES"], "no confirmed OCID"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", TENANCY, "--approve-scan", "YES"], "wrong OCID"),
            (["-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"], "no region"),
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MODULE.main(argv, oci_module=build_sdk())
            assert rc == 1, (why, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*.csv")), "a refused scan wrote evidence"


@check
def test_readonly_allowlist_is_the_complete_cloud_surface():
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name
    assert MODULE.source_selfcheck()


def main() -> int:
    failures = 0
    for fn in CHECKS:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL {fn.__name__}: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            # An unexpected exception is a failure, not a crash. Catching only
            # AssertionError let a collector that raised anything else take the
            # whole runner down with a traceback and no FAIL line -- the run
            # still exited non-zero, but said nothing about which check broke.
            failures += 1
            print(f"  FAIL {fn.__name__}: unexpected "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
    if failures:
        print(f"FAIL: CP09-01 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CP09-01 SDK backup configuration, immutability and fail-closed gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
