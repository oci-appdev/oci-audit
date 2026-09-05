#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CP09-02 SDK collector.

Fixtures mirror real SDK response models, verified against oci==2.185.1. The
PreauthenticatedRequestSummary fixtures deliberately carry NO access_uri,
because the real summary model has none -- only the full object does, and this
collector must never read it.

PYTHON FILES USED:
  cp09-02/cp09-02-backup-access.py   the collector under test
  lib/oci_audit_sdk.py               loaded transitively by the collector
"""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
import tempfile
import types
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TENANCY = "ocid1.tenancy.oc1..cp0902mock"
SHARED = "ocid1.compartment.oc1..sharedservices"

_spec = importlib.util.spec_from_file_location(
    "cp0902", ROOT / "cp09-02" / "cp09-02-backup-access.py")
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)

NOW = MODULE.utc_now()
FUTURE = (NOW + timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
PAST = (NOW - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Obj:
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
    pars = False


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

    def list_policies(self, **kw):
        return Response([
            Obj(id="ocid1.policy.oc1..p1", name="backup-admins", statements=[
                "Allow group BackupAdmins to manage volume-backups in tenancy",
                "Allow group BackupOps to read buckets in compartment Shared",
                # Not a backup statement -- must be ignored entirely.
                "Allow group Network to manage virtual-network-family in tenancy",
            ]),
            Obj(id="ocid1.policy.oc1..p2", name="public-grant", statements=[
                "Allow any-user to read objects in compartment Shared",
            ]),
            # statements absent: unusable read, not "grants nothing".
            Obj(id="ocid1.policy.oc1..p3", name="opaque-policy"),
        ])


class ObjectStorageClient(BaseClient):
    def get_namespace(self, **kw):
        return Response("mocknamespace")

    def list_buckets(self, **kw):
        return Response([Obj(name="backup-bucket"), Obj(name="public-bucket")])

    def get_bucket(self, namespace_name, bucket_name, **kw):
        public = bucket_name == "public-bucket"
        return Response(Obj(
            id=f"ocid1.bucket.oc1..{bucket_name}", name=bucket_name,
            public_access_type="ObjectRead" if public else "NoPublicAccess",
            is_read_only=not public))

    def list_preauthenticated_requests(self, namespace_name, bucket_name, **kw):
        if Denials.pars:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               f"list PARs on {bucket_name} was denied")
        if bucket_name != "backup-bucket":
            return Response([])
        # No access_uri on any of these: the real summary model has none.
        return Response([
            Obj(id="ocid1.par.oc1..live", name="live-share",
                access_type="ObjectRead", object_name="backups/db.bak",
                time_expires=FUTURE),
            Obj(id="ocid1.par.oc1..stale", name="stale-share",
                access_type="ObjectRead", object_name="backups/old.bak",
                time_expires=PAST),
            Obj(id="ocid1.par.oc1..forever", name="permanent-share",
                access_type="AnyObjectReadWrite", bucket_listing_action="ListObjects"),
        ])


class BlockstorageClient(BaseClient):
    def list_volume_backups(self, **kw):
        return Response([
            Obj(id="ocid1.volumebackup.oc1..locked", display_name="locked-backup",
                type="FULL", source_type="MANUAL",
                is_retention_lock_enabled=True, is_prevent_deletion_enabled=True),
            Obj(id="ocid1.volumebackup.oc1..open", display_name="deletable-backup",
                type="INCREMENTAL", source_type="SCHEDULED",
                is_retention_lock_enabled=False, is_prevent_deletion_enabled=False),
            # Neither field exposed: unknown, not "deletable".
            Obj(id="ocid1.volumebackup.oc1..quiet", display_name="silent-backup",
                type="FULL"),
        ])

    def list_boot_volume_backups(self, **kw):
        return Response([])


class DatabaseClient(BaseClient):
    def list_autonomous_database_backups(self, **kw):
        return Response([Obj(id="ocid1.adbbackup.oc1..b1", display_name="adb-backup",
                             type="FULL", is_automatic=True,
                             retention_period_in_days=60,
                             lifecycle_state="ACTIVE")])

    def list_backups(self, **kw):
        return Response([Obj(id="ocid1.dbbackup.oc1..b2", display_name="base-backup",
                             type="INCREMENTAL", lifecycle_state="ACTIVE")])


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_all(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(list_call_get_all_results=list_all)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.object_storage = types.SimpleNamespace(ObjectStorageClient=ObjectStorageClient)
    oci.core = types.SimpleNamespace(BlockstorageClient=BlockstorageClient)
    oci.database = types.SimpleNamespace(DatabaseClient=DatabaseClient)
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


def one(rows, subject):
    hits = [r for r in rows if r["subject"] == subject]
    assert len(hits) == 1, f"expected exactly one {subject} row, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_policy_bucket_par_and_backup_protection():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "backup_access_2")

        policy_rows = [r for r in rows if r["access_surface"] == "IAMPolicy"]
        # The virtual-network statement touches no backup resource and must
        # produce no row at all.
        assert not [r for r in policy_rows if "virtual-network" in r["exposure"]], policy_rows
        broad = [r for r in policy_rows if r["finding"] == "BROAD-BACKUP-DELETE-GRANT"]
        assert len(broad) == 1 and broad[0]["scope_of_grant"] == "TENANCY", policy_rows
        assert "manage:" in broad[0]["grants"], broad[0]
        assert [r for r in policy_rows if r["finding"] == "ANY-USER-BACKUP-GRANT"], policy_rows
        assert [r for r in policy_rows if r["finding"] == "BACKUP-ACCESS-GRANT"], policy_rows
        # A policy whose statements did not come back is unusable, not empty.
        assert one(rows, "opaque-policy")["finding"] == "UNKNOWN-POLICY-STATEMENTS"

        assert one(rows, "public-bucket")["finding"] == "PUBLIC-BUCKET"
        assert one(rows, "public-bucket")["exposure"] == "ANONYMOUS-READ"
        assert one(rows, "backup-bucket")["finding"] == "OK-NO-PUBLIC-ACCESS"

        assert one(rows, "backup-bucket:live-share")["finding"] == "ACTIVE-PAR-ON-BACKUP-BUCKET"
        assert one(rows, "backup-bucket:stale-share")["finding"] == "PAR-EXPIRED"
        forever = one(rows, "backup-bucket:permanent-share")
        assert forever["finding"] == "PAR-WITHOUT-EXPIRY", forever
        assert forever["expiry"] == "none"

        assert one(rows, "locked-backup")["finding"] == "OK-RETENTION-LOCKED"
        assert one(rows, "deletable-backup")["finding"] == "BACKUP-DELETABLE"
        # Neither protection field exposed is UNKNOWN, never "deletable".
        assert one(rows, "silent-backup")["finding"] == "UNKNOWN-BACKUP-PROTECTION"

        assert one(rows, "adb-backup")["finding"] == "OK-RETENTION-SET"
        assert "60d" in one(rows, "adb-backup")["deletion_protected"]
        assert one(rows, "base-backup")["finding"] == "UNKNOWN-BACKUP-PROTECTION"

        coverage = read_csv(tmp, "coverage")
        assert all(r["collection_status"] == "OK" for r in coverage), coverage


@check
def test_no_bearer_url_or_secret_reaches_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        run([], tmp)
        for path in Path(tmp).rglob("*.csv"):
            body = path.read_text(encoding="utf-8")
            for banned in ("access_uri", "https://objectstorage", "/p/"):
                assert banned not in body, (path.name, banned)


@check
def test_denied_par_listing_is_never_no_pars():
    Denials.pars = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "pars"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "backup_access_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
            coverage = read_csv(tmp, "coverage")
            assert any(r["collection_status"] == "DENIED" for r in coverage), coverage
    finally:
        Denials.pars = False


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
            (["-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"], "no region"),
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MODULE.main(argv, oci_module=build_sdk())
            assert rc == 1, (why, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*.csv")), "a refused scan wrote evidence"


@check
def test_bearer_url_read_is_structurally_unreachable():
    assert "get_preauthenticated_request" not in MODULE.SDK_READ_METHODS
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
    if failures:
        print(f"FAIL: CP09-02 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CP09-02 SDK backup access, PAR exposure and deletion-protection gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
