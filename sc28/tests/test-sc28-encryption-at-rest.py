#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the SC28-01 SDK collector.

This is the equivalence specification carried over from
sc28/tests/test-encryption-at-rest.sh: the SDK port must produce the same
findings, the same key-custody classifications and the same fail-closed
behaviour as the Bash/OCI-CLI collector it replaces.

The fixtures deliberately mirror the real SDK response models, not the
collector's expectations. A mock shaped to agree with the collector proves
nothing — the Autonomous Database external-key cases below exist precisely
because a mock built from the collector's own assumptions once agreed with a
bug that classified an AWS-keyed database as Oracle-managed.

PYTHON FILES USED:
  sc28/sc28-oci-encryption-at-rest.py   the collector under test
  lib/oci_audit_sdk.py                  loaded transitively by the collector
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

TENANCY = "ocid1.tenancy.oc1..sc28mock"
SHARED = "ocid1.compartment.oc1..sharedservices"

_spec = importlib.util.spec_from_file_location(
    "sc28_collector", ROOT / "sc28" / "sc28-oci-encryption-at-rest.py")
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)


# --- SDK response shapes ---------------------------------------------------

class Obj:
    """A generated SDK model: attributes, and None for anything unset."""

    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __getattr__(self, name):  # unset model fields read as None, as in the SDK
        return None


class Response:
    def __init__(self, data, request_id="mock-opc-request-id"):
        self.data = data
        self.headers = {"opc-request-id": request_id}
        self.status = 200


class ServiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.headers = {"opc-request-id": "mock-denied-request-id"}


class Denials:
    """Which mock calls should fail, so fail-closed paths can be exercised."""

    keys = False
    key_versions = False


# --- mock clients ----------------------------------------------------------

class BaseClient:
    def __init__(self, config, **kwargs):
        self.config = config


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kw):
        names = {TENANCY: "MockTenancy", SHARED: "Shared Services"}
        return Response(Obj(id=compartment_id, name=names.get(compartment_id, "unknown")))

    def list_compartments(self, compartment_id, **kw):
        return Response([Obj(id=SHARED, name="Shared Services", lifecycle_state="ACTIVE")])

    def list_availability_domains(self, **kw):
        return Response([Obj(name="mock-AD-1")])


class BlockstorageClient(BaseClient):
    def list_volumes(self, **kw):
        return Response([
            Obj(display_name="cmk-volume", kms_key_id="ocid1.key.oc1..vol"),
        ])

    def list_boot_volumes(self, **kw):
        # No kms_key_id at all: block storage exposes no external-key option,
        # so absence here genuinely means Oracle-managed.
        return Response([Obj(display_name="platform-boot-volume")])


class ObjectStorageClient(BaseClient):
    def get_namespace(self, **kw):
        return Response("mocknamespace")

    def list_buckets(self, **kw):
        return Response([Obj(name="evidence-bucket")])

    def get_bucket(self, **kw):
        return Response(Obj(name="evidence-bucket", kms_key_id="ocid1.key.oc1..bucket"))


class FileStorageClient(BaseClient):
    def list_file_systems(self, **kw):
        return Response([Obj(display_name="shared-fs", kms_key_id="ocid1.key.oc1..fss")])


class DatabaseClient(BaseClient):
    def list_autonomous_databases(self, **kw):
        return Response([
            # 1. OCI Vault CMK.
            Obj(db_name="ADBCMK", kms_key_id="ocid1.key.oc1..adb",
                kms_key_version_id="ocid1.keyversion.oc1..v2"),
            # 2. AWS-held key: no kms_key_id, provider says otherwise.
            Obj(db_name="ADBAWS", encryption_key=Obj(provider="AWS")),
            # 3. Oracle Key Vault: no kms_key_id, no provider, key_store_id set.
            Obj(db_name="ADBOKV", key_store_id="ocid1.keystore.oc1..okv1"),
            # 4. Explicitly Oracle-managed.
            Obj(db_name="ADBORACLE", encryption_key=Obj(provider="ORACLE_MANAGED")),
            # 4b. provider=OCI is a valid value meaning an OCI Vault key. It is
            # customer-managed but NOT external; demanding third-party custody
            # evidence for it would be wrong.
            Obj(db_name="ADBOCIVAULT", encryption_key=Obj(provider="OCI")),
            # 5. Response establishes custody neither way.
            Obj(db_name="ADBSILENT"),
        ])

    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.dbsystem.oc1..base", display_name="base-db")])

    def list_databases(self, **kw):
        return Response([
            Obj(db_name="BASECMK", kms_key_id="ocid1.key.oc1..basedb",
                kms_key_version_id="ocid1.keyversion.oc1..basev1"),
            Obj(db_name="BASEOKV", key_store_id="ocid1.keystore.oc1..okv"),
            Obj(db_name="BASEEXT",
                encryption_key_location_details=Obj(provider_type="AZURE")),
            Obj(db_name="BASEPLAIN",
                encryption_key_location_details=Obj(provider_type="ORACLE_MANAGED")),
        ])


class MysqlDbSystemClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.mysqldbsystem.oc1..m1")])

    def get_db_system(self, **kw):
        return Response(Obj(display_name="mysql-prod",
                            encrypt_data=Obj(key_generation_type="BYOK",
                                             key_id="ocid1.key.oc1..data")))


class PostgresqlClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.postgresqldbsystem.oc1..p1")])

    def get_db_system(self, **kw):
        return Response(Obj(display_name="pgsql-prod",
                            storage_details=Obj(system_type="OCI_OPTIMIZED_STORAGE")))


class KmsVaultClient(BaseClient):
    def list_vaults(self, **kw):
        return Response([Obj(id="ocid1.vault.oc1..v1", display_name="ocs-vault",
                             vault_type="DEFAULT", lifecycle_state="ACTIVE",
                             management_endpoint="https://mock-vault.example")])


class KmsManagementClient(BaseClient):
    def __init__(self, config, service_endpoint=None, **kw):
        super().__init__(config, **kw)
        self.service_endpoint = service_endpoint

    def list_keys(self, **kw):
        if Denials.keys:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "list KMS keys in ocs-vault was denied")
        return Response([Obj(id="ocid1.key.oc1..k1", display_name="ocs-master-key")])

    def get_key(self, **kw):
        return Response(Obj(
            id="ocid1.key.oc1..k1", display_name="ocs-master-key",
            protection_mode="HSM", lifecycle_state="ENABLED",
            key_shape=Obj(algorithm="AES", length=32),
            is_auto_rotation_enabled=True,
            auto_key_rotation_details=Obj(
                rotation_interval_in_days=90,
                time_of_schedule_start="2026-03-01T00:00:00Z",
                time_of_next_rotation="2026-09-01T00:00:00Z",
                time_of_last_rotation="2026-06-01T00:00:00Z",
                last_rotation_status=("FAILED" if Denials.key_versions else "SUCCESS"),
            )))

    def list_key_versions(self, **kw):
        # Ascending, oldest first. The SDK does not document list order, so a
        # collector that takes versions[0] as "latest" must fail here.
        return Response([
            Obj(id="ocid1.keyversion.oc1..kv1", lifecycle_state="ENABLED",
                time_created="2026-03-01T00:00:00Z", origin="INTERNAL",
                is_auto_rotated=False),
            Obj(id="ocid1.keyversion.oc1..kv2", lifecycle_state="ENABLED",
                time_created="2026-06-01T00:00:00Z", origin="INTERNAL",
                is_auto_rotated=True),
        ])


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_call_get_all_results(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(
        list_call_get_all_results=list_call_get_all_results)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.core = types.SimpleNamespace(BlockstorageClient=BlockstorageClient)
    oci.object_storage = types.SimpleNamespace(ObjectStorageClient=ObjectStorageClient)
    oci.file_storage = types.SimpleNamespace(FileStorageClient=FileStorageClient)
    oci.database = types.SimpleNamespace(DatabaseClient=DatabaseClient)
    oci.mysql = types.SimpleNamespace(DbSystemClient=MysqlDbSystemClient)
    oci.psql = types.SimpleNamespace(PostgresqlClient=PostgresqlClient)
    oci.key_management = types.SimpleNamespace(
        KmsVaultClient=KmsVaultClient, KmsManagementClient=KmsManagementClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


# --- harness ---------------------------------------------------------------

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


def by_resource(rows, name):
    hits = [row for row in rows if row["resource"] == name]
    assert len(hits) == 1, f"expected exactly one {name} row, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_full_collection_findings():
    """Every custody classification the Bash collector made, made identically."""
    Denials.keys = False
    Denials.key_versions = False
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        assert "RESULT   : COMPLETE" in out, out
        rows = read_csv(tmp, "atrest_encryption_2")
        coverage = read_csv(tmp, "coverage")
        assert not list(Path(tmp).rglob("*collection_errors*")), "clean run wrote an error file"

        volume = by_resource(rows, "cmk-volume")
        assert volume["key_management"] == "CUSTOMER-MANAGED"
        assert volume["finding"] == "OK-CMK"

        boot = by_resource(rows, "platform-boot-volume")
        assert boot["key_management"] == "ORACLE-MANAGED"
        assert boot["finding"] == "REVIEW-USE-CMK"

        mysql = by_resource(rows, "mysql-prod")
        assert mysql["key_management"] == "CUSTOMER-MANAGED"
        assert mysql["key_ocid_or_detail"] == "ocid1.key.oc1..data"

        adb_cmk = by_resource(rows, "ADBCMK")
        assert adb_cmk["key_management"] == "CUSTOMER-MANAGED"
        assert adb_cmk["finding"] == "OK-CMK"
        assert "ocid1.keyversion.oc1..v2" in adb_cmk["key_ocid_or_detail"]

        adb_aws = by_resource(rows, "ADBAWS")
        assert adb_aws["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", adb_aws
        assert adb_aws["finding"] == "MANUAL-VERIFY-EXTERNAL-KEY-CUSTODY"
        assert "encryption-key-provider=AWS" in adb_aws["key_ocid_or_detail"]

        adb_okv = by_resource(rows, "ADBOKV")
        assert adb_okv["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", adb_okv
        assert "ocid1.keystore.oc1..okv1" in adb_okv["key_ocid_or_detail"]

        adb_oracle = by_resource(rows, "ADBORACLE")
        assert adb_oracle["key_management"] == "ORACLE-MANAGED"
        assert adb_oracle["finding"] == "REVIEW-USE-CMK"

        # provider=OCI is an OCI Vault key: customer-managed, not external and
        # not a REVIEW-USE-CMK finding.
        adb_oci = by_resource(rows, "ADBOCIVAULT")
        assert adb_oci["key_management"] == "CUSTOMER-MANAGED", adb_oci
        assert adb_oci["finding"] == "MANUAL-VERIFY-KEY-CUSTODY", adb_oci

        adb_silent = by_resource(rows, "ADBSILENT")
        assert adb_silent["key_management"] == "UNKNOWN", adb_silent
        assert adb_silent["finding"] == "MANUAL-VERIFY-KEY-CUSTODY"

        assert by_resource(rows, "BASECMK")["key_management"] == "CUSTOMER-MANAGED"
        basedb_okv = by_resource(rows, "BASEOKV")
        assert basedb_okv["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", basedb_okv
        assert "ocid1.keystore.oc1..okv" in basedb_okv["key_ocid_or_detail"]
        basedb_ext = by_resource(rows, "BASEEXT")
        assert basedb_ext["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", basedb_ext
        assert "provider=AZURE" in basedb_ext["key_ocid_or_detail"], basedb_ext
        assert by_resource(rows, "BASEPLAIN")["key_management"] == "ORACLE-MANAGED"

        postgres = by_resource(rows, "pgsql-prod")
        assert postgres["key_management"] == "PLATFORM-MANAGED"
        assert postgres["finding"] == "MANUAL-VERIFY-KEY-CUSTODY"
        assert "data-key-id-not-exposed" in postgres["key_ocid_or_detail"]

        key = by_resource(rows, "ocs-master-key")
        assert key["key_management"] == "HSM"
        assert key["key_lifecycle"] == "ENABLED"
        assert key["finding"] == "OK-HSM-AUTO-ROTATION"
        # Same rotation field set the Bash collector emitted, including the
        # newest version resolved by time_created rather than list position.
        for fragment in ("auto-enabled=true", "interval-days=90",
                         "schedule-start=2026-03-01T00:00:00Z", "versions=2",
                         "auto-rotated-versions=1", "pending-version-deletions=0",
                         "latest-version=ocid1.keyversion.oc1..kv2",
                         "latest-version-state=ENABLED",
                         "latest-version-created=2026-06-01T00:00:00Z",
                         "next=2026-09-01T00:00:00Z", "last=2026-06-01T00:00:00Z"):
            assert fragment in key["key_rotation"], (fragment, key["key_rotation"])

        expected = {"BlockVolume", "BootVolume", "ObjectStorage", "FSS", "AutonomousDB",
                    "BaseDB", "MySQL", "PostgreSQL", "Vault", "KMS-Key"}
        actual = {row["service"] for row in rows}
        assert expected == actual, (expected - actual, actual - expected)
        assert all(row["collection_status"] == "OK" for row in coverage), coverage


@check
def test_failed_rotation_is_a_finding_not_a_pass():
    Denials.keys = False
    Denials.key_versions = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "vault"], tmp)
            assert rc == 0, (rc, out)
            key = by_resource(read_csv(tmp, "atrest_encryption_2"), "ocs-master-key")
            assert key["finding"] == "AUTO-ROTATION-FAILED", key
    finally:
        Denials.key_versions = False


@check
def test_denied_key_listing_is_never_reported_as_no_keys():
    """AGENTS.md rule 3: a denial is a COLLECTION-FAILED row and exit 3."""
    Denials.keys = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "vault"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "atrest_encryption_2")
            failed = [r for r in rows if r["finding"] == "COLLECTION-FAILED"]
            assert len(failed) == 1, rows
            assert failed[0]["service"] == "KMS-Key"
            assert failed[0]["resource"] == "<collection:ocs-vault>"
            assert failed[0]["collection_status"] == "DENIED", failed[0]

            coverage = read_csv(tmp, "coverage")
            kms = [r for r in coverage if r["service"] == "KMS-Key"]
            assert kms and kms[0]["collection_status"] == "DENIED", coverage
            # Deliberate divergence from the Bash collector, which wrote 0 here.
            # A denied listing does not establish that zero keys exist, and a 0
            # in an assets column is read as a count. UNKNOWN says what is true.
            assert kms[0]["assets_found"] == "UNKNOWN", coverage

            errors = read_csv(tmp, "collection_errors")
            assert any("list KMS keys in ocs-vault" in r["message"] for r in errors), errors
            assert not any("NO-KEYS" in ",".join(r.values()) for r in rows), rows
    finally:
        Denials.keys = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
    """-c selects a scope; approval is separate. Fail closed on each omission."""
    with tempfile.TemporaryDirectory() as tmp:
        for argv, why in (
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED], "missing --approve-scan"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "yes"], "lowercase yes"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--approve-scan", "YES"], "no confirmed OCID"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", TENANCY, "--approve-scan", "YES"], "wrong OCID"),
            (["-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"], "no region"),
        ):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                rc = MODULE.main(argv, oci_module=build_sdk())
            assert rc == 1, (why, rc, buffer.getvalue())
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
    if failures:
        print(f"FAIL: SC28-01 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: SC28-01 SDK key custody, rotation, fail-closed and approval gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
