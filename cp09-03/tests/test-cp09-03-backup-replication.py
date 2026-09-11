#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CP09-03 SDK collector.

Fixtures mirror real SDK response models, verified against oci==2.185.1.

The central property under test: replication being *configured* is not the same
as backups being *off-site and current*. A same-region destination, a paused
policy and a never-synced policy are each configured and each fail CP-6, so
each has its own fixture and its own finding.

PYTHON FILES USED:
  cp09-03/cp09-03-backup-replication.py   the collector under test
  lib/oci_audit_sdk.py                    loaded transitively by the collector
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
TENANCY = "ocid1.tenancy.oc1..cp0903mock"
SHARED = "ocid1.compartment.oc1..sharedservices"
HOME = "us-langley-1"
REMOTE = "us-ashburn-1"

_spec = importlib.util.spec_from_file_location(
    "cp0903", ROOT / "cp09-03" / "cp09-03-backup-replication.py")
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)


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
    replication_policies = False
    fss_detail = False


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


class ObjectStorageClient(BaseClient):
    def get_namespace(self, **kw):
        return Response("mocknamespace")

    def list_buckets(self, **kw):
        return Response([Obj(name="offsite-bucket"), Obj(name="sameregion-bucket"),
                         Obj(name="paused-bucket"), Obj(name="never-synced-bucket"),
                         Obj(name="unreplicated-bucket"),
                         Obj(name="mixedcase-sameregion-bucket"),
                         Obj(name="unknown-destination-bucket")])

    def list_replication_policies(self, namespace_name, bucket_name, **kw):
        if Denials.replication_policies:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               f"list replication policies on {bucket_name} denied")
        table = {
            "offsite-bucket": Obj(id="rp1", name="to-ashburn",
                                  destination_bucket_name="dr-bucket",
                                  destination_region_name=REMOTE, status="ACTIVE",
                                  time_last_sync="2026-09-04T00:00:00Z"),
            # Configured and healthy, but same region: not alternate storage.
            "sameregion-bucket": Obj(id="rp2", name="to-local",
                                     destination_bucket_name="local-copy",
                                     destination_region_name=HOME, status="ACTIVE",
                                     time_last_sync="2026-09-04T00:00:00Z"),
            "paused-bucket": Obj(id="rp3", name="broken",
                                 destination_bucket_name="dr-bucket",
                                 destination_region_name=REMOTE, status="PAUSED",
                                 time_last_sync="2026-01-01T00:00:00Z"),
            # Active, off-site, and has never actually copied anything.
            "never-synced-bucket": Obj(id="rp4", name="new",
                                       destination_bucket_name="dr-bucket",
                                       destination_region_name=REMOTE,
                                       status="ACTIVE"),
            # Same region as the scan, spelled differently. Nothing in the API
            # contract guarantees the destination comes back in the same form
            # the operator typed for -r, and a raw string comparison resolves
            # that mismatch as "different region" -- i.e. off_site=YES, a false
            # CP-9(1) pass. The fixture exists to pin the failure direction.
            "mixedcase-sameregion-bucket": Obj(
                id="rp5", name="to-local-mixedcase",
                destination_bucket_name="local-copy",
                destination_region_name=HOME.upper(), status="ACTIVE",
                time_last_sync="2026-09-04T00:00:00Z"),
            # Replicating somewhere the API did not name. Unknown is not a pass.
            "unknown-destination-bucket": Obj(
                id="rp6", name="to-nowhere-named",
                destination_bucket_name="dr-bucket", status="ACTIVE",
                time_last_sync="2026-09-04T00:00:00Z"),
        }
        policy = table.get(bucket_name)
        return Response([policy] if policy else [])


# ReplicationSummary (what list_replications returns) declares NO delta_status,
# source_id or replication_target_id. The full Replication from get_replication
# does. The mock used to put those fields on the summary, which is what let the
# collector's summary-only read pass its own test while the real API would have
# reported every replication UNKNOWN.
REPLICATION_DETAIL = {
    "ocid1.replication.oc1..r1": dict(
        display_name="fs-replication",
        source_id="ocid1.filesystem.oc1..fs1",
        replication_target_id="ocid1.replicationtarget.oc1..t1",
        delta_status="IDLE", recovery_point_time="2026-09-04T12:00:00Z",
        replication_interval=60, lifecycle_state="ACTIVE"),
    "ocid1.replication.oc1..r2": dict(
        display_name="broken-replication",
        source_id="ocid1.filesystem.oc1..fs2",
        replication_target_id="ocid1.replicationtarget.oc1..t2",
        delta_status="FAILED", recovery_point_time=None,
        replication_interval=None, lifecycle_state="ACTIVE"),
}


class FileStorageClient(BaseClient):
    def list_replications(self, **kw):
        # Summary shape only.
        return Response([
            Obj(id="ocid1.replication.oc1..r1", display_name="fs-replication",
                lifecycle_state="ACTIVE", availability_domain="AD-1",
                compartment_id="c", replication_interval=60,
                recovery_point_time="2026-09-04T12:00:00Z"),
            Obj(id="ocid1.replication.oc1..r2", display_name="broken-replication",
                lifecycle_state="ACTIVE", availability_domain="AD-1",
                compartment_id="c", replication_interval=None,
                recovery_point_time=None),
        ])

    def get_replication(self, replication_id, **kw):
        if Denials.fss_detail:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "get replication was denied")
        detail = REPLICATION_DETAIL[replication_id]
        return Response(Obj(id=replication_id, **detail))


class BlockstorageClient(BaseClient):
    def list_volume_backup_policies(self, **kw):
        return Response([
            Obj(id="ocid1.volumebackuppolicy.oc1..p1", display_name="dr-policy",
                destination_region=REMOTE),
            Obj(id="ocid1.volumebackuppolicy.oc1..p2", display_name="local-policy",
                destination_region=HOME),
            Obj(id="ocid1.volumebackuppolicy.oc1..p3", display_name="no-copy-policy"),
            # Same region as the scan, different spelling.
            Obj(id="ocid1.volumebackuppolicy.oc1..p4",
                display_name="mixedcase-local-policy",
                destination_region=HOME.upper()),
        ])


class MysqlDbSystemClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.mysqldbsystem.oc1..m1"),
                         Obj(id="ocid1.mysqldbsystem.oc1..m2"),
                         Obj(id="ocid1.mysqldbsystem.oc1..m3")])

    def get_db_system(self, db_system_id, **kw):
        if db_system_id.endswith("m2"):
            return Response(Obj(id=db_system_id, display_name="mysql-silent"))
        if db_system_id.endswith("m3"):
            # A copy policy that exists but names no usable region. It
            # establishes that copying is configured and nothing about where
            # the copy lands, which is UNKNOWN -- not an off-site pass.
            return Response(Obj(
                id=db_system_id, display_name="mysql-blank-region",
                backup_policy=Obj(is_enabled=True, copy_policies=[
                    Obj(copy_to_region="   ", backup_copy_retention_in_days=30)])))
        return Response(Obj(
            id=db_system_id, display_name="mysql-dr",
            backup_policy=Obj(is_enabled=True, copy_policies=[
                Obj(copy_to_region=REMOTE, backup_copy_retention_in_days=90)])))


class PostgresqlClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.postgresqldbsystem.oc1..p1"),
                         Obj(id="ocid1.postgresqldbsystem.oc1..p2")])

    def get_db_system(self, db_system_id, **kw):
        if db_system_id.endswith("p2"):
            # No management_policy at all: unknown, not "no replication".
            return Response(Obj(id=db_system_id, display_name="pgsql-silent"))
        return Response(Obj(
            id=db_system_id, display_name="pgsql-dr",
            management_policy=Obj(backup_policy=Obj(
                kind="DAILY", retention_days=31,
                copy_policy=Obj(regions=[REMOTE], retention_period=90)))))


class DatabaseClient(BaseClient):
    def list_autonomous_databases(self, **kw):
        return Response([
            Obj(id="ocid1.adb.oc1..a1", db_name="ADBREMOTE",
                is_remote_data_guard_enabled=True, is_local_data_guard_enabled=True,
                disaster_recovery_region_type="REMOTE",
                peer_db_ids=["ocid1.adb.oc1..peer"]),
            # Local standby only: same region, so not alternate storage -- but
            # reporting it as "no replication" would understate what exists.
            Obj(id="ocid1.adb.oc1..a2", db_name="ADBLOCAL",
                is_remote_data_guard_enabled=False,
                is_local_data_guard_enabled=True),
            Obj(id="ocid1.adb.oc1..a3", db_name="ADBNONE",
                is_remote_data_guard_enabled=False,
                is_local_data_guard_enabled=False),
            Obj(id="ocid1.adb.oc1..a4", db_name="ADBSILENT"),
        ])


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
    oci.file_storage = types.SimpleNamespace(FileStorageClient=FileStorageClient)
    oci.core = types.SimpleNamespace(BlockstorageClient=BlockstorageClient)
    oci.mysql = types.SimpleNamespace(DbSystemClient=MysqlDbSystemClient)
    oci.psql = types.SimpleNamespace(PostgresqlClient=PostgresqlClient)
    oci.database = types.SimpleNamespace(DatabaseClient=DatabaseClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": HOME},
        validate_config=lambda config: None)
    return oci


def run(extra_args, tmp):
    argv = ["-r", HOME, "-o", str(tmp), "-c", SHARED, "--non-interactive",
            "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"] + list(extra_args)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = MODULE.main(argv, oci_module=build_sdk())
    return rc, buffer.getvalue()


def read_csv(tmp, marker):
    matches = sorted(Path(tmp).rglob(f"*{marker}*.csv"))
    assert matches, f"no CSV matching {marker} under {tmp}"
    with open(matches[0], newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def one(rows, source):
    hits = [r for r in rows if r["source_resource"] == source]
    assert len(hits) == 1, f"expected exactly one {source} row, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_configured_is_not_the_same_as_offsite_and_current():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "backup_replication_2")

        good = one(rows, "offsite-bucket")
        assert good["finding"] == "OK-OFFSITE-REPLICATION", good
        assert good["off_site"] == "YES" and good["destination_region"] == REMOTE

        # Healthy, configured, same region: must NOT read as off-site.
        same = one(rows, "sameregion-bucket")
        assert same["finding"] == "REPLICATION-SAME-REGION", same
        assert same["off_site"] == "NO", same

        paused = one(rows, "paused-bucket")
        assert paused["finding"] == "REPLICATION-UNHEALTHY-PAUSED", paused

        never = one(rows, "never-synced-bucket")
        assert never["finding"] == "REPLICATION-NEVER-SYNCED", never
        assert never["last_sync_or_recovery_point"] == "never"

        assert one(rows, "unreplicated-bucket")["finding"] == "NO-REPLICATION-CONFIGURED"

        # FSS does not expose the target region, so off-site must stay UNKNOWN
        # rather than being assumed either way.
        fs = one(rows, "fs-replication")
        assert fs["finding"] == "MANUAL-VERIFY-REPLICATION-TARGET-REGION", fs
        assert fs["off_site"] == "UNKNOWN", fs
        assert one(rows, "broken-replication")["finding"] == "REPLICATION-UNHEALTHY-FAILED"

        assert one(rows, "dr-policy")["finding"] == "OK-OFFSITE-REPLICATION"
        assert one(rows, "local-policy")["finding"] == "REPLICATION-SAME-REGION"
        assert one(rows, "no-copy-policy")["finding"] == "NO-REPLICATION-CONFIGURED"

        assert one(rows, "mysql-dr")["finding"] == "OK-OFFSITE-REPLICATION"
        assert one(rows, "pgsql-dr")["finding"] == "OK-OFFSITE-REPLICATION"

        assert one(rows, "ADBREMOTE")["finding"] == "OK-OFFSITE-REPLICATION"
        # Local-only standby is distinguished from having nothing at all.
        local = one(rows, "ADBLOCAL")
        assert local["finding"] == "LOCAL-DATA-GUARD-ONLY", local
        assert local["off_site"] == "NO", local
        assert one(rows, "ADBNONE")["finding"] == "NO-REPLICATION-CONFIGURED"

        # Silence is never a negative finding, on any service.
        for silent in ("mysql-silent", "pgsql-silent", "ADBSILENT"):
            assert one(rows, silent)["finding"] == "UNKNOWN-REPLICATION-CONFIG", silent

        coverage = read_csv(tmp, "coverage")
        assert all(r["collection_status"] == "OK" for r in coverage), coverage


@check
def test_denied_read_is_never_no_replication():
    Denials.replication_policies = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "object"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "backup_replication_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert not [r for r in rows if r["finding"] == "NO-REPLICATION-CONFIGURED"], rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
    finally:
        Denials.replication_policies = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
    with tempfile.TemporaryDirectory() as tmp:
        for argv, why in (
            (["-r", HOME, "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED], "missing --approve-scan"),
            (["-r", HOME, "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "yes"], "lowercase"),
            (["-r", HOME, "-o", tmp, "-c", SHARED, "--non-interactive",
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
def test_readonly_allowlist_is_the_complete_cloud_surface():
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name
    assert MODULE.source_selfcheck()



@check
def test_fss_health_comes_from_the_full_replication_not_the_summary():
    """ReplicationSummary declares no delta_status, so a FAILED replication
    could never match FSS_UNHEALTHY and was emitted as MANUAL-VERIFY."""
    with tempfile.TemporaryDirectory() as tmp:
        run(["-c", SHARED, "-s", "fss"], tmp)
        rows = [r for r in read_csv(tmp, "replication")
                if r["service"] == "FSSReplication"]
        by_name = {r["source_resource"]: r for r in rows}
        broken = by_name["broken-replication"]
        assert broken["finding"] == "REPLICATION-UNHEALTHY-FAILED", broken
        assert "delta=FAILED" in broken["replication_state"], broken
        healthy = by_name["fs-replication"]
        assert healthy["finding"] == "MANUAL-VERIFY-REPLICATION-TARGET-REGION", healthy
        # source_id lives only on the full model; a blank column would mean the
        # collector never read it.
        assert healthy["source_ocid"] == "ocid1.filesystem.oc1..fs1", healthy


@check
def test_denied_replication_detail_is_unknown_not_healthy():
    """A denied get_replication must not leave the replication looking fine."""
    Denials.fss_detail = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, _ = run(["-c", SHARED, "-s", "fss"], tmp)
            rows = [r for r in read_csv(tmp, "replication")
                    if r["service"] == "FSSReplication"]
            assert rows, "expected replication rows"
            for row in rows:
                # No health verdict may be emitted from a denied detail read.
                assert row["finding"] == "COLLECTION-FAILED", row
                assert row["collection_status"] == "DENIED", row
                assert "UNHEALTHY" not in row["finding"], row
            assert rc == 3, f"a denied detail read must not exit 0 (got {rc})"
    finally:
        Denials.fss_detail = False


def verdict_for(home_region):
    """A Collector built straight from a region string.

    Deliberately NOT routed through validate_argument_combination. That is where
    the lib normalizes args.region, and a check that went through it would be
    asserting the lib's behaviour while leaving offsite_verdict free to compare
    raw strings again. The collector has to be correct about a region it was
    handed, not only about one the validator happened to clean up first.
    """
    return MODULE.Collector(None, None, types.SimpleNamespace(region=home_region))


@check
def test_offsite_verdict_does_not_depend_on_region_spelling():
    """Two spellings of one region are one region.

    The failure this pins is directional: comparing the strings raw makes a
    SAME-region replica read as off_site=YES, which asserts CP-9(1) alternate
    storage on evidence that does not support it.
    """
    upper = verdict_for("US-LANGLEY-1")
    for destination in ("us-langley-1", " us-langley-1 ", "Us-Langley-1"):
        got = upper.offsite_verdict(destination)
        assert got == "NO", (f"scanned US-LANGLEY-1, destination {destination!r}: "
                             f"same region reported off_site={got}")

    lower = verdict_for(HOME)
    for destination in (HOME.upper(), f"  {HOME}  "):
        got = lower.offsite_verdict(destination)
        assert got == "NO", (f"scanned {HOME}, destination {destination!r}: "
                             f"same region reported off_site={got}")

    # A genuinely different region is still off-site, in either spelling.
    for home, destination in ((lower, REMOTE), (lower, REMOTE.upper()),
                              (upper, REMOTE)):
        got = home.offsite_verdict(destination)
        assert got == "YES", (f"scanned {home.home_region}, destination "
                              f"{destination!r}: expected YES, got {got}")


@check
def test_unknown_region_on_either_side_is_never_offsite():
    """YES has to come from a known destination AND a known scanned region."""
    known = verdict_for(HOME)
    for missing in ("", "   ", None):
        got = known.offsite_verdict(missing or "")
        assert got == "UNKNOWN", (f"destination {missing!r} established no "
                                  f"region, but off_site={got}")

    # Nothing to be "elsewhere" from: an unknown scanned region cannot produce
    # a pass either.
    for blank_home in ("", "   "):
        unknown_home = verdict_for(blank_home)
        for destination in (REMOTE, HOME):
            got = unknown_home.offsite_verdict(destination)
            assert got == "UNKNOWN", (f"scanned region {blank_home!r} is unknown, "
                                      f"destination {destination}: off_site={got}")


@check
def test_region_spelling_never_turns_a_same_region_copy_into_a_pass():
    """The same property, end to end, on every service that names a region."""
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "backup_replication_2")

        same = one(rows, "mixedcase-sameregion-bucket")
        assert same["off_site"] == "NO", same
        assert same["finding"] == "REPLICATION-SAME-REGION", same
        # Written normalized, so whoever adjudicates the CSV is not left
        # repeating the comparison that was just fixed.
        assert same["destination_region"] == HOME, same

        volume = one(rows, "mixedcase-local-policy")
        assert volume["off_site"] == "NO", volume
        assert volume["finding"] == "REPLICATION-SAME-REGION", volume
        assert volume["destination_region"] == HOME, volume

        # A named destination the API did not give: UNKNOWN, never YES.
        unnamed = one(rows, "unknown-destination-bucket")
        assert unnamed["off_site"] == "UNKNOWN", unnamed
        assert unnamed["finding"] == "UNKNOWN-REPLICATION-DESTINATION", unnamed

        # The copy-region path shares offsite_verdict and needs the same
        # UNKNOWN branch; it used to fall through to an off-site pass.
        blank = one(rows, "mysql-blank-region")
        assert blank["off_site"] == "UNKNOWN", blank
        assert blank["finding"] == "UNKNOWN-REPLICATION-DESTINATION", blank

        # And the genuine off-site copies are untouched.
        for source in ("offsite-bucket", "dr-policy", "mysql-dr", "pgsql-dr"):
            row = one(rows, source)
            assert row["off_site"] == "YES", row
            assert row["finding"] == "OK-OFFSITE-REPLICATION", row

        # No row anywhere claims off-site without naming where.
        for row in rows:
            if row["off_site"] == "YES":
                assert row["destination_region"] not in ("", "not-exposed"), row


@check
def test_unhealthy_delta_set_matches_the_sdk_enum():
    """Two members were invented and two real error states were missing."""
    assert MODULE.FSS_UNHEALTHY == {"FAILED", "SERVICE_ERROR", "USER_ERROR"}


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
        print(f"FAIL: CP09-03 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CP09-03 SDK off-site replication, health and same-region gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
