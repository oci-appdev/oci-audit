#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CM02-01 and CM08-01 collectors.

They share lib/oci_audit_inventory.py, so they share one mock SDK and one test.

Fixtures mirror real SDK response models, verified against oci==2.185.1. The
instance fixtures deliberately carry realistic metadata -- an ssh_authorized_keys
value and a base64 cloud-init user_data payload with a password in it -- because
the property most worth testing is that neither reaches a CSV.

PYTHON FILES USED:
  cm02-01/cm02-01-configuration-baseline.py   collector under test
  cm08-01/cm08-01-component-inventory.py      collector under test
  lib/oci_audit_inventory.py                  shared enumeration
  lib/oci_audit_sdk.py                        loaded transitively
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
TENANCY = "ocid1.tenancy.oc1..cmmock"
SHARED = "ocid1.compartment.oc1..sharedservices"

SECRET_USER_DATA = "I2Nsb3VkLWNvbmZpZwpwYXNzd29yZDogaHVudGVyMg=="
SECRET_SSH_KEY = "ssh-rsa AAAAB3NzaC1yc2ETESTKEYMATERIAL admin@example"


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CM02 = load("cm0201", "cm02-01/cm02-01-configuration-baseline.py")
CM08 = load("cm0801", "cm08-01/cm08-01-component-inventory.py")


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
    search = False
    instances = False


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


INSTANCES = [
    Obj(id="ocid1.instance.oc1..web1", display_name="web-01",
        lifecycle_state="RUNNING", availability_domain="mock-AD-1",
        time_created="2026-01-01T00:00:00Z", shape="VM.Standard.E4.Flex",
        shape_config=Obj(ocpus=2, memory_in_gbs=32),
        image_id="ocid1.image.oc1..ol8",
        launch_options=Obj(firmware="UEFI_64", network_type="PARAVIRTUALIZED",
                           boot_volume_type="PARAVIRTUALIZED"),
        instance_options=Obj(are_legacy_imds_endpoints_disabled=True),
        agent_config=Obj(is_management_disabled=False, is_monitoring_disabled=False),
        metadata={"ssh_authorized_keys": SECRET_SSH_KEY,
                  "user_data": SECRET_USER_DATA, "hostname": "web-01"}),
    # Drifted: wrong shape and a disabled monitoring agent.
    Obj(id="ocid1.instance.oc1..web2", display_name="web-02",
        lifecycle_state="RUNNING", availability_domain="mock-AD-1",
        time_created="2026-02-01T00:00:00Z", shape="VM.Standard.E5.Flex",
        shape_config=Obj(ocpus=4, memory_in_gbs=64),
        image_id="ocid1.image.oc1..ol8",
        instance_options=Obj(are_legacy_imds_endpoints_disabled=False),
        agent_config=Obj(are_all_plugins_disabled=True),
        metadata={"user_data": SECRET_USER_DATA}),
    # Running but absent from the approved baseline.
    Obj(id="ocid1.instance.oc1..rogue", display_name="rogue-01",
        lifecycle_state="RUNNING", availability_domain="mock-AD-1",
        time_created="2026-08-01T00:00:00Z", shape="VM.Standard.E4.Flex",
        image_id="ocid1.image.oc1..ol8"),
    # Terminated: must not appear at all.
    Obj(id="ocid1.instance.oc1..dead", display_name="old-01",
        lifecycle_state="TERMINATED", shape="VM.Standard.E2.1"),
]


class ComputeClient(BaseClient):
    def list_instances(self, **kw):
        if Denials.instances:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "list instances was denied")
        return Response(list(INSTANCES))

    def get_image(self, image_id, **kw):
        if image_id.endswith("ol8"):
            return Response(Obj(id=image_id, display_name="Oracle-Linux-8.9-2026.01"))
        raise ServiceError(404, "NotFound", "image not found")


class ResourceSearchClient(BaseClient):
    def list_resource_types(self, **kw):
        return Response([Obj(name=n) for n in
                         ("Instance", "Vcn", "Bucket", "AutonomousDatabase",
                          "Vault", "LoadBalancer")])

    def search_resources(self, search_details, **kw):
        if Denials.search:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "search resources was denied")
        return Response([
            Obj(identifier="ocid1.instance.oc1..web1", display_name="web-01",
                resource_type="Instance", lifecycle_state="RUNNING",
                availability_domain="mock-AD-1", time_created="2026-01-01T00:00:00Z",
                freeform_tags={"env": "prod"},
                defined_tags={"Operations": {"Owner": "team-a"}}),
            Obj(identifier="ocid1.vcn.oc1..v1", display_name="core-vcn",
                resource_type="Vcn", lifecycle_state="AVAILABLE"),
            Obj(identifier="ocid1.bucket.oc1..b1", display_name="evidence",
                resource_type="Bucket", lifecycle_state="ACTIVE"),
            # An unmapped type must still be inventoried, as OTHER.
            Obj(identifier="ocid1.exotic.oc1..x1", display_name="exotic-thing",
                resource_type="QuantumWidget", lifecycle_state="ACTIVE"),
            # Terminated: excluded.
            Obj(identifier="ocid1.instance.oc1..dead", display_name="old-01",
                resource_type="Instance", lifecycle_state="TERMINATED"),
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
    oci.core = types.SimpleNamespace(ComputeClient=ComputeClient)
    oci.resource_search = types.SimpleNamespace(
        ResourceSearchClient=ResourceSearchClient,
        models=types.SimpleNamespace(
            StructuredSearchDetails=lambda **kw: Obj(**kw)))
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


def run(module, extra_args, tmp):
    argv = ["-r", "us-langley-1", "-o", str(tmp), "-c", SHARED, "--non-interactive",
            "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"] + list(extra_args)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = module.main(argv, oci_module=build_sdk())
    return rc, buffer.getvalue()


def read_csv(tmp, marker):
    matches = sorted(Path(tmp).rglob(f"*{marker}*.csv"))
    assert matches, f"no CSV matching {marker} under {tmp}"
    with open(matches[0], newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def one(rows, name, key="resource_name"):
    hits = [r for r in rows if r[key] == name]
    assert len(hits) == 1, f"expected exactly one {name} row, got {len(hits)}"
    return hits[0]


def write_baseline(tmp, rows, fields=("resource_ocid", "resource_name", "shape",
                                      "image_name", "legacy_imds", "agent_plugins")):
    path = Path(tmp) / "baseline.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        writer.writerows(rows)
    return str(path)


APPROVED = [
    {"resource_ocid": "ocid1.instance.oc1..web1", "resource_name": "web-01",
     "shape": "VM.Standard.E4.Flex", "image_name": "Oracle-Linux-8.9-2026.01",
     "legacy_imds": "DISABLED", "agent_plugins": "management=on;monitoring=on"},
    {"resource_ocid": "ocid1.instance.oc1..web2", "resource_name": "web-02",
     "shape": "VM.Standard.E4.Flex", "image_name": "Oracle-Linux-8.9-2026.01",
     "legacy_imds": "DISABLED", "agent_plugins": "management=on;monitoring=on"},
    # Approved but no longer running: drift the running-set never sees.
    {"resource_ocid": "ocid1.instance.oc1..retired", "resource_name": "retired-01",
     "shape": "VM.Standard.E4.Flex", "image_name": "Oracle-Linux-8.9-2026.01",
     "legacy_imds": "DISABLED", "agent_plugins": "management=on;monitoring=on"},
]

CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_cm02_drift_classification_against_an_approved_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(CM02, ["--baseline", write_baseline(tmp, APPROVED)], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "configuration_baseline_2")

        good = one(rows, "web-01")
        assert good["finding"] == "OK-MATCHES-BASELINE", good
        assert good["shape"] == "VM.Standard.E4.Flex"
        assert good["image_name"] == "Oracle-Linux-8.9-2026.01"
        assert good["legacy_imds"] == "DISABLED"

        drift = one(rows, "web-02")
        assert drift["finding"] == "CONFIGURATION-DRIFT", drift
        assert "shape:expected=VM.Standard.E4.Flex" in drift["baseline_deviation"]
        assert "legacy_imds:expected=DISABLED;actual=ENABLED" in drift["baseline_deviation"]
        assert "agent_plugins" in drift["baseline_deviation"], drift

        assert one(rows, "rogue-01")["finding"] == "UNAPPROVED-COMPONENT"
        # An approved component that is gone is drift the running set misses.
        retired = one(rows, "retired-01")
        assert retired["finding"] == "BASELINE-COMPONENT-MISSING", retired
        assert retired["lifecycle_state"] == "NOT-FOUND-IN-SCOPE"

        assert not [r for r in rows if r["resource_name"] == "old-01"], "terminated included"


@check
def test_cm02_without_a_baseline_does_not_claim_no_drift():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(CM02, [], tmp)
        assert rc == 0, (rc, out)
        assert "drift was NOT assessed" in out, out
        rows = read_csv(tmp, "configuration_baseline_2")
        assert rows and all(r["finding"] == "SNAPSHOT-ONLY-NO-BASELINE" for r in rows), rows
        assert all(r["baseline_status"] == "NOT-ASSESSED" for r in rows), rows


@check
def test_cm02_unusable_baseline_fails_before_scanning():
    """A bad baseline must not become 'every instance is unapproved'."""
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "wrong-columns.csv"
        bad.write_text("name,size\nweb-01,large\n", encoding="utf-8")
        for path, why in ((str(bad), "missing required columns"),
                          (str(Path(tmp) / "nope.csv"), "file not found")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = CM02.main(["-r", "us-langley-1", "-o", tmp, "-c", SHARED,
                                "--non-interactive", "--confirm-scope-ocid", SHARED,
                                "--approve-scan", "YES", "--baseline", path],
                               oci_module=build_sdk())
            assert rc == 1, (why, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*configuration_baseline*.csv")), \
            "an unusable baseline still produced evidence"


@check
def test_no_instance_metadata_value_reaches_evidence():
    """user_data and ssh_authorized_keys must never leave the collector."""
    with tempfile.TemporaryDirectory() as tmp:
        run(CM02, ["--baseline", write_baseline(tmp, APPROVED)], tmp)
        run(CM08, [], tmp)
        csvs = [p for p in Path(tmp).rglob("*.csv") if p.name != "baseline.csv"]
        assert csvs, "no evidence written"
        for path in csvs:
            body = path.read_text(encoding="utf-8")
            for secret in (SECRET_USER_DATA, SECRET_SSH_KEY, "hunter2", "ssh-rsa"):
                assert secret not in body, (path.name, secret)
        # The key NAMES are evidence and must survive, marked redacted.
        rows = read_csv(tmp, "configuration_baseline_2")
        keys = one(rows, "web-01")["metadata_keys"]
        assert "user_data(redacted)" in keys and "ssh_authorized_keys(redacted)" in keys, keys
        assert "hostname" in keys, keys


@check
def test_cm08_inventory_states_its_own_boundary():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(CM08, [], tmp)
        assert rc == 0, (rc, out)
        assert "eventually consistent" in out, out
        rows = read_csv(tmp, "component_inventory_2")

        assert one(rows, "core-vcn")["component_class"] == "NETWORK"
        assert one(rows, "evidence")["component_class"] == "STORAGE"
        # An unrecognised type is still inventoried, never dropped.
        exotic = one(rows, "exotic-thing")
        assert exotic["component_class"] == "OTHER", exotic
        assert not [r for r in rows if r["resource_name"] == "old-01"], "terminated included"

        web = [r for r in rows if r["resource_name"] == "web-01"]
        sources = {r["inventory_source"] for r in web}
        assert sources == {"RESOURCE-SEARCH-INDEX", "COMPUTE-SERVICE"}, sources
        enriched = [r for r in web if r["inventory_source"] == "COMPUTE-SERVICE"][0]
        assert "ocpus=2" in enriched["shape"], enriched
        assert enriched["image_or_version"] == "Oracle-Linux-8.9-2026.01"
        indexed = [r for r in web if r["inventory_source"] == "RESOURCE-SEARCH-INDEX"][0]
        assert "Operations.Owner" in indexed["tag_keys"], indexed

        coverage = read_csv(tmp, "coverage")
        inv = [r for r in coverage if r["service"] == "ResourceInventory"]
        assert inv and "queryable-types=6" in inv[0]["collection_error"], coverage
        assert "eventually-consistent" in inv[0]["collection_error"], coverage


@check
def test_denied_reads_are_never_an_empty_inventory():
    Denials.search = True
    Denials.instances = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(CM08, [], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "component_inventory_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
            assert not [r for r in rows if r["finding"] == "OK-INVENTORIED"], rows
    finally:
        Denials.search = False
        Denials.instances = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
    for module in (CM02, CM08):
        with tempfile.TemporaryDirectory() as tmp:
            for argv, why in (
                (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
                  "--confirm-scope-ocid", SHARED], "missing --approve-scan"),
                (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
                  "--confirm-scope-ocid", SHARED, "--approve-scan", "yes"], "lowercase"),
                (["-o", tmp, "-c", SHARED, "--non-interactive",
                  "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"], "no region"),
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = module.main(argv, oci_module=build_sdk())
                assert rc == 1, (module.COLLECTOR, why, rc, buf.getvalue())
            assert not list(Path(tmp).rglob("*.csv")), "a refused scan wrote evidence"


@check
def test_readonly_allowlists_are_the_complete_cloud_surface():
    for module in (CM02, CM08):
        for name in module.SDK_READ_METHODS:
            assert name.startswith(("list_", "get_", "search_")), (module.COLLECTOR, name)
        assert module.source_selfcheck(), module.COLLECTOR


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
        print(f"FAIL: CM02-01/CM08-01 SDK collectors ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CM02-01 drift classification and CM08-01 inventory, "
          "metadata-secret and fail-closed gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
