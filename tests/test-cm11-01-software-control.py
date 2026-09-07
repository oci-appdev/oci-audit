#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CM11-01 SDK collector.

Fixtures mirror real SDK response models, verified against oci==2.185.1. The
installed-package fixtures matter most: InstalledPackageSummary reports
provenance in a software_sources LIST of SoftwareSourceDetails, and has no
software_source_name field at all. A collector reading the missing field and
falling back to the package `type` reports every package's source as "RPM" --
a format, not a provenance.

PYTHON FILES USED:
  cm11-01/cm11-01-software-installation-control.py   collector under test
  lib/oci_audit_sdk.py                               loaded transitively
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
TENANCY = "ocid1.tenancy.oc1..cm11mock"
SHARED = "ocid1.compartment.oc1..sharedservices"

_spec = importlib.util.spec_from_file_location(
    "cm1101", ROOT / "cm11-01" / "cm11-01-software-installation-control.py")
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
    packages = False


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
            Obj(id="ocid1.policy.oc1..p1", name="patch-admins", statements=[
                "Allow group PatchAdmins to manage osmh-family in tenancy",
                "Allow group Builders to use instance-images in compartment Shared",
                "Allow group Network to manage virtual-network-family in tenancy",
            ]),
            Obj(id="ocid1.policy.oc1..p2", name="open-repos", statements=[
                "Allow any-user to manage repos in tenancy",
            ]),
            Obj(id="ocid1.policy.oc1..p3", name="opaque-policy"),
        ])


class SoftwareSourceClient(BaseClient):
    def list_software_sources(self, **kw):
        return Response([
            Obj(id="ocid1.swsrc.oc1..s1", display_name="ol8-baseos-approved",
                software_source_type="VENDOR", url="https://approved.example/ol8"),
            Obj(id="ocid1.swsrc.oc1..s2", display_name="thirdparty-extras",
                software_source_type="CUSTOM", url="https://random.example/extras"),
        ])


class ManagedInstanceClient(BaseClient):
    def list_managed_instances(self, **kw):
        return Response([Obj(id="ocid1.managedinstance.oc1..m1",
                             display_name="app-01")])

    def list_managed_instance_installed_packages(self, managed_instance_id, **kw):
        if Denials.packages:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "list installed packages was denied")
        return Response([
            # Provenance is the software_sources LIST. There is deliberately no
            # software_source_name field on any of these, because the real model
            # has none.
            Obj(name="openssl", display_name="openssl", version="3.0.7-1",
                type="RPM", package_classification="SECURITY",
                time_installed="2026-05-01T00:00:00Z",
                software_sources=[Obj(id="ocid1.swsrc.oc1..s1",
                                      display_name="ol8-baseos-approved",
                                      software_source_type="VENDOR")]),
            Obj(name="customtool", display_name="customtool", version="1.2.3",
                type="RPM", package_classification="OTHER",
                software_sources=[Obj(id="ocid1.swsrc.oc1..s2",
                                      display_name="thirdparty-extras",
                                      software_source_type="CUSTOM")]),
            # No declared source: installed outside managed software sources.
            Obj(name="hand-installed", display_name="hand-installed",
                version="0.9", type="RPM"),
        ])


class ArtifactsClient(BaseClient):
    def list_container_repositories(self, **kw):
        return Response([
            Obj(id="ocid1.containerrepo.oc1..r1", display_name="internal-apps",
                is_public=False, image_count=4),
            Obj(id="ocid1.containerrepo.oc1..r2", display_name="public-mirror",
                is_public=True, image_count=1),
        ])

    def list_container_images(self, **kw):
        return Response([Obj(id="ocid1.containerimage.oc1..i1",
                             display_name="internal-apps:web-1.4",
                             repository_name="internal-apps", version="1.4")])


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_all(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(list_call_get_all_results=list_all)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.os_management_hub = types.SimpleNamespace(
        SoftwareSourceClient=SoftwareSourceClient,
        ManagedInstanceClient=ManagedInstanceClient)
    oci.artifacts = types.SimpleNamespace(ArtifactsClient=ArtifactsClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


def run(extra_args, tmp):
    argv = ["-r", "us-langley-1", "-o", str(tmp), "-c", SHARED, "--non-interactive",
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


def one(rows, subject):
    hits = [r for r in rows if r["subject"] == subject]
    assert len(hits) == 1, f"expected exactly one {subject} row, got {len(hits)}"
    return hits[0]


def write_approved(tmp, names):
    path = Path(tmp) / "approved-sources.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["software_source_name"])
        writer.writeheader()
        writer.writerows([{"software_source_name": n} for n in names])
    return str(path)


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_package_provenance_comes_from_the_software_sources_list():
    with tempfile.TemporaryDirectory() as tmp:
        approved = write_approved(tmp, ["ol8-baseos-approved", "internal-apps"])
        rc, out = run(["--approved-sources", approved], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "software_installation_2")

        ok = one(rows, "app-01:openssl")
        assert ok["finding"] == "OK-APPROVED-SOURCE", ok
        # The provenance must be the source NAME, never the package format.
        assert ok["provenance"] == "ol8-baseos-approved", ok
        assert ok["provenance"] != "RPM", ok

        bad = one(rows, "app-01:customtool")
        assert bad["finding"] == "UNAPPROVED-PACKAGE-SOURCE", bad
        assert bad["provenance"] == "thirdparty-extras", bad

        # No declared source is its own finding: not unapproved, not a failure.
        orphan = one(rows, "app-01:hand-installed")
        assert orphan["finding"] == "UNKNOWN-PACKAGE-PROVENANCE", orphan
        assert orphan["provenance"] == "no-software-source-declared", orphan
        assert orphan["approval_status"] == "CANNOT-ADJUDICATE", orphan

        assert one(rows, "ol8-baseos-approved")["finding"] == "OK-APPROVED-SOURCE"
        assert one(rows, "thirdparty-extras")["finding"] == "UNAPPROVED-SOURCE"

        assert one(rows, "internal-apps")["finding"] == "OK-PRIVATE-REPOSITORY"
        assert one(rows, "public-mirror")["finding"] == "PUBLIC-CONTAINER-REPOSITORY"

        entitle = [r for r in rows if r["control_surface"] == "InstallEntitlement"]
        assert not [r for r in entitle if "virtual-network" in r["detail"]], entitle
        assert [r for r in entitle if r["finding"] == "BROAD-INSTALL-GRANT"], entitle
        assert [r for r in entitle if r["finding"] == "ANY-USER-INSTALL-GRANT"], entitle
        assert one(rows, "opaque-policy")["finding"] == "UNKNOWN-POLICY-STATEMENTS"

        coverage = read_csv(tmp, "coverage")
        assert all(r["collection_status"] == "OK" for r in coverage), coverage


@check
def test_without_an_approved_list_nothing_is_adjudicated():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(["-s", "packages sources"], tmp)
        assert rc == 0, (rc, out)
        assert "NOT adjudicated" in out, out
        rows = read_csv(tmp, "software_installation_2")
        adjudicated = [r for r in rows
                       if r["finding"] in ("OK-APPROVED-SOURCE", "UNAPPROVED-SOURCE",
                                           "UNAPPROVED-PACKAGE-SOURCE")]
        assert not adjudicated, adjudicated
        # A package with no source is still a finding without an approved list.
        assert one(rows, "app-01:hand-installed")["finding"] == "UNKNOWN-PACKAGE-PROVENANCE"


@check
def test_unusable_approved_list_fails_before_scanning():
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "wrong.csv"
        bad.write_text("name\nol8\n", encoding="utf-8")
        for path in (str(bad), str(Path(tmp) / "missing.csv")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MODULE.main(["-r", "us-langley-1", "-o", tmp, "-c", SHARED,
                                  "--non-interactive", "--confirm-scope-ocid", SHARED,
                                  "--approve-scan", "YES", "--approved-sources", path],
                                 oci_module=build_sdk())
            assert rc == 1, (path, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*software_installation*.csv")), \
            "an unusable approved list still produced evidence"


@check
def test_denied_package_listing_is_never_nothing_installed():
    Denials.packages = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "packages"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "software_installation_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
    finally:
        Denials.packages = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
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
            failures += 1
            print(f"  FAIL {fn.__name__}: unexpected "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
    if failures:
        print(f"FAIL: CM11-01 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CM11-01 SDK package provenance, entitlement and fail-closed gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
