#!/usr/bin/env python3
#
# cm11-01/cm11-01-software-installation-control.py
# Collector ID: CM11-01
#
# TASK 7 / CM-11, CM-11(2), CM-7(5) — SOFTWARE INSTALLATION CONTROL
#
# OCI TOOLING:
#   Oracle's official OCI Python SDK, pinned in requirements-oci-sdk.txt.
#   Generated service clients, oci.pagination.list_call_get_all_results and
#   oci.retry.DEFAULT_RETRY_STRATEGY. No OCI CLI, no raw REST.
#
# PYTHON FILES USED:
#   lib/oci_audit_sdk.py   shared SDK primitives: auth, client construction,
#                          the runtime list_*/get_* allowlist, scope discovery
#                          and confirmation, the coverage/error ledger and
#                          formula-safe CSV output
#
# Designed against the SDK response models directly. Not a translation of
# cm11-01-software-installation-control.sh, which remains in place unchanged.
#
# CM-11 is two questions that are easy to conflate:
#
#   1. WHO is entitled to install software? That is an IAM question, answered
#      from policy statements granting package install through OS Management
#      Hub, image provisioning through Compute, or publish through Container
#      Registry.
#   2. WHAT is actually installed, and did it come from an approved source?
#      That is answered from the managed instances' installed-package
#      inventories and the software sources those packages came from.
#
# The model detail that matters: InstalledPackageSummary reports provenance in
# a `software_sources` LIST of SoftwareSourceDetails objects. There is no
# software_source_name or software_source_id field -- reading those yields
# nothing, and a collector that then falls back to the package `type` reports
# every package's source as "RPM", which is a format, not a provenance. A
# package whose software_sources list is empty has UNKNOWN provenance and is a
# real CM-11 finding; it is not the same as a package from an unapproved
# source, and not the same as a failed read.
#
# Approved-source and authorised-installer lists are governance inputs. Without
# --approved-sources the collector reports provenance without adjudicating it,
# rather than inventing an allowlist from whatever it happens to find.
#
# Usage:
#   python3 cm11-01/cm11-01-software-installation-control.py --selfcheck
#   python3 cm11-01/cm11-01-software-installation-control.py -r us-langley-1 -o ./evidence
#   python3 cm11-01/cm11-01-software-installation-control.py -r us-langley-1 \
#       --approved-sources ./approved-software-sources.csv \
#       -c ocid1.compartment... --non-interactive \
#       --confirm-scope-ocid ocid1.compartment... --approve-scan YES
#
# Exit codes:
#   0  collection completed with no failed or unusable reads
#   1  precondition, scope or approval failure; nothing was collected
#   3  collection ran, but one or more reads failed or returned unusable data

from __future__ import annotations

import argparse
import ast
import csv
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    Ledger, ScanRefused, ScopeItem,
    add_standard_arguments, build_auth_context, build_client,
    confirm_targets_interactively, discover_scope, iso, load_oci,
    print_scan_plan, require_final_approval, resolve_scope,
    sdk_list_items, selfcheck_allowlist, sha256_file, utc_now,
    validate_argument_combination, write_csv,
)

COLLECTOR = "cm11-01/cm11-01-software-installation-control.py"
CONTROLS = "CM-11 / CM-11(2) / CM-7(5)"

SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_policies",
    "list_managed_instances",
    "list_managed_instance_installed_packages",
    "list_software_sources",
    "list_container_repositories",
    "list_container_images",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "control_surface", "subject",
    "subject_ocid", "detail", "provenance", "provenance_type",
    "approval_status", "finding", "control", "collection_status",
    "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["entitlement", "sources", "packages", "images"]

# IAM resource families through which software reaches a system.
INSTALL_RESOURCE_TOKENS = (
    "osmh-family", "management-agent-family", "instance-family",
    "instance-images", "repos", "artifacts", "generic-artifacts-family",
    "software-sources", "managed-instances", "all-resources",
)
BROAD_SCOPE = re.compile(r"\bin\s+tenancy\b", re.IGNORECASE)
ANY_USER = re.compile(r"\ballow\s+any-user\b", re.IGNORECASE)

# Required columns in an approved-source list. A file without them cannot
# adjudicate anything, and pretending otherwise would mark every package
# unapproved.
APPROVED_REQUIRED = ("software_source_name",)


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class ApprovalListUnusable(Exception):
    """The supplied approved-source list cannot adjudicate; do not guess."""


def load_approved_sources(path: str) -> Set[str]:
    target = Path(path).expanduser()
    if not target.is_file():
        raise ApprovalListUnusable(f"approved-source list not found: {path}")
    with target.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [c for c in APPROVED_REQUIRED if c not in fields]
        if missing:
            raise ApprovalListUnusable(
                "approved-source list is missing required columns: " + ", ".join(missing))
        names = {(row.get("software_source_name") or "").strip()
                 for row in reader}
    names.discard("")
    if not names:
        raise ApprovalListUnusable("approved-source list contains no source names")
    return names


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace,
                 approved: Set[str] | None) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.approved = approved
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def row(self, target: ScopeItem, surface: str, subject: str, ocid: str,
            finding: str, *, detail: str = "", provenance: str = "",
            provenance_type: str = "", approval: str = "",
            status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "control_surface": surface, "subject": subject, "subject_ocid": ocid,
            "detail": detail, "provenance": provenance,
            "provenance_type": provenance_type, "approval_status": approval,
            "finding": finding, "control": CONTROLS,
            "collection_status": status, "collection_error": error,
        })

    def failed(self, target: ScopeItem, surface: str, subject: str,
               exc: Exception) -> None:
        record = self.ledger.failed(target, surface, exc)
        self.row(target, surface, subject, "UNKNOWN", "COLLECTION-FAILED",
                 provenance="UNKNOWN", approval="UNKNOWN",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    # -- who may install ---------------------------------------------------

    def check_entitlement(self, target: ScopeItem) -> None:
        client = self.client("identity", "identity", "IdentityClient")
        try:
            policies = sdk_list_items(self.oci, client, "list_policies",
                                      SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "InstallEntitlement", "<collection>", exc)
            return
        for policy in policies:
            name = text(policy, "name", "policy")
            ocid = text(policy, "id")
            statements = getattr(policy, "statements", None)
            if statements is None:
                self.row(target, "InstallEntitlement", name, ocid,
                         "UNKNOWN-POLICY-STATEMENTS",
                         detail="statements-not-exposed")
                continue
            for statement in statements:
                self.emit_statement(target, name, ocid, str(statement))
        self.ledger.ok(target, "InstallEntitlement", len(policies))

    def emit_statement(self, target: ScopeItem, name: str, ocid: str,
                       statement: str) -> None:
        lowered = statement.lower()
        touched = [t for t in INSTALL_RESOURCE_TOKENS if t in lowered]
        if not touched:
            return
        manage = "manage" in lowered
        if ANY_USER.search(statement):
            finding = "ANY-USER-INSTALL-GRANT"
        elif manage and BROAD_SCOPE.search(statement):
            finding = "BROAD-INSTALL-GRANT"
        elif manage:
            finding = "INSTALL-GRANT"
        else:
            finding = "INSTALL-ADJACENT-GRANT"
        self.row(target, "InstallEntitlement", name, ocid, finding,
                 detail=statement[:400],
                 provenance=",".join(sorted(set(touched))),
                 provenance_type="IAM-POLICY-STATEMENT",
                 approval="REQUIRES-AUTHORIZED-INSTALLER-LIST")

    # -- configured software sources ---------------------------------------

    def check_sources(self, target: ScopeItem) -> None:
        client = self.client("osmh_source", "os_management_hub", "SoftwareSourceClient")
        try:
            sources = sdk_list_items(self.oci, client, "list_software_sources",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "SoftwareSource", "<collection>", exc)
            return
        for source in sources:
            name = text(source, "display_name", "software-source")
            self.row(target, "SoftwareSource", name, text(source, "id"),
                     self.adjudicate(name, "OK-APPROVED-SOURCE",
                                     "UNAPPROVED-SOURCE"),
                     detail=f"url={text(source, 'url', 'not-exposed')}",
                     provenance=name,
                     provenance_type=text(source, "software_source_type", "UNKNOWN"),
                     approval=self.approval_label(name))
        self.ledger.ok(target, "SoftwareSource", len(sources))

    def approval_label(self, name: str) -> str:
        if self.approved is None:
            return "NOT-ADJUDICATED"
        return "APPROVED" if name in self.approved else "NOT-ON-APPROVED-LIST"

    def adjudicate(self, name: str, ok_finding: str, bad_finding: str) -> str:
        if self.approved is None:
            return "SOURCE-RECORDED-NOT-ADJUDICATED"
        return ok_finding if name in self.approved else bad_finding

    # -- what is installed -------------------------------------------------

    def check_packages(self, target: ScopeItem) -> None:
        client = self.client("osmh_instance", "os_management_hub",
                             "ManagedInstanceClient")
        try:
            instances = sdk_list_items(self.oci, client, "list_managed_instances",
                                       SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "InstalledPackage", "<managed-instances>", exc)
            return
        total = 0
        for instance in instances:
            instance_id = text(instance, "id")
            instance_name = text(instance, "display_name", "managed-instance")
            try:
                packages = sdk_list_items(
                    self.oci, client, "list_managed_instance_installed_packages",
                    SDK_READ_METHODS, managed_instance_id=instance_id)
            except Exception as exc:
                # A denied package listing must never read as "nothing installed".
                self.failed(target, "InstalledPackage", instance_name, exc)
                continue
            for package in packages:
                total += 1
                self.emit_package(target, instance_name, instance_id, package)
        self.ledger.ok(target, "InstalledPackage", total)

    def emit_package(self, target: ScopeItem, instance_name: str,
                     instance_id: str, package: Any) -> None:
        name = text(package, "display_name") or text(package, "name", "package")
        version = text(package, "version", "not-exposed")
        # Provenance is a LIST of SoftwareSourceDetails. There is no
        # software_source_name field; falling back to package `type` would
        # report the format (RPM) as the provenance.
        sources = getattr(package, "software_sources", None) or []
        source_names = [text(s, "display_name") for s in sources
                        if text(s, "display_name")]
        detail = (f"instance={instance_name};version={version};"
                  f"classification={text(package, 'package_classification', 'not-exposed')};"
                  f"installed={iso(getattr(package, 'time_installed', None)) or 'not-exposed'}")

        if not source_names:
            # No declared source: installed outside managed software sources,
            # which is exactly what CM-11 exists to detect. Distinct from a
            # source that is merely unapproved, and from a failed read.
            self.row(target, "InstalledPackage", f"{instance_name}:{name}",
                     instance_id, "UNKNOWN-PACKAGE-PROVENANCE", detail=detail,
                     provenance="no-software-source-declared",
                     provenance_type=text(package, "type", "not-exposed"),
                     approval="CANNOT-ADJUDICATE")
            return

        unapproved = ([s for s in source_names if s not in self.approved]
                      if self.approved is not None else [])
        if self.approved is None:
            finding, approval = "SOURCE-RECORDED-NOT-ADJUDICATED", "NOT-ADJUDICATED"
        elif unapproved:
            finding, approval = "UNAPPROVED-PACKAGE-SOURCE", "NOT-ON-APPROVED-LIST"
        else:
            finding, approval = "OK-APPROVED-SOURCE", "APPROVED"
        self.row(target, "InstalledPackage", f"{instance_name}:{name}",
                 instance_id, finding, detail=detail,
                 provenance=";".join(sorted(set(source_names))),
                 provenance_type=text(package, "type", "not-exposed"),
                 approval=approval)

    # -- container images --------------------------------------------------

    def check_images(self, target: ScopeItem) -> None:
        client = self.client("artifacts", "artifacts", "ArtifactsClient")
        try:
            repositories = sdk_list_items(self.oci, client,
                                          "list_container_repositories",
                                          SDK_READ_METHODS,
                                          compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ContainerRepository", "<collection>", exc)
            return
        for repository in repositories:
            public = getattr(repository, "is_public", None)
            name = text(repository, "display_name", "repository")
            if public is True:
                finding = "PUBLIC-CONTAINER-REPOSITORY"
            elif public is False:
                finding = "OK-PRIVATE-REPOSITORY"
            else:
                finding = "UNKNOWN-REPOSITORY-VISIBILITY"
            self.row(target, "ContainerRepository", name,
                     text(repository, "id"), finding,
                     detail=f"images={text(repository, 'image_count', 'not-exposed')}",
                     provenance="OCI-CONTAINER-REGISTRY",
                     provenance_type="CONTAINER-IMAGE-SOURCE",
                     approval=self.approval_label(name))
        try:
            images = sdk_list_items(self.oci, client, "list_container_images",
                                    SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ContainerImage", "<collection>", exc)
            return
        for image in images:
            self.row(target, "ContainerImage",
                     text(image, "display_name", "image"), text(image, "id"),
                     "OK-INVENTORIED",
                     detail=f"repository={text(image, 'repository_name', 'not-exposed')};"
                            f"version={text(image, 'version', 'not-exposed')}",
                     provenance=text(image, "repository_name", "not-exposed"),
                     provenance_type="CONTAINER-IMAGE",
                     approval=self.approval_label(
                         text(image, "repository_name", "")))
        self.ledger.ok(target, "ContainerRepository", len(repositories))
        self.ledger.ok(target, "ContainerImage", len(images))

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "entitlement": self.check_entitlement, "sources": self.check_sources,
            "packages": self.check_packages, "images": self.check_images,
        }
        for target in targets:
            print(f"[CM-11] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


# Fields that do not exist on InstalledPackageSummary. Naming them here lets the
# self-check refuse the exact mistake that once made every package report its
# provenance as "RPM".
NONEXISTENT_PACKAGE_FIELDS = ("software_source_name", "software_source_id")


def source_selfcheck() -> bool:
    if not selfcheck_allowlist(SDK_READ_METHODS, "cm11-01-software-installation-control"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "install_", "remove_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    # Only a READ of these names off an SDK object is the defect. The
    # approved-source CSV legitimately has a software_source_name column, so a
    # bare string literal is not evidence of the mistake -- what matters is
    # attribute access, or the name passed to text()/getattr() as a field.
    def flagged(node: ast.AST) -> str:
        if isinstance(node, ast.Attribute) and node.attr in NONEXISTENT_PACKAGE_FIELDS:
            return node.attr
        if isinstance(node, ast.Call):
            func = node.func
            fname = getattr(func, "id", None) or getattr(func, "attr", None)
            if fname in ("text", "getattr") and len(node.args) >= 2:
                second = node.args[1]
                if (isinstance(second, ast.Constant)
                        and second.value in NONEXISTENT_PACKAGE_FIELDS):
                    return str(second.value)
        return ""

    for node in ast.walk(tree):
        name = flagged(node)
        if name:
            print(f"SELF-CHECK: FAILED — {name} at line {node.lineno} is not a field "
                  "on InstalledPackageSummary; provenance is the software_sources list",
                  file=sys.stderr)
            return False
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    parser.add_argument("--approved-sources",
                        help="approved software-source CSV; without it provenance "
                             "is recorded but not adjudicated")
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cm11-01-software-installation-control)")
            print("Oracle SDK cloud methods are restricted to the explicit list/get allowlist.")
            return 0
        return 1

    services = args.services.split()
    unknown = [s for s in services if s not in ALL_SERVICES]
    if unknown:
        print(f"ERROR: unknown service selector: {', '.join(unknown)}", file=sys.stderr)
        return 1

    try:
        validate_argument_combination(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    approved = None
    approval_note = "no approved-source list supplied; provenance not adjudicated"
    if args.approved_sources:
        try:
            approved = load_approved_sources(args.approved_sources)
        except ApprovalListUnusable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        approval_note = (f"approved-sources={args.approved_sources};"
                         f"entries={len(approved)};"
                         f"sha256={sha256_file(args.approved_sources)}")

    oci = oci_module if oci_module is not None else load_oci()
    context = build_auth_context(oci, args)
    identity = build_client(oci, context, "identity", "IdentityClient")

    try:
        catalog = discover_scope(oci, identity, context.tenancy_id, SDK_READ_METHODS)
        selected, targets, confirmed = resolve_scope(args, catalog)
        if not args.non_interactive and not confirmed:
            confirm_targets_interactively(targets)
    except Exception as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    out_root = Path(args.output_dir)
    if out_root.name != "cm11-01":
        out_root = out_root / "cm11-01"
    outputs = {
        "evidence": str(out_root / f"cm11_01_software_installation_{stamp}.csv"),
        "coverage": str(out_root / f"cm11_01_software_installation_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cm11_01_software_installation_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CM-11 SOFTWARE INSTALLATION CONTROL", COLLECTOR, CONTROLS,
                    args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    f"IAM install entitlement, software sources, installed "
                    f"package provenance and container images; {approval_note}")

    try:
        require_final_approval(args, targets)
    except ScanRefused as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    collector = Collector(oci, context, args, approved)
    collector.run(targets, services)

    write_csv(outputs["evidence"], EVIDENCE_FIELDS, collector.rows)
    write_csv(outputs["coverage"], COVERAGE_FIELDS, collector.ledger.coverage)
    if collector.ledger.errors:
        write_csv(outputs["errors"], ERROR_FIELDS, collector.ledger.errors)

    code = collector.ledger.exit_code()
    print(f"\nEvidence CSV written to: {outputs['evidence']}")
    print(f"Coverage CSV written to: {outputs['coverage']}")
    if collector.ledger.errors:
        print(f"Collection errors retained in: {outputs['errors']}")
    if approved is None:
        print("NOTE     : no --approved-sources supplied. Provenance was recorded "
              "but NOT adjudicated against an approved list.")
    print("RESULT   : " + ("COMPLETE" if code == 0 else "INCOMPLETE"))
    return code


if __name__ == "__main__":
    sys.exit(main())
