#!/usr/bin/env python3
#
# cm02-01/cm02-01-configuration-baseline.py
# Collector ID: CM02-01
#
# TASK 8 / CM-2, CM-2(2), CM-6 — BASELINE CONFIGURATION AND DRIFT
#
# OCI TOOLING:
#   Oracle's official OCI Python SDK, pinned in requirements-oci-sdk.txt.
#   Generated service clients, oci.pagination.list_call_get_all_results and
#   oci.retry.DEFAULT_RETRY_STRATEGY. No OCI CLI, no raw REST.
#
# PYTHON FILES USED:
#   lib/oci_audit_sdk.py         shared SDK primitives: auth, client
#                                construction, the runtime allowlist, scope
#                                discovery and confirmation, the coverage/error
#                                ledger and formula-safe CSV output
#   lib/oci_audit_inventory.py   resource enumeration shared with CM-8, and the
#                                metadata key summariser that keeps cloud-init
#                                user_data out of evidence
#
# Designed against the SDK response models directly. Not a translation of
# cm02-01-configuration-baseline.sh, which remains in place unchanged.
#
# CM-2 is a comparison, and a comparison needs two sides. OCI supplies the
# current configuration; the approved baseline is a governance input that no
# API can produce. This collector therefore does two separable things:
#
#   1. Always: capture the current configuration of every compute instance in
#      scope -- shape, image, launch options, agent plugins, legacy IMDS -- as
#      the CM-2 snapshot.
#   2. Only when --baseline is supplied: compare that snapshot against the
#      approved baseline CSV and classify each row.
#
# Without --baseline it reports the snapshot and says plainly that drift was
# not assessed. It does not invent a baseline from the current state, because a
# baseline derived from what is running cannot detect that what is running is
# wrong -- it would agree with any drift by construction.
#
# Baseline rows the snapshot does not account for are reported too. A component
# that has vanished since the baseline was approved is drift in the direction
# an inventory-only comparison never sees.
#
# Usage:
#   python3 cm02-01/cm02-01-configuration-baseline.py --selfcheck
#   python3 cm02-01/cm02-01-configuration-baseline.py -r us-langley-1 -o ./evidence
#   python3 cm02-01/cm02-01-configuration-baseline.py -r us-langley-1 \
#       --baseline ./approved-baseline.csv -c ocid1.compartment... \
#       --non-interactive --confirm-scope-ocid ocid1.compartment... \
#       --approve-scan YES
#
# Exit codes:
#   0  collection completed with no failed or unusable reads
#   1  precondition, scope or approval failure; nothing was collected
#   3  collection ran, but one or more reads failed or returned unusable data

from __future__ import annotations

import argparse
import ast
import csv
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    Ledger, ScanRefused, ScopeItem,
    add_standard_arguments, build_auth_context, build_client,
    confirm_targets_interactively, discover_scope, load_oci,
    print_scan_plan, require_final_approval, resolve_scope, sdk_get,
    sdk_list_items, selfcheck_allowlist, sha256_file, utc_now,
    validate_argument_combination, write_csv,
)
from oci_audit_inventory import metadata_key_summary  # noqa: E402

COLLECTOR = "cm02-01/cm02-01-configuration-baseline.py"
CONTROLS = "CM-2 / CM-2(2) / CM-6"

SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_instances",
    "get_image",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "resource_name", "resource_ocid",
    "lifecycle_state", "shape", "ocpus", "memory_gb", "image_name", "image_ocid",
    "launch_options", "legacy_imds", "agent_plugins", "metadata_keys",
    "baseline_status", "baseline_deviation", "finding", "control",
    "collection_status", "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

# Columns an approved baseline CSV must provide. Anything else in the file is
# carried through untouched; anything missing makes the file unusable rather
# than silently producing "no drift".
BASELINE_REQUIRED = ("resource_ocid", "shape", "image_name")

# Fields compared against the baseline, in report order.
COMPARED_FIELDS = ("shape", "image_name", "legacy_imds", "agent_plugins")

GONE_STATES = {"TERMINATED", "DELETED"}


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class BaselineUnusable(Exception):
    """The supplied baseline cannot be compared against; do not report no-drift."""


def load_baseline(path: str) -> Dict[str, Dict[str, str]]:
    """Read the approved baseline. A malformed file is an error, not an absence.

    Returning an empty mapping for an unreadable or wrong-shaped file would
    make every instance report NOT-IN-BASELINE, which reads as catastrophic
    drift caused entirely by a typo in a filename.
    """
    target = Path(path).expanduser()
    if not target.is_file():
        raise BaselineUnusable(f"baseline file not found: {path}")
    with target.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [c for c in BASELINE_REQUIRED if c not in fields]
        if missing:
            raise BaselineUnusable(
                "baseline is missing required columns: " + ", ".join(missing))
        rows = {}
        for row in reader:
            ocid = (row.get("resource_ocid") or "").strip()
            if ocid:
                rows[ocid] = {k: (v or "").strip() for k, v in row.items()}
    if not rows:
        raise BaselineUnusable("baseline contains no rows with a resource_ocid")
    return rows


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace,
                 baseline: Dict[str, Dict[str, str]] | None) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.baseline = baseline
        self.seen_ocids: Set[str] = set()
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}
        self._image_cache: Dict[str, str] = {}

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def blank(self) -> Dict[str, Any]:
        return {field: "" for field in EVIDENCE_FIELDS}

    def emit(self, row: Dict[str, Any]) -> None:
        complete = self.blank()
        complete.update(row)
        complete["control"] = CONTROLS
        complete.setdefault("collection_status", "OK")
        self.rows.append(complete)

    def failed(self, target: ScopeItem, name: str, exc: Exception) -> None:
        record = self.ledger.failed(target, "ComputeBaseline", exc)
        self.emit({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "resource_name": name, "resource_ocid": "UNKNOWN",
            "lifecycle_state": "UNKNOWN", "baseline_status": "UNKNOWN",
            "finding": "COLLECTION-FAILED",
            "collection_status": record.get("status", "ERROR"),
            "collection_error": record.get("message", ""),
        })

    def image_name(self, image_id: str) -> str:
        if not image_id:
            return "not-exposed"
        if image_id not in self._image_cache:
            client = self.client("compute", "core", "ComputeClient")
            try:
                image = sdk_get(self.oci, client, "get_image", SDK_READ_METHODS,
                                image_id=image_id).data
                self._image_cache[image_id] = text(image, "display_name", image_id)
            except Exception:
                self._image_cache[image_id] = f"UNRESOLVED-IMAGE:{image_id}"
        return self._image_cache[image_id]

    def snapshot(self, target: ScopeItem, instance: Any) -> Dict[str, Any]:
        shape_config = getattr(instance, "shape_config", None)
        launch = getattr(instance, "launch_options", None)
        options = getattr(instance, "instance_options", None)
        agent = getattr(instance, "agent_config", None)
        image_id = text(instance, "image_id") or text(
            getattr(instance, "source_details", None), "image_id")

        if agent is None:
            plugins = "not-exposed"
        elif getattr(agent, "are_all_plugins_disabled", False):
            plugins = "ALL-DISABLED"
        else:
            plugins = (
                f"management={'off' if getattr(agent, 'is_management_disabled', False) else 'on'};"
                f"monitoring={'off' if getattr(agent, 'is_monitoring_disabled', False) else 'on'}")

        legacy = getattr(options, "are_legacy_imds_endpoints_disabled", None) if options else None
        return {
            "compartment_id": target.ocid, "compartment_name": target.name,
            "resource_name": text(instance, "display_name", "instance"),
            "resource_ocid": text(instance, "id"),
            "lifecycle_state": text(instance, "lifecycle_state", "UNKNOWN"),
            "shape": text(instance, "shape", "not-exposed"),
            "ocpus": text(shape_config, "ocpus", "not-exposed") if shape_config else "not-exposed",
            "memory_gb": text(shape_config, "memory_in_gbs", "not-exposed") if shape_config else "not-exposed",
            "image_name": self.image_name(image_id),
            "image_ocid": image_id or "not-exposed",
            "launch_options": (
                f"firmware={text(launch, 'firmware', '?')};"
                f"network={text(launch, 'network_type', '?')};"
                f"boot-volume={text(launch, 'boot_volume_type', '?')}"
                if launch else "not-exposed"),
            "legacy_imds": ("DISABLED" if legacy else "ENABLED"
                            if legacy is not None else "not-exposed"),
            "agent_plugins": plugins,
            # Key names only; user_data is a cloud-init payload.
            "metadata_keys": metadata_key_summary(
                getattr(instance, "metadata", None),
                getattr(instance, "extended_metadata", None)),
        }

    def classify(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """Compare one snapshot against the approved baseline."""
        if self.baseline is None:
            snapshot["baseline_status"] = "NOT-ASSESSED"
            snapshot["baseline_deviation"] = "no-baseline-supplied"
            snapshot["finding"] = "SNAPSHOT-ONLY-NO-BASELINE"
            return snapshot

        approved = self.baseline.get(snapshot["resource_ocid"])
        if approved is None:
            # Running but not in the approved baseline: an unapproved component.
            snapshot["baseline_status"] = "NOT-IN-BASELINE"
            snapshot["baseline_deviation"] = "instance-absent-from-approved-baseline"
            snapshot["finding"] = "UNAPPROVED-COMPONENT"
            return snapshot

        deviations = []
        for field in COMPARED_FIELDS:
            expected = approved.get(field, "")
            if not expected:
                continue  # the baseline does not constrain this field
            actual = str(snapshot.get(field, ""))
            if expected != actual:
                deviations.append(f"{field}:expected={expected};actual={actual}")

        if deviations:
            snapshot["baseline_status"] = "DEVIATION"
            snapshot["baseline_deviation"] = " | ".join(deviations)
            snapshot["finding"] = "CONFIGURATION-DRIFT"
        else:
            snapshot["baseline_status"] = "MATCHES-BASELINE"
            snapshot["baseline_deviation"] = ""
            snapshot["finding"] = "OK-MATCHES-BASELINE"
        return snapshot

    def check_compute(self, target: ScopeItem) -> None:
        client = self.client("compute", "core", "ComputeClient")
        try:
            instances = sdk_list_items(self.oci, client, "list_instances",
                                       SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "<collection>", exc)
            return
        live = [i for i in instances
                if text(i, "lifecycle_state").upper() not in GONE_STATES]
        for instance in live:
            snapshot = self.snapshot(target, instance)
            self.seen_ocids.add(snapshot["resource_ocid"])
            self.emit(self.classify(snapshot))
        self.ledger.ok(target, "ComputeBaseline", len(live))

    def report_missing_baseline_rows(self, targets: Sequence[ScopeItem]) -> None:
        """Baseline entries with no live instance.

        Drift in this direction -- an approved component that is gone -- is
        invisible to a comparison that only walks what is currently running.
        """
        if self.baseline is None:
            return
        anchor = targets[0] if targets else None
        for ocid, approved in sorted(self.baseline.items()):
            if ocid in self.seen_ocids:
                continue
            self.emit({
                "compartment_id": anchor.ocid if anchor else "",
                "compartment_name": anchor.name if anchor else "",
                "resource_name": approved.get("resource_name", "<from-baseline>"),
                "resource_ocid": ocid,
                "lifecycle_state": "NOT-FOUND-IN-SCOPE",
                "shape": approved.get("shape", ""),
                "image_name": approved.get("image_name", ""),
                "baseline_status": "BASELINE-ROW-UNMATCHED",
                "baseline_deviation": "approved component not found in the scanned scope",
                "finding": "BASELINE-COMPONENT-MISSING",
            })

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        for target in targets:
            print(f"[CM-2] {target.name} ({target.ocid})")
            self.check_compute(target)
        self.report_missing_baseline_rows(targets)


def source_selfcheck() -> bool:
    if not selfcheck_allowlist(SDK_READ_METHODS, "cm02-01-configuration-baseline"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "launch_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript):
            value = node.value
            if isinstance(value, ast.Attribute) and value.attr in (
                    "metadata", "extended_metadata"):
                print(f"SELF-CHECK: FAILED — metadata value read at line "
                      f"{node.lineno}; use metadata_key_summary", file=sys.stderr)
                return False
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("--baseline",
                        help="approved baseline CSV; without it drift is not assessed")
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cm02-01-configuration-baseline)")
            print("Oracle SDK cloud methods are restricted to the explicit list/get "
                  "allowlist; instance metadata values are unreachable.")
            return 0
        return 1

    try:
        validate_argument_combination(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    baseline = None
    baseline_note = "no baseline supplied; drift not assessed"
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except BaselineUnusable as exc:
            # Fail before scanning. Proceeding would report every instance as
            # unapproved and call it drift.
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        baseline_note = (f"baseline={args.baseline};rows={len(baseline)};"
                         f"sha256={sha256_file(args.baseline)}")

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
    if out_root.name != "cm02-01":
        out_root = out_root / "cm02-01"
    outputs = {
        "evidence": str(out_root / f"cm02_01_configuration_baseline_{stamp}.csv"),
        "coverage": str(out_root / f"cm02_01_configuration_baseline_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cm02_01_configuration_baseline_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CM-2 BASELINE CONFIGURATION AND DRIFT", COLLECTOR, CONTROLS,
                    args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    f"instance shapes, images, launch options, agent plugins and "
                    f"metadata KEY NAMES only; {baseline_note}")

    try:
        require_final_approval(args, targets)
    except ScanRefused as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    collector = Collector(oci, context, args, baseline)
    collector.run(targets, [])

    write_csv(outputs["evidence"], EVIDENCE_FIELDS, collector.rows)
    write_csv(outputs["coverage"], COVERAGE_FIELDS, collector.ledger.coverage)
    if collector.ledger.errors:
        write_csv(outputs["errors"], ERROR_FIELDS, collector.ledger.errors)

    code = collector.ledger.exit_code()
    print(f"\nEvidence CSV written to: {outputs['evidence']}")
    print(f"Coverage CSV written to: {outputs['coverage']}")
    if collector.ledger.errors:
        print(f"Collection errors retained in: {outputs['errors']}")
    if baseline is None:
        print("NOTE     : no --baseline supplied. This run is a configuration "
              "snapshot only; CM-2 drift was NOT assessed.")
    print("RESULT   : " + ("COMPLETE" if code == 0 else "INCOMPLETE"))
    return code


if __name__ == "__main__":
    sys.exit(main())
