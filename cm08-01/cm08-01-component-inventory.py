#!/usr/bin/env python3
#
# cm08-01/cm08-01-component-inventory.py
# Collector ID: CM08-01
#
# TASK 9 / CM-8, CM-8(1) — INFORMATION SYSTEM COMPONENT INVENTORY
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
#   lib/oci_audit_inventory.py   resource enumeration shared with CM-2, and the
#                                metadata key summariser that keeps cloud-init
#                                user_data out of evidence
#
# Designed against the SDK response models directly. Not a translation of
# cm08-01-component-inventory-baseline.sh or cm08-hw-sw-baseline.sh, which
# remain in place unchanged.
#
# The honesty problem in a component inventory is the word "complete". This
# collector enumerates through Resource Search, which is an eventually
# consistent index rather than the services themselves: a resource created
# moments ago may not appear, and the index only covers the types the service
# knows about. An inventory that quietly implies exhaustiveness is worse
# evidence than one that states its own boundary, so the coverage ledger
# records how many resource types were queryable and the run reports the index
# as its source. CM-8(1) completeness is then a reconciliation against the
# authoritative asset register, not something this collector can assert alone.
#
# Compute instances are enriched from the Compute service directly, because an
# inventory that cannot say which image and shape a host runs is not a baseline
# anyone can compare against. Their metadata is summarised by key name only --
# Instance.metadata carries ssh_authorized_keys and cloud-init user_data, and
# user_data commonly embeds bootstrap credentials.
#
# Usage:
#   python3 cm08-01/cm08-01-component-inventory.py --selfcheck
#   python3 cm08-01/cm08-01-component-inventory.py -r us-langley-1 -o ./evidence
#   python3 cm08-01/cm08-01-component-inventory.py -r us-langley-1 \
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
    sdk_list_items, selfcheck_allowlist, utc_now,
    validate_argument_combination, write_csv,
)
from oci_audit_inventory import (  # noqa: E402
    INVENTORY_READ_METHODS, SEARCH_METHOD, metadata_key_summary,
    resource_row, search_compartment, searchable_types,
)

COLLECTOR = "cm08-01/cm08-01-component-inventory.py"
CONTROLS = "CM-8 / CM-8(1)"

SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_instances",
    "get_image",
    SEARCH_METHOD,
} | INVENTORY_READ_METHODS

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "resource_type", "resource_name",
    "resource_ocid", "lifecycle_state", "availability_domain", "time_created",
    "tag_keys", "component_class", "shape", "image_or_version",
    "metadata_keys", "monitoring_agent", "inventory_source",
    "finding", "control", "collection_status", "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["resources", "compute"]

# Resource types grouped into the component classes an inventory is read by.
# Anything unmapped is reported as OTHER rather than dropped -- a component the
# collector does not recognise still belongs in the inventory.
COMPONENT_CLASS = {
    "Instance": "COMPUTE", "Image": "COMPUTE", "BootVolume": "STORAGE",
    "Volume": "STORAGE", "FileSystem": "STORAGE", "Bucket": "STORAGE",
    "VolumeBackup": "STORAGE", "BootVolumeBackup": "STORAGE",
    "Vcn": "NETWORK", "Subnet": "NETWORK", "SecurityList": "NETWORK",
    "NetworkSecurityGroup": "NETWORK", "RouteTable": "NETWORK",
    "InternetGateway": "NETWORK", "NatGateway": "NETWORK",
    "ServiceGateway": "NETWORK", "Drg": "NETWORK", "LoadBalancer": "NETWORK",
    "NetworkLoadBalancer": "NETWORK", "PublicIp": "NETWORK",
    "AutonomousDatabase": "DATABASE", "DbSystem": "DATABASE",
    "Database": "DATABASE", "MysqlDbSystem": "DATABASE",
    "PostgresqlDbSystem": "DATABASE",
    "Vault": "SECURITY", "Key": "SECURITY", "Policy": "SECURITY",
    "Group": "IDENTITY", "User": "IDENTITY", "DynamicGroup": "IDENTITY",
    "Cluster": "CONTAINER", "NodePool": "CONTAINER",
    "FunctionsApplication": "SERVERLESS", "FunctionsFunction": "SERVERLESS",
}

GONE_STATES = {"TERMINATED", "DELETED"}


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}
        self._image_cache: Dict[str, str] = {}
        self.types_available = 0

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def row(self, base: Dict[str, Any], component_class: str, source: str,
            finding: str, *, shape: str = "", image: str = "",
            metadata_keys: str = "", monitoring: str = "",
            status: str = "OK", error: str = "") -> None:
        row = dict(base)
        row.update({
            "component_class": component_class, "shape": shape,
            "image_or_version": image, "metadata_keys": metadata_keys,
            "monitoring_agent": monitoring, "inventory_source": source,
            "finding": finding, "control": CONTROLS,
            "collection_status": status, "collection_error": error,
        })
        self.rows.append(row)

    def failed(self, target: ScopeItem, service: str, name: str,
               exc: Exception) -> None:
        record = self.ledger.failed(target, service, exc)
        self.row({"compartment_id": target.ocid, "compartment_name": target.name,
                  "resource_type": service, "resource_name": name,
                  "resource_ocid": "UNKNOWN", "lifecycle_state": "UNKNOWN",
                  "availability_domain": "UNKNOWN", "time_created": "UNKNOWN",
                  "tag_keys": "UNKNOWN"},
                 "UNKNOWN", service, "COLLECTION-FAILED",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    # -- indexed enumeration ----------------------------------------------

    def check_resources(self, target: ScopeItem) -> None:
        client = self.client("search", "resource_search", "ResourceSearchClient")
        # Read the type catalogue so coverage can state the index's breadth
        # rather than leaving "complete" to be assumed.
        try:
            types = searchable_types(self.oci, client, SDK_READ_METHODS)
            self.types_available = len(types)
        except Exception as exc:
            self.failed(target, "ResourceTypeCatalog", "<collection>", exc)
            types = []

        try:
            items = search_compartment(self.oci, client, SDK_READ_METHODS,
                                       target.ocid)
        except Exception as exc:
            self.failed(target, "ResourceInventory", "<collection>", exc)
            return

        counted = 0
        for item in items:
            base = resource_row(target, item)
            if base["lifecycle_state"].upper() in GONE_STATES:
                continue
            counted += 1
            resource_type = base["resource_type"]
            self.row(base, COMPONENT_CLASS.get(resource_type, "OTHER"),
                     "RESOURCE-SEARCH-INDEX", "OK-INVENTORIED")
        # The ledger records the index's own boundary alongside the count.
        self.ledger.coverage.append({
            "compartment_ocid": target.ocid, "compartment_name": target.name,
            "service": "ResourceInventory", "assets_found": counted,
            "collection_status": "OK",
            "collection_error": (f"source=resource-search-index;"
                                 f"queryable-types={self.types_available};"
                                 f"index-is-eventually-consistent"),
        })

    # -- compute enrichment ------------------------------------------------

    def image_name(self, image_id: str) -> str:
        """Resolve image OCIDs once; many instances share an image."""
        if not image_id:
            return "not-exposed"
        if image_id not in self._image_cache:
            client = self.client("compute", "core", "ComputeClient")
            try:
                image = sdk_get(self.oci, client, "get_image", SDK_READ_METHODS,
                                image_id=image_id).data
                self._image_cache[image_id] = text(image, "display_name", image_id)
            except Exception:
                # An unreadable image is recorded as unresolved, not guessed.
                self._image_cache[image_id] = f"UNRESOLVED-IMAGE:{image_id}"
        return self._image_cache[image_id]

    def check_compute(self, target: ScopeItem) -> None:
        client = self.client("compute", "core", "ComputeClient")
        try:
            instances = sdk_list_items(self.oci, client, "list_instances",
                                       SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ComputeInstance", "<collection>", exc)
            return
        live = [i for i in instances if text(i, "lifecycle_state").upper() not in GONE_STATES]
        for instance in live:
            base = {
                "compartment_id": target.ocid, "compartment_name": target.name,
                "resource_type": "Instance",
                "resource_name": text(instance, "display_name", "instance"),
                "resource_ocid": text(instance, "id"),
                "lifecycle_state": text(instance, "lifecycle_state", "UNKNOWN"),
                "availability_domain": text(instance, "availability_domain", "UNKNOWN"),
                "time_created": text(instance, "time_created", "not-exposed"),
                "tag_keys": "see-resource-search-row",
            }
            agent = getattr(instance, "agent_config", None)
            if agent is None:
                monitoring = "not-exposed"
            elif getattr(agent, "are_all_plugins_disabled", False):
                monitoring = "ALL-PLUGINS-DISABLED"
            else:
                monitoring = (
                    f"management={'off' if getattr(agent, 'is_management_disabled', False) else 'on'};"
                    f"monitoring={'off' if getattr(agent, 'is_monitoring_disabled', False) else 'on'}")
            # Key names only. Never the values: user_data is a cloud-init
            # payload that routinely carries bootstrap credentials.
            keys = metadata_key_summary(getattr(instance, "metadata", None),
                                        getattr(instance, "extended_metadata", None))
            shape_config = getattr(instance, "shape_config", None)
            shape = text(instance, "shape", "not-exposed")
            if shape_config is not None:
                shape += (f";ocpus={text(shape_config, 'ocpus', '?')}"
                          f";memory-gb={text(shape_config, 'memory_in_gbs', '?')}")
            image_id = text(instance, "image_id") or text(
                getattr(instance, "source_details", None), "image_id")
            self.row(base, "COMPUTE", "COMPUTE-SERVICE", "OK-INVENTORIED",
                     shape=shape, image=self.image_name(image_id),
                     metadata_keys=keys, monitoring=monitoring)
        self.ledger.ok(target, "ComputeInstance", len(live))

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {"resources": self.check_resources, "compute": self.check_compute}
        for target in targets:
            print(f"[CM-8] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    # selfcheck_allowlist already permits the search_ prefix, then screens the
    # name for sensitivity like any other read.
    if not selfcheck_allowlist(SDK_READ_METHODS, "cm08-01-component-inventory"):
        return False
    try:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "launch_", "instance_action")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    # Metadata values must never be emitted. metadata_key_summary is the only
    # supported reader; a direct subscript of an instance metadata mapping is
    # how a user_data payload would reach a CSV.
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
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cm08-01-component-inventory)")
            print("Oracle SDK cloud methods are restricted to the explicit "
                  "list/get/search allowlist; instance metadata values are unreachable.")
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
    if out_root.name != "cm08-01":
        out_root = out_root / "cm08-01"
    outputs = {
        "evidence": str(out_root / f"cm08_01_component_inventory_{stamp}.csv"),
        "coverage": str(out_root / f"cm08_01_component_inventory_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cm08_01_component_inventory_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CM-8 COMPONENT INVENTORY", COLLECTOR, CONTROLS, args,
                    context, selected, targets, SDK_READ_METHODS, outputs.values(),
                    "resource OCIDs, types, lifecycle states, compute shapes "
                    "and images, and metadata KEY NAMES only")

    try:
        require_final_approval(args, targets)
    except ScanRefused as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    collector = Collector(oci, context, args)
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
    print("NOTE     : enumeration source is the Resource Search index, which is "
          "eventually consistent. CM-8(1) completeness requires reconciliation "
          "against the authoritative asset register.")
    print("RESULT   : " + ("COMPLETE" if code == 0 else "INCOMPLETE"))
    return code


if __name__ == "__main__":
    sys.exit(main())
