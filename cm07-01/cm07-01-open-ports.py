#!/usr/bin/env python3
#
# cm07-01/cm07-01-open-ports.py
# Collector ID: CM07-01
#
# TASK 6 / CM-7, CM-7(1), CA-9 — PORTS, PROTOCOLS AND SERVICES
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
# cm07-01-open-ports-protocols-services.sh, which remains in place unchanged.
#
# Two rule shapes and one scoping problem drive this design. Each produced a
# real defect in the predecessor, and each is handled deliberately here:
#
# 1. PORTLESS PROTOCOLS. ICMP (protocol 1) and ICMPv6 (58) have no ports; they
#    have type and code. Modelling them as 0-65535 makes every ICMP rule
#    overlap every port-scoped PPSM entry, so an ICMP rule matches a line that
#    says "TCP 3389 prohibited". Portless rules return no port range at all and
#    match only protocol-scoped entries, optionally narrowed by ICMP type/code.
#
# 2. TWO DIFFERENT RULE MODELS. Security lists use IngressSecurityRule and
#    EgressSecurityRule -- separate types, with source on one and destination on
#    the other and no direction field. NSGs use a single SecurityRule with an
#    explicit direction. Normalising both into one shape is what makes
#    reconciliation possible at all.
#
# 3. CROSS-COMPARTMENT REFERENCES. A subnet in scope can reference a security
#    list that lives in another compartment. list_security_lists is per
#    compartment, so a scan of one compartment sees the subnet but not its
#    rules. Referenced security lists are resolved by OCID with a read-only get;
#    when that fails the row is UNRESOLVED-SECURITY-LIST, never "no rules".
#
# The approved PPSM list is a governance input. Without --ppsm the collector
# reports every open port without adjudicating it, because an allowlist
# synthesised from what is currently open approves whatever is currently open.
#
# Usage:
#   python3 cm07-01/cm07-01-open-ports.py --selfcheck
#   python3 cm07-01/cm07-01-open-ports.py -r us-langley-1 -o ./evidence
#   python3 cm07-01/cm07-01-open-ports.py -r us-langley-1 --ppsm ./approved-ppsm.csv \
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
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    Ledger, ScanRefused, ScopeItem,
    add_standard_arguments, build_auth_context, build_client,
    confirm_targets_interactively, discover_scope, load_oci,
    print_scan_plan, require_final_approval, resolve_scope, sdk_get,
    sdk_list_items, selfcheck_allowlist, sha256_file, stable_hash, utc_now,
    validate_argument_combination, write_csv,
)

COLLECTOR = "cm07-01/cm07-01-open-ports.py"
CONTROLS = "CM-7 / CM-7(1) / CA-9"

SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_subnets",
    "list_security_lists",
    "get_security_list",
    "list_network_security_groups",
    "list_network_security_group_security_rules",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "container_type", "container_name",
    "container_ocid", "attached_to", "direction", "protocol", "protocol_name",
    "port_from", "port_to", "icmp_type", "icmp_code", "peer", "peer_type",
    "is_stateless", "description", "semantic_rule_key", "ppsm_status",
    "ppsm_reference", "finding", "control", "collection_status",
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

ALL_SERVICES = ["securitylists", "nsgs"]

# OCI writes protocols as IANA numbers, or "all". ICMP and ICMPv6 carry no
# ports -- that is the whole point of the portless handling below.
PROTOCOL_NAMES = {"1": "ICMP", "6": "TCP", "17": "UDP", "58": "ICMPv6",
                  "all": "ALL"}
PORTLESS_PROTOCOLS = {"1", "58"}

# Sources that expose a port to everything.
WORLD_SOURCES = {"0.0.0.0/0", "::/0"}

PPSM_REQUIRED = ("protocol", "port_from", "port_to", "direction", "disposition")
PPSM_DISPOSITIONS = {"APPROVED", "PROHIBITED", "RESTRICTED"}


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class PpsmUnusable(Exception):
    """The approved list cannot adjudicate; do not report everything approved."""


def load_ppsm(path: str) -> List[Dict[str, str]]:
    target = Path(path).expanduser()
    if not target.is_file():
        raise PpsmUnusable(f"PPSM list not found: {path}")
    with target.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames or []
        missing = [c for c in PPSM_REQUIRED if c not in fields]
        if missing:
            raise PpsmUnusable("PPSM list is missing required columns: "
                               + ", ".join(missing))
        rows = [{k: (v or "").strip() for k, v in row.items()} for row in reader]
    rows = [r for r in rows if r.get("disposition")]
    bad = sorted({r["disposition"].upper() for r in rows} - PPSM_DISPOSITIONS)
    if bad:
        raise PpsmUnusable("PPSM list has unknown dispositions: " + ", ".join(bad))
    if not rows:
        raise PpsmUnusable("PPSM list contains no usable rows")
    return rows


class Rule:
    """One normalised rule, from either rule model.

    port_range is None for portless protocols. That is the distinction that
    keeps an ICMP rule from matching a PPSM line scoped to TCP 3389.
    """

    def __init__(self, direction: str, protocol: str, peer: str, peer_type: str,
                 tcp_udp: Any, icmp: Any, stateless: Any, description: str) -> None:
        self.direction = direction
        self.protocol = str(protocol or "all")
        self.peer = peer
        self.peer_type = peer_type
        self.stateless = stateless
        self.description = description
        self.icmp_type = text(icmp, "type", "") if icmp is not None else ""
        self.icmp_code = text(icmp, "code", "") if icmp is not None else ""
        self.port_range: Optional[Tuple[int, int]] = None
        if self.protocol not in PORTLESS_PROTOCOLS and tcp_udp is not None:
            port_range = getattr(tcp_udp, "destination_port_range", None)
            if port_range is not None:
                low = getattr(port_range, "min", None)
                high = getattr(port_range, "max", None)
                if low is not None and high is not None:
                    self.port_range = (int(low), int(high))

    @property
    def protocol_name(self) -> str:
        return PROTOCOL_NAMES.get(self.protocol, f"IANA-{self.protocol}")

    @property
    def portless(self) -> bool:
        return self.protocol in PORTLESS_PROTOCOLS

    @property
    def ports(self) -> Tuple[str, str]:
        if self.port_range is None:
            # Portless, or a protocol-wide rule with no port constraint. Either
            # way there is no port to report, and inventing 0-65535 would make
            # this rule overlap every port-scoped PPSM entry.
            return ("n/a" if self.portless else "all", "n/a" if self.portless else "all")
        return (str(self.port_range[0]), str(self.port_range[1]))

    def semantic_key(self, container_ocid: str) -> str:
        """Stable identity for a rule across runs.

        Security-list rules have no OCID, so without this a reordered rule set
        looks like every rule was deleted and recreated.
        """
        low, high = self.ports
        return stable_hash([container_ocid, self.direction, self.protocol, low,
                            high, self.icmp_type, self.icmp_code, self.peer])


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace,
                 ppsm: List[Dict[str, str]] | None) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.ppsm = ppsm
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}
        self._seen_lists: Set[str] = set()

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
        if not complete["collection_status"]:
            complete["collection_status"] = "OK"
        self.rows.append(complete)

    def failed(self, target: ScopeItem, service: str, name: str,
               exc: Exception) -> None:
        record = self.ledger.failed(target, service, exc)
        self.emit({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "container_type": service, "container_name": name,
            "container_ocid": "UNKNOWN", "finding": "COLLECTION-FAILED",
            "ppsm_status": "UNKNOWN",
            "collection_status": record.get("status", "ERROR"),
            "collection_error": record.get("message", ""),
        })

    # -- PPSM reconciliation ----------------------------------------------

    def adjudicate(self, rule: Rule) -> Tuple[str, str, str]:
        """Return (ppsm_status, reference, finding) for one rule."""
        world = rule.direction == "INGRESS" and rule.peer in WORLD_SOURCES

        if self.ppsm is None:
            status, reference = "NOT-ADJUDICATED", "no-ppsm-supplied"
            finding = ("WORLD-OPEN-INGRESS" if world
                       else "OPEN-PORT-RECORDED-NOT-ADJUDICATED")
            return status, reference, finding

        match = self.match_ppsm(rule)
        if match is None:
            return ("NOT-ON-APPROVED-LIST", "",
                    "WORLD-OPEN-UNAPPROVED" if world else "UNAPPROVED-PORT")

        disposition = match.get("disposition", "").upper()
        reference = match.get("approval_id") or match.get("source_reference") or ""
        if disposition == "PROHIBITED":
            return "PROHIBITED", reference, "PROHIBITED-PORT-OPEN"
        if disposition == "RESTRICTED":
            return ("RESTRICTED", reference,
                    "RESTRICTED-PORT-WORLD-OPEN" if world else "RESTRICTED-PORT-OPEN")
        return ("APPROVED", reference,
                "APPROVED-BUT-WORLD-OPEN" if world else "OK-APPROVED-PORT")

    def match_ppsm(self, rule: Rule) -> Optional[Dict[str, str]]:
        """First matching PPSM row, prohibitions considered first.

        A rule that matches both a PROHIBITED and an APPROVED line must be
        reported as prohibited; taking whichever appears first in the file
        would make the finding depend on row order.
        """
        candidates = [r for r in self.ppsm or [] if self.ppsm_applies(rule, r)]
        if not candidates:
            return None
        for wanted in ("PROHIBITED", "RESTRICTED", "APPROVED"):
            for row in candidates:
                if row.get("disposition", "").upper() == wanted:
                    return row
        return candidates[0]

    def ppsm_applies(self, rule: Rule, entry: Dict[str, str]) -> bool:
        direction = entry.get("direction", "").upper()
        if direction and direction != rule.direction:
            return False

        entry_protocol = entry.get("protocol", "").strip().upper()
        if entry_protocol and entry_protocol not in ("ANY", "ALL"):
            if entry_protocol != rule.protocol_name.upper():
                return False

        if rule.portless:
            # A portless rule can only match a protocol-scoped entry. An entry
            # that names ports is about a port-bearing protocol, so it does not
            # describe this rule at all.
            if entry.get("port_from") or entry.get("port_to"):
                return False
            for field, actual in (("icmp_type", rule.icmp_type),
                                  ("icmp_code", rule.icmp_code)):
                wanted = entry.get(field, "").strip()
                if wanted and wanted != actual:
                    return False
            return True

        if rule.port_range is None:
            # Protocol-wide rule with no port constraint: it exposes every port,
            # so any port-scoped entry for this protocol describes part of it.
            return True

        low, high = rule.port_range
        try:
            entry_low = int(entry.get("port_from") or 0)
            entry_high = int(entry.get("port_to") or 65535)
        except ValueError:
            return False
        return low <= entry_high and entry_low <= high

    # -- rule emission -----------------------------------------------------

    def emit_rule(self, target: ScopeItem, container_type: str, name: str,
                  ocid: str, attached_to: str, rule: Rule) -> None:
        status, reference, finding = self.adjudicate(rule)
        low, high = rule.ports
        self.emit({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "container_type": container_type, "container_name": name,
            "container_ocid": ocid, "attached_to": attached_to,
            "direction": rule.direction, "protocol": rule.protocol,
            "protocol_name": rule.protocol_name,
            "port_from": low, "port_to": high,
            "icmp_type": rule.icmp_type or "n/a",
            "icmp_code": rule.icmp_code or "n/a",
            "peer": rule.peer, "peer_type": rule.peer_type,
            "is_stateless": ("YES" if rule.stateless else "NO"
                             if rule.stateless is not None else "not-exposed"),
            "description": (rule.description or "")[:200],
            "semantic_rule_key": rule.semantic_key(ocid),
            "ppsm_status": status, "ppsm_reference": reference,
            "finding": finding,
        })

    # -- security lists ----------------------------------------------------

    def security_list_rules(self, entry: Any) -> List[Rule]:
        rules: List[Rule] = []
        for item in getattr(entry, "ingress_security_rules", None) or []:
            rules.append(Rule("INGRESS", text(item, "protocol", "all"),
                              text(item, "source", "not-exposed"),
                              text(item, "source_type", "CIDR_BLOCK"),
                              getattr(item, "tcp_options", None)
                              or getattr(item, "udp_options", None),
                              getattr(item, "icmp_options", None),
                              getattr(item, "is_stateless", None),
                              text(item, "description")))
        for item in getattr(entry, "egress_security_rules", None) or []:
            rules.append(Rule("EGRESS", text(item, "protocol", "all"),
                              text(item, "destination", "not-exposed"),
                              text(item, "destination_type", "CIDR_BLOCK"),
                              getattr(item, "tcp_options", None)
                              or getattr(item, "udp_options", None),
                              getattr(item, "icmp_options", None),
                              getattr(item, "is_stateless", None),
                              text(item, "description")))
        return rules

    def check_securitylists(self, target: ScopeItem) -> None:
        client = self.client("vcn", "core", "VirtualNetworkClient")
        try:
            lists = sdk_list_items(self.oci, client, "list_security_lists",
                                   SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "SecurityList", "<collection>", exc)
            return
        for entry in lists:
            self.emit_security_list(target, entry, "in-compartment")
            self._seen_lists.add(text(entry, "id"))
        self.ledger.ok(target, "SecurityList", len(lists))
        self.resolve_referenced_lists(target, client)

    def emit_security_list(self, target: ScopeItem, entry: Any,
                           attached_to: str) -> None:
        name = text(entry, "display_name", "security-list")
        ocid = text(entry, "id")
        rules = self.security_list_rules(entry)
        if not rules:
            self.emit({
                "compartment_id": target.ocid, "compartment_name": target.name,
                "container_type": "SecurityList", "container_name": name,
                "container_ocid": ocid, "attached_to": attached_to,
                "finding": "NO-RULES-DEFINED", "ppsm_status": "N/A",
            })
            return
        for rule in rules:
            self.emit_rule(target, "SecurityList", name, ocid, attached_to, rule)

    def resolve_referenced_lists(self, target: ScopeItem, client: Any) -> None:
        """Security lists attached to in-scope subnets but held elsewhere.

        list_security_lists is per compartment. Without this, a subnet in scope
        whose security list lives in another compartment contributes no rules
        at all, and the run reports fewer open ports than exist.
        """
        try:
            subnets = sdk_list_items(self.oci, client, "list_subnets",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "SubnetAssociation", "<collection>", exc)
            return
        referenced: Dict[str, str] = {}
        for subnet in subnets:
            subnet_name = text(subnet, "display_name", "subnet")
            for list_id in getattr(subnet, "security_list_ids", None) or []:
                if list_id not in self._seen_lists:
                    referenced.setdefault(str(list_id), subnet_name)
        for list_id, subnet_name in sorted(referenced.items()):
            try:
                entry = sdk_get(self.oci, client, "get_security_list",
                                SDK_READ_METHODS, security_list_id=list_id).data
            except Exception as exc:
                # Unreadable, not empty. Reporting no rules here would understate
                # the exposed surface of a subnet that is in scope.
                record = self.ledger.failed(target, "ReferencedSecurityList", exc)
                self.emit({
                    "compartment_id": target.ocid,
                    "compartment_name": target.name,
                    "container_type": "SecurityList",
                    "container_name": f"<cross-compartment:{list_id}>",
                    "container_ocid": list_id,
                    "attached_to": f"subnet:{subnet_name}",
                    "finding": "UNRESOLVED-SECURITY-LIST",
                    "ppsm_status": "UNKNOWN",
                    "collection_status": record.get("status", "ERROR"),
                    "collection_error": record.get("message", ""),
                })
                continue
            self._seen_lists.add(list_id)
            self.emit_security_list(target, entry,
                                    f"cross-compartment via subnet:{subnet_name}")

    # -- network security groups -------------------------------------------

    def check_nsgs(self, target: ScopeItem) -> None:
        client = self.client("vcn", "core", "VirtualNetworkClient")
        try:
            groups = sdk_list_items(self.oci, client,
                                    "list_network_security_groups",
                                    SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "NetworkSecurityGroup", "<collection>", exc)
            return
        total = 0
        for group in groups:
            name = text(group, "display_name", "nsg")
            ocid = text(group, "id")
            try:
                rules = sdk_list_items(
                    self.oci, client,
                    "list_network_security_group_security_rules",
                    SDK_READ_METHODS, network_security_group_id=ocid)
            except Exception as exc:
                self.failed(target, "NetworkSecurityGroup", name, exc)
                continue
            if not rules:
                self.emit({
                    "compartment_id": target.ocid,
                    "compartment_name": target.name,
                    "container_type": "NetworkSecurityGroup",
                    "container_name": name, "container_ocid": ocid,
                    "finding": "NO-RULES-DEFINED", "ppsm_status": "N/A",
                })
                continue
            for item in rules:
                total += 1
                # NSG rules carry an explicit direction, unlike security lists.
                direction = text(item, "direction", "INGRESS").upper()
                peer = (text(item, "source") if direction == "INGRESS"
                        else text(item, "destination")) or "not-exposed"
                peer_type = (text(item, "source_type") if direction == "INGRESS"
                             else text(item, "destination_type")) or "CIDR_BLOCK"
                rule = Rule(direction, text(item, "protocol", "all"), peer,
                            peer_type,
                            getattr(item, "tcp_options", None)
                            or getattr(item, "udp_options", None),
                            getattr(item, "icmp_options", None),
                            getattr(item, "is_stateless", None),
                            text(item, "description"))
                self.emit_rule(target, "NetworkSecurityGroup", name, ocid,
                               f"nsg-membership;valid={text(item, 'is_valid', 'not-exposed')}",
                               rule)
        self.ledger.ok(target, "NetworkSecurityGroup", total)

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {"securitylists": self.check_securitylists, "nsgs": self.check_nsgs}
        for target in targets:
            print(f"[CM-7] {target.name} ({target.ocid})")
            self._seen_lists.clear()
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    if not selfcheck_allowlist(SDK_READ_METHODS, "cm07-01-open-ports"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    # add_ and remove_ are banned because the NSG service really does expose
    # add_network_security_group_security_rules and
    # remove_network_security_group_security_rules -- the two mutating calls a
    # CM-7 collector is most likely to reach for by mistake. argparse's
    # add_argument collides with that prefix and is not an SDK call, so it is
    # named as the one exception rather than weakening the prefix.
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "add_", "remove_")
    NON_SDK_ATTRIBUTES = {"add_argument", "add_argument_group", "add_mutually_exclusive_group"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr in NON_SDK_ATTRIBUTES:
            continue
        if any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    # There is deliberately no source scan for a literal 65535 here. The
    # property that matters -- an ICMP rule must not match a PPSM entry scoped
    # to TCP 3389 -- is behavioural, and the mock test asserts it directly by
    # feeding a portless rule against a port-scoped approved list. A source
    # grep for a magic number is a weak proxy for that, and it flagged its own
    # implementation, which is how such checks end up quietly weakened.
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    parser.add_argument("--ppsm",
                        help="approved PPSM CSV; without it open ports are "
                             "recorded but not adjudicated")
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cm07-01-open-ports)")
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

    ppsm = None
    ppsm_note = "no PPSM list supplied; open ports not adjudicated"
    if args.ppsm:
        try:
            ppsm = load_ppsm(args.ppsm)
        except PpsmUnusable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        ppsm_note = (f"ppsm={args.ppsm};rows={len(ppsm)};"
                     f"sha256={sha256_file(args.ppsm)}")

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
    if out_root.name != "cm07-01":
        out_root = out_root / "cm07-01"
    outputs = {
        "evidence": str(out_root / f"cm07_01_open_ports_{stamp}.csv"),
        "coverage": str(out_root / f"cm07_01_open_ports_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cm07_01_open_ports_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CM-7 PORTS, PROTOCOLS AND SERVICES", COLLECTOR, CONTROLS,
                    args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    f"security list and NSG rules, peers, port ranges and ICMP "
                    f"type/code; {ppsm_note}")

    try:
        require_final_approval(args, targets)
    except ScanRefused as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    collector = Collector(oci, context, args, ppsm)
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
    if ppsm is None:
        print("NOTE     : no --ppsm supplied. Open ports were recorded but NOT "
              "adjudicated against an approved list.")
    print("RESULT   : " + ("COMPLETE" if code == 0 else "INCOMPLETE"))
    return code


if __name__ == "__main__":
    sys.exit(main())
