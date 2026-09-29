#!/usr/bin/env python3
"""Read-only OCI old/new network and pre-cutoff resource gap analysis.

This collector never deletes or changes an OCI resource.  It inventories
network containers and common network-attached services, builds dependency
edges, and produces conservative keep/decommission-review candidates.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
GAP_COMMON = SCRIPT_PATH.parent
sys.path.insert(0, str(GAP_COMMON))
sys.path.insert(0, str(REPO_ROOT / "lib"))

from gap_common import (  # noqa: E402
    IDENTITY_SCOPE_METHODS,
    EvidenceRuntime,
    ScopeItem,
    add_common_arguments,
    begin_run,
    finish_run,
    output_paths,
    parse_work,
    pipe,
    source_selfcheck,
    text,
    value,
)
from oci_audit_sdk import iso, stable_hash, write_csv  # noqa: E402

COLLECTOR = "OCI-NETWORK-GAP-01"
CONTROLS = "Environment decommission planning / CM-8 supporting evidence"

WORK = (
    "core-network",
    "compute",
    "load-balancers",
    "databases",
    "platform-services",
)

CORE_METHODS = {
    "list_vcns",
    "list_subnets",
    "list_vlans",
    "list_route_tables",
    "list_security_lists",
    "list_dhcp_options",
    "list_internet_gateways",
    "list_nat_gateways",
    "list_service_gateways",
    "list_local_peering_gateways",
    "list_drgs",
    "list_drg_attachments",
    "list_network_security_groups",
    "list_private_ips",
}
COMPUTE_METHODS = {
    "list_instances",
    "list_vnic_attachments",
    "list_volumes",
    "list_volume_groups",
    "list_boot_volumes",
    "list_volume_attachments",
    "list_boot_volume_attachments",
    "list_availability_domains",
    "list_private_ips",
    "get_vnic",
}
LB_METHODS = {"list_load_balancers", "list_network_load_balancers"}
DATABASE_METHODS = {
    "list_db_systems",
    "list_autonomous_databases",
    "list_vm_clusters",
    "list_cloud_vm_clusters",
}
PLATFORM_METHODS = {
    "list_availability_domains",
    "list_clusters",
    "list_gateways",
    "list_bastions",
    "list_mount_targets",
    "list_file_systems",
    "list_exports",
    "list_applications",
}
SDK_READ_METHODS = (
    IDENTITY_SCOPE_METHODS
    | CORE_METHODS
    | COMPUTE_METHODS
    | LB_METHODS
    | DATABASE_METHODS
    | PLATFORM_METHODS
)

ARTIFACTS = (
    "plan",
    "resources",
    "keep_candidates",
    "destroy_review_candidates",
    "holds_and_other_review",
    "old_landing_zone_resources",
    "dependencies",
    "unresolved_links",
    "decision_template",
    "coverage",
    "errors",
    "summary",
    "manifest",
)

RESOURCE_FIELDS = [
    "resource_key",
    "resource_type",
    "resource_name",
    "resource_ocid",
    "compartment_name",
    "compartment_ocid",
    "old_landing_zone",
    "old_landing_zone_root_ocids",
    "lifecycle_state",
    "time_created",
    "created_before_cutoff",
    "age_status",
    "network_class",
    "network_basis",
    "cidrs",
    "ip_addresses",
    "vcn_ocids",
    "subnet_ocids",
    "vlan_ocids",
    "depends_on_count",
    "dependent_count",
    "suggested_disposition",
    "confidence",
    "reason",
]
DEPENDENCY_FIELDS = [
    "source_key",
    "source_type",
    "source_name",
    "source_ocid",
    "relationship",
    "target_key",
    "target_type",
    "target_name",
    "target_ocid",
    "resolution_status",
]
UNRESOLVED_FIELDS = [
    "source_key",
    "source_type",
    "source_name",
    "source_ocid",
    "relationship",
    "target_ocid",
    "impact",
]
DECISION_FIELDS = [
    "resource_key",
    "resource_type",
    "resource_name",
    "resource_ocid",
    "time_created",
    "network_class",
    "old_landing_zone",
    "old_landing_zone_root_ocids",
    "suggested_disposition",
    "approved_decision",
    "business_owner",
    "technical_owner",
    "migration_status",
    "dependency_review_complete",
    "backup_or_export_verified",
    "retention_or_legal_hold_checked",
    "security_owner_approval",
    "change_ticket",
    "planned_action_date",
    "reviewer",
    "approval_date",
    "notes",
]


@dataclass
class Resource:
    key: str
    resource_type: str
    resource_name: str
    resource_ocid: str
    compartment_name: str
    compartment_ocid: str
    lifecycle_state: str
    time_created: Any
    cidrs: Set[str] = field(default_factory=set)
    ip_addresses: Set[str] = field(default_factory=set)
    vcn_ocids: Set[str] = field(default_factory=set)
    subnet_ocids: Set[str] = field(default_factory=set)
    vlan_ocids: Set[str] = field(default_factory=set)
    network_class: str = "UNRESOLVED"
    network_basis: Set[str] = field(default_factory=set)
    unresolved_refs: Set[str] = field(default_factory=set)
    old_landing_zone_roots: Set[str] = field(default_factory=set)


@dataclass(frozen=True)
class Link:
    source_key: str
    relationship: str
    target_ocid: str


def attr_path(item: Any, *path: str) -> Any:
    current = item
    for part in path:
        if current is None:
            return None
        if isinstance(current, Mapping):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def values_from(item: Any, *paths: Sequence[str]) -> Set[str]:
    found: Set[str] = set()
    for path in paths:
        raw = attr_path(item, *path)
        if raw in (None, ""):
            continue
        if isinstance(raw, (list, tuple, set)):
            found.update(str(part) for part in raw if part not in (None, ""))
        else:
            found.add(str(raw))
    return found


def resource_id(item: Any) -> str:
    return str(value(item, "id", ""))


def resource_name(item: Any) -> str:
    for name in ("display_name", "name", "hostname_label", "dns_label"):
        candidate = str(value(item, name, ""))
        if candidate:
            return candidate
    return "<unnamed>"


def resource_time(item: Any) -> Any:
    for name in ("time_created", "created_time", "time_created_on"):
        candidate = value(item, name, None)
        if candidate is not None:
            return candidate
    return None


def resource_state(item: Any) -> str:
    for name in ("lifecycle_state", "state", "status"):
        candidate = str(value(item, name, ""))
        if candidate:
            return candidate
    return "UNKNOWN"


def resource_key(kind: str, ocid: str, fallback: str) -> str:
    material = ocid or fallback
    return f"{kind}:{stable_hash((kind, material))[:20]}"


def parse_networks(raw: Sequence[str], label: str) -> List[ipaddress._BaseNetwork]:
    parsed: List[ipaddress._BaseNetwork] = []
    for value_ in raw:
        try:
            parsed.append(ipaddress.ip_network(value_.strip(), strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid {label} CIDR {value_!r}: {exc}") from exc
    if not parsed:
        raise ValueError(f"at least one {label} CIDR is required")
    return parsed


def validate_network_sets(
    old_networks: Sequence[ipaddress._BaseNetwork],
    new_networks: Sequence[ipaddress._BaseNetwork],
) -> None:
    for old_network in old_networks:
        for new_network in new_networks:
            if old_network.version == new_network.version and old_network.overlaps(
                new_network
            ):
                raise ValueError(
                    f"old CIDR {old_network} overlaps new CIDR {new_network}"
                )


def landing_zone_membership(
    catalog: Sequence[ScopeItem], root_ocids: Sequence[str]
) -> Dict[str, Set[str]]:
    roots = set(root_ocids)
    by_id = {item.ocid: item for item in catalog}
    membership: Dict[str, Set[str]] = {}
    for item in catalog:
        if item.kind != "COMPARTMENT":
            continue
        current = item
        seen: Set[str] = set()
        matched: Set[str] = set()
        while current.ocid not in seen:
            seen.add(current.ocid)
            if current.ocid in roots:
                matched.add(current.ocid)
            parent = by_id.get(current.parent_ocid)
            if parent is None:
                break
            current = parent
        if matched:
            membership[item.ocid] = matched
    return membership


def classify_values(
    cidrs: Iterable[str],
    addresses: Iterable[str],
    old_networks: Sequence[ipaddress._BaseNetwork],
    new_networks: Sequence[ipaddress._BaseNetwork],
) -> Tuple[str, Set[str]]:
    old = False
    new = False
    other = False
    basis: Set[str] = set()

    for raw in cidrs:
        try:
            observed = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            other = True
            basis.add(f"INVALID-CIDR:{raw}")
            continue
        matched = False
        for expected in old_networks:
            if observed.version == expected.version and observed.overlaps(expected):
                old = True
                matched = True
                basis.add(f"CIDR:{raw}->OLD:{expected}")
        for expected in new_networks:
            if observed.version == expected.version and observed.overlaps(expected):
                new = True
                matched = True
                basis.add(f"CIDR:{raw}->NEW:{expected}")
        if not matched:
            other = True
            basis.add(f"CIDR:{raw}->OTHER")

    for raw in addresses:
        try:
            observed_ip = ipaddress.ip_address(raw)
        except ValueError:
            other = True
            basis.add(f"INVALID-IP:{raw}")
            continue
        matched = False
        for expected in old_networks:
            if observed_ip.version == expected.version and observed_ip in expected:
                old = True
                matched = True
                basis.add(f"IP:{raw}->OLD:{expected}")
        for expected in new_networks:
            if observed_ip.version == expected.version and observed_ip in expected:
                new = True
                matched = True
                basis.add(f"IP:{raw}->NEW:{expected}")
        if not matched:
            other = True
            basis.add(f"IP:{raw}->OTHER")

    if old and new:
        return "MIXED-OLD-NEW", basis
    if old:
        return ("OLD-172.16-WITH-OTHER" if other else "OLD-172.16"), basis
    if new:
        return ("NEW-10-WITH-OTHER" if other else "NEW-10"), basis
    if other:
        return "OTHER-NETWORK", basis
    return "UNRESOLVED", basis


def combine_network_classes(classes: Iterable[str]) -> str:
    values_ = set(classes)
    has_old = any(
        value_.startswith("OLD-172.16") or value_ == "MIXED-OLD-NEW"
        for value_ in values_
    )
    has_new = any(
        value_.startswith("NEW-10") or value_ == "MIXED-OLD-NEW" for value_ in values_
    )
    has_other = any("OTHER" in value_ for value_ in values_)
    if has_old and has_new:
        return "MIXED-OLD-NEW"
    if has_old:
        return "OLD-172.16-WITH-OTHER" if has_other else "OLD-172.16"
    if has_new:
        return "NEW-10-WITH-OTHER" if has_other else "NEW-10"
    if has_other:
        return "OTHER-NETWORK"
    return "UNRESOLVED"


def parsed_time(value_: Any) -> Optional[datetime]:
    if value_ is None or value_ == "":
        return None
    if isinstance(value_, datetime):
        result = value_
    elif isinstance(value_, date):
        result = datetime.combine(value_, time.min)
    else:
        raw = str(value_).strip()
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            result = datetime.fromisoformat(raw)
        except ValueError:
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def age_status(value_: Any, cutoff: datetime) -> Tuple[str, str]:
    observed = parsed_time(value_)
    if observed is None:
        return "UNKNOWN", "UNKNOWN"
    if observed < cutoff:
        return "YES", "PRE-CUTOFF"
    return "NO", "AT-OR-AFTER-CUTOFF"


def suggested_disposition(
    network_class: str,
    before_cutoff: str,
    *,
    unresolved: bool,
    tenancy_wide: bool,
    collection_complete: bool,
    old_landing_zone: bool = False,
) -> Tuple[str, str, str]:
    if not collection_complete:
        return (
            "HOLD-INCOMPLETE-COVERAGE",
            "LOW",
            "At least one required collection phase was omitted, an allowlisted "
            "SDK call failed, or an unresolved reference exists elsewhere in the "
            "inventory; hidden dependencies may exist.",
        )
    if unresolved:
        return (
            "HOLD-UNRESOLVED-DEPENDENCY",
            "LOW",
            "One or more referenced OCI resources were not resolved in the "
            "selected scope.",
        )
    if network_class == "MIXED-OLD-NEW":
        return (
            "KEEP-SHARED",
            "HIGH",
            "The resource is linked to both the 172.16 and 10.x environments.",
        )
    if network_class.startswith("NEW-10"):
        return (
            "KEEP-CANDIDATE",
            "HIGH",
            "The resource is linked to the newer 10.0.0.0/8 network family.",
        )
    if network_class == "OLD-172.16-WITH-OTHER":
        return (
            "HOLD-OLD-AND-OTHER-NETWORK",
            "LOW",
            "The resource is linked to 172.16 and at least one non-10 network; "
            "it is not an exclusive old-environment destroy candidate.",
        )
    if network_class == "OLD-172.16":
        if before_cutoff == "YES":
            if not tenancy_wide:
                return (
                    "HOLD-PARTIAL-SCOPE",
                    "LOW",
                    "Old, pre-cutoff resource found, but a compartment scan cannot "
                    "exclude cross-compartment dependencies.",
                )
            return (
                "REVIEW-DESTROY-CANDIDATE",
                "MEDIUM",
                "Pre-cutoff resource is linked only to the 172.16 network; owner, "
                "dependency, backup, retention and change approvals are still "
                "required.",
            )
        if before_cutoff == "NO":
            return (
                "REVIEW-OLD-NETWORK-POST-CUTOFF",
                "HIGH",
                "Resource is linked to 172.16 but was created at or after the cutoff.",
            )
        return (
            "HOLD-UNKNOWN-CREATION-DATE",
            "LOW",
            "Resource is linked to 172.16 but its creation time was unavailable.",
        )
    if old_landing_zone:
        if before_cutoff == "YES":
            if not tenancy_wide:
                return (
                    "HOLD-PARTIAL-SCOPE",
                    "LOW",
                    "Pre-cutoff resource is under an old landing-zone root, but "
                    "a non-tenancy scan cannot exclude dependencies elsewhere.",
                )
            return (
                "REVIEW-OLD-LANDING-ZONE-CANDIDATE",
                "MEDIUM",
                "Pre-cutoff resource is under a confirmed old landing-zone "
                "compartment; owner and dependency approvals are still required.",
            )
        if before_cutoff == "NO":
            return (
                "REVIEW-OLD-LANDING-ZONE-POST-CUTOFF",
                "HIGH",
                "Resource is under an old landing-zone compartment but was "
                "created at or after the cutoff.",
            )
        return (
            "HOLD-UNKNOWN-CREATION-DATE",
            "LOW",
            "Resource is under an old landing-zone compartment but its creation "
            "time was unavailable.",
        )
    if before_cutoff == "YES":
        return (
            "REVIEW-PRE-CUTOFF-NO-OLD-LINK",
            "LOW",
            "Resource predates the cutoff but no exclusive 172.16 relationship "
            "was proven.",
        )
    return (
        "REVIEW-NO-OLD-LINK",
        "LOW",
        "No exclusive 172.16 relationship was proven.",
    )


class Inventory:
    def __init__(
        self,
        scope_names: Mapping[str, str],
        landing_zone_roots: Mapping[str, Set[str]] | None = None,
    ) -> None:
        self.scope_names = dict(scope_names)
        self.landing_zone_roots = {
            ocid: set(roots) for ocid, roots in (landing_zone_roots or {}).items()
        }
        self.resources: Dict[str, Resource] = {}
        self.ocid_to_key: Dict[str, str] = {}
        self.links: List[Link] = []

    def add(
        self,
        kind: str,
        item: Any,
        scope: ScopeItem,
        *,
        ocid: str = "",
        name: str = "",
        cidrs: Iterable[str] = (),
        ip_addresses: Iterable[str] = (),
        vcn_ocids: Iterable[str] = (),
        subnet_ocids: Iterable[str] = (),
        vlan_ocids: Iterable[str] = (),
        time_created: Any = None,
        lifecycle_state: str = "",
    ) -> Resource:
        actual_ocid = ocid or resource_id(item)
        actual_name = name or resource_name(item)
        fallback = f"{scope.ocid}|{actual_name}|{len(self.resources)}"
        key = resource_key(kind, actual_ocid, fallback)
        compartment_id = str(value(item, "compartment_id", scope.ocid)) or scope.ocid
        resource = self.resources.get(key)
        if resource is None:
            resource = Resource(
                key=key,
                resource_type=kind,
                resource_name=actual_name,
                resource_ocid=actual_ocid,
                compartment_name=self.scope_names.get(
                    compartment_id, "<not-discovered>"
                ),
                compartment_ocid=compartment_id,
                lifecycle_state=lifecycle_state or resource_state(item),
                time_created=time_created
                if time_created is not None
                else resource_time(item),
                old_landing_zone_roots=set(
                    self.landing_zone_roots.get(compartment_id, set())
                ),
            )
            self.resources[key] = resource
            if actual_ocid:
                self.ocid_to_key[actual_ocid] = key
            else:
                self.links.append(Link(key, "MISSING-RESOURCE-OCID", "<missing>"))
        resource.cidrs.update(str(part) for part in cidrs if part)
        resource.ip_addresses.update(str(part) for part in ip_addresses if part)
        resource.vcn_ocids.update(str(part) for part in vcn_ocids if part)
        resource.subnet_ocids.update(str(part) for part in subnet_ocids if part)
        resource.vlan_ocids.update(str(part) for part in vlan_ocids if part)
        for target in resource.vcn_ocids:
            self.links.append(Link(key, "USES-VCN", target))
        for target in resource.subnet_ocids:
            self.links.append(Link(key, "USES-SUBNET", target))
        for target in resource.vlan_ocids:
            self.links.append(Link(key, "USES-VLAN", target))
        return resource

    def link(self, source_key: str, relationship: str, target_ocid: str) -> None:
        if target_ocid:
            self.links.append(Link(source_key, relationship, target_ocid))

    def dedupe_links(self) -> None:
        self.links = sorted(
            set(self.links),
            key=lambda row: (row.source_key, row.relationship, row.target_ocid),
        )


def collect_core_network(
    rt: EvidenceRuntime, inventory: Inventory, scopes: Sequence[ScopeItem]
) -> None:
    client = rt.client("core", "VirtualNetworkClient")
    simple_lists = (
        ("VCN", "list_vcns", (), ("cidr_block", "cidr_blocks"), ()),
        (
            "SUBNET",
            "list_subnets",
            ("vcn_id",),
            ("cidr_block", "ipv6_cidr_block", "ipv6_cidr_blocks"),
            (),
        ),
        (
            "VLAN",
            "list_vlans",
            ("vcn_id",),
            ("cidr_block", "ipv6_cidr_block", "ipv6_cidr_blocks"),
            (),
        ),
        ("ROUTE_TABLE", "list_route_tables", ("vcn_id",), (), ()),
        ("SECURITY_LIST", "list_security_lists", ("vcn_id",), (), ()),
        ("DHCP_OPTIONS", "list_dhcp_options", ("vcn_id",), (), ()),
        ("INTERNET_GATEWAY", "list_internet_gateways", ("vcn_id",), (), ()),
        ("NAT_GATEWAY", "list_nat_gateways", ("vcn_id",), (), ("nat_ip",)),
        ("SERVICE_GATEWAY", "list_service_gateways", ("vcn_id",), (), ()),
        ("LOCAL_PEERING_GATEWAY", "list_local_peering_gateways", ("vcn_id",), (), ()),
        ("DRG", "list_drgs", (), (), ()),
    )
    known_subnets: list[tuple[ScopeItem, str]] = []
    drg_attachment_edges: list[tuple[str, str, str]] = []
    for scope in scopes:
        for kind, method, vcn_fields, cidr_fields, extra_fields in simple_lists:
            items = rt.list_items(scope, "Virtual Network", client, method, scope.ocid)
            if items is None:
                continue
            for item in items:
                vcn_ids = values_from(item, *((field,) for field in vcn_fields))
                cidrs = values_from(item, *((field,) for field in cidr_fields))
                ips = values_from(item, *((field,) for field in extra_fields))
                resource = inventory.add(
                    kind,
                    item,
                    scope,
                    cidrs=cidrs,
                    ip_addresses=ips,
                    vcn_ocids=vcn_ids,
                )
                if kind == "SUBNET":
                    known_subnets.append((scope, resource.resource_ocid))
                    inventory.link(
                        resource.key, "USES-ROUTE-TABLE", text(item, "route_table_id")
                    )
                    inventory.link(
                        resource.key,
                        "USES-DHCP-OPTIONS",
                        text(item, "dhcp_options_id"),
                    )
                    for target in values_from(item, ("security_list_ids",)):
                        inventory.link(resource.key, "USES-SECURITY-LIST", target)
                elif kind == "VLAN":
                    inventory.link(
                        resource.key, "USES-ROUTE-TABLE", text(item, "route_table_id")
                    )
                    for target in values_from(item, ("nsg_ids",)):
                        inventory.link(resource.key, "USES-NSG", target)
                elif kind == "VCN":
                    for field_name, relationship in (
                        ("default_route_table_id", "DEFAULT-ROUTE-TABLE"),
                        ("default_security_list_id", "DEFAULT-SECURITY-LIST"),
                        ("default_dhcp_options_id", "DEFAULT-DHCP-OPTIONS"),
                    ):
                        inventory.link(
                            resource.key, relationship, text(item, field_name)
                        )
                elif kind == "ROUTE_TABLE":
                    for route_rule in value(item, "route_rules", []) or []:
                        inventory.link(
                            resource.key,
                            "ROUTES-TO-NETWORK-ENTITY",
                            text(route_rule, "network_entity_id"),
                        )
                elif kind == "LOCAL_PEERING_GATEWAY":
                    inventory.link(
                        resource.key, "PEERS-WITH-LPG", text(item, "peer_id")
                    )

        attachments = rt.list_items(
            scope,
            "Dynamic Routing Gateway",
            client,
            "list_drg_attachments",
            scope.ocid,
            attachment_type="ALL",
        )
        if attachments is not None:
            for item in attachments:
                network_type = str(
                    attr_path(item, "network_details", "type") or ""
                ).upper()
                network_id = str(attr_path(item, "network_details", "id") or "")
                vcn_ids = values_from(item, ("vcn_id",))
                if network_type == "VCN" and network_id:
                    vcn_ids.add(network_id)
                attachment = inventory.add(
                    "DRG_ATTACHMENT", item, scope, vcn_ocids=vcn_ids
                )
                drg_attachment_edges.append(
                    (text(item, "drg_id"), attachment.key, attachment.resource_ocid)
                )
        # This generated method accepts keyword-only filters. Compartment scope
        # returns all NSGs there; vcn_id on each model provides the relationship.
        items = rt.list_items(
            scope,
            "Virtual Network",
            client,
            "list_network_security_groups",
            compartment_id=scope.ocid,
        )
        if items is not None:
            for item in items:
                inventory.add(
                    "NETWORK_SECURITY_GROUP",
                    item,
                    scope,
                    vcn_ocids=values_from(item, ("vcn_id",)),
                )

    for drg_id, attachment_key, attachment_id in drg_attachment_edges:
        drg_key = inventory.ocid_to_key.get(drg_id)
        if drg_key:
            inventory.link(drg_key, "HAS-DRG-ATTACHMENT", attachment_id)
        else:
            inventory.link(
                attachment_key,
                "USES-UNRESOLVED-DRG",
                drg_id or "<missing-drg>",
            )

    # Subnet enumeration captures service-managed private IPs as well as
    # Compute VNIC addresses. Duplicate OCIDs are de-duplicated by Inventory.
    for scope, subnet_id in known_subnets:
        private_ips = rt.list_items(
            scope,
            "Virtual Network",
            client,
            "list_private_ips",
            subnet_id=subnet_id,
        )
        if private_ips is not None:
            for item in private_ips:
                inventory.add(
                    "PRIVATE_IP",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_id",)),
                    ip_addresses=values_from(item, ("ip_address",)),
                )


def collect_compute(
    rt: EvidenceRuntime, inventory: Inventory, scopes: Sequence[ScopeItem]
) -> None:
    compute = rt.client("core", "ComputeClient")
    network = rt.client("core", "VirtualNetworkClient")
    block = rt.client("core", "BlockstorageClient")
    identity = rt.client("identity", "IdentityClient")
    tenancy_scope = next(
        (scope for scope in scopes if scope.ocid == rt.context.tenancy_id),
        ScopeItem(rt.context.tenancy_id, "tenancy root", "TENANCY"),
    )
    availability_domains = rt.list_items(
        tenancy_scope,
        "Identity",
        identity,
        "list_availability_domains",
        rt.context.tenancy_id,
    )
    ad_names = [
        text(item, "name") for item in availability_domains or [] if text(item, "name")
    ]
    pending_volume_attachments: List[Tuple[str, str, str]] = []
    for scope in scopes:
        volumes = rt.list_items(
            scope,
            "Block Volume",
            block,
            "list_volumes",
            compartment_id=scope.ocid,
        )
        if volumes is not None:
            for item in volumes:
                inventory.add("BLOCK_VOLUME", item, scope)
        volume_groups = rt.list_items(
            scope,
            "Block Volume",
            block,
            "list_volume_groups",
            scope.ocid,
        )
        if volume_groups is not None:
            for item in volume_groups:
                group = inventory.add("VOLUME_GROUP", item, scope)
                for target in values_from(item, ("volume_ids",)):
                    inventory.link(group.key, "HAS-VOLUME", target)
        for availability_domain in ad_names:
            boot_volumes = rt.list_items(
                scope,
                "Boot Volume",
                block,
                "list_boot_volumes",
                compartment_id=scope.ocid,
                availability_domain=availability_domain,
            )
            if boot_volumes is not None:
                for item in boot_volumes:
                    inventory.add("BOOT_VOLUME", item, scope)
        instances = rt.list_items(
            scope, "Compute", compute, "list_instances", scope.ocid
        )
        if instances is not None:
            for item in instances:
                inventory.add("COMPUTE_INSTANCE", item, scope)
        volume_attachments = rt.list_items(
            scope,
            "Compute",
            compute,
            "list_volume_attachments",
            scope.ocid,
        )
        if volume_attachments is not None:
            for item in volume_attachments:
                pending_volume_attachments.append(
                    (
                        text(item, "volume_id"),
                        text(item, "instance_id"),
                        "BLOCK-VOLUME-ATTACHED-TO-INSTANCE",
                    )
                )
        for availability_domain in ad_names:
            boot_attachments = rt.list_items(
                scope,
                "Compute",
                compute,
                "list_boot_volume_attachments",
                availability_domain,
                scope.ocid,
            )
            if boot_attachments is not None:
                for item in boot_attachments:
                    pending_volume_attachments.append(
                        (
                            text(item, "boot_volume_id"),
                            text(item, "instance_id"),
                            "BOOT-VOLUME-ATTACHED-TO-INSTANCE",
                        )
                    )
        attachments = rt.list_items(
            scope, "Compute", compute, "list_vnic_attachments", scope.ocid
        )
        if attachments is None:
            continue
        for attachment in attachments:
            vnic_id = text(attachment, "vnic_id")
            instance_id = text(attachment, "instance_id")
            if not vnic_id:
                continue
            vnic = rt.get_item(scope, "Virtual Network", network, "get_vnic", vnic_id)
            if vnic is None:
                if instance_id and instance_id in inventory.ocid_to_key:
                    inventory.link(
                        inventory.ocid_to_key[instance_id],
                        "HAS-UNRESOLVED-VNIC",
                        vnic_id,
                    )
                continue
            vnic_resource = inventory.add(
                "VNIC",
                vnic,
                scope,
                subnet_ocids=values_from(vnic, ("subnet_id",)),
                vlan_ocids=values_from(vnic, ("vlan_id",)),
                ip_addresses=values_from(vnic, ("private_ip",), ("public_ip",)),
            )
            for target in values_from(vnic, ("nsg_ids",)):
                inventory.link(vnic_resource.key, "USES-NSG", target)
            inventory.link(
                vnic_resource.key,
                "USES-ROUTE-TABLE",
                text(vnic, "route_table_id"),
            )
            if instance_id and instance_id in inventory.ocid_to_key:
                inventory.link(inventory.ocid_to_key[instance_id], "HAS-VNIC", vnic_id)
            elif instance_id:
                inventory.link(
                    vnic_resource.key,
                    "ATTACHED-TO-UNRESOLVED-INSTANCE",
                    instance_id,
                )
            private_ips = rt.list_items(
                scope,
                "Virtual Network",
                network,
                "list_private_ips",
                vnic_id=vnic_id,
            )
            if private_ips is None:
                continue
            for private_ip in private_ips:
                private_resource = inventory.add(
                    "PRIVATE_IP",
                    private_ip,
                    scope,
                    subnet_ocids=values_from(private_ip, ("subnet_id",)),
                    ip_addresses=values_from(private_ip, ("ip_address",)),
                )
                inventory.link(
                    vnic_resource.key, "HAS-PRIVATE-IP", private_resource.resource_ocid
                )

    for volume_id, instance_id, relationship in pending_volume_attachments:
        volume_key = inventory.ocid_to_key.get(volume_id)
        instance_key = inventory.ocid_to_key.get(instance_id)
        if volume_key:
            inventory.link(
                volume_key,
                relationship,
                instance_id or "<missing-instance>",
            )
        elif instance_key:
            inventory.link(
                instance_key,
                "USES-UNRESOLVED-VOLUME",
                volume_id or "<missing-volume>",
            )


def collect_load_balancers(
    rt: EvidenceRuntime, inventory: Inventory, scopes: Sequence[ScopeItem]
) -> None:
    classic = rt.client("load_balancer", "LoadBalancerClient")
    network = rt.client("network_load_balancer", "NetworkLoadBalancerClient")
    for scope in scopes:
        lbs = rt.list_items(
            scope, "Load Balancer", classic, "list_load_balancers", scope.ocid
        )
        if lbs is not None:
            for item in lbs:
                resource = inventory.add(
                    "LOAD_BALANCER",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_ids",)),
                    ip_addresses={
                        text(ip, "ip_address")
                        for ip in value(item, "ip_addresses", []) or []
                    },
                )
                for target in values_from(item, ("network_security_group_ids",)):
                    inventory.link(resource.key, "USES-NSG", target)
        nlbs = rt.list_items(
            scope,
            "Network Load Balancer",
            network,
            "list_network_load_balancers",
            scope.ocid,
        )
        if nlbs is not None:
            for item in nlbs:
                resource = inventory.add(
                    "NETWORK_LOAD_BALANCER",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_id",)),
                    ip_addresses={
                        text(ip, "ip_address")
                        for ip in value(item, "ip_addresses", []) or []
                    },
                )
                for target in values_from(item, ("network_security_group_ids",)):
                    inventory.link(resource.key, "USES-NSG", target)


def collect_databases(
    rt: EvidenceRuntime, inventory: Inventory, scopes: Sequence[ScopeItem]
) -> None:
    database = rt.client("database", "DatabaseClient")
    mysql = rt.client("mysql", "DbSystemClient")
    postgres = rt.client("psql", "PostgresqlClient")
    classic = (
        ("BASE_DATABASE_SYSTEM", "list_db_systems"),
        ("AUTONOMOUS_DATABASE", "list_autonomous_databases"),
        ("VM_CLUSTER", "list_vm_clusters"),
        ("CLOUD_VM_CLUSTER", "list_cloud_vm_clusters"),
    )
    for scope in scopes:
        for kind, method in classic:
            items = rt.list_items(scope, "Database", database, method, scope.ocid)
            if items is not None:
                for item in items:
                    resource = inventory.add(
                        kind,
                        item,
                        scope,
                        vcn_ocids=values_from(item, ("vcn_id",)),
                        subnet_ocids=values_from(
                            item, ("subnet_id",), ("backup_subnet_id",)
                        ),
                        ip_addresses=values_from(
                            item, ("private_endpoint",), ("private_endpoint_ip",)
                        ),
                    )
                    for target in values_from(
                        item, ("nsg_ids",), ("network_security_group_ids",)
                    ):
                        inventory.link(resource.key, "USES-NSG", target)
        mysql_items = rt.list_items(
            scope, "MySQL", mysql, "list_db_systems", scope.ocid
        )
        if mysql_items is not None:
            for item in mysql_items:
                resource = inventory.add(
                    "MYSQL_DB_SYSTEM",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_id",)),
                    ip_addresses=values_from(item, ("ip_address",)),
                )
                for target in values_from(item, ("nsg_ids",)):
                    inventory.link(resource.key, "USES-NSG", target)
        postgres_items = rt.list_items(
            scope,
            "PostgreSQL",
            postgres,
            "list_db_systems",
            compartment_id=scope.ocid,
        )
        if postgres_items is not None:
            for item in postgres_items:
                resource = inventory.add(
                    "POSTGRESQL_DB_SYSTEM",
                    item,
                    scope,
                    subnet_ocids=values_from(
                        item, ("subnet_id",), ("network_details", "subnet_id")
                    ),
                    ip_addresses=values_from(item, ("network_details", "private_ip")),
                )
                for target in values_from(
                    item,
                    ("nsg_ids",),
                    ("network_details", "nsg_ids"),
                ):
                    inventory.link(resource.key, "USES-NSG", target)


def collect_platform(
    rt: EvidenceRuntime, inventory: Inventory, scopes: Sequence[ScopeItem]
) -> None:
    identity = rt.client("identity", "IdentityClient")
    oke = rt.client("container_engine", "ContainerEngineClient")
    gateway = rt.client("apigateway", "GatewayClient")
    bastion = rt.client("bastion", "BastionClient")
    fss = rt.client("file_storage", "FileStorageClient")
    functions = rt.client("functions", "FunctionsManagementClient")
    tenancy_scope = next(
        (scope for scope in scopes if scope.ocid == rt.context.tenancy_id),
        ScopeItem(rt.context.tenancy_id, "tenancy root", "TENANCY"),
    )
    availability_domains = rt.list_items(
        tenancy_scope,
        "Identity",
        identity,
        "list_availability_domains",
        rt.context.tenancy_id,
    )
    ad_names = [
        text(item, "name") for item in availability_domains or [] if text(item, "name")
    ]
    mount_target_by_export_set: Dict[str, str] = {}
    pending_file_export: List[Tuple[str, str, str]] = []
    pending_export_mount: List[Tuple[str, str]] = []

    for scope in scopes:
        clusters = rt.list_items(scope, "OKE", oke, "list_clusters", scope.ocid)
        if clusters is not None:
            for item in clusters:
                resource = inventory.add(
                    "OKE_CLUSTER",
                    item,
                    scope,
                    vcn_ocids=values_from(item, ("vcn_id",)),
                    subnet_ocids=values_from(
                        item,
                        ("endpoint_config", "subnet_id"),
                        ("options", "service_lb_subnet_ids"),
                    ),
                )
                for target in values_from(
                    item,
                    ("endpoint_config", "nsg_ids"),
                    ("options", "service_lb_config", "network_security_group_ids"),
                ):
                    inventory.link(resource.key, "USES-NSG", target)
        gateways = rt.list_items(
            scope, "API Gateway", gateway, "list_gateways", scope.ocid
        )
        if gateways is not None:
            for item in gateways:
                resource = inventory.add(
                    "API_GATEWAY",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_id",)),
                    ip_addresses={
                        text(ip, "ip_address")
                        for ip in value(item, "ip_addresses", []) or []
                    },
                )
                for target in values_from(item, ("network_security_group_ids",)):
                    inventory.link(resource.key, "USES-NSG", target)
        bastions = rt.list_items(scope, "Bastion", bastion, "list_bastions", scope.ocid)
        if bastions is not None:
            for item in bastions:
                inventory.add(
                    "BASTION",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("target_subnet_id",)),
                )
        for availability_domain in ad_names:
            file_systems = rt.list_items(
                scope,
                "File Storage",
                fss,
                "list_file_systems",
                scope.ocid,
                availability_domain,
            )
            if file_systems is not None:
                for item in file_systems:
                    inventory.add("FILE_SYSTEM", item, scope)
            mount_targets = rt.list_items(
                scope,
                "File Storage",
                fss,
                "list_mount_targets",
                scope.ocid,
                availability_domain,
            )
            if mount_targets is not None:
                for item in mount_targets:
                    resource = inventory.add(
                        "FSS_MOUNT_TARGET",
                        item,
                        scope,
                        subnet_ocids=values_from(item, ("subnet_id",)),
                        ip_addresses=values_from(item, ("ip_address",)),
                    )
                    for target in values_from(item, ("nsg_ids",)):
                        inventory.link(resource.key, "USES-NSG", target)
                    for target in values_from(item, ("private_ip_ids",)):
                        inventory.link(resource.key, "USES-PRIVATE-IP", target)
                    export_set_id = text(item, "export_set_id")
                    if export_set_id:
                        mount_target_by_export_set[export_set_id] = (
                            resource.resource_ocid
                        )
        exports = rt.list_items(
            scope,
            "File Storage",
            fss,
            "list_exports",
            compartment_id=scope.ocid,
        )
        if exports is not None:
            for item in exports:
                resource = inventory.add("FSS_EXPORT", item, scope)
                pending_file_export.append(
                    (
                        text(item, "file_system_id"),
                        resource.key,
                        resource.resource_ocid,
                    )
                )
                pending_export_mount.append(
                    (resource.key, text(item, "export_set_id"))
                )
        applications = rt.list_items(
            scope, "Functions", functions, "list_applications", scope.ocid
        )
        if applications is not None:
            for item in applications:
                resource = inventory.add(
                    "FUNCTIONS_APPLICATION",
                    item,
                    scope,
                    subnet_ocids=values_from(item, ("subnet_ids",)),
                )
                for target in values_from(item, ("network_security_group_ids",)):
                    inventory.link(resource.key, "USES-NSG", target)

    for file_system_id, export_key, export_id in pending_file_export:
        file_system_key = inventory.ocid_to_key.get(file_system_id)
        if file_system_key:
            inventory.link(file_system_key, "HAS-EXPORT", export_id)
        else:
            inventory.link(
                export_key,
                "USES-UNRESOLVED-FILE-SYSTEM",
                file_system_id or "<missing-file-system>",
            )
    for export_key, export_set_id in pending_export_mount:
        mount_target_id = mount_target_by_export_set.get(export_set_id, "")
        if mount_target_id:
            inventory.link(export_key, "USES-MOUNT-TARGET", mount_target_id)
        else:
            inventory.link(
                export_key,
                "USES-UNRESOLVED-EXPORT-SET",
                export_set_id or "<missing-export-set>",
            )


def resolve_networks(
    inventory: Inventory,
    old_networks: Sequence[ipaddress._BaseNetwork],
    new_networks: Sequence[ipaddress._BaseNetwork],
) -> None:
    inventory.dedupe_links()
    for resource in inventory.resources.values():
        direct, basis = classify_values(
            resource.cidrs, resource.ip_addresses, old_networks, new_networks
        )
        resource.network_class = direct
        resource.network_basis.update(basis)

    # Propagate the network identity along dependency edges until stable.
    for _ in range(max(len(inventory.resources), 1)):
        changed = False
        for link in inventory.links:
            source = inventory.resources[link.source_key]
            target_key = inventory.ocid_to_key.get(link.target_ocid)
            if target_key is None:
                source.unresolved_refs.add(link.target_ocid)
                continue
            target = inventory.resources[target_key]
            combined = combine_network_classes(
                (source.network_class, target.network_class)
            )
            if combined != source.network_class:
                source.network_class = combined
                changed = True
            source.network_basis.add(
                f"{link.relationship}:{target.resource_type}:{link.target_ocid}"
            )
        if not changed:
            break


def decision_gate_complete(
    inventory: Inventory,
    work: Sequence[str],
    errors: Sequence[Mapping[str, Any]],
) -> bool:
    """Return true only when a destroy-review result can be considered."""
    return (
        not errors
        and set(work) == set(WORK)
        and not any(
            resource.unresolved_refs for resource in inventory.resources.values()
        )
    )


def build_rows(
    inventory: Inventory,
    cutoff: datetime,
    *,
    tenancy_wide: bool,
    collection_complete: bool,
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    inventory.dedupe_links()
    outgoing: Counter[str] = Counter(link.source_key for link in inventory.links)
    incoming: Counter[str] = Counter()
    dependency_rows: List[Dict[str, Any]] = []
    unresolved_rows: List[Dict[str, Any]] = []
    for link in inventory.links:
        source = inventory.resources[link.source_key]
        target_key = inventory.ocid_to_key.get(link.target_ocid, "")
        target = inventory.resources.get(target_key)
        if target is not None:
            incoming[target.key] += 1
        dependency_rows.append(
            {
                "source_key": source.key,
                "source_type": source.resource_type,
                "source_name": source.resource_name,
                "source_ocid": source.resource_ocid,
                "relationship": link.relationship,
                "target_key": target.key if target else "",
                "target_type": target.resource_type if target else "",
                "target_name": target.resource_name if target else "",
                "target_ocid": link.target_ocid,
                "resolution_status": "RESOLVED" if target else "UNRESOLVED",
            }
        )
        if target is None:
            unresolved_rows.append(
                {
                    "source_key": source.key,
                    "source_type": source.resource_type,
                    "source_name": source.resource_name,
                    "source_ocid": source.resource_ocid,
                    "relationship": link.relationship,
                    "target_ocid": link.target_ocid,
                    "impact": (
                        "Decommission disposition is held until the referenced "
                        "resource is resolved."
                    ),
                }
            )

    resource_rows: List[Dict[str, Any]] = []
    decision_rows: List[Dict[str, Any]] = []
    for resource in sorted(
        inventory.resources.values(),
        key=lambda row: (
            row.resource_type,
            row.resource_name.lower(),
            row.resource_ocid,
        ),
    ):
        before, age = age_status(resource.time_created, cutoff)
        disposition, confidence, reason = suggested_disposition(
            resource.network_class,
            before,
            unresolved=bool(resource.unresolved_refs),
            tenancy_wide=tenancy_wide,
            collection_complete=collection_complete,
            old_landing_zone=bool(resource.old_landing_zone_roots),
        )
        if incoming[resource.key]:
            if disposition == "REVIEW-DESTROY-CANDIDATE":
                disposition = "REVIEW-DESTROY-AFTER-DEPENDENCIES"
                reason = (
                    f"Pre-cutoff resource is exclusive to 172.16 but has "
                    f"{incoming[resource.key]} inventoried dependent(s); disposition "
                    "dependents first, then complete approvals."
                )
            elif disposition == "REVIEW-OLD-LANDING-ZONE-CANDIDATE":
                disposition = "REVIEW-OLD-LANDING-ZONE-AFTER-DEPENDENCIES"
                reason = (
                    f"Pre-cutoff resource is under an old landing-zone root and has "
                    f"{incoming[resource.key]} inventoried dependent(s); disposition "
                    "dependents first, then complete approvals."
                )
        row = {
            "resource_key": resource.key,
            "resource_type": resource.resource_type,
            "resource_name": resource.resource_name,
            "resource_ocid": resource.resource_ocid,
            "compartment_name": resource.compartment_name,
            "compartment_ocid": resource.compartment_ocid,
            "old_landing_zone": ("YES" if resource.old_landing_zone_roots else "NO"),
            "old_landing_zone_root_ocids": pipe(resource.old_landing_zone_roots),
            "lifecycle_state": resource.lifecycle_state,
            "time_created": iso(resource.time_created),
            "created_before_cutoff": before,
            "age_status": age,
            "network_class": resource.network_class,
            "network_basis": pipe(resource.network_basis),
            "cidrs": pipe(resource.cidrs),
            "ip_addresses": pipe(resource.ip_addresses),
            "vcn_ocids": pipe(resource.vcn_ocids),
            "subnet_ocids": pipe(resource.subnet_ocids),
            "vlan_ocids": pipe(resource.vlan_ocids),
            "depends_on_count": outgoing[resource.key],
            "dependent_count": incoming[resource.key],
            "suggested_disposition": disposition,
            "confidence": confidence,
            "reason": reason,
        }
        resource_rows.append(row)
        decision_rows.append({field: row.get(field, "") for field in DECISION_FIELDS})
    return resource_rows, dependency_rows, unresolved_rows, decision_rows


def parse_cutoff(raw: str) -> datetime:
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError("--cutoff-date must be YYYY-MM-DD") from exc
    return datetime.combine(parsed, time.min, tzinfo=timezone.utc)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only OCI old/new network and pre-cutoff resource gap analysis."
        )
    )
    add_common_arguments(parser, allowed_work=WORK, default_work=WORK)
    parser.add_argument("--cutoff-date", default="2026-01-01")
    parser.add_argument(
        "--old-cidr",
        action="append",
        default=[],
        help="Old-environment CIDR; repeatable. Default: 172.16.0.0/16",
    )
    parser.add_argument(
        "--new-cidr",
        action="append",
        default=[],
        help="New-environment CIDR; repeatable. Default: 10.0.0.0/8",
    )
    parser.add_argument(
        "--old-landing-zone-compartment-id",
        action="append",
        default=[],
        help=(
            "Confirmed old landing-zone root compartment OCID; repeatable. "
            "All discovered descendants must be included in the scan."
        ),
    )
    parser.add_argument(
        "--confirm-old-landing-zone-compartment-ocid",
        action="append",
        default=[],
        help=(
            "Automation-only exact confirmation for each old landing-zone root "
            "compartment OCID."
        ),
    )
    return parser


def methods_for_work(work: Sequence[str]) -> Set[str]:
    selected = set(IDENTITY_SCOPE_METHODS)
    mapping = {
        "core-network": CORE_METHODS,
        "compute": COMPUTE_METHODS,
        "load-balancers": LB_METHODS,
        "databases": DATABASE_METHODS,
        "platform-services": PLATFORM_METHODS,
    }
    for phase in work:
        selected.update(mapping[phase])
    return selected


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.selfcheck:
        return 0 if source_selfcheck(SCRIPT_PATH, COLLECTOR, SDK_READ_METHODS) else 2
    try:
        work = parse_work(args.services, WORK)
        cutoff = parse_cutoff(args.cutoff_date)
        old_networks = parse_networks(args.old_cidr or ["172.16.0.0/16"], "old")
        new_networks = parse_networks(args.new_cidr or ["10.0.0.0/8"], "new")
        validate_network_sets(old_networks, new_networks)
        outputs = output_paths(args.output_dir, "oci_network_gap", ARTIFACTS)
        planned_methods = methods_for_work(work)
        scope_notes = [
            f"Cutoff: resources created before {cutoff.date().isoformat()} are "
            "pre-cutoff.",
            "Old CIDR set: " + ", ".join(str(item) for item in old_networks),
            "New CIDR set: " + ", ".join(str(item) for item in new_networks),
            "Only a tenancy-wide, error-free scan can emit REVIEW-DESTROY-CANDIDATE.",
            "No output authorizes deletion; owner, dependency, backup, retention, "
            "security and change approvals remain mandatory.",
        ]
        if args.old_landing_zone_compartment_id:
            scope_notes.append(
                "Requested old landing-zone root OCIDs: "
                + ", ".join(args.old_landing_zone_compartment_id)
            )
        oci, context, catalog, selected, targets = begin_run(
            args,
            collector=COLLECTOR,
            controls=CONTROLS,
            title="OCI OLD/NEW ENVIRONMENT GAP ANALYSIS",
            work=work,
            methods=planned_methods,
            outputs=outputs,
            scope_notes=scope_notes,
            extra_scope_ocids=args.old_landing_zone_compartment_id,
            extra_confirm_ocids=(args.confirm_old_landing_zone_compartment_ocid),
            extra_scope_label="old landing-zone compartment",
            require_extra_descendants_in_targets=True,
        )
    except (ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    runtime = EvidenceRuntime(oci, context, SDK_READ_METHODS)
    landing_zones = landing_zone_membership(
        catalog, args.old_landing_zone_compartment_id
    )
    inventory = Inventory(
        {item.ocid: item.name for item in catalog},
        landing_zone_roots=landing_zones,
    )
    runtime.coverage.append(
        {
            "scope_name": selected.name,
            "scope_ocid": selected.ocid,
            "service": "Manual boundary",
            "operation": "unsupported-service-resource-types",
            "status": "MANUAL-BOUNDARY",
            "item_count": "UNKNOWN",
            "pagination": "",
            "request_id": "",
            "message": (
                "The list/get-only inventory covers documented service families, "
                "not every OCI resource type; reconcile other services separately."
            ),
        }
    )
    for omitted_phase in sorted(set(WORK) - set(work)):
        runtime.coverage.append(
            {
                "scope_name": selected.name,
                "scope_ocid": selected.ocid,
                "service": omitted_phase,
                "operation": "<phase>",
                "status": "OMITTED",
                "item_count": "UNKNOWN",
                "pagination": "",
                "request_id": "",
                "message": (
                    "Phase was not requested; destroy-review conclusions are held."
                ),
            }
        )
    if "core-network" in work:
        collect_core_network(runtime, inventory, targets)
    if "compute" in work:
        collect_compute(runtime, inventory, targets)
    if "load-balancers" in work:
        collect_load_balancers(runtime, inventory, targets)
    if "databases" in work:
        collect_databases(runtime, inventory, targets)
    if "platform-services" in work:
        collect_platform(runtime, inventory, targets)

    resolve_networks(inventory, old_networks, new_networks)
    collection_complete = decision_gate_complete(inventory, work, runtime.errors)
    tenancy_wide = selected.kind == "TENANCY"
    resources, dependencies, unresolved, decisions = build_rows(
        inventory,
        cutoff,
        tenancy_wide=tenancy_wide,
        collection_complete=collection_complete,
    )
    write_csv(outputs["resources"], RESOURCE_FIELDS, resources)
    destroy_dispositions = {
        "REVIEW-DESTROY-CANDIDATE",
        "REVIEW-DESTROY-AFTER-DEPENDENCIES",
        "REVIEW-OLD-LANDING-ZONE-CANDIDATE",
        "REVIEW-OLD-LANDING-ZONE-AFTER-DEPENDENCIES",
    }
    keep_candidates = [
        row
        for row in resources
        if str(row["suggested_disposition"]).startswith("KEEP-")
    ]
    destroy_candidates = [
        row for row in resources if row["suggested_disposition"] in destroy_dispositions
    ]
    holds_and_other = [
        row
        for row in resources
        if row not in keep_candidates and row not in destroy_candidates
    ]
    old_landing_zone_resources = [
        row for row in resources if row["old_landing_zone"] == "YES"
    ]
    write_csv(outputs["keep_candidates"], RESOURCE_FIELDS, keep_candidates)
    write_csv(outputs["destroy_review_candidates"], RESOURCE_FIELDS, destroy_candidates)
    write_csv(outputs["holds_and_other_review"], RESOURCE_FIELDS, holds_and_other)
    write_csv(
        outputs["old_landing_zone_resources"],
        RESOURCE_FIELDS,
        old_landing_zone_resources,
    )
    write_csv(outputs["dependencies"], DEPENDENCY_FIELDS, dependencies)
    write_csv(outputs["unresolved_links"], UNRESOLVED_FIELDS, unresolved)
    write_csv(outputs["decision_template"], DECISION_FIELDS, decisions)

    dispositions = Counter(row["suggested_disposition"] for row in resources)
    network_classes = Counter(row["network_class"] for row in resources)
    old_landing_zone_root_count = len(set(args.old_landing_zone_compartment_id))
    old_landing_zone_resource_count = sum(
        row["old_landing_zone"] == "YES" for row in resources
    )
    summary_lines = [
        "OCI old/new environment gap analysis",
        f"Collector                  : {COLLECTOR}",
        f"Region                     : {args.region}",
        f"Selected scope             : {selected.kind} / {selected.name}",
        f"Cutoff                     : {cutoff.date().isoformat()}",
        f"Old CIDRs                  : {', '.join(str(item) for item in old_networks)}",
        f"New CIDRs                  : {', '.join(str(item) for item in new_networks)}",
        f"Old landing-zone roots     : {old_landing_zone_root_count}",
        f"Resources in old LZ        : {old_landing_zone_resource_count}",
        f"Resources                  : {len(resources)}",
        f"Dependency edges           : {len(dependencies)}",
        f"Unresolved dependency edges: {len(unresolved)}",
        f"Collection errors          : {len(runtime.errors)}",
        f"All required phases run    : {'YES' if set(work) == set(WORK) else 'NO'}",
        f"Destroy-review gate complete: {'YES' if collection_complete else 'NO'}",
        "",
        "Network classes:",
    ]
    summary_lines.extend(
        f"  {name:<30} {count}" for name, count in sorted(network_classes.items())
    )
    summary_lines.extend(("", "Suggested dispositions:"))
    summary_lines.extend(
        f"  {name:<36} {count}" for name, count in sorted(dispositions.items())
    )
    summary_lines.extend(
        (
            "",
            "IMPORTANT: REVIEW-DESTROY-CANDIDATE is a technical review queue, "
            "not deletion authorization.",
            "Approve each decision only after business ownership, dependency, "
            "backup/export, retention/legal-hold, security and change-control review.",
            "Services not selected, unsupported service-specific attachments, "
            "guest/application dependencies and other regions remain outside "
            "this package.",
        )
    )
    summary = "\n".join(summary_lines) + "\n"
    print(summary)
    result = finish_run(
        runtime=runtime,
        outputs=outputs,
        summary_text=summary,
        artifact_keys=(
            "plan",
            "resources",
            "keep_candidates",
            "destroy_review_candidates",
            "holds_and_other_review",
            "old_landing_zone_resources",
            "dependencies",
            "unresolved_links",
            "decision_template",
            "coverage",
            "errors",
            "summary",
        ),
    )
    return 3 if not collection_complete else result


if __name__ == "__main__":
    raise SystemExit(main())
