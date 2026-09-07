#!/usr/bin/env python3
"""CP-2 contingency planning evidence using Oracle's OCI Python SDK.

PYTHON FILES USED: none beyond lib/oci_audit_sdk.py, which this imports.

What OCI can and cannot establish
---------------------------------
CP-2 asks whether an approved contingency plan exists, names the systems it
covers, and states an RTO and RPO for each. **OCI has no API for any of that.**
There is no recovery-time-objective field anywhere in the SDK. What OCI can
show is the technical arrangement a plan would rely on: Full Stack DR
protection groups and their members, the DR plans defined against them,
whether the tenancy is even subscribed to a second region, and how many
availability and fault domains are available.

So this collector does two separate things and never confuses them:

  1. It records the observable DR configuration.
  2. It reconciles that configuration against an approved ISCP register
     supplied with ``--iscp-register``, which is the only place RTO, RPO,
     recovery priority and owner can legitimately come from.

Without the register the run is ``SNAPSHOT-ONLY-NO-ISCP-REGISTER``. A register
synthesised from what happens to be configured would agree with any gap by
construction, exactly as CM02-01's baseline would.

The absence of Full Stack DR is not a finding
---------------------------------------------
Most tenancies implement disaster recovery without Full Stack DR -- with
cross-region backups, manual runbooks, or replication managed outside OCI. An
empty ``list_dr_protection_groups`` therefore means "OCI holds no DR
configuration record", not "there is no contingency plan". It is reported as
``MANUAL-VERIFY-NO-OCI-DR-RECORD`` and never as a failure. CP09-03 already
covers backup replication, which is where a tenancy without Full Stack DR
usually keeps its recovery capability.

Model traps (verified against oci==2.185.1)
-------------------------------------------
* ``DrProtectionGroupSummary`` has no ``members``. Only the full
  ``DrProtectionGroup`` from ``get_dr_protection_group`` carries them, so a
  collector that lists groups reports every one of them as protecting nothing.
* ``DrPlanSummary`` has no ``plan_groups``, so plan steps are invisible to
  ``list_dr_plans``.
* The detail field is ``life_cycle_details`` -- three words -- while the state
  field beside it is ``lifecycle_state``. Reading ``lifecycle_details`` returns
  nothing. (Cloud Guard spells the same idea ``lifecyle_details``; no two
  services agree.)
* ``list_dr_plans`` and ``list_dr_plan_executions`` take a
  ``dr_protection_group_id``, not a ``compartment_id``. There is no way to
  enumerate plans across a compartment directly.
"""

from __future__ import annotations

import argparse
import ast
import csv
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
# lib/ is at the repository root, one level above this task folder.
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    ScopeItem,
    build_auth_context,
    build_client,
    discover_scope,
    error_record,
    iso,
    load_oci,
    request_id,
    sdk_get,
    sdk_list,
    sha256_file,
    stable_hash,
    utc_now,
    write_csv,
    write_private_text,
)

VERSION = "1.0.0"
COLLECTOR = "CP02-01"
CONTROLS = "CP-2 / CP-6 / CP-7 / CP-10"

SDK_READ_METHODS: Set[str] = {
    "get_compartment",
    "list_compartments",
    "list_region_subscriptions",
    "list_availability_domains",
    "list_fault_domains",
    "list_dr_protection_groups",
    # Required, not enrichment: DrProtectionGroupSummary has no members.
    "get_dr_protection_group",
    "list_dr_plans",
    # Required, not enrichment: DrPlanSummary has no plan_groups.
    "get_dr_plan",
}

# START_DRILL and STOP_DRILL exercise a plan without moving production; the
# other two are real moves. Which types a protection group defines is part of
# whether it can be tested at all, which CP04-01 then assesses.
DRILL_PLAN_TYPES: Set[str] = {"START_DRILL", "STOP_DRILL"}

REGION_FIELDS = [
    "region_key", "region_name", "status", "is_home_region", "region_finding",
]

RESILIENCE_FIELDS = [
    "region", "availability_domain", "fault_domains", "resilience_finding",
]

GROUP_FIELDS = [
    "group_key", "group_id", "display_name", "compartment_id", "compartment_name",
    "role", "peer_id", "peer_region", "lifecycle_state", "lifecycle_sub_state",
    "lifecycle_detail", "member_count", "member_types", "plan_count",
    "plan_types", "has_drill_plan", "group_finding", "time_created", "region",
]

MEMBER_FIELDS = [
    "member_key", "group_id", "group_name", "compartment_name",
    "member_id", "member_type", "region",
]

PLAN_FIELDS = [
    "plan_key", "plan_id", "display_name", "group_id", "group_name",
    "compartment_name", "plan_type", "peer_region", "lifecycle_state",
    "lifecycle_detail", "group_step_count", "step_count", "disabled_step_count",
    "plan_finding", "time_created", "region",
]

ISCP_REGISTER_FIELDS = [
    "system_id", "system_name", "system_owner", "resource_ocid",
    "rto_hours", "rpo_hours", "recovery_priority", "alternate_site",
    "approval_reference",
]

RECONCILIATION_FIELDS = ISCP_REGISTER_FIELDS + [
    "dr_protection_group", "dr_member_type", "coverage_status", "coverage_detail",
]

COLLECTION_COVERAGE_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "status", "item_count", "request_id", "message",
]

ERROR_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "http_status", "service_code", "request_id", "message",
]

SUMMARY_NOTE = (
    "OCI holds no recovery-time or recovery-point objective for any resource. "
    "RTO, RPO, recovery priority and plan approval come from the ISCP register "
    "and are reconciled here, never derived from the tenancy."
)


class RegisterUnusable(Exception):
    """The supplied ISCP register could not be read or parsed.

    Fails before any scanning: a register that degraded to an empty mapping
    would report every approved system as uncovered.
    """


def _text(obj: Any, attr: str) -> str:
    value = getattr(obj, attr, None)
    return "" if value is None else str(value)


def load_register(path: str) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise RegisterUnusable(f"ISCP register has no header row: {path}")
            missing = [f for f in ISCP_REGISTER_FIELDS if f not in reader.fieldnames]
            if missing:
                raise RegisterUnusable(
                    f"ISCP register {path} is missing required columns: "
                    + ", ".join(missing))
            rows = [dict(row) for row in reader]
    except OSError as exc:
        raise RegisterUnusable(f"ISCP register could not be read: {exc}") from exc
    if not rows:
        raise RegisterUnusable(
            f"ISCP register {path} contains no rows. An empty register would report "
            "no system as needing recovery at all; supply the approved register or "
            "omit --iscp-register to run snapshot-only.")
    for index, row in enumerate(rows, start=2):
        if not str(row.get("system_name", "")).strip():
            raise RegisterUnusable(f"{path} line {index}: system_name is empty")
    return rows


def group_rows(
    group: Any,
    detail: Any,
    plans: Sequence[Mapping[str, Any]],
    target: ScopeItem,
    region: str,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """One protection group plus its member rows.

    ``detail`` is the full DrProtectionGroup; the summary carries no members at
    all, so when the get failed the member count is UNKNOWN rather than 0.
    Reporting 0 would say the group protects nothing, which is a finding we did
    not observe.
    """
    group_id = _text(group, "id")
    name = _text(group, "display_name")
    members = list(getattr(detail, "members", None) or []) if detail is not None else []
    member_rows: List[Dict[str, Any]] = []
    for member in members:
        member_id = _text(member, "member_id")
        member_rows.append({
            "member_key": stable_hash([group_id, member_id, region]),
            "group_id": group_id, "group_name": name,
            "compartment_name": target.name,
            "member_id": member_id,
            "member_type": _text(member, "member_type"),
            "region": region,
        })

    plan_types = sorted({str(p.get("plan_type", "")) for p in plans if p.get("plan_type")})
    has_drill = any(t in DRILL_PLAN_TYPES for t in plan_types)
    state = _text(group, "lifecycle_state")
    role = _text(group, "role")
    peer = _text(group, "peer_id")

    if detail is None:
        finding = "GROUP-DETAIL-NOT-READ"
    elif state.upper() not in {"ACTIVE", "UPDATING"}:
        finding = "GROUP-NOT-ACTIVE"
    elif not members:
        # An explicit empty member list from a successful get: the group exists
        # and protects nothing.
        finding = "GROUP-HAS-NO-MEMBERS"
    elif not peer:
        finding = "GROUP-HAS-NO-PEER"
    elif not plans:
        finding = "GROUP-HAS-NO-PLAN"
    elif not has_drill:
        # Without a drill plan the arrangement cannot be exercised without
        # moving production, which is what CP-4 testing needs.
        finding = "GROUP-HAS-NO-DRILL-PLAN"
    else:
        finding = "OK"

    return {
        "group_key": stable_hash([group_id, region]),
        "group_id": group_id,
        "display_name": name,
        "compartment_id": _text(group, "compartment_id"),
        "compartment_name": target.name,
        "role": role,
        "peer_id": peer,
        "peer_region": _text(group, "peer_region"),
        "lifecycle_state": state,
        "lifecycle_sub_state": _text(group, "lifecycle_sub_state"),
        # life_cycle_details, not lifecycle_details: the model spells the state
        # field one way and the detail field beside it another.
        "lifecycle_detail": _text(group, "life_cycle_details"),
        "member_count": len(members) if detail is not None else "UNKNOWN",
        "member_types": " ".join(sorted({r["member_type"] for r in member_rows
                                         if r["member_type"]})),
        "plan_count": len(plans),
        "plan_types": " ".join(plan_types),
        "has_drill_plan": "YES" if has_drill else "NO",
        "group_finding": finding,
        "time_created": iso(getattr(group, "time_created", None)),
        "region": region,
    }, member_rows


def plan_row(plan: Any, detail: Any, group_id: str, group_name: str,
             target: ScopeItem, region: str) -> Dict[str, Any]:
    plan_id = _text(plan, "id")
    plan_groups = list(getattr(detail, "plan_groups", None) or []) if detail is not None else []
    steps: List[Any] = []
    for entry in plan_groups:
        steps.extend(list(getattr(entry, "steps", None) or []))
    disabled = sum(1 for s in steps if getattr(s, "is_enabled", None) is False)
    plan_type = _text(plan, "type")

    if detail is None:
        finding = "PLAN-DETAIL-NOT-READ"
    elif not steps:
        finding = "PLAN-HAS-NO-STEPS"
    elif disabled == len(steps):
        finding = "PLAN-ALL-STEPS-DISABLED"
    elif disabled:
        finding = "PLAN-HAS-DISABLED-STEPS"
    else:
        finding = "OK"

    return {
        "plan_key": stable_hash([plan_id, region]),
        "plan_id": plan_id,
        "display_name": _text(plan, "display_name"),
        "group_id": group_id,
        "group_name": group_name,
        "compartment_name": target.name,
        "plan_type": plan_type,
        "peer_region": _text(plan, "peer_region"),
        "lifecycle_state": _text(plan, "lifecycle_state"),
        "lifecycle_detail": _text(plan, "life_cycle_details"),
        "group_step_count": len(plan_groups) if detail is not None else "UNKNOWN",
        "step_count": len(steps) if detail is not None else "UNKNOWN",
        "disabled_step_count": disabled if detail is not None else "UNKNOWN",
        "plan_finding": finding,
        "time_created": iso(getattr(plan, "time_created", None)),
        "region": region,
    }


def reconcile_register(
    register: Sequence[Mapping[str, str]],
    members: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Match approved systems to DR members by OCID, never by name.

    A display name is not an identity: two compartments can hold resources with
    the same name, and a rename would silently move coverage from one system to
    another.
    """
    by_ocid: Dict[str, Mapping[str, Any]] = {}
    for row in members:
        member_id = str(row.get("member_id", ""))
        if member_id:
            by_ocid[member_id] = row
    group_names = {str(g.get("group_id", "")): str(g.get("display_name", "")) for g in groups}

    results: List[Dict[str, Any]] = []
    blocking: List[str] = []
    for row in register:
        ocid = str(row.get("resource_ocid", "")).strip()
        rto = str(row.get("rto_hours", "")).strip()
        rpo = str(row.get("rpo_hours", "")).strip()
        member = by_ocid.get(ocid)

        if not ocid:
            status = "REGISTER-INCOMPLETE"
            detail = "resource_ocid is empty; coverage cannot be established by name"
        elif member is None:
            status = "NOT-IN-DR-PROTECTION-GROUP"
            detail = ("the approved system is not a member of any DR protection group "
                      "discovered in the selected scope")
        else:
            status = "DR-PROTECTED"
            detail = "the approved system is a member of a DR protection group"

        missing = [name for name, value in (("rto_hours", rto), ("rpo_hours", rpo)) if not value]
        if missing:
            # An RTO/RPO the register does not state is not something OCI can
            # supply. It is an incomplete approval record.
            status = "REGISTER-INCOMPLETE"
            detail = "register does not state " + ", ".join(missing)

        if status != "DR-PROTECTED":
            blocking.append(f"{row.get('system_name', '')}={status}")
        results.append({
            **row,
            "dr_protection_group": group_names.get(
                str(member.get("group_id", "")), "") if member else "",
            "dr_member_type": str(member.get("member_type", "")) if member else "",
            "coverage_status": status,
            "coverage_detail": detail,
        })
    return results, blocking


def collect(oci: Any, args: argparse.Namespace, context: Any,
            targets: Sequence[ScopeItem]) -> Tuple[List[Dict[str, Any]], ...]:
    region = args.region
    identity = build_client(oci, context, "identity", "IdentityClient")
    dr = build_client(oci, context, "disaster_recovery", "DisasterRecoveryClient")

    region_rows: List[Dict[str, Any]] = []
    resilience_rows: List[Dict[str, Any]] = []
    group_list: List[Dict[str, Any]] = []
    member_list: List[Dict[str, Any]] = []
    plan_list: List[Dict[str, Any]] = []
    coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    def ok(target: ScopeItem, operation: str, count: int, response: Any = None) -> None:
        coverage.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "status": "OK" if count else "EMPTY", "item_count": count,
            "request_id": request_id(response) if response is not None else "",
            "message": "",
        })

    def failed(target: ScopeItem, operation: str, exc: Exception) -> None:
        record = error_record(exc)
        coverage.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "status": record.get("status", "ERROR"), "item_count": "UNKNOWN",
            "request_id": record.get("request_id", ""),
            "message": record.get("message", ""),
        })
        errors.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "http_status": record.get("http_status", ""),
            "service_code": record.get("service_code", ""),
            "request_id": record.get("request_id", ""),
            "message": record.get("message", ""),
        })

    tenancy_scope = ScopeItem(context.tenancy_id, "<tenancy>", "TENANCY")

    # A tenancy subscribed to exactly one region cannot fail over to another
    # region, whatever a plan document says. That is checkable, so it is checked.
    try:
        items, response = sdk_list(oci, identity, "list_region_subscriptions",
                                   SDK_READ_METHODS, context.tenancy_id)
        for item in items:
            region_rows.append({
                "region_key": _text(item, "region_key"),
                "region_name": _text(item, "region_name"),
                "status": _text(item, "status"),
                "is_home_region": "YES" if getattr(item, "is_home_region", False) else "NO",
                "region_finding": "OK",
            })
        if len(region_rows) == 1:
            region_rows[0]["region_finding"] = "SINGLE-REGION-TENANCY"
        ok(tenancy_scope, "identity.list_region_subscriptions", len(items), response)
    except Exception as exc:  # noqa: BLE001
        failed(tenancy_scope, "identity.list_region_subscriptions", exc)

    try:
        ads, response = sdk_list(oci, identity, "list_availability_domains",
                                 SDK_READ_METHODS, context.tenancy_id)
        ok(tenancy_scope, "identity.list_availability_domains", len(ads), response)
        for ad in ads:
            ad_name = _text(ad, "name")
            try:
                fds, fd_response = sdk_list(oci, identity, "list_fault_domains",
                                            SDK_READ_METHODS, context.tenancy_id, ad_name)
                resilience_rows.append({
                    "region": region, "availability_domain": ad_name,
                    "fault_domains": len(fds),
                    "resilience_finding": "OK" if len(fds) > 1 else "SINGLE-FAULT-DOMAIN",
                })
                ok(tenancy_scope, f"identity.list_fault_domains[{ad_name}]",
                   len(fds), fd_response)
            except Exception as exc:  # noqa: BLE001
                failed(tenancy_scope, f"identity.list_fault_domains[{ad_name}]", exc)
        if len(ads) == 1:
            for row in resilience_rows:
                row["resilience_finding"] = "SINGLE-AVAILABILITY-DOMAIN-REGION"
    except Exception as exc:  # noqa: BLE001
        failed(tenancy_scope, "identity.list_availability_domains", exc)

    for target in targets:
        try:
            groups, response = sdk_list(oci, dr, "list_dr_protection_groups",
                                        SDK_READ_METHODS, target.ocid)
            ok(target, "disaster_recovery.list_dr_protection_groups",
               len(groups), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "disaster_recovery.list_dr_protection_groups", exc)
            continue

        for group in groups:
            group_id = _text(group, "id")
            if not group_id:
                continue
            detail = None
            try:
                detail = getattr(sdk_get(oci, dr, "get_dr_protection_group",
                                         SDK_READ_METHODS, group_id), "data", None)
            except Exception as exc:  # noqa: BLE001
                failed(target, f"disaster_recovery.get_dr_protection_group[{group_id}]", exc)

            # Plans hang off the protection group, not the compartment.
            plans_for_group: List[Dict[str, Any]] = []
            try:
                plans, plan_response = sdk_list(oci, dr, "list_dr_plans",
                                                SDK_READ_METHODS, group_id)
                ok(target, f"disaster_recovery.list_dr_plans[{group_id}]",
                   len(plans), plan_response)
                for plan in plans:
                    plan_id = _text(plan, "id")
                    plan_detail = None
                    if plan_id:
                        try:
                            plan_detail = getattr(
                                sdk_get(oci, dr, "get_dr_plan", SDK_READ_METHODS, plan_id),
                                "data", None)
                        except Exception as exc:  # noqa: BLE001
                            failed(target, f"disaster_recovery.get_dr_plan[{plan_id}]", exc)
                    plans_for_group.append(plan_row(
                        plan, plan_detail, group_id, _text(group, "display_name"),
                        target, region))
            except Exception as exc:  # noqa: BLE001
                failed(target, f"disaster_recovery.list_dr_plans[{group_id}]", exc)

            row, members = group_rows(group, detail, plans_for_group, target, region)
            group_list.append(row)
            member_list.extend(members)
            plan_list.extend(plans_for_group)

    return (region_rows, resilience_rows, group_list, member_list, plan_list,
            coverage, errors)


def source_selfcheck() -> bool:
    if not SDK_READ_METHODS or any(
        not (name.startswith("list_") or name.startswith("get_"))
        for name in SDK_READ_METHODS
    ):
        print("READ-ONLY SDK SELF-CHECK: FAILED — invalid method in allowlist", file=sys.stderr)
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    problems: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in {"sdk_list", "sdk_get"} or len(node.args) < 3:
            continue
        method_node = node.args[2]
        if not isinstance(method_node, ast.Constant) or not isinstance(method_node.value, str):
            problems.append(f"line {node.lineno}: SDK method bypasses a literal guarded name")
            continue
        method = method_node.value
        prefix = "list_" if node.func.id == "sdk_list" else "get_"
        if method not in SDK_READ_METHODS or not method.startswith(prefix):
            problems.append(f"line {node.lineno}: blocked method {method}")

    # Disaster Recovery's mutating surface is the most dangerous in the SDK:
    # these move production between regions.
    forbidden = ("create_", "update_", "delete_", "change_", "move_", "cancel_",
                 "ignore_", "pause_", "resume_", "retry_", "associate_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")
    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (cp02-01-contingency-planning)")
    print("Oracle SDK cloud methods are restricted to Disaster Recovery and Identity "
          "list/get reads plus scope discovery.")
    print("No switchover, failover or plan-execution operation is reachable from this "
          "collector.")
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI contingency planning (CP-2) evidence collector.")
    p.add_argument("-r", "--region", required=False)
    p.add_argument("-o", "--output-dir", default=".")
    p.add_argument("-p", "--profile", default="DEFAULT")
    p.add_argument("--config-file", default="~/.oci/config")
    p.add_argument("--auth", choices=("config", "instance-principal", "resource-principal"),
                   default="config")
    p.add_argument("-c", "--compartment-id", action="append", default=[])
    p.add_argument("-n", "--compartment-names", default="")
    p.add_argument("--tenancy-scope", action="store_true")
    p.add_argument("--iscp-register",
                   help="CSV of the approved ISCP system register. The only source of "
                        "RTO, RPO, recovery priority and approval: OCI has no API for "
                        "any of them. Without it the run is snapshot-only.")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--confirm-scope-ocid", action="append", default=[])
    p.add_argument("--approve-scan", default="")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def resolve_targets(args: argparse.Namespace,
                    catalog: Sequence[ScopeItem]) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit = sum(bool(v) for v in
                   (args.compartment_id, args.compartment_names, args.tenancy_scope))
    if explicit > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")
    if not explicit:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}")
            print(f"              {item.ocid}")
        selected = by_id.get(
            input("Enter the exact tenancy or compartment OCID to select: ").strip())
        if selected is None:
            raise ValueError("entered OCID was not discovered")
        if input("Re-enter the exact same OCID: ").strip() != selected.ocid:
            raise ValueError("second scope confirmation did not match")
        return selected, list(catalog) if selected.kind == "TENANCY" else [selected]

    if args.tenancy_scope:
        selected, targets = catalog[0], list(catalog)
    elif args.compartment_id:
        targets = []
        for ocid in args.compartment_id:
            item = by_id.get(ocid)
            if item is None or item.kind != "COMPARTMENT":
                raise ValueError(f"compartment OCID was not discovered: {ocid}")
            if item not in targets:
                targets.append(item)
        selected = ScopeItem(
            "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
            "explicit compartments" if len(targets) > 1 else targets[0].name,
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT")
    else:
        wanted = {i.strip().lower() for i in args.compartment_names.split(",") if i.strip()}
        targets = [i for i in catalog if i.kind == "COMPARTMENT" and i.name.lower() in wanted]
        missing = sorted(wanted - {i.name.lower() for i in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = ScopeItem(
            "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
            args.compartment_names,
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT")

    if not args.non_interactive:
        for item in targets:
            first = input(f"Enter the exact OCID for {item.name}: ").strip()
            second = input("Re-enter the exact same OCID: ").strip()
            if first != item.ocid or second != item.ocid:
                raise ValueError(f"scope confirmation failed for {item.name}")
    return selected, targets


def build_plan(args: argparse.Namespace, context: Any, selected: ScopeItem,
               targets: Sequence[ScopeItem], outputs: Mapping[str, str]) -> str:
    lines = [
        "======================================================================",
        " CP-2 CONTINGENCY PLANNING PRE-SCAN SAFETY SUMMARY",
        "======================================================================",
        f"Collector       : {COLLECTOR}",
        f"Controls        : {CONTROLS}",
        f"Region          : {args.region}",
        f"Authentication  : {context.auth_label}",
        f"Profile         : {context.profile if args.auth == 'config' else '<not applicable>'}",
        f"Scope type      : {selected.kind}",
        f"Scope name      : {selected.name}",
        f"Selected OCID   : {selected.ocid}",
        f"Compartments    : {len(targets)}",
        "Cloud operations: Oracle OCI Python SDK list/get methods only",
        "Mutation boundary: no create/update/delete/change/move method is permitted",
        "DR boundary     : no switchover, failover, drill or plan-execution operation "
        "is reachable; this collector reads DR configuration and never runs it",
        "Sensitive data  : OCIDs, DR group and plan names, region subscriptions",
        f"ISCP register   : {args.iscp_register or '<none — SNAPSHOT-ONLY-NO-ISCP-REGISTER>'}",
        "RTO/RPO         : not available from any OCI API; supplied by the register only",
        "",
        "Target compartments:",
    ]
    for item in targets:
        lines.extend([f"  - {item.name}", f"    {item.ocid}"])
    lines.extend(["", "Read-only SDK operations:"])
    for method in sorted(SDK_READ_METHODS):
        lines.append("  - " + method)
    lines.extend(["", "Output files:"])
    for path in outputs.values():
        lines.append("  - " + path)
    lines.append("======================================================================")
    return "\n".join(lines) + "\n"


def validate_final_approval(args: argparse.Namespace, targets: Sequence[ScopeItem]) -> None:
    if args.non_interactive:
        expected = sorted(item.ocid for item in targets)
        supplied = sorted(set(args.confirm_scope_ocid))
        if supplied != expected:
            raise ValueError("automation confirmation OCIDs do not exactly match resolved targets")
        if args.approve_scan != "YES":
            raise ValueError("automation requires exact --approve-scan YES")
        print("Approval mode   : strict automation confirmation accepted")
        return
    if input("Type exact uppercase YES to start the read-only SDK scan: ").strip() != "YES":
        raise ValueError("operator did not enter exact uppercase YES")


def main(argv: Optional[Sequence[str]] = None, oci_module: Any = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.selfcheck:
        return 0 if source_selfcheck() else 1
    if not args.region or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
        for char in args.region
    ):
        print("ERROR: one explicit OCI region is required", file=sys.stderr)
        return 1

    register: Optional[List[Dict[str, str]]] = None
    if args.iscp_register:
        try:
            register = load_register(args.iscp_register)
        except RegisterUnusable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    now = utc_now()
    try:
        oci = oci_module or load_oci()
        context = build_auth_context(oci, args)
        identity = build_client(oci, context, "identity", "IdentityClient")
        catalog = discover_scope(oci, identity, context.tenancy_id, SDK_READ_METHODS)
        selected, targets = resolve_targets(args, catalog)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1

    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    output_dir = str(Path(args.output_dir))
    prefix = f"cp02-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "regions": f"{output_dir}/{prefix}_region_subscriptions.csv",
        "resilience": f"{output_dir}/{prefix}_domain_resilience.csv",
        "groups": f"{output_dir}/{prefix}_dr_protection_groups.csv",
        "members": f"{output_dir}/{prefix}_dr_members.csv",
        "plans": f"{output_dir}/{prefix}_dr_plans.csv",
        "reconciliation": f"{output_dir}/{prefix}_iscp_reconciliation.csv",
        "register_template": f"{output_dir}/{prefix}_iscp_register_template.csv",
        "coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    plan_text = build_plan(args, context, selected, targets, outputs)
    print(plan_text, end="")
    try:
        validate_final_approval(args, targets)
    except ValueError as exc:
        print(f"SCAN NOT STARTED: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    collisions = [p for p in outputs.values() if Path(p).exists()]
    if collisions:
        print("SCAN NOT STARTED: output collision; refusing to overwrite evidence:",
              file=sys.stderr)
        for path in collisions:
            print("  " + path, file=sys.stderr)
        return 1

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    write_private_text(outputs["plan"], plan_text + "SCAN APPROVED\n")

    (region_rows, resilience_rows, groups, members, plans,
     coverage, errors) = collect(oci, args, context, targets)

    write_csv(outputs["regions"], REGION_FIELDS, region_rows)
    write_csv(outputs["resilience"], RESILIENCE_FIELDS, resilience_rows)
    write_csv(outputs["groups"], GROUP_FIELDS, groups)
    write_csv(outputs["members"], MEMBER_FIELDS, members)
    write_csv(outputs["plans"], PLAN_FIELDS, plans)
    write_csv(outputs["coverage"], COLLECTION_COVERAGE_FIELDS, coverage)
    write_csv(outputs["errors"], ERROR_FIELDS, errors)
    # A blank register to be filled in and approved. Never pre-populated from
    # the tenancy: a register derived from what is configured cannot show that
    # something in scope was left out of the DR arrangement.
    write_csv(outputs["register_template"], ISCP_REGISTER_FIELDS, [])

    reconciliation: List[Dict[str, Any]] = []
    blocking: List[str] = []
    if register is not None:
        reconciliation, blocking = reconcile_register(register, members, groups)
    write_csv(outputs["reconciliation"], RECONCILIATION_FIELDS, reconciliation)

    input_sources = []
    if args.iscp_register:
        input_sources.append({
            "input_type": "ISCP-REGISTER", "path": args.iscp_register,
            "sha256": sha256_file(args.iscp_register), "row_count": len(register or []),
        })
    write_csv(outputs["inputs"], ["input_type", "path", "sha256", "row_count"], input_sources)

    collection_complete = not errors and all(
        row.get("status") in {"OK", "EMPTY"} for row in coverage)
    dr_configured = bool(groups)
    multi_region = len(region_rows) > 1

    summary_lines = [
        "CP02-01 Contingency Planning (CP-2) Summary",
        "===========================================",
        f"Region                     : {args.region}",
        f"Selected scope             : {selected.kind} / {selected.name}",
        f"Target compartments        : {len(targets)}",
        f"Collected                  : {iso(now)}",
        f"OCI SDK version            : {getattr(oci, '__version__', '<unknown>')}",
        f"Region subscriptions       : {len(region_rows)}",
        f"Alternate region available : {'YES' if multi_region else 'NO'}",
        f"Availability domains       : {len(resilience_rows)}",
        f"DR protection groups       : {len(groups)}",
        f"  protecting no members    : {sum(1 for g in groups if g['group_finding'] == 'GROUP-HAS-NO-MEMBERS')}",
        f"  without a peer           : {sum(1 for g in groups if g['group_finding'] == 'GROUP-HAS-NO-PEER')}",
        f"  without any plan         : {sum(1 for g in groups if g['group_finding'] == 'GROUP-HAS-NO-PLAN')}",
        f"  without a drill plan     : {sum(1 for g in groups if g['group_finding'] == 'GROUP-HAS-NO-DRILL-PLAN')}",
        f"DR members                 : {len(members)}",
        f"DR plans                   : {len(plans)}",
        f"Collection errors          : {len(errors)}",
        f"COLLECTION STATUS          : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"OCI DR RECORD              : {'PRESENT' if dr_configured else 'MANUAL-VERIFY-NO-OCI-DR-RECORD'}",
        f"ISCP REGISTER MODE         : {'RECONCILIATION' if register is not None else 'SNAPSHOT-ONLY-NO-ISCP-REGISTER'}",
    ]
    if register is not None:
        summary_lines.extend([
            f"Approved systems           : {len(register)}",
            f"  covered by a DR group    : {sum(1 for r in reconciliation if r['coverage_status'] == 'DR-PROTECTED')}",
            f"  not in any DR group      : {sum(1 for r in reconciliation if r['coverage_status'] == 'NOT-IN-DR-PROTECTION-GROUP')}",
            f"  register incomplete      : {sum(1 for r in reconciliation if r['coverage_status'] == 'REGISTER-INCOMPLETE')}",
        ])
    if not dr_configured:
        summary_lines.extend([
            "",
            "No Full Stack DR protection group was found in the selected scope.",
            "That is NOT a CP-2 failure on its own: disaster recovery is commonly",
            "implemented without Full Stack DR, using cross-region backups and",
            "documented runbooks. See CP09-03 for backup replication evidence, and",
            "establish the approved ISCP separately.",
        ])
    summary_lines.extend(["", SUMMARY_NOTE])

    write_private_text(outputs["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")

    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {outputs['coverage']}", file=sys.stderr)
        return 3
    if register is not None and blocking:
        print(f"ISCP REGISTER NOT RECONCILED — review {outputs['reconciliation']}",
              file=sys.stderr)
        return 3
    print("CP02-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
