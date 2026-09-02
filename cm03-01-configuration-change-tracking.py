#!/usr/bin/env python3
"""CM-3 configuration-change tracking evidence using Oracle's OCI Python SDK."""

from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
sys.path.insert(0, str(SCRIPT_DIR / "lib"))

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
COLLECTOR = "CM03-01"
CONTROLS = "CM-3 / CM-3(1) / CM-3(2)"
AUDIT_CHUNK_DAYS = 7

SDK_READ_METHODS: Set[str] = {
    "get_compartment",
    "get_configuration",
    "list_compartments",
    "list_events",
}

EVENT_FIELDS = [
    "event_key", "event_id", "event_grouping_id", "region", "compartment_name",
    "compartment_ocid", "event_time", "event_type", "event_name", "source",
    "http_method", "request_id", "request_path", "principal_name", "principal_id",
    "caller_name", "caller_id", "auth_type", "ip_address", "user_agent",
    "resource_name", "resource_ocid", "availability_domain", "response_status",
    "response_time", "outcome", "classification", "classification_basis",
    "state_changed", "previous_state_sha256", "current_state_sha256",
    "additional_details_sha256",
]

CONFIG_FIELDS = [
    "region", "tenancy_ocid", "retention_period_days", "requested_start_time",
    "requested_end_time", "requested_window_days", "within_retention", "status",
    "request_id", "message",
]

COVERAGE_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation", "window_start",
    "window_end", "status", "item_count", "request_id", "message",
]

ERROR_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation", "window_start",
    "window_end", "http_status", "service_code", "request_id", "message",
]

REGISTER_FIELDS = [
    "crq_id", "change_title", "change_type", "change_status", "planned_start",
    "planned_end", "actual_start", "actual_end", "requester", "implementer",
    "audit_event_ids", "audit_event_grouping_ids", "resource_ocids",
    "implementation_result", "validation_result", "rollback_result",
    "ccb_approval_reference", "emergency_approval_reference", "authority",
    "source_export_time", "evidence_reference", "oci_event_name",
]

OWNER_FIELDS = [
    "crq_id", "system_name", "system_owner", "approver_principal",
    "approval_status", "approval_time", "approval_type", "approval_reference",
    "authority", "evidence_reference",
]

SAMPLE_FIELDS = [
    "sample_id", "crq_id", "audit_event_ids", "selection_basis",
    "implementation_evidence_reference", "validation_evidence_reference",
    "backout_evidence_reference", "reviewer", "review_date", "sample_result",
    "authority", "evidence_reference",
]

RECON_FIELDS = [
    "event_key", "event_id", "event_grouping_id", "event_time", "event_name",
    "http_method", "outcome", "compartment_name", "compartment_ocid",
    "resource_name", "resource_ocid", "principal_name", "principal_id",
    "matched_crq_id", "binding_basis", "change_type", "change_status",
    "system_owner", "owner_approval_status", "approval_timing", "sample_ids",
    "reconciliation_status", "validation_message",
]

INPUT_SOURCE_FIELDS = ["input_type", "path", "sha256", "row_count"]
INPUT_VALIDATION_FIELDS = ["input_type", "row_key", "validation_status", "validation_message"]

REVIEW_FIELDS = [
    "snapshot_sha256", "review_period_start", "review_period_end",
    "total_audit_events", "change_candidate_count", "review_candidate_count", "successful_change_count",
    "failed_change_attempt_count", "validated_count", "untracked_count",
    "ambiguous_count", "unapproved_count", "sampled_crq_count", "reviewer",
    "review_date", "sampling_conclusion", "sampling_policy_reference",
    "approval_status", "evidence_reference", "notes",
]
REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]

CHANGE_TYPES = {"STANDARD", "NORMAL", "EMERGENCY"}
CHANGE_STATUSES = {"IMPLEMENTED", "CLOSED"}
APPROVAL_TYPES = {"PRE-IMPLEMENTATION", "EMERGENCY-POST"}
VALID_RESULTS = {"PASS", "PASS-WITH-FINDINGS"}
MUTATING_HTTP_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MUTATING_EVENT_RE = re.compile(
    r"^(Create|Update|Delete|Change|Move|Attach|Detach|Launch|Terminate|Restore|"
    r"Enable|Disable|Add|Remove|Rotate|Patch)",
    re.IGNORECASE,
)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI Audit change-event inventory and CM-3 governance reconciliation."
    )
    p.add_argument("-r", "--region", required=False)
    p.add_argument("-o", "--output-dir", default=".")
    p.add_argument("-p", "--profile", default="DEFAULT")
    p.add_argument("--config-file", default="~/.oci/config")
    p.add_argument(
        "--auth", choices=("config", "instance-principal", "resource-principal"),
        default="config",
    )
    p.add_argument("-i", "--select-scope", action="store_true")
    p.add_argument("-c", "--compartment-id", action="append", default=[])
    p.add_argument("-n", "--compartment-names", default="")
    p.add_argument("--tenancy-scope", action="store_true")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--confirm-scope-ocid", action="append", default=[])
    p.add_argument("--approve-scan", default="")
    p.add_argument("--lookback-days", type=int, default=30)
    p.add_argument("--start-time")
    p.add_argument("--end-time")
    p.add_argument("--change-register")
    p.add_argument("--owner-approvals")
    p.add_argument("--change-samples")
    p.add_argument("--monthly-review")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


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

    forbidden = ("create_", "update_", "delete_", "change_", "move_", "upload_", "import_", "export_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")

    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (cm03-01-configuration-change-tracking)")
    print("Oracle SDK cloud methods are restricted to get_configuration and paginated list_events plus scope discovery.")
    return True


def parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {label} timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def review_window(args: argparse.Namespace, now: datetime) -> Tuple[datetime, datetime]:
    if bool(args.start_time) != bool(args.end_time):
        raise ValueError("--start-time and --end-time must be supplied together")
    if args.lookback_days < 1 or args.lookback_days > 365:
        raise ValueError("--lookback-days must be between 1 and 365")
    if args.start_time:
        start = parse_time(args.start_time, "start")
        end = parse_time(args.end_time, "end")
    else:
        end = now
        start = end - timedelta(days=args.lookback_days)
    start = start.replace(second=0, microsecond=0)
    end = end.replace(second=0, microsecond=0)
    if start >= end:
        raise ValueError("review start must be before review end")
    if end > now + timedelta(minutes=1):
        raise ValueError("review end cannot be in the future")
    if end - start > timedelta(days=365):
        raise ValueError("review window cannot exceed OCI Audit's 365-day maximum retention")
    return start, end


def required_headers(path: str, fields: Sequence[str], label: str) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [field for field in fields if field not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"{label} is missing columns: {', '.join(missing)}")
            return [
                {key: (value or "").strip() for key, value in row.items()}
                for row in reader
                if any((value or "").strip() for value in row.values())
            ]
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}: {exc}") from exc


def pipe_values(value: str) -> Set[str]:
    return {part.strip() for part in value.split("|") if part.strip()}


def names_filter(value: str) -> Set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def resolve_targets(args: argparse.Namespace, catalog: Sequence[ScopeItem]) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit_modes = sum(bool(value) for value in (
        args.compartment_id, args.compartment_names, args.tenancy_scope,
    ))
    if explicit_modes > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")
    if args.select_scope and explicit_modes:
        raise ValueError("interactive selection cannot be combined with -c, -n or --tenancy-scope")

    if not explicit_modes:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}")
            print(f"              {item.ocid}")
        print("\nSelecting the tenancy scans root plus every active discovered compartment.")
        selected = by_id.get(input("Enter the exact tenancy or compartment OCID to select: ").strip())
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
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT",
        )
    else:
        wanted = names_filter(args.compartment_names)
        targets = [item for item in catalog if item.kind == "COMPARTMENT" and item.name.lower() in wanted]
        missing = sorted(wanted - {item.name.lower() for item in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = ScopeItem(
            "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
            args.compartment_names,
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT",
        )

    if not args.non_interactive:
        for item in targets:
            first = input(f"Enter the exact OCID for {item.name}: ").strip()
            second = input("Re-enter the exact same OCID: ").strip()
            if first != item.ocid or second != item.ocid:
                raise ValueError(f"scope confirmation failed for {item.name}")
    return selected, targets


def build_plan(
    args: argparse.Namespace,
    context: Any,
    selected: ScopeItem,
    targets: Sequence[ScopeItem],
    start: datetime,
    end: datetime,
    outputs: Mapping[str, str],
) -> str:
    lines = [
        "======================================================================",
        " CM-3 CONFIGURATION CHANGE TRACKING PRE-SCAN SAFETY SUMMARY",
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
        f"Review start    : {iso(start)}",
        f"Review end      : {iso(end)}",
        f"Audit chunks    : {AUDIT_CHUNK_DAYS} days per paginated query",
        "Cloud operations: Oracle OCI Python SDK list/get methods only",
        "Mutation boundary: no create/update/delete/change/move methods are permitted",
        "Classification  : mutating event-name verbs are candidates; unresolved non-read events require review",
        "Sensitive data  : OCIDs, identities, IP addresses, user agents, CRQs and approvals",
        "Payload boundary: request parameters/headers, credentials and response payloads are not exported",
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


def object_hash(value: Any) -> str:
    if value is None:
        return ""
    material = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return stable_hash([material])


def text(item: Any, name: str) -> str:
    value = getattr(item, name, "")
    return "" if value is None else str(value)


def event_row(args: argparse.Namespace, target: ScopeItem, event: Any) -> Dict[str, Any]:
    data = getattr(event, "data", None)
    identity = getattr(data, "identity", None)
    request = getattr(data, "request", None)
    response = getattr(data, "response", None)
    state = getattr(data, "state_change", None)
    method = text(request, "action").upper()
    event_name = text(data, "event_name")
    if method in {"GET", "HEAD", "OPTIONS"}:
        classification, basis = "NON-CHANGE", "READ-ONLY-HTTP-METHOD"
    elif MUTATING_EVENT_RE.match(event_name):
        classification = "CHANGE-CANDIDATE"
        basis = "MUTATING-EVENT-NAME+HTTP-METHOD" if method in MUTATING_HTTP_METHODS else "MUTATING-EVENT-NAME-METHOD-UNKNOWN"
    elif method in MUTATING_HTTP_METHODS:
        classification, basis = "REVIEW-CANDIDATE", "NON-READ-HTTP-METHOD-NAME-UNCONFIRMED"
    else:
        classification, basis = "REVIEW-CANDIDATE", "HTTP-METHOD-UNKNOWN"

    status = text(response, "status")
    match = re.search(r"\b([1-5][0-9]{2})\b", status)
    if match:
        code = int(match.group(1))
        outcome = "SUCCESS" if 200 <= code < 400 else "FAILED"
    else:
        outcome = "UNKNOWN"
    previous = getattr(state, "previous", None)
    current = getattr(state, "current", None)
    if previous is None and current is None:
        state_changed = "UNKNOWN"
    else:
        state_changed = "YES" if object_hash(previous) != object_hash(current) else "NO"
    event_id = text(event, "event_id")
    event_key = event_id or stable_hash([
        text(event, "event_time"), event_name, text(data, "resource_id"),
        text(request, "id"), target.ocid,
    ])
    return {
        "event_key": event_key, "event_id": event_id,
        "event_grouping_id": text(data, "event_grouping_id"),
        "region": args.region, "compartment_name": target.name,
        "compartment_ocid": text(data, "compartment_id") or target.ocid,
        "event_time": iso(getattr(event, "event_time", None)),
        "event_type": text(event, "event_type"), "event_name": event_name,
        "source": text(event, "source"), "http_method": method,
        "request_id": text(request, "id"), "request_path": text(request, "path"),
        "principal_name": text(identity, "principal_name"),
        "principal_id": text(identity, "principal_id"),
        "caller_name": text(identity, "caller_name"), "caller_id": text(identity, "caller_id"),
        "auth_type": text(identity, "auth_type"), "ip_address": text(identity, "ip_address"),
        "user_agent": text(identity, "user_agent"),
        "resource_name": text(data, "resource_name"), "resource_ocid": text(data, "resource_id"),
        "availability_domain": text(data, "availability_domain"),
        "response_status": status, "response_time": iso(getattr(response, "response_time", None)),
        "outcome": outcome, "classification": classification, "classification_basis": basis,
        "state_changed": state_changed,
        "previous_state_sha256": object_hash(previous), "current_state_sha256": object_hash(current),
        "additional_details_sha256": object_hash(getattr(data, "additional_details", None)),
    }


def time_chunks(start: datetime, end: datetime) -> Iterable[Tuple[datetime, datetime]]:
    cursor = start
    while cursor < end:
        chunk_end = min(cursor + timedelta(days=AUDIT_CHUNK_DAYS), end)
        yield cursor, chunk_end
        cursor = chunk_end


def collect(
    oci: Any,
    args: argparse.Namespace,
    context: Any,
    targets: Sequence[ScopeItem],
    start: datetime,
    end: datetime,
    now: datetime,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    config_rows: List[Dict[str, Any]] = []
    coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    events_by_key: Dict[str, Dict[str, Any]] = {}
    retention_days: Optional[int] = None
    try:
        audit = build_client(oci, context, "audit", "AuditClient")
    except Exception as exc:
        detail = error_record(exc)
        config_rows.append({
            "region": args.region, "tenancy_ocid": context.tenancy_id,
            "retention_period_days": "", "requested_start_time": iso(start),
            "requested_end_time": iso(end),
            "requested_window_days": round((end - start).total_seconds() / 86400, 3),
            "within_retention": "UNKNOWN", "status": "FAILED",
            "request_id": detail["request_id"], "message": detail["message"],
        })
        errors.append({
            "region": args.region, "compartment_name": "<tenancy>",
            "compartment_ocid": context.tenancy_id, "operation": "build_audit_client",
            "window_start": "", "window_end": "", **detail,
        })
        return config_rows, [], coverage, errors
    try:
        response = sdk_get(
            oci, audit, "get_configuration", SDK_READ_METHODS, context.tenancy_id
        )
        retention_days = getattr(getattr(response, "data", None), "retention_period_days", None)
        if not isinstance(retention_days, int) or not 90 <= retention_days <= 365:
            raise ValueError("OCI Audit configuration returned an invalid retention_period_days value")
        within = "UNKNOWN"
        if isinstance(retention_days, int):
            within = "YES" if start >= now - timedelta(days=retention_days) else "NO"
        config_rows.append({
            "region": args.region, "tenancy_ocid": context.tenancy_id,
            "retention_period_days": retention_days if retention_days is not None else "",
            "requested_start_time": iso(start), "requested_end_time": iso(end),
            "requested_window_days": round((end - start).total_seconds() / 86400, 3),
            "within_retention": within,
            "status": "OK" if within != "NO" else "OUTSIDE-RETENTION",
            "request_id": request_id(response),
            "message": "" if within != "NO" else "Requested start predates the configured OCI Audit retention window",
        })
    except Exception as exc:
        detail = error_record(exc)
        config_rows.append({
            "region": args.region, "tenancy_ocid": context.tenancy_id,
            "retention_period_days": "", "requested_start_time": iso(start),
            "requested_end_time": iso(end),
            "requested_window_days": round((end - start).total_seconds() / 86400, 3),
            "within_retention": "UNKNOWN", "status": "FAILED",
            "request_id": detail["request_id"], "message": detail["message"],
        })
        errors.append({
            "region": args.region, "compartment_name": "<tenancy>",
            "compartment_ocid": context.tenancy_id, "operation": "get_configuration",
            "window_start": "", "window_end": "", **detail,
        })

    for target in targets:
        for chunk_start, chunk_end in time_chunks(start, end):
            try:
                items, response = sdk_list(
                    oci, audit, "list_events", SDK_READ_METHODS, target.ocid,
                    chunk_start, chunk_end,
                )
                if not isinstance(getattr(response, "data", None), list):
                    raise ValueError("OCI Audit list_events returned an unexpected response shape")
                coverage.append({
                    "region": args.region, "compartment_name": target.name,
                    "compartment_ocid": target.ocid, "operation": "list_events",
                    "window_start": iso(chunk_start), "window_end": iso(chunk_end),
                    "status": "OK" if items else "EMPTY", "item_count": len(items),
                    "request_id": request_id(response), "message": "",
                })
                for item in items:
                    row = event_row(args, target, item)
                    events_by_key[row["event_key"]] = row
            except Exception as exc:
                detail = error_record(exc)
                coverage.append({
                    "region": args.region, "compartment_name": target.name,
                    "compartment_ocid": target.ocid, "operation": "list_events",
                    "window_start": iso(chunk_start), "window_end": iso(chunk_end),
                    "status": "FAILED", "item_count": 0,
                    "request_id": detail["request_id"], "message": detail["message"],
                })
                errors.append({
                    "region": args.region, "compartment_name": target.name,
                    "compartment_ocid": target.ocid, "operation": "list_events",
                    "window_start": iso(chunk_start), "window_end": iso(chunk_end), **detail,
                })

    events = sorted(events_by_key.values(), key=lambda row: (
        row["event_time"], row["compartment_name"].lower(), row["event_key"]
    ))
    return config_rows, events, coverage, errors


def register_template(changes: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for row in changes:
        rows.append({
            **{field: "" for field in REGISTER_FIELDS},
            "audit_event_ids": row["event_id"],
            "audit_event_grouping_ids": row["event_grouping_id"],
            "resource_ocids": row["resource_ocid"],
            "oci_event_name": row["event_name"],
        })
    return rows


def owner_template(register_rows: Sequence[Mapping[str, str]]) -> List[Dict[str, Any]]:
    return [
        {**{field: "" for field in OWNER_FIELDS}, "crq_id": row.get("crq_id", "")}
        for row in register_rows if row.get("crq_id")
    ]


def sample_template(register_rows: Sequence[Mapping[str, str]]) -> List[Dict[str, Any]]:
    return [
        {
            **{field: "" for field in SAMPLE_FIELDS},
            "crq_id": row.get("crq_id", ""),
            "audit_event_ids": row.get("audit_event_ids", ""),
        }
        for row in register_rows if row.get("crq_id")
    ]


def validate_inputs(
    changes: Sequence[Mapping[str, Any]],
    register_rows: Sequence[Mapping[str, str]],
    owner_rows: Sequence[Mapping[str, str]],
    sample_rows: Sequence[Mapping[str, str]],
) -> Tuple[
    Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]],
    List[Dict[str, Any]], List[str],
]:
    live_ids = {str(row["event_id"]) for row in changes if row.get("event_id")}
    live_groups = {str(row["event_grouping_id"]) for row in changes if row.get("event_grouping_id")}
    register: Dict[str, Dict[str, Any]] = {}
    owners: Dict[str, Dict[str, Any]] = {}
    samples: Dict[str, Dict[str, Any]] = {}
    validations: List[Dict[str, Any]] = []
    blocking: List[str] = []

    for number, source in enumerate(register_rows, 1):
        row = dict(source)
        crq = row.get("crq_id", "")
        errors: List[str] = []
        if not crq:
            errors.append("crq_id is required")
            crq = f"<row-{number}>"
        elif crq in register:
            errors.append("duplicate crq_id")
        for field in (
            "change_title", "planned_start", "planned_end", "actual_start", "actual_end",
            "requester", "implementer", "implementation_result", "validation_result",
            "authority", "source_export_time", "evidence_reference",
        ):
            if not row.get(field):
                errors.append(f"{field} is required")
        change_type = row.get("change_type", "").upper()
        change_status = row.get("change_status", "").upper()
        if change_type not in CHANGE_TYPES:
            errors.append("change_type must be STANDARD, NORMAL or EMERGENCY")
        if change_status not in CHANGE_STATUSES:
            errors.append("change_status must be IMPLEMENTED or CLOSED")
        if row.get("validation_result", "").upper() not in VALID_RESULTS:
            errors.append("validation_result must be PASS or PASS-WITH-FINDINGS")
        if change_type == "EMERGENCY":
            if not row.get("emergency_approval_reference"):
                errors.append("emergency change requires emergency_approval_reference")
        elif not row.get("ccb_approval_reference"):
            errors.append("standard/normal change requires ccb_approval_reference")
        event_ids = pipe_values(row.get("audit_event_ids", ""))
        group_ids = pipe_values(row.get("audit_event_grouping_ids", ""))
        if not event_ids and not group_ids:
            errors.append("an exact audit_event_id or audit_event_grouping_id is required")
        if not ((event_ids & live_ids) or (group_ids & live_groups)):
            errors.append("no exact binding resolves to a live change candidate")
        parsed: Dict[str, datetime] = {}
        for field in ("planned_start", "planned_end", "actual_start", "actual_end", "source_export_time"):
            if row.get(field):
                try:
                    parsed[field] = parse_time(row[field], field)
                except ValueError as exc:
                    errors.append(str(exc))
        for left, right in (("planned_start", "planned_end"), ("actual_start", "actual_end")):
            if left in parsed and right in parsed and parsed[left] > parsed[right]:
                errors.append(f"{left} must not be after {right}")
        row.update({
            "change_type": change_type, "change_status": change_status,
            "_event_ids": event_ids, "_group_ids": group_ids, "_parsed": parsed,
            "_errors": errors,
        })
        if crq not in register:
            register[crq] = row
        status = "VALID" if not errors else "INVALID"
        message = "; ".join(errors) if errors else "Remedy/CRQ row is complete and exactly bound"
        validations.append({"input_type": "CHANGE-REGISTER", "row_key": crq, "validation_status": status, "validation_message": message})
        if errors:
            blocking.append(f"{crq}: {message}")

    for number, source in enumerate(owner_rows, 1):
        row = dict(source)
        crq = row.get("crq_id", "") or f"<row-{number}>"
        errors: List[str] = []
        if crq not in register:
            errors.append("crq_id is not present in the supplied change register")
        if crq in owners:
            errors.append("duplicate owner approval for crq_id")
        for field in (
            "system_name", "system_owner", "approver_principal", "approval_time",
            "approval_reference", "authority", "evidence_reference",
        ):
            if not row.get(field):
                errors.append(f"{field} is required")
        if row.get("approval_status", "").upper() != "APPROVED":
            errors.append("approval_status must be APPROVED")
        approval_type = row.get("approval_type", "").upper()
        if approval_type not in APPROVAL_TYPES:
            errors.append("approval_type must be PRE-IMPLEMENTATION or EMERGENCY-POST")
        parsed_approval: Optional[datetime] = None
        if row.get("approval_time"):
            try:
                parsed_approval = parse_time(row["approval_time"], "approval_time")
            except ValueError as exc:
                errors.append(str(exc))
        row.update({
            "approval_status": row.get("approval_status", "").upper(),
            "approval_type": approval_type, "_approval_time": parsed_approval,
            "_errors": errors,
        })
        if crq not in owners:
            owners[crq] = row
        status = "VALID" if not errors else "INVALID"
        message = "; ".join(errors) if errors else "System Owner approval row is complete"
        validations.append({"input_type": "OWNER-APPROVAL", "row_key": crq, "validation_status": status, "validation_message": message})
        if errors:
            blocking.append(f"{crq}: {message}")

    event_to_crqs: Dict[str, Set[str]] = defaultdict(set)
    for crq, row in register.items():
        for event_id in row.get("_event_ids", set()):
            event_to_crqs[event_id].add(crq)
    for number, source in enumerate(sample_rows, 1):
        row = dict(source)
        sample_id = row.get("sample_id", "") or f"<row-{number}>"
        crq = row.get("crq_id", "")
        errors: List[str] = []
        if sample_id in samples:
            errors.append("duplicate sample_id")
        if crq not in register:
            errors.append("crq_id is not present in the supplied change register")
        event_ids = pipe_values(row.get("audit_event_ids", ""))
        if not event_ids:
            errors.append("audit_event_ids is required")
        for event_id in event_ids:
            if event_id not in live_ids:
                errors.append(f"sample event is not live: {event_id}")
            elif crq not in event_to_crqs.get(event_id, set()):
                errors.append(f"sample event is not exactly bound to {crq}: {event_id}")
        for field in (
            "selection_basis", "implementation_evidence_reference",
            "validation_evidence_reference", "reviewer", "review_date", "authority",
            "evidence_reference",
        ):
            if not row.get(field):
                errors.append(f"{field} is required")
        if row.get("sample_result", "").upper() not in VALID_RESULTS:
            errors.append("sample_result must be PASS or PASS-WITH-FINDINGS")
        if row.get("review_date"):
            try:
                parse_time(row["review_date"], "sample review_date")
            except ValueError as exc:
                errors.append(str(exc))
        row.update({"_event_ids": event_ids, "_errors": errors})
        if sample_id not in samples:
            samples[sample_id] = row
        status = "VALID" if not errors else "INVALID"
        message = "; ".join(errors) if errors else "Representative sample row is complete and exactly bound"
        validations.append({"input_type": "CHANGE-SAMPLE", "row_key": sample_id, "validation_status": status, "validation_message": message})
        if errors:
            blocking.append(f"{sample_id}: {message}")

    return register, owners, samples, validations, blocking


def reconcile(
    changes: Sequence[Mapping[str, Any]],
    register: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, Mapping[str, Any]],
    samples: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    by_event: Dict[str, Set[str]] = defaultdict(set)
    by_group: Dict[str, Set[str]] = defaultdict(set)
    for crq, row in register.items():
        for event_id in row.get("_event_ids", set()):
            by_event[event_id].add(crq)
        for group_id in row.get("_group_ids", set()):
            by_group[group_id].add(crq)
    samples_by_event: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for sample_id, row in samples.items():
        if row.get("_errors"):
            continue
        for event_id in row.get("_event_ids", set()):
            samples_by_event[(row.get("crq_id", ""), event_id)].append(sample_id)

    rows: List[Dict[str, Any]] = []
    for event in changes:
        event_id = str(event.get("event_id", ""))
        group_id = str(event.get("event_grouping_id", ""))
        matches = set(by_event.get(event_id, set()))
        basis: List[str] = ["EVENT-ID"] if matches else []
        group_matches = set(by_group.get(group_id, set())) if group_id else set()
        if group_matches:
            matches.update(group_matches)
            basis.append("EVENT-GROUPING-ID")
        base = {
            field: event.get(field, "") for field in (
                "event_key", "event_id", "event_grouping_id", "event_time", "event_name",
                "http_method", "outcome", "compartment_name", "compartment_ocid",
                "resource_name", "resource_ocid", "principal_name", "principal_id",
            )
        }
        if not matches:
            rows.append({
                **base, "matched_crq_id": "", "binding_basis": "", "change_type": "",
                "change_status": "", "system_owner": "", "owner_approval_status": "",
                "approval_timing": "UNKNOWN", "sample_ids": "",
                "reconciliation_status": "UNTRACKED",
                "validation_message": "No exact Remedy/CRQ binding was supplied",
            })
            continue
        if len(matches) > 1:
            rows.append({
                **base, "matched_crq_id": "|".join(sorted(matches)),
                "binding_basis": "|".join(basis), "change_type": "", "change_status": "",
                "system_owner": "", "owner_approval_status": "", "approval_timing": "UNKNOWN",
                "sample_ids": "", "reconciliation_status": "AMBIGUOUS-CRQ",
                "validation_message": "The event resolves to more than one CRQ",
            })
            continue

        crq = next(iter(matches))
        change = register[crq]
        owner = owners.get(crq)
        status, message = "VALIDATED", "Exact CRQ and System Owner approval validated"
        timing = "UNKNOWN"
        event_time = parse_time(str(event["event_time"]), "event")
        parsed = change.get("_parsed", {})
        if change.get("_errors"):
            status, message = "INVALID-CRQ", "; ".join(change["_errors"])
        elif parsed.get("actual_start") and parsed.get("actual_end") and not (
            parsed["actual_start"] <= event_time <= parsed["actual_end"]
        ):
            status, message = "EVENT-OUTSIDE-CRQ-WINDOW", "Event time is outside the CRQ actual implementation window"
        elif owner is None:
            status, message = "OWNER-APPROVAL-MISSING", "No System Owner approval row was supplied"
        elif owner.get("_errors"):
            status, message = "OWNER-APPROVAL-INVALID", "; ".join(owner["_errors"])
        else:
            approval_time = owner.get("_approval_time")
            if approval_time and approval_time <= event_time:
                timing = "PRE-IMPLEMENTATION"
                if owner.get("approval_type") != "PRE-IMPLEMENTATION":
                    status, message = "OWNER-APPROVAL-INVALID", "Pre-event approval must use PRE-IMPLEMENTATION approval_type"
            elif change.get("change_type") == "EMERGENCY" and owner.get("approval_type") == "EMERGENCY-POST":
                timing = "EMERGENCY-POST"
                status, message = "VALIDATED-EMERGENCY", "Emergency post-approval and reference validated"
            else:
                timing = "POST-IMPLEMENTATION"
                status, message = "OWNER-APPROVAL-LATE", "Normal/standard changes require approval before the event"
            if status.startswith("VALIDATED") and event.get("outcome") == "FAILED":
                status, message = "VALIDATED-FAILED-ATTEMPT", "Failed change attempt is tracked to an approved CRQ"
        sample_ids = sorted(samples_by_event.get((crq, event_id), []))
        rows.append({
            **base, "matched_crq_id": crq, "binding_basis": "|".join(basis),
            "change_type": change.get("change_type", ""),
            "change_status": change.get("change_status", ""),
            "system_owner": owner.get("system_owner", "") if owner else "",
            "owner_approval_status": owner.get("approval_status", "") if owner else "",
            "approval_timing": timing, "sample_ids": "|".join(sample_ids),
            "reconciliation_status": status, "validation_message": message,
        })
    return rows


def expected_review(
    snapshot_hash: str,
    start: datetime,
    end: datetime,
    events: Sequence[Mapping[str, Any]],
    changes: Sequence[Mapping[str, Any]],
    reconciliation: Sequence[Mapping[str, Any]],
    samples: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    statuses = Counter(str(row.get("reconciliation_status", "")) for row in reconciliation)
    sampled = {
        str(row.get("crq_id", "")) for row in samples.values()
        if not row.get("_errors") and row.get("crq_id")
    }
    validated = sum(count for status, count in statuses.items() if status.startswith("VALIDATED"))
    unapproved = sum(count for status, count in statuses.items() if status in {
        "INVALID-CRQ", "EVENT-OUTSIDE-CRQ-WINDOW", "OWNER-APPROVAL-MISSING",
        "OWNER-APPROVAL-INVALID", "OWNER-APPROVAL-LATE",
    })
    return {
        "snapshot_sha256": snapshot_hash,
        "review_period_start": iso(start), "review_period_end": iso(end),
        "total_audit_events": len(events), "change_candidate_count": len(changes),
        "review_candidate_count": sum(1 for row in events if row.get("classification") == "REVIEW-CANDIDATE"),
        "successful_change_count": sum(1 for row in changes if row.get("outcome") == "SUCCESS"),
        "failed_change_attempt_count": sum(1 for row in changes if row.get("outcome") == "FAILED"),
        "validated_count": validated, "untracked_count": statuses["UNTRACKED"],
        "ambiguous_count": statuses["AMBIGUOUS-CRQ"], "unapproved_count": unapproved,
        "sampled_crq_count": len(sampled), "reviewer": "", "review_date": "",
        "sampling_conclusion": "", "sampling_policy_reference": "",
        "approval_status": "", "evidence_reference": "", "notes": "",
    }


def validate_review(row: Mapping[str, str], expected: Mapping[str, Any]) -> Tuple[str, str]:
    messages: List[str] = []
    count_fields = (
        "snapshot_sha256", "review_period_start", "review_period_end", "total_audit_events",
        "change_candidate_count", "review_candidate_count", "successful_change_count", "failed_change_attempt_count",
        "validated_count", "untracked_count", "ambiguous_count", "unapproved_count",
        "sampled_crq_count",
    )
    for field in count_fields:
        if str(row.get(field, "")) != str(expected.get(field, "")):
            messages.append(f"{field} does not match the current snapshot")
    for field in ("reviewer", "review_date", "evidence_reference"):
        if not row.get(field):
            messages.append(f"{field} is required")
    if row.get("review_date"):
        try:
            parse_time(row["review_date"], "review_date")
        except ValueError as exc:
            messages.append(str(exc))
    if row.get("approval_status", "").upper() != "APPROVED":
        messages.append("approval_status must be APPROVED")
    change_count = int(expected.get("change_candidate_count", 0))
    conclusion = row.get("sampling_conclusion", "").upper()
    if change_count:
        if conclusion != "REPRESENTATIVE":
            messages.append("sampling_conclusion must be REPRESENTATIVE when changes exist")
        if not row.get("sampling_policy_reference"):
            messages.append("sampling_policy_reference is required when changes exist")
        if int(expected.get("sampled_crq_count", 0)) < 1:
            messages.append("at least one validated representative sample is required when changes exist")
    elif conclusion != "NO-CHANGES":
        messages.append("sampling_conclusion must be NO-CHANGES when no changes exist")
    if int(expected.get("review_candidate_count", 0)) and not row.get("notes"):
        messages.append("notes must disposition unresolved review candidates")
    return ("INVALID", "; ".join(messages)) if messages else (
        "VALID", "Approved review matches the exact Audit snapshot and sample counts"
    )


def main(argv: Optional[Sequence[str]] = None, oci_module: Any = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.selfcheck:
        return 0 if source_selfcheck() else 1
    if not args.region or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-" for char in args.region):
        print("ERROR: one explicit OCI region is required", file=sys.stderr)
        return 1
    governance_paths = [args.change_register, args.owner_approvals, args.change_samples, args.monthly_review]
    if args.owner_approvals and not args.change_register:
        print("ERROR: --owner-approvals requires --change-register", file=sys.stderr)
        return 1
    if args.change_samples and not (args.change_register and args.owner_approvals):
        print("ERROR: --change-samples requires --change-register and --owner-approvals", file=sys.stderr)
        return 1
    if args.monthly_review and not all(governance_paths[:3]):
        print("ERROR: --monthly-review requires the change register, owner approvals and samples", file=sys.stderr)
        return 1

    now = utc_now()
    try:
        start, end = review_window(args, now)
        register_rows = required_headers(args.change_register, REGISTER_FIELDS, "change register") if args.change_register else []
        owner_rows = required_headers(args.owner_approvals, OWNER_FIELDS, "owner approvals") if args.owner_approvals else []
        sample_rows = required_headers(args.change_samples, SAMPLE_FIELDS, "change samples") if args.change_samples else []
        review_rows = required_headers(args.monthly_review, REVIEW_FIELDS, "monthly review") if args.monthly_review else []
        if args.monthly_review and len(review_rows) != 1:
            raise ValueError("monthly review must contain exactly one data row")
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
    prefix = f"cm03-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "config": f"{output_dir}/{prefix}_audit_configuration.csv",
        "events": f"{output_dir}/{prefix}_audit_event_inventory.csv",
        "changes": f"{output_dir}/{prefix}_change_candidates.csv",
        "coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv (only when errors exist)",
        "register_template": f"{output_dir}/{prefix}_remedy_change_register_template.csv",
        "owner_template": f"{output_dir}/{prefix}_system_owner_approval_template.csv",
        "sample_template": f"{output_dir}/{prefix}_change_sample_template.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "input_validation": f"{output_dir}/{prefix}_input_validation.csv",
        "reconciliation": f"{output_dir}/{prefix}_change_reconciliation.csv",
        "review_template": f"{output_dir}/{prefix}_monthly_review_template.csv",
        "review_validation": f"{output_dir}/{prefix}_monthly_review_validation.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    actual_outputs = {key: value.split(" (only", 1)[0] for key, value in outputs.items()}
    plan = build_plan(args, context, selected, targets, start, end, outputs)
    print(plan, end="")
    try:
        validate_final_approval(args, targets)
    except ValueError as exc:
        print(f"SCAN NOT STARTED: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    collisions = [path for path in actual_outputs.values() if Path(path).exists()]
    if collisions:
        print("SCAN NOT STARTED: output collision; refusing to overwrite evidence:", file=sys.stderr)
        for path in collisions:
            print("  " + path, file=sys.stderr)
        return 1

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    write_private_text(actual_outputs["plan"], plan + "SCAN APPROVED\n")
    config_rows, events, coverage, errors = collect(oci, args, context, targets, start, end, now)
    changes = [row for row in events if row["classification"] == "CHANGE-CANDIDATE"]
    write_csv(actual_outputs["config"], CONFIG_FIELDS, config_rows)
    write_csv(actual_outputs["events"], EVENT_FIELDS, events)
    write_csv(actual_outputs["changes"], EVENT_FIELDS, changes)
    write_csv(actual_outputs["coverage"], COVERAGE_FIELDS, coverage)
    if errors:
        write_csv(actual_outputs["errors"], ERROR_FIELDS, errors)

    register_templates = register_template(changes)
    write_csv(actual_outputs["register_template"], REGISTER_FIELDS, register_templates)
    write_csv(actual_outputs["owner_template"], OWNER_FIELDS, owner_template(register_rows))
    write_csv(actual_outputs["sample_template"], SAMPLE_FIELDS, sample_template(register_rows))

    input_sources: List[Dict[str, Any]] = []
    for label, path, rows in (
        ("CHANGE-REGISTER", args.change_register, register_rows),
        ("OWNER-APPROVAL", args.owner_approvals, owner_rows),
        ("CHANGE-SAMPLE", args.change_samples, sample_rows),
        ("MONTHLY-REVIEW", args.monthly_review, review_rows),
    ):
        if path:
            input_sources.append({"input_type": label, "path": path, "sha256": sha256_file(path), "row_count": len(rows)})
    write_csv(actual_outputs["inputs"], INPUT_SOURCE_FIELDS, input_sources)

    register, owners, samples, input_validation, input_errors = validate_inputs(
        changes, register_rows, owner_rows, sample_rows
    )
    write_csv(actual_outputs["input_validation"], INPUT_VALIDATION_FIELDS, input_validation)
    reconciliation = reconcile(changes, register, owners, samples)
    write_csv(actual_outputs["reconciliation"], RECON_FIELDS, reconciliation)
    snapshot_hash = sha256_file(actual_outputs["changes"])
    expected = expected_review(snapshot_hash, start, end, events, changes, reconciliation, samples)
    write_csv(actual_outputs["review_template"], REVIEW_FIELDS, [expected])
    review_results: List[Dict[str, Any]] = []
    review_error = ""
    if review_rows:
        status, message = validate_review(review_rows[0], expected)
        review_results.append({**review_rows[0], "validation_status": status, "validation_message": message})
        if status != "VALID":
            review_error = message
    write_csv(actual_outputs["review_validation"], REVIEW_RESULT_FIELDS, review_results)

    config_complete = bool(config_rows) and all(row.get("status") == "OK" for row in config_rows)
    collection_complete = config_complete and not errors and all(
        row.get("status") in {"OK", "EMPTY"} for row in coverage
    )
    governance_mode = any(governance_paths)
    blocking_statuses = {
        "UNTRACKED", "AMBIGUOUS-CRQ", "INVALID-CRQ", "EVENT-OUTSIDE-CRQ-WINDOW",
        "OWNER-APPROVAL-MISSING", "OWNER-APPROVAL-INVALID", "OWNER-APPROVAL-LATE",
    }
    governance_complete = (
        governance_mode and args.change_register and args.owner_approvals
        and (not changes or bool(args.change_samples)) and args.monthly_review
        and not input_errors and not review_error and review_results
        and review_results[0].get("validation_status") == "VALID"
        and not any(row.get("reconciliation_status") in blocking_statuses for row in reconciliation)
    )
    classifications = Counter(row["classification"] for row in events)
    outcomes = Counter(row["outcome"] for row in changes)
    recon = Counter(row["reconciliation_status"] for row in reconciliation)
    summary_lines = [
        "CM03-01 Configuration Change Tracking Summary",
        "==============================================",
        f"Region                  : {args.region}",
        f"Selected scope          : {selected.kind} / {selected.name}",
        f"Target compartments     : {len(targets)}",
        f"Review start            : {iso(start)}",
        f"Review end              : {iso(end)}",
        f"Collected               : {iso(now)}",
        f"OCI SDK version         : {getattr(oci, '__version__', '<unknown>')}",
        f"Audit retention days    : {config_rows[0].get('retention_period_days', '<unknown>') if config_rows else '<unknown>'}",
        f"Total Audit events      : {len(events)}",
        f"Change candidates       : {len(changes)}",
        f"Review-only candidates  : {classifications['REVIEW-CANDIDATE']}",
        f"Non-change events       : {classifications['NON-CHANGE']}",
        f"Successful candidates   : {outcomes['SUCCESS']}",
        f"Failed change attempts  : {outcomes['FAILED']}",
        f"Validated/approved rows : {sum(count for status, count in recon.items() if status.startswith('VALIDATED'))}",
        f"Untracked rows          : {recon['UNTRACKED']}",
        f"Ambiguous rows          : {recon['AMBIGUOUS-CRQ']}",
        f"Collection errors       : {len(errors)}",
        f"Change snapshot SHA-256 : {snapshot_hash}",
        f"COLLECTION STATUS       : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"Governance mode         : {'RECONCILIATION' if governance_mode else 'TEMPLATE-GENERATION'}",
        f"GOVERNANCE INPUT STATUS : {'VALIDATED' if governance_complete else 'NOT-VALIDATED'}",
        "",
        "An Audit change candidate is an inference, not proof of an approved configuration change.",
        "Remedy/CRQ owners, System Owners and reviewers remain the authorities for approvals and samples.",
    ]
    write_private_text(actual_outputs["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")
    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {actual_outputs['coverage']}", file=sys.stderr)
        return 3
    if governance_mode and not governance_complete:
        print(f"GOVERNANCE INPUTS NOT VALIDATED — review {actual_outputs['reconciliation']}", file=sys.stderr)
        return 3
    print("CM03-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
