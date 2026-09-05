#!/usr/bin/env python3
"""SI-4 SIEM integration and CrowdStrike log-forwarding evidence using Oracle's OCI Python SDK."""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
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
COLLECTOR = "SI04-01"
CONTROLS = "SI-4 / AU-12 / SI-4(2)"

SDK_READ_METHODS: Set[str] = {
    "get_compartment",
    "get_service_connector",
    "list_compartments",
    "list_log_groups",
    "list_logs",
    "list_service_connectors",
}

CROWDSTRIKE_KEYWORDS: Set[str] = {"crowdstrike", "falcon"}
SIEM_TARGET_KINDS: Set[str] = {"functions", "http", "streaming", "loggingAnalytics"}

CONNECTOR_FIELDS = [
    "connector_key", "connector_id", "connector_name", "compartment_id",
    "compartment_name", "lifecycle_state", "description",
    "source_kind", "source_log_sources", "source_stream_id",
    "tasks_present", "task_kinds",
    "target_kind", "target_stream_id", "target_function_id",
    "target_http_url", "target_log_group_id", "target_bucket",
    "crowdstrike_target", "siem_forwarding",
    "time_created", "time_updated", "region",
]

LOG_SOURCE_FIELDS = [
    "source_key", "log_group_id", "log_group_name", "log_id", "log_name",
    "compartment_id", "compartment_name", "log_type", "lifecycle_state",
    "is_enabled", "forwarded_by_connector_ids", "forwarding_coverage", "region",
]

FORWARDING_COVERAGE_FIELDS = [
    "coverage_key", "connector_id", "connector_name", "source_kind",
    "log_group_id", "log_group_name", "log_id", "log_name",
    "compartment_name", "target_kind", "crowdstrike_target", "siem_forwarding",
    "connector_lifecycle_state", "region",
]

COLLECTION_COVERAGE_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "status", "item_count", "request_id", "message",
]

ERROR_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "http_status", "service_code", "request_id", "message",
]

TEST_EVENT_FIELDS = [
    "test_id", "connector_id", "connector_name", "source_kind",
    "event_type", "test_method", "test_time",
    "siem_system", "siem_receipt_reference", "receipt_time",
    "ingestion_latency_seconds", "test_result",
    "tester", "test_date", "authority", "evidence_reference",
]

APPROVAL_FIELDS = [
    "authority_id", "system_name", "system_owner", "approver_principal",
    "siem_system", "crowdstrike_integration", "source_scope",
    "approval_status", "approval_time", "evidence_reference",
]

REVIEW_FIELDS = [
    "snapshot_sha256", "review_period",
    "total_connectors", "active_connectors", "inactive_connectors",
    "log_groups_discovered", "logs_discovered", "logs_forwarded",
    "logs_not_forwarded", "crowdstrike_connectors", "siem_connectors",
    "test_events_executed", "test_events_passed",
    "coverage_gaps", "reviewer", "review_date",
    "approval_status", "evidence_reference", "notes",
]

REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]

INPUT_SOURCE_FIELDS = ["input_type", "path", "sha256", "row_count"]
INPUT_VALIDATION_FIELDS = ["input_type", "row_key", "validation_status", "validation_message"]


def _text(obj: Any, attr: str) -> str:
    value = getattr(obj, attr, None)
    return "" if value is None else str(value)


def _is_crowdstrike(name: str, url: str) -> bool:
    combined = (name + " " + url).lower()
    return any(kw in combined for kw in CROWDSTRIKE_KEYWORDS)


def _is_siem_target(kind: str, url: str, name: str) -> bool:
    if kind in SIEM_TARGET_KINDS:
        return True
    combined = (name + " " + url).lower()
    return any(kw in combined for kw in {"siem", "splunk", "qradar", "sentinel"} | CROWDSTRIKE_KEYWORDS)


def _source_log_list(source: Any) -> List[Dict[str, str]]:
    """Return list of {log_group_id, log_id} dicts from a logging source."""
    log_sources = getattr(source, "log_sources", None) or []
    rows = []
    for ls in log_sources:
        rows.append({
            "log_group_id": str(getattr(ls, "log_group_id", "") or ""),
            "log_id": str(getattr(ls, "log_id", "") or ""),
        })
    return rows


def connector_row(
    connector: Any,
    compartment_name: str,
    region: str,
) -> Dict[str, Any]:
    source = getattr(connector, "source", None)
    target = getattr(connector, "target", None)
    tasks = getattr(connector, "tasks", None) or []

    source_kind = _text(source, "kind")
    target_kind = _text(target, "kind")

    source_log_parts = []
    source_stream_id = ""
    if source_kind == "logging":
        for ls in _source_log_list(source):
            part = ls["log_group_id"]
            if ls["log_id"]:
                part += "/" + ls["log_id"]
            source_log_parts.append(part)
    elif source_kind == "streaming":
        source_stream_id = _text(source, "stream_id")

    target_stream_id = _text(target, "stream_id")
    target_function_id = _text(target, "function_id")
    target_http_url = _text(target, "url") or _text(target, "endpoint")
    target_log_group_id = _text(target, "log_group_id")
    bucket = _text(target, "bucket_name")

    task_kinds = "|".join(
        _text(t, "kind") for t in tasks if _text(t, "kind")
    )

    connector_name = _text(connector, "display_name")
    is_cs = _is_crowdstrike(connector_name, target_http_url)
    is_siem = is_cs or _is_siem_target(target_kind, target_http_url, connector_name)

    connector_id = _text(connector, "id")
    return {
        "connector_key": stable_hash([connector_id, region]),
        "connector_id": connector_id,
        "connector_name": connector_name,
        "compartment_id": _text(connector, "compartment_id"),
        "compartment_name": compartment_name,
        "lifecycle_state": _text(connector, "lifecycle_state"),
        "description": _text(connector, "description"),
        "source_kind": source_kind,
        "source_log_sources": "|".join(source_log_parts),
        "source_stream_id": source_stream_id,
        "tasks_present": "YES" if tasks else "NO",
        "task_kinds": task_kinds,
        "target_kind": target_kind,
        "target_stream_id": target_stream_id,
        "target_function_id": target_function_id,
        "target_http_url": target_http_url,
        "target_log_group_id": target_log_group_id,
        "target_bucket": bucket,
        "crowdstrike_target": "YES" if is_cs else "NO",
        "siem_forwarding": "YES" if is_siem else "NO",
        "time_created": iso(getattr(connector, "time_created", None)),
        "time_updated": iso(getattr(connector, "time_updated", None)),
        "region": region,
    }


def log_group_rows(
    group: Any,
    compartment_name: str,
    logs: Sequence[Any],
    region: str,
) -> List[Dict[str, Any]]:
    group_id = _text(group, "id")
    group_name = _text(group, "display_name")
    compartment_id = _text(group, "compartment_id")
    group_state = _text(group, "lifecycle_state")

    if not logs:
        key = stable_hash([group_id, "", region])
        return [{
            "source_key": key,
            "log_group_id": group_id, "log_group_name": group_name,
            "log_id": "", "log_name": "(no logs)",
            "compartment_id": compartment_id, "compartment_name": compartment_name,
            "log_type": "", "lifecycle_state": group_state,
            "is_enabled": "", "forwarded_by_connector_ids": "",
            "forwarding_coverage": "UNKNOWN", "region": region,
        }]

    rows = []
    for log in logs:
        log_id = _text(log, "id")
        key = stable_hash([group_id, log_id, region])
        rows.append({
            "source_key": key,
            "log_group_id": group_id, "log_group_name": group_name,
            "log_id": log_id, "log_name": _text(log, "display_name"),
            "compartment_id": _text(log, "compartment_id") or compartment_id,
            "compartment_name": compartment_name,
            "log_type": _text(log, "log_type"),
            "lifecycle_state": _text(log, "lifecycle_state"),
            "is_enabled": str(getattr(log, "is_enabled", "")).upper(),
            "forwarded_by_connector_ids": "",
            "forwarding_coverage": "UNKNOWN",
            "region": region,
        })
    return rows


def coverage_rows_for_connector(
    connector_row_data: Dict[str, Any],
    region: str,
) -> List[Dict[str, Any]]:
    """Generate a forwarding-coverage row for each log source in a connector."""
    rows: List[Dict[str, Any]] = []
    source_kind = connector_row_data.get("source_kind", "")
    source_log_sources = connector_row_data.get("source_log_sources", "")
    connector_id = connector_row_data.get("connector_id", "")
    connector_name = connector_row_data.get("connector_name", "")

    if source_kind == "logging" and source_log_sources:
        for entry in source_log_sources.split("|"):
            parts = entry.split("/", 1)
            log_group_id = parts[0]
            log_id = parts[1] if len(parts) > 1 else ""
            key = stable_hash([connector_id, log_group_id, log_id, region])
            rows.append({
                "coverage_key": key,
                "connector_id": connector_id,
                "connector_name": connector_name,
                "source_kind": source_kind,
                "log_group_id": log_group_id,
                "log_group_name": "",
                "log_id": log_id,
                "log_name": "",
                "compartment_name": connector_row_data.get("compartment_name", ""),
                "target_kind": connector_row_data.get("target_kind", ""),
                "crowdstrike_target": connector_row_data.get("crowdstrike_target", ""),
                "siem_forwarding": connector_row_data.get("siem_forwarding", ""),
                "connector_lifecycle_state": connector_row_data.get("lifecycle_state", ""),
                "region": region,
            })
    elif source_kind:
        key = stable_hash([connector_id, source_kind, region])
        rows.append({
            "coverage_key": key,
            "connector_id": connector_id,
            "connector_name": connector_name,
            "source_kind": source_kind,
            "log_group_id": "",
            "log_group_name": "",
            "log_id": "",
            "log_name": "",
            "compartment_name": connector_row_data.get("compartment_name", ""),
            "target_kind": connector_row_data.get("target_kind", ""),
            "crowdstrike_target": connector_row_data.get("crowdstrike_target", ""),
            "siem_forwarding": connector_row_data.get("siem_forwarding", ""),
            "connector_lifecycle_state": connector_row_data.get("lifecycle_state", ""),
            "region": region,
        })
    return rows


def collect(
    oci: Any,
    args: argparse.Namespace,
    context: Any,
    targets: Sequence[ScopeItem],
) -> Tuple[
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    connectors: List[Dict[str, Any]] = []
    log_sources: List[Dict[str, Any]] = []
    coverage_list: List[Dict[str, Any]] = []
    coll_coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    seen_connector_ids: Set[str] = set()
    seen_log_ids: Set[str] = set()

    def _cov(target: ScopeItem, op: str, count: int, rid: str, msg: str, ok: bool) -> None:
        coll_coverage.append({
            "region": args.region,
            "compartment_name": target.name,
            "compartment_ocid": target.ocid,
            "operation": op,
            "status": "OK" if ok and not msg else ("FAILED" if not ok else "EMPTY"),
            "item_count": count,
            "request_id": rid,
            "message": msg,
        })

    def _err(target: ScopeItem, op: str, exc: Exception) -> None:
        detail = error_record(exc)
        coll_coverage.append({
            "region": args.region,
            "compartment_name": target.name,
            "compartment_ocid": target.ocid,
            "operation": op,
            "status": "FAILED",
            "item_count": 0,
            "request_id": detail["request_id"],
            "message": detail["message"],
        })
        errors.append({
            "region": args.region,
            "compartment_name": target.name,
            "compartment_ocid": target.ocid,
            "operation": op,
            **detail,
        })

    try:
        sch_client = build_client(oci, context, "sch", "ServiceConnectorClient")
    except Exception as exc:
        detail = error_record(exc)
        errors.append({
            "region": args.region, "compartment_name": "<build>",
            "compartment_ocid": "", "operation": "build_sch_client", **detail,
        })
        sch_client = None

    try:
        log_client = build_client(oci, context, "logging_management", "LoggingManagementClient")
    except Exception as exc:
        detail = error_record(exc)
        errors.append({
            "region": args.region, "compartment_name": "<build>",
            "compartment_ocid": "", "operation": "build_log_client", **detail,
        })
        log_client = None

    for target in targets:
        # Service Connector Hub connectors
        if sch_client is not None:
            try:
                summaries, resp = sdk_list(
                    oci, sch_client, "list_service_connectors", SDK_READ_METHODS,
                    target.ocid,
                )
                new_connectors = []
                for summary in summaries:
                    cid = _text(summary, "id")
                    if cid in seen_connector_ids:
                        continue
                    seen_connector_ids.add(cid)
                    try:
                        full_resp = sdk_get(
                            oci, sch_client, "get_service_connector", SDK_READ_METHODS, cid,
                        )
                        full = getattr(full_resp, "data", summary)
                    except Exception as get_exc:
                        detail = error_record(get_exc)
                        errors.append({
                            "region": args.region, "compartment_name": target.name,
                            "compartment_ocid": target.ocid,
                            "operation": f"get_service_connector/{cid}", **detail,
                        })
                        full = summary
                    row = connector_row(full, target.name, args.region)
                    new_connectors.append(row)
                    coverage_list.extend(coverage_rows_for_connector(row, args.region))
                connectors.extend(new_connectors)
                _cov(target, "list_service_connectors", len(new_connectors),
                     request_id(resp), "", True)
            except Exception as exc:
                _err(target, "list_service_connectors", exc)

        # Log groups and logs
        if log_client is not None:
            try:
                groups, grp_resp = sdk_list(
                    oci, log_client, "list_log_groups", SDK_READ_METHODS,
                    target.ocid,
                )
                _cov(target, "list_log_groups", len(groups), request_id(grp_resp), "", True)
                for group in groups:
                    group_id = _text(group, "id")
                    try:
                        logs, log_resp = sdk_list(
                            oci, log_client, "list_logs", SDK_READ_METHODS,
                            group_id,
                        )
                        _cov(target, f"list_logs/{group_id}", len(logs),
                             request_id(log_resp), "", True)
                        for lr in log_group_rows(group, target.name, logs, args.region):
                            lid = lr["log_id"] or lr["log_group_id"]
                            key = lr["source_key"]
                            if key not in seen_log_ids:
                                seen_log_ids.add(key)
                                log_sources.append(lr)
                    except Exception as exc:
                        _err(target, f"list_logs/{group_id}", exc)
            except Exception as exc:
                _err(target, "list_log_groups", exc)

    # Annotate log sources with which connectors forward them
    connector_by_group: Dict[str, List[str]] = defaultdict(list)
    connector_by_log: Dict[str, List[str]] = defaultdict(list)
    for cr in coverage_list:
        cid = cr["connector_id"]
        lg_id = cr.get("log_group_id", "")
        l_id = cr.get("log_id", "")
        if lg_id:
            connector_by_group[lg_id].append(cid)
        if l_id:
            connector_by_log[l_id].append(cid)

    # Enrich coverage rows with log names
    log_name_by_id = {ls["log_id"]: ls["log_name"] for ls in log_sources if ls["log_id"]}
    log_group_name_by_id = {ls["log_group_id"]: ls["log_group_name"] for ls in log_sources}
    for cr in coverage_list:
        if cr.get("log_group_id"):
            cr["log_group_name"] = log_group_name_by_id.get(cr["log_group_id"], "")
        if cr.get("log_id"):
            cr["log_name"] = log_name_by_id.get(cr["log_id"], "")

    # Annotate log sources with forwarding info
    for ls in log_sources:
        gid = ls["log_group_id"]
        lid = ls["log_id"]
        forwarding_ids = set()
        forwarding_ids.update(connector_by_group.get(gid, []))
        forwarding_ids.update(connector_by_log.get(lid, []))
        # A connector with empty log_id in its source covers all logs in the group
        for cr in coverage_list:
            if cr.get("log_group_id") == gid and not cr.get("log_id"):
                forwarding_ids.add(cr["connector_id"])
        ls["forwarded_by_connector_ids"] = "|".join(sorted(forwarding_ids))
        ls["forwarding_coverage"] = "COVERED" if forwarding_ids else "NOT-COVERED"

    return connectors, log_sources, coverage_list, coll_coverage, errors


def test_event_template(connectors: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for conn in connectors:
        if conn.get("lifecycle_state", "").upper() == "ACTIVE":
            rows.append({
                **{field: "" for field in TEST_EVENT_FIELDS},
                "connector_id": conn["connector_id"],
                "connector_name": conn["connector_name"],
                "source_kind": conn["source_kind"],
                "siem_system": "CrowdStrike" if conn.get("crowdstrike_target") == "YES" else "",
            })
    return rows


def owner_approval_template() -> List[Dict[str, Any]]:
    return [{**{field: "" for field in APPROVAL_FIELDS}}]


def expected_review(
    snapshot_hash: str,
    connectors: Sequence[Mapping[str, Any]],
    log_sources: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    total = len(connectors)
    active = sum(1 for c in connectors if c.get("lifecycle_state", "").upper() == "ACTIVE")
    inactive = total - active
    lg_set = {ls["log_group_id"] for ls in log_sources}
    log_set = {ls["log_id"] for ls in log_sources if ls.get("log_id")}
    forwarded = sum(1 for ls in log_sources if ls.get("forwarding_coverage") == "COVERED")
    not_forwarded = sum(1 for ls in log_sources if ls.get("forwarding_coverage") == "NOT-COVERED")
    cs_connectors = sum(1 for c in connectors if c.get("crowdstrike_target") == "YES")
    siem_connectors = sum(1 for c in connectors if c.get("siem_forwarding") == "YES")
    coverage_gaps = not_forwarded
    return {
        "snapshot_sha256": snapshot_hash,
        "review_period": "",
        "total_connectors": total,
        "active_connectors": active,
        "inactive_connectors": inactive,
        "log_groups_discovered": len(lg_set),
        "logs_discovered": len(log_set),
        "logs_forwarded": forwarded,
        "logs_not_forwarded": not_forwarded,
        "crowdstrike_connectors": cs_connectors,
        "siem_connectors": siem_connectors,
        "test_events_executed": "",
        "test_events_passed": "",
        "coverage_gaps": coverage_gaps,
        "reviewer": "",
        "review_date": "",
        "approval_status": "",
        "evidence_reference": "",
        "notes": "",
    }


def required_headers(path: str, fields: Sequence[str], label: str) -> List[Dict[str, str]]:
    import csv
    try:
        with open(path, newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            missing = [f for f in fields if f not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"{label} is missing columns: {', '.join(missing)}")
            return [
                {k: (v or "").strip() for k, v in row.items()}
                for row in reader
                if any((v or "").strip() for v in row.values())
            ]
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}: {exc}") from exc


def validate_test_register(
    test_rows: Sequence[Mapping[str, str]],
    connectors: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    known_ids = {c["connector_id"] for c in connectors}
    validations: List[Dict[str, Any]] = []
    blocking: List[str] = []
    for i, row in enumerate(test_rows, 1):
        tid = row.get("test_id", "") or f"<row-{i}>"
        errs: List[str] = []
        if not row.get("connector_id"):
            errs.append("connector_id is required")
        elif row["connector_id"] not in known_ids:
            errs.append("connector_id was not discovered in this scan")
        for field in ("event_type", "test_method", "siem_system",
                       "siem_receipt_reference", "test_result",
                       "tester", "test_date", "authority", "evidence_reference"):
            if not row.get(field):
                errs.append(f"{field} is required")
        if row.get("test_result", "").upper() not in {"PASS", "FAIL", "PASS-WITH-FINDINGS"}:
            errs.append("test_result must be PASS, FAIL or PASS-WITH-FINDINGS")
        status = "VALID" if not errs else "INVALID"
        message = "; ".join(errs) if errs else "Test event row is complete"
        validations.append({"input_type": "TEST-EVENT-REGISTER",
                             "row_key": tid, "validation_status": status,
                             "validation_message": message})
        if errs:
            blocking.append(f"{tid}: {message}")
    return validations, blocking


def validate_approvals(
    approval_rows: Sequence[Mapping[str, str]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    validations: List[Dict[str, Any]] = []
    blocking: List[str] = []
    for i, row in enumerate(approval_rows, 1):
        aid = row.get("authority_id", "") or f"<row-{i}>"
        errs: List[str] = []
        for field in ("system_name", "system_owner", "approver_principal",
                       "siem_system", "approval_time", "evidence_reference"):
            if not row.get(field):
                errs.append(f"{field} is required")
        if row.get("approval_status", "").upper() != "APPROVED":
            errs.append("approval_status must be APPROVED")
        status = "VALID" if not errs else "INVALID"
        message = "; ".join(errs) if errs else "Approval row is complete"
        validations.append({"input_type": "OWNER-APPROVAL",
                             "row_key": aid, "validation_status": status,
                             "validation_message": message})
        if errs:
            blocking.append(f"{aid}: {message}")
    return validations, blocking


def validate_review_row(
    row: Mapping[str, str],
    expected: Mapping[str, Any],
) -> Tuple[str, str]:
    messages: List[str] = []
    count_fields = (
        "snapshot_sha256", "total_connectors", "active_connectors", "inactive_connectors",
        "log_groups_discovered", "logs_discovered", "logs_forwarded",
        "logs_not_forwarded", "crowdstrike_connectors", "siem_connectors", "coverage_gaps",
    )
    for field in count_fields:
        if str(row.get(field, "")) != str(expected.get(field, "")):
            messages.append(f"{field} does not match the current snapshot")
    for field in ("reviewer", "review_date", "evidence_reference", "review_period"):
        if not row.get(field):
            messages.append(f"{field} is required")
    if row.get("approval_status", "").upper() != "APPROVED":
        messages.append("approval_status must be APPROVED")
    gaps = int(expected.get("coverage_gaps", 0))
    if gaps and not row.get("notes"):
        messages.append("notes must disposition every log source with no forwarding coverage")
    return ("INVALID", "; ".join(messages)) if messages else (
        "VALID", "Approved review matches the exact connector/source snapshot counts"
    )


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
    print("READ-ONLY SDK SELF-CHECK: PASSED (si04-01-siem-crowdstrike-forwarding)")
    print("Oracle SDK cloud methods are restricted to list_service_connectors, "
          "get_service_connector, list_log_groups, list_logs, and scope discovery.")
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI SIEM integration and CrowdStrike log-forwarding evidence."
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
    p.add_argument("--test-event-register")
    p.add_argument("--owner-approvals")
    p.add_argument("--monthly-review")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def resolve_targets(
    args: argparse.Namespace,
    catalog: Sequence[ScopeItem],
) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit_modes = sum(bool(v) for v in (
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
        targets: List[ScopeItem] = []
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
        wanted = {item.strip().lower() for item in args.compartment_names.split(",") if item.strip()}
        targets = [i for i in catalog if i.kind == "COMPARTMENT" and i.name.lower() in wanted]
        missing = sorted(wanted - {i.name.lower() for i in targets})
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
    outputs: Mapping[str, str],
) -> str:
    lines = [
        "======================================================================",
        " SI-4 SIEM INTEGRATION / CROWDSTRIKE FORWARDING PRE-SCAN SAFETY SUMMARY",
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
        "Mutation boundary: no create/update/delete/change/move methods are permitted",
        "Sensitive data  : OCIDs, connector names, target endpoints, log group names",
        "Endpoint boundary: target HTTP URLs are recorded for evidence; "
        "no secrets, credentials or tokens are exported",
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
    if args.monthly_review and not (args.test_event_register and args.owner_approvals):
        print("ERROR: --monthly-review requires --test-event-register and --owner-approvals",
              file=sys.stderr)
        return 1

    now = utc_now()
    try:
        test_rows = (
            required_headers(args.test_event_register, TEST_EVENT_FIELDS, "test event register")
            if args.test_event_register else []
        )
        approval_rows = (
            required_headers(args.owner_approvals, APPROVAL_FIELDS, "owner approvals")
            if args.owner_approvals else []
        )
        review_rows = (
            required_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")
            if args.monthly_review else []
        )
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
    prefix = f"si04-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "connectors": f"{output_dir}/{prefix}_connector_inventory.csv",
        "log_sources": f"{output_dir}/{prefix}_log_source_inventory.csv",
        "coverage": f"{output_dir}/{prefix}_forwarding_coverage.csv",
        "coll_coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv (only when errors exist)",
        "test_template": f"{output_dir}/{prefix}_test_event_register_template.csv",
        "approval_template": f"{output_dir}/{prefix}_owner_approval_template.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "input_validation": f"{output_dir}/{prefix}_input_validation.csv",
        "review_template": f"{output_dir}/{prefix}_monthly_review_template.csv",
        "review_validation": f"{output_dir}/{prefix}_monthly_review_validation.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    actual_outputs = {k: v.split(" (only", 1)[0] for k, v in outputs.items()}
    plan = build_plan(args, context, selected, targets, outputs)
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
    connectors, log_sources, cov_rows, coll_cov, errors = collect(
        oci, args, context, targets
    )
    write_csv(actual_outputs["connectors"], CONNECTOR_FIELDS, connectors)
    write_csv(actual_outputs["log_sources"], LOG_SOURCE_FIELDS, log_sources)
    write_csv(actual_outputs["coverage"], FORWARDING_COVERAGE_FIELDS, cov_rows)
    write_csv(actual_outputs["coll_coverage"], COLLECTION_COVERAGE_FIELDS, coll_cov)
    if errors:
        write_csv(actual_outputs["errors"], ERROR_FIELDS, errors)

    write_csv(actual_outputs["test_template"], TEST_EVENT_FIELDS, test_event_template(connectors))
    write_csv(actual_outputs["approval_template"], APPROVAL_FIELDS, owner_approval_template())

    input_sources: List[Dict[str, Any]] = []
    for label, path, rows in (
        ("TEST-EVENT-REGISTER", args.test_event_register, test_rows),
        ("OWNER-APPROVAL", args.owner_approvals, approval_rows),
        ("MONTHLY-REVIEW", args.monthly_review, review_rows),
    ):
        if path:
            input_sources.append({
                "input_type": label, "path": path,
                "sha256": sha256_file(path), "row_count": len(rows),
            })
    write_csv(actual_outputs["inputs"], INPUT_SOURCE_FIELDS, input_sources)

    all_validations: List[Dict[str, Any]] = []
    all_blocking: List[str] = []
    if test_rows:
        tv, tb = validate_test_register(test_rows, connectors)
        all_validations.extend(tv)
        all_blocking.extend(tb)
    if approval_rows:
        av, ab = validate_approvals(approval_rows)
        all_validations.extend(av)
        all_blocking.extend(ab)
    write_csv(actual_outputs["input_validation"], INPUT_VALIDATION_FIELDS, all_validations)

    snapshot_hash = sha256_file(actual_outputs["connectors"])
    expected = expected_review(snapshot_hash, connectors, log_sources)
    write_csv(actual_outputs["review_template"], REVIEW_FIELDS, [expected])
    review_results: List[Dict[str, Any]] = []
    review_error = ""
    if review_rows:
        status, message = validate_review_row(review_rows[0], expected)
        review_results.append({**review_rows[0], "validation_status": status,
                                "validation_message": message})
        if status != "VALID":
            review_error = message
    write_csv(actual_outputs["review_validation"], REVIEW_RESULT_FIELDS, review_results)

    collection_complete = not errors and all(
        row.get("status") in {"OK", "EMPTY"} for row in coll_cov
    )
    governance_mode = bool(args.test_event_register or args.owner_approvals or args.monthly_review)
    governance_complete = (
        governance_mode
        and args.test_event_register and args.owner_approvals and args.monthly_review
        and not all_blocking and not review_error
        and review_results and review_results[0].get("validation_status") == "VALID"
    )

    cs_count = sum(1 for c in connectors if c.get("crowdstrike_target") == "YES")
    siem_count = sum(1 for c in connectors if c.get("siem_forwarding") == "YES")
    covered = sum(1 for ls in log_sources if ls.get("forwarding_coverage") == "COVERED")
    not_covered = sum(1 for ls in log_sources if ls.get("forwarding_coverage") == "NOT-COVERED")
    summary_lines = [
        "SI04-01 SIEM Integration / CrowdStrike Forwarding Summary",
        "=========================================================",
        f"Region                  : {args.region}",
        f"Selected scope          : {selected.kind} / {selected.name}",
        f"Target compartments     : {len(targets)}",
        f"Collected               : {iso(now)}",
        f"OCI SDK version         : {getattr(oci, '__version__', '<unknown>')}",
        f"Total connectors        : {len(connectors)}",
        f"Active connectors       : {sum(1 for c in connectors if c.get('lifecycle_state', '').upper() == 'ACTIVE')}",
        f"CrowdStrike connectors  : {cs_count}",
        f"SIEM-forwarding total   : {siem_count}",
        f"Log groups discovered   : {len({ls['log_group_id'] for ls in log_sources})}",
        f"Logs discovered         : {sum(1 for ls in log_sources if ls.get('log_id'))}",
        f"Logs forwarded          : {covered}",
        f"Logs NOT forwarded      : {not_covered}",
        f"Collection errors       : {len(errors)}",
        f"Connector snapshot SHA  : {snapshot_hash}",
        f"COLLECTION STATUS       : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"Governance mode         : {'RECONCILIATION' if governance_mode else 'TEMPLATE-GENERATION'}",
        f"GOVERNANCE INPUT STATUS : {'VALIDATED' if governance_complete else 'NOT-VALIDATED'}",
        "",
        "A connector record is an OCI configuration fact, not proof of successful log delivery.",
        "Test event execution, SIEM receipt confirmation and owner approvals remain required.",
    ]
    write_private_text(actual_outputs["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")
    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {actual_outputs['coll_coverage']}", file=sys.stderr)
        return 3
    if governance_mode and not governance_complete:
        print(f"GOVERNANCE INPUTS NOT VALIDATED — review {actual_outputs['input_validation']}",
              file=sys.stderr)
        return 3
    print("SI04-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
