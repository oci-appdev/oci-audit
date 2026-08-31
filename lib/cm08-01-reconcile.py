#!/usr/bin/env python3
"""Normalize CM08 inventory and reconcile Task 9 / CM-8 evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Iterable


sys.dont_write_bytecode = True
CORE_PATH = Path(__file__).with_name("cm02-01-reconcile.py")
CORE_SPEC = importlib.util.spec_from_file_location("oci_inventory_core", CORE_PATH)
if CORE_SPEC is None or CORE_SPEC.loader is None:
    raise RuntimeError(f"unable to load shared inventory normalizer: {CORE_PATH}")
core = importlib.util.module_from_spec(CORE_SPEC)
CORE_SPEC.loader.exec_module(core)


COMPONENT_FIELDS = [
    "component_key", "component_class", "resource_type", "component_id",
    "resource_name", "region", "compartment_ocid", "compartment_name",
    "lifecycle_state", "manufacturer", "model_or_shape", "version",
    "serial_or_asset_id", "source_dataset", "inventory_fingerprint",
    "collection_status", "source_path",
]

BASELINE_FIELDS = [
    "component_key", "component_class", "resource_type", "component_id",
    "resource_name", "region", "compartment_ocid", "compartment_name",
    "inventory_fingerprint", "system_name", "system_owner",
    "technical_owner", "environment", "criticality", "inventory_status",
    "baseline_id", "approval_status", "approval_id", "approval_authority",
    "approved_by", "approval_date", "effective_date", "expiration_date",
    "source_reference", "change_reference", "retirement_reference", "notes",
]

RECON_FIELDS = [
    "reconciliation_key", "component_key", "component_class",
    "resource_type", "component_id", "resource_name", "region",
    "compartment_ocid", "previous_fingerprint", "current_fingerprint",
    "reconciliation_status", "baseline_id", "approval_id",
    "change_reference", "retirement_reference", "note",
]

DISPOSITION_FIELDS = [
    "disposition_id", "component_key", "change_type", "previous_fingerprint",
    "current_fingerprint", "disposition_status", "change_reference",
    "exception_id", "corrective_action", "action_owner", "due_date",
    "reviewed_by", "review_date", "approval_id", "approved_by",
    "approval_date", "evidence_reference", "notes",
]
DISPOSITION_RESULT_FIELDS = DISPOSITION_FIELDS + [
    "validation_status", "validation_message",
]

REVIEW_FIELDS = [
    "review_id", "review_period", "review_date", "reviewer", "reviewer_role",
    "scope_ocid", "baseline_id", "reconciliation_reference",
    "unchanged_count", "added_count", "removed_count", "changed_count",
    "unmanaged_gap_count", "inventory_reviewed", "changes_dispositioned",
    "coverage_reviewed", "corrective_actions", "review_status", "approver",
    "approval_date", "evidence_reference", "notes",
]
REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]

GAP_FIELDS = [
    "gap_id", "severity", "gap_type", "component_key", "resource_type",
    "component_id", "resource_name", "region", "compartment_ocid",
    "gap_status", "evidence_observed", "required_action",
]

FINDING_FIELDS = [
    "finding_id", "severity", "finding_type", "component_key",
    "resource_type", "component_id", "resource_name",
    "reconciliation_status", "change_reference", "exception_id",
    "required_action",
]

COVERAGE_FIELDS = [
    "raw_directory", "timestamp", "region", "compartment_ocid", "service",
    "operation", "status", "exit_code", "error_category", "label",
]
ERROR_FIELDS = ["stage", "source", "status", "category", "message"]
SOURCE_FIELDS = [
    "input_type", "path", "sha256", "row_count", "provided_by",
    "authority", "source_reference", "validation_status",
]


CLASS_BY_TYPE = {
    "COMPUTE_INSTANCE": "COMPUTE",
    "DEDICATED_VM_HOST": "COMPUTE",
    "VNIC": "NETWORK",
    "VCN": "NETWORK",
    "SUBNET": "NETWORK",
    "ROUTE_TABLE": "NETWORK",
    "SECURITY_LIST": "NETWORK",
    "NETWORK_SECURITY_GROUP": "NETWORK",
    "NETWORK_GATEWAY": "NETWORK",
    "NETWORK_FIREWALL": "NETWORK",
    "LOAD_BALANCER": "NETWORK",
    "BLOCK_VOLUME": "STORAGE",
    "BOOT_VOLUME": "STORAGE",
    "VOLUME_ATTACHMENT": "STORAGE",
    "FSS_FILE_SYSTEM": "STORAGE",
    "FSS_MOUNT_TARGET": "STORAGE",
    "FSS_EXPORT": "STORAGE",
    "OBJECT_STORAGE_BUCKET": "STORAGE",
    "COMPUTE_IMAGE": "SOFTWARE",
    "OS_PACKAGE": "SOFTWARE",
    "OS_MANAGED_INSTANCE": "SOFTWARE",
    "OKE_CLUSTER": "PLATFORM",
    "OKE_NODE_POOL": "PLATFORM",
    "OKE_VIRTUAL_NODE_POOL": "PLATFORM",
    "CONTAINER_INSTANCE": "PLATFORM",
    "CONTAINER": "SOFTWARE",
    "FUNCTION": "SOFTWARE",
    "DB_HOME": "SOFTWARE",
    "DATABASE": "DATABASE",
    "DB_SYSTEM": "DATABASE",
    "EXADATA_INFRASTRUCTURE": "DATABASE",
    "VM_CLUSTER": "DATABASE",
    "AUTONOMOUS_DATABASE": "DATABASE",
    "AUTONOMOUS_CONTAINER_DATABASE": "DATABASE",
    "MYSQL_DB_SYSTEM": "DATABASE",
    "POSTGRESQL_DB_SYSTEM": "DATABASE",
    "NOSQL_TABLE": "DATABASE",
}

VERSION_FIELDS = {
    "COMPUTE_INSTANCE": ("image_os", "image_os_version"),
    "COMPUTE_IMAGE": ("operating_system", "os_version"),
    "OS_PACKAGE": ("package_version",),
    "OS_MANAGED_INSTANCE": ("os_name", "os_version", "kernel_version"),
    "OKE_CLUSTER": ("kubernetes_version",),
    "OKE_NODE_POOL": ("kubernetes_version",),
    "OKE_VIRTUAL_NODE_POOL": ("kubernetes_version",),
    "DB_SYSTEM": ("db_system_version",),
    "DB_HOME": ("db_version",),
    "VM_CLUSTER": ("gi_version", "system_version"),
    "AUTONOMOUS_DATABASE": ("db_version",),
    "AUTONOMOUS_CONTAINER_DATABASE": ("db_version",),
    "MYSQL_DB_SYSTEM": ("mysql_version",),
    "POSTGRESQL_DB_SYSTEM": ("db_version",),
}

MODEL_FIELDS = {
    "COMPUTE_INSTANCE": ("shape", "form_factor"),
    "DEDICATED_VM_HOST": ("dvh_shape",),
    "CONTAINER_INSTANCE": ("shape",),
    "FUNCTION": ("shape",),
    "OKE_NODE_POOL": ("node_shape",),
    "OKE_VIRTUAL_NODE_POOL": ("pod_shape",),
    "DB_SYSTEM": ("shape",),
    "EXADATA_INFRASTRUCTURE": ("shape",),
    "VM_CLUSTER": ("shape",),
    "MYSQL_DB_SYSTEM": ("shape",),
    "POSTGRESQL_DB_SYSTEM": ("shape",),
}

CHANGE_TYPES = {"ADDED", "REMOVED", "CHANGED"}
ACCEPTED_DISPOSITIONS = {"APPROVED", "ACCEPTED-EXCEPTION", "CORRECTIVE-ACTION-OPEN"}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--validate-only", action="store_true")
    result.add_argument("--raw-dir", action="append", default=[])
    result.add_argument("--scope-ocid", default="")
    result.add_argument("--scope-kind", default="")
    result.add_argument("--region", default="")
    result.add_argument("--collected-at", default="")
    result.add_argument("--inventory-only", action="store_true")
    result.add_argument("--approved-inventory", default="")
    result.add_argument("--change-dispositions", default="")
    result.add_argument("--monthly-review", default="")
    for name in (
        "components", "baseline-template", "reconciliation",
        "disposition-template", "disposition", "review-template", "review",
        "gaps", "sources", "coverage", "findings", "errors", "summary",
    ):
        result.add_argument(f"--{name}-out", default="")
    return result


def clean(value: object) -> str:
    return core.clean(value)


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def join_values(row: dict[str, str], fields: tuple[str, ...]) -> str:
    return " | ".join(value for field in fields if (value := clean(row.get(field, ""))))


def raw_index(raw_dirs: list[str]) -> dict[tuple[str, str], dict[str, str]]:
    result: dict[tuple[str, str], dict[str, str]] = {}
    for raw_name in raw_dirs:
        raw = Path(raw_name)
        for dataset, (_, id_field, _) in core.DATASET_SPECS.items():
            path = raw / dataset
            if not path.is_file():
                continue
            _, rows = core.read_csv(path)
            for row in rows:
                identity = clean(row.get(id_field, "")) if id_field else core.synthetic_identity(dataset, row)
                if identity:
                    result[(str(path), identity)] = row
    return result


def stable_component_id(resource_type: str, item: dict[str, str], row: dict[str, str]) -> str:
    if resource_type == "OS_PACKAGE":
        material = "|".join([
            row.get("region", ""), row.get("managed_instance_ocid", ""),
            row.get("package_name", ""), row.get("package_architecture", ""),
            row.get("package_type", ""),
        ])
        return "cm08.os-package." + hash_text(material)
    return item["resource_ocid"]


def normalize_components(
    raw_dirs: list[str], collected_at: str,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], dict[str, dict[str, str]]]:
    # Index before the shared normalizer rewrites raw CSVs with spreadsheet-safe
    # cells; this preserves exact joins for synthetic identities.
    source_rows = raw_index(raw_dirs)
    items, attributes, coverage, errors = core.normalize_inventory(raw_dirs, collected_at)
    attrs_by_ci: dict[str, dict[str, str]] = defaultdict(dict)
    for attr in attributes:
        attrs_by_ci[attr["ci_key"]][attr["attribute_name"]] = attr["current_value"]
    components: list[dict[str, str]] = []
    component_raw: dict[str, dict[str, str]] = {}
    seen: dict[str, str] = {}

    for item in items:
        resource_type = item["resource_type"]
        dataset = item["source_dataset"]
        row = source_rows.get((item["source_path"], item["resource_ocid"]), {})
        values = {**attrs_by_ci[item["ci_key"]], **row}
        component_id = stable_component_id(resource_type, item, values)
        component_key = hash_text(f"CM08|{resource_type}|{item['region']}|{component_id}")
        if component_key in seen:
            errors.append({
                "stage": "NORMALIZATION", "source": item["source_path"],
                "status": "FAILED", "category": "DUPLICATE-COMPONENT",
                "message": f"component also appeared in {seen[component_key]}: {component_id}",
            })
            continue
        seen[component_key] = item["source_path"]
        material = {
            key: clean(value) for key, value in values.items()
            if key not in core.VOLATILE_FIELDS and key != "time_created"
        }
        fingerprint = hash_text(json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ))
        component = {
            "component_key": component_key,
            "component_class": CLASS_BY_TYPE.get(resource_type, "CLOUD-RESOURCE"),
            "resource_type": resource_type,
            "component_id": component_id,
            "resource_name": item["resource_name"],
            "region": item["region"],
            "compartment_ocid": item["compartment_ocid"],
            "compartment_name": item["compartment_name"],
            "lifecycle_state": clean(values.get("lifecycle_state", values.get("status", ""))),
            "manufacturer": "Oracle Cloud Infrastructure" if resource_type != "OS_PACKAGE" else "",
            "model_or_shape": join_values(values, MODEL_FIELDS.get(resource_type, ())),
            "version": join_values(values, VERSION_FIELDS.get(resource_type, ())),
            "serial_or_asset_id": component_id,
            "source_dataset": dataset,
            "inventory_fingerprint": fingerprint,
            "collection_status": item["collection_status"],
            "source_path": item["source_path"],
        }
        components.append(component)
        component_raw[component_key] = values

    components.sort(key=lambda row: (row["component_class"], row["resource_type"], row["component_id"]))
    return components, coverage, errors, component_raw


def approved_template(components: list[dict[str, str]]) -> list[dict[str, str]]:
    rows = []
    for component in components:
        row = {field: component.get(field, "") for field in BASELINE_FIELDS}
        row.update({
            "inventory_status": "ACTIVE",
            "approval_status": "PENDING-REVIEW",
            "notes": "Current technical inventory only; validate ownership and obtain accountable approval",
        })
        rows.append(row)
    return rows


def parse_date(value: str, label: str, blank: bool = False) -> date | None:
    if not value and blank:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be YYYY-MM-DD") from exc


def approved_row_status(row: dict[str, str]) -> tuple[bool, str]:
    required = [
        "component_key", "component_class", "resource_type", "component_id",
        "resource_name", "region", "inventory_fingerprint", "system_name",
        "system_owner", "technical_owner", "environment", "criticality",
        "inventory_status", "baseline_id", "approval_id", "approval_authority",
        "approved_by", "approval_date", "effective_date", "source_reference",
    ]
    missing = [field for field in required if not row.get(field)]
    if row.get("approval_status", "").upper() != "APPROVED":
        missing.append("approval_status=APPROVED")
    if row.get("inventory_status", "").upper() not in {"ACTIVE", "PLANNED", "RETIRED"}:
        missing.append("inventory_status=ACTIVE|PLANNED|RETIRED")
    if missing:
        return False, "missing/incomplete: " + ", ".join(missing)
    if len(row["component_key"]) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in row["component_key"]):
        return False, "component_key must be a 64-character SHA-256 hex value"
    if len(row["inventory_fingerprint"]) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in row["inventory_fingerprint"]):
        return False, "inventory_fingerprint must be a 64-character SHA-256 hex value"
    approval = parse_date(row["approval_date"], "inventory approval_date")
    effective = parse_date(row["effective_date"], "inventory effective_date")
    expiration = parse_date(row.get("expiration_date", ""), "inventory expiration_date", blank=True)
    if approval and approval > date.today():
        return False, "approval_date cannot be in the future"
    if effective and effective > date.today():
        return False, "effective_date cannot be in the future"
    if expiration and effective and expiration < effective:
        return False, "expiration_date precedes effective_date"
    if expiration and expiration < date.today():
        return False, "approved inventory row is expired"
    return True, "approved inventory row"


def recon_row(component: dict[str, str], baseline: dict[str, str], status: str, note: str) -> dict[str, str]:
    key = component.get("component_key", baseline.get("component_key", ""))
    previous = baseline.get("inventory_fingerprint", "")
    current = component.get("inventory_fingerprint", "")
    return {
        "reconciliation_key": hash_text(f"{key}|{previous}|{current}|{status}"),
        "component_key": key,
        "component_class": component.get("component_class", baseline.get("component_class", "")),
        "resource_type": component.get("resource_type", baseline.get("resource_type", "")),
        "component_id": component.get("component_id", baseline.get("component_id", "")),
        "resource_name": component.get("resource_name", baseline.get("resource_name", "")),
        "region": component.get("region", baseline.get("region", "")),
        "compartment_ocid": component.get("compartment_ocid", baseline.get("compartment_ocid", "")),
        "previous_fingerprint": previous,
        "current_fingerprint": current,
        "reconciliation_status": status,
        "baseline_id": baseline.get("baseline_id", ""),
        "approval_id": baseline.get("approval_id", ""),
        "change_reference": baseline.get("change_reference", ""),
        "retirement_reference": baseline.get("retirement_reference", ""),
        "note": note,
    }


def finding(kind: str, severity: str, row: dict[str, str], action: str, exception_id: str = "") -> dict[str, str]:
    key = row.get("component_key", "")
    return {
        "finding_id": "CM08-" + hash_text(f"{kind}|{key}|{row.get('reconciliation_status', '')}")[:16].upper(),
        "severity": severity, "finding_type": kind, "component_key": key,
        "resource_type": row.get("resource_type", ""),
        "component_id": row.get("component_id", ""),
        "resource_name": row.get("resource_name", ""),
        "reconciliation_status": row.get("reconciliation_status", ""),
        "change_reference": row.get("change_reference", ""),
        "exception_id": exception_id,
        "required_action": action,
    }


def reconcile_inventory(
    components: list[dict[str, str]], baseline_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], bool]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in baseline_rows:
        groups[row.get("component_key", "")].append(row)
    live = {row["component_key"]: row for row in components}
    reconciled: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    structurally_incomplete = False

    for baseline in groups.get("", []):
        row = recon_row({}, baseline, "APPROVED-INVENTORY-INCOMPLETE", "Approved inventory row has no component_key")
        findings.append(finding(
            "APPROVED-INVENTORY-INCOMPLETE", "HIGH", row,
            "Remove the malformed row or provide its exact generated component key and approval data",
        ))
        reconciled.append(row)
        structurally_incomplete = True

    for component in components:
        candidates = groups.get(component["component_key"], [])
        if not candidates:
            row = recon_row(component, {}, "ADDED", "Live component is absent from the approved prior inventory")
            findings.append(finding("UNAPPROVED-ADDITION", "HIGH", row, "Approve and disposition the addition or remove the unauthorized component"))
        elif len(candidates) != 1:
            row = recon_row(component, candidates[0], "AMBIGUOUS-APPROVED-INVENTORY", "Multiple approved rows claim the component key")
            findings.append(finding("AMBIGUOUS-APPROVED-INVENTORY", "HIGH", row, "Remove duplicate approved inventory rows"))
            structurally_incomplete = True
        else:
            baseline = candidates[0]
            try:
                complete, note = approved_row_status(baseline)
            except ValueError as exc:
                complete, note = False, str(exc)
            identity_ok = all(
                baseline.get(field, "") == component.get(field, "")
                for field in ("component_class", "resource_type", "component_id", "region")
            )
            if not complete:
                row = recon_row(component, baseline, "APPROVED-INVENTORY-INCOMPLETE", note)
                findings.append(finding("APPROVED-INVENTORY-INCOMPLETE", "HIGH", row, note))
                structurally_incomplete = True
            elif not identity_ok:
                row = recon_row(component, baseline, "COMPONENT-IDENTITY-MISMATCH", "Approved identity fields do not match the live component")
                findings.append(finding("COMPONENT-IDENTITY-MISMATCH", "HIGH", row, "Correct the approved inventory identity fields"))
                structurally_incomplete = True
            elif baseline["inventory_fingerprint"] == component["inventory_fingerprint"]:
                row = recon_row(component, baseline, "UNCHANGED", "Live component matches the approved prior inventory fingerprint")
            else:
                row = recon_row(component, baseline, "CHANGED", "Live component fingerprint differs from the approved prior inventory")
                findings.append(finding("COMPONENT-CHANGED", "HIGH", row, "Validate and disposition the component change"))
        reconciled.append(row)

    for key, candidates in groups.items():
        if key and key not in live:
            baseline = candidates[0]
            if len(candidates) != 1:
                row = recon_row({}, baseline, "AMBIGUOUS-APPROVED-INVENTORY", "Multiple approved rows claim an absent component key")
                structurally_incomplete = True
            else:
                try:
                    complete, note = approved_row_status(baseline)
                except ValueError as exc:
                    complete, note = False, str(exc)
                if not complete:
                    row = recon_row({}, baseline, "APPROVED-INVENTORY-INCOMPLETE", note)
                    structurally_incomplete = True
                else:
                    row = recon_row({}, baseline, "REMOVED", "Approved prior component is absent from the live inventory")
            kind = "COMPONENT-REMOVED" if row["reconciliation_status"] == "REMOVED" else row["reconciliation_status"]
            findings.append(finding(kind, "HIGH", row, "Validate removal, retirement, scope and collection coverage"))
            reconciled.append(row)

    reconciled.sort(key=lambda row: (row["reconciliation_status"], row["resource_type"], row["component_id"]))
    return reconciled, findings, structurally_incomplete


def disposition_template(reconciled: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for row in reconciled:
        if row["reconciliation_status"] not in CHANGE_TYPES:
            continue
        result.append({
            "disposition_id": "", "component_key": row["component_key"],
            "change_type": row["reconciliation_status"],
            "previous_fingerprint": row["previous_fingerprint"],
            "current_fingerprint": row["current_fingerprint"],
            "disposition_status": "PENDING", "change_reference": "",
            "exception_id": "", "corrective_action": "", "action_owner": "",
            "due_date": "", "reviewed_by": "", "review_date": "",
            "approval_id": "", "approved_by": "", "approval_date": "",
            "evidence_reference": "", "notes": "",
        })
    return result


def complete_disposition(row: dict[str, str]) -> tuple[bool, str]:
    required = [
        "disposition_id", "component_key", "change_type", "disposition_status",
        "reviewed_by", "review_date", "approval_id", "approved_by",
        "approval_date", "evidence_reference",
    ]
    missing = [field for field in required if not row.get(field)]
    status = row.get("disposition_status", "").upper()
    if status not in ACCEPTED_DISPOSITIONS:
        missing.append("disposition_status=APPROVED|ACCEPTED-EXCEPTION|CORRECTIVE-ACTION-OPEN")
    if row.get("change_type", "").upper() not in CHANGE_TYPES:
        missing.append("change_type=ADDED|REMOVED|CHANGED")
    if not row.get("change_reference") and not row.get("exception_id"):
        missing.append("change_reference or exception_id")
    if status == "ACCEPTED-EXCEPTION" and not row.get("exception_id"):
        missing.append("exception_id")
    if status == "CORRECTIVE-ACTION-OPEN":
        for field in ("corrective_action", "action_owner", "due_date"):
            if not row.get(field):
                missing.append(field)
    if missing:
        return False, "missing/incomplete: " + ", ".join(missing)
    review = parse_date(row["review_date"], "disposition review_date")
    approval = parse_date(row["approval_date"], "disposition approval_date")
    due = parse_date(row.get("due_date", ""), "disposition due_date", blank=True)
    if review and review > date.today():
        return False, "review_date cannot be in the future"
    if approval and approval > date.today():
        return False, "approval_date cannot be in the future"
    if review and approval and approval < review:
        return False, "approval_date precedes review_date"
    if status == "CORRECTIVE-ACTION-OPEN" and due and due < date.today():
        return False, "open corrective action due_date is overdue"
    return True, "approved change disposition"


def validate_dispositions(
    reconciled: list[dict[str, str]], rows: list[dict[str, str]], supplied: bool,
) -> tuple[list[dict[str, str]], list[dict[str, str]], bool]:
    events = {
        (row["component_key"], row["reconciliation_status"]): row
        for row in reconciled if row["reconciliation_status"] in CHANGE_TYPES
    }
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[(row.get("component_key", ""), row.get("change_type", "").upper())].append(row)
    results: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    incomplete = False

    for key, event in events.items():
        candidates = groups.get(key, [])
        issues: list[str] = []
        candidate = candidates[0] if candidates else {
            "component_key": key[0], "change_type": key[1],
            "previous_fingerprint": event["previous_fingerprint"],
            "current_fingerprint": event["current_fingerprint"],
        }
        if not supplied:
            issues.append("change-disposition input was not supplied")
        elif len(candidates) != 1:
            issues.append("exactly one disposition must match this component and change type")
        else:
            try:
                complete, note = complete_disposition(candidate)
            except ValueError as exc:
                complete, note = False, str(exc)
            if not complete:
                issues.append(note)
            if candidate.get("previous_fingerprint", "") != event["previous_fingerprint"]:
                issues.append("previous_fingerprint does not match reconciliation")
            if candidate.get("current_fingerprint", "") != event["current_fingerprint"]:
                issues.append("current_fingerprint does not match reconciliation")
        valid = not issues
        results.append({
            **candidate,
            "validation_status": "VALID" if valid else "INVALID",
            "validation_message": "; ".join(issues) or "approved disposition matches the live reconciliation",
        })
        if not valid:
            incomplete = True
            findings.append(finding(
                "CHANGE-NOT-DISPOSITIONED", "HIGH", event,
                "Complete one exact approved disposition for this monthly inventory change",
                candidate.get("exception_id", ""),
            ))

    for key, candidates in groups.items():
        if key not in events:
            for candidate in candidates:
                results.append({
                    **candidate, "validation_status": "STALE",
                    "validation_message": "disposition does not match a current ADDED, REMOVED or CHANGED event",
                })
                incomplete = True
    return results, findings, incomplete


def gap_row(kind: str, severity: str, component: dict[str, str], status: str, observed: str, action: str) -> dict[str, str]:
    key = component.get("component_key", "")
    return {
        "gap_id": "CM08-GAP-" + hash_text(f"{kind}|{key}")[:16].upper(),
        "severity": severity, "gap_type": kind, "component_key": key,
        "resource_type": component.get("resource_type", ""),
        "component_id": component.get("component_id", ""),
        "resource_name": component.get("resource_name", ""),
        "region": component.get("region", ""),
        "compartment_ocid": component.get("compartment_ocid", ""),
        "gap_status": status, "evidence_observed": observed,
        "required_action": action,
    }


def coverage_gaps(
    components: list[dict[str, str]], raw_values: dict[str, dict[str, str]], scope_ocid: str,
) -> list[dict[str, str]]:
    gaps: list[dict[str, str]] = []
    managed_names = {
        row["resource_name"].casefold() for row in components
        if row["resource_type"] == "OS_MANAGED_INSTANCE" and row["resource_name"]
    }
    packages_by_managed: Counter[str] = Counter()
    for component in components:
        if component["resource_type"] == "OS_PACKAGE":
            packages_by_managed[raw_values[component["component_key"]].get("managed_instance_ocid", "")] += 1

    for component in components:
        values = raw_values.get(component["component_key"], {})
        rtype = component["resource_type"]
        if rtype == "COMPUTE_INSTANCE":
            if component["resource_name"].casefold() in managed_names:
                gaps.append(gap_row(
                    "IN-GUEST-IDENTITY-LINK-NOT-PROVEN", "LOW", component, "PARTIAL",
                    "An OS-managed instance has the same display name, but the raw dataset has no compute-OCID join",
                    "Retain an authoritative compute-to-agent identity mapping and guest/application inventory",
                ))
            else:
                gaps.append(gap_row(
                    "IN-GUEST-SOFTWARE-INVENTORY-NOT-PROVEN", "HIGH", component, "OPEN",
                    "No OS-managed instance with the same display name was collected",
                    "Enroll the instance or retain approved in-guest OS, middleware and application inventory evidence",
                ))
        elif rtype == "OS_MANAGED_INSTANCE":
            expected = clean(values.get("installed_packages", ""))
            actual = packages_by_managed[component["component_id"]]
            if expected.isdigit() and int(expected) > 0 and actual == 0:
                gaps.append(gap_row(
                    "INSTALLED-PACKAGE-DETAIL-NOT-COLLECTED", "HIGH", component, "OPEN",
                    f"Managed-instance summary reports {expected} packages; detailed package rows collected: 0",
                    "Resolve package-list coverage and rerun the evidence collector",
                ))
        elif rtype in {"OKE_NODE_POOL", "OKE_VIRTUAL_NODE_POOL"}:
            gaps.append(gap_row(
                "RUNNING-NODE-INVENTORY-NOT-VERIFIED", "MEDIUM", component, "MANUAL-BOUNDARY",
                "OCI dataset contains configured pool size, not an authoritative list of running guest nodes",
                "Retain kubectl/OKE node inventory and in-guest software evidence for the review period",
            ))
        elif rtype == "FUNCTION" and not values.get("image_digest", ""):
            gaps.append(gap_row(
                "FUNCTION-IMAGE-DIGEST-NOT-RETURNED", "MEDIUM", component, "OPEN",
                "Function image digest is blank; mutable tag alone is not a stable software identity",
                "Retain the deployed immutable image digest or approved build/deployment provenance",
            ))
        elif rtype == "CONTAINER" and "@sha256:" not in values.get("image_url", ""):
            gaps.append(gap_row(
                "CONTAINER-IMAGE-DIGEST-NOT-PINNED", "MEDIUM", component, "OPEN",
                "Container image URL does not include a sha256 digest",
                "Retain the running image digest or approved immutable deployment provenance",
            ))
        if rtype != "COMPUTE_IMAGE" and not component.get("compartment_ocid"):
            gaps.append(gap_row(
                "COMPARTMENT-OCID-NOT-RETURNED", "MEDIUM", component, "OPEN",
                "The source row does not identify an OCI compartment OCID",
                "Resolve the authoritative component location before approving the inventory",
            ))

    scope_component = {
        "component_key": hash_text(f"CM08|PHYSICAL-HARDWARE|{scope_ocid}"),
        "resource_type": "CLOUD-PROVIDER-PHYSICAL-HARDWARE",
        "component_id": scope_ocid, "resource_name": "OCI provider-managed physical layer",
        "region": "", "compartment_ocid": scope_ocid,
    }
    gaps.append(gap_row(
        "PROVIDER-PHYSICAL-HARDWARE-OUTSIDE-OCI-API", "LOW", scope_component, "MANUAL-BOUNDARY",
        "OCI customer APIs inventory logical resources but do not expose provider serial/firmware records",
        "Retain the inherited-control/service-provider evidence and document the responsibility boundary",
    ))
    gaps.sort(key=lambda row: (row["severity"], row["gap_type"], row["component_id"]))
    return gaps


def review_template(scope_ocid: str, counts: Counter[str], gap_count: int) -> list[dict[str, str]]:
    return [{
        "review_id": "", "review_period": date.today().strftime("%Y-%m"),
        "review_date": "", "reviewer": "", "reviewer_role": "",
        "scope_ocid": scope_ocid, "baseline_id": "",
        "reconciliation_reference": "",
        "unchanged_count": str(counts["UNCHANGED"]),
        "added_count": str(counts["ADDED"]),
        "removed_count": str(counts["REMOVED"]),
        "changed_count": str(counts["CHANGED"]),
        "unmanaged_gap_count": str(gap_count),
        "inventory_reviewed": "NO", "changes_dispositioned": "NO",
        "coverage_reviewed": "NO", "corrective_actions": "",
        "review_status": "PENDING", "approver": "", "approval_date": "",
        "evidence_reference": "", "notes": "",
    }]


def validate_reviews(
    rows: list[dict[str, str]], scope_ocid: str, counts: Counter[str], gap_count: int,
) -> tuple[list[dict[str, str]], bool]:
    results = []
    period = date.today().strftime("%Y-%m")
    expected_counts = {
        "unchanged_count": counts["UNCHANGED"], "added_count": counts["ADDED"],
        "removed_count": counts["REMOVED"], "changed_count": counts["CHANGED"],
        "unmanaged_gap_count": gap_count,
    }
    current_rows = 0
    valid_current = 0
    for row in rows:
        issues: list[str] = []
        required = [
            "review_id", "review_period", "review_date", "reviewer", "reviewer_role",
            "scope_ocid", "baseline_id", "reconciliation_reference",
            "corrective_actions", "approver", "approval_date", "evidence_reference",
        ]
        issues.extend(f"missing {field}" for field in required if not row.get(field))
        for flag in ("inventory_reviewed", "changes_dispositioned", "coverage_reviewed"):
            if row.get(flag, "").upper() != "YES":
                issues.append(f"{flag} must be YES")
        if row.get("review_status", "").upper() != "APPROVED":
            issues.append("review_status must be APPROVED")
        if row.get("scope_ocid") != scope_ocid:
            issues.append("scope_ocid does not match the approved scan scope")
        for field, expected in expected_counts.items():
            try:
                actual = int(row.get(field, ""))
            except ValueError:
                issues.append(f"{field} must be an integer")
            else:
                if actual != expected:
                    issues.append(f"{field} does not match reconciliation ({expected})")
        try:
            reviewed = parse_date(row.get("review_date", ""), "review_date")
            approved = parse_date(row.get("approval_date", ""), "review approval_date")
            if reviewed and reviewed > date.today():
                issues.append("review_date cannot be in the future")
            if approved and approved > date.today():
                issues.append("approval_date cannot be in the future")
            if reviewed and approved and approved < reviewed:
                issues.append("approval_date precedes review_date")
            if reviewed and row.get("review_period") != reviewed.strftime("%Y-%m"):
                issues.append("review_period does not match review_date")
        except ValueError as exc:
            issues.append(str(exc))
        status = "VALID" if not issues else "INVALID"
        if row.get("review_period") == period:
            current_rows += 1
        if status == "VALID" and row.get("review_period") == period:
            valid_current += 1
        results.append({**row, "validation_status": status, "validation_message": "; ".join(issues) or "approved count-bound monthly inventory review"})
    return results, current_rows != 1 or valid_current != 1


def require_headers(path: str, fields: list[str], label: str) -> list[dict[str, str]]:
    return core.require_headers(path, fields, label)


def validate_inputs(args: argparse.Namespace) -> None:
    if not args.approved_inventory:
        raise ValueError("approved inventory is required")
    require_headers(args.approved_inventory, BASELINE_FIELDS, "approved inventory")
    if args.change_dispositions:
        require_headers(args.change_dispositions, DISPOSITION_FIELDS, "change dispositions")
    if args.monthly_review:
        require_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")


def source_row(input_type: str, path: str, rows: list[dict[str, str]]) -> dict[str, str]:
    first = rows[0] if rows else {}
    if input_type == "APPROVED-INVENTORY":
        provided, authority, reference = first.get("approved_by", ""), first.get("approval_authority", ""), first.get("source_reference", "")
    elif input_type == "CHANGE-DISPOSITIONS":
        provided, authority, reference = first.get("reviewed_by", ""), first.get("approved_by", ""), first.get("evidence_reference", "")
    else:
        provided, authority, reference = first.get("reviewer", ""), first.get("approver", ""), first.get("evidence_reference", "")
    return {
        "input_type": input_type, "path": path,
        "sha256": core.sha256_file(Path(path)), "row_count": str(len(rows)),
        "provided_by": provided, "authority": authority,
        "source_reference": reference, "validation_status": "PROVIDED",
    }


def missing_source(input_type: str, status: str) -> dict[str, str]:
    return {
        "input_type": input_type, "path": "", "sha256": "", "row_count": "0",
        "provided_by": "", "authority": "", "source_reference": "",
        "validation_status": status,
    }


def write_csv(path: str, fields: list[str], rows: Iterable[dict[str, object]]) -> None:
    core.write_csv(path, fields, rows)


def main() -> int:
    args = parser().parse_args()
    try:
        if args.validate_only:
            validate_inputs(args)
            print("CM08-01 input headers validated.")
            return 0
        required_outputs = [
            args.components_out, args.baseline_template_out,
            args.reconciliation_out, args.disposition_template_out,
            args.disposition_out, args.review_template_out, args.review_out,
            args.gaps_out, args.sources_out, args.coverage_out,
            args.findings_out, args.errors_out, args.summary_out,
        ]
        if not args.raw_dir or not all(required_outputs):
            raise ValueError("raw directories and every output path are required")
        if not args.inventory_only:
            validate_inputs(args)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    components, coverage, errors, raw_values = normalize_components(args.raw_dir, args.collected_at)
    gaps = coverage_gaps(components, raw_values, args.scope_ocid)
    baseline_rows: list[dict[str, str]] = []
    reconciled: list[dict[str, str]] = []
    disposition_rows: list[dict[str, str]] = []
    disposition_results: list[dict[str, str]] = []
    review_rows: list[dict[str, str]] = []
    review_results: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    sources: list[dict[str, str]] = []
    incomplete = bool(errors)

    if args.inventory_only:
        sources = [
            missing_source(kind, "SKIPPED-INVENTORY-ONLY")
            for kind in ("APPROVED-INVENTORY", "CHANGE-DISPOSITIONS", "MONTHLY-REVIEW")
        ]
    else:
        try:
            baseline_rows = require_headers(args.approved_inventory, BASELINE_FIELDS, "approved inventory")
            sources.append(source_row("APPROVED-INVENTORY", args.approved_inventory, baseline_rows))
            reconciled, recon_findings, recon_incomplete = reconcile_inventory(components, baseline_rows)
            findings.extend(recon_findings)
            incomplete = incomplete or recon_incomplete

            if args.change_dispositions:
                disposition_rows = require_headers(args.change_dispositions, DISPOSITION_FIELDS, "change dispositions")
                sources.append(source_row("CHANGE-DISPOSITIONS", args.change_dispositions, disposition_rows))
            else:
                sources.append(missing_source("CHANGE-DISPOSITIONS", "NOT-SUPPLIED"))
            disposition_results, disposition_findings, disposition_incomplete = validate_dispositions(
                reconciled, disposition_rows, bool(args.change_dispositions),
            )
            findings.extend(disposition_findings)
            incomplete = incomplete or disposition_incomplete

            counts = Counter(row["reconciliation_status"] for row in reconciled)
            if args.monthly_review:
                review_rows = require_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")
                sources.append(source_row("MONTHLY-REVIEW", args.monthly_review, review_rows))
                review_results, review_incomplete = validate_reviews(review_rows, args.scope_ocid, counts, len(gaps))
            else:
                sources.append(missing_source("MONTHLY-REVIEW", "NOT-SUPPLIED"))
                review_incomplete = True
            if review_incomplete:
                errors.append({
                    "stage": "MONTHLY-REVIEW", "source": args.monthly_review or "<not supplied>",
                    "status": "INCOMPLETE", "category": "NO-VALID-CURRENT-REVIEW",
                    "message": "exactly one valid approved, count-bound review is required for the current YYYY-MM period",
                })
                incomplete = True
        except (OSError, ValueError) as exc:
            errors.append({
                "stage": "RECONCILIATION", "source": "control inputs",
                "status": "FAILED", "category": "INPUT-VALIDATION", "message": str(exc),
            })
            incomplete = True

    counts = Counter(row.get("reconciliation_status", "") for row in reconciled)
    write_csv(args.components_out, COMPONENT_FIELDS, components)
    write_csv(args.baseline_template_out, BASELINE_FIELDS, approved_template(components))
    write_csv(args.reconciliation_out, RECON_FIELDS, reconciled)
    write_csv(args.disposition_template_out, DISPOSITION_FIELDS, disposition_template(reconciled))
    write_csv(args.disposition_out, DISPOSITION_RESULT_FIELDS, disposition_results)
    write_csv(args.review_template_out, REVIEW_FIELDS, review_template(args.scope_ocid, counts, len(gaps)))
    write_csv(args.review_out, REVIEW_RESULT_FIELDS, review_results)
    write_csv(args.gaps_out, GAP_FIELDS, gaps)
    write_csv(args.sources_out, SOURCE_FIELDS, sources)
    write_csv(args.coverage_out, COVERAGE_FIELDS, coverage)
    write_csv(args.findings_out, FINDING_FIELDS, findings)
    if errors:
        write_csv(args.errors_out, ERROR_FIELDS, errors)

    coverage_counts = Counter(row.get("status", "UNKNOWN") for row in coverage)
    finding_counts = Counter(row.get("severity", "UNKNOWN") for row in findings)
    gap_counts = Counter(row.get("severity", "UNKNOWN") for row in gaps)
    with Path(args.summary_out).open("w", encoding="utf-8") as handle:
        handle.write("CM08-01 System Component Inventory Summary\n")
        handle.write("==========================================\n")
        handle.write(f"Scope kind             : {args.scope_kind}\n")
        handle.write(f"Scope OCID             : {args.scope_ocid}\n")
        handle.write(f"Region                 : {args.region}\n")
        handle.write(f"Collected              : {args.collected_at}\n")
        handle.write(f"Mode                   : {'INVENTORY-ONLY' if args.inventory_only else 'MONTHLY-RECONCILIATION'}\n")
        handle.write(f"Components             : {len(components)}\n")
        handle.write(f"Coverage OK            : {coverage_counts['OK']}\n")
        handle.write(f"Coverage EMPTY         : {coverage_counts['EMPTY']}\n")
        handle.write(f"Coverage FAILED        : {coverage_counts['FAILED']}\n")
        handle.write(f"Unchanged              : {counts['UNCHANGED']}\n")
        handle.write(f"Added                  : {counts['ADDED']}\n")
        handle.write(f"Removed                : {counts['REMOVED']}\n")
        handle.write(f"Changed                : {counts['CHANGED']}\n")
        handle.write(f"Unmanaged/visibility gaps: {len(gaps)}\n")
        handle.write(f"Gap HIGH               : {gap_counts['HIGH']}\n")
        handle.write(f"Gap MEDIUM             : {gap_counts['MEDIUM']}\n")
        handle.write(f"Findings HIGH          : {finding_counts['HIGH']}\n")
        handle.write(f"Findings MEDIUM        : {finding_counts['MEDIUM']}\n")
        handle.write(f"Evidence errors        : {len(errors)}\n")
        handle.write(f"EVIDENCE STATUS        : {'INCOMPLETE' if incomplete else 'COMPLETE-FOR-REVIEW'}\n")
        handle.write("\nA COMPLETE-FOR-REVIEW result is not an authorization decision. The designated\n")
        handle.write("inventory authority must review gaps/findings and approve the retained package.\n")

    return 3 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
