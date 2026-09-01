#!/usr/bin/env python3
"""Normalize CM08 inventory and reconcile Task 8 / CM-2 evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path
from typing import Iterable


DATASET_SPECS = {
    "compute_instances.csv": ("COMPUTE_INSTANCE", "instance_ocid", "instance_name"),
    "instance_vnics.csv": ("VNIC", "vnic_ocid", "vnic_name"),
    "images_in_use.csv": ("COMPUTE_IMAGE", "image_ocid", "image_name"),
    "dedicated_vm_hosts.csv": ("DEDICATED_VM_HOST", "host_ocid", "host_name"),
    "block_volumes.csv": ("BLOCK_VOLUME", "volume_ocid", "volume_name"),
    "boot_volumes.csv": ("BOOT_VOLUME", "volume_ocid", "volume_name"),
    "volume_attachments.csv": ("VOLUME_ATTACHMENT", "", "attachment_type"),
    "fss_file_systems.csv": ("FSS_FILE_SYSTEM", "fs_ocid", "fs_name"),
    "fss_mount_targets.csv": ("FSS_MOUNT_TARGET", "mt_ocid", "mt_name"),
    "fss_exports.csv": ("FSS_EXPORT", "export_ocid", "path"),
    "object_storage_buckets.csv": ("OBJECT_STORAGE_BUCKET", "", "bucket_name"),
    "network_vcns.csv": ("VCN", "vcn_ocid", "vcn_name"),
    "network_subnets.csv": ("SUBNET", "subnet_ocid", "subnet_name"),
    "network_route_tables.csv": ("ROUTE_TABLE", "rt_ocid", "rt_name"),
    "network_security_lists.csv": ("SECURITY_LIST", "sl_ocid", "sl_name"),
    "network_nsgs.csv": ("NETWORK_SECURITY_GROUP", "nsg_ocid", "nsg_name"),
    "network_gateways.csv": ("NETWORK_GATEWAY", "gateway_ocid", "gateway_name"),
    "network_firewalls.csv": ("NETWORK_FIREWALL", "nfw_ocid", "nfw_name"),
    "load_balancers.csv": ("LOAD_BALANCER", "lb_ocid", "lb_name"),
    "oke_clusters.csv": ("OKE_CLUSTER", "cluster_ocid", "cluster_name"),
    "oke_node_pools.csv": ("OKE_NODE_POOL", "node_pool_ocid", "node_pool_name"),
    "oke_virtual_node_pools.csv": ("OKE_VIRTUAL_NODE_POOL", "vnp_ocid", "vnp_name"),
    "container_instances.csv": ("CONTAINER_INSTANCE", "ci_ocid", "ci_name"),
    "containers.csv": ("CONTAINER", "container_ocid", "container_name"),
    "functions.csv": ("FUNCTION", "function_ocid", "function_name"),
    "db_systems.csv": ("DB_SYSTEM", "db_system_ocid", "db_system_name"),
    "db_homes.csv": ("DB_HOME", "db_home_ocid", "db_home_name"),
    "databases.csv": ("DATABASE", "database_ocid", "db_name"),
    "exadata_infrastructure.csv": ("EXADATA_INFRASTRUCTURE", "infra_ocid", "infra_name"),
    "vm_clusters.csv": ("VM_CLUSTER", "cluster_ocid", "cluster_name"),
    "autonomous_databases.csv": ("AUTONOMOUS_DATABASE", "adb_ocid", "adb_display_name"),
    "autonomous_container_databases.csv": ("AUTONOMOUS_CONTAINER_DATABASE", "acd_ocid", "acd_name"),
    "mysql_db_systems.csv": ("MYSQL_DB_SYSTEM", "mysql_ocid", "mysql_name"),
    "postgresql_db_systems.csv": ("POSTGRESQL_DB_SYSTEM", "psql_ocid", "psql_name"),
    "nosql_tables.csv": ("NOSQL_TABLE", "table_ocid", "table_name"),
    "os_managed_instances.csv": ("OS_MANAGED_INSTANCE", "managed_instance_ocid", "managed_instance_name"),
    "os_installed_packages.csv": ("OS_PACKAGE", "", "package_name"),
}

IDENTITY_FIELDS = {
    "region",
    "compartment_name",
    "compartment_ocid",
    "lifecycle_state",
    "time_created",
}

VOLATILE_FIELDS = {
    "remaining_ocpus",
    "remaining_memory_gb",
    "approximate_object_count",
    "approximate_size_bytes",
    "security_updates_available",
    "bug_updates_available",
    "other_updates_available",
    "status",
    "instance_count",
}

CI_FIELDS = [
    "ci_key", "resource_type", "resource_ocid", "resource_name", "region",
    "compartment_ocid", "compartment_name", "source_dataset",
    "configuration_hash", "attribute_count", "collection_status", "source_path",
]

ATTRIBUTE_FIELDS = [
    "attribute_key", "ci_key", "resource_type", "resource_ocid",
    "resource_name", "region", "compartment_ocid", "compartment_name",
    "attribute_name", "current_value", "source_dataset", "collected_at",
]

CI_REGISTER_FIELDS = [
    "ci_key", "resource_type", "resource_ocid", "resource_name", "region",
    "compartment_ocid", "compartment_name", "system_name", "system_owner",
    "technical_owner", "criticality", "environment",
    "configuration_baseline_id", "system_design_reference", "review_frequency",
    "registration_status", "approval_id", "approved_by", "approval_date",
    "source_reference", "notes",
]

BASELINE_FIELDS = [
    "baseline_id", "ci_key", "resource_type", "resource_ocid",
    "attribute_name", "expected_value", "comparison", "approval_status",
    "approval_id", "approval_authority", "approved_by", "approval_date",
    "effective_date", "expiration_date", "system_design_reference",
    "change_reference", "exception_id", "notes",
]

REVIEW_FIELDS = [
    "review_id", "review_period", "review_date", "reviewer", "reviewer_role",
    "scope_ocid", "baseline_id", "reconciliation_reference",
    "findings_reviewed", "changes_validated", "exceptions_reviewed",
    "corrective_actions", "review_status", "approver", "approval_date",
    "evidence_reference", "notes",
]

RECON_FIELDS = [
    "reconciliation_key", "ci_key", "resource_type", "resource_ocid",
    "resource_name", "attribute_name", "current_value", "expected_value",
    "comparison", "reconciliation_status", "baseline_id", "approval_id",
    "change_reference", "exception_id", "system_design_reference", "note",
]

FINDING_FIELDS = [
    "finding_id", "severity", "finding_type", "ci_key", "resource_type",
    "resource_ocid", "resource_name", "attribute_name", "current_value",
    "expected_value", "baseline_id", "change_reference", "exception_id",
    "required_action",
]

COVERAGE_FIELDS = [
    "raw_directory", "timestamp", "region", "compartment_ocid", "service",
    "operation", "status", "exit_code", "error_category", "label",
]

ERROR_FIELDS = ["stage", "source", "status", "category", "message"]
SOURCE_FIELDS = [
    "input_type", "path", "sha256", "row_count", "provided_by", "authority",
    "source_reference", "validation_status",
]
REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    p.add_argument("--validate-only", action="store_true")
    p.add_argument("--raw-dir", action="append", default=[])
    p.add_argument("--scope-ocid", default="")
    p.add_argument("--scope-kind", default="")
    p.add_argument("--region", default="")
    p.add_argument("--collected-at", default="")
    p.add_argument("--inventory-only", action="store_true")
    p.add_argument("--ci-register", default="")
    p.add_argument("--baseline", default="")
    p.add_argument("--monthly-review", default="")
    for name in (
        "items", "attributes", "ci-template", "baseline-template",
        "reconciliation", "review-template", "review", "sources", "coverage",
        "findings", "errors", "summary",
    ):
        p.add_argument(f"--{name}-out", default="")
    return p


def clean(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def safe_cell(value: object) -> str:
    text = clean(value).replace("\x00", "")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        rows = [{key: clean(value) for key, value in row.items()} for row in reader]
    return fields, rows


def write_csv(path: str, fields: list[str], rows: Iterable[dict[str, object]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=fields, extrasaction="ignore",
            quoting=csv.QUOTE_ALL, lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({field: safe_cell(row.get(field, "")) for field in fields})


def require_headers(path: str, required: list[str], label: str) -> list[dict[str, str]]:
    fields, rows = read_csv(Path(path))
    missing = sorted(set(required) - set(fields))
    if missing:
        raise ValueError(f"{label} missing required columns: {', '.join(missing)}")
    return rows


def validate_inputs(args: argparse.Namespace) -> None:
    if not args.ci_register or not args.baseline or not args.monthly_review:
        raise ValueError("CI register, approved baseline and monthly review are all required")
    require_headers(args.ci_register, CI_REGISTER_FIELDS, "CI register")
    require_headers(args.baseline, BASELINE_FIELDS, "approved baseline")
    require_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")


def parse_date(value: str, label: str, allow_blank: bool = False) -> date | None:
    if not value and allow_blank:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be YYYY-MM-DD") from exc


def synthetic_identity(dataset: str, row: dict[str, str]) -> str:
    if dataset == "object_storage_buckets.csv":
        identity = [row.get("region", ""), row.get("namespace", ""), row.get("bucket_name", "")]
    elif dataset == "volume_attachments.csv":
        identity = [row.get("region", ""), row.get("attachment_type", ""), row.get("instance_ocid", ""), row.get("volume_ocid", "")]
    elif dataset == "os_installed_packages.csv":
        identity = [
            row.get("region", ""), row.get("managed_instance_ocid", ""),
            row.get("package_name", ""), row.get("package_version", ""),
            row.get("package_architecture", ""),
        ]
    else:
        identity = [dataset] + [f"{key}={row.get(key, '')}" for key in sorted(row)]
    return "cm02.synthetic." + sha256_text("|".join(identity))


def normalize_inventory(
    raw_dirs: list[str], collected_at: str
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    items: list[dict[str, str]] = []
    attributes: list[dict[str, str]] = []
    coverage: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    seen_ci: dict[str, str] = {}

    for raw_name in raw_dirs:
        raw = Path(raw_name)
        console_path = raw / "collector-console.log"
        if console_path.is_file():
            console_text = console_path.read_text(encoding="utf-8", errors="replace")
            console_markers = (
                "jq: error", "compile error", "Traceback (most recent call last)",
                "write error: Broken pipe", "syntax error",
            )
            if any(marker in console_text for marker in console_markers):
                errors.append({
                    "stage": "COLLECTION", "source": str(console_path), "status": "FAILED",
                    "category": "COLLECTOR-POSTPROCESSING-ERROR",
                    "message": "collector console contains a jq/Python/shell processing error; inspect the retained private log",
                })
        raw_error_path = raw / "errors.log"
        if raw_error_path.is_file() and raw_error_path.stat().st_size:
            errors.append({
                "stage": "COLLECTION", "source": str(raw_error_path), "status": "INCOMPLETE",
                "category": "RAW-ERROR-LEDGER-NONEMPTY",
                "message": "inventory engine retained stderr or processing details; inspect and disposition the private raw error log",
            })
        status_path = raw / "collection_status.csv"
        if not status_path.is_file():
            errors.append({
                "stage": "COLLECTION", "source": str(raw), "status": "FAILED",
                "category": "MISSING-LEDGER", "message": "collection_status.csv is missing",
            })
        else:
            fields, rows = read_csv(status_path)
            write_csv(str(status_path), fields, rows)
            required = {"timestamp", "region", "compartment_ocid", "service", "operation", "status", "exit_code", "error_category", "label"}
            if not required.issubset(fields):
                errors.append({
                    "stage": "COLLECTION", "source": str(status_path), "status": "FAILED",
                    "category": "BAD-LEDGER-SCHEMA", "message": "collection ledger has unexpected columns",
                })
            for row in rows:
                coverage.append({"raw_directory": str(raw), **row})
                if row.get("status") == "FAILED":
                    errors.append({
                        "stage": "COLLECTION", "source": str(raw), "status": "FAILED",
                        "category": row.get("error_category", "UNKNOWN"),
                        "message": f"{row.get('service', '')} {row.get('operation', '')}: {row.get('label', '')}",
                    })

        for dataset, (resource_type, id_field, name_field) in DATASET_SPECS.items():
            path = raw / dataset
            if not path.is_file():
                errors.append({
                    "stage": "NORMALIZATION", "source": str(path), "status": "FAILED",
                    "category": "MISSING-DATASET", "message": f"expected dataset missing: {dataset}",
                })
                continue
            fields, rows = read_csv(path)
            # Raw collector CSVs are retained for traceability. Normalize their
            # quoting and neutralize spreadsheet formulas before publication.
            write_csv(str(path), fields, rows)
            if not fields:
                errors.append({
                    "stage": "NORMALIZATION", "source": str(path), "status": "FAILED",
                    "category": "BAD-DATASET-SCHEMA", "message": f"dataset has no CSV header: {dataset}",
                })
                continue
            if id_field and id_field not in fields:
                errors.append({
                    "stage": "NORMALIZATION", "source": str(path), "status": "FAILED",
                    "category": "BAD-DATASET-SCHEMA", "message": f"{dataset} is missing {id_field}",
                })
                continue
            for row_index, row in enumerate(rows, start=2):
                resource_ocid = clean(row.get(id_field, "")) if id_field else synthetic_identity(dataset, row)
                if not resource_ocid:
                    errors.append({
                        "stage": "NORMALIZATION", "source": f"{path}:{row_index}", "status": "FAILED",
                        "category": "MISSING-RESOURCE-IDENTITY", "message": f"{dataset} row has no stable identity",
                    })
                    continue
                region = row.get("region", "")
                ci_key = sha256_text(f"CM02|{resource_type}|{region}|{resource_ocid}")
                if ci_key in seen_ci:
                    if seen_ci[ci_key] != str(path):
                        errors.append({
                            "stage": "NORMALIZATION", "source": str(path), "status": "FAILED",
                            "category": "DUPLICATE-CI", "message": f"CI also appeared in {seen_ci[ci_key]}: {resource_ocid}",
                        })
                    continue
                seen_ci[ci_key] = str(path)
                identity_columns = set(IDENTITY_FIELDS)
                identity_columns.update({id_field, name_field})
                attr_rows: list[dict[str, str]] = []
                for field in fields:
                    if not field or field in identity_columns or field in VOLATILE_FIELDS:
                        continue
                    value = clean(row.get(field, ""))
                    attr_rows.append({
                        "attribute_key": sha256_text(f"{ci_key}|{field}"),
                        "ci_key": ci_key,
                        "resource_type": resource_type,
                        "resource_ocid": resource_ocid,
                        "resource_name": row.get(name_field, ""),
                        "region": region,
                        "compartment_ocid": row.get("compartment_ocid", ""),
                        "compartment_name": row.get("compartment_name", ""),
                        "attribute_name": field,
                        "current_value": value,
                        "source_dataset": dataset,
                        "collected_at": collected_at,
                    })
                config_hash = sha256_text(json.dumps(
                    {a["attribute_name"]: a["current_value"] for a in attr_rows},
                    sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                ))
                items.append({
                    "ci_key": ci_key,
                    "resource_type": resource_type,
                    "resource_ocid": resource_ocid,
                    "resource_name": row.get(name_field, ""),
                    "region": region,
                    "compartment_ocid": row.get("compartment_ocid", ""),
                    "compartment_name": row.get("compartment_name", ""),
                    "source_dataset": dataset,
                    "configuration_hash": config_hash,
                    "attribute_count": str(len(attr_rows)),
                    "collection_status": "OK",
                    "source_path": str(path),
                })
                attributes.extend(attr_rows)

    items.sort(key=lambda r: (r["resource_type"], r["resource_ocid"]))
    attributes.sort(key=lambda r: (r["resource_type"], r["resource_ocid"], r["attribute_name"]))
    return items, attributes, coverage, errors


def ci_template(items: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for item in items:
        result.append({
            **{field: item.get(field, "") for field in CI_REGISTER_FIELDS},
            "review_frequency": "MONTHLY",
            "registration_status": "PENDING-REVIEW",
        })
    return result


def baseline_template(attributes: list[dict[str, str]]) -> list[dict[str, str]]:
    result = []
    for attr in attributes:
        result.append({
            "baseline_id": "",
            "ci_key": attr["ci_key"],
            "resource_type": attr["resource_type"],
            "resource_ocid": attr["resource_ocid"],
            "attribute_name": attr["attribute_name"],
            "expected_value": attr["current_value"],
            "comparison": "EXACT",
            "approval_status": "PENDING-REVIEW",
            "approval_id": "",
            "approval_authority": "",
            "approved_by": "",
            "approval_date": "",
            "effective_date": "",
            "expiration_date": "",
            "system_design_reference": "",
            "change_reference": "",
            "exception_id": "",
            "notes": "Inventory value only; validate against the approved System Design Form before approval",
        })
    return result


def review_template(scope_ocid: str) -> list[dict[str, str]]:
    period = date.today().strftime("%Y-%m")
    return [{
        "review_id": "", "review_period": period, "review_date": "",
        "reviewer": "", "reviewer_role": "", "scope_ocid": scope_ocid,
        "baseline_id": "", "reconciliation_reference": "",
        "findings_reviewed": "NO", "changes_validated": "NO",
        "exceptions_reviewed": "NO", "corrective_actions": "",
        "review_status": "PENDING", "approver": "", "approval_date": "",
        "evidence_reference": "", "notes": "",
    }]


def complete_ci_registration(row: dict[str, str]) -> tuple[bool, str]:
    required = [
        "system_name", "system_owner", "technical_owner", "criticality",
        "environment", "configuration_baseline_id", "system_design_reference",
        "review_frequency", "approval_id", "approved_by", "approval_date",
        "source_reference",
    ]
    missing = [field for field in required if not row.get(field)]
    if row.get("registration_status", "").upper() != "APPROVED":
        missing.append("registration_status=APPROVED")
    if missing:
        return False, "missing/incomplete: " + ", ".join(missing)
    approved = parse_date(row["approval_date"], "CI approval_date")
    if approved and approved > date.today():
        return False, "CI approval_date cannot be in the future"
    if row.get("review_frequency", "").upper() != "MONTHLY":
        return False, "review_frequency must be MONTHLY for this worksheet workflow"
    return True, "approved CI registration"


def complete_baseline(row: dict[str, str]) -> tuple[bool, str]:
    required = [
        "baseline_id", "ci_key", "resource_type", "resource_ocid",
        "attribute_name", "comparison", "approval_id", "approval_authority",
        "approved_by", "approval_date", "effective_date",
        "system_design_reference",
    ]
    missing = [field for field in required if not row.get(field)]
    if row.get("approval_status", "").upper() != "APPROVED":
        missing.append("approval_status=APPROVED")
    if missing:
        return False, "missing/incomplete: " + ", ".join(missing)
    approval = parse_date(row["approval_date"], "baseline approval_date")
    effective = parse_date(row["effective_date"], "baseline effective_date")
    expiration = parse_date(row.get("expiration_date", ""), "baseline expiration_date", allow_blank=True)
    if approval and approval > date.today():
        return False, "approval_date cannot be in the future"
    if effective and effective > date.today():
        return False, "effective_date cannot be in the future"
    if expiration and effective and expiration < effective:
        return False, "expiration_date precedes effective_date"
    if expiration and expiration < date.today():
        return False, "baseline row is expired"
    if row["comparison"].upper() not in {"EXACT", "CASE_INSENSITIVE", "SET_EQUAL", "PRESENT", "ABSENT", "NUMERIC_EQ", "NUMERIC_MIN", "NUMERIC_MAX"}:
        return False, "unsupported comparison operator"
    return True, "approved baseline row"


def compare(current: str, expected: str, operator: str) -> bool:
    op = operator.upper()
    if op == "EXACT":
        return current == expected
    if op == "CASE_INSENSITIVE":
        return current.casefold() == expected.casefold()
    if op == "SET_EQUAL":
        left = sorted(part.strip() for part in current.split("|") if part.strip())
        right = sorted(part.strip() for part in expected.split("|") if part.strip())
        return left == right
    if op == "PRESENT":
        return bool(current)
    if op == "ABSENT":
        return not current
    try:
        left_num = float(current)
        right_num = float(expected)
    except ValueError:
        return False
    if op == "NUMERIC_EQ":
        return left_num == right_num
    if op == "NUMERIC_MIN":
        return left_num >= right_num
    if op == "NUMERIC_MAX":
        return left_num <= right_num
    return False


def finding(
    finding_type: str, severity: str, row: dict[str, str], action: str,
    current: str = "", expected: str = "", attribute: str = "",
    baseline: dict[str, str] | None = None,
) -> dict[str, str]:
    base = baseline or {}
    material = "|".join([finding_type, row.get("ci_key", ""), attribute, current, expected])
    return {
        "finding_id": "CM02-" + sha256_text(material)[:16].upper(),
        "severity": severity,
        "finding_type": finding_type,
        "ci_key": row.get("ci_key", ""),
        "resource_type": row.get("resource_type", ""),
        "resource_ocid": row.get("resource_ocid", ""),
        "resource_name": row.get("resource_name", ""),
        "attribute_name": attribute,
        "current_value": current,
        "expected_value": expected,
        "baseline_id": base.get("baseline_id", ""),
        "change_reference": base.get("change_reference", ""),
        "exception_id": base.get("exception_id", ""),
        "required_action": action,
    }


def reconcile(
    items: list[dict[str, str]], attributes: list[dict[str, str]],
    ci_rows: list[dict[str, str]], baseline_rows: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], bool]:
    findings: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []
    reconciled: list[dict[str, str]] = []
    incomplete = False

    ci_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in ci_rows:
        ci_groups[row.get("ci_key", "")].append(row)
    live_items = {row["ci_key"]: row for row in items}

    for item in items:
        candidates = ci_groups.get(item["ci_key"], [])
        if not candidates:
            findings.append(finding("CI-NOT-REGISTERED", "HIGH", item, "Register the live CI, assign owners and obtain approval"))
            incomplete = True
        elif len(candidates) != 1:
            findings.append(finding("AMBIGUOUS-CI-REGISTRATION", "HIGH", item, "Remove duplicate CI register entries"))
            incomplete = True
        else:
            candidate = candidates[0]
            try:
                complete, note = complete_ci_registration(candidate)
            except ValueError as exc:
                complete, note = False, str(exc)
            if not complete:
                findings.append(finding("CI-REGISTRATION-INCOMPLETE", "HIGH", item, note))
                incomplete = True
            if candidate.get("resource_type") != item["resource_type"] or candidate.get("resource_ocid") != item["resource_ocid"]:
                findings.append(finding("CI-IDENTITY-MISMATCH", "HIGH", item, "Correct the CI register identity fields"))
                incomplete = True

    for key, rows in ci_groups.items():
        if key and key not in live_items:
            row = rows[0]
            findings.append(finding("REGISTERED-CI-NOT-LIVE", "MEDIUM", row, "Confirm retirement, scope, collection coverage or approved removal"))

    baseline_groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in baseline_rows:
        baseline_groups[(row.get("ci_key", ""), row.get("attribute_name", ""))].append(row)
    live_attr = {(row["ci_key"], row["attribute_name"]): row for row in attributes}

    for key, attr in live_attr.items():
        candidates = baseline_groups.get(key, [])
        result = {
            "reconciliation_key": sha256_text("|".join(key)),
            "ci_key": attr["ci_key"], "resource_type": attr["resource_type"],
            "resource_ocid": attr["resource_ocid"], "resource_name": attr["resource_name"],
            "attribute_name": attr["attribute_name"], "current_value": attr["current_value"],
            "expected_value": "", "comparison": "", "reconciliation_status": "",
            "baseline_id": "", "approval_id": "", "change_reference": "",
            "exception_id": "", "system_design_reference": "", "note": "",
        }
        if not candidates:
            result.update(reconciliation_status="ATTRIBUTE-NOT-BASELINED", note="No approved baseline row matches the live attribute")
            findings.append(finding("ATTRIBUTE-NOT-BASELINED", "HIGH", attr, "Add the attribute to the approved baseline or document its exclusion", current=attr["current_value"], attribute=attr["attribute_name"]))
            incomplete = True
        elif len(candidates) != 1:
            result.update(reconciliation_status="AMBIGUOUS-BASELINE", note="Multiple baseline rows match the live attribute")
            findings.append(finding("AMBIGUOUS-BASELINE", "HIGH", attr, "Remove duplicate baseline rows", current=attr["current_value"], attribute=attr["attribute_name"]))
            incomplete = True
        else:
            base = candidates[0]
            result.update({
                "expected_value": base.get("expected_value", ""),
                "comparison": base.get("comparison", ""),
                "baseline_id": base.get("baseline_id", ""),
                "approval_id": base.get("approval_id", ""),
                "change_reference": base.get("change_reference", ""),
                "exception_id": base.get("exception_id", ""),
                "system_design_reference": base.get("system_design_reference", ""),
            })
            try:
                complete, note = complete_baseline(base)
            except ValueError as exc:
                complete, note = False, str(exc)
            if not complete:
                result.update(reconciliation_status="BASELINE-INCOMPLETE", note=note)
                findings.append(finding("BASELINE-INCOMPLETE", "HIGH", attr, note, current=attr["current_value"], expected=base.get("expected_value", ""), attribute=attr["attribute_name"], baseline=base))
                incomplete = True
            elif compare(attr["current_value"], base.get("expected_value", ""), base.get("comparison", "")):
                result.update(reconciliation_status="MATCH", note="Live configuration matches the approved baseline")
            else:
                result.update(reconciliation_status="CONFIGURATION-DRIFT", note="Live value differs from the approved baseline")
                severity = "MEDIUM" if base.get("change_reference") or base.get("exception_id") else "HIGH"
                findings.append(finding("CONFIGURATION-DRIFT", severity, attr, "Validate the change reference/exception or restore the approved configuration", current=attr["current_value"], expected=base.get("expected_value", ""), attribute=attr["attribute_name"], baseline=base))
        reconciled.append(result)

    for key, rows in baseline_groups.items():
        if key not in live_attr:
            base = rows[0]
            row = {
                "ci_key": base.get("ci_key", ""), "resource_type": base.get("resource_type", ""),
                "resource_ocid": base.get("resource_ocid", ""), "resource_name": "",
            }
            reconciled.append({
                "reconciliation_key": sha256_text("|".join(key)),
                **row, "attribute_name": base.get("attribute_name", ""),
                "current_value": "", "expected_value": base.get("expected_value", ""),
                "comparison": base.get("comparison", ""),
                "reconciliation_status": "APPROVED-ATTRIBUTE-NOT-LIVE",
                "baseline_id": base.get("baseline_id", ""), "approval_id": base.get("approval_id", ""),
                "change_reference": base.get("change_reference", ""), "exception_id": base.get("exception_id", ""),
                "system_design_reference": base.get("system_design_reference", ""),
                "note": "Approved baseline attribute is absent from the live inventory",
            })
            findings.append(finding("APPROVED-ATTRIBUTE-NOT-LIVE", "MEDIUM", row, "Confirm retirement, scope, collection coverage or approved baseline removal", expected=base.get("expected_value", ""), attribute=base.get("attribute_name", ""), baseline=base))
            incomplete = True

    return reconciled, findings, errors, incomplete


def validate_reviews(rows: list[dict[str, str]], scope_ocid: str) -> tuple[list[dict[str, str]], bool]:
    results = []
    current_period = date.today().strftime("%Y-%m")
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
        if row.get("findings_reviewed", "").upper() != "YES":
            issues.append("findings_reviewed must be YES")
        if row.get("changes_validated", "").upper() != "YES":
            issues.append("changes_validated must be YES")
        if row.get("exceptions_reviewed", "").upper() != "YES":
            issues.append("exceptions_reviewed must be YES")
        if row.get("review_status", "").upper() != "APPROVED":
            issues.append("review_status must be APPROVED")
        if row.get("scope_ocid") != scope_ocid:
            issues.append("scope_ocid does not match the approved scan scope")
        try:
            review_date = parse_date(row.get("review_date", ""), "review_date")
            approval_date = parse_date(row.get("approval_date", ""), "review approval_date")
            if review_date and review_date > date.today():
                issues.append("review_date cannot be in the future")
            if approval_date and approval_date > date.today():
                issues.append("approval_date cannot be in the future")
            if review_date and approval_date and approval_date < review_date:
                issues.append("approval_date precedes review_date")
            if review_date and row.get("review_period") != review_date.strftime("%Y-%m"):
                issues.append("review_period does not match review_date")
        except ValueError as exc:
            issues.append(str(exc))
        status = "VALID" if not issues else "INVALID"
        if row.get("review_period") == current_period:
            current_rows += 1
        if status == "VALID" and row.get("review_period") == current_period:
            valid_current += 1
        results.append({**row, "validation_status": status, "validation_message": "; ".join(issues) or "approved monthly review"})
    if current_rows != 1 or valid_current != 1:
        return results, True
    return results, False


def source_row(input_type: str, path: str, rows: list[dict[str, str]]) -> dict[str, str]:
    provided_by = ""
    authority = ""
    reference = ""
    if rows:
        if input_type == "CI-REGISTER":
            provided_by, authority, reference = rows[0].get("approved_by", ""), rows[0].get("system_owner", ""), rows[0].get("source_reference", "")
        elif input_type == "APPROVED-BASELINE":
            provided_by, authority, reference = rows[0].get("approved_by", ""), rows[0].get("approval_authority", ""), rows[0].get("system_design_reference", "")
        else:
            provided_by, authority, reference = rows[0].get("reviewer", ""), rows[0].get("approver", ""), rows[0].get("evidence_reference", "")
    return {
        "input_type": input_type, "path": path, "sha256": sha256_file(Path(path)),
        "row_count": str(len(rows)), "provided_by": provided_by, "authority": authority,
        "source_reference": reference, "validation_status": "PROVIDED",
    }


def main() -> int:
    args = parser().parse_args()
    try:
        if args.validate_only:
            validate_inputs(args)
            print("CM02-01 input headers validated.")
            return 0
        required_outputs = [
            args.items_out, args.attributes_out, args.ci_template_out,
            args.baseline_template_out, args.reconciliation_out,
            args.review_template_out, args.review_out, args.sources_out,
            args.coverage_out, args.findings_out, args.errors_out, args.summary_out,
        ]
        if not args.raw_dir or not all(required_outputs):
            raise ValueError("raw directories and every output path are required")
        if not args.inventory_only:
            validate_inputs(args)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    items, attributes, coverage, errors = normalize_inventory(args.raw_dir, args.collected_at)
    ci_rows: list[dict[str, str]] = []
    baseline_rows: list[dict[str, str]] = []
    review_rows: list[dict[str, str]] = []
    reconciled: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    review_results: list[dict[str, str]] = []
    sources: list[dict[str, str]] = []
    incomplete = bool(errors)

    if args.inventory_only:
        sources = [
            {"input_type": kind, "path": "", "sha256": "", "row_count": "0", "provided_by": "", "authority": "", "source_reference": "", "validation_status": "SKIPPED-INVENTORY-ONLY"}
            for kind in ("CI-REGISTER", "APPROVED-BASELINE", "MONTHLY-REVIEW")
        ]
    else:
        try:
            ci_rows = require_headers(args.ci_register, CI_REGISTER_FIELDS, "CI register")
            baseline_rows = require_headers(args.baseline, BASELINE_FIELDS, "approved baseline")
            review_rows = require_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")
            sources = [
                source_row("CI-REGISTER", args.ci_register, ci_rows),
                source_row("APPROVED-BASELINE", args.baseline, baseline_rows),
                source_row("MONTHLY-REVIEW", args.monthly_review, review_rows),
            ]
            reconciled, new_findings, new_errors, recon_incomplete = reconcile(items, attributes, ci_rows, baseline_rows)
            findings.extend(new_findings)
            errors.extend(new_errors)
            incomplete = incomplete or recon_incomplete
            review_results, review_incomplete = validate_reviews(review_rows, args.scope_ocid)
            incomplete = incomplete or review_incomplete
            if review_incomplete:
                errors.append({
                    "stage": "MONTHLY-REVIEW", "source": args.monthly_review,
                    "status": "INCOMPLETE", "category": "NO-VALID-CURRENT-REVIEW",
                    "message": "exactly one valid approved review is required for the current YYYY-MM period",
                })
        except (OSError, ValueError) as exc:
            errors.append({
                "stage": "RECONCILIATION", "source": "control inputs", "status": "FAILED",
                "category": "INPUT-VALIDATION", "message": str(exc),
            })
            incomplete = True

    write_csv(args.items_out, CI_FIELDS, items)
    write_csv(args.attributes_out, ATTRIBUTE_FIELDS, attributes)
    write_csv(args.ci_template_out, CI_REGISTER_FIELDS, ci_template(items))
    write_csv(args.baseline_template_out, BASELINE_FIELDS, baseline_template(attributes))
    write_csv(args.reconciliation_out, RECON_FIELDS, reconciled)
    write_csv(args.review_template_out, REVIEW_FIELDS, review_template(args.scope_ocid))
    write_csv(args.review_out, REVIEW_RESULT_FIELDS, review_results)
    write_csv(args.sources_out, SOURCE_FIELDS, sources)
    write_csv(args.coverage_out, COVERAGE_FIELDS, coverage)
    write_csv(args.findings_out, FINDING_FIELDS, findings)
    if errors:
        write_csv(args.errors_out, ERROR_FIELDS, errors)

    coverage_counts = Counter(row.get("status", "UNKNOWN") for row in coverage)
    recon_counts = Counter(row.get("reconciliation_status", "UNKNOWN") for row in reconciled)
    finding_counts = Counter(row.get("severity", "UNKNOWN") for row in findings)
    with Path(args.summary_out).open("w", encoding="utf-8") as handle:
        if args.inventory_only:
            handle.write("CM02-01 Technical Configuration Snapshot Summary\n")
            handle.write("================================================\n")
        else:
            handle.write("CM02-01 Configuration Baseline Summary\n")
            handle.write("======================================\n")
        handle.write(f"Scope kind             : {args.scope_kind}\n")
        handle.write(f"Scope OCID             : {args.scope_ocid}\n")
        handle.write(f"Region                 : {args.region}\n")
        handle.write(f"Collected              : {args.collected_at}\n")
        handle.write(f"Mode                   : {'SIMPLE-TECHNICAL-COLLECTION' if args.inventory_only else 'COMPLETE-RECONCILIATION'}\n")
        handle.write(f"Configuration items    : {len(items)}\n")
        handle.write(f"Configuration attributes: {len(attributes)}\n")
        handle.write(f"Coverage rows          : {len(coverage)}\n")
        handle.write(f"Coverage OK            : {coverage_counts['OK']}\n")
        handle.write(f"Coverage EMPTY         : {coverage_counts['EMPTY']}\n")
        handle.write(f"Coverage FAILED        : {coverage_counts['FAILED']}\n")
        handle.write(f"Evidence errors/gaps   : {len(errors)}\n")
        if args.inventory_only:
            handle.write(f"COLLECTION STATUS      : {'INCOMPLETE' if incomplete else 'COMPLETE'}\n")
            handle.write("\nThis package is a technical configuration snapshot.\n")
        else:
            handle.write(f"Baseline matches       : {recon_counts['MATCH']}\n")
            handle.write(f"Configuration drift    : {recon_counts['CONFIGURATION-DRIFT']}\n")
            handle.write(f"Not baselined          : {recon_counts['ATTRIBUTE-NOT-BASELINED']}\n")
            handle.write(f"Findings HIGH          : {finding_counts['HIGH']}\n")
            handle.write(f"Findings MEDIUM        : {finding_counts['MEDIUM']}\n")
            handle.write(f"EVIDENCE STATUS        : {'INCOMPLETE' if incomplete else 'COMPLETE-FOR-REVIEW'}\n")

    return 3 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
