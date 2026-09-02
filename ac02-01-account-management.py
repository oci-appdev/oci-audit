#!/usr/bin/env python3
"""AC-2 account-management evidence using Oracle's OCI Python SDK."""

from __future__ import annotations

import argparse
import ast
import csv
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

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
    sdk_scim_list,
    sha256_file,
    stable_hash,
    utc_now,
    write_csv,
    write_private_text,
)


VERSION = "1.0.0"
COLLECTOR = "AC02-01"
CONTROLS = "AC-2 / AC-2(1) / AC-2(3) / AC-2(4) / AC-2(7) / AC-6 / IA-2"

CLASSIC_METHODS: Set[str] = {
    "get_authentication_policy", "get_compartment", "list_api_keys",
    "list_auth_tokens", "list_compartments", "list_customer_secret_keys",
    "list_db_credentials", "list_domains", "list_dynamic_groups", "list_groups",
    "list_network_sources", "list_o_auth_client_credentials", "list_policies",
    "list_smtp_credentials", "list_user_group_memberships", "list_users",
}
SCIM_METHODS: Set[str] = {"list_groups", "list_users"}
SDK_READ_METHODS = CLASSIC_METHODS | SCIM_METHODS

DOMAIN_FIELDS = [
    "domain_ocid", "display_name", "compartment_ocid", "domain_type",
    "license_type", "home_region", "lifecycle_state", "time_created",
    "domain_url_host", "collection_status", "request_id", "message",
]
ACCOUNT_FIELDS = [
    "account_key", "source_system", "domain_ocid", "account_id", "account_ocid",
    "account_name", "display_name", "directory_user_type", "lifecycle_state",
    "is_federated", "mfa_status", "last_successful_login", "time_created",
    "time_modified", "directory_manager_id", "directory_manager_name",
    "can_use_console_password", "can_use_api_keys", "can_use_auth_tokens",
    "can_use_smtp_credentials", "can_use_db_credentials",
    "can_use_customer_secret_keys", "can_use_oauth2_client_credentials",
    "group_count", "credential_count",
]
GROUP_FIELDS = [
    "group_key", "source_system", "domain_ocid", "domain_name", "group_id", "group_ocid",
    "group_name", "group_type", "lifecycle_state", "time_created",
    "time_modified", "matching_rule",
]
MEMBERSHIP_FIELDS = [
    "access_key", "source_system", "domain_ocid", "membership_id",
    "account_key", "account_id", "account_name", "group_key", "group_id",
    "group_name", "membership_type", "lifecycle_state", "time_created",
    "privilege_keys",
]
CREDENTIAL_FIELDS = [
    "credential_key", "account_key", "account_id", "account_name",
    "credential_type", "credential_id_or_fingerprint", "lifecycle_state",
    "time_created", "time_expires", "description",
]
POLICY_FIELDS = [
    "policy_statement_key", "policy_id", "policy_name", "attachment_compartment_name",
    "attachment_compartment_ocid", "statement_index", "lifecycle_state",
    "policy_version_date", "statement",
]
PRIVILEGE_FIELDS = [
    "privilege_key", "source_system", "policy_id", "policy_name",
    "attachment_compartment_name", "attachment_compartment_ocid", "statement_index",
    "principal_kind", "principal_reference", "group_key", "group_name",
    "verb", "resource_family", "scope_clause", "condition_present",
    "candidate_level", "mapping_status", "statement",
]
AUTH_POLICY_FIELDS = [
    "tenancy_ocid", "minimum_password_length", "uppercase_required",
    "lowercase_required", "numeric_required", "special_required",
    "username_containment_allowed", "network_source_ids", "collection_status",
    "request_id", "message",
]
NETWORK_SOURCE_FIELDS = [
    "network_source_id", "name", "description", "public_source_count",
    "virtual_source_count", "lifecycle_state", "time_created",
]
COVERAGE_FIELDS = [
    "scope_name", "scope_ocid", "source_system", "operation", "subject_id",
    "status", "item_count", "page_count", "request_id", "message",
]
ERROR_FIELDS = [
    "scope_name", "scope_ocid", "source_system", "operation", "subject_id",
    "http_status", "service_code", "request_id", "message",
]
GAP_FIELDS = ["gap_key", "source", "status", "required_evidence", "message"]

ACCOUNT_REGISTER_FIELDS = [
    "account_key", "account_name", "account_type", "system_name", "manager",
    "account_owner", "employment_status", "expected_lifecycle_state",
    "request_reference", "approval_status", "approver", "approval_date",
    "last_authoritative_activity", "inactivity_exception_reference",
    "exception_approver", "exception_expiration", "exception_evidence_reference",
    "deactivation_due_date", "authoritative_source", "evidence_reference",
]
ACCESS_APPROVAL_FIELDS = [
    "access_key", "account_key", "account_name", "group_key", "group_name",
    "reviewed_privilege_keys", "access_decision", "manager", "approver",
    "approval_status", "approval_date", "request_reference", "expiration_date",
    "authority", "evidence_reference",
]
PRIVILEGE_REVIEW_FIELDS = [
    "privilege_key", "policy_id", "group_key", "principal_reference",
    "privilege_decision", "privilege_owner", "approver", "approval_status",
    "approval_date", "request_reference", "expiration_date",
    "least_privilege_rationale", "authority", "evidence_reference",
]
INACTIVITY_POLICY_FIELDS = [
    "account_type", "max_inactive_days", "unknown_activity_action",
    "removal_sla_days", "policy_owner", "authority", "effective_date",
    "approval_status", "approver", "evidence_reference",
]
LIFECYCLE_FIELDS = [
    "procedure_id", "process_owner", "request_process_reference",
    "modification_process_reference", "deactivation_process_reference",
    "authoritative_hr_source", "joiner_sla_days", "mover_sla_days",
    "leaver_sla_days", "unused_account_review_frequency",
    "privileged_review_frequency", "service_account_review_frequency",
    "review_template_reference", "approval_status", "approver", "approval_date",
    "evidence_reference",
]
ACCOUNT_RECON_FIELDS = ACCOUNT_FIELDS + [
    "account_type", "manager", "account_owner", "request_reference", "approver",
    "approval_status", "effective_last_activity", "inactive_days",
    "inactivity_threshold_days", "inactivity_status", "deactivation_due_date",
    "reconciliation_status", "validation_message",
]
ACCESS_RECON_FIELDS = MEMBERSHIP_FIELDS + [
    "access_decision", "manager", "approver", "approval_status",
    "request_reference", "expiration_date", "reconciliation_status",
    "validation_message",
]
PRIVILEGE_RECON_FIELDS = PRIVILEGE_FIELDS + [
    "privilege_decision", "privilege_owner", "approver", "approval_status",
    "request_reference", "expiration_date", "reconciliation_status",
    "validation_message",
]
INPUT_SOURCE_FIELDS = ["input_type", "path", "sha256", "row_count"]
INPUT_VALIDATION_FIELDS = [
    "input_type", "row_key", "validation_status", "validation_message"
]
REVIEW_FIELDS = [
    "snapshot_sha256", "review_period", "account_count", "active_account_count",
    "group_count", "membership_count", "credential_count",
    "privilege_candidate_count", "unregistered_count", "account_drift_count",
    "inactive_candidate_count", "unknown_activity_count",
    "access_approval_gap_count", "access_removal_open_count",
    "privilege_review_gap_count", "privilege_removal_open_count",
    "manual_gap_count", "reviewer", "review_date", "compliance_result",
    "corrective_action_reference", "approval_status", "approver",
    "evidence_reference", "notes",
]
REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]

ACCOUNT_TYPES = {"HUMAN", "SERVICE", "BREAK-GLASS", "FEDERATED", "GENERIC"}
UNKNOWN_ACTIONS = {"INVESTIGATE", "DISABLE", "DOCUMENT-EXCEPTION"}
ACCESS_DECISIONS = {"KEEP", "REMOVE"}
PRIVILEGE_DECISIONS = {"KEEP", "REMOVE"}
ALLOW_RE = re.compile(
    r"^\s*allow\s+(group|dynamic-group)\s+(.+?)\s+to\s+"
    r"(inspect|read|use|manage)\s+(.+?)\s+in\s+(.+?)(?:\s+where\b|$)",
    re.IGNORECASE,
)
ANY_USER_RE = re.compile(
    r"^\s*allow\s+any-user\s+to\s+(inspect|read|use|manage)\s+(.+?)\s+in\s+"
    r"(.+?)(?:\s+where\b|$)", re.IGNORECASE,
)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI account, group, privilege and credential-metadata evidence."
    )
    p.add_argument("-r", "--region")
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
    p.add_argument("--account-register")
    p.add_argument("--access-approvals")
    p.add_argument("--privilege-review")
    p.add_argument("--inactivity-policy")
    p.add_argument("--lifecycle-procedure")
    p.add_argument("--monthly-review")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def source_selfcheck() -> bool:
    if any(not name.startswith(("list_", "get_")) for name in SDK_READ_METHODS):
        print("READ-ONLY SDK SELF-CHECK: FAILED — invalid allowlist", file=sys.stderr)
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    problems: List[str] = []
    guarded = {"classic_list": "list_", "classic_get": "get_", "scim_list": "list_"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in guarded or len(node.args) < 3:
            continue
        method_node = node.args[2]
        if not isinstance(method_node, ast.Constant) or not isinstance(method_node.value, str):
            problems.append(f"line {node.lineno}: guarded SDK method is not a literal")
            continue
        method = method_node.value
        if method not in SDK_READ_METHODS or not method.startswith(guarded[node.func.id]):
            problems.append(f"line {node.lineno}: blocked SDK method {method}")
    forbidden = (
        "create_", "update_", "delete_", "change_", "move_", "upload_",
        "import_", "export_", "patch_", "put_", "remove_",
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")
    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (ac02-01-account-management)")
    print("Generated OCI clients are restricted to allowlisted list/get operations.")
    print("Credential values, passwords, private keys, MFA seeds and recovery data are never exported.")
    return True


def required_headers(path: str, fields: Sequence[str], label: str) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [field for field in fields if field not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"{label} is missing columns: {', '.join(missing)}")
            return [
                {key: (value or "").strip() for key, value in row.items()}
                for row in reader if any((value or "").strip() for value in row.values())
            ]
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}: {exc}") from exc


def parse_time(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {label}: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def names_filter(value: str) -> Set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def pipe_values(value: str) -> Set[str]:
    return {item.strip() for item in value.split("|") if item.strip() and item.strip() != "NONE"}


def text(item: Any, name: str) -> str:
    value = getattr(item, name, "")
    return "" if value is None else str(value)


def bool_text(value: Any) -> str:
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "UNKNOWN"


def object_time(item: Any, *names: str) -> str:
    for name in names:
        value = getattr(item, name, None)
        if value is not None:
            return iso(value)
    return ""


def resolve_targets(
    args: argparse.Namespace, catalog: Sequence[ScopeItem]
) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit_modes = sum(bool(value) for value in (
        args.compartment_id, args.compartment_names, args.tenancy_scope,
    ))
    if explicit_modes > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")
    if args.select_scope and explicit_modes:
        raise ValueError("interactive selection cannot be combined with explicit scope")
    if not explicit_modes:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}\n              {item.ocid}")
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
            targets[0].ocid if len(targets) == 1 else "MULTIPLE",
            targets[0].name if len(targets) == 1 else "explicit compartments",
            "COMPARTMENT" if len(targets) == 1 else "MULTI-COMPARTMENT",
        )
    else:
        wanted = names_filter(args.compartment_names)
        targets = [
            item for item in catalog
            if item.kind == "COMPARTMENT" and item.name.lower() in wanted
        ]
        missing = sorted(wanted - {item.name.lower() for item in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = ScopeItem(
            targets[0].ocid if len(targets) == 1 else "MULTIPLE",
            targets[0].name if len(targets) == 1 else args.compartment_names,
            "COMPARTMENT" if len(targets) == 1 else "MULTI-COMPARTMENT",
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
        " AC-2 ACCOUNT MANAGEMENT PRE-SCAN SAFETY SUMMARY",
        "======================================================================",
        f"Collector       : {COLLECTOR}", f"Controls        : {CONTROLS}",
        f"Region          : {args.region}", f"Authentication  : {context.auth_label}",
        f"Profile         : {context.profile if args.auth == 'config' else '<not applicable>'}",
        f"Scope type      : {selected.kind}", f"Scope name      : {selected.name}",
        f"Selected OCID   : {selected.ocid}", f"Targets         : {len(targets)}",
        "Identity scope  : tenancy IAM directory plus every active OCI Identity Domain",
        "Policy scope    : tenancy/all compartments for tenancy scans; root/ancestors/targets otherwise",
        "Cloud operations: Oracle OCI Python SDK generated list/get methods only",
        "Volume warning  : classic IAM performs up to 7 metadata list calls per user; Identity Domains are paginated",
        "Mutation boundary: no create/update/delete/change/patch/put methods are permitted",
        "Credential limit: metadata only; no token, password, key value, MFA seed or recovery data",
        "Decision boundary: policy statements are privilege candidates, not effective-access decisions",
        "Sensitive data  : identity names, OCIDs, groups, credentials metadata and approvals",
        "Local files     : private mode 0600, formula-safe and never overwritten",
        "", "Confirmed workload targets:",
    ]
    for item in targets:
        lines.extend([f"  - {item.name}", f"    {item.ocid}"])
    lines.extend(["", "Read-only SDK operations:"])
    for method in sorted(SDK_READ_METHODS):
        lines.append("  - " + method)
    lines.extend(["", "Governance inputs:"])
    for label, path in (
        ("Account register", args.account_register),
        ("Group-access approvals", args.access_approvals),
        ("Privilege review", args.privilege_review),
        ("Inactivity policy", args.inactivity_policy),
        ("Lifecycle procedure", args.lifecycle_procedure),
        ("Monthly review", args.monthly_review),
    ):
        lines.append(f"  - {label}: {path or '<not supplied; template generation>'}")
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


def domain_endpoint(url: str) -> Tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Identity Domain returned an invalid HTTPS service endpoint")
    if parsed.query or parsed.fragment:
        raise ValueError("Identity Domain endpoint contains an unexpected query or fragment")
    endpoint = f"https://{parsed.netloc}{parsed.path.rstrip('/')}"
    return endpoint, parsed.hostname


def account_key(source: str, domain_id: str, native_id: str, ocid: str = "") -> str:
    if ocid.startswith("ocid1.user."):
        return "OCI:" + ocid
    if source == "OCI-CLASSIC" and native_id.startswith("ocid1.user."):
        return "OCI:" + native_id
    return "IDENTITY-DOMAIN:" + domain_id + ":" + native_id


def group_key(source: str, domain_id: str, native_id: str, ocid: str = "") -> str:
    if ocid.startswith("ocid1.group.") or ocid.startswith("ocid1.dynamicgroup."):
        return "OCI-GROUP:" + ocid
    if source == "OCI-CLASSIC" and native_id.startswith(("ocid1.group.", "ocid1.dynamicgroup.")):
        return "OCI-GROUP:" + native_id
    return "IDENTITY-DOMAIN-GROUP:" + domain_id + ":" + native_id


def credential_key(account: str, kind: str, identifier: str) -> str:
    return stable_hash([account, kind, identifier])


def add_coverage(
    rows: List[Dict[str, Any]], scope: ScopeItem, source: str, operation: str,
    status: str, count: int, response: Any = None, subject_id: str = "",
    pages: int = 1, message: str = "",
) -> None:
    rows.append({
        "scope_name": scope.name, "scope_ocid": scope.ocid,
        "source_system": source, "operation": operation, "subject_id": subject_id,
        "status": status, "item_count": count, "page_count": pages,
        "request_id": request_id(response) if response is not None else "",
        "message": message,
    })


def add_error(
    errors: List[Dict[str, Any]], coverage: List[Dict[str, Any]], scope: ScopeItem,
    source: str, operation: str, exc: Exception, subject_id: str = "",
) -> None:
    detail = error_record(exc)
    add_coverage(
        coverage, scope, source, operation, "FAILED", 0, subject_id=subject_id,
        pages=0, message=detail["message"],
    )
    errors.append({
        "scope_name": scope.name, "scope_ocid": scope.ocid,
        "source_system": source, "operation": operation, "subject_id": subject_id,
        **detail,
    })


def classic_list(
    oci: Any, client: Any, method: str, scope: ScopeItem,
    coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], *args: Any,
    subject_id: str = "", **kwargs: Any,
) -> List[Any]:
    try:
        items, response = sdk_list(oci, client, method, CLASSIC_METHODS, *args, **kwargs)
        data = getattr(response, "data", None)
        if not isinstance(data, list):
            raise ValueError(f"{method} returned an unexpected response shape")
        add_coverage(
            coverage, scope, "OCI-CLASSIC", method, "OK" if items else "EMPTY",
            len(items), response, subject_id,
        )
        return items
    except Exception as exc:
        add_error(errors, coverage, scope, "OCI-CLASSIC", method, exc, subject_id)
        return []


def classic_get(
    oci: Any, client: Any, method: str, scope: ScopeItem,
    coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], *args: Any,
    subject_id: str = "", **kwargs: Any,
) -> Any:
    try:
        response = sdk_get(oci, client, method, CLASSIC_METHODS, *args, **kwargs)
        if getattr(response, "data", None) is None:
            raise ValueError(f"{method} returned an empty response object")
        add_coverage(
            coverage, scope, "OCI-CLASSIC", method, "OK", 1, response,
            subject_id=subject_id,
        )
        return response
    except Exception as exc:
        add_error(errors, coverage, scope, "OCI-CLASSIC", method, exc, subject_id)
        return None


def scim_list(
    oci: Any, client: Any, method: str, scope: ScopeItem,
    coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], **kwargs: Any,
) -> List[Any]:
    try:
        items, responses = sdk_scim_list(
            oci, client, method, SCIM_METHODS, count=1000, **kwargs
        )
        add_coverage(
            coverage, scope, "OCI-IDENTITY-DOMAIN", method,
            "OK" if items else "EMPTY", len(items), responses[-1] if responses else None,
            pages=len(responses),
        )
        return items
    except Exception as exc:
        add_error(errors, coverage, scope, "OCI-IDENTITY-DOMAIN", method, exc)
        return []


def merge_account(rows: Dict[str, Dict[str, Any]], row: Dict[str, Any]) -> None:
    key = str(row["account_key"])
    if key not in rows:
        rows[key] = row
        return
    current = rows[key]
    sources = set(str(current.get("source_system", "")).split("+"))
    sources.update(str(row.get("source_system", "")).split("+"))
    current["source_system"] = "+".join(sorted(source for source in sources if source))
    for field, value in row.items():
        if field in {"account_key", "source_system"}:
            continue
        if value not in {"", "UNKNOWN", None}:
            current[field] = value


def merge_group(rows: Dict[str, Dict[str, Any]], row: Dict[str, Any]) -> None:
    key = str(row["group_key"])
    if key not in rows:
        rows[key] = row
        return
    current = rows[key]
    sources = set(str(current.get("source_system", "")).split("+"))
    sources.update(str(row.get("source_system", "")).split("+"))
    current["source_system"] = "+".join(sorted(source for source in sources if source))
    for field, value in row.items():
        if field in {"group_key", "source_system"}:
            continue
        if value not in {"", None}:
            current[field] = value


def classic_account_row(user: Any) -> Dict[str, Any]:
    user_id = text(user, "id")
    caps = getattr(user, "capabilities", None)
    return {
        "account_key": account_key("OCI-CLASSIC", "", user_id, user_id),
        "source_system": "OCI-CLASSIC", "domain_ocid": "",
        "account_id": user_id, "account_ocid": user_id,
        "account_name": text(user, "name"), "display_name": text(user, "name"),
        "directory_user_type": "", "lifecycle_state": text(user, "lifecycle_state"),
        "is_federated": bool_text(bool(text(user, "identity_provider_id"))),
        "mfa_status": "ENROLLED" if getattr(user, "is_mfa_activated", None) is True else (
            "NOT-ENROLLED" if getattr(user, "is_mfa_activated", None) is False else "UNKNOWN"
        ),
        "last_successful_login": iso(getattr(user, "last_successful_login_time", None)),
        "time_created": iso(getattr(user, "time_created", None)), "time_modified": "",
        "directory_manager_id": "", "directory_manager_name": "",
        "can_use_console_password": bool_text(getattr(caps, "can_use_console_password", None)),
        "can_use_api_keys": bool_text(getattr(caps, "can_use_api_keys", None)),
        "can_use_auth_tokens": bool_text(getattr(caps, "can_use_auth_tokens", None)),
        "can_use_smtp_credentials": bool_text(getattr(caps, "can_use_smtp_credentials", None)),
        "can_use_db_credentials": bool_text(getattr(caps, "can_use_db_credentials", None)),
        "can_use_customer_secret_keys": bool_text(getattr(caps, "can_use_customer_secret_keys", None)),
        "can_use_oauth2_client_credentials": bool_text(
            getattr(caps, "can_use_o_auth2_client_credentials", None)
        ),
        "group_count": 0, "credential_count": 0,
    }


def domain_account_row(domain: Any, user: Any) -> Dict[str, Any]:
    domain_id = text(domain, "id")
    user_id = text(user, "id")
    user_ocid = text(user, "ocid")
    meta = getattr(user, "meta", None)
    state = getattr(
        user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user", None
    )
    extension = getattr(
        user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user", None
    )
    mfa = getattr(user, "urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user", None)
    enterprise = getattr(
        user, "urn_ietf_params_scim_schemas_extension_enterprise2_0_user", None
    )
    manager = getattr(enterprise, "manager", None)
    active = getattr(user, "active", None)
    return {
        "account_key": account_key("OCI-IDENTITY-DOMAIN", domain_id, user_id, user_ocid),
        "source_system": "OCI-IDENTITY-DOMAIN", "domain_ocid": domain_id,
        "account_id": user_id, "account_ocid": user_ocid,
        "account_name": text(user, "user_name"), "display_name": text(user, "display_name"),
        "directory_user_type": text(user, "user_type"),
        "lifecycle_state": "ACTIVE" if active is True else (
            "INACTIVE" if active is False else "UNKNOWN"
        ),
        "is_federated": bool_text(getattr(extension, "is_federated_user", None)),
        "mfa_status": text(mfa, "mfa_status") or "UNKNOWN",
        "last_successful_login": text(state, "last_successful_login_date"),
        "time_created": text(meta, "created"), "time_modified": text(meta, "last_modified"),
        "directory_manager_id": text(manager, "value"),
        "directory_manager_name": text(manager, "display_name") or text(manager, "display"),
        "can_use_console_password": "UNKNOWN", "can_use_api_keys": "UNKNOWN",
        "can_use_auth_tokens": "UNKNOWN", "can_use_smtp_credentials": "UNKNOWN",
        "can_use_db_credentials": "UNKNOWN", "can_use_customer_secret_keys": "UNKNOWN",
        "can_use_oauth2_client_credentials": "UNKNOWN",
        "group_count": 0, "credential_count": 0,
    }


def classic_group_row(group: Any, kind: str = "CLASSIC") -> Dict[str, Any]:
    group_id = text(group, "id")
    return {
        "group_key": group_key("OCI-CLASSIC", "", group_id, group_id),
        "source_system": "OCI-CLASSIC", "domain_ocid": "", "domain_name": "",
        "group_id": group_id, "group_ocid": group_id,
        "group_name": text(group, "name"), "group_type": kind,
        "lifecycle_state": text(group, "lifecycle_state"),
        "time_created": iso(getattr(group, "time_created", None)), "time_modified": "",
        "matching_rule": text(group, "matching_rule") if kind == "DYNAMIC" else "",
    }


def domain_group_row(domain: Any, group: Any) -> Dict[str, Any]:
    domain_id = text(domain, "id")
    group_id = text(group, "id")
    group_ocid = text(group, "ocid")
    meta = getattr(group, "meta", None)
    return {
        "group_key": group_key("OCI-IDENTITY-DOMAIN", domain_id, group_id, group_ocid),
        "source_system": "OCI-IDENTITY-DOMAIN", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"),
        "group_id": group_id, "group_ocid": group_ocid,
        "group_name": text(group, "display_name"), "group_type": "IDENTITY-DOMAIN",
        "lifecycle_state": "ACTIVE",
        "time_created": text(meta, "created"), "time_modified": text(meta, "last_modified"),
        "matching_rule": "",
    }


def credential_identifier(kind: str, item: Any) -> str:
    if kind == "API-KEY":
        return text(item, "fingerprint")
    return text(item, "id")


def collect_classic_credentials(
    oci: Any, identity: Any, root: ScopeItem, user: Any, account: str,
    coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    caps = getattr(user, "capabilities", None)
    operations = (
        ("API-KEY", "list_api_keys", "can_use_api_keys"),
        ("AUTH-TOKEN", "list_auth_tokens", "can_use_auth_tokens"),
        ("CUSTOMER-SECRET-KEY", "list_customer_secret_keys", "can_use_customer_secret_keys"),
        ("DB-CREDENTIAL", "list_db_credentials", "can_use_db_credentials"),
        ("OAUTH2-CLIENT-CREDENTIAL", "list_o_auth_client_credentials", "can_use_o_auth2_client_credentials"),
        ("SMTP-CREDENTIAL", "list_smtp_credentials", "can_use_smtp_credentials"),
    )
    rows: List[Dict[str, Any]] = []
    user_id = text(user, "id")
    user_name = text(user, "name")
    disabled = {
        method for _, method, capability in operations
        if getattr(caps, capability, None) is False
    }
    for _, method, _ in operations:
        if method in disabled:
            add_coverage(
                coverage, root, "OCI-CLASSIC", method, "SKIPPED-CAPABILITY-DISABLED",
                0, subject_id=user_id, pages=0,
            )
    collected: List[Tuple[str, str, List[Any]]] = []
    if "list_api_keys" not in disabled:
        collected.append(("API-KEY", "list_api_keys", classic_list(
            oci, identity, "list_api_keys", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    if "list_auth_tokens" not in disabled:
        collected.append(("AUTH-TOKEN", "list_auth_tokens", classic_list(
            oci, identity, "list_auth_tokens", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    if "list_customer_secret_keys" not in disabled:
        collected.append(("CUSTOMER-SECRET-KEY", "list_customer_secret_keys", classic_list(
            oci, identity, "list_customer_secret_keys", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    if "list_db_credentials" not in disabled:
        collected.append(("DB-CREDENTIAL", "list_db_credentials", classic_list(
            oci, identity, "list_db_credentials", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    if "list_o_auth_client_credentials" not in disabled:
        collected.append(("OAUTH2-CLIENT-CREDENTIAL", "list_o_auth_client_credentials", classic_list(
            oci, identity, "list_o_auth_client_credentials", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    if "list_smtp_credentials" not in disabled:
        collected.append(("SMTP-CREDENTIAL", "list_smtp_credentials", classic_list(
            oci, identity, "list_smtp_credentials", root, coverage, errors,
            user_id, subject_id=user_id,
        )))
    for kind, method, items in collected:
        for item in items:
            identifier = credential_identifier(kind, item)
            if not identifier:
                add_error(
                    errors, coverage, root, "OCI-CLASSIC", method,
                    ValueError(f"{method} returned a credential without a stable identifier"),
                    user_id,
                )
                continue
            rows.append({
                "credential_key": credential_key(account, kind, identifier),
                "account_key": account, "account_id": user_id,
                "account_name": user_name, "credential_type": kind,
                "credential_id_or_fingerprint": identifier,
                "lifecycle_state": text(item, "lifecycle_state"),
                "time_created": object_time(item, "time_created"),
                "time_expires": object_time(item, "time_expires"),
                "description": text(item, "description"),
            })
    return rows


def policy_scope_items(
    oci: Any, identity: Any, context: Any, selected: ScopeItem,
    targets: Sequence[ScopeItem], catalog: Sequence[ScopeItem],
    coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]],
) -> List[ScopeItem]:
    if selected.kind == "TENANCY":
        return list(targets)
    by_id = {item.ocid: item for item in catalog}
    root = catalog[0]
    resolved: Dict[str, ScopeItem] = {root.ocid: root}
    for target in targets:
        current = target
        seen: Set[str] = set()
        while current.ocid != context.tenancy_id:
            if current.ocid in seen:
                add_error(
                    errors, coverage, current, "OCI-CLASSIC", "get_compartment",
                    ValueError("compartment ancestry contained a cycle"), current.ocid,
                )
                break
            seen.add(current.ocid)
            resolved[current.ocid] = current
            response = classic_get(
                oci, identity, "get_compartment", current, coverage, errors,
                current.ocid, subject_id=current.ocid,
            )
            if response is None:
                break
            data = response.data
            parent_id = text(data, "compartment_id")
            if not parent_id:
                add_error(
                    errors, coverage, current, "OCI-CLASSIC", "get_compartment",
                    ValueError("compartment response omitted parent compartment OCID"),
                    current.ocid,
                )
                break
            if parent_id == context.tenancy_id:
                resolved[root.ocid] = root
                break
            known = by_id.get(parent_id)
            current = known or ScopeItem(parent_id, parent_id, "COMPARTMENT")
    return sorted(resolved.values(), key=lambda row: (row.kind != "TENANCY", row.name.lower(), row.ocid))


def split_principals(value: str) -> List[str]:
    return [part.strip() for part in re.split(r"\s*,\s*(?:group\s+)?", value) if part.strip()]


def group_indexes(groups: Sequence[Mapping[str, Any]]) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
    plain: Dict[str, Set[str]] = defaultdict(set)
    qualified: Dict[str, Set[str]] = defaultdict(set)
    for group in groups:
        name = str(group.get("group_name", "")).strip().lower()
        if name:
            plain[name].add(str(group["group_key"]))
        domain = str(group.get("domain_ocid", ""))
        if domain:
            qualified[f"{domain.lower()}/{name}"].add(str(group["group_key"]))
            domain_name = str(group.get("domain_name", "")).strip().lower()
            if domain_name:
                qualified[f"{domain_name}/{name}"].add(str(group["group_key"]))
    return plain, qualified


def map_group_reference(
    reference: str, plain: Mapping[str, Set[str]], qualified: Mapping[str, Set[str]],
) -> Tuple[str, str]:
    cleaned = reference.strip().replace("'", "").replace('"', "")
    candidates: Set[str] = set()
    if "/" in cleaned:
        candidates.update(qualified.get(cleaned.lower(), set()))
        if not candidates:
            candidates.update(plain.get(cleaned.rsplit("/", 1)[-1].lower(), set()))
    else:
        candidates.update(plain.get(cleaned.lower(), set()))
    if len(candidates) == 1:
        return next(iter(candidates)), "RESOLVED"
    return "", "AMBIGUOUS" if candidates else "UNRESOLVED"


def policy_and_privilege_rows(
    policies: Sequence[Tuple[ScopeItem, Any]], groups: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    policy_rows: List[Dict[str, Any]] = []
    privilege_rows: List[Dict[str, Any]] = []
    plain, qualified = group_indexes(groups)
    group_names = {str(row["group_key"]): str(row.get("group_name", "")) for row in groups}
    for scope, policy in policies:
        policy_id = text(policy, "id")
        policy_name = text(policy, "name")
        statements = getattr(policy, "statements", None)
        if not isinstance(statements, list):
            statements = []
        for index, statement_value in enumerate(statements, 1):
            statement = str(statement_value)
            statement_key = stable_hash([policy_id, index, statement])
            policy_rows.append({
                "policy_statement_key": statement_key, "policy_id": policy_id,
                "policy_name": policy_name, "attachment_compartment_name": scope.name,
                "attachment_compartment_ocid": scope.ocid, "statement_index": index,
                "lifecycle_state": text(policy, "lifecycle_state"),
                "policy_version_date": iso(getattr(policy, "version_date", None)),
                "statement": statement,
            })
            match = ALLOW_RE.match(statement)
            any_match = ANY_USER_RE.match(statement)
            candidates: List[Tuple[str, str, str, str, str]] = []
            if match:
                kind, principals, verb, resource, scope_clause = match.groups()
                for principal in split_principals(principals):
                    candidates.append((kind.upper(), principal, verb, resource, scope_clause))
            elif any_match:
                verb, resource, scope_clause = any_match.groups()
                candidates.append(("ANY-USER", "ANY-USER", verb, resource, scope_clause))
            else:
                candidates.append(("UNPARSED", "<UNPARSED-STATEMENT>", "", "", ""))
            for candidate_number, (kind, principal, verb, resource, scope_clause) in enumerate(candidates, 1):
                mapped_key, mapping = ("", "NOT-APPLICABLE")
                if kind in {"GROUP", "DYNAMIC-GROUP"}:
                    mapped_key, mapping = map_group_reference(principal, plain, qualified)
                level = {"MANAGE": "ADMIN-CANDIDATE", "USE": "WRITE-CANDIDATE",
                         "READ": "READ-CANDIDATE", "INSPECT": "INSPECT-CANDIDATE"}.get(
                    verb.upper(), "REVIEW-CANDIDATE"
                )
                privilege_rows.append({
                    "privilege_key": stable_hash([statement_key, candidate_number, principal]),
                    "source_system": "OCI-IAM-POLICY", "policy_id": policy_id,
                    "policy_name": policy_name, "attachment_compartment_name": scope.name,
                    "attachment_compartment_ocid": scope.ocid, "statement_index": index,
                    "principal_kind": kind, "principal_reference": principal,
                    "group_key": mapped_key, "group_name": group_names.get(mapped_key, ""),
                    "verb": verb.upper(), "resource_family": resource,
                    "scope_clause": scope_clause, "condition_present": "YES" if re.search(r"\swhere\b", statement, re.I) else "NO",
                    "candidate_level": level, "mapping_status": mapping,
                    "statement": statement,
                })
    for group in groups:
        if str(group.get("group_name", "")).lower() != "administrators":
            continue
        if "OCI-CLASSIC" not in str(group.get("source_system", "")):
            continue
        privilege_rows.append({
            "privilege_key": stable_hash(["BUILTIN-ADMINISTRATORS", group["group_key"]]),
            "source_system": "ORACLE-DOCUMENTED-BUILTIN", "policy_id": "",
            "policy_name": "BUILTIN-ADMINISTRATORS",
            "attachment_compartment_name": "root",
            "attachment_compartment_ocid": "", "statement_index": "",
            "principal_kind": "GROUP", "principal_reference": group["group_name"],
            "group_key": group["group_key"], "group_name": group["group_name"],
            "verb": "MANAGE", "resource_family": "ALL-RESOURCES",
            "scope_clause": "TENANCY", "condition_present": "NO",
            "candidate_level": "ADMIN-CANDIDATE", "mapping_status": "RESOLVED",
            "statement": "Oracle-documented built-in Administrators tenancy grant; validate independently",
        })
    return policy_rows, privilege_rows


def collect(
    oci: Any,
    args: argparse.Namespace,
    context: Any,
    identity: Any,
    catalog: Sequence[ScopeItem],
    selected: ScopeItem,
    targets: Sequence[ScopeItem],
) -> Tuple[
    List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
    List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
    List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
    List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]],
]:
    root = catalog[0]
    coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    accounts_by_key: Dict[str, Dict[str, Any]] = {}
    groups_by_key: Dict[str, Dict[str, Any]] = {}
    memberships_by_key: Dict[str, Dict[str, Any]] = {}
    credentials: List[Dict[str, Any]] = []
    domains_out: List[Dict[str, Any]] = []

    classic_users = classic_list(
        oci, identity, "list_users", root, coverage, errors, context.tenancy_id
    )
    classic_groups = classic_list(
        oci, identity, "list_groups", root, coverage, errors, context.tenancy_id
    )
    dynamic_groups = classic_list(
        oci, identity, "list_dynamic_groups", root, coverage, errors, context.tenancy_id
    )
    domains = classic_list(
        oci, identity, "list_domains", root, coverage, errors, context.tenancy_id
    )
    network_sources = classic_list(
        oci, identity, "list_network_sources", root, coverage, errors,
        context.tenancy_id,
    )

    for user in classic_users:
        if not text(user, "id"):
            add_error(
                errors, coverage, root, "OCI-CLASSIC", "list_users",
                ValueError("list_users returned a user without an OCID"),
            )
            continue
        row = classic_account_row(user)
        merge_account(accounts_by_key, row)
    for group in classic_groups:
        if not text(group, "id"):
            add_error(
                errors, coverage, root, "OCI-CLASSIC", "list_groups",
                ValueError("list_groups returned a group without an OCID"),
            )
            continue
        merge_group(groups_by_key, classic_group_row(group))
    for group in dynamic_groups:
        if not text(group, "id"):
            add_error(
                errors, coverage, root, "OCI-CLASSIC", "list_dynamic_groups",
                ValueError("list_dynamic_groups returned a group without an OCID"),
            )
            continue
        merge_group(groups_by_key, classic_group_row(group, "DYNAMIC"))

    classic_group_lookup = {
        str(row["group_id"]): row for row in groups_by_key.values()
        if "OCI-CLASSIC" in str(row.get("source_system", ""))
    }
    for user in classic_users:
        user_id = text(user, "id")
        if not user_id:
            continue
        akey = account_key("OCI-CLASSIC", "", user_id, user_id)
        memberships = classic_list(
            oci, identity, "list_user_group_memberships", root, coverage, errors,
            context.tenancy_id, user_id=user_id, subject_id=user_id,
        )
        for membership in memberships:
            group_id = text(membership, "group_id")
            group = classic_group_lookup.get(group_id)
            if group is None:
                add_error(
                    errors, coverage, root, "OCI-CLASSIC",
                    "list_user_group_memberships",
                    ValueError("membership references a group absent from list_groups"),
                    user_id,
                )
                continue
            access = stable_hash([akey, group["group_key"]])
            memberships_by_key[access] = {
                "access_key": access, "source_system": "OCI-CLASSIC",
                "domain_ocid": "", "membership_id": text(membership, "id"),
                "account_key": akey, "account_id": user_id,
                "account_name": text(user, "name"), "group_key": group["group_key"],
                "group_id": group_id, "group_name": group["group_name"],
                "membership_type": "DIRECT", "lifecycle_state": text(membership, "lifecycle_state"),
                "time_created": iso(getattr(membership, "time_created", None)),
                "privilege_keys": "",
            }
        credentials.extend(
            collect_classic_credentials(
                oci, identity, root, user, akey, coverage, errors
            )
        )

    for domain in domains:
        domain_id = text(domain, "id")
        domain_scope = ScopeItem(domain_id, text(domain, "display_name"), "IDENTITY-DOMAIN")
        status = text(domain, "lifecycle_state")
        domain_row = {
            "domain_ocid": domain_id, "display_name": text(domain, "display_name"),
            "compartment_ocid": text(domain, "compartment_id"),
            "domain_type": text(domain, "type"), "license_type": text(domain, "license_type"),
            "home_region": text(domain, "home_region"), "lifecycle_state": status,
            "time_created": iso(getattr(domain, "time_created", None)),
            "domain_url_host": "", "collection_status": "NOT-APPLICABLE",
            "request_id": "", "message": "Inactive domains are inventoried but not queried",
        }
        if not domain_id:
            add_error(
                errors, coverage, root, "OCI-CLASSIC", "list_domains",
                ValueError("list_domains returned a domain without an OCID"),
            )
            domain_row["collection_status"] = "FAILED"
            domain_row["message"] = "Identity Domain OCID is required for stable evidence"
            domains_out.append(domain_row)
            continue
        if status != "ACTIVE":
            domains_out.append(domain_row)
            continue
        before_errors = len(errors)
        try:
            endpoint, host = domain_endpoint(text(domain, "url"))
            domain_row["domain_url_host"] = host
            domain_client = build_client(
                oci, context, "identity_domains", "IdentityDomainsClient",
                service_endpoint=endpoint,
            )
        except Exception as exc:
            add_error(
                errors, coverage, domain_scope, "OCI-IDENTITY-DOMAIN",
                "build_identity_domains_client", exc,
            )
            domain_row["collection_status"] = "FAILED"
            domain_row["message"] = error_record(exc)["message"]
            domains_out.append(domain_row)
            continue
        domain_users = scim_list(
            oci, domain_client, "list_users", domain_scope, coverage, errors,
            attributes=(
                "id,ocid,userName,displayName,userType,active,groups,meta,"
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,"
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:user:User,"
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User,"
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:mfa:User"
            ),
        )
        domain_groups = scim_list(
            oci, domain_client, "list_groups", domain_scope, coverage, errors,
            attributes="id,ocid,displayName,meta",
        )
        domain_group_lookup: Dict[str, Dict[str, Any]] = {}
        for group in domain_groups:
            if not text(group, "id"):
                add_error(
                    errors, coverage, domain_scope, "OCI-IDENTITY-DOMAIN",
                    "list_groups", ValueError("Identity Domain group has no stable id"),
                )
                continue
            row = domain_group_row(domain, group)
            merge_group(groups_by_key, row)
            rows_group = groups_by_key[row["group_key"]]
            domain_group_lookup[text(group, "id")] = rows_group
            if text(group, "ocid"):
                domain_group_lookup[text(group, "ocid")] = rows_group
        for user in domain_users:
            user_id = text(user, "id")
            if not user_id:
                add_error(
                    errors, coverage, domain_scope, "OCI-IDENTITY-DOMAIN",
                    "list_users", ValueError("Identity Domain user has no stable id"),
                )
                continue
            row = domain_account_row(domain, user)
            merge_account(accounts_by_key, row)
            akey = str(row["account_key"])
            for reference in getattr(user, "groups", None) or []:
                ref_id = text(reference, "value") or text(reference, "ocid")
                group = domain_group_lookup.get(ref_id)
                if group is None:
                    add_error(
                        errors, coverage, domain_scope, "OCI-IDENTITY-DOMAIN",
                        "list_users", ValueError("user group reference was absent from list_groups"),
                        user_id,
                    )
                    continue
                access = stable_hash([akey, group["group_key"]])
                current = memberships_by_key.get(access)
                membership_row = {
                    "access_key": access, "source_system": "OCI-IDENTITY-DOMAIN",
                    "domain_ocid": domain_id,
                    "membership_id": text(reference, "membership_ocid"),
                    "account_key": akey, "account_id": user_id,
                    "account_name": text(user, "user_name"),
                    "group_key": group["group_key"], "group_id": group["group_id"],
                    "group_name": group["group_name"],
                    "membership_type": text(reference, "type") or "DIRECT-OR-INHERITED",
                    "lifecycle_state": "ACTIVE",
                    "time_created": text(reference, "date_added"), "privilege_keys": "",
                }
                if current:
                    sources = set(str(current["source_system"]).split("+"))
                    sources.add("OCI-IDENTITY-DOMAIN")
                    current["source_system"] = "+".join(sorted(sources))
                    for field, value in membership_row.items():
                        if value not in {"", None} and field not in {"access_key", "source_system"}:
                            current[field] = value
                else:
                    memberships_by_key[access] = membership_row
        domain_row["collection_status"] = "OK" if len(errors) == before_errors else "FAILED"
        domain_row["message"] = "Generated SDK list_users/list_groups completed" if len(errors) == before_errors else "Review collection errors"
        domains_out.append(domain_row)

    auth_rows: List[Dict[str, Any]] = []
    auth_response = classic_get(
        oci, identity, "get_authentication_policy", root, coverage, errors,
        context.tenancy_id,
    )
    if auth_response is not None:
        auth = auth_response.data
        password = getattr(auth, "password_policy", None)
        network = getattr(auth, "network_policy", None)
        auth_rows.append({
            "tenancy_ocid": context.tenancy_id,
            "minimum_password_length": getattr(password, "minimum_password_length", ""),
            "uppercase_required": bool_text(getattr(password, "is_uppercase_characters_required", None)),
            "lowercase_required": bool_text(getattr(password, "is_lowercase_characters_required", None)),
            "numeric_required": bool_text(getattr(password, "is_numeric_characters_required", None)),
            "special_required": bool_text(getattr(password, "is_special_characters_required", None)),
            "username_containment_allowed": bool_text(getattr(password, "is_username_containment_allowed", None)),
            "network_source_ids": "|".join(sorted(str(value) for value in (getattr(network, "network_source_ids", None) or []))),
            "collection_status": "OK", "request_id": request_id(auth_response), "message": "",
        })
    else:
        auth_rows.append({
            **{field: "" for field in AUTH_POLICY_FIELDS},
            "tenancy_ocid": context.tenancy_id, "collection_status": "FAILED",
            "message": "Review collection errors",
        })

    network_rows = [{
        "network_source_id": text(item, "id"), "name": text(item, "name"),
        "description": text(item, "description"),
        "public_source_count": len(getattr(item, "public_source_list", None) or []),
        "virtual_source_count": len(getattr(item, "virtual_source_list", None) or []),
        "lifecycle_state": text(item, "lifecycle_state"),
        "time_created": iso(getattr(item, "time_created", None)),
    } for item in network_sources]

    scopes = policy_scope_items(
        oci, identity, context, selected, targets, catalog, coverage, errors
    )
    policies: List[Tuple[ScopeItem, Any]] = []
    for scope in scopes:
        for item in classic_list(
            oci, identity, "list_policies", scope, coverage, errors, scope.ocid
        ):
            if not isinstance(getattr(item, "statements", None), list):
                add_error(
                    errors, coverage, scope, "OCI-CLASSIC", "list_policies",
                    ValueError("list_policies returned a policy without a statements list"),
                    text(item, "id"),
                )
                continue
            policies.append((scope, item))
    groups = sorted(groups_by_key.values(), key=lambda row: (
        str(row.get("group_name", "")).lower(), str(row["group_key"])
    ))
    policy_rows, privileges = policy_and_privilege_rows(policies, groups)
    privilege_by_group: Dict[str, List[str]] = defaultdict(list)
    for row in privileges:
        if row.get("group_key"):
            privilege_by_group[str(row["group_key"])].append(str(row["privilege_key"]))
    for membership in memberships_by_key.values():
        keys = sorted(set(privilege_by_group.get(str(membership["group_key"]), [])))
        membership["privilege_keys"] = "|".join(keys) if keys else "NONE"

    membership_counts = Counter(str(row["account_key"]) for row in memberships_by_key.values())
    credential_counts = Counter(str(row["account_key"]) for row in credentials)
    for key, row in accounts_by_key.items():
        row["group_count"] = membership_counts[key]
        row["credential_count"] = credential_counts[key]

    gaps = [
        {"gap_key": "AUTHORITATIVE-WORKFORCE-SOURCE", "source": "HR/contractor source",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Authoritative active/terminated workforce export and owner",
         "message": "OCI cannot prove employment or contract status."},
        {"gap_key": "FEDERATION-LIFECYCLE", "source": "Okta/DOJLogin/federation",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Provisioning/deprovisioning configuration and test",
         "message": "Task 13 owns detailed integration configuration; Task 12 must reconcile lifecycle coverage."},
        {"gap_key": "HOST-LOCAL-ACCOUNTS", "source": "Compute/OS/local directories",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Local, SSH, sudo and break-glass account inventory",
         "message": "OCI IAM APIs do not enumerate in-guest accounts."},
        {"gap_key": "DATABASE-NATIVE-ACCOUNTS", "source": "Database platforms",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Database-native account and role export",
         "message": "OCI control-plane users are not the database user population."},
        {"gap_key": "APPLICATION-ACCOUNTS", "source": "Applications and SaaS",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Application/service account inventory and review",
         "message": "Application-local accounts are outside OCI IAM inventory."},
        {"gap_key": "BREAK-GLASS-USAGE", "source": "Emergency access process",
         "status": "MANUAL-EVIDENCE-REQUIRED", "required_evidence": "Custody, activation, monitoring and post-use review proof",
         "message": "Directory membership alone does not prove emergency-account control operation."},
    ]
    return (
        sorted(accounts_by_key.values(), key=lambda row: str(row["account_key"])),
        groups,
        sorted(memberships_by_key.values(), key=lambda row: str(row["access_key"])),
        sorted(credentials, key=lambda row: str(row["credential_key"])),
        sorted(domains_out, key=lambda row: str(row["domain_ocid"])),
        policy_rows, privileges, auth_rows, network_rows, gaps, coverage, errors,
    )


def account_register_template(accounts: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [{
        **{field: "" for field in ACCOUNT_REGISTER_FIELDS},
        "account_key": row["account_key"], "account_name": row["account_name"],
        "expected_lifecycle_state": row["lifecycle_state"],
    } for row in accounts]


def access_approval_template(memberships: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [{
        **{field: "" for field in ACCESS_APPROVAL_FIELDS},
        "access_key": row["access_key"], "account_key": row["account_key"],
        "account_name": row["account_name"], "group_key": row["group_key"],
        "group_name": row["group_name"],
        "reviewed_privilege_keys": row["privilege_keys"],
    } for row in memberships]


def privilege_review_template(privileges: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [{
        **{field: "" for field in PRIVILEGE_REVIEW_FIELDS},
        "privilege_key": row["privilege_key"], "policy_id": row["policy_id"],
        "group_key": row["group_key"],
        "principal_reference": row["principal_reference"],
    } for row in privileges]


def inactivity_policy_template() -> List[Dict[str, Any]]:
    return [{
        **{field: "" for field in INACTIVITY_POLICY_FIELDS}, "account_type": kind,
    } for kind in sorted(ACCOUNT_TYPES)]


def lifecycle_template() -> List[Dict[str, Any]]:
    return [{field: "" for field in LIFECYCLE_FIELDS}]


def date_value(
    row: Mapping[str, str], field: str, errors: List[str], *, required: bool = False,
    future_ok: bool = False, now: Optional[datetime] = None,
) -> Optional[datetime]:
    value = row.get(field, "")
    if not value:
        if required:
            errors.append(f"{field} is required")
        return None
    try:
        parsed = parse_time(value, field)
    except ValueError as exc:
        errors.append(str(exc))
        return None
    if not future_ok and now is not None and parsed > now + timedelta(minutes=1):
        errors.append(f"{field} cannot be in the future")
    return parsed


def required_values(row: Mapping[str, str], fields: Sequence[str], errors: List[str]) -> None:
    for field in fields:
        if not row.get(field):
            errors.append(f"{field} is required")


def validation_result(
    rows: List[Dict[str, Any]], input_type: str, key: str, errors: Sequence[str],
    success: str,
) -> None:
    rows.append({
        "input_type": input_type, "row_key": key,
        "validation_status": "INVALID" if errors else "VALID",
        "validation_message": "; ".join(errors) if errors else success,
    })


def validate_governance(
    accounts: Sequence[Mapping[str, Any]], memberships: Sequence[Mapping[str, Any]],
    privileges: Sequence[Mapping[str, Any]], account_rows: Sequence[Mapping[str, str]],
    access_rows: Sequence[Mapping[str, str]], privilege_rows: Sequence[Mapping[str, str]],
    inactivity_rows: Sequence[Mapping[str, str]], lifecycle_rows: Sequence[Mapping[str, str]],
    now: datetime,
) -> Tuple[
    Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]],
    Dict[str, Dict[str, Any]], List[Dict[str, Any]], List[str], str,
]:
    live_accounts = {str(row["account_key"]): row for row in accounts}
    live_access = {str(row["access_key"]): row for row in memberships}
    live_privileges = {str(row["privilege_key"]): row for row in privileges}
    registers: Dict[str, Dict[str, Any]] = {}
    approvals: Dict[str, Dict[str, Any]] = {}
    privilege_reviews: Dict[str, Dict[str, Any]] = {}
    inactivity: Dict[str, Dict[str, Any]] = {}
    validations: List[Dict[str, Any]] = []
    blocking: List[str] = []

    for number, source in enumerate(account_rows, 1):
        row: Dict[str, Any] = dict(source)
        key = row.get("account_key", "") or f"row-{number}"
        errors: List[str] = []
        if not row.get("account_key"):
            errors.append("account_key is required")
        elif row["account_key"] in registers:
            errors.append("duplicate account_key")
        if row.get("account_key") not in live_accounts and row.get("expected_lifecycle_state") != "DELETED":
            errors.append("account_key is not live; expected_lifecycle_state must be DELETED to retain a closed record")
        required_values(row, (
            "account_name", "account_type", "system_name", "manager", "account_owner",
            "employment_status", "expected_lifecycle_state", "request_reference",
            "approval_status", "approver", "approval_date", "authoritative_source",
            "evidence_reference",
        ), errors)
        if row.get("account_type") not in ACCOUNT_TYPES:
            errors.append("account_type must be HUMAN, SERVICE, BREAK-GLASS, FEDERATED or GENERIC")
        if row.get("approval_status", "").upper() != "APPROVED":
            errors.append("approval_status must be APPROVED")
        row["_approval_date"] = date_value(row, "approval_date", errors, required=True, now=now)
        row["_last_activity"] = date_value(
            row, "last_authoritative_activity", errors, future_ok=False, now=now
        )
        row["_deactivation_due"] = date_value(
            row, "deactivation_due_date", errors, future_ok=True, now=now
        )
        exception_fields = (
            "inactivity_exception_reference", "exception_approver",
            "exception_expiration", "exception_evidence_reference",
        )
        exception_values = [bool(row.get(field)) for field in exception_fields]
        if any(exception_values) and not all(exception_values):
            errors.append("all inactivity exception fields are required together")
        row["_exception_expiration"] = date_value(
            row, "exception_expiration", errors, future_ok=True, now=now
        )
        if row.get("_exception_expiration") and row["_exception_expiration"] < now:
            errors.append("inactivity exception is expired")
        row["_errors"] = errors
        if row.get("account_key") and row["account_key"] not in registers:
            registers[row["account_key"]] = row
        validation_result(
            validations, "ACCOUNT-REGISTER", key, errors,
            "Account ownership, lifecycle and approval evidence is complete",
        )
        blocking.extend(f"ACCOUNT-REGISTER {key}: {error}" for error in errors)

    for number, source in enumerate(access_rows, 1):
        row = dict(source)
        key = row.get("access_key", "") or f"row-{number}"
        errors = []
        if not row.get("access_key"):
            errors.append("access_key is required")
        elif row["access_key"] in approvals:
            errors.append("duplicate access_key")
        live = live_access.get(row.get("access_key", ""))
        if live is None:
            errors.append("access_key does not match a live membership")
        else:
            for field in ("account_key", "group_key"):
                if row.get(field) != str(live.get(field, "")):
                    errors.append(f"{field} does not match the live membership")
        required_values(row, (
            "account_key", "account_name", "group_key", "group_name",
            "reviewed_privilege_keys", "access_decision", "manager", "approver",
            "approval_status", "approval_date", "request_reference", "authority",
            "evidence_reference",
        ), errors)
        if row.get("access_decision") not in ACCESS_DECISIONS:
            errors.append("access_decision must be KEEP or REMOVE")
        if row.get("approval_status", "").upper() != "APPROVED":
            errors.append("approval_status must be APPROVED")
        date_value(row, "approval_date", errors, required=True, now=now)
        expiry = date_value(row, "expiration_date", errors, future_ok=True, now=now)
        if expiry and expiry < now:
            errors.append("access approval is expired")
        row["_errors"] = errors
        if row.get("access_key") and row["access_key"] not in approvals:
            approvals[row["access_key"]] = row
        validation_result(
            validations, "ACCESS-APPROVAL", key, errors,
            "Membership decision and approval evidence is complete",
        )
        blocking.extend(f"ACCESS-APPROVAL {key}: {error}" for error in errors)

    for number, source in enumerate(privilege_rows, 1):
        row = dict(source)
        key = row.get("privilege_key", "") or f"row-{number}"
        errors = []
        if not row.get("privilege_key"):
            errors.append("privilege_key is required")
        elif row["privilege_key"] in privilege_reviews:
            errors.append("duplicate privilege_key")
        live = live_privileges.get(row.get("privilege_key", ""))
        if live is None:
            errors.append("privilege_key does not match a live candidate")
        else:
            for field in ("policy_id", "group_key", "principal_reference"):
                if row.get(field, "") != str(live.get(field, "")):
                    errors.append(f"{field} does not match the live privilege candidate")
        required_values(row, (
            "privilege_key", "principal_reference", "privilege_decision",
            "privilege_owner", "approver", "approval_status", "approval_date",
            "request_reference", "least_privilege_rationale", "authority",
            "evidence_reference",
        ), errors)
        if row.get("privilege_decision") not in PRIVILEGE_DECISIONS:
            errors.append("privilege_decision must be KEEP or REMOVE")
        if row.get("approval_status", "").upper() != "APPROVED":
            errors.append("approval_status must be APPROVED")
        date_value(row, "approval_date", errors, required=True, now=now)
        expiry = date_value(row, "expiration_date", errors, future_ok=True, now=now)
        if expiry and expiry < now:
            errors.append("privilege review is expired")
        row["_errors"] = errors
        if row.get("privilege_key") and row["privilege_key"] not in privilege_reviews:
            privilege_reviews[row["privilege_key"]] = row
        validation_result(
            validations, "PRIVILEGE-REVIEW", key, errors,
            "Privilege decision, least-privilege rationale and approval are complete",
        )
        blocking.extend(f"PRIVILEGE-REVIEW {key}: {error}" for error in errors)

    for number, source in enumerate(inactivity_rows, 1):
        row = dict(source)
        kind = row.get("account_type", "") or f"row-{number}"
        errors = []
        if row.get("account_type") not in ACCOUNT_TYPES:
            errors.append("account_type is invalid")
        elif row["account_type"] in inactivity:
            errors.append("duplicate account_type")
        required_values(row, (
            "account_type", "max_inactive_days", "unknown_activity_action",
            "removal_sla_days", "policy_owner", "authority", "effective_date",
            "approval_status", "approver", "evidence_reference",
        ), errors)
        try:
            row["_max_days"] = int(row.get("max_inactive_days", ""))
            if not 1 <= row["_max_days"] <= 3650:
                raise ValueError
        except ValueError:
            errors.append("max_inactive_days must be an integer from 1 to 3650")
        try:
            row["_removal_days"] = int(row.get("removal_sla_days", ""))
            if not 0 <= row["_removal_days"] <= 365:
                raise ValueError
        except ValueError:
            errors.append("removal_sla_days must be an integer from 0 to 365")
        if row.get("unknown_activity_action") not in UNKNOWN_ACTIONS:
            errors.append("unknown_activity_action must be INVESTIGATE, DISABLE or DOCUMENT-EXCEPTION")
        if row.get("approval_status", "").upper() != "APPROVED":
            errors.append("approval_status must be APPROVED")
        date_value(row, "effective_date", errors, required=True, now=now)
        row["_errors"] = errors
        if row.get("account_type") in ACCOUNT_TYPES and row["account_type"] not in inactivity:
            inactivity[row["account_type"]] = row
        validation_result(
            validations, "INACTIVITY-POLICY", kind, errors,
            "Approved inactivity threshold and removal SLA are complete",
        )
        blocking.extend(f"INACTIVITY-POLICY {kind}: {error}" for error in errors)

    lifecycle_status = "NOT-SUPPLIED"
    if lifecycle_rows:
        if len(lifecycle_rows) != 1:
            message = "lifecycle procedure must contain exactly one row"
            validation_result(validations, "LIFECYCLE-PROCEDURE", "file", [message], "")
            blocking.append("LIFECYCLE-PROCEDURE: " + message)
            lifecycle_status = "INVALID"
        else:
            row = lifecycle_rows[0]
            errors = []
            required_values(row, LIFECYCLE_FIELDS, errors)
            for field in ("joiner_sla_days", "mover_sla_days", "leaver_sla_days"):
                try:
                    value = int(row.get(field, ""))
                    if not 0 <= value <= 365:
                        raise ValueError
                except ValueError:
                    errors.append(f"{field} must be an integer from 0 to 365")
            if row.get("approval_status", "").upper() != "APPROVED":
                errors.append("approval_status must be APPROVED")
            date_value(row, "approval_date", errors, required=True, now=now)
            validation_result(
                validations, "LIFECYCLE-PROCEDURE", row.get("procedure_id", "row-1"),
                errors, "Approved request, modification, deactivation and review processes are complete",
            )
            blocking.extend(f"LIFECYCLE-PROCEDURE: {error}" for error in errors)
            lifecycle_status = "INVALID" if errors else "VALID"
    return (
        registers, approvals, privilege_reviews, inactivity, validations, blocking,
        lifecycle_status,
    )


def newest_activity(account: Mapping[str, Any], register: Mapping[str, Any]) -> Optional[datetime]:
    values: List[datetime] = []
    for value in (str(account.get("last_successful_login", "")),):
        if value:
            try:
                values.append(parse_time(value, "last_successful_login"))
            except ValueError:
                pass
    if register.get("_last_activity"):
        values.append(register["_last_activity"])
    return max(values) if values else None


def reconcile_accounts(
    accounts: Sequence[Mapping[str, Any]], registers: Mapping[str, Mapping[str, Any]],
    inactivity: Mapping[str, Mapping[str, Any]], now: datetime,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    live_keys: Set[str] = set()
    for account in accounts:
        key = str(account["account_key"])
        live_keys.add(key)
        register = registers.get(key)
        base = {field: account.get(field, "") for field in ACCOUNT_FIELDS}
        if register is None:
            rows.append({
                **base, **{field: "" for field in ACCOUNT_RECON_FIELDS if field not in base},
                "inactivity_status": "NOT-EVALUATED",
                "reconciliation_status": "UNREGISTERED",
                "validation_message": "No authoritative account-register row was supplied",
            })
            continue
        output = {
            **base, "account_type": register.get("account_type", ""),
            "manager": register.get("manager", ""),
            "account_owner": register.get("account_owner", ""),
            "request_reference": register.get("request_reference", ""),
            "approver": register.get("approver", ""),
            "approval_status": register.get("approval_status", ""),
            "effective_last_activity": "", "inactive_days": "",
            "inactivity_threshold_days": "", "inactivity_status": "NOT-EVALUATED",
            "deactivation_due_date": register.get("deactivation_due_date", ""),
            "reconciliation_status": "VALIDATED", "validation_message": "Account ownership and lifecycle are approved",
        }
        if register.get("_errors"):
            output["reconciliation_status"] = "REGISTER-INVALID"
            output["validation_message"] = "; ".join(register["_errors"])
        elif register.get("expected_lifecycle_state") != account.get("lifecycle_state"):
            output["reconciliation_status"] = "ACCOUNT-STATE-DRIFT"
            output["validation_message"] = "Live lifecycle state differs from the approved register"
        policy = inactivity.get(str(register.get("account_type", "")))
        if policy is None or policy.get("_errors"):
            output["inactivity_status"] = "POLICY-MISSING-OR-INVALID"
            if output["reconciliation_status"] == "VALIDATED":
                output["reconciliation_status"] = "INACTIVITY-POLICY-GAP"
                output["validation_message"] = "No valid approved inactivity policy exists for this account type"
        elif account.get("lifecycle_state") != "ACTIVE":
            output["inactivity_status"] = "NOT-ACTIVE"
            output["inactivity_threshold_days"] = policy.get("_max_days", "")
        else:
            activity = newest_activity(account, register)
            output["inactivity_threshold_days"] = policy.get("_max_days", "")
            if activity is None:
                output["inactivity_status"] = "ACTIVITY-UNKNOWN"
                if output["reconciliation_status"] == "VALIDATED":
                    output["reconciliation_status"] = "ACTIVITY-UNKNOWN"
                    output["validation_message"] = (
                        "No technical or authoritative activity time is available; apply the approved unknown-activity action "
                        + str(policy.get("unknown_activity_action", ""))
                    )
            else:
                inactive_days = max(0, (now - activity).days)
                output["effective_last_activity"] = iso(activity)
                output["inactive_days"] = inactive_days
                if inactive_days > int(policy.get("_max_days", 0)):
                    if register.get("_exception_expiration") and register["_exception_expiration"] >= now:
                        output["inactivity_status"] = "APPROVED-EXCEPTION"
                    else:
                        output["inactivity_status"] = "INACTIVE-CANDIDATE"
                        if output["reconciliation_status"] == "VALIDATED":
                            output["reconciliation_status"] = "INACTIVE-REMOVAL-DUE"
                            output["validation_message"] = "Inactivity exceeds the approved threshold without a current exception"
                else:
                    output["inactivity_status"] = "WITHIN-THRESHOLD"
        rows.append(output)
    for key, register in registers.items():
        if key in live_keys:
            continue
        status = "VALIDATED-NOT-LIVE" if register.get("expected_lifecycle_state") == "DELETED" and not register.get("_errors") else "REGISTERED-NOT-LIVE"
        rows.append({
            **{field: "" for field in ACCOUNT_RECON_FIELDS},
            "account_key": key, "account_name": register.get("account_name", ""),
            "account_type": register.get("account_type", ""), "manager": register.get("manager", ""),
            "account_owner": register.get("account_owner", ""),
            "request_reference": register.get("request_reference", ""),
            "approver": register.get("approver", ""),
            "approval_status": register.get("approval_status", ""),
            "deactivation_due_date": register.get("deactivation_due_date", ""),
            "inactivity_status": "NOT-LIVE", "reconciliation_status": status,
            "validation_message": "Closed account is absent from the current directory" if status == "VALIDATED-NOT-LIVE" else "Register row is absent from the current directory and is not a valid closed record",
        })
    return rows


def reconcile_access(
    memberships: Sequence[Mapping[str, Any]], approvals: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for membership in memberships:
        base = {field: membership.get(field, "") for field in MEMBERSHIP_FIELDS}
        approval = approvals.get(str(membership["access_key"]))
        if approval is None:
            rows.append({
                **base, "access_decision": "", "manager": "", "approver": "",
                "approval_status": "", "request_reference": "", "expiration_date": "",
                "reconciliation_status": "ACCESS-APPROVAL-MISSING",
                "validation_message": "No exact group-access approval was supplied",
            })
            continue
        status, message = "VALIDATED", "Current membership and privilege set were approved"
        if approval.get("_errors"):
            status, message = "ACCESS-APPROVAL-INVALID", "; ".join(approval["_errors"])
        elif pipe_values(str(approval.get("reviewed_privilege_keys", ""))) != pipe_values(str(membership.get("privilege_keys", ""))):
            status, message = "PRIVILEGE-SET-STALE", "Reviewed privilege keys do not exactly match the current group privilege candidates"
        elif approval.get("access_decision") == "REMOVE":
            status, message = "ACCESS-REMOVAL-OPEN", "Approved removal decision still has a live membership"
        rows.append({
            **base, "access_decision": approval.get("access_decision", ""),
            "manager": approval.get("manager", ""), "approver": approval.get("approver", ""),
            "approval_status": approval.get("approval_status", ""),
            "request_reference": approval.get("request_reference", ""),
            "expiration_date": approval.get("expiration_date", ""),
            "reconciliation_status": status, "validation_message": message,
        })
    return rows


def reconcile_privileges(
    privileges: Sequence[Mapping[str, Any]], reviews: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for privilege in privileges:
        base = {field: privilege.get(field, "") for field in PRIVILEGE_FIELDS}
        review = reviews.get(str(privilege["privilege_key"]))
        if review is None:
            rows.append({
                **base, "privilege_decision": "", "privilege_owner": "",
                "approver": "", "approval_status": "", "request_reference": "",
                "expiration_date": "", "reconciliation_status": "PRIVILEGE-REVIEW-MISSING",
                "validation_message": "No exact privilege-candidate review was supplied",
            })
            continue
        status, message = "VALIDATED", "Privilege candidate has approved least-privilege review"
        if review.get("_errors"):
            status, message = "PRIVILEGE-REVIEW-INVALID", "; ".join(review["_errors"])
        elif review.get("privilege_decision") == "REMOVE":
            status, message = "PRIVILEGE-REMOVAL-OPEN", "Approved removal decision still has a live policy candidate"
        rows.append({
            **base, "privilege_decision": review.get("privilege_decision", ""),
            "privilege_owner": review.get("privilege_owner", ""),
            "approver": review.get("approver", ""),
            "approval_status": review.get("approval_status", ""),
            "request_reference": review.get("request_reference", ""),
            "expiration_date": review.get("expiration_date", ""),
            "reconciliation_status": status, "validation_message": message,
        })
    return rows


def expected_review(
    snapshot_hash: str, now: datetime, accounts: Sequence[Mapping[str, Any]],
    groups: Sequence[Mapping[str, Any]], memberships: Sequence[Mapping[str, Any]],
    credentials: Sequence[Mapping[str, Any]], privileges: Sequence[Mapping[str, Any]],
    account_recon: Sequence[Mapping[str, Any]], access_recon: Sequence[Mapping[str, Any]],
    privilege_recon: Sequence[Mapping[str, Any]], gaps: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    account_status = Counter(str(row.get("reconciliation_status", "")) for row in account_recon)
    access_status = Counter(str(row.get("reconciliation_status", "")) for row in access_recon)
    privilege_status = Counter(str(row.get("reconciliation_status", "")) for row in privilege_recon)
    return {
        "snapshot_sha256": snapshot_hash, "review_period": now.strftime("%Y-%m"),
        "account_count": len(accounts),
        "active_account_count": sum(1 for row in accounts if row.get("lifecycle_state") == "ACTIVE"),
        "group_count": len(groups), "membership_count": len(memberships),
        "credential_count": len(credentials), "privilege_candidate_count": len(privileges),
        "unregistered_count": account_status["UNREGISTERED"],
        "account_drift_count": sum(
            count for status, count in account_status.items()
            if status not in {"VALIDATED", "VALIDATED-NOT-LIVE", "UNREGISTERED", "ACTIVITY-UNKNOWN", "INACTIVE-REMOVAL-DUE"}
        ),
        "inactive_candidate_count": account_status["INACTIVE-REMOVAL-DUE"],
        "unknown_activity_count": account_status["ACTIVITY-UNKNOWN"],
        "access_approval_gap_count": sum(
            count for status, count in access_status.items()
            if status in {"ACCESS-APPROVAL-MISSING", "ACCESS-APPROVAL-INVALID", "PRIVILEGE-SET-STALE"}
        ),
        "access_removal_open_count": access_status["ACCESS-REMOVAL-OPEN"],
        "privilege_review_gap_count": sum(
            count for status, count in privilege_status.items()
            if status in {"PRIVILEGE-REVIEW-MISSING", "PRIVILEGE-REVIEW-INVALID"}
        ),
        "privilege_removal_open_count": privilege_status["PRIVILEGE-REMOVAL-OPEN"],
        "manual_gap_count": len(gaps), "reviewer": "", "review_date": "",
        "compliance_result": "", "corrective_action_reference": "",
        "approval_status": "", "approver": "", "evidence_reference": "", "notes": "",
    }


def validate_review(
    row: Mapping[str, str], expected: Mapping[str, Any], now: datetime,
) -> Tuple[str, str]:
    errors: List[str] = []
    bound_fields = REVIEW_FIELDS[:17]
    for field in bound_fields:
        if str(row.get(field, "")) != str(expected.get(field, "")):
            errors.append(f"{field} does not match the current snapshot")
    required_values(row, (
        "reviewer", "review_date", "compliance_result", "approval_status",
        "approver", "evidence_reference", "notes",
    ), errors)
    date_value(row, "review_date", errors, required=True, now=now)
    if row.get("approval_status", "").upper() != "APPROVED":
        errors.append("approval_status must be APPROVED")
    open_count = sum(int(expected.get(field, 0)) for field in (
        "unregistered_count", "account_drift_count", "inactive_candidate_count",
        "unknown_activity_count", "access_approval_gap_count",
        "access_removal_open_count", "privilege_review_gap_count",
        "privilege_removal_open_count", "manual_gap_count",
    ))
    result = row.get("compliance_result", "").upper()
    if open_count:
        if result != "PASS-WITH-FINDINGS":
            errors.append("compliance_result must be PASS-WITH-FINDINGS while findings or manual gaps remain")
        if not row.get("corrective_action_reference"):
            errors.append("corrective_action_reference is required while findings or manual gaps remain")
    elif result != "PASS":
        errors.append("compliance_result must be PASS when no findings remain")
    return ("INVALID", "; ".join(errors)) if errors else (
        "VALID", "Approved review exactly matches the account, access and privilege snapshot",
    )


def snapshot_manifest(
    paths: Mapping[str, str], row_counts: Mapping[str, int]
) -> Tuple[List[Dict[str, Any]], str]:
    rows: List[Dict[str, Any]] = []
    for artifact in sorted(row_counts):
        path = paths[artifact]
        rows.append({
            "artifact": artifact, "path": path, "sha256": sha256_file(path),
            "row_count": row_counts[artifact],
        })
    overall = stable_hash(
        [f"{row['artifact']}:{row['sha256']}:{row['row_count']}" for row in rows]
    )
    return rows, overall


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
    governance_paths = {
        "ACCOUNT-REGISTER": args.account_register,
        "ACCESS-APPROVAL": args.access_approvals,
        "PRIVILEGE-REVIEW": args.privilege_review,
        "INACTIVITY-POLICY": args.inactivity_policy,
        "LIFECYCLE-PROCEDURE": args.lifecycle_procedure,
        "MONTHLY-REVIEW": args.monthly_review,
    }
    now = utc_now()
    try:
        account_rows = required_headers(
            args.account_register, ACCOUNT_REGISTER_FIELDS, "account register"
        ) if args.account_register else []
        access_rows = required_headers(
            args.access_approvals, ACCESS_APPROVAL_FIELDS, "access approvals"
        ) if args.access_approvals else []
        privilege_input_rows = required_headers(
            args.privilege_review, PRIVILEGE_REVIEW_FIELDS, "privilege review"
        ) if args.privilege_review else []
        inactivity_rows = required_headers(
            args.inactivity_policy, INACTIVITY_POLICY_FIELDS, "inactivity policy"
        ) if args.inactivity_policy else []
        lifecycle_rows = required_headers(
            args.lifecycle_procedure, LIFECYCLE_FIELDS, "lifecycle procedure"
        ) if args.lifecycle_procedure else []
        review_rows = required_headers(
            args.monthly_review, REVIEW_FIELDS, "monthly review"
        ) if args.monthly_review else []
        if args.monthly_review and len(review_rows) != 1:
            raise ValueError("monthly review must contain exactly one data row")
        oci = oci_module or load_oci()
        context = build_auth_context(oci, args)
        identity = build_client(oci, context, "identity", "IdentityClient")
        catalog = discover_scope(oci, identity, context.tenancy_id, CLASSIC_METHODS)
        selected, targets = resolve_targets(args, catalog)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1

    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    output_dir = str(Path(args.output_dir))
    prefix = f"ac02-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "domains": f"{output_dir}/{prefix}_identity_domains.csv",
        "accounts": f"{output_dir}/{prefix}_account_inventory.csv",
        "groups": f"{output_dir}/{prefix}_group_inventory.csv",
        "memberships": f"{output_dir}/{prefix}_group_memberships.csv",
        "credentials": f"{output_dir}/{prefix}_credential_metadata.csv",
        "policies": f"{output_dir}/{prefix}_policy_statements.csv",
        "privileges": f"{output_dir}/{prefix}_privilege_candidates.csv",
        "auth_policy": f"{output_dir}/{prefix}_authentication_policy.csv",
        "network_sources": f"{output_dir}/{prefix}_network_sources.csv",
        "gaps": f"{output_dir}/{prefix}_manual_evidence_gaps.csv",
        "coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv (only when errors exist)",
        "account_template": f"{output_dir}/{prefix}_account_register_template.csv",
        "access_template": f"{output_dir}/{prefix}_access_approval_template.csv",
        "privilege_template": f"{output_dir}/{prefix}_privilege_review_template.csv",
        "inactivity_template": f"{output_dir}/{prefix}_inactivity_policy_template.csv",
        "lifecycle_template": f"{output_dir}/{prefix}_lifecycle_procedure_template.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "input_validation": f"{output_dir}/{prefix}_input_validation.csv",
        "account_recon": f"{output_dir}/{prefix}_account_reconciliation.csv",
        "access_recon": f"{output_dir}/{prefix}_access_reconciliation.csv",
        "privilege_recon": f"{output_dir}/{prefix}_privilege_reconciliation.csv",
        "manifest": f"{output_dir}/{prefix}_snapshot_manifest.csv",
        "review_template": f"{output_dir}/{prefix}_monthly_review_template.csv",
        "review_validation": f"{output_dir}/{prefix}_monthly_review_validation.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    actual = {key: value.split(" (only", 1)[0] for key, value in outputs.items()}
    plan = build_plan(args, context, selected, targets, outputs)
    print(plan, end="")
    try:
        validate_final_approval(args, targets)
    except ValueError as exc:
        print(f"SCAN NOT STARTED: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    collisions = [path for path in actual.values() if Path(path).exists()]
    if collisions:
        print("SCAN NOT STARTED: output collision; refusing to overwrite evidence:", file=sys.stderr)
        for path in collisions:
            print("  " + path, file=sys.stderr)
        return 1

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    write_private_text(actual["plan"], plan + "SCAN APPROVED\n")
    (
        accounts, groups, memberships, credentials, domains, policies, privileges,
        auth_policy, network_sources, gaps, coverage, errors,
    ) = collect(oci, args, context, identity, catalog, selected, targets)
    write_csv(actual["domains"], DOMAIN_FIELDS, domains)
    write_csv(actual["accounts"], ACCOUNT_FIELDS, accounts)
    write_csv(actual["groups"], GROUP_FIELDS, groups)
    write_csv(actual["memberships"], MEMBERSHIP_FIELDS, memberships)
    write_csv(actual["credentials"], CREDENTIAL_FIELDS, credentials)
    write_csv(actual["policies"], POLICY_FIELDS, policies)
    write_csv(actual["privileges"], PRIVILEGE_FIELDS, privileges)
    write_csv(actual["auth_policy"], AUTH_POLICY_FIELDS, auth_policy)
    write_csv(actual["network_sources"], NETWORK_SOURCE_FIELDS, network_sources)
    write_csv(actual["gaps"], GAP_FIELDS, gaps)
    write_csv(actual["coverage"], COVERAGE_FIELDS, coverage)
    if errors:
        write_csv(actual["errors"], ERROR_FIELDS, errors)

    write_csv(
        actual["account_template"], ACCOUNT_REGISTER_FIELDS,
        account_register_template(accounts),
    )
    write_csv(
        actual["access_template"], ACCESS_APPROVAL_FIELDS,
        access_approval_template(memberships),
    )
    write_csv(
        actual["privilege_template"], PRIVILEGE_REVIEW_FIELDS,
        privilege_review_template(privileges),
    )
    write_csv(
        actual["inactivity_template"], INACTIVITY_POLICY_FIELDS,
        inactivity_policy_template(),
    )
    write_csv(actual["lifecycle_template"], LIFECYCLE_FIELDS, lifecycle_template())

    registers, approvals, privilege_reviews, inactivity, validations, input_errors, lifecycle_status = validate_governance(
        accounts, memberships, privileges, account_rows, access_rows,
        privilege_input_rows, inactivity_rows, lifecycle_rows, now,
    )
    account_recon = reconcile_accounts(accounts, registers, inactivity, now)
    access_recon = reconcile_access(memberships, approvals)
    privilege_recon = reconcile_privileges(privileges, privilege_reviews)
    write_csv(actual["input_validation"], INPUT_VALIDATION_FIELDS, validations)
    write_csv(actual["account_recon"], ACCOUNT_RECON_FIELDS, account_recon)
    write_csv(actual["access_recon"], ACCESS_RECON_FIELDS, access_recon)
    write_csv(actual["privilege_recon"], PRIVILEGE_RECON_FIELDS, privilege_recon)
    input_sources = []
    input_rows_by_type = {
        "ACCOUNT-REGISTER": account_rows, "ACCESS-APPROVAL": access_rows,
        "PRIVILEGE-REVIEW": privilege_input_rows,
        "INACTIVITY-POLICY": inactivity_rows,
        "LIFECYCLE-PROCEDURE": lifecycle_rows, "MONTHLY-REVIEW": review_rows,
    }
    for kind, path in governance_paths.items():
        if path:
            input_sources.append({
                "input_type": kind, "path": path, "sha256": sha256_file(path),
                "row_count": len(input_rows_by_type[kind]),
            })
    write_csv(actual["inputs"], INPUT_SOURCE_FIELDS, input_sources)

    manifest_paths = {
        "accounts": actual["accounts"], "groups": actual["groups"],
        "memberships": actual["memberships"], "credentials": actual["credentials"],
        "policies": actual["policies"], "privileges": actual["privileges"],
        "domains": actual["domains"], "auth_policy": actual["auth_policy"],
        "network_sources": actual["network_sources"], "gaps": actual["gaps"],
        "coverage": actual["coverage"],
    }
    row_counts = {
        "accounts": len(accounts), "groups": len(groups), "memberships": len(memberships),
        "credentials": len(credentials), "policies": len(policies),
        "privileges": len(privileges), "domains": len(domains),
        "auth_policy": len(auth_policy), "network_sources": len(network_sources),
        "gaps": len(gaps), "coverage": len(coverage),
    }
    manifest_rows, snapshot_hash = snapshot_manifest(manifest_paths, row_counts)
    write_csv(actual["manifest"], ["artifact", "path", "sha256", "row_count"], manifest_rows)
    expected = expected_review(
        snapshot_hash, now, accounts, groups, memberships, credentials, privileges,
        account_recon, access_recon, privilege_recon, gaps,
    )
    write_csv(actual["review_template"], REVIEW_FIELDS, [expected])
    review_results: List[Dict[str, Any]] = []
    review_error = ""
    if review_rows:
        status, message = validate_review(review_rows[0], expected, now)
        review_results.append({
            **review_rows[0], "validation_status": status,
            "validation_message": message,
        })
        if status != "VALID":
            review_error = message
    write_csv(actual["review_validation"], REVIEW_RESULT_FIELDS, review_results)

    collection_complete = not errors and all(
        row.get("status") in {"OK", "EMPTY", "SKIPPED-CAPABILITY-DISABLED"}
        for row in coverage
    )
    governance_mode = any(governance_paths.values())
    required_governance = all(governance_paths.values())
    account_blocking = sum(
        1 for row in account_recon
        if row.get("reconciliation_status") not in {"VALIDATED", "VALIDATED-NOT-LIVE"}
    )
    access_blocking = sum(
        1 for row in access_recon if row.get("reconciliation_status") != "VALIDATED"
    )
    privilege_blocking = sum(
        1 for row in privilege_recon if row.get("reconciliation_status") != "VALIDATED"
    )
    governance_complete = bool(
        governance_mode and required_governance and not input_errors
        and lifecycle_status == "VALID" and not account_blocking and not access_blocking
        and not privilege_blocking and review_results and not review_error
        and review_results[0].get("validation_status") == "VALID"
    )
    summary_lines = [
        "AC02-01 Account Management Summary",
        "====================================",
        f"Region                    : {args.region}",
        f"Selected scope            : {selected.kind} / {selected.name}",
        f"Confirmed targets         : {len(targets)}",
        f"Collected                 : {iso(now)}",
        f"OCI SDK version           : {getattr(oci, '__version__', '<unknown>')}",
        f"Identity domains          : {len(domains)}",
        f"Accounts                  : {len(accounts)}",
        f"Active accounts           : {sum(1 for row in accounts if row.get('lifecycle_state') == 'ACTIVE')}",
        f"Groups                    : {len(groups)}",
        f"Memberships               : {len(memberships)}",
        f"Credential metadata rows  : {len(credentials)}",
        f"Policy statements         : {len(policies)}",
        f"Privilege candidates      : {len(privileges)}",
        f"Account findings          : {account_blocking}",
        f"Access findings           : {access_blocking}",
        f"Privilege findings        : {privilege_blocking}",
        f"Manual evidence gaps      : {len(gaps)}",
        f"Collection errors         : {len(errors)}",
        f"Snapshot SHA-256          : {snapshot_hash}",
        f"COLLECTION STATUS         : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"Governance mode           : {'RECONCILIATION' if governance_mode else 'TEMPLATE-GENERATION'}",
        f"GOVERNANCE INPUT STATUS   : {'VALIDATED' if governance_complete else 'NOT-VALIDATED'}",
        "",
        "OCI policy rows are candidates for human least-privilege review, not effective-access decisions.",
        "This collector never disables accounts, removes memberships, changes policy or retrieves credential values.",
    ]
    write_private_text(actual["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")
    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {actual['coverage']}", file=sys.stderr)
        return 3
    if governance_mode and not governance_complete:
        print(f"GOVERNANCE INPUTS NOT VALIDATED — review {actual['input_validation']}", file=sys.stderr)
        return 3
    print("AC02-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
