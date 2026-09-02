#!/usr/bin/env python3
"""IA-2 Okta/DOJLogin federation configuration evidence via Oracle OCI SDK."""

from __future__ import annotations

import argparse
import ast
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
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
    sdk_list,
    sdk_resources_page_list,
    sdk_scim_list,
    sha256_file,
    stable_hash,
    utc_now,
    write_csv,
    write_private_text,
)

VERSION = "1.0.0"
COLLECTOR = "IA02-01"
CONTROLS = "IA-2 / IA-2(1) / IA-5 / AC-2"

CLASSIC_METHODS: Set[str] = {"get_compartment", "list_compartments", "list_domains"}
SCIM_METHODS: Set[str] = {"list_apps", "list_identity_providers", "list_policies", "list_rules"}
RESOURCE_PAGE_METHODS: Set[str] = {"list_authentication_factor_settings"}
SDK_READ_METHODS = CLASSIC_METHODS | SCIM_METHODS | RESOURCE_PAGE_METHODS

DOMAIN_FIELDS = [
    "domain_ocid", "display_name", "compartment_ocid", "domain_type", "home_region",
    "lifecycle_state", "time_created", "domain_url_host", "collection_status", "message",
]
PROVIDER_FIELDS = [
    "provider_key", "domain_ocid", "domain_name", "provider_id", "provider_ocid",
    "partner_name", "provider_type", "enabled", "shown_on_login_page", "sso_url_host",
    "sso_url_sha256", "logout_request_url_host", "logout_request_url_sha256",
    "logout_response_url_host", "logout_response_url_sha256", "authn_request_binding",
    "logout_binding", "logout_enabled", "signature_hash_algorithm", "name_id_format",
    "signing_certificate_present", "signing_certificate_sha256",
    "encryption_certificate_present", "encryption_certificate_sha256", "require_force_authn",
    "requires_encrypted_assertion", "jit_user_provisioning", "jit_create_user",
    "jit_attribute_update", "jit_group_assertion", "jit_static_groups",
    "jit_group_assignment_method", "jit_group_mapping_mode", "jit_group_mapping_count",
    "jit_assigned_group_count", "user_mapping_method", "user_mapping_store_attribute",
    "assertion_attribute", "requested_authentication_context_count", "time_created",
    "time_modified", "config_sha256",
]
APP_FIELDS = [
    "app_key", "domain_ocid", "domain_name", "app_id", "app_ocid", "name",
    "display_name", "active", "login_mechanism", "is_login_target",
    "is_saml_service_provider", "is_oauth_client", "is_managed_app", "client_type",
    "allowed_grants", "allowed_scope_count", "identity_provider_refs",
    "app_signon_policy_ref", "based_on_template_ref", "saml_service_provider_ref",
    "time_created", "time_modified", "config_sha256",
]
POLICY_FIELDS = [
    "policy_key", "domain_ocid", "domain_name", "policy_id", "policy_ocid", "name",
    "active", "policy_type", "rule_refs", "policy_groovy_present", "policy_groovy_sha256",
    "time_created", "time_modified", "config_sha256",
]
RULE_FIELDS = [
    "rule_key", "domain_ocid", "domain_name", "rule_id", "rule_ocid", "name", "active",
    "locked", "policy_type", "condition_sha256", "condition_present", "return_count",
    "return_names", "return_values_sha256", "rule_groovy_present", "rule_groovy_sha256",
    "time_created", "time_modified", "config_sha256",
]
MFA_FIELDS = [
    "factor_setting_key", "domain_ocid", "domain_name", "setting_id", "setting_ocid",
    "mfa_enrollment_type", "mfa_enabled_category", "email_enabled", "sms_enabled",
    "phone_call_enabled", "totp_enabled", "push_enabled", "fido_authenticator_enabled",
    "yubico_otp_enabled", "bypass_code_enabled", "security_questions_enabled",
    "hide_backup_factor_enabled", "auto_enroll_email_factor_disabled",
    "user_enrollment_disabled_factors", "time_created", "time_modified", "config_sha256",
]
COVERAGE_FIELDS = [
    "scope_name", "scope_ocid", "operation", "status", "item_count", "page_count",
    "request_id", "message",
]
ERROR_FIELDS = [
    "scope_name", "scope_ocid", "operation", "http_status", "service_code",
    "request_id", "message",
]
REGISTER_FIELDS = [
    "provider_key", "provider_partner_name", "provider_config_sha256", "snapshot_sha256",
    "disposition", "provider_system", "integration_role", "provisioning_mode",
    "selected_app_keys", "selected_policy_keys", "selected_rule_keys",
    "external_config_reference", "external_config_sha256", "mapping_review_status",
    "certificate_review_status", "system_owner", "approver", "approval_status",
    "approval_date", "authority", "rationale", "evidence_reference",
]
TEST_FIELDS = [
    "provider_key", "snapshot_sha256", "test_type", "test_result", "tested_at", "tester",
    "expected_result", "evidence_reference", "exception_reference", "approver",
    "approval_status", "rationale",
]
RECON_FIELDS = REGISTER_FIELDS + ["validation_status", "validation_message"]
TEST_RESULT_FIELDS = TEST_FIELDS + ["validation_status", "validation_message"]
INPUT_FIELDS = ["input_type", "path", "sha256", "row_count"]
MANIFEST_FIELDS = ["artifact", "path", "sha256", "row_count"]

DISPOSITIONS = {"APPLICABLE", "NOT-APPLICABLE"}
PROVIDER_SYSTEMS = {"OKTA", "DOJLOGIN", "OTHER"}
PROVISIONING_MODES = {"SCIM", "JIT", "MANUAL", "NONE"}
REQUIRED_TESTS = {"AUTHENTICATION", "MFA", "PROVISIONING", "DEPROVISIONING", "GROUP-MAPPING"}
TEST_RESULTS = {"PASS", "FAIL", "NOT-APPLICABLE"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI federation configuration inventory and approved applicability review."
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
    p.add_argument("--integration-register")
    p.add_argument("--test-evidence")
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
    guarded = {
        "classic_list": CLASSIC_METHODS,
        "scim_list": SCIM_METHODS,
        "resources_list": RESOURCE_PAGE_METHODS,
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in guarded or len(node.args) < 3:
            continue
        method_node = node.args[2]
        if not isinstance(method_node, ast.Constant) or not isinstance(method_node.value, str):
            problems.append(f"line {node.lineno}: guarded SDK method is not a literal")
        elif method_node.value not in guarded[node.func.id]:
            problems.append(f"line {node.lineno}: blocked SDK method {method_node.value}")
    forbidden = ("create_", "update_", "delete_", "change_", "move_", "upload_", "patch_", "put_", "remove_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")
    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (ia02-01-federation-configuration)")
    print("Only allowlisted generated list/get operations are permitted.")
    print("Client secrets, tokens, SAML metadata XML, raw certificates and recovery data are excluded.")
    return True


def text(item: Any, name: str) -> str:
    value = getattr(item, name, "")
    return "" if value is None else str(value)


def bool_text(value: Any) -> str:
    return "YES" if value is True else "NO" if value is False else "UNKNOWN"


def meta_time(item: Any, name: str) -> str:
    meta = getattr(item, "meta", None)
    return iso(getattr(meta, name, None))


def pipe(values: Iterable[Any]) -> str:
    return "|".join(sorted({str(value) for value in values if value not in (None, "")}))


def pipe_set(value: str) -> Set[str]:
    return {part.strip() for part in value.split("|") if part.strip() and part.strip() != "NONE"}


def nested_ref(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    for name in ("value", "id", "ocid", "name"):
        candidate = text(value, name)
        if candidate:
            return candidate
    return ""


def enum_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return text(value, "value") or text(value, "name") or str(value)


def url_fingerprint(value: str) -> Tuple[str, str]:
    if not value:
        return "", ""
    parsed = urlparse(value)
    host = parsed.hostname or "INVALID-URL"
    return host, stable_hash([value])


def certificate_fingerprint(value: str) -> Tuple[str, str]:
    return ("YES", stable_hash([value])) if value else ("NO", "")


def domain_endpoint(url: str) -> Tuple[str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Identity Domain returned an invalid HTTPS service endpoint")
    if parsed.query or parsed.fragment:
        raise ValueError("Identity Domain endpoint contains an unexpected query or fragment")
    return f"https://{parsed.netloc}{parsed.path.rstrip('/')}", parsed.hostname


def names_filter(value: str) -> Set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def resolve_targets(args: argparse.Namespace, catalog: Sequence[ScopeItem]) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit = sum(bool(value) for value in (args.compartment_id, args.compartment_names, args.tenancy_scope))
    if explicit > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")
    if args.select_scope and explicit:
        raise ValueError("interactive selection cannot be combined with explicit scope")
    if not explicit:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}\n              {item.ocid}")
        print("\nSelecting the tenancy confirms root plus every active discovered compartment.")
        chosen = by_id.get(input("Enter the exact tenancy or compartment OCID to select: ").strip())
        if chosen is None:
            raise ValueError("entered OCID was not discovered")
        if input("Re-enter the exact same OCID: ").strip() != chosen.ocid:
            raise ValueError("second scope confirmation did not match")
        return chosen, list(catalog) if chosen.kind == "TENANCY" else [chosen]
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
        selected = targets[0] if len(targets) == 1 else ScopeItem("MULTIPLE", "explicit compartments", "MULTI-COMPARTMENT")
    else:
        wanted = names_filter(args.compartment_names)
        targets = [item for item in catalog if item.kind == "COMPARTMENT" and item.name.lower() in wanted]
        missing = sorted(wanted - {item.name.lower() for item in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = targets[0] if len(targets) == 1 else ScopeItem("MULTIPLE", args.compartment_names, "MULTI-COMPARTMENT")
    if not args.non_interactive:
        for item in targets:
            first = input(f"Enter the exact OCID for {item.name}: ").strip()
            second = input("Re-enter the exact same OCID: ").strip()
            if first != item.ocid or second != item.ocid:
                raise ValueError(f"scope confirmation failed for {item.name}")
    return selected, targets


def build_plan(args: argparse.Namespace, context: Any, selected: ScopeItem, targets: Sequence[ScopeItem], outputs: Mapping[str, str]) -> str:
    lines = [
        "=" * 70, " IA-2 OKTA/DOJLOGIN FEDERATION PRE-SCAN SAFETY SUMMARY", "=" * 70,
        f"Collector       : {COLLECTOR}", f"Controls        : {CONTROLS}",
        f"Region          : {args.region}", f"Authentication  : {context.auth_label}",
        f"Profile         : {context.profile if args.auth == 'config' else '<not applicable>'}",
        f"Selected scope  : {selected.kind} / {selected.name}", f"Selected OCID   : {selected.ocid}",
        f"Confirmed targets: {len(targets)}",
        "Directory scope : Identity Domains located in the confirmed target compartment(s)",
        "Completion scope: Task 13 completion requires tenancy selection (root plus all active compartments)",
        "Cloud operations: generated Oracle OCI Python SDK list/get methods only",
        "Mutation boundary: no create/update/delete/change/patch/put methods are permitted",
        "Secret boundary : no client secret, token, password, SAML metadata XML, raw certificate, MFA seed or recovery data",
        "Decision boundary: OCI configuration facts are not an authorization or applicability decision",
        "Volume warning  : every active domain's identity providers, apps, policies, rules and MFA settings are paginated",
        "Local files     : private 0600, formula-safe and never overwritten", "", "Confirmed targets:",
    ]
    for item in targets:
        lines.extend([f"  - {item.name}", f"    {item.ocid}"])
    lines.extend(["", "Read-only SDK operations:"])
    lines.extend("  - " + method for method in sorted(SDK_READ_METHODS))
    lines.extend([
        "", "Governance inputs:",
        f"  - Integration register: {args.integration_register or '<not supplied; template generation>'}",
        f"  - Test evidence: {args.test_evidence or '<not supplied; template generation>'}",
        "", "Output files:",
    ])
    lines.extend("  - " + path for path in outputs.values())
    lines.append("=" * 70)
    return "\n".join(lines) + "\n"


def validate_final_approval(args: argparse.Namespace, targets: Sequence[ScopeItem]) -> None:
    if args.non_interactive:
        if sorted(set(args.confirm_scope_ocid)) != sorted(item.ocid for item in targets):
            raise ValueError("automation confirmation OCIDs do not exactly match resolved targets")
        if args.approve_scan != "YES":
            raise ValueError("automation requires exact --approve-scan YES")
        print("Approval mode   : strict automation confirmation accepted")
    elif input("Type exact uppercase YES to start the read-only SDK scan: ").strip() != "YES":
        raise ValueError("operator did not enter exact uppercase YES")


def add_coverage(rows: List[Dict[str, Any]], scope: ScopeItem, operation: str, status: str, count: int, response: Any = None, pages: int = 1, message: str = "") -> None:
    rows.append({
        "scope_name": scope.name, "scope_ocid": scope.ocid, "operation": operation,
        "status": status, "item_count": count, "page_count": pages,
        "request_id": request_id(response) if response is not None else "", "message": message,
    })


def add_error(errors: List[Dict[str, Any]], coverage: List[Dict[str, Any]], scope: ScopeItem, operation: str, exc: Exception) -> None:
    detail = error_record(exc)
    add_coverage(coverage, scope, operation, "FAILED", 0, pages=0, message=detail["message"])
    errors.append({"scope_name": scope.name, "scope_ocid": scope.ocid, "operation": operation, **detail})


def classic_list(oci: Any, client: Any, method: str, scope: ScopeItem, coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], *args: Any, **kwargs: Any) -> List[Any]:
    try:
        items, response = sdk_list(oci, client, method, CLASSIC_METHODS, *args, **kwargs)
        if not isinstance(getattr(response, "data", None), list):
            raise ValueError(f"{method} returned an unexpected response shape")
        add_coverage(coverage, scope, method, "OK" if items else "EMPTY", len(items), response)
        return items
    except Exception as exc:
        add_error(errors, coverage, scope, method, exc)
        return []


def scim_list(oci: Any, client: Any, method: str, scope: ScopeItem, coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], **kwargs: Any) -> List[Any]:
    try:
        items, responses = sdk_scim_list(oci, client, method, SCIM_METHODS, count=1000, **kwargs)
        add_coverage(coverage, scope, method, "OK" if items else "EMPTY", len(items), responses[-1] if responses else None, len(responses))
        return items
    except Exception as exc:
        add_error(errors, coverage, scope, method, exc)
        return []


def resources_list(oci: Any, client: Any, method: str, scope: ScopeItem, coverage: List[Dict[str, Any]], errors: List[Dict[str, Any]], **kwargs: Any) -> List[Any]:
    try:
        items, responses = sdk_resources_page_list(oci, client, method, RESOURCE_PAGE_METHODS, limit=1000, **kwargs)
        add_coverage(coverage, scope, method, "OK" if items else "EMPTY", len(items), responses[-1] if responses else None, len(responses))
        return items
    except Exception as exc:
        add_error(errors, coverage, scope, method, exc)
        return []


def provider_row(domain: Any, item: Any) -> Dict[str, Any]:
    domain_id, native_id = text(domain, "id"), text(item, "id")
    sso_host, sso_hash = url_fingerprint(text(item, "idp_sso_url"))
    lr_host, lr_hash = url_fingerprint(text(item, "logout_request_url"))
    lp_host, lp_hash = url_fingerprint(text(item, "logout_response_url"))
    sign_present, sign_hash = certificate_fingerprint(text(item, "signing_certificate"))
    enc_present, enc_hash = certificate_fingerprint(text(item, "encryption_certificate"))
    row = {
        "provider_key": f"IDP:{domain_id}:{native_id}", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"), "provider_id": native_id,
        "provider_ocid": text(item, "ocid"), "partner_name": text(item, "partner_name"),
        "provider_type": text(item, "type"), "enabled": bool_text(getattr(item, "enabled", None)),
        "shown_on_login_page": bool_text(getattr(item, "shown_on_login_page", None)),
        "sso_url_host": sso_host, "sso_url_sha256": sso_hash,
        "logout_request_url_host": lr_host, "logout_request_url_sha256": lr_hash,
        "logout_response_url_host": lp_host, "logout_response_url_sha256": lp_hash,
        "authn_request_binding": text(item, "authn_request_binding"),
        "logout_binding": text(item, "logout_binding"), "logout_enabled": bool_text(getattr(item, "logout_enabled", None)),
        "signature_hash_algorithm": text(item, "signature_hash_algorithm"), "name_id_format": text(item, "name_id_format"),
        "signing_certificate_present": sign_present, "signing_certificate_sha256": sign_hash,
        "encryption_certificate_present": enc_present, "encryption_certificate_sha256": enc_hash,
        "require_force_authn": bool_text(getattr(item, "require_force_authn", None)),
        "requires_encrypted_assertion": bool_text(getattr(item, "requires_encrypted_assertion", None)),
        "jit_user_provisioning": bool_text(getattr(item, "jit_user_prov_enabled", None)),
        "jit_create_user": bool_text(getattr(item, "jit_user_prov_create_user_enabled", None)),
        "jit_attribute_update": bool_text(getattr(item, "jit_user_prov_attribute_update_enabled", None)),
        "jit_group_assertion": bool_text(getattr(item, "jit_user_prov_group_assertion_attribute_enabled", None)),
        "jit_static_groups": bool_text(getattr(item, "jit_user_prov_group_static_list_enabled", None)),
        "jit_group_assignment_method": text(item, "jit_user_prov_group_assignment_method"),
        "jit_group_mapping_mode": text(item, "jit_user_prov_group_mapping_mode"),
        "jit_group_mapping_count": len(getattr(item, "jit_user_prov_group_mappings", None) or []),
        "jit_assigned_group_count": len(getattr(item, "jit_user_prov_assigned_groups", None) or []),
        "user_mapping_method": text(item, "user_mapping_method"),
        "user_mapping_store_attribute": text(item, "user_mapping_store_attribute"),
        "assertion_attribute": text(item, "assertion_attribute"),
        "requested_authentication_context_count": len(getattr(item, "requested_authentication_context", None) or []),
        "time_created": meta_time(item, "created"), "time_modified": meta_time(item, "last_modified"),
    }
    row["config_sha256"] = stable_hash(row[field] for field in PROVIDER_FIELDS if field != "config_sha256")
    return row


def app_row(domain: Any, item: Any) -> Dict[str, Any]:
    domain_id, native_id = text(domain, "id"), text(item, "id")
    row = {
        "app_key": f"APP:{domain_id}:{native_id}", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"), "app_id": native_id, "app_ocid": text(item, "ocid"),
        "name": text(item, "name"), "display_name": text(item, "display_name"),
        "active": bool_text(getattr(item, "active", None)), "login_mechanism": text(item, "login_mechanism"),
        "is_login_target": bool_text(getattr(item, "is_login_target", None)),
        "is_saml_service_provider": bool_text(getattr(item, "is_saml_service_provider", None)),
        "is_oauth_client": bool_text(getattr(item, "is_o_auth_client", None)),
        "is_managed_app": bool_text(getattr(item, "is_managed_app", None)), "client_type": text(item, "client_type"),
        "allowed_grants": pipe(getattr(item, "allowed_grants", None) or []),
        "allowed_scope_count": len(getattr(item, "allowed_scopes", None) or []),
        "identity_provider_refs": pipe(nested_ref(value) for value in (getattr(item, "identity_providers", None) or [])),
        "app_signon_policy_ref": nested_ref(getattr(item, "app_signon_policy", None)),
        "based_on_template_ref": nested_ref(getattr(item, "based_on_template", None)),
        "saml_service_provider_ref": nested_ref(getattr(item, "saml_service_provider", None)),
        "time_created": meta_time(item, "created"), "time_modified": meta_time(item, "last_modified"),
    }
    row["config_sha256"] = stable_hash(row[field] for field in APP_FIELDS if field != "config_sha256")
    return row


def policy_row(domain: Any, item: Any) -> Dict[str, Any]:
    domain_id, native_id = text(domain, "id"), text(item, "id")
    groovy = text(item, "policy_groovy")
    row = {
        "policy_key": f"POLICY:{domain_id}:{native_id}", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"), "policy_id": native_id, "policy_ocid": text(item, "ocid"),
        "name": text(item, "name"), "active": bool_text(getattr(item, "active", None)),
        "policy_type": enum_value(getattr(item, "policy_type", None)),
        "rule_refs": pipe(nested_ref(value) for value in (getattr(item, "rules", None) or [])),
        "policy_groovy_present": "YES" if groovy else "NO", "policy_groovy_sha256": stable_hash([groovy]) if groovy else "",
        "time_created": meta_time(item, "created"), "time_modified": meta_time(item, "last_modified"),
    }
    row["config_sha256"] = stable_hash(row[field] for field in POLICY_FIELDS if field != "config_sha256")
    return row


def rule_row(domain: Any, item: Any) -> Dict[str, Any]:
    domain_id, native_id = text(domain, "id"), text(item, "id")
    condition, groovy = text(item, "condition"), text(item, "rule_groovy")
    returns = getattr(item, "_return", None) or []
    names = [text(value, "name") for value in returns]
    values = [text(value, "value") for value in returns]
    return_groovy = [text(value, "return_groovy") for value in returns]
    row = {
        "rule_key": f"RULE:{domain_id}:{native_id}", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"), "rule_id": native_id, "rule_ocid": text(item, "ocid"),
        "name": text(item, "name"), "active": bool_text(getattr(item, "active", None)),
        "locked": bool_text(getattr(item, "locked", None)), "policy_type": enum_value(getattr(item, "policy_type", None)),
        "condition_sha256": stable_hash([condition]) if condition else "", "condition_present": "YES" if condition else "NO",
        "return_count": len(returns), "return_names": pipe(names),
        "return_values_sha256": stable_hash(values + return_groovy) if returns else "",
        "rule_groovy_present": "YES" if groovy else "NO", "rule_groovy_sha256": stable_hash([groovy]) if groovy else "",
        "time_created": meta_time(item, "created"), "time_modified": meta_time(item, "last_modified"),
    }
    row["config_sha256"] = stable_hash(row[field] for field in RULE_FIELDS if field != "config_sha256")
    return row


def mfa_row(domain: Any, item: Any) -> Dict[str, Any]:
    domain_id, native_id = text(domain, "id"), text(item, "id")
    row = {
        "factor_setting_key": f"MFA:{domain_id}:{native_id}", "domain_ocid": domain_id,
        "domain_name": text(domain, "display_name"), "setting_id": native_id, "setting_ocid": text(item, "ocid"),
        "mfa_enrollment_type": text(item, "mfa_enrollment_type"), "mfa_enabled_category": text(item, "mfa_enabled_category"),
        "email_enabled": bool_text(getattr(item, "email_enabled", None)), "sms_enabled": bool_text(getattr(item, "sms_enabled", None)),
        "phone_call_enabled": bool_text(getattr(item, "phone_call_enabled", None)), "totp_enabled": bool_text(getattr(item, "totp_enabled", None)),
        "push_enabled": bool_text(getattr(item, "push_enabled", None)), "fido_authenticator_enabled": bool_text(getattr(item, "fido_authenticator_enabled", None)),
        "yubico_otp_enabled": bool_text(getattr(item, "yubico_otp_enabled", None)), "bypass_code_enabled": bool_text(getattr(item, "bypass_code_enabled", None)),
        "security_questions_enabled": bool_text(getattr(item, "security_questions_enabled", None)),
        "hide_backup_factor_enabled": bool_text(getattr(item, "hide_backup_factor_enabled", None)),
        "auto_enroll_email_factor_disabled": bool_text(getattr(item, "auto_enroll_email_factor_disabled", None)),
        "user_enrollment_disabled_factors": pipe(getattr(item, "user_enrollment_disabled_factors", None) or []),
        "time_created": meta_time(item, "created"), "time_modified": meta_time(item, "last_modified"),
    }
    row["config_sha256"] = stable_hash(row[field] for field in MFA_FIELDS if field != "config_sha256")
    return row


def collect(oci: Any, context: Any, identity: Any, targets: Sequence[ScopeItem]) -> Tuple[List[Dict[str, Any]], ...]:
    domains_out: List[Dict[str, Any]] = []
    providers: List[Dict[str, Any]] = []
    apps: List[Dict[str, Any]] = []
    policies: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    factors: List[Dict[str, Any]] = []
    coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    domains: List[Any] = []
    seen_domain_ids: Set[str] = set()
    for target in targets:
        for domain in classic_list(
            oci, identity, "list_domains", target, coverage, errors, target.ocid
        ):
            domain_id = text(domain, "id")
            if domain_id and domain_id in seen_domain_ids:
                continue
            if domain_id:
                seen_domain_ids.add(domain_id)
            domains.append(domain)
    for domain in domains:
        domain_id = text(domain, "id")
        scope = ScopeItem(domain_id, text(domain, "display_name"), "IDENTITY-DOMAIN")
        row = {
            "domain_ocid": domain_id, "display_name": text(domain, "display_name"),
            "compartment_ocid": text(domain, "compartment_id"), "domain_type": text(domain, "type"),
            "home_region": text(domain, "home_region"), "lifecycle_state": text(domain, "lifecycle_state"),
            "time_created": iso(getattr(domain, "time_created", None)), "domain_url_host": "",
            "collection_status": "SKIPPED-INACTIVE", "message": "Inactive domain was not queried",
        }
        if not domain_id:
            add_error(errors, coverage, targets[0], "list_domains", ValueError("domain is missing its OCID"))
            row.update(collection_status="FAILED", message="Stable domain OCID is required")
            domains_out.append(row)
            continue
        if row["lifecycle_state"] != "ACTIVE":
            domains_out.append(row)
            continue
        before = len(errors)
        try:
            endpoint, host = domain_endpoint(text(domain, "url"))
            row["domain_url_host"] = host
            client = build_client(oci, context, "identity_domains", "IdentityDomainsClient", service_endpoint=endpoint)
        except Exception as exc:
            add_error(errors, coverage, scope, "build_identity_domains_client", exc)
            row.update(collection_status="FAILED", message=error_record(exc)["message"])
            domains_out.append(row)
            continue
        domain_providers = scim_list(oci, client, "list_identity_providers", scope, coverage, errors, attributes=(
            "id,ocid,partnerName,type,enabled,shownOnLoginPage,idpSsoUrl,logoutRequestUrl,logoutResponseUrl,"
            "authnRequestBinding,logoutBinding,logoutEnabled,signatureHashAlgorithm,nameIdFormat,signingCertificate,"
            "encryptionCertificate,requireForceAuthn,requiresEncryptedAssertion,jitUserProvEnabled,"
            "jitUserProvCreateUserEnabled,jitUserProvAttributeUpdateEnabled,jitUserProvGroupAssertionAttributeEnabled,"
            "jitUserProvGroupStaticListEnabled,jitUserProvGroupAssignmentMethod,jitUserProvGroupMappingMode,"
            "jitUserProvGroupMappings,jitUserProvAssignedGroups,userMappingMethod,userMappingStoreAttribute,"
            "assertionAttribute,requestedAuthenticationContext,meta"
        ))
        domain_apps = scim_list(oci, client, "list_apps", scope, coverage, errors, attributes=(
            "id,ocid,name,displayName,active,loginMechanism,isLoginTarget,isSamlServiceProvider,isOAuthClient,"
            "isManagedApp,clientType,allowedGrants,allowedScopes,identityProviders,appSignonPolicy,basedOnTemplate,"
            "samlServiceProvider,meta"
        ))
        domain_policies = scim_list(oci, client, "list_policies", scope, coverage, errors, attributes=(
            "id,ocid,name,active,policyType,rules,policyGroovy,meta"
        ))
        domain_rules = scim_list(oci, client, "list_rules", scope, coverage, errors, attributes=(
            "id,ocid,name,active,locked,policyType,condition,return,ruleGroovy,meta"
        ))
        domain_factors = resources_list(oci, client, "list_authentication_factor_settings", scope, coverage, errors, attributes=(
            "id,ocid,mfaEnrollmentType,mfaEnabledCategory,emailEnabled,smsEnabled,phoneCallEnabled,totpEnabled,"
            "pushEnabled,fidoAuthenticatorEnabled,yubicoOtpEnabled,bypassCodeEnabled,securityQuestionsEnabled,"
            "hideBackupFactorEnabled,autoEnrollEmailFactorDisabled,userEnrollmentDisabledFactors,meta"
        ))
        for item, target, convert, label in (
            (domain_providers, providers, provider_row, "identity provider"),
            (domain_apps, apps, app_row, "app"), (domain_policies, policies, policy_row, "policy"),
            (domain_rules, rules, rule_row, "rule"), (domain_factors, factors, mfa_row, "MFA setting"),
        ):
            for value in item:
                if not text(value, "id"):
                    add_error(errors, coverage, scope, "validate_identity_domain_rows", ValueError(f"{label} is missing its stable id"))
                    continue
                target.append(convert(domain, value))
        row["collection_status"] = "OK" if len(errors) == before else "INCOMPLETE"
        row["message"] = "All configured collections completed" if len(errors) == before else "One or more domain collections failed validation"
        domains_out.append(row)
    return domains_out, providers, apps, policies, rules, factors, coverage, errors


def technical_snapshot(rows_by_name: Mapping[str, Sequence[Mapping[str, Any]]]) -> str:
    material = []
    for name in sorted(rows_by_name):
        encoded = json.dumps(list(rows_by_name[name]), sort_keys=True, separators=(",", ":"), default=str)
        material.append(name + ":" + stable_hash([encoded]))
    return stable_hash(material)


def register_template(providers: Sequence[Mapping[str, Any]], snapshot: str, tenancy_id: str) -> List[Dict[str, Any]]:
    source = providers or [{"provider_key": f"NO-PROVIDER:{tenancy_id}", "partner_name": "NONE", "config_sha256": "NONE"}]
    return [{
        "provider_key": row["provider_key"], "provider_partner_name": row.get("partner_name", ""),
        "provider_config_sha256": row.get("config_sha256", "NONE"), "snapshot_sha256": snapshot,
        "disposition": "", "provider_system": "", "integration_role": "",
        "provisioning_mode": "", "selected_app_keys": "NONE", "selected_policy_keys": "NONE",
        "selected_rule_keys": "NONE", "external_config_reference": "", "external_config_sha256": "",
        "mapping_review_status": "", "certificate_review_status": "", "system_owner": "",
        "approver": "", "approval_status": "", "approval_date": "", "authority": "",
        "rationale": "", "evidence_reference": "",
    } for row in source]


def test_template(register_rows: Sequence[Mapping[str, Any]], snapshot: str) -> List[Dict[str, Any]]:
    return [{
        "provider_key": row["provider_key"], "snapshot_sha256": snapshot, "test_type": test,
        "test_result": "", "tested_at": "", "tester": "", "expected_result": "",
        "evidence_reference": "", "exception_reference": "", "approver": "",
        "approval_status": "", "rationale": "",
    } for row in register_rows if row.get("disposition") == "APPLICABLE" for test in sorted(REQUIRED_TESTS)]


def read_rows(path: str, fields: Sequence[str], label: str) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [field for field in fields if field not in (reader.fieldnames or [])]
            if missing:
                raise ValueError(f"{label} is missing columns: {', '.join(missing)}")
            return [{key: (value or "").strip() for key, value in row.items()} for row in reader if any((value or "").strip() for value in row.values())]
    except OSError as exc:
        raise ValueError(f"cannot read {label}: {path}: {exc}") from exc


def valid_date(value: str, label: str, now: datetime) -> Optional[str]:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        if parsed.astimezone(timezone.utc) > now:
            return f"{label} is in the future"
    except ValueError:
        return f"{label} is not ISO-8601"
    return None


def validate_register(rows: Sequence[Mapping[str, str]], providers: Sequence[Mapping[str, Any]], snapshot: str, tenancy_id: str, app_keys: Set[str], policy_keys: Set[str], rule_keys: Set[str], now: datetime) -> Tuple[List[Dict[str, Any]], Set[str], List[str]]:
    expected = {str(row["provider_key"]): row for row in providers}
    if not expected:
        expected = {f"NO-PROVIDER:{tenancy_id}": {"provider_key": f"NO-PROVIDER:{tenancy_id}", "config_sha256": "NONE"}}
    seen: Set[str] = set()
    applicable: Set[str] = set()
    errors: List[str] = []
    results: List[Dict[str, Any]] = []
    for row in rows:
        key = row.get("provider_key", "")
        messages: List[str] = []
        live = expected.get(key)
        if not live:
            messages.append("provider_key is not live in this snapshot")
        elif key in seen:
            messages.append("duplicate provider_key")
        seen.add(key)
        if live and row.get("provider_config_sha256") != str(live.get("config_sha256")):
            messages.append("provider_config_sha256 does not match the live provider")
        if row.get("snapshot_sha256") != snapshot:
            messages.append("snapshot_sha256 does not match")
        disposition = row.get("disposition", "")
        if disposition not in DISPOSITIONS:
            messages.append("disposition must be APPLICABLE or NOT-APPLICABLE")
        if row.get("provider_system") not in PROVIDER_SYSTEMS:
            messages.append("provider_system must be OKTA, DOJLOGIN or OTHER")
        if row.get("provisioning_mode") not in PROVISIONING_MODES:
            messages.append("invalid provisioning_mode")
        for field in ("system_owner", "approver", "authority", "rationale", "evidence_reference"):
            if not row.get(field):
                messages.append(field + " is required")
        if row.get("approval_status") != "APPROVED":
            messages.append("approval_status must be APPROVED")
        if row.get("approval_date"):
            issue = valid_date(row["approval_date"], "approval_date", now)
            if issue:
                messages.append(issue)
        else:
            messages.append("approval_date is required")
        selected_sets = (
            ("selected_app_keys", app_keys), ("selected_policy_keys", policy_keys),
            ("selected_rule_keys", rule_keys),
        )
        for field, live_keys in selected_sets:
            unknown = pipe_set(row.get(field, "")) - live_keys
            if unknown:
                messages.append(f"{field} contains non-live keys: {'|'.join(sorted(unknown))}")
        if disposition == "APPLICABLE":
            applicable.add(key)
            if not row.get("integration_role"):
                messages.append("integration_role is required for applicable providers")
            if row.get("external_config_reference") == "":
                messages.append("external_config_reference is required")
            if not SHA256_RE.fullmatch(row.get("external_config_sha256", "")):
                messages.append("external_config_sha256 must be a lowercase SHA-256")
            if row.get("mapping_review_status") != "APPROVED":
                messages.append("mapping_review_status must be APPROVED")
            if row.get("certificate_review_status") != "APPROVED":
                messages.append("certificate_review_status must be APPROVED")
        elif disposition == "NOT-APPLICABLE":
            if row.get("provisioning_mode") != "NONE":
                messages.append("not-applicable providers require provisioning_mode NONE")
            if any(pipe_set(row.get(field, "")) for field, _ in selected_sets):
                messages.append("not-applicable providers cannot select live app/policy/rule keys")
            if row.get("mapping_review_status") != "NOT-APPLICABLE" or row.get("certificate_review_status") != "NOT-APPLICABLE":
                messages.append("not-applicable review statuses must be NOT-APPLICABLE")
        status = "VALID" if not messages else "INVALID"
        results.append({**row, "validation_status": status, "validation_message": "; ".join(messages)})
        errors.extend(f"{key}: {message}" for message in messages)
    for key in sorted(set(expected) - seen):
        errors.append(f"{key}: missing required provider disposition")
    if len(rows) != len(expected):
        errors.append("integration register must contain exactly one row per discovered provider")
    return results, applicable, errors


def validate_tests(rows: Sequence[Mapping[str, str]], applicable: Set[str], snapshot: str, now: datetime) -> Tuple[List[Dict[str, Any]], List[str]]:
    expected = {(provider, test) for provider in applicable for test in REQUIRED_TESTS}
    seen: Set[Tuple[str, str]] = set()
    errors: List[str] = []
    results: List[Dict[str, Any]] = []
    for row in rows:
        key = (row.get("provider_key", ""), row.get("test_type", ""))
        messages: List[str] = []
        if key not in expected:
            messages.append("provider/test pair is not required for an applicable live provider")
        elif key in seen:
            messages.append("duplicate provider/test pair")
        seen.add(key)
        if row.get("snapshot_sha256") != snapshot:
            messages.append("snapshot_sha256 does not match")
        result = row.get("test_result", "")
        if result not in TEST_RESULTS:
            messages.append("test_result must be PASS, FAIL or NOT-APPLICABLE")
        if result == "FAIL":
            messages.append("failed test remains unresolved")
        if result == "NOT-APPLICABLE" and (not row.get("rationale") or not row.get("evidence_reference")):
            messages.append("NOT-APPLICABLE test requires rationale and evidence")
        for field in ("tested_at", "tester", "expected_result", "evidence_reference", "approver"):
            if not row.get(field):
                messages.append(field + " is required")
        if row.get("approval_status") != "APPROVED":
            messages.append("approval_status must be APPROVED")
        if row.get("tested_at"):
            issue = valid_date(row["tested_at"], "tested_at", now)
            if issue:
                messages.append(issue)
        status = "VALID" if not messages else "INVALID"
        results.append({**row, "validation_status": status, "validation_message": "; ".join(messages)})
        errors.extend(f"{key[0]}/{key[1]}: {message}" for message in messages)
    for key in sorted(expected - seen):
        errors.append(f"{key[0]}/{key[1]}: required test evidence is missing")
    return results, errors


def main(argv: Optional[Sequence[str]] = None, oci_module: Any = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.selfcheck:
        return 0 if source_selfcheck() else 1
    if not args.region or not re.fullmatch(r"[A-Za-z0-9-]+", args.region):
        print("ERROR: one explicit OCI region is required", file=sys.stderr)
        return 1
    try:
        register_input = read_rows(args.integration_register, REGISTER_FIELDS, "integration register") if args.integration_register else []
        test_input = read_rows(args.test_evidence, TEST_FIELDS, "test evidence") if args.test_evidence else []
        if args.test_evidence and not args.integration_register:
            raise ValueError("--test-evidence requires --integration-register")
        oci = oci_module or load_oci()
        context = build_auth_context(oci, args)
        identity = build_client(oci, context, "identity", "IdentityClient")
        catalog = discover_scope(oci, identity, context.tenancy_id, CLASSIC_METHODS)
        selected, targets = resolve_targets(args, catalog)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    now = utc_now()
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(args.output_dir)
    prefix = f"ia02-01_{timestamp}"
    outputs = {name: str(output_dir / f"{prefix}_{suffix}") for name, suffix in {
        "plan": "approved_scan_plan.txt", "domains": "identity_domains.csv",
        "providers": "identity_providers.csv", "apps": "federation_apps.csv",
        "policies": "signon_policies.csv", "rules": "signon_rules.csv",
        "mfa": "authentication_factor_settings.csv", "coverage": "collection_coverage.csv",
        "errors": "collection_errors.csv", "manifest": "snapshot_manifest.csv",
        "register_template": "integration_register_template.csv", "test_template": "test_evidence_template.csv",
        "inputs": "input_sources.csv", "register_validation": "integration_register_validation.csv",
        "test_validation": "test_evidence_validation.csv", "summary": "summary.txt",
    }.items()}
    plan = build_plan(args, context, selected, targets, outputs)
    print(plan, end="")
    try:
        validate_final_approval(args, targets)
    except ValueError as exc:
        print(f"SCAN NOT STARTED: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    collisions = [path for path in outputs.values() if Path(path).exists()]
    if collisions:
        print("SCAN NOT STARTED: output collision; refusing to overwrite evidence:", file=sys.stderr)
        for path in collisions:
            print("  " + path, file=sys.stderr)
        return 1
    output_dir.mkdir(parents=True, exist_ok=True)
    write_private_text(outputs["plan"], plan + "SCAN APPROVED\n")
    domains, providers, apps, policies, rules, factors, coverage, errors = collect(
        oci, context, identity, targets
    )
    write_csv(outputs["domains"], DOMAIN_FIELDS, domains)
    write_csv(outputs["providers"], PROVIDER_FIELDS, providers)
    write_csv(outputs["apps"], APP_FIELDS, apps)
    write_csv(outputs["policies"], POLICY_FIELDS, policies)
    write_csv(outputs["rules"], RULE_FIELDS, rules)
    write_csv(outputs["mfa"], MFA_FIELDS, factors)
    write_csv(outputs["coverage"], COVERAGE_FIELDS, coverage)
    if errors:
        write_csv(outputs["errors"], ERROR_FIELDS, errors)
    configuration_rows = {
        "domains": domains, "providers": providers, "apps": apps,
        "policies": policies, "rules": rules, "mfa": factors,
    }
    # Coverage contains volatile request IDs. Bind approvals only to the stable
    # configuration facts so a reviewed template can validate on a later run.
    snapshot = technical_snapshot(configuration_rows)
    rows_by_name = {**configuration_rows, "coverage": coverage}
    technical_paths = {name: outputs[name] for name in rows_by_name}
    manifest = [{"artifact": name, "path": technical_paths[name], "sha256": sha256_file(technical_paths[name]), "row_count": len(rows_by_name[name])} for name in sorted(technical_paths)]
    write_csv(outputs["manifest"], MANIFEST_FIELDS, manifest)
    seeded_register = register_template(providers, snapshot, context.tenancy_id)
    write_csv(outputs["register_template"], REGISTER_FIELDS, seeded_register)
    register_results: List[Dict[str, Any]] = []
    test_results: List[Dict[str, Any]] = []
    applicable: Set[str] = set()
    governance_errors: List[str] = []
    if register_input:
        register_results, applicable, governance_errors = validate_register(
            register_input, providers, snapshot, context.tenancy_id,
            {str(row["app_key"]) for row in apps}, {str(row["policy_key"]) for row in policies},
            {str(row["rule_key"]) for row in rules}, now,
        )
    elif args.integration_register:
        governance_errors.append("integration register has no data rows")
    else:
        governance_errors.append("approved integration register is required")
    template_source = register_input if register_input else []
    write_csv(outputs["test_template"], TEST_FIELDS, test_template(template_source, snapshot))
    if applicable:
        if test_input:
            test_results, test_errors = validate_tests(test_input, applicable, snapshot, now)
            governance_errors.extend(test_errors)
        else:
            governance_errors.append("test evidence is required for every applicable provider")
    elif test_input:
        test_results, test_errors = validate_tests(test_input, applicable, snapshot, now)
        governance_errors.extend(test_errors)
    write_csv(outputs["register_validation"], RECON_FIELDS, register_results)
    write_csv(outputs["test_validation"], TEST_RESULT_FIELDS, test_results)
    input_rows = []
    for label, path, rows in (
        ("INTEGRATION-REGISTER", args.integration_register, register_input),
        ("TEST-EVIDENCE", args.test_evidence, test_input),
    ):
        if path:
            input_rows.append({"input_type": label, "path": path, "sha256": sha256_file(path), "row_count": len(rows)})
    write_csv(outputs["inputs"], INPUT_FIELDS, input_rows)
    collection_complete = not errors and all(row.get("status") in {"OK", "EMPTY"} for row in coverage)
    tenancy_complete = selected.kind == "TENANCY"
    governance_complete = bool(args.integration_register and not governance_errors and register_results and all(row["validation_status"] == "VALID" for row in register_results) and (not applicable or (args.test_evidence and test_results and all(row["validation_status"] == "VALID" for row in test_results))))
    status = "COMPLETE" if collection_complete and tenancy_complete and governance_complete else "INCOMPLETE"
    summary = "\n".join([
        "IA02-01 Federation Configuration Summary", "========================================",
        f"Region                    : {args.region}", f"Selected scope            : {selected.kind} / {selected.name}",
        f"Directory collection       : {'TENANCY-WIDE' if tenancy_complete else 'SELECTED-COMPARTMENT-ONLY'}",
        f"Confirmed targets         : {len(targets)}",
        f"Collected                 : {iso(now)}", f"OCI SDK version           : {getattr(oci, '__version__', '<unknown>')}",
        f"Identity domains          : {len(domains)}", f"Identity providers        : {len(providers)}",
        f"Apps                      : {len(apps)}", f"Policies                  : {len(policies)}",
        f"Rules                     : {len(rules)}", f"MFA settings              : {len(factors)}",
        f"Collection errors         : {len(errors)}", f"Applicable providers      : {len(applicable)}",
        f"Governance errors         : {len(governance_errors)}", f"Snapshot SHA-256          : {snapshot}",
        f"Evidence result           : {status}",
        "Decision note             : technical OCI facts alone are not an authorization, compliance or N/A decision",
    ]) + "\n"
    if governance_errors:
        summary += "\nGovernance blockers:\n" + "\n".join("- " + value for value in governance_errors) + "\n"
    write_private_text(outputs["summary"], summary)
    print(summary, end="")
    if not collection_complete:
        return 2
    return 0 if tenancy_complete and governance_complete else 3


if __name__ == "__main__":
    raise SystemExit(main())
