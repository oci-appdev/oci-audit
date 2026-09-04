#!/usr/bin/env python3
"""Shared, read-only helpers for OCI Python SDK audit collectors."""

from __future__ import annotations

import csv
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class AuthContext:
    config: Dict[str, Any]
    signer: Any
    tenancy_id: str
    auth_label: str
    profile: str


@dataclass(frozen=True)
class ScopeItem:
    ocid: str
    name: str
    kind: str


def load_oci() -> Any:
    try:
        import oci  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "Oracle OCI Python SDK is required. Install the pinned dependency with "
            "'python3 -m pip install -r ra05-01/requirements-oci-sdk.txt'."
        ) from exc
    return oci


def build_auth_context(oci: Any, args: Any) -> AuthContext:
    if args.auth == "config":
        config_path = str(Path(args.config_file).expanduser())
        config = dict(oci.config.from_file(config_path, args.profile))
        config["region"] = args.region
        oci.config.validate_config(config)
        tenancy_id = str(config.get("tenancy", ""))
        signer = None
        label = "CONFIG-PROFILE"
    elif args.auth == "instance-principal":
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        config = {"region": args.region}
        tenancy_id = str(getattr(signer, "tenancy_id", ""))
        label = "INSTANCE-PRINCIPAL"
    elif args.auth == "resource-principal":
        signer = oci.auth.signers.get_resource_principals_signer()
        config = {"region": args.region}
        tenancy_id = str(getattr(signer, "tenancy_id", ""))
        label = "RESOURCE-PRINCIPAL"
    else:
        raise ValueError("unsupported authentication mode")

    if not tenancy_id.startswith("ocid1.tenancy."):
        raise ValueError("authenticated tenancy OCID could not be resolved")
    return AuthContext(config, signer, tenancy_id, label, args.profile)


def build_client(oci: Any, context: AuthContext, namespace: str, class_name: str) -> Any:
    module = getattr(oci, namespace)
    client_class = getattr(module, class_name)
    kwargs: Dict[str, Any] = {"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY}
    if context.signer is not None:
        kwargs["signer"] = context.signer
    return client_class(context.config, **kwargs)


def _check_method(method_name: str, allowed_methods: Set[str], prefix: str) -> None:
    if method_name not in allowed_methods or not method_name.startswith(prefix):
        raise RuntimeError("blocked SDK method outside the read-only allowlist: " + method_name)


def response_items(response: Any) -> List[Any]:
    data = getattr(response, "data", None)
    if data is None:
        return []
    if isinstance(data, list):
        return data
    items = getattr(data, "items", None)
    if items is None and isinstance(data, Mapping):
        items = data.get("items")
    return list(items or [])


def sdk_list(
    oci: Any,
    client: Any,
    method_name: str,
    allowed_methods: Set[str],
    *args: Any,
    **kwargs: Any,
) -> Tuple[List[Any], Any]:
    _check_method(method_name, allowed_methods, "list_")
    method = getattr(client, method_name)
    response = oci.pagination.list_call_get_all_results(
        method,
        *args,
        retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
        **kwargs,
    )
    return response_items(response), response


def sdk_list_items(
    oci: Any,
    client: Any,
    method_name: str,
    allowed_methods: Set[str],
    *args: Any,
    **kwargs: Any,
) -> List[Any]:
    """sdk_list when only the items are wanted.

    sdk_list returns (items, response) because the error ledger needs the
    response for its opc-request-id. Assigning that tuple to one name yields a
    two-element list that iterates as [items, response] and reports len() == 2 —
    a silent miscount, not a crash. Callers that do not need the response should
    use this instead.
    """
    items, _ = sdk_list(oci, client, method_name, allowed_methods, *args, **kwargs)
    return items


def sdk_get(
    oci: Any,
    client: Any,
    method_name: str,
    allowed_methods: Set[str],
    *args: Any,
    **kwargs: Any,
) -> Any:
    _check_method(method_name, allowed_methods, "get_")
    method = getattr(client, method_name)
    return method(*args, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY, **kwargs)


def discover_scope(
    oci: Any,
    identity_client: Any,
    tenancy_id: str,
    allowed_methods: Set[str],
) -> List[ScopeItem]:
    tenancy_response = sdk_get(
        oci, identity_client, "get_compartment", allowed_methods, tenancy_id
    )
    tenancy_data = getattr(tenancy_response, "data", None)
    tenancy_name = str(getattr(tenancy_data, "name", "root") or "root")
    compartments, _ = sdk_list(
        oci,
        identity_client,
        "list_compartments",
        allowed_methods,
        tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ANY",
        lifecycle_state="ACTIVE",
    )
    catalog = [ScopeItem(tenancy_id, tenancy_name, "TENANCY")]
    for item in compartments:
        ocid = str(getattr(item, "id", ""))
        if ocid.startswith("ocid1.compartment."):
            catalog.append(ScopeItem(ocid, str(getattr(item, "name", "")), "COMPARTMENT"))
    return [catalog[0]] + sorted(catalog[1:], key=lambda row: (row.name.lower(), row.ocid))


def iso(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stable_hash(parts: Iterable[Any]) -> str:
    material = "\x1f".join("" if part is None else str(part) for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_cell(value: Any) -> Any:
    if value is None:
        return ""
    if not isinstance(value, str):
        return value
    cleaned = value.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    if cleaned[:1] in {"=", "+", "-", "@", "\t"}:
        return "'" + cleaned
    return cleaned


def write_csv(path: str, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: safe_cell(row.get(field, "")) for field in fieldnames})
    os.chmod(target, 0o600)


def write_private_text(path: str, text: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    os.chmod(target, 0o600)


def request_id(response: Any) -> str:
    headers = getattr(response, "headers", {}) or {}
    if isinstance(headers, Mapping):
        return str(headers.get("opc-request-id", headers.get("opc-request-id".title(), "")))
    return ""


def error_record(exc: Exception) -> Dict[str, Any]:
    message = str(getattr(exc, "message", "") or str(exc)).replace("\r", " ").replace("\n", " ")
    message = re.sub(
        r"(?i)(token|secret|password|private[-_ ]?key)([=: ]+)([^ ]+)",
        r"\1\2<redacted>",
        message,
    )
    status = getattr(exc, "status", "")
    code = str(getattr(exc, "code", "") or type(exc).__name__)

    # "We were refused" and "the call broke" are different evidence. Collapsing
    # both to ERROR loses the distinction an auditor reads the coverage ledger
    # for, so classify explicitly. Ledger.failed puts this in the coverage row.
    if status in (401, 403, "401", "403") or code in (
            "NotAuthenticated", "NotAuthorized", "NotAuthorizedOrNotFound"):
        classification = "DENIED"
    elif status in (404, "404"):
        classification = "NOT-FOUND"
    elif status in (429, "429"):
        classification = "THROTTLED"
    elif isinstance(status, int) and status >= 500:
        classification = "SERVICE-ERROR"
    else:
        classification = "ERROR"

    # Real oci.exceptions.ServiceError exposes request_id; some wrappers carry
    # opc_request_id or only the raw header. Take whichever is present rather
    # than silently writing an empty column into the error ledger.
    headers = getattr(exc, "headers", None) or {}
    opc = (getattr(exc, "request_id", "")
           or getattr(exc, "opc_request_id", "")
           or (headers.get("opc-request-id", "") if isinstance(headers, Mapping) else ""))

    return {
        "status": classification,
        "http_status": status,
        "service_code": code,
        "request_id": opc,
        "message": message[:2000],
    }


# ---------------------------------------------------------------------------
# Shared collector framework
#
# Every SDK collector needs the same scope-confirmation gate, the same
# failure-aware coverage ledger and the same self-check. In the Bash
# generation each collector reimplemented these, and they drifted: five of the
# nine shipped without the strict automation contract at all until it was
# retrofitted. Putting them here means a new collector inherits the contract
# instead of re-deriving it.
# ---------------------------------------------------------------------------


class ScanRefused(Exception):
    """Operator or automation did not authorise the scan. Nothing was collected."""


def add_standard_arguments(parser: Any) -> Any:
    """The scope, auth and approval interface every collector must expose."""
    # Not argparse-required: --selfcheck must run without a region so the test
    # suite can prove the read-only allowlist without any scope or credentials.
    # validate_argument_combination enforces it for every real collection.
    parser.add_argument("-r", "--region", default="",
                        help="explicit region; a CLI default is not acceptable evidence provenance")
    parser.add_argument("-o", "--output-dir", default=".")
    parser.add_argument("-c", "--compartment-id", action="append", default=[])
    parser.add_argument("-n", "--compartment-names", default="")
    parser.add_argument("--auth", choices=("config", "instance-principal", "resource-principal"),
                        default="config")
    parser.add_argument("-p", "--profile", default="DEFAULT")
    parser.add_argument("--config-file", default="~/.oci/config")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--confirm-scope-ocid", action="append", default=[])
    parser.add_argument("--approve-scan", default="")
    parser.add_argument("--selfcheck", action="store_true")
    return parser


VALID_REGION_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")


def validate_argument_combination(args: Any) -> None:
    """-c/-n select a scope; they are not evidence that a scan was approved."""
    region = getattr(args, "region", "") or ""
    if not region or any(char not in VALID_REGION_CHARS for char in region):
        raise ValueError("one explicit OCI region is required (-r/--region)")
    if not args.non_interactive and (args.confirm_scope_ocid or args.approve_scan):
        raise ValueError("--confirm-scope-ocid and --approve-scan require --non-interactive")
    if args.non_interactive and not (args.compartment_id or args.compartment_names):
        raise ValueError("--non-interactive requires an explicit -c or -n scope")
    if args.compartment_id and args.compartment_names:
        raise ValueError("-c and -n are mutually exclusive scope modes")


def confirm_targets_interactively(targets: Sequence[ScopeItem]) -> None:
    """Every resolved target OCID, entered exactly, twice."""
    print("\nResolved scope requires interactive OCID confirmation.")
    for item in targets:
        print(f"\nTarget: {item.name}\nOCID  : {item.ocid}")
        first = input("Enter this exact OCID to select the target: ").strip()
        if first != item.ocid:
            raise ScanRefused(f"scope OCID did not match {item.ocid}")
        second = input("Re-enter the exact same OCID to confirm: ").strip()
        if second != item.ocid:
            raise ScanRefused(f"scope confirmation did not match {item.ocid}")
    print("\nAll resolved target OCIDs were confirmed twice.")


def require_final_approval(args: Any, targets: Sequence[ScopeItem]) -> None:
    """Exact uppercase YES, or a fully matching automation confirmation set."""
    if args.non_interactive:
        expected = sorted(item.ocid for item in targets)
        supplied = sorted(set(args.confirm_scope_ocid))
        if supplied != expected:
            raise ScanRefused(
                f"automation supplied {len(supplied)} scope confirmations; "
                f"expected exactly {expected}")
        if args.approve_scan != "YES":
            raise ScanRefused("automation did not supply exact --approve-scan YES")
        print("Approval mode   : strict automation confirmation accepted\n")
        return
    approval = input("Type exact uppercase YES to start the read-only SDK scan: ").strip()
    if approval != "YES":
        raise ScanRefused("operator did not enter exact uppercase YES")
    print("SCAN APPROVED: starting read-only SDK collection.\n")


def print_scan_plan(heading: str, collector: str, controls: str, args: Any,
                    context: AuthContext, selected: ScopeItem,
                    targets: Sequence[ScopeItem], methods: Iterable[str],
                    outputs: Iterable[str], evidence_note: str) -> None:
    print("=" * 70)
    print(f" {heading} PRE-SCAN SAFETY SUMMARY")
    print("=" * 70)
    print(f"Collector       : {collector}")
    print(f"Controls        : {controls}")
    print(f"Region          : {args.region}")
    print(f"Authentication  : {context.auth_label}")
    print(f"Profile         : {context.profile if args.auth == 'config' else '<not applicable>'}")
    print(f"Scope type      : {selected.kind}")
    print(f"Scope name      : {selected.name}")
    print(f"Selected OCID   : {selected.ocid}")
    print(f"Compartments    : {len(targets)}")
    print("Cloud operations: Oracle OCI Python SDK list/get methods only")
    print("Mutation boundary: no create/update/delete/change/move method is permitted")
    print("Pagination      : oci.pagination.list_call_get_all_results")
    print("Retries         : oci.retry.DEFAULT_RETRY_STRATEGY")
    print(f"Evidence data   : {evidence_note}")
    print("\nTarget compartments:")
    for item in targets:
        print(f"  - {item.name}\n    {item.ocid}")
    print("\nRead-only SDK operations:")
    for method in sorted(methods):
        print("  - " + method)
    print("\nOutput files:")
    for path in outputs:
        print("  - " + path)
    print("=" * 70)


class Ledger:
    """Coverage and error ledgers, plus the incomplete flag that drives exit 3.

    Rule 3 of AGENTS.md in code form: a failed or ambiguous call becomes a
    non-OK coverage row and a retained error, never an empty result that reads
    as a clean negative finding.
    """

    def __init__(self) -> None:
        self.coverage: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.incomplete = False

    def ok(self, target: ScopeItem, service: str, count: int) -> None:
        self.coverage.append({
            "compartment_ocid": target.ocid, "compartment_name": target.name,
            "service": service, "assets_found": count,
            "collection_status": "OK", "collection_error": "",
        })

    def failed(self, target: ScopeItem, service: str, exc: Exception) -> Dict[str, Any]:
        record = error_record(exc)
        self.incomplete = True
        self.coverage.append({
            "compartment_ocid": target.ocid, "compartment_name": target.name,
            "service": service, "assets_found": "UNKNOWN",
            "collection_status": record.get("status", "ERROR"),
            "collection_error": record.get("message", ""),
        })
        self.errors.append({
            "compartment_ocid": target.ocid, "compartment_name": target.name,
            "service": service, **record,
        })
        return record

    def exit_code(self) -> int:
        return 3 if self.incomplete else 0


def selfcheck_allowlist(methods: Iterable[str], label: str) -> bool:
    """Every declared SDK method must be a read, and none may return secrets.

    SECRET_SDK_METHODS mirrors tests/test-readonly-proof.sh: read-only is not
    the same as safe to write into an evidence file, and this repo is public.
    """
    methods = set(methods)
    if not methods:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED ({label}) — empty allowlist", file=__import__("sys").stderr)
        return False
    bad = sorted(m for m in methods
                 if not (m.startswith("list_") or m.startswith("get_") or m.startswith("search_")))
    if bad:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED ({label}) — not reads: {bad}",
              file=__import__("sys").stderr)
        return False
    secret = sorted(methods & SECRET_SDK_METHODS)
    if secret:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED ({label}) — returns credential material: {secret}",
              file=__import__("sys").stderr)
        return False
    return True


SECRET_SDK_METHODS: Set[str] = {
    "get_api_key", "list_api_keys", "search_api_keys",
    "get_auth_token", "list_auth_tokens", "search_auth_tokens",
    "get_customer_secret_key", "list_customer_secret_keys", "search_customer_secret_keys",
    "get_identity_propagation_trust", "list_identity_propagation_trusts",
    "get_o_auth2_client_credential", "list_o_auth2_client_credentials",
    "get_o_auth_client_certificate", "list_o_auth_client_certificates",
    "get_o_auth_partner_certificate", "list_o_auth_partner_certificates",
    "get_smtp_credential", "list_smtp_credentials",
    "get_user_db_credential", "list_user_db_credentials",
    "get_secret_bundle", "get_secret_bundle_by_name",
    "get_windows_instance_initial_credentials", "get_console_history_content",
    "get_autonomous_database_wallet", "get_autonomous_database_regional_wallet",
    "get_user_ui_password_information", "list_swift_passwords", "list_db_credentials",
}


# ---------------------------------------------------------------------------
# Shared scope resolution.
#
# SCRIPT-DESIGN-STANDARD.md steps 3-6: display the discovered catalog, take an
# exact OCID, take it again. Steps 7-8 (plan, then exact YES) happen in the
# collector after this returns, in that order. Printing the plan before the
# double-OCID entry inverts the standard and is a review finding, not a style
# preference.
# ---------------------------------------------------------------------------


def names_filter(raw: str) -> Set[str]:
    return {part.strip().lower() for part in str(raw or "").split(",") if part.strip()}


def resolve_scope(args: Any, catalog: Sequence[ScopeItem]) -> Tuple[ScopeItem, List[ScopeItem], bool]:
    """Return (selected, targets, already_confirmed).

    ``already_confirmed`` is True only for the interactive catalog path, whose
    selection *is* the double-OCID entry. Every other path returns False so the
    caller still runs confirm_targets_interactively; -c/-n select a scope and
    never stand in for confirming one.
    """
    if not catalog:
        raise ValueError("scope discovery returned no compartments")
    by_id = {item.ocid: item for item in catalog}

    if args.compartment_id and args.compartment_names:
        raise ValueError("-c and -n are mutually exclusive scope modes")

    if not (args.compartment_id or args.compartment_names):
        if args.non_interactive:
            raise ValueError("--non-interactive requires an explicit -c or -n scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}")
            print(f"              {item.ocid}")
        print("\nSelecting the tenancy scans the root plus every active "
              "discovered compartment.")
        entered = input("Enter the exact tenancy or compartment OCID to select: ").strip()
        selected = by_id.get(entered)
        if selected is None:
            raise ScanRefused("entered OCID was not discovered")
        print(f"\nResolved: {selected.kind} / {selected.name}\nOCID    : {selected.ocid}")
        if input("Re-enter the exact same OCID: ").strip() != selected.ocid:
            raise ScanRefused("second scope confirmation did not match")
        targets = list(catalog) if selected.kind == "TENANCY" else [selected]
        return selected, targets, True

    if args.compartment_id:
        targets: List[ScopeItem] = []
        for ocid in args.compartment_id:
            item = by_id.get(ocid)
            if item is None or item.kind != "COMPARTMENT":
                raise ValueError(f"compartment OCID was not discovered: {ocid}")
            if item not in targets:
                targets.append(item)
        label = "explicit compartments" if len(targets) > 1 else targets[0].name
    else:
        wanted = names_filter(args.compartment_names)
        targets = [item for item in catalog
                   if item.kind == "COMPARTMENT" and item.name.lower() in wanted]
        missing = sorted(wanted - {item.name.lower() for item in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        label = args.compartment_names

    if not targets:
        raise ValueError("no target compartments resolved")
    selected = ScopeItem(
        "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
        label,
        "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT",
    )
    return selected, targets, False
