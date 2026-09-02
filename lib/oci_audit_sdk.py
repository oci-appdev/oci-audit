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
            "'python3 -m pip install -r requirements-oci-sdk.txt'."
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
    return {
        "http_status": getattr(exc, "status", ""),
        "service_code": getattr(exc, "code", type(exc).__name__),
        "request_id": getattr(exc, "opc_request_id", ""),
        "message": message[:2000],
    }
