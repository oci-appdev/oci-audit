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


def build_client(
    oci: Any,
    context: AuthContext,
    namespace: str,
    class_name: str,
    *,
    service_endpoint: Optional[str] = None,
) -> Any:
    module = getattr(oci, namespace)
    client_class = getattr(module, class_name)
    kwargs: Dict[str, Any] = {"retry_strategy": oci.retry.DEFAULT_RETRY_STRATEGY}
    if context.signer is not None:
        kwargs["signer"] = context.signer
    if service_endpoint is not None:
        kwargs["service_endpoint"] = service_endpoint
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


def sdk_scim_list(
    oci: Any,
    client: Any,
    method_name: str,
    allowed_methods: Set[str],
    *,
    count: int = 1000,
    **kwargs: Any,
) -> Tuple[List[Any], List[Any]]:
    """Collect an Identity Domains SCIM list using its generated SDK model.

    Identity Domains list responses use SCIM ``startIndex``, ``itemsPerPage``
    and ``totalResults`` instead of OCI's normal ``opc-next-page`` header.  The
    generated client and retry strategy are still used for every request; this
    helper only advances the protocol-defined start index and validates that a
    truncated or malformed page cannot be mistaken for a complete inventory.
    """

    _check_method(method_name, allowed_methods, "list_")
    if count < 1 or count > 1000:
        raise ValueError("SCIM page count must be between 1 and 1000")
    method = getattr(client, method_name)
    items: List[Any] = []
    responses: List[Any] = []
    start_index = 1
    expected_total: Optional[int] = None

    while True:
        response = method(
            start_index=start_index,
            count=count,
            retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
            **kwargs,
        )
        data = getattr(response, "data", None)
        resources = getattr(data, "resources", None)
        total = getattr(data, "total_results", None)
        page_start = getattr(data, "start_index", None)
        per_page = getattr(data, "items_per_page", None)
        if data is None or resources is None or not isinstance(total, int) or total < 0:
            raise ValueError(f"{method_name} returned a malformed SCIM list response")
        if page_start is not None and page_start != start_index:
            raise ValueError(f"{method_name} returned an unexpected SCIM start index")
        page_items = list(resources)
        if expected_total is None:
            expected_total = total
        elif total != expected_total:
            raise ValueError(f"{method_name} changed totalResults during pagination")
        responses.append(response)
        items.extend(page_items)
        if len(items) >= total:
            if len(items) != total:
                raise ValueError(f"{method_name} returned more SCIM resources than totalResults")
            return items, responses
        advance = per_page if isinstance(per_page, int) and per_page > 0 else len(page_items)
        if not page_items or advance < len(page_items):
            raise ValueError(f"{method_name} returned an incomplete SCIM page")
        start_index += advance


def sdk_resources_page_list(
    oci: Any,
    client: Any,
    method_name: str,
    allowed_methods: Set[str],
    *,
    limit: int = 1000,
    **kwargs: Any,
) -> Tuple[List[Any], List[Any]]:
    """Collect a generated SDK list whose model uses ``resources`` and headers.

    Some Identity Domains endpoints expose normal OCI ``page``/``limit``
    parameters but return a SCIM-shaped model with ``resources`` instead of
    ``items``.  Oracle's generic pagination helper cannot combine those two
    shapes.  This guard calls only the allowlisted generated method, follows
    the generated response's next-page token, and rejects malformed or looping
    pagination so partial evidence cannot look complete.
    """

    _check_method(method_name, allowed_methods, "list_")
    if limit < 1 or limit > 1000:
        raise ValueError("resource page limit must be between 1 and 1000")
    method = getattr(client, method_name)
    items: List[Any] = []
    responses: List[Any] = []
    page: Optional[str] = None
    seen_pages: Set[str] = set()

    while True:
        call_kwargs = dict(kwargs)
        call_kwargs["limit"] = limit
        if page is not None:
            call_kwargs["page"] = page
        response = method(
            retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY,
            **call_kwargs,
        )
        data = getattr(response, "data", None)
        resources = getattr(data, "resources", None)
        if data is None or resources is None:
            raise ValueError(f"{method_name} returned a malformed resources list response")
        try:
            page_items = list(resources)
        except TypeError as exc:
            raise ValueError(
                f"{method_name} returned a non-iterable resources collection"
            ) from exc
        items.extend(page_items)
        responses.append(response)

        next_page = getattr(response, "next_page", None)
        if not next_page:
            headers = getattr(response, "headers", {}) or {}
            if isinstance(headers, Mapping):
                next_page = headers.get("opc-next-page") or headers.get("Opc-Next-Page")
        if not next_page:
            return items, responses
        next_page = str(next_page)
        if next_page in seen_pages or next_page == page:
            raise ValueError(f"{method_name} returned a repeated next-page token")
        seen_pages.add(next_page)
        page = next_page


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
