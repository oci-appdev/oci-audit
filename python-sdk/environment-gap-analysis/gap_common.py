#!/usr/bin/env python3
"""Shared safety, scope and evidence helpers for environment gap analysis."""

from __future__ import annotations

import argparse
import ast
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parents[1]
sys.path.insert(0, str(REPO_ROOT / "lib"))

from oci_audit_sdk import (  # noqa: E402
    AuthContext,
    build_auth_context,
    build_client,
    error_record,
    load_oci,
    request_id,
    sdk_get,
    sdk_list,
    sha256_file,
    utc_now,
    write_csv,
    write_private_text,
)


@dataclass(frozen=True)
class ScopeItem:
    ocid: str
    name: str
    kind: str
    parent_ocid: str = ""


IDENTITY_SCOPE_METHODS: Set[str] = {"get_compartment", "list_compartments"}
COVERAGE_FIELDS = [
    "scope_name",
    "scope_ocid",
    "service",
    "operation",
    "status",
    "item_count",
    "pagination",
    "request_id",
    "message",
]
ERROR_FIELDS = [
    "scope_name",
    "scope_ocid",
    "service",
    "operation",
    "http_status",
    "service_code",
    "request_id",
    "message",
]


def discover_scope(
    oci: Any,
    identity_client: Any,
    tenancy_id: str,
    allowed_methods: Set[str],
) -> List[ScopeItem]:
    """Discover active compartments while retaining the hierarchy."""
    tenancy_response = sdk_get(
        oci,
        identity_client,
        "get_compartment",
        allowed_methods,
        tenancy_id,
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
            catalog.append(
                ScopeItem(
                    ocid,
                    str(getattr(item, "name", "")),
                    "COMPARTMENT",
                    str(getattr(item, "compartment_id", "") or ""),
                )
            )
    return [catalog[0]] + sorted(
        catalog[1:], key=lambda row: (row.name.lower(), row.ocid)
    )
MANIFEST_FIELDS = ["artifact", "path", "sha256", "row_count"]


def add_common_arguments(
    parser: argparse.ArgumentParser,
    *,
    allowed_work: Sequence[str],
    default_work: Sequence[str],
) -> None:
    parser.add_argument("-r", "--region")
    parser.add_argument("-o", "--output-dir", default=".")
    parser.add_argument("-p", "--profile", default="DEFAULT")
    parser.add_argument("--config-file", default="~/.oci/config")
    parser.add_argument(
        "--auth",
        choices=("config", "instance-principal", "resource-principal"),
        default="config",
    )
    parser.add_argument("-i", "--select-scope", action="store_true")
    parser.add_argument("-c", "--compartment-id", action="append", default=[])
    parser.add_argument("-n", "--compartment-names", default="")
    parser.add_argument("--tenancy-scope", action="store_true")
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--confirm-scope-ocid", action="append", default=[])
    parser.add_argument("--approve-scan", default="")
    parser.add_argument(
        "-s",
        "--services",
        default=" ".join(default_work),
        help="space- or comma-separated subset: " + ", ".join(allowed_work),
    )
    parser.add_argument("--selfcheck", action="store_true")


def parse_work(value: str, allowed: Sequence[str]) -> List[str]:
    selected = [part for part in value.replace(",", " ").split() if part]
    if not selected:
        raise ValueError("at least one service or phase must be selected")
    unknown = sorted(set(selected) - set(allowed))
    if unknown:
        raise ValueError("unsupported service or phase: " + ", ".join(unknown))
    return list(dict.fromkeys(selected))


def source_selfcheck(
    script_path: Path,
    collector: str,
    allowed_methods: Set[str],
) -> bool:
    problems: List[str] = []
    if any(not name.startswith(("list_", "get_")) for name in allowed_methods):
        problems.append("SDK allowlist contains a non-list/get method")
    for path in (
        script_path,
        THIS_DIR / "gap_common.py",
        REPO_ROOT / "lib" / "oci_audit_sdk.py",
    ):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError) as exc:
            problems.append(f"cannot parse {path}: {exc}")
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules: List[str] = []
                if isinstance(node, ast.Import):
                    modules = [alias.name for alias in node.names]
                elif node.module:
                    modules = [node.module]
                if any(
                    module == "subprocess" or module.startswith("subprocess.")
                    for module in modules
                ):
                    problems.append(
                        f"{path.name}:{node.lineno}: subprocess is forbidden"
                    )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr.startswith(
                    (
                        "create_",
                        "update_",
                        "delete_",
                        "change_",
                        "move_",
                        "upload_",
                        "put_",
                        "patch_",
                        "remove_",
                        "restore_",
                        "enable_",
                        "disable_",
                        "rotate_",
                        "invoke_",
                    )
                ):
                    problems.append(
                        f"{path.name}:{node.lineno}: mutating-style call "
                        f"{node.func.attr}"
                    )
                if path == script_path and node.func.attr in {
                    "list_items",
                    "get_item",
                }:
                    if len(node.args) < 4:
                        problems.append(
                            f"{path.name}:{node.lineno}: guarded SDK call has no "
                            "literal method"
                        )
                    else:
                        method_node = node.args[3]
                        if (
                            isinstance(method_node, ast.Constant)
                            and isinstance(method_node.value, str)
                            and method_node.value not in allowed_methods
                        ):
                            problems.append(
                                f"{path.name}:{node.lineno}: blocked SDK method "
                                f"{method_node.value}"
                            )
    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print(f"READ-ONLY SDK SELF-CHECK: PASSED ({collector})")
    print(
        "Only allowlisted generated Oracle OCI Python SDK list/get operations are "
        "permitted."
    )
    print(
        "The collector does not import subprocess, call OCI CLI, or invoke custom "
        "REST APIs."
    )
    return True


def _names_filter(value: str) -> Set[str]:
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def resolve_targets(
    args: argparse.Namespace,
    catalog: Sequence[ScopeItem],
) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit = sum(
        bool(value)
        for value in (args.compartment_id, args.compartment_names, args.tenancy_scope)
    )
    if explicit > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")
    if args.select_scope and explicit:
        raise ValueError("--select-scope cannot be combined with an explicit scope")

    if not explicit:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}\n              {item.ocid}")
        print(
            "\nSelecting the tenancy includes root and every active discovered "
            "compartment."
        )
        entered = input(
            "Enter the exact tenancy or compartment OCID to select: "
        ).strip()
        selected = by_id.get(entered)
        if selected is None:
            raise ValueError("entered OCID was not discovered")
        if input("Re-enter the exact same OCID: ").strip() != selected.ocid:
            raise ValueError("second scope confirmation did not match")
        return selected, list(catalog) if selected.kind == "TENANCY" else [selected]

    if args.tenancy_scope:
        selected = catalog[0]
        targets = list(catalog)
    elif args.compartment_id:
        targets = []
        for ocid in args.compartment_id:
            item = by_id.get(ocid)
            if item is None or item.kind != "COMPARTMENT":
                raise ValueError(f"compartment OCID was not discovered: {ocid}")
            if item not in targets:
                targets.append(item)
        selected = (
            targets[0]
            if len(targets) == 1
            else ScopeItem("MULTIPLE", "explicit compartments", "MULTI-COMPARTMENT")
        )
    else:
        wanted = _names_filter(args.compartment_names)
        targets = [
            item
            for item in catalog
            if item.kind == "COMPARTMENT" and item.name.lower() in wanted
        ]
        missing = sorted(wanted - {item.name.lower() for item in targets})
        if missing:
            raise ValueError(
                "compartment names were not discovered: " + ", ".join(missing)
            )
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = (
            targets[0]
            if len(targets) == 1
            else ScopeItem("MULTIPLE", args.compartment_names, "MULTI-COMPARTMENT")
        )

    if not args.non_interactive:
        confirmation_targets = [selected] if args.tenancy_scope else targets
        for item in confirmation_targets:
            if input(f"Enter the exact OCID for {item.name}: ").strip() != item.ocid:
                raise ValueError(f"first scope confirmation failed for {item.name}")
            if input("Re-enter the exact same OCID: ").strip() != item.ocid:
                raise ValueError(f"second scope confirmation failed for {item.name}")
    return selected, targets


def policy_containers(
    catalog: Sequence[ScopeItem],
    targets: Sequence[ScopeItem],
) -> List[ScopeItem]:
    """Return root/ancestors whose policies may govern the selected resources."""

    by_id = {item.ocid: item for item in catalog}
    wanted: Set[str] = {catalog[0].ocid}
    for target in targets:
        current = target
        seen: Set[str] = set()
        while current.ocid not in seen:
            seen.add(current.ocid)
            wanted.add(current.ocid)
            if not current.parent_ocid or current.parent_ocid == current.ocid:
                break
            parent = by_id.get(current.parent_ocid)
            if parent is None:
                break
            current = parent
    return [item for item in catalog if item.ocid in wanted]


def policy_ancestry_gaps(
    catalog: Sequence[ScopeItem],
    targets: Sequence[ScopeItem],
) -> List[Tuple[ScopeItem, str]]:
    """Return unresolved parent OCIDs that could hide governing IAM policies."""

    by_id = {item.ocid: item for item in catalog}
    gaps: List[Tuple[ScopeItem, str]] = []
    for target in targets:
        current = target
        seen: Set[str] = set()
        while current.ocid not in seen:
            seen.add(current.ocid)
            parent_id = current.parent_ocid
            if not parent_id or parent_id == current.ocid:
                break
            parent = by_id.get(parent_id)
            if parent is None:
                gaps.append((target, parent_id))
                break
            current = parent
    return gaps


def output_paths(
    output_dir: str,
    prefix: str,
    artifacts: Sequence[str],
) -> Dict[str, str]:
    stamp = utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    base = Path(output_dir).expanduser().resolve()
    return {
        name: str(
            base
            / (
                f"{prefix}_{name}_{stamp}."
                f"{'txt' if name in {'plan', 'summary'} else 'csv'}"
            )
        )
        for name in artifacts
    }


def _build_plan(
    args: argparse.Namespace,
    collector: str,
    controls: str,
    title: str,
    context: AuthContext,
    selected: ScopeItem,
    targets: Sequence[ScopeItem],
    work: Sequence[str],
    methods: Set[str],
    outputs: Mapping[str, str],
    scope_notes: Sequence[str] = (),
) -> str:
    lines = [
        "=" * 76,
        f" {title} — PRE-SCAN SAFETY SUMMARY",
        "=" * 76,
        f"Collector         : {collector}",
        f"Controls          : {controls}",
        f"Region            : {args.region}",
        f"Authentication    : {context.auth_label}",
        "Profile           : "
        + (context.profile if args.auth == "config" else "<not applicable>"),
        f"Selected scope    : {selected.kind} / {selected.name}",
        f"Selected OCID     : {selected.ocid}",
        f"Resolved targets  : {len(targets)}",
        "Cloud operations  : generated Oracle OCI Python SDK list/get methods only",
        "Mutation boundary : no OCI resource is created, changed, restored, or deleted",
        "Decision boundary : results are inventory/evidence, not an authorization "
        "or compliance decision",
        "Collection rule   : permission/API failures are explicit and never "
        "treated as empty results",
        "Local files       : private 0600, formula-safe, timestamped, never "
        "overwritten",
        "",
        "Resolved target OCIDs:",
    ]
    for item in targets:
        lines.extend((f"  - {item.name}", f"    {item.ocid}"))
    if scope_notes:
        lines.extend(("", "Additional read-only scope notes:"))
        lines.extend("  - " + item for item in scope_notes)
    lines.extend(("", "Requested services/phases:"))
    lines.extend("  - " + item for item in work)
    lines.extend(("", "Allowlisted SDK operations:"))
    lines.extend("  - " + method for method in sorted(methods))
    lines.extend(("", "Planned output files:"))
    lines.extend("  - " + path for path in outputs.values())
    lines.append("=" * 76)
    return "\n".join(lines) + "\n"


def _approve(args: argparse.Namespace, targets: Sequence[ScopeItem]) -> None:
    if args.non_interactive:
        expected = sorted(item.ocid for item in targets)
        supplied = sorted(args.confirm_scope_ocid)
        if supplied != expected:
            raise ValueError(
                "automation confirmation OCIDs do not exactly match resolved targets"
            )
        if args.approve_scan != "YES":
            raise ValueError("automation requires exact --approve-scan YES")
        print("Approval mode     : strict automation confirmation accepted")
    elif (
        input("Type exact uppercase YES to start the read-only SDK scan: ").strip()
        != "YES"
    ):
        raise ValueError("operator did not enter exact uppercase YES")


def begin_run(
    args: argparse.Namespace,
    *,
    collector: str,
    controls: str,
    title: str,
    work: Sequence[str],
    methods: Set[str],
    outputs: Mapping[str, str],
    scope_notes: Sequence[str] = (),
    extra_scope_ocids: Sequence[str] = (),
    extra_confirm_ocids: Sequence[str] = (),
    extra_scope_label: str = "additional compartment",
    require_extra_descendants_in_targets: bool = False,
) -> Tuple[Any, AuthContext, List[ScopeItem], ScopeItem, List[ScopeItem]]:
    if not args.region:
        raise ValueError("--region is required for an evidence run")
    oci = load_oci()
    context = build_auth_context(oci, args)
    identity = build_client(oci, context, "identity", "IdentityClient")
    catalog = discover_scope(oci, identity, context.tenancy_id, IDENTITY_SCOPE_METHODS)
    selected, targets = resolve_targets(args, catalog)
    by_id = {item.ocid: item for item in catalog}
    extra_items: List[ScopeItem] = []
    for ocid in dict.fromkeys(extra_scope_ocids):
        item = by_id.get(ocid)
        if item is None or item.kind != "COMPARTMENT":
            raise ValueError(
                f"{extra_scope_label} OCID was not a discovered compartment: {ocid}"
            )
        extra_items.append(item)
    if extra_confirm_ocids and not extra_items:
        raise ValueError(
            f"{extra_scope_label} confirmations were supplied without targets"
        )

    if require_extra_descendants_in_targets:
        target_ids = {item.ocid for item in targets}
        catalog_by_id = {item.ocid: item for item in catalog}

        def belongs_to(item: ScopeItem, root_ocid: str) -> bool:
            current = item
            seen: Set[str] = set()
            while current.ocid not in seen:
                seen.add(current.ocid)
                if current.ocid == root_ocid:
                    return True
                parent = catalog_by_id.get(current.parent_ocid)
                if parent is None:
                    return False
                current = parent
            return False

        required_ids = {
            item.ocid
            for root in extra_items
            for item in catalog
            if item.kind == "COMPARTMENT" and belongs_to(item, root.ocid)
        }
        missing_ids = sorted(required_ids - target_ids)
        if missing_ids:
            raise ValueError(
                f"scan targets omit discovered descendants of {extra_scope_label}: "
                + ", ".join(missing_ids)
                + "; use tenancy scope or include every descendant compartment"
            )

    if extra_items and not args.non_interactive:
        for item in extra_items:
            prompt = f"Enter the exact {extra_scope_label} OCID for {item.name}: "
            if input(prompt).strip() != item.ocid:
                raise ValueError(f"first {extra_scope_label} confirmation failed")
            if input("Re-enter the exact same OCID: ").strip() != item.ocid:
                raise ValueError(f"second {extra_scope_label} confirmation failed")

    resolved_notes = list(scope_notes)
    if extra_items:
        resolved_notes.append(f"Confirmed {extra_scope_label} roots:")
        resolved_notes.extend(f"{item.name} / {item.ocid}" for item in extra_items)
    plan = _build_plan(
        args,
        collector,
        controls,
        title,
        context,
        selected,
        targets,
        work,
        methods,
        outputs,
        resolved_notes,
    )
    print(plan)
    if args.non_interactive:
        expected_extra = sorted(item.ocid for item in extra_items)
        supplied_extra = sorted(extra_confirm_ocids)
        if supplied_extra != expected_extra:
            raise ValueError(
                f"automation {extra_scope_label} confirmation OCIDs do not exactly "
                "match resolved targets"
            )
    _approve(args, targets)
    for path in outputs.values():
        if Path(path).exists():
            raise ValueError(f"refusing to overwrite existing evidence file: {path}")
    os.umask(0o077)
    Path(args.output_dir).expanduser().resolve().mkdir(
        parents=True, exist_ok=True, mode=0o700
    )
    if "plan" in outputs:
        write_private_text(outputs["plan"], plan + "SCAN APPROVED\n")
    return oci, context, catalog, selected, targets


@dataclass
class EvidenceRuntime:
    oci: Any
    context: AuthContext
    allowed_methods: Set[str]
    coverage: List[Dict[str, Any]]
    errors: List[Dict[str, Any]]

    def __init__(
        self, oci: Any, context: AuthContext, allowed_methods: Set[str]
    ) -> None:
        self.oci = oci
        self.context = context
        self.allowed_methods = allowed_methods
        self.coverage = []
        self.errors = []
        self._clients: Dict[Tuple[str, str, str], Any] = {}

    def client(
        self,
        namespace: str,
        class_name: str,
        *,
        service_endpoint: str = "",
    ) -> Any:
        key = (namespace, class_name, service_endpoint)
        if key not in self._clients:
            self._clients[key] = build_client(
                self.oci,
                self.context,
                namespace,
                class_name,
                service_endpoint=service_endpoint or None,
            )
        return self._clients[key]

    def _success(
        self,
        scope: ScopeItem,
        service: str,
        operation: str,
        count: int,
        response: Any,
        pagination: str,
    ) -> None:
        self.coverage.append(
            {
                "scope_name": scope.name,
                "scope_ocid": scope.ocid,
                "service": service,
                "operation": operation,
                "status": "OK" if count else "EMPTY",
                "item_count": count,
                "pagination": pagination,
                "request_id": request_id(response),
                "message": "",
            }
        )

    def _failure(
        self,
        scope: ScopeItem,
        service: str,
        operation: str,
        exc: Exception,
    ) -> None:
        detail = error_record(exc)
        self.coverage.append(
            {
                "scope_name": scope.name,
                "scope_ocid": scope.ocid,
                "service": service,
                "operation": operation,
                "status": "FAILED",
                "item_count": "UNKNOWN",
                "pagination": "",
                "request_id": detail["request_id"],
                "message": detail["message"],
            }
        )
        self.errors.append(
            {
                "scope_name": scope.name,
                "scope_ocid": scope.ocid,
                "service": service,
                "operation": operation,
                **detail,
            }
        )

    def list_items(
        self,
        scope: ScopeItem,
        service: str,
        client: Any,
        method: str,
        *args: Any,
        **kwargs: Any,
    ) -> Optional[List[Any]]:
        try:
            items, response = sdk_list(
                self.oci, client, method, self.allowed_methods, *args, **kwargs
            )
            self._success(scope, service, method, len(items), response, "SDK-GET-ALL")
            return items
        except Exception as exc:
            self._failure(scope, service, method, exc)
            return None

    def get_item(
        self,
        scope: ScopeItem,
        service: str,
        client: Any,
        method: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        try:
            response = sdk_get(
                self.oci, client, method, self.allowed_methods, *args, **kwargs
            )
            data = getattr(response, "data", None)
            if data is None:
                raise ValueError(f"{method} returned no data")
            self._success(scope, service, method, 1, response, "SINGLE")
            return data
        except Exception as exc:
            self._failure(scope, service, method, exc)
            return None

def row_count(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as handle:
            return max(sum(1 for _ in handle) - 1, 0)
    except OSError:
        return 0


def finish_run(
    *,
    runtime: EvidenceRuntime,
    outputs: Mapping[str, str],
    summary_text: str,
    artifact_keys: Sequence[str],
) -> int:
    write_csv(outputs["coverage"], COVERAGE_FIELDS, runtime.coverage)
    write_csv(outputs["errors"], ERROR_FIELDS, runtime.errors)
    write_private_text(outputs["summary"], summary_text)
    manifest_rows: List[Dict[str, Any]] = []
    for key in artifact_keys:
        path = outputs[key]
        manifest_rows.append(
            {
                "artifact": key,
                "path": path,
                "sha256": sha256_file(path),
                "row_count": row_count(path) if path.endswith(".csv") else "",
            }
        )
    write_csv(outputs["manifest"], MANIFEST_FIELDS, manifest_rows)
    return 3 if runtime.errors else 0


def value(item: Any, name: str, default: Any = "") -> Any:
    result = getattr(item, name, default)
    return default if result is None else result


def text(item: Any, name: str, default: str = "") -> str:
    return str(value(item, name, default))


def yes_no_unknown(item: Any) -> str:
    if item is True:
        return "YES"
    if item is False:
        return "NO"
    return "UNKNOWN"


def pipe(values: Iterable[Any]) -> str:
    return "|".join(sorted({str(item) for item in values if item not in (None, "")}))
