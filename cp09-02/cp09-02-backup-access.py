#!/usr/bin/env python3
#
# cp09-02/cp09-02-backup-access.py
# Collector ID: CP09-02
#
# TASK 1 / CP-9, CP-9(5), AC-3, AC-6 — WHO CAN REACH AND DESTROY THE BACKUPS
#
# OCI TOOLING:
#   Oracle's official OCI Python SDK, pinned in requirements-oci-sdk.txt.
#   Generated service clients, oci.pagination.list_call_get_all_results and
#   oci.retry.DEFAULT_RETRY_STRATEGY. No OCI CLI, no raw REST.
#
# PYTHON FILES USED:
#   lib/oci_audit_sdk.py   shared SDK primitives: auth, client construction,
#                          the runtime list_*/get_* allowlist, scope discovery
#                          and confirmation, the coverage/error ledger and
#                          formula-safe CSV output
#
# Designed against the SDK response models directly. Not a translation of
# cp09-02-backup-access-files-check.sh, which remains in place unchanged.
#
# A backup that anyone can delete is not a backup. CP-9 access evidence has to
# answer three separate questions, because a control failure in any one of them
# defeats the other two:
#
#   1. Who is authorised to reach or destroy backups? -- IAM policy statements.
#   2. Can a backup be reached without authorisation at all? -- bucket public
#      access and pre-authenticated requests, which are bearer URLs that bypass
#      IAM entirely.
#   3. Can an authorised principal destroy one? -- per-backup retention lock and
#      deletion prevention.
#
# On pre-authenticated requests, deliberately: this collector calls
# list_preauthenticated_requests and never get_preauthenticated_request.
# PreauthenticatedRequestSummary carries name, access type, target object and
# expiry -- exactly the access evidence needed. PreauthenticatedRequest adds
# access_uri, a bearer URL that grants object access with no further
# authentication. Reading it would put a live credential into an evidence CSV.
# tests/test-readonly-proof.sh blocks that call repository-wide.
#
# Policy statements are reported, not adjudicated. Deciding whether
# "allow group X to manage object-family in tenancy" is appropriate needs the
# authorisation baseline, which is a governance input, not an API fact. The
# collector flags the statements that touch backups and says which are broad;
# a human dispositions them.
#
# Usage:
#   python3 cp09-02/cp09-02-backup-access.py --selfcheck
#   python3 cp09-02/cp09-02-backup-access.py -r us-langley-1 -o ./evidence
#   python3 cp09-02/cp09-02-backup-access.py -r us-langley-1 \
#       -c ocid1.compartment... --non-interactive \
#       --confirm-scope-ocid ocid1.compartment... --approve-scan YES
#
# Exit codes:
#   0  collection completed with no failed or unusable reads
#   1  precondition, scope or approval failure; nothing was collected
#   3  collection ran, but one or more reads failed or returned unusable data

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    Ledger, ScanRefused, ScopeItem,
    add_standard_arguments, build_auth_context, build_client,
    confirm_targets_interactively, discover_scope, iso, load_oci,
    print_scan_plan, require_final_approval, resolve_scope, sdk_get,
    sdk_list_items, selfcheck_allowlist, utc_now,
    validate_argument_combination, write_csv,
)

COLLECTOR = "cp09-02/cp09-02-backup-access.py"
CONTROLS = "CP-9 / CP-9(5) / AC-3 / AC-6"

# Runtime allowlist. get_preauthenticated_request is deliberately absent: see
# the note in the header. Adding it would put a bearer URL into evidence.
SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_policies",
    "get_namespace",
    "list_buckets",
    "get_bucket",
    "list_preauthenticated_requests",
    "list_volume_backups",
    "list_boot_volume_backups",
    "list_autonomous_database_backups",
    "list_backups",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "access_surface", "subject",
    "subject_ocid", "grants", "scope_of_grant", "exposure", "expiry",
    "deletion_protected", "finding", "control", "collection_status",
    "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["policies", "buckets", "pars", "volbackups", "dbbackups"]

# Resource families whose IAM statements govern backup access. A statement is
# in scope for CP-9 if it touches any of these.
BACKUP_RESOURCE_TOKENS = (
    "backups", "volume-backups", "boot-volume-backups", "volume-family",
    "object-family", "objects", "buckets", "database-family",
    "autonomous-database-family", "file-family", "backup-policies",
    "all-resources",
)
# Verbs ordered by destructive power. "manage" includes delete.
DESTRUCTIVE_VERBS = ("manage",)
WRITE_VERBS = ("use",)

# A statement whose scope is the tenancy, or whose subject is any-user, is
# broad regardless of the verb.
BROAD_SCOPE = re.compile(r"\bin\s+tenancy\b", re.IGNORECASE)
ANY_USER = re.compile(r"\ballow\s+any-user\b", re.IGNORECASE)


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def row(self, target: ScopeItem, surface: str, subject: str, ocid: str,
            grants: str, finding: str, *, scope_of_grant: str = "",
            exposure: str = "", expiry: str = "", deletion_protected: str = "",
            status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "access_surface": surface, "subject": subject, "subject_ocid": ocid,
            "grants": grants, "scope_of_grant": scope_of_grant,
            "exposure": exposure, "expiry": expiry,
            "deletion_protected": deletion_protected, "finding": finding,
            "control": CONTROLS, "collection_status": status,
            "collection_error": error,
        })

    def failed(self, target: ScopeItem, service: str, subject: str,
               exc: Exception) -> None:
        """A failed read is an attributed COLLECTION-FAILED row, never absence."""
        record = self.ledger.failed(target, service, exc)
        self.row(target, service, subject, "UNKNOWN", "UNKNOWN",
                 "COLLECTION-FAILED",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    # -- IAM policy statements --------------------------------------------

    def check_policies(self, target: ScopeItem) -> None:
        client = self.client("identity", "identity", "IdentityClient")
        try:
            policies = sdk_list_items(self.oci, client, "list_policies",
                                      SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "IAMPolicy", "<collection>", exc)
            return
        for policy in policies:
            name = text(policy, "name", "policy")
            ocid = text(policy, "id")
            statements = getattr(policy, "statements", None)
            if statements is None:
                # The policy object came back without its statements. That is
                # not "this policy grants nothing"; it is an unusable read.
                self.row(target, "IAMPolicy", name, ocid, "UNKNOWN",
                         "UNKNOWN-POLICY-STATEMENTS",
                         scope_of_grant="statements-not-exposed")
                continue
            for statement in statements:
                self.emit_statement(target, name, ocid, str(statement))
        self.ledger.ok(target, "IAMPolicy", len(policies))

    def emit_statement(self, target: ScopeItem, policy_name: str,
                       policy_ocid: str, statement: str) -> None:
        lowered = statement.lower()
        touched = [t for t in BACKUP_RESOURCE_TOKENS if t in lowered]
        if not touched:
            return  # not a backup-access statement; out of CP-9 scope

        verb = ("manage" if any(v in lowered for v in DESTRUCTIVE_VERBS)
                else "use" if any(v in lowered for v in WRITE_VERBS)
                else "read/inspect")
        tenancy_wide = bool(BROAD_SCOPE.search(statement))
        any_user = bool(ANY_USER.search(statement))

        if any_user:
            finding = "ANY-USER-BACKUP-GRANT"
        elif verb == "manage" and tenancy_wide:
            finding = "BROAD-BACKUP-DELETE-GRANT"
        elif verb == "manage":
            finding = "BACKUP-DELETE-GRANT"
        else:
            finding = "BACKUP-ACCESS-GRANT"

        self.row(target, "IAMPolicy", policy_name, policy_ocid,
                 f"{verb}:{','.join(sorted(set(touched)))}", finding,
                 scope_of_grant=("TENANCY" if tenancy_wide else "COMPARTMENT"),
                 exposure=statement[:400])

    # -- bucket exposure ---------------------------------------------------

    def object_storage(self, target: ScopeItem):
        client = self.client("object_storage", "object_storage", "ObjectStorageClient")
        namespace = sdk_get(self.oci, client, "get_namespace", SDK_READ_METHODS).data
        return client, namespace

    def check_buckets(self, target: ScopeItem) -> None:
        try:
            client, namespace = self.object_storage(target)
            buckets = sdk_list_items(self.oci, client, "list_buckets",
                                     SDK_READ_METHODS, namespace_name=namespace,
                                     compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "BucketAccess", "<collection>", exc)
            return
        for summary in buckets:
            name = text(summary, "name")
            try:
                bucket = sdk_get(self.oci, client, "get_bucket", SDK_READ_METHODS,
                                 namespace_name=namespace, bucket_name=name).data
            except Exception as exc:
                self.failed(target, "BucketAccess", name, exc)
                continue
            access = text(bucket, "public_access_type", "UNKNOWN")
            read_only = getattr(bucket, "is_read_only", None)
            if access == "UNKNOWN":
                finding = "UNKNOWN-BUCKET-ACCESS"
            elif access == "NoPublicAccess":
                finding = "OK-NO-PUBLIC-ACCESS"
            else:
                # Anonymous read of a bucket that may hold backups.
                finding = "PUBLIC-BUCKET"
            self.row(target, "BucketAccess", name, text(bucket, "id"),
                     f"public-access={access}", finding,
                     exposure=("ANONYMOUS-READ" if finding == "PUBLIC-BUCKET"
                               else "IAM-ONLY"),
                     deletion_protected=("READ-ONLY" if read_only else "NO"
                                         if read_only is not None else "not-exposed"))
        self.ledger.ok(target, "BucketAccess", len(buckets))

    def check_pars(self, target: ScopeItem) -> None:
        """Pre-authenticated requests bypass IAM entirely.

        Only the summary is read. The full object's access_uri is a live bearer
        URL and must never enter evidence.
        """
        try:
            client, namespace = self.object_storage(target)
            buckets = sdk_list_items(self.oci, client, "list_buckets",
                                     SDK_READ_METHODS, namespace_name=namespace,
                                     compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "PreauthenticatedRequest", "<collection>", exc)
            return
        count = 0
        now = utc_now()
        for summary in buckets:
            bucket_name = text(summary, "name")
            try:
                pars = sdk_list_items(self.oci, client,
                                      "list_preauthenticated_requests",
                                      SDK_READ_METHODS, namespace_name=namespace,
                                      bucket_name=bucket_name)
            except Exception as exc:
                self.failed(target, "PreauthenticatedRequest", bucket_name, exc)
                continue
            for par in pars:
                count += 1
                expires_raw = getattr(par, "time_expires", None)
                expires = iso(expires_raw)
                access = text(par, "access_type", "UNKNOWN")
                target_object = text(par, "object_name") or "<whole-bucket>"
                if not expires:
                    # A PAR with no expiry is a permanent bearer URL.
                    finding = "PAR-WITHOUT-EXPIRY"
                elif expires < iso(now):
                    finding = "PAR-EXPIRED"
                elif "Write" in access or "Read" in access:
                    finding = "ACTIVE-PAR-ON-BACKUP-BUCKET"
                else:
                    finding = "ACTIVE-PAR"
                self.row(target, "PreauthenticatedRequest",
                         f"{bucket_name}:{text(par, 'name', 'par')}",
                         text(par, "id"), f"access-type={access}", finding,
                         scope_of_grant=target_object,
                         exposure="BEARER-URL-BYPASSES-IAM", expiry=expires or "none")
        self.ledger.ok(target, "PreauthenticatedRequest", count)

    # -- per-backup deletion protection ------------------------------------

    def emit_volume_backup(self, target: ScopeItem, surface: str, item: Any) -> None:
        lock = getattr(item, "is_retention_lock_enabled", None)
        prevent = getattr(item, "is_prevent_deletion_enabled", None)
        indefinite = getattr(item, "is_indefinite_retention_enabled", None)
        if lock:
            finding = "OK-RETENTION-LOCKED"
        elif prevent:
            finding = "OK-DELETION-PREVENTED"
        elif lock is None and prevent is None:
            finding = "UNKNOWN-BACKUP-PROTECTION"
        else:
            # An authorised principal can delete this backup today.
            finding = "BACKUP-DELETABLE"
        protection = ";".join(filter(None, [
            f"retention-lock={'YES' if lock else 'NO' if lock is not None else 'not-exposed'}",
            f"prevent-deletion={'YES' if prevent else 'NO' if prevent is not None else 'not-exposed'}",
            f"indefinite-retention={'YES' if indefinite else 'NO'}" if indefinite is not None else "",
        ]))
        self.row(target, surface, text(item, "display_name", "backup"),
                 text(item, "id"), f"type={text(item, 'type', 'not-exposed')}",
                 finding,
                 scope_of_grant=text(item, "source_type", "not-exposed"),
                 expiry=iso(getattr(item, "time_retention_expires_at", None))
                        or iso(getattr(item, "expiration_time", None)) or "none",
                 deletion_protected=protection)

    def check_volbackups(self, target: ScopeItem) -> None:
        client = self.client("blockstorage", "core", "BlockstorageClient")
        total = 0
        for method, surface in (("list_volume_backups", "VolumeBackup"),
                                ("list_boot_volume_backups", "BootVolumeBackup")):
            try:
                items = sdk_list_items(self.oci, client, method, SDK_READ_METHODS,
                                       compartment_id=target.ocid)
            except Exception as exc:
                self.failed(target, surface, "<collection>", exc)
                continue
            for item in items:
                self.emit_volume_backup(target, surface, item)
            total += len(items)
            self.ledger.ok(target, surface, len(items))
        return total

    def check_dbbackups(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        for method, surface in (("list_autonomous_database_backups", "AutonomousDBBackup"),
                                ("list_backups", "BaseDBBackup")):
            try:
                items = sdk_list_items(self.oci, client, method, SDK_READ_METHODS,
                                       compartment_id=target.ocid)
            except Exception as exc:
                self.failed(target, surface, "<collection>", exc)
                continue
            for item in items:
                days = getattr(item, "retention_period_in_days", None)
                years = getattr(item, "retention_period_in_years", None)
                if days is None and years is None:
                    finding = "UNKNOWN-BACKUP-PROTECTION"
                    retention = "not-exposed"
                else:
                    finding = "OK-RETENTION-SET"
                    retention = (f"{years}y" if years is not None else f"{days}d")
                self.row(target, surface, text(item, "display_name", "backup"),
                         text(item, "id"),
                         f"type={text(item, 'type', 'not-exposed')};"
                         f"automatic={getattr(item, 'is_automatic', 'not-exposed')}",
                         finding,
                         scope_of_grant=text(item, "lifecycle_state", "UNKNOWN"),
                         expiry=iso(getattr(item, "time_expiry_scheduled", None))
                                or iso(getattr(item, "time_available_till", None))
                                or "none",
                         deletion_protected=f"retention={retention}")
            self.ledger.ok(target, surface, len(items))

    # -- driver ------------------------------------------------------------

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "policies": self.check_policies, "buckets": self.check_buckets,
            "pars": self.check_pars, "volbackups": self.check_volbackups,
            "dbbackups": self.check_dbbackups,
        }
        for target in targets:
            print(f"[CP-9 ACCESS] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    """Prove read-only, and prove the bearer-URL read is absent."""
    if not selfcheck_allowlist(SDK_READ_METHODS, "cp09-02-backup-access"):
        return False
    try:
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "copy_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    # The PAR bearer URL must be unreachable from this collector: neither the
    # get that returns it, nor the attribute itself, may appear in an executed
    # position anywhere in the collector. This function names both in order to
    # forbid them, so its own body is the one excluded region.
    guard = next((n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "source_selfcheck"), None)
    guard_lines = range(guard.lineno, (guard.end_lineno or guard.lineno) + 1) if guard else ()
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        if name in ("get_preauthenticated_request", "access_uri") \
                and getattr(node, "lineno", -1) not in guard_lines:
            print(f"SELF-CHECK: FAILED — {name} at line {node.lineno} would put a "
                  "bearer URL into evidence", file=sys.stderr)
            return False
    if "get_preauthenticated_request" in SDK_READ_METHODS:
        print("SELF-CHECK: FAILED — bearer-URL read is in the allowlist",
              file=sys.stderr)
        return False
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cp09-02-backup-access)")
            print("Oracle SDK cloud methods are restricted to the explicit list/get "
                  "allowlist; the pre-authenticated-request bearer URL is unreachable.")
            return 0
        return 1

    services = args.services.split()
    unknown = [s for s in services if s not in ALL_SERVICES]
    if unknown:
        print(f"ERROR: unknown service selector: {', '.join(unknown)}", file=sys.stderr)
        return 1

    try:
        validate_argument_combination(args)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    oci = oci_module if oci_module is not None else load_oci()
    context = build_auth_context(oci, args)
    identity = build_client(oci, context, "identity", "IdentityClient")

    try:
        catalog = discover_scope(oci, identity, context.tenancy_id, SDK_READ_METHODS)
        selected, targets, confirmed = resolve_scope(args, catalog)
        if not args.non_interactive and not confirmed:
            confirm_targets_interactively(targets)
    except Exception as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    out_root = Path(args.output_dir)
    if out_root.name != "cp09-02":
        out_root = out_root / "cp09-02"
    outputs = {
        "evidence": str(out_root / f"cp09_02_backup_access_{stamp}.csv"),
        "coverage": str(out_root / f"cp09_02_backup_access_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cp09_02_backup_access_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CP-9 BACKUP ACCESS AND DELETION PROTECTION", COLLECTOR,
                    CONTROLS, args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    "IAM policy statements, bucket public access, "
                    "pre-authenticated request metadata and per-backup "
                    "retention locks")

    try:
        require_final_approval(args, targets)
    except ScanRefused as exc:
        print(f"SCAN NOT STARTED: {exc}", file=sys.stderr)
        return 1

    out_root.mkdir(parents=True, exist_ok=True)
    collector = Collector(oci, context, args)
    collector.run(targets, services)

    write_csv(outputs["evidence"], EVIDENCE_FIELDS, collector.rows)
    write_csv(outputs["coverage"], COVERAGE_FIELDS, collector.ledger.coverage)
    if collector.ledger.errors:
        write_csv(outputs["errors"], ERROR_FIELDS, collector.ledger.errors)

    code = collector.ledger.exit_code()
    print(f"\nEvidence CSV written to: {outputs['evidence']}")
    print(f"Coverage CSV written to: {outputs['coverage']}")
    if collector.ledger.errors:
        print(f"Collection errors retained in: {outputs['errors']}")
    print("RESULT   : " + ("COMPLETE" if code == 0 else "INCOMPLETE"))
    return code


if __name__ == "__main__":
    sys.exit(main())
