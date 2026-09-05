#!/usr/bin/env python3
#
# cp09-03/cp09-03-backup-replication.py
# Collector ID: CP09-03
#
# TASK 1 / CP-9, CP-9(1), CP-6 — OFF-SITE REPLICATION OF BACKUPS
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
# cp09-03-backup-replication-check.sh, which remains in place unchanged.
#
# CP-6 alternate storage means a copy that survives loss of the primary site.
# "Replication is configured" is not that evidence on its own -- three things
# have to hold together, and each service reports them differently:
#
#   1. A replication relationship exists.
#   2. Its destination is a DIFFERENT region. A replication policy pointing at
#      another bucket in the same region survives a bucket deletion but not a
#      region loss, and reporting it as off-site would overstate the control.
#   3. It is actually working. Object Storage replication carries a status and
#      a last-sync time; FSS replication carries a delta status and a recovery
#      point. A policy in ACTIVE state whose last sync is stale is a failing
#      control that looks configured.
#
# Object Storage replication is also the one place a same-region destination is
# genuinely reported by the API, via destination_region_name, so it can be
# checked rather than assumed.
#
# Usage:
#   python3 cp09-03/cp09-03-backup-replication.py --selfcheck
#   python3 cp09-03/cp09-03-backup-replication.py -r us-langley-1 -o ./evidence
#   python3 cp09-03/cp09-03-backup-replication.py -r us-langley-1 \
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

COLLECTOR = "cp09-03/cp09-03-backup-replication.py"
CONTROLS = "CP-9 / CP-9(1) / CP-6"

SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_availability_domains",
    "get_namespace",
    "list_buckets",
    "list_replication_policies",
    "list_replications",
    "list_volume_backup_policies",
    "list_db_systems",
    "get_db_system",
    "list_autonomous_databases",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "service", "source_resource",
    "source_ocid", "replication_configured", "destination", "destination_region",
    "off_site", "replication_state", "last_sync_or_recovery_point",
    "replication_interval", "finding", "control", "collection_status",
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

ALL_SERVICES = ["object", "fss", "volumepolicy", "mysql", "postgres", "adb"]

# Object Storage replication statuses that mean the copy is not current.
OS_UNHEALTHY = {"CLIENT_ERROR", "PAUSED"}
# FSS delta statuses that mean the target is not tracking the source.
FSS_UNHEALTHY = {"FAILED", "TRANSFERRING_ERROR", "IDLE_ERROR"}


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.home_region = str(args.region)
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def row(self, target: ScopeItem, service: str, source: str, ocid: str,
            configured: str, finding: str, *, destination: str = "",
            destination_region: str = "", off_site: str = "",
            state: str = "", last_sync: str = "", interval: str = "",
            status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "service": service, "source_resource": source, "source_ocid": ocid,
            "replication_configured": configured, "destination": destination,
            "destination_region": destination_region, "off_site": off_site,
            "replication_state": state,
            "last_sync_or_recovery_point": last_sync,
            "replication_interval": interval, "finding": finding,
            "control": CONTROLS, "collection_status": status,
            "collection_error": error,
        })

    def failed(self, target: ScopeItem, service: str, source: str,
               exc: Exception) -> None:
        record = self.ledger.failed(target, service, exc)
        self.row(target, service, source, "UNKNOWN", "UNKNOWN",
                 "COLLECTION-FAILED",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    def offsite_verdict(self, destination_region: str) -> str:
        """A destination in the same region is not alternate storage."""
        if not destination_region:
            return "UNKNOWN"
        return "NO" if destination_region == self.home_region else "YES"

    # -- object storage ----------------------------------------------------

    def check_object(self, target: ScopeItem) -> None:
        client = self.client("object_storage", "object_storage", "ObjectStorageClient")
        try:
            namespace = sdk_get(self.oci, client, "get_namespace",
                                SDK_READ_METHODS).data
            buckets = sdk_list_items(self.oci, client, "list_buckets",
                                     SDK_READ_METHODS, namespace_name=namespace,
                                     compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ObjectStorage", "<collection>", exc)
            return
        for summary in buckets:
            name = text(summary, "name")
            try:
                policies = sdk_list_items(self.oci, client,
                                          "list_replication_policies",
                                          SDK_READ_METHODS,
                                          namespace_name=namespace,
                                          bucket_name=name)
            except Exception as exc:
                self.failed(target, "ObjectStorage", name, exc)
                continue
            if not policies:
                # An empty policy list is an explicit negative from the API.
                self.row(target, "ObjectStorage", name, "", "NO",
                         "NO-REPLICATION-CONFIGURED", off_site="NO")
                continue
            for policy in policies:
                region = text(policy, "destination_region_name")
                status = text(policy, "status", "UNKNOWN")
                last_sync = iso(getattr(policy, "time_last_sync", None))
                off_site = self.offsite_verdict(region)
                if status in OS_UNHEALTHY:
                    finding = f"REPLICATION-UNHEALTHY-{status}"
                elif off_site == "NO":
                    # Configured, working, and useless against region loss.
                    finding = "REPLICATION-SAME-REGION"
                elif off_site == "UNKNOWN":
                    finding = "UNKNOWN-REPLICATION-DESTINATION"
                elif not last_sync:
                    # Active but never observed to have synced.
                    finding = "REPLICATION-NEVER-SYNCED"
                else:
                    finding = "OK-OFFSITE-REPLICATION"
                self.row(target, "ObjectStorage", name, text(policy, "id"), "YES",
                         finding,
                         destination=text(policy, "destination_bucket_name", "not-exposed"),
                         destination_region=region or "not-exposed",
                         off_site=off_site, state=status,
                         last_sync=last_sync or "never")
        self.ledger.ok(target, "ObjectStorage", len(buckets))

    # -- file storage ------------------------------------------------------

    def check_fss(self, target: ScopeItem) -> None:
        client = self.client("file_storage", "file_storage", "FileStorageClient")
        count = 0
        try:
            domains = sdk_list_items(
                self.oci, self.client("identity", "identity", "IdentityClient"),
                "list_availability_domains", SDK_READ_METHODS,
                compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "FSSReplication", "<availability-domains>", exc)
            return
        for domain in domains:
            ad = text(domain, "name")
            try:
                replications = sdk_list_items(self.oci, client, "list_replications",
                                              SDK_READ_METHODS,
                                              compartment_id=target.ocid,
                                              availability_domain=ad)
            except Exception as exc:
                self.failed(target, "FSSReplication", f"<{ad}>", exc)
                continue
            for replication in replications:
                count += 1
                delta = text(replication, "delta_status", "UNKNOWN")
                state = text(replication, "lifecycle_state", "UNKNOWN")
                recovery = iso(getattr(replication, "recovery_point_time", None))
                interval = text(replication, "replication_interval", "not-exposed")
                # FSS does not report the target's region on the replication
                # object, so off-site cannot be asserted from this read alone.
                if delta in FSS_UNHEALTHY:
                    finding = f"REPLICATION-UNHEALTHY-{delta}"
                elif state != "ACTIVE":
                    finding = f"REPLICATION-STATE-{state}"
                elif not recovery:
                    finding = "REPLICATION-NEVER-SYNCED"
                else:
                    finding = "MANUAL-VERIFY-REPLICATION-TARGET-REGION"
                self.row(target, "FSSReplication",
                         text(replication, "display_name", "replication"),
                         text(replication, "source_id"), "YES", finding,
                         destination=text(replication, "replication_target_id",
                                          "not-exposed"),
                         destination_region="not-exposed-by-api",
                         off_site="UNKNOWN", state=f"{state};delta={delta}",
                         last_sync=recovery or "never",
                         interval=f"{interval}min" if interval.isdigit() else interval)
        self.ledger.ok(target, "FSSReplication", count)

    # -- volume backup policies -------------------------------------------

    def check_volumepolicy(self, target: ScopeItem) -> None:
        """Volume backup policies replicate via destination_region on the policy."""
        client = self.client("blockstorage", "core", "BlockstorageClient")
        try:
            policies = sdk_list_items(self.oci, client, "list_volume_backup_policies",
                                      SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "VolumeBackupPolicy", "<collection>", exc)
            return
        for policy in policies:
            name = text(policy, "display_name", "policy")
            region = text(policy, "destination_region")
            if not region:
                self.row(target, "VolumeBackupPolicy", name, text(policy, "id"),
                         "NO", "NO-REPLICATION-CONFIGURED", off_site="NO")
                continue
            off_site = self.offsite_verdict(region)
            finding = ("REPLICATION-SAME-REGION" if off_site == "NO"
                       else "OK-OFFSITE-REPLICATION")
            self.row(target, "VolumeBackupPolicy", name, text(policy, "id"), "YES",
                     finding, destination=f"region:{region}",
                     destination_region=region, off_site=off_site,
                     state="POLICY-CONFIGURED")
        self.ledger.ok(target, "VolumeBackupPolicy", len(policies))

    # -- managed databases -------------------------------------------------

    def emit_copy_regions(self, target: ScopeItem, service: str, name: str,
                          ocid: str, regions: Sequence[str], detail: str) -> None:
        if not regions:
            self.row(target, service, name, ocid, "NO",
                     "NO-REPLICATION-CONFIGURED", off_site="NO", state=detail)
            return
        for region in regions:
            off_site = self.offsite_verdict(str(region))
            finding = ("REPLICATION-SAME-REGION" if off_site == "NO"
                       else "OK-OFFSITE-REPLICATION")
            self.row(target, service, name, ocid, "YES", finding,
                     destination=f"region:{region}", destination_region=str(region),
                     off_site=off_site, state=detail)

    def check_mysql(self, target: ScopeItem) -> None:
        client = self.client("mysql_db", "mysql", "DbSystemClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "MySQLBackupCopy", "<collection>", exc)
            return
        for summary in systems:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system",
                                 SDK_READ_METHODS, db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "MySQLBackupCopy", system_id, exc)
                continue
            name = text(system, "display_name", "mysql")
            policy = getattr(system, "backup_policy", None)
            if policy is None:
                self.row(target, "MySQLBackupCopy", name, system_id, "UNKNOWN",
                         "UNKNOWN-REPLICATION-CONFIG",
                         state="backup-policy-not-exposed")
                continue
            copies = getattr(policy, "copy_policies", None) or []
            regions = [text(c, "copy_to_region") for c in copies
                       if text(c, "copy_to_region")]
            retention = ";".join(
                f"{text(c, 'copy_to_region', '?')}="
                f"{text(c, 'backup_copy_retention_in_days', '?')}d" for c in copies)
            self.emit_copy_regions(target, "MySQLBackupCopy", name, system_id,
                                   regions, retention or "no-copy-policies")
        self.ledger.ok(target, "MySQLBackupCopy", len(systems))

    def check_postgres(self, target: ScopeItem) -> None:
        client = self.client("psql", "psql", "PostgresqlClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "PostgreSQLBackupCopy", "<collection>", exc)
            return
        for summary in systems:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system",
                                 SDK_READ_METHODS, db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "PostgreSQLBackupCopy", system_id, exc)
                continue
            name = text(system, "display_name", "postgresql")
            # Nested at management_policy.backup_policy.copy_policy.
            management = getattr(system, "management_policy", None)
            policy = getattr(management, "backup_policy", None) if management else None
            if policy is None:
                self.row(target, "PostgreSQLBackupCopy", name, system_id, "UNKNOWN",
                         "UNKNOWN-REPLICATION-CONFIG",
                         state="management-policy.backup-policy-not-exposed")
                continue
            copy_policy = getattr(policy, "copy_policy", None)
            regions = list(getattr(copy_policy, "regions", None) or []) if copy_policy else []
            retention = (text(copy_policy, "retention_period", "not-exposed")
                         if copy_policy else "no-copy-policy")
            self.emit_copy_regions(target, "PostgreSQLBackupCopy", name, system_id,
                                   regions, f"copy-retention={retention}")
        self.ledger.ok(target, "PostgreSQLBackupCopy", len(systems))

    def check_adb(self, target: ScopeItem) -> None:
        """Autonomous Database cross-region protection is Autonomous Data Guard.

        The standby is reported on the database itself, so absence of a standby
        is a real negative rather than an unread field.
        """
        client = self.client("database", "database", "DatabaseClient")
        try:
            items = sdk_list_items(self.oci, client, "list_autonomous_databases",
                                   SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "AutonomousDBStandby", "<collection>", exc)
            return
        for item in items:
            name = text(item, "db_name") or text(item, "display_name", "adb")
            ocid = text(item, "id")
            regions = list(getattr(item, "peer_db_ids", None) or [])
            standby_region = text(item, "disaster_recovery_region_type")
            remote = getattr(item, "is_remote_data_guard_enabled", None)
            # A LOCAL Data Guard standby is in the same region. It is real
            # resilience against instance loss but not alternate storage, so it
            # is recorded rather than counted -- and reporting such a database
            # as having no replication at all would understate what exists.
            local = getattr(item, "is_local_data_guard_enabled", None)
            local_note = ("local-data-guard=enabled" if local
                          else "local-data-guard=disabled" if local is not None
                          else "local-data-guard=not-exposed")
            if remote is True:
                self.row(target, "AutonomousDBStandby", name, ocid, "YES",
                         "OK-OFFSITE-REPLICATION",
                         destination=f"peers={len(regions)}",
                         destination_region=standby_region or "not-exposed",
                         off_site="YES",
                         state=f"REMOTE-DATA-GUARD;{local_note}")
            elif remote is False:
                self.row(target, "AutonomousDBStandby", name, ocid, "NO",
                         ("LOCAL-DATA-GUARD-ONLY" if local
                          else "NO-REPLICATION-CONFIGURED"),
                         off_site="NO",
                         state=f"remote-data-guard=disabled;{local_note}")
            else:
                self.row(target, "AutonomousDBStandby", name, ocid, "UNKNOWN",
                         "UNKNOWN-REPLICATION-CONFIG",
                         state=f"is-remote-data-guard-enabled=not-exposed;{local_note}")
        self.ledger.ok(target, "AutonomousDBStandby", len(items))

    # -- driver ------------------------------------------------------------

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "object": self.check_object, "fss": self.check_fss,
            "volumepolicy": self.check_volumepolicy, "mysql": self.check_mysql,
            "postgres": self.check_postgres, "adb": self.check_adb,
        }
        for target in targets:
            print(f"[CP-9 REPLICATION] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    if not selfcheck_allowlist(SDK_READ_METHODS, "cp09-03-backup-replication"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "copy_to_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
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
            print("READ-ONLY SDK SELF-CHECK: PASSED (cp09-03-backup-replication)")
            print("Oracle SDK cloud methods are restricted to the explicit list/get allowlist.")
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
    if out_root.name != "cp09-03":
        out_root = out_root / "cp09-03"
    outputs = {
        "evidence": str(out_root / f"cp09_03_backup_replication_{stamp}.csv"),
        "coverage": str(out_root / f"cp09_03_backup_replication_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cp09_03_backup_replication_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CP-9 OFF-SITE BACKUP REPLICATION", COLLECTOR, CONTROLS,
                    args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    "replication relationships, destination regions, "
                    "replication health and last-sync times")

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
