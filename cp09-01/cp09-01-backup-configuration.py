#!/usr/bin/env python3
#
# cp09-01/cp09-01-backup-configuration.py
# Collector ID: CP09-01
#
# TASK 1 / CP-9, CP-9(1), CP-9(8) — BACKUP TYPE, CONFIGURATION AND FREQUENCY
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
# This collector is designed against the SDK response models directly. It is
# not a translation of cp09-01-backup-type-config-frequency.sh, which remains
# in place unchanged.
#
# What CP-9 needs from each protected resource: whether a backup is configured,
# by what mechanism, how often, how long it is kept, and whether the retention
# can be deleted or altered. Those five facts are spread across eight different
# service models with no common shape, so each service has its own reader and
# they all normalise into one row schema.
#
# Three model facts drive the design, each of which silently produces a wrong
# answer if missed:
#
#   1. FileSystemSummary has no filesystem_snapshot_policy_id -- only the full
#      FileSystem from get_file_system does. A collector that only lists file
#      systems sees no policy on any of them and reports every one unprotected.
#   2. PostgreSQL nests its policy at management_policy.backup_policy. Reading
#      a flat backup_policy yields None for every system.
#   3. Block and boot volumes carry no policy field at all. The assignment is a
#      separate object, read per asset with
#      get_volume_backup_policy_asset_assignment.
#
# And the rule that governs all of them: a response that does not establish the
# backup posture is UNKNOWN-BACKUP-CONFIG, never NO-BACKUP-CONFIGURED. Only an
# explicit negative from the API -- kind=NONE, is_enabled=false, an empty
# assignment list -- earns a negative finding.
#
# Usage:
#   python3 cp09-01/cp09-01-backup-configuration.py --selfcheck
#   python3 cp09-01/cp09-01-backup-configuration.py -r us-langley-1 -o ./evidence
#   python3 cp09-01/cp09-01-backup-configuration.py -r us-langley-1 \
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

COLLECTOR = "cp09-01/cp09-01-backup-configuration.py"
CONTROLS = "CP-9 / CP-9(1) / CP-9(8)"

# Runtime allowlist. Every cloud call goes through sdk_list_items/sdk_get,
# which refuses any method not named here, so this set is the collector's
# complete cloud surface.
SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_availability_domains",
    "list_volumes",
    "list_boot_volumes",
    "get_volume_backup_policy_asset_assignment",
    "get_volume_backup_policy",
    "list_file_systems",
    "get_file_system",
    "get_filesystem_snapshot_policy",
    "get_namespace",
    "list_buckets",
    "get_bucket",
    "list_retention_rules",
    "list_autonomous_databases",
    "list_db_systems",
    "list_databases",
    "get_db_system",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "service", "resource_name",
    "resource_ocid", "backup_configured", "backup_mechanism", "policy_name",
    "policy_ocid", "backup_type", "frequency", "retention", "retention_lock",
    "deletion_protection", "point_in_time_recovery", "finding", "control",
    "collection_status", "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["volumes", "bootvol", "fss", "object", "adb", "basedb",
                "mysql", "postgres"]

# Lifecycle states in which a missing backup policy is not a finding, because
# the resource is on its way out. Reporting a terminating volume as unprotected
# generates a corrective action against something that will not exist.
GONE_STATES = {"TERMINATED", "TERMINATING", "DELETED", "DELETING", "FAILED"}

# BackupDestinationDetails carries vpc_user and vpc_password. They are returned
# by an ordinary read, so the read-only gate does not stop them -- but this
# repository is public and evidence files are restricted. Never emit them.
NEVER_EMIT = {"vpc_password", "vpc_user"}

SECONDS_PER_DAY = 86400


def text(item: Any, name: str, default: str = "") -> str:
    value = getattr(item, name, None)
    return default if value is None else str(value)


def describe_retention_seconds(seconds: Any) -> str:
    """Volume schedules express retention in seconds; report days for a human."""
    if seconds is None:
        return "not-exposed"
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return f"unparsable={seconds}"
    if total % SECONDS_PER_DAY == 0:
        return f"{total // SECONDS_PER_DAY}d"
    return f"{total}s"


class Collector:
    def __init__(self, oci: Any, context: Any, args: argparse.Namespace) -> None:
        self.oci = oci
        self.context = context
        self.args = args
        self.rows: List[Dict[str, Any]] = []
        self.ledger = Ledger()
        self._clients: Dict[str, Any] = {}
        self._policy_cache: Dict[str, Any] = {}

    def client(self, key: str, namespace: str, class_name: str) -> Any:
        if key not in self._clients:
            self._clients[key] = build_client(self.oci, self.context, namespace, class_name)
        return self._clients[key]

    def row(self, target: ScopeItem, service: str, name: str, ocid: str,
            configured: str, mechanism: str, finding: str, *,
            policy_name: str = "", policy_ocid: str = "", backup_type: str = "",
            frequency: str = "", retention: str = "", retention_lock: str = "",
            deletion_protection: str = "", pitr: str = "",
            status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "service": service, "resource_name": name, "resource_ocid": ocid,
            "backup_configured": configured, "backup_mechanism": mechanism,
            "policy_name": policy_name, "policy_ocid": policy_ocid,
            "backup_type": backup_type, "frequency": frequency,
            "retention": retention, "retention_lock": retention_lock,
            "deletion_protection": deletion_protection,
            "point_in_time_recovery": pitr, "finding": finding,
            "control": CONTROLS, "collection_status": status,
            "collection_error": error,
        })

    def failed(self, target: ScopeItem, service: str, resource: str,
               exc: Exception) -> None:
        """A failed read is an attributed COLLECTION-FAILED row, never absence."""
        record = self.ledger.failed(target, service, exc)
        self.row(target, service, resource, "UNKNOWN", "UNKNOWN", "UNKNOWN",
                 "COLLECTION-FAILED",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    def alive(self, item: Any) -> bool:
        return text(item, "lifecycle_state").upper() not in GONE_STATES

    # -- block and boot volumes -------------------------------------------

    def volume_policy(self, client: Any, policy_id: str) -> Any:
        """Policies are shared across many volumes; read each one once."""
        if policy_id not in self._policy_cache:
            self._policy_cache[policy_id] = sdk_get(
                self.oci, client, "get_volume_backup_policy", SDK_READ_METHODS,
                policy_id=policy_id).data
        return self._policy_cache[policy_id]

    def emit_volume_asset(self, target: ScopeItem, client: Any, service: str,
                          item: Any) -> None:
        """Volumes carry no policy field; the assignment is a separate object."""
        name = text(item, "display_name", "volume")
        ocid = text(item, "id")
        try:
            assignments = sdk_get(
                self.oci, client, "get_volume_backup_policy_asset_assignment",
                SDK_READ_METHODS, asset_id=ocid).data or []
        except Exception as exc:
            self.failed(target, service, name, exc)
            return

        if not assignments:
            # An empty assignment list is an explicit negative from the API:
            # this asset has no policy attached. That is a real CP-9 finding.
            self.row(target, service, name, ocid, "NO", "NONE",
                     "NO-BACKUP-CONFIGURED")
            return

        for assignment in assignments:
            policy_id = text(assignment, "policy_id")
            try:
                policy = self.volume_policy(client, policy_id)
            except Exception as exc:
                self.failed(target, service, f"{name}:{policy_id}", exc)
                continue
            policy_name = text(policy, "display_name", "policy")
            schedules = getattr(policy, "schedules", None) or []
            if not schedules:
                self.row(target, service, name, ocid, "UNKNOWN", "VOLUME-POLICY",
                         "UNKNOWN-BACKUP-CONFIG", policy_name=policy_name,
                         policy_ocid=policy_id,
                         frequency="policy-exposes-no-schedules")
                continue
            for schedule in schedules:
                lock = getattr(schedule, "is_retention_lock_enabled", None)
                prevent = getattr(schedule, "is_prevent_deletion_enabled", None)
                # retention_seconds is the long-standing field; retention_period
                # appears on newer schedules. Reading only one loses the value.
                retention = describe_retention_seconds(
                    getattr(schedule, "retention_seconds", None))
                if retention == "not-exposed":
                    retention = text(schedule, "retention_period", "not-exposed")
                self.row(
                    target, service, name, ocid, "YES", "VOLUME-POLICY",
                    "OK-SCHEDULED-BACKUP",
                    policy_name=policy_name, policy_ocid=policy_id,
                    backup_type=text(schedule, "backup_type", "not-exposed"),
                    frequency=text(schedule, "period", "not-exposed"),
                    retention=retention,
                    retention_lock=("YES" if lock else "NO" if lock is not None
                                    else "not-exposed"),
                    deletion_protection=("YES" if prevent else "NO"
                                         if prevent is not None else "not-exposed"))

    def check_volumes(self, target: ScopeItem) -> None:
        client = self.client("blockstorage", "core", "BlockstorageClient")
        try:
            items = sdk_list_items(self.oci, client, "list_volumes",
                                   SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "BlockVolume", "<collection>", exc)
            return
        live = [i for i in items if self.alive(i)]
        for item in live:
            self.emit_volume_asset(target, client, "BlockVolume", item)
        self.ledger.ok(target, "BlockVolume", len(live))

    def availability_domains(self, target: ScopeItem) -> List[Any]:
        client = self.client("identity", "identity", "IdentityClient")
        return sdk_list_items(self.oci, client, "list_availability_domains",
                              SDK_READ_METHODS, compartment_id=target.ocid)

    def check_bootvol(self, target: ScopeItem) -> None:
        client = self.client("blockstorage", "core", "BlockstorageClient")
        count = 0
        try:
            domains = self.availability_domains(target)
        except Exception as exc:
            self.failed(target, "BootVolume", "<availability-domains>", exc)
            return
        for domain in domains:
            ad = text(domain, "name")
            try:
                items = sdk_list_items(self.oci, client, "list_boot_volumes",
                                       SDK_READ_METHODS, availability_domain=ad,
                                       compartment_id=target.ocid)
            except Exception as exc:
                self.failed(target, "BootVolume", f"<{ad}>", exc)
                continue
            for item in items:
                if not self.alive(item):
                    continue
                count += 1
                self.emit_volume_asset(target, client, "BootVolume", item)
        self.ledger.ok(target, "BootVolume", count)

    # -- file storage ------------------------------------------------------

    def check_fss(self, target: ScopeItem) -> None:
        client = self.client("file_storage", "file_storage", "FileStorageClient")
        count = 0
        try:
            domains = self.availability_domains(target)
        except Exception as exc:
            self.failed(target, "FSS", "<availability-domains>", exc)
            return
        for domain in domains:
            ad = text(domain, "name")
            try:
                summaries = sdk_list_items(self.oci, client, "list_file_systems",
                                           SDK_READ_METHODS,
                                           compartment_id=target.ocid,
                                           availability_domain=ad)
            except Exception as exc:
                self.failed(target, "FSS", f"<{ad}>", exc)
                continue
            for summary in summaries:
                if not self.alive(summary):
                    continue
                count += 1
                self.emit_file_system(target, client, summary)
        self.ledger.ok(target, "FSS", count)

    def emit_file_system(self, target: ScopeItem, client: Any, summary: Any) -> None:
        name = text(summary, "display_name", "file-system")
        ocid = text(summary, "id")
        # The policy id is only on the full FileSystem, not on the summary.
        try:
            fs = sdk_get(self.oci, client, "get_file_system", SDK_READ_METHODS,
                         file_system_id=ocid).data
        except Exception as exc:
            self.failed(target, "FSS", name, exc)
            return

        policy_id = text(fs, "filesystem_snapshot_policy_id")
        if not policy_id:
            self.row(target, "FSS", name, ocid, "NO", "NONE",
                     "NO-BACKUP-CONFIGURED")
            return
        try:
            policy = sdk_get(self.oci, client, "get_filesystem_snapshot_policy",
                             SDK_READ_METHODS,
                             filesystem_snapshot_policy_id=policy_id).data
        except Exception as exc:
            self.failed(target, "FSS", f"{name}:{policy_id}", exc)
            return

        policy_name = text(policy, "display_name", "snapshot-policy")
        state = text(policy, "lifecycle_state", "UNKNOWN")
        schedules = getattr(policy, "schedules", None) or []
        if not schedules:
            self.row(target, "FSS", name, ocid, "UNKNOWN", "SNAPSHOT-POLICY",
                     "UNKNOWN-BACKUP-CONFIG", policy_name=policy_name,
                     policy_ocid=policy_id,
                     frequency="policy-exposes-no-schedules")
            return
        # An INACTIVE snapshot policy is attached but not taking snapshots.
        # Reporting it as OK would assert protection that is not happening.
        finding = ("OK-SCHEDULED-SNAPSHOT" if state == "ACTIVE"
                   else f"SNAPSHOT-POLICY-{state}")
        for schedule in schedules:
            self.row(
                target, "FSS", name, ocid, "YES", "SNAPSHOT-POLICY", finding,
                policy_name=policy_name, policy_ocid=policy_id,
                backup_type="SNAPSHOT",
                frequency=text(schedule, "period", "not-exposed"),
                retention=describe_retention_seconds(
                    getattr(schedule, "retention_duration_in_seconds", None)),
                retention_lock=("YES" if getattr(schedule, "lock_duration_details", None)
                                else "NO"))

    # -- object storage ----------------------------------------------------

    def check_object(self, target: ScopeItem) -> None:
        client = self.client("object_storage", "object_storage", "ObjectStorageClient")
        try:
            namespace = sdk_get(self.oci, client, "get_namespace",
                                SDK_READ_METHODS).data
        except Exception as exc:
            self.failed(target, "ObjectStorage", "<namespace>", exc)
            return
        try:
            buckets = sdk_list_items(self.oci, client, "list_buckets",
                                     SDK_READ_METHODS, namespace_name=namespace,
                                     compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ObjectStorage", "<collection>", exc)
            return
        for summary in buckets:
            self.emit_bucket(target, client, namespace, text(summary, "name"))
        self.ledger.ok(target, "ObjectStorage", len(buckets))

    def emit_bucket(self, target: ScopeItem, client: Any, namespace: str,
                    name: str) -> None:
        """Object Storage has no backup policy. Versioning plus retention rules
        are the CP-9 durability and WORM evidence, so report those and say
        plainly that they are not a scheduled backup."""
        try:
            bucket = sdk_get(self.oci, client, "get_bucket", SDK_READ_METHODS,
                             namespace_name=namespace, bucket_name=name).data
        except Exception as exc:
            self.failed(target, "ObjectStorage", name, exc)
            return
        try:
            rules = sdk_list_items(self.oci, client, "list_retention_rules",
                                   SDK_READ_METHODS, namespace_name=namespace,
                                   bucket_name=name)
        except Exception as exc:
            self.failed(target, "ObjectStorage", f"{name}:retention-rules", exc)
            return

        versioning = text(bucket, "versioning", "UNKNOWN")
        locked = [r for r in rules if getattr(r, "time_rule_locked", None) is not None]
        if rules:
            retention = ";".join(
                f"{text(r, 'display_name', 'rule')}="
                f"{text(getattr(r, 'duration', None), 'time_amount', '?')}"
                f"{text(getattr(r, 'duration', None), 'time_unit', '')}"
                for r in rules)
        else:
            retention = "no-retention-rules"

        if versioning == "Enabled" and locked:
            finding = "OK-VERSIONED-WORM"
        elif versioning == "Enabled":
            finding = "OK-VERSIONED-NO-LOCK"
        elif versioning == "UNKNOWN":
            finding = "UNKNOWN-BACKUP-CONFIG"
        else:
            finding = "REVIEW-OBJECT-VERSIONING-DISABLED"

        self.row(target, "ObjectStorage", name, text(bucket, "id"),
                 "N/A-SEE-VERSIONING", "VERSIONING-AND-RETENTION-RULES", finding,
                 backup_type="OBJECT-VERSIONING",
                 frequency=f"versioning={versioning}",
                 retention=retention,
                 retention_lock=("YES" if locked else "NO" if rules else "not-exposed"))

    # -- databases ---------------------------------------------------------

    def check_adb(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        try:
            items = sdk_list_items(self.oci, client, "list_autonomous_databases",
                                   SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "AutonomousDB", "<collection>", exc)
            return
        live = [i for i in items if self.alive(i)]
        for item in live:
            name = text(item, "db_name") or text(item, "display_name", "adb")
            days = getattr(item, "backup_retention_period_in_days", None)
            locked = getattr(item, "is_backup_retention_locked", None)
            long_term = getattr(item, "long_term_backup_schedule", None)
            if long_term is not None and not getattr(long_term, "is_disabled", False):
                cadence = text(long_term, "repeat_cadence", "not-exposed")
                lt = (f"long-term={cadence}"
                      f";retention={text(long_term, 'retention_period_in_days', '?')}d")
            else:
                lt = "long-term=none"
            # Autonomous Database always takes automatic backups; the evidence
            # question is the retention window, not whether it is enabled.
            if days is None:
                finding, configured = "UNKNOWN-BACKUP-CONFIG", "UNKNOWN"
            else:
                finding, configured = "OK-AUTOMATIC-BACKUP", "YES"
            self.row(target, "AutonomousDB", name, text(item, "id"), configured,
                     "AUTOMATIC-BACKUP", finding,
                     backup_type="AUTOMATIC",
                     frequency=f"continuous;{lt}",
                     retention=(f"{days}d" if days is not None else "not-exposed"),
                     retention_lock=("YES" if locked else "NO" if locked is not None
                                     else "not-exposed"))
        self.ledger.ok(target, "AutonomousDB", len(live))

    def check_basedb(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        count = 0
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "BaseDB", "<db-systems>", exc)
            return
        for system in systems:
            if not self.alive(system):
                continue
            system_id = text(system, "id")
            try:
                databases = sdk_list_items(self.oci, client, "list_databases",
                                           SDK_READ_METHODS,
                                           compartment_id=target.ocid,
                                           db_system_id=system_id)
            except Exception as exc:
                self.failed(target, "BaseDB", system_id, exc)
                continue
            for database in databases:
                count += 1
                self.emit_basedb(target, database)
        self.ledger.ok(target, "BaseDB", count)

    def emit_basedb(self, target: ScopeItem, database: Any) -> None:
        name = text(database, "db_name", "database")
        ocid = text(database, "id")
        config = getattr(database, "db_backup_config", None)
        if config is None:
            # The response did not carry a backup config object. That is not
            # the same as "backups are off", so it must not read as one.
            self.row(target, "BaseDB", name, ocid, "UNKNOWN", "AUTOMATIC-BACKUP",
                     "UNKNOWN-BACKUP-CONFIG",
                     frequency="db-backup-config-not-exposed")
            return
        enabled = getattr(config, "auto_backup_enabled", None)
        destinations = getattr(config, "backup_destination_details", None) or []
        # vpc_user/vpc_password live on these objects. Emit only type, region
        # and retention-lock; never the credentials. See NEVER_EMIT.
        dest = ";".join(
            f"{text(d, 'type', 'UNKNOWN')}"
            f"{'@' + text(d, 'remote_region') if text(d, 'remote_region') else ''}"
            f"{';locked' if getattr(d, 'is_retention_lock_enabled', False) else ''}"
            for d in destinations) or "default-managed"
        window = text(config, "auto_backup_window", "not-exposed")
        recovery = getattr(config, "recovery_window_in_days", None)

        if enabled is True:
            finding, configured = "OK-AUTOMATIC-BACKUP", "YES"
        elif enabled is False:
            finding, configured = "NO-BACKUP-CONFIGURED", "NO"
        else:
            finding, configured = "UNKNOWN-BACKUP-CONFIG", "UNKNOWN"

        self.row(target, "BaseDB", name, ocid, configured, "AUTOMATIC-BACKUP",
                 finding, backup_type="AUTOMATIC",
                 frequency=f"window={window};destination={dest}",
                 retention=(f"{recovery}d" if recovery is not None else "not-exposed"),
                 deletion_protection=text(config, "backup_deletion_policy",
                                          "not-exposed"))

    def check_mysql(self, target: ScopeItem) -> None:
        client = self.client("mysql_db", "mysql", "DbSystemClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "MySQL", "<collection>", exc)
            return
        live = [s for s in systems if self.alive(s)]
        for summary in live:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system",
                                 SDK_READ_METHODS, db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "MySQL", system_id, exc)
                continue
            name = text(system, "display_name", "mysql")
            policy = getattr(system, "backup_policy", None)
            if policy is None:
                self.row(target, "MySQL", name, system_id, "UNKNOWN",
                         "MANAGED-BACKUP", "UNKNOWN-BACKUP-CONFIG",
                         frequency="backup-policy-not-exposed")
                continue
            enabled = getattr(policy, "is_enabled", None)
            pitr = getattr(policy, "pitr_policy", None)
            copies = getattr(policy, "copy_policies", None) or []
            copy_detail = ";".join(
                f"{text(c, 'copy_to_region', '?')}="
                f"{text(c, 'backup_copy_retention_in_days', '?')}d" for c in copies)
            if enabled is True:
                finding, configured = "OK-AUTOMATIC-BACKUP", "YES"
            elif enabled is False:
                finding, configured = "BACKUP-DISABLED", "NO"
            else:
                finding, configured = "UNKNOWN-BACKUP-CONFIG", "UNKNOWN"
            days = getattr(policy, "retention_in_days", None)
            self.row(target, "MySQL", name, system_id, configured,
                     "MANAGED-BACKUP", finding, backup_type="AUTOMATIC",
                     frequency=(f"window={text(policy, 'window_start_time', 'not-exposed')}"
                                + (f";copy={copy_detail}" if copy_detail else "")),
                     retention=(f"{days}d" if days is not None else "not-exposed"),
                     deletion_protection=text(policy, "soft_delete", "not-exposed"),
                     pitr=("ENABLED" if getattr(pitr, "is_enabled", False)
                           else "DISABLED" if pitr is not None else "not-exposed"))
        self.ledger.ok(target, "MySQL", len(live))

    def check_postgres(self, target: ScopeItem) -> None:
        client = self.client("psql", "psql", "PostgresqlClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "PostgreSQL", "<collection>", exc)
            return
        live = [s for s in systems if self.alive(s)]
        for summary in live:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system",
                                 SDK_READ_METHODS, db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "PostgreSQL", system_id, exc)
                continue
            name = text(system, "display_name", "postgresql")
            # The policy is nested under management_policy. Reading a flat
            # backup_policy returns None for every system, which previously
            # made every PostgreSQL system look unprotected.
            management = getattr(system, "management_policy", None)
            policy = getattr(management, "backup_policy", None) if management else None
            if policy is None:
                self.row(target, "PostgreSQL", name, system_id, "UNKNOWN",
                         "MANAGED-BACKUP", "UNKNOWN-BACKUP-CONFIG",
                         frequency="management-policy.backup-policy-not-exposed")
                continue
            kind = text(policy, "kind", "UNKNOWN").upper()
            days = getattr(policy, "retention_days", None)
            copy_policy = getattr(policy, "copy_policy", None)
            regions = ",".join(getattr(copy_policy, "regions", None) or []) if copy_policy else ""
            pitr = getattr(management, "pitr_policy", None)
            if kind == "NONE":
                finding, configured = "NO-BACKUP-CONFIGURED", "NO"
            elif kind in ("DAILY", "WEEKLY", "MONTHLY"):
                finding, configured = "OK-SCHEDULED-BACKUP", "YES"
            else:
                finding, configured = "UNKNOWN-BACKUP-CONFIG", "UNKNOWN"
            self.row(target, "PostgreSQL", name, system_id, configured,
                     "MANAGED-BACKUP", finding, backup_type=kind,
                     frequency=(kind + (f";copy-regions={regions}" if regions else "")),
                     retention=(f"{days}d" if days is not None else "not-exposed"),
                     pitr=("ENABLED" if getattr(pitr, "is_enabled", False)
                           else "DISABLED" if pitr is not None else "not-exposed"))
        self.ledger.ok(target, "PostgreSQL", len(live))

    # -- driver ------------------------------------------------------------

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "volumes": self.check_volumes, "bootvol": self.check_bootvol,
            "fss": self.check_fss, "object": self.check_object,
            "adb": self.check_adb, "basedb": self.check_basedb,
            "mysql": self.check_mysql, "postgres": self.check_postgres,
        }
        for target in targets:
            print(f"[CP-9] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    """Prove read-only from this file's own source, as the shell collectors do."""
    if not selfcheck_allowlist(SDK_READ_METHODS, "cp09-01-backup-configuration"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
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
    # BackupDestinationDetails carries vpc_user and vpc_password. They come back
    # from an ordinary read, so the read-only allowlist cannot stop them; the
    # only defence is never naming them as a field to pull. Any attribute access
    # or getattr for those names is a defect. The NEVER_EMIT set itself is the
    # one permitted mention, so it is excluded by line number.
    declaration = next(
        (n.lineno for n in ast.walk(tree)
         if isinstance(n, ast.Assign)
         and any(getattr(t, "id", "") == "NEVER_EMIT" for t in n.targets)),
        -1)
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Attribute) and node.attr in NEVER_EMIT:
            name = node.attr
        elif isinstance(node, ast.Constant) and node.value in NEVER_EMIT:
            name = node.value
        if name and getattr(node, "lineno", -1) != declaration:
            print(f"SELF-CHECK: FAILED — credential field {name} is read at line "
                  f"{node.lineno}; it must never enter evidence", file=sys.stderr)
            return False
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (cp09-01-backup-configuration)")
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

    # Standard steps 1-6: discover, display, then take the exact OCID twice.
    # The plan (step 7) is printed only after the scope is confirmed.
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
    if out_root.name != "cp09-01":
        out_root = out_root / "cp09-01"
    outputs = {
        "evidence": str(out_root / f"cp09_01_backup_configuration_{stamp}.csv"),
        "coverage": str(out_root / f"cp09_01_backup_configuration_coverage_{stamp}.csv"),
        "errors": str(out_root / f"cp09_01_backup_configuration_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("CP-9 BACKUP TYPE, CONFIGURATION AND FREQUENCY", COLLECTOR,
                    CONTROLS, args, context, selected, targets, SDK_READ_METHODS,
                    outputs.values(),
                    "resource OCIDs, backup policy OCIDs, schedules, retention "
                    "and immutability settings")

    # Standard step 8: exact uppercase YES, or the full automation set.
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
