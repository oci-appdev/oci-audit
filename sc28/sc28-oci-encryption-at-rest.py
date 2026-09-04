#!/usr/bin/env python3
#
# sc28/sc28-oci-encryption-at-rest.py
# Collector ID: SC28-01
#
# TASK 3 / SC-28, SC-28(1), SC-12 — ENCRYPTION AT REST
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
# This is the SDK port of sc28-oci-encryption-at-rest.sh. It reproduces that
# collector's evidence semantics exactly: the same CSV schema, the same finding
# vocabulary, and the same rule that a failed or ambiguous call becomes a
# COLLECTION-FAILED row plus a non-OK coverage row and exit 3 — never an empty
# result that reads as a clean negative finding.
#
# Key custody is deliberately not decided from kms_key_id alone. Autonomous
# Database and Base Database both expose external-key fields (encryption_key
# provider, key_store_id, encryption_key_location_details), and a database keyed
# from AWS, Azure, GCP or Oracle Key Vault has no kms_key_id. Classifying those
# as Oracle-managed would report a customer-managed database as a finding.
#
# Usage:
#   python3 sc28/sc28-oci-encryption-at-rest.py --selfcheck
#   python3 sc28/sc28-oci-encryption-at-rest.py -r us-langley-1 -o ./evidence
#   python3 sc28/sc28-oci-encryption-at-rest.py -r us-langley-1 \
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
from datetime import datetime, timezone
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
    sdk_list_items,
    selfcheck_allowlist, utc_now, validate_argument_combination, write_csv,
)

COLLECTOR = "sc28/sc28-oci-encryption-at-rest.py"
CONTROLS = "SC-28 / SC-28(1) / SC-12"

# Runtime allowlist. Every cloud call goes through sdk_list/sdk_get, which
# refuses any method not named here, so this set is the collector's complete
# cloud surface.
SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_volumes",
    "list_boot_volumes",
    "list_availability_domains",
    "list_buckets",
    "get_bucket",
    "get_namespace",
    "list_file_systems",
    "list_autonomous_databases",
    "list_db_systems",
    "get_db_system",
    "list_databases",
    "list_vaults",
    "list_keys",
    "get_key",
    "list_key_versions",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "service", "resource", "encrypted",
    "key_management", "key_ocid_or_detail", "key_lifecycle", "key_rotation",
    "finding", "control", "collection_status", "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
# Field names match the keys error_record() actually produces. write_csv uses
# extrasaction="ignore" with a "" default, so a schema that disagrees with the
# record silently emits blank columns instead of failing.
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["volumes", "bootvol", "object", "fss", "adb", "basedb",
                "mysql", "postgres", "vault"]

# AutonomousDatabaseEncryptionKeyDetails.provider is one of OKV, AZURE, AWS,
# OCI, GCP, ORACLE_MANAGED; EncryptionKeyLocationDetails.provider_type is one of
# EXTERNAL, GCP, AZURE, AWS. Only these mean the key lives outside OCI KMS.
# "OCI" does not — it is an OCI Vault key, which is customer-managed but not
# external, and treating it as external would demand key-custody evidence from
# a third party that does not hold the key.
EXTERNAL_KEY_PROVIDERS = {"OKV", "AWS", "AZURE", "GCP", "EXTERNAL"}


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

    def row(self, target: ScopeItem, service: str, resource: str, encrypted: str,
            key_management: str, detail: str, lifecycle: str, rotation: str,
            finding: str, status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "service": service, "resource": resource, "encrypted": encrypted,
            "key_management": key_management, "key_ocid_or_detail": detail,
            "key_lifecycle": lifecycle, "key_rotation": rotation,
            "finding": finding, "control": CONTROLS,
            "collection_status": status, "collection_error": error,
        })

    def failed(self, target: ScopeItem, service: str, resource: str, exc: Exception) -> None:
        """A failed read is an attributed COLLECTION-FAILED row, never an absence."""
        record = self.ledger.failed(target, service, exc)
        self.row(target, service, resource, "UNKNOWN", "UNKNOWN", "UNKNOWN",
                 "UNKNOWN", "UNKNOWN", "COLLECTION-FAILED",
                 record.get("status", "ERROR"), record.get("message", ""))

    # -- key custody -------------------------------------------------------

    def emit_store_key(self, target: ScopeItem, service: str, resource: str,
                       encrypted: str, key_id: str) -> None:
        """Services whose only custody field is kms_key_id.

        Block volumes, boot volumes, Object Storage and File Storage expose no
        external-key option, so absence of a key genuinely means Oracle-managed.
        """
        if key_id:
            self.row(target, service, resource, encrypted, "CUSTOMER-MANAGED", key_id,
                     "REFER-TO-KMS-KEY-ROW", "REFER-TO-KMS-KEY-ROW", "OK-CMK")
        else:
            self.row(target, service, resource, encrypted, "ORACLE-MANAGED", "no-kms-key-id",
                     "PLATFORM-MANAGED", "PROVIDER-MANAGED", "REVIEW-USE-CMK")

    def emit_database_key(self, target: ScopeItem, service: str, resource: str,
                          key_id: str, key_version: str, provider: str,
                          key_store: str) -> None:
        """Autonomous and Base Database custody, including external providers.

        A database keyed from AWS, Azure, GCP or Oracle Key Vault has no
        kms_key_id. Deciding custody from that field alone reported such a
        database as ORACLE-MANAGED with a REVIEW-USE-CMK finding, which is a
        fabricated negative finding against a customer-managed database.
        """
        if key_id:
            detail = key_id + (f";key-version={key_version}" if key_version else "")
            self.row(target, service, resource, "YES(TDE)", "CUSTOMER-MANAGED", detail,
                     "REFER-TO-KMS-KEY-ROW", "REFER-TO-KMS-KEY-ROW", "OK-CMK")
        elif provider in EXTERNAL_KEY_PROVIDERS:
            detail = f"encryption-key-provider={provider}"
            if key_store:
                detail += f";key-store-id={key_store}"
            self.row(target, service, resource, "YES(TDE)", "CUSTOMER-MANAGED-EXTERNAL",
                     detail, "EXTERNAL-TO-OCI-KMS", "EXTERNAL-TO-OCI-KMS",
                     "MANUAL-VERIFY-EXTERNAL-KEY-CUSTODY")
        elif key_store:
            self.row(target, service, resource, "YES(TDE)", "CUSTOMER-MANAGED-EXTERNAL",
                     f"key-store-id={key_store}", "EXTERNAL-TO-OCI-KMS",
                     "EXTERNAL-TO-OCI-KMS", "MANUAL-VERIFY-EXTERNAL-KEY-CUSTODY")
        elif provider == "OCI":
            # An OCI Vault key with no kms_key_id in this response. It is
            # customer-managed, so REVIEW-USE-CMK would be a false finding; the
            # key OCID just is not exposed here and needs manual confirmation.
            self.row(target, service, resource, "YES(TDE)", "CUSTOMER-MANAGED",
                     "encryption-key-provider=OCI;kms-key-id-not-exposed",
                     "OCI-KMS", "OCI-KMS", "MANUAL-VERIFY-KEY-CUSTODY")
        elif provider == "ORACLE_MANAGED":
            self.row(target, service, resource, "YES(TDE)", "ORACLE-MANAGED",
                     "encryption-key-provider=ORACLE_MANAGED", "PLATFORM-MANAGED",
                     "PROVIDER-MANAGED", "REVIEW-USE-CMK")
        else:
            # The response establishes custody neither way. Recording it as
            # Oracle-managed would assert something the API did not say.
            self.row(target, service, resource, "YES(TDE)", "UNKNOWN",
                     "no-kms-key-id;no-encryption-key-provider", "UNKNOWN", "UNKNOWN",
                     "MANUAL-VERIFY-KEY-CUSTODY")

    # -- services ----------------------------------------------------------

    def check_volumes(self, target: ScopeItem) -> None:
        client = self.client("blockstorage", "core", "BlockstorageClient")
        try:
            items = sdk_list_items(self.oci, client, "list_volumes", SDK_READ_METHODS,
                             compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "BlockVolume", "<collection>", exc)
            return
        for item in items:
            self.emit_store_key(target, "BlockVolume",
                                text(item, "display_name", "volume"),
                                "YES(AES-256)", text(item, "kms_key_id"))
        self.ledger.ok(target, "BlockVolume", len(items))

    def availability_domains(self, target: ScopeItem) -> List[Any]:
        client = self.client("identity", "identity", "IdentityClient")
        return sdk_list_items(self.oci, client, "list_availability_domains", SDK_READ_METHODS,
                        compartment_id=target.ocid)

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
                items = sdk_list_items(self.oci, client, "list_boot_volumes", SDK_READ_METHODS,
                                 availability_domain=ad, compartment_id=target.ocid)
            except Exception as exc:
                self.failed(target, "BootVolume", f"<{ad}>", exc)
                continue
            for item in items:
                count += 1
                self.emit_store_key(target, "BootVolume",
                                    text(item, "display_name", "boot-volume"),
                                    "YES(AES-256)", text(item, "kms_key_id"))
        self.ledger.ok(target, "BootVolume", count)

    def check_object(self, target: ScopeItem) -> None:
        client = self.client("object_storage", "object_storage", "ObjectStorageClient")
        try:
            namespace = sdk_get(self.oci, client, "get_namespace", SDK_READ_METHODS).data
        except Exception as exc:
            self.failed(target, "ObjectStorage", "<namespace>", exc)
            return
        try:
            buckets = sdk_list_items(self.oci, client, "list_buckets", SDK_READ_METHODS,
                               namespace_name=namespace, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "ObjectStorage", "<collection>", exc)
            return
        for summary in buckets:
            name = text(summary, "name")
            try:
                bucket = sdk_get(self.oci, client, "get_bucket", SDK_READ_METHODS,
                                 namespace_name=namespace, bucket_name=name).data
            except Exception as exc:
                self.failed(target, "ObjectStorage", name, exc)
                continue
            self.emit_store_key(target, "ObjectStorage", name, "YES(AES-256)",
                                text(bucket, "kms_key_id"))
        self.ledger.ok(target, "ObjectStorage", len(buckets))

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
                items = sdk_list_items(self.oci, client, "list_file_systems", SDK_READ_METHODS,
                                 compartment_id=target.ocid, availability_domain=ad)
            except Exception as exc:
                self.failed(target, "FSS", f"<{ad}>", exc)
                continue
            for item in items:
                count += 1
                self.emit_store_key(target, "FSS",
                                    text(item, "display_name", "file-system"),
                                    "YES(AES-256)", text(item, "kms_key_id"))
        self.ledger.ok(target, "FSS", count)

    def check_adb(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        try:
            items = sdk_list_items(self.oci, client, "list_autonomous_databases", SDK_READ_METHODS,
                             compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "AutonomousDB", "<collection>", exc)
            return
        for item in items:
            encryption_key = getattr(item, "encryption_key", None)
            self.emit_database_key(
                target, "AutonomousDB",
                text(item, "db_name") or text(item, "display_name", "autonomous-db"),
                text(item, "kms_key_id"), text(item, "kms_key_version_id"),
                text(encryption_key, "provider") if encryption_key else "",
                text(item, "key_store_id"))
        self.ledger.ok(target, "AutonomousDB", len(items))

    def check_basedb(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        count = 0
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems", SDK_READ_METHODS,
                               compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "BaseDB", "<db-systems>", exc)
            return
        for system in systems:
            system_id = text(system, "id")
            try:
                databases = sdk_list_items(self.oci, client, "list_databases", SDK_READ_METHODS,
                                     compartment_id=target.ocid, db_system_id=system_id)
            except Exception as exc:
                self.failed(target, "BaseDB", system_id, exc)
                continue
            for database in databases:
                count += 1
                location = getattr(database, "encryption_key_location_details", None)
                self.emit_database_key(
                    target, "BaseDB", text(database, "db_name", "database"),
                    text(database, "kms_key_id"), text(database, "kms_key_version_id"),
                    text(location, "provider_type") if location else "",
                    text(database, "key_store_id"))
        self.ledger.ok(target, "BaseDB", count)

    def check_mysql(self, target: ScopeItem) -> None:
        client = self.client("mysql_db", "mysql", "DbSystemClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems", SDK_READ_METHODS,
                               compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "MySQL", "<collection>", exc)
            return
        for summary in systems:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system", SDK_READ_METHODS,
                                 db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "MySQL", system_id, exc)
                continue
            name = text(system, "display_name", "mysql")
            encrypt = getattr(system, "encrypt_data", None)
            generation = text(encrypt, "key_generation_type") if encrypt else ""
            key_id = text(encrypt, "key_id") if encrypt else ""
            if generation == "BYOK" and key_id:
                self.row(target, "MySQL", name, "YES(AES-256)", "CUSTOMER-MANAGED", key_id,
                         "REFER-TO-KMS-KEY-ROW", "REFER-TO-KMS-KEY-ROW", "OK-CMK")
            elif generation == "SYSTEM":
                self.row(target, "MySQL", name, "YES(AES-256)", "ORACLE-MANAGED",
                         "key-generation-type=SYSTEM", "PLATFORM-MANAGED",
                         "PROVIDER-MANAGED", "REVIEW-USE-CMK")
            else:
                self.row(target, "MySQL", name, "YES(platform)", "UNKNOWN",
                         f"key-generation-type={generation or 'not-exposed'};"
                         f"key-id={key_id or 'not-exposed'}",
                         "UNKNOWN", "UNKNOWN", "MANUAL-VERIFY-KEY-CUSTODY")
        self.ledger.ok(target, "MySQL", len(systems))

    def check_postgres(self, target: ScopeItem) -> None:
        client = self.client("psql", "psql", "PostgresqlClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems", SDK_READ_METHODS,
                               compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "PostgreSQL", "<collection>", exc)
            return
        for summary in systems:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system", SDK_READ_METHODS,
                                 db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "PostgreSQL", system_id, exc)
                continue
            storage = getattr(system, "storage_details", None)
            system_type = text(storage, "system_type") if storage else "not-exposed"
            # The current psql DbSystem model exposes no customer-key field, so
            # the row records platform encryption and asks for manual custody
            # verification rather than inventing a key OCID.
            self.row(target, "PostgreSQL", text(system, "display_name", "postgresql"),
                     "YES(platform)", "PLATFORM-MANAGED",
                     f"data-key-id-not-exposed;storage-system-type={system_type}",
                     "PLATFORM-MANAGED", "PROVIDER-MANAGED", "MANUAL-VERIFY-KEY-CUSTODY")
        self.ledger.ok(target, "PostgreSQL", len(systems))

    def check_vault(self, target: ScopeItem) -> None:
        vault_client = self.client("kms_vault", "key_management", "KmsVaultClient")
        try:
            vaults = sdk_list_items(self.oci, vault_client, "list_vaults", SDK_READ_METHODS,
                              compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "Vault", "<collection>", exc)
            return

        key_count = 0
        for vault in vaults:
            name = text(vault, "display_name", "vault")
            self.row(target, "Vault", name, "n/a", text(vault, "vault_type", "UNKNOWN"),
                     text(vault, "id"), text(vault, "lifecycle_state", "UNKNOWN"),
                     "n/a", "OK-VAULT")
            endpoint = text(vault, "management_endpoint")
            if not endpoint:
                continue
            management = self.oci.key_management.KmsManagementClient(
                self.context.config, service_endpoint=endpoint,
                **({"signer": self.context.signer} if self.context.signer else {}))
            try:
                keys = sdk_list_items(self.oci, management, "list_keys", SDK_READ_METHODS,
                                compartment_id=target.ocid)
            except Exception as exc:
                # A denied key listing must never be reported as "no keys".
                self.failed(target, "KMS-Key", f"<collection:{name}>", exc)
                continue
            for key_summary in keys:
                key_count += 1
                self.emit_key(target, management, key_summary)
        self.ledger.ok(target, "Vault", len(vaults))
        self.ledger.ok(target, "KMS-Key", key_count)

    def emit_key(self, target: ScopeItem, management: Any, summary: Any) -> None:
        """KMS key posture, with the Bash collector's full finding ladder.

        SC-12 evidence distinguishes a disabled key, a software-protected key,
        an under-length key, a failed rotation, auto-rotation configured without
        an interval, manual rotation, and rotation that has never actually
        produced a second version. Collapsing those into OK/REVIEW loses the
        finding an assessor acts on.
        """
        key_id = text(summary, "id")
        name = text(summary, "display_name", "key")
        try:
            key = sdk_get(self.oci, management, "get_key", SDK_READ_METHODS,
                          key_id=key_id).data
        except Exception as exc:
            self.failed(target, "KMS-Key", name, exc)
            return

        protection = text(key, "protection_mode", "UNKNOWN")
        shape = getattr(key, "key_shape", None)
        algorithm = text(shape, "algorithm", "UNKNOWN") if shape else "UNKNOWN"
        length = text(shape, "length", "UNKNOWN") if shape else "UNKNOWN"
        key_state = text(key, "lifecycle_state", "UNKNOWN")

        auto = getattr(key, "auto_key_rotation_details", None)
        enabled = getattr(key, "is_auto_rotation_enabled", None)
        interval = text(auto, "rotation_interval_in_days") if auto else ""
        schedule_start = iso(getattr(auto, "time_of_schedule_start", None)) if auto else ""
        last_rotation = iso(getattr(auto, "time_of_last_rotation", None)) if auto else ""
        next_rotation = iso(getattr(auto, "time_of_next_rotation", None)) if auto else ""
        last_status = text(auto, "last_rotation_status") if auto else ""
        last_message = (text(auto, "last_rotation_message") if auto else "")
        last_message = last_message.replace("\n", " ").replace("\r", " ")[:120]

        version_count = latest_version = latest_state = latest_created = "UNKNOWN"
        auto_versions = pending_deletions = "UNKNOWN"
        versions_failed = False
        try:
            versions = sdk_list_items(self.oci, management, "list_key_versions",
                                      SDK_READ_METHODS, key_id=key_id)
            version_count = str(len(versions))
            # Sort by time_created; SDK list order is not a documented guarantee,
            # so indexing [0] is not the same as "latest".
            ordered = sorted(versions, key=lambda v: iso(getattr(v, "time_created", None)))
            if ordered:
                newest = ordered[-1]
                latest_version = text(newest, "id", "none")
                latest_state = text(newest, "lifecycle_state", "none")
                latest_created = iso(getattr(newest, "time_created", None)) or "none"
            else:
                latest_version = latest_state = latest_created = "none"
            auto_versions = str(sum(
                1 for v in versions if getattr(v, "is_auto_rotated", None) is True))
            pending_deletions = str(sum(
                1 for v in versions if getattr(v, "time_of_deletion", None) is not None))
        except Exception as exc:
            # A denied version listing must not silently become "not rotated".
            self.ledger.failed(target, "KMS-KeyVersion", exc)
            versions_failed = True

        rotation = ";".join([
            f"auto-enabled={'true' if enabled else 'false'}",
            f"interval-days={interval or 'not-exposed'}",
            f"schedule-start={schedule_start or 'not-exposed'}",
            f"last={last_rotation or 'not-exposed'}",
            f"last-status={last_status or 'not-exposed'}",
            f"last-message={last_message or 'none'}",
            f"next={next_rotation or 'not-exposed'}",
            f"versions={version_count}",
            f"auto-rotated-versions={auto_versions}",
            f"pending-version-deletions={pending_deletions}",
            f"latest-version={latest_version}",
            f"latest-version-state={latest_state}",
            f"latest-version-created={latest_created}",
        ])

        if versions_failed:
            finding = "COLLECTION-FAILED"
        elif key_state != "ENABLED":
            finding = f"KEY-STATE-{key_state}"
        elif protection != "HSM":
            finding = "REVIEW-SOFTWARE-KEY"
        elif algorithm != "AES" or length != "32":
            finding = f"REVIEW-AES-KEY-LENGTH-{algorithm}-{length}"
        elif last_status.upper() == "FAILED":
            finding = "AUTO-ROTATION-FAILED"
        elif enabled and (not interval or not next_rotation):
            finding = "REVIEW-AUTO-ROTATION-DETAILS"
        elif not enabled:
            finding = "REVIEW-MANUAL-ROTATION-EVIDENCE"
        elif int(version_count) <= 1 and int(auto_versions) == 0:
            finding = "REVIEW-ROTATION-NOT-CONFIRMED"
        else:
            finding = "OK-HSM-AUTO-ROTATION"

        status = "ERROR" if versions_failed else "OK"
        self.row(target, "KMS-Key", name, "n/a", protection,
                 f"{key_id};algorithm={algorithm};length={length}",
                 key_state, rotation, finding, status)

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "volumes": self.check_volumes, "bootvol": self.check_bootvol,
            "object": self.check_object, "fss": self.check_fss,
            "adb": self.check_adb, "basedb": self.check_basedb,
            "mysql": self.check_mysql, "postgres": self.check_postgres,
            "vault": self.check_vault,
        }
        for target in targets:
            print(f"[SC-28] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


def source_selfcheck() -> bool:
    """Prove read-only from this file's own source, as the shell collectors do."""
    if not selfcheck_allowlist(SDK_READ_METHODS, "sc28-oci-encryption-at-rest"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_", "backup_")
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
            print("READ-ONLY SDK SELF-CHECK: PASSED (sc28-oci-encryption-at-rest)")
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
    if out_root.name != "sc28":
        out_root = out_root / "sc28"
    outputs = {
        "evidence": str(out_root / f"sc28_atrest_encryption_{stamp}.csv"),
        "coverage": str(out_root / f"sc28_atrest_encryption_coverage_{stamp}.csv"),
        "errors": str(out_root / f"sc28_atrest_encryption_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("SC-28 ENCRYPTION AT REST", COLLECTOR, CONTROLS, args, context,
                    selected, targets, SDK_READ_METHODS, outputs.values(),
                    "resource OCIDs, key OCIDs, key custody, rotation metadata")

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
