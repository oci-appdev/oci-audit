#!/usr/bin/env python3
#
# sc08-02/sc08-02-in-transit-encryption.py
# Collector ID: SC08-02
#
# TASK 2 / SC-8, SC-8(1), SC-13 — ENCRYPTION IN TRANSIT
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
# sc08-02-in-transit-encryption.sh, which remains in place unchanged.
#
# The hard part of SC-8 evidence is not finding the TLS settings. It is being
# honest about the services whose transport security the control plane does not
# describe, because those are exactly the ones where a confident row is a lie:
#
#   * Network Load Balancer listeners have no ssl_configuration at all. NLB is
#     layer 4; TLS terminates at the backend. Reporting an NLB listener as
#     "no TLS" would be a fabricated finding against a correctly encrypted
#     service, and reporting it as OK would assert something unverified.
#   * MountTarget exposes no in-transit encryption field. FSS in-transit
#     encryption is a client-side mount option (oci-fss-utils), invisible to
#     the API.
#   * PostgreSQL NetworkDetails carries subnet, NSGs and endpoint IPs, and no
#     TLS field whatsoever.
#
# Each of those is MANUAL-VERIFY with the reason recorded, not a pass and not a
# finding.
#
# On IPSec: this collector reads tunnels and their negotiated phase-one and
# phase-two parameters, which is the actual SC-8 crypto evidence, and never
# reads a pre-shared key. get_ip_sec_connection_tunnel_shared_secret and the
# whole CPE device-config family (whose rendered output embeds the PSK) are
# blocked repository-wide in tests/test-readonly-proof.sh and are absent from
# this collector's allowlist.
#
# Usage:
#   python3 sc08-02/sc08-02-in-transit-encryption.py --selfcheck
#   python3 sc08-02/sc08-02-in-transit-encryption.py -r us-langley-1 -o ./evidence
#   python3 sc08-02/sc08-02-in-transit-encryption.py -r us-langley-1 \
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
    confirm_targets_interactively, discover_scope, load_oci,
    print_scan_plan, require_final_approval, resolve_scope, sdk_get,
    sdk_list_items, selfcheck_allowlist, utc_now,
    validate_argument_combination, write_csv,
)

COLLECTOR = "sc08-02/sc08-02-in-transit-encryption.py"
CONTROLS = "SC-8 / SC-8(1) / SC-13"

# Runtime allowlist. The IPSec pre-shared-key read and the CPE device-config
# family are deliberately absent; see the header. The negotiated crypto
# parameters come from the tunnel object, which carries no secret.
SDK_READ_METHODS: Set[str] = {
    "list_compartments",
    "get_compartment",
    "list_availability_domains",
    "list_load_balancers",
    "list_network_load_balancers",
    "list_listeners",
    "list_autonomous_databases",
    "list_db_systems",
    "get_db_system",
    "list_volume_attachments",
    "list_mount_targets",
    "list_gateways",
    "list_clusters",
    "list_ip_sec_connections",
    "list_ip_sec_connection_tunnels",
}

EVIDENCE_FIELDS = [
    "compartment_id", "compartment_name", "service", "resource_name",
    "resource_ocid", "endpoint", "in_transit_encryption", "protocol",
    "tls_versions", "cipher_or_algorithms", "peer_verification",
    "finding", "control", "collection_status", "collection_error",
]
COVERAGE_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "assets_found",
    "collection_status", "collection_error",
]
ERROR_FIELDS = [
    "compartment_ocid", "compartment_name", "service", "status", "http_status",
    "service_code", "request_id", "message",
]

ALL_SERVICES = ["lb", "nlb", "adb", "mysql", "postgres", "volumes", "fss",
                "apigw", "oke", "ipsec"]

# TLS versions that no longer meet SC-13. Named explicitly so the finding says
# which one was seen rather than "weak".
DEPRECATED_TLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
# IPSec tunnel states that mean traffic is not protected right now.
TUNNEL_DOWN = {"DOWN", "DOWN_FOR_MAINTENANCE", "PARTIAL_UP"}


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

    def row(self, target: ScopeItem, service: str, name: str, ocid: str,
            encryption: str, finding: str, *, endpoint: str = "",
            protocol: str = "", tls_versions: str = "",
            ciphers: str = "", peer_verification: str = "",
            status: str = "OK", error: str = "") -> None:
        self.rows.append({
            "compartment_id": target.ocid, "compartment_name": target.name,
            "service": service, "resource_name": name, "resource_ocid": ocid,
            "endpoint": endpoint, "in_transit_encryption": encryption,
            "protocol": protocol, "tls_versions": tls_versions,
            "cipher_or_algorithms": ciphers,
            "peer_verification": peer_verification, "finding": finding,
            "control": CONTROLS, "collection_status": status,
            "collection_error": error,
        })

    def failed(self, target: ScopeItem, service: str, name: str,
               exc: Exception) -> None:
        record = self.ledger.failed(target, service, exc)
        self.row(target, service, name, "UNKNOWN", "UNKNOWN",
                 "COLLECTION-FAILED",
                 status=record.get("status", "ERROR"),
                 error=record.get("message", ""))

    # -- load balancers ----------------------------------------------------

    def check_lb(self, target: ScopeItem) -> None:
        client = self.client("lb", "load_balancer", "LoadBalancerClient")
        try:
            balancers = sdk_list_items(self.oci, client, "list_load_balancers",
                                       SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "LoadBalancer", "<collection>", exc)
            return
        count = 0
        for lb in balancers:
            lb_name = text(lb, "display_name", "load-balancer")
            lb_id = text(lb, "id")
            # Listeners hang off the LoadBalancer object as a dict; there is no
            # list_listeners on this client.
            listeners = getattr(lb, "listeners", None) or {}
            items = listeners.values() if hasattr(listeners, "values") else listeners
            for listener in items:
                count += 1
                self.emit_lb_listener(target, lb_name, lb_id, listener)
            backend_sets = getattr(lb, "backend_sets", None) or {}
            bs_items = (backend_sets.items() if hasattr(backend_sets, "items")
                        else [(text(b, "name", "backend-set"), b) for b in backend_sets])
            for bs_name, backend_set in bs_items:
                self.emit_backend_set(target, lb_name, lb_id, str(bs_name), backend_set)
        self.ledger.ok(target, "LoadBalancer", count)

    def emit_lb_listener(self, target: ScopeItem, lb_name: str, lb_id: str,
                         listener: Any) -> None:
        name = f"{lb_name}:{text(listener, 'name', 'listener')}"
        protocol = text(listener, "protocol", "UNKNOWN")
        port = text(listener, "port", "?")
        ssl = getattr(listener, "ssl_configuration", None)
        if ssl is None:
            # No SSL configuration on an HTTP/TCP listener means the listener
            # itself terminates plaintext. That is an explicit negative.
            self.row(target, "LoadBalancer", name, lb_id, "NO",
                     "PLAINTEXT-LISTENER", endpoint=f":{port}", protocol=protocol)
            return
        protocols = getattr(ssl, "protocols", None) or []
        deprecated = sorted(set(protocols) & DEPRECATED_TLS)
        verify = getattr(ssl, "verify_peer_certificate", None)
        if deprecated:
            finding = "DEPRECATED-TLS-VERSION-" + ",".join(deprecated)
        elif not protocols:
            # SSL is configured but the versions were not returned. Do not
            # claim a version posture that the response did not state.
            finding = "UNKNOWN-TLS-VERSIONS"
        else:
            finding = "OK-TLS-ENFORCED"
        self.row(target, "LoadBalancer", name, lb_id, "YES", finding,
                 endpoint=f":{port}", protocol=protocol,
                 tls_versions=",".join(protocols) if protocols else "not-exposed",
                 ciphers=text(ssl, "cipher_suite_name", "not-exposed"),
                 peer_verification=("REQUIRED" if verify else "NOT-REQUIRED"
                                    if verify is not None else "not-exposed"))

    def emit_backend_set(self, target: ScopeItem, lb_name: str, lb_id: str,
                         bs_name: str, backend_set: Any) -> None:
        """Backend encryption is a separate leg from the client-facing one."""
        ssl = getattr(backend_set, "ssl_configuration", None)
        if ssl is None:
            self.row(target, "LoadBalancerBackend", f"{lb_name}:{bs_name}", lb_id,
                     "NO", "BACKEND-PLAINTEXT",
                     protocol="lb-to-backend")
            return
        protocols = getattr(ssl, "protocols", None) or []
        verify = getattr(ssl, "verify_peer_certificate", None)
        self.row(target, "LoadBalancerBackend", f"{lb_name}:{bs_name}", lb_id,
                 "YES", "OK-BACKEND-TLS", protocol="lb-to-backend",
                 tls_versions=",".join(protocols) if protocols else "not-exposed",
                 ciphers=text(ssl, "cipher_suite_name", "not-exposed"),
                 peer_verification=("REQUIRED" if verify else "NOT-REQUIRED"
                                    if verify is not None else "not-exposed"))

    def check_nlb(self, target: ScopeItem) -> None:
        """NLB is layer 4. Its listeners carry no TLS configuration at all."""
        client = self.client("nlb", "network_load_balancer",
                             "NetworkLoadBalancerClient")
        try:
            balancers = sdk_list_items(self.oci, client,
                                       "list_network_load_balancers",
                                       SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "NetworkLoadBalancer", "<collection>", exc)
            return
        count = 0
        for nlb in balancers:
            nlb_name = text(nlb, "display_name", "network-load-balancer")
            nlb_id = text(nlb, "id")
            try:
                listeners = sdk_list_items(self.oci, client, "list_listeners",
                                           SDK_READ_METHODS,
                                           network_load_balancer_id=nlb_id)
            except Exception as exc:
                self.failed(target, "NetworkLoadBalancer", nlb_name, exc)
                continue
            for listener in listeners:
                count += 1
                # The model has no ssl_configuration. Neither OK nor a finding
                # can be asserted from this read.
                self.row(target, "NetworkLoadBalancer",
                         f"{nlb_name}:{text(listener, 'name', 'listener')}", nlb_id,
                         "MANUAL-VERIFY", "MANUAL-VERIFY-BACKEND-TLS",
                         endpoint=f":{text(listener, 'port', '?')}",
                         protocol=text(listener, "protocol", "UNKNOWN"),
                         ciphers="nlb-is-layer-4;tls-terminates-at-backend")
        self.ledger.ok(target, "NetworkLoadBalancer", count)

    # -- databases ---------------------------------------------------------

    def check_adb(self, target: ScopeItem) -> None:
        client = self.client("database", "database", "DatabaseClient")
        try:
            items = sdk_list_items(self.oci, client, "list_autonomous_databases",
                                   SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "AutonomousDB", "<collection>", exc)
            return
        for item in items:
            name = text(item, "db_name") or text(item, "display_name", "adb")
            mtls = getattr(item, "is_mtls_connection_required", None)
            if mtls is True:
                finding, encryption = "OK-MTLS-REQUIRED", "YES(mTLS)"
            elif mtls is False:
                # TLS still applies; only mutual authentication is optional.
                finding, encryption = "REVIEW-MTLS-NOT-REQUIRED", "YES(TLS)"
            else:
                finding, encryption = "UNKNOWN-TLS-CONFIG", "UNKNOWN"
            self.row(target, "AutonomousDB", name, text(item, "id"), encryption,
                     finding, protocol="SQL*Net/TLS",
                     peer_verification=("MUTUAL" if mtls else "SERVER-ONLY"
                                        if mtls is not None else "not-exposed"))
        self.ledger.ok(target, "AutonomousDB", len(items))

    def check_mysql(self, target: ScopeItem) -> None:
        client = self.client("mysql_db", "mysql", "DbSystemClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "MySQL", "<collection>", exc)
            return
        for summary in systems:
            system_id = text(summary, "id")
            try:
                system = sdk_get(self.oci, client, "get_db_system",
                                 SDK_READ_METHODS, db_system_id=system_id).data
            except Exception as exc:
                self.failed(target, "MySQL", system_id, exc)
                continue
            name = text(system, "display_name", "mysql")
            secure = getattr(system, "secure_connections", None)
            if secure is None:
                self.row(target, "MySQL", name, system_id, "UNKNOWN",
                         "UNKNOWN-TLS-CONFIG", protocol="MySQL/TLS",
                         ciphers="secure-connections-not-exposed")
                continue
            generation = text(secure, "certificate_generation_type", "UNKNOWN")
            self.row(target, "MySQL", name, system_id, "YES(TLS)",
                     "OK-TLS-ENFORCED", protocol="MySQL/TLS",
                     ciphers=f"certificate-generation={generation}",
                     peer_verification=text(secure, "certificate_id",
                                            "system-generated"))
        self.ledger.ok(target, "MySQL", len(systems))

    def check_postgres(self, target: ScopeItem) -> None:
        """PostgreSQL NetworkDetails carries no TLS field of any kind."""
        client = self.client("psql", "psql", "PostgresqlClient")
        try:
            systems = sdk_list_items(self.oci, client, "list_db_systems",
                                     SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "PostgreSQL", "<collection>", exc)
            return
        for summary in systems:
            self.row(target, "PostgreSQL",
                     text(summary, "display_name", "postgresql"),
                     text(summary, "id"), "MANUAL-VERIFY",
                     "MANUAL-VERIFY-DATABASE-TLS", protocol="PostgreSQL/TLS",
                     ciphers="network-details-exposes-no-tls-field")
        self.ledger.ok(target, "PostgreSQL", len(systems))

    # -- attached storage --------------------------------------------------

    def check_volumes(self, target: ScopeItem) -> None:
        client = self.client("compute", "core", "ComputeClient")
        try:
            attachments = sdk_list_items(self.oci, client, "list_volume_attachments",
                                         SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "VolumeAttachment", "<collection>", exc)
            return
        for attachment in attachments:
            enabled = getattr(attachment, "is_pv_encryption_in_transit_enabled", None)
            if enabled is True:
                finding, encryption = "OK-PV-ENCRYPTION-IN-TRANSIT", "YES"
            elif enabled is False:
                finding, encryption = "PV-ENCRYPTION-IN-TRANSIT-DISABLED", "NO"
            else:
                finding, encryption = "UNKNOWN-TLS-CONFIG", "UNKNOWN"
            self.row(target, "VolumeAttachment",
                     text(attachment, "display_name", "attachment"),
                     text(attachment, "id"), encryption, finding,
                     endpoint=text(attachment, "instance_id", "not-exposed"),
                     protocol=text(attachment, "attachment_type", "UNKNOWN"))
        self.ledger.ok(target, "VolumeAttachment", len(attachments))

    def check_fss(self, target: ScopeItem) -> None:
        """FSS in-transit encryption is a client mount option, not an API fact."""
        client = self.client("file_storage", "file_storage", "FileStorageClient")
        # list_mount_targets requires an availability domain; it is not an
        # optional filter. Calling it with compartment_id alone fails.
        try:
            domains = sdk_list_items(
                self.oci, self.client("identity", "identity", "IdentityClient"),
                "list_availability_domains", SDK_READ_METHODS,
                compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "FSSMountTarget", "<availability-domains>", exc)
            return
        count = 0
        for domain in domains:
            ad = text(domain, "name")
            try:
                mounts = sdk_list_items(self.oci, client, "list_mount_targets",
                                        SDK_READ_METHODS,
                                        compartment_id=target.ocid,
                                        availability_domain=ad)
            except Exception as exc:
                self.failed(target, "FSSMountTarget", f"<{ad}>", exc)
                continue
            for mount in mounts:
                count += 1
                self.row(target, "FSSMountTarget",
                         text(mount, "display_name", "mount-target"),
                         text(mount, "id"), "MANUAL-VERIFY",
                         "MANUAL-VERIFY-FSS-MOUNT-ENCRYPTION", protocol="NFS",
                         endpoint=ad,
                         ciphers="in-transit-encryption-is-a-client-mount-option")
        self.ledger.ok(target, "FSSMountTarget", count)

    # -- gateways and clusters ---------------------------------------------

    def check_apigw(self, target: ScopeItem) -> None:
        client = self.client("apigateway", "apigateway", "GatewayClient")
        try:
            gateways = sdk_list_items(self.oci, client, "list_gateways",
                                      SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "APIGateway", "<collection>", exc)
            return
        for gateway in gateways:
            certificate = text(gateway, "certificate_id")
            endpoint_type = text(gateway, "endpoint_type", "UNKNOWN")
            # API Gateway serves HTTPS regardless; a custom certificate means a
            # custom hostname rather than the presence or absence of TLS.
            self.row(target, "APIGateway",
                     text(gateway, "display_name", "gateway"),
                     text(gateway, "id"), "YES(TLS)",
                     "OK-TLS-ENFORCED" if certificate else "OK-TLS-DEFAULT-CERT",
                     endpoint=text(gateway, "hostname", "not-exposed"),
                     protocol=f"HTTPS;endpoint-type={endpoint_type}",
                     peer_verification=certificate or "oracle-managed-certificate")
        self.ledger.ok(target, "APIGateway", len(gateways))

    def check_oke(self, target: ScopeItem) -> None:
        client = self.client("oke", "container_engine", "ContainerEngineClient")
        try:
            clusters = sdk_list_items(self.oci, client, "list_clusters",
                                      SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "OKECluster", "<collection>", exc)
            return
        for cluster in clusters:
            endpoints = getattr(cluster, "endpoints", None)
            public = text(endpoints, "public_endpoint") if endpoints else ""
            private = text(endpoints, "private_endpoint") if endpoints else ""
            # The Kubernetes API server is TLS-only. The SC-8 question is
            # whether it is reachable from the public internet.
            self.row(target, "OKECluster", text(cluster, "name", "cluster"),
                     text(cluster, "id"), "YES(TLS)",
                     "REVIEW-PUBLIC-API-ENDPOINT" if public else "OK-PRIVATE-API-ENDPOINT",
                     endpoint=public or private or "not-exposed",
                     protocol="HTTPS/kube-apiserver")
        self.ledger.ok(target, "OKECluster", len(clusters))

    # -- IPSec -------------------------------------------------------------

    def check_ipsec(self, target: ScopeItem) -> None:
        """Tunnel crypto evidence. The pre-shared key is never read."""
        client = self.client("vcn", "core", "VirtualNetworkClient")
        try:
            connections = sdk_list_items(self.oci, client, "list_ip_sec_connections",
                                         SDK_READ_METHODS, compartment_id=target.ocid)
        except Exception as exc:
            self.failed(target, "IPSecTunnel", "<collection>", exc)
            return
        count = 0
        for connection in connections:
            conn_name = text(connection, "display_name", "ipsec-connection")
            conn_id = text(connection, "id")
            try:
                tunnels = sdk_list_items(self.oci, client,
                                         "list_ip_sec_connection_tunnels",
                                         SDK_READ_METHODS, ipsc_id=conn_id)
            except Exception as exc:
                self.failed(target, "IPSecTunnel", conn_name, exc)
                continue
            # A redundant VPN is two tunnels. One tunnel is a single point of
            # failure and is reported as such rather than silently accepted.
            if len(tunnels) < 2:
                self.row(target, "IPSecTunnel", conn_name, conn_id, "PARTIAL",
                         "IPSEC-TUNNEL-PAIR-INCOMPLETE",
                         protocol=f"IPSec;tunnels={len(tunnels)}")
            for tunnel in tunnels:
                count += 1
                self.emit_tunnel(target, conn_name, tunnel)
        self.ledger.ok(target, "IPSecTunnel", count)

    def emit_tunnel(self, target: ScopeItem, conn_name: str, tunnel: Any) -> None:
        name = f"{conn_name}:{text(tunnel, 'display_name', 'tunnel')}"
        status = text(tunnel, "status", "UNKNOWN").upper()
        phase_one = getattr(tunnel, "phase_one_details", None)
        phase_two = getattr(tunnel, "phase_two_details", None)

        def negotiated(phase: Any, label: str) -> str:
            if phase is None:
                return f"{label}=not-exposed"
            return (f"{label}="
                    f"{text(phase, 'negotiated_encryption_algorithm', '?')}/"
                    f"{text(phase, 'negotiated_authentication_algorithm', '?')}/"
                    f"dh={text(phase, 'negotiated_dh_group', '?')}")

        algorithms = ";".join([negotiated(phase_one, "phase1"),
                               negotiated(phase_two, "phase2")])
        pfs = getattr(phase_two, "is_pfs_enabled", None) if phase_two else None

        if status in TUNNEL_DOWN:
            finding = f"IPSEC-TUNNEL-{status}"
        elif status != "UP":
            finding = "UNKNOWN-TUNNEL-STATUS"
        elif pfs is False:
            finding = "IPSEC-NO-PERFECT-FORWARD-SECRECY"
        else:
            finding = "OK-IPSEC-TUNNEL-UP"

        self.row(target, "IPSecTunnel", name, text(tunnel, "id"),
                 "YES(IPSec)" if status == "UP" else "NO", finding,
                 endpoint=text(tunnel, "vpn_ip", "not-exposed"),
                 protocol=f"IPSec;ike={text(tunnel, 'ike_version', 'not-exposed')}",
                 ciphers=algorithms,
                 peer_verification=("PFS-ENABLED" if pfs else "PFS-DISABLED"
                                    if pfs is not None else "not-exposed"))

    # -- driver ------------------------------------------------------------

    def run(self, targets: Sequence[ScopeItem], services: Sequence[str]) -> None:
        dispatch = {
            "lb": self.check_lb, "nlb": self.check_nlb, "adb": self.check_adb,
            "mysql": self.check_mysql, "postgres": self.check_postgres,
            "volumes": self.check_volumes, "fss": self.check_fss,
            "apigw": self.check_apigw, "oke": self.check_oke,
            "ipsec": self.check_ipsec,
        }
        for target in targets:
            print(f"[SC-8] {target.name} ({target.ocid})")
            for service in services:
                dispatch[service](target)


# Every route to an IPSec pre-shared key. None may appear in this collector.
PSK_READS = (
    "get_ip_sec_connection_tunnel_shared_secret",
    "get_cpe_device_config_content",
    "get_ipsec_cpe_device_config_content",
    "get_tunnel_cpe_device_config",
    "get_tunnel_cpe_device_config_content",
)


def source_selfcheck() -> bool:
    if not selfcheck_allowlist(SDK_READ_METHODS, "sc08-02-in-transit-encryption"):
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False
    banned = ("create_", "update_", "delete_", "change_", "move_", "restore_",
              "enable_", "disable_", "rotate_", "attach_", "detach_", "terminate_",
              "import_", "export_", "schedule_", "cancel_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and any(node.attr.startswith(p) for p in banned):
            print(f"READ-ONLY SDK SELF-CHECK: FAILED — mutating call {node.attr}",
                  file=sys.stderr)
            return False
    # The PSK must be unreachable. PSK_READS and this function name the reads in
    # order to forbid them, so those two regions are the excluded ones.
    declaration = next(
        (n.lineno for n in ast.walk(tree)
         if isinstance(n, ast.Assign)
         and any(getattr(t, "id", "") == "PSK_READS" for t in n.targets)), -1)
    guard = next((n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "source_selfcheck"), None)
    allowed = set(range(guard.lineno, (guard.end_lineno or guard.lineno) + 1)) if guard else set()
    if declaration > 0:
        end = next((n.end_lineno for n in ast.walk(tree)
                    if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "PSK_READS" for t in n.targets)),
                   declaration)
        allowed |= set(range(declaration, (end or declaration) + 1))
    for node in ast.walk(tree):
        name = None
        if isinstance(node, ast.Attribute):
            name = node.attr
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            name = node.value
        if name in PSK_READS and getattr(node, "lineno", -1) not in allowed:
            print(f"SELF-CHECK: FAILED — {name} at line {node.lineno} would read an "
                  "IPSec pre-shared key", file=sys.stderr)
            return False
    for name in PSK_READS:
        if name in SDK_READ_METHODS:
            print(f"SELF-CHECK: FAILED — {name} is in the allowlist", file=sys.stderr)
            return False
    return True


def main(argv: Sequence[str] | None = None, oci_module: Any = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    add_standard_arguments(parser)
    parser.add_argument("-s", "--services", default=" ".join(ALL_SERVICES))
    args = parser.parse_args(argv)

    if args.selfcheck:
        if source_selfcheck():
            print("READ-ONLY SDK SELF-CHECK: PASSED (sc08-02-in-transit-encryption)")
            print("Oracle SDK cloud methods are restricted to the explicit list/get "
                  "allowlist; every route to an IPSec pre-shared key is unreachable.")
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
    if out_root.name != "sc08-02":
        out_root = out_root / "sc08-02"
    outputs = {
        "evidence": str(out_root / f"sc08_02_in_transit_encryption_{stamp}.csv"),
        "coverage": str(out_root / f"sc08_02_in_transit_encryption_coverage_{stamp}.csv"),
        "errors": str(out_root / f"sc08_02_in_transit_encryption_collection_errors_{stamp}.csv"),
    }

    print_scan_plan("SC-8 ENCRYPTION IN TRANSIT", COLLECTOR, CONTROLS, args,
                    context, selected, targets, SDK_READ_METHODS, outputs.values(),
                    "listener TLS configuration, database transport security, "
                    "and negotiated IPSec algorithms; never a pre-shared key")

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
