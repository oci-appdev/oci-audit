#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the SC08-02 SDK collector.

Fixtures mirror real SDK response models, verified against oci==2.185.1. Two
of them exist because the model is *missing* a field, which is the harder case
to get right:

  * NetworkLoadBalancer listeners have no ssl_configuration -- the fixture
    therefore has none, and the collector must say MANUAL-VERIFY rather than
    inventing either a pass or a finding;
  * MountTarget has no in-transit encryption field, for the same reason.

The IPSec fixtures carry phase-one and phase-two negotiated algorithms and no
pre-shared key, because the tunnel model has none.

PYTHON FILES USED:
  sc08-02/sc08-02-in-transit-encryption.py   the collector under test
  lib/oci_audit_sdk.py                       loaded transitively by the collector
"""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
import tempfile
import types
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TENANCY = "ocid1.tenancy.oc1..sc08mock"
SHARED = "ocid1.compartment.oc1..sharedservices"

_spec = importlib.util.spec_from_file_location(
    "sc0802", ROOT / "sc08-02" / "sc08-02-in-transit-encryption.py")
MODULE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MODULE)


class Obj:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def __getattr__(self, name):
        return None


class Response:
    def __init__(self, data):
        self.data = data
        self.headers = {"opc-request-id": "mock-request-id"}
        self.status = 200


class ServiceError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.headers = {"opc-request-id": "mock-denied"}


class Denials:
    tunnels = False


class BaseClient:
    def __init__(self, config, **kwargs):
        self.config = config


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kw):
        names = {TENANCY: "MockTenancy", SHARED: "Shared Services"}
        return Response(Obj(id=compartment_id, name=names.get(compartment_id, "?")))

    def list_compartments(self, compartment_id, **kw):
        return Response([Obj(id=SHARED, name="Shared Services",
                             lifecycle_state="ACTIVE")])

    def list_availability_domains(self, **kw):
        return Response([Obj(name="mock-AD-1")])


class LoadBalancerClient(BaseClient):
    def list_load_balancers(self, **kw):
        return Response([Obj(
            id="ocid1.loadbalancer.oc1..lb1", display_name="public-lb",
            listeners={
                "https": Obj(name="https", port=443, protocol="HTTP",
                             ssl_configuration=Obj(
                                 protocols=["TLSv1.2", "TLSv1.3"],
                                 cipher_suite_name="oci-modern-ssl-cipher-suite-v1",
                                 verify_peer_certificate=True)),
                "legacy": Obj(name="legacy", port=8443, protocol="HTTP",
                              ssl_configuration=Obj(
                                  protocols=["TLSv1.1", "TLSv1.2"],
                                  cipher_suite_name="oci-default-ssl-cipher-suite-v1")),
                "plain": Obj(name="plain", port=80, protocol="HTTP"),
                # SSL configured but versions not returned: unknown, not OK.
                "quiet": Obj(name="quiet", port=9443, protocol="HTTP",
                             ssl_configuration=Obj(
                                 cipher_suite_name="custom")),
            },
            backend_sets={
                "encrypted-bs": Obj(name="encrypted-bs",
                                    ssl_configuration=Obj(protocols=["TLSv1.2"],
                                                          verify_peer_certificate=True)),
                "plain-bs": Obj(name="plain-bs"),
            })])


class NetworkLoadBalancerClient(BaseClient):
    def list_network_load_balancers(self, **kw):
        return Response([Obj(id="ocid1.networkloadbalancer.oc1..n1",
                             display_name="internal-nlb")])

    def list_listeners(self, network_load_balancer_id, **kw):
        # No ssl_configuration: the real Listener model has no such field.
        return Response([Obj(name="tcp-443", port=443, protocol="TCP")])


class DatabaseClient(BaseClient):
    def list_autonomous_databases(self, **kw):
        return Response([
            Obj(id="ocid1.adb.oc1..a1", db_name="ADBMTLS",
                is_mtls_connection_required=True),
            Obj(id="ocid1.adb.oc1..a2", db_name="ADBTLSONLY",
                is_mtls_connection_required=False),
            Obj(id="ocid1.adb.oc1..a3", db_name="ADBSILENT"),
        ])


class MysqlDbSystemClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.mysqldbsystem.oc1..m1"),
                         Obj(id="ocid1.mysqldbsystem.oc1..m2")])

    def get_db_system(self, db_system_id, **kw):
        if db_system_id.endswith("m2"):
            return Response(Obj(id=db_system_id, display_name="mysql-silent"))
        return Response(Obj(id=db_system_id, display_name="mysql-tls",
                            secure_connections=Obj(
                                certificate_generation_type="SYSTEM")))


class PostgresqlClient(BaseClient):
    def list_db_systems(self, **kw):
        return Response([Obj(id="ocid1.postgresqldbsystem.oc1..p1",
                             display_name="pgsql-prod")])


class ComputeClient(BaseClient):
    def list_volume_attachments(self, **kw):
        return Response([
            Obj(id="ocid1.volumeattachment.oc1..v1", display_name="encrypted-attach",
                attachment_type="paravirtualized", instance_id="ocid1.instance.oc1..i1",
                is_pv_encryption_in_transit_enabled=True),
            Obj(id="ocid1.volumeattachment.oc1..v2", display_name="plain-attach",
                attachment_type="paravirtualized", instance_id="ocid1.instance.oc1..i2",
                is_pv_encryption_in_transit_enabled=False),
            Obj(id="ocid1.volumeattachment.oc1..v3", display_name="silent-attach",
                attachment_type="iscsi", instance_id="ocid1.instance.oc1..i3"),
        ])


class FileStorageClient(BaseClient):
    def list_mount_targets(self, compartment_id, availability_domain, **kw):
        # Requires availability_domain. A collector that omits it fails here.
        assert availability_domain, "list_mount_targets requires an AD"
        return Response([Obj(id="ocid1.mounttarget.oc1..mt1",
                             display_name="shared-mount")])


class GatewayClient(BaseClient):
    def list_gateways(self, **kw):
        return Response([
            Obj(id="ocid1.apigateway.oc1..g1", display_name="custom-cert-gw",
                certificate_id="ocid1.certificate.oc1..c1", endpoint_type="PUBLIC",
                hostname="api.example.gov"),
            Obj(id="ocid1.apigateway.oc1..g2", display_name="default-cert-gw",
                endpoint_type="PRIVATE"),
        ])


class ContainerEngineClient(BaseClient):
    def list_clusters(self, **kw):
        return Response([
            Obj(id="ocid1.cluster.oc1..k1", name="public-cluster",
                endpoints=Obj(public_endpoint="1.2.3.4:6443",
                              private_endpoint="10.0.0.4:6443")),
            Obj(id="ocid1.cluster.oc1..k2", name="private-cluster",
                endpoints=Obj(private_endpoint="10.0.0.5:6443")),
        ])


class VirtualNetworkClient(BaseClient):
    def list_ip_sec_connections(self, **kw):
        return Response([
            Obj(id="ocid1.ipsecconnection.oc1..c1", display_name="dual-tunnel-vpn"),
            Obj(id="ocid1.ipsecconnection.oc1..c2", display_name="single-tunnel-vpn"),
        ])

    def list_ip_sec_connection_tunnels(self, ipsc_id, **kw):
        if Denials.tunnels:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "list IPSec tunnels was denied")
        # No pre-shared key on any of these: the real model has none.
        healthy = Obj(
            id="ocid1.tunnel.oc1..t1", display_name="tunnel-1", status="UP",
            ike_version="V2", vpn_ip="203.0.113.1",
            phase_one_details=Obj(negotiated_encryption_algorithm="AES_256_CBC",
                                  negotiated_authentication_algorithm="HMAC_SHA2_384",
                                  negotiated_dh_group="GROUP20"),
            phase_two_details=Obj(negotiated_encryption_algorithm="AES_256_GCM",
                                  negotiated_authentication_algorithm="HMAC_SHA2_256",
                                  negotiated_dh_group="GROUP20", is_pfs_enabled=True))
        if ipsc_id.endswith("c2"):
            return Response([healthy])          # only one tunnel: not redundant
        down = Obj(id="ocid1.tunnel.oc1..t2", display_name="tunnel-2", status="DOWN",
                   ike_version="V2", vpn_ip="203.0.113.2")
        nopfs = Obj(id="ocid1.tunnel.oc1..t3", display_name="tunnel-3", status="UP",
                    ike_version="V1", vpn_ip="203.0.113.3",
                    phase_two_details=Obj(is_pfs_enabled=False))
        return Response([healthy, down, nopfs])


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_all(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(list_call_get_all_results=list_all)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.load_balancer = types.SimpleNamespace(LoadBalancerClient=LoadBalancerClient)
    oci.network_load_balancer = types.SimpleNamespace(
        NetworkLoadBalancerClient=NetworkLoadBalancerClient)
    oci.database = types.SimpleNamespace(DatabaseClient=DatabaseClient)
    oci.mysql = types.SimpleNamespace(DbSystemClient=MysqlDbSystemClient)
    oci.psql = types.SimpleNamespace(PostgresqlClient=PostgresqlClient)
    oci.core = types.SimpleNamespace(ComputeClient=ComputeClient,
                                     VirtualNetworkClient=VirtualNetworkClient)
    oci.file_storage = types.SimpleNamespace(FileStorageClient=FileStorageClient)
    oci.apigateway = types.SimpleNamespace(GatewayClient=GatewayClient)
    oci.container_engine = types.SimpleNamespace(
        ContainerEngineClient=ContainerEngineClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


def run(extra_args, tmp):
    argv = ["-r", "us-langley-1", "-o", str(tmp), "-c", SHARED, "--non-interactive",
            "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"] + list(extra_args)
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        rc = MODULE.main(argv, oci_module=build_sdk())
    return rc, buffer.getvalue()


def read_csv(tmp, marker):
    matches = sorted(Path(tmp).rglob(f"*{marker}*.csv"))
    assert matches, f"no CSV matching {marker} under {tmp}"
    with open(matches[0], newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def one(rows, name):
    hits = [r for r in rows if r["resource_name"] == name]
    assert len(hits) == 1, f"expected exactly one {name} row, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_transport_posture_across_every_service():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run([], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "in_transit_encryption_2")

        good = one(rows, "public-lb:https")
        assert good["finding"] == "OK-TLS-ENFORCED", good
        assert good["peer_verification"] == "REQUIRED"
        legacy = one(rows, "public-lb:legacy")
        assert legacy["finding"] == "DEPRECATED-TLS-VERSION-TLSv1.1", legacy
        assert one(rows, "public-lb:plain")["finding"] == "PLAINTEXT-LISTENER"
        # SSL configured but versions absent: do not claim a posture.
        assert one(rows, "public-lb:quiet")["finding"] == "UNKNOWN-TLS-VERSIONS"

        assert one(rows, "public-lb:encrypted-bs")["finding"] == "OK-BACKEND-TLS"
        assert one(rows, "public-lb:plain-bs")["finding"] == "BACKEND-PLAINTEXT"

        # NLB has no ssl_configuration field: neither pass nor finding.
        nlb = one(rows, "internal-nlb:tcp-443")
        assert nlb["finding"] == "MANUAL-VERIFY-BACKEND-TLS", nlb
        assert nlb["in_transit_encryption"] == "MANUAL-VERIFY", nlb

        assert one(rows, "ADBMTLS")["finding"] == "OK-MTLS-REQUIRED"
        assert one(rows, "ADBTLSONLY")["finding"] == "REVIEW-MTLS-NOT-REQUIRED"
        assert one(rows, "ADBSILENT")["finding"] == "UNKNOWN-TLS-CONFIG"

        assert one(rows, "mysql-tls")["finding"] == "OK-TLS-ENFORCED"
        assert one(rows, "mysql-silent")["finding"] == "UNKNOWN-TLS-CONFIG"

        # PostgreSQL exposes no TLS field at all.
        assert one(rows, "pgsql-prod")["finding"] == "MANUAL-VERIFY-DATABASE-TLS"

        assert one(rows, "encrypted-attach")["finding"] == "OK-PV-ENCRYPTION-IN-TRANSIT"
        assert one(rows, "plain-attach")["finding"] == "PV-ENCRYPTION-IN-TRANSIT-DISABLED"
        assert one(rows, "silent-attach")["finding"] == "UNKNOWN-TLS-CONFIG"

        # MountTarget has no in-transit field; the AD is required to list them.
        mount = one(rows, "shared-mount")
        assert mount["finding"] == "MANUAL-VERIFY-FSS-MOUNT-ENCRYPTION", mount
        assert mount["endpoint"] == "mock-AD-1", mount

        assert one(rows, "custom-cert-gw")["finding"] == "OK-TLS-ENFORCED"
        assert one(rows, "default-cert-gw")["finding"] == "OK-TLS-DEFAULT-CERT"

        assert one(rows, "public-cluster")["finding"] == "REVIEW-PUBLIC-API-ENDPOINT"
        assert one(rows, "private-cluster")["finding"] == "OK-PRIVATE-API-ENDPOINT"

        healthy = one(rows, "dual-tunnel-vpn:tunnel-1")
        assert healthy["finding"] == "OK-IPSEC-TUNNEL-UP", healthy
        assert "phase1=AES_256_CBC/HMAC_SHA2_384/dh=GROUP20" in healthy["cipher_or_algorithms"]
        assert healthy["peer_verification"] == "PFS-ENABLED"
        assert one(rows, "dual-tunnel-vpn:tunnel-2")["finding"] == "IPSEC-TUNNEL-DOWN"
        assert one(rows, "dual-tunnel-vpn:tunnel-3")["finding"] == "IPSEC-NO-PERFECT-FORWARD-SECRECY"
        # A single-tunnel VPN is not redundant and is reported as such.
        assert one(rows, "single-tunnel-vpn")["finding"] == "IPSEC-TUNNEL-PAIR-INCOMPLETE"

        coverage = read_csv(tmp, "coverage")
        assert all(r["collection_status"] == "OK" for r in coverage), coverage


@check
def test_no_preshared_key_reaches_evidence():
    with tempfile.TemporaryDirectory() as tmp:
        run([], tmp)
        for path in Path(tmp).rglob("*.csv"):
            body = path.read_text(encoding="utf-8").lower()
            for banned in ("shared_secret", "shared-secret", "psk", "pre-shared"):
                assert banned not in body, (path.name, banned)


@check
def test_denied_tunnel_listing_is_never_no_tunnels():
    Denials.tunnels = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "ipsec"], tmp)
            assert rc == 3, (rc, out)
            assert "RESULT   : INCOMPLETE" in out, out
            rows = read_csv(tmp, "in_transit_encryption_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert all(r["collection_status"] == "DENIED" for r in rows), rows
    finally:
        Denials.tunnels = False


@check
def test_scope_flags_alone_do_not_approve_a_scan():
    with tempfile.TemporaryDirectory() as tmp:
        for argv, why in (
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED], "missing --approve-scan"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "yes"], "lowercase"),
            (["-r", "us-langley-1", "-o", tmp, "-c", SHARED, "--non-interactive",
              "--approve-scan", "YES"], "no confirmed OCID"),
            (["-o", tmp, "-c", SHARED, "--non-interactive",
              "--confirm-scope-ocid", SHARED, "--approve-scan", "YES"], "no region"),
        ):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MODULE.main(argv, oci_module=build_sdk())
            assert rc == 1, (why, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*.csv")), "a refused scan wrote evidence"


@check
def test_every_route_to_a_preshared_key_is_unreachable():
    for name in MODULE.PSK_READS:
        assert name not in MODULE.SDK_READ_METHODS, name
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name
    assert MODULE.source_selfcheck()


def main() -> int:
    failures = 0
    for fn in CHECKS:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as exc:
            failures += 1
            print(f"  FAIL {fn.__name__}: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            # An unexpected exception is a failure, not a crash. Catching only
            # AssertionError let a collector that raised anything else take the
            # whole runner down with a traceback and no FAIL line -- the run
            # still exited non-zero, but said nothing about which check broke.
            failures += 1
            print(f"  FAIL {fn.__name__}: unexpected "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
    if failures:
        print(f"FAIL: SC08-02 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: SC08-02 SDK transport security, IPSec crypto and PSK-exclusion gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
