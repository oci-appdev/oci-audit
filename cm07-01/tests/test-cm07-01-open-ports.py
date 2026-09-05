#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for the CM07-01 SDK collector.

Fixtures mirror real SDK response models, verified against oci==2.185.1, and
exercise both rule models: security lists use separate IngressSecurityRule and
EgressSecurityRule types with no direction field, while NSGs use one
SecurityRule with an explicit direction.

The central property: a portless protocol must not match a port-scoped PPSM
entry. The ICMP fixture below sits alongside a PPSM list that prohibits TCP
3389, and the collector must not report the ICMP rule as hitting it. Modelling
ICMP as ports 0-65535 makes exactly that false match.

PYTHON FILES USED:
  cm07-01/cm07-01-open-ports.py   collector under test
  lib/oci_audit_sdk.py            loaded transitively
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
TENANCY = "ocid1.tenancy.oc1..cm07mock"
SHARED = "ocid1.compartment.oc1..sharedservices"
FOREIGN_LIST = "ocid1.securitylist.oc1..elsewhere"
UNREADABLE_LIST = "ocid1.securitylist.oc1..denied"

_spec = importlib.util.spec_from_file_location(
    "cm0701", ROOT / "cm07-01" / "cm07-01-open-ports.py")
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
    nsg_rules = False


def port(low, high):
    return Obj(destination_port_range=Obj(min=low, max=high))


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


class VirtualNetworkClient(BaseClient):
    def list_security_lists(self, **kw):
        return Response([
            Obj(id="ocid1.securitylist.oc1..sl1", display_name="web-tier",
                ingress_security_rules=[
                    # Approved: HTTPS from anywhere.
                    Obj(protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
                        tcp_options=port(443, 443), is_stateless=False,
                        description="https"),
                    # Prohibited: RDP.
                    Obj(protocol="6", source="10.0.0.0/8", source_type="CIDR_BLOCK",
                        tcp_options=port(3389, 3389), description="rdp"),
                    # ICMP: portless. Must NOT match the TCP 3389 prohibition.
                    Obj(protocol="1", source="10.0.0.0/8", source_type="CIDR_BLOCK",
                        icmp_options=Obj(type=8, code=0), description="ping"),
                    # Protocol-wide with no port constraint.
                    Obj(protocol="6", source="192.168.0.0/16",
                        source_type="CIDR_BLOCK", description="all tcp"),
                ],
                egress_security_rules=[
                    Obj(protocol="all", destination="0.0.0.0/0",
                        destination_type="CIDR_BLOCK", description="egress any"),
                ]),
            Obj(id="ocid1.securitylist.oc1..empty", display_name="empty-list"),
        ])

    def list_subnets(self, **kw):
        return Response([
            Obj(id="ocid1.subnet.oc1..s1", display_name="app-subnet",
                security_list_ids=["ocid1.securitylist.oc1..sl1", FOREIGN_LIST]),
            Obj(id="ocid1.subnet.oc1..s2", display_name="locked-subnet",
                security_list_ids=[UNREADABLE_LIST]),
        ])

    def get_security_list(self, security_list_id, **kw):
        if security_list_id == UNREADABLE_LIST:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "read cross-compartment security list denied")
        return Response(Obj(
            id=security_list_id, display_name="shared-services-list",
            ingress_security_rules=[
                Obj(protocol="6", source="0.0.0.0/0", source_type="CIDR_BLOCK",
                    tcp_options=port(22, 22), description="ssh from anywhere")]))

    def list_network_security_groups(self, **kw):
        return Response([Obj(id="ocid1.nsg.oc1..n1", display_name="db-nsg")])

    def list_network_security_group_security_rules(self, network_security_group_id, **kw):
        if Denials.nsg_rules:
            raise ServiceError(403, "NotAuthorizedOrNotFound",
                               "list NSG rules was denied")
        return Response([
            Obj(id="nsgrule1", direction="INGRESS", protocol="6",
                source="10.1.0.0/16", source_type="CIDR_BLOCK",
                tcp_options=port(1521, 1521), is_valid=True, description="oracle"),
            Obj(id="nsgrule2", direction="EGRESS", protocol="17",
                destination="10.2.0.0/16", destination_type="CIDR_BLOCK",
                tcp_options=port(53, 53), is_valid=True, description="dns"),
        ])


def build_sdk() -> types.ModuleType:
    oci = types.ModuleType("oci")

    def list_all(method, *args, **kwargs):
        kwargs.pop("retry_strategy", None)
        return method(*args, **kwargs)

    oci.pagination = types.SimpleNamespace(list_call_get_all_results=list_all)
    oci.retry = types.SimpleNamespace(DEFAULT_RETRY_STRATEGY=object())
    oci.exceptions = types.SimpleNamespace(ServiceError=ServiceError)
    oci.identity = types.SimpleNamespace(IdentityClient=IdentityClient)
    oci.core = types.SimpleNamespace(VirtualNetworkClient=VirtualNetworkClient)
    oci.config = types.SimpleNamespace(
        from_file=lambda path, profile: {"tenancy": TENANCY, "region": "us-langley-1"},
        validate_config=lambda config: None)
    return oci


PPSM_FIELDS = ["protocol", "port_from", "port_to", "direction", "disposition",
               "icmp_type", "icmp_code", "approval_id"]
PPSM_ROWS = [
    {"protocol": "TCP", "port_from": "443", "port_to": "443",
     "direction": "INGRESS", "disposition": "APPROVED", "approval_id": "PPSM-443"},
    {"protocol": "TCP", "port_from": "3389", "port_to": "3389",
     "direction": "INGRESS", "disposition": "PROHIBITED", "approval_id": "PPSM-RDP"},
    {"protocol": "TCP", "port_from": "22", "port_to": "22",
     "direction": "INGRESS", "disposition": "RESTRICTED", "approval_id": "PPSM-SSH"},
    # Protocol-scoped ICMP entry, no ports: this is what an ICMP rule may match.
    {"protocol": "ICMP", "port_from": "", "port_to": "", "direction": "INGRESS",
     "disposition": "APPROVED", "icmp_type": "8", "approval_id": "PPSM-PING"},
    # An ANY-protocol entry WITH ports. This is the row that catches the real
    # defect: the protocol check does not filter it out, so only the portless
    # rule's refusal to match a port-scoped entry stops an ICMP rule from being
    # reported as a prohibited port.
    {"protocol": "ANY", "port_from": "3389", "port_to": "3389",
     "direction": "INGRESS", "disposition": "PROHIBITED",
     "approval_id": "PPSM-ANY-RDP"},
]


def write_ppsm(tmp, rows=None):
    path = Path(tmp) / "ppsm.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PPSM_FIELDS)
        writer.writeheader()
        for row in (rows if rows is not None else PPSM_ROWS):
            writer.writerow({f: row.get(f, "") for f in PPSM_FIELDS})
    return str(path)


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


def rule(rows, **criteria):
    hits = [r for r in rows if all(r.get(k) == v for k, v in criteria.items())]
    assert len(hits) == 1, f"expected one rule matching {criteria}, got {len(hits)}"
    return hits[0]


CHECKS = []


def check(fn):
    CHECKS.append(fn)
    return fn


@check
def test_portless_icmp_does_not_match_a_port_scoped_prohibition():
    """The defect this collector exists to avoid.

    Modelling ICMP as ports 0-65535 makes an ICMP rule overlap the TCP 3389
    prohibition, reporting a ping rule as a prohibited RDP port.
    """
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(["--ppsm", write_ppsm(tmp), "-s", "securitylists"], tmp)
        assert rc == 3, (rc, out)   # the unreadable cross-compartment list
        rows = read_csv(tmp, "open_ports_2")

        icmp = rule(rows, protocol_name="ICMP", container_name="web-tier")
        # PPSM_ROWS contains an ANY-protocol entry prohibiting port 3389, which
        # the protocol check does NOT filter out. Only the portless rule's
        # refusal to match a port-scoped entry keeps this ping rule from being
        # reported as a prohibited RDP port.
        assert icmp["ppsm_status"] == "APPROVED", icmp
        assert icmp["ppsm_reference"] == "PPSM-PING", icmp
        assert icmp["ppsm_status"] != "PROHIBITED", icmp
        assert icmp["finding"] == "OK-APPROVED-PORT", icmp
        # A portless rule reports no ports at all.
        assert icmp["port_from"] == "n/a" and icmp["port_to"] == "n/a", icmp
        assert icmp["icmp_type"] == "8", icmp

        rdp = rule(rows, port_from="3389", container_name="web-tier")
        assert rdp["ppsm_status"] == "PROHIBITED", rdp
        assert rdp["finding"] == "PROHIBITED-PORT-OPEN", rdp


@check
def test_world_open_and_disposition_classification():
    with tempfile.TemporaryDirectory() as tmp:
        run(["--ppsm", write_ppsm(tmp), "-s", "securitylists"], tmp)
        rows = read_csv(tmp, "open_ports_2")

        https = rule(rows, port_from="443", container_name="web-tier")
        assert https["ppsm_status"] == "APPROVED", https
        # Approved, but exposed to the whole internet: still surfaced.
        assert https["finding"] == "APPROVED-BUT-WORLD-OPEN", https

        # Cross-compartment list resolved by OCID, and its SSH rule adjudicated.
        ssh = rule(rows, port_from="22")
        assert ssh["container_name"] == "shared-services-list", ssh
        assert "cross-compartment" in ssh["attached_to"], ssh
        assert ssh["finding"] == "RESTRICTED-PORT-WORLD-OPEN", ssh

        # A protocol-wide rule with no port constraint exposes every port.
        wide = rule(rows, peer="192.168.0.0/16")
        assert wide["port_from"] == "all" and wide["port_to"] == "all", wide

        assert rule(rows, container_name="empty-list")["finding"] == "NO-RULES-DEFINED"

        egress = rule(rows, direction="EGRESS", container_name="web-tier")
        assert egress["peer"] == "0.0.0.0/0", egress
        # World-open applies to ingress; an egress-any rule is not that finding.
        assert egress["finding"] != "WORLD-OPEN-INGRESS", egress


@check
def test_unreadable_cross_compartment_list_is_never_no_rules():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(["--ppsm", write_ppsm(tmp), "-s", "securitylists"], tmp)
        assert rc == 3, (rc, out)
        assert "RESULT   : INCOMPLETE" in out, out
        rows = read_csv(tmp, "open_ports_2")
        unresolved = [r for r in rows if r["finding"] == "UNRESOLVED-SECURITY-LIST"]
        assert len(unresolved) == 1, rows
        assert unresolved[0]["collection_status"] == "DENIED", unresolved[0]
        assert "locked-subnet" in unresolved[0]["attached_to"], unresolved[0]
        assert not [r for r in rows
                    if r["container_ocid"] == UNREADABLE_LIST
                    and r["finding"] == "NO-RULES-DEFINED"], rows


@check
def test_nsg_rules_carry_their_own_direction():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(["--ppsm", write_ppsm(tmp), "-s", "nsgs"], tmp)
        assert rc == 0, (rc, out)
        rows = read_csv(tmp, "open_ports_2")
        ingress = rule(rows, port_from="1521")
        assert ingress["direction"] == "INGRESS" and ingress["peer"] == "10.1.0.0/16"
        assert ingress["finding"] == "UNAPPROVED-PORT", ingress
        egress = rule(rows, port_from="53")
        assert egress["direction"] == "EGRESS" and egress["peer"] == "10.2.0.0/16"


@check
def test_prohibition_wins_over_approval_regardless_of_row_order():
    """A rule matching both dispositions must report the prohibition."""
    with tempfile.TemporaryDirectory() as tmp:
        rows_in = [
            {"protocol": "TCP", "port_from": "3389", "port_to": "3389",
             "direction": "INGRESS", "disposition": "APPROVED", "approval_id": "OOPS"},
            {"protocol": "TCP", "port_from": "3389", "port_to": "3389",
             "direction": "INGRESS", "disposition": "PROHIBITED", "approval_id": "PPSM-RDP"},
        ]
        run(["--ppsm", write_ppsm(tmp, rows_in), "-s", "securitylists"], tmp)
        rdp = rule(read_csv(tmp, "open_ports_2"), port_from="3389",
                   container_name="web-tier")
        assert rdp["ppsm_status"] == "PROHIBITED", rdp
        assert rdp["ppsm_reference"] == "PPSM-RDP", rdp


@check
def test_without_a_ppsm_nothing_is_adjudicated():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out = run(["-s", "nsgs"], tmp)
        assert rc == 0, (rc, out)
        assert "NOT adjudicated" in out, out
        rows = read_csv(tmp, "open_ports_2")
        assert rows and all(r["ppsm_status"] == "NOT-ADJUDICATED" for r in rows), rows
        assert not [r for r in rows if r["finding"].startswith("OK-APPROVED")], rows


@check
def test_unusable_ppsm_fails_before_scanning():
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "wrong.csv"
        bad.write_text("port\n443\n", encoding="utf-8")
        unknown = Path(tmp) / "unknown-disposition.csv"
        with unknown.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=PPSM_FIELDS)
            writer.writeheader()
            writer.writerow({f: "" for f in PPSM_FIELDS} | {
                "protocol": "TCP", "port_from": "1", "port_to": "1",
                "direction": "INGRESS", "disposition": "MAYBE"})
        for path in (str(bad), str(unknown), str(Path(tmp) / "missing.csv")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MODULE.main(["-r", "us-langley-1", "-o", tmp, "-c", SHARED,
                                  "--non-interactive", "--confirm-scope-ocid", SHARED,
                                  "--approve-scan", "YES", "--ppsm", path],
                                 oci_module=build_sdk())
            assert rc == 1, (path, rc, buf.getvalue())
        assert not list(Path(tmp).rglob("*open_ports*.csv")), \
            "an unusable PPSM still produced evidence"


@check
def test_denied_nsg_rule_listing_is_never_no_rules():
    Denials.nsg_rules = True
    try:
        with tempfile.TemporaryDirectory() as tmp:
            rc, out = run(["-s", "nsgs"], tmp)
            assert rc == 3, (rc, out)
            rows = read_csv(tmp, "open_ports_2")
            assert rows and all(r["finding"] == "COLLECTION-FAILED" for r in rows), rows
            assert not [r for r in rows if r["finding"] == "NO-RULES-DEFINED"], rows
    finally:
        Denials.nsg_rules = False


@check
def test_semantic_rule_keys_are_stable_and_distinct():
    with tempfile.TemporaryDirectory() as tmp:
        run(["--ppsm", write_ppsm(tmp), "-s", "securitylists"], tmp)
        first = read_csv(tmp, "open_ports_2")
    with tempfile.TemporaryDirectory() as tmp:
        run(["--ppsm", write_ppsm(tmp), "-s", "securitylists"], tmp)
        second = read_csv(tmp, "open_ports_2")
    keys_first = [r["semantic_rule_key"] for r in first if r["semantic_rule_key"]]
    keys_second = [r["semantic_rule_key"] for r in second if r["semantic_rule_key"]]
    # Stable across runs: security-list rules have no OCID, so without this a
    # reordered rule set looks like every rule was replaced.
    assert keys_first == keys_second, (keys_first, keys_second)
    assert len(set(keys_first)) == len(keys_first), "duplicate semantic keys"


@check
def test_readonly_allowlist_is_the_complete_cloud_surface():
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
            failures += 1
            print(f"  FAIL {fn.__name__}: unexpected "
                  f"{type(exc).__name__}: {exc}", file=sys.stderr)
    if failures:
        print(f"FAIL: CM07-01 SDK collector ({failures} failed)", file=sys.stderr)
        return 1
    print("PASS: CM07-01 SDK portless-protocol, PPSM reconciliation, "
          "cross-compartment and fail-closed gates")
    return 0


if __name__ == "__main__":
    sys.exit(main())
