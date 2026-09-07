#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for CP02-01 contingency planning.

The mock mirrors oci==2.185.1. Two omissions are deliberate: the protection
group summary has no ``members`` and the plan summary has no ``plan_groups``,
because the real ones do not. Supplying them would let a collector that never
calls the get operations pass.
"""

from __future__ import annotations

import csv
import importlib.util
import io
import os
import stat
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cp02_01", ROOT / "cp02-01" / "cp02-01-contingency-planning.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..cp02tenancy"
SHARED = "ocid1.compartment.oc1..cp02shared"
NOW = datetime.now(timezone.utc)

FULL_GROUP = "ocid1.drprotectiongroup.oc1..cp02full"
EMPTY_GROUP = "ocid1.drprotectiongroup.oc1..cp02empty"
NODRILL_GROUP = "ocid1.drprotectiongroup.oc1..cp02nodrill"

PROTECTED_DB = "ocid1.autonomousdatabase.oc1..cp02db"
PROTECTED_VM = "ocid1.instance.oc1..cp02vm"
UNPROTECTED_VM = "ocid1.instance.oc1..cp02unprotected"

FULL_PLAN = "ocid1.drplan.oc1..cp02fullplan"
DRILL_PLAN = "ocid1.drplan.oc1..cp02drillplan"
NODRILL_PLAN = "ocid1.drplan.oc1..cp02nodrillplan"


class Response:
    def __init__(self, data, rid="mock-req"):
        self.data = data
        self.headers = {"opc-request-id": rid}
        self.next_page = None


class Collection:
    def __init__(self, items):
        self.items = items


class FakeServiceError(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.status = 403
        self.code = "NotAuthorizedOrNotFound"
        self.opc_request_id = "denied-req"
        self.message = msg


class FakeState:
    def __init__(self):
        self.calls: List[Any] = []
        self.fail_method = ""
        self.groups = [FULL_GROUP, EMPTY_GROUP, NODRILL_GROUP]
        self.regions = ["us-ashburn-1", "us-phoenix-1"]

    def call(self, method, arg=""):
        self.calls.append((method, arg))
        if self.fail_method == method:
            raise FakeServiceError(f"mock denied token=abc123 method={method}")

    def workload_calls(self):
        scope = {"get_compartment", "list_compartments"}
        return [c for c in self.calls if c[0] not in scope]


class BaseClient:
    state: Optional[FakeState] = None

    def __init__(self, config, **kwargs):
        self.config = config


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kwargs):
        self.state.call("get_compartment", compartment_id)
        names = {TENANCY: "MockTenancy", SHARED: "Shared"}
        return Response(SimpleNamespace(id=compartment_id,
                                        name=names.get(compartment_id, "?")))

    def list_compartments(self, compartment_id, **kwargs):
        self.state.call("list_compartments", compartment_id)
        return Response(Collection([SimpleNamespace(id=SHARED, name="Shared")]))

    def list_region_subscriptions(self, tenancy_id, **kwargs):
        self.state.call("list_region_subscriptions", tenancy_id)
        return Response(Collection([
            SimpleNamespace(region_key=name[:3], region_name=name, status="READY",
                            is_home_region=(index == 0))
            for index, name in enumerate(self.state.regions)
        ]))

    def list_availability_domains(self, compartment_id, **kwargs):
        self.state.call("list_availability_domains", compartment_id)
        return Response(Collection([
            SimpleNamespace(name="AD-1", id="ocid1.ad.1"),
            SimpleNamespace(name="AD-2", id="ocid1.ad.2"),
        ]))

    def list_fault_domains(self, compartment_id, availability_domain, **kwargs):
        self.state.call("list_fault_domains", availability_domain)
        return Response(Collection([
            SimpleNamespace(name="FD-1"), SimpleNamespace(name="FD-2"),
            SimpleNamespace(name="FD-3"),
        ]))


def _group_summary(group_id, name, peer="ocid1.drprotectiongroup.oc1..peer"):
    """Mirrors DrProtectionGroupSummary -- which has NO members field."""
    return SimpleNamespace(
        id=group_id, compartment_id=SHARED, display_name=name, role="PRIMARY",
        peer_id=peer, peer_region="us-phoenix-1", time_created=NOW, time_updated=NOW,
        lifecycle_state="ACTIVE", lifecycle_sub_state="",
        # The model really does spell it life_cycle_details while the state
        # field beside it is lifecycle_state.
        life_cycle_details="group is healthy",
    )


GROUP_MEMBERS = {
    FULL_GROUP: [
        SimpleNamespace(member_id=PROTECTED_DB, member_type="AUTONOMOUS_DATABASE"),
        SimpleNamespace(member_id=PROTECTED_VM, member_type="COMPUTE_INSTANCE"),
    ],
    EMPTY_GROUP: [],
    NODRILL_GROUP: [SimpleNamespace(member_id=PROTECTED_VM,
                                    member_type="COMPUTE_INSTANCE")],
}

GROUP_PLANS = {
    FULL_GROUP: [
        (FULL_PLAN, "prod-switchover", "SWITCHOVER"),
        (DRILL_PLAN, "prod-drill", "START_DRILL"),
    ],
    EMPTY_GROUP: [],
    NODRILL_GROUP: [(NODRILL_PLAN, "failover-only", "FAILOVER")],
}


class DisasterRecoveryClient(BaseClient):
    def list_dr_protection_groups(self, compartment_id, **kwargs):
        self.state.call("list_dr_protection_groups", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        names = {FULL_GROUP: "prod-dr", EMPTY_GROUP: "empty-dr",
                 NODRILL_GROUP: "nodrill-dr"}
        return Response(Collection([_group_summary(g, names[g])
                                    for g in self.state.groups]))

    def get_dr_protection_group(self, dr_protection_group_id, **kwargs):
        self.state.call("get_dr_protection_group", dr_protection_group_id)
        summary = _group_summary(dr_protection_group_id, "detail")
        summary.members = GROUP_MEMBERS[dr_protection_group_id]
        summary.log_location = None
        return Response(summary)

    def list_dr_plans(self, dr_protection_group_id, **kwargs):
        self.state.call("list_dr_plans", dr_protection_group_id)
        return Response(Collection([
            # Mirrors DrPlanSummary -- NO plan_groups field.
            SimpleNamespace(id=pid, compartment_id=SHARED, display_name=name,
                            type=ptype, dr_protection_group_id=dr_protection_group_id,
                            peer_region="us-phoenix-1", time_created=NOW,
                            lifecycle_state="ACTIVE", lifecycle_sub_state="",
                            life_cycle_details="")
            for pid, name, ptype in GROUP_PLANS[dr_protection_group_id]
        ]))

    def get_dr_plan(self, dr_plan_id, **kwargs):
        self.state.call("get_dr_plan", dr_plan_id)
        steps = [SimpleNamespace(id="s1", is_enabled=True, display_name="stop app"),
                 SimpleNamespace(id="s2", is_enabled=True, display_name="switch db")]
        if dr_plan_id == NODRILL_PLAN:
            steps = [SimpleNamespace(id="s1", is_enabled=False, display_name="disabled")]
        return Response(SimpleNamespace(
            id=dr_plan_id, display_name="detail", compartment_id=SHARED,
            type="SWITCHOVER", time_created=NOW, peer_region="us-phoenix-1",
            lifecycle_state="ACTIVE", life_cycle_details="",
            plan_groups=[SimpleNamespace(id="g1", type="USER_DEFINED",
                                         display_name="group", steps=steps)],
        ))


def _fake_oci(state: FakeState) -> Any:
    IdentityClient.state = state
    DisasterRecoveryClient.state = state

    class pagination:
        @staticmethod
        def list_call_get_all_results(fn, *args, **kwargs):
            resp = fn(*args, **kwargs)
            data = resp.data
            resp.data = list(getattr(data, "items", data if isinstance(data, list) else []))
            return resp

    class retry:
        DEFAULT_RETRY_STRATEGY = None

    class identity:
        IdentityClient = globals()["IdentityClient"]

    class disaster_recovery:
        DisasterRecoveryClient = globals()["DisasterRecoveryClient"]

    class exceptions:
        ServiceError = FakeServiceError

    return SimpleNamespace(
        pagination=pagination, retry=retry, identity=identity,
        disaster_recovery=disaster_recovery, exceptions=exceptions,
        config=SimpleNamespace(
            from_file=lambda *a, **kw: {"tenancy": TENANCY, "region": "us-ashburn-1"},
            validate_config=lambda c: None),
        auth=SimpleNamespace(signers=SimpleNamespace(
            InstancePrincipalsSecurityTokenSigner=lambda: None,
            get_resource_principals_signer=lambda: None)),
        __version__="2.185.1-mock",
    )


def _run(args, state=None):
    if state is None:
        state = FakeState()
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = MODULE.main(args, oci_module=_fake_oci(state))
    return rc, out.getvalue(), err.getvalue(), state


def _read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _base_args(tmp):
    return ["--region", "us-ashburn-1", "--output-dir", tmp, "--tenancy-scope",
            "--non-interactive", "--approve-scan", "YES",
            "--confirm-scope-ocid", TENANCY, "--confirm-scope-ocid", SHARED]


def _find(tmp, suffix):
    matches = [str(p) for p in Path(tmp).glob(f"*{suffix}")]
    assert matches, f"no output matching *{suffix}"
    return matches[0]


def _write_register(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=MODULE.ISCP_REGISTER_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def _register_row(**kw):
    row = {f: "" for f in MODULE.ISCP_REGISTER_FIELDS}
    row.update({"system_id": "S1", "system_name": "Prod DB", "system_owner": "ops",
                "rto_hours": "4", "rpo_hours": "1", "recovery_priority": "1",
                "alternate_site": "us-phoenix-1", "approval_reference": "ISCP-1"})
    row.update(kw)
    return row


# --------------------------------------------------------------------------


def test_selfcheck():
    out = io.StringIO()
    with redirect_stdout(out):
        rc = MODULE.main(["--selfcheck"])
    assert rc == 0 and "PASSED" in out.getvalue()


def test_region_required():
    rc, _, err, state = _run(["--tenancy-scope", "--non-interactive",
                              "--approve-scan", "YES"])
    assert rc == 1 and "region" in err.lower()
    assert not state.calls


def test_approval_refusal_reads_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        args = _base_args(tmp)
        args[args.index("YES")] = "yes"
        rc, _, _, state = _run(args)
        assert rc == 1
        assert not state.workload_calls()


def test_full_collection():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, err, _ = _run(_base_args(tmp))
        assert rc == 0, err
        assert "CP02-01 COLLECTION COMPLETE" in out


def test_get_protection_group_is_called_because_summary_has_no_members():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        groups = {g["group_id"]: g for g in _read_csv(_find(tmp, "_dr_protection_groups.csv"))}
        assert groups[FULL_GROUP]["member_count"] == "2"
        assert "AUTONOMOUS_DATABASE" in groups[FULL_GROUP]["member_types"]
        members = _read_csv(_find(tmp, "_dr_members.csv"))
        assert {m["member_id"] for m in members} >= {PROTECTED_DB, PROTECTED_VM}


def test_member_count_is_unknown_not_zero_when_the_get_fails():
    """Reporting 0 members would say the group protects nothing -- a finding we
    did not observe. A failed read is UNKNOWN."""
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "get_dr_protection_group"
        rc, _, _, _ = _run(_base_args(tmp), state=state)
        assert rc == 3
        groups = _read_csv(_find(tmp, "_dr_protection_groups.csv"))
        assert all(g["member_count"] == "UNKNOWN" for g in groups)
        assert all(g["group_finding"] == "GROUP-DETAIL-NOT-READ" for g in groups)


def test_get_dr_plan_is_called_because_summary_has_no_plan_groups():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        plans = {p["plan_id"]: p for p in _read_csv(_find(tmp, "_dr_plans.csv"))}
        assert plans[FULL_PLAN]["step_count"] == "2"
        assert plans[FULL_PLAN]["plan_finding"] == "OK"
        assert plans[NODRILL_PLAN]["plan_finding"] == "PLAN-ALL-STEPS-DISABLED"


def test_group_findings():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        groups = {g["group_id"]: g for g in _read_csv(_find(tmp, "_dr_protection_groups.csv"))}
        assert groups[FULL_GROUP]["group_finding"] == "OK"
        assert groups[FULL_GROUP]["has_drill_plan"] == "YES"
        assert groups[EMPTY_GROUP]["group_finding"] == "GROUP-HAS-NO-MEMBERS"
        # Has members and a plan, but no drill plan: it cannot be exercised
        # without moving production.
        assert groups[NODRILL_GROUP]["group_finding"] == "GROUP-HAS-NO-DRILL-PLAN"


def test_reads_life_cycle_details_not_lifecycle_details():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        groups = _read_csv(_find(tmp, "_dr_protection_groups.csv"))
        assert groups[0]["lifecycle_detail"] == "group is healthy"


def test_absent_full_stack_dr_is_not_a_failure():
    """Most tenancies do DR without Full Stack DR. An empty result means OCI
    holds no DR record, not that no contingency plan exists."""
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.groups = []
        rc, out, _, _ = _run(_base_args(tmp), state=state)
        assert rc == 0, "no DR configuration must not fail the collection"
        assert "MANUAL-VERIFY-NO-OCI-DR-RECORD" in out
        assert "NOT a CP-2 failure" in out


def test_single_region_tenancy_is_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.regions = ["us-ashburn-1"]
        rc, out, _, _ = _run(_base_args(tmp), state=state)
        rows = _read_csv(_find(tmp, "_region_subscriptions.csv"))
        assert rows[0]["region_finding"] == "SINGLE-REGION-TENANCY"
        assert "Alternate region available : NO" in out


def test_fault_domains_recorded():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = _read_csv(_find(tmp, "_domain_resilience.csv"))
        assert len(rows) == 2
        assert all(r["fault_domains"] == "3" for r in rows)


# --------------------------------------------------------------------------
# ISCP register
# --------------------------------------------------------------------------


def test_snapshot_only_without_register():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _, _ = _run(_base_args(tmp))
        assert rc == 0
        assert "SNAPSHOT-ONLY-NO-ISCP-REGISTER" in out


def test_unusable_register_fails_before_scanning():
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, _, state = _run(_base_args(tmp) +
                               ["--iscp-register", str(Path(tmp) / "nope.csv")])
        assert rc == 1 and not state.calls

        empty = str(Path(tmp) / "empty.csv")
        _write_register(empty, [])
        rc, _, err, state = _run(_base_args(tmp) + ["--iscp-register", empty])
        assert rc == 1 and "no rows" in err and not state.calls


def test_register_reconciliation_by_ocid():
    with tempfile.TemporaryDirectory() as tmp:
        register = str(Path(tmp) / "iscp.csv")
        _write_register(register, [
            _register_row(system_id="S1", system_name="Prod DB",
                          resource_ocid=PROTECTED_DB),
            _register_row(system_id="S2", system_name="Orphan VM",
                          resource_ocid=UNPROTECTED_VM),
            _register_row(system_id="S3", system_name="No RTO stated",
                          resource_ocid=PROTECTED_VM, rto_hours=""),
        ])
        rc, _, _, _ = _run(_base_args(tmp) + ["--iscp-register", register])
        rows = {r["system_name"]: r for r in _read_csv(_find(tmp, "_iscp_reconciliation.csv"))}
        assert rows["Prod DB"]["coverage_status"] == "DR-PROTECTED"
        assert rows["Prod DB"]["dr_member_type"] == "AUTONOMOUS_DATABASE"
        assert rows["Orphan VM"]["coverage_status"] == "NOT-IN-DR-PROTECTION-GROUP"
        # OCI cannot supply an RTO, so a register that omits one is incomplete.
        assert rows["No RTO stated"]["coverage_status"] == "REGISTER-INCOMPLETE"
        assert rc == 3


def test_coverage_is_matched_by_ocid_not_display_name():
    """A name is not an identity: a rename would silently move coverage."""
    with tempfile.TemporaryDirectory() as tmp:
        register = str(Path(tmp) / "iscp.csv")
        _write_register(register, [
            _register_row(system_name="prod-dr", resource_ocid=""),
        ])
        rc, _, _, _ = _run(_base_args(tmp) + ["--iscp-register", register])
        row = _read_csv(_find(tmp, "_iscp_reconciliation.csv"))[0]
        assert row["coverage_status"] == "REGISTER-INCOMPLETE"
        assert "by name" in row["coverage_detail"]


def test_register_template_is_blank():
    """A register pre-filled from the tenancy could never show that something
    in scope was left out of the DR arrangement."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        assert _read_csv(_find(tmp, "_iscp_register_template.csv")) == []


# --------------------------------------------------------------------------


def test_denied_call_is_coverage_not_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_dr_protection_groups"
        rc, _, _, _ = _run(_base_args(tmp), state=state)
        assert rc == 3
        rows = [r for r in _read_csv(_find(tmp, "_collection_coverage.csv"))
                if r["operation"] == "disaster_recovery.list_dr_protection_groups"]
        assert rows and all(r["status"] == "DENIED" for r in rows)
        assert _read_csv(_find(tmp, "_dr_protection_groups.csv")) == []
        assert _read_csv(_find(tmp, "_collection_errors.csv"))


def test_secret_redacted_in_errors():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_dr_plans"
        _run(_base_args(tmp), state=state)
        text = Path(_find(tmp, "_collection_errors.csv")).read_text()
        assert "abc123" not in text and "<redacted>" in text


def test_private_outputs():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        for path in Path(tmp).glob("cp02-01_*"):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path


def test_plan_names_the_dr_boundary():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        plan = Path(_find(tmp, "_approved_scan_plan.txt")).read_text()
        assert "SCAN APPROVED" in plan
        assert "switchover" in plan.lower() and "failover" in plan.lower()
        assert "RTO/RPO" in plan


def test_no_mutating_dr_operation_is_declared():
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name
    for forbidden in ("create_dr_plan_execution", "delete_dr_protection_group",
                      "change_dr_protection_group_compartment"):
        assert forbidden not in MODULE.SDK_READ_METHODS


if __name__ == "__main__":
    import traceback
    tests = [
        test_selfcheck, test_region_required, test_approval_refusal_reads_nothing,
        test_full_collection,
        test_get_protection_group_is_called_because_summary_has_no_members,
        test_member_count_is_unknown_not_zero_when_the_get_fails,
        test_get_dr_plan_is_called_because_summary_has_no_plan_groups,
        test_group_findings, test_reads_life_cycle_details_not_lifecycle_details,
        test_absent_full_stack_dr_is_not_a_failure,
        test_single_region_tenancy_is_flagged, test_fault_domains_recorded,
        test_snapshot_only_without_register,
        test_unusable_register_fails_before_scanning,
        test_register_reconciliation_by_ocid,
        test_coverage_is_matched_by_ocid_not_display_name,
        test_register_template_is_blank,
        test_denied_call_is_coverage_not_a_finding,
        test_secret_redacted_in_errors, test_private_outputs,
        test_plan_names_the_dr_boundary, test_no_mutating_dr_operation_is_declared,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        # Exception, not only AssertionError: otherwise an unexpected raise
        # takes the runner down with no FAIL line.
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
