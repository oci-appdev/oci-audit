#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for CP04-01 contingency plan testing.

The central assertion in this file is that a ``*_PRECHECK`` execution is never
counted as a test. A precheck validates that a plan could run; it does not run
it. Prechecks are cheap, frequent and routinely succeed, so treating one as an
exercise is the easiest way to report an untested plan as tested.

``DrPlanExecutionSummary`` here has no ``is_automatic`` and no
``step_status_counts``, because the real one does not -- that is what forces
``get_dr_plan_execution``.
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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "cp04_01", ROOT / "cp04-01" / "cp04-01-contingency-plan-testing.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..cp04tenancy"
SHARED = "ocid1.compartment.oc1..cp04shared"
NOW = datetime.now(timezone.utc)
# Relative offsets only: a literal date would silently change what the fixture
# asserts once it passed.
RECENT = NOW - timedelta(days=30)
STALE = NOW - timedelta(days=500)

GROUP = "ocid1.drprotectiongroup.oc1..cp04group"

TESTED_PLAN = "ocid1.drplan.oc1..cp04tested"
PRECHECK_PLAN = "ocid1.drplan.oc1..cp04precheck"
STALE_PLAN = "ocid1.drplan.oc1..cp04stale"
NEVER_PLAN = "ocid1.drplan.oc1..cp04never"
REALMOVE_PLAN = "ocid1.drplan.oc1..cp04realmove"
AUTO_PLAN = "ocid1.drplan.oc1..cp04auto"

GOOD_DRILL = "ocid1.drplanexecution.oc1..cp04gooddrill"
PRECHECK_EXEC = "ocid1.drplanexecution.oc1..cp04precheck"
STALE_DRILL = "ocid1.drplanexecution.oc1..cp04staledrill"
REAL_MOVE = "ocid1.drplanexecution.oc1..cp04realmove"
AUTO_EXEC = "ocid1.drplanexecution.oc1..cp04auto"


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
        self.has_groups = True

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


PLANS = [
    (TESTED_PLAN, "tested-drill", "START_DRILL"),
    (PRECHECK_PLAN, "precheck-only", "START_DRILL"),
    (STALE_PLAN, "stale-drill", "START_DRILL"),
    (NEVER_PLAN, "never-run", "SWITCHOVER"),
    (REALMOVE_PLAN, "real-move-only", "FAILOVER"),
    (AUTO_PLAN, "automatic-only", "FAILOVER"),
]


def _execution(exec_id, plan_id, kind, state, started):
    """Mirrors DrPlanExecutionSummary: no is_automatic, no step_status_counts."""
    return SimpleNamespace(
        id=exec_id, compartment_id=SHARED, display_name=f"exec-{kind}",
        plan_id=plan_id, plan_execution_type=kind,
        dr_protection_group_id=GROUP, peer_dr_protection_group_id="",
        peer_region="us-phoenix-1", log_location=None,
        time_created=started, time_started=started, time_updated=started,
        time_ended=started + timedelta(minutes=20),
        execution_duration_in_sec=1200, lifecycle_state=state,
        life_cycle_details="",
    )


EXECUTIONS = [
    _execution(GOOD_DRILL, TESTED_PLAN, "START_DRILL", "SUCCEEDED", RECENT),
    # A precheck of a drill. The name contains START_DRILL, which is exactly
    # why a substring test would misclassify it.
    _execution(PRECHECK_EXEC, PRECHECK_PLAN, "START_DRILL_PRECHECK", "SUCCEEDED", RECENT),
    _execution(STALE_DRILL, STALE_PLAN, "START_DRILL", "SUCCEEDED", STALE),
    _execution(REAL_MOVE, REALMOVE_PLAN, "FAILOVER", "SUCCEEDED", RECENT),
    _execution(AUTO_EXEC, AUTO_PLAN, "FAILOVER", "SUCCEEDED", RECENT),
]

AUTOMATIC = {AUTO_EXEC}


class DisasterRecoveryClient(BaseClient):
    def list_dr_protection_groups(self, compartment_id, **kwargs):
        self.state.call("list_dr_protection_groups", compartment_id)
        if compartment_id != SHARED or not self.state.has_groups:
            return Response(Collection([]))
        return Response(Collection([SimpleNamespace(
            id=GROUP, compartment_id=SHARED, display_name="prod-dr", role="PRIMARY",
            peer_id="ocid1.drprotectiongroup.oc1..peer", peer_region="us-phoenix-1",
            time_created=NOW, lifecycle_state="ACTIVE", life_cycle_details="")]))

    def list_dr_plans(self, dr_protection_group_id, **kwargs):
        self.state.call("list_dr_plans", dr_protection_group_id)
        return Response(Collection([
            SimpleNamespace(id=pid, compartment_id=SHARED, display_name=name,
                            type=ptype, dr_protection_group_id=GROUP,
                            peer_region="us-phoenix-1", time_created=NOW,
                            lifecycle_state="ACTIVE", life_cycle_details="")
            for pid, name, ptype in PLANS
        ]))

    def list_dr_plan_executions(self, dr_protection_group_id, **kwargs):
        self.state.call("list_dr_plan_executions", dr_protection_group_id)
        return Response(Collection(list(EXECUTIONS)))

    def get_dr_plan_execution(self, dr_plan_execution_id, **kwargs):
        self.state.call("get_dr_plan_execution", dr_plan_execution_id)
        base = next(e for e in EXECUTIONS if e.id == dr_plan_execution_id)
        return Response(SimpleNamespace(
            id=base.id, compartment_id=SHARED, display_name=base.display_name,
            plan_id=base.plan_id, plan_execution_type=base.plan_execution_type,
            lifecycle_state=base.lifecycle_state, time_started=base.time_started,
            time_ended=base.time_ended, life_cycle_details="",
            execution_duration_in_sec=base.execution_duration_in_sec,
            # Only the full model carries these two.
            is_automatic=dr_plan_execution_id in AUTOMATIC,
            # Mirrors DrPlanExecutionStepStatusCounts: an object, not a dict.
            # failed_steps is itself an object carrying total_failed.
            step_status_counts=SimpleNamespace(
                total_steps=4, remaining_steps=0, skipped_steps=0,
                successful_steps=4, warning_steps=0,
                failed_steps=SimpleNamespace(total_failed=0, failed=0, timed_out=0)),
            group_executions=[], execution_options=None,
            automatic_execution_details=None,
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
        w = csv.DictWriter(fh, fieldnames=MODULE.TEST_REGISTER_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow(row)


def _register_row(**kw):
    row = {f: "" for f in MODULE.TEST_REGISTER_FIELDS}
    row.update({"test_id": "T1", "plan_id": TESTED_PLAN, "execution_ocid": GOOD_DRILL,
                "test_date": "2026-08-01", "test_type": "DRILL",
                "participants": "ops, secops", "test_report_reference": "RPT-1",
                "findings_count": "2", "corrective_actions_reference": "CAP-1",
                "approver": "CISO", "approval_status": "APPROVED"})
    row.update(kw)
    return row


# --------------------------------------------------------------------------


def test_selfcheck():
    out = io.StringIO()
    with redirect_stdout(out):
        rc = MODULE.main(["--selfcheck"])
    assert rc == 0 and "PASSED" in out.getvalue()


def test_exercise_class_unit():
    ec = MODULE.exercise_class
    assert ec("START_DRILL") == "DRILL"
    assert ec("STOP_DRILL") == "DRILL"
    assert ec("SWITCHOVER") == "REAL-MOVE"
    assert ec("FAILOVER") == "REAL-MOVE"
    # Every precheck variant, including the two whose names contain a drill
    # type. A substring check would call these drills.
    assert ec("START_DRILL_PRECHECK") == "PRECHECK"
    assert ec("STOP_DRILL_PRECHECK") == "PRECHECK"
    assert ec("SWITCHOVER_PRECHECK") == "PRECHECK"
    assert ec("FAILOVER_PRECHECK") == "PRECHECK"
    assert ec("") == "UNKNOWN"


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
        assert rc == 1 and not state.workload_calls()


def test_full_collection():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, err, _ = _run(_base_args(tmp))
        assert rc == 0, err
        assert "CP04-01 COLLECTION COMPLETE" in out


def test_precheck_is_never_counted_as_a_test():
    """The headline assertion. A plan whose only execution is a precheck has
    never been tested, however many prechecks succeeded."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        plans = {p["plan_id"]: p for p in _read_csv(_find(tmp, "_plan_test_status.csv"))}
        precheck = plans[PRECHECK_PLAN]
        assert precheck["executions_total"] == "1"
        assert precheck["prechecks_total"] == "1"
        assert precheck["drills_total"] == "0"
        assert precheck["test_status"] == "PLAN-PRECHECK-ONLY"
        assert precheck["days_since_last_exercise"] == "", \
            "a precheck must not count toward exercise recency"

        executions = {e["execution_id"]: e
                      for e in _read_csv(_find(tmp, "_dr_plan_executions.csv"))}
        assert executions[PRECHECK_EXEC]["exercise_class"] == "PRECHECK"
        assert executions[PRECHECK_EXEC]["execution_finding"] == "PRECHECK-NOT-AN-EXERCISE"


def test_plan_test_statuses():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        plans = {p["plan_id"]: p for p in _read_csv(_find(tmp, "_plan_test_status.csv"))}
        assert plans[TESTED_PLAN]["test_status"] == "OK"
        assert plans[TESTED_PLAN]["successful_drills"] == "1"
        assert plans[NEVER_PLAN]["test_status"] == "PLAN-NEVER-EXECUTED"
        assert plans[STALE_PLAN]["test_status"] == "PLAN-NO-EXERCISE-IN-WINDOW"
        # A real failover proves the plan works but is an event, not a test.
        assert plans[REALMOVE_PLAN]["test_status"] == "PLAN-EXERCISED-BY-REAL-MOVE-ONLY"


def test_stale_drill_passes_with_a_wider_window():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp) + ["--test-window-days", "900"])
        plans = {p["plan_id"]: p for p in _read_csv(_find(tmp, "_plan_test_status.csv"))}
        assert plans[STALE_PLAN]["test_status"] == "OK"


def test_get_execution_is_called_because_summary_has_no_is_automatic():
    """An execution the service started by itself is not a contingency test,
    and only the full model says which is which."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        executions = {e["execution_id"]: e
                      for e in _read_csv(_find(tmp, "_dr_plan_executions.csv"))}
        assert executions[AUTO_EXEC]["is_automatic"] == "YES"
        assert executions[AUTO_EXEC]["execution_finding"] == \
            "AUTOMATIC-EXECUTION-NOT-A-SCHEDULED-TEST"
        assert executions[GOOD_DRILL]["is_automatic"] == "NO"
        assert executions[GOOD_DRILL]["execution_finding"] == "OK"
        # step_status_counts is also only on the full model.
        assert executions[GOOD_DRILL]["steps_total"] == "4"
        assert executions[GOOD_DRILL]["steps_failed"] == "0"


def test_no_dr_plans_is_reported_honestly():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.has_groups = False
        rc, out, _, _ = _run(_base_args(tmp), state=state)
        assert rc == 0
        assert "No Full Stack DR plan was found" in out
        assert "test report, not an API result" in out


# --------------------------------------------------------------------------
# Test register
# --------------------------------------------------------------------------


def test_snapshot_only_without_register():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _, _ = _run(_base_args(tmp))
        assert rc == 0 and "SNAPSHOT-ONLY-NO-TEST-REGISTER" in out


def test_unusable_register_fails_before_scanning():
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, _, state = _run(_base_args(tmp) +
                               ["--test-register", str(Path(tmp) / "nope.csv")])
        assert rc == 1 and not state.calls
        empty = str(Path(tmp) / "empty.csv")
        _write_register(empty, [])
        rc, _, err, state = _run(_base_args(tmp) + ["--test-register", empty])
        assert rc == 1 and not state.calls


def test_register_claiming_a_precheck_is_rejected():
    """A recorded test pointing at a precheck is the exact overstatement this
    collector exists to catch."""
    with tempfile.TemporaryDirectory() as tmp:
        register = str(Path(tmp) / "tests.csv")
        _write_register(register, [_register_row(test_id="T-PRE",
                                                 execution_ocid=PRECHECK_EXEC)])
        rc, _, _, _ = _run(_base_args(tmp) + ["--test-register", register])
        row = _read_csv(_find(tmp, "_test_register_validation.csv"))[0]
        assert row["validation_status"] == "INVALID"
        assert "precheck" in row["validation_message"]
        assert rc == 3


def test_register_validation_outcomes():
    with tempfile.TemporaryDirectory() as tmp:
        register = str(Path(tmp) / "tests.csv")
        _write_register(register, [
            _register_row(test_id="T-OK"),
            _register_row(test_id="T-UNKNOWN",
                          execution_ocid="ocid1.drplanexecution.oc1..nosuch"),
            _register_row(test_id="T-NOAPPROVAL", approval_status="DRAFT"),
            _register_row(test_id="T-NOREPORT", test_report_reference=""),
        ])
        rc, _, _, _ = _run(_base_args(tmp) + ["--test-register", register])
        rows = {r["test_id"]: r for r in _read_csv(_find(tmp, "_test_register_validation.csv"))}
        assert rows["T-OK"]["validation_status"] == "VALID"
        assert rows["T-OK"]["observed_execution_type"] == "START_DRILL"
        assert rows["T-UNKNOWN"]["validation_status"] == "INVALID"
        assert "does not match" in rows["T-UNKNOWN"]["validation_message"]
        assert rows["T-NOAPPROVAL"]["validation_status"] == "INVALID"
        assert rows["T-NOREPORT"]["validation_status"] == "INVALID"
        assert "test_report_reference" in rows["T-NOREPORT"]["validation_message"]
        assert rc == 3


def test_fully_valid_register_exits_zero():
    with tempfile.TemporaryDirectory() as tmp:
        register = str(Path(tmp) / "tests.csv")
        _write_register(register, [_register_row(test_id="T-OK")])
        rc, _, err, _ = _run(_base_args(tmp) + ["--test-register", register])
        assert rc == 0, err


def test_register_template_is_blank():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        assert _read_csv(_find(tmp, "_test_register_template.csv")) == []


# --------------------------------------------------------------------------


def test_denied_call_is_coverage_not_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_dr_plan_executions"
        rc, _, _, _ = _run(_base_args(tmp), state=state)
        assert rc == 3
        rows = [r for r in _read_csv(_find(tmp, "_collection_coverage.csv"))
                if r["operation"].startswith("disaster_recovery.list_dr_plan_executions")]
        assert rows and all(r["status"] == "DENIED" for r in rows)
        assert _read_csv(_find(tmp, "_dr_plan_executions.csv")) == []


def test_secret_redacted_in_errors():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_dr_plans"
        _run(_base_args(tmp), state=state)
        text = Path(_find(tmp, "_collection_errors.csv")).read_text()
        assert "abc123" not in text and "<redacted>" in text


def test_private_outputs_and_plan_boundary():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        for path in Path(tmp).glob("cp04-01_*"):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path
        plan = Path(_find(tmp, "_approved_scan_plan.txt")).read_text()
        assert "SCAN APPROVED" in plan
        assert "create_dr_plan_execution is unreachable" in plan
        assert "PRECHECK" in plan


def test_collector_cannot_start_an_execution():
    """A collector that audits DR testing must never be able to run a test:
    create_dr_plan_execution performs a real switchover or failover."""
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name
    assert "create_dr_plan_execution" not in MODULE.SDK_READ_METHODS
    source = (ROOT / "cp04-01" / "cp04-01-contingency-plan-testing.py").read_text()
    assert "create_dr_plan_execution(" not in source



def test_denied_execution_list_is_not_never_executed():
    """A denied list_dr_plan_executions must not assert testing history.

    group_executions stayed [] and every plan came out PLAN-NEVER-EXECUTED
    with executions_total=0 -- a 403 asserting "this plan has never been run".
    The original denied-call test only opened _dr_plan_executions.csv and the
    coverage ledger, never the file carrying the adjudication, so it passed.
    """
    state = FakeState()
    state.fail_method = "list_dr_plan_executions"
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, _, _ = _run(_base_args(tmp), state=state)
        rows = _read_csv(_find(tmp, "_plan_test_status.csv"))
        assert rows, "expected plan rows"
        for row in rows:
            assert row["test_status"] == "PLAN-EXECUTIONS-NOT-READ", row
            assert row["executions_total"] == "UNKNOWN", row
        assert rc == 3


def test_window_is_judged_on_successful_drills_only():
    """A recent failover must not satisfy the drill-testing window.

    latest was taken over DRILL and REAL-MOVE, successful or failed, so a plan
    whose last successful drill was 500 days ago reported OK with the detail
    "a successful drill was recorded within the window" -- a sentence the data
    contradicted.
    """
    original = list(EXECUTIONS)
    try:
        EXECUTIONS[:] = [
            _execution("ocid1.drplanexecution.oc1..olddrill", TESTED_PLAN,
                       "START_DRILL", "SUCCEEDED", STALE),
            _execution("ocid1.drplanexecution.oc1..newmove", TESTED_PLAN,
                       "FAILOVER", "SUCCEEDED", RECENT),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            _run(_base_args(tmp), state=FakeState())
            row = {r["plan_id"]: r
                   for r in _read_csv(_find(tmp, "_plan_test_status.csv"))}[TESTED_PLAN]
            assert row["test_status"] == "PLAN-NO-EXERCISE-IN-WINDOW", row
            assert "successful drill" in row["test_detail"]

        # A recent FAILED drill must not satisfy the window either.
        EXECUTIONS[:] = [
            _execution("ocid1.drplanexecution.oc1..olddrill", TESTED_PLAN,
                       "START_DRILL", "SUCCEEDED", STALE),
            _execution("ocid1.drplanexecution.oc1..faildrill", TESTED_PLAN,
                       "START_DRILL", "FAILED", RECENT),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            _run(_base_args(tmp), state=FakeState())
            row = {r["plan_id"]: r
                   for r in _read_csv(_find(tmp, "_plan_test_status.csv"))}[TESTED_PLAN]
            assert row["test_status"] == "PLAN-NO-EXERCISE-IN-WINDOW", row
    finally:
        EXECUTIONS[:] = original


def test_unread_is_automatic_is_not_credited_as_a_test():
    """get_dr_plan_execution exists to read is_automatic. If it failed, the
    execution cannot be credited OK -- that is the distinction it was called for."""
    row = MODULE.execution_row(
        EXECUTIONS[0], None, {}, GROUP, "prod-dr",
        MODULE.ScopeItem(SHARED, "Shared", "COMPARTMENT"), "us-ashburn-1", NOW)
    assert row["is_automatic"] == "NOT-READ"
    assert row["execution_finding"] == "EXERCISE-OUTCOME-UNCONFIRMED", row


if __name__ == "__main__":
    import traceback
    tests = [
        test_selfcheck, test_exercise_class_unit, test_region_required,
        test_approval_refusal_reads_nothing, test_full_collection,
        test_precheck_is_never_counted_as_a_test, test_plan_test_statuses,
        test_stale_drill_passes_with_a_wider_window,
        test_get_execution_is_called_because_summary_has_no_is_automatic,
        test_no_dr_plans_is_reported_honestly,
        test_snapshot_only_without_register,
        test_unusable_register_fails_before_scanning,
        test_register_claiming_a_precheck_is_rejected,
        test_register_validation_outcomes, test_fully_valid_register_exits_zero,
        test_register_template_is_blank,
        test_denied_call_is_coverage_not_a_finding, test_secret_redacted_in_errors,
        test_private_outputs_and_plan_boundary,
        test_collector_cannot_start_an_execution,
        test_denied_execution_list_is_not_never_executed,
        test_window_is_judged_on_successful_drills_only,
        test_unread_is_automatic_is_not_credited_as_a_test,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
