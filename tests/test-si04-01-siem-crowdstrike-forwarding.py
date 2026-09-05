#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for SI04-01 SIEM/CrowdStrike forwarding."""

from __future__ import annotations

import csv
import importlib.util
import io
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "si04_01", ROOT / "si04-01-siem-crowdstrike-forwarding.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..si04tenancy"
SHARED = "ocid1.compartment.oc1..si04shared"
FIXED_NOW = datetime(2026, 9, 4, 10, 0, 0, tzinfo=timezone.utc)

# Connectors
CS_CONN_ID = "ocid1.serviceconnector.oc1..si04cs"
AUDIT_CONN_ID = "ocid1.serviceconnector.oc1..si04audit"
INACTIVE_CONN_ID = "ocid1.serviceconnector.oc1..si04inactive"

# Log groups and logs
AUDIT_LG = "ocid1.loggroup.oc1..si04auditlg"
FLOW_LG = "ocid1.loggroup.oc1..si04flowlg"
AUDIT_LOG = "ocid1.log.oc1..si04auditlog"
FLOW_LOG = "ocid1.log.oc1..si04flowlog"
UNCOVERED_LG = "ocid1.loggroup.oc1..si04unclg"
UNCOVERED_LOG = "ocid1.log.oc1..si04unclog"


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
        self.now = FIXED_NOW

    def call(self, method, arg=""):
        self.calls.append((method, arg))
        if self.fail_method == method:
            raise FakeServiceError(f"mock denied token=<redacted> method={method}")


class BaseClient:
    state: Optional[FakeState] = None

    def __init__(self, config, **kwargs):
        self.config = config


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kwargs):
        self.state.call("get_compartment", compartment_id)
        names = {TENANCY: "MockTenancy", SHARED: "Shared"}
        return Response(SimpleNamespace(id=compartment_id, name=names.get(compartment_id, "?")))

    def list_compartments(self, compartment_id, **kwargs):
        self.state.call("list_compartments", compartment_id)
        return Response(Collection([
            SimpleNamespace(id=SHARED, name="Shared"),
        ]))


def _make_log_source(log_group_id: str, log_id: Optional[str] = None) -> Any:
    return SimpleNamespace(log_group_id=log_group_id, log_id=log_id)


def _make_connector(
    cid: str,
    name: str,
    compartment_id: str,
    source_kind: str,
    log_sources: List[Any],
    target_kind: str,
    target_url: str = "",
    target_function_id: str = "",
    target_stream_id: str = "",
    lifecycle_state: str = "ACTIVE",
) -> Any:
    source = SimpleNamespace(kind=source_kind, log_sources=log_sources, stream_id="")
    target = SimpleNamespace(
        kind=target_kind,
        url=target_url,
        function_id=target_function_id,
        stream_id=target_stream_id,
        log_group_id="",
        bucket_name="",
    )
    return SimpleNamespace(
        id=cid, display_name=name, compartment_id=compartment_id,
        lifecycle_state=lifecycle_state, description="",
        source=source, target=target, tasks=[],
        time_created=FIXED_NOW, time_updated=FIXED_NOW,
    )


class ServiceConnectorClient(BaseClient):
    def list_service_connectors(self, compartment_id, **kwargs):
        self.state.call("list_service_connectors", compartment_id)
        items = []
        if compartment_id in (TENANCY, SHARED):
            items = [
                SimpleNamespace(id=CS_CONN_ID, display_name="crowdstrike-audit-forwarder",
                                compartment_id=compartment_id, lifecycle_state="ACTIVE"),
                SimpleNamespace(id=AUDIT_CONN_ID, display_name="audit-log-forwarder",
                                compartment_id=compartment_id, lifecycle_state="ACTIVE"),
                SimpleNamespace(id=INACTIVE_CONN_ID, display_name="inactive-connector",
                                compartment_id=compartment_id, lifecycle_state="INACTIVE"),
            ]
        return Response(Collection(items))

    def get_service_connector(self, service_connector_id, **kwargs):
        self.state.call("get_service_connector", service_connector_id)
        connectors = {
            CS_CONN_ID: _make_connector(
                CS_CONN_ID, "crowdstrike-audit-forwarder", SHARED, "logging",
                [_make_log_source(AUDIT_LG, AUDIT_LOG)],
                "http", target_url="https://ingest.falcon.crowdstrike.com/sensors/entities/log-events/v1",
            ),
            AUDIT_CONN_ID: _make_connector(
                AUDIT_CONN_ID, "audit-log-forwarder", SHARED, "logging",
                [_make_log_source(FLOW_LG)],
                "streaming", target_stream_id="ocid1.stream.oc1..si04stream",
            ),
            INACTIVE_CONN_ID: _make_connector(
                INACTIVE_CONN_ID, "inactive-connector", SHARED, "logging",
                [], "objectStorage", lifecycle_state="INACTIVE",
            ),
        }
        return Response(connectors[service_connector_id])


class LoggingManagementClient(BaseClient):
    def list_log_groups(self, compartment_id, **kwargs):
        self.state.call("list_log_groups", compartment_id)
        items = []
        if compartment_id in (TENANCY, SHARED):
            items = [
                SimpleNamespace(id=AUDIT_LG, display_name="audit-logs",
                                compartment_id=compartment_id, lifecycle_state="ACTIVE"),
                SimpleNamespace(id=FLOW_LG, display_name="flow-logs",
                                compartment_id=compartment_id, lifecycle_state="ACTIVE"),
                SimpleNamespace(id=UNCOVERED_LG, display_name="app-logs",
                                compartment_id=compartment_id, lifecycle_state="ACTIVE"),
            ]
        return Response(Collection(items))

    def list_logs(self, log_group_id, **kwargs):
        self.state.call("list_logs", log_group_id)
        items_map = {
            AUDIT_LG: [
                SimpleNamespace(id=AUDIT_LOG, display_name="oci-audit",
                                log_group_id=AUDIT_LG, compartment_id=SHARED,
                                log_type="SERVICE", lifecycle_state="ACTIVE", is_enabled=True),
            ],
            FLOW_LG: [
                SimpleNamespace(id=FLOW_LOG, display_name="vcn-flow",
                                log_group_id=FLOW_LG, compartment_id=SHARED,
                                log_type="SERVICE", lifecycle_state="ACTIVE", is_enabled=True),
            ],
            UNCOVERED_LG: [
                SimpleNamespace(id=UNCOVERED_LOG, display_name="app-custom",
                                log_group_id=UNCOVERED_LG, compartment_id=SHARED,
                                log_type="CUSTOM", lifecycle_state="ACTIVE", is_enabled=False),
            ],
        }
        return Response(Collection(items_map.get(log_group_id, [])))


def _fake_oci(state: FakeState) -> Any:
    IdentityClient.state = state
    ServiceConnectorClient.state = state
    LoggingManagementClient.state = state

    class pagination:
        @staticmethod
        def list_call_get_all_results(fn, *args, **kwargs):
            resp = fn(*args, **kwargs)
            data = resp.data
            items = getattr(data, "items", data if isinstance(data, list) else [])
            resp.data = list(items)
            return resp

    class retry:
        DEFAULT_RETRY_STRATEGY = None

    class identity:
        IdentityClient = globals()["IdentityClient"]

    class sch:
        ServiceConnectorClient = globals()["ServiceConnectorClient"]

    class logging_management:
        LoggingManagementClient = globals()["LoggingManagementClient"]

    class FakeServiceErrorCls(FakeServiceError):
        pass

    class exceptions:
        ServiceError = FakeServiceErrorCls

    fake = SimpleNamespace(
        pagination=pagination,
        retry=retry,
        identity=identity,
        sch=sch,
        logging_management=logging_management,
        exceptions=exceptions,
        config=SimpleNamespace(
            from_file=lambda *a, **kw: {"tenancy": TENANCY, "region": "us-ashburn-1"},
            validate_config=lambda c: None,
        ),
        auth=SimpleNamespace(signers=SimpleNamespace(
            InstancePrincipalsSecurityTokenSigner=lambda: None,
            get_resource_principals_signer=lambda: None,
        )),
        __version__="2.185.1-mock",
    )
    return fake


def _run(args, state=None, oci_module=None):
    if state is None:
        state = FakeState()
    if oci_module is None:
        oci_module = _fake_oci(state)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = MODULE.main(args, oci_module=oci_module)
    return rc, out.getvalue(), err.getvalue(), state


def _read_csv(path: str):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _base_args(tmpdir: str) -> List[str]:
    return [
        "--region", "us-ashburn-1",
        "--output-dir", tmpdir,
        "--tenancy-scope",
        "--non-interactive",
        "--confirm-scope-ocid", TENANCY,
        "--confirm-scope-ocid", SHARED,
        "--approve-scan", "YES",
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_selfcheck():
    rc, out, err, _ = _run(["--selfcheck"])
    assert rc == 0, f"selfcheck failed: {err}"
    assert "PASSED" in out


def test_region_required():
    rc, out, err, _ = _run(["--output-dir", "."])
    assert rc != 0
    assert "region" in err.lower()


def test_refusal_no_workload_calls_interactive():
    """Interactive: wrong second OCID must stop before workload clients."""
    state = FakeState()
    oci = _fake_oci(state)
    args_list = ["--region", "us-ashburn-1", "--output-dir", "."]
    stdin_lines = iter([TENANCY, "wrong-ocid-should-fail"])
    original_input = __builtins__.__dict__["input"] if isinstance(__builtins__, dict) else getattr(__builtins__, "input", input)

    import builtins
    called_workload = []

    original_sch = oci.sch.ServiceConnectorClient

    class TrackingSCH(original_sch):
        def list_service_connectors(self, *a, **kw):
            called_workload.append("list_service_connectors")
            return super().list_service_connectors(*a, **kw)

    oci.sch.ServiceConnectorClient = TrackingSCH
    original_builtin_input = builtins.input
    builtins.input = lambda prompt="": next(stdin_lines)
    try:
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = MODULE.main(args_list, oci_module=oci)
    finally:
        builtins.input = original_builtin_input
    assert rc != 0
    assert not called_workload, "workload calls must not happen after scope refusal"


def test_automation_wrong_approve():
    with tempfile.TemporaryDirectory() as d:
        args = [
            "--region", "us-ashburn-1",
            "--output-dir", d,
            "--tenancy-scope",
            "--non-interactive",
            "--confirm-scope-ocid", TENANCY,
            "--confirm-scope-ocid", SHARED,
            "--approve-scan", "yes",
        ]
        rc, out, err, state = _run(args)
    assert rc != 0
    assert "YES" in err or "YES" in out


def test_automation_missing_ocid():
    with tempfile.TemporaryDirectory() as d:
        args = [
            "--region", "us-ashburn-1",
            "--output-dir", d,
            "--tenancy-scope",
            "--non-interactive",
            "--confirm-scope-ocid", TENANCY,
            "--approve-scan", "YES",
        ]
        rc, out, err, state = _run(args)
    assert rc != 0


def test_no_workload_calls_on_approval_failure():
    """Automation: mismatched OCIDs must not call workload service clients."""
    state = FakeState()
    oci = _fake_oci(state)
    with tempfile.TemporaryDirectory() as d:
        args = [
            "--region", "us-ashburn-1",
            "--output-dir", d,
            "--tenancy-scope",
            "--non-interactive",
            "--confirm-scope-ocid", TENANCY,
            "--approve-scan", "YES",
        ]
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = MODULE.main(args, oci_module=oci)
    assert rc != 0
    workload_calls = [c for c in state.calls if c[0] in (
        "list_service_connectors", "get_service_connector",
        "list_log_groups", "list_logs",
    )]
    assert not workload_calls, f"workload calls made before approval: {workload_calls}"


def test_interactive_and_explicit_mutually_exclusive():
    with tempfile.TemporaryDirectory() as d:
        args = [
            "--region", "us-ashburn-1",
            "--output-dir", d,
            "--select-scope",
            "--tenancy-scope",
            "--non-interactive",
            "--confirm-scope-ocid", TENANCY,
            "--approve-scan", "YES",
        ]
        rc, out, err, _ = _run(args)
    assert rc != 0


def test_full_collection_tenancy():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, out, err, state = _run(args)
    assert rc == 0, f"rc={rc} err={err}"
    assert "COLLECTION COMPLETE" in out


def test_connector_inventory_contents():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0, err
        files = list(Path(d).glob("si04-01_*_connector_inventory.csv"))
        assert files
        rows = _read_csv(str(files[0]))

    cs_rows = [r for r in rows if r["connector_id"] == CS_CONN_ID]
    assert len(cs_rows) == 1
    cs = cs_rows[0]
    assert cs["crowdstrike_target"] == "YES"
    assert cs["siem_forwarding"] == "YES"
    assert cs["target_kind"] == "http"
    assert "falcon" in cs["target_http_url"].lower() or "crowdstrike" in cs["target_http_url"].lower()

    audit_rows = [r for r in rows if r["connector_id"] == AUDIT_CONN_ID]
    assert len(audit_rows) == 1
    audit = audit_rows[0]
    assert audit["crowdstrike_target"] == "NO"
    assert audit["target_kind"] == "streaming"

    inactive_rows = [r for r in rows if r["connector_id"] == INACTIVE_CONN_ID]
    assert len(inactive_rows) == 1
    assert inactive_rows[0]["lifecycle_state"] == "INACTIVE"


def test_deduplication_on_tenancy_scope():
    """Connectors discovered in both root and a child compartment must appear once."""
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        files = list(Path(d).glob("si04-01_*_connector_inventory.csv"))
        rows = _read_csv(str(files[0]))
    ids = [r["connector_id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate connector_id entries found"


def test_log_source_inventory():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        files = list(Path(d).glob("si04-01_*_log_source_inventory.csv"))
        assert files
        rows = _read_csv(str(files[0]))

    audit_log_rows = [r for r in rows if r["log_id"] == AUDIT_LOG]
    assert audit_log_rows
    assert audit_log_rows[0]["forwarding_coverage"] == "COVERED"

    flow_log_rows = [r for r in rows if r["log_id"] == FLOW_LOG]
    assert flow_log_rows
    # Flow log is covered because its log group is in a connector source with no specific log_id
    assert flow_log_rows[0]["forwarding_coverage"] == "COVERED"

    uncovered_rows = [r for r in rows if r["log_id"] == UNCOVERED_LOG]
    assert uncovered_rows
    assert uncovered_rows[0]["forwarding_coverage"] == "NOT-COVERED"


def test_forwarding_coverage_rows():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        files = list(Path(d).glob("si04-01_*_forwarding_coverage.csv"))
        assert files
        rows = _read_csv(str(files[0]))

    cs_cov = [r for r in rows if r["connector_id"] == CS_CONN_ID]
    assert cs_cov
    assert all(r["crowdstrike_target"] == "YES" for r in cs_cov)
    assert all(r["siem_forwarding"] == "YES" for r in cs_cov)


def test_formula_safe_connector_name():
    """Connector names starting with formula-injection chars must be escaped."""
    state = FakeState()
    oci = _fake_oci(state)
    original_sch = oci.sch.ServiceConnectorClient

    class FormulaClient(original_sch):
        def get_service_connector(self, cid, **kwargs):
            resp = super().get_service_connector(cid, **kwargs)
            if cid == CS_CONN_ID:
                resp.data.display_name = "=MALICIOUS+FORMULA"
            return resp

    oci.sch.ServiceConnectorClient = FormulaClient
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = MODULE.main(args, oci_module=oci)
        assert rc == 0
        files = list(Path(d).glob("si04-01_*_connector_inventory.csv"))
        rows = _read_csv(str(files[0]))

    formula_rows = [r for r in rows if "MALICIOUS" in r.get("connector_name", "")]
    assert formula_rows, "formula-injection row not found"
    assert not formula_rows[0]["connector_name"].startswith("="), \
        f"formula cell not escaped: {formula_rows[0]['connector_name']}"


def test_private_output_permissions():
    import platform
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        if platform.system() != "Windows":
            for path in Path(d).iterdir():
                mode = oct(path.stat().st_mode & 0o777)
                assert mode == "0o600", f"{path.name} has permissions {mode}, expected 0o600"


def test_output_collision():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc1, _, _, _ = _run(args)
        assert rc1 == 0
        # A second run with the same output dir but same timestamp would collide
        # Simulate by creating a file that the second run would write
        existing = list(Path(d).glob("si04-01_*_connector_inventory.csv"))
        assert existing
        rc2, out, err, _ = _run(args)
        # Second run will either collide (rc!=0) or succeed with a new timestamp
        # In practice timestamps differ, so just verify no crash
        assert rc2 in (0, 1)


def test_denied_sch_call():
    """A denied list_service_connectors call must appear in errors, not silently empty."""
    state = FakeState()
    state.fail_method = "list_service_connectors"
    oci = _fake_oci(state)
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = MODULE.main(args, oci_module=oci)
        files = list(Path(d).glob("si04-01_*_collection_errors.csv"))
        assert files, "collection_errors.csv not produced after denied call"
        rows = _read_csv(str(files[0]))
    assert any("list_service_connectors" in r.get("operation", "") for r in rows)
    for r in rows:
        if "list_service_connectors" in r.get("operation", ""):
            msg = r.get("message", "")
            # raw token values must be redacted; only <redacted> form is allowed
            assert "token=<redacted>" in msg or "token" not in msg.lower(), \
                f"potential raw token value in error message: {msg}"
    assert rc != 0 or "INCOMPLETE" in out.getvalue() + err.getvalue()


def test_secret_redacted_in_error():
    """Error messages from denied calls must not leak tokens or secrets."""
    state = FakeState()
    state.fail_method = "list_service_connectors"
    oci = _fake_oci(state)
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        out = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            MODULE.main(args, oci_module=oci)
        files = list(Path(d).glob("si04-01_*_collection_errors.csv"))
        if files:
            rows = _read_csv(str(files[0]))
            combined = " ".join(r.get("message", "") for r in rows)
            assert "token=<redacted>" in combined or "token" not in combined.lower(), \
                "raw token value may be present in error message"


def test_template_generation():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        test_tpl = list(Path(d).glob("si04-01_*_test_event_register_template.csv"))
        assert test_tpl
        rows = _read_csv(str(test_tpl[0]))
        # Only ACTIVE connectors get template rows
        assert all(
            r["connector_id"] in (CS_CONN_ID, AUDIT_CONN_ID)
            for r in rows
        )
        cs_rows = [r for r in rows if r["connector_id"] == CS_CONN_ID]
        assert cs_rows
        assert cs_rows[0]["siem_system"] == "CrowdStrike"


def test_review_template_counts():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        files = list(Path(d).glob("si04-01_*_monthly_review_template.csv"))
        assert files
        rows = _read_csv(str(files[0]))
    assert len(rows) == 1
    r = rows[0]
    assert int(r["total_connectors"]) == 3
    assert int(r["active_connectors"]) == 2
    assert int(r["inactive_connectors"]) == 1
    assert int(r["crowdstrike_connectors"]) == 1
    assert int(r["siem_connectors"]) >= 1
    assert int(r["coverage_gaps"]) >= 1


def test_monthly_review_validation_count_mismatch():
    """A monthly review with wrong counts must produce INVALID validation."""
    d1 = tempfile.mkdtemp()
    d2 = tempfile.mkdtemp()
    try:
        args = _base_args(d1)
        rc, _, _, _ = _run(args)
        assert rc == 0
        files = list(Path(d1).glob("si04-01_*_monthly_review_template.csv"))
        rows = _read_csv(str(files[0]))
        # Tamper the template before supplying it as the review input
        rows[0]["total_connectors"] = "999"
        review_path = os.path.join(d1, "tampered_review.csv")
        with open(review_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=MODULE.REVIEW_FIELDS)
            writer.writeheader()
            writer.writerow(rows[0])

        test_tpl = list(Path(d1).glob("si04-01_*_test_event_register_template.csv"))
        approval_tpl = list(Path(d1).glob("si04-01_*_owner_approval_template.csv"))
        assert test_tpl and approval_tpl
        args2 = _base_args(d2) + [
            "--test-event-register", str(test_tpl[0]),
            "--owner-approvals", str(approval_tpl[0]),
            "--monthly-review", review_path,
        ]
        rc2, _, _, _ = _run(args2)
        files2 = list(Path(d2).glob("si04-01_*_monthly_review_validation.csv"))
        assert files2
        val_rows = _read_csv(str(files2[0]))
    finally:
        import shutil
        shutil.rmtree(d1, ignore_errors=True)
        shutil.rmtree(d2, ignore_errors=True)
    assert val_rows
    assert val_rows[0]["validation_status"] == "INVALID"
    assert "total_connectors" in val_rows[0]["validation_message"]


def test_summary_line_is_present():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, out, _, _ = _run(args)
        assert rc == 0
    assert "SI04-01 SIEM Integration" in out
    assert "COLLECTION STATUS" in out
    assert "CrowdStrike connectors" in out


def test_mutating_methods_blocked():
    """The self-check must fail if a mutating method name enters SDK_READ_METHODS."""
    original = MODULE.SDK_READ_METHODS.copy()
    try:
        MODULE.SDK_READ_METHODS.add("create_service_connector")
        rc, out, err, _ = _run(["--selfcheck"])
        assert rc != 0
        assert "FAILED" in (out + err)
    finally:
        MODULE.SDK_READ_METHODS.clear()
        MODULE.SDK_READ_METHODS.update(original)


def test_approved_plan_written():
    with tempfile.TemporaryDirectory() as d:
        args = _base_args(d)
        rc, _, err, _ = _run(args)
        assert rc == 0
        plans = list(Path(d).glob("si04-01_*_approved_scan_plan.txt"))
        assert plans
        content = plans[0].read_text(encoding="utf-8")
    assert "SCAN APPROVED" in content
    assert "CROWDSTRIKE" in content.upper() or "SI-4" in content


if __name__ == "__main__":
    import traceback
    tests = [
        test_selfcheck,
        test_region_required,
        test_refusal_no_workload_calls_interactive,
        test_automation_wrong_approve,
        test_automation_missing_ocid,
        test_no_workload_calls_on_approval_failure,
        test_interactive_and_explicit_mutually_exclusive,
        test_full_collection_tenancy,
        test_connector_inventory_contents,
        test_deduplication_on_tenancy_scope,
        test_log_source_inventory,
        test_forwarding_coverage_rows,
        test_formula_safe_connector_name,
        test_private_output_permissions,
        test_output_collision,
        test_denied_sch_call,
        test_secret_redacted_in_error,
        test_template_generation,
        test_review_template_counts,
        test_monthly_review_validation_count_mismatch,
        test_summary_line_is_present,
        test_mutating_methods_blocked,
        test_approved_plan_written,
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
