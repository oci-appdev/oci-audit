#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for CM03-01."""

from __future__ import annotations

import csv
import importlib.util
import io
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cm03_01", ROOT / "cm03-01-configuration-change-tracking.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..cm03tenancy"
CONFIG = "ocid1.compartment.oc1..cm03config"
SHARED = "ocid1.compartment.oc1..cm03shared"
FIXED_NOW = datetime(2026, 9, 2, 12, 34, 0, tzinfo=timezone.utc)


class Response:
    def __init__(self, data, request_id="mock-cm03-request"):
        self.data = data
        self.headers = {"opc-request-id": request_id}


class Collection:
    def __init__(self, items):
        self.items = items


class FakeServiceError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.status = 403
        self.code = "NotAuthorizedOrNotFound"
        self.opc_request_id = "cm03-denied-request"
        self.message = message


class FakeState:
    def __init__(self):
        self.calls = []
        self.pagination_calls = 0
        self.fail_method = ""
        self.retention_days = 365

    def call(self, method, compartment=""):
        self.calls.append((method, compartment))
        if self.fail_method == method:
            raise FakeServiceError("mock denied password=do-not-export")


class BaseClient:
    state = None

    def __init__(self, config, **kwargs):
        self.config = config
        self.kwargs = kwargs


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kwargs):
        self.state.call("get_compartment", compartment_id)
        names = {TENANCY: "MockTenancy", CONFIG: "Configuration", SHARED: "Shared Services"}
        return Response(SimpleNamespace(id=compartment_id, name=names[compartment_id]))

    def list_compartments(self, compartment_id, **kwargs):
        self.state.call("list_compartments", compartment_id)
        return Response(Collection([
            SimpleNamespace(id=CONFIG, name="Configuration"),
            SimpleNamespace(id=SHARED, name="Shared Services"),
        ]))


def audit_event(
    event_id, event_time, event_name, method, status, compartment, resource_id,
    principal="operator", grouping="",
):
    return SimpleNamespace(
        event_id=event_id,
        event_time=event_time,
        event_type=f"com.oraclecloud.MockApi.{event_name}",
        source="MockApi",
        data=SimpleNamespace(
            event_grouping_id=grouping,
            event_name=event_name,
            compartment_id=compartment,
            compartment_name="Configuration" if compartment == CONFIG else "Shared Services",
            resource_name="mock-resource",
            resource_id=resource_id,
            availability_domain="LNGY:US-LANGLEY-1-AD-1",
            identity=SimpleNamespace(
                principal_name=principal,
                principal_id="ocid1.user.oc1..cm03operator",
                caller_name=principal,
                caller_id="ocid1.user.oc1..cm03operator",
                auth_type="natv", ip_address="192.0.2.10", user_agent="mock-agent",
                credentials="SECRET-CREDENTIAL-MUST-NOT-EXPORT",
            ),
            request=SimpleNamespace(
                id=f"request-{event_id}", path="/20160918/mock", action=method,
                parameters={"password": ["SECRET-PARAM-MUST-NOT-EXPORT"]},
                headers={"authorization": ["SECRET-HEADER-MUST-NOT-EXPORT"]},
            ),
            response=SimpleNamespace(
                status=status, response_time=event_time + timedelta(seconds=2),
                headers={"set-cookie": ["SECRET-COOKIE-MUST-NOT-EXPORT"]},
                payload={"token": "SECRET-PAYLOAD-MUST-NOT-EXPORT"}, message="",
            ),
            state_change=SimpleNamespace(previous={"shape": "old"}, current={"shape": "new"}),
            additional_details={"privateKey": "SECRET-DETAIL-MUST-NOT-EXPORT"},
        ),
    )


class AuditClient(BaseClient):
    def __init__(self, config, **kwargs):
        if self.state.fail_method == "build_audit_client":
            raise FakeServiceError("mock client failure private_key=do-not-export")
        super().__init__(config, **kwargs)

    def get_configuration(self, compartment_id, **kwargs):
        self.state.call("get_configuration", compartment_id)
        if self.state.fail_method == "malformed_configuration":
            return Response(SimpleNamespace(retention_period_days="365"))
        return Response(SimpleNamespace(retention_period_days=self.state.retention_days))

    def list_events(self, compartment_id, start_time, end_time, **kwargs):
        self.state.call("list_events", compartment_id)
        if self.state.fail_method == "malformed_list_events":
            return Response(Collection([]))
        candidates = []
        if compartment_id == CONFIG:
            candidates = [
                audit_event(
                    "event-read", FIXED_NOW - timedelta(days=1), "GetRouteTable", "GET", "200",
                    CONFIG, "ocid1.routetable.oc1..cm03",
                ),
                audit_event(
                    "event-update", FIXED_NOW - timedelta(days=3), "UpdateRouteTable", "PUT", "200 OK",
                    CONFIG, "ocid1.routetable.oc1..cm03", principal="=change-bot", grouping="group-update",
                ),
                audit_event(
                    "event-delete-failed", FIXED_NOW - timedelta(days=2), "DeleteSecurityList", "DELETE", "409 Conflict",
                    CONFIG, "ocid1.securitylist.oc1..cm03", grouping="group-delete",
                ),
                audit_event(
                    "event-search", FIXED_NOW - timedelta(days=2), "SearchResources", "POST", "200",
                    CONFIG, "ocid1.tenancy.oc1..cm03search",
                ),
            ]
        elif compartment_id == SHARED:
            candidates = [
                audit_event(
                    "event-create", FIXED_NOW - timedelta(days=4), "CreateServiceConnector", "POST", "202",
                    SHARED, "ocid1.serviceconnector.oc1..cm03", grouping="group-create",
                )
            ]
        return Response([event for event in candidates if start_time <= event.event_time < end_time])


def fake_oci():
    state = FakeState()
    for client in (IdentityClient, AuditClient):
        client.state = state

    def paginate(method, *args, **kwargs):
        state.pagination_calls += 1
        return method(*args, **kwargs)

    sdk = SimpleNamespace(
        __version__="2.185.1-mock",
        config=SimpleNamespace(
            from_file=lambda path, profile: {
                "tenancy": TENANCY, "user": "ocid1.user.oc1..mock", "fingerprint": "aa:bb",
                "key_file": "/mock/key.pem", "region": "us-langley-1",
            },
            validate_config=lambda config: None,
        ),
        retry=SimpleNamespace(DEFAULT_RETRY_STRATEGY=object()),
        pagination=SimpleNamespace(list_call_get_all_results=paginate),
        identity=SimpleNamespace(IdentityClient=IdentityClient),
        audit=SimpleNamespace(AuditClient=AuditClient),
        auth=SimpleNamespace(signers=SimpleNamespace()),
    )
    return sdk, state


def run(sdk, argv, stdin=""):
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = MODULE.main(argv, oci_module=sdk)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


def one(root, pattern):
    matches = list(Path(root).glob(pattern))
    assert len(matches) == 1, (pattern, matches)
    return matches[0]


def rows(path):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, fields, data):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def main():
    MODULE.utc_now = lambda: FIXED_NOW
    assert MODULE.source_selfcheck()
    MODULE.SDK_READ_METHODS.add("delete_configuration")
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert not MODULE.source_selfcheck()
    MODULE.SDK_READ_METHODS.remove("delete_configuration")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        # Tenancy run proves pagination, classification, retention, payload
        # minimization, formula safety and private evidence permissions.
        technical = root / "technical"
        sdk, state = fake_oci()
        rc, stdout, stderr = run(
            sdk, ["-r", "us-langley-1", "-o", str(technical)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 0, (stdout, stderr)
        assert state.pagination_calls >= 10, state.pagination_calls
        assert "CM03-01 COLLECTION COMPLETE" in stdout
        events = rows(one(technical, "*_audit_event_inventory.csv"))
        changes = rows(one(technical, "*_change_candidates.csv"))
        assert len(events) == 5, events
        assert {row["event_id"] for row in changes} == {
            "event-update", "event-delete-failed", "event-create"
        }
        failed = next(row for row in changes if row["event_id"] == "event-delete-failed")
        assert failed["outcome"] == "FAILED"
        assert failed["classification_basis"] == "MUTATING-EVENT-NAME+HTTP-METHOD"
        search = next(row for row in events if row["event_id"] == "event-search")
        assert search["classification"] == "REVIEW-CANDIDATE"
        inventory_text = one(technical, "*_audit_event_inventory.csv").read_text(encoding="utf-8")
        assert "'=change-bot" in inventory_text
        assert "SECRET-" not in inventory_text
        assert oct(one(technical, "*_change_candidates.csv").stat().st_mode & 0o777) == "0o600"
        assert rows(one(technical, "*_audit_configuration.csv"))[0]["within_retention"] == "YES"
        assert "COLLECTION STATUS       : COMPLETE" in one(technical, "*_summary.txt").read_text()

        # A repeated timestamp refuses immutable evidence overwrite before an
        # Audit workload call.
        sdk_collision, collision_state = fake_oci()
        rc, stdout, stderr = run(
            sdk_collision, ["-r", "us-langley-1", "-o", str(technical)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 1 and "output collision" in stderr
        assert not any(call[0] in {"get_configuration", "list_events"} for call in collision_state.calls)

        # Manual exact compartment flags still require two OCID entries and
        # exact YES, while refusal leaves no workload evidence.
        refused = root / "refused"
        sdk_refused, refused_state = fake_oci()
        rc, stdout, stderr = run(
            sdk_refused, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(refused)],
            f"{CONFIG}\n{CONFIG}\nNO\n",
        )
        assert rc == 1 and "SCAN NOT STARTED" in stderr and not refused.exists()
        assert not any(call[0] in {"get_configuration", "list_events"} for call in refused_state.calls)

        # Strict automation prints the plan first and validates the complete
        # resolved confirmation set before any Audit call.
        mismatch = root / "mismatch"
        sdk_mismatch, mismatch_state = fake_oci()
        rc, stdout, stderr = run(sdk_mismatch, [
            "-r", "us-langley-1", "--tenancy-scope", "--non-interactive",
            "--confirm-scope-ocid", TENANCY, "--approve-scan", "YES", "-o", str(mismatch),
        ])
        assert rc == 1 and "PRE-SCAN SAFETY SUMMARY" in stdout
        assert "do not exactly match" in stderr and not mismatch.exists()
        assert not any(call[0] in {"get_configuration", "list_events"} for call in mismatch_state.calls)

        automated = root / "automated"
        sdk_auto, auto_state = fake_oci()
        rc, stdout, stderr = run(sdk_auto, [
            "-r", "us-langley-1", "-c", CONFIG, "--non-interactive",
            "--confirm-scope-ocid", CONFIG, "--approve-scan", "YES", "-o", str(automated),
        ])
        assert rc == 0, (stdout, stderr)
        assert any(call[0] == "list_events" for call in auto_state.calls)

        # Denied Audit reads and retention gaps are explicit incomplete
        # evidence, never a fabricated no-change result.
        denied = root / "denied"
        sdk_denied, denied_state = fake_oci()
        denied_state.fail_method = "list_events"
        rc, stdout, stderr = run(
            sdk_denied, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(denied)],
            f"{CONFIG}\n{CONFIG}\nYES\n",
        )
        assert rc == 3 and "COLLECTION INCOMPLETE" in stderr
        error_text = one(denied, "*_collection_errors.csv").read_text(encoding="utf-8")
        assert "cm03-denied-request" in error_text and "do-not-export" not in error_text

        client_failure = root / "client-failure"
        sdk_client, client_state = fake_oci()
        client_state.fail_method = "build_audit_client"
        rc, stdout, stderr = run(
            sdk_client, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(client_failure)],
            f"{CONFIG}\n{CONFIG}\nYES\n",
        )
        assert rc == 3
        client_errors = one(client_failure, "*_collection_errors.csv").read_text(encoding="utf-8")
        assert "build_audit_client" in client_errors and "do-not-export" not in client_errors

        malformed = root / "malformed"
        sdk_malformed, malformed_state = fake_oci()
        malformed_state.fail_method = "malformed_list_events"
        rc, stdout, stderr = run(
            sdk_malformed, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(malformed)],
            f"{CONFIG}\n{CONFIG}\nYES\n",
        )
        assert rc == 3
        malformed_coverage = rows(one(malformed, "*_collection_coverage.csv"))
        assert malformed_coverage and all(row["status"] == "FAILED" for row in malformed_coverage)

        malformed_config = root / "malformed-config"
        sdk_bad_config, bad_config_state = fake_oci()
        bad_config_state.fail_method = "malformed_configuration"
        rc, stdout, stderr = run(
            sdk_bad_config, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(malformed_config)],
            f"{CONFIG}\n{CONFIG}\nYES\n",
        )
        assert rc == 3
        assert rows(one(malformed_config, "*_audit_configuration.csv"))[0]["status"] == "FAILED"

        retention = root / "retention"
        sdk_retention, retention_state = fake_oci()
        retention_state.retention_days = 90
        rc, stdout, stderr = run(
            sdk_retention, [
                "-r", "us-langley-1", "-c", CONFIG, "--lookback-days", "120",
                "-o", str(retention),
            ],
            f"{CONFIG}\n{CONFIG}\nYES\n",
        )
        assert rc == 3
        config = rows(one(retention, "*_audit_configuration.csv"))[0]
        assert config["status"] == "OUTSIDE-RETENTION" and config["within_retention"] == "NO"

        # Build exact CRQ, System Owner and representative-sample inputs from
        # the current technical snapshot.
        register_path = root / "approved-change-register.csv"
        owner_path = root / "approved-owner-approvals.csv"
        sample_path = root / "approved-samples.csv"
        register_data = []
        owner_data = []
        for index, event in enumerate(changes, 1):
            event_time = MODULE.parse_time(event["event_time"], "event")
            crq = f"CRQ00000{index}"
            register_data.append({
                "crq_id": crq, "change_title": event["event_name"], "change_type": "NORMAL",
                "change_status": "CLOSED", "planned_start": MODULE.iso(event_time - timedelta(hours=2)),
                "planned_end": MODULE.iso(event_time + timedelta(hours=2)),
                "actual_start": MODULE.iso(event_time - timedelta(hours=1)),
                "actual_end": MODULE.iso(event_time + timedelta(hours=1)),
                "requester": "requester@example.test", "implementer": "operator@example.test",
                "audit_event_ids": event["event_id"],
                "audit_event_grouping_ids": event["event_grouping_id"],
                "resource_ocids": event["resource_ocid"],
                "implementation_result": "FAILED" if event["outcome"] == "FAILED" else "SUCCESS",
                "validation_result": "PASS", "rollback_result": "NOT-REQUIRED",
                "ccb_approval_reference": f"CCB-{index}", "emergency_approval_reference": "",
                "authority": "Remedy Change Management", "source_export_time": MODULE.iso(FIXED_NOW),
                "evidence_reference": f"evidence/crq-{index}", "oci_event_name": event["event_name"],
            })
            owner_data.append({
                "crq_id": crq, "system_name": "OCS", "system_owner": "System Owner",
                "approver_principal": "owner@example.test", "approval_status": "APPROVED",
                "approval_time": MODULE.iso(event_time - timedelta(hours=3)),
                "approval_type": "PRE-IMPLEMENTATION", "approval_reference": f"SO-{index}",
                "authority": "OCS System Owner", "evidence_reference": f"evidence/owner-{index}",
            })
        write_csv(register_path, MODULE.REGISTER_FIELDS, register_data)
        write_csv(owner_path, MODULE.OWNER_FIELDS, owner_data)
        sampled_event = changes[0]
        write_csv(sample_path, MODULE.SAMPLE_FIELDS, [{
            "sample_id": "SAMPLE-001", "crq_id": "CRQ000001",
            "audit_event_ids": sampled_event["event_id"],
            "selection_basis": "Representative normal OCI configuration change",
            "implementation_evidence_reference": "evidence/implementation-1",
            "validation_evidence_reference": "evidence/validation-1",
            "backout_evidence_reference": "evidence/backout-1",
            "reviewer": "CM Reviewer", "review_date": MODULE.iso(FIXED_NOW),
            "sample_result": "PASS", "authority": "Configuration Control Board",
            "evidence_reference": "evidence/sample-1",
        }])

        governed_draft = root / "governed-draft"
        sdk_draft, _ = fake_oci()
        rc, stdout, stderr = run(
            sdk_draft, [
                "-r", "us-langley-1", "--change-register", str(register_path),
                "--owner-approvals", str(owner_path), "--change-samples", str(sample_path),
                "-o", str(governed_draft),
            ], f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 3 and "GOVERNANCE INPUTS NOT VALIDATED" in stderr
        reconciled = rows(one(governed_draft, "*_change_reconciliation.csv"))
        assert all(row["reconciliation_status"].startswith("VALIDATED") for row in reconciled), reconciled

        review_path = root / "approved-monthly-review.csv"
        review = rows(one(governed_draft, "*_monthly_review_template.csv"))[0]
        review.update({
            "reviewer": "CM Review Board", "review_date": MODULE.iso(FIXED_NOW),
            "sampling_conclusion": "REPRESENTATIVE",
            "sampling_policy_reference": "CM-SAMPLING-POLICY-001",
            "approval_status": "APPROVED", "evidence_reference": "evidence/monthly-review",
            "notes": "Exact snapshot reviewed",
        })
        write_csv(review_path, MODULE.REVIEW_FIELDS, [review])

        final = root / "final"
        sdk_final, _ = fake_oci()
        rc, stdout, stderr = run(
            sdk_final, [
                "-r", "us-langley-1", "--change-register", str(register_path),
                "--owner-approvals", str(owner_path), "--change-samples", str(sample_path),
                "--monthly-review", str(review_path), "-o", str(final),
            ], f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 0, (stdout, stderr)
        summary = one(final, "*_summary.txt").read_text(encoding="utf-8")
        assert "GOVERNANCE INPUT STATUS : VALIDATED" in summary
        validation = rows(one(final, "*_monthly_review_validation.csv"))
        assert validation[0]["validation_status"] == "VALID", validation

    print("PASS: CM03-01 SDK Audit collection, scope safety, CRQ approvals, samples and monthly review")


if __name__ == "__main__":
    main()
