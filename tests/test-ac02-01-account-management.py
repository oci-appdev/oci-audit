#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for AC02-01."""

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
SPEC = importlib.util.spec_from_file_location(
    "ac02_01", ROOT / "ac02-01-account-management.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..ac02tenancy"
CONFIG = "ocid1.compartment.oc1..ac02config"
SHARED = "ocid1.compartment.oc1..ac02shared"
ALICE = "ocid1.user.oc1..ac02alice"
SERVICE = "ocid1.user.oc1..ac02service"
DEVELOPERS = "ocid1.group.oc1..ac02developers"
ADMINS = "ocid1.group.oc1..ac02admins"
DOMAIN = "ocid1.domain.oc1..ac02default"
FIXED_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)


class Response:
    def __init__(self, data, request_id="ac02-mock-request"):
        self.data = data
        self.headers = {"opc-request-id": request_id}


class Collection:
    def __init__(self, items):
        self.items = items


class ScimCollection:
    def __init__(self, resources, total, start):
        self.resources = resources
        self.total_results = total
        self.start_index = start
        self.items_per_page = len(resources)


class FakeServiceError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.status = 403
        self.code = "NotAuthorizedOrNotFound"
        self.opc_request_id = "ac02-denied-request"
        self.message = message


class FakeState:
    def __init__(self):
        self.calls = []
        self.fail_method = ""
        self.malformed_scim = False
        self.classic_pages = 0
        self.scim_pages = 0

    def call(self, method, subject=""):
        self.calls.append((method, subject))
        if self.fail_method == method:
            raise FakeServiceError("mock denied token=SECRET-TOKEN password=SECRET-PASSWORD")


class BaseClient:
    state = None

    def __init__(self, config, **kwargs):
        self.config = config
        self.kwargs = kwargs


def caps(**overrides):
    values = {
        "can_use_console_password": True,
        "can_use_api_keys": True,
        "can_use_auth_tokens": True,
        "can_use_smtp_credentials": True,
        "can_use_db_credentials": True,
        "can_use_customer_secret_keys": True,
        "can_use_o_auth2_client_credentials": True,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


class IdentityClient(BaseClient):
    def get_compartment(self, compartment_id, **kwargs):
        self.state.call("get_compartment", compartment_id)
        names = {TENANCY: "MockTenancy", CONFIG: "Configuration", SHARED: "Shared Services"}
        parents = {TENANCY: "", CONFIG: TENANCY, SHARED: TENANCY}
        return Response(SimpleNamespace(
            id=compartment_id, name=names[compartment_id], compartment_id=parents[compartment_id]
        ))

    def list_compartments(self, compartment_id, **kwargs):
        self.state.call("list_compartments", compartment_id)
        return Response(Collection([
            SimpleNamespace(id=CONFIG, name="Configuration"),
            SimpleNamespace(id=SHARED, name="Shared Services"),
        ]))

    def list_users(self, compartment_id, **kwargs):
        self.state.call("list_users", compartment_id)
        return Response([SimpleNamespace(
            id=ALICE, name="=alice", lifecycle_state="ACTIVE",
            identity_provider_id="", is_mfa_activated=True,
            last_successful_login_time=FIXED_NOW - timedelta(days=2),
            time_created=FIXED_NOW - timedelta(days=700), capabilities=caps(),
            password="SECRET-CLASSIC-PASSWORD",
        )])

    def list_groups(self, compartment_id, **kwargs):
        self.state.call("list_groups", compartment_id)
        return Response([
            SimpleNamespace(id=DEVELOPERS, name="Developers", lifecycle_state="ACTIVE", time_created=FIXED_NOW - timedelta(days=600)),
            SimpleNamespace(id=ADMINS, name="Administrators", lifecycle_state="ACTIVE", time_created=FIXED_NOW - timedelta(days=600)),
        ])

    def list_dynamic_groups(self, compartment_id, **kwargs):
        self.state.call("list_dynamic_groups", compartment_id)
        return Response([SimpleNamespace(
            id="ocid1.dynamicgroup.oc1..ac02build", name="BuildAgents",
            lifecycle_state="ACTIVE", time_created=FIXED_NOW - timedelta(days=100),
            matching_rule="ALL {resource.type='instance'}",
        )])

    def list_domains(self, compartment_id, **kwargs):
        self.state.call("list_domains", compartment_id)
        return Response([SimpleNamespace(
            id=DOMAIN, display_name="Default", compartment_id=TENANCY,
            type="DEFAULT", license_type="FREE", home_region="us-langley-1",
            lifecycle_state="ACTIVE", time_created=FIXED_NOW - timedelta(days=800),
            url="https://idcs-ac02.identity.example.test",
        )])

    def list_network_sources(self, compartment_id, **kwargs):
        self.state.call("list_network_sources", compartment_id)
        return Response([SimpleNamespace(
            id="ocid1.networksource.oc1..ac02", name="Corporate",
            description="Corporate ranges", public_source_list=["192.0.2.0/24"],
            virtual_source_list=[], lifecycle_state="ACTIVE",
            time_created=FIXED_NOW - timedelta(days=90),
        )])

    def list_user_group_memberships(self, compartment_id, user_id=None, **kwargs):
        self.state.call("list_user_group_memberships", user_id or compartment_id)
        return Response([SimpleNamespace(
            id="ocid1.groupmembership.oc1..alice-dev", user_id=ALICE,
            group_id=DEVELOPERS, lifecycle_state="ACTIVE",
            time_created=FIXED_NOW - timedelta(days=400),
        )] if user_id == ALICE else [])

    def list_api_keys(self, user_id, **kwargs):
        self.state.call("list_api_keys", user_id)
        return Response([SimpleNamespace(
            fingerprint="aa:bb:cc", lifecycle_state="ACTIVE",
            time_created=FIXED_NOW - timedelta(days=100), description="=automation",
            key_value="SECRET-PUBLIC-KEY-VALUE",
        )])

    def list_auth_tokens(self, user_id, **kwargs):
        self.state.call("list_auth_tokens", user_id)
        return Response([SimpleNamespace(
            id="ocid1.credential.oc1..auth", lifecycle_state="ACTIVE",
            time_created=FIXED_NOW - timedelta(days=60), description="integration",
            token="SECRET-AUTH-TOKEN",
        )])

    def list_customer_secret_keys(self, user_id, **kwargs):
        self.state.call("list_customer_secret_keys", user_id)
        return Response([])

    def list_db_credentials(self, user_id, **kwargs):
        self.state.call("list_db_credentials", user_id)
        return Response([])

    def list_o_auth_client_credentials(self, user_id, **kwargs):
        self.state.call("list_o_auth_client_credentials", user_id)
        return Response([])

    def list_smtp_credentials(self, user_id, **kwargs):
        self.state.call("list_smtp_credentials", user_id)
        return Response([])

    def get_authentication_policy(self, compartment_id, **kwargs):
        self.state.call("get_authentication_policy", compartment_id)
        return Response(SimpleNamespace(
            password_policy=SimpleNamespace(
                minimum_password_length=14, is_uppercase_characters_required=True,
                is_lowercase_characters_required=True,
                is_numeric_characters_required=True,
                is_special_characters_required=True,
                is_username_containment_allowed=False,
            ),
            network_policy=SimpleNamespace(
                network_source_ids=["ocid1.networksource.oc1..ac02"]
            ),
        ))

    def list_policies(self, compartment_id, **kwargs):
        self.state.call("list_policies", compartment_id)
        statements = []
        if compartment_id == TENANCY:
            statements = ["Allow group Developers to manage instances in tenancy"]
        elif compartment_id == CONFIG:
            statements = [
                "Allow group 'Default'/'Operators' to read audit-events in compartment Configuration where request.permission='AUDIT_EVENT_READ'"
            ]
        return Response([SimpleNamespace(
            id=f"ocid1.policy.oc1..{compartment_id[-6:]}", name=f"policy-{compartment_id[-6:]}",
            lifecycle_state="ACTIVE", version_date=FIXED_NOW - timedelta(days=10),
            statements=statements,
        )] if statements else [])


class IdentityDomainsClient(BaseClient):
    def list_users(self, start_index=1, count=1000, **kwargs):
        self.state.call("domain_list_users", str(start_index))
        self.state.scim_pages += 1
        if self.state.malformed_scim:
            return Response(SimpleNamespace(
                resources=None, total_results=1, start_index=start_index,
                items_per_page=0,
            ), "domain-users-malformed")
        meta = lambda days: SimpleNamespace(
            created=(FIXED_NOW - timedelta(days=days)).isoformat(),
            last_modified=(FIXED_NOW - timedelta(days=1)).isoformat(),
        )
        state = lambda days: SimpleNamespace(
            last_successful_login_date=(FIXED_NOW - timedelta(days=days)).isoformat()
        )
        mfa = SimpleNamespace(mfa_status="ENROLLED")
        extension = SimpleNamespace(is_federated_user=True)
        manager = SimpleNamespace(value="manager-1", display_name="Manager One")
        enterprise = SimpleNamespace(manager=manager)
        users = [
            SimpleNamespace(
                id="domain-alice", ocid=ALICE, user_name="=alice@example.test",
                display_name="Alice", user_type="Employee", active=True,
                groups=[SimpleNamespace(
                    value="domain-developers", ocid=DEVELOPERS,
                    membership_ocid="ocid1.groupmembership.oc1..alice-dev",
                    type="direct", date_added=(FIXED_NOW - timedelta(days=400)).isoformat(),
                )], meta=meta(700),
                urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user=state(2),
                urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user=mfa,
                urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user=extension,
                urn_ietf_params_scim_schemas_extension_enterprise2_0_user=enterprise,
                password="SECRET-DOMAIN-PASSWORD", bypass_codes=["SECRET-BYPASS"],
            ),
            SimpleNamespace(
                id="domain-service", ocid=SERVICE, user_name="svc-build",
                display_name="Build Service", user_type="Service", active=True,
                groups=[SimpleNamespace(
                    value="domain-operators", ocid="",
                    membership_ocid="domain-membership-service-operators",
                    type="direct", date_added=(FIXED_NOW - timedelta(days=30)).isoformat(),
                )], meta=meta(100),
                urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user=SimpleNamespace(last_successful_login_date=""),
                urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user=SimpleNamespace(mfa_status="NOT-APPLICABLE"),
                urn_ietf_params_scim_schemas_oracle_idcs_extension_user_user=SimpleNamespace(is_federated_user=False),
                urn_ietf_params_scim_schemas_extension_enterprise2_0_user=SimpleNamespace(manager=None),
                password="SECRET-SERVICE-PASSWORD",
            ),
        ]
        page = users[start_index - 1:start_index]
        return Response(ScimCollection(page, len(users), start_index), "domain-users")

    def list_groups(self, start_index=1, count=1000, **kwargs):
        self.state.call("domain_list_groups", str(start_index))
        self.state.scim_pages += 1
        meta = SimpleNamespace(
            created=(FIXED_NOW - timedelta(days=600)).isoformat(),
            last_modified=(FIXED_NOW - timedelta(days=1)).isoformat(),
        )
        groups = [
            SimpleNamespace(id="domain-developers", ocid=DEVELOPERS, display_name="Developers", meta=meta),
            SimpleNamespace(id="domain-operators", ocid="", display_name="Operators", meta=meta),
        ]
        page = groups[start_index - 1:start_index]
        return Response(ScimCollection(page, len(groups), start_index), "domain-groups")


def fake_oci():
    state = FakeState()
    for client in (IdentityClient, IdentityDomainsClient):
        client.state = state

    def paginate(method, *args, **kwargs):
        state.classic_pages += 1
        return method(*args, **kwargs)

    sdk = SimpleNamespace(
        __version__="2.185.1-mock",
        config=SimpleNamespace(
            from_file=lambda path, profile: {
                "tenancy": TENANCY, "user": "ocid1.user.oc1..mock",
                "fingerprint": "aa:bb", "key_file": "/mock/key.pem",
                "region": "us-langley-1",
            },
            validate_config=lambda config: None,
        ),
        retry=SimpleNamespace(DEFAULT_RETRY_STRATEGY=object()),
        pagination=SimpleNamespace(list_call_get_all_results=paginate),
        identity=SimpleNamespace(IdentityClient=IdentityClient),
        identity_domains=SimpleNamespace(IdentityDomainsClient=IdentityDomainsClient),
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
    with Path(path).open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, fields, data):
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)


def populate_governance(technical: Path, target: Path):
    target.mkdir()
    account_data = rows(one(technical, "*_account_register_template.csv"))
    for row in account_data:
        row.update({
            "account_type": "SERVICE" if "service" in row["account_key"] else "HUMAN",
            "system_name": "OCS", "manager": "Manager One", "account_owner": "System Owner",
            "employment_status": "ACTIVE", "request_reference": "REQ-100",
            "approval_status": "APPROVED", "approver": "IAM Approver",
            "approval_date": "2026-09-01T10:00:00Z",
            "last_authoritative_activity": "2026-09-01T09:00:00Z",
            "authoritative_source": "HR-and-service-account-register",
            "evidence_reference": "evidence://accounts/2026-09",
        })
    account_path = target / "account.csv"
    write_csv(account_path, MODULE.ACCOUNT_REGISTER_FIELDS, account_data)

    access_data = rows(one(technical, "*_access_approval_template.csv"))
    for row in access_data:
        row.update({
            "access_decision": "KEEP", "manager": "Manager One",
            "approver": "IAM Approver", "approval_status": "APPROVED",
            "approval_date": "2026-09-01T10:00:00Z", "request_reference": "REQ-ACCESS-100",
            "authority": "Access Control Policy", "evidence_reference": "evidence://access/2026-09",
        })
    access_path = target / "access.csv"
    write_csv(access_path, MODULE.ACCESS_APPROVAL_FIELDS, access_data)

    privilege_data = rows(one(technical, "*_privilege_review_template.csv"))
    for row in privilege_data:
        row.update({
            "privilege_decision": "KEEP", "privilege_owner": "Cloud Owner",
            "approver": "ISSO", "approval_status": "APPROVED",
            "approval_date": "2026-09-01T10:00:00Z", "request_reference": "REQ-PRIV-100",
            "least_privilege_rationale": "Required for approved OCS duties",
            "authority": "Least Privilege Standard", "evidence_reference": "evidence://privileges/2026-09",
        })
    privilege_path = target / "privilege.csv"
    write_csv(privilege_path, MODULE.PRIVILEGE_REVIEW_FIELDS, privilege_data)

    policy_data = []
    for kind in ("HUMAN", "SERVICE"):
        policy_data.append({
            "account_type": kind, "max_inactive_days": "90",
            "unknown_activity_action": "INVESTIGATE", "removal_sla_days": "5",
            "policy_owner": "IAM Owner", "authority": "Account Management Policy",
            "effective_date": "2026-01-01T00:00:00Z", "approval_status": "APPROVED",
            "approver": "ISSO", "evidence_reference": "evidence://policy/ac2",
        })
    policy_path = target / "inactivity.csv"
    write_csv(policy_path, MODULE.INACTIVITY_POLICY_FIELDS, policy_data)

    lifecycle_data = [{
        "procedure_id": "AC2-PROC-1", "process_owner": "IAM Owner",
        "request_process_reference": "procedure://joiner", "modification_process_reference": "procedure://mover",
        "deactivation_process_reference": "procedure://leaver", "authoritative_hr_source": "HRIS",
        "joiner_sla_days": "2", "mover_sla_days": "2", "leaver_sla_days": "1",
        "unused_account_review_frequency": "MONTHLY", "privileged_review_frequency": "MONTHLY",
        "service_account_review_frequency": "MONTHLY", "review_template_reference": "template://ac2-review",
        "approval_status": "APPROVED", "approver": "ISSO",
        "approval_date": "2026-08-31T10:00:00Z", "evidence_reference": "evidence://procedure/ac2",
    }]
    lifecycle_path = target / "lifecycle.csv"
    write_csv(lifecycle_path, MODULE.LIFECYCLE_FIELDS, lifecycle_data)

    review_data = rows(one(technical, "*_monthly_review_template.csv"))
    review_data[0].update({
        "reviewer": "Compliance Reviewer", "review_date": "2026-09-02T11:00:00Z",
        "compliance_result": "PASS-WITH-FINDINGS",
        "corrective_action_reference": "POAM-AC2-MANUAL-BOUNDARIES",
        "approval_status": "APPROVED", "approver": "ISSO",
        "evidence_reference": "evidence://reviews/2026-09",
        "notes": "Manual gaps acknowledged and tracked for HR, federation, local, database, application and break-glass evidence.",
    })
    review_path = target / "review.csv"
    write_csv(review_path, MODULE.REVIEW_FIELDS, review_data)
    return account_path, access_path, privilege_path, policy_path, lifecycle_path, review_path


def main():
    MODULE.utc_now = lambda: FIXED_NOW
    assert MODULE.source_selfcheck()
    MODULE.SDK_READ_METHODS.add("delete_user")
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        assert not MODULE.source_selfcheck()
    MODULE.SDK_READ_METHODS.remove("delete_user")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        technical = root / "technical"
        sdk, state = fake_oci()
        rc, stdout, stderr = run(
            sdk, ["-r", "us-langley-1", "-o", str(technical)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 0, (stdout, stderr)
        assert "AC02-01 COLLECTION COMPLETE" in stdout
        assert state.classic_pages >= 15 and state.scim_pages == 4
        account_rows = rows(one(technical, "*_account_inventory.csv"))
        assert len(account_rows) == 2, account_rows
        assert {row["account_key"] for row in account_rows} == {"OCI:" + ALICE, "OCI:" + SERVICE}
        alice = next(row for row in account_rows if row["account_key"] == "OCI:" + ALICE)
        assert alice["source_system"] == "OCI-CLASSIC+OCI-IDENTITY-DOMAIN"
        assert alice["mfa_status"] == "ENROLLED" and alice["group_count"] == "1"
        memberships = rows(one(technical, "*_group_memberships.csv"))
        assert len(memberships) == 2 and all(row["privilege_keys"] for row in memberships)
        privileges = rows(one(technical, "*_privilege_candidates.csv"))
        assert len(privileges) == 3, privileges
        assert {row["mapping_status"] for row in privileges} == {"RESOLVED"}
        credential_text = one(technical, "*_credential_metadata.csv").read_text(encoding="utf-8")
        assert "SECRET-" not in credential_text and "'=automation" in credential_text
        assert oct(one(technical, "*_account_inventory.csv").stat().st_mode & 0o777) == "0o600"
        assert "COMPLETE" in one(technical, "*_summary.txt").read_text(encoding="utf-8")

        # Immutable output collision refuses before workload account calls.
        sdk_collision, collision_state = fake_oci()
        rc, _, stderr = run(
            sdk_collision, ["-r", "us-langley-1", "-o", str(technical)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 1 and "output collision" in stderr
        assert not any(call[0] == "list_users" for call in collision_state.calls)

        # Manual explicit scope and strict automation cannot bypass the exact
        # OCID-twice/plan/uppercase-YES boundary.
        refused = root / "refused"
        sdk_refused, refused_state = fake_oci()
        rc, stdout, stderr = run(
            sdk_refused, ["-r", "us-langley-1", "-c", CONFIG, "-o", str(refused)],
            f"{CONFIG}\n{CONFIG}\nno\n",
        )
        assert rc == 1 and "SCAN NOT STARTED" in stderr and not refused.exists()
        assert "PRE-SCAN SAFETY SUMMARY" in stdout
        assert not any(call[0] == "list_users" for call in refused_state.calls)

        mismatch = root / "mismatch"
        sdk_mismatch, mismatch_state = fake_oci()
        rc, stdout, stderr = run(sdk_mismatch, [
            "-r", "us-langley-1", "--tenancy-scope", "--non-interactive",
            "--confirm-scope-ocid", TENANCY, "--approve-scan", "YES",
            "-o", str(mismatch),
        ])
        assert rc == 1 and "do not exactly match" in stderr and not mismatch.exists()
        assert "PRE-SCAN SAFETY SUMMARY" in stdout
        assert not any(call[0] == "list_users" for call in mismatch_state.calls)

        automated = root / "automated"
        sdk_auto, _ = fake_oci()
        confirmations = []
        for ocid in (TENANCY, CONFIG, SHARED):
            confirmations.extend(["--confirm-scope-ocid", ocid])
        rc, stdout, stderr = run(sdk_auto, [
            "-r", "us-langley-1", "--tenancy-scope", "--non-interactive",
            *confirmations, "--approve-scan", "YES", "-o", str(automated),
        ])
        assert rc == 0, (stdout, stderr)

        # Denied credential metadata remains an attributed/redacted failure and
        # cannot look like zero credentials.
        denied = root / "denied"
        sdk_denied, denied_state = fake_oci()
        denied_state.fail_method = "list_api_keys"
        rc, stdout, stderr = run(
            sdk_denied, ["-r", "us-langley-1", "-o", str(denied)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 3 and "COLLECTION INCOMPLETE" in stderr
        error_text = one(denied, "*_collection_errors.csv").read_text(encoding="utf-8")
        assert "<redacted>" in error_text and "SECRET-" not in error_text
        assert any(row["operation"] == "list_api_keys" and row["status"] == "FAILED" for row in rows(one(denied, "*_collection_coverage.csv")))

        # A malformed generated SCIM response is a collection failure, not an
        # empty Identity Domain account inventory.
        malformed = root / "malformed-scim"
        sdk_malformed, malformed_state = fake_oci()
        malformed_state.malformed_scim = True
        rc, stdout, stderr = run(
            sdk_malformed, ["-r", "us-langley-1", "-o", str(malformed)],
            f"{TENANCY}\n{TENANCY}\nYES\n",
        )
        assert rc == 3 and "COLLECTION INCOMPLETE" in stderr
        assert any(
            row["source_system"] == "OCI-IDENTITY-DOMAIN"
            and row["operation"] == "list_users" and row["status"] == "FAILED"
            for row in rows(one(malformed, "*_collection_coverage.csv"))
        )

        # Full governance is bound to exact account/access/privilege keys and
        # to the exact reconciled snapshot and count set.  The review is
        # completed from the template emitted after the first five governance
        # inputs have been reconciled, never from the technical-only template.
        input_dir = root / "inputs"
        paths = populate_governance(technical, input_dir)
        review_prep = root / "review-prep"
        sdk_review_prep, _ = fake_oci()
        rc, stdout, stderr = run(sdk_review_prep, [
            "-r", "us-langley-1", "-o", str(review_prep),
            "--account-register", str(paths[0]), "--access-approvals", str(paths[1]),
            "--privilege-review", str(paths[2]), "--inactivity-policy", str(paths[3]),
            "--lifecycle-procedure", str(paths[4]),
        ], f"{TENANCY}\n{TENANCY}\nYES\n")
        assert rc == 3 and "GOVERNANCE INPUTS NOT VALIDATED" in stderr
        assert "COLLECTION STATUS         : COMPLETE" in stdout
        review_data = rows(one(review_prep, "*_monthly_review_template.csv"))
        review_data[0].update({
            "reviewer": "Compliance Reviewer", "review_date": "2026-09-02T11:00:00Z",
            "compliance_result": "PASS-WITH-FINDINGS",
            "corrective_action_reference": "POAM-AC2-MANUAL-BOUNDARIES",
            "approval_status": "APPROVED", "approver": "ISSO",
            "evidence_reference": "evidence://reviews/2026-09",
            "notes": "Manual gaps acknowledged and tracked for HR, federation, local, database, application and break-glass evidence.",
        })
        write_csv(paths[5], MODULE.REVIEW_FIELDS, review_data)
        governed = root / "governed"
        sdk_governed, _ = fake_oci()
        rc, stdout, stderr = run(sdk_governed, [
            "-r", "us-langley-1", "-o", str(governed),
            "--account-register", str(paths[0]), "--access-approvals", str(paths[1]),
            "--privilege-review", str(paths[2]), "--inactivity-policy", str(paths[3]),
            "--lifecycle-procedure", str(paths[4]), "--monthly-review", str(paths[5]),
        ], f"{TENANCY}\n{TENANCY}\nYES\n")
        assert rc == 0, (stdout, stderr)
        assert "GOVERNANCE INPUT STATUS   : VALIDATED" in stdout
        assert all(row["reconciliation_status"] in {"VALIDATED", "VALIDATED-NOT-LIVE"} for row in rows(one(governed, "*_account_reconciliation.csv")))
        assert all(row["reconciliation_status"] == "VALIDATED" for row in rows(one(governed, "*_access_reconciliation.csv")))
        assert rows(one(governed, "*_monthly_review_validation.csv"))[0]["validation_status"] == "VALID"

        # A stale privilege binding fails governance without changing the
        # underlying technical collection status.
        stale_rows = rows(paths[1])
        stale_rows[0]["reviewed_privilege_keys"] = "stale-key"
        stale_path = input_dir / "access-stale.csv"
        write_csv(stale_path, MODULE.ACCESS_APPROVAL_FIELDS, stale_rows)
        stale = root / "stale"
        sdk_stale, _ = fake_oci()
        rc, stdout, stderr = run(sdk_stale, [
            "-r", "us-langley-1", "-o", str(stale),
            "--account-register", str(paths[0]), "--access-approvals", str(stale_path),
            "--privilege-review", str(paths[2]), "--inactivity-policy", str(paths[3]),
            "--lifecycle-procedure", str(paths[4]), "--monthly-review", str(paths[5]),
        ], f"{TENANCY}\n{TENANCY}\nYES\n")
        assert rc == 3 and "GOVERNANCE INPUTS NOT VALIDATED" in stderr
        assert "COLLECTION STATUS         : COMPLETE" in stdout
        assert any(row["reconciliation_status"] == "PRIVILEGE-SET-STALE" for row in rows(one(stale, "*_access_reconciliation.csv")))

    print("PASS: AC02-01 SDK accounts, domains, groups, privileges, inactivity and approvals")


if __name__ == "__main__":
    main()
