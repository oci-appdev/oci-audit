#!/usr/bin/env python3
"""Mock generated-OCI-client regression for IA02-01."""

from __future__ import annotations

import csv
import importlib.util
import io
import os
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ia02_01", ROOT / "ia02-01-federation-configuration.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..ia02tenancy"
COMPARTMENT = "ocid1.compartment.oc1..ia02shared"
DOMAIN = "ocid1.domain.oc1..ia02default"
FIXED_NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)


class Response:
    def __init__(self, data, request_id="ia02-request", next_page=None):
        self.data = data
        self.headers = {"opc-request-id": request_id}
        if next_page:
            self.headers["opc-next-page"] = next_page
        self.next_page = next_page


class Collection:
    def __init__(self, items):
        self.items = items


class ScimCollection:
    def __init__(self, resources, total, start):
        self.resources = resources
        self.total_results = total
        self.start_index = start
        self.items_per_page = len(resources)


class ResourcesCollection:
    def __init__(self, resources):
        self.resources = resources


class FakeServiceError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.status = 403
        self.code = "NotAuthorizedOrNotFound"
        self.opc_request_id = "denied-request"
        self.message = message


class State:
    def __init__(self):
        self.calls = []
        self.fail_method = ""
        self.factor_pages = []

    def call(self, method, subject=""):
        self.calls.append((method, subject))
        if self.fail_method == method:
            raise FakeServiceError("denied token=SECRET-TOKEN password=SECRET-PASSWORD")


STATE = State()


class IdentityClient:
    def __init__(self, config, **kwargs):
        self.config = config

    def get_compartment(self, compartment_id, **kwargs):
        STATE.call("get_compartment", compartment_id)
        name = "MockTenancy" if compartment_id == TENANCY else "Shared Services"
        return Response(SimpleNamespace(id=compartment_id, name=name))

    def list_compartments(self, compartment_id, **kwargs):
        STATE.call("list_compartments", compartment_id)
        return Response(Collection([SimpleNamespace(id=COMPARTMENT, name="Shared Services")]))

    def list_domains(self, compartment_id, **kwargs):
        STATE.call("list_domains", compartment_id)
        return Response(Collection([SimpleNamespace(
            id=DOMAIN, display_name="Default", compartment_id=TENANCY, type="DEFAULT",
            home_region="us-langley-1", lifecycle_state="ACTIVE",
            time_created=FIXED_NOW, url="https://idcs-ia02.identity.example.test",
        )]))


def meta():
    return SimpleNamespace(created="2025-01-01T00:00:00Z", last_modified="2026-09-01T00:00:00Z")


class IdentityDomainsClient:
    def __init__(self, config, **kwargs):
        self.config = config
        self.endpoint = kwargs.get("service_endpoint")

    def _scim(self, method, values, start_index):
        STATE.call(method, str(start_index))
        # Force the provider endpoint through two SCIM pages.
        if method == "list_identity_providers":
            page = values[start_index - 1:start_index]
        else:
            page = values if start_index == 1 else []
        return Response(ScimCollection(page, len(values), start_index), method + "-request")

    def list_identity_providers(self, start_index=1, count=1000, **kwargs):
        values = [
            SimpleNamespace(
                id="idp-okta", ocid="ocid1.identityprovider.oc1..okta", partner_name="=Okta",
                type="SAML", enabled=True, shown_on_login_page=True,
                idp_sso_url="https://example.okta.test/app/SECRET-PATH/sso/saml",
                logout_request_url="https://example.okta.test/logout/request",
                logout_response_url="https://example.okta.test/logout/response",
                authn_request_binding="HTTP-Redirect", logout_binding="HTTP-Redirect",
                logout_enabled=True, signature_hash_algorithm="SHA-256",
                name_id_format="persistent", signing_certificate="SECRET-RAW-CERTIFICATE",
                encryption_certificate="SECRET-ENCRYPTION-CERTIFICATE", require_force_authn=True,
                requires_encrypted_assertion=True, jit_user_prov_enabled=True,
                jit_user_prov_create_user_enabled=True, jit_user_prov_attribute_update_enabled=True,
                jit_user_prov_group_assertion_attribute_enabled=True,
                jit_user_prov_group_static_list_enabled=False,
                jit_user_prov_group_assignment_method="ASSERTION",
                jit_user_prov_group_mapping_mode="EXPLICIT",
                jit_user_prov_group_mappings=[SimpleNamespace(value="SensitiveMapping")],
                jit_user_prov_assigned_groups=[], user_mapping_method="NameID",
                user_mapping_store_attribute="userName", assertion_attribute="NameID",
                requested_authentication_context=["PasswordProtectedTransport"], meta=meta(),
                client_secret="SECRET-CLIENT-SECRET",
            ),
            SimpleNamespace(
                id="idp-other", ocid="", partner_name="Other IdP", type="SAML", enabled=False,
                shown_on_login_page=False, meta=meta(),
            ),
        ]
        return self._scim("list_identity_providers", values, start_index)

    def list_apps(self, start_index=1, count=1000, **kwargs):
        values = [SimpleNamespace(
            id="app-console", ocid="ocid1.app.oc1..console", name="OCI Console",
            display_name="=OCI Console", active=True, login_mechanism="SAML",
            is_login_target=True, is_saml_service_provider=True, is_o_auth_client=False,
            is_managed_app=False, client_type="", allowed_grants=["authorization_code"],
            allowed_scopes=[SimpleNamespace(value="openid")],
            identity_providers=[SimpleNamespace(value="idp-okta")],
            app_signon_policy=SimpleNamespace(value="policy-signon"),
            based_on_template=SimpleNamespace(value="template-console"),
            saml_service_provider=SimpleNamespace(value="sp-console"), meta=meta(),
            client_secret="SECRET-APP-CLIENT-SECRET", hashed_client_secret="SECRET-HASH",
        )]
        return self._scim("list_apps", values, start_index)

    def list_policies(self, start_index=1, count=1000, **kwargs):
        values = [SimpleNamespace(
            id="policy-signon", ocid="", name="Console Sign-On", active=True,
            policy_type=SimpleNamespace(value="SIGN_ON"),
            rules=[SimpleNamespace(value="rule-mfa")], policy_groovy="SECRET-GROOVY", meta=meta(),
        )]
        return self._scim("list_policies", values, start_index)

    def list_rules(self, start_index=1, count=1000, **kwargs):
        STATE.call("list_rules", str(start_index))
        values = [SimpleNamespace(
            id="rule-mfa", ocid="", name="Require MFA", active=True, locked=False,
            policy_type=SimpleNamespace(value="SIGN_ON"), condition="group eq SensitiveGroup",
            _return=[SimpleNamespace(name="mfaRequired", value="true", return_groovy="SECRET-RETURN")],
            rule_groovy="SECRET-RULE-GROOVY", meta=meta(),
        )]
        return Response(ScimCollection(values, 1, 1), "list_rules-request")

    def list_authentication_factor_settings(self, page=None, limit=1000, **kwargs):
        STATE.call("list_authentication_factor_settings", page or "FIRST")
        STATE.factor_pages.append(page)
        if page is None:
            values = [SimpleNamespace(
                id="factor-one", ocid="", mfa_enrollment_type="MANDATORY",
                mfa_enabled_category="ALL", email_enabled=True, sms_enabled=True,
                phone_call_enabled=False, totp_enabled=True, push_enabled=True,
                fido_authenticator_enabled=True, yubico_otp_enabled=False,
                bypass_code_enabled=False, security_questions_enabled=False,
                hide_backup_factor_enabled=True, auto_enroll_email_factor_disabled=True,
                user_enrollment_disabled_factors=["SECURITY_QUESTIONS"], meta=meta(),
                bypass_code_settings="SECRET-RECOVERY-DATA",
            )]
            return Response(ResourcesCollection(values), "factor-page-1", "NEXT")
        return Response(ResourcesCollection([]), "factor-page-2")


class Config:
    @staticmethod
    def from_file(path, profile):
        return {"tenancy": TENANCY, "region": "us-langley-1"}

    @staticmethod
    def validate_config(config):
        return None


class Pagination:
    @staticmethod
    def list_call_get_all_results(method, *args, **kwargs):
        response = method(*args, **kwargs)
        data = response.data
        if hasattr(data, "items"):
            return Response(list(data.items), response.headers.get("opc-request-id", "ia02-request"))
        return response


OCI = SimpleNamespace(
    __version__="2.185.1-mock", config=Config,
    retry=SimpleNamespace(DEFAULT_RETRY_STRATEGY=object()), pagination=Pagination,
    identity=SimpleNamespace(IdentityClient=IdentityClient),
    identity_domains=SimpleNamespace(IdentityDomainsClient=IdentityDomainsClient),
)


def run(args):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = MODULE.main(args, oci_module=OCI)
    return code, stdout.getvalue(), stderr.getvalue()


def csv_rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def latest(directory, suffix):
    matches = list(Path(directory).glob("ia02-01_*_" + suffix))
    assert len(matches) == 1, (suffix, matches)
    return matches[0]


def write_rows(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def base_args(output):
    return [
        "-r", "us-langley-1", "--tenancy-scope", "--non-interactive",
        "--confirm-scope-ocid", TENANCY, "--confirm-scope-ocid", COMPARTMENT,
        "--approve-scan", "YES", "-o", str(output),
    ]


def main():
    MODULE.utc_now = lambda: FIXED_NOW
    assert MODULE.source_selfcheck()
    loop_calls = []

    class LoopClient:
        def list_authentication_factor_settings(self, page=None, **kwargs):
            loop_calls.append(page)
            return Response(ResourcesCollection([]), next_page="LOOP")

    try:
        MODULE.sdk_resources_page_list(
            OCI, LoopClient(), "list_authentication_factor_settings",
            MODULE.RESOURCE_PAGE_METHODS,
        )
        raise AssertionError("repeated page token was accepted")
    except ValueError as exc:
        assert "repeated next-page token" in str(exc)
    assert loop_calls == [None, "LOOP"]

    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        technical = root / "technical"
        code, stdout, stderr = run(base_args(technical))
        assert code == 3, (code, stderr)
        assert "Completion scope: Task 13 completion requires tenancy selection" in stdout
        assert "Decision note" in stdout
        assert STATE.factor_pages[-2:] == [None, "NEXT"]
        providers = csv_rows(latest(technical, "identity_providers.csv"))
        apps = csv_rows(latest(technical, "federation_apps.csv"))
        policies = csv_rows(latest(technical, "signon_policies.csv"))
        rules = csv_rows(latest(technical, "signon_rules.csv"))
        assert len(providers) == 2 and len(apps) == len(policies) == len(rules) == 1
        assert providers[0]["partner_name"] == "'=Okta"
        evidence = "\n".join(path.read_text(encoding="utf-8") for path in technical.iterdir())
        for secret in (
            "SECRET-CLIENT-SECRET", "SECRET-APP-CLIENT-SECRET", "SECRET-HASH",
            "SECRET-RAW-CERTIFICATE", "SECRET-ENCRYPTION-CERTIFICATE",
            "SECRET-GROOVY", "SECRET-RETURN", "SECRET-RULE-GROOVY", "SECRET-RECOVERY-DATA",
            "SECRET-PATH",
        ):
            assert secret not in evidence
        for path in technical.iterdir():
            assert os.stat(path).st_mode & 0o777 == 0o600

        domain_calls = len([call for call in STATE.calls if call[0] == "list_domains"])
        code, _, collision_error = run(base_args(technical))
        assert code == 1 and "output collision" in collision_error
        assert len([call for call in STATE.calls if call[0] == "list_domains"]) == domain_calls

        compartment = root / "compartment"
        compartment_args = [
            "-r", "us-langley-1", "-c", COMPARTMENT, "--non-interactive",
            "--confirm-scope-ocid", COMPARTMENT, "--approve-scan", "YES",
            "-o", str(compartment),
        ]
        code, _, _ = run(compartment_args)
        assert code == 3
        assert "Directory collection       : SELECTED-COMPARTMENT-ONLY" in latest(compartment, "summary.txt").read_text()

        manual_refused = root / "manual-refused"
        calls_before_manual = len([call for call in STATE.calls if call[0] == "list_domains"])
        with patch("builtins.input", side_effect=[COMPARTMENT, "ocid1.compartment.oc1..wrong"]):
            code, _, _ = run(["-r", "us-langley-1", "-o", str(manual_refused)])
        assert code == 1 and not manual_refused.exists()
        assert len([call for call in STATE.calls if call[0] == "list_domains"]) == calls_before_manual

        manual_flag_refused = root / "manual-flag-refused"
        with patch("builtins.input", side_effect=[COMPARTMENT, COMPARTMENT, "yes"]):
            code, _, _ = run([
                "-r", "us-langley-1", "-c", COMPARTMENT,
                "-o", str(manual_flag_refused),
            ])
        assert code == 1 and not manual_flag_refused.exists()
        assert len([call for call in STATE.calls if call[0] == "list_domains"]) == calls_before_manual

        register = csv_rows(latest(technical, "integration_register_template.csv"))
        assert len(register) == 2
        snapshot = register[0]["snapshot_sha256"]
        app_key = apps[0]["app_key"]
        policy_key = policies[0]["policy_key"]
        rule_key = rules[0]["rule_key"]
        for row in register:
            row.update({
                "provider_system": "OKTA" if row["provider_key"].endswith("idp-okta") else "OTHER",
                "system_owner": "System Owner", "approver": "Security Approver",
                "approval_status": "APPROVED", "approval_date": "2026-09-02T10:00:00Z",
                "authority": "Approved federation standard", "rationale": "Reviewed applicability",
                "evidence_reference": "restricted://task13/provider-review",
            })
            if row["provider_key"].endswith("idp-okta"):
                row.update({
                    "disposition": "APPLICABLE", "integration_role": "OCI workforce authentication",
                    "provisioning_mode": "JIT", "selected_app_keys": app_key,
                    "selected_policy_keys": policy_key, "selected_rule_keys": rule_key,
                    "external_config_reference": "restricted://okta/app-config",
                    "external_config_sha256": "a" * 64, "mapping_review_status": "APPROVED",
                    "certificate_review_status": "APPROVED",
                })
            else:
                row.update({
                    "disposition": "NOT-APPLICABLE", "integration_role": "NONE",
                    "provisioning_mode": "NONE", "mapping_review_status": "NOT-APPLICABLE",
                    "certificate_review_status": "NOT-APPLICABLE",
                })
        _, _, omission_errors = MODULE.validate_register(
            register[:1], providers, snapshot, TENANCY, {app_key}, {policy_key},
            {rule_key}, FIXED_NOW,
        )
        assert any("missing required provider disposition" in value for value in omission_errors)
        register_path = root / "approved-register.csv"
        write_rows(register_path, MODULE.REGISTER_FIELDS, register)

        reconciliation = root / "reconciliation"
        code, stdout, stderr = run(base_args(reconciliation) + ["--integration-register", str(register_path)])
        assert code == 3 and "test evidence is required" in latest(reconciliation, "summary.txt").read_text()
        tests = csv_rows(latest(reconciliation, "test_evidence_template.csv"))
        assert {row["test_type"] for row in tests} == MODULE.REQUIRED_TESTS
        for row in tests:
            row.update({
                "test_result": "PASS", "tested_at": "2026-09-02T11:00:00Z", "tester": "Test User",
                "expected_result": "Approved authentication behavior observed",
                "evidence_reference": "restricted://task13/test/" + row["test_type"].lower(),
                "approver": "Security Approver", "approval_status": "APPROVED",
            })
        tests_path = root / "approved-tests.csv"
        write_rows(tests_path, MODULE.TEST_FIELDS, tests)

        final = root / "final"
        code, stdout, stderr = run(base_args(final) + [
            "--integration-register", str(register_path), "--test-evidence", str(tests_path),
        ])
        assert code == 0, (code, stderr, latest(final, "summary.txt").read_text())
        assert "Evidence result           : COMPLETE" in latest(final, "summary.txt").read_text()
        assert all(row["validation_status"] == "VALID" for row in csv_rows(latest(final, "integration_register_validation.csv")))
        assert all(row["validation_status"] == "VALID" for row in csv_rows(latest(final, "test_evidence_validation.csv")))

        calls_before = len([call for call in STATE.calls if call[0] == "list_domains"])
        refused = root / "refused"
        bad = base_args(refused)
        bad[bad.index(TENANCY, bad.index("--confirm-scope-ocid"))] = "ocid1.tenancy.oc1..wrong"
        code, _, _ = run(bad)
        assert code == 1 and not refused.exists()
        assert len([call for call in STATE.calls if call[0] == "list_domains"]) == calls_before

        STATE.fail_method = "list_rules"
        denied = root / "denied"
        code, _, _ = run(base_args(denied))
        STATE.fail_method = ""
        assert code == 2
        error_text = latest(denied, "collection_errors.csv").read_text()
        assert "<redacted>" in error_text and "SECRET-TOKEN" not in error_text
        assert "Evidence result           : INCOMPLETE" in latest(denied, "summary.txt").read_text()

    print("IA02-01 mock SDK tests passed")


if __name__ == "__main__":
    main()
