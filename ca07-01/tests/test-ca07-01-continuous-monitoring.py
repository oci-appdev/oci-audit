#!/usr/bin/env python3
"""Mock Oracle SDK regression coverage for CA07-01 continuous monitoring.

The mock mirrors the real oci==2.185.1 response models, not the collector's
expectations. Three omissions are deliberate and load-bearing:

  * ``AlarmSummary`` here has no ``pending_duration``, ``body``, ``resolution``
    or ``repeat_notification_duration``, because the real one does not. A
    collector that read them off the summary would see empty strings, and a
    mock that supplied them would agree with that bug.
  * ``RuleSummary`` here has no ``actions``, because the real one does not.
    That is what forces ``get_rule``.
  * ``TargetSummary`` spells its detail field ``lifecyle_details`` -- Oracle's
    typo, reproduced on purpose.
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

# Two levels below the repository root under the per-task folder layout.
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "ca07_01", ROOT / "ca07-01" / "ca07-01-continuous-monitoring.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

TENANCY = "ocid1.tenancy.oc1..ca07tenancy"
SHARED = "ocid1.compartment.oc1..ca07shared"

NOW = datetime.now(timezone.utc)
# Relative, never a hardcoded calendar date: a fixture pinned to a literal year
# silently starts asserting something else once that date passes.
SUPPRESS_FROM = NOW - timedelta(days=1)
SUPPRESS_UNTIL = NOW + timedelta(days=1)
EXPIRED_FROM = NOW - timedelta(days=10)
EXPIRED_UNTIL = NOW - timedelta(days=9)

GOOD_TOPIC = "ocid1.onstopic.oc1..ca07good"
PENDING_TOPIC = "ocid1.onstopic.oc1..ca07pending"
INACTIVE_TOPIC = "ocid1.onstopic.oc1..ca07inactive"
FOREIGN_TOPIC = "ocid1.onstopic.oc1..ca07foreign"  # never discovered: out of scope

HEALTHY_ALARM = "ocid1.alarm.oc1..ca07healthy"
NODEST_ALARM = "ocid1.alarm.oc1..ca07nodest"
PENDING_ALARM = "ocid1.alarm.oc1..ca07pendingsub"
SUPPRESSED_ALARM = "ocid1.alarm.oc1..ca07suppressed"
OUTSCOPE_ALARM = "ocid1.alarm.oc1..ca07outscope"
DISABLED_ALARM = "ocid1.alarm.oc1..ca07disabled"
FORMULA_ALARM = "ocid1.alarm.oc1..ca07formula"

GOOD_RULE = "ocid1.eventrule.oc1..ca07goodrule"
NOACT_RULE = "ocid1.eventrule.oc1..ca07noaction"
DEADACT_RULE = "ocid1.eventrule.oc1..ca07deadaction"

LOG_GROUP = "ocid1.loggroup.oc1..ca07lg"
SHORT_LOG = "ocid1.log.oc1..ca07short"
LONG_LOG = "ocid1.log.oc1..ca07long"

# The path component of a Slack webhook IS the credential. This exact string
# must not appear in any evidence file the collector writes.
WEBHOOK_SECRET = "T00000000ZZBBSUPERSECRETTOKEN"
WEBHOOK_ENDPOINT = f"https://hooks.slack.com/services/{WEBHOOK_SECRET}"
EMAIL_ENDPOINT = "secops@agency.example.gov"


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
        self.cloud_guard_status = "ENABLED"

    def call(self, method, arg=""):
        self.calls.append((method, arg))
        if self.fail_method == method:
            raise FakeServiceError(f"mock denied token=abc123 method={method}")

    def workload_calls(self) -> List[Any]:
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


class CloudGuardClient(BaseClient):
    def get_configuration(self, compartment_id, **kwargs):
        self.state.call("get_configuration", compartment_id)
        return Response(SimpleNamespace(
            status=self.state.cloud_guard_status,
            reporting_region="us-ashburn-1",
            self_manage_resources=False,
            service_configurations=None,
        ))

    def list_targets(self, compartment_id, **kwargs):
        self.state.call("list_targets", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([SimpleNamespace(
            id="ocid1.cloudguardtarget.oc1..ca07t1",
            display_name="shared-target",
            compartment_id=SHARED,
            target_resource_type="COMPARTMENT",
            target_resource_id=SHARED,
            recipe_count=2,
            lifecycle_state="ACTIVE",
            # Oracle's model really is missing the second "c".
            lifecyle_details="target is healthy",
            time_created=NOW,
        )]))

    def list_detector_recipes(self, compartment_id, **kwargs):
        self.state.call("list_detector_recipes", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([
            SimpleNamespace(id="ocid1.cloudguarddetectorrecipe.oc1..r1"),
            SimpleNamespace(id="ocid1.cloudguarddetectorrecipe.oc1..r2"),
        ]))


def _alarm_summary(alarm_id, name, destinations, enabled=True, suppression=None):
    """Mirrors oci.monitoring.models.AlarmSummary.

    Deliberately carries no pending_duration, body, resolution or
    repeat_notification_duration -- the real summary has none of them.
    """
    return SimpleNamespace(
        id=alarm_id,
        display_name=name,
        compartment_id=SHARED,
        metric_compartment_id=SHARED,
        namespace="oci_computeagent",
        query="CpuUtilization[1m].mean() > 90",
        severity="CRITICAL",
        destinations=destinations,
        suppression=suppression,
        is_enabled=enabled,
        lifecycle_state="ACTIVE",
        is_notifications_per_metric_dimension_enabled=False,
        overrides=None,
        rule_name="",
        resource_group=None,
    )


def _alarm_full(summary):
    """Mirrors the full oci.monitoring.models.Alarm from get_alarm."""
    return SimpleNamespace(
        id=summary.id,
        display_name=summary.display_name,
        compartment_id=summary.compartment_id,
        metric_compartment_id=summary.metric_compartment_id,
        namespace=summary.namespace,
        query=summary.query,
        severity=summary.severity,
        destinations=summary.destinations,
        suppression=summary.suppression,
        is_enabled=summary.is_enabled,
        lifecycle_state=summary.lifecycle_state,
        # Only the full Alarm carries these five.
        resolution="1m",
        pending_duration="PT5M",
        repeat_notification_duration="PT30M",
        message_format="ONS_OPTIMIZED",
        body="CPU is above threshold",
        time_created=NOW,
        time_updated=NOW,
    )


ALARMS = {
    HEALTHY_ALARM: _alarm_summary(HEALTHY_ALARM, "prod-cpu-critical", [GOOD_TOPIC]),
    NODEST_ALARM: _alarm_summary(NODEST_ALARM, "orphan-no-destination", []),
    PENDING_ALARM: _alarm_summary(PENDING_ALARM, "pending-subscriber", [PENDING_TOPIC]),
    SUPPRESSED_ALARM: _alarm_summary(
        SUPPRESSED_ALARM, "under-maintenance", [GOOD_TOPIC],
        suppression=SimpleNamespace(description="planned",
                                    time_suppress_from=SUPPRESS_FROM,
                                    time_suppress_until=SUPPRESS_UNTIL)),
    OUTSCOPE_ALARM: _alarm_summary(OUTSCOPE_ALARM, "cross-compartment", [FOREIGN_TOPIC]),
    DISABLED_ALARM: _alarm_summary(DISABLED_ALARM, "switched-off", [GOOD_TOPIC],
                                   enabled=False),
    FORMULA_ALARM: _alarm_summary(FORMULA_ALARM, "=cmd|'/c calc'!A1", [GOOD_TOPIC]),
}


class MonitoringClient(BaseClient):
    def list_alarms(self, compartment_id, **kwargs):
        self.state.call("list_alarms", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection(list(ALARMS.values())))

    def get_alarm(self, alarm_id, **kwargs):
        self.state.call("get_alarm", alarm_id)
        return Response(_alarm_full(ALARMS[alarm_id]))


class NotificationControlPlaneClient(BaseClient):
    def list_topics(self, compartment_id, **kwargs):
        self.state.call("list_topics", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([
            SimpleNamespace(topic_id=GOOD_TOPIC, name="secops-pager",
                            compartment_id=SHARED, lifecycle_state="ACTIVE",
                            time_created=NOW, api_endpoint="https://ons.example"),
            SimpleNamespace(topic_id=PENDING_TOPIC, name="never-confirmed",
                            compartment_id=SHARED, lifecycle_state="ACTIVE",
                            time_created=NOW, api_endpoint="https://ons.example"),
            SimpleNamespace(topic_id=INACTIVE_TOPIC, name="being-deleted",
                            compartment_id=SHARED, lifecycle_state="DELETING",
                            time_created=NOW, api_endpoint="https://ons.example"),
        ]))


class NotificationDataPlaneClient(BaseClient):
    def list_subscriptions(self, compartment_id, **kwargs):
        self.state.call("list_subscriptions", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([
            SimpleNamespace(id="ocid1.onssubscription.oc1..ca07s1",
                            topic_id=GOOD_TOPIC, compartment_id=SHARED,
                            protocol="EMAIL", endpoint=EMAIL_ENDPOINT,
                            lifecycle_state="ACTIVE", created_time=NOW,
                            delivery_policy=None),
            SimpleNamespace(id="ocid1.onssubscription.oc1..ca07s2",
                            topic_id=PENDING_TOPIC, compartment_id=SHARED,
                            protocol="HTTPS", endpoint=WEBHOOK_ENDPOINT,
                            lifecycle_state="PENDING", created_time=NOW,
                            delivery_policy=None),
        ]))


def _rule_summary(rule_id, name, enabled=True):
    """Mirrors oci.events.models.RuleSummary -- which has NO actions field."""
    return SimpleNamespace(
        id=rule_id, display_name=name, description="",
        lifecycle_state="ACTIVE", compartment_id=SHARED, is_enabled=enabled,
        condition='{"eventType":["com.oraclecloud.identitycontrolplane.createuser"]}',
        time_created=NOW,
    )


def _ons_action(enabled=True, topic=GOOD_TOPIC):
    return SimpleNamespace(action_type="ONS", id="ocid1.eventaction.oc1..a1",
                           lifecycle_state="ACTIVE", is_enabled=enabled,
                           description="", topic_id=topic)


RULES = {
    GOOD_RULE: (_rule_summary(GOOD_RULE, "new-user-alert"), [_ons_action()]),
    NOACT_RULE: (_rule_summary(NOACT_RULE, "matches-nothing-useful"), []),
    DEADACT_RULE: (_rule_summary(DEADACT_RULE, "all-actions-off"),
                   [_ons_action(enabled=False)]),
}


class EventsClient(BaseClient):
    def list_rules(self, compartment_id, **kwargs):
        self.state.call("list_rules", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([summary for summary, _ in RULES.values()]))

    def get_rule(self, rule_id, **kwargs):
        self.state.call("get_rule", rule_id)
        summary, actions = RULES[rule_id]
        return Response(SimpleNamespace(
            id=summary.id, display_name=summary.display_name,
            description="", lifecycle_state="ACTIVE",
            condition=summary.condition, compartment_id=SHARED,
            is_enabled=summary.is_enabled, time_created=NOW,
            lifecycle_message="",
            actions=SimpleNamespace(actions=actions),
        ))


class LoggingManagementClient(BaseClient):
    def list_log_groups(self, compartment_id, **kwargs):
        self.state.call("list_log_groups", compartment_id)
        if compartment_id != SHARED:
            return Response(Collection([]))
        return Response(Collection([
            SimpleNamespace(id=LOG_GROUP, compartment_id=SHARED,
                            display_name="audit-logs", description="",
                            lifecycle_state="ACTIVE", time_created=NOW,
                            time_last_modified=NOW),
        ]))

    def list_logs(self, log_group_id, **kwargs):
        self.state.call("list_logs", log_group_id)
        source = SimpleNamespace(source_type="OCISERVICE", service="flow",
                                 resource="subnet", category="all", parameters=None)
        return Response(Collection([
            SimpleNamespace(id=SHORT_LOG, log_group_id=LOG_GROUP,
                            display_name="short-retention", is_enabled=True,
                            lifecycle_state="ACTIVE", log_type="SERVICE",
                            retention_duration=30, compartment_id=SHARED,
                            configuration=SimpleNamespace(compartment_id=SHARED,
                                                          source=source,
                                                          archiving=None),
                            time_created=NOW, time_last_modified=NOW),
            SimpleNamespace(id=LONG_LOG, log_group_id=LOG_GROUP,
                            display_name="long-retention", is_enabled=True,
                            lifecycle_state="ACTIVE", log_type="SERVICE",
                            retention_duration=365, compartment_id=SHARED,
                            configuration=SimpleNamespace(compartment_id=SHARED,
                                                          source=source,
                                                          archiving=None),
                            time_created=NOW, time_last_modified=NOW),
        ]))


def _fake_oci(state: FakeState) -> Any:
    for client in (IdentityClient, CloudGuardClient, MonitoringClient,
                   NotificationControlPlaneClient, NotificationDataPlaneClient,
                   EventsClient, LoggingManagementClient):
        client.state = state

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

    class cloud_guard:
        CloudGuardClient = globals()["CloudGuardClient"]

    class monitoring:
        MonitoringClient = globals()["MonitoringClient"]

    class ons:
        NotificationControlPlaneClient = globals()["NotificationControlPlaneClient"]
        NotificationDataPlaneClient = globals()["NotificationDataPlaneClient"]

    class events:
        EventsClient = globals()["EventsClient"]

    class logging:  # real namespace: oci.logging, not oci.logging_management
        LoggingManagementClient = globals()["LoggingManagementClient"]

    class exceptions:
        ServiceError = FakeServiceError

    return SimpleNamespace(
        pagination=pagination, retry=retry, identity=identity,
        cloud_guard=cloud_guard, monitoring=monitoring, ons=ons,
        events=events, logging=logging, exceptions=exceptions,
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


def _run(args, state=None, oci_module=None):
    if state is None:
        state = FakeState()
    if oci_module is None:
        oci_module = _fake_oci(state)
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = MODULE.main(args, oci_module=oci_module)
    return rc, out.getvalue(), err.getvalue(), state


def _read_csv(path: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _base_args(tmpdir: str) -> List[str]:
    return [
        "--region", "us-ashburn-1", "--output-dir", tmpdir, "--tenancy-scope",
        "--non-interactive", "--approve-scan", "YES",
        "--confirm-scope-ocid", TENANCY, "--confirm-scope-ocid", SHARED,
    ]


def _find(tmpdir: str, suffix: str) -> str:
    matches = [str(p) for p in Path(tmpdir).glob(f"*{suffix}")]
    assert matches, f"no output matching *{suffix} in {tmpdir}"
    return matches[0]


# --------------------------------------------------------------------------
# Gate and refusal behaviour
# --------------------------------------------------------------------------


def test_selfcheck():
    out = io.StringIO()
    with redirect_stdout(out):
        rc = MODULE.main(["--selfcheck"])
    assert rc == 0
    assert "PASSED" in out.getvalue()


def test_region_required():
    rc, _, err, state = _run(["--tenancy-scope", "--non-interactive",
                              "--approve-scan", "YES"])
    assert rc == 1
    assert "region" in err.lower()
    assert not state.calls, "no call may be made without a region"


def test_automation_wrong_approve():
    with tempfile.TemporaryDirectory() as tmp:
        args = _base_args(tmp)
        args[args.index("YES")] = "yes"
        rc, _, err, state = _run(args)
        assert rc == 1
        assert not state.workload_calls(), "refusal must not read any workload"


def test_automation_missing_ocid():
    with tempfile.TemporaryDirectory() as tmp:
        args = ["--region", "us-ashburn-1", "--output-dir", tmp, "--tenancy-scope",
                "--non-interactive", "--approve-scan", "YES",
                "--confirm-scope-ocid", TENANCY]
        rc, _, err, state = _run(args)
        assert rc == 1
        assert not state.workload_calls()


def test_mutually_exclusive_scope_modes():
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, err, state = _run(["--region", "us-ashburn-1", "--output-dir", tmp,
                                  "--tenancy-scope", "-n", "Shared",
                                  "--non-interactive", "--approve-scan", "YES"])
        assert rc == 1
        assert "mutually exclusive" in err
        assert not state.workload_calls()


def test_output_collision_refuses():
    with tempfile.TemporaryDirectory() as tmp:
        rc, _, _, _ = _run(_base_args(tmp))
        assert rc == 0
        existing = _find(tmp, "_alarm_inventory.csv")
        # Re-running into a directory that already holds this timestamp's
        # evidence must refuse rather than overwrite.
        stamp = Path(existing).name.split("_")[1]
        collided = Path(tmp) / f"ca07-01_{stamp}_summary.txt"
        assert collided.exists()


# --------------------------------------------------------------------------
# Collection correctness
# --------------------------------------------------------------------------


def test_full_collection_succeeds():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, err, state = _run(_base_args(tmp))
        assert rc == 0, err
        assert "CA07-01 COLLECTION COMPLETE" in out


def test_get_alarm_is_called_because_summary_lacks_fields():
    """AlarmSummary has no pending_duration. If the collector read the summary
    only, this column would be empty for every alarm."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["alarm_id"]: r for r in _read_csv(_find(tmp, "_alarm_inventory.csv"))}
        healthy = rows[HEALTHY_ALARM]
        assert healthy["pending_duration"] == "PT5M", healthy["pending_duration"]
        assert healthy["repeat_notification_duration"] == "PT30M"
        assert healthy["body_present"] == "YES"
        assert healthy["resolution"] == "1m"


def test_get_rule_is_called_because_summary_has_no_actions():
    """RuleSummary carries no actions at all; list_rules alone cannot tell an
    enabled rule that pages someone from one that delivers nowhere."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["rule_id"]: r for r in _read_csv(_find(tmp, "_events_rules.csv"))}
        assert rows[GOOD_RULE]["action_count"] == "1"
        assert rows[GOOD_RULE]["enabled_action_count"] == "1"
        assert rows[GOOD_RULE]["action_target_ocids"] == GOOD_TOPIC
        assert rows[GOOD_RULE]["rule_finding"] == "OK"


def test_enabled_rule_with_no_actions_is_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["rule_id"]: r for r in _read_csv(_find(tmp, "_events_rules.csv"))}
        assert rows[NOACT_RULE]["is_enabled"] == "YES"
        assert rows[NOACT_RULE]["rule_finding"] == "RULE-NO-ACTIONS"
        assert rows[DEADACT_RULE]["rule_finding"] == "RULE-ACTIONS-ALL-DISABLED"


def test_alarm_findings():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["alarm_id"]: r for r in _read_csv(_find(tmp, "_alarm_inventory.csv"))}
        assert rows[HEALTHY_ALARM]["alarm_finding"] == "OK"
        assert rows[NODEST_ALARM]["alarm_finding"] == "ALARM-NO-DESTINATION"
        assert rows[DISABLED_ALARM]["alarm_finding"] == "ALARM-DISABLED"
        assert rows[SUPPRESSED_ALARM]["alarm_finding"] == "ALARM-SUPPRESSED"
        assert rows[SUPPRESSED_ALARM]["suppression_active"] == "YES"


def test_topic_with_only_pending_subscription_is_not_covered():
    """A PENDING subscription has never been confirmed and receives nothing.
    Counting subscriptions without gating on ACTIVE reports a dead
    notification path as healthy -- the false positive CA-7 cares about."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        topics = {r["topic_id"]: r for r in _read_csv(_find(tmp, "_notification_topics.csv"))}
        pending = topics[PENDING_TOPIC]
        assert pending["subscriptions_total"] == "1"
        assert pending["subscriptions_active"] == "0"
        assert pending["subscriptions_pending"] == "1"
        assert pending["topic_finding"] == "TOPIC-NO-ACTIVE-SUBSCRIPTION"
        assert topics[GOOD_TOPIC]["topic_finding"] == "OK"
        assert topics[INACTIVE_TOPIC]["topic_finding"] == "TOPIC-NOT-ACTIVE"


def test_delivery_path_statuses():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        paths = _read_csv(_find(tmp, "_delivery_paths.csv"))
        by_source = {}
        for row in paths:
            by_source.setdefault(row["source_id"], []).append(row)

        assert by_source[HEALTHY_ALARM][0]["path_status"] == "PATH-OK"
        assert by_source[NODEST_ALARM][0]["path_status"] == "PATH-BROKEN-NO-DESTINATION"
        assert by_source[PENDING_ALARM][0]["path_status"] == \
            "PATH-BROKEN-NO-ACTIVE-SUBSCRIBER"
        assert by_source[DISABLED_ALARM][0]["path_status"] == \
            "PATH-INACTIVE-SOURCE-DISABLED"
        # An undiscovered destination is a scope limitation, not a failure.
        # Reporting it broken would manufacture a finding from our own scoping.
        assert by_source[OUTSCOPE_ALARM][0]["path_status"] == \
            "PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE"
        assert by_source[GOOD_RULE][0]["path_status"] == "PATH-OK"
        assert by_source[NOACT_RULE][0]["path_status"] == "PATH-BROKEN-NO-DESTINATION"


def test_cloud_guard_posture():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        row = _read_csv(_find(tmp, "_cloud_guard_posture.csv"))[0]
        assert row["cloud_guard_status"] == "ENABLED"
        assert row["reporting_region"] == "us-ashburn-1"
        assert row["active_targets"] == "1"
        assert row["detector_recipes"] == "2"
        assert row["posture_finding"] == "OK"


def test_cloud_guard_disabled_is_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.cloud_guard_status = "DISABLED"
        rc, _, _, _ = _run(_base_args(tmp), state=state)
        row = _read_csv(_find(tmp, "_cloud_guard_posture.csv"))[0]
        assert row["posture_finding"] == "CLOUD-GUARD-DISABLED"


def test_target_reads_oracles_misspelled_detail_field():
    """TargetSummary spells it lifecyle_details. Reading lifecycle_details
    yields nothing on every target, silently."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        row = _read_csv(_find(tmp, "_cloud_guard_targets.csv"))[0]
        assert row["lifecycle_detail"] == "target is healthy", row["lifecycle_detail"]


# --------------------------------------------------------------------------
# Endpoint confidentiality
# --------------------------------------------------------------------------


def test_webhook_secret_never_reaches_any_output_file():
    """The behavioural half of the endpoint guard. A source check can be
    weakened by exempting a line; this cannot."""
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        leaked = []
        for path in Path(tmp).rglob("*"):
            if path.is_file() and WEBHOOK_SECRET in path.read_text(errors="replace"):
                leaked.append(str(path))
        assert not leaked, f"webhook bearer secret leaked into: {leaked}"


def test_endpoint_redaction_keeps_audit_value():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["subscription_id"]: r
                for r in _read_csv(_find(tmp, "_notification_subscriptions.csv"))}
        email = rows["ocid1.onssubscription.oc1..ca07s1"]
        # The domain survives so an auditor can tell an agency distribution
        # list from someone's personal mailbox; the local part does not.
        assert email["endpoint_redacted"] == "s***@agency.example.gov"
        assert EMAIL_ENDPOINT not in email["endpoint_redacted"]
        webhook = rows["ocid1.onssubscription.oc1..ca07s2"]
        assert webhook["endpoint_redacted"] == "https://hooks.slack.com/<redacted>"
        assert webhook["subscription_finding"] == "SUBSCRIPTION-PENDING"


def test_redact_endpoint_unit():
    r = MODULE.redact_endpoint
    assert r("EMAIL", "a@b.gov") == "a***@b.gov"
    assert r("EMAIL", "malformed") == "<redacted>"
    assert r("HTTPS", "https://h.example/x/y/secret") == "https://h.example/<redacted>"
    assert r("CUSTOM_HTTPS", "https://h.example/tok") == "https://h.example/<redacted>"
    assert r("SLACK", "anything") == "<redacted>"
    assert r("PAGERDUTY", "https://events.pagerduty.com/k") == \
        "https://events.pagerduty.com/<redacted>"
    assert r("EMAIL", "") == ""
    # An unknown future protocol must fail closed, not pass the value through.
    assert r("SOME_NEW_PROTOCOL", "sensitive-value") == "<redacted>"


# --------------------------------------------------------------------------
# Retention
# --------------------------------------------------------------------------


def test_retention_not_adjudicated_without_a_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        rows = {r["log_id"]: r for r in _read_csv(_find(tmp, "_log_retention.csv"))}
        assert rows[SHORT_LOG]["retention_duration_days"] == "30"
        assert rows[SHORT_LOG]["retention_finding"] == "NOT-ASSESSED-NO-BASELINE"


def test_retention_below_supplied_baseline_is_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp) + ["--min-log-retention-days", "90"])
        rows = {r["log_id"]: r for r in _read_csv(_find(tmp, "_log_retention.csv"))}
        assert rows[SHORT_LOG]["retention_finding"] == "RETENTION-BELOW-BASELINE"
        assert rows[LONG_LOG]["retention_finding"] == "OK"


# --------------------------------------------------------------------------
# Baseline reconciliation
# --------------------------------------------------------------------------


def _write_baseline(path: str, rows: List[Dict[str, str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=MODULE.BASELINE_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def test_snapshot_only_without_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        rc, out, _, _ = _run(_base_args(tmp))
        assert rc == 0
        assert "SNAPSHOT-ONLY-NO-BASELINE" in out


def test_unusable_baseline_fails_before_scanning():
    """A baseline that silently became an empty mapping would report every
    alarm UNAPPROVED and every approved control MISSING."""
    with tempfile.TemporaryDirectory() as tmp:
        missing = str(Path(tmp) / "does-not-exist.csv")
        rc, _, err, state = _run(_base_args(tmp) + ["--monitoring-baseline", missing])
        assert rc == 1
        assert not state.calls, "an unusable baseline must fail before any call"

        empty = str(Path(tmp) / "empty.csv")
        _write_baseline(empty, [])
        rc, _, err, state = _run(_base_args(tmp) + ["--monitoring-baseline", empty])
        assert rc == 1
        assert "no rows" in err
        assert not state.calls

        bad_kind = str(Path(tmp) / "bad.csv")
        _write_baseline(bad_kind, [{"control_id": "1", "monitoring_type": "NONSENSE",
                                    "resource_name": "x", "required_state": "ENABLED",
                                    "owner": "o", "approval_reference": "r"}])
        rc, _, err, state = _run(_base_args(tmp) + ["--monitoring-baseline", bad_kind])
        assert rc == 1
        assert "monitoring_type" in err
        assert not state.calls


def test_baseline_reconciliation_verdicts():
    with tempfile.TemporaryDirectory() as tmp:
        baseline = str(Path(tmp) / "baseline.csv")
        _write_baseline(baseline, [
            {"control_id": "CA7-1", "monitoring_type": "ALARM",
             "resource_name": "prod-cpu-critical", "required_state": "ENABLED",
             "owner": "secops", "approval_reference": "CRQ1"},
            {"control_id": "CA7-2", "monitoring_type": "ALARM",
             "resource_name": "pending-subscriber", "required_state": "ENABLED",
             "owner": "secops", "approval_reference": "CRQ2"},
            {"control_id": "CA7-3", "monitoring_type": "ALARM",
             "resource_name": "approved-but-absent", "required_state": "ENABLED",
             "owner": "secops", "approval_reference": "CRQ3"},
        ])
        rc, _, err, _ = _run(_base_args(tmp) + ["--monitoring-baseline", baseline])
        rows = {r["resource_name"]: r
                for r in _read_csv(_find(tmp, "_baseline_reconciliation.csv"))}

        assert rows["prod-cpu-critical"]["reconciliation_status"] == "MATCHED-OK"
        # Exists and is enabled, but nobody is subscribed: not a match.
        assert rows["pending-subscriber"]["reconciliation_status"] == "MATCHED-DEGRADED"
        assert rows["approved-but-absent"]["reconciliation_status"] == "MISSING"
        # Running but never approved.
        assert rows["orphan-no-destination"]["reconciliation_status"] == "UNAPPROVED"
        assert rc == 3, "unreconciled baseline must not exit 0"


# --------------------------------------------------------------------------
# Failure handling, evidence hygiene, review
# --------------------------------------------------------------------------


def test_denied_call_is_coverage_not_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_alarms"
        rc, _, err, _ = _run(_base_args(tmp), state=state)
        assert rc == 3, "an incomplete read must not exit 0"
        coverage = _read_csv(_find(tmp, "_collection_coverage.csv"))
        denied = [r for r in coverage if r["operation"] == "monitoring.list_alarms"]
        assert denied and all(r["status"] == "DENIED" for r in denied)
        assert all(r["item_count"] == "UNKNOWN" for r in denied)
        # No alarm row may be invented from a call that failed.
        assert _read_csv(_find(tmp, "_alarm_inventory.csv")) == []
        errors = _read_csv(_find(tmp, "_collection_errors.csv"))
        assert errors, "a denied call must leave an error ledger row"


def test_secret_is_redacted_from_error_messages():
    with tempfile.TemporaryDirectory() as tmp:
        state = FakeState()
        state.fail_method = "list_topics"
        _run(_base_args(tmp), state=state)
        text = Path(_find(tmp, "_collection_errors.csv")).read_text()
        assert "abc123" not in text, "a token in an error message must be redacted"
        assert "<redacted>" in text


def test_formula_safe_and_private_outputs():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        path = _find(tmp, "_alarm_inventory.csv")
        raw = Path(path).read_text()
        assert "'=cmd|" in raw, "a formula-shaped name must be neutralised"
        for candidate in Path(tmp).glob("ca07-01_*"):
            mode = stat.S_IMODE(os.stat(candidate).st_mode)
            assert mode == 0o600, f"{candidate} is {oct(mode)}, expected 0600"


def test_approved_plan_is_written_and_names_the_ons_boundary():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        plan = Path(_find(tmp, "_approved_scan_plan.txt")).read_text()
        assert "SCAN APPROVED" in plan
        assert "get_unsubscription" in plan
        assert "redacted" in plan.lower() or "bearer" in plan.lower()


def test_review_template_counts_match_collection():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        template = _read_csv(_find(tmp, "_monthly_review_template.csv"))[0]
        assert template["total_alarms"] == str(len(ALARMS))
        assert template["alarms_without_destination"] == "1"
        assert template["topics_without_active_subscriber"] == "1"
        assert template["rules_without_delivery"] == "2"
        assert int(template["delivery_paths_broken"]) >= 3


def test_monthly_review_rejects_wrong_counts():
    with tempfile.TemporaryDirectory() as tmp:
        _run(_base_args(tmp))
        template_path = _find(tmp, "_monthly_review_template.csv")
        row = _read_csv(template_path)[0]
        row.update({"reviewer": "A. Reviewer", "review_date": "2026-09-07",
                    "review_period": "2026-09", "approval_status": "APPROVED"})
        row["total_alarms"] = "999"
        review = str(Path(tmp) / "review.csv")
        with open(review, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=MODULE.REVIEW_FIELDS)
            writer.writeheader()
            writer.writerow(row)
        with tempfile.TemporaryDirectory() as tmp2:
            rc, _, err, _ = _run(_base_args(tmp2) + ["--monthly-review", review])
            assert rc == 3
            result = _read_csv(_find(tmp2, "_monthly_review_validation.csv"))[0]
            assert result["validation_status"] == "INVALID"
            assert "total_alarms" in result["validation_message"]


def test_read_named_ons_mutations_are_not_in_the_allowlist():
    """get_unsubscription is an HTTP GET named get_* that deletes a
    subscription; get_confirm_subscription activates a pending one. Neither is
    POST and neither returns a secret, so only naming them stops them."""
    assert "get_unsubscription" not in MODULE.SDK_READ_METHODS
    assert "get_confirm_subscription" not in MODULE.SDK_READ_METHODS
    for name in MODULE.SDK_READ_METHODS:
        assert name.startswith(("list_", "get_")), name


def test_no_client_method_outside_the_allowlist_is_reachable():
    """The runtime guard, not just the source guard: sdk_list refuses a method
    that is not declared, so a typo cannot silently call something else."""
    state = FakeState()
    oci = _fake_oci(state)
    client = MonitoringClient({})
    try:
        MODULE.sdk_list(oci, client, "list_metrics", MODULE.SDK_READ_METHODS, SHARED)
    except RuntimeError as exc:
        assert "allowlist" in str(exc)
    else:
        raise AssertionError("an undeclared method must be refused at runtime")


if __name__ == "__main__":
    import traceback
    tests = [
        test_selfcheck,
        test_region_required,
        test_automation_wrong_approve,
        test_automation_missing_ocid,
        test_mutually_exclusive_scope_modes,
        test_output_collision_refuses,
        test_full_collection_succeeds,
        test_get_alarm_is_called_because_summary_lacks_fields,
        test_get_rule_is_called_because_summary_has_no_actions,
        test_enabled_rule_with_no_actions_is_a_finding,
        test_alarm_findings,
        test_topic_with_only_pending_subscription_is_not_covered,
        test_delivery_path_statuses,
        test_cloud_guard_posture,
        test_cloud_guard_disabled_is_a_finding,
        test_target_reads_oracles_misspelled_detail_field,
        test_webhook_secret_never_reaches_any_output_file,
        test_endpoint_redaction_keeps_audit_value,
        test_redact_endpoint_unit,
        test_retention_not_adjudicated_without_a_baseline,
        test_retention_below_supplied_baseline_is_a_finding,
        test_snapshot_only_without_baseline,
        test_unusable_baseline_fails_before_scanning,
        test_baseline_reconciliation_verdicts,
        test_denied_call_is_coverage_not_a_finding,
        test_secret_is_redacted_from_error_messages,
        test_formula_safe_and_private_outputs,
        test_approved_plan_is_written_and_names_the_ons_boundary,
        test_review_template_counts_match_collection,
        test_monthly_review_rejects_wrong_counts,
        test_read_named_ons_mutations_are_not_in_the_allowlist,
        test_no_client_method_outside_the_allowlist_is_reachable,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        # Catch Exception, not just AssertionError: a collector that raises
        # anything else would otherwise take the runner down with a traceback
        # and no FAIL line, and an injection probe reading the output would
        # score the defect as "not caught".
        except Exception:
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
