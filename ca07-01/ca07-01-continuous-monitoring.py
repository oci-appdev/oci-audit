#!/usr/bin/env python3
"""CA-7 continuous monitoring evidence using Oracle's OCI Python SDK.

PYTHON FILES USED: none beyond lib/oci_audit_sdk.py, which this imports.

What this collector is for
--------------------------
CA-7 is not satisfied by the existence of an alarm. It is satisfied by a
detection that reaches a human. This collector therefore does not stop at an
inventory: it reconstructs the delivery path

    alarm  / events rule  ->  destination OCID  ->  ONS topic  ->  ACTIVE subscription

and reports the first link that is broken. An enabled alarm with no
destination, a topic with no confirmed subscriber, and an events rule whose
only action is disabled all look healthy in a plain inventory and all deliver
nothing. Those are false positives in the direction that matters: they tell an
assessor the tenancy is monitored when nobody would be told.

Model traps this collector exists on the far side of (oci==2.185.1)
------------------------------------------------------------------
* ``AlarmSummary`` carries no ``pending_duration``, ``body``, ``resolution`` or
  ``repeat_notification_duration``. Only the full ``Alarm`` from ``get_alarm``
  does, so each alarm is read individually. Same shape as the
  ``ServiceConnectorSummary`` trap in SI04-01.
* ``RuleSummary`` carries no ``actions`` at all. An events rule's entire
  delivery configuration is invisible to ``list_rules``; ``get_rule`` is
  mandatory, not an enrichment.
* ``Subscription.endpoint`` is either personal data (an ``EMAIL`` address) or a
  credential (an ``HTTPS`` webhook whose path component is the bearer secret
  for Slack, PagerDuty and most other targets). Read-only is not the same as
  safe to write into evidence, and this repository is public. ``redact_endpoint``
  is the only reader, and the test asserts a planted webhook token reaches no
  output file.
* ``TargetSummary`` spells its detail field ``lifecyle_details`` -- the typo is
  Oracle's and is part of the wire contract. Reading ``lifecycle_details``
  silently yields nothing.
* A ``PENDING`` subscription has never been confirmed and receives no message.
  Counting subscriptions without gating on ``ACTIVE`` reports a dead
  notification path as covered.
"""

from __future__ import annotations

import argparse
import ast
import csv
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

SCRIPT_PATH = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT_PATH.parent
# lib/ is at the repository root, one level above this task folder.
sys.path.insert(0, str(SCRIPT_DIR.parent / "lib"))

from oci_audit_sdk import (  # noqa: E402
    ScopeItem,
    build_auth_context,
    build_client,
    discover_scope,
    error_record,
    iso,
    load_oci,
    request_id,
    sdk_get,
    sdk_list,
    sha256_file,
    stable_hash,
    utc_now,
    write_csv,
    write_private_text,
)

VERSION = "1.0.0"
COLLECTOR = "CA07-01"
CONTROLS = "CA-7 / SI-4 / AU-6 / IR-5"

SDK_READ_METHODS: Set[str] = {
    "get_compartment",
    "list_compartments",
    # Cloud Guard posture
    "get_configuration",
    "list_targets",
    "list_detector_recipes",
    # Alarms. get_alarm is required, not an enrichment: AlarmSummary has no
    # pending_duration, body, resolution or repeat_notification_duration.
    "list_alarms",
    "get_alarm",
    # Notification delivery path
    "list_topics",
    "list_subscriptions",
    # Events. get_rule is required: RuleSummary carries no actions at all.
    "list_rules",
    "get_rule",
    # Log retention
    "list_log_groups",
    "list_logs",
}

# Protocols whose endpoint is a bearer URL rather than an address. The path
# component of a Slack or PagerDuty webhook is the credential.
WEBHOOK_PROTOCOLS: Set[str] = {"HTTPS", "HTTP", "CUSTOM_HTTPS", "SLACK", "PAGERDUTY"}

# oci.events.models.Action.get_subtype dispatches on exactly these three.
ACTION_TARGET_ATTR: Dict[str, str] = {
    "ONS": "topic_id",
    "OSS": "stream_id",
    "FAAS": "function_id",
}

CLOUD_GUARD_FIELDS = [
    "scope_kind", "scope_ocid", "scope_name", "cloud_guard_status",
    "reporting_region", "self_manage_resources", "targets_discovered",
    "active_targets", "detector_recipes", "posture_finding", "region",
]

TARGET_FIELDS = [
    "target_key", "target_id", "display_name", "compartment_id",
    "compartment_name", "target_resource_type", "target_resource_id",
    "recipe_count", "lifecycle_state", "lifecycle_detail",
    "time_created", "target_finding", "region",
]

ALARM_FIELDS = [
    "alarm_key", "alarm_id", "display_name", "compartment_id", "compartment_name",
    "metric_compartment_id", "namespace", "severity", "is_enabled",
    "lifecycle_state", "query", "resolution", "pending_duration",
    "repeat_notification_duration", "message_format", "body_present",
    "destination_count", "destination_ocids", "suppression_active",
    "suppression_from", "suppression_until", "alarm_finding",
    "time_created", "region",
]

TOPIC_FIELDS = [
    "topic_key", "topic_id", "topic_name", "compartment_id", "compartment_name",
    "lifecycle_state", "subscriptions_total", "subscriptions_active",
    "subscriptions_pending", "protocols", "topic_finding", "time_created", "region",
]

SUBSCRIPTION_FIELDS = [
    "subscription_key", "subscription_id", "topic_id", "topic_name",
    "compartment_id", "compartment_name", "protocol", "endpoint_redacted",
    "lifecycle_state", "created_time", "subscription_finding", "region",
]

RULE_FIELDS = [
    "rule_key", "rule_id", "display_name", "compartment_id", "compartment_name",
    "lifecycle_state", "is_enabled", "condition_present", "condition_event_types",
    "action_count", "enabled_action_count", "action_kinds", "action_target_ocids",
    "rule_finding", "time_created", "region",
]

LOG_FIELDS = [
    "log_key", "log_group_id", "log_group_name", "log_id", "log_name",
    "compartment_id", "compartment_name", "log_type", "is_enabled",
    "lifecycle_state", "retention_duration_days", "source_service",
    "source_resource", "source_category", "retention_finding", "region",
]

PATH_FIELDS = [
    "path_key", "source_kind", "source_id", "source_name", "source_enabled",
    "compartment_name", "destination_ocid", "destination_kind",
    "topic_name", "topic_lifecycle_state", "active_subscribers",
    "path_status", "path_detail", "region",
]

BASELINE_FIELDS = [
    "control_id", "monitoring_type", "resource_name", "required_state",
    "owner", "approval_reference",
]

RECONCILIATION_FIELDS = BASELINE_FIELDS + [
    "observed_state", "observed_id", "delivery_status", "reconciliation_status",
    "reconciliation_detail",
]

COLLECTION_COVERAGE_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "status", "item_count", "request_id", "message",
]

ERROR_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "http_status", "service_code", "request_id", "message",
]

REVIEW_FIELDS = [
    "snapshot_sha256", "review_period", "cloud_guard_status",
    "total_alarms", "enabled_alarms", "alarms_without_destination",
    "total_rules", "enabled_rules", "rules_without_delivery",
    "total_topics", "topics_without_active_subscriber",
    "delivery_paths_ok", "delivery_paths_broken", "delivery_paths_unknown",
    "logs_below_retention_baseline",
    "reviewer", "review_date", "approval_status", "evidence_reference", "notes",
]

REVIEW_RESULT_FIELDS = REVIEW_FIELDS + ["validation_status", "validation_message"]

INPUT_SOURCE_FIELDS = ["input_type", "path", "sha256", "row_count"]
INPUT_VALIDATION_FIELDS = ["input_type", "row_key", "validation_status", "validation_message"]


class BaselineUnusable(Exception):
    """The supplied monitoring baseline could not be read or parsed.

    Fails the run before any scanning. An unreadable baseline that degraded to
    an empty mapping would report every discovered alarm as UNAPPROVED and
    every approved alarm as MISSING -- a catastrophic reconciliation caused by
    a typo in a filename. Same rule as CM02-01.
    """


def _text(obj: Any, attr: str) -> str:
    value = getattr(obj, attr, None)
    return "" if value is None else str(value)


def _int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def redact_endpoint(protocol: str, endpoint: str) -> str:
    """The only supported reader of a subscription endpoint.

    For EMAIL the endpoint is a person's address; the domain is kept because an
    auditor needs to distinguish an internal distribution list from someone's
    personal mailbox, and that judgement is the point of the evidence. For any
    HTTP-based protocol the path component IS the shared secret, so only scheme
    and host survive. Nothing else is emitted whole.
    """
    endpoint = str(endpoint or "")
    if not endpoint:
        return ""
    proto = str(protocol or "").upper()
    if proto == "EMAIL":
        local, sep, domain = endpoint.partition("@")
        if not sep or not domain:
            return "<redacted>"
        return f"{local[:1]}***@{domain}"
    if proto in WEBHOOK_PROTOCOLS:
        match = re.match(r"^(https?)://([^/?#]+)", endpoint)
        if match:
            return f"{match.group(1)}://{match.group(2)}/<redacted>"
        return "<redacted>"
    return "<redacted>"


def suppression_window(alarm: Any, now: datetime) -> Tuple[str, str, str]:
    """Return (active, from, until) for the alarm's suppression, if any.

    A suppressed alarm evaluates and notifies nobody for the duration. It is a
    legitimate operational control, but an assessor reading "is_enabled=true"
    would never see it, so it is surfaced explicitly.
    """
    suppression = getattr(alarm, "suppression", None)
    if suppression is None:
        return "NO", "", ""
    start = getattr(suppression, "time_suppress_from", None)
    end = getattr(suppression, "time_suppress_until", None)
    active = "UNKNOWN"
    if isinstance(start, datetime) and isinstance(end, datetime):
        left = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
        right = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
        active = "YES" if left <= now <= right else "NO"
    return active, iso(start), iso(end)


def load_baseline(path: str) -> List[Dict[str, str]]:
    """Read the approved continuous-monitoring baseline, or refuse to run."""
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise BaselineUnusable(f"monitoring baseline has no header row: {path}")
            missing = [f for f in BASELINE_FIELDS if f not in reader.fieldnames]
            if missing:
                raise BaselineUnusable(
                    f"monitoring baseline {path} is missing required columns: "
                    + ", ".join(missing))
            rows = [dict(row) for row in reader]
    except OSError as exc:
        raise BaselineUnusable(f"monitoring baseline could not be read: {exc}") from exc
    if not rows:
        raise BaselineUnusable(
            f"monitoring baseline {path} contains no rows. An empty baseline would "
            "report every discovered control as UNAPPROVED; supply the approved "
            "baseline or omit --monitoring-baseline to run snapshot-only.")
    for index, row in enumerate(rows, start=2):
        if not str(row.get("resource_name", "")).strip():
            raise BaselineUnusable(f"{path} line {index}: resource_name is empty")
        kind = str(row.get("monitoring_type", "")).strip().upper()
        if kind not in {"ALARM", "EVENTS-RULE", "CLOUD-GUARD", "LOG-RETENTION"}:
            raise BaselineUnusable(
                f"{path} line {index}: monitoring_type {kind!r} is not one of "
                "ALARM, EVENTS-RULE, CLOUD-GUARD, LOG-RETENTION")
    return rows


def alarm_row(alarm: Any, detail: Any, target: ScopeItem, region: str,
              now: datetime) -> Dict[str, Any]:
    """One alarm, merged from its summary and its full get_alarm record."""
    source = detail if detail is not None else alarm
    alarm_id = _text(alarm, "id")
    destinations = list(getattr(source, "destinations", None) or [])
    enabled = getattr(source, "is_enabled", None)
    active, sup_from, sup_until = suppression_window(source, now)

    # Findings are earned from explicit negatives only. "destinations is empty"
    # is an explicit negative from the API; "we could not read the alarm" is not
    # and stays out of this column entirely -- it is a coverage row.
    if enabled is False:
        finding = "ALARM-DISABLED"
    elif not destinations:
        finding = "ALARM-NO-DESTINATION"
    elif active == "YES":
        finding = "ALARM-SUPPRESSED"
    elif enabled is None:
        finding = "ALARM-STATE-UNKNOWN"
    else:
        finding = "OK"

    return {
        "alarm_key": stable_hash([alarm_id, region]),
        "alarm_id": alarm_id,
        "display_name": _text(alarm, "display_name"),
        "compartment_id": _text(alarm, "compartment_id"),
        "compartment_name": target.name,
        "metric_compartment_id": _text(source, "metric_compartment_id"),
        "namespace": _text(source, "namespace"),
        "severity": _text(source, "severity"),
        "is_enabled": "" if enabled is None else ("YES" if enabled else "NO"),
        "lifecycle_state": _text(source, "lifecycle_state"),
        "query": _text(source, "query"),
        # resolution, pending_duration, repeat_notification_duration,
        # message_format and body exist only on the full Alarm.
        "resolution": _text(detail, "resolution") if detail is not None else "NOT-READ",
        "pending_duration": _text(detail, "pending_duration") if detail is not None else "NOT-READ",
        "repeat_notification_duration": (
            _text(detail, "repeat_notification_duration") if detail is not None else "NOT-READ"),
        "message_format": _text(detail, "message_format") if detail is not None else "NOT-READ",
        "body_present": (
            ("YES" if _text(detail, "body") else "NO") if detail is not None else "NOT-READ"),
        "destination_count": len(destinations),
        "destination_ocids": " ".join(str(d) for d in destinations),
        "suppression_active": active,
        "suppression_from": sup_from,
        "suppression_until": sup_until,
        "alarm_finding": finding,
        "time_created": iso(getattr(detail, "time_created", None)) if detail is not None else "",
        "region": region,
    }


def rule_row(rule: Any, detail: Any, target: ScopeItem, region: str) -> Dict[str, Any]:
    """One events rule, merged with get_rule -- RuleSummary has no actions."""
    rule_id = _text(rule, "id")
    enabled = getattr(rule, "is_enabled", None)
    actions: List[Any] = []
    if detail is not None:
        container = getattr(detail, "actions", None)
        actions = list(getattr(container, "actions", None) or [])

    kinds: List[str] = []
    targets: List[str] = []
    enabled_actions = 0
    for action in actions:
        kind = _text(action, "action_type")
        kinds.append(kind or "UNKNOWN")
        attr = ACTION_TARGET_ATTR.get(kind.upper())
        if attr:
            value = _text(action, attr)
            if value:
                targets.append(value)
        if getattr(action, "is_enabled", None) is True:
            enabled_actions += 1

    if detail is None:
        finding = "RULE-ACTIONS-NOT-READ"
    elif enabled is False:
        finding = "RULE-DISABLED"
    elif not actions:
        # An enabled rule with no actions matches events and delivers nowhere.
        finding = "RULE-NO-ACTIONS"
    elif enabled_actions == 0:
        finding = "RULE-ACTIONS-ALL-DISABLED"
    else:
        finding = "OK"

    condition = _text(rule, "condition")
    event_types: List[str] = []
    if condition:
        event_types = sorted(set(re.findall(r'"(com\.oraclecloud\.[^"]+)"', condition)))

    return {
        "rule_key": stable_hash([rule_id, region]),
        "rule_id": rule_id,
        "display_name": _text(rule, "display_name"),
        "compartment_id": _text(rule, "compartment_id"),
        "compartment_name": target.name,
        "lifecycle_state": _text(rule, "lifecycle_state"),
        "is_enabled": "" if enabled is None else ("YES" if enabled else "NO"),
        "condition_present": "YES" if condition else "NO",
        "condition_event_types": " ".join(event_types),
        "action_count": len(actions) if detail is not None else "UNKNOWN",
        "enabled_action_count": enabled_actions if detail is not None else "UNKNOWN",
        "action_kinds": " ".join(sorted(set(kinds))),
        "action_target_ocids": " ".join(targets),
        "rule_finding": finding,
        "time_created": iso(getattr(rule, "time_created", None)),
        "region": region,
    }


def log_rows(group: Any, logs: Sequence[Any], target: ScopeItem, region: str,
             min_retention: Optional[int]) -> List[Dict[str, Any]]:
    """Retention evidence per log. Below-baseline is only judged when a
    baseline was supplied; otherwise retention is reported, not adjudicated."""
    group_id = _text(group, "id")
    group_name = _text(group, "display_name")
    rows: List[Dict[str, Any]] = []
    for log in logs:
        retention = _int(getattr(log, "retention_duration", None))
        configuration = getattr(log, "configuration", None)
        source = getattr(configuration, "source", None) if configuration is not None else None
        if retention is None:
            finding = "RETENTION-UNKNOWN"
        elif min_retention is None:
            finding = "NOT-ASSESSED-NO-BASELINE"
        elif retention < min_retention:
            finding = "RETENTION-BELOW-BASELINE"
        else:
            finding = "OK"
        log_id = _text(log, "id")
        rows.append({
            "log_key": stable_hash([log_id, region]),
            "log_group_id": group_id,
            "log_group_name": group_name,
            "log_id": log_id,
            "log_name": _text(log, "display_name"),
            "compartment_id": _text(log, "compartment_id"),
            "compartment_name": target.name,
            "log_type": _text(log, "log_type"),
            "is_enabled": (
                "" if getattr(log, "is_enabled", None) is None
                else ("YES" if getattr(log, "is_enabled") else "NO")),
            "lifecycle_state": _text(log, "lifecycle_state"),
            "retention_duration_days": "" if retention is None else retention,
            "source_service": _text(source, "service") if source is not None else "",
            "source_resource": _text(source, "resource") if source is not None else "",
            "source_category": _text(source, "category") if source is not None else "",
            "retention_finding": finding,
            "region": region,
        })
    return rows


def delivery_paths(
    alarms: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
    topics_by_id: Mapping[str, Mapping[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    """Reconstruct source -> destination -> topic -> active subscriber.

    A destination OCID that is not among the discovered topics is UNKNOWN, not
    broken: the topic may live in a compartment outside the selected scope. An
    out-of-scope destination is a scope limitation to disclose, and reporting it
    as a failure would manufacture a finding out of our own scope choice.
    """
    rows: List[Dict[str, Any]] = []

    def emit(kind: str, sid: str, name: str, enabled: str, compartment: str,
             destination: str, dest_kind: str) -> None:
        topic = topics_by_id.get(destination)
        topic_name = str(topic.get("topic_name", "")) if topic else ""
        topic_state = str(topic.get("lifecycle_state", "")) if topic else ""
        active = topic.get("subscriptions_active", "") if topic else ""
        if enabled == "NO":
            status, detail = "PATH-INACTIVE-SOURCE-DISABLED", "source is disabled"
        elif not destination:
            status, detail = "PATH-BROKEN-NO-DESTINATION", "source has no destination"
        elif dest_kind != "ONS-TOPIC":
            status = "PATH-NOT-ASSESSED-NON-ONS"
            detail = f"destination is a {dest_kind}; delivery is not observable from ONS"
        elif topic is None:
            status = "PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE"
            detail = "destination topic was not discovered in the selected scope"
        elif topic_state.upper() != "ACTIVE":
            status, detail = "PATH-BROKEN-TOPIC-INACTIVE", f"topic lifecycle_state={topic_state}"
        elif active == 0:
            status = "PATH-BROKEN-NO-ACTIVE-SUBSCRIBER"
            detail = "topic has no ACTIVE subscription; a PENDING subscription is never delivered to"
        else:
            status, detail = "PATH-OK", f"{active} active subscriber(s)"
        rows.append({
            "path_key": stable_hash([kind, sid, destination, region]),
            "source_kind": kind, "source_id": sid, "source_name": name,
            "source_enabled": enabled, "compartment_name": compartment,
            "destination_ocid": destination, "destination_kind": dest_kind,
            "topic_name": topic_name, "topic_lifecycle_state": topic_state,
            "active_subscribers": active, "path_status": status,
            "path_detail": detail, "region": region,
        })

    for alarm in alarms:
        destinations = [d for d in str(alarm.get("destination_ocids", "")).split(" ") if d]
        enabled = "NO" if alarm.get("is_enabled") == "NO" else "YES"
        if not destinations:
            emit("ALARM", str(alarm.get("alarm_id", "")), str(alarm.get("display_name", "")),
                 enabled, str(alarm.get("compartment_name", "")), "", "NONE")
            continue
        for destination in destinations:
            kind = "ONS-TOPIC" if ".onstopic." in destination else "OTHER"
            emit("ALARM", str(alarm.get("alarm_id", "")), str(alarm.get("display_name", "")),
                 enabled, str(alarm.get("compartment_name", "")), destination, kind)

    for rule in rules:
        destinations = [d for d in str(rule.get("action_target_ocids", "")).split(" ") if d]
        enabled = "NO" if rule.get("is_enabled") == "NO" else "YES"
        if not destinations:
            emit("EVENTS-RULE", str(rule.get("rule_id", "")), str(rule.get("display_name", "")),
                 enabled, str(rule.get("compartment_name", "")), "", "NONE")
            continue
        for destination in destinations:
            if ".onstopic." in destination:
                kind = "ONS-TOPIC"
            elif ".stream." in destination:
                kind = "STREAM"
            elif ".fnfunc." in destination:
                kind = "FUNCTION"
            else:
                kind = "OTHER"
            emit("EVENTS-RULE", str(rule.get("rule_id", "")), str(rule.get("display_name", "")),
                 enabled, str(rule.get("compartment_name", "")), destination, kind)

    return rows


def collect(
    oci: Any,
    args: argparse.Namespace,
    context: Any,
    targets: Sequence[ScopeItem],
    min_retention: Optional[int],
) -> Tuple[List[Dict[str, Any]], ...]:
    """Read every service. Any failure becomes a coverage row, never a finding."""
    region = args.region
    now = utc_now()
    cloud_guard = build_client(oci, context, "cloud_guard", "CloudGuardClient")
    monitoring = build_client(oci, context, "monitoring", "MonitoringClient")
    ons_cp = build_client(oci, context, "ons", "NotificationControlPlaneClient")
    ons_dp = build_client(oci, context, "ons", "NotificationDataPlaneClient")
    events = build_client(oci, context, "events", "EventsClient")
    logging_mgmt = build_client(oci, context, "logging", "LoggingManagementClient")

    cg_rows: List[Dict[str, Any]] = []
    target_rows: List[Dict[str, Any]] = []
    alarm_rows: List[Dict[str, Any]] = []
    topic_rows: List[Dict[str, Any]] = []
    subscription_rows: List[Dict[str, Any]] = []
    rule_rows: List[Dict[str, Any]] = []
    logging_rows: List[Dict[str, Any]] = []
    coverage: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    def ok(target: ScopeItem, operation: str, count: int, response: Any = None) -> None:
        coverage.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "status": "OK" if count else "EMPTY", "item_count": count,
            "request_id": request_id(response) if response is not None else "",
            "message": "",
        })

    def failed(target: ScopeItem, operation: str, exc: Exception) -> None:
        record = error_record(exc)
        coverage.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "status": record.get("status", "ERROR"), "item_count": "UNKNOWN",
            "request_id": record.get("request_id", ""),
            "message": record.get("message", ""),
        })
        errors.append({
            "region": region, "compartment_name": target.name,
            "compartment_ocid": target.ocid, "operation": operation,
            "http_status": record.get("http_status", ""),
            "service_code": record.get("service_code", ""),
            "request_id": record.get("request_id", ""),
            "message": record.get("message", ""),
        })

    # Cloud Guard configuration is a tenancy-level fact, so it is read once
    # against the tenancy rather than once per compartment.
    tenancy_scope = ScopeItem(context.tenancy_id, "<tenancy>", "TENANCY")
    cg_status = "UNKNOWN"
    cg_reporting = ""
    cg_self_manage = ""
    try:
        response = sdk_get(oci, cloud_guard, "get_configuration", SDK_READ_METHODS,
                           context.tenancy_id)
        data = getattr(response, "data", None)
        cg_status = _text(data, "status") or "UNKNOWN"
        cg_reporting = _text(data, "reporting_region")
        cg_self_manage = _text(data, "self_manage_resources")
        ok(tenancy_scope, "cloud_guard.get_configuration", 1, response)
    except Exception as exc:  # noqa: BLE001 - any failure is a coverage row
        failed(tenancy_scope, "cloud_guard.get_configuration", exc)

    total_targets = 0
    active_targets = 0
    total_recipes = 0

    for target in targets:
        try:
            items, response = sdk_list(oci, cloud_guard, "list_targets", SDK_READ_METHODS,
                                       target.ocid)
            for item in items:
                total_targets += 1
                state = _text(item, "lifecycle_state")
                if state.upper() == "ACTIVE":
                    active_targets += 1
                target_id = _text(item, "id")
                target_rows.append({
                    "target_key": stable_hash([target_id, region]),
                    "target_id": target_id,
                    "display_name": _text(item, "display_name"),
                    "compartment_id": _text(item, "compartment_id"),
                    "compartment_name": target.name,
                    "target_resource_type": _text(item, "target_resource_type"),
                    "target_resource_id": _text(item, "target_resource_id"),
                    "recipe_count": _text(item, "recipe_count"),
                    "lifecycle_state": state,
                    # Oracle's model spells this without the second "c".
                    # lifecycle_details silently returns nothing.
                    "lifecycle_detail": _text(item, "lifecyle_details"),
                    "time_created": iso(getattr(item, "time_created", None)),
                    "target_finding": (
                        "OK" if state.upper() == "ACTIVE" else "TARGET-NOT-ACTIVE"),
                    "region": region,
                })
            ok(target, "cloud_guard.list_targets", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "cloud_guard.list_targets", exc)

        try:
            items, response = sdk_list(oci, cloud_guard, "list_detector_recipes",
                                       SDK_READ_METHODS, target.ocid)
            total_recipes += len(items)
            ok(target, "cloud_guard.list_detector_recipes", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "cloud_guard.list_detector_recipes", exc)

        # Alarms. Each summary is followed by get_alarm because AlarmSummary
        # omits pending_duration, body, resolution and repeat_notification_duration.
        try:
            items, response = sdk_list(oci, monitoring, "list_alarms", SDK_READ_METHODS,
                                       target.ocid)
            for item in items:
                detail = None
                alarm_id = _text(item, "id")
                if alarm_id:
                    try:
                        detail = getattr(
                            sdk_get(oci, monitoring, "get_alarm", SDK_READ_METHODS, alarm_id),
                            "data", None)
                    except Exception as exc:  # noqa: BLE001
                        failed(target, f"monitoring.get_alarm[{alarm_id}]", exc)
                alarm_rows.append(alarm_row(item, detail, target, region, now))
            ok(target, "monitoring.list_alarms", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "monitoring.list_alarms", exc)

        # Subscriptions first, so each topic can be reported with its real
        # ACTIVE subscriber count rather than a total that counts PENDING.
        subs_by_topic: Dict[str, List[Any]] = {}
        try:
            items, response = sdk_list(oci, ons_dp, "list_subscriptions", SDK_READ_METHODS,
                                       target.ocid)
            for item in items:
                topic_id = _text(item, "topic_id")
                subs_by_topic.setdefault(topic_id, []).append(item)
                protocol = _text(item, "protocol")
                state = _text(item, "lifecycle_state")
                subscription_id = _text(item, "id")
                subscription_rows.append({
                    "subscription_key": stable_hash([subscription_id, region]),
                    "subscription_id": subscription_id,
                    "topic_id": topic_id,
                    "topic_name": "",
                    "compartment_id": _text(item, "compartment_id"),
                    "compartment_name": target.name,
                    "protocol": protocol,
                    # Never the raw value: an EMAIL endpoint is personal data
                    # and an HTTPS endpoint's path is the bearer secret.
                    "endpoint_redacted": redact_endpoint(
                        protocol, getattr(item, "endpoint", "")),
                    "lifecycle_state": state,
                    "created_time": iso(getattr(item, "created_time", None)),
                    "subscription_finding": (
                        "OK" if state.upper() == "ACTIVE"
                        else "SUBSCRIPTION-PENDING" if state.upper() == "PENDING"
                        else "SUBSCRIPTION-NOT-ACTIVE"),
                    "region": region,
                })
            ok(target, "ons.list_subscriptions", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "ons.list_subscriptions", exc)

        try:
            items, response = sdk_list(oci, ons_cp, "list_topics", SDK_READ_METHODS, target.ocid)
            for item in items:
                topic_id = _text(item, "topic_id")
                subs = subs_by_topic.get(topic_id, [])
                active = sum(1 for s in subs
                             if _text(s, "lifecycle_state").upper() == "ACTIVE")
                pending = sum(1 for s in subs
                              if _text(s, "lifecycle_state").upper() == "PENDING")
                state = _text(item, "lifecycle_state")
                topic_name = _text(item, "name")
                for row in subscription_rows:
                    if row["topic_id"] == topic_id and not row["topic_name"]:
                        row["topic_name"] = topic_name
                topic_rows.append({
                    "topic_key": stable_hash([topic_id, region]),
                    "topic_id": topic_id,
                    "topic_name": topic_name,
                    "compartment_id": _text(item, "compartment_id"),
                    "compartment_name": target.name,
                    "lifecycle_state": state,
                    "subscriptions_total": len(subs),
                    "subscriptions_active": active,
                    "subscriptions_pending": pending,
                    "protocols": " ".join(sorted({_text(s, "protocol") for s in subs if
                                                  _text(s, "protocol")})),
                    "topic_finding": (
                        "TOPIC-NOT-ACTIVE" if state.upper() != "ACTIVE"
                        else "TOPIC-NO-ACTIVE-SUBSCRIPTION" if active == 0 else "OK"),
                    "time_created": iso(getattr(item, "time_created", None)),
                    "region": region,
                })
            ok(target, "ons.list_topics", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "ons.list_topics", exc)

        # Events rules. get_rule is mandatory: RuleSummary has no actions, so
        # list_rules alone cannot tell an enabled rule that delivers nowhere
        # from one that pages the on-call engineer.
        try:
            items, response = sdk_list(oci, events, "list_rules", SDK_READ_METHODS, target.ocid)
            for item in items:
                detail = None
                rule_id = _text(item, "id")
                if rule_id:
                    try:
                        detail = getattr(
                            sdk_get(oci, events, "get_rule", SDK_READ_METHODS, rule_id),
                            "data", None)
                    except Exception as exc:  # noqa: BLE001
                        failed(target, f"events.get_rule[{rule_id}]", exc)
                rule_rows.append(rule_row(item, detail, target, region))
            ok(target, "events.list_rules", len(items), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "events.list_rules", exc)

        try:
            groups, response = sdk_list(oci, logging_mgmt, "list_log_groups",
                                        SDK_READ_METHODS, target.ocid)
            ok(target, "logging.list_log_groups", len(groups), response)
            for group in groups:
                group_id = _text(group, "id")
                if not group_id:
                    continue
                try:
                    logs, log_response = sdk_list(oci, logging_mgmt, "list_logs",
                                                  SDK_READ_METHODS, group_id)
                    logging_rows.extend(
                        log_rows(group, logs, target, region, min_retention))
                    ok(target, f"logging.list_logs[{group_id}]", len(logs), log_response)
                except Exception as exc:  # noqa: BLE001
                    failed(target, f"logging.list_logs[{group_id}]", exc)
        except Exception as exc:  # noqa: BLE001
            failed(target, "logging.list_log_groups", exc)

    cg_rows.append({
        "scope_kind": "TENANCY", "scope_ocid": context.tenancy_id,
        "scope_name": "<tenancy>",
        "cloud_guard_status": cg_status,
        "reporting_region": cg_reporting,
        "self_manage_resources": cg_self_manage,
        "targets_discovered": total_targets,
        "active_targets": active_targets,
        "detector_recipes": total_recipes,
        "posture_finding": (
            "CLOUD-GUARD-DISABLED" if cg_status.upper() == "DISABLED"
            else "CLOUD-GUARD-STATUS-UNKNOWN" if cg_status == "UNKNOWN"
            else "CLOUD-GUARD-ENABLED-NO-ACTIVE-TARGET" if active_targets == 0
            else "OK"),
        "region": region,
    })

    topics_by_id = {row["topic_id"]: row for row in topic_rows}
    path_rows = delivery_paths(alarm_rows, rule_rows, topics_by_id, region)

    return (cg_rows, target_rows, alarm_rows, topic_rows, subscription_rows,
            rule_rows, logging_rows, path_rows, coverage, errors)


def reconcile_baseline(
    baseline: Sequence[Mapping[str, str]],
    alarms: Sequence[Mapping[str, Any]],
    rules: Sequence[Mapping[str, Any]],
    logs: Sequence[Mapping[str, Any]],
    cloud_guard: Sequence[Mapping[str, Any]],
    paths: Sequence[Mapping[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Compare the approved baseline against what was actually observed."""
    delivery_by_source: Dict[str, List[str]] = {}
    for row in paths:
        delivery_by_source.setdefault(str(row.get("source_name", "")), []).append(
            str(row.get("path_status", "")))

    alarms_by_name = {str(r.get("display_name", "")): r for r in alarms}
    rules_by_name = {str(r.get("display_name", "")): r for r in rules}
    logs_by_name = {str(r.get("log_name", "")): r for r in logs}

    results: List[Dict[str, Any]] = []
    blocking: List[str] = []
    seen_alarms: Set[str] = set()
    seen_rules: Set[str] = set()

    for row in baseline:
        kind = str(row.get("monitoring_type", "")).strip().upper()
        name = str(row.get("resource_name", "")).strip()
        required = str(row.get("required_state", "")).strip().upper() or "ENABLED"
        observed_state = "ABSENT"
        observed_id = ""
        delivery = ""
        status = "MISSING"
        detail = "approved baseline entry was not found in the collected scope"

        if kind == "ALARM" and name in alarms_by_name:
            seen_alarms.add(name)
            record = alarms_by_name[name]
            observed_state = "ENABLED" if record.get("is_enabled") == "YES" else "DISABLED"
            observed_id = str(record.get("alarm_id", ""))
            statuses = delivery_by_source.get(name, [])
            delivery = " ".join(sorted(set(statuses)))
            status, detail = _verdict(required, observed_state, statuses)
        elif kind == "EVENTS-RULE" and name in rules_by_name:
            seen_rules.add(name)
            record = rules_by_name[name]
            observed_state = "ENABLED" if record.get("is_enabled") == "YES" else "DISABLED"
            observed_id = str(record.get("rule_id", ""))
            statuses = delivery_by_source.get(name, [])
            delivery = " ".join(sorted(set(statuses)))
            status, detail = _verdict(required, observed_state, statuses)
        elif kind == "LOG-RETENTION" and name in logs_by_name:
            record = logs_by_name[name]
            observed_state = str(record.get("retention_duration_days", ""))
            observed_id = str(record.get("log_id", ""))
            finding = str(record.get("retention_finding", ""))
            if finding == "RETENTION-BELOW-BASELINE":
                status, detail = "MATCHED-DEGRADED", "retention is below the supplied baseline"
            elif finding in {"OK", "NOT-ASSESSED-NO-BASELINE"}:
                status, detail = "MATCHED-OK", finding
            else:
                status, detail = "MATCHED-UNKNOWN", finding
        elif kind == "CLOUD-GUARD" and cloud_guard:
            record = cloud_guard[0]
            observed_state = str(record.get("cloud_guard_status", ""))
            finding = str(record.get("posture_finding", ""))
            if finding == "OK":
                status, detail = "MATCHED-OK", finding
            elif finding == "CLOUD-GUARD-STATUS-UNKNOWN":
                status, detail = "MATCHED-UNKNOWN", finding
            else:
                status, detail = "MATCHED-DEGRADED", finding

        if status not in {"MATCHED-OK"}:
            blocking.append(f"{kind}:{name}={status}")
        results.append({**row, "observed_state": observed_state, "observed_id": observed_id,
                        "delivery_status": delivery, "reconciliation_status": status,
                        "reconciliation_detail": detail})

    for name, record in alarms_by_name.items():
        if name not in seen_alarms:
            results.append(_unapproved("ALARM", name, str(record.get("alarm_id", "")),
                                       "ENABLED" if record.get("is_enabled") == "YES"
                                       else "DISABLED"))
            blocking.append(f"ALARM:{name}=UNAPPROVED")
    for name, record in rules_by_name.items():
        if name not in seen_rules:
            results.append(_unapproved("EVENTS-RULE", name, str(record.get("rule_id", "")),
                                       "ENABLED" if record.get("is_enabled") == "YES"
                                       else "DISABLED"))
            blocking.append(f"EVENTS-RULE:{name}=UNAPPROVED")
    return results, blocking


def _verdict(required: str, observed_state: str, statuses: Sequence[str]) -> Tuple[str, str]:
    """A control that exists but delivers nothing is not a match."""
    if required == "ENABLED" and observed_state != "ENABLED":
        return "MATCHED-DEGRADED", "approved as ENABLED but observed DISABLED"
    if any(s.startswith("PATH-BROKEN") for s in statuses):
        return "MATCHED-DEGRADED", "control exists but its notification path is broken"
    if any(s == "PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE" for s in statuses):
        return "MATCHED-UNKNOWN", "destination is outside the selected scope"
    if any(s == "PATH-NOT-ASSESSED-NON-ONS" for s in statuses):
        return "MATCHED-UNKNOWN", "delivery target is not an ONS topic"
    if not statuses:
        return "MATCHED-UNKNOWN", "no delivery path was reconstructed"
    return "MATCHED-OK", "control is enabled and its notification path is intact"


def _unapproved(kind: str, name: str, observed_id: str, state: str) -> Dict[str, Any]:
    return {
        "control_id": "", "monitoring_type": kind, "resource_name": name,
        "required_state": "", "owner": "", "approval_reference": "",
        "observed_state": state, "observed_id": observed_id, "delivery_status": "",
        "reconciliation_status": "UNAPPROVED",
        "reconciliation_detail": "present in the tenancy but absent from the approved baseline",
    }


def baseline_template(alarms: Sequence[Mapping[str, Any]],
                      rules: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """A blank register to be approved, never a baseline synthesised from
    current state -- one derived from what is running agrees with any drift by
    construction and can never detect it."""
    rows: List[Dict[str, Any]] = [{
        "control_id": "", "monitoring_type": "CLOUD-GUARD", "resource_name": "<tenancy>",
        "required_state": "ENABLED", "owner": "", "approval_reference": "",
    }]
    for record in alarms:
        rows.append({
            "control_id": "", "monitoring_type": "ALARM",
            "resource_name": str(record.get("display_name", "")),
            "required_state": "", "owner": "", "approval_reference": "",
        })
    for record in rules:
        rows.append({
            "control_id": "", "monitoring_type": "EVENTS-RULE",
            "resource_name": str(record.get("display_name", "")),
            "required_state": "", "owner": "", "approval_reference": "",
        })
    return rows


def expected_review(snapshot_hash: str, cloud_guard: Sequence[Mapping[str, Any]],
                    alarms: Sequence[Mapping[str, Any]], rules: Sequence[Mapping[str, Any]],
                    topics: Sequence[Mapping[str, Any]], logs: Sequence[Mapping[str, Any]],
                    paths: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    return {
        "snapshot_sha256": snapshot_hash,
        "review_period": "",
        "cloud_guard_status": cloud_guard[0].get("cloud_guard_status", "") if cloud_guard else "",
        "total_alarms": len(alarms),
        "enabled_alarms": sum(1 for a in alarms if a.get("is_enabled") == "YES"),
        "alarms_without_destination": sum(
            1 for a in alarms if a.get("alarm_finding") == "ALARM-NO-DESTINATION"),
        "total_rules": len(rules),
        "enabled_rules": sum(1 for r in rules if r.get("is_enabled") == "YES"),
        "rules_without_delivery": sum(
            1 for r in rules
            if r.get("rule_finding") in {"RULE-NO-ACTIONS", "RULE-ACTIONS-ALL-DISABLED"}),
        "total_topics": len(topics),
        "topics_without_active_subscriber": sum(
            1 for t in topics if t.get("topic_finding") == "TOPIC-NO-ACTIVE-SUBSCRIPTION"),
        "delivery_paths_ok": sum(1 for p in paths if p.get("path_status") == "PATH-OK"),
        "delivery_paths_broken": sum(
            1 for p in paths if str(p.get("path_status", "")).startswith("PATH-BROKEN")),
        "delivery_paths_unknown": sum(
            1 for p in paths
            if str(p.get("path_status", "")).startswith(("PATH-UNKNOWN", "PATH-NOT-ASSESSED"))),
        "logs_below_retention_baseline": sum(
            1 for row in logs if row.get("retention_finding") == "RETENTION-BELOW-BASELINE"),
        "reviewer": "", "review_date": "", "approval_status": "",
        "evidence_reference": "", "notes": "",
    }


def required_headers(path: str, fields: Sequence[str], label: str) -> List[Dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{label} has no header row: {path}")
        missing = [f for f in fields if f not in reader.fieldnames]
        if missing:
            raise ValueError(f"{label} {path} is missing columns: " + ", ".join(missing))
        return [dict(row) for row in reader]


def validate_review_row(row: Mapping[str, str],
                        expected: Mapping[str, Any]) -> Tuple[str, str]:
    """The review must be bound to the exact snapshot and its real counts."""
    if str(row.get("snapshot_sha256", "")).strip() != expected["snapshot_sha256"]:
        return "INVALID", "snapshot_sha256 does not match the collected alarm inventory"
    for field in ("total_alarms", "enabled_alarms", "alarms_without_destination",
                  "total_rules", "enabled_rules", "rules_without_delivery",
                  "total_topics", "topics_without_active_subscriber",
                  "delivery_paths_ok", "delivery_paths_broken",
                  "delivery_paths_unknown", "logs_below_retention_baseline"):
        if str(row.get(field, "")).strip() != str(expected[field]):
            return "INVALID", (f"{field} is {row.get(field, '')!r}; "
                               f"collection observed {expected[field]}")
    for field in ("reviewer", "review_date", "review_period", "approval_status"):
        if not str(row.get(field, "")).strip():
            return "INVALID", f"{field} is empty"
    if str(row.get("approval_status", "")).strip().upper() != "APPROVED":
        return "INVALID", "approval_status is not APPROVED"
    return "VALID", ""


def source_selfcheck() -> bool:
    """Prove read-only, and prove no raw subscription endpoint can be emitted."""
    if not SDK_READ_METHODS or any(
        not (name.startswith("list_") or name.startswith("get_"))
        for name in SDK_READ_METHODS
    ):
        print("READ-ONLY SDK SELF-CHECK: FAILED — invalid method in allowlist", file=sys.stderr)
        return False
    # get_unsubscription and get_confirm_subscription are named as reads, issue
    # HTTP GET, and change state: one deletes a subscription and one activates a
    # pending one. This collector calls list_subscriptions and is one
    # autocomplete away from either.
    forbidden_ons = {"get_unsubscription", "get_confirm_subscription"}
    if SDK_READ_METHODS & forbidden_ons:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — read-named state-changing ONS "
              f"operation in allowlist: {sorted(SDK_READ_METHODS & forbidden_ons)}",
              file=sys.stderr)
        return False
    try:
        tree = ast.parse(SCRIPT_PATH.read_text(encoding="utf-8"))
    except (OSError, SyntaxError) as exc:
        print(f"READ-ONLY SDK SELF-CHECK: FAILED — {exc}", file=sys.stderr)
        return False

    problems: List[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id not in {"sdk_list", "sdk_get"} or len(node.args) < 3:
            continue
        method_node = node.args[2]
        if not isinstance(method_node, ast.Constant) or not isinstance(method_node.value, str):
            problems.append(f"line {node.lineno}: SDK method bypasses a literal guarded name")
            continue
        method = method_node.value
        prefix = "list_" if node.func.id == "sdk_list" else "get_"
        if method not in SDK_READ_METHODS or not method.startswith(prefix):
            problems.append(f"line {node.lineno}: blocked method {method}")

    forbidden = ("create_", "update_", "delete_", "change_", "move_", "upload_",
                 "import_", "export_", "publish_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")
            if node.func.attr in forbidden_ons:
                problems.append(f"line {node.lineno}: read-named mutation {node.func.attr}")

    # A subscription endpoint is personal data or a bearer secret. redact_endpoint
    # is the only place allowed to touch one; anywhere else is a leak into a
    # public repository's evidence file.
    redactor = next((n for n in ast.walk(tree)
                     if isinstance(n, ast.FunctionDef) and n.name == "redact_endpoint"), None)
    allowed_lines = set()
    if redactor is not None:
        allowed_lines = {n.lineno for n in ast.walk(redactor) if hasattr(n, "lineno")}
    # The one legitimate read hands the value straight to redact_endpoint as an
    # argument, so it is permitted; any other route to the attribute is not.
    handed_to_redactor = {
        id(arg)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "redact_endpoint"
        for arg in node.args
    }
    for node in ast.walk(tree):
        if getattr(node, "lineno", None) in allowed_lines:
            continue
        if isinstance(node, ast.Attribute) and node.attr == "endpoint":
            problems.append(
                f"line {node.lineno}: raw subscription endpoint read outside redact_endpoint")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "getattr" and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "endpoint"
                and id(node) not in handed_to_redactor):
            problems.append(
                f"line {node.lineno}: subscription endpoint read is not handed to redact_endpoint")

    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (ca07-01-continuous-monitoring)")
    print("Oracle SDK cloud methods are restricted to Cloud Guard, Monitoring, "
          "ONS, Events and Logging list/get reads plus scope discovery.")
    print("get_unsubscription and get_confirm_subscription are blocked by name: both are "
          "named as reads, issue HTTP GET, and change state.")
    print("Subscription endpoints are emitted only through redact_endpoint.")
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI continuous monitoring (CA-7) evidence collector."
    )
    p.add_argument("-r", "--region", required=False)
    p.add_argument("-o", "--output-dir", default=".")
    p.add_argument("-p", "--profile", default="DEFAULT")
    p.add_argument("--config-file", default="~/.oci/config")
    p.add_argument("--auth", choices=("config", "instance-principal", "resource-principal"),
                   default="config")
    p.add_argument("-c", "--compartment-id", action="append", default=[])
    p.add_argument("-n", "--compartment-names", default="")
    p.add_argument("--tenancy-scope", action="store_true")
    p.add_argument("--monitoring-baseline",
                   help="CSV of the approved continuous-monitoring baseline. Without "
                        "it the run is SNAPSHOT-ONLY-NO-BASELINE: drift cannot be "
                        "detected against a baseline derived from current state.")
    p.add_argument("--min-log-retention-days", type=int, default=None,
                   help="approved minimum log retention. Without it retention is "
                        "reported but not adjudicated.")
    p.add_argument("--monthly-review")
    p.add_argument("--non-interactive", action="store_true")
    p.add_argument("--confirm-scope-ocid", action="append", default=[])
    p.add_argument("--approve-scan", default="")
    p.add_argument("--selfcheck", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def resolve_targets(args: argparse.Namespace,
                    catalog: Sequence[ScopeItem]) -> Tuple[ScopeItem, List[ScopeItem]]:
    by_id = {item.ocid: item for item in catalog}
    explicit = sum(bool(v) for v in
                   (args.compartment_id, args.compartment_names, args.tenancy_scope))
    if explicit > 1:
        raise ValueError("-c, -n and --tenancy-scope are mutually exclusive")

    if not explicit:
        if args.non_interactive:
            raise ValueError("automation requires -c, -n or --tenancy-scope")
        print("\nDiscovered tenancy and active compartments:")
        for item in catalog:
            print(f"  {item.kind:<11} {item.name}")
            print(f"              {item.ocid}")
        print("\nSelecting the tenancy scans root plus every active discovered compartment.")
        selected = by_id.get(
            input("Enter the exact tenancy or compartment OCID to select: ").strip())
        if selected is None:
            raise ValueError("entered OCID was not discovered")
        if input("Re-enter the exact same OCID: ").strip() != selected.ocid:
            raise ValueError("second scope confirmation did not match")
        return selected, list(catalog) if selected.kind == "TENANCY" else [selected]

    if args.tenancy_scope:
        selected, targets = catalog[0], list(catalog)
    elif args.compartment_id:
        targets = []
        for ocid in args.compartment_id:
            item = by_id.get(ocid)
            if item is None or item.kind != "COMPARTMENT":
                raise ValueError(f"compartment OCID was not discovered: {ocid}")
            if item not in targets:
                targets.append(item)
        selected = ScopeItem(
            "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
            "explicit compartments" if len(targets) > 1 else targets[0].name,
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT")
    else:
        wanted = {i.strip().lower() for i in args.compartment_names.split(",") if i.strip()}
        targets = [i for i in catalog if i.kind == "COMPARTMENT" and i.name.lower() in wanted]
        missing = sorted(wanted - {i.name.lower() for i in targets})
        if missing:
            raise ValueError("compartment names were not discovered: " + ", ".join(missing))
        if not targets:
            raise ValueError("no target compartments resolved")
        selected = ScopeItem(
            "MULTIPLE" if len(targets) > 1 else targets[0].ocid,
            args.compartment_names,
            "MULTI-COMPARTMENT" if len(targets) > 1 else "COMPARTMENT")

    if not args.non_interactive:
        for item in targets:
            first = input(f"Enter the exact OCID for {item.name}: ").strip()
            second = input("Re-enter the exact same OCID: ").strip()
            if first != item.ocid or second != item.ocid:
                raise ValueError(f"scope confirmation failed for {item.name}")
    return selected, targets


def build_plan(args: argparse.Namespace, context: Any, selected: ScopeItem,
               targets: Sequence[ScopeItem], outputs: Mapping[str, str]) -> str:
    retention_floor = (
        f"{args.min_log_retention_days} days" if args.min_log_retention_days is not None
        else "<none — retention reported, not adjudicated>")
    lines = [
        "======================================================================",
        " CA-7 CONTINUOUS MONITORING PRE-SCAN SAFETY SUMMARY",
        "======================================================================",
        f"Collector       : {COLLECTOR}",
        f"Controls        : {CONTROLS}",
        f"Region          : {args.region}",
        f"Authentication  : {context.auth_label}",
        f"Profile         : {context.profile if args.auth == 'config' else '<not applicable>'}",
        f"Scope type      : {selected.kind}",
        f"Scope name      : {selected.name}",
        f"Selected OCID   : {selected.ocid}",
        f"Compartments    : {len(targets)}",
        "Cloud operations: Oracle OCI Python SDK list/get methods only",
        "Mutation boundary: no create/update/delete/change/move method is permitted",
        "ONS boundary    : get_unsubscription and get_confirm_subscription are named as "
        "reads and issue HTTP GET, but change state. Both are blocked by name.",
        "Sensitive data  : OCIDs, alarm and rule names, log group names, topic names",
        "Endpoint boundary: subscription endpoints are personal data (EMAIL) or bearer "
        "secrets (HTTPS webhook paths). Only a redacted form is written.",
        f"Baseline        : {args.monitoring_baseline or '<none — SNAPSHOT-ONLY-NO-BASELINE>'}",
        f"Retention floor : {retention_floor}",
        "",
        "Target compartments:",
    ]
    for item in targets:
        lines.extend([f"  - {item.name}", f"    {item.ocid}"])
    lines.extend(["", "Read-only SDK operations:"])
    for method in sorted(SDK_READ_METHODS):
        lines.append("  - " + method)
    lines.extend(["", "Output files:"])
    for path in outputs.values():
        lines.append("  - " + path)
    lines.append("======================================================================")
    return "\n".join(lines) + "\n"


def validate_final_approval(args: argparse.Namespace, targets: Sequence[ScopeItem]) -> None:
    if args.non_interactive:
        expected = sorted(item.ocid for item in targets)
        supplied = sorted(set(args.confirm_scope_ocid))
        if supplied != expected:
            raise ValueError("automation confirmation OCIDs do not exactly match resolved targets")
        if args.approve_scan != "YES":
            raise ValueError("automation requires exact --approve-scan YES")
        print("Approval mode   : strict automation confirmation accepted")
        return
    if input("Type exact uppercase YES to start the read-only SDK scan: ").strip() != "YES":
        raise ValueError("operator did not enter exact uppercase YES")


def main(argv: Optional[Sequence[str]] = None, oci_module: Any = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.selfcheck:
        return 0 if source_selfcheck() else 1
    if not args.region or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
        for char in args.region
    ):
        print("ERROR: one explicit OCI region is required", file=sys.stderr)
        return 1
    if args.min_log_retention_days is not None and args.min_log_retention_days <= 0:
        print("ERROR: --min-log-retention-days must be a positive number of days",
              file=sys.stderr)
        return 1

    # Loaded before any scanning. An unusable baseline that degraded to an empty
    # mapping would report every alarm UNAPPROVED and every approved control
    # MISSING -- a fabricated catastrophe caused by a filename typo.
    baseline: Optional[List[Dict[str, str]]] = None
    if args.monitoring_baseline:
        try:
            baseline = load_baseline(args.monitoring_baseline)
        except BaselineUnusable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    now = utc_now()
    try:
        review_rows = (required_headers(args.monthly_review, REVIEW_FIELDS, "monthly review")
                       if args.monthly_review else [])
        if args.monthly_review and len(review_rows) != 1:
            raise ValueError("monthly review must contain exactly one data row")
        oci = oci_module or load_oci()
        context = build_auth_context(oci, args)
        identity = build_client(oci, context, "identity", "IdentityClient")
        catalog = discover_scope(oci, identity, context.tenancy_id, SDK_READ_METHODS)
        selected, targets = resolve_targets(args, catalog)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1

    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    output_dir = str(Path(args.output_dir))
    prefix = f"ca07-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "cloud_guard": f"{output_dir}/{prefix}_cloud_guard_posture.csv",
        "targets": f"{output_dir}/{prefix}_cloud_guard_targets.csv",
        "alarms": f"{output_dir}/{prefix}_alarm_inventory.csv",
        "topics": f"{output_dir}/{prefix}_notification_topics.csv",
        "subscriptions": f"{output_dir}/{prefix}_notification_subscriptions.csv",
        "rules": f"{output_dir}/{prefix}_events_rules.csv",
        "logs": f"{output_dir}/{prefix}_log_retention.csv",
        "paths": f"{output_dir}/{prefix}_delivery_paths.csv",
        "coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv",
        "baseline_template": f"{output_dir}/{prefix}_monitoring_baseline_template.csv",
        "reconciliation": f"{output_dir}/{prefix}_baseline_reconciliation.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "review_template": f"{output_dir}/{prefix}_monthly_review_template.csv",
        "review_validation": f"{output_dir}/{prefix}_monthly_review_validation.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    plan = build_plan(args, context, selected, targets, outputs)
    print(plan, end="")
    try:
        validate_final_approval(args, targets)
    except ValueError as exc:
        print(f"SCAN NOT STARTED: {exc}. Nothing was scanned.", file=sys.stderr)
        return 1
    collisions = [p for p in outputs.values() if Path(p).exists()]
    if collisions:
        print("SCAN NOT STARTED: output collision; refusing to overwrite evidence:",
              file=sys.stderr)
        for path in collisions:
            print("  " + path, file=sys.stderr)
        return 1

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    write_private_text(outputs["plan"], plan + "SCAN APPROVED\n")

    (cg_rows, target_rows, alarm_rows, topic_rows, subscription_rows,
     rule_rows, logging_rows, path_rows, coverage, errors) = collect(
        oci, args, context, targets, args.min_log_retention_days)

    write_csv(outputs["cloud_guard"], CLOUD_GUARD_FIELDS, cg_rows)
    write_csv(outputs["targets"], TARGET_FIELDS, target_rows)
    write_csv(outputs["alarms"], ALARM_FIELDS, alarm_rows)
    write_csv(outputs["topics"], TOPIC_FIELDS, topic_rows)
    write_csv(outputs["subscriptions"], SUBSCRIPTION_FIELDS, subscription_rows)
    write_csv(outputs["rules"], RULE_FIELDS, rule_rows)
    write_csv(outputs["logs"], LOG_FIELDS, logging_rows)
    write_csv(outputs["paths"], PATH_FIELDS, path_rows)
    write_csv(outputs["coverage"], COLLECTION_COVERAGE_FIELDS, coverage)
    write_csv(outputs["errors"], ERROR_FIELDS, errors)
    write_csv(outputs["baseline_template"], BASELINE_FIELDS,
              baseline_template(alarm_rows, rule_rows))

    reconciliation: List[Dict[str, Any]] = []
    blocking: List[str] = []
    if baseline is not None:
        reconciliation, blocking = reconcile_baseline(
            baseline, alarm_rows, rule_rows, logging_rows, cg_rows, path_rows)
    write_csv(outputs["reconciliation"], RECONCILIATION_FIELDS, reconciliation)

    input_sources: List[Dict[str, Any]] = []
    for label, path, count in (
        ("MONITORING-BASELINE", args.monitoring_baseline, len(baseline or [])),
        ("MONTHLY-REVIEW", args.monthly_review, len(review_rows)),
    ):
        if path:
            input_sources.append({"input_type": label, "path": path,
                                  "sha256": sha256_file(path), "row_count": count})
    write_csv(outputs["inputs"], INPUT_SOURCE_FIELDS, input_sources)

    snapshot_hash = sha256_file(outputs["alarms"])
    expected = expected_review(snapshot_hash, cg_rows, alarm_rows, rule_rows,
                               topic_rows, logging_rows, path_rows)
    write_csv(outputs["review_template"], REVIEW_FIELDS, [expected])
    review_results: List[Dict[str, Any]] = []
    review_error = ""
    if review_rows:
        status, message = validate_review_row(review_rows[0], expected)
        review_results.append({**review_rows[0], "validation_status": status,
                               "validation_message": message})
        if status != "VALID":
            review_error = message
    write_csv(outputs["review_validation"], REVIEW_RESULT_FIELDS, review_results)

    collection_complete = not errors and all(
        row.get("status") in {"OK", "EMPTY"} for row in coverage)
    broken = sum(1 for p in path_rows if str(p.get("path_status", "")).startswith("PATH-BROKEN"))
    unknown = sum(1 for p in path_rows
                  if str(p.get("path_status", "")).startswith(("PATH-UNKNOWN", "PATH-NOT-ASSESSED")))

    summary_lines = [
        "CA07-01 Continuous Monitoring (CA-7) Summary",
        "============================================",
        f"Region                     : {args.region}",
        f"Selected scope             : {selected.kind} / {selected.name}",
        f"Target compartments        : {len(targets)}",
        f"Collected                  : {iso(now)}",
        f"OCI SDK version            : {getattr(oci, '__version__', '<unknown>')}",
        f"Cloud Guard status         : {cg_rows[0]['cloud_guard_status'] if cg_rows else 'UNKNOWN'}",
        f"Cloud Guard targets        : {cg_rows[0]['targets_discovered'] if cg_rows else 0}",
        f"Alarms                     : {len(alarm_rows)}",
        f"  enabled                  : {sum(1 for a in alarm_rows if a['is_enabled'] == 'YES')}",
        f"  no destination           : {sum(1 for a in alarm_rows if a['alarm_finding'] == 'ALARM-NO-DESTINATION')}",
        f"Events rules               : {len(rule_rows)}",
        f"  no delivery              : {sum(1 for r in rule_rows if r['rule_finding'] in {'RULE-NO-ACTIONS', 'RULE-ACTIONS-ALL-DISABLED'})}",
        f"Notification topics        : {len(topic_rows)}",
        f"  no active subscriber     : {sum(1 for t in topic_rows if t['topic_finding'] == 'TOPIC-NO-ACTIVE-SUBSCRIPTION')}",
        f"Subscriptions              : {len(subscription_rows)}",
        f"  pending (never confirmed): {sum(1 for s in subscription_rows if s['subscription_finding'] == 'SUBSCRIPTION-PENDING')}",
        f"Logs                       : {len(logging_rows)}",
        f"  below retention baseline : {sum(1 for row in logging_rows if row['retention_finding'] == 'RETENTION-BELOW-BASELINE')}",
        f"Delivery paths             : {len(path_rows)}",
        f"  intact                   : {sum(1 for p in path_rows if p['path_status'] == 'PATH-OK')}",
        f"  broken                   : {broken}",
        f"  unknown / not assessed   : {unknown}",
        f"Collection errors          : {len(errors)}",
        f"Alarm snapshot SHA         : {snapshot_hash}",
        f"COLLECTION STATUS          : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"BASELINE MODE              : {'RECONCILIATION' if baseline is not None else 'SNAPSHOT-ONLY-NO-BASELINE'}",
        "",
        "An alarm or rule that exists is not evidence that anyone is notified.",
        "A broken delivery path is a CA-7 finding even when the alarm is enabled.",
    ]
    write_private_text(outputs["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")

    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {outputs['coverage']}", file=sys.stderr)
        return 3
    if baseline is not None and blocking:
        print(f"BASELINE NOT RECONCILED — review {outputs['reconciliation']}", file=sys.stderr)
        return 3
    if review_rows and review_error:
        print(f"MONTHLY REVIEW NOT VALIDATED — {review_error}", file=sys.stderr)
        return 3
    print("CA07-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
