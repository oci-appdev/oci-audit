#!/usr/bin/env python3
"""CP-4 contingency plan testing evidence using Oracle's OCI Python SDK.

PYTHON FILES USED: none beyond lib/oci_audit_sdk.py, which this imports.

What this collector is for
--------------------------
CP-2 asks whether a plan exists; CP-4 asks whether it has been exercised. The
technical record of an exercise is a Full Stack DR plan execution, and this
collector reads them, classifies what each one actually proves, and reconciles
them against the test register that carries the parts OCI cannot hold: who took
part, what the test report concluded, what corrective actions came out of it,
and who approved the result.

Three distinctions the execution type makes, which decide what an execution is
worth as CP-4 evidence
----------------------------------------------------------------------------
``plan_execution_type`` has eight values in oci==2.185.1, and collapsing them
loses the whole point:

* ``START_DRILL`` / ``STOP_DRILL`` -- a drill exercises the plan without moving
  production. This is what a scheduled contingency test looks like and is the
  strongest evidence CP-4 can get from the API.
* ``SWITCHOVER`` / ``FAILOVER`` -- a real move. It proves the plan works, but it
  is an event, not a test, and an assessor should see the difference.
* ``SWITCHOVER_PRECHECK`` / ``FAILOVER_PRECHECK`` / ``START_DRILL_PRECHECK`` /
  ``STOP_DRILL_PRECHECK`` -- a **precheck validates that a plan could run. It
  does not run it.** Counting a precheck as a test is the single easiest way to
  overstate CP-4 compliance, because prechecks are cheap, frequent and succeed
  routinely. A plan whose only executions are prechecks has never been tested.

Model traps (verified against oci==2.185.1)
-------------------------------------------
* ``DrPlanExecutionSummary`` has no ``is_automatic``, no ``step_status_counts``
  and no ``group_executions``. Only the full ``DrPlanExecution`` from
  ``get_dr_plan_execution`` carries them -- and ``is_automatic`` is what
  separates a deliberate exercise from one the service started by itself, which
  is not a contingency *test*.
* ``list_dr_plan_executions`` takes a ``dr_protection_group_id``, not a plan id
  and not a compartment id, so executions are reached through the protection
  group and then attributed to plans by ``plan_id``.
* The detail field is ``life_cycle_details``; the state field beside it is
  ``lifecycle_state``. Reading ``lifecycle_details`` returns nothing.
"""

from __future__ import annotations

import argparse
import ast
import csv
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

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
COLLECTOR = "CP04-01"
CONTROLS = "CP-4 / CP-2 / CP-10"

SDK_READ_METHODS: Set[str] = {
    "get_compartment",
    "list_compartments",
    "list_dr_protection_groups",
    "list_dr_plans",
    "list_dr_plan_executions",
    # Required, not enrichment: the summary has no is_automatic, which is what
    # separates a deliberate test from a service-initiated execution.
    "get_dr_plan_execution",
}

DRILL_TYPES: Set[str] = {"START_DRILL", "STOP_DRILL"}
REAL_MOVE_TYPES: Set[str] = {"SWITCHOVER", "FAILOVER"}
PRECHECK_SUFFIX = "_PRECHECK"

SUCCESS_STATES: Set[str] = {"SUCCEEDED"}
FAILURE_STATES: Set[str] = {"FAILED", "CANCELED"}

EXECUTION_FIELDS = [
    "execution_key", "execution_id", "display_name", "plan_id", "plan_name",
    "group_id", "group_name", "compartment_name", "execution_type",
    "exercise_class", "lifecycle_state", "outcome", "is_automatic",
    "time_started", "time_ended", "duration_seconds", "age_days",
    "steps_total", "steps_failed", "lifecycle_detail", "execution_finding", "region",
]

PLAN_TEST_FIELDS = [
    "plan_key", "plan_id", "plan_name", "group_id", "group_name",
    "compartment_name", "plan_type", "executions_total", "drills_total",
    "prechecks_total", "real_moves_total", "successful_drills",
    "last_exercise_type", "last_exercise_time", "last_exercise_outcome",
    "days_since_last_exercise", "test_status", "test_detail", "region",
]

TEST_REGISTER_FIELDS = [
    "test_id", "plan_id", "execution_ocid", "test_date", "test_type",
    "participants", "test_report_reference", "findings_count",
    "corrective_actions_reference", "approver", "approval_status",
]

REGISTER_VALIDATION_FIELDS = TEST_REGISTER_FIELDS + [
    "observed_execution_type", "observed_outcome", "validation_status",
    "validation_message",
]

COLLECTION_COVERAGE_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "status", "item_count", "request_id", "message",
]

ERROR_FIELDS = [
    "region", "compartment_name", "compartment_ocid", "operation",
    "http_status", "service_code", "request_id", "message",
]


class RegisterUnusable(Exception):
    """The supplied test register could not be read or parsed."""


def _text(obj: Any, attr: str) -> str:
    value = getattr(obj, attr, None)
    return "" if value is None else str(value)


def exercise_class(execution_type: str) -> str:
    """What an execution of this type actually proves.

    A precheck is classified first, because START_DRILL_PRECHECK contains
    START_DRILL and a substring test would call it a drill.
    """
    kind = str(execution_type or "").upper()
    if not kind:
        return "UNKNOWN"
    if kind.endswith(PRECHECK_SUFFIX):
        return "PRECHECK"
    if kind in DRILL_TYPES:
        return "DRILL"
    if kind in REAL_MOVE_TYPES:
        return "REAL-MOVE"
    return "UNKNOWN"


def _age_days(when: Any, now: datetime) -> Optional[int]:
    if not isinstance(when, datetime):
        return None
    moment = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
    return int((now - moment).total_seconds() // 86400)


def load_register(path: str) -> List[Dict[str, str]]:
    try:
        with open(path, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise RegisterUnusable(f"test register has no header row: {path}")
            missing = [f for f in TEST_REGISTER_FIELDS if f not in reader.fieldnames]
            if missing:
                raise RegisterUnusable(
                    f"test register {path} is missing required columns: "
                    + ", ".join(missing))
            rows = [dict(row) for row in reader]
    except OSError as exc:
        raise RegisterUnusable(f"test register could not be read: {exc}") from exc
    if not rows:
        raise RegisterUnusable(
            f"test register {path} contains no rows. Omit --test-register to run "
            "snapshot-only rather than supplying an empty one.")
    return rows


def execution_row(execution: Any, detail: Any, plan_names: Mapping[str, str],
                  group_id: str, group_name: str, target: ScopeItem,
                  region: str, now: datetime) -> Dict[str, Any]:
    execution_id = _text(execution, "id")
    kind = _text(execution, "plan_execution_type")
    state = _text(execution, "lifecycle_state").upper()
    started = getattr(execution, "time_started", None)
    klass = exercise_class(kind)

    if state in SUCCESS_STATES:
        outcome = "SUCCEEDED"
    elif state in FAILURE_STATES:
        outcome = state
    elif state:
        outcome = "IN-PROGRESS-OR-OTHER"
    else:
        outcome = "UNKNOWN"

    counts = getattr(detail, "step_status_counts", None) if detail is not None else None
    steps_total = ""
    steps_failed = ""
    if counts is not None:
        try:
            as_dict = dict(counts) if isinstance(counts, Mapping) else {
                _text(c, "type"): getattr(c, "count", "") for c in counts}
            steps_total = sum(int(v) for v in as_dict.values() if str(v).isdigit())
            steps_failed = as_dict.get("FAILED", as_dict.get("failed", ""))
        except (TypeError, ValueError):
            steps_total = ""

    if detail is None:
        automatic = "NOT-READ"
    else:
        flag = getattr(detail, "is_automatic", None)
        automatic = "" if flag is None else ("YES" if flag else "NO")

    if klass == "PRECHECK":
        # The distinction that matters most: a precheck validates that the plan
        # could run. It does not run it.
        finding = "PRECHECK-NOT-AN-EXERCISE"
    elif outcome in FAILURE_STATES:
        finding = "EXERCISE-FAILED"
    elif automatic == "YES":
        finding = "AUTOMATIC-EXECUTION-NOT-A-SCHEDULED-TEST"
    elif klass == "REAL-MOVE":
        finding = "REAL-MOVE-NOT-A-SCHEDULED-TEST"
    elif klass == "DRILL" and outcome == "SUCCEEDED":
        finding = "OK"
    else:
        finding = "EXERCISE-OUTCOME-UNCONFIRMED"

    age = _age_days(started, now)
    return {
        "execution_key": stable_hash([execution_id, region]),
        "execution_id": execution_id,
        "display_name": _text(execution, "display_name"),
        "plan_id": _text(execution, "plan_id"),
        "plan_name": plan_names.get(_text(execution, "plan_id"), ""),
        "group_id": group_id,
        "group_name": group_name,
        "compartment_name": target.name,
        "execution_type": kind,
        "exercise_class": klass,
        "lifecycle_state": state,
        "outcome": outcome,
        "is_automatic": automatic,
        "time_started": iso(started),
        "time_ended": iso(getattr(execution, "time_ended", None)),
        "duration_seconds": _text(execution, "execution_duration_in_sec"),
        "age_days": "" if age is None else age,
        "steps_total": steps_total,
        "steps_failed": steps_failed,
        "lifecycle_detail": _text(execution, "life_cycle_details"),
        "execution_finding": finding,
        "region": region,
    }


def plan_test_row(plan: Any, executions: Sequence[Mapping[str, Any]],
                  group_id: str, group_name: str, target: ScopeItem,
                  region: str, window_days: int) -> Dict[str, Any]:
    """Whether this plan has actually been tested, and how recently."""
    plan_id = _text(plan, "id")
    mine = [e for e in executions if e.get("plan_id") == plan_id]
    drills = [e for e in mine if e.get("exercise_class") == "DRILL"]
    prechecks = [e for e in mine if e.get("exercise_class") == "PRECHECK"]
    real_moves = [e for e in mine if e.get("exercise_class") == "REAL-MOVE"]
    good_drills = [e for e in drills if e.get("outcome") == "SUCCEEDED"]

    # Only a real exercise counts toward recency; a precheck never does.
    exercises = [e for e in mine if e.get("exercise_class") in {"DRILL", "REAL-MOVE"}]
    dated = [e for e in exercises if str(e.get("age_days", "")) != ""]
    latest = min(dated, key=lambda e: int(e["age_days"])) if dated else None

    if not mine:
        status, detail = "PLAN-NEVER-EXECUTED", "no execution of any kind was recorded"
    elif not exercises:
        status = "PLAN-PRECHECK-ONLY"
        detail = (f"{len(prechecks)} precheck(s) and no exercise; a precheck validates "
                  "that the plan could run and does not run it")
    elif not good_drills and real_moves:
        status = "PLAN-EXERCISED-BY-REAL-MOVE-ONLY"
        detail = "the plan has run as a real switchover or failover but never as a drill"
    elif not good_drills:
        status = "PLAN-NO-SUCCESSFUL-DRILL"
        detail = f"{len(drills)} drill(s) recorded, none of which succeeded"
    elif latest is not None and int(latest["age_days"]) > window_days:
        status = "PLAN-NO-EXERCISE-IN-WINDOW"
        detail = (f"most recent exercise was {latest['age_days']} days ago, "
                  f"outside the {window_days}-day window")
    else:
        status, detail = "OK", "a successful drill was recorded within the window"

    return {
        "plan_key": stable_hash([plan_id, region]),
        "plan_id": plan_id,
        "plan_name": _text(plan, "display_name"),
        "group_id": group_id,
        "group_name": group_name,
        "compartment_name": target.name,
        "plan_type": _text(plan, "type"),
        "executions_total": len(mine),
        "drills_total": len(drills),
        "prechecks_total": len(prechecks),
        "real_moves_total": len(real_moves),
        "successful_drills": len(good_drills),
        "last_exercise_type": latest["execution_type"] if latest else "",
        "last_exercise_time": latest["time_started"] if latest else "",
        "last_exercise_outcome": latest["outcome"] if latest else "",
        "days_since_last_exercise": latest["age_days"] if latest else "",
        "test_status": status,
        "test_detail": detail,
        "region": region,
    }


def validate_register(register: Sequence[Mapping[str, str]],
                      executions: Sequence[Mapping[str, Any]]
                      ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Every claimed test must point at an execution that actually happened."""
    by_id = {str(e.get("execution_id", "")): e for e in executions}
    results: List[Dict[str, Any]] = []
    blocking: List[str] = []
    for row in register:
        ocid = str(row.get("execution_ocid", "")).strip()
        observed = by_id.get(ocid)
        status = "VALID"
        message = ""

        if not ocid:
            status = "INVALID"
            message = "execution_ocid is empty; the claimed test cannot be corroborated"
        elif observed is None:
            status = "INVALID"
            message = ("execution_ocid does not match any DR plan execution in the "
                       "collected scope")
        elif observed.get("exercise_class") == "PRECHECK":
            status = "INVALID"
            message = ("the referenced execution is a precheck, which validates the "
                       "plan without running it, and is not a contingency test")
        elif observed.get("outcome") != "SUCCEEDED":
            status = "INVALID"
            message = f"the referenced execution outcome was {observed.get('outcome')}"

        if status == "VALID":
            missing = [field for field in
                       ("test_date", "participants", "test_report_reference",
                        "corrective_actions_reference", "approver", "approval_status")
                       if not str(row.get(field, "")).strip()]
            if missing:
                status = "INVALID"
                message = "register does not state " + ", ".join(missing)
            elif str(row.get("approval_status", "")).strip().upper() != "APPROVED":
                status = "INVALID"
                message = "approval_status is not APPROVED"

        if status != "VALID":
            blocking.append(f"{row.get('test_id', '')}={message}")
        results.append({
            **row,
            "observed_execution_type": observed.get("execution_type", "") if observed else "",
            "observed_outcome": observed.get("outcome", "") if observed else "",
            "validation_status": status,
            "validation_message": message,
        })
    return results, blocking


def collect(oci: Any, args: argparse.Namespace, context: Any,
            targets: Sequence[ScopeItem]) -> Tuple[List[Dict[str, Any]], ...]:
    region = args.region
    now = utc_now()
    dr = build_client(oci, context, "disaster_recovery", "DisasterRecoveryClient")

    executions: List[Dict[str, Any]] = []
    plan_tests: List[Dict[str, Any]] = []
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

    for target in targets:
        try:
            groups, response = sdk_list(oci, dr, "list_dr_protection_groups",
                                        SDK_READ_METHODS, target.ocid)
            ok(target, "disaster_recovery.list_dr_protection_groups", len(groups), response)
        except Exception as exc:  # noqa: BLE001
            failed(target, "disaster_recovery.list_dr_protection_groups", exc)
            continue

        for group in groups:
            group_id = _text(group, "id")
            group_name = _text(group, "display_name")
            if not group_id:
                continue

            plans: List[Any] = []
            try:
                plans, plan_response = sdk_list(oci, dr, "list_dr_plans",
                                                SDK_READ_METHODS, group_id)
                ok(target, f"disaster_recovery.list_dr_plans[{group_id}]",
                   len(plans), plan_response)
            except Exception as exc:  # noqa: BLE001
                failed(target, f"disaster_recovery.list_dr_plans[{group_id}]", exc)

            plan_names = {_text(p, "id"): _text(p, "display_name") for p in plans}

            group_executions: List[Dict[str, Any]] = []
            try:
                items, exec_response = sdk_list(oci, dr, "list_dr_plan_executions",
                                                SDK_READ_METHODS, group_id)
                ok(target, f"disaster_recovery.list_dr_plan_executions[{group_id}]",
                   len(items), exec_response)
                for item in items:
                    execution_id = _text(item, "id")
                    detail = None
                    if execution_id:
                        try:
                            detail = getattr(
                                sdk_get(oci, dr, "get_dr_plan_execution",
                                        SDK_READ_METHODS, execution_id), "data", None)
                        except Exception as exc:  # noqa: BLE001
                            failed(target,
                                   f"disaster_recovery.get_dr_plan_execution[{execution_id}]",
                                   exc)
                    group_executions.append(execution_row(
                        item, detail, plan_names, group_id, group_name,
                        target, region, now))
            except Exception as exc:  # noqa: BLE001
                failed(target, f"disaster_recovery.list_dr_plan_executions[{group_id}]", exc)

            executions.extend(group_executions)
            for plan in plans:
                plan_tests.append(plan_test_row(
                    plan, group_executions, group_id, group_name, target,
                    region, args.test_window_days))

    return executions, plan_tests, coverage, errors


def source_selfcheck() -> bool:
    if not SDK_READ_METHODS or any(
        not (name.startswith("list_") or name.startswith("get_"))
        for name in SDK_READ_METHODS
    ):
        print("READ-ONLY SDK SELF-CHECK: FAILED — invalid method in allowlist", file=sys.stderr)
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

    # This collector reads the record of DR exercises. The operations that
    # START one sit on the same client: create_dr_plan_execution runs a real
    # switchover or failover. A collector that audits testing must never be
    # able to perform a test.
    forbidden = ("create_", "update_", "delete_", "change_", "move_", "cancel_",
                 "ignore_", "pause_", "resume_", "retry_", "associate_")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr.startswith(forbidden):
                problems.append(f"line {node.lineno}: direct mutating-style call {node.func.attr}")
    if problems:
        print("READ-ONLY SDK SELF-CHECK: FAILED", file=sys.stderr)
        for problem in problems:
            print("  " + problem, file=sys.stderr)
        return False
    print("READ-ONLY SDK SELF-CHECK: PASSED (cp04-01-contingency-plan-testing)")
    print("Oracle SDK cloud methods are restricted to Disaster Recovery list/get reads "
          "plus scope discovery.")
    print("create_dr_plan_execution and every other execution-starting operation are "
          "unreachable: this collector reads test records and never runs a test.")
    return True


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Read-only OCI contingency plan testing (CP-4) evidence collector.")
    p.add_argument("-r", "--region", required=False)
    p.add_argument("-o", "--output-dir", default=".")
    p.add_argument("-p", "--profile", default="DEFAULT")
    p.add_argument("--config-file", default="~/.oci/config")
    p.add_argument("--auth", choices=("config", "instance-principal", "resource-principal"),
                   default="config")
    p.add_argument("-c", "--compartment-id", action="append", default=[])
    p.add_argument("-n", "--compartment-names", default="")
    p.add_argument("--tenancy-scope", action="store_true")
    p.add_argument("--test-window-days", type=int, default=365,
                   help="how recent an exercise must be to satisfy the testing "
                        "frequency (default 365).")
    p.add_argument("--test-register",
                   help="CSV of recorded contingency tests. The only source of "
                        "participants, test report, corrective actions and approval: "
                        "OCI holds none of them.")
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
    lines = [
        "======================================================================",
        " CP-4 CONTINGENCY PLAN TESTING PRE-SCAN SAFETY SUMMARY",
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
        "DR boundary     : this collector READS the record of DR plan executions. It "
        "cannot start one; create_dr_plan_execution is unreachable.",
        f"Testing window  : {args.test_window_days} days",
        f"Test register   : {args.test_register or '<none — SNAPSHOT-ONLY-NO-TEST-REGISTER>'}",
        "Precheck note   : a *_PRECHECK execution validates that a plan could run and "
        "does not run it; it is never counted as a test",
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
    if args.test_window_days <= 0:
        print("ERROR: --test-window-days must be a positive number of days", file=sys.stderr)
        return 1

    register: Optional[List[Dict[str, str]]] = None
    if args.test_register:
        try:
            register = load_register(args.test_register)
        except RegisterUnusable as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

    now = utc_now()
    try:
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
    prefix = f"cp04-01_{timestamp}"
    outputs = {
        "plan": f"{output_dir}/{prefix}_approved_scan_plan.txt",
        "executions": f"{output_dir}/{prefix}_dr_plan_executions.csv",
        "plan_tests": f"{output_dir}/{prefix}_plan_test_status.csv",
        "register_validation": f"{output_dir}/{prefix}_test_register_validation.csv",
        "register_template": f"{output_dir}/{prefix}_test_register_template.csv",
        "coverage": f"{output_dir}/{prefix}_collection_coverage.csv",
        "errors": f"{output_dir}/{prefix}_collection_errors.csv",
        "inputs": f"{output_dir}/{prefix}_input_sources.csv",
        "summary": f"{output_dir}/{prefix}_summary.txt",
    }
    plan_text = build_plan(args, context, selected, targets, outputs)
    print(plan_text, end="")
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
    write_private_text(outputs["plan"], plan_text + "SCAN APPROVED\n")

    executions, plan_tests, coverage, errors = collect(oci, args, context, targets)

    write_csv(outputs["executions"], EXECUTION_FIELDS, executions)
    write_csv(outputs["plan_tests"], PLAN_TEST_FIELDS, plan_tests)
    write_csv(outputs["coverage"], COLLECTION_COVERAGE_FIELDS, coverage)
    write_csv(outputs["errors"], ERROR_FIELDS, errors)
    write_csv(outputs["register_template"], TEST_REGISTER_FIELDS, [])

    validations: List[Dict[str, Any]] = []
    blocking: List[str] = []
    if register is not None:
        validations, blocking = validate_register(register, executions)
    write_csv(outputs["register_validation"], REGISTER_VALIDATION_FIELDS, validations)

    input_sources = []
    if args.test_register:
        input_sources.append({
            "input_type": "TEST-REGISTER", "path": args.test_register,
            "sha256": sha256_file(args.test_register), "row_count": len(register or []),
        })
    write_csv(outputs["inputs"], ["input_type", "path", "sha256", "row_count"], input_sources)

    collection_complete = not errors and all(
        row.get("status") in {"OK", "EMPTY"} for row in coverage)
    tested = sum(1 for p in plan_tests if p["test_status"] == "OK")
    precheck_only = sum(1 for p in plan_tests if p["test_status"] == "PLAN-PRECHECK-ONLY")

    summary_lines = [
        "CP04-01 Contingency Plan Testing (CP-4) Summary",
        "===============================================",
        f"Region                       : {args.region}",
        f"Selected scope               : {selected.kind} / {selected.name}",
        f"Target compartments          : {len(targets)}",
        f"Collected                    : {iso(now)}",
        f"OCI SDK version              : {getattr(oci, '__version__', '<unknown>')}",
        f"Testing window               : {args.test_window_days} days",
        f"DR plans discovered          : {len(plan_tests)}",
        f"  tested in window           : {tested}",
        f"  never executed             : {sum(1 for p in plan_tests if p['test_status'] == 'PLAN-NEVER-EXECUTED')}",
        f"  precheck only              : {precheck_only}",
        f"  real move only             : {sum(1 for p in plan_tests if p['test_status'] == 'PLAN-EXERCISED-BY-REAL-MOVE-ONLY')}",
        f"  no successful drill        : {sum(1 for p in plan_tests if p['test_status'] == 'PLAN-NO-SUCCESSFUL-DRILL')}",
        f"  outside window             : {sum(1 for p in plan_tests if p['test_status'] == 'PLAN-NO-EXERCISE-IN-WINDOW')}",
        f"Executions discovered        : {len(executions)}",
        f"  drills                     : {sum(1 for e in executions if e['exercise_class'] == 'DRILL')}",
        f"  prechecks (not a test)     : {sum(1 for e in executions if e['exercise_class'] == 'PRECHECK')}",
        f"  real moves                 : {sum(1 for e in executions if e['exercise_class'] == 'REAL-MOVE')}",
        f"Collection errors            : {len(errors)}",
        f"COLLECTION STATUS            : {'COMPLETE' if collection_complete else 'INCOMPLETE'}",
        f"TEST REGISTER MODE           : {'RECONCILIATION' if register is not None else 'SNAPSHOT-ONLY-NO-TEST-REGISTER'}",
    ]
    if register is not None:
        summary_lines.extend([
            f"Recorded tests               : {len(register)}",
            f"  corroborated by OCI        : {sum(1 for v in validations if v['validation_status'] == 'VALID')}",
            f"  not corroborated           : {sum(1 for v in validations if v['validation_status'] == 'INVALID')}",
        ])
    if not plan_tests:
        summary_lines.extend([
            "",
            "No Full Stack DR plan was found in the selected scope, so OCI holds no",
            "execution record to assess. Contingency testing is commonly performed",
            "against documented runbooks rather than Full Stack DR; that evidence is",
            "a test report, not an API result, and remains required.",
        ])
    summary_lines.extend([
        "",
        "A *_PRECHECK execution validates that a plan could run. It does not run it,",
        "and it is never counted as a contingency test.",
        "OCI holds no participant list, test report, lesson learned or corrective",
        "action. Those come from the test register and remain required.",
    ])

    write_private_text(outputs["summary"], "\n".join(summary_lines) + "\n")
    print("\n" + "\n".join(summary_lines))
    print(f"\nEvidence directory: {output_dir}")

    if not collection_complete:
        print(f"COLLECTION INCOMPLETE — review {outputs['coverage']}", file=sys.stderr)
        return 3
    if register is not None and blocking:
        print(f"TEST REGISTER NOT CORROBORATED — review {outputs['register_validation']}",
              file=sys.stderr)
        return 3
    print("CP04-01 COLLECTION COMPLETE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
