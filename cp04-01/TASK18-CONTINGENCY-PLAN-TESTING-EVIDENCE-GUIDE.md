# Task 18 Evidence Guide — Contingency Plan Testing (CP-4)

**Control family:** CP-4, CP-2, CP-10
**Collector:** `cp04-01/cp04-01-contingency-plan-testing.py`
**Step-by-step manual procedures:** `MANUAL-EVIDENCE-PROCEDURES.md` §Task 18

Do not place completed test registers, execution OCIDs, participant names or
test reports in this public repository. Store the completed package in the
approved restricted evidence location.

## The distinction this whole task turns on

`plan_execution_type` has eight values in `oci==2.185.1`, and collapsing them
destroys the control:

| Class | Types | What it proves |
|---|---|---|
| `DRILL` | `START_DRILL`, `STOP_DRILL` | **The plan was exercised** without moving production. The strongest CP-4 evidence the API can give. |
| `REAL-MOVE` | `SWITCHOVER`, `FAILOVER` | The plan works — but this is an *event*, not a scheduled test. |
| `PRECHECK` | the four `*_PRECHECK` variants | **Nothing about execution.** A precheck validates that a plan *could* run. It does not run it. |

**Prechecks are cheap, frequent and routinely succeed, so counting one as a test
is the easiest available way to report an untested plan as tested.** The
collector refuses to: prechecks never count toward recency, a plan whose only
executions are prechecks is `PLAN-PRECHECK-ONLY`, and a register entry pointing
at a precheck is rejected as `INVALID`.

Classification is by **suffix, not substring** — `START_DRILL_PRECHECK` contains
`START_DRILL`, so a substring test would call a precheck a drill.

## Collection record

| Field | Value |
|---|---|
| Evidence package/reference | |
| Tenancy | |
| Region(s) | |
| Compartments | VCN / Shared Services / CD3 |
| Approved testing frequency (days) | |
| Collector commit | |
| Collection UTC date/time | |
| Operator | |
| Reviewer | |
| Review UTC date/time | |
| Exceptions/remediation references | |

## Run sequence

```
# 1. Snapshot only
python3 cp04-01/cp04-01-contingency-plan-testing.py \
    -r <region> -o <evidence-root> --tenancy-scope \
    --test-window-days <approved-frequency>

# 2. With the completed test register
python3 cp04-01/cp04-01-contingency-plan-testing.py \
    -r <region> -o <evidence-root> --tenancy-scope \
    --test-window-days <approved-frequency> \
    --test-register <completed-test-register.csv>
```

## Automated integrity gate

- [ ] `python3 cp04-01/cp04-01-contingency-plan-testing.py --selfcheck` passed.
      It confirms `create_dr_plan_execution` and every other execution-starting
      operation is unreachable: **a collector that audits DR testing must never
      be able to run a test.**
- [ ] The retained scan plan shows the region, scope OCIDs and the DR boundary.
- [ ] `--test-window-days` matches the approved testing frequency; it is a
      governance threshold, not a default to accept.
- [ ] Exited `0`, or `3` with a documented reason.
- [ ] Every coverage row is `OK`; the error ledger is empty or dispositioned.

## Findings that must be dispositioned

- [ ] `PLAN-NEVER-EXECUTED` — no execution of any kind recorded.
- [ ] `PLAN-PRECHECK-ONLY` — **prechecks only; the plan has never been tested.**
- [ ] `PLAN-NO-SUCCESSFUL-DRILL` — drills ran and none succeeded.
- [ ] `PLAN-EXERCISED-BY-REAL-MOVE-ONLY` — proven by a real failover, never by a
      scheduled test.
- [ ] `PLAN-NO-EXERCISE-IN-WINDOW` — last exercise is older than the approved
      frequency.
- [ ] `AUTOMATIC-EXECUTION-NOT-A-SCHEDULED-TEST` — the service started it, so it
      is not a contingency *test*.
- [ ] `EXERCISE-FAILED` — a failed drill is a finding with corrective actions,
      not a retry to hide.

## Manual evidence

- [ ] A drill was scheduled and run, and `STOP_DRILL` returned the environment
      to steady state.
- [ ] The execution OCID is recorded — the register requires it.
- [ ] The test report exists: participants and roles, whether **RTO and RPO were
      actually met** (compare `execution_duration_in_sec` against the CP-2
      register's `rto_hours`), every finding, and corrective actions with owners
      and due dates.
- [ ] Every register row has `approval_status` exactly `APPROVED`.
- [ ] The collector was re-run with `--test-register` and exited `0`. Any
      `INVALID` row means the claimed test is not corroborated by a real,
      successful, non-precheck execution.
- [ ] Corrective actions are tracked to closure and the ISCP/BIA updated.
- [ ] Where Full Stack DR is not in use, the runbook exercise record stands in
      for the execution reference and the report requirements are unchanged.
