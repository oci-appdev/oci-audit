# Task 16 Evidence Guide — Contingency Planning (CP-2)

**Control family:** CP-2, CP-6, CP-7, CP-10
**Collector:** `cp02-01/cp02-01-contingency-planning.py`
**Step-by-step manual procedures:** `MANUAL-EVIDENCE-PROCEDURES.md` §Task 16

Do not place completed registers, OCIDs, system names, RTO/RPO values or DR
topology in this public repository. Store the completed package in the approved
restricted evidence location and record only its controlled reference.

## Read this before interpreting an empty result

**An empty DR section is not a finding.** `MANUAL-VERIFY-NO-OCI-DR-RECORD` means
OCI holds no Full Stack DR configuration record — not that there is no
contingency plan. Most tenancies implement disaster recovery with cross-region
backups and documented runbooks, in which case CP09-03 carries the recovery
capability evidence and this collector's DR tables are legitimately empty.

**Decide which model is in use and record that decision first.** Everything
below depends on it.

## What no API can supply

**There is no recovery-time or recovery-point objective field anywhere in the
OCI SDK.** RTO, RPO, recovery priority, alternate site and plan approval come
from the Business Impact Analysis and the ISCP register, and are reconciled
here — never derived from the tenancy.

## Collection record

| Field | Value |
|---|---|
| Evidence package/reference | |
| Tenancy | |
| Region(s) | |
| Compartments | VCN / Shared Services / CD3 |
| DR model in use | Full Stack DR / backup + runbook / other |
| Collector commit | |
| Collection UTC date/time | |
| Operator | |
| Reviewer | |
| Review UTC date/time | |
| Exceptions/remediation references | |

## Run sequence

```
# 1. Snapshot only
python3 cp02-01/cp02-01-contingency-planning.py \
    -r <region> -o <evidence-root> --tenancy-scope

# 2. With the approved ISCP register
python3 cp02-01/cp02-01-contingency-planning.py \
    -r <region> -o <evidence-root> --tenancy-scope \
    --iscp-register <approved-iscp-register.csv>
```

## Automated integrity gate

- [ ] `python3 cp02-01/cp02-01-contingency-planning.py --selfcheck` passed. It
      confirms no switchover, failover or plan-execution operation is reachable.
- [ ] The retained scan plan shows region, scope OCIDs, the approved read-only
      operations and the DR mutation boundary.
- [ ] Run under a read-only principal in every in-scope region.
- [ ] Exited `0`, or `3` with a documented reason.
- [ ] Every coverage row is `OK`; the error ledger is empty or dispositioned.

## Structural facts to read off the collection

- [ ] `SINGLE-REGION-TENANCY` — a tenancy subscribed to one region **cannot fail
      over to another region**, whatever the plan document says. If present, the
      ISCP must be corrected or a region subscription added.
- [ ] `SINGLE-FAULT-DOMAIN` / `SINGLE-AVAILABILITY-DOMAIN-REGION` — record the
      resulting exposure.
- [ ] `GROUP-HAS-NO-MEMBERS` — the protection group exists and protects nothing.
- [ ] `GROUP-HAS-NO-PEER` — no standby to recover to.
- [ ] `GROUP-HAS-NO-PLAN` — members but no recovery plan.
- [ ] `GROUP-HAS-NO-DRILL-PLAN` — **this blocks Task 18.** Without a
      `START_DRILL`/`STOP_DRILL` plan the arrangement cannot be exercised
      without moving production.
- [ ] `PLAN-ALL-STEPS-DISABLED` / `PLAN-HAS-DISABLED-STEPS`.
- [ ] `GROUP-DETAIL-NOT-READ` — the member count is `UNKNOWN`, not `0`. This is
      a collection failure to resolve, never evidence that the group is empty.

## Manual evidence

- [ ] The Business Impact Analysis is complete and approved.
- [ ] The ISCP register states `rto_hours` and `rpo_hours` for every in-scope
      system. A blank one reports `REGISTER-INCOMPLETE`; OCI cannot fill it in.
- [ ] **`resource_ocid` is populated on every row.** Matching is by OCID, never
      by display name — a name is not an identity, and a rename would silently
      move coverage from one system to another.
- [ ] Every `NOT-IN-DR-PROTECTION-GROUP` row is dispositioned: the system is
      approved for recovery but is not actually protected.
- [ ] The ISCP itself is drafted and approved.
- [ ] Communications bridge and call tree are documented and current.
- [ ] Per-system recovery procedures exist.
- [ ] The test plan exists and feeds Task 18.
- [ ] Where the DR model is backup + runbook rather than Full Stack DR, CP09-03
      replication evidence is attached and the runbooks are approved.
