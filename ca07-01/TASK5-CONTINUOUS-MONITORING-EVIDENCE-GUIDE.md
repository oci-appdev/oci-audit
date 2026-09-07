# Task 5 Evidence Guide — Continuous Monitoring (CA-7)

**Control family:** CA-7, SI-4, AU-6, IR-5
**Collector:** `ca07-01/ca07-01-continuous-monitoring.py`
**Step-by-step manual procedures:** `MANUAL-EVIDENCE-PROCEDURES.md` §Task 5

Do not place completed screenshots, exported CSVs, OCIDs, topic names, alarm
names or subscriber addresses in this public repository. Store the completed
package in the approved restricted evidence location and record only its
controlled reference in the audit worksheet.

## What this collector proves, and what it does not

It reconstructs the delivery path

```
alarm / events rule -> destination OCID -> ONS topic -> ACTIVE subscription
```

and reports the first link that is broken. That matters because an enabled alarm
with no destination, a topic whose only subscription is `PENDING`, and an events
rule whose only action is disabled all look healthy in a plain inventory and all
deliver nothing to anyone.

It does **not** prove a message was received, and it cannot approve the
monitoring baseline. Both remain manual.

## Collection record

| Field | Value |
|---|---|
| Evidence package/reference | |
| Tenancy | |
| Region(s) | |
| Compartments | VCN / Shared Services / CD3 |
| Collector commit | |
| Collection UTC date/time | |
| Operator | |
| Reviewer | |
| Review UTC date/time | |
| Exceptions/remediation references | |

## Run sequence

```
# 1. Snapshot only — produces the blank baseline and the review template
python3 ca07-01/ca07-01-continuous-monitoring.py \
    -r <region> -o <evidence-root> --tenancy-scope

# 2. With the approved governance inputs
python3 ca07-01/ca07-01-continuous-monitoring.py \
    -r <region> -o <evidence-root> --tenancy-scope \
    --monitoring-baseline <approved-baseline.csv> \
    --min-log-retention-days <approved-floor> \
    --monthly-review <completed-review.csv>
```

Automation additionally requires `--non-interactive`, one exact
`--confirm-scope-ocid` per resolved target and `--approve-scan YES`.

## Automated integrity gate

- [ ] `python3 ca07-01/ca07-01-continuous-monitoring.py --selfcheck` passed.
- [ ] The retained scan plan shows region, scope OCIDs, compartment count, the
      approved read-only operations and the output paths.
- [ ] The run used a read-only principal, in every region holding in-scope
      resources.
- [ ] The process exited `0`. An exit of `3` was treated as incomplete evidence.
- [ ] Every compartment/service pair has a coverage row; none is non-`OK`.
- [ ] `*_collection_errors.csv` is empty, or every row is dispositioned.

## Findings that must be dispositioned

- [ ] `ALARM-NO-DESTINATION` — the alarm fires and notifies nobody.
- [ ] `ALARM-DISABLED`, `ALARM-SUPPRESSED` — confirm each is intended, with an
      owner and an end date for the suppression window.
- [ ] `RULE-NO-ACTIONS`, `RULE-ACTIONS-ALL-DISABLED` — the rule matches events
      and delivers nowhere.
- [ ] `TOPIC-NO-ACTIVE-SUBSCRIPTION` — nobody is subscribed.
- [ ] `SUBSCRIPTION-PENDING` — **never confirmed, so never delivered to.**
      Someone must click the confirmation link.
- [ ] `CLOUD-GUARD-DISABLED` / `CLOUD-GUARD-ENABLED-NO-ACTIVE-TARGET`.
- [ ] `RETENTION-BELOW-BASELINE` — only produced when
      `--min-log-retention-days` was supplied.
- [ ] Every `PATH-BROKEN-*` row in `*_delivery_paths.csv`.
- [ ] `PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE` — **not a failure.** The topic is
      in a compartment outside the scan. Either widen the scope and re-run, or
      record the scope limitation explicitly.

## Manual evidence

- [ ] The monitoring baseline was built from the **System Security Plan and
      Continuous Monitoring Form**, not from the snapshot, and is approved.
      A baseline derived from running alarms agrees with any gap by construction.
- [ ] Every `MATCHED-DEGRADED` row is dispositioned. These are controls that
      **exist but do not work** — the verdict an inventory would miss.
- [ ] Every `MISSING` row (approved but absent) has a remediation plan.
- [ ] Every `UNAPPROVED` row is either approved or removed.
- [ ] The retention floor came from the approved retention policy.
- [ ] At least one end-to-end notification test per `PATH-OK` route: alarm, UTC
      fire time, recipient, UTC receipt time, who confirmed.
- [ ] The Continuous Monitoring Form review is complete, with feedback log,
      disposition and approval.
- [ ] The monthly review row was completed **without editing the counts** and
      re-validated to exit `0`. `snapshot_sha256` binds it to this snapshot.

## Confidentiality note

Subscription endpoints are never exported whole. An `EMAIL` endpoint is personal
data and is emitted as `s***@domain`; an HTTPS endpoint's path component **is
the bearer secret** for Slack, PagerDuty and most webhook targets, so only
scheme and host survive. If a reviewer needs a full endpoint, retrieve it from
the Console under the evidence-handling rules — do not change the collector.
