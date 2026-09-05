# Task 14 — SIEM Integration / CrowdStrike Log Forwarding Evidence Guide

**Control mapping:** SI-4 / AU-12 / SI-4(2)

**Collector:** `si04-01-siem-crowdstrike-forwarding.py`

**Prerequisite:** `requirements-oci-sdk.txt` installed — `python3 -m pip install -r requirements-oci-sdk.txt`

---

## What this collector produces

| Output file | Content |
|---|---|
| `si04-01_<TS>_approved_scan_plan.txt` | Signed pre-scan summary with scope, region, SDK operations and output paths |
| `si04-01_<TS>_connector_inventory.csv` | All Service Connector Hub connectors in scope with source/target config and CrowdStrike/SIEM flags |
| `si04-01_<TS>_log_source_inventory.csv` | All log groups and logs with forwarding coverage status |
| `si04-01_<TS>_forwarding_coverage.csv` | Per-source binding of each active connector to its log sources |
| `si04-01_<TS>_collection_coverage.csv` | Per-compartment SDK call status |
| `si04-01_<TS>_collection_errors.csv` | API errors (only written when errors occur) |
| `si04-01_<TS>_test_event_register_template.csv` | Pre-populated test-event template (one row per active connector) |
| `si04-01_<TS>_owner_approval_template.csv` | Owner approval template |
| `si04-01_<TS>_input_sources.csv` | SHA-256 provenance of all supplied governance inputs |
| `si04-01_<TS>_input_validation.csv` | Row-level validation results for governance inputs |
| `si04-01_<TS>_monthly_review_template.csv` | Count-bound monthly review template |
| `si04-01_<TS>_monthly_review_validation.csv` | Validation result when `--monthly-review` is supplied |
| `si04-01_<TS>_summary.txt` | Collector summary with counts and collection status |

All outputs are written mode `0600`. Never store them outside the approved restricted evidence location.

---

## Running the collector

### Interactive (default)

```bash
python3 si04-01-siem-crowdstrike-forwarding.py \
  --region us-ashburn-1 \
  --output-dir /restricted/evidence/si04 \
  --profile PROD
```

The script will:
1. Discover the authenticated tenancy and all active compartments.
2. Display every compartment name and OCID.
3. Prompt for an exact discovered OCID (twice).
4. Print the full pre-scan summary including every SDK operation and output path.
5. Require exact uppercase `YES` before any service collection begins.

### Non-interactive (scheduled/automated)

```bash
python3 si04-01-siem-crowdstrike-forwarding.py \
  --region us-ashburn-1 \
  --output-dir /restricted/evidence/si04 \
  --profile PROD \
  --tenancy-scope \
  --non-interactive \
  --confirm-scope-ocid ocid1.tenancy.oc1..EXACT \
  --confirm-scope-ocid ocid1.compartment.oc1..EXACT \
  --approve-scan YES
```

Every resolved compartment OCID must appear as a separate `--confirm-scope-ocid` value. The exact OCID set is validated against the live discovered set after the plan prints. Any mismatch or a value other than exact uppercase `YES` terminates before collection.

### Governance validation run

Supply all three governance inputs on the same run that produces the final evidence package:

```bash
python3 si04-01-siem-crowdstrike-forwarding.py \
  --region us-ashburn-1 \
  --output-dir /restricted/evidence/si04/final \
  --profile PROD \
  --tenancy-scope \
  --non-interactive \
  --confirm-scope-ocid ... \
  --approve-scan YES \
  --test-event-register /restricted/evidence/si04/test_event_register.csv \
  --owner-approvals /restricted/evidence/si04/owner_approvals.csv \
  --monthly-review /restricted/evidence/si04/monthly_review.csv
```

---

## CrowdStrike and SIEM detection

The collector flags connectors using heuristic keyword matching. A connector is marked `crowdstrike_target=YES` when its display name or HTTP target URL contains `crowdstrike` or `falcon` (case-insensitive). A connector is marked `siem_forwarding=YES` when any of: the target kind is `http`, `functions`, `streaming`, or `loggingAnalytics`; or the name/URL contains a SIEM-platform keyword.

These heuristics assist scope identification. The system owner must review the `connector_inventory.csv` and confirm which connectors are authoritative SIEM forwarding paths. The `NOT-APPLICABLE` disposition in the owner approval covers connectors that are not part of the SIEM integration.

---

## Evidence required to close Task 14

The collector produces technical configuration facts. The following organizational evidence must be separately obtained and approved before Task 14 is audit-complete.

### 1. Connector scope confirmation (system owner)

Obtain a signed statement from the system owner identifying:
- Every active connector that is part of the authoritative SIEM integration.
- Every connector that is explicitly `NOT-APPLICABLE` for SIEM forwarding.
- The authoritative SIEM system name and CrowdStrike tenant/deployment reference.

### 2. Source coverage review

For every log source row with `forwarding_coverage=NOT-COVERED`:
- Document whether the source is in-scope for SIEM forwarding.
- If in-scope and not covered: open a corrective action and record it in the monthly review notes.
- If not in-scope: record the `NOT-APPLICABLE` disposition with authority reference.

### 3. Test event evidence

For each active SIEM-forwarding connector, execute a test event and capture:
- The exact event type and generation method.
- The SIEM receipt reference (ingestion ID, search query, screenshot).
- Ingestion latency in seconds.
- Tester name, test date, and test result.

Fill the `test_event_register_template.csv` generated by the collector and supply it as `--test-event-register` on the governance run.

Acceptable test methods:
- `OCI-AUDIT-API-CALL` — a controlled read-only API call whose Audit event is verified in the SIEM.
- `OCI-LOGGING-CUSTOM` — a custom log entry injected via a controlled Function.
- `SYNTHETIC-LOG-ENTRY` — a synthetic entry injected directly into a log stream.

Proof of SIEM receipt must include a screenshot or saved search export showing the event in the SIEM console with a timestamp within the expected ingestion window.

### 4. Owner approval

Complete the `owner_approval_template.csv` with:
- `system_name`: the OCI environment name.
- `system_owner`: the authoritative system owner.
- `approver_principal`: name and role of the approving official.
- `siem_system`: the SIEM system (e.g., `CrowdStrike Falcon LogScale`).
- `crowdstrike_integration`: the CrowdStrike integration reference (connector ID or pipeline name).
- `source_scope`: a plain-language description of which OCI log sources are in scope.
- `approval_status`: must be `APPROVED`.
- `approval_time`: ISO-8601 UTC timestamp.
- `evidence_reference`: the restricted evidence package path.

### 5. Monthly review

The `monthly_review_template.csv` is pre-populated with exact snapshot counts. Fill in:
- `review_period`: the review period covered (e.g., `2026-09-01 to 2026-09-30`).
- `test_events_executed`: the number of test events executed this period.
- `test_events_passed`: the number that passed SIEM receipt verification.
- `reviewer`: name of the reviewer.
- `review_date`: ISO-8601 UTC date.
- `approval_status`: `APPROVED`.
- `evidence_reference`: the restricted evidence package path.
- `notes`: required if `coverage_gaps > 0` — must disposition every uncovered log source.

Do not change any of the pre-populated count fields. The validation run checks every count field against the current snapshot SHA-256.

---

## CrowdStrike-specific evidence

In addition to the OCI connector configuration, retain:

- The CrowdStrike Falcon tenant ID and the connector pipeline or API token reference (store securely, never in this repository).
- A screenshot of the CrowdStrike Data Onboarding or LogScale/Falcon Data Replicator configuration showing the OCI source is enabled and active.
- The CrowdStrike event search confirming receipt of the test event.
- The CrowdStrike team or owner contact who approved the integration configuration.

---

## Non-OCI log source gaps

This collector covers only OCI Service Connector Hub forwarding paths. The following sources are outside the OCI collection boundary and must be addressed through separate evidence:

- CrowdStrike sensor agent logs from OCI Compute instances (host-level, not OCI Logging).
- Application-level logs not routed through OCI Logging or a Service Connector.
- Third-party or on-premise sources feeding the same SIEM.
- OCI Streaming streams consumed externally without a Service Connector.

Document each gap in the monthly review notes with an owner, coverage method, and evidence reference.

---

## Closing conditions

Task 14 is not audit-complete until all of the following are true:

- [ ] The collector has been run tenancy-wide in every in-scope region with exit code 0.
- [ ] Every active connector's source scope has been confirmed by the system owner.
- [ ] Every in-scope log source has `forwarding_coverage=COVERED` or an approved `NOT-APPLICABLE` disposition.
- [ ] At least one test event per active SIEM connector has been executed with SIEM receipt proof.
- [ ] The owner approval is complete and `approval_status=APPROVED`.
- [ ] The monthly review matches the exact snapshot counts and is `approval_status=APPROVED`.
- [ ] CrowdStrike-specific configuration screenshots and tenant references are in the evidence package.
- [ ] Non-OCI source gaps are documented with dispositions in the monthly review.
- [ ] The evidence package is signed, archived, and stored in the approved restricted location.
