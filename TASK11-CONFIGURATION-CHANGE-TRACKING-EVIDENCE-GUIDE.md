# Task 11 Configuration Change Tracking Evidence Guide

## Purpose

`cm03-01-configuration-change-tracking.py` is the canonical CM-3 configuration
change workflow. It uses Oracle's official OCI Python SDK to collect OCI Audit
events for an approved tenancy or compartment scope and reconcile likely
configuration changes to:

1. an authoritative Remedy/CRQ export;
2. System Owner approval records;
3. representative implementation and validation samples; and
4. an exact snapshot- and count-bound monthly review.

The collector is read-only. It cannot create, update, delete, approve or close
an OCI resource or a Remedy record.

## Oracle SDK boundary

The runtime allowlist contains only:

- `IdentityClient.get_compartment`;
- `IdentityClient.list_compartments`;
- `AuditClient.get_configuration`; and
- `AuditClient.list_events`.

`oci.pagination.list_call_get_all_results` performs Audit pagination and
`oci.retry.DEFAULT_RETRY_STRATEGY` handles supported transient failures. The
collector uses the SDK version pinned in `requirements-oci-sdk.txt`.

Audit event request parameters, request/response headers, identity credentials
and response payloads are deliberately not exported. Those structures can
contain tokens, cookies, submitted configuration or other sensitive data. The
collector retains only the minimum event metadata needed for change tracking,
plus SHA-256 hashes of state-change and additional-detail objects.

## Prerequisites

Use a dedicated approved virtual environment when the OCI SDK is not already
available:

```bash
python3 -m venv /approved/tools/oci-audit-venv
source /approved/tools/oci-audit-venv/bin/activate
python3 -m pip install -r requirements-oci-sdk.txt
```

The execution principal needs read access to Identity compartments, the Audit
configuration and Audit events in every selected compartment. Evidence
contains OCIDs, identities, source IP addresses, user agents, CRQ identifiers
and approval references. Store it only in the approved restricted location and
do not commit live evidence to this repository.

## Step 1 — Verify the read-only boundary

```bash
python3 cm03-01-configuration-change-tracking.py --selfcheck
```

The result must include:

```text
READ-ONLY SDK SELF-CHECK: PASSED (cm03-01-configuration-change-tracking)
```

## Step 2 — Collect the technical Audit snapshot

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  --lookback-days 30 \
  -o ./evidence/task11-technical
```

The normal workflow:

1. discovers the authenticated tenancy and active compartments;
2. displays their complete OCIDs;
3. requires the selected tenancy or compartment OCID twice;
4. displays the exact region, time window, target compartments, SDK methods
   and output paths;
5. requires exact uppercase `YES`; and
6. starts Audit collection only after approval.

Selecting the tenancy queries the root plus every active discovered child
compartment. Audit calls are divided into seven-day windows and each window is
paginated by the SDK.

For an exact historical window, supply both timestamps. Seconds are normalized
to zero because that is the Audit API contract:

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  --start-time 2026-08-01T00:00:00Z \
  --end-time 2026-09-01T00:00:00Z \
  -o ./evidence/task11-august
```

The collector obtains the tenancy Audit retention setting. A requested start
outside the configured retention period is `OUTSIDE-RETENTION`, makes the
collection incomplete and exits `3`. OCI Audit retention is evidence coverage;
it must never be assumed from the requested date range.

Unexpected Audit-list or retention-configuration response shapes are also
collection failures. They cannot silently become an empty or compliant result.

### Strict automation

Automation must explicitly select a scope, confirm every resolved target OCID
and approve the printed plan:

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  -c ocid1.compartment.oc1..example \
  --non-interactive \
  --confirm-scope-ocid ocid1.compartment.oc1..example \
  --approve-scan YES \
  -o ./evidence/task11-automation
```

Supplying `-c` or `-n` without `--non-interactive` still requires every
resolved OCID twice and exact `YES`.

## Change-candidate boundary

The OCI facts do not prove authorization. The collector classifies an Audit
event as `CHANGE-CANDIDATE` only when its event name begins with a mutating verb
such as Create, Update, Delete, Move, Attach, Detach, Enable or Disable. The
request HTTP method is retained as corroborating evidence.

Read methods are `NON-CHANGE`. A non-read HTTP method whose event name does not
confirm mutation is `REVIEW-CANDIDATE`; it stays in the full Audit inventory
and its count is bound to the monthly review, but it is not forced into a fake
CRQ. The reviewer must disposition any review candidates in the monthly-review
notes.

Failed API operations remain visible as failed change attempts. They are not
treated as successful resource changes, but they must still be reconciled to
an approved CRQ or investigated.

## Step 3 — Complete the Remedy/CRQ register

The technical run creates `*_remedy_change_register_template.csv`, with exact
Audit event IDs, event-grouping IDs, resource OCIDs and event names
prepopulated. The authoritative Remedy or change-management owner completes:

- CRQ identifier and title;
- Standard, Normal or Emergency change type;
- Implemented or Closed status;
- planned and actual implementation windows;
- requester and implementer;
- implementation, validation and rollback results;
- CCB approval reference, or emergency approval reference;
- source authority, export time and retained evidence reference.

The event must bind through an exact Audit event ID or event-grouping ID. A
resource OCID or matching timestamp by itself is not an authorization join.

Run again with the completed register:

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  --change-register ./approved/cm03-remedy-change-register.csv \
  -o ./evidence/task11-with-register
```

Exit `3` is expected while governance evidence is incomplete. This run creates
CRQ-bound System Owner approval and sample templates.

## Step 4 — Complete System Owner approvals

For every in-scope CRQ, complete the generated
`*_system_owner_approval_template.csv` with:

- system name and System Owner;
- identifiable approver principal;
- `APPROVED` status;
- approval timestamp and reference;
- `PRE-IMPLEMENTATION` or `EMERGENCY-POST` approval type;
- source authority and evidence reference.

Standard and Normal changes require approval before the Audit event. Emergency
post-approval is accepted only when the CRQ is classified `EMERGENCY`, the
approval row uses `EMERGENCY-POST`, and the change register contains the
emergency approval reference. The collector does not invent an emergency
approval deadline; the organization's policy and evidence remain authoritative.

## Step 5 — Select and document representative samples

Use `*_change_sample_template.csv` as a candidate population. Retain only the
approved representative sample rows and complete:

- sample ID and selection basis;
- exact CRQ and Audit event IDs;
- implementation evidence;
- validation/test evidence;
- rollback or backout evidence where applicable;
- reviewer, date, result, authority and retained evidence reference.

The collector validates exact sample-to-event-to-CRQ binding. It does not claim
that a sample is representative merely because a row exists. The accountable
reviewer makes that determination under the referenced sampling policy.

## Step 6 — Generate the exact monthly review

Run with all three organizational inputs and omit `--monthly-review`:

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  --change-register ./approved/cm03-remedy-change-register.csv \
  --owner-approvals ./approved/cm03-system-owner-approvals.csv \
  --change-samples ./approved/cm03-change-samples.csv \
  -o ./evidence/task11-review-draft
```

The expected exit is `3`. Review `*_input_validation.csv` and
`*_change_reconciliation.csv`, correct all invalid, ambiguous, untracked,
late-approval and outside-window rows, then approve the generated
`*_monthly_review_template.csv`.

The review binds the exact change-candidate CSV SHA-256 and counts for total
Audit events, change candidates, unresolved review candidates, successful
events, failed attempts, validated changes, untracked/ambiguous/unapproved rows
and sampled CRQs.

## Step 7 — Produce the governed package

```bash
python3 cm03-01-configuration-change-tracking.py \
  -r us-langley-1 \
  --change-register ./approved/cm03-remedy-change-register.csv \
  --owner-approvals ./approved/cm03-system-owner-approvals.csv \
  --change-samples ./approved/cm03-change-samples.csv \
  --monthly-review ./approved/cm03-monthly-review.csv \
  -o ./evidence/task11-final
```

A governed exit `0` requires complete OCI collection, exact CRQ bindings,
valid System Owner approvals, no blocking reconciliation statuses, at least one
valid sample when approved changes exist, and a monthly review matching the
exact current snapshot and counts.

## Evidence outputs

| Output | Purpose |
|---|---|
| `approved_scan_plan` | Operator-approved scope, time and SDK method plan |
| `audit_configuration` | Retention setting and requested-window coverage |
| `audit_event_inventory` | Minimum-data inventory of all returned Audit events |
| `change_candidates` | Mutating event-name candidates requiring reconciliation |
| `collection_coverage` | Compartment and seven-day query coverage ledger |
| `collection_errors` | OCI status, service code, request ID and redacted error |
| `remedy_change_register_template` | Exact-event CRQ input template |
| `system_owner_approval_template` | CRQ-bound approval input template |
| `change_sample_template` | Exact-event representative-sample template |
| `input_sources` | Input paths, row counts and SHA-256 hashes |
| `input_validation` | Row-level authority, completeness and binding validation |
| `change_reconciliation` | Event-to-CRQ-to-owner-to-sample result |
| `monthly_review_template` | Exact snapshot/count-bound review template |
| `monthly_review_validation` | Submitted review validation result |
| `summary` | Technical collection and governance status |

All evidence files use mode `0600` and spreadsheet-formula prefixes are
neutralized.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Technical collection completed; supplied governance inputs also validated |
| `1` | Dependency, input, authentication, scope or approval failure before Audit collection |
| `3` | Audit collection/retention coverage failed, or supplied governance evidence is incomplete |

A technical-only run can exit `0` while `GOVERNANCE INPUT STATUS` remains
`NOT-VALIDATED`. That is expected template generation, not authorization and
not Task 11 operational closure.

## Manual and external boundaries

OCI Audit does not prove:

- that Remedy contains every non-OCI, in-guest, application or database change;
- that the CCB or System Owner followed the complete organizational process;
- that implementation screenshots, test results or rollback evidence exist;
- that emergency approvals met an organization-specific deadline;
- that a selected sample is representative under the approved sampling policy;
- that failed attempts were investigated; or
- that changes outside OCI Audit retention were covered by another retained log.

The final evidence package must include the referenced Remedy exports,
approvals, samples, validation/rollback records, review approval and evidence
location. Never treat absence from OCI Audit as proof that no configuration
change occurred.
