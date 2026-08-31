# Task 8 Configuration Baseline Evidence Guide

## Control objective

Task 8 asks the organization to identify controlled configuration items (CIs),
tie their approved settings to the System Design Form or equivalent baseline,
compare live configuration monthly, and retain reviewer/approval evidence.

The canonical collector is `cm02-01-configuration-baseline.sh`. The filename
uses **CM02** because baseline configuration is CM-2. The existing
`cm08-hw-sw-baseline.sh` remains the broad CM-8 component-inventory engine and
is invoked only after CM02-01 completes its scope-approval boundary.

The evidence model follows the distinction between CM-2 baseline configuration
and CM-8 system component inventory in [NIST SP 800-53 Revision 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final).

## What the workflow proves

CM02-01 produces evidence for four separate assertions:

1. **Live configuration facts** — read-only OCI list/get results normalized
   from the CM08 inventory engine.
2. **Controlled CI register** — organization-owned system/technical owners,
   criticality, environment, baseline ID, System Design Form reference and
   approval.
3. **Approved baseline** — one approved expected value and comparison method
   for every controlled live attribute.
4. **Monthly review** — reviewer, period, findings/change/exception review,
   corrective action, approver and retained evidence reference.

The script does not turn a live value into an approved value automatically.
Generated templates are marked `PENDING-REVIEW` and require accountable human
approval.

## Scope and safety boundary

The normal run:

1. uses IAM list/get calls to discover the tenancy and active compartments;
2. displays the full tenancy and compartment OCIDs;
3. requires the operator to enter an exact tenancy or compartment OCID;
4. requires the same OCID a second time;
5. displays the region, profile, every target, evidence work and output path;
6. requires exact uppercase `YES` before any workload-service collection.

Manual `-c` and `-n` runs still require every resolved compartment OCID twice
and the final `YES`. Approved automation additionally requires
`--non-interactive`, one `--confirm-scope-ocid` per exact target and
`--approve-scan YES`.

For an approved single compartment, the invoked inventory engine is forced to
that exact compartment and cannot silently expand to children. Tenancy
selection explicitly shows and scans the root plus every discovered active
child compartment.

Run the source-level boundary check before collection:

```bash
bash cm02-01-configuration-baseline.sh --selfcheck
```

The self-check covers CM02-01, the shared scope helper and the invoked CM08
inventory engine. It rejects OCI mutations and non-GET raw requests.

## Phase 1 — inventory and template generation

```bash
bash cm02-01-configuration-baseline.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task8-inventory
```

Use `-p DOJ-GOV-PROFILE` when a named OCI CLI profile is required. The profile
is printed in the approved plan and passed to discovery and inventory calls.

Review these primary outputs:

| Output | Purpose |
|---|---|
| `configuration_items` | One normalized row and fingerprint per live CI |
| `configuration_attributes` | Current value of each baseline-eligible attribute |
| `ci_register_template` | CI ownership and registration approval worksheet |
| `baseline_template` | Expected-value/System Design Form approval worksheet |
| `monthly_review_template` | Monthly comparison/reviewer record |
| `coverage` | Every underlying OCI operation and its status |
| `raw_inventory` | Private source CSVs, engine summary, ledger and console log |
| `approved_scan_plan` | Exact scope, profile, work and outputs approved before collection |

The generated `configuration_hash` detects change to the normalized attribute
set. It is a technical fingerprint, not an approval record.

## Phase 2 — approve the CI register

Complete the generated CI register template. Required fields include:

- system name and system owner;
- technical owner;
- criticality and environment;
- approved configuration baseline ID;
- System Design Form/reference;
- `MONTHLY` review frequency;
- registration status `APPROVED`;
- approval ID, approver and approval date;
- authoritative source reference.

Do not change `ci_key`, `resource_type` or `resource_ocid`. Those fields join
the approved record to the current live CI.

Live resources missing from the approved register become
`CI-NOT-REGISTERED`. Duplicate or incomplete entries fail closed.

## Phase 3 — approve the configuration baseline

The inventory value in the generated baseline template is a starting point for
review. Validate it against the approved System Design Form, security design,
Terraform/CD3 source, vendor standard and approved change records.

Every approved row requires:

- baseline ID;
- exact CI and attribute identity;
- expected value and comparison method;
- status `APPROVED`;
- approval ID and authority;
- approver and approval date;
- effective date and optional expiration date;
- System Design Form/reference;
- change or exception reference where applicable.

Supported comparisons are:

| Comparison | Meaning |
|---|---|
| `EXACT` | Current and expected strings must be identical |
| `CASE_INSENSITIVE` | Case-insensitive string equality |
| `SET_EQUAL` | Pipe-delimited values must contain the same members |
| `PRESENT` | Current value must be non-empty |
| `ABSENT` | Current value must be empty |
| `NUMERIC_EQ` | Numeric equality |
| `NUMERIC_MIN` | Current value must be at least the approved value |
| `NUMERIC_MAX` | Current value must not exceed the approved value |

Do not use broad wildcards for sensitive settings. If an attribute is excluded
from configuration control, document the approved rationale instead of simply
deleting it from the baseline. A live attribute with no row is reported as
`ATTRIBUTE-NOT-BASELINED`.

## Phase 4 — reconcile and complete the monthly review

Run reconciliation using the approved CI register and baseline plus the current
monthly-review record:

```bash
bash cm02-01-configuration-baseline.sh \
  -r us-langley-1 \
  -g ./approved/cm02-ci-register.csv \
  -b ./approved/cm02-configuration-baseline.csv \
  -m ./approved/cm02-monthly-review.csv \
  -o ./evidence/task8-monthly
```

The monthly review must contain exactly one valid approved row for the current
`YYYY-MM` period and exact approved scan scope. It must show that findings,
changes and exceptions were reviewed and must reference the retained
reconciliation/evidence location.

A practical first-month sequence is:

1. run inventory-only and approve the CI/baseline inputs;
2. run reconciliation with the review template, accepting exit `3` while the
   monthly review is pending;
3. have the configuration manager review the reconciliation and record change,
   exception and corrective-action dispositions;
4. obtain approval of the monthly review record;
5. rerun with the completed review input and retain the final package.

## Result interpretation

| Status | Interpretation |
|---|---|
| `MATCH` | Live value matches a complete approved baseline row |
| `CONFIGURATION-DRIFT` | Live value differs; validate a change/exception or restore it |
| `ATTRIBUTE-NOT-BASELINED` | Live attribute has no approved baseline row |
| `BASELINE-INCOMPLETE` | Baseline row lacks required approval/provenance or has invalid dates |
| `AMBIGUOUS-BASELINE` | Multiple baseline rows claim the same CI attribute |
| `APPROVED-ATTRIBUTE-NOT-LIVE` | Approved attribute/resource is absent from current collection |
| `CI-NOT-REGISTERED` | Live CI is missing from the approved CI register |
| `REGISTERED-CI-NOT-LIVE` | Registered CI was not found; validate retirement or coverage |

Exit `0` means collection and required evidence validation completed. It does
not mean there were no drift findings. Exit `3` means the evidence is
incomplete and cannot support a completeness assertion.

## Required manual evidence boundaries

OCI APIs do not contain the full organizational baseline process. Retain these
records outside this public repository:

- signed System Design Form and configuration-management plan;
- approved CI register and baseline versions;
- CCB/Remedy change approvals and exception records;
- Terraform/CD3 source/version and deployment evidence where applicable;
- in-guest OS, middleware and application settings not exposed by OCI APIs;
- rule-level route, Security List and NSG configuration evidence;
- reviewer sign-off and corrective-action closure evidence;
- restricted evidence repository path, retention and access approval.

The CM08 engine records counts for some network rule sets rather than their
full contents. Use the corrected CM07 workflow for rule-level ports/protocols
evidence after its corrective gate is closed. Do not represent counts as proof
that the individual rules match the approved design.

## Evidence handling

CM02-01 uses a private file-creation mask, no timestamp overwrite, SHA-256 input
provenance, retained collection/console ledgers and spreadsheet-formula
neutralization for canonical and raw CSVs.

Configuration metadata, OCIDs, owners and design references may be sensitive.
Do not commit live output, approved inputs or screenshots to this repository.
Store the final package in the restricted audit evidence location and record
only its approved reference in the audit tracker.
