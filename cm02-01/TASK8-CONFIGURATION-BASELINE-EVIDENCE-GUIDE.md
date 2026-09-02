# Task 8 Simple Configuration Snapshot Guide

**Collector:** `cm02-01/cm02-01-configuration-baseline.sh`

**Control:** CM-2, Baseline Configuration

**Mode:** read-only technical collection

## What the script does

CM02-01 collects the OCI resources and configuration attributes visible in one
confirmed tenancy or compartment scope. It produces a current technical
snapshot, stable configuration fingerprints, operation coverage and explicit
collection errors.

It does not:

- create or change OCI resources;
- decide whether a configuration is approved;
- ingest a CI register, System Design Form or approved baseline;
- compare the snapshot to an approved baseline;
- validate a monthly review;
- replace in-guest, application, middleware, Remedy/CRQ or CCB evidence.

The simplification is intentional. A successful run means collection worked.
It does not mean the system passed CM-2.

## Prerequisites

- Bash 4 or later
- authenticated OCI CLI
- `jq`, Python 3 and `mktemp`
- one explicit OCI region
- read permissions for the in-scope resources
- an approved restricted directory for the generated evidence

Run the source safety check first:

```bash
bash cm02-01/cm02-01-configuration-baseline.sh --selfcheck
```

## Normal run

```bash
bash cm02-01/cm02-01-configuration-baseline.sh \
  -r us-langley-1 \
  -o ./evidence/cm02
```

The script then:

1. discovers the authenticated tenancy and visible active compartments;
2. asks you to select a tenancy or compartment by entering its exact OCID;
3. asks for the exact same OCID again;
4. prints the region, selected scope, every target, read-only work and outputs;
5. requires exact uppercase `YES`;
6. starts collection only after approval.

Selecting the tenancy scans the tenancy root and every visible active child
compartment. Selecting a compartment scans only that exact compartment.

## Manual exact-compartment run

Supplying `-c` does not bypass confirmation:

```bash
bash cm02-01/cm02-01-configuration-baseline.sh \
  -c ocid1.compartment... \
  -r us-langley-1 \
  -o ./evidence/cm02
```

You must still enter that compartment OCID twice and approve the displayed
plan with exact uppercase `YES`.

Use `-p PROFILE` when a named OCI CLI profile is required. The selected profile
is printed in the retained plan and passed to discovery and collection calls.

## Approved automation

Automation must be explicit and confirm every resolved target:

```bash
bash cm02-01/cm02-01-configuration-baseline.sh \
  -c ocid1.compartment... \
  -r us-langley-1 \
  --non-interactive \
  --confirm-scope-ocid ocid1.compartment... \
  --approve-scan YES \
  -o ./evidence/cm02
```

Missing, extra or incorrect confirmation OCIDs—or any approval value other
than exact `YES`—stop the run before workload collection.

## Primary outputs

| Output | Purpose |
|---|---|
| `configuration_items` | One normalized row and SHA-256 configuration fingerprint per visible OCI resource |
| `configuration_attributes` | Current normalized technical attributes used to construct each fingerprint |
| `coverage` | Every underlying read operation with `OK`, `EMPTY` or `FAILED` status |
| `collection_errors` | Created when a call, raw collector or normalizer fails |
| `summary` | Counts and final `COLLECTION STATUS` |
| `approved_scan_plan` | Exact scope, profile, work and outputs approved before collection |
| `raw_inventory` | Private source CSVs, collector ledger, summary and console log |

Generated files use a private creation mask and spreadsheet-formula
neutralization. Do not commit live evidence to this public repository.

## Result interpretation

| Exit | Terminal result | Meaning |
|---:|---|---|
| `0` | `COLLECTION COMPLETE` | All required technical collection and normalization completed |
| `1` | validation/scope error | The scan did not start or could not establish a safe scope |
| `3` | `COLLECTION INCOMPLETE` | At least one read failed, returned malformed data or the raw collector failed |

On exit `3`, the terminal prints the exact coverage file and, when present,
the collection-error file. Review `FAILED` rows before rerunning. An IAM denial
is evidence of missing visibility, not proof that the resource is absent.

`--inventory-only` remains accepted as a compatibility no-op. The former
`--ci-register`, `--approved-baseline` and `--monthly-review` options are
rejected because the simple collector does not perform governance decisions.

## Evidence still required to close Task 8

The technical snapshot is only one part of CM-2. The responsible configuration
authority must separately retain:

- an approved and owned CI register;
- the approved System Design Form/configuration baseline;
- a documented monthly comparison process;
- a completed and approved current monthly review;
- Remedy/CRQ, CCB and system-owner approvals for changes;
- exception records and corrective-action follow-up;
- Terraform/CD3 source and deployment evidence where applicable;
- in-guest operating-system, middleware and application settings;
- rule-level route, Security List and NSG evidence;
- the restricted evidence location, reviewer and retention record.

Until those records are produced and reconciled to this snapshot, Task 8
remains **Partial**, not audit-complete.
