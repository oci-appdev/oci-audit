# Task 12 Account Management Evidence Guide

`ac02-01-account-management.py` is the canonical AC-2 technical inventory and
governance-reconciliation workflow. It collects OCI facts with Oracle's
official Python SDK and binds separately supplied organizational approvals to
stable account, membership and privilege keys.

The collector is read-only. A successful run does not authorize access, prove
employment status or remove an unused account.

## Evidence boundaries

| Source | What the collector establishes | What remains authoritative elsewhere |
|---|---|---|
| OCI classic IAM | Users, groups, direct memberships, dynamic groups, account capabilities and credential metadata | Manager, employment/contract status, business owner and approval |
| OCI Identity Domains | Users, groups, user group references, federation indicator, MFA status and available last-login metadata | Okta/DOJLogin provisioning, source-of-truth lifecycle and authentication assurance |
| OCI IAM policies | Current policy statements and principal/verb/resource/scope review candidates | Effective-access analysis, least-privilege decision and approval |
| OCI authentication policy and network sources | Current classic-IAM password/network-policy configuration facts | Identity Domain sign-on policy and external identity-provider settings |
| Governance CSV inputs | Exact approvals and lifecycle/inactivity procedures supplied by their owners | Authenticity of the cited ticket, policy, HR and approval records |

Credential collection is metadata-only: ID or API-key fingerprint, lifecycle
state, creation/expiration time and description. Passwords, private keys,
tokens, customer secrets, SMTP passwords, MFA seeds, recovery material and
SCIM password attributes are never written.

## Prerequisites

- Python 3 and the SDK version pinned in `requirements-oci-sdk.txt`.
- A config profile, instance principal or resource principal with approved
  read access.
- One explicit OCI region.
- A restricted evidence directory. Files contain identities, OCIDs,
  memberships, policy statements and approval references.
- Read access to classic IAM and Identity Domains. A denied source is recorded
  as a collection failure; it never becomes an empty/compliant result.

Install and verify:

```bash
python3 -m pip install -r requirements-oci-sdk.txt
python3 ac02-01-account-management.py --selfcheck
```

## Mandatory scope approval

A normal run discovers the tenancy and active compartments. Enter one exact
tenancy or compartment OCID twice. The script then prints the resolved target
set, identity and policy scope, every SDK operation, every governance input and
every output. Only exact uppercase `YES` starts account collection.

Selecting a tenancy confirms the root and every active discovered compartment.
Selecting a compartment limits policy attachment discovery to that compartment
plus its ancestors; account directories remain tenancy identity sources and
are identified as such in the pre-scan plan.

Manual `-c` and `-n` selections retain the same exact-OCID-twice and `YES`
steps. Approved automation must use `--non-interactive`, one exact
`--confirm-scope-ocid` for every resolved target and `--approve-scan YES`.

## Evidence lifecycle

Use a new output directory for every run. Evidence is immutable and the
collector refuses to overwrite an existing artifact.

### 1. Collect the technical snapshot

```bash
python3 ac02-01-account-management.py \
  -r us-langley-1 \
  -o ./evidence/task12-technical
```

Require `COLLECTION STATUS : COMPLETE`. Review the coverage and error ledgers
before using any generated templates.

### 2. Complete the five authority-owned inputs

Copy the generated templates into the approved evidence workspace and complete
them without changing their stable keys or headers.

| Input | Required owner/content |
|---|---|
| Account register | HR/service-account authority; type, manager, owner, lifecycle state, request and approval; authoritative activity or exception where applicable |
| Access approvals | Manager/access authority decision for each exact live membership and its current `reviewed_privilege_keys` set |
| Privilege review | Privilege owner and approver decision for every policy/built-in privilege candidate, including rationale |
| Inactivity policy | Approved threshold, unknown-activity action and removal SLA for every account type used by the register |
| Lifecycle procedure | Approved request, modification, deactivation, joiner/mover/leaver SLA and review-frequency references |

`account_type` is one of `HUMAN`, `SERVICE`, `BREAK-GLASS`, `FEDERATED` or
`GENERIC`. The collector does not infer this organizational classification.

### 3. Generate the reconciled monthly-review template

Run with the five completed inputs and omit `--monthly-review`:

```bash
python3 ac02-01-account-management.py \
  -r us-langley-1 \
  --account-register ./approved/ac02-account-register.csv \
  --access-approvals ./approved/ac02-access-approvals.csv \
  --privilege-review ./approved/ac02-privilege-review.csv \
  --inactivity-policy ./approved/ac02-inactivity-policy.csv \
  --lifecycle-procedure ./approved/ac02-lifecycle-procedure.csv \
  -o ./evidence/task12-review-prep
```

Exit `3` is expected because the required monthly review is deliberately
absent. Collection must still be `COMPLETE`. Resolve invalid inputs and open
reconciliation findings, then complete and approve the newly generated
`monthly_review_template.csv`. Do not use the technical-only run's review
template: its counts correctly show that approvals were not supplied.

The review binds to the exact snapshot SHA-256 and the current account, group,
membership, credential, privilege and finding counts. Any later account,
membership, policy or evidence change requires a new review template.

### 4. Produce the final governed package

```bash
python3 ac02-01-account-management.py \
  -r us-langley-1 \
  --account-register ./approved/ac02-account-register.csv \
  --access-approvals ./approved/ac02-access-approvals.csv \
  --privilege-review ./approved/ac02-privilege-review.csv \
  --inactivity-policy ./approved/ac02-inactivity-policy.csv \
  --lifecycle-procedure ./approved/ac02-lifecycle-procedure.csv \
  --monthly-review ./approved/ac02-monthly-review.csv \
  -o ./evidence/task12-final
```

Exit `0` requires complete technical collection, all six governance inputs,
valid exact-key reconciliation, no open account/access/privilege disposition
and a valid snapshot-bound monthly review. Manual evidence gaps may be tracked
as findings, but the approved review must cite their corrective-action record.

## Review the outputs

| Artifact group | Review purpose |
|---|---|
| `identity_domains`, `account_inventory`, `group_inventory`, `group_memberships` | Completeness, lifecycle state, federation/MFA/activity visibility and group access |
| `credential_metadata` | Active or stale non-password credential metadata; never secret values |
| `policy_statements`, `privilege_candidates` | Human least-privilege review; unresolved/ambiguous mappings require investigation |
| `authentication_policy`, `network_sources` | Classic IAM authentication restrictions |
| `account/access/privilege_reconciliation` | Exact approvals, drift, removal decisions and inactivity findings |
| `input_sources`, `input_validation` | Input hashes, row counts and validation failures |
| `snapshot_manifest`, `monthly_review_validation` | Immutable snapshot binding and review approval |
| `manual_evidence_gaps` | Required external coverage |
| `collection_coverage`, `collection_errors`, `summary` | Source completeness, failures and final status |

OCI policy syntax is preserved as evidence. The parser only extracts review
candidates for common allow statements. `UNPARSED`, `UNRESOLVED` and
`AMBIGUOUS` rows must be reviewed; they are not treated as no access. The
Administrators group is emitted as a separate Oracle-documented built-in
tenancy privilege candidate.

## Required manual completion

The final audit package also needs evidence for:

- authoritative workforce/contractor status and termination feed;
- Okta/DOJLogin provisioning and deprovisioning, if integrated (Task 13);
- host-local, SSH, sudo and local break-glass accounts;
- database-native users and roles;
- application and SaaS accounts;
- break-glass custody, activation, monitoring and post-use review;
- approvals and source documents referenced by every governance row.

Record immutable evidence references, reviewer, review date, dispositions and
approvals. Do not commit generated evidence to this public repository.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Technical collection is complete and either no governance input was requested or the complete governed package validated |
| 1 | The run did not start: invalid arguments/auth/scope/confirmation/input schema or output collision |
| 3 | Collection ran but a source failed, governance inputs are partial/invalid, reconciliation is open or the monthly review is absent/stale |

An exit code of `0` from a technical-only run means the SDK inventory
completed. It is not an authorization, compliance or account-removal decision.
