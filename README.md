# OCI Audit Evidence Collectors

Read-only OCI collectors and supporting documentation for the OCS audit
worksheet. The scripts collect configuration facts; they do not make OCI
changes and they do not replace the required human approvals, screenshots,
monthly reviews, training records, or contingency exercises.

## Current position

- Tasks 1, 2, 3, 7, 9 and 10: implementation milestones complete;
  live/approved evidence is still pending.
- Tasks 6 and 8: partial collectors exist; Task 6 has corrective blockers and
  Task 8 is now intentionally technical-collection-only.
- Tasks 5, 11–14 and 16–18: not yet implemented in this repository.
- Tasks 4 and 15: worksheet N/A.

See [MASTER-TASK-LIST.md](MASTER-TASK-LIST.md) for the control-by-control status
and [HANDOFF.md](HANDOFF.md) for the latest implementation handoff. All future
collector work must follow [SCRIPT-DESIGN-STANDARD.md](SCRIPT-DESIGN-STANDARD.md).

## Canonical Task 1 workflow

Use these three scripts together. Legacy `backup-storage.sh` and
`oci_backup_audit.py` are retained only for reference.

| Script | Evidence dimension |
|---|---|
| `cp09-01/cp09-01-backup-type-config-frequency.sh` | Backup configuration, type, schedule, retention and last successful backup |
| `cp09-02/cp09-02-backup-access-files-check.sh` | IAM grants, named principals, KMS custody, PARs and public/cross-tenancy exposure |
| `cp09-03/cp09-03-backup-replication-check.sh` | Replication, second copies, Data Guard, versioning and WORM posture |

### Prerequisites

- OCI CLI authenticated to the target tenancy
- `jq`
- Python 3
- Bash 4 or later
- Read-only IAM permissions covering the services being collected

Run the read-only verification before using the collectors:

```bash
bash cp09-01/cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02/cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03/cp09-03-backup-replication-check.sh --selfcheck
```

### Interactive scope discovery and confirmation

Scripts 01, 02 and 03 default to interactive scope discovery. They discover
the authenticated tenancy and active compartments, require the selected OCID
twice, display the complete resolved scan plan, and require exact uppercase
`YES` before service collection starts. The same mandatory interface is
implemented by the Task 2, Task 3, Task 6, Task 7, Task 8, Task 9 and Task 10 collectors:

Every canonical collector writes into its own collector-specific subdirectory
beneath the supplied output root, so `-o ./evidence` produces task-grouped
packages such as `./evidence/cp09-01/`, `./evidence/cm07-01/` and
`./evidence/ra05-01/`.

```bash
bash cp09-01/cp09-01-backup-type-config-frequency.sh \
  -r us-langley-1 -o ./evidence

bash cp09-02/cp09-02-backup-access-files-check.sh \
  -r us-langley-1 -o ./evidence

bash cp09-03/cp09-03-backup-replication-check.sh \
  -r us-langley-1 -o ./evidence
```

The explicit interactive options are `-i` and `--select-scope`, but neither is
required for a normal operator run. Selecting the tenancy scans root plus every
active discovered child compartment. Selecting a compartment scans only that
exact OCID. A missing/unknown/mismatched OCID or anything other than exact
uppercase `YES` exits before workload-service collection and removes
header-only evidence files. Do not combine interactive selection with `-c` or
`-n`.

The existing `-c` and `-n` modes remain available for approved non-interactive
automation.

Example GovCloud collection for the three audit scopes:

```bash
REGION=us-langley-1
SCOPE_NAMES='VCN,Shared Services,CD3'
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="./evidence/${REGION}/${RUN_ID}"

mkdir -p "$EVIDENCE_DIR"

bash cp09-01/cp09-01-backup-type-config-frequency.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"

bash cp09-02/cp09-02-backup-access-files-check.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"

bash cp09-03/cp09-03-backup-replication-check.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"
```

Use the exact compartment names from the tenancy. Repeat the collection in
every subscribed region that contains in-scope resources.

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | Collection completed without detected collection failures |
| 1 | The collector could not start or establish its required scope |
| 3 | Collection ran, but one or more calls or rows are incomplete |

An exit code of `0` means the collection completed. It does not mean the
tenancy passed the control. Review the findings and evidence rows separately.

## Canonical Task 2 workflow

`sc08-02/sc08-02-in-transit-encryption.sh` is the canonical SC08-02 SC-8/SC-8(1)/SC-13 collector. It covers Load
Balancer frontend and backend TLS, NLB passthrough, Autonomous and Base
databases, Object Storage, volume attachments, FSS, API Gateway, OKE and the
Site-to-Site VPN chain (CPE, IPSec connection, tunnels and DRG attachment/route
context).

The collector uses only OCI list/get operations and intentionally never calls
`network ip-sec-psk get`, the separate operation that retrieves an IPSec
pre-shared key. The full source and evidence-handling review is in
[sc08-02/SC08-SAFETY-REVIEW.md](sc08-02/SC08-SAFETY-REVIEW.md).

Run the read-only check:

```bash
bash sc08-02/sc08-02-in-transit-encryption.sh --selfcheck
```

No-argument execution is interactive by default. It discovers the tenancy and
active compartments, requires the exact selected OCID twice, displays the
complete scan plan and starts service collection only after exact uppercase
`YES`:

```bash
bash sc08-02/sc08-02-in-transit-encryption.sh \
  -r us-langley-1 -o ./evidence
```

`-i` and `--select-scope` explicitly select the same workflow. Selecting the
tenancy means root plus every active discovered compartment. A missing or
mismatched OCID, or anything other than exact uppercase `YES`, exits before the
first service call and removes header-only CSVs.

Example GovCloud collection:

```bash
REGION=us-langley-1
SCOPE_NAMES='VCN,Shared Services,CD3'
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="./evidence/${REGION}/${RUN_ID}"

mkdir -p "$EVIDENCE_DIR"

bash sc08-02/sc08-02-in-transit-encryption.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"
```

Explicit `-c` and `-n` are approved non-interactive automation modes. Their
resolved scan plan is printed to the job log, but they do not prompt.

The run produces an evidence CSV and compartment-by-service coverage CSV. A
failed OCI call produces an attributed `COLLECTION-FAILED` row, a retained
error ledger and exit code `3`; it cannot be mistaken for an absent service or
down tunnel. Successful CLI processes are also checked for valid, expected
JSON response shapes so a malformed response cannot become a false zero-asset
result. Generated CSVs use private permissions and neutralize spreadsheet
formula prefixes.

Each OCI Site-to-Site VPN connection is expected to expose two tunnel objects.
Both are collected independently. A successful tunnel list with a count other
than two produces `IPSEC-TUNNEL-PAIR-INCOMPLETE` for review.

Complete the API evidence with
[sc08-02/TASK2-MANUAL-EVIDENCE-CHECKLIST.md](sc08-02/TASK2-MANUAL-EVIDENCE-CHECKLIST.md),
including IPSec tunnel screenshots, Base DB `sqlnet.ora`, encrypted FSS mounts
and backend TLS hidden by NLB passthrough.

## Canonical Task 3 workflow

`sc28/sc28-oci-encryption-at-rest.sh` is the SC-28/SC-28(1)/SC-12 collector. It
covers Block and Boot Volumes, Object Storage, FSS, Autonomous and Base
databases, MySQL, OCI Database with PostgreSQL, Vaults, KMS key protection,
lifecycle, automatic-rotation metadata and key-version history.

The collector uses only list/get operations and never retrieves key material
or secrets. Run the source check first, then select and confirm the exact OCI
scope:

```bash
bash sc28/sc28-oci-encryption-at-rest.sh --selfcheck

bash sc28/sc28-oci-encryption-at-rest.sh \
  -r us-langley-1 -o ./evidence
```

The normal SC-28 command discovers the tenancy/compartments, requires the exact
selected OCID twice, prints all resolved targets/services/output files, and
requires exact uppercase `YES` before the first encryption-at-rest service
call.

For approved automation, use explicit `-c` or `-n` scope flags. Example:

```bash
bash sc28/sc28-oci-encryption-at-rest.sh \
  -r us-langley-1 -n 'VCN,Shared Services,CD3' -o ./evidence
```

The evidence distinguishes customer-managed and Oracle-managed data stores.
MySQL key custody is read from the current `encrypt-data` model. The current
PostgreSQL DB-system model does not expose an equivalent customer-key field, so
the row records platform encryption and requires manual custody verification
instead of inventing a key OCID.

KMS key rows include HSM/software protection, algorithm/length, lifecycle and
deletion posture, automatic-rotation schedule/status and key-version history.
A failed API call yields an attributed `COLLECTION-FAILED` row, non-OK coverage,
a retained error ledger and exit code `3`; it is never reported as an empty
service or absent key.

Complete the API evidence with
[sc28/TASK3-MANUAL-EVIDENCE-CHECKLIST.md](sc28/TASK3-MANUAL-EVIDENCE-CHECKLIST.md),
including key-administrator approval, AES-256/HSM validation, rotation Audit
logs, manual rotation procedure where applicable and reviewer sign-off.

## Canonical Task 6 workflow

> **Corrective status:** Do not use CM07-01 as complete audit evidence yet.
> Controlled use found cross-compartment coverage and ICMP restricted-match
> defects. See
> [cm07-01/CM07-CORRECTIVE-REVIEW.md](cm07-01/CM07-CORRECTIVE-REVIEW.md) for the findings and
> acceptance gate. The commands below document the intended interface pending
> correction and live validation.

`cm07-01/cm07-01-open-ports-protocols-services.sh` is the CM-7/CM-7(1)/PPSM
collector. It inventories Security List and NSG rules, Security List-to-subnet
associations and NSG-to-VNIC membership. It records OCI packet-filter facts,
common-service inference, accountable actual-service/listener verification,
approval reconciliation, restricted-list matches, input provenance and
collection coverage.

The normal command discovers the tenancy and active compartments, asks for the
exact tenancy or compartment OCID twice, prints the resolved plan and requires
exact uppercase `YES` before the first Networking service call:

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh --selfcheck

bash cm07-01/cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task6-inventory
```

Use the generated service-mapping template to have system/application owners
verify each actual resource, listener, service, function and justification. Use
the approval template to obtain the organization's CCB/PPSM/ISSO approval, and
obtain the restricted PPS list from the authoritative PPSM or enterprise
security-policy owner. Then run the complete reconciliation:

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  -a ./approved/cm07-approved-ports.csv \
  -x ./approved/cm07-restricted-ports.csv \
  -s ./approved/cm07-verified-services.csv \
  -o ./evidence/task6-final
```

Supplying `-c` or `-n` manually still requires every resolved OCID twice and
exact uppercase `YES`. Approved automation is explicit:

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh \
  -c ocid1.compartment... \
  --non-interactive \
  --confirm-scope-ocid ocid1.compartment... \
  --approve-scan YES \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task6-inventory
```

The script requires `-r`; it will not record an unresolved CLI-default region.

The collector does not ship a static list that could be mistaken for current
organizational policy. Both source CSVs record the authority, provider, source
reference and dates; the evidence package records their SHA-256 hashes.

An OCI rule permits traffic but does not prove that a host process is listening
or that the path is reachable. Complete the layered-control and actual-listener
checks in [cm07-01/TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md](cm07-01/TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md).

The older `cm07-openports.sh`, `cm07-ppsm.sh` and
`cm07-proof-opened-ports.sh` files are retained as legacy references. They
are not canonical evidence collectors because they suppress OCI errors and do
not enforce the mandatory scope-confirmation boundary.

## Canonical Task 7 workflow

`cm11-01/cm11-01-software-installation-control.sh` is the CM-11/CM-11(1) collector.
It keeps three evidence questions separate: candidate technical installation
capability, approved installed/available software resources, and current
restricted/prohibited software policy.

The read-only inventory includes:

- IAM policies attached to the target and ancestor compartments, classic IAM
  groups/members, dynamic-group rules and identity-domain boundaries;
- OS Management Hub managed instances and installed packages;
- Compute instance boot-image names, versions and exact image OCIDs;
- Container Registry repositories and images;
- OSMH software sources, managed-instance groups, lifecycle environments and
  scheduled jobs as technical-control evidence.

Start with an inventory-only run:

```bash
bash cm11-01/cm11-01-software-installation-control.sh --selfcheck

bash cm11-01/cm11-01-software-installation-control.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task7-inventory
```

The normal command discovers the tenancy and active compartments, asks for the
exact tenancy or compartment OCID twice, displays the complete plan and
requires exact uppercase `YES`. Manual `-c`/`-n` runs have the same approval
boundary. Approved automation requires `--non-interactive`, one exact
`--confirm-scope-ocid` for every resolved target and `--approve-scan YES`.
Use `-p/--profile` when the approved OCI CLI configuration uses a named
profile; the selected profile is printed in the plan.

The inventory run generates authorized-installer and approved-software
templates. Have the responsible system/IAM owners and configuration control
authority complete them, obtain the current restricted-software list from the
ISSO/designated policy owner, then run the reconciliation:

```bash
bash cm11-01/cm11-01-software-installation-control.sh \
  -r us-langley-1 \
  -u ./approved/cm11-authorized-installers.csv \
  -a ./approved/cm11-approved-software.csv \
  -x ./approved/cm11-restricted-software.csv \
  -o ./evidence/task7-final
```

OCI does not provide an API that returns fully evaluated effective IAM
permissions. The script transparently labels policy parsing as candidate
entitlement evidence and exits incomplete for referenced identity-domain groups
whose user membership was not collected. Complete the Identity Domains,
SSH/sudo/local-admin, break-glass, unmanaged-host and deployment-runtime checks
in
[cm11-01/TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md](cm11-01/TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md).

## Canonical Task 8 workflow

`cm02-01/cm02-01-configuration-baseline.sh` is now a simple CM-2 technical
configuration collector. It records the current visible OCI resources,
configuration attributes, fingerprints, per-operation coverage and collection
errors. It does not ingest approval files or perform governance reconciliation.

Run one guarded collection command:

```bash
bash cm02-01/cm02-01-configuration-baseline.sh --selfcheck

bash cm02-01/cm02-01-configuration-baseline.sh \
  -r us-langley-1 \
  -o ./evidence/task8-technical-snapshot
```

The command defaults to discovered tenancy/compartment selection, requires the
exact OCID twice, displays the complete scope/profile/work/output plan and
requires exact uppercase `YES`. Manual `-c`/`-n` uses the same confirmation;
automation requires explicit `--non-interactive`, matching confirmation OCIDs
and `--approve-scan YES`.

Successful collection exits `0` and prints `COLLECTION COMPLETE`. Exit `3`
means at least one read-only OCI operation failed or returned unusable data;
the terminal prints the exact coverage/error paths to review. The legacy
`--inventory-only` flag remains a harmless compatibility alias. The former
`--ci-register`, `--approved-baseline` and `--monthly-review` flags are rejected
because the simplified script no longer makes organizational approval claims.

CM02-01 invokes `cm08-01/cm08-hw-sw-baseline.sh` only after operator approval and
normalizes live CIs/attributes into private, formula-safe evidence. A technical
snapshot alone does not satisfy the worksheet's approved System Design Form,
baseline or monthly-review requirements.
See
[cm02-01/TASK8-CONFIGURATION-BASELINE-EVIDENCE-GUIDE.md](cm02-01/TASK8-CONFIGURATION-BASELINE-EVIDENCE-GUIDE.md)
for output interpretation and the remaining manual governance evidence.

## Canonical Task 9 workflow

`cm08-01/cm08-01-component-inventory-baseline.sh` is the CM-8/CM-8(1) system-component
inventory workflow. It keeps the current technical snapshot, the
organization-approved prior inventory, monthly additions/removals/changes,
their dispositions, coverage gaps and the signed monthly review separate.

Start with a guarded inventory-only run:

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh --selfcheck

bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task9-inventory
```

The normal command discovers tenancy/compartment scopes, requires the exact
OCID twice, discloses installed-package volume and all evidence work/outputs,
and requires exact uppercase `YES`. Manual `-c`/`-n` uses the same gate.
Automation requires `--non-interactive`, every exact confirmation OCID and
`--approve-scan YES`.

After approving the current inventory, compare a later scan to the prior
approved version. The first comparison can omit dispositions/review and exit
`3` while creating exact current templates:

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  -b ./approved/cm08-component-inventory-prior.csv \
  -o ./evidence/task9-pending
```

Disposition every `ADDED`, `REMOVED` and `CHANGED` row, complete the generated
count-bound monthly review, then run the final package:

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  -b ./approved/cm08-component-inventory-prior.csv \
  -d ./approved/cm08-change-dispositions.csv \
  -m ./approved/cm08-monthly-review.csv \
  -o ./evidence/task9-final
```

The workflow always collects installed-package detail where OS Management Hub
permits it and explicitly records guest, OKE-node, image-digest and
provider-physical-layer visibility limits. The shared raw CM08 engine refuses
direct execution and accepts only a wrapper-approved caller/scope/region plus
runtime-allowlisted read actions. See
[cm08-01/TASK9-COMPONENT-INVENTORY-EVIDENCE-GUIDE.md](cm08-01/TASK9-COMPONENT-INVENTORY-EVIDENCE-GUIDE.md)
for the monthly lifecycle and evidence boundaries.

## Canonical Task 10 workflow

`ra05-01/ra05-01-vulnerability-tracking.py` is the RA-5/SI-2 host and container
vulnerability workflow and the first collector built on Oracle's official OCI
Python SDK standard. Install the reviewed SDK version in an approved virtual
environment when it is not already present:

```bash
python3 -m pip install -r ra05-01/requirements-oci-sdk.txt
python3 ra05-01/ra05-01-vulnerability-tracking.py --selfcheck
```

Start with a guarded technical collection:

```bash
python3 ra05-01/ra05-01-vulnerability-tracking.py \
  -r us-langley-1 \
  -o ./evidence/task10-inventory
```

The collector uses generated Identity, Compute, Artifacts and Vulnerability
Scanning clients, Oracle pagination and Oracle retries. Its runtime method
allowlist contains only required `list_*` and `get_*` operations. The normal
command requires an exact tenancy/compartment OCID twice, prints every target,
SDK operation and output, then requires exact uppercase `YES`.

The first run generates organization-owned SLA and remediation tracker
templates. After supplying the approved SLA and completed tracker, run once
without `--monthly-review`; the expected exit `3` produces the reconciled,
current-count monthly-review template. After approval, supply all three inputs
for the governed package:

```bash
python3 ra05-01/ra05-01-vulnerability-tracking.py \
  -r us-langley-1 \
  --sla-policy ./approved/ra05-sla-policy.csv \
  --remediation-tracker ./approved/ra05-remediation-tracker.csv \
  --monthly-review ./approved/ra05-monthly-review.csv \
  -o ./evidence/task10-final
```

The workflow uses stable finding keys, validates owners/tickets/follow-up and
exceptions, calculates due dates only from the supplied approved SLA, and
binds the monthly review to exact snapshot SHA-256 and counts. See
[ra05-01/TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md](ra05-01/TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md)
for the full run/review sequence and non-VSS coverage requirements.

## Tests

Run the repository regression suite with:

```bash
bash tests/run.sh
```

The suite performs Bash/Python syntax and read-only checks for CP-9, SC-8,
SC-28, CM-7, CM-11, CM-2, CM-8 and RA-5. It
exercises all seven `cp09-03` service paths and every Task 2 service path
against mock OCI CLIs. The SC-8 safety gate independently parses all 27 OCI
wrapper call sites, injects prohibited mutation/PSK calls, proves default
interactive plan approval/refusal, checks malformed response handling and
validates private/formula-safe CSV output. Task 3 exercises all data-store/KMS paths, the current
MySQL and PostgreSQL schemas, rotation success/failure and a denied key-list
call. Task 2 requires both IPSec tunnels and separately proves the
incomplete-pair finding. Denied-call regressions prove that unavailable replica,
IPSec tunnel or KMS key data becomes an incomplete row and exit code `3`, never
a fabricated negative finding. Scope-selection regressions prove confirmed
compartment and tenancy scans plus fail-closed behavior on a mismatched OCID.
CM07-01 regressions cover rule/association inventory, input provenance,
approval reconciliation, restricted-list matches, denied calls, malformed JSON,
private/formula-safe evidence and exact-OCID/exact-`YES` refusal gates.
CM11-01 regressions cover IAM entitlement expansion, package/image inventory,
installer and software approval reconciliation, prohibited-software matches,
OSMH control coverage, denied/malformed calls, identity-domain gaps,
private/formula-safe output, tenancy expansion and fail-closed manual/automation
approval.
CM02-01 regressions cover the one-command technical snapshot, clear
complete/incomplete results, denied collection, named profiles, formula-safe
raw/canonical CSVs, image ownership attribution, tenancy/compartment
confirmation, legacy-governance flag rejection and refusal before workload
collection.
CM08-01 regressions cover inventory/template generation, stable component
identity, approved prior-inventory matching, exact addition/removal/change
dispositions, count-bound monthly review, guest/provider coverage gaps, denied
collection, installed-package/profile propagation, formula safety and all
manual/automation scope refusal paths.
RA05-01 regressions mock Oracle SDK clients and prove official pagination,
host/container CVE and package extraction, cross-compartment scan-target
resolution, conservative exact-scope evidence, structured service failures,
private/formula-safe output, double-OCID/plan/`YES` refusal, strict automation,
approved SLA ingestion, stable-key remediation reconciliation and exact
snapshot/count-bound monthly review validation.

## Evidence handling

This repository is public. Do not commit generated evidence here. OCI evidence
can expose OCIDs, IAM memberships, network rules, database names and security
configuration. Store evidence in the approved restricted evidence location and
record its immutable reference, reviewer, review date and disposition in the
audit package.
