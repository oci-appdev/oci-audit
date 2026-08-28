# OCI Audit Evidence Collectors

Read-only OCI collectors and supporting documentation for the OCS audit
worksheet. The scripts collect configuration facts; they do not make OCI
changes and they do not replace the required human approvals, screenshots,
monthly reviews, training records, or contingency exercises.

## Current position

- Tasks 1, 2, 3 and 6: implementation milestones complete on `main`;
  live/approved evidence is still pending.
- Tasks 8 and 9: partial collectors exist.
- Tasks 5, 7, 10–14 and 16–18: not yet implemented in this repository.
- Tasks 4 and 15: worksheet N/A.

See [MASTER-TASK-LIST.md](MASTER-TASK-LIST.md) for the control-by-control status
and [HANDOFF.md](HANDOFF.md) for the latest implementation handoff. All future
collector work must follow [SCRIPT-DESIGN-STANDARD.md](SCRIPT-DESIGN-STANDARD.md).

## Canonical Task 1 workflow

Use these three scripts together. Legacy `backup-storage.sh` and
`oci_backup_audit.py` are retained only for reference.

| Script | Evidence dimension |
|---|---|
| `cp09-01-backup-type-config-frequency.sh` | Backup configuration, type, schedule, retention and last successful backup |
| `cp09-02-backup-access-files-check.sh` | IAM grants, named principals, KMS custody, PARs and public/cross-tenancy exposure |
| `cp09-03-backup-replication-check.sh` | Replication, second copies, Data Guard, versioning and WORM posture |

### Prerequisites

- OCI CLI authenticated to the target tenancy
- `jq`
- Python 3
- Bash 4 or later
- Read-only IAM permissions covering the services being collected

Run the read-only verification before using the collectors:

```bash
bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
```

### Interactive scope discovery and confirmation

Scripts 01, 02 and 03 default to interactive scope discovery. They discover
the authenticated tenancy and active compartments, require the selected OCID
twice, display the complete resolved scan plan, and require exact uppercase
`YES` before service collection starts. The same mandatory interface is
implemented by the Task 2, Task 3 and Task 6 collectors:

```bash
bash cp09-01-backup-type-config-frequency.sh \
  -r us-langley-1 -o ./evidence

bash cp09-02-backup-access-files-check.sh \
  -r us-langley-1 -o ./evidence

bash cp09-03-backup-replication-check.sh \
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

bash cp09-01-backup-type-config-frequency.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"

bash cp09-02-backup-access-files-check.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"

bash cp09-03-backup-replication-check.sh \
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

`sc08-02-in-transit-encryption.sh` is the canonical SC08-02 SC-8/SC-8(1)/SC-13 collector. It covers Load
Balancer frontend and backend TLS, NLB passthrough, Autonomous and Base
databases, Object Storage, volume attachments, FSS, API Gateway, OKE and the
Site-to-Site VPN chain (CPE, IPSec connection, tunnels and DRG attachment/route
context).

The collector uses only OCI list/get operations and intentionally never calls
`network ip-sec-psk get`, the separate operation that retrieves an IPSec
pre-shared key. The full source and evidence-handling review is in
[SC08-SAFETY-REVIEW.md](SC08-SAFETY-REVIEW.md).

Run the read-only check:

```bash
bash sc08-02-in-transit-encryption.sh --selfcheck
```

No-argument execution is interactive by default. It discovers the tenancy and
active compartments, requires the exact selected OCID twice, displays the
complete scan plan and starts service collection only after exact uppercase
`YES`:

```bash
bash sc08-02-in-transit-encryption.sh \
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

bash sc08-02-in-transit-encryption.sh \
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
[TASK2-MANUAL-EVIDENCE-CHECKLIST.md](TASK2-MANUAL-EVIDENCE-CHECKLIST.md),
including IPSec tunnel screenshots, Base DB `sqlnet.ora`, encrypted FSS mounts
and backend TLS hidden by NLB passthrough.

## Canonical Task 3 workflow

`sc28-oci-encryption-at-rest.sh` is the SC-28/SC-28(1)/SC-12 collector. It
covers Block and Boot Volumes, Object Storage, FSS, Autonomous and Base
databases, MySQL, OCI Database with PostgreSQL, Vaults, KMS key protection,
lifecycle, automatic-rotation metadata and key-version history.

The collector uses only list/get operations and never retrieves key material
or secrets. Run the source check first, then select and confirm the exact OCI
scope:

```bash
bash sc28-oci-encryption-at-rest.sh --selfcheck

bash sc28-oci-encryption-at-rest.sh \
  -r us-langley-1 -o ./evidence
```

The normal SC-28 command discovers the tenancy/compartments, requires the exact
selected OCID twice, prints all resolved targets/services/output files, and
requires exact uppercase `YES` before the first encryption-at-rest service
call.

For approved automation, use explicit `-c` or `-n` scope flags. Example:

```bash
bash sc28-oci-encryption-at-rest.sh \
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
[TASK3-MANUAL-EVIDENCE-CHECKLIST.md](TASK3-MANUAL-EVIDENCE-CHECKLIST.md),
including key-administrator approval, AES-256/HSM validation, rotation Audit
logs, manual rotation procedure where applicable and reviewer sign-off.

## Canonical Task 6 workflow

`cm07-01-open-ports-protocols-services.sh` is the CM-7/CM-7(1)/PPSM
collector. It inventories Security List and NSG rules, Security List-to-subnet
associations and NSG-to-VNIC membership. It records OCI packet-filter facts,
common-service inference, accountable actual-service/listener verification,
approval reconciliation, restricted-list matches, input provenance and
collection coverage.

The normal command discovers the tenancy and active compartments, asks for the
exact tenancy or compartment OCID twice, prints the resolved plan and requires
exact uppercase `YES` before the first Networking service call:

```bash
bash cm07-01-open-ports-protocols-services.sh --selfcheck

bash cm07-01-open-ports-protocols-services.sh \
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
bash cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  -a ./approved/cm07-approved-ports.csv \
  -x ./approved/cm07-restricted-ports.csv \
  -s ./approved/cm07-verified-services.csv \
  -o ./evidence/task6-final
```

Supplying `-c` or `-n` manually still requires every resolved OCID twice and
exact uppercase `YES`. Approved automation is explicit:

```bash
bash cm07-01-open-ports-protocols-services.sh \
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
checks in [TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md](TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md).

The older `cm07-openports.sh`, `cm07-ppsm.sh` and
`cm07-proof-opened-ports.sh` files are retained as legacy references. They
are not canonical evidence collectors because they suppress OCI errors and do
not enforce the mandatory scope-confirmation boundary.

## Tests

Run the repository regression suite with:

```bash
bash tests/run.sh
```

The suite performs Bash syntax and read-only checks for CP-9, SC-8, SC-28 and CM-7. It
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

## Evidence handling

This repository is public. Do not commit generated evidence here. OCI evidence
can expose OCIDs, IAM memberships, network rules, database names and security
configuration. Store evidence in the approved restricted evidence location and
record its immutable reference, reviewer, review date and disposition in the
audit package.
