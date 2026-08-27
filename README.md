# OCI Audit Evidence Collectors

Read-only OCI collectors and supporting documentation for the OCS audit
worksheet. The scripts collect configuration facts; they do not make OCI
changes and they do not replace the required human approvals, screenshots,
monthly reviews, training records, or contingency exercises.

## Current position

- Tasks 1 and 2: implementation milestones complete on
  `codex/task1-audit-hardening`; live OCI evidence is still pending.
- Tasks 3, 6, 8 and 9: partial collectors exist.
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

Scripts 01, 02 and 03 can discover the authenticated tenancy and active
compartments, then require the selected OCID twice before service collection
starts:

```bash
bash cp09-01-backup-type-config-frequency.sh \
  --select-scope -r us-langley-1 -o ./evidence

bash cp09-02-backup-access-files-check.sh \
  --select-scope -r us-langley-1 -o ./evidence

bash cp09-03-backup-replication-check.sh \
  --select-scope -r us-langley-1 -o ./evidence
```

The short option is `-i`. Selecting the tenancy scans root plus every active
discovered child compartment. Selecting a compartment scans only that exact
OCID. A missing, unknown or mismatched confirmation exits before the collector
loop. Do not combine interactive selection with `-c` or `-n`.

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

`in-transit-encryption.sh` is the SC-8/SC-8(1)/SC-13 collector. It covers Load
Balancer frontend and backend TLS, NLB passthrough, Autonomous and Base
databases, Object Storage, volume attachments, FSS, API Gateway, OKE and the
Site-to-Site VPN chain (CPE, IPSec connection, tunnels and DRG attachment/route
context).

The collector uses only OCI list/get operations and intentionally never
retrieves an IPSec pre-shared key.

Run the read-only check:

```bash
bash in-transit-encryption.sh --selfcheck
```

Example GovCloud collection:

```bash
REGION=us-langley-1
SCOPE_NAMES='VCN,Shared Services,CD3'
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EVIDENCE_DIR="./evidence/${REGION}/${RUN_ID}"

mkdir -p "$EVIDENCE_DIR"

bash in-transit-encryption.sh \
  -r "$REGION" -n "$SCOPE_NAMES" -o "$EVIDENCE_DIR"
```

The run produces an evidence CSV and compartment-by-service coverage CSV. A
failed OCI call produces an attributed `COLLECTION-FAILED` row, a retained
error ledger and exit code `3`; it cannot be mistaken for an absent service or
down tunnel.

Complete the API evidence with
[TASK2-MANUAL-EVIDENCE-CHECKLIST.md](TASK2-MANUAL-EVIDENCE-CHECKLIST.md),
including IPSec tunnel screenshots, Base DB `sqlnet.ora`, encrypted FSS mounts
and backend TLS hidden by NLB passthrough.

## Tests

Run the repository regression suite with:

```bash
bash tests/run.sh
```

The suite performs Bash syntax and read-only checks for CP-9 and SC-8. It
exercises all seven `cp09-03` service paths and every Task 2 service path
against mock OCI CLIs. Denied-call regressions prove that unavailable replica
or IPSec tunnel data becomes an incomplete row and exit code `3`, never a
fabricated negative finding. Scope-selection regressions prove confirmed
compartment and tenancy scans plus fail-closed behavior on a mismatched OCID.

## Evidence handling

This repository is public. Do not commit generated evidence here. OCI evidence
can expose OCIDs, IAM memberships, network rules, database names and security
configuration. Store evidence in the approved restricted evidence location and
record its immutable reference, reviewer, review date and disposition in the
audit package.
