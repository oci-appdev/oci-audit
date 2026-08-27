# OCI Audit Evidence Collectors

Read-only OCI collectors and supporting documentation for the OCS audit
worksheet. The scripts collect configuration facts; they do not make OCI
changes and they do not replace the required human approvals, screenshots,
monthly reviews, training records, or contingency exercises.

## Current position

- Task 1, backup type/frequency/access/replication: implementation milestone
  complete on `codex/task1-audit-hardening`; live OCI evidence is still pending.
- Tasks 2, 3, 6, 8 and 9: partial collectors exist.
- Tasks 5, 7, 10–14 and 16–18: not yet implemented in this repository.
- Tasks 4 and 15: worksheet N/A.

See [MASTER-TASK-LIST.md](MASTER-TASK-LIST.md) for the control-by-control status
and [HANDOFF.md](HANDOFF.md) for the latest implementation handoff.

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
- Bash 4 or later
- Read-only IAM permissions covering the services being collected

Run the read-only verification before using the collectors:

```bash
bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
```

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

## Tests

Run the repository CP-9 regression suite with:

```bash
bash tests/run.sh
```

The suite performs Bash syntax checks, executes the read-only self-check on all
three CP-9 collectors, exercises all seven `cp09-03` service paths against a
mock OCI CLI, and proves that a denied replica call becomes an incomplete row
and exit code `3` instead of a false `NO-REPLICA` result.

## Evidence handling

This repository is public. Do not commit generated evidence here. OCI evidence
can expose OCIDs, IAM memberships, network rules, database names and security
configuration. Store evidence in the approved restricted evidence location and
record its immutable reference, reviewer, review date and disposition in the
audit package.
