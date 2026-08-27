# Implementation Handoff

**Updated:** 2026-08-27

**Working branch:** `codex/task1-audit-hardening`

**Base commit:** `b196f45f43d95add1480da2cc50aa852762ecba7`

**Current milestone:** Task 1 collector implementation complete; live OCI evidence pending

## What changed

### `cp09-03-backup-replication-check.sh`

- Added the same read-only `--selfcheck` boundary used by `cp09-01` and `cp09-02`.
- Added `-n` compartment-name filtering and `-o` output-directory support.
- Replaced command-substitution wrapper state with explicit captured OCI calls.
- Added `collection_status` and `collection_error` to every evidence row.
- Added a compartment-by-service coverage CSV.
- Added synthetic `COLLECTION-FAILED` rows when a primary service collection fails.
- A failed replica lookup now yields `replicated=UNKNOWN`, not a false `NO-REPLICA` finding.
- Retained the failed-call ledger and exit code `3` for incomplete runs.
- Reduced repeated API calls by collecting volume, boot-volume and FSS replica lists once per scope rather than once per asset.
- Added consistent support for both OCI list shapes: `.data[]` and `.data.items[]`.

### Regression tests

Added:

- `tests/mock-oci`
- `tests/test-cp09-03.sh`
- `tests/run.sh`

The mock exercises Object Storage, Block Volume, Boot Volume, volume backups,
FSS, Autonomous Database and Base DB. It also injects a `403` on the Block
Volume replica call and verifies all of the following:

- process exits `3`;
- the asset row is `DENIED` and `UNKNOWN`;
- coverage is `DENIED`;
- the failed-call ledger is retained;
- `NO-VOLUME-REPLICA` is not fabricated.

Latest local result:

```text
READ-ONLY SELF-CHECK: PASSED (cp09-01)
READ-ONLY SELF-CHECK: PASSED (cp09-02)
READ-ONLY SELF-CHECK: PASSED (cp09-03)
PASS: cp09-03 success and denied-collection regressions
PASS: CP-9 static, read-only and mock test suite
```

Run with:

```bash
bash tests/run.sh
```

### Legacy collectors

`backup-storage.sh` and `oci_backup_audit.py` are now explicitly marked
deprecated. They remain as reference implementations but are not canonical
evidence sources because they lack the CP-9 family's row-level collection
integrity.

## Do not overstate the milestone

Task 1 code is ready for a controlled OCI run. Task 1 is not audit-complete.
The following operational work remains:

1. Run all three CP-9 collectors in each required region.
2. Use the exact compartment names for VCN, Shared Services and CD3.
3. Treat exit `3`, non-OK rows and unresolved principals as incomplete evidence.
4. Review findings and document accepted exceptions/remediation owners.
5. Store outputs in the approved restricted evidence location.
6. Record the evidence reference, operator, reviewer, dates and approval.

Do not commit live OCI CSVs or screenshots to this public repository.

## Next implementation task for Claude

Continue with worksheet Task 2. Do not skip ahead to Task 6.

Target `in-transit-encryption.sh`:

1. Replace discarded stderr with the CP-9-style captured-call wrapper.
2. Add per-row `collection_status` and `collection_error`.
3. Add a compartment-by-service coverage ledger and exit code `3`.
4. Add Site-to-Site VPN evidence for CPEs, IPSec connections, tunnels, tunnel
   status, IKE/IPSec parameters, DRG attachment and relevant route context.
5. Add a manual screenshot/evidence checklist for tunnel console state,
   Base DB `sqlnet.ora`, FSS encrypted mounts and any backend TLS hidden by an NLB.
6. Add mock tests proving a denied IPSec/tunnel call cannot look like “no VPN”.
7. Update `MASTER-TASK-LIST.md`, `AUDIT.md` and this handoff when the milestone is done.

## Known later blocker

Task 6 has a confirmed baseline-ingestion defect in
`cm07-proof-opened-ports.sh`: the approved CSV is piped to `python3 -` while a
here-document simultaneously occupies Python's standard input. The CSV reader
therefore receives no baseline rows. Fix it during Task 6, not before Tasks 2–5.
