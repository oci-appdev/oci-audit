# Implementation Handoff

**Updated:** 2026-08-27

**Working branch:** `codex/task1-audit-hardening`

**Base commit:** `b196f45f43d95add1480da2cc50aa852762ecba7`

**Current milestone:** Tasks 1 and 2 collector implementations complete; live/manual evidence pending

**Draft PR:** <https://github.com/oci-appdev/oci-audit/pull/1>

## Mandatory scope-selection standard

Scripts `cp09-01`, `cp09-02`, `cp09-03` and `in-transit-encryption.sh` now
support `-i` / `--select-scope`. They discover the tenancy and active
compartments, display full OCIDs, require an exact discovered OCID and require
the same OCID again before starting service collection. A tenancy selection
means root plus every active child compartment. A mismatch exits before the
collector loop; script 03 and SC-8 have dedicated fail-closed regressions.

The shared implementation is `lib/oci-scope-selector.sh`; regression coverage
is in `tests/test-scope-selection.sh`.

Every new or materially redesigned collector must follow
`SCRIPT-DESIGN-STANDARD.md`. Preserve `-c`/`-n` for approved non-interactive
automation, but do not create a different interactive selection workflow.

## Latest milestone — Task 2

### `in-transit-encryption.sh`

- Replaced discarded stderr with current-shell captured calls.
- Added `collection_status` and `collection_error` to evidence rows.
- Added compartment-by-service coverage and failed-call CSVs.
- Added exit code `3` for any incomplete collection.
- Added `--selfcheck`, compartment-name filtering and output routing.
- Added confirmed tenancy/compartment discovery with exact double-OCID entry.
- Added Load Balancer backend-set SSL collection.
- Added CPE, IPSec connection, tunnel and DRG attachment/route context.
- Tunnel rows include lifecycle/status, IKE version, routing/BGP state,
  negotiated phase-one/phase-two algorithms and PFS.
- Both OCI tunnel objects are required per connection; any other successful
  count produces `IPSEC-TUNNEL-PAIR-INCOMPLETE`.
- The collector never retrieves an IPSec pre-shared key.

### Task 2 manual evidence

`TASK2-MANUAL-EVIDENCE-CHECKLIST.md` covers IPSec screenshots, Base DB
`sqlnet.ora`, encrypted FSS client mounts, NLB backend TLS, reconciliation,
evidence handling and reviewer sign-off.

### Task 2 regression gate

Added `tests/mock-oci-task2` and `tests/test-in-transit-encryption.sh`. The
success path exercises every Task 2 service and requires two independent IPSec
tunnel rows. A one-tunnel fixture must produce the incomplete-pair finding. The
denied path injects a 403 on the IPSec tunnel list and requires exit `3`, an
attributed `DENIED/COLLECTION-FAILED` row, denied coverage and an error ledger.
It also proves the failure cannot become `TUNNEL-DOWN`, `NO-IPSEC` or `NO-VPN`.

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
READ-ONLY SELF-CHECK: PASSED (in-transit-encryption)
PASS: cp09-03 success and denied-collection regressions
PASS: Task 2 two-tunnel, incomplete-pair and denied-IPSec regressions
PASS: CP-9 and SC-8 interactive scope discovery and OCID confirmation
PASS: CP-9 and SC-8 static, read-only and mock test suite
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

## Task 2 is not audit-complete

1. Run the collector in every in-scope region and exact worksheet compartment.
2. Require exit `0` and reconcile every coverage row and finding.
3. Complete `TASK2-MANUAL-EVIDENCE-CHECKLIST.md`.
4. Capture both IPSec tunnels, Base DB `sqlnet.ora`, FSS encrypted mounts and
   NLB backend TLS without capturing PSKs or other secrets.
5. Store and approve the package in the restricted evidence location.

Do not commit live OCI CSVs or screenshots to this public repository.

## Next implementation task for Claude

Continue with worksheet Task 3. Do not skip ahead to Task 6.

Target `sc28-oci-encryption-at-rest.sh`:

1. Adopt `lib/oci-scope-selector.sh` and the mandatory `-i` /
   `--select-scope` confirmation workflow.
2. Inventory its OCI calls and eliminate discarded errors.
3. Add row-level collection status/error and compartment-by-service coverage.
4. Add exit code `3` and an error ledger for incomplete collection.
5. Verify KMS key, vault/HSM, rotation and lifecycle evidence without exposing
   key material.
6. Add mock success and denied-call regressions.
7. Add the Task 3 manual evidence/reviewer checklist.
8. Update `MASTER-TASK-LIST.md`, `AUDIT.md` and this handoff when the milestone is done.

## Known later blocker

Task 6 has a confirmed baseline-ingestion defect in
`cm07-proof-opened-ports.sh`: the approved CSV is piped to `python3 -` while a
here-document simultaneously occupies Python's standard input. The CSV reader
therefore receives no baseline rows. Fix it during Task 6, not before Tasks 2–5.
