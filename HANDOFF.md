# Implementation Handoff

**Updated:** 2026-08-27

**Working branch:** `codex/task1-audit-hardening`

**Base commit:** `b196f45f43d95add1480da2cc50aa852762ecba7`

**Current milestone:** Tasks 1–3 collector implementations complete; live/manual evidence pending

**Draft PR:** <https://github.com/oci-appdev/oci-audit/pull/1>

## Mandatory scope-selection standard

Root-cause correction: the earlier CP-9 and SC-28 implementations only set
interactive mode when `-i`/`--select-scope` was present, while their regression
cases also passed that flag. That allowed the tests to pass even though a
normal command containing only region/output options silently used the old
tenancy-wide path. The option parser and tests now exercise the real no-scope-
flag operator command for every canonical collector.

Scripts `cp09-01`, `cp09-02`, `cp09-03`, `in-transit-encryption.sh` and
`sc28-oci-encryption-at-rest.sh` now default normal/manual runs to interactive
scope selection; `-i` / `--select-scope` are optional aliases. They discover
the tenancy and active compartments, display full OCIDs, require an exact
discovered OCID twice, print the resolved scan plan, and require exact uppercase
`YES` before workload-service collection. A tenancy selection means root plus
every active child compartment. Mismatch/refusal exits before the collector
loop, removes header-only CSVs and has dedicated fail-closed regressions for all
five collectors.

The shared implementation is `lib/oci-scope-selector.sh`; regression coverage
is in `tests/test-scope-selection.sh`.

Every new or materially redesigned collector must follow
`SCRIPT-DESIGN-STANDARD.md`. Preserve `-c`/`-n` for approved non-interactive
automation, but do not create a different interactive selection workflow.

## Latest safety hardening — SC-8

`SC08-SAFETY-REVIEW.md` records a second source-level review of
`in-transit-encryption.sh`:

- 27 OCI wrapper call sites parsed and restricted to `list`/`get`;
- `network ip-sec-psk get` explicitly prohibited and injection-tested;
- default interactive double-OCID, pre-scan summary and exact-`YES` gate;
- invalid compartment, ambiguous scope and unknown service failures before
  collection;
- successful CLI JSON syntax/shape validation to prevent false zero assets;
- secure temporary files, private/no-clobber/formula-safe CSV output;
- missing volume encryption fields remain unknown instead of false disabled;
- backend TLS peer-verification disabled is an explicit review finding.

Tests are in `tests/test-sc8-safety.sh`,
`tests/test-in-transit-encryption.sh` and `tests/test-scope-selection.sh`.
Static/mock review passed; live OCI evidence remains pending.

## Prior milestone — Task 3

### `sc28-oci-encryption-at-rest.sh`

- Replaced discarded stderr with current-shell captured calls.
- Added row-level `collection_status`/`collection_error`, a
  compartment-by-service coverage CSV and a failed-call CSV.
- Added exit code `3` for any incomplete collection.
- Added read-only `--selfcheck`, `-n`, `-o` and confirmed double-OCID scope
  selection.
- Covers Block/Boot Volumes, Object Storage, FSS, Autonomous DB, Base DB,
  MySQL, PostgreSQL, Vaults and KMS keys.
- Corrected MySQL to the current `encrypt-data.key-generation-type/key-id`
  model.
- Does not fabricate a PostgreSQL CMK field; records platform encryption and a
  manual key-custody boundary.
- Added Vault type/lifecycle/deletion and KMS key `get` plus key-version `list`
  evidence.
- KMS rows include HSM/software protection, AES key shape, lifecycle/deletion,
  auto-rotation interval/last/next/status and version counts.
- Never retrieves key material or secrets.

### Task 3 manual evidence

`TASK3-MANUAL-EVIDENCE-CHECKLIST.md` covers run integrity, CMK-to-key
reconciliation, HSM/AES-256, key administrators, pending deletion, OCI Audit
rotation proof, manual rotation procedures, evidence handling and sign-off.

### Task 3 regression gate

Added `tests/mock-oci-task3` and `tests/test-encryption-at-rest.sh`. The success
path exercises every service and requires HSM AES-256 automatic-rotation plus
version history. A rotation-failure fixture must emit
`AUTO-ROTATION-FAILED`. A denied KMS key-list fixture must exit `3`, retain an
error ledger and produce attributed `DENIED/COLLECTION-FAILED` evidence and
coverage; it cannot produce a fake no-keys result.

## Prior milestone — Task 2

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
READ-ONLY/NO-SECRET SELF-CHECK: PASSED (in-transit-encryption)
READ-ONLY SELF-CHECK: PASSED (sc28-oci-encryption-at-rest)
PASS: cp09-03 success and denied-collection regressions
Verified 27 SC-8 OCI wrapper calls: list/get only; no PSK retrieval
PASS: SC-8 static OCI action, mutation, secret and pre-scan validation gates
PASS: Task 2 integrity, TLS/IPSec findings and evidence-file safety regressions
PASS: SC-28 data-store, KMS rotation and failure-ledger evidence
PASS: CP-9, SC-8 and SC-28 default interactive scope, double-OCID and exact-YES gates
PASS: CP-9, SC-8 and SC-28 static, read-only and mock test suite
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
2. For an operator run, retain the double-OCID and approved pre-scan summary;
   exact uppercase `YES` must precede service calls.
3. Require exit `0` and reconcile every coverage row and finding.
4. Complete `TASK2-MANUAL-EVIDENCE-CHECKLIST.md`.
5. Capture both IPSec tunnels, Base DB `sqlnet.ora`, FSS encrypted mounts and
   NLB backend TLS without capturing PSKs or other secrets.
6. Store and approve the package in the restricted evidence location.

Do not commit live OCI CSVs or screenshots to this public repository.

## Task 3 is not audit-complete

1. Run the collector in every in-scope region and exact worksheet compartment.
2. Require exit `0` and reconcile every coverage row, CMK OCID and finding.
3. Complete `TASK3-MANUAL-EVIDENCE-CHECKLIST.md`.
4. Confirm key administrators, HSM/AES-256 posture, rotation schedule/history
   and OCI Audit proof; document any approved manual rotation process.
5. Store and approve the package in the restricted evidence location.

Do not commit live OCI CSVs, key-administrator identities or screenshots to
this public repository.

## Next implementation task for Claude

Skip worksheet Task 4 because it is N/A, then continue with Task 5. Do not skip
ahead to Task 6.

Task 5 target — Continuous Monitoring Form review/feedback:

1. Locate or obtain the current form; do not invent form fields that are not in
   the source artifact.
2. Review required monitoring sources, cadence, thresholds, owners,
   escalation, evidence retention and approval fields.
3. Add a feedback/disposition log with finding, recommendation, owner, due
   date, status and approver.
4. Retain the reviewed form version, reviewer/date and final approval evidence.
5. Update `MASTER-TASK-LIST.md`, `AUDIT.md` and this handoff when the milestone
   is done.

## Known later blocker

Task 6 has a confirmed baseline-ingestion defect in
`cm07-proof-opened-ports.sh`: the approved CSV is piped to `python3 -` while a
here-document simultaneously occupies Python's standard input. The CSV reader
therefore receives no baseline rows. Fix it during Task 6, not before Tasks 2–5.
