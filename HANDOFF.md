# Implementation Handoff

**Updated:** 2026-08-28

**Working branch:** `codex/task7-cm11-software-control`

**Base commit:** `882fe0be8f8a708ff0cd24fb9104d6f081ff0fbc`

**Current milestone:** Tasks 1–3 and Task 7 collector implementations complete; Task 6 corrective patch required; live/manual/approval evidence pending

**Pull request:** not opened for the Task 7 branch

## Mandatory scope-selection standard

Root-cause correction: the earlier CP-9 and SC-28 implementations only set
interactive mode when `-i`/`--select-scope` was present, while their regression
cases also passed that flag. That allowed the tests to pass even though a
normal command containing only region/output options silently used the old
tenancy-wide path. The option parser and tests now exercise the real no-scope-
flag operator command for every canonical collector.

Scripts `cp09-01`, `cp09-02`, `cp09-03`, `sc08-02-in-transit-encryption.sh`,
`sc28-oci-encryption-at-rest.sh`, `cm07-01-open-ports-protocols-services.sh` and
`cm11-01-software-installation-control.sh` now default normal/manual runs to interactive
scope selection; `-i` / `--select-scope` are optional aliases. They discover
the tenancy and active compartments, display full OCIDs, require an exact
discovered OCID twice, print the resolved scan plan, and require exact uppercase
`YES` before workload-service collection. A tenancy selection means root plus
every active child compartment. Mismatch/refusal exits before the collector
loop, removes header-only CSVs and has dedicated fail-closed regressions for all
seven collectors.

The shared implementation is `lib/oci-scope-selector.sh`; regression coverage
is in `tests/test-scope-selection.sh`.

Every new or materially redesigned collector must follow
`SCRIPT-DESIGN-STANDARD.md`. `-c`/`-n` alone are scope selectors, not proof of
automation approval. New collectors require explicit automation mode, exact
resolved-OCID confirmation values and exact `YES` approval.

## Latest milestone — Task 7 software installation control

The user directed Task 7 after the Task 6 CM-7 workflow. The canonical
collector is `cm11-01-software-installation-control.sh`; its evidence and manual
boundary guide is `TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md`.

The collector is read-only and separates three evidence sources:

- OCI technical facts: candidate IAM installer/provisioner/publisher grants,
  classic group members, OSMH packages/controls, Compute boot images and
  Container Registry images/repositories;
- the signed organizational list of authorized installer principals/users,
  including manager, request process, technical control and approval;
- the signed approved software/resource list and current authoritative
  restricted/prohibited list.

The normal command discovers the tenancy and active compartments, requires the
exact tenancy or compartment OCID twice, displays the complete plan and starts
only after exact uppercase `YES`. A manual `-c`/`-n` run confirms every
resolved OCID twice. Automation requires explicit `--non-interactive`, one
exact `--confirm-scope-ocid` per resolved target and exact
`--approve-scan YES`. The region is mandatory.

For a child workload compartment, policy listing includes the tenancy and
ancestor attachment compartments because parent policies can affect the child;
the workload inventory still remains within the confirmed target. All calls
are list/get, response shapes are validated, failed calls produce explicit
coverage/error evidence and outputs are private, no-clobber and formula-safe.

OCI IAM has no API that returns a fully evaluated effective-policy decision.
The post-processor in `lib/cm11-01-reconcile.py` preserves every statement and
labels installation classification as candidate evidence. It recognizes OSMH
package installation, Compute image/instance provisioning, Container Registry
publishing and the separately labeled Oracle-documented built-in Administrators
grant. It expands classic IAM groups to visible members, retains dynamic-group
rules and causes exit `3` when a referenced identity-domain group remains
unresolved.

The two-pass workflow first runs `--inventory-only`, then uses the generated
authorized-installer and approved-software templates plus the organization's
restricted list. Full reconciliation reports unauthorized candidate
entitlements, unapproved software drift and restricted/prohibited matches. The
input-source output records row counts, provider/authority/references/dates and
SHA-256 hashes.

OSMH installed packages are authoritative only for successfully collected
managed instances. Compute-to-OSMH ID mismatches are `NOT-VERIFIED`, not proof
that OSMH is absent. Identity Domains membership, SSH/sudo/local admins,
break-glass, unmanaged/Windows inventory, Kubernetes/Functions/deployment
runtimes and installation/change samples remain mandatory manual evidence.

Regression coverage is in
`tests/test-cm11-01-software-installation-control.sh` using
`tests/mock-oci-task7`. It covers the full three-source reconciliation,
prohibited Telnet, authorized entitlement expansion, input hashes, technical
controls, denied package calls, malformed list responses, formula safety,
manual/default/tenancy scope paths, refusal/mismatch before collection, strict
automation and identity-domain gaps. Both the Task 7 test and the full
repository suite pass on the staged Task 7 tree. Require GitHub Actions on the
exact published branch head before merge.

## Latest milestone — Task 6 open ports, protocols and services

**Corrective status:** Task 6 is Partial. Do not use CM07-01 as complete audit
evidence until the findings and acceptance gate in `CM07-CORRECTIVE-REVIEW.md`
are closed.

The user directed Task 6 implementation before Task 5. The canonical collector
is `cm07-01-open-ports-protocols-services.sh`.

It inventories Security Lists, NSGs, their rules and their subnet/VNIC
associations. It defaults to tenancy/compartment discovery, exact double-OCID
confirmation, a complete pre-scan summary and exact uppercase `YES`. Manual
`-c`/`-n` runs also confirm every resolved OCID twice and require `YES`.
Automation must explicitly provide `--non-interactive`, every resolved OCID and
`--approve-scan YES`. A mismatch or refusal reaches no Networking command and
leaves no evidence CSV. The region is mandatory evidence provenance.

The evidence workflow separates OCI facts from organizational attestations:

- OCI Network/Cloud Operations runs the live inventory.
- System/application owners complete the generated mapping for the actual OCI
  resource, listener status/address/port/protocol, service, function and
  justification, with verifier/date/evidence references.
- The designated CCB/PPSM/ISSO authority approves the exact rule baseline.
- The designated PPSM/security-policy owner supplies the restricted list.
- Input-source evidence records provider, authority, reference, dates and file
  SHA-256.

The collector emits failure-aware inventory, actual-service mapping template
and reconciliation, approval template/reconciliation, restricted findings,
source provenance, coverage and a retained error ledger. Missing service
mapping, approval or restricted inputs cause exit `3` unless
`--inventory-only` was explicitly selected. Future approval/verification dates,
reversed date ranges and incomplete live-rule service mappings fail closed.

Regression coverage is in `tests/test-cm07-01-open-ports.sh` with
`tests/mock-oci-task6`. It covers successful inventory/reconciliation,
restricted SSH, actual-service verification, missing/incomplete mappings,
future/reversed approval dates, both OCI list shapes, missing inputs, denied
NSG rules, malformed JSON, formula-safe CSV, compartment/tenancy expansion,
manual flag-based confirmation, explicit automation refusal, double-OCID
mismatch, lowercase-`yes` refusal and mixed-scope rejection.

The three older CM-7 scripts remain legacy references and are not canonical
evidence sources.

The expanded CM07-01 mock suite passes locally, but mock success did not expose
the cross-compartment coverage or ICMP restricted-match defects found during
controlled use and source review. The legacy `cm07-openports.sh` produced useful
live output; `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` did not. Use the
legacy query behavior only as a comparison fixture. Static validation still
confirms all OCI wrapper sites are restricted to list/get.


## Prior safety hardening — SC-8

`SC08-SAFETY-REVIEW.md` records a second source-level review of
`sc08-02-in-transit-encryption.sh`:

The collector now uses the canonical `SC08-02` filename and `sc08-02_...`
evidence prefix. The obsolete unprefixed script and regression-test paths were
removed from this branch.

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
`tests/test-sc08-02-in-transit-encryption.sh` and `tests/test-scope-selection.sh`.
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

### `sc08-02-in-transit-encryption.sh`

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

Added `tests/mock-oci-task2` and `tests/test-sc08-02-in-transit-encryption.sh`. The
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
READ-ONLY/NO-SECRET SELF-CHECK: PASSED (sc08-02-in-transit-encryption)
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

Task 7 implementation is complete on the local feature branch. Before new
implementation, publish the branch, run the full GitHub Actions gate on the
exact head, review the diff and merge only when the user requests it.

The immediate corrective item is Task 6. Patch CM07-01 according to
`CM07-CORRECTIVE-REVIEW.md`, extend the mock suite and complete known-object
compartment and tenancy runs before promoting it again. Do not allow an
unresolved cross-compartment association to produce `OK` coverage or an
inactive-container conclusion, and do not apply transport-port overlap to ICMP.

After that corrective gate, the next item in the user's recent Task 6 → Task 7 progression is Task 8 —
configuration baseline. A partial `cm08-hw-sw-baseline.sh` collector exists but
does not yet provide the full control workflow. The next implementation should:

1. identify the controlled configuration items and their owners;
2. ingest the approved System Design Form/configuration baseline rather than
   inventing baseline values;
3. compare live configuration to the signed baseline with change/exception
   disposition;
4. define and evidence the monthly review process, reviewer and approval;
5. adopt the strict OCID/plan/`YES`, failure-ledger, provenance and regression
   contract from CM07-01 and CM11-01.

Task 5 Continuous Monitoring Form review/feedback remains the earliest
unimplemented worksheet item because the user chose to advance Tasks 6 and 7
first. Do not represent it as complete; return to it when the user directs.

## Resolved Task 6 blocker

The legacy `cm07-proof-opened-ports.sh` stdin collision is superseded by the
canonical CM07-01 collector. Its post-processor receives the baseline path as
an argument and opens the CSV directly, while the embedded Python program alone
uses standard input.
