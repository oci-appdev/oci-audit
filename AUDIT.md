# OCI Audit Implementation Review

**Last updated:** 2026-08-28

**Current branch:** `main`

**Master tracker:** `MASTER-TASK-LIST.md`

**Continuation notes:** `HANDOFF.md`

## Current audit position

Tasks 1, 2, 3 and 6 now have implementation-complete collector workflows and
reproducible mock gates ready for controlled OCI runs. None is
audit-complete: live CSVs, Task 2 manual/screenshotted proof, Task 3 key
custody/rotation proof, reviewer
disposition, evidence-location references and approval records have not been
produced in this repository.

The remaining worksheet position is tracked in `MASTER-TASK-LIST.md`. Continue
in worksheet order. After Tasks 1–3 operational evidence, Task 4 is N/A and
Task 5 is the next implementation target.

On 2026-08-28 the Task 2 collector was normalized to the canonical
`sc08-02-in-transit-encryption.sh` name. Its evidence artifacts now use the
`sc08-02_...` prefix, and the obsolete unprefixed script/test paths were
removed; the collector's read-only and no-secret safety boundary is unchanged.

---

## 2026-08-28 — Task 6 CM-7/PPSM open-port evidence workflow

The three older CM-7 scripts collected useful rule data, but each suppressed
OCI stderr. A denied VCN, Security List or NSG call could therefore look like
an empty network surface. They also lacked the mandatory tenancy/compartment
OCID confirmation and used separate inventory, restricted-list and approval
paths. The approval script had a confirmed stdin collision: a pipeline supplied
the baseline CSV while a Python here-document simultaneously occupied stdin,
so no baseline rows reached the CSV reader.

`cm07-01-open-ports-protocols-services.sh` is now the canonical Task 6
collector. It:

- defaults manual runs to discovered tenancy/compartment selection, requires the
  exact selected OCID twice, prints every target/input/output and requires exact
  uppercase `YES` before the first Networking call;
- uses only OCI list/get operations and has a source-level read-only self-check;
- inventories Security List and NSG rules, Security List-to-subnet associations
  and NSG-to-VNIC membership;
- validates successful JSON response shapes and turns denied/failed calls into
  failed coverage, explicit inventory gaps, an error ledger and exit code `3`;
- produces a normalized approval template and reconciles live rules to signed
  approval rows without the prior stdin collision;
- requires approval authority, approver, approval ID/date, business function,
  justification and source reference before an approved match is accepted;
- matches live rules to an externally supplied authoritative restricted list;
- records who supplied both lists, their authority/source/dates and SHA-256
  hashes;
- creates private, no-clobber, spreadsheet-formula-safe evidence;
- labels missing approval/restricted inputs as incomplete unless the operator
  explicitly selected inventory-only mode.

No built-in restricted list is treated as authoritative. The designated
PPSM/security-policy owner must provide the current list, and the designated
CCB/PPSM/ISSO authority must approve the exact live-rule baseline.

The collector records OCI packet-filter permissions, not actual listening
processes or end-to-end reachability. Routes, IP addressing, OCI Network
Firewall, ZPR, load-balancer listeners, host firewalls and application
configuration remain manual reconciliation boundaries documented in
`TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md`.

---

## 2026-08-27 — SC-8 pre-scan authorization and safety review

A second source-level safety review of `sc08-02-in-transit-encryption.sh` verified 27
OCI wrapper call sites. All are `list`/`get`, and none retrieves the separate
IPSec shared-secret object. The review also found that the previous
no-argument path immediately expanded to a tenancy scan and that the original
self-check could miss a mutating command introduced through `oci_capture`.

The SC-8 collector now:

- defaults no-argument/manual runs to interactive discovery;
- requires exact discovered tenancy/compartment OCID entry twice;
- displays region, selected scope, every target compartment, requested
  services, local outputs and evidence sensitivity before service collection;
- requires exact uppercase `YES` after that summary and removes header-only
  outputs on refusal;
- retains explicit `-c`/`-n` for approved non-interactive jobs and prints the
  resolved plan to their logs;
- rejects invalid compartment OCIDs, ambiguous `-c`/`-n` combinations and
  unknown service tokens before collection;
- validates successful list/get JSON response shapes so malformed output cannot
  become a false zero-resource result;
- explicitly prohibits `network ip-sec-psk get` in both the self-check and an
  injection regression;
- uses secure temporary files, private output permissions, no-clobber output
  creation and CSV formula neutralization;
- reports missing volume encryption fields as unknown/review rather than
  fabricating a disabled result;
- reports backend TLS with peer verification disabled as a review finding.

`SC08-SAFETY-REVIEW.md` records the complete review, command inventory,
resolved findings, local-write boundary and remaining manual evidence.

---

## 2026-08-27 — Task 3 SC-28 encryption-at-rest integrity and KMS evidence

The original `sc28-oci-encryption-at-rest.sh` discarded stderr for every OCI
call. A permission denial therefore looked like an empty service or absent key.
It also used obsolete/nonexistent MySQL and PostgreSQL key paths and listed KMS
keys without collecting the full key or version metadata needed to prove
protection and rotation posture.

The collector now:

- performs a source-level read-only self-check and uses only list/get calls;
- implements the mandatory tenancy/compartment discovery and double-OCID
  confirmation boundary;
- records row-level collection status/error, compartment/service coverage and
  a retained failed-call ledger, exiting `3` when collection is incomplete;
- covers Block/Boot Volumes, Object Storage, FSS, Autonomous DB, Base DB,
  MySQL, OCI Database with PostgreSQL, Vaults and KMS keys;
- reads MySQL custody from `encrypt-data.key-generation-type/key-id`;
- records PostgreSQL platform encryption and a manual custody boundary because
  the current DB-system API does not expose an equivalent customer-key field;
- records Vault type, lifecycle, deletion schedule and management endpoint;
- calls KMS key `get` plus key-version `list` and records HSM/software
  protection, algorithm/length, lifecycle/deletion, automatic rotation
  interval/last/next/status and version history;
- treats pending deletion, disabled/unexpected key state, software keys,
  non-AES-256 shape and failed/unconfirmed rotation as explicit findings;
- never retrieves key material, secrets or protected configuration values.

`TASK3-MANUAL-EVIDENCE-CHECKLIST.md` defines the required CMK reconciliation,
key administrator approval, HSM/AES-256 review, OCI Audit rotation proof,
manual rotation procedure, evidence integrity and sign-off package.

The Task 3 mock suite exercises every service path, automatic rotation success
and failure, and a 403 on KMS key listing. The denied case must exit `3`, retain
the error ledger and produce `DENIED/COLLECTION-FAILED` evidence and coverage;
it is forbidden from reporting the result as no keys.

---

## 2026-08-27 — Task 2 SC-8 collection integrity and IPSec coverage

The original `sc08-02-in-transit-encryption.sh` discarded stderr for every OCI call.
A permission denial therefore looked exactly like an empty service. It also
claimed Load Balancer backend coverage without collecting backend sets and had
no Site-to-Site VPN evidence.

The collector now:

- performs a source-level read-only self-check and uses only list/get calls;
- records `collection_status` and `collection_error` on every evidence row;
- produces a compartment-by-service coverage ledger and failed-call ledger;
- exits `3` when collection is incomplete;
- distinguishes missing data from a verified zero-resource result;
- collects Load Balancer listeners and backend-set SSL independently;
- covers CPEs, IPSec connections, tunnel lifecycle/status, IKE version,
  routing/BGP state, negotiated phase-one/phase-two parameters and PFS;
- collects both OCI tunnel objects independently and flags any connection that
  does not return exactly two tunnels as `IPSEC-TUNNEL-PAIR-INCOMPLETE`;
- records DRG attachment, route-table and attached-network context;
- never requests or exposes an IPSec pre-shared key;
- retains manual-evidence boundaries for NLB backend TLS, Base DB `sqlnet.ora`
  and FSS encrypted client mounts.

`TASK2-MANUAL-EVIDENCE-CHECKLIST.md` defines the screenshot/config package and
review sign-off required to close those boundaries.

The regression suite exercises every Task 2 service path. A denied tunnel-list
call must yield exit `3`, a `DENIED/COLLECTION-FAILED` IPSec tunnel row, denied
coverage and a retained error ledger. It is forbidden from producing
`TUNNEL-DOWN`, `NO-IPSEC` or `NO-VPN`.

---

## 2026-08-27 — default interactive OCI scope and final approval standard

Follow-up testing found that CP-9 scripts 01–03 and SC-28 previously entered
interactive mode only when `-i`/`--select-scope` was supplied. Their tests
supplied the same flag, so they did not detect that a normal region/output-only
operator command bypassed the prompt. This was a real implementation and test
gap, not an operator error.

All three CP-9 collectors plus the SC-8 and SC-28 encryption collectors now
default normal/manual runs to interactive discovery. `-i` / `--select-scope`
remain explicit aliases. The scripts discover the authenticated tenancy and
active subtree compartments, show the full name/OCID catalog, require an exact
discovered OCID twice, display the resolved targets/work/output plan, then
require exact uppercase `YES`. Selecting the tenancy explicitly means root plus
all active child compartments.

The selector rejects unknown OCIDs, mismatched confirmation and combinations
with `-c` or `-n`. Regression coverage proves every collector refuses lowercase
`yes` before any workload call and removes header-only CSVs. Existing explicit
`-c`/`-n` scope flags remain available for approved automation and print the
resolved plan to the job log without prompting.

`SCRIPT-DESIGN-STANDARD.md` makes this interface mandatory for every new or
materially redesigned collector. The shared behavior lives in
`lib/oci-scope-selector.sh` so future scripts do not invent a different prompt
or confirmation boundary.

---

## Original SDK collector review

**Script:** `oci_backup_audit.py`

**Original review date:** 2026-07-14

**Original reviewer:** Copilot Audit Agent

---

## Summary

The script is a **tenancy-wide backup/snapshot posture audit** tool. Its stated design is read-only: it iterates all active compartments and **reports** on backup/snapshot configuration across multiple OCI services. It produces a console summary and a timestamped CSV file written locally.

---

## ✅ Read-Only Operations (expected)

The script reports on the following services using only `list_*` / `get_*` OCI SDK calls (HTTP GET — no side effects):

| Service | What Is Read |
|---|---|
| Block / Boot Volumes | Backup policies, policy asset assignments |
| Base DB Systems | Backup configs, backup schedules |
| Autonomous DB | Backup configs |
| File Storage (FSS) | Snapshot policies |
| Object Storage | Lifecycle policies, replication rules, retention rules |
| MySQL | Backup configs |
| PostgreSQL | Backup configs |

---

## ⚠️ Verification Checklist

Before running in any environment, confirm the following in the script source:

- [ ] Only `list_*`, `get_*`, `search_*` OCI SDK methods are used — no `create_*`, `update_*`, `delete_*`, `change_*`, or `restore_*` calls
- [ ] No OCI CLI sub-commands that write (e.g., `backup create`, `restore`, `update`) are shelled out
- [ ] File output is local only (timestamped CSV) — no writes to OCI Object Storage or other cloud resources
- [ ] `get_volume_backup_policy_asset_assignment` is used (read-only), NOT `create_volume_backup_policy_assignment` (write)

---

## 🔒 Recommended IAM Policy (Least Privilege)

Run the script under a principal with only the following OCI IAM policies to enforce read-only at the cloud level — this provides a hard enforcement boundary even if the script code contains an accidental write call:

```
Allow group AuditGroup to inspect all-resources in tenancy
Allow group AuditGroup to read backup-policies in tenancy
Allow group AuditGroup to read volume-backups in tenancy
Allow group AuditGroup to read db-backups in tenancy
Allow group AuditGroup to read autonomous-backups in tenancy
Allow group AuditGroup to read file-systems in tenancy
Allow group AuditGroup to read buckets in tenancy
Allow group AuditGroup to read mysql-backups in tenancy
```

With these policies in place, OCI will reject any write operation with a `403 Authorization failed` error, regardless of what the script attempts.

---

## Conclusion

The script's **stated purpose and design are read-only**. To confirm fully, review every SDK/CLI call in the source against the verification checklist above. Coupling that review with the least-privilege IAM policy above provides defense in depth and ensures no changes are made to the tenancy.

---

## CP-9 family — current state

| Script | Dimension | Status |
|---|---|---|
| `cp09-01-backup-type-config-frequency.sh` | backup type / configuration / frequency | implementation complete; OCI evidence pending |
| `cp09-02-backup-access-files-check.sh` | who can access the backup files | implementation complete; OCI evidence pending |
| `cp09-03-backup-replication-check.sh` | replication, retention, versioning (DR) | row-level failure attribution and coverage complete; OCI evidence pending |

All three are read-only, record compartment names, and refuse to let a failed
collection look like a clean result. All three carry a `--selfcheck` flag that
proves read-only-ness against their own source.

Together these cover the evidence line item *"Backup type/frequency, access,
replication — all OCS assets (VCN, Shared Services, CD3)"*.

---

## 2026-08-27 — cp09-01 coverage review (blockers found — now fixed, see below)

A 7-lens review of `cp09-01-backup-type-config-frequency.sh` against the CP-9 evidence requirement "Backup type/frequency, access, replication — all OCS assets (VCN, Shared Services, CD3)" found several **blocker**-severity defects still open:

- `oci fs snapshot-policy list` is not a real CLI command — every FSS row fails. The correct command (used by `backup-storage.sh`) is `oci fs filesystem-snapshot-policy list`.
- FSS schedules are read off the `list` response, which never carries `schedules` — every FSS policy reports `NO_SCHEDULES` even when one exists.
- The default config path is `/.oci/config` instead of `$HOME/.oci/config`, so config-auth mode aborts on a normal workstation.
- The volume→policy linkage relies on an unverified showoci CSV column instead of calling `oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment`.
- No compartment **name** is ever recorded (only OCID), so output cannot be broken out by VCN / Shared Services / CD3.
- No coverage of Base DB, Autonomous DB, MySQL, or PostgreSQL.
- "Access" and "replication" dimensions are entirely absent from this script's output — see the next section for where that evidence now lives.

**Remediated 2026-08-27** — see the rewrite section below.

---

## 2026-08-27 — cp09-01 rewritten as a direct-CLI collector

Patching the individual bugs would have left the architecture intact, and the architecture was the problem: collection ran through showoci and the join guessed CSV filenames and column headers. Rewritten in the same house style as `cp09-02`/`cp09-03`. showoci and the embedded Python workers are no longer required.

### Blockers fixed

- **`oci fs snapshot-policy list` does not exist** — the command group is `oci fs filesystem-snapshot-policy`. Every FSS row previously errored.
- **FSS schedules are not in the LIST response** — they appear only on GET. Fixing only the command name would have converted hard errors into *silent false-clean* `NO_SCHEDULES` rows, so both were fixed together and each policy is now fetched by id. Regression-tested with a mock whose list response deliberately omits `schedules`.
- **Per-asset policy linkage** now uses the authoritative `bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment` rather than a showoci column that may not exist.
- **Compartment names** are recorded, so evidence is filterable by VCN / Shared Services / CD3.
- **Coverage added** for Base DB, Autonomous DB, MySQL, PostgreSQL and volume groups.
- **Denials no longer read as "no backup configured"** — stderr is captured, every row carries `collection_status`, and the run exits 3 if any collection was incomplete.
- A new **coverage CSV** records every compartment/service pair actually visited, so "no assets" is distinguishable from "never collected".
- `last_backup_time` and `backup_count` show whether schedules actually **fire**, not merely that they are configured.

### Bug found during end-to-end testing

`check_volumes` captured the volume list *after* the backup-list call had already overwritten the shared output variable, so the loop iterated over backups and **no block volume was ever processed**. Static reading did not catch this; running against a mock did.

---

## 2026-08-27 — cp09-03 row-level collection integrity

`cp09-03` had the same defect as the retired access scripts: `o() { oci ... 2>/dev/null; }` discarded all stderr. For a replication control this is the worst possible failure mode — a 403 on `bv block-volume-replica list` returns nothing, and nothing is then reported as `NO-REPLICA`. An auditor would read a permissions problem as proof that no DR copy exists.

The first repair captured errors in a separate file, but status assignments made
inside command substitutions could not reach the caller. That made it
impossible to attribute incomplete collection to the affected evidence row.

The collector now uses explicit captured calls in the current shell. Every row
has `collection_status` and `collection_error`. Each compartment/service also
has a coverage row, and a failed primary collection produces a synthetic
`COLLECTION-FAILED` evidence row. Failed replica lookups produce
`replicated=UNKNOWN`; they can no longer produce a false `NO-REPLICA` finding.

Other changes:

- Added `--selfcheck`, `-n` compartment-name filtering and `-o` output routing.
- Reduced repeated API calls by caching replica lists per compartment or AD.
- Added support for both `.data[]` and `.data.items[]` response shapes.
- Added mock coverage for all seven service paths.
- Added a denied-call regression that requires exit `3`, a `DENIED` asset row,
  a `DENIED` coverage row and a retained failed-call ledger.

Regression command:

```bash
bash tests/run.sh
```

---

## 2026-08-27 — cp09-02-backup-access-files-check.sh (new script)

Added to fill the empty slot between `cp09-01` (type/frequency) and `cp09-03` (replication): **who can access the backup files**, resolved down to named users rather than stopping at a group name.

**Consolidated and removed** (superseded, no unique content lost — verified by diff before deletion):
- `oci-backup-access.sh` — older duplicate of `backup-storage-access.sh`
- `oci-backup-audit.sh` — older duplicate of `backup-storage.sh`
- `backup-storage-access.sh` — fully superseded by `cp09-02`

**Later status:** `cp09-01` now covers Base DB, ADB, MySQL and PostgreSQL with
failure-aware rows and a coverage ledger. `backup-storage.sh` and
`oci_backup_audit.py` are therefore deprecated compatibility/reference
collectors and are not canonical audit evidence sources.

### Gaps closed vs. the scripts it replaces

| Gap | Why it mattered |
|---|---|
| `all-resources` grants | Confers full backup access without naming a backup keyword — the old keyword filter missed it entirely |
| Multi-grantee statements | `Allow group A, group B to ...` — old regex `head -1`'d and dropped co-grantees |
| Verb capture | `inspect` (can see it exists) vs `manage` (can delete it) are different audit answers |
| Statement scope | A tenancy-root grant is no longer mistaken for compartment-local |
| KMS key custody | Whoever can `use` the key decrypts backups; `manage` destroys them |
| PAR expiry + scope | Old script emitted a count only; now distinguishes an active bucket-level `AnyObjectReadWrite` PAR from an expired object-level one |
| Cross-tenancy `Endorse`/`Admit` | Flags a foreign tenancy reading this tenancy's backups |
| Denials ≠ absence | Old wrapper piped stderr to `/dev/null`, so a 403 read identically to "nobody has access". Every row now carries `collection_status`; the run exits 3 if anything was incomplete |

### Read-only guarantee

`--selfcheck` greps the script's own source against a deny-list of mutating OCI subcommands and refuses to run if one is found. Verified by injecting `oci bv backup delete` into a test copy — caught correctly. Works without the OCI CLI installed.

### Bugs found and fixed during end-to-end testing (mocked OCI CLI)

Static review missed all five of these; they only surfaced running the script against realistic mock responses:

- `tr '\x1e' '\n'` — GNU `tr` has no `\xHH` escapes; it was translating the literal characters `\`, `x`, `1`, `e`, truncating every OCID at its first `1`. Fixed with bash parameter expansion instead.
- `(.data.items // .data)` in jq — errors (not null) when `.data` is an array, so `//` never caught it and PAR/replication rows were silently dropped. Fixed to `.data.items?`.
- `printf '%s' "$x" | while read` — no trailing newline, so single-grantee policy statements (the common case) produced zero grantee rows. Fixed to `printf '%s\n'`.
- `objects` substring-matched inside `objectstorage`; `backups` matched inside a `where ...='prod-backups'` clause value. Fixed with `\b` word boundaries and stripping the where-clause before resource matching.
- `local a=... b="${a...}"` — `a` isn't visible to `b`'s expansion within the same `local` statement under `set -u`. Split into separate assignment lines.

Also fixed: jq builds that emit CRLF (seen on Windows) were leaving a trailing `\r` inside parsed field values and map keys, breaking group-name lookups and padding CSV cells.
