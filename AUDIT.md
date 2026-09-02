# OCI Audit Implementation Review

**Last updated:** 2026-09-02

**Current branch:** `copilot/review-repo`

**Current head:** `4f63cd467d9273c31190c4942df0f2c76d76c413`

**Master tracker:** `MASTER-TASK-LIST.md`

**Continuation notes:** `HANDOFF.md`

## Current audit position

Tasks 1, 2, 3, 7, 9 and 10 have implementation-complete collector workflows and
reproducible mock gates ready for controlled OCI runs. None is
audit-complete: live CSVs, Task 2 manual/screenshotted proof, Task 3 key
custody/rotation proof, Task 7 identity/host/manual proof, Task 9 approved prior inventory,
change-disposition/monthly-review and guest/provider-boundary proof, reviewer
disposition, evidence-location references and approval records have not been
produced in this repository. Task 6 remains Partial after a controlled-use
report and source review identified material CM07-01 defects. Task 8 is also
Partial after the user selected a simple technical-collection-only CM02 script;
approved baseline and monthly-review reconciliation are now external evidence.

Task 10 is implemented with Oracle's official OCI Python SDK. The current user
direction is that this SDK-only approach is now the guard rail for all script
work going forward, even though several earlier collectors still predate that
standard. Live VSS,
approved SLA/tracker/monthly-review and non-VSS evidence remain pending, so it
is not audit-complete.

The remaining worksheet position is tracked in `MASTER-TASK-LIST.md`. Continue
in worksheet order. After Tasks 1–3 operational evidence, Task 4 is N/A and
Task 5 remains the earliest unimplemented worksheet item. Tasks 7–9 were
implemented next at the user's direction.

### Task 6 corrective status

The operator reported that legacy `cm07-01/legacy/cm07-openports.sh` produced useful output,
while CM07-01 and the legacy PPSM/proof scripts did not work in the target
environment. Source review confirmed two high-severity correctness defects:

- compartment-scoped collection can miss related subnets or Security Lists in
  other compartments and can incorrectly label live rules as unattached;
- portless ICMP rules are modeled as port range `0-65535` and can false-match a
  narrow port-based restricted entry.

The committed scope helper is present, so the missing-helper concern is not a
current defect. `cm07-01/CM07-CORRECTIVE-REVIEW.md` records the remaining hardening and
the live acceptance gate. Mock regression success must not be represented as
proof that Task 6 works in OCI.

On 2026-08-28 the Task 2 collector was normalized to the canonical
`sc08-02/sc08-02-in-transit-encryption.sh` name. Its evidence artifacts now use the
`sc08-02_...` prefix, and the obsolete unprefixed script/test paths were
removed; the collector's read-only and no-secret safety boundary is unchanged.

---

## 2026-09-02 — Task 10 RA-5/SI-2 vulnerability tracking

The user directed all new or materially rewritten OCI collectors to use
Oracle's official Python SDK and to avoid custom implementations unless the SDK
cannot satisfy a requirement. `SCRIPT-DESIGN-STANDARD.md` now requires the
pinned Oracle SDK, generated clients/models, official pagination/retries,
supported signers, runtime list/get allowlists and structured service errors.

`ra05-01/ra05-01-vulnerability-tracking.py` implements Task 10 with:

- config-profile, instance-principal and resource-principal authentication;
- explicit region, default interactive tenancy/compartment discovery, exact
  double-OCID, full SDK method/output plan and exact uppercase `YES`;
- strict automation requiring every resolved OCID and `--approve-scan YES`;
- Compute-instance and OCIR-repository asset inventory;
- VSS host/container target inventory, latest results and detailed
  per-resource/per-package CVE rows;
- cross-compartment target resolution for tenancy runs and conservative
  `UNKNOWN` target status for incomplete exact-scope visibility;
- organization-owned SLA ingestion and source hash, with no built-in policy
  represented as authoritative;
- stable finding-key remediation owner/ticket/follow-up/exception validation;
- snapshot-SHA/count-bound monthly review validation;
- coverage and structured service-error ledgers with `opc-request-id`;
- mode-`0600`, formula-safe outputs and fail-closed collection status.

The collector deliberately does not claim coverage for non-OCI hosts,
appliances, managed services, application scanning or third-party scanner
sources. Those boundaries, remediation closure proof and signed approval remain
required in `ra05-01/TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`.

The mock SDK gate exercises pagination, host/container details,
cross-compartment targets, exact-scope conservatism, mutation injection,
manual/automation refusal before workload calls, structured denied-read
handling and governed reconciliation.

---

## 2026-09-01 — CM02 simplified to technical collection

The user selected a simple CM02 workflow after the prior evidence-completeness
and authorization wording caused operational confusion. CM02-01 now has one
collection mode:

- no CI-register, approved-baseline or monthly-review inputs;
- no top-level approval or reconciliation templates;
- one command after the mandatory tenancy/compartment selection, exact OCID
  twice, complete plan and exact uppercase `YES`;
- exit `0` only when the technical snapshot and normalization complete;
- exit `3` only for failed/malformed OCI or raw collector evidence, with exact
  coverage/error paths printed to the terminal;
- a clear `COLLECTION STATUS: COMPLETE` or `INCOMPLETE` summary.

Named profiles, strict automation confirmation, read-only source/runtime
checks, private/formula-safe output, CM08 raw collection, configuration
fingerprints and the `617fc56` Compute-image owner-compartment fix remain.
Because this version intentionally does not establish or reconcile an approved
organizational baseline, Task 8 is Partial and requires separate CI register,
System Design Form/baseline, monthly review, change and exception evidence.

---

## 2026-08-31 — Task 9 CM-8 system component inventory workflow

The broad `cm08-01/cm08-hw-sw-baseline.sh` engine collected useful OCI facts, but it
did not establish an approved component owner/register, classify monthly
addition/removal/change, require exact dispositions, bind a signed review to
current counts or publish visibility gaps.

`cm08-01/cm08-01-component-inventory-baseline.sh` is now the canonical Task 9 workflow.
It:

- defaults to discovered tenancy/compartment selection, exact double-OCID, a
  full plan and exact uppercase `YES` before workload collection;
- applies the same gate to manual `-c`/`-n` and requires explicit confirmation
  OCIDs plus `--approve-scan YES` for automation;
- requires one region, supports named profiles, discloses installed-package
  volume and invokes the raw CM08 engine only after approval;
- makes the raw engine refuse direct execution without the wrapper-approved
  caller/scope/region handshake and runtime-allowlists read action variants;
- normalizes cloud resources and software into stable component keys and
  inventory fingerprints, with package versions treated as mutable state;
- generates pending approved-inventory, change-disposition and count-bound
  monthly-review templates without inventing organizational approval;
- validates ownership, criticality, inventory status, baseline ID, approval
  authority/dates and authoritative source provenance;
- reconciles `UNCHANGED`, `ADDED`, `REMOVED` and `CHANGED`, requiring one exact
  approved change, exception or corrective-action disposition for every change;
- validates exactly one approved current-month review whose scope and counts
  match the live reconciliation and unmanaged-gap ledger;
- records input hashes, collection coverage and errors and produces private,
  no-clobber, spreadsheet-formula-safe raw/canonical evidence.

The gap ledger records compute guest/agent linkage, package detail, OKE running
nodes, immutable image digests, compartment location and provider physical
hardware boundaries. These are review inputs, not silently inferred negatives.

Task 9 also corrected raw CM08 location provenance: child-derived attachment,
FSS, OKE, container, Function, database and OS/package CSVs now carry
compartment OCIDs. Regression coverage is in
`cm08-01/tests/test-cm08-01-component-inventory.sh`; operating instructions and the
recurring monthly sequence are in
`cm08-01/TASK9-COMPONENT-INVENTORY-EVIDENCE-GUIDE.md`.

---

## 2026-08-28 — Task 8 CM-2 configuration baseline workflow

**Historical implementation note:** this governed reconciliation interface was
superseded by the user-directed simple technical collector on 2026-09-01.

The existing `cm08-01/cm08-hw-sw-baseline.sh` captured broad hardware/software and
configuration facts, but it did not establish controlled CI ownership, ingest
an approved System Design Form/baseline, reconcile live attributes to approved
values or validate a monthly review. It also predated the mandatory scan-
approval boundary.

`cm02-01/cm02-01-configuration-baseline.sh` is now the canonical Task 8 workflow. The
CM02 name preserves the control mapping: configuration baseline is CM-2, while
the existing CM08 file remains the invoked component-inventory engine. CM02-01:

- defaults to discovered tenancy/compartment selection, exact double-OCID, a
  complete plan and exact uppercase `YES` before workload collection;
- applies the same double-confirmation boundary to manual `-c`/`-n` and requires
  explicit confirmation OCIDs plus `--approve-scan YES` for automation;
- requires one explicit region, supports a named profile and retains the
  approved plan;
- invokes the CM08 inventory engine only after approval and forces a selected
  compartment to remain exact rather than silently expanding to children;
- normalizes broad OCI inventory into stable CI keys, baseline-eligible
  attributes and SHA-256 configuration fingerprints;
- generates CI register, approved baseline/System Design Form and monthly-review
  templates without representing observed live values as approved truth;
- reconciles `EXACT`, case-insensitive, set, presence/absence and numeric
  comparison methods and retains change/exception references;
- distinguishes configuration drift from unregistered CIs, unbaselined live
  attributes, incomplete/ambiguous baselines and approved attributes not live;
- validates exactly one approved review for the current month and confirmed
  scope, including findings/change/exception review and corrective action;
- records input hashes, coverage and errors; produces private, no-clobber,
  spreadsheet-formula-safe canonical and raw CSV evidence.

Task 8 implementation also corrected pre-existing CM08 engine defects found by
execution rather than static review: direct `jq` calls referenced an undefined
`dat` function; image rows were double-encoded and included a blank image; and
VNIC rows omitted compartment OCIDs. CM02-01 additionally treats retained raw
stderr or downstream parser failures as incomplete evidence so they cannot
survive behind an `OK` OCI-call ledger.

Regression coverage is in `cm02-01/tests/test-cm02-01-configuration-baseline.sh` with
`cm08-01/tests/mock-oci-task8`. The manual evidence and first-month three-pass workflow
are documented in `cm02-01/TASK8-CONFIGURATION-BASELINE-EVIDENCE-GUIDE.md`.

---

## 2026-08-28 — Task 7 CM-11 software installation control workflow

The existing `cm08-01/cm08-hw-sw-baseline.sh` package inventory was adjacent CM-8/CM-2
evidence, but it could not answer who was authorized to install software,
whether live software was approved, or whether it matched an authoritative
restricted list. It also predated the mandatory scope approval contract.

`cm11-01/cm11-01-software-installation-control.sh` is now the canonical Task 7
collector. It:

- defaults manual runs to discovered tenancy/compartment selection, requires
  the exact selected OCID twice, prints the complete plan and requires exact
  uppercase `YES` before IAM policy/identity or workload collection;
- requires manual `-c`/`-n` runs to confirm every resolved OCID twice and
  requires explicit `--non-interactive`, matching confirmation OCIDs and exact
  `--approve-scan YES` for automation;
- requires an explicit OCI region and limits cloud calls to list/get;
- includes policies attached to a selected compartment's ancestors because
  parent IAM policies can affect the child without expanding the confirmed
  workload inventory scope;
- preserves every IAM statement and transparently classifies only candidate
  package-install, Compute-provisioning and container-image-publish
  capabilities;
- expands classic IAM group principals to visible group members, records
  dynamic-group matching rules and fails incomplete when a referenced
  identity-domain group cannot be resolved to users;
- inventories OSMH installed packages, Compute boot images and Container
  Registry images/resources;
- records OSMH managed instances, software sources, groups, lifecycle
  environments, scheduled jobs, repository posture and image pinning as
  technical-control evidence;
- generates authorized-installer and approved-software templates, then
  reconciles live evidence to signed installer, approved software and
  restricted/prohibited software inputs;
- validates approval/effective dates and required authority/process fields;
- records input provenance and SHA-256, uses private/formula-safe outputs and
  retains failed coverage/error evidence with exit code `3`;
- explicitly labels the documented built-in Administrators grant separately
  from OCI API-returned policies.

No output is represented as an effective-permissions calculation. OCI's policy
list documentation states that the API does not automatically determine which
policies apply to a group or compartment. Conditions, policy combinations,
inheritance, deny/cross-tenancy statements and identity-domain membership need
IAM review.

The collector also cannot see host SSH/sudo/local administrators, break-glass
paths, packages installed outside the authoritative management platform,
Windows installed applications, or Kubernetes/Functions/deployment-runtime
permissions. Those required evidence boundaries and the controlled two-pass
workflow are documented in
`cm11-01/TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md`.

Regression coverage in
`cm11-01/tests/test-cm11-01-software-installation-control.sh` exercises successful
inventory/reconciliation, authorization expansion, a prohibited Telnet match,
input hashes, OSMH control coverage, denied packages, malformed JSON,
formula-safe output, manual and default interactive selection, tenancy
expansion, mismatch/refusal before collection, strict automation and a
referenced identity-domain membership gap.

---

## 2026-08-28 — Task 6 CM-7/PPSM open-port evidence workflow

The three older CM-7 scripts collected useful rule data, but each suppressed
OCI stderr. A denied VCN, Security List or NSG call could therefore look like
an empty network surface. They also lacked the mandatory tenancy/compartment
OCID confirmation and used separate inventory, restricted-list and approval
paths. The approval script had a confirmed stdin collision: a pipeline supplied
the baseline CSV while a Python here-document simultaneously occupied stdin,
so no baseline rows reached the CSV reader.

`cm07-01/cm07-01-open-ports-protocols-services.sh` is now the canonical Task 6
collector. It:

- defaults manual runs to discovered tenancy/compartment selection, requires the
  exact selected OCID twice, prints every target/input/output and requires exact
  uppercase `YES` before the first Networking call;
- does not let `-c` or `-n` silently bypass authorization: manual flag-based
  runs confirm every resolved OCID twice, while automation requires explicit
  `--non-interactive`, matching confirmation OCIDs and exact
  `--approve-scan YES`;
- requires an explicit OCI region so the evidence package never records an
  unresolved CLI default;
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
- generates and reconciles a system-owner service/listener mapping so packet
  permissions are not represented as proof of an actual service;
- rejects future approval/verification dates and reversed approval or policy
  effective/expiration ranges;
- preserves subnet associations for both OCI CLI list shapes, `.data[]` and
  `.data.items[]`;
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
`cm07-01/TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md`.

---

## 2026-08-27 — SC-8 pre-scan authorization and safety review

A second source-level safety review of `sc08-02/sc08-02-in-transit-encryption.sh` verified 27
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

`sc08-02/SC08-SAFETY-REVIEW.md` records the complete review, command inventory,
resolved findings, local-write boundary and remaining manual evidence.

---

## 2026-08-27 — Task 3 SC-28 encryption-at-rest integrity and KMS evidence

The original `sc28/sc28-oci-encryption-at-rest.sh` discarded stderr for every OCI
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

`sc28/TASK3-MANUAL-EVIDENCE-CHECKLIST.md` defines the required CMK reconciliation,
key administrator approval, HSM/AES-256 review, OCI Audit rotation proof,
manual rotation procedure, evidence integrity and sign-off package.

The Task 3 mock suite exercises every service path, automatic rotation success
and failure, and a 403 on KMS key listing. The denied case must exit `3`, retain
the error ledger and produce `DENIED/COLLECTION-FAILED` evidence and coverage;
it is forbidden from reporting the result as no keys.

---

## 2026-08-27 — Task 2 SC-8 collection integrity and IPSec coverage

The original `sc08-02/sc08-02-in-transit-encryption.sh` discarded stderr for every OCI call.
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

`sc08-02/TASK2-MANUAL-EVIDENCE-CHECKLIST.md` defines the screenshot/config package and
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

**Script:** `cp09/cp09-01/legacy/oci_backup_audit.py`

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
| `cp09/cp09-01/cp09-01-backup-type-config-frequency.sh` | backup type / configuration / frequency | implementation complete; OCI evidence pending |
| `cp09/cp09-02/cp09-02-backup-access-files-check.sh` | who can access the backup files | implementation complete; OCI evidence pending |
| `cp09/cp09-03/cp09-03-backup-replication-check.sh` | replication, retention, versioning (DR) | row-level failure attribution and coverage complete; OCI evidence pending |

All three are read-only, record compartment names, and refuse to let a failed
collection look like a clean result. All three carry a `--selfcheck` flag that
proves read-only-ness against their own source.

Together these cover the evidence line item *"Backup type/frequency, access,
replication — all OCS assets (VCN, Shared Services, CD3)"*.

---

## 2026-08-27 — cp09-01 coverage review (blockers found — now fixed, see below)

A 7-lens review of `cp09/cp09-01/cp09-01-backup-type-config-frequency.sh` against the CP-9 evidence requirement "Backup type/frequency, access, replication — all OCS assets (VCN, Shared Services, CD3)" found several **blocker**-severity defects still open:

- `oci fs snapshot-policy list` is not a real CLI command — every FSS row fails. The correct command (used by `cp09/cp09-01/legacy/backup-storage.sh`) is `oci fs filesystem-snapshot-policy list`.
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

## 2026-08-27 — cp09/cp09-02/cp09-02-backup-access-files-check.sh (new script)

Added to fill the empty slot between `cp09-01` (type/frequency) and `cp09-03` (replication): **who can access the backup files**, resolved down to named users rather than stopping at a group name.

**Consolidated and removed** (superseded, no unique content lost — verified by diff before deletion):
- `oci-backup-access.sh` — older duplicate of `backup-storage-access.sh`
- `oci-backup-audit.sh` — older duplicate of `cp09/cp09-01/legacy/backup-storage.sh`
- `backup-storage-access.sh` — fully superseded by `cp09-02`

**Later status:** `cp09-01` now covers Base DB, ADB, MySQL and PostgreSQL with
failure-aware rows and a coverage ledger. `cp09/cp09-01/legacy/backup-storage.sh` and
`cp09/cp09-01/legacy/oci_backup_audit.py` are therefore deprecated compatibility/reference
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
