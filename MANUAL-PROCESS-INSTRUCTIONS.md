# Manual Process Instructions

**Your working instructions for everything the collectors cannot do for you.**

This is the *operator* document: what to do, in what order, and what to type
into each form. It is a companion to
[`MANUAL-EVIDENCE-PROCEDURES.md`](MANUAL-EVIDENCE-PROCEDURES.md), which explains
*why* each item exists and what the API can and cannot establish. When you want
the reasoning, go there. When you want to get the work done, stay here.

**Last updated:** 2026-09-09

**Which tasks need which:** the SDK-vs-manual split for all 18 worksheet
items is one table in [`MASTER-TASK-LIST.md`](MASTER-TASK-LIST.md#which-tasks-are-sdk-which-are-manual).
Short version: 15 tasks are SDK + manual, Task 17 is manual-only, two are
N/A, and **none is SDK-only**.


---

## 0. Before you start

### 0.1 Three things to settle in writing

| Decision | Why it must come first |
|---|---|
| **Scope** — exact tenancy, exact regions, exact compartments (VCN / Shared Services / CD3) | Every collector asks you to confirm the scope OCID twice and type `YES`. An evidence package that does not name its scope proves nothing about coverage. |
| **Evidence store** — the approved restricted location | **This repository is public.** Nothing you produce goes in it. |
| **Roles** — who runs collectors, who owns each system, who approves | Every register has an owner and an approver column. Filling them in retrospectively is how packages get rejected. |

### 0.2 Set up

```bash
# The collectors need Oracle's pinned SDK
python3 -m pip install -r ra05-01/requirements-oci-sdk.txt

# Prove the tooling is intact before you trust any output
bash tests/run.sh
```

Use a **read-only principal**. The collectors enforce this themselves, but the
principal should not be able to mutate anything regardless.

### 0.3 How to read an exit code

| Code | Meaning | What to do |
|---|---|---|
| `0` | Complete | Proceed. |
| `3` | Incomplete, or a register did not reconcile | **Not a pass.** Open the coverage CSV and the reconciliation CSV. |
| `1` | Refused before scanning | Usually a bad register file or a missing region. Nothing was read. |
| `2` | *(IA-2 only, pending fix)* incomplete | Treat as `3`. |

**An empty CSV proves absence only when the coverage ledger says `OK`.** If it
says `DENIED`, the empty file means "we were refused", not "there is nothing
there".

---

## 1. Phase 1 — Snapshot everything first

Run every collector **without** any governance input. This does two things: it
tells you what is actually in the tenancy, and it generates the blank register
templates pre-shaped to the exact schema.

```bash
EV=/path/to/restricted/evidence          # NOT inside this repository
R=us-ashburn-1                           # repeat per in-scope region
```

**The collectors have two different scope interfaces.** This is a real
inconsistency in the tooling, not a typo — check which one you are running.

**Group A — select the tenancy interactively.** Omit `-c` and `-n`; the
collector lists the tenancy and every active compartment and asks you to enter
the tenancy OCID. Selecting the tenancy scans the root plus every discovered
compartment.

```bash
python3 cp09-01/cp09-01-backup-configuration.py          -r $R -o $EV
python3 cp09-02/cp09-02-backup-access.py                 -r $R -o $EV
python3 cp09-03/cp09-03-backup-replication.py            -r $R -o $EV
python3 sc08-02/sc08-02-in-transit-encryption.py         -r $R -o $EV
python3 sc28/sc28-oci-encryption-at-rest.py              -r $R -o $EV
python3 cm02-01/cm02-01-configuration-baseline.py        -r $R -o $EV
python3 cm07-01/cm07-01-open-ports.py                    -r $R -o $EV
python3 cm08-01/cm08-01-component-inventory.py           -r $R -o $EV
python3 cm11-01/cm11-01-software-installation-control.py -r $R -o $EV
```

**Group B — accept an explicit `--tenancy-scope` flag.**

```bash
python3 ra05-01/ra05-01-vulnerability-tracking.py        -r $R -o $EV --tenancy-scope
python3 si04-01/si04-01-siem-crowdstrike-forwarding.py   -r $R -o $EV --tenancy-scope
python3 ca07-01/ca07-01-continuous-monitoring.py         -r $R -o $EV --tenancy-scope
python3 cp02-01/cp02-01-contingency-planning.py          -r $R -o $EV --tenancy-scope
python3 cp04-01/cp04-01-contingency-plan-testing.py      -r $R -o $EV --tenancy-scope
```

Either way you can scope to named compartments instead with
`-n "VCN,Shared Services,CD3"`, or to explicit OCIDs with repeated `-c`.

Each prompts you to type the scope OCID twice, shows a pre-scan plan, then waits
for exact uppercase `YES`. **Read the plan.** It lists every operation that will
run.

**Keep from this phase:** every `*_approved_scan_plan.txt`, every
`*_collection_coverage.csv`, and every `*_template.csv`.

**Then fix any exit `3` before going further.** A register reconciled against an
incomplete snapshot is worthless.

---

## 2. Phase 2 — Fill in the registers

This is the bulk of the manual work. Blank forms are in `templates/`; the
collectors also emit an identical one each run. **Do not hand-type the headers** —
they are validated exactly, and a missing column fails the run before scanning.

> Where a column says *exact*, the value is compared literally. `Approved` is
> not `APPROVED`.

### 2.1 CA-7 monitoring baseline → `templates/ca07-01-monitoring-baseline-template.csv`

One row per monitoring control your **System Security Plan** requires. Build it
from the SSP and the Continuous Monitoring Form — **not** from the snapshot. A
baseline copied from what is already running agrees with any gap by construction
and can never show that a required alarm was never created.

| Column | What to put |
|---|---|
| `control_id` | Your control reference, e.g. `CA7-01` |
| `monitoring_type` | Exactly one of `ALARM`, `EVENTS-RULE`, `CLOUD-GUARD`, `LOG-RETENTION` |
| `resource_name` | The alarm or rule display name; `<tenancy>` for `CLOUD-GUARD` |
| `required_state` | Normally `ENABLED` |
| `owner` | A named individual, not a team |
| `approval_reference` | The approval record ID |

### 2.2 CP-2 ISCP register → `templates/cp02-01-iscp-register-template.csv`

One row per system in the contingency plan. **RTO and RPO come from your
Business Impact Analysis — there is no field for them anywhere in the OCI SDK.**

| Column | What to put |
|---|---|
| `system_id`, `system_name`, `system_owner` | Your identifiers; owner is a named individual |
| `resource_ocid` | **Mandatory.** Matching is by OCID, never by name — a rename would silently move coverage between systems |
| `rto_hours`, `rpo_hours` | Numeric, from the BIA. Blank ⇒ `REGISTER-INCOMPLETE` |
| `recovery_priority` | Your ranking, e.g. `1` |
| `alternate_site` | The recovery region or facility |
| `approval_reference` | The ISCP approval record |

### 2.3 CP-4 test register → `templates/cp04-01-test-register-template.csv`

One row per contingency test performed. Fill in **after** the drill (§3.5).

| Column | What to put |
|---|---|
| `test_id`, `plan_id` | Your test reference and the DR plan OCID |
| `execution_ocid` | The DR plan **execution** OCID. Must be a real, successful, non-precheck execution |
| `test_date`, `test_type` | Date of the exercise; `DRILL`, `SWITCHOVER` or `FAILOVER` |
| `participants` | Names and roles |
| `test_report_reference` | The report's controlled ID |
| `findings_count` | Number of findings raised |
| `corrective_actions_reference` | The CAP reference |
| `approver` | Named approver |
| `approval_status` | **Exact** `APPROVED` |

### 2.4 SI-4 SIEM destinations → `templates/si04-01-siem-destinations-template.csv`

Two columns: `target_resource_ocid`, `siem_system`.

Establish each from the **receiving side** — the SIEM itself, the function's
code, the stream consumer. OCI cannot tell you: Service Connector Hub has six
target kinds and none exposes a destination URL. Without this file every
connector is `MANUAL-VERIFY-SIEM-DESTINATION`, and a display-name keyword match
is recorded as `UNCONFIRMED`, never as a pass.

### 2.5 The pre-existing registers

| Task | Templates |
|---|---|
| CM-7 ports | `templates/cm07-01-approval-baseline-template.csv`, `-restricted-ports-list-`, `-service-mapping-` |
| CM-11 software | `templates/cm11-01-authorized-installers-`, `-approved-software-`, `-restricted-software-` |
| CM-2 baseline | `templates/cm02-01-approved-baseline-`, `-ci-register-` |
| CM-8 inventory | `templates/cm08-01-approved-inventory-`, `-change-disposition-` |

For CM-7, the restricted/prohibited list must be the **current signed one**. A
stale list is worse than none — it produces confident wrong verdicts. Set
`expiration_date` on each approval; an expired approval reports
`APPROVAL-INCOMPLETE` by design.

---

## 3. Phase 3 — Evidence no API can see

### 3.1 Oracle Base Database — native network encryption (SC-8)

On each DB host, as the Oracle owner:

```bash
grep -Ei 'SQLNET\.(ENCRYPTION|CRYPTO_CHECKSUM)_(SERVER|TYPES_SERVER)' \
     "$ORACLE_HOME/network/admin/sqlnet.ora"
```

`SQLNET.ENCRYPTION_SERVER` must be `REQUIRED`. `ACCEPTED` and `REQUESTED` both
permit an unencrypted session. Capture output with hostname and UTC time.

### 3.2 File Storage mounts (SC-8)

`MountTarget` has no in-transit field — FSS encryption is a client mount option,
so the tenancy cannot report it. On each client:

```bash
mount | grep -E 'oci-fss|nfs'
rpm -q oci-fss-utils 2>/dev/null || dpkg -s oci-fss-utils 2>/dev/null
```

An encrypted mount goes through `oci-fss-utils` and shows as an `oci-fss` type.
A plain `nfs` mount to a mount-target IP is **not** encrypted in transit.

### 3.3 IPSec tunnels (SC-8)

Console → **Networking → Customer connectivity → Site-to-Site VPN**. For each
connection capture **both tunnels in one view**: status, IKE version, Phase 1
and Phase 2 encryption, authentication and DH group. Cross-check against the
collector's tunnel rows — a disagreement is a finding, not a screenshot problem.

One tunnel `UP` is the disposition `IPSEC-TUNNEL-PAIR-INCOMPLETE`. Record it;
do not capture only the healthy tunnel.

### 3.4 Local install paths (CM-11)

IAM cannot see who can install software on a host. Per host:

```bash
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|allowusers|allowgroups'
sudo -ll
ls -l /etc/sudoers.d/
getent group wheel sudo adm 2>/dev/null
```

Windows: `Get-LocalGroupMember -Group Administrators`

Also document: break-glass accounts and their custody; every host **not**
enrolled in OS Management Hub (an unmanaged host returns no package inventory at
all — that is a coverage gap, never an empty result); and the Kubernetes
admission controls that stop a pod installing arbitrary software.

### 3.5 DR drill (CP-4)

1. Confirm the protection group has a drill plan — CP-2 reports
   `GROUP-HAS-NO-DRILL-PLAN` if not, and that blocks this task.
2. Run `START_DRILL`, then `STOP_DRILL` to return to steady state.
3. **Record the execution OCID.**
4. Confirm it reached `SUCCEEDED`.

**A `*_PRECHECK` execution is not a test.** It validates that the plan *could*
run without running it. Prechecks are cheap and succeed routinely, so counting
one is the easiest way to report an untested plan as tested. The collector
rejects a register entry pointing at one.

### 3.6 Notification delivery test (CA-7)

An `ACTIVE` subscription proves someone confirmed it once, not that mail is
being delivered today. For each `PATH-OK` route, trigger a controlled test and
record the alarm, UTC fire time, recipient, UTC receipt time and who confirmed.

Resolve every `PATH-BROKEN-*` first. `PATH-BROKEN-NO-ACTIVE-SUBSCRIBER` usually
means a `PENDING` subscription was never confirmed — someone must click the
link in the confirmation email.

### 3.7 ISCP training (CP-3, Task 17)

**No collector exists or should.** This procedure is the entire task.

1. List everyone holding an ISCP role — cross-check against `system_owner` in
   your CP-2 register so the two records agree.
2. Confirm content is role-appropriate and reflects the **current** approved
   ISCP. Training against a superseded plan is not evidence.
3. Deliver it. Record date, method, instructor, and the ISCP version.
4. Retain the materials as delivered, versioned.
5. Retain attendance — name, role, date, completion. Include non-attendees and
   the plan to cover them.
6. Record assessment results per attendee.
7. Record lessons learned; feed them into the next ISCP revision.
8. Set the refresh cycle, next due date, and the retraining trigger.
9. Approve and archive.

---

## 4. Phase 4 — Re-run with your registers

```bash
python3 ca07-01/ca07-01-continuous-monitoring.py -r $R -o $EV2 --tenancy-scope \
    --monitoring-baseline approved-baseline.csv \
    --min-log-retention-days 365 \
    --monthly-review completed-review.csv

python3 cp02-01/cp02-01-contingency-planning.py -r $R -o $EV2 --tenancy-scope \
    --iscp-register approved-iscp.csv

python3 cp04-01/cp04-01-contingency-plan-testing.py -r $R -o $EV2 --tenancy-scope \
    --test-window-days 365 --test-register completed-tests.csv

python3 si04-01/si04-01-siem-crowdstrike-forwarding.py -r $R -o $EV2 --tenancy-scope \
    --siem-destinations destinations.csv
```

Use a **fresh output directory** — the collectors refuse to overwrite existing
evidence.

### Verdicts to work through

| Verdict | Meaning |
|---|---|
| `MATCHED-OK` | Approved, present, working. |
| `MATCHED-DEGRADED` | **Exists but does not work.** An alarm with no destination, a topic with no confirmed subscriber. This is the verdict a plain inventory would miss. |
| `MISSING` | Approved but absent from the tenancy. |
| `UNAPPROVED` | Running but not in your baseline. Approve it or remove it. |
| `REGISTER-INCOMPLETE` | Your form is missing something OCI cannot supply. |
| `NOT-IN-DR-PROTECTION-GROUP` | Approved for recovery, not actually protected. |
| `PLAN-PRECHECK-ONLY` | Never actually tested. |

Everything not `MATCHED-OK` needs a named owner and either a remediation date or
an approved exception.

---

## 5. Phase 5 — Review and sign off

### 5.1 Monthly reviews

Take the generated `*_monthly_review_template.csv`. It is **pre-filled with the
real counts** and bound to `snapshot_sha256`.

Fill in `review_period`, `reviewer`, `review_date`, `approval_status` (exact
`APPROVED`), `evidence_reference`, `notes`.

**Do not edit the counts.** The collector recomputes them and rejects a
mismatch. That is the point: it makes the review provably about *this* snapshot
rather than some other run.

### 5.2 A package is complete when all four hold

1. Collection complete — exit `0`, every coverage row `OK`, run in every
   in-scope region and compartment.
2. Every register supplied **and fed back** to the collector, exiting `0`. A
   register written but never validated has been checked against nothing.
3. Every non-OK row dispositioned with a named owner.
4. The review's `snapshot_sha256` matches and its counts are unedited.

### 5.3 Sign, archive, record the reference

Store the package in the approved restricted location. Put only the controlled
reference in the worksheet.

---

## 6. Task-by-task quick reference

| # | Task | Collector | Your manual work |
|---:|---|---|---|
| 1 | Backups | `cp09-01/02/03` | Run per region; disposition findings; approve |
| 2 | In transit | `sc08-02` | §3.1 sqlnet.ora, §3.2 FSS, §3.3 IPSec, NLB backend TLS, psql `sslmode` |
| 3 | At rest | `sc28` | Key-admin evidence, rotation procedure, reviewer sign-off |
| 5 | Continuous monitoring | `ca07-01` | §2.1 baseline, §3.6 delivery test, Form review + feedback log |
| 6 | Ports | `cm07-01` | §2.5 PPSM + **current signed** restricted list; live validation runbook |
| 7 | Software control | `cm11-01` | §2.5 lists, §3.4 local paths, break-glass, unmanaged hosts |
| 8 | Config baseline | `cm02-01` | §2.5 baseline from the System Design Form; monthly review |
| 9 | Inventory | `cm08-01` | §2.5 approved inventory; disposition every add/remove/change |
| 10 | Vulnerabilities | `ra05-01` | Approve the SLA; owner + ticket per finding; non-VSS coverage |
| 11 | Change tracking | `cm03-01` * | Remedy CRQ/SO process and approved change samples |
| 12 | Account management | `ac02-01` * | Lifecycle procedures, inactivity policy, access review |
| 13 | Federation | `ia02-01` * | Confirm applicability; approved configuration evidence |
| 14 | SIEM | `si04-01` | §2.4 destination map, test event + receipt |
| 16 | Contingency planning | `cp02-01` | BIA, §2.2 register, ISCP, call tree, recovery procedures |
| 17 | **ISCP training** | **none possible** | §3.7 — all nine steps |
| 18 | ISCP testing | `cp04-01` | §3.5 drill, test report, §2.3 register |

\* Tasks 11–13 are on `main` and not yet merged here. See
`CODEX-TASKS-11-13-REVIEW.md` — AC-2 has two blocked calls outstanding and IA-2
returns the wrong exit code.

Tasks 4 and 15 are N/A.

---

## 7. Tracking checklist

Copy this into your working notes.

```
[ ] 0  Scope, evidence store and roles agreed in writing
[ ] 0  bash tests/run.sh passes; SDK installed; read-only principal confirmed
[ ] 1  All 14 collectors run snapshot-only, every in-scope region
[ ] 1  Every exit 3 resolved; all coverage rows OK
[ ] 2  CA-7 monitoring baseline approved
[ ] 2  CP-2 ISCP register complete (RTO/RPO from the BIA, resource_ocid on every row)
[ ] 2  SI-4 destination map established from the receiving side
[ ] 2  CM-7 PPSM + current signed restricted list
[ ] 2  CM-11 installer/software/restricted lists
[ ] 2  CM-2 baseline from the System Design Form
[ ] 2  CM-8 approved inventory
[ ] 2  RA-5 remediation SLA approved
[ ] 3  sqlnet.ora captured on every Base DB host
[ ] 3  FSS mount type captured on every client
[ ] 3  Both IPSec tunnels captured per connection
[ ] 3  NLB backend TLS termination evidenced
[ ] 3  sshd / sudo / local admin captured per host
[ ] 3  Break-glass accounts and unmanaged hosts documented
[ ] 3  DR drill run; execution OCID recorded; SUCCEEDED
[ ] 3  Notification delivery tested end to end
[ ] 3  ISCP training delivered; attendance, results, lessons retained
[ ] 4  All collectors re-run with registers; exit 0
[ ] 4  Every MATCHED-DEGRADED / MISSING / UNAPPROVED dispositioned
[ ] 5  Monthly reviews completed with unedited counts
[ ] 5  All approvals obtained
[ ] 5  Package signed, archived, reference recorded in the worksheet
```
