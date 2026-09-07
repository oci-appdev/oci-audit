# Manual Evidence Procedures

**Step-by-step procedures for every piece of audit evidence the OCI Python SDK
cannot produce.**

**Last updated:** 2026-09-07
**Companion to:** `MASTER-TASK-LIST.md` (what is outstanding) and `AGENTS.md`
(how the collectors behave)

---

## 1. Why this document exists

Fifteen of the sixteen actionable worksheet tasks now have an SDK-native
collector. Not one of them can close its task alone, because three categories of
evidence are not present in any OCI API:

| Category | Examples | Why no API can supply it |
|---|---|---|
| **Approvals and ownership** | signed baselines, approved restricted lists, system owners, reviewer sign-off | An approval is a human decision recorded outside the tenancy. The tenancy holds the *result* of a change, never its authorisation. |
| **Objectives and thresholds** | RTO, RPO, BIA, retention floors, approved configuration baselines | There is no recovery-objective field anywhere in the OCI SDK. A threshold derived from current state agrees with any drift by construction and can never detect it. |
| **Human activity** | training attendance, DR test participants, test reports, findings, corrective actions | Nothing in the control plane observes what people did. |

A fourth category is narrower but sharper — **specific facts the API is simply
blind to**, verified against `oci==2.185.1` while building the collectors:

- Service Connector Hub has six target kinds and **none** exposes a destination
  URL, so no API call can state that a connector feeds CrowdStrike.
- NLB `Listener` has no `ssl_configuration` (layer 4 — TLS terminates at the
  backend), `MountTarget` has no in-transit field (it is a client mount option),
  and psql `NetworkDetails` has no TLS field.
- Nothing in the control plane sees inside a guest OS: local accounts, sudoers,
  `sqlnet.ora`, installed packages on unmanaged hosts.

**The rule this document enforces:** where the API cannot establish a fact, the
collector takes a governance input and *validates* it, or reports
`MANUAL-VERIFY`. It never guesses, and it never treats a missing input as a
pass. This document is how those inputs get produced.

---

## 2. Evidence handling — read before collecting anything

**This repository is public.** Nothing produced by these procedures belongs in
it.

- Never commit screenshots, exported CSVs, OCIDs, public IPs, hostnames,
  database names, route details, security configuration, or completed
  registers.
- Store every completed package in the approved restricted evidence location.
- Record only the controlled reference (package ID) in the audit worksheet and
  in the `evidence_reference` column of the registers below.
- Collector output files are written `0600` and land under `-o <root>/<task-id>/`.
  Keep them there; do not copy them into the working tree.
- Redact before sharing outside the evidence store. Note that the collectors
  already redact what they can: subscription endpoints (an `EMAIL` address is
  personal data, an HTTPS webhook path is a bearer secret), instance metadata
  (`user_data` is a base64 cloud-init payload that routinely embeds bootstrap
  credentials), and error messages containing tokens.

---

## 3. Governance inputs the collectors consume

Produce these with the procedures in Part 1, then hand them back to the
collector, which validates them against the collected snapshot. **Column names
are exact — a missing column fails the run before any scanning**, deliberately,
because an input that silently degraded to empty would report every control as
unapproved.

| Collector | Flag | Exact columns |
|---|---|---|
| `ca07-01` | `--monitoring-baseline` | `control_id, monitoring_type, resource_name, required_state, owner, approval_reference` |
| `ca07-01` | `--monthly-review` | `snapshot_sha256, review_period, cloud_guard_status, total_alarms, enabled_alarms, alarms_without_destination, total_rules, enabled_rules, rules_without_delivery, total_topics, topics_without_active_subscriber, delivery_paths_ok, delivery_paths_broken, delivery_paths_unknown, logs_below_retention_baseline, reviewer, review_date, approval_status, evidence_reference, notes` |
| `ca07-01` | `--min-log-retention-days` | integer (approved retention floor) |
| `cp02-01` | `--iscp-register` | `system_id, system_name, system_owner, resource_ocid, rto_hours, rpo_hours, recovery_priority, alternate_site, approval_reference` |
| `cp04-01` | `--test-register` | `test_id, plan_id, execution_ocid, test_date, test_type, participants, test_report_reference, findings_count, corrective_actions_reference, approver, approval_status` |
| `si04-01` | `--siem-destinations` | `target_resource_ocid, siem_system` |
| `si04-01` | `--test-event-register`, `--owner-approvals`, `--monthly-review` | generated templates — see `si04-01/TASK14-SIEM-CROWDSTRIKE-EVIDENCE-GUIDE.md` |
| `cm07-01` | approval baseline, restricted list, service mapping | `templates/cm07-01-*.csv` |
| `cm11-01` | authorized installers, approved software, restricted list | `templates/cm11-01-*.csv` |
| `cm02-01` | `--baseline`, CI register | `templates/cm02-01-*.csv` |
| `cm08-01` | approved inventory, change disposition | `templates/cm08-01-*.csv` |

**Every collector generates a blank template of its own inputs on each run.**
Use the generated template rather than typing headers by hand; it is guaranteed
to match the schema the same build validates against.

Two templates are deliberately **blank, never pre-populated** — the CA-7
monitoring baseline and the CP-2 ISCP register. A baseline derived from what is
currently running agrees with any gap by construction: it can never show that
something in scope was left out.

---

## 4. Universal sequence

Every task below follows the same shape. Do not skip step 0.

0. **Confirm scope in writing.** Region(s), compartments (VCN / Shared Services
   / CD3), and the exact tenancy. An evidence package that does not name its
   scope proves nothing about coverage.
1. **Run the collector** under a read-only principal, in every in-scope region.
   Retain the printed pre-scan plan and the approved scan plan file.
2. **Check the exit code.** `0` = complete. `3` = incomplete; the coverage
   ledger says why. **An empty CSV proves absence only when the coverage ledger
   says `OK`.** Never read an exit `3` result as a clean pass.
3. **Perform the manual procedure** for this task (Part 1 below).
4. **Complete the register**, using the collector's generated template.
5. **Re-run the collector with the register supplied.** It validates the input
   against the snapshot and exits `3` if they disagree.
6. **Obtain approval**, then sign and archive the package.

---

# Part 1 — Per-task procedures

---

## Task 2 (SC-8) — Encryption in transit

Collector: `sc08-02/sc08-02-in-transit-encryption.py` (and the `.sh` incumbent).
Existing checklist: `sc08-02/TASK2-MANUAL-EVIDENCE-CHECKLIST.md`.

### 2a. IPSec tunnels — both must be evidenced

**API blind spot:** the collector reads `IPSecConnectionTunnel.phase_one_details`
and `phase_two_details`, which carry the negotiated crypto and no secret. It
deliberately **cannot** read the pre-shared key —
`get_ip_sec_connection_tunnel_shared_secret` and the whole CPE device-config
family are blocked repository-wide, because the rendered device config embeds
the PSK.

1. For each IPSec connection in scope, open the Console at
   **Networking → Customer connectivity → Site-to-Site VPN → \<connection\>**.
2. Capture both tunnels in one view showing, for each: tunnel status `UP`,
   IKE version, and Phase 1 / Phase 2 encryption, authentication and DH group.
3. Cross-check each captured value against the collector's tunnel rows. They
   must agree. A disagreement is a finding, not a screenshot problem.
4. If only one tunnel is `UP`, that is the disposition
   `IPSEC-TUNNEL-PAIR-INCOMPLETE` — record it with an owner and remediation
   reference. **Do not** capture only the healthy tunnel.

**Artifact:** one screenshot per connection showing both tunnels.
**Acceptance:** every in-scope connection has two tunnels evidenced, or a
recorded `IPSEC-TUNNEL-PAIR-INCOMPLETE` disposition.

### 2b. Oracle Base Database — `sqlnet.ora`

**API blind spot:** native network encryption is a database-side setting; no
control-plane API exposes it.

1. Connect to the DB system host as the Oracle owner.
2. Capture the relevant lines:
   ```
   grep -Ei 'SQLNET\.(ENCRYPTION|CRYPTO_CHECKSUM)_(SERVER|TYPES_SERVER)' \
        "$ORACLE_HOME/network/admin/sqlnet.ora"
   ```
3. Confirm `SQLNET.ENCRYPTION_SERVER` is `REQUIRED` (not `ACCEPTED` or
   `REQUESTED` — those permit an unencrypted session) and that
   `SQLNET.ENCRYPTION_TYPES_SERVER` names an approved algorithm.

**Artifact:** command output with hostname and UTC timestamp.
**Acceptance:** `REQUIRED` on every in-scope Base DB host.

### 2c. File Storage — in-transit encryption is a mount option

**API blind spot:** `MountTarget` has **no** in-transit field. FSS in-transit
encryption is established by the client at mount time, so the tenancy cannot
report it and the collector records `MANUAL-VERIFY` with that reason.

1. On each client that mounts an in-scope file system, run:
   ```
   mount | grep -E 'oci-fss|nfs'
   rpm -q oci-fss-utils 2>/dev/null || dpkg -s oci-fss-utils 2>/dev/null
   ```
2. An encrypted mount goes through `oci-fss-utils` and appears as an `oci-fss`
   type mount. A plain `nfs` mount to a mount-target IP is **not** encrypted in
   transit.

**Artifact:** command output per client host.
**Acceptance:** every in-scope mount is evidenced as encrypted, or carries a
recorded exception.

### 2d. Network Load Balancer — TLS terminates at the backend

**API blind spot:** NLB `Listener` has no `ssl_configuration`. It is layer 4;
it forwards, it does not terminate TLS. The collector records `MANUAL-VERIFY`
rather than asserting a pass or a finding, either of which would be invention.

1. Identify the backend servers behind each in-scope NLB listener.
2. On each backend, evidence that the listening service terminates TLS — the
   web/app server config block showing the certificate and protocol versions.
3. Record the minimum TLS version and cipher suite actually configured.

**Artifact:** backend server configuration extract per NLB listener.
**Acceptance:** every in-scope NLB listener has a backend TLS termination
proof, or a recorded exception.

### 2e. PostgreSQL

**API blind spot:** psql `NetworkDetails` has no TLS field. Evidence the
connection policy from the database side or the application connection string
(`sslmode=require` or stronger).

---

## Task 5 (CA-7) — Continuous monitoring

Collector: `ca07-01/ca07-01-continuous-monitoring.py`.

The collector proves the notification **path** is intact —
alarm/rule → destination → ONS topic → `ACTIVE` subscription. It cannot prove a
message was **received**, and it cannot approve the baseline.

### 5a. Approve the monitoring baseline

**Why manual:** a baseline built from the alarms that happen to exist agrees
with any gap. If a required alarm was never created, a synthesised baseline
would never say so.

1. Run the collector without `--monitoring-baseline` to get a snapshot and the
   blank template `*_monitoring_baseline_template.csv`.
2. Working from the **System Security Plan and the Continuous Monitoring Form**
   — not from the snapshot — list every monitoring control that is *required*.
   One row per control:
   - `monitoring_type`: `ALARM`, `EVENTS-RULE`, `CLOUD-GUARD` or `LOG-RETENTION`
   - `resource_name`: the alarm/rule display name, or `<tenancy>` for Cloud Guard
   - `required_state`: normally `ENABLED`
   - `owner`, `approval_reference`: the accountable owner and the approval record
3. Have the system owner approve the completed baseline.
4. Re-run with `--monitoring-baseline <file>`.

**Read the reconciliation carefully.** Four verdicts, and the middle two are the
ones that matter:
- `MATCHED-OK` — required, present, enabled, delivery path intact.
- `MATCHED-DEGRADED` — **it exists but does not work.** Enabled with no
  destination, or its topic has no confirmed subscriber. Treat as a finding.
- `MISSING` — approved but absent from the tenancy.
- `UNAPPROVED` — running but not in the baseline. Either approve it or remove it.

### 5b. Confirm log retention

`--min-log-retention-days` is an approved threshold, not an observation. Without
it every log reports `NOT-ASSESSED-NO-BASELINE`. Take the value from the
approved retention policy and supply it.

### 5c. Test the notification path end-to-end

**Why manual:** an `ACTIVE` subscription proves someone confirmed it, not that
mail is being delivered today.

1. For each `PATH-OK` route, trigger a controlled test — a deliberate threshold
   breach in a non-production resource, or an operational alarm firing naturally.
2. Record: the alarm, the UTC fire time, the recipient, the UTC receipt time,
   and who confirmed receipt.
3. Resolve every `PATH-BROKEN-*` row before claiming coverage. In particular
   `PATH-BROKEN-NO-ACTIVE-SUBSCRIBER` means a **`PENDING` subscription was never
   confirmed** — someone must click the confirmation link.
4. `PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE` is not a failure: the destination
   topic is in a compartment outside the scan. Either widen the scope and re-run
   or record the scope limitation explicitly.

### 5d. Complete the Continuous Monitoring Form review

**Why manual:** this is the worksheet item itself — a reviewed form with
feedback, disposition and approval.

1. Take the generated `*_monthly_review_template.csv`. It is **pre-filled with
   the real counts** from the snapshot and bound to `snapshot_sha256`.
2. Fill in `review_period`, `reviewer`, `review_date`, `approval_status`
   (exact `APPROVED`), `evidence_reference` and `notes`. **Do not edit the
   counts** — the collector recomputes them and rejects a mismatch, which is the
   point: it makes the review provably about this snapshot.
3. Record the form feedback log and disposition alongside it.
4. Re-run with `--monthly-review <file>`; exit `0` means the review is bound to
   the snapshot.

---

## Task 6 (CM-7) — Ports, protocols and services

Collector: `cm07-01/`. Guides: `TASK6-OPEN-PORTS-EVIDENCE-GUIDE.md`,
`TASK6-LIVE-VALIDATION-RUNBOOK.md`.

**API blind spot:** OCI reports which ports are open. It has no concept of which
are *approved*.

1. Complete `templates/cm07-01-approval-baseline-template.csv` (the approved
   PPSM), `cm07-01-restricted-ports-list-template.csv` (the organisation's
   current restricted/prohibited list) and `cm07-01-service-mapping-template.csv`.
2. The restricted list must be the **current signed** one. A stale list is worse
   than none: it produces confident wrong verdicts.
3. Set `expiration_date` on each approval. An expired approval reports
   `APPROVAL-INCOMPLETE` by design.
4. Reconcile counts against a Console spot check per
   `TASK6-LIVE-VALIDATION-RUNBOOK.md` — **this is the only task whose acceptance
   gate is explicitly blocked on a live run.**

Note the reconciliation ordering: **prohibition beats restricted beats
approved.** A rule matching both an approval and a prohibition is a finding.

---

## Task 7 (CM-11) — Software installation control

Collector: `cm11-01/`. Guide:
`cm11-01/TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md`.

The collector separates *who may install* (IAM policy) from *what is installed*
(OS Management Hub). Four blind spots need in-guest evidence:

### 7a. Local install paths IAM cannot see

On each in-scope host:
```
# Who can log in and escalate
sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|allowusers|allowgroups'
sudo -ll
ls -l /etc/sudoers.d/
getent group wheel sudo adm 2>/dev/null
```
Windows:
```
Get-LocalGroupMember -Group Administrators
```
Anyone with root/sudo/local-admin can install software regardless of what the
IAM policy says. That population is part of CM-11 and appears in no OCI API.

### 7b. Break-glass accounts
Document each emergency account, its approval, its custody and its use log.

### 7c. Unmanaged hosts
Any host not enrolled in OS Management Hub returns no package inventory at all.
List them explicitly with the reason and a remediation plan — an unmanaged host
is a coverage gap, never an empty result.

### 7d. Container and Kubernetes runtime
```
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.labels}{"\n"}{end}'
```
Evidence the admission controls that stop a pod installing arbitrary software.

**Note the model trap the collector already handles:**
`InstalledPackageSummary.software_sources` is a **list**; there is no
`software_source_name`. Reading that field yields nothing and falling back to
package `type` reports every package's source as `RPM` — a format, not a
provenance. If a reviewer asks why the source column looks unfamiliar, this is
why.

---

## Tasks 8 and 9 (CM-2 / CM-8) — Baseline and inventory

Collectors: `cm02-01/`, `cm08-01/`. Guides in each folder.

### 8a. Establish and approve the configuration baseline

**Why manual:** `cm02-01` refuses to synthesise a baseline. Without `--baseline`
it reports `SNAPSHOT-ONLY-NO-BASELINE`. A baseline taken from running instances
would agree with any drift.

1. Derive the baseline from the **approved System Design Form / CI register**.
2. Complete `templates/cm02-01-approved-baseline-template.csv` and
   `cm02-01-ci-register-template.csv`.
3. Re-run with `--baseline`. Rows approved but no longer present are reported;
   they are as important as unapproved additions.

### 8b. Two disclosure duties on the inventory

- **Resource Search is an index, not the services.** It is eventually
  consistent and covers only the types it knows about. The coverage ledger
  records `queryable-types=N` and `index-is-eventually-consistent`. State this
  in the evidence package: completeness is a reconciliation task, not an
  assertion.
- **No control-plane API sees inside a guest.** In-guest software, unmanaged
  hosts, OKE workloads and third-party providers are coverage gaps to list
  explicitly.

### 8c. Monthly review
Use the generated count-bound review template. Disposition every `ADDED`,
`REMOVED` and `CHANGED` row, approve, then promote the snapshot as next month's
comparison point.

---

## Task 10 (RA-5) — Vulnerability tracking

Collector: `ra05-01/`. Guide: `ra05-01/TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`.

Manual remainder: approve the remediation SLA (an organisational decision, not
an API value); give every finding an owner, ticket and follow-up or an approved
exception; and extend coverage beyond VSS — non-VSS, third-party and
application-layer scanning appear in no OCI API.

---

## Task 14 (SI-4) — SIEM / CrowdStrike forwarding

Collector: `si04-01/`. Guide: `si04-01/TASK14-SIEM-CROWDSTRIKE-EVIDENCE-GUIDE.md`.

### 14a. Supply the destination map — this is not optional

**API blind spot, stated precisely:** Service Connector Hub has exactly six
target kinds — monitoring, loggingAnalytics, functions, objectStorage,
streaming, notifications — and **no model among them exposes a URL or endpoint
field**. OCI therefore cannot state that a stream, bucket or function feeds
CrowdStrike.

Without `--siem-destinations` the collector reports
`MANUAL-VERIFY-SIEM-DESTINATION` and marks any name-keyword match as
`UNCONFIRMED` with `siem_attribution=NAME-KEYWORD-ONLY`. That is deliberate: a
connector named `prod-forwarder` that feeds CrowdStrike would be missed, and one
named `crowdstrike-test` that feeds nothing would be counted.

1. For each connector target, establish from the **receiving side** (the SIEM,
   the function's code, the stream consumer) where the data actually lands.
2. Record two columns: `target_resource_ocid, siem_system`.
3. Re-run with `--siem-destinations <file>`.

### 14b. Test event and receipt
Send a controlled test event; record the source, UTC send time, the SIEM search
that found it, UTC receipt time and ingestion latency. Configuration is not
delivery.

### 14c. Check the lifecycle gate
A connector in `FAILED`, `INACTIVE` or `NEEDS_ATTENTION` does **not** provide
coverage. The collector gates on `ACTIVE`; confirm no in-scope log source
depends on an unhealthy connector.

---

## Task 16 (CP-2) — Contingency planning

Collector: `cp02-01/cp02-01-contingency-planning.py`.

### 16a. First, decide whether Full Stack DR is even in use

**Do not misread an empty result.** `MANUAL-VERIFY-NO-OCI-DR-RECORD` means OCI
holds no DR configuration record — **not** that there is no contingency plan.
Most tenancies implement DR with cross-region backups and documented runbooks.
If that is the case here, CP09-03 (backup replication) carries the recovery
capability evidence and this collector's DR sections will legitimately be empty.
Record which model is in use before going further.

### 16b. Establish RTO and RPO

**API blind spot, stated plainly: there is no recovery-time or recovery-point
objective field anywhere in the OCI SDK.** These come from the Business Impact
Analysis and nowhere else.

1. Conduct the BIA. For each in-scope system determine RTO (hours), RPO (hours)
   and recovery priority.
2. Complete the ISCP register. **`resource_ocid` is mandatory and matching is by
   OCID, never by display name** — a name is not an identity, two compartments
   can hold resources with the same name, and a rename would silently move
   coverage from one system to another.
3. Re-run with `--iscp-register <file>`.

Verdicts:
- `DR-PROTECTED` — the approved system is a member of a DR protection group.
- `NOT-IN-DR-PROTECTION-GROUP` — approved for recovery, not actually protected.
- `REGISTER-INCOMPLETE` — `resource_ocid`, `rto_hours` or `rpo_hours` missing.
  OCI cannot fill these in; the approval record is incomplete.

### 16c. Read the two structural facts the collector does establish

- **`SINGLE-REGION-TENANCY`** — a tenancy subscribed to one region cannot fail
  over to another region, whatever the plan document says. This is checkable and
  is checked.
- **`GROUP-HAS-NO-DRILL-PLAN`** — the group has members and a plan, but no
  `START_DRILL`/`STOP_DRILL` plan, so it cannot be exercised without moving
  production. That blocks Task 18.

### 16d. Produce the plan documents
Draft and approve: the ISCP itself, the communications bridge and call tree,
recovery procedures per system, and the test plan. None is derivable from any
API.

---

## Task 17 (CP-3) — ISCP training

**There is no collector for this task and none should be written.** No operation
anywhere in the OCI SDK reports whether training was delivered, who attended, or
what the results were. This procedure is the entire task.

1. **Identify the audience.** Everyone with an ISCP role: system owners,
   recovery leads, on-call responders, the communications lead. Cross-check
   against the `system_owner` column of the CP-2 ISCP register so the two
   records agree.
2. **Confirm role-appropriate content.** Training must match what the person
   would actually do during a contingency event, and must reflect the *current*
   approved ISCP. Training against a superseded plan is not evidence.
3. **Deliver the training** and record: date, delivery method, instructor, and
   the ISCP version trained against.
4. **Retain the materials** — the deck or module, as delivered, versioned.
5. **Retain the attendance record** — name, role, date, completion status.
   Include anyone who did not attend and the plan to cover them.
6. **Record results** — assessment or acknowledgement per attendee.
7. **Record lessons learned** and feed them into the next ISCP revision.
8. **Set the refresh cycle** — the required frequency, the next due date, and
   the trigger for ad-hoc retraining (a material ISCP change, or a role change).
9. **Obtain approval** and archive.

**Acceptance:** every person holding an ISCP role in the approved register has a
dated training record against the current plan version, or a documented gap with
a remediation date.

---

## Task 18 (CP-4) — ISCP testing

Collector: `cp04-01/cp04-01-contingency-plan-testing.py`.

### 18a. Understand what counts as a test before planning one

`plan_execution_type` has eight values and the distinction carries the control:

| Class | Types | What it proves |
|---|---|---|
| `DRILL` | `START_DRILL`, `STOP_DRILL` | **The plan was exercised** without moving production. This is what a scheduled contingency test looks like and is the strongest evidence the API can give. |
| `REAL-MOVE` | `SWITCHOVER`, `FAILOVER` | The plan works — but this is an *event*, not a scheduled test. |
| `PRECHECK` | the four `*_PRECHECK` variants | **Nothing about execution.** A precheck validates that a plan *could* run. It does not run it. |

**Prechecks are cheap, frequent and routinely succeed, so counting one as a test
is the easiest available way to report an untested plan as tested.** The
collector refuses to: prechecks never count toward recency, a plan whose only
executions are prechecks is `PLAN-PRECHECK-ONLY`, and a test register entry
pointing at a precheck is rejected as `INVALID`.

### 18b. Run the drill

1. Confirm the protection group has a drill plan (CP-2 reports
   `GROUP-HAS-NO-DRILL-PLAN` if not).
2. Schedule and run a `START_DRILL`, then `STOP_DRILL` to return to steady state.
3. Record the execution OCID — the register needs it.
4. Verify the execution reached `SUCCEEDED`. A `FAILED` or `CANCELED` drill is a
   finding with corrective actions, not a retry to hide.

### 18c. Produce the test report

**API blind spot:** OCI holds no participant list, test report, lesson learned or
corrective action.

Record, per test: participants and their roles; whether RTO and RPO were
actually met (compare `execution_duration_in_sec` against the register's
`rto_hours`); every finding; corrective actions with owners and due dates; and
approval.

### 18d. Complete the test register and re-run

Columns: `test_id, plan_id, execution_ocid, test_date, test_type, participants,
test_report_reference, findings_count, corrective_actions_reference, approver,
approval_status`.

The collector rejects an entry whose `execution_ocid` does not match a real
execution, points at a precheck, or references an execution that did not succeed
— and requires `approval_status` to be exactly `APPROVED`. Set
`--test-window-days` to the approved testing frequency.

### 18e. If Full Stack DR is not in use
`cp04-01` will find no plans and says so. Contingency testing against documented
runbooks is entirely valid; the evidence is then a test report rather than an API
result, and steps 18c–18d still apply with the execution reference pointing at
the runbook exercise record.

---

# Part 2 — Artifacts every task needs

Regardless of task, a package is not complete without these. They are the most
common reason an otherwise-good collection cannot be signed off.

| Artifact | What it must show |
|---|---|
| **Approved scan plan** | The collector's `*_approved_scan_plan.txt`, retained. It records the region, scope OCIDs, the exact read-only operations approved, and the mutation boundary. |
| **Operator record** | Who ran it, UTC time, which principal, which commit. |
| **Coverage ledger** | Every requested compartment/service pair has a row. Non-`OK` rows are dispositioned. |
| **Error ledger** | Retained whenever it is non-empty. `DENIED` and `ERROR` are different evidence — an authorisation refusal is a scope problem, a broken call is a collection problem. |
| **Exit code** | `0`, or a documented reason for `3`. |
| **Owner and approver** | Named individuals, not teams, for every register row. |
| **Exceptions** | Every accepted risk with a reference, an owner and an expiry. |
| **Package reference** | The controlled ID recorded in the worksheet — never the evidence itself in this repository. |

---

# Part 3 — Acceptance criteria

A task is closeable when all four hold. Most rejected packages fail on the
second or the fourth.

1. **Technical collection is complete.** Exit `0`, every coverage row `OK`, run
   in every in-scope region and compartment.
2. **Every governance input is supplied and validated.** The collector was
   re-run with the register and exited `0`. A register that was written but never
   fed back to the collector has not been validated against anything.
3. **Every non-OK row has a disposition** with a named owner and either a
   remediation date or an approved exception.
4. **The review is bound to the snapshot.** Where a monthly review applies, its
   `snapshot_sha256` matches the collected snapshot and its counts were not
   edited. This is what makes the review provably about the evidence in the
   package rather than about a different run.

### Three failure modes to check for explicitly

- **An empty CSV read as a clean pass.** It proves absence only when the
  coverage ledger says `OK`. If the ledger says `DENIED`, the empty file means
  "we were refused", not "there is nothing there".
- **A control that exists but does not work.** `MATCHED-DEGRADED` (CA-7), a
  `PENDING` subscription, an alarm with no destination, a rule whose only action
  is disabled. These read as healthy in any inventory.
- **A precheck counted as a test** (CP-4), or a name keyword counted as a SIEM
  destination (SI-4). Both are confident wrong answers rather than gaps.

---

# Appendix — Why some things are UNKNOWN rather than a finding

Reviewers ask about this, so it is worth stating once.

**A response that does not establish a fact is `UNKNOWN`, never a negative
finding.** Only an explicit negative from the API — `kind=NONE`,
`is_enabled=false`, an empty assignment list from a successful read — earns one.

Consequences visible in the evidence:

- A failed `get` produces `UNKNOWN`, not `0`. If a DR protection group's member
  read fails, the count is `UNKNOWN`; reporting `0` would assert the group
  protects nothing, which was not observed.
- A destination outside the scanned scope is
  `PATH-UNKNOWN-DESTINATION-OUT-OF-SCOPE`, not broken. Reporting it as a failure
  would manufacture a finding out of our own scoping decision.
- Where OCI genuinely describes nothing — NLB TLS, FSS in-transit, psql TLS —
  the row is `MANUAL-VERIFY` with the reason recorded. Asserting either a pass
  or a finding would be invention.

This is why the manual procedures in Part 1 exist: they are how an `UNKNOWN`
becomes a determination, by a human who looked.
