# OCS Audit Master Task List

**Last reviewed:** 2026-09-07

**Tracking basis:** repository implementation plus evidence artifacts visible in this repository

**Collector API verification:** the Task 1, 2, 3, 7 and 9 collectors were
rechecked field-by-field against `oracle/oci-python-sdk` v2.185.1 on 2026-09-02.
Three defects were found and fixed; see the 2026-09-02 entry in `AUDIT.md`.
Verification confirms the collectors read the current API models. It is not a
substitute for a controlled live run.

**Rule:** a collector is not proof of control operation until it has been run, reviewed and linked to the approved evidence location.

**Scope-automation contract — closed 2026-09-02:** the CP-9, SC-8 and SC-28
collectors were retrofitted to the strict contract in
`SCRIPT-DESIGN-STANDARD.md`. A manual `-c`/`-n` run now confirms every resolved
OCID twice and requires exact uppercase `YES`; automation requires
`--non-interactive`, one exact `--confirm-scope-ocid` per resolved target and
`--approve-scan YES`. All nine canonical collectors now implement it. The
fail-closed regression is `tests/test-task1-3-automation-contract.sh`.

## Status legend

| Status | Meaning |
|---|---|
| Implementation complete | Collector/workflow code is ready for a controlled OCI run; operational evidence is still required |
| Partial | Some technical foundation exists, but material control or evidence requirements remain |
| Not started | No substantive implementation or evidence package exists in this repository |
| N/A | Worksheet marks the item not applicable |

## Worksheet tracker

| # | Worksheet task | Status | Repository coverage | Required next evidence/action |
|---:|---|---|---|---|
| 1 | Backup type/frequency, access and replication for VCN, Shared Services and CD3 | Implementation complete | Strict scope-automation contract (retrofitted 2026-09-02). Canonical `cp09-01`, `cp09-02`, `cp09-03` family; read-only self-checks; failure-aware CSVs; default interactive tenancy/compartment discovery, double-OCID, resolved plan and exact-`YES` gate on all three scripts; refusal/no-workload-call regressions; CP-9 mock suite | Run in every in-scope region and compartment; retain the approved scan plan; review exit codes, coverage, findings, unresolved identities and exceptions; store signed evidence package |
| 2 | Encryption in transit, including IPSec screenshots and overall proof | Implementation complete | Strict scope-automation contract (retrofitted 2026-09-02). Safety-reviewed `sc08-02/sc08-02-in-transit-encryption.sh`; default interactive tenancy/compartment discovery, double-OCID and final scan-summary/`YES` gate; 27 list/get call sites with mutation and PSK-read injection gates; failure-aware/response-shape-validated CSVs; private/formula-safe evidence; LB frontend/backend, NLB, databases, Object Storage, volumes, FSS, API Gateway, OKE, CPE/IPSec tunnels and DRG context; two-tunnel/denied-call gates; safety report and manual checklist | Run in every in-scope region/compartment under a read-only principal; retain approved scan summary; reconcile coverage/findings; require both IPSec tunnels or disposition `IPSEC-TUNNEL-PAIR-INCOMPLETE`; complete screenshots, Base DB `sqlnet.ora`, FSS mounts and NLB backend proof; decide whether to add MySQL `secure-connections` in-transit coverage, which SC-8 does not currently collect; review and store signed evidence package |
| 3 | Encryption at rest | Implementation complete | Strict scope-automation contract (retrofitted 2026-09-02). Failure-aware `sc28/sc28-oci-encryption-at-rest.sh`; default interactive tenancy/compartment discovery, double-OCID, resolved plan and exact-`YES` gate; storage/database key custody; current MySQL/PostgreSQL handling; Vault type/lifecycle/deletion; KMS HSM, AES key shape, automatic rotation and key-version evidence; refusal/no-workload-call, denied-call and rotation regressions; manual evidence checklist | Run in every in-scope region/compartment; retain the approved scan plan; reconcile CMK data stores to keys; resolve non-OK rows and CMK/HSM/rotation findings; complete key-admin, Audit-log, procedure and reviewer evidence; store signed package |
| 4 | N/A | N/A | None required | None |
| 5 | Continuous Monitoring Form review/feedback | Partial | SDK-native `ca07-01/ca07-01-continuous-monitoring.py` (2026-09-07). Cloud Guard posture, alarms, ONS topics/subscriptions, Events rules and log retention, reconstructed into an end-to-end delivery path (alarm/rule → destination → topic → ACTIVE subscription) so an alarm that notifies nobody is a finding. Subscription endpoints redacted (EMAIL is personal data; an HTTPS webhook path is a bearer secret). Baseline reconciliation via `--monitoring-baseline`, retention floor via `--min-log-retention-days`; snapshot-only without them. 32 mock regressions | Run in every in-scope region/scope; approve the monitoring baseline; resolve every broken delivery path; **then** complete the governance half this collector cannot produce — the reviewed Continuous Monitoring Form, feedback log, owner, disposition and approval |
| 6 | Ports/protocols/services list, approval proof and restricted list | Partial | `cm07-01/cm07-01-open-ports-protocols-services.sh` has the scope-confirmation, evidence-separation and reconciliation foundation, whose cross-compartment coverage and ICMP restricted-match defects are now fixed; the legacy `cm07-openports.sh` produced useful output while `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` did not; see `cm07-01/CM07-CORRECTIVE-REVIEW.md` | **Everything closed except live validation (2026-09-02)** — cross-compartment resolution, portless ICMP matching, `-p/--profile`, semantic rule identity, packaged scan summary, SDK field cross-check, realigned templates, updated evidence guide and disabled legacy scripts, all with regressions (`cm07-01/tests/test-cm07-01-corrective.sh`). **Sole remaining item:** the controlled compartment and tenancy runs with count reconciliation and reviewer disposition, per `cm07-01/TASK6-LIVE-VALIDATION-RUNBOOK.md`. Needs tenancy access; no agent session has had it |
| 7 | Software installation control | Implementation complete | Canonical `cm11-01/cm11-01-software-installation-control.sh`; default tenancy/compartment discovery, exact double-OCID and final `YES`; strict automation confirmation; explicit region; read-only IAM policy/group evidence; candidate entitlement classification for OSMH package install, Compute image provisioning and Container Registry publish; classic group-member expansion plus identity-domain boundary; OSMH installed packages, Compute boot images, container images; generated authorized-installer/approved-software templates; authoritative installer/approval/restricted-list reconciliation; OSMH/repository/image technical-control evidence; source hashes, private/formula-safe outputs, coverage/error ledgers and mock gate | Run inventory-only in every scope; obtain signed authorized-installer, approved-software and current restricted/prohibited lists; export referenced Identity Domains membership; complete SSH/sudo/local-admin, break-glass, unmanaged-host, Windows, Kubernetes/runtime and request/change-sample evidence; rerun reconciliation; disposition prohibited/restricted/unapproved/unauthorized rows and store the signed package |
| 8 | Configuration baseline | Partial | Simplified `cm02-01/cm02-01-configuration-baseline.sh`; one-command read-only technical snapshot; mandatory tenancy/compartment double-OCID, full plan and exact `YES`; strict automation, explicit region and named-profile support; normalized CI/attribute fingerprints; private/formula-safe raw and canonical evidence; explicit coverage/error ledger; exit `0` only when technical collection succeeds; mock safety/failure gate | Run in every exact region/scope and retain the snapshot; separately establish and approve the CI register, System Design Form/configuration baseline and monthly review; reconcile technical values to those approved records; retain change/exception, in-guest and rule-level evidence before representing CM-2 as complete |
| 9 | Hardware/software inventory baseline | Implementation complete | Canonical `cm08-01/cm08-01-component-inventory-baseline.sh`; mandatory tenancy/compartment double-OCID, complete plan, package-volume disclosure and exact `YES`; strict automation, explicit region and named-profile support; corrected failure-aware CM08 engine; stable component keys/fingerprints; generated approved-inventory, change-disposition and count-bound monthly-review templates; `UNCHANGED`/`ADDED`/`REMOVED`/`CHANGED` reconciliation; authoritative ownership/approval and exact disposition validation; unmanaged/in-guest/provider coverage-gap ledger; input SHA-256; private/formula-safe raw and canonical evidence; mock gate | Run inventory-only in every exact region/scope; resolve guest/package/OKE/digest/provider-boundary gaps; approve the inventory; compare to the prior approved month; disposition every addition/removal/change; complete and approve the count-bound monthly review; rerun to exit `0`; sign/archive the package and promote the current snapshot for the next month |
| 10 | Vulnerability tracking | Implementation complete | Canonical `ra05-01/ra05-01-vulnerability-tracking.py` built on Oracle's pinned OCI Python SDK; config/instance/resource-principal auth; SDK pagination/retries and runtime list/get allowlist; mandatory tenancy/compartment double-OCID, complete SDK plan and exact `YES`; Compute/OCIR asset coverage; VSS host/container targets, latest scans and detailed CVE/package rows; conservative cross-compartment target resolution; organization-owned SLA ingestion; stable-key remediation tracker; exception/follow-up validation; snapshot-hash/count-bound monthly review; private/formula-safe evidence, structured coverage/errors and mock gate | Run tenancy-wide in every in-scope region; approve the SLA; complete every remediation owner/ticket/follow-up or approved exception; resolve stale/unscanned/unknown assets and failed calls; add non-VSS/third-party/application coverage; submit and approve the exact monthly review; sign/archive the final package |
| 11 | Configuration change tracking | Implementation complete | Codex's `cm03-01-configuration-change-tracking.py`, **published flat on `main` (`915cc12`); not on `claude/repo-study-u22ntx` and never reviewed by Claude** | Review it against the SDK models; merge into the per-task folder layout; add Remedy CRQ/SO approval process and approved change samples |
| 12 | Account management | Implementation complete | Codex's `ac02-01-account-management.py`, **published flat on `main` (`915cc12`); not on this branch and never reviewed by Claude**. The CP-9 access collector is limited to backup access and is not an account-management review | Add lifecycle procedures, manager/approver ownership, inactivity removal, group/privilege baseline, review template and completed approvals |
| 13 | OKTA/DOJLogin configuration | Implementation complete | Codex's `ia02-01-federation-configuration.py`, **published flat on `main` (`915cc12`); not on this branch and never reviewed by Claude** | Review it against the SDK models (see the Identity Domains secret-read note in `AGENTS.md`); merge into the folder layout; confirm integration applicability and capture approved configuration evidence |
| 14 | SIEM integration/CrowdStrike forwarding | Implementation complete | `si04-01/si04-01-siem-crowdstrike-forwarding.py`. Copilot's original plus four defect fixes (2026-09-07), one of them runtime-fatal: `oci.logging_management` does not exist. Destination attribution comes from `--siem-destinations`, never from a display-name keyword. 28 mock regressions | Capture forwarding configuration, source coverage, test event and SIEM receipt evidence; supply the governance destination map |
| 15 | N/A | N/A | None required | None |
| 16 | Contingency planning | Partial | SDK-native `cp02-01/cp02-01-contingency-planning.py` (2026-09-07). Full Stack DR protection groups and members, DR plans and steps, region subscriptions and AD/FD spread; ISCP reconciliation by OCID via `--iscp-register`. **OCI has no RTO/RPO field anywhere in the SDK**, so those come from the register only. Absence of Full Stack DR is `MANUAL-VERIFY-NO-OCI-DR-RECORD`, not a failure. 22 mock regressions | Run in every in-scope region/scope; **then** define and approve RTO/RPO, BIA, communications bridge, recovery procedures, the ISCP itself and the test plan — none of which any API can supply |
| 17 | ISCP training | Not started | **None possible.** No OCI API reports whether training was delivered, who attended or what the results were. No collector exists or should be written | Conduct training; retain materials, attendance, results and lessons learned |
| 18 | ISCP testing | Partial | SDK-native `cp04-01/cp04-01-contingency-plan-testing.py` (2026-09-07). DR plan executions classified as DRILL / REAL-MOVE / PRECHECK — **a `*_PRECHECK` validates that a plan could run without running it and is never counted as a test** — with recency against `--test-window-days` and corroboration of `--test-register` entries against real executions. 20 mock regressions | Execute a drill; **then** publish the test report, participant list, findings and corrective actions, record them in the test register, and finalize the ISCP/BIA — none of which any API can supply |

## Completion snapshot

Excluding the two N/A items, **ten of sixteen** actionable worksheet tasks have
implementation-complete collector workflows and **five** have partial
foundations — every one of those fifteen now has an SDK-native collector.
**One (Task 17, ISCP training) has none and never will**: no OCI API reports
whether training happened.

The remaining work is almost entirely of one kind. Every collector is verified
against the SDK models, the surface gate and mocked clients, and **not one has
ever run against a real tenancy**. Building more collectors is no longer the
constraint; running the ones that exist is.

No actionable task should be represented as audit-complete until its
operational evidence and approval records are produced and reviewed.

### What no collector can supply

Three categories of evidence are governance artefacts, taken as validated
inputs and never generated: approvals and owner sign-off; RTO, RPO and BIA
(there is no recovery-objective field anywhere in the OCI SDK); and human
activity records — training attendance, test participants, test reports,
findings and corrective actions. A collector that produced any of these would
be inventing evidence.

## Work order

The order has changed: collector development is essentially finished, so the
first item is no longer "write the next one".

1. **Live-validate the SDK collectors.** This is the largest remaining risk in
   the repository and it needs tenancy access no agent session has had. Start
   with `cm07-01/TASK6-LIVE-VALIDATION-RUNBOOK.md`, which is the only task
   whose gate is explicitly blocked on it.
2. Execute and close Tasks 1, 2 and 3 operational and manual evidence.
3. Execute and close Tasks 7, 8, 9 and 10 evidence and monthly reviews.
4. Run CA07-01 for Task 5, then complete the Continuous Monitoring Form review,
   feedback log and approval it cannot produce.
5. Review Codex's Tasks 11, 12 and 13 collectors against the SDK models and
   merge them from `main` into the per-task folder layout.
6. Run SI04-01 for Task 14 with a governance destination map; capture the test
   event and SIEM receipt.
7. Run CP02-01 for Task 16, then define and approve the ISCP, RTO/RPO and BIA.
8. Conduct Task 17 ISCP training and retain the records; there is nothing to
   automate.
9. Run a DR drill, then run CP04-01 for Task 18 and complete the test report
   and corrective actions.
