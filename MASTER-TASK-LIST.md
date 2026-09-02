# OCS Audit Master Task List

**Last reviewed:** 2026-08-31

**Tracking basis:** repository implementation plus evidence artifacts visible in this repository

**Collector API verification:** the Task 1, 2, 3, 7 and 9 collectors were
rechecked field-by-field against `oracle/oci-python-sdk` v2.185.1 on 2026-09-02.
Three defects were found and fixed; see the 2026-09-02 entry in `AUDIT.md`.
Verification confirms the collectors read the current API models. It is not a
substitute for a controlled live run.

**Rule:** a collector is not proof of control operation until it has been run, reviewed and linked to the approved evidence location.

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
| 1 | Backup type/frequency, access and replication for VCN, Shared Services and CD3 | Implementation complete | Canonical `cp09-01`, `cp09-02`, `cp09-03` family; read-only self-checks; failure-aware CSVs; default interactive tenancy/compartment discovery, double-OCID, resolved plan and exact-`YES` gate on all three scripts; refusal/no-workload-call regressions; CP-9 mock suite | Run in every in-scope region and compartment; retain the approved scan plan; review exit codes, coverage, findings, unresolved identities and exceptions; store signed evidence package |
| 2 | Encryption in transit, including IPSec screenshots and overall proof | Implementation complete | Safety-reviewed `sc08-02-in-transit-encryption.sh`; default interactive tenancy/compartment discovery, double-OCID and final scan-summary/`YES` gate; 27 list/get call sites with mutation and PSK-read injection gates; failure-aware/response-shape-validated CSVs; private/formula-safe evidence; LB frontend/backend, NLB, databases, Object Storage, volumes, FSS, API Gateway, OKE, CPE/IPSec tunnels and DRG context; two-tunnel/denied-call gates; safety report and manual checklist | Run in every in-scope region/compartment under a read-only principal; retain approved scan summary; reconcile coverage/findings; require both IPSec tunnels or disposition `IPSEC-TUNNEL-PAIR-INCOMPLETE`; complete screenshots, Base DB `sqlnet.ora`, FSS mounts and NLB backend proof; decide whether to add MySQL `secure-connections` in-transit coverage, which SC-8 does not currently collect; review and store signed evidence package |
| 3 | Encryption at rest | Implementation complete | Failure-aware `sc28-oci-encryption-at-rest.sh`; default interactive tenancy/compartment discovery, double-OCID, resolved plan and exact-`YES` gate; storage/database key custody; current MySQL/PostgreSQL handling; Vault type/lifecycle/deletion; KMS HSM, AES key shape, automatic rotation and key-version evidence; refusal/no-workload-call, denied-call and rotation regressions; manual evidence checklist | Run in every in-scope region/compartment; retain the approved scan plan; reconcile CMK data stores to keys; resolve non-OK rows and CMK/HSM/rotation findings; complete key-admin, Audit-log, procedure and reviewer evidence; store signed package |
| 4 | N/A | N/A | None required | None |
| 5 | Continuous Monitoring Form review/feedback | Not started | None | Add reviewed form, feedback log, owner, disposition and approval |
| 6 | Ports/protocols/services list, approval proof and restricted list | Partial | `cm07-01-open-ports-protocols-services.sh` has the scope-confirmation, evidence-separation and reconciliation foundation, but controlled use found material cross-compartment coverage and ICMP restricted-match defects; the legacy `cm07-openports.sh` produced useful output while `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` did not; see `CM07-CORRECTIVE-REVIEW.md` | Patch cross-compartment resolution and portless-protocol matching; add profile support, semantic rule identity and packaged summary; extend regressions; complete known-object compartment and tenancy validation before collecting approval/restricted-list evidence |
| 7 | Software installation control | Implementation complete | Canonical `cm11-01-software-installation-control.sh`; default tenancy/compartment discovery, exact double-OCID and final `YES`; strict automation confirmation; explicit region; read-only IAM policy/group evidence; candidate entitlement classification for OSMH package install, Compute image provisioning and Container Registry publish; classic group-member expansion plus identity-domain boundary; OSMH installed packages, Compute boot images, container images; generated authorized-installer/approved-software templates; authoritative installer/approval/restricted-list reconciliation; OSMH/repository/image technical-control evidence; source hashes, private/formula-safe outputs, coverage/error ledgers and mock gate | Run inventory-only in every scope; obtain signed authorized-installer, approved-software and current restricted/prohibited lists; export referenced Identity Domains membership; complete SSH/sudo/local-admin, break-glass, unmanaged-host, Windows, Kubernetes/runtime and request/change-sample evidence; rerun reconciliation; disposition prohibited/restricted/unapproved/unauthorized rows and store the signed package |
| 8 | Configuration baseline | Partial | Simplified `cm02-01-configuration-baseline.sh`; one-command read-only technical snapshot; mandatory tenancy/compartment double-OCID, full plan and exact `YES`; strict automation, explicit region and named-profile support; normalized CI/attribute fingerprints; private/formula-safe raw and canonical evidence; explicit coverage/error ledger; exit `0` only when technical collection succeeds; mock safety/failure gate | Run in every exact region/scope and retain the snapshot; separately establish and approve the CI register, System Design Form/configuration baseline and monthly review; reconcile technical values to those approved records; retain change/exception, in-guest and rule-level evidence before representing CM-2 as complete |
| 9 | Hardware/software inventory baseline | Implementation complete | Canonical `cm08-01-component-inventory-baseline.sh`; mandatory tenancy/compartment double-OCID, complete plan, package-volume disclosure and exact `YES`; strict automation, explicit region and named-profile support; corrected failure-aware CM08 engine; stable component keys/fingerprints; generated approved-inventory, change-disposition and count-bound monthly-review templates; `UNCHANGED`/`ADDED`/`REMOVED`/`CHANGED` reconciliation; authoritative ownership/approval and exact disposition validation; unmanaged/in-guest/provider coverage-gap ledger; input SHA-256; private/formula-safe raw and canonical evidence; mock gate | Run inventory-only in every exact region/scope; resolve guest/package/OKE/digest/provider-boundary gaps; approve the inventory; compare to the prior approved month; disposition every addition/removal/change; complete and approve the count-bound monthly review; rerun to exit `0`; sign/archive the package and promote the current snapshot for the next month |
| 10 | Vulnerability tracking | Not started | CM-8 collector exposes limited update counts only | Add monthly vulnerability tracker, SLA, remediation owner, exception and follow-up evidence |
| 11 | Configuration change tracking | Not started | None | Add Remedy CRQ/SO approval process and approved change samples |
| 12 | Account management | Not started | CP-9 access collector is limited to backup access and is not an account-management review | Add lifecycle procedures, manager/approver ownership, inactivity removal, group/privilege baseline, review template and completed approvals |
| 13 | OKTA/DOJLogin configuration | Not started | None | Confirm integration applicability and capture approved configuration evidence |
| 14 | SIEM integration/CrowdStrike forwarding | Not started | None | Capture forwarding configuration, source coverage, test event and SIEM receipt evidence |
| 15 | N/A | N/A | None required | None |
| 16 | Contingency planning | Not started | None | Define RTO/RPO, BIA, communications bridge, recovery procedures, draft ISCP and test plan |
| 17 | ISCP training | Not started | None | Conduct training; retain materials, attendance, results and lessons learned |
| 18 | ISCP testing | Not started | None | Execute test, publish report, track corrective actions and finalize ISCP/BIA |

## Completion snapshot

Excluding the two N/A items, five of sixteen actionable worksheet tasks have
implementation-complete collector workflows. Two have partial foundations and
nine are not started. No actionable task should be represented as audit-complete
until its operational evidence and approval records are produced and reviewed.

## Work order

Continue in worksheet order:

1. Execute and close Task 1 operational evidence.
2. Execute and close Task 2 operational/manual evidence.
3. Execute and close Task 3 operational/manual evidence.
4. Skip Task 4 as N/A and complete Task 5 form review/feedback.
5. Correct and live-validate Task 6, then close its operational, approval and restricted-list evidence.
6. Execute and close Task 7 operational, identity, approval and restriction evidence.
7. Execute and close Task 8 configuration-baseline and monthly-review evidence.
8. Execute and close Task 9 component-inventory and monthly-review evidence.
9. Continue Tasks 10–14, skip Task 15, then complete Tasks 16–18.
