# OCS Audit Master Task List

**Last reviewed:** 2026-08-28

**Tracking basis:** repository implementation plus evidence artifacts visible in this repository

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
| 2 | Encryption in transit, including IPSec screenshots and overall proof | Implementation complete | Safety-reviewed `sc08-02-in-transit-encryption.sh`; default interactive tenancy/compartment discovery, double-OCID and final scan-summary/`YES` gate; 27 list/get call sites with mutation and PSK-read injection gates; failure-aware/response-shape-validated CSVs; private/formula-safe evidence; LB frontend/backend, NLB, databases, Object Storage, volumes, FSS, API Gateway, OKE, CPE/IPSec tunnels and DRG context; two-tunnel/denied-call gates; safety report and manual checklist | Run in every in-scope region/compartment under a read-only principal; retain approved scan summary; reconcile coverage/findings; require both IPSec tunnels or disposition `IPSEC-TUNNEL-PAIR-INCOMPLETE`; complete screenshots, Base DB `sqlnet.ora`, FSS mounts and NLB backend proof; review and store signed evidence package |
| 3 | Encryption at rest | Implementation complete | Failure-aware `sc28-oci-encryption-at-rest.sh`; default interactive tenancy/compartment discovery, double-OCID, resolved plan and exact-`YES` gate; storage/database key custody; current MySQL/PostgreSQL handling; Vault type/lifecycle/deletion; KMS HSM, AES key shape, automatic rotation and key-version evidence; refusal/no-workload-call, denied-call and rotation regressions; manual evidence checklist | Run in every in-scope region/compartment; retain the approved scan plan; reconcile CMK data stores to keys; resolve non-OK rows and CMK/HSM/rotation findings; complete key-admin, Audit-log, procedure and reviewer evidence; store signed package |
| 4 | N/A | N/A | None required | None |
| 5 | Continuous Monitoring Form review/feedback | Not started | None | Add reviewed form, feedback log, owner, disposition and approval |
| 6 | Ports/protocols/services list, approval proof and restricted list | Partial | Three CM-7/PPSM collectors exist | Fix approval-baseline ingestion and reconciliation identity; add failure ledger; use authoritative PPSM CAL; obtain CCB/PPSM approval and reconciliation evidence |
| 7 | Software installation control | Not started | Package inventory is adjacent evidence only | Document authorized installers, approved software list, request/approval process and technical enforcement |
| 8 | Configuration baseline | Partial | `cm08-hw-sw-baseline.sh` captures configuration attributes | Establish CI register, System Design Form, approved baseline, monthly comparison/review process and signed evidence |
| 9 | Hardware/software inventory baseline | Partial | `cm08-hw-sw-baseline.sh` provides a strong failure-aware inventory collector | Execute monthly, compare to approved baseline, disposition changes, sign and archive evidence |
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

Excluding the two N/A items, three of sixteen actionable worksheet tasks have
implementation-complete collector workflows. Three have partial foundations and
ten are not started. No actionable task should be represented as audit-complete
until its operational evidence and approval records are produced and reviewed.

## Work order

Continue in worksheet order:

1. Execute and close Task 1 operational evidence.
2. Execute and close Task 2 operational/manual evidence.
3. Execute and close Task 3 operational/manual evidence.
4. Skip Task 4 as N/A and complete Task 5 form review/feedback.
5. Repair and operationalize Task 6.
6. Continue Tasks 7–14, skip Task 15, then complete Tasks 16–18.
