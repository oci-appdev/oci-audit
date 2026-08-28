# Task 6 Evidence Guide — Open Ports, Protocols and Services

**Control family:** CM-7, CM-7(1), PPSM  
**Canonical collector:** `cm07-01-open-ports-protocols-services.sh`  
**Last reviewed:** 2026-08-28

## Worksheet questions and evidence ownership

| Worksheet request | Primary evidence | Who must provide or approve it |
|---|---|---|
| List open ports, protocols and services, including function/justification | Collector inventory plus completed approval template | OCI Network/Cloud Operations runs the collector; system/application owners identify the actual business function and justification |
| Proof the open PPS were approved | Approval reconciliation and source-provenance CSV | The organization's designated CCB, PPSM authorizer, ISSO/ISSM or equivalent approving authority |
| Restricted PPS list | Restricted-list CSV, provenance and match report | The authoritative PPSM or enterprise security-policy owner; the exact office/person and source reference must be recorded |

Repository role names are examples, not a substitute for the organization's
actual delegation. The evidence package must name the real provider, approver,
date and source record.

## What the collector proves

The collector reads:

- VCNs;
- subnets and their Security List associations;
- Security Lists and embedded ingress/egress rules;
- NSGs and their ingress/egress rules;
- VNIC membership for each NSG;
- container tags that may help correlate ownership or approval records.

OCI documents Security Lists and NSGs as packet-level virtual firewall
features. Security Lists apply to VNICs through subnet association; NSGs apply
to selected VNICs. The collector therefore records both the rule and whether
the rule container is associated with a subnet or VNIC.

The collector does **not** prove that a host process is listening or that a
path is end-to-end reachable. Routes, public/private IPs, OCI Network Firewall,
Zero Trust Packet Routing, load-balancer listeners, host firewalls and
application configuration can further permit or block traffic.

Oracle references:

- <https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/rules/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/vnics/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/subnet/list.html>

## Safety and scope confirmation

A normal run is interactive. It:

1. Resolves the authenticated tenancy.
2. Lists the tenancy and every active discovered compartment with full OCIDs.
3. Requires the operator to enter the exact tenancy or compartment OCID.
4. Displays the resolved name/type and requires the exact same OCID again.
5. Expands a tenancy choice to root plus every active child compartment.
6. Prints every target, requested work, local output and input source.
7. Requires exact uppercase `YES`.
8. Starts Networking collection only after all confirmations pass.

Anything else aborts before the first Networking call and leaves no misleading
header-only CSV. Explicit `-c` and `-n` remain the approved automation paths.

Run the source-level guard first:

```bash
bash cm07-01-open-ports-protocols-services.sh --selfcheck
```

## Phase 1 — produce the live inventory and approval template

```bash
bash cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task6-inventory
```

Select either the tenancy or one exact compartment OCID when prompted. Enter
the selected OCID twice, review the summary, then type `YES`.

Inventory-only mode deliberately labels approval and restricted-list
evaluation as skipped. It generates:

- the live OCI rule inventory;
- a baseline template containing every normalized rule identity;
- coverage for VCNs, subnets, Security Lists, NSGs, NSG rules and VNIC
  associations;
- input-source records showing the two authority inputs were intentionally
  skipped.

## Phase 2 — obtain organizational approval

Use the generated `cm07-01_approval_baseline_template_*.csv`. Do not change
the normalized rule identity columns. The approving authority completes:

| Field | Requirement |
|---|---|
| `approval_status` | `APPROVED`, `DENIED` or `PENDING-REVIEW` |
| `approval_id` | CCB/PPSM/change-record identifier |
| `approval_authority` | Name of the delegated approving office |
| `approved_by` | Approver name or accountable role |
| `approval_date` | ISO date: `YYYY-MM-DD` |
| `expiration_date` | ISO date, when approval is time-limited |
| `business_function` | Actual system/service function |
| `justification` | Why this exact rule, direction, peer and range are required |
| `source_reference` | Immutable record, ticket, register or evidence reference |

An `APPROVED` row missing its authority, approver, date, business function,
justification or source reference is classified `APPROVAL-INCOMPLETE`.

## Phase 3 — obtain the authoritative restricted list

Start with
`templates/cm07-01-restricted-ports-list-template.csv`. The authoritative
PPSM/security-policy owner supplies each entry and must populate:

- unique entry ID;
- protocol and port/range;
- applicable direction;
- `RESTRICTED` or `PROHIBITED` category;
- service and policy function;
- authority and provider;
- source reference;
- effective and expiration dates.

The collector intentionally does not ship a built-in “DoD-aligned” list. A
static list without current authority, provider and source reference is not
defensible proof of the organization's restricted PPS baseline.

## Phase 4 — run the approval and restricted-list reconciliation

```bash
bash cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  -a ./approved/cm07-approved-ports.csv \
  -x ./approved/cm07-restricted-ports.csv \
  -o ./evidence/task6-final
```

The run generates:

| Output | Purpose |
|---|---|
| Open PPS inventory | Live rules, attachment context, inferred common service, approval and restricted status |
| Approval baseline template | Current live identities for the next approval cycle |
| Approval reconciliation | Approved matches, denied/pending rows, unapproved drift and approved rules no longer live |
| Restricted findings | One row per authoritative restricted/prohibited match with severity and provenance |
| Input sources | File hash, provider, authority, source reference and dates |
| Coverage | Scope and successful/failed collection by resource type |
| Error ledger | Retained only when a call or local post-processing step fails |

## Review rules

- `UNAPPROVED-DRIFT`, `DENIED`, `EXPIRED`,
  `APPROVAL-INCOMPLETE` and `AMBIGUOUS-BASELINE` require disposition.
- Every `RESTRICTED-MATCH` or `PROHIBITED-MATCH` requires review against
  the governing source.
- Every `INTERNET-WIDE` ingress rule requires explicit justification and
  layered-control evidence.
- Rules in containers with zero subnet/VNIC associations are not reported as
  active exposure; they remain reviewable stale configuration.
- Exit code `3`, non-OK coverage or a retained error ledger means the
  evidence is incomplete.
- Exit code `0` means collection completed. It does not mean the control
  passed.

## Required manual closure

- [ ] System/application owners verified actual listeners and service functions.
- [ ] Network diagrams and routes were reconciled to the listed rules.
- [ ] OCI Network Firewall/ZPR/load-balancer/host-firewall controls were
      reviewed where applicable.
- [ ] The approval authority signed the exact baseline used by the collector.
- [ ] The restricted-list owner certified the exact list and source reference.
- [ ] Findings, exceptions, remediation owners and due dates were documented.
- [ ] The complete package was stored in the approved restricted evidence
      location.
- [ ] Reviewer, review date and final disposition were recorded.

Do not commit live OCI evidence, OCIDs, CIDRs or approval identities to this
public repository.
