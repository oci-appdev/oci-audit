# Task 6 Evidence Guide — Open Ports, Protocols and Services

**Control family:** CM-7, CM-7(1), PPSM  
**Canonical collector:** `cm07-01/cm07-01-open-ports-protocols-services.sh`  
**Last reviewed:** 2026-08-28

## Worksheet questions and evidence ownership

| Worksheet request | Primary evidence | Who must provide or approve it |
|---|---|---|
| List open ports, protocols and services, including function/justification | Collector inventory plus completed service/listener mapping | OCI Network/Cloud Operations runs the collector; system/application owners verify the actual resource, listener, service, function and justification |
| Proof the open PPS were approved | Approval reconciliation and source-provenance CSV | The organization's designated CCB, PPSM authorizer, ISSO/ISSM or equivalent approving authority |
| Restricted PPS list | Restricted-list CSV, provenance and match report | The authoritative PPSM or enterprise security-policy owner; the exact office/person and source reference must be recorded |

Repository role names are examples, not a substitute for the organization's
actual delegation. The evidence package must name the real provider, approver,
date and source record.

## What the collector proves

The collector reads:

- VCNs;
- subnets and their Security List associations;
- Security Lists and embedded ingress/egress rules, **including Security Lists
  that live in another compartment but are attached to an in-scope subnet**;
- NSGs and their ingress/egress rules;
- VNIC membership for each NSG;
- container tags that may help correlate ownership or approval records.

OCI documents Security Lists and NSGs as packet-level virtual firewall
features. Security Lists apply to VNICs through subnet association; NSGs apply
to selected VNICs. The collector therefore records both the rule and whether
the rule container is associated with a subnet or VNIC.

The OCI calls do **not** prove that a host process is listening or that a path
is end-to-end reachable. The generated service-mapping template closes that
boundary through accountable system-owner verification and an evidence
reference for each live rule. Routes, public/private IPs, OCI Network Firewall,
Zero Trust Packet Routing and host firewalls can still further permit or block
traffic and remain part of final review.

Oracle references:

- <https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/securityrules.htm>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/security-list/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/rules/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/nsg/vnics/list.html>
- <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/network/subnet/list.html>

## Retired reference scripts

`cm07-openports.sh`, `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` refuse to
run and exit `2`. They suppress OCI stderr, so a denied call would be recorded
as "no rules found", and `cm07-ppsm.sh` additionally embeds a static restricted
list that could be mistaken for current organizational policy. They remain in
the repository as readable reference only.

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
header-only CSV. The region is mandatory so the evidence never records an
unknown CLI default.

Supplying `-c` or `-n` manually does not bypass authorization. Every resolved
OCID is entered twice, the complete plan is shown and exact uppercase `YES` is
still required. Automation must add `--non-interactive`, one exact
`--confirm-scope-ocid` for every resolved compartment and
`--approve-scan YES`.

Run the source-level guard first:

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh --selfcheck
```

## Phase 1 — produce live inventory and review templates

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh \
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
- a service/listener mapping template containing every normalized rule
  identity;
- coverage for VCNs, subnets, Security Lists, NSGs, NSG rules and VNIC
  associations;
- input-source records showing the two authority inputs were intentionally
  skipped.

## Phase 2 — verify actual services and listeners

Use the generated `cm07-01_service_mapping_template_*.csv`. A rule is not proof
of an actual service. The system/application owner must add one or more mapping
rows per `rule_key` and provide:

| Field group | Requirement |
|---|---|
| Mapping | Unique `mapping_id` and unchanged generated `rule_key` |
| Resource | OCI resource OCID, type and name |
| Listener | `LISTENING`, `NOT-LISTENING` or `NOT-APPLICABLE`; address, port and protocol are mandatory when listening |
| Service | Actual service name, business function and justification |
| Accountability | System owner, verifier and verification date |
| Evidence | Listener/configuration evidence reference and source record |

`UNKNOWN`, a missing live-rule mapping, future verification date or incomplete
required fields causes exit `3`. Multiple mappings per rule are allowed when a
shared rule genuinely applies to multiple resources or listeners.

## Phase 3 — obtain organizational approval

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

Approval dates cannot be in the future, and expiration cannot precede approval.

## Phase 4 — obtain the authoritative restricted list

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

## Phase 5 — run the complete reconciliation

```bash
bash cm07-01/cm07-01-open-ports-protocols-services.sh \
  -r us-langley-1 \
  -a ./approved/cm07-approved-ports.csv \
  -x ./approved/cm07-restricted-ports.csv \
  -s ./approved/cm07-verified-services.csv \
  -o ./evidence/task6-final
```

The run generates:

| Output | Purpose |
|---|---|
| Open PPS inventory | Live rules, attachment context, inferred common service, approval and restricted status |
| Approval baseline template | Current live identities for the next approval cycle |
| Approval reconciliation | Approved matches, denied/pending rows, unapproved drift and approved rules no longer live |
| Restricted findings | One row per authoritative restricted/prohibited match with severity and provenance |
| Service mapping template | Current live identities for the next owner-verification cycle |
| Service reconciliation | Actual resources/listeners/services, owner evidence, missing mappings and stale mappings |
| Input sources | File hash, provider, authority, source reference and dates |
| Coverage | Scope and successful/failed collection by resource type |
| Error ledger | Retained only when a call or local post-processing step fails |

## Reading the 2026-09-02 corrective outputs

Four things changed when the defects in `cm07-01/CM07-CORRECTIVE-REVIEW.md` were fixed.

**Cross-compartment Security Lists.** A Security List owned by another
compartment but attached to an in-scope subnet is now resolved with a read-only
`get` and appears with `container_type` `SecurityList(cross-compartment)` and
the `compartment_id` of its **owner**, not of the scanned compartment. If that
resolution fails, you get an `UNRESOLVED-SECURITY-LIST` coverage row and exit
`3` — never a silently missing rule.

**`attachment_count` of `UNKNOWN` under a partial scope.** A compartment-scoped
run cannot enumerate subnets elsewhere, so it cannot prove that nothing attaches
a container. Zero in-scope associations is therefore recorded as `UNKNOWN` with
an `UNRESOLVED-SUBNET-ASSOCIATION` coverage row. **Do not read this as an
unattached container.** Run a tenancy scope to establish that; the scan summary
records `scope_covers_tenancy`.

**ICMP and other portless protocols.** ICMP and ICMPv6 carry type and code, not
ports, so their `destination_port_min/max` are blank and they no longer match
port-scoped restricted entries. In the restricted list, an entry naming a range
narrower than `0-65535` is transport-scoped and cannot describe a portless
protocol; an entry left at the full range (or blank) is protocol-scoped and does
cover them. Use `icmp_type`/`icmp_code` to target ICMP specifically. A portless
entry that names ports is rejected at input validation.

**`semantic_rule_key` and `APPROVED-CONTAINER-RECREATED`.** `rule_key` binds a
rule to its container OCID; `semantic_rule_key` is the same identity without it.
When a Security List or NSG is deleted and recreated, its rules are unchanged
but the OCID is new, so the strict key no longer matches the baseline. That case
is now labelled `APPROVED-CONTAINER-RECREATED` instead of `UNAPPROVED-DRIFT`.
**It is counted as unapproved, not approved.** Confirm the new container is the
approved one, then update the baseline.

`peer_type` is emitted alongside `source_type`; `source_type` names the peer at
both ends and is misleading on egress rules. `source_type` remains part of the
identity hash, so existing approved baselines stay valid and either column may
be supplied.

The run also writes `cm07-01_scan_summary_*.csv`, carrying the region, CLI
profile, scope type and OCID, compartment count, `scope_covers_tenancy`, the
subnet-association caveat and every count. Retain it: it is the only record in
the evidence package of what the run actually covered.

Pass `-p/--profile` when the approved run uses a named OCI CLI profile. It is
shown in the pre-scan plan and recorded in the scan summary.

## Review rules

- `APPROVED-CONTAINER-RECREATED` requires confirming the new container is the
  approved one before the rule is accepted, and a baseline update.
- `UNRESOLVED-SECURITY-LIST` and `UNRESOLVED-SUBNET-ASSOCIATION` coverage rows
  mean the inventory is not provably complete for that object.
- `UNAPPROVED-DRIFT`, `DENIED`, `EXPIRED`,
  `APPROVAL-INCOMPLETE` and `AMBIGUOUS-BASELINE` require disposition.
- Every `RESTRICTED-MATCH` or `PROHIBITED-MATCH` requires review against
  the governing source.
- Every `INTERNET-WIDE` ingress rule requires explicit justification and
  layered-control evidence.
- `SERVICE-MAPPING-NOT-PROVIDED`, `SERVICE-MAPPING-MISSING`,
  `SERVICE-MAPPING-INCOMPLETE` or `UNKNOWN` listener status means actual service
  proof is incomplete and causes exit `3`.
- Rules in containers with zero subnet/VNIC associations are not reported as
  active exposure; they remain reviewable stale configuration. Under a partial
  scope this shows as `UNKNOWN`, not `0`, because absence of an in-scope
  association does not prove absence of an association.
- Exit code `3`, non-OK coverage or a retained error ledger means the
  evidence is incomplete.
- Exit code `0` means collection completed. It does not mean the control
  passed.

## Required manual closure

- [ ] System/application owners completed and signed the actual-service/listener
      mapping for every live rule.
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
