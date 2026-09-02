# Task 7 — CM-11 Software Installation Control Evidence Guide

`cm11-01/cm11-01-software-installation-control.sh` is the canonical Task 7 collector.
It is a read-only evidence workflow for these worksheet questions:

1. Who can install or provision software/resources?
2. What software/resources are approved?
3. What software/resources are restricted or prohibited?
4. Which request, approval and technical controls enforce those decisions?

The collector does not decide who should be authorized and does not provide a
generic restricted-software list. Those are organizational decisions that must
come from named, current and approved sources.

## Evidence model

| Question | OCI evidence | Required organizational evidence |
|---|---|---|
| Who can install | IAM policies attached to the tenancy, target or ancestor compartments; classic IAM groups/members; dynamic-group rules | Authorized-installer list, manager, approval authority, request process, technical control and identity-domain membership export where applicable |
| What is installed or available | OS Management Hub installed packages, Compute boot-image OCIDs, Container Registry images | Approved software/resource list with version/scope, business function, justification and approval |
| What is restricted | Live inventory matched to an external pattern list | Current prohibited/restricted list from the ISSO or designated policy authority, including effective dates and required restriction |
| How installation is controlled | OSMH managed instances, software sources, groups, lifecycle environments and scheduled jobs; private/public repository posture; exact Compute images | Host package-manager controls, sudo/local-admin restrictions, deployment-pipeline controls, exception process and approved change samples |

OCI documents that policy listing does not calculate which policies effectively
apply to a group or compartment. The collector therefore labels every parsed
installation grant as a **candidate entitlement**. Conditions, statement
combinations, inheritance, deny policies and cross-tenancy policy language
still require IAM review.

## Safe operating sequence

### 1. Run discovery only

```bash
bash cm11-01/cm11-01-software-installation-control.sh --selfcheck

bash cm11-01/cm11-01-software-installation-control.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task7-inventory
```

The normal run discovers the authenticated tenancy and active compartments,
displays full OCIDs, and asks for the exact tenancy or compartment OCID twice.
It then prints the region, every workload target, ancestor IAM policy boundary,
requested calls, inputs, outputs and sensitive-data warning. Collection starts
only after exact uppercase `YES`.

Selecting the tenancy scans the tenancy root plus every active discovered child
compartment. Selecting a compartment scans only that exact workload
compartment, while IAM policy evidence also includes its ancestors because
parent policies can affect a child.

Manual `-c` or `-n` runs also require every resolved OCID twice and exact
uppercase `YES`. Approved automation is explicit:

```bash
bash cm11-01/cm11-01-software-installation-control.sh \
  -c ocid1.compartment... \
  -r us-langley-1 \
  --non-interactive \
  --confirm-scope-ocid ocid1.compartment... \
  --approve-scan YES \
  --inventory-only \
  -o ./evidence/task7-inventory
```

For a multi-compartment `-n` job, provide one
`--confirm-scope-ocid <resolved-ocid>` in the displayed target order for every
resolved target. Use `-p/--profile` when the approved CLI configuration uses a
named profile; the profile is included in the pre-scan evidence plan.

### 2. Complete the authoritative inputs

Use the generated, timestamped templates from the inventory run. Repository
header-only references are also available in `templates/`.

#### Authorized installers

The system owner, IAM owner and ISSO review each candidate principal/user and
complete:

- authorization status and exact permitted capability;
- target scope and any conditions;
- manager and approval authority;
- approval ID, approver, approval date and expiration;
- technical enforcement, such as an OCI IAM group, OSMH operator role,
  restricted sudo rule or deployment-pipeline role;
- the access-request/modification/removal process and source reference.

Remove duplicate or superseded template rows. An authorization can be recorded
at group/principal level or for an exact user OCID. Use `ANY` only when the
approved source genuinely applies to every listed installation capability.

#### Approved software/resources

The configuration control board and system owner approve exact or wildcard
patterns for:

- `OS_PACKAGE` — package name, version, architecture, source/publisher and
  compartment/resource scope;
- `COMPUTE_BOOT_IMAGE` — exact approved image name/version and, where possible,
  the image OCID represented by the inventory source field;
- `CONTAINER_IMAGE` — repository, image/tag/version and immutable digest.

Each approved row needs an approval ID/authority/approver/date, business
function, justification and source reference. Broad `*` patterns should be
specifically justified and approved.

#### Restricted/prohibited software/resources

The ISSO or designated enterprise policy owner supplies the current list. Each
row must identify its authority, provider, source reference, effective date,
expiration if any and the required restriction. Categories are:

- `PROHIBITED` — not allowed without a separately approved exception;
- `RESTRICTED` — allowed only under the stated scope or technical conditions.

The collector intentionally has no built-in list that could become stale or be
mistaken for DOJ/OCS policy.

### 3. Run the complete reconciliation

```bash
bash cm11-01/cm11-01-software-installation-control.sh \
  -r us-langley-1 \
  -u ./approved/cm11-authorized-installers.csv \
  -a ./approved/cm11-approved-software.csv \
  -x ./approved/cm11-restricted-software.csv \
  -o ./evidence/task7-final
```

The input-provenance CSV records the absolute path, row count, SHA-256 hash,
authority, provider, source reference and dates for each supplied list.

## Output interpretation

| Output | Review purpose |
|---|---|
| `software_inventory` | OCI facts only: package/image/resource identity, version, source, lifecycle and collection state |
| `installer_entitlements` | Candidate IAM capability expanded to known classic-group users and reconciled to the authorized-installer source |
| `authorized_installer_template` | Review starting point; not authorization until completed and signed |
| `approved_software_template` | Distinct live items converted to approval-review rows |
| `software_reconciliation` | Approval status, restricted-list match and prioritized review result for every live item |
| `restricted_findings` | One row for every restricted/prohibited list match |
| `technical_controls` | OSMH, repository, image-pinning and Compute-to-OSMH coverage evidence |
| `iam_policy_statements` | Every collected statement plus transparent heuristic parsing and the documented built-in Administrators grant |
| `identity_membership` | Classic group users, dynamic-group matching rules and identity-domain boundary rows |
| `coverage` | Compartment/service/parent result counts; required to distinguish zero assets from failed collection |
| `collection_errors` | Failed/denied/unsupported calls; retained only when present |

Exit code `0` means collection and reconciliation completed. It does not mean
the control passed. Exit code `3` means evidence is incomplete, including a
denied call, malformed response, missing required source list, or a referenced
identity-domain group whose members were not collected.

Prioritize these review results:

1. `PROHIBITED-SOFTWARE`
2. `RESTRICTED-SOFTWARE-REVIEW`
3. `UNAUTHORIZED-ENTITLEMENT`
4. `UNAPPROVED-SOFTWARE`
5. `COLLECTION-INCOMPLETE`

## Mandatory manual evidence boundaries

The OCI APIs in this collector cannot prove all installation paths. Complete
and cross-reference the following evidence:

- Identity Domains group/user membership for every domain-qualified principal,
  including active status, export time and reviewer. Do not infer membership
  from the group name alone.
- SSH keys, Bastion/session controls, local Linux `sudo`/root rules and Windows
  local/domain administrator membership for every in-scope host.
- Break-glass accounts, credential custody, activation approval, monitoring and
  post-use review.
- Host package-manager configuration and repository restrictions for systems
  not fully enrolled in OS Management Hub.
- Windows installed-application inventory and any Windows systems for which the
  OSMH package endpoint is not the authoritative application inventory.
- Kubernetes, Functions, deployment pipeline and other application-runtime
  install/deploy permissions not represented by Compute boot images or
  Container Registry availability.
- Container image signing/scanning, immutable-digest deployment and promotion
  controls. A registry image is available software; it is not proof that the
  image is deployed.
- Approved software installation request, approval, implementation and
  validation procedure, including emergency and exception handling.
- At least one normal and one emergency/exception installation sample showing
  requester, manager/system-owner approval, installer, change ticket, technical
  result and post-install validation.
- Periodic review evidence for installer access, OSMH sources/lifecycle stages,
  approved software and restricted software.

For every Compute row with `OSMH-INVENTORY-COVERAGE=NOT-VERIFIED`, obtain an
alternate authoritative host package/application inventory. The value does not
prove that OSMH is disabled; it records that the exact Compute OCID was not
verified in the collected OSMH managed-instance set.

## Evidence handling and sign-off

Generated evidence contains user/group names, policy statements, full OCIDs,
package versions, repository names and security-control metadata. Do not commit
live evidence to this public repository. Store it in the approved restricted
evidence location and record:

- run date, region, selected OCID and exact target list;
- collector commit/version and command;
- operator and reviewer;
- all source-list immutable references and hashes;
- coverage/error disposition;
- finding owner, due date, exception/approval and closure evidence;
- system owner, IAM owner, ISSO and configuration-control approval.

## Oracle references used for the evidence boundary

- OCI IAM policy listing states that effective policy applicability cannot be
  obtained automatically through the API:
  <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/policy/list.html>
- IAM policy inheritance:
  <https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policies.htm>
- OS Management Hub package inventory:
  <https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/os-management-hub/managed-instance/list-installed-packages.html>
- OS Management Hub permissions, including package installation permissions:
  <https://docs.oracle.com/en-us/iaas/osmh/doc/policies-reference.htm>
- Container Registry push/pull policy controls:
  <https://docs.oracle.com/en-us/iaas/Content/Registry/Concepts/registrypolicyrepoaccess.htm>
- Compute launch/image policy examples:
  <https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/commonpolicies.htm>
