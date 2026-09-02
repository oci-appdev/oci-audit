# Task 9 System Component Inventory Evidence Guide

## Control objective

Task 9 asks the organization to maintain an approved hardware/software
inventory baseline, review it monthly, identify additions/removals/changes, and
retain evidence of accountable review and corrective action.

The canonical collector is `cm08-01/cm08-01-component-inventory-baseline.sh`. It uses
the corrected `cm08-01/cm08-hw-sw-baseline.sh` as its read-only raw OCI inventory
engine. The raw engine refuses direct execution; CM02-01 or CM08-01 must pass
the exact approved caller, scope and region handshake after operator approval.
Both the discovery wrapper and raw engine also enforce a runtime positive
allowlist of OCI `list`/`get` action variants. The evidence design follows
CM-8 and CM-8(1) in
[NIST SP 800-53 Revision 5, Update 1](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final):
the component inventory and its updates are separate from CM-2 configuration
settings and approval decisions.

## What the workflow proves

CM08-01 keeps five assertions separate:

1. **Current technical inventory** — hardware, software and logical OCI
   components observed through read-only list/get calls.
2. **Approved prior inventory** — organization-owned component identity,
   system/technical owners, environment, criticality and approval provenance.
3. **Monthly reconciliation** — stable component keys and SHA-256 fingerprints
   classify components as `UNCHANGED`, `ADDED`, `REMOVED` or `CHANGED`.
4. **Change disposition** — each current addition, removal or change has one
   exact approved change, exception or corrective-action record.
5. **Coverage and monthly review** — API failures and guest/provider visibility
   gaps are retained, while reviewer counts are bound to the exact current
   reconciliation and scope.

The script never promotes a generated current snapshot into an approved asset
register. Generated templates are `PENDING-REVIEW` until an accountable owner
completes and approves them.

## Scope and safety boundary

Before workload collection, every normal run:

1. uses IAM list/get operations to discover the tenancy and active compartments;
2. displays tenancy and compartment OCIDs;
3. requires the exact selected tenancy or compartment OCID;
4. requires the same OCID a second time;
5. displays the region, profile, every target, high-volume installed-package
   collection, evidence work and output paths;
6. requires exact uppercase `YES`.

Manual `-c` and `-n` runs still require each resolved target OCID twice and the
final `YES`. Approved automation requires `--non-interactive`, one
`--confirm-scope-ocid` per exact resolved target, and `--approve-scan YES`.

An approved single compartment is forced to exact scope. It does not silently
expand into child compartments. A tenancy selection explicitly shows and scans
the root plus all discovered active child compartments. Oracle documents that
`compartment-id-in-subtree` applies to the tenancy/root compartment; the wrapper
therefore enumerates exact non-root targets instead of assuming subtree behavior
([OCI CLI compartment list reference](https://docs.oracle.com/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/iam/compartment/list.html)).

Run the source-level boundary check before collection:

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh --selfcheck
```

The check covers CM08-01, the shared scope helper and the invoked inventory
engine. It rejects OCI mutations and non-GET raw requests.

## Phase 1 — collect the current inventory

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  --inventory-only \
  -o ./evidence/task9-inventory
```

Use `-p DOJ-GOV-PROFILE` when a named OCI CLI profile is required. The named
profile is displayed in the approved plan and passed to discovery and raw
collection.

Installed-package collection is enabled for Task 9. OCI OS Management Hub uses
Oracle Cloud Agent enrollment for managed-instance inventory, so an OCI compute
instance alone is not proof that its in-guest packages were inventoried
([Oracle OS Management Hub overview](https://docs.oracle.com/iaas/osmh/doc/overview.htm)).

Primary outputs:

| Output | Purpose |
|---|---|
| `component_inventory` | Current normalized component identity and inventory fingerprint |
| `approved_inventory_template` | Pending ownership/approval worksheet for the next approved inventory |
| `unmanaged_coverage_gaps` | Guest, digest, OKE-node, location and provider-boundary limitations |
| `coverage` | Status of every underlying OCI operation |
| `raw_inventory` | Private per-service CSVs, engine summary, ledger and console log |
| `approved_scan_plan` | Exact scope/profile/work/output plan approved before collection |

The stable `component_key` is based on resource type, region and component
identity. It does not include the mutable inventory fingerprint. For installed
packages, the key uses managed-instance ID, package name, architecture and
package type; a package version update is therefore `CHANGED`, not an unrelated
removal plus addition.

## Phase 2 — approve the component inventory

Complete the generated approved-inventory template. Required governance fields
include:

- system name and system owner;
- technical owner;
- environment and criticality;
- inventory status (`ACTIVE`, `PLANNED` or `RETIRED`);
- baseline/inventory version ID;
- approval status `APPROVED`;
- approval ID, authority, approver and approval/effective dates;
- authoritative asset-register or evidence reference.

Do not change the technical identity or fingerprint fields merely to make a
later comparison match. Review current technical values, resolve gaps, and then
approve the retained snapshot as the authoritative inventory for the next
comparison period.

## Phase 3 — compare with the prior approved inventory

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  -b ./approved/cm08-component-inventory-2026-07.csv \
  -o ./evidence/task9-2026-08-pending
```

This run may correctly exit `3`: it creates the exact change-disposition and
monthly-review templates for the newly observed reconciliation. Exit `3` means
the evidence package is incomplete, not that collection should be discarded.

Reconciliation statuses:

| Status | Interpretation |
|---|---|
| `UNCHANGED` | Live identity and fingerprint match one complete approved prior row |
| `ADDED` | Live component has no matching prior approved component key |
| `REMOVED` | Prior approved component is absent from the live inventory |
| `CHANGED` | Stable component exists, but its inventory fingerprint differs |
| `APPROVED-INVENTORY-INCOMPLETE` | Ownership, approval, date or provenance is missing/invalid |
| `AMBIGUOUS-APPROVED-INVENTORY` | Multiple approved rows claim one component key |
| `COMPONENT-IDENTITY-MISMATCH` | Approved immutable identity fields disagree with the live component |

## Phase 4 — disposition changes and approve the monthly review

Every `ADDED`, `REMOVED` or `CHANGED` event requires exactly one disposition
whose component key, change type, previous fingerprint and current fingerprint
match the reconciliation. Accepted statuses are:

| Disposition | Additional evidence |
|---|---|
| `APPROVED` | Approved change/reference and retained evidence |
| `ACCEPTED-EXCEPTION` | Exception ID plus approval/evidence |
| `CORRECTIVE-ACTION-OPEN` | Corrective action, owner and unexpired due date plus approval/evidence |

Then complete the generated monthly-review template. Its counts are generated
from the current comparison and are validated on rerun. The record must have
exactly one current `YYYY-MM` row for the approved scope, all three review flags
set to `YES`, corrective-action status, approval and retained evidence location.

```bash
bash cm08-01/cm08-01-component-inventory-baseline.sh \
  -r us-langley-1 \
  -b ./approved/cm08-component-inventory-2026-07.csv \
  -d ./approved/cm08-change-dispositions-2026-08.csv \
  -m ./approved/cm08-monthly-review-2026-08.csv \
  -o ./evidence/task9-2026-08-final
```

A practical recurring sequence is:

1. compare the current scan to the prior approved inventory;
2. review coverage/errors and the unmanaged-gap ledger;
3. disposition every addition, removal and change;
4. complete and approve the count-bound monthly review;
5. rerun and retain the final evidence package;
6. approve the current snapshot as the next period's prior inventory.

NIST CM-8(1) expects inventory updates during component installations,
removals and system updates. Monthly comparison is compensating evidence; it
does not replace timely asset/change processes between scans.

## Coverage-gap interpretation

The gap ledger prevents broader claims than OCI can prove:

- compute-to-OS-agent identity is not asserted from display-name coincidence;
- compute instances without OS-managed evidence are explicit guest-software gaps;
- an OS summary reporting packages without package detail is explicit;
- OKE configured pool size is not treated as a running-node inventory;
- mutable Function/container tags without a digest are not stable software identity;
- provider-managed physical serial/firmware records remain an inherited/manual
  evidence boundary.

Gaps remain visible even when a monthly review is valid. The reviewer must
document how each relevant gap is mitigated or covered by retained evidence.

## Evidence integrity and exit codes

CM08-01 uses a private file mask, no timestamp overwrite, SHA-256 hashes for all
supplied governance inputs, retained raw/console/coverage ledgers, and
spreadsheet-formula neutralization for raw and canonical CSVs.

Exit `0` means collection and required evidence validation completed. It does
not mean that every finding is resolved or that the system is authorized.
Exit `3` means a collection failure, structural baseline problem, undispositioned
change, or missing/invalid current monthly review prevents a completeness claim.

Component metadata, OCIDs, package versions, owners and change references may
be sensitive. Store final evidence in the approved restricted repository and
apply the organization's retention and access rules.
