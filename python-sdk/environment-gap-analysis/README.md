# OCI old/new environment gap analysis

`oci-network-gap-analysis.py` is a read-only Oracle OCI Python SDK collector
for decommission planning. It compares common network and network-attached
resources against:

- a cutoff date (default `2026-01-01`);
- an old CIDR set (default `172.16.0.0/16`);
- a new CIDR set (default `10.0.0.0/8`); and
- optional confirmed old landing-zone root compartments and all discovered
  descendants.

It does **not** delete resources and does **not** make an authorization,
compliance, retention, legal-hold or business-owner decision.

## Decision rules

The collector emits conservative suggestions:

| Suggestion | Meaning |
|---|---|
| `REVIEW-DESTROY-CANDIDATE` | Created before the cutoff, linked only to the old CIDR, tenancy-wide full scan, no failed SDK calls, no unresolved references or inventoried dependents; approvals still required |
| `REVIEW-DESTROY-AFTER-DEPENDENCIES` | Same old/pre-cutoff evidence, but inventoried dependent resources must be dispositioned first |
| `REVIEW-OLD-LANDING-ZONE-CANDIDATE` | Pre-cutoff resource is under a confirmed old landing-zone root but has no exclusive 172.16 relationship; owner/dependency approval is required |
| `KEEP-CANDIDATE` | Linked to the new CIDR family |
| `KEEP-SHARED` | Linked to both old and new environments |
| `HOLD-*` | Collection, scope, creation-time or dependency evidence is incomplete |
| `REVIEW-*` | Technical facts do not support either an exclusive old-environment candidate or a protected new/shared classification |

Only a tenancy-wide, all-phase, error-free run can produce
`REVIEW-DESTROY-CANDIDATE`. Compartment scans are useful for investigation,
but old-network candidates remain `HOLD-PARTIAL-SCOPE` because dependencies
can cross compartment boundaries. Any unresolved relationship anywhere in the
inventory closes the global destroy-review gate; an apparently complete
resource cannot bypass an incomplete dependency elsewhere.

## Run

Install the repository-pinned Oracle SDK version:

```bash
python3 -m pip install -r requirements-oci-sdk.txt
```

Manual runs discover the tenancy and compartments, ask for an exact tenancy
or compartment OCID twice, print the complete plan, then require exact
uppercase `YES`:

```bash
python3 python-sdk/environment-gap-analysis/oci-network-gap-analysis.py \
  --region us-ashburn-1 \
  --output-dir /restricted/evidence/network-gap
```

For custom CIDRs, repeat `--old-cidr` or `--new-cidr`:

```bash
python3 python-sdk/environment-gap-analysis/oci-network-gap-analysis.py \
  --region us-ashburn-1 \
  --cutoff-date 2026-01-01 \
  --old-cidr 172.16.0.0/16 \
  --new-cidr 10.0.0.0/8 \
  --output-dir /restricted/evidence/network-gap
```

To include an old landing-zone compartment hierarchy, provide each root
compartment OCID. The script validates it against discovered compartments,
requires the exact OCID twice in a manual run, and requires every discovered
descendant to be present in the scan. A tenancy scan is recommended:

```bash
python3 python-sdk/environment-gap-analysis/oci-network-gap-analysis.py \
  --region us-ashburn-1 \
  --tenancy-scope \
  --old-landing-zone-compartment-id ocid1.compartment...old_landing_zone \
  --output-dir /restricted/evidence/network-gap
```

Automation requires the exact resolved target OCID set and exact approval:

```bash
python3 python-sdk/environment-gap-analysis/oci-network-gap-analysis.py \
  --region us-ashburn-1 \
  --tenancy-scope \
  --non-interactive \
  --confirm-scope-ocid ocid1.tenancy... \
  --confirm-scope-ocid ocid1.compartment... \
  --old-landing-zone-compartment-id ocid1.compartment...old_landing_zone \
  --confirm-old-landing-zone-compartment-ocid ocid1.compartment...old_landing_zone \
  --approve-scan YES \
  --output-dir /restricted/evidence/network-gap
```

For tenancy scope, supply one `--confirm-scope-ocid` for the tenancy root and
every active discovered child compartment printed in the plan.

## Evidence

The collector writes private, timestamped files:

- `resources.csv`: age, network classification and suggested disposition;
- `keep_candidates.csv`: protected new/shared candidates;
- `destroy_review_candidates.csv`: pre-cutoff exclusive-old or confirmed
  landing-zone resources that can enter the approval review;
- `holds_and_other_review.csv`: incomplete, ambiguous, post-cutoff and other
  review rows;
- `old_landing_zone_resources.csv`: every inventoried resource in a confirmed
  old landing-zone root or discovered descendant;
- `dependencies.csv`: resolved and unresolved resource relationships;
- `unresolved_links.csv`: references that prevent safe decommission decisions;
- `decision_template.csv`: organization-owned approval fields;
- `coverage.csv` and `errors.csv`: per-operation coverage and failures;
- `plan.txt`, `summary.txt` and `manifest.csv`.

Before any destruction, complete the decision template and independently
verify business ownership, migration completion, upstream/downstream
dependencies, backups/exports, retention and legal holds, security approval,
the change ticket, the correct region, and non-OCI or guest/application
dependencies. The script deliberately contains no delete, terminate or update
operation.

## Current technical coverage

The SDK inventory includes VCNs, subnets, VLANs, route/security/DHCP objects,
gateways, DRGs/attachments, NSGs, Compute instances/VNICs/private IPs,
Block/Boot Volumes and Volume Groups/attachments, classic and network load
balancers, Base/Autonomous/MySQL/PostgreSQL database systems, VM clusters, OKE,
API Gateway, Bastion, FSS mount targets and Functions applications.

Volume attachments are reconciled after every target compartment is scanned,
so an instance and its volume may reside in different compartments without the
relationship depending on collection order. Missing DRG, volume, VNIC, FSS or
export-set references are written as unresolved evidence and hold the global
destroy-review gate.

Service-specific private endpoints outside that list, other regions,
in-guest dependencies, DNS consumers, external systems, Terraform state,
application dependencies and organization-owned records are explicit manual
boundaries. Omitting a collection phase or encountering a missing SDK
permission blocks every destroy candidate.

Exit `0` means every requested call completed and all required phases were
selected; it still does not approve destruction. Exit `2` means startup,
scope, confirmation or input validation failed. Exit `3` means a required
phase was omitted, at least one SDK call failed, or an inventory relationship
remained unresolved, so destroy conclusions are held.
