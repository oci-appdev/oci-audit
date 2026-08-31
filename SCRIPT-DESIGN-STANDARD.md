# OCI Audit Collector Design Standard

**Effective:** 2026-08-27

This standard applies to every new or materially redesigned collector in this
repository. Existing scripts should adopt it when they are next hardened.

## Required scope-selection interface

Every collector must support both of these modes:

1. **Interactive:** the default manual/no-scope-flag path, plus explicit `-i`
   and `--select-scope`
2. **Non-interactive:** an explicit automation mode plus compartment
   OCID/name flags, resolved-OCID confirmations and an exact approval value

Interactive mode must use `lib/oci-scope-selector.sh` and follow this sequence:

1. Resolve the authenticated tenancy OCID using a read-only OCI call.
2. List all active child compartments visible with `--access-level ANY` and
   `--compartment-id-in-subtree true`.
3. Display the tenancy and every discovered compartment with type, name and
   full OCID.
4. Require the operator to enter an exact discovered tenancy or compartment
   OCID. Names, partial OCIDs and menu numbers are not confirmation.
5. Resolve and display the selected type, name and OCID.
6. Require the operator to enter the exact same OCID a second time.
7. Resolve the final compartment list, then display a pre-scan summary with
   collector/control, region, selected type/name/OCID, every target
   compartment, requested services, output paths, cloud-operation boundary and
   sensitive-data warning.
8. Require exact uppercase `YES` after the summary.
9. Start service collection only after the two OCIDs match and `YES` is given.
10. Exit nonzero before the collector loop when the OCID is unknown, missing or
    mismatched, or final approval is refused/missing.

Selecting the tenancy means the tenancy root **plus every active discovered
child compartment**. The script must display that warning before confirmation.

## Safety and automation rules

- Interactive selection cannot be combined with `-c` or `-n`.
- A no-argument/manual run should default to interactive selection. It must not
  silently expand into a whole-tenancy service scan.
- Supplying `-c` or `-n` alone must not bypass confirmation. A manual run using
  those flags must confirm every resolved OCID twice and require exact uppercase
  `YES` after the plan.
- Scheduled runs must explicitly opt into `--non-interactive`, provide one
  exact `--confirm-scope-ocid` for every resolved target, and provide exact
  `--approve-scan YES`. These values must be part of the approved job
  definition and validated only after the plan is printed.
- Evidence collectors must require an explicit region or resolve and record the
  effective CLI region. A placeholder such as `default` is not acceptable
  evidence provenance.
- Scope discovery and validation must use only read-only list/get calls.
- Selection does not prove full visibility. Coverage ledgers and failed-call
  status remain mandatory so an IAM denial cannot look like an empty scope.
- A selector/approval abort must make no service collection calls or cloud
  changes. New and redesigned collectors should remove their own header-only
  outputs when the operator refuses the final plan.
- Full OCIDs and generated evidence are sensitive and must remain in the
  approved restricted evidence location.

## Required regression coverage

Each collector integration must prove:

- a discovered compartment can be selected and confirmed;
- the tenancy choice expands to root plus all active child compartments;
- a mismatched second OCID stops the run before the collector loop;
- a correct double-OCID entry followed by anything other than exact uppercase
  `YES` stops before the first service call;
- the pre-scan summary identifies region, resolved targets, requested services,
  local outputs and sensitive evidence;
- interactive and non-interactive scope flags cannot be combined;
- the read-only self-check and normal non-interactive interface still pass.
- a normal `-c`/`-n` run cannot silently become non-interactive;
- explicit automation fails closed for a missing/mismatched resolved OCID or
  any approval value other than exact uppercase `YES`.

The shared double-OCID implementation and regression examples are:

- `cp09-01-backup-type-config-frequency.sh`
- `cp09-02-backup-access-files-check.sh`
- `cp09-03-backup-replication-check.sh`
- `sc08-02-in-transit-encryption.sh`
- `sc28-oci-encryption-at-rest.sh`
- `cm07-01-open-ports-protocols-services.sh`
- `cm11-01-software-installation-control.sh`
- `cm02-01-configuration-baseline.sh`
- `cm08-01-component-inventory-baseline.sh`
- `tests/test-scope-selection.sh`
- `tests/test-cm07-01-open-ports.sh`
- `tests/test-cm11-01-software-installation-control.sh`
- `tests/test-cm02-01-configuration-baseline.sh`
- `tests/test-cm08-01-component-inventory.sh`

All nine canonical Task 1–3 and Task 6–9 collectors default no-scope manual runs to
the shared interactive workflow and implement the pre-scan summary plus
exact-`YES` gate. CM07-01 also implements the stricter explicit automation
contract above, as do CM11-01, CM02-01 and CM08-01. Retrofit the earlier collectors before their next material
change; every future collector must use the strict contract when introduced.
