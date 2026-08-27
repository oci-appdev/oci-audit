# OCI Audit Collector Design Standard

**Effective:** 2026-08-27

This standard applies to every new or materially redesigned collector in this
repository. Existing scripts should adopt it when they are next hardened.

## Required scope-selection interface

Every collector must support both of these modes:

1. **Interactive:** `-i` and `--select-scope`
2. **Non-interactive:** explicit compartment OCID/name flags for controlled
   automation

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
7. Start service collection only after the two OCIDs match.
8. Exit nonzero before the collector loop when the OCID is unknown, missing or
   mismatched.

Selecting the tenancy means the tenancy root **plus every active discovered
child compartment**. The script must display that warning before confirmation.

## Safety and automation rules

- Interactive selection cannot be combined with `-c` or `-n`.
- Scheduled/non-interactive runs may continue to use explicit `-c` or `-n`
  scope flags; those values must be supplied by the approved job definition.
- Scope discovery and validation must use only read-only list/get calls.
- Selection does not prove full visibility. Coverage ledgers and failed-call
  status remain mandatory so an IAM denial cannot look like an empty scope.
- A selector abort may leave local empty/header-only output files, but it must
  make no service collection calls and no cloud changes.
- Full OCIDs and generated evidence are sensitive and must remain in the
  approved restricted evidence location.

## Required regression coverage

Each collector integration must prove:

- a discovered compartment can be selected and confirmed;
- the tenancy choice expands to root plus all active child compartments;
- a mismatched second OCID stops the run before the collector loop;
- interactive and non-interactive scope flags cannot be combined;
- the read-only self-check and normal non-interactive interface still pass.

The current implementation and regression examples are:

- `cp09-01-backup-type-config-frequency.sh`
- `cp09-02-backup-access-files-check.sh`
- `tests/test-scope-selection.sh`

