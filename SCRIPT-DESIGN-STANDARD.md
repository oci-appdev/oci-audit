# OCI Audit Collector Design Standard

**Effective:** 2026-08-27; OCI Python SDK requirement added 2026-09-02

This standard applies to every new or materially redesigned collector in this
repository. Existing scripts should adopt it when they are next hardened.

## Required OCI Python SDK foundation

Every new or materially rewritten collector must use Oracle's official
`oci-python-sdk`. Use the version pinned in `ra05-01/requirements-oci-sdk.txt` unless a
documented service requirement needs a newer Oracle release.

- Use generated service clients and model attributes. Do not implement custom
  REST requests or duplicate SDK response models.
- Use `oci.pagination.list_call_get_all_results` for paginated list operations.
- Use `oci.retry.DEFAULT_RETRY_STRATEGY` unless the collector documents why a
  narrower Oracle SDK strategy is required.
- Use supported SDK authentication: config profiles, instance principals or
  resource principals. Require and record one explicit region.
- Put every cloud method behind an explicit runtime allowlist containing only
  required `list_*` and `get_*` methods. The self-check must fail if a mutating
  method enters that allowlist.
- Retain OCI HTTP status, service code and `opc-request-id` in the collection
  error ledger. A denied or malformed response must never become an empty or
  compliant result.
- Mock generated clients in regressions; prove that refusal and confirmation
  failure make no workload-client calls.

Do not recreate pagination, retries, signing, endpoints, request serialization
or service schemas unless the official SDK lacks the required capability. If
that happens, record the exact SDK limitation in `AUDIT.md` before adding a
custom implementation.

## Required scope-selection interface

Every collector must support both of these modes:

1. **Interactive:** the default manual/no-scope-flag path, plus explicit `-i`
   and `--select-scope`
2. **Non-interactive:** an explicit automation mode plus compartment
   OCID/name flags, resolved-OCID confirmations and an exact approval value

Shell collectors use `lib/oci-scope-selector.sh`. Python SDK collectors must
implement the same sequence through their shared SDK safety helper:

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

- `cp09-01/cp09-01-backup-type-config-frequency.sh`
- `cp09-02/cp09-02-backup-access-files-check.sh`
- `cp09-03/cp09-03-backup-replication-check.sh`
- `sc08-02/sc08-02-in-transit-encryption.sh`
- `sc28/sc28-oci-encryption-at-rest.sh`
- `cm07-01/cm07-01-open-ports-protocols-services.sh`
- `cm11-01/cm11-01-software-installation-control.sh`
- `cm02-01/cm02-01-configuration-baseline.sh`
- `cm08-01/cm08-01-component-inventory-baseline.sh`
- `tests/test-scope-selection.sh`
- `cm07-01/tests/test-cm07-01-open-ports.sh`
- `cm11-01/tests/test-cm11-01-software-installation-control.sh`
- `cm02-01/tests/test-cm02-01-configuration-baseline.sh`
- `cm08-01/tests/test-cm08-01-component-inventory.sh`

All nine canonical Task 1–3 and Task 6–9 collectors default no-scope manual runs
to the shared interactive workflow and implement the pre-scan summary plus
exact-`YES` gate. As of 2026-09-02 all nine also implement the strict explicit
automation contract above: the CP-9, SC-8 and SC-28 retrofit is complete, so
there are no remaining collectors on the old `-c`/`-n` bypass. Every future
collector must use the strict contract when introduced.

The shared implementations are `oci_scope_confirm_resolved_targets` and
`oci_scope_validate_automation` in `lib/oci-scope-selector.sh`.
`oci_scope_require_final_approval` no longer has a non-prompting branch; passing
anything other than `1` fails closed. The cross-collector fail-closed regression
is `tests/test-task1-3-automation-contract.sh`.

`ra05-01/ra05-01-vulnerability-tracking.py` is the first collector built on the Oracle
SDK standard. Its shared SDK primitives are in `ra05-01/lib/oci_audit_sdk.py`, and its
mock-client gate is `ra05-01/tests/test-ra05-01-vulnerability-tracking.py`.
