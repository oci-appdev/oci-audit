# Task 13 Okta/DOJLogin Configuration Evidence Guide

## Purpose and evidence boundary

`ia02-01-federation-configuration.py` inventories the OCI side of Identity
Domains federation with Oracle's OCI Python SDK, then reconciles every
discovered identity provider to an owner-approved applicability decision. It
does not infer that a provider is Okta or DOJLogin, declare an integration
approved, or prove successful authentication from configuration alone.

The collector deliberately excludes client secrets, hashed client secrets,
tokens, passwords, SAML metadata XML, raw certificates, MFA seeds, bypass data
and recovery data. URLs and certificates are represented by host names,
presence flags and SHA-256 values. Groovy configuration and rule-return values
are hashed rather than exported as clear text.

## Install and safety check

```bash
python3 -m pip install -r requirements-oci-sdk.txt
python3 ia02-01-federation-configuration.py --selfcheck
```

The runtime allowlist permits only:

- classic Identity `get_compartment`, `list_compartments` and `list_domains`;
- Identity Domains `list_identity_providers`, `list_apps`, `list_policies`,
  `list_rules` and `list_authentication_factor_settings`.

No SDK create, update, delete or equivalent method is allowed.

## Scope and confirmation

A normal run discovers the tenancy and active compartments and asks for the
exact tenancy or compartment OCID twice. It then prints the full plan and
requires exact uppercase `YES` before Identity Domain collection begins.
Manual `-c` and `-n` runs retain both confirmations.

Task 13 is a tenancy-level integration question. A compartment selection is
supported for investigation, but it queries only Identity Domains located in
that confirmed compartment and can never produce a `COMPLETE` Task 13 result.
Use tenancy scope for the final package; this queries root and every active
discovered compartment.

Strict automation requires all resolved target OCIDs:

```bash
python3 ia02-01-federation-configuration.py \
  -r us-langley-1 \
  --tenancy-scope \
  --non-interactive \
  --confirm-scope-ocid ocid1.tenancy... \
  --confirm-scope-ocid ocid1.compartment... \
  --approve-scan YES \
  -o ./evidence/task13-technical
```

Provide one `--confirm-scope-ocid` for the root and every active compartment
shown in the plan. Scheduled-job OCIDs and approval must be part of the
approved job definition.

## Evidence lifecycle

### 1. Generate the technical snapshot

Run without governance inputs. Exit `3` is expected: OCI collection can be
complete while the applicability and external test evidence are still
missing. Preserve the approved plan, configuration inventories, coverage,
manifest and summary.

The main outputs are:

- `identity_providers.csv`: SAML/federation settings with URL/certificate
  fingerprints and JIT/mapping facts;
- `federation_apps.csv`: safe app linkage, grant and sign-on references without
  client secrets or certificates;
- `signon_policies.csv` and `signon_rules.csv`: stable identifiers and hashed
  executable/condition values;
- `authentication_factor_settings.csv`: non-secret MFA enablement settings;
- `integration_register_template.csv`: one exact row per provider, or one
  `NO-PROVIDER:<tenancy>` row when none is configured;
- collection coverage, errors, manifest and summary.

### 2. Approve the applicability register

Complete every row of `integration_register_template.csv`. Do not remove an
inactive or apparently unrelated provider. Each discovered provider must be
marked `APPLICABLE` or `NOT-APPLICABLE` and approved by the responsible owner.

For an applicable row:

- identify `OKTA`, `DOJLOGIN` or `OTHER` from authoritative records;
- state the integration role and provisioning mode (`SCIM`, `JIT`, `MANUAL` or
  `NONE`);
- bind any reviewed app, policy and rule keys to the current OCI snapshot;
- reference and hash the restricted external provider configuration export;
- record approved certificate and mapping reviews;
- include owner, approver, authority, rationale and evidence reference.

For a not-applicable row, use provisioning mode `NONE`, select no live
app/policy/rule keys, set both review statuses to `NOT-APPLICABLE`, and retain
the approved rationale and evidence. A technical absence is not its own N/A
approval.

Run with the register to validate it and generate the applicable-provider test
template:

```bash
python3 ia02-01-federation-configuration.py \
  -r us-langley-1 \
  --integration-register ./approved/ia02-integration-register.csv \
  -o ./evidence/task13-reconciliation
```

### 3. Complete external tests

For every applicable provider, the generated template requires:

- `AUTHENTICATION`;
- `MFA`;
- `PROVISIONING`;
- `DEPROVISIONING`;
- `GROUP-MAPPING`.

Record the expected result, actual `PASS`/`FAIL`/`NOT-APPLICABLE` result,
timestamp, tester, evidence reference, approver and approval status. Use
`NOT-APPLICABLE` only when that function is intentionally unused and retain a
rationale and evidence. A failed test blocks completion.

### 4. Build the final package

```bash
python3 ia02-01-federation-configuration.py \
  -r us-langley-1 \
  --integration-register ./approved/ia02-integration-register.csv \
  --test-evidence ./approved/ia02-test-evidence.csv \
  -o ./evidence/task13-final
```

The final run exits `0` only when tenancy-wide collection succeeds, every
provider has a valid approved disposition, and all required applicable-provider
tests are valid and approved.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Tenancy-wide technical collection and governance/test reconciliation are complete. |
| `1` | Input, scope, confirmation, collision or pre-scan validation failed; workload collection did not start where applicable. |
| `2` | A collection call or response-shape validation failed; the evidence is incomplete. |
| `3` | Technical collection completed, but scope or organizational evidence is incomplete. |

## Evidence still owned outside OCI

Retain the external IdP application/configuration export, certificate lifecycle
approval, attribute/group mapping approval, user lifecycle design, test
screenshots/logs, test identities, owner approval and any exception record in
the approved restricted evidence location. Never commit generated evidence or
secret-bearing provider exports to this public repository.
