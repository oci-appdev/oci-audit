# SC-8 In-Transit Encryption Collector Safety Review

**Reviewed:** 2026-08-28  
**Collector:** `sc08-02/sc08-02-in-transit-encryption.sh`  
**Controls:** SC-8, SC-8(1), SC-13  
**Review scope:** source safety, OCI command inventory, scope authorization,
secret handling, collection integrity, local evidence handling and regression
coverage

## Verdict

**Static and mock safety review: PASS. Live tenancy execution: PENDING.**

The reviewed source contains 27 OCI wrapper call sites. Every cloud operation
is a `list` or `get`. The collector does not create, update, attach, detach,
rotate, delete or otherwise modify an OCI resource. It explicitly prohibits
`oci network ip-sec-psk get`, which would reveal an IPSec tunnel pre-shared
key.

This result means the collector is ready for a controlled read-only run. It is
not evidence that a live tenancy is compliant, that the operator has complete
visibility, or that the required manual evidence has been collected.

## Required interactive scan sequence

A no-argument invocation now enters interactive mode. It no longer defaults to
an immediate whole-tenancy service sweep.

```bash
bash sc08-02/sc08-02-in-transit-encryption.sh -r us-langley-1 -o ./evidence
```

The operator must complete these gates in order:

1. Review the discovered tenancy and active-compartment catalog.
2. Enter the exact discovered tenancy or compartment OCID.
3. Review the resolved type, name and full OCID.
4. Enter the exact same OCID again.
5. Review the pre-scan safety summary, including region, scope, every target
   compartment, requested services, local outputs and sensitive data warning.
6. Type exact uppercase `YES`.
7. Only then can the first SC-8 service API call run.

Selecting the tenancy means the root compartment plus every active discovered
child compartment. Any missing, unknown or mismatched OCID, end-of-input, or
response other than exact uppercase `YES` aborts before service collection.
Refused runs remove the header-only CSVs so they cannot be mistaken for
evidence.

Explicit `-c` and `-n` remain available for approved non-interactive job
definitions. Their resolved plan is printed to the job log, but they do not
prompt. `-c` accepts only a compartment OCID and is validated before service
collection. Use interactive mode to select the tenancy.

## OCI command inventory

| Area | Read-only operations |
|---|---|
| Scope discovery | IAM compartment `list`/`get` |
| Load Balancer | load balancer, listener and backend-set `list` |
| Network Load Balancer | NLB and listener `list` |
| Databases | Autonomous DB and Base DB system `list` |
| Object Storage | namespace `get`, bucket `list`/`get` |
| Compute storage | volume attachment and instance `list` |
| File Storage | availability-domain and mount-target `list` |
| API Gateway / OKE | gateway and cluster `list` |
| Site-to-Site VPN | CPE `list`, IPSec connection `list`/`get`, tunnel `list`, DRG attachment `list` |

The IPSec tunnel `list` response contains tunnel configuration/status and does
not include the shared-secret object. The separate `network ip-sec-psk get`
operation is prohibited by the self-check and static regression gate.

## Findings resolved by this review

| Severity | Previous condition | Resolution |
|---|---|---|
| High | No-argument execution immediately enumerated and scanned the tenancy | No-argument runs now require interactive double-OCID confirmation, plan review and exact `YES` |
| High | Source self-check focused on direct `oci` text and could miss a mutating `oci_capture` invocation | Self-check now scans wrapped calls; a parser regression independently requires every wrapper action to be `list`/`get` |
| High | A CLI process returning success with malformed/unexpected JSON could become a false zero-resource result | JSON syntax and list/get response shape are validated; bad responses become `ERROR`, retained evidence/error rows and exit `3` |
| High | A read-only PSK retrieval could satisfy a list/get-only policy while exposing a secret | `network ip-sec-psk get` is an explicit prohibited operation with an injection regression |
| Medium | Explicit `-c` lookup failure did not immediately stop the scan | Invalid/denied compartment validation exits before service collection |
| Medium | Unknown service tokens were detected only after the compartment loop began | Service allowlist validation occurs before any OCI request |
| Medium | Missing volume encryption fields defaulted to `false` | Missing fields now produce `unknown` plus a review finding, never a fabricated disabled assertion |
| Medium | CSV fields could begin with spreadsheet formula characters | Evidence, coverage and error CSV fields neutralize leading `=`, `+`, `-` and `@` |
| Medium | Generated evidence inherited the caller's file permissions | The collector sets `umask 077`; generated files are private to the operator by default |
| Medium | Predictable `/tmp` fallback could be used if `mktemp` failed | Secure `mktemp` creation is mandatory; failure stops the collector |
| Low | An existing timestamped output path could be overwritten | Header creation uses no-clobber semantics and refuses an existing path |
| Low | Backend TLS with peer verification disabled used an `OK-*` label | It now emits `REVIEW-BACKEND-CERT-VERIFY-DISABLED` |
| Low | `-c` plus `-n`, and whitespace in `-n`, produced ambiguous scope behavior | Scope modes are mutually exclusive and comma-separated names are trimmed/case-normalized |

## Collection integrity behavior

- Every evidence row carries `collection_status` and `collection_error`.
- Every requested compartment/service produces a coverage row.
- Every failed OCI call, including `NOTFOUND`, makes the run incomplete.
- A failed call produces an attributed `COLLECTION-FAILED` row and retained
  error ledger.
- Incomplete collection exits `3`; startup/scope/approval failure exits `1`.
- A denied IPSec tunnel call cannot become `TUNNEL-DOWN`, `NO-IPSEC` or
  `NO-VPN`.
- A successfully collected connection with other than two tunnel objects
  produces `IPSEC-TUNNEL-PAIR-INCOMPLETE` as a configuration finding.

## Local writes and sensitive data

The collector writes only to the operator-selected local output directory:

- evidence CSV;
- compartment/service coverage CSV;
- collection-error CSV, retained only for incomplete runs;
- one secure temporary stderr file per OCI request, immediately removed.

The output can contain full compartment OCIDs, resource names, endpoints,
public CPE addresses, static routes and negotiated TLS/IPSec parameters. Store
it only in the approved restricted evidence location. Do not commit live CSVs
or screenshots to this public repository.

## Remaining manual evidence boundaries

The API collector cannot by itself prove all end-to-end encryption paths.
Complete `sc08-02/TASK2-MANUAL-EVIDENCE-CHECKLIST.md`, including:

- both IPSec tunnel screenshots without exposing PSKs;
- Base DB `sqlnet.ora` or approved TCPS proof;
- encrypted FSS client-mount proof;
- NLB backend TLS proof;
- finding disposition, reviewer sign-off and controlled evidence reference.

## Regression gates

Run:

```bash
bash tests/run.sh
```

The suite proves:

- source syntax and read-only/no-secret self-check;
- all 27 wrapper call sites resolve to `list`/`get`;
- injected mutation and PSK-read calls fail the self-check;
- default interactive selection, compartment and tenancy confirmation;
- final `YES` approval and refusal before service calls;
- malformed response, denied tunnel and incomplete tunnel-pair handling;
- backend certificate verification and missing-volume-field findings;
- CSV formula neutralization and private output permissions.

Use a principal limited to OCI inspect/read permissions. Least-privilege IAM is
the cloud enforcement boundary even if a future source defect is introduced.
