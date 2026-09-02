# Implementation Handoff

**Updated:** 2026-09-02

**Working branch:** `codex/task13-ia02-federation`

**Published base:** `ec973ceb8b9dd70e05627a435712bd35e196eee7` (`main`)

**Task 13 implementation commit:** `526b2e1`

**Current milestone:** Tasks 1–3, 7 and 9–13 collector implementations complete; Tasks 6 and 8 partial; live/manual/approval evidence pending

**Delivery:** IA02-01 focused and full repository gates passed locally; publication is pending user direction

## Latest milestone — Task 13 Okta/DOJLogin federation

`ia02-01-federation-configuration.py` is the canonical applicability-first
Task 13 workflow. It uses only Oracle's generated Identity and Identity Domains
clients. It inventories domains, providers, safe app linkage, sign-on
policies/rules and authentication-factor settings without exporting client
secrets, hashed secrets, tokens, passwords, SAML metadata XML, raw
certificates, MFA seeds, bypass data or recovery data.

The normal run discovers the tenancy and active compartments, requires an
exact tenancy or compartment OCID twice, prints every target, SDK method,
governance input and output, then requires exact uppercase `YES`. Manual
`-c`/`-n` retains the same gate. Automation requires every exact resolved
target OCID and `--approve-scan YES`.

The Oracle Identity `list_domains` endpoint has no subtree flag. Tenancy mode
therefore queries root and every active discovered compartment separately and
de-duplicates domain OCIDs. A compartment mode is supported for investigation,
but remains explicitly `INCOMPLETE` for the tenancy-level Task 13 conclusion.

Identity Providers, Apps, Policies and Rules use the existing generated SCIM
start-index helper. Oracle SDK 2.185.1 exposes
`list_authentication_factor_settings` with `page`/`limit` while returning a
`resources` collection, which is incompatible with both Oracle's normal
`items` paginator and start-index paging. The documented shared
`sdk_resources_page_list` guard follows only generated response page tokens,
uses Oracle retries and rejects malformed/repeated pagination; no custom REST
request or model exists.

The technical run generates an exact provider register. Every discovered
provider, including inactive/unrelated candidates, requires an owner-approved
`APPLICABLE` or `NOT-APPLICABLE` disposition. Applicable rows bind the exact
configuration snapshot plus selected app/policy/rule keys to an external
configuration reference/hash. A second stage requires approved
`AUTHENTICATION`, `MFA`, `PROVISIONING`, `DEPROVISIONING` and `GROUP-MAPPING`
tests for every applicable provider. OCI facts alone never become an approval,
compliance result or N/A decision.

Instructions are in `TASK13-OKTA-DOJLOGIN-EVIDENCE-GUIDE.md`. The focused gate
is `tests/test-ia02-01-federation-configuration.py`; it covers both Identity
Domains pagination shapes, tenancy expansion, compartment-only status,
repeated-page rejection, stable snapshot binding, secret exclusion,
private/formula-safe/immutable output, manual and automation refusal before
directory reads, denied calls, exact provider coverage and all five test types.

Task 13 is not audit-complete. Run it tenancy-wide, resolve collection errors,
obtain the authoritative Okta/DOJLogin/provider dispositions and restricted
external configuration export, complete certificate/mapping review, execute
and approve all five tests, and archive the signed final package.

## Next implementation target

Task 14 is SIEM integration and CrowdStrike log forwarding. Start by confirming
which OCI and CrowdStrike sources are in scope, then design source-coverage,
forwarding-configuration, test-event, SIEM-receipt and owner-approval evidence.
Continue using the pinned OCI Python SDK, mandatory exact scope confirmation,
full pre-scan plan, exact `YES`, strict automation and memory update rules.

## Prior milestone — Task 12 account management

`ac02-01-account-management.py` is the canonical AC-2 workflow and the third
collector under the user-directed Oracle OCI Python SDK standard. Generated
classic Identity and Identity Domains clients collect users, groups,
memberships, dynamic groups, classic authentication/network policy, credential
metadata and IAM policy statements. Credential values and SCIM password/MFA
recovery material are never selected or written.

The normal run requires an exact discovered tenancy or compartment OCID twice,
prints every target, identity and policy scope, SDK operation, governance input
and output, then requires exact uppercase `YES`. Manual `-c`/`-n` retains the
same gate. Automation requires `--non-interactive`, the complete exact target
OCID set and `--approve-scan YES`.

Classic list operations use Oracle pagination/retries. The Identity Domains
generated SCIM responses use start-index/total-result pagination rather than
`opc-next-page`, so `lib/oci_audit_sdk.py` now has a narrowly guarded
`sdk_scim_list` helper. It still calls only generated `list_users` and
`list_groups` methods and fails on malformed, changing or incomplete response
shapes.

The workflow separates technical facts from authority. OCI OCIDs de-duplicate
classic and Identity Domain accounts/groups. Policy statements and the built-in
Administrators grant are privilege candidates, not effective-access decisions.
Five organization-owned inputs establish the account register, membership and
privilege decisions, inactivity policy and lifecycle procedure. A reconciliation
run generates the exact current snapshot/count-bound monthly-review template;
the final run validates all six inputs.

Evidence instructions are in `TASK12-ACCOUNT-MANAGEMENT-EVIDENCE-GUIDE.md`.
The focused gate is `tests/test-ac02-01-account-management.py`; it covers both
pagination models, de-duplication, access/privilege binding, secret exclusion,
denied and malformed collection, private/formula-safe immutable output,
double-OCID/plan/`YES`, strict automation, refusal before account calls,
inactivity decisions and full governance validation.

Task 12 is not audit-complete. Live collection, authoritative HR and service
account records, manager/approver proof, unused-account disposition,
Okta/DOJLogin, host-local, database-native, application and break-glass
coverage, the approved monthly review and archive references are still needed.

## Prior milestone — Task 11 configuration change tracking

`cm03-01-configuration-change-tracking.py` is the canonical CM-3 workflow and
the second collector under the user-directed Oracle OCI Python SDK standard.
It uses guarded Identity scope discovery plus Audit `get_configuration` and
paginated `list_events`; no mutating SDK method is allowed.

The normal run requires an exact discovered tenancy or compartment OCID twice,
prints the region, time window, every target, every SDK method and every output,
then requires exact uppercase `YES`. Manual `-c`/`-n` still confirms every
resolved OCID twice. Automation requires `--non-interactive`, the exact complete
target-OCID set and `--approve-scan YES` after the plan is printed.

Collection is divided into seven-day Audit windows per compartment and records
the tenancy retention setting. A requested period outside retention, or a
failed Audit query, makes collection incomplete. The evidence export excludes
identity credentials, request parameters/headers and response headers/payloads;
only minimum event metadata plus state/additional-detail hashes are retained.

The workflow separates OCI facts from organizational authority. Mutating event
names create change candidates; read events remain facts; unresolved non-read
events remain review candidates. Exact Audit event or grouping IDs join live
events to Remedy CRQs. Separate inputs validate System Owner approval timing,
Emergency post-approval, representative samples and an exact snapshot/count-
bound monthly review. A successful technical run never becomes an approval
decision.

Evidence instructions are in
`TASK11-CONFIGURATION-CHANGE-TRACKING-EVIDENCE-GUIDE.md`. The focused gate is
`tests/test-cm03-01-configuration-change-tracking.py`; it covers SDK pagination,
retention, payload exclusion, formula safety, change classification, failed
attempts, double-OCID/plan/`YES`, strict automation, refusal before Audit calls,
denied reads, malformed response shapes, output collision, exact CRQ binding,
approval timing, samples and monthly-review validation.

## Earlier milestone — Task 10 vulnerability tracking

`ra05-01-vulnerability-tracking.py` is the canonical RA-5/SI-2 workflow and the
first collector under the user-directed Oracle OCI Python SDK standard. The
reviewed SDK is pinned in `requirements-oci-sdk.txt`; shared authentication,
pagination, retry, guarded list/get, error and private-output primitives are in
`lib/oci_audit_sdk.py`.

The collector covers Compute and OCI Container Registry asset visibility, VSS
host/container targets, latest scan results and detailed CVE/package findings.
It resolves target objects across compartments on tenancy runs and uses
`UNKNOWN`, never `NO`, when an exact-compartment run cannot exclude an
out-of-scope target object.

The workflow separates technical facts from organizational decisions. It
generates an SLA-policy template and ingests only an authority-approved SLA;
uses stable finding keys to reconcile remediation owner, ticket, planned date,
follow-up and time-bound exceptions; and validates a monthly review against the
exact snapshot SHA-256 and current counts. Collection errors retain OCI status,
service code and request ID. Outputs are mode `0600` and formula-safe.

The mock gate is `tests/test-ra05-01-vulnerability-tracking.py`. It covers SDK
pagination, detailed host/container findings, cross-compartment target
resolution, exact-scope conservatism, mutation injection, manual and automation
refusal before workload clients, denied detailed reads and complete governed
reconciliation.

## Mandatory scope-selection standard

Root-cause correction: the earlier CP-9 and SC-28 implementations only set
interactive mode when `-i`/`--select-scope` was present, while their regression
cases also passed that flag. That allowed the tests to pass even though a
normal command containing only region/output options silently used the old
tenancy-wide path. The option parser and tests now exercise the real no-scope-
flag operator command for every canonical collector.

Scripts `cp09-01`, `cp09-02`, `cp09-03`, `sc08-02-in-transit-encryption.sh`,
`sc28-oci-encryption-at-rest.sh`, `cm07-01-open-ports-protocols-services.sh` and
`cm11-01-software-installation-control.sh` and
`cm02-01-configuration-baseline.sh` and
`cm08-01-component-inventory-baseline.sh` now default normal/manual runs to interactive
scope selection; `-i` / `--select-scope` are optional aliases. They discover
the tenancy and active compartments, display full OCIDs, require an exact
discovered OCID twice, print the resolved scan plan, and require exact uppercase
`YES` before workload-service collection. A tenancy selection means root plus
every active child compartment. Mismatch/refusal exits before the collector
loop, removes header-only CSVs and has dedicated fail-closed regressions for all
nine collectors.

The shared implementation is `lib/oci-scope-selector.sh`; regression coverage
is in `tests/test-scope-selection.sh`.

Every new or materially redesigned collector must follow
`SCRIPT-DESIGN-STANDARD.md`. `-c`/`-n` alone are scope selectors, not proof of
automation approval. New collectors require explicit automation mode, exact
resolved-OCID confirmation values and exact `YES` approval.

## Latest milestone — simplified Task 8 CM02 collector

At the user's direction, CM02-01 was reduced to one technical collection mode.
A normal command requires only region/output plus the mandatory scope gate; the
legacy `--inventory-only` flag is accepted as a no-op. The script no longer
accepts CI-register, approved-baseline or monthly-review inputs and no longer
publishes approval/reconciliation templates at the evidence-directory root.

Exit `0` now means only that technical collection and normalization completed.
Exit `3` is reserved for failed/malformed read collection and prints the exact
coverage/error paths. The summary uses `COLLECTION STATUS: COMPLETE` or
`INCOMPLETE` and no longer prints the confusing authorization-decision text.

The mandatory tenancy/compartment OCID-twice, resolved plan, exact `YES`, named
profile, strict automation, read-only source/runtime boundary, private output,
formula safety, image-owner compartment attribution and raw failure handling
remain intact. Task 8 is therefore tracked as Partial: the system owner still
must supply and reconcile an approved CI register, System Design Form/baseline,
monthly review, changes and exceptions outside this simplified collector.

## Latest milestone — Task 9 hardware/software component inventory

The canonical workflow is `cm08-01-component-inventory-baseline.sh`; the guide
is `TASK9-COMPONENT-INVENTORY-EVIDENCE-GUIDE.md`. The existing
`cm08-hw-sw-baseline.sh` remains the broad raw collector, now invoked only after
CM08-01 completes the scope and final approval boundary. It refuses direct
execution unless CM02-01 or CM08-01 supplies the exact approved caller, scope
and region handshake; wrapper discovery and raw calls also use a runtime
positive allowlist of list/get action variants.

CM08-01 requires the exact tenancy or every resolved compartment OCID twice,
prints the complete scope/profile/work/output plan, discloses that installed
package collection can be high volume and requires exact uppercase `YES`.
Automation requires `--non-interactive`, every exact confirmation OCID and
`--approve-scan YES`. One explicit region is mandatory; `-p/--profile` is
passed to IAM discovery and the raw inventory engine.

The workflow separates current technical facts from three governance records:

- approved prior component inventory: system/technical owner, environment,
  criticality, inventory status, baseline version and approval provenance;
- exact disposition of every monthly `ADDED`, `REMOVED` or `CHANGED` event,
  bound to both prior and current fingerprints;
- current count-bound monthly review: exact scope, unchanged/add/remove/change
  and coverage-gap totals, corrective action, reviewer and approver.

Stable component keys exclude mutable inventory state. Installed-package keys
exclude package version, so an upgrade becomes `CHANGED` instead of a false
removal/addition pair. Generated approval templates remain `PENDING-REVIEW`.
Supplied governance inputs receive SHA-256 provenance.

CM08-01 also publishes an explicit unmanaged/visibility gap ledger: compute
guest inventory without an authoritative agent join, package summaries without
detail, configured OKE pools without running-node inventory, mutable
Function/container image references, missing compartment OCIDs and the
provider-managed physical-hardware responsibility boundary. A valid review
must acknowledge the exact current gap count; the collector never hides these
limitations behind a successful API exit.

Task 9 work corrected the raw CM08 schemas so volume/boot attachments, FSS
exports, OKE node pools, containers, Functions, databases, OS-managed
instances and installed packages retain their compartment OCIDs. This extends
the Task 8 engine fixes without merging CM-2 configuration approvals into CM-8
inventory assertions.

Regression coverage is in `tests/test-cm08-01-component-inventory.sh` using
`tests/mock-oci-task8`. It covers inventory/template generation, stable keys,
unchanged matching, undispositioned and fully dispositioned changes,
count-bound review, package/profile propagation, coverage gaps, denied calls,
formula safety, manual/default/tenancy selection, strict automation and
refusal before workload collection. The focused gate and full repository suite
must pass on the exact commit published to `main`.

## Latest milestone — Task 8 configuration baseline

**Superseded on 2026-09-01:** the implementation details below describe the
former governed reconciliation mode. The current user-selected CM02 interface
is the simple technical collector documented above and in the Task 8 guide.

The canonical workflow is `cm02-01-configuration-baseline.sh`; the guide is
`TASK8-CONFIGURATION-BASELINE-EVIDENCE-GUIDE.md`. Configuration baseline maps to
CM-2, so the existing `cm08-hw-sw-baseline.sh` remains a separate CM-8 inventory
engine invoked only after CM02-01 obtains scan approval.

CM02-01 requires an exact tenancy or compartment OCID twice, prints the full
scope/profile/work/output plan and requires exact uppercase `YES`. Manual
`-c`/`-n` confirms every resolved compartment twice. Automation requires
`--non-interactive`, every exact confirmation OCID and `--approve-scan YES`.
One region is mandatory and `-p/--profile` is passed to discovery and inventory.

The workflow separates live facts from three signed organizational inputs:

- CI register: system/technical owners, criticality, environment, baseline ID,
  System Design Form reference, monthly frequency and registration approval;
- approved configuration baseline: expected attribute values, comparison,
  design/change/exception references and approval provenance;
- current monthly review: reviewer, findings/change/exception validation,
  corrective actions, approval and retained evidence reference.

Inventory-only creates all three templates. Full reconciliation reports match,
configuration drift, unregistered CIs, unbaselined attributes, incomplete or
ambiguous approvals and approved attributes not found live. Input SHA-256,
configuration fingerprints, private/formula-safe raw and canonical CSVs,
coverage, error and summary evidence are retained. An exact compartment is
passed to the CM08 engine with child expansion disabled; tenancy expansion is
disclosed in the approved plan.

Execution testing fixed three existing CM08 defects: undefined `dat` filters in
direct jq calls, double-encoded/blank image inventory and missing VNIC
compartment OCIDs. Raw stderr or downstream parser errors now force CM02-01
incomplete rather than hiding behind successful OCI calls.

Regression coverage is in `tests/test-cm02-01-configuration-baseline.sh` using
`tests/mock-oci-task8`. It covers complete matching, drift, missing baseline
coverage, current monthly review, denied collection, profile propagation,
formula safety, manual/default/tenancy scope paths, strict automation and
refusal before workload collection. The dedicated test and full repository
suite pass locally; require GitHub Actions on the exact published head before
merge.

## Latest milestone — Task 7 software installation control

The user directed Task 7 after the Task 6 CM-7 workflow. The canonical
collector is `cm11-01-software-installation-control.sh`; its evidence and manual
boundary guide is `TASK7-SOFTWARE-INSTALLATION-CONTROL-EVIDENCE-GUIDE.md`.

The collector is read-only and separates three evidence sources:

- OCI technical facts: candidate IAM installer/provisioner/publisher grants,
  classic group members, OSMH packages/controls, Compute boot images and
  Container Registry images/repositories;
- the signed organizational list of authorized installer principals/users,
  including manager, request process, technical control and approval;
- the signed approved software/resource list and current authoritative
  restricted/prohibited list.

The normal command discovers the tenancy and active compartments, requires the
exact tenancy or compartment OCID twice, displays the complete plan and starts
only after exact uppercase `YES`. A manual `-c`/`-n` run confirms every
resolved OCID twice. Automation requires explicit `--non-interactive`, one
exact `--confirm-scope-ocid` per resolved target and exact
`--approve-scan YES`. The region is mandatory.

For a child workload compartment, policy listing includes the tenancy and
ancestor attachment compartments because parent policies can affect the child;
the workload inventory still remains within the confirmed target. All calls
are list/get, response shapes are validated, failed calls produce explicit
coverage/error evidence and outputs are private, no-clobber and formula-safe.

OCI IAM has no API that returns a fully evaluated effective-policy decision.
The post-processor in `lib/cm11-01-reconcile.py` preserves every statement and
labels installation classification as candidate evidence. It recognizes OSMH
package installation, Compute image/instance provisioning, Container Registry
publishing and the separately labeled Oracle-documented built-in Administrators
grant. It expands classic IAM groups to visible members, retains dynamic-group
rules and causes exit `3` when a referenced identity-domain group remains
unresolved.

The two-pass workflow first runs `--inventory-only`, then uses the generated
authorized-installer and approved-software templates plus the organization's
restricted list. Full reconciliation reports unauthorized candidate
entitlements, unapproved software drift and restricted/prohibited matches. The
input-source output records row counts, provider/authority/references/dates and
SHA-256 hashes.

OSMH installed packages are authoritative only for successfully collected
managed instances. Compute-to-OSMH ID mismatches are `NOT-VERIFIED`, not proof
that OSMH is absent. Identity Domains membership, SSH/sudo/local admins,
break-glass, unmanaged/Windows inventory, Kubernetes/Functions/deployment
runtimes and installation/change samples remain mandatory manual evidence.

Regression coverage is in
`tests/test-cm11-01-software-installation-control.sh` using
`tests/mock-oci-task7`. It covers the full three-source reconciliation,
prohibited Telnet, authorized entitlement expansion, input hashes, technical
controls, denied package calls, malformed list responses, formula safety,
manual/default/tenancy scope paths, refusal/mismatch before collection, strict
automation and identity-domain gaps. Both the Task 7 test and the full
repository suite pass on the staged Task 7 tree. Require GitHub Actions on the
exact published branch head before merge.

## Latest milestone — Task 6 open ports, protocols and services

**Corrective status:** Task 6 is Partial. Do not use CM07-01 as complete audit
evidence until the findings and acceptance gate in `CM07-CORRECTIVE-REVIEW.md`
are closed.

The user directed Task 6 implementation before Task 5. The canonical collector
is `cm07-01-open-ports-protocols-services.sh`.

It inventories Security Lists, NSGs, their rules and their subnet/VNIC
associations. It defaults to tenancy/compartment discovery, exact double-OCID
confirmation, a complete pre-scan summary and exact uppercase `YES`. Manual
`-c`/`-n` runs also confirm every resolved OCID twice and require `YES`.
Automation must explicitly provide `--non-interactive`, every resolved OCID and
`--approve-scan YES`. A mismatch or refusal reaches no Networking command and
leaves no evidence CSV. The region is mandatory evidence provenance.

The evidence workflow separates OCI facts from organizational attestations:

- OCI Network/Cloud Operations runs the live inventory.
- System/application owners complete the generated mapping for the actual OCI
  resource, listener status/address/port/protocol, service, function and
  justification, with verifier/date/evidence references.
- The designated CCB/PPSM/ISSO authority approves the exact rule baseline.
- The designated PPSM/security-policy owner supplies the restricted list.
- Input-source evidence records provider, authority, reference, dates and file
  SHA-256.

The collector emits failure-aware inventory, actual-service mapping template
and reconciliation, approval template/reconciliation, restricted findings,
source provenance, coverage and a retained error ledger. Missing service
mapping, approval or restricted inputs cause exit `3` unless
`--inventory-only` was explicitly selected. Future approval/verification dates,
reversed date ranges and incomplete live-rule service mappings fail closed.

Regression coverage is in `tests/test-cm07-01-open-ports.sh` with
`tests/mock-oci-task6`. It covers successful inventory/reconciliation,
restricted SSH, actual-service verification, missing/incomplete mappings,
future/reversed approval dates, both OCI list shapes, missing inputs, denied
NSG rules, malformed JSON, formula-safe CSV, compartment/tenancy expansion,
manual flag-based confirmation, explicit automation refusal, double-OCID
mismatch, lowercase-`yes` refusal and mixed-scope rejection.

The three older CM-7 scripts remain legacy references and are not canonical
evidence sources.

The expanded CM07-01 mock suite passes locally, but mock success did not expose
the cross-compartment coverage or ICMP restricted-match defects found during
controlled use and source review. The legacy `cm07-openports.sh` produced useful
live output; `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` did not. Use the
legacy query behavior only as a comparison fixture. Static validation still
confirms all OCI wrapper sites are restricted to list/get.


## Prior safety hardening — SC-8

`SC08-SAFETY-REVIEW.md` records a second source-level review of
`sc08-02-in-transit-encryption.sh`:

The collector now uses the canonical `SC08-02` filename and `sc08-02_...`
evidence prefix. The obsolete unprefixed script and regression-test paths were
removed from this branch.

- 27 OCI wrapper call sites parsed and restricted to `list`/`get`;
- `network ip-sec-psk get` explicitly prohibited and injection-tested;
- default interactive double-OCID, pre-scan summary and exact-`YES` gate;
- invalid compartment, ambiguous scope and unknown service failures before
  collection;
- successful CLI JSON syntax/shape validation to prevent false zero assets;
- secure temporary files, private/no-clobber/formula-safe CSV output;
- missing volume encryption fields remain unknown instead of false disabled;
- backend TLS peer-verification disabled is an explicit review finding.

Tests are in `tests/test-sc8-safety.sh`,
`tests/test-sc08-02-in-transit-encryption.sh` and `tests/test-scope-selection.sh`.
Static/mock review passed; live OCI evidence remains pending.

## Prior milestone — Task 3

### `sc28-oci-encryption-at-rest.sh`

- Replaced discarded stderr with current-shell captured calls.
- Added row-level `collection_status`/`collection_error`, a
  compartment-by-service coverage CSV and a failed-call CSV.
- Added exit code `3` for any incomplete collection.
- Added read-only `--selfcheck`, `-n`, `-o` and confirmed double-OCID scope
  selection.
- Covers Block/Boot Volumes, Object Storage, FSS, Autonomous DB, Base DB,
  MySQL, PostgreSQL, Vaults and KMS keys.
- Corrected MySQL to the current `encrypt-data.key-generation-type/key-id`
  model.
- Does not fabricate a PostgreSQL CMK field; records platform encryption and a
  manual key-custody boundary.
- Added Vault type/lifecycle/deletion and KMS key `get` plus key-version `list`
  evidence.
- KMS rows include HSM/software protection, AES key shape, lifecycle/deletion,
  auto-rotation interval/last/next/status and version counts.
- Never retrieves key material or secrets.

### Task 3 manual evidence

`TASK3-MANUAL-EVIDENCE-CHECKLIST.md` covers run integrity, CMK-to-key
reconciliation, HSM/AES-256, key administrators, pending deletion, OCI Audit
rotation proof, manual rotation procedures, evidence handling and sign-off.

### Task 3 regression gate

Added `tests/mock-oci-task3` and `tests/test-encryption-at-rest.sh`. The success
path exercises every service and requires HSM AES-256 automatic-rotation plus
version history. A rotation-failure fixture must emit
`AUTO-ROTATION-FAILED`. A denied KMS key-list fixture must exit `3`, retain an
error ledger and produce attributed `DENIED/COLLECTION-FAILED` evidence and
coverage; it cannot produce a fake no-keys result.

## Prior milestone — Task 2

### `sc08-02-in-transit-encryption.sh`

- Replaced discarded stderr with current-shell captured calls.
- Added `collection_status` and `collection_error` to evidence rows.
- Added compartment-by-service coverage and failed-call CSVs.
- Added exit code `3` for any incomplete collection.
- Added `--selfcheck`, compartment-name filtering and output routing.
- Added confirmed tenancy/compartment discovery with exact double-OCID entry.
- Added Load Balancer backend-set SSL collection.
- Added CPE, IPSec connection, tunnel and DRG attachment/route context.
- Tunnel rows include lifecycle/status, IKE version, routing/BGP state,
  negotiated phase-one/phase-two algorithms and PFS.
- Both OCI tunnel objects are required per connection; any other successful
  count produces `IPSEC-TUNNEL-PAIR-INCOMPLETE`.
- The collector never retrieves an IPSec pre-shared key.

### Task 2 manual evidence

`TASK2-MANUAL-EVIDENCE-CHECKLIST.md` covers IPSec screenshots, Base DB
`sqlnet.ora`, encrypted FSS client mounts, NLB backend TLS, reconciliation,
evidence handling and reviewer sign-off.

### Task 2 regression gate

Added `tests/mock-oci-task2` and `tests/test-sc08-02-in-transit-encryption.sh`. The
success path exercises every Task 2 service and requires two independent IPSec
tunnel rows. A one-tunnel fixture must produce the incomplete-pair finding. The
denied path injects a 403 on the IPSec tunnel list and requires exit `3`, an
attributed `DENIED/COLLECTION-FAILED` row, denied coverage and an error ledger.
It also proves the failure cannot become `TUNNEL-DOWN`, `NO-IPSEC` or `NO-VPN`.

## What changed

### `cp09-03-backup-replication-check.sh`

- Added the same read-only `--selfcheck` boundary used by `cp09-01` and `cp09-02`.
- Added `-n` compartment-name filtering and `-o` output-directory support.
- Replaced command-substitution wrapper state with explicit captured OCI calls.
- Added `collection_status` and `collection_error` to every evidence row.
- Added a compartment-by-service coverage CSV.
- Added synthetic `COLLECTION-FAILED` rows when a primary service collection fails.
- A failed replica lookup now yields `replicated=UNKNOWN`, not a false `NO-REPLICA` finding.
- Retained the failed-call ledger and exit code `3` for incomplete runs.
- Reduced repeated API calls by collecting volume, boot-volume and FSS replica lists once per scope rather than once per asset.
- Added consistent support for both OCI list shapes: `.data[]` and `.data.items[]`.

### Regression tests

Added:

- `tests/mock-oci`
- `tests/test-cp09-03.sh`
- `tests/run.sh`

The mock exercises Object Storage, Block Volume, Boot Volume, volume backups,
FSS, Autonomous Database and Base DB. It also injects a `403` on the Block
Volume replica call and verifies all of the following:

- process exits `3`;
- the asset row is `DENIED` and `UNKNOWN`;
- coverage is `DENIED`;
- the failed-call ledger is retained;
- `NO-VOLUME-REPLICA` is not fabricated.

Latest full-suite result:

```text
PASS: CM03-01 SDK Audit collection, scope safety, CRQ approvals, samples and monthly review
PASS: AC02-01 SDK accounts, domains, groups, privileges, inactivity and approvals
PASS: CP-9, SC-8, SC-28, CM-7, CM-11, CM-2, CM-8, RA-5, CM-3 and AC-2 static, read-only and mock test suite
```

Run with:

```bash
bash tests/run.sh
```

### Legacy collectors

`backup-storage.sh` and `oci_backup_audit.py` are now explicitly marked
deprecated. They remain as reference implementations but are not canonical
evidence sources because they lack the CP-9 family's row-level collection
integrity.

## Do not overstate the milestone

Task 1 code is ready for a controlled OCI run. Task 1 is not audit-complete.
The following operational work remains:

1. Run all three CP-9 collectors in each required region.
2. Use the exact compartment names for VCN, Shared Services and CD3.
3. Treat exit `3`, non-OK rows and unresolved principals as incomplete evidence.
4. Review findings and document accepted exceptions/remediation owners.
5. Store outputs in the approved restricted evidence location.
6. Record the evidence reference, operator, reviewer, dates and approval.

Do not commit live OCI CSVs or screenshots to this public repository.

## Task 2 is not audit-complete

1. Run the collector in every in-scope region and exact worksheet compartment.
2. For an operator run, retain the double-OCID and approved pre-scan summary;
   exact uppercase `YES` must precede service calls.
3. Require exit `0` and reconcile every coverage row and finding.
4. Complete `TASK2-MANUAL-EVIDENCE-CHECKLIST.md`.
5. Capture both IPSec tunnels, Base DB `sqlnet.ora`, FSS encrypted mounts and
   NLB backend TLS without capturing PSKs or other secrets.
6. Store and approve the package in the restricted evidence location.

Do not commit live OCI CSVs or screenshots to this public repository.

## Task 3 is not audit-complete

1. Run the collector in every in-scope region and exact worksheet compartment.
2. Require exit `0` and reconcile every coverage row, CMK OCID and finding.
3. Complete `TASK3-MANUAL-EVIDENCE-CHECKLIST.md`.
4. Confirm key administrators, HSM/AES-256 posture, rotation schedule/history
   and OCI Audit proof; document any approved manual rotation process.
5. Store and approve the package in the restricted evidence location.

Do not commit live OCI CSVs, key-administrator identities or screenshots to
this public repository.

## Next implementation task for Claude

Task 12 implementation is complete after the focused/full local gate. The next
worksheet item is Task 13 Okta/DOJLogin configuration. First determine whether
the integration applies, then collect approved configuration, provisioning and
deprovisioning behavior, authentication controls, test evidence and owner
approval without exporting secrets. Reuse AC02-01's `FEDERATION-LIFECYCLE`
boundary rather than treating OCI directory inventory as proof of the external
identity-provider process.

The outstanding corrective item is Task 6. Patch CM07-01 according to
`CM07-CORRECTIVE-REVIEW.md`, extend the mock suite and complete known-object
compartment and tenancy runs before promoting it again. Do not allow an
unresolved cross-compartment association to produce `OK` coverage or an
inactive-container conclusion, and do not apply transport-port overlap to ICMP.

Do not represent a successful RA05 technical run as vulnerability-management
approval. Complete the approved SLA, remediation tracker, exceptions,
follow-up, rescans, monthly review and non-VSS/third-party coverage described in
`TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`.

Task 5 Continuous Monitoring Form review/feedback remains the earliest
unimplemented worksheet item because the user chose to advance Tasks 6–9
first. Do not represent it as complete; return to it when the user directs.

## Resolved Task 6 blocker

The legacy `cm07-proof-opened-ports.sh` stdin collision is superseded by the
canonical CM07-01 collector. Its post-processor receives the baseline path as
an argument and opens the CSV directly, while the embedded Python program alone
uses standard input.
