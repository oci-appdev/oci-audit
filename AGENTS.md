# Agent working agreement

Shared contract for every AI agent working in this repository (Codex, Claude
and any other). Read this before editing. `CLAUDE.md` points here; this file is
the single source of truth.

**Last updated:** 2026-09-05 (all nine SDK-native and surface-verified)

## Non-negotiable repository rules

1. `SCRIPT-DESIGN-STANDARD.md` is binding on every new or materially
   redesigned collector. Do not add a collector that skips the
   discovery / double-OCID / pre-scan-plan / exact-`YES` sequence.
   Since 2026-09-02 that standard also requires every **new or materially
   rewritten** collector to use Oracle's official `oci-python-sdk`, pinned in
   `requirements-oci-sdk.txt`, with generated clients, SDK pagination/retries
   and a runtime `list_*`/`get_*` allowlist. `ra05-01/ra05-01-vulnerability-tracking.py`
   and `lib/oci_audit_sdk.py` are the reference implementation.
   This does **not** mean the existing Bash/OCI-CLI collectors should be
   rewritten opportunistically. A targeted correctness fix to one of them — such
   as the three SDK-verified fixes below — is not a material rewrite and does not
   trigger a port. Port a collector only when it is being materially redesigned
   anyway, or when the user asks.
2. Collectors are **read-only**. Only OCI `list`/`get` operations. Shell
   collectors enforce this with a `--selfcheck` that greps their own source for
   mutating verbs; SDK collectors enforce it with a runtime `list_*`/`get_*`
   method allowlist their `--selfcheck` validates. If you add a call that trips
   either gate, the call is wrong, not the gate.
3. A failed or ambiguous API call must never become a negative finding. It
   becomes a `COLLECTION-FAILED` row, a non-OK coverage row, a retained error
   ledger and exit code `3`. An empty CSV proves absence only when the coverage
   ledger says `OK`.
4. Generated evidence never gets committed. This repository is public.
5. `bash tests/run.sh` must pass before any commit.
6. `tests/test-readonly-proof.sh` is the repository-wide read-only gate and is
   an **allowlist**, unlike the per-collector `--selfcheck` denylists. Every OCI
   wrapper call site in every shell file, canonical and legacy, must carry a
   `list`/`get` action token. It additionally blocks:
   - the 18 SDK operations named `list_*`/`get_*` that issue **POST**, not GET,
     so "it is called get" is never taken as proof of a read;
   - the 51 SDK reads that return credential or key material (wallets, auth
     tokens, API keys, PSKs, initial passwords). **Read-only is not the same as
     safe to write into evidence**, and this repository is public. The SC-8
     collector already blocked `ip-sec-psk`; this generalises it everywhere.
   Since 2026-09-02 it matches **both spellings**: the kebab form the OCI CLI
   uses (`iam auth-token list`) and the snake form the Python SDK uses
   (`client.get_auth_token(...)`). Matching only one left SDK collectors
   unchecked. 47 secret-returning SDK reads are screened by name.
   Discovery is **recursive** and the gate asserts a **coverage floor** (18
   shell files, 200 call sites). It previously globbed only the repository root
   plus `lib/`, which meant a per-task folder reorganisation dropped every
   canonical collector out of scope: coverage fell from 252 call sites to 53 and
   it still reported PASS. A safety check that can quietly stop checking is
   worse than none. If the floor trips, fix discovery — never lower the floor.
   Do not add an exemption to get a call past this gate. The call is wrong.

### Identity Domains: read the note before building an identity collector

Identity Domains has 162 read operations. Most are legitimate identity
evidence, but a specific set returns client secrets, tokens, raw certificates
or federation trust material, and an IA-2 or AC-2 collector sits directly
beside them. `get_identity_propagation_trust` returns a client secret;
`get_auth_token`, `get_customer_secret_key`, `get_smtp_credential`,
`get_user_db_credential`, the `o_auth*_credential` and `o_auth*_certificate`
families and all their `list_*`/`search_*`/`*_my_*` variants are blocked by
name in `tests/test-readonly-proof.sh`.

Password **policy** operations (`list_password_policies`,
`get_password_policy`) are deliberately **not** blocked: they return complexity
and expiry configuration, which is exactly the AC-2/IA-5 evidence such a
collector should gather.

Note also that all 43 Identity Domains `search_*` operations issue **POST**,
not GET. They are genuine reads — the filter travels in the body — so the gate
permits a `search_` prefix in an SDK allowlist, then screens the name for
sensitivity like any other. Do not assume a `search_*` call fails the read-only
rule, and do not assume it passes it either.

## Repository layout — every task owns a folder

Each canonical collector lives in its own `<task-id>/` folder with everything
that belongs to it:

```
cp09-01/  cp09-01-backup-type-config-frequency.sh
          tests/{test-cp09-01-backup-config.sh, mock-oci-cp0901}
cm08-01/  cm08-01-component-inventory-baseline.sh, cm08-hw-sw-baseline.sh,
          cm08-01-reconcile.py, TASK9-…-GUIDE.md, tests/
ra05-01/  ra05-01-vulnerability-tracking.py, lib/oci_audit_sdk.py,
          requirements-oci-sdk.txt, tests/
lib/      oci-scope-selector.sh   — shared by every shell collector
tests/    run.sh and the repository-wide gates only
```

`-o` namespaces output under `<root>/<task-id>/`, so one evidence root holds
every task's results without collision. Guarded by `basename`, so
`-o ./evidence/cp09-01` does not nest twice.

Two cross-folder dependencies are deliberate and easy to break:
`cm02-01` invokes `../cm08-01/cm08-hw-sw-baseline.sh`, and
`cm08-01-reconcile.py` imports `../cm02-01/cm02-01-reconcile.py` as its shared
core. Moving either file breaks the other.

Tests in a task folder are two levels below the root and must use
`ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"`. Tests in `tests/`
use a single `..`. Getting this wrong produces a doubled path and `rc=127`.

**Every collector's header carries a `PYTHON FILES USED:` block** naming the
`.py` files it invokes, or stating plainly that it uses none. Three collectors
(`cp09-01`, `cp09-02`, `cp09-03`) use no Python at all; three (`sc08-02`,
`sc28`, `cm07-01`) use only an inline `python3 - <<'PY'` heredoc with no
separate module — CM07-01's entire reconciliation engine is that heredoc.

`tests/test-repo-structure.sh` enforces both: the folder layout, and that each
header names every `.py` the script actually calls and no `.py` that does not
exist. A header that is confidently wrong is worse than none.

## The shared SDK framework — use it, do not re-derive it

`lib/oci_audit_sdk.py` is the single place a Python collector gets auth, client
construction, the runtime `list_*`/`get_*` allowlist, scope discovery and
resolution, the confirmation and approval gates, the coverage/error ledger and
formula-safe CSV output. It moved from `ra05-01/lib/` to the repository root on
2026-09-04 so every port shares one copy.

Three things the port surfaced that a new collector must get right:

- **`sdk_list()` returns `(items, response)`.** Use `sdk_list_items()` unless
  you need the response for its request id. Assigning the tuple to one name
  does not raise — it silently iterates `[items, response]` and reports
  `len() == 2`.
- **The gate order is fixed by `SCRIPT-DESIGN-STANDARD.md`:** discover, display,
  exact OCID twice (`resolve_scope` / `confirm_targets_interactively`), *then*
  the pre-scan plan (`print_scan_plan`), *then* exact uppercase `YES`
  (`require_final_approval`). Printing the plan before confirmation inverts
  steps 6 and 7 and is a review finding.
- **`-r/--region` is validated, not `argparse`-required**, so `--selfcheck`
  runs with no region and no credentials. `validate_argument_combination`
  enforces it for every real collection.

A collector's `main()` takes `(argv=None, oci_module=None)` so its test can
drive it with a mock SDK. The mock must mirror the real response models, not
the collector's expectations — see the section below.

## SDK model traps found by reading the models, not the Bash

Each of these silently produces a confident wrong answer. Verified against
oci==2.185.1 on 2026-09-04.

- **`FileSystemSummary` has no `filesystem_snapshot_policy_id`.** Only the full
  `FileSystem` from `get_file_system` carries it. A collector that lists file
  systems and reads the summary sees no policy on any of them and reports every
  file system unprotected.
- **`ServiceConnectorSummary` has no `source`, `target` or `tasks`.** Only
  `get_service_connector` returns them.
- **PostgreSQL nests its backup policy at `management_policy.backup_policy`.**
  A flat read returns `None` for every system.
- **Block and boot volumes carry no policy field.** The assignment is a
  separate object read per asset with
  `get_volume_backup_policy_asset_assignment`; an empty list is the only
  legitimate negative.
- **`BackupDestinationDetails` carries `vpc_user` and `vpc_password`.** They
  come back from an ordinary read, so the read-only allowlist cannot stop them.
  CP09-01's `--selfcheck` fails if either name is read anywhere in its source.
- **`LogSource.log_id` and `log_group_id` are optional, and `log_group_id` may
  be the literal `_Audit`.** Absent means "all logs in scope"; matching only on
  exact OCIDs reports covered logs as uncovered.

- **`PreauthenticatedRequest.access_uri` is a bearer URL.** It grants object
  access with no further authentication. `PreauthenticatedRequestSummary` from
  the list operation has no such field, so *listing* PARs is legitimate access
  evidence and the *get* is what must never run. `get_preauthenticated_request`
  is now blocked repository-wide in `tests/test-readonly-proof.sh` (48 secret
  reads), and CP09-02's `--selfcheck` additionally fails if that call, or the
  `access_uri` attribute, appears anywhere in its source.
- **A replication destination in the same region is not alternate storage.**
  Object Storage reports `destination_region_name`, so this is checkable rather
  than assumed. FSS does not report the target's region on the replication
  object at all, so off-site there stays UNKNOWN rather than being guessed
  either way.
- **Replication being configured is not the same as backups being current.**
  Object Storage carries `status` and `time_last_sync`; FSS carries
  `delta_status` and `recovery_point_time`. An ACTIVE policy that has never
  synced is a failing control that reads as configured.
- **Autonomous Database has both `is_local_data_guard_enabled` and
  `is_remote_data_guard_enabled`.** A local standby is same-region. It does not
  satisfy CP-6, but reporting such a database as having no replication at all
  understates what exists, so it gets its own `LOCAL-DATA-GUARD-ONLY` finding.

- **Five routes to an IPSec pre-shared key were unguarded.** The SC-8 shell
  collector blocked the CLI spelling `ip-sec-psk` from the day it was written,
  but `get_ip_sec_connection_tunnel_shared_secret` and the whole CPE
  device-config family — whose rendered output embeds the PSK — were absent
  from `tests/test-readonly-proof.sh`. Same kebab/snake blind spot that once
  let `get_auth_token` through. All five are now blocked (53 secret reads), and
  SC08-02's `--selfcheck` independently fails if any appears in its source. The
  crypto evidence comes from `IPSecConnectionTunnel.phase_one_details` and
  `phase_two_details`, which carry no secret.
- **Three services describe no transport security at all.** NLB `Listener` has
  no `ssl_configuration` (layer 4, TLS terminates at the backend); `MountTarget`
  has no in-transit field (FSS in-transit encryption is a client mount option);
  psql `NetworkDetails` has no TLS field. Each is MANUAL-VERIFY with the reason
  recorded — asserting either a pass or a finding would be invention.
- **`list_mount_targets` requires `availability_domain`.** It is not an optional
  filter; calling it with `compartment_id` alone fails outright.
- **Load balancer listeners are a dict on the `LoadBalancer` object.** There is
  no `list_listeners` on `LoadBalancerClient` — only NLB has one.

- **`Instance.metadata` and `extended_metadata` carry secrets.** They routinely
  hold `ssh_authorized_keys` and `user_data`, and `user_data` is a base64
  cloud-init payload that commonly embeds bootstrap credentials. Read-only does
  not make it safe to write into evidence. `metadata_key_summary` in
  `lib/oci_audit_inventory.py` is the only supported reader — it returns key
  NAMES, marking sensitive ones `(redacted)`, and never a value. Both CM
  collectors' `--selfcheck` fails on a direct subscript of a metadata mapping.
- **Resource Search is an index, not the services.** `search_resources` is a
  POST-shaped read (query in the body) and is permitted, but the index is
  eventually consistent and covers only the types it knows about. CM08-01
  records `queryable-types=N` and `index-is-eventually-consistent` in the
  coverage ledger rather than implying the inventory is exhaustive.
- **A baseline derived from current state cannot detect drift.** CM02-01
  compares against a supplied `--baseline` or reports
  `SNAPSHOT-ONLY-NO-BASELINE`; it never synthesises one. An unusable baseline
  file fails *before* scanning, because returning an empty mapping would report
  every instance as `UNAPPROVED-COMPONENT` — catastrophic drift caused by a
  typo in a filename.

## Test harnesses must catch more than AssertionError

Every SDK mock test uses a small runner. It originally caught only
`AssertionError`, so a collector that raised anything else took the whole
runner down with a traceback and no `FAIL` line. The suite still exited
non-zero — the gate held — but the output named no failing check, and an
injection probe reading the output scored it as "not caught". All six runners
now also catch `Exception` and report it as a failure. Fixed 2026-09-05.

- **`InstalledPackageSummary` reports provenance in a `software_sources` LIST.**
  There is no `software_source_name` or `software_source_id`. Reading those
  yields nothing, and falling back to the package `type` reports every
  package's source as `RPM` — a format, not a provenance. CM11-01's
  `--selfcheck` fails on any attribute access or `text()`/`getattr()` read of
  those names.
- **Security lists and NSGs use different rule models.**
  `IngressSecurityRule`/`EgressSecurityRule` are separate types with no
  direction field; NSG `SecurityRule` is one type with an explicit `direction`.
  Both normalise into one shape before reconciliation.
- **ICMP (1) and ICMPv6 (58) have no ports.** Modelling them as 0-65535 makes
  every ICMP rule overlap every port-scoped PPSM entry. The case that actually
  bites is an entry scoped to protocol `ANY` **with** ports — the protocol
  check does not filter that out, so only the portless rule's refusal to match
  a port-scoped entry prevents a ping rule being reported as a prohibited RDP
  port. That exact fixture is in the CM07-01 test.
- **`list_security_lists` is per compartment.** A subnet in scope can reference
  a security list held elsewhere; referenced lists are resolved by OCID and an
  unreadable one is `UNRESOLVED-SECURITY-LIST`, never "no rules".

## tests/verify-sdk-surface.py — the gate that proves a method exists

Three checks now cover an SDK collector's cloud surface, and they prove
different things:

| Gate | Proves |
|---|---|
| per-collector `--selfcheck` | every declared method *looks* like a read, and the source contains no mutating call |
| `tests/test-readonly-proof.sh` | no declared method is on the POST-shaped or secret-returning blocklists |
| `tests/verify-sdk-surface.py` | every declared method **actually exists** on a client the collector constructs, every call is allowlisted, and no allowlist entry is unused |

Only the third can catch a method that does not exist, sits on a different
client, or is declared and never called. All three defect classes were verified
by injection. It found five unused allowlist entries across cp09-02, cp09-03
and cm07-01 on its first run — not a safety hole, but the pre-scan plan prints
the allowlist to the approver as "Read-only SDK operations", so an entry the
collector never performs overstates what is being approved.

It needs the `oci` package. When that is absent it prints **SKIPPED** with the
install command and exits 0. That is a deliberate, stated compromise: a skip
that announces itself is honest, whereas a check that silently passes is the
failure mode rule 6 exists to prevent. Set `OCI_SDK_PATH` to point at a
vendored copy, or install `ra05-01/requirements-oci-sdk.txt`.

## Do not write a source guard where a behavioural test belongs

CM07-01 briefly carried a `--selfcheck` that scanned its own source for a
literal `65535`, as a proxy for "portless protocols carry no port range". It
flagged its own implementation, and the fix would have been a third
line-number exclusion on top of the two already needed elsewhere. It was
removed. The property is behavioural and the mock test asserts it directly by
feeding a portless rule against an ANY-protocol port-scoped PPSM entry — which
is both stronger and not self-referential. A guard that must exempt its own
code to pass is a guard that will be weakened rather than fixed.

The general rule these share: **a response that does not establish a fact is
UNKNOWN, never a negative finding.** Only an explicit negative from the API —
`kind=NONE`, `is_enabled=false`, an empty assignment list — earns one.

## Ownership boundaries — read before you edit

Work is split across agents. Respect these boundaries; if you believe a change
outside your area is required, say so in your summary rather than silently
making it.

| Area | Owner | Status |
|---|---|---|
| Task 10 — vulnerability tracking (RA-5/SI-2) | **Codex** | Delivered to `main` (`030af450`). `ra05-01/ra05-01-vulnerability-tracking.py`, `lib/oci_audit_sdk.py`, `ra05-01/tests/test-ra05-01-vulnerability-tracking.py`, `ra05-01/TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`. Claude did not review it. |
| Task 11 — configuration change tracking | **Codex** | Reported built; **not on origin**. Claude must not touch it. |
| Task 12 — account management | **Codex** | Reported built; **not on origin**. Claude must not touch it. |
| Task 13 — OKTA/DOJLogin federation (IA-2) | **Codex** | Reported implementation-complete on `codex/task13-ia02-federation` (`719b5c9`, `c31bae0`); **not pushed, so not reviewable**. `ia02-01-federation-configuration.py`. |
| Tasks 1, 2, 3, 7, 9 collectors | Claude (SDK recheck + bug review, 2026-09-02) | See below. Do not revert without reading the rationale. |
| Task 10 RA-5 collector | Codex (built) / Claude (reviewed 2026-09-02) | Reviewed, no defects found. Still Codex's to change. |
| Per-task folder layout | Copilot (authored) / Claude (merged 2026-09-02) | Copilot's `copilot/review-repo` reorg was reviewed (`COPILOT-REORG-REVIEW.md`) and **merged** into `claude/repo-study-u22ntx`. The two `.pyc` files were dropped, the read-only gate was made layout-independent first, and `tests/test-repo-structure.sh` now guards the layout. |
| SDK-native collectors | Claude (in progress, 2026-09-04) | The user directed that collectors use only the Oracle OCI Python SDK, written fresh against the SDK models rather than translated from Bash. **The Bash collectors are not to be edited.** Done: `sc28/sc28-oci-encryption-at-rest.py`, `cp09-01/cp09-01-backup-configuration.py`, `cp09-02/cp09-02-backup-access.py`, `cp09-03/cp09-03-backup-replication.py`, `sc08-02/sc08-02-in-transit-encryption.py`. `cm08-01/cm08-01-component-inventory.py`, `cm02-01/cm02-01-configuration-baseline.py`, sharing `lib/oci_audit_inventory.py`. `cm11-01/cm11-01-software-installation-control.py`, `cm07-01/cm07-01-open-ports.py`. **All nine canonical collectors now have an SDK-native implementation.** The Bash originals are retained, unmodified, until each port is live-validated. |
| (superseded row) | Claude | The user directed that collectors use only the Oracle OCI Python SDK. `sc28/sc28-oci-encryption-at-rest.py` is ported and tested; the Bash original is retained until every port lands. Shared framework lives in `lib/oci_audit_sdk.py`. Remaining: `cp09-01/02/03`, `sc08-02`, `cm07-01`, `cm11-01`, `cm02-01`, `cm08-01`. |
| CP-9 SDK port | **Another agent** (reported 2026-09-04) | Reported complete locally at `c22674e` / `6a0e4bf` with 15 tests passing. **Neither commit is on origin and neither is in this tree**, so it is unreviewed and unmerged. Do not re-port CP-9 until it is pushed or confirmed abandoned. |
| Task 6 — CM07-01 corrective work | Claude (2026-09-02) | Everything closed except live validation: code, 6 gate regressions, SDK field check, templates aligned, evidence guide updated, legacy scripts disabled. **Only `cm07-01/TASK6-LIVE-VALIDATION-RUNBOOK.md` remains**, and it needs tenancy access. |

## SDK-verified changes — do not revert blindly (2026-09-02)

The completed-task collectors were rechecked field-by-field against
[`oracle/oci-python-sdk`](https://github.com/oracle/oci-python-sdk) **v2.185.1**
(commit `33c54ebf`), using each service model's `attribute_map` as the
authoritative list of response fields. The OCI CLI emits those JSON names in
kebab-case, so SDK `lifecycle_state` is CLI `lifecycle-state`.

Three defects were found and fixed. Each is guarded by a regression that was
verified to **fail** without its fix. If you change any of these, the paired
test must be updated with a stated reason, not deleted.

| Fix | File | Guarded by |
|---|---|---|
| Autonomous DB key custody must read `encryption-key.provider`, `key-store-id` and `kms-key-version-id`, not `kms-key-id` alone. An externally keyed ADB (AWS / AZURE / OKV) has no `kms-key-id`; classifying it from that field alone reported a customer-managed database as `ORACLE-MANAGED` / `REVIEW-USE-CMK` — a fabricated negative finding. | `sc28/sc28-oci-encryption-at-rest.sh` | `sc28/tests/test-encryption-at-rest.sh` |
| Installed-package software source comes from the `software-sources` list on `InstalledPackageSummary`. The old code read `software-source-name` and `software-source-id`, which do not exist in the model, and silently fell through to the package `type` (`RPM`). | `cm11-01/cm11-01-software-installation-control.sh` | `cm11-01/tests/test-cm11-01-software-installation-control.sh` |
| The `-c`/`-n` paths of all five Task 1–3 collectors bypassed the scope-automation contract entirely: no double-OCID confirmation, no `--approve-scan YES`. Retrofitted 2026-09-02; `oci_scope_require_final_approval` no longer has a non-prompting branch. | `cp09-01/02/03`, `sc08-02`, `sc28`, `lib/oci-scope-selector.sh` | `tests/test-task1-3-automation-contract.sh` |
| PostgreSQL backup policy is nested at `management-policy.backup-policy`, not at the top level of the db-system response. Reading the flat path always produced an empty `kind`, so **every** PostgreSQL system was reported `backup_configured=NO` with a HIGH `no-backup-policy` finding — including correctly backed-up ones. An absent policy object is now `UNKNOWN`, and only `kind=NONE` raises the HIGH finding. | `cp09-01/cp09-01-backup-type-config-frequency.sh` | `cp09-01/tests/test-cp09-01-backup-config.sh` |
| Base DB key custody had the same defect as Autonomous DB: `Database` also exposes `key-store-id` and `encryption-key-location-details.provider-type` (EXTERNAL/AWS/AZURE/GCP). A key-store or externally keyed database was reported `ORACLE-MANAGED` / `REVIEW-USE-CMK`. The first pass fixed only Autonomous DB and missed this. | `sc28/sc28-oci-encryption-at-rest.sh` | `sc28/tests/test-encryption-at-rest.sh` |
| `os retention-rule list` and `os replication list-replication-policies` are paginated but were called without `--all` in five places. A truncated list became `repl=NO` / an understated WORM posture — a negative finding from an incomplete read. | `cp09-01`, `cp09-02`, `cp09-03` | `cp09-03/tests/test-cp09-03.sh`, `cp09-01/tests/test-cp09-01-backup-config.sh` |
| CM07-01 `rule_port_range()` returned `0-65535` for ICMP, so every ICMP rule overlapped every port-scoped restriction and matched entries like "protocol ANY, port 3389". Portless protocols now return `None` and match only protocol-scoped entries, with optional `icmp_type`/`icmp_code` targeting. | `cm07-01/cm07-01-open-ports-protocols-services.sh` | `cm07-01/tests/test-cm07-01-corrective.sh` |
| CM07-01 listed Security Lists per target compartment, so a list in another compartment attached to an in-scope subnet was missed entirely, and a partial scope could report an attached container as unattached. Referenced OCIDs are now resolved with read-only gets (`UNRESOLVED-SECURITY-LIST` when that fails), and a partial scope reports associations `UNKNOWN` rather than zero. | `cm07-01/cm07-01-open-ports-protocols-services.sh` | `cm07-01/tests/test-cm07-01-corrective.sh` |
| The three retired CM-7 reference scripts (`cm07-openports.sh`, `cm07-ppsm.sh`, `cm07-proof-opened-ports.sh`) suppress OCI stderr on 14–17 call sites, so a denied call became "no rules found" — rule 3's exact prohibition — and `cm07-ppsm.sh` embedded a static restricted list. A "LEGACY REFERENCE" comment does not stop execution, so they now refuse to run and exit 2. | `cm07-openports.sh`, `cm07-ppsm.sh`, `cm07-proof-opened-ports.sh` | `cm07-01/tests/test-cm07-01-corrective.sh` |
| The shipped CM07-01 CSV templates drifted from what the collector generates once `semantic_rule_key` and `peer_type` were added, so an operator would have filled in a schema the reconciler rejects. Templates are realigned and a drift gate compares shipped against generated headers. | `templates/cm07-01-*.csv` | `cm07-01/tests/test-cm07-01-corrective.sh` |
| SC-8 collected no MySQL evidence although `mysql.models.DbSystem.secure_connections` is in-transit TLS configuration and SC-28 already covered MySQL at rest. | `sc08-02/sc08-02-in-transit-encryption.sh` | `sc08-02/tests/test-sc08-02-in-transit-encryption.sh` |
| `sdk_list()` returns `(items, response)`. The SC-28 port assigned it to a single name at 13 call sites, so every loop iterated `[items, response]` and every `len()` reported 2 — a silent miscount, not a crash. Added `sdk_list_items()` for callers that do not need the response. | `lib/oci_audit_sdk.py`, `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| `error_record()` never produced the `status` key that `Ledger.failed()` reads, so **every** failure was recorded as `ERROR` and an authorization denial was indistinguishable from a broken call. It now classifies DENIED / NOT-FOUND / THROTTLED / SERVICE-ERROR / ERROR, and reads the request id from `request_id`, `opc_request_id` or the raw header rather than only the last. | `lib/oci_audit_sdk.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| SC-28's `ERROR_FIELDS` named `code`/`opc_request_id`, which `error_record()` does not produce. `write_csv` uses `extrasaction="ignore"` with a `""` default, so the mismatch emitted blank columns instead of failing — the error ledger would have shipped with only `message` populated. | `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| An SDK allowlist must be checked against the method actually called. A draft of the SC-28 port passed `_allow_as="list_db_systems_mysql"` to disambiguate the MySQL and PostgreSQL clients, which share `list_db_systems`. That checks one name and calls another — the same laundering blind spot the read-only gate was hardened against. The allowlist proves the verb; it is not the place to record which client a call sits on. | `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| SC-28's key finding ladder had collapsed from the Bash collector's eight outcomes to four, dropping `KEY-STATE-*`, `REVIEW-SOFTWARE-KEY`, `REVIEW-AES-KEY-LENGTH-*`, `REVIEW-AUTO-ROTATION-DETAILS`, `REVIEW-MANUAL-ROTATION-EVIDENCE` and `REVIEW-ROTATION-NOT-CONFIRMED`, plus the `last-message`, `auto-rotated-versions`, `pending-version-deletions` and `latest-version` rotation fields. A port that claims evidence equivalence has to carry the whole vocabulary. | `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| SC-28 took `versions[0]` as the newest key version. SDK list order is not a documented guarantee, and the mock happened to return newest-first — so the mock agreed with the bug. Versions are now sorted by `time_created`, and the mock returns ascending order so the old code fails. | `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| `AutonomousDatabaseEncryptionKeyDetails.provider` is one of OKV / AZURE / AWS / **OCI** / GCP / ORACLE_MANAGED. SC-28 treated everything except `ORACLE_MANAGED` as external, so an OCI Vault key (`provider=OCI`) was reported `CUSTOMER-MANAGED-EXTERNAL` and demanded third-party custody evidence from a party that does not hold the key. `EXTERNAL_KEY_PROVIDERS` now names the external set explicitly. | `sc28/sc28-oci-encryption-at-rest.py` | `sc28/tests/test-sc28-encryption-at-rest.py` |
| `cm07-01/tests/test-cm07-01-corrective.sh` hardcoded `expiration_date: 2027-01-01` in a fixture meant to be currently approved. On 2027-01-01 all six rows silently become `APPROVAL-INCOMPLETE` and the test starts asserting something else. Dates are now computed relative to today, as `test-cm07-01-open-ports.sh` already did. Verified by setting the fixture to yesterday: the test fails. | `cm07-01/tests/test-cm07-01-corrective.sh` | itself |
| Volume backup schedules expose `is-retention-lock-enabled` and `is-prevent-deletion-enabled` (the CP-9 WORM evidence) and may express retention as `retention-period` instead of `retention-seconds`. None of these were collected. | `cp09-01/cp09-01-backup-type-config-frequency.sh` | `cp09-01/tests/test-cp09-01-backup-config.sh` (new) |

## The SDK can be installed here — verify against it, do not reason from memory

`python3 -m pip install --target <dir> oci==2.185.1` works in this environment.
Field paths, method names and enum values must be checked against the installed
package (`attribute_map`, and the `get_subtype` dispatch for polymorphic
models), not recalled. Doing that on 2026-09-04 confirmed every SC-28 method
and field, and found three defects a mock had agreed with.

## Review method that found these

Static analysis alone does not find this class of defect: `shellcheck -S warning`
is clean on every collector, and the two hits it does report are false
positives. Every defect found in both passes came from checking the collector's
field paths and pagination against the SDK model, and from asking what a
response that establishes nothing gets recorded as. Run that check, not just the
linter.

## Mocks must mirror the real SDK model

`tests/mock-oci-task7` previously returned a `software-source-name` field that
the OCI API does not produce. The mock agreed with the bug, so the suite passed
while the collector wrote the wrong value into evidence.

**When you add or change a mock payload, copy the field names from the SDK
model, not from the script you are testing.** This applies equally to the mock
OCI CLI shims and to the mocked generated clients used by SDK collectors: a mock
that agrees with the collector proves nothing. Find the real names with:

```bash
python3 - <<'PY'
import re
t = open('src/oci/<service>/models/<model>.py').read()
m = re.search(r'self\.attribute_map\s*=\s*\{(.*?)\}', t, re.S)
print(m.group(1))
PY
```

then convert each camelCase JSON name to kebab-case.

## Known open items (not defects introduced by the above)

- **PostgreSQL CLI command spelling is inconsistent.** `sc28` calls
  `psql db-system-collection list-db-systems`; `cp09-01` and the CM-8 engine
  call `psql db-system list`. At most one is correct for a given OCI CLI build,
  and the wrong one fails closed as `CLI_UNSUPPORTED`, collecting no PostgreSQL
  evidence at all. This cannot be settled from `oci-python-sdk` — the CLI is a
  separate repository. `sc28` now tries the second form on `CLI_UNSUPPORTED`;
  confirm the correct spelling on the target CLI during the live run and
  standardise.
- **`warn()` in `cm08-01/cm08-hw-sw-baseline.sh` is dead code** (defined at line 142,
  never called). It looks like error logging but writes nothing. Harmless, but
  do not assume it is capturing anything.
- **Task 6 needs live validation.** The corrective code and all five
  acceptance-gate regressions in `cm07-01/CM07-CORRECTIVE-REVIEW.md` are done, but that
  gate also requires a controlled compartment run and a controlled tenancy run
  against known network objects, with counts reconciled to Console/CLI spot
  checks. Mock success is explicitly not sufficient. Task 6 stays **Partial**
  until those runs are recorded. **No agent session so far has had OCI access**
  (no `oci` CLI, no `~/.oci`, no credentials), so this cannot be closed from a
  session — it needs a human with tenancy access working through
  `cm07-01/TASK6-LIVE-VALIDATION-RUNBOOK.md`. The same is true of the pending live runs
  for Tasks 1, 2, 3, 7, 9 and 10.
- **Only 1 of 10 canonical collectors uses the OCI Python SDK.** `ra05-01` is
  SDK-native; the other nine are Bash + OCI CLI. The SDK requirement in rule 1
  is forward-looking and applies to new or materially rewritten collectors.
  Porting the nine existing ones is roughly 19k lines across seven control
  families and has not been started or requested.

## Repository hygiene

A `.gitignore` exists as of 2026-09-02 covering `__pycache__/`, `*.pyc` and
collected `evidence/`. Before it, the repository had none, and two compiled
`.pyc` files reached a commit on `copilot/review-repo`. Rule 4 says generated
evidence is never committed; the ignore file is what makes that hold by default
rather than by everyone remembering.

## Branches

Claude develops on `claude/repo-study-u22ntx`; Codex publishes to `main`. Do not
force-push or rebase another agent's branch.

`main` was merged into `claude/repo-study-u22ntx` on 2026-09-02 to pick up the
RA-5 collector. Two conflicts were resolved by keeping both sides: the
`AUDIT.md` dated sections, and the `tests/run.sh` entries for
`cp09-01/tests/test-cp09-01-backup-config.sh` and the RA-5 self-check. If you merge
these branches again, keep both sides of those hunks rather than taking one.
