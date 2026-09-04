# Agent working agreement

Shared contract for every AI agent working in this repository (Codex, Claude
and any other). Read this before editing. `CLAUDE.md` points here; this file is
the single source of truth.

**Last updated:** 2026-09-04 (SDK port under way; SC-28 ported)

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
| SDK port of the Bash collectors | Claude (in progress, 2026-09-04) | The user directed that collectors use only the Oracle OCI Python SDK. `sc28/sc28-oci-encryption-at-rest.py` is ported and tested; the Bash original is retained until every port lands. Shared framework lives in `lib/oci_audit_sdk.py`. Remaining: `cp09-01/02/03`, `sc08-02`, `cm07-01`, `cm11-01`, `cm02-01`, `cm08-01`. |
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
| `cm07-01/tests/test-cm07-01-corrective.sh` hardcoded `expiration_date: 2027-01-01` in a fixture meant to be currently approved. On 2027-01-01 all six rows silently become `APPROVAL-INCOMPLETE` and the test starts asserting something else. Dates are now computed relative to today, as `test-cm07-01-open-ports.sh` already did. Verified by setting the fixture to yesterday: the test fails. | `cm07-01/tests/test-cm07-01-corrective.sh` | itself |
| Volume backup schedules expose `is-retention-lock-enabled` and `is-prevent-deletion-enabled` (the CP-9 WORM evidence) and may express retention as `retention-period` instead of `retention-seconds`. None of these were collected. | `cp09-01/cp09-01-backup-type-config-frequency.sh` | `cp09-01/tests/test-cp09-01-backup-config.sh` (new) |

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
