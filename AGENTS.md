# Agent working agreement

Shared contract for every AI agent working in this repository (Codex, Claude
and any other). Read this before editing. `CLAUDE.md` points here; this file is
the single source of truth.

**Last updated:** 2026-09-02 (repository-wide read-only proof)

## Non-negotiable repository rules

1. `SCRIPT-DESIGN-STANDARD.md` is binding on every new or materially
   redesigned collector. Do not add a collector that skips the
   discovery / double-OCID / pre-scan-plan / exact-`YES` sequence.
   Since 2026-09-02 that standard also requires every **new or materially
   rewritten** collector to use Oracle's official `oci-python-sdk`, pinned in
   `requirements-oci-sdk.txt`, with generated clients, SDK pagination/retries
   and a runtime `list_*`/`get_*` allowlist. `ra05-01-vulnerability-tracking.py`
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
   Do not add an exemption to get a call past this gate. The call is wrong.

## Ownership boundaries — read before you edit

Work is split across agents. Respect these boundaries; if you believe a change
outside your area is required, say so in your summary rather than silently
making it.

| Area | Owner | Status |
|---|---|---|
| Task 10 — vulnerability tracking (RA-5/SI-2) | **Codex** | Delivered to `main` (`030af450`). `ra05-01-vulnerability-tracking.py`, `lib/oci_audit_sdk.py`, `tests/test-ra05-01-vulnerability-tracking.py`, `TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`. Claude did not review it. |
| Task 11 — configuration change tracking | **Codex** | In progress, OCI Python SDK. Claude must not touch it. |
| Tasks 1, 2, 3, 7, 9 collectors | Claude (SDK recheck + bug review, 2026-09-02) | See below. Do not revert without reading the rationale. |
| Task 10 RA-5 collector | Codex (built) / Claude (reviewed 2026-09-02) | Reviewed, no defects found. Still Codex's to change. |
| Task 6 — CM07-01 corrective work | Claude (2026-09-02) | Code and regressions complete; **live validation still required** before Task 6 leaves Partial. Runbook: `TASK6-LIVE-VALIDATION-RUNBOOK.md`. |

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
| Autonomous DB key custody must read `encryption-key.provider`, `key-store-id` and `kms-key-version-id`, not `kms-key-id` alone. An externally keyed ADB (AWS / AZURE / OKV) has no `kms-key-id`; classifying it from that field alone reported a customer-managed database as `ORACLE-MANAGED` / `REVIEW-USE-CMK` — a fabricated negative finding. | `sc28-oci-encryption-at-rest.sh` | `tests/test-encryption-at-rest.sh` |
| Installed-package software source comes from the `software-sources` list on `InstalledPackageSummary`. The old code read `software-source-name` and `software-source-id`, which do not exist in the model, and silently fell through to the package `type` (`RPM`). | `cm11-01-software-installation-control.sh` | `tests/test-cm11-01-software-installation-control.sh` |
| The `-c`/`-n` paths of all five Task 1–3 collectors bypassed the scope-automation contract entirely: no double-OCID confirmation, no `--approve-scan YES`. Retrofitted 2026-09-02; `oci_scope_require_final_approval` no longer has a non-prompting branch. | `cp09-01/02/03`, `sc08-02`, `sc28`, `lib/oci-scope-selector.sh` | `tests/test-task1-3-automation-contract.sh` |
| PostgreSQL backup policy is nested at `management-policy.backup-policy`, not at the top level of the db-system response. Reading the flat path always produced an empty `kind`, so **every** PostgreSQL system was reported `backup_configured=NO` with a HIGH `no-backup-policy` finding — including correctly backed-up ones. An absent policy object is now `UNKNOWN`, and only `kind=NONE` raises the HIGH finding. | `cp09-01-backup-type-config-frequency.sh` | `tests/test-cp09-01-backup-config.sh` |
| Base DB key custody had the same defect as Autonomous DB: `Database` also exposes `key-store-id` and `encryption-key-location-details.provider-type` (EXTERNAL/AWS/AZURE/GCP). A key-store or externally keyed database was reported `ORACLE-MANAGED` / `REVIEW-USE-CMK`. The first pass fixed only Autonomous DB and missed this. | `sc28-oci-encryption-at-rest.sh` | `tests/test-encryption-at-rest.sh` |
| `os retention-rule list` and `os replication list-replication-policies` are paginated but were called without `--all` in five places. A truncated list became `repl=NO` / an understated WORM posture — a negative finding from an incomplete read. | `cp09-01`, `cp09-02`, `cp09-03` | `tests/test-cp09-03.sh`, `tests/test-cp09-01-backup-config.sh` |
| CM07-01 `rule_port_range()` returned `0-65535` for ICMP, so every ICMP rule overlapped every port-scoped restriction and matched entries like "protocol ANY, port 3389". Portless protocols now return `None` and match only protocol-scoped entries, with optional `icmp_type`/`icmp_code` targeting. | `cm07-01-open-ports-protocols-services.sh` | `tests/test-cm07-01-corrective.sh` |
| CM07-01 listed Security Lists per target compartment, so a list in another compartment attached to an in-scope subnet was missed entirely, and a partial scope could report an attached container as unattached. Referenced OCIDs are now resolved with read-only gets (`UNRESOLVED-SECURITY-LIST` when that fails), and a partial scope reports associations `UNKNOWN` rather than zero. | `cm07-01-open-ports-protocols-services.sh` | `tests/test-cm07-01-corrective.sh` |
| SC-8 collected no MySQL evidence although `mysql.models.DbSystem.secure_connections` is in-transit TLS configuration and SC-28 already covered MySQL at rest. | `sc08-02-in-transit-encryption.sh` | `tests/test-sc08-02-in-transit-encryption.sh` |
| Volume backup schedules expose `is-retention-lock-enabled` and `is-prevent-deletion-enabled` (the CP-9 WORM evidence) and may express retention as `retention-period` instead of `retention-seconds`. None of these were collected. | `cp09-01-backup-type-config-frequency.sh` | `tests/test-cp09-01-backup-config.sh` (new) |

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
- **`warn()` in `cm08-hw-sw-baseline.sh` is dead code** (defined at line 142,
  never called). It looks like error logging but writes nothing. Harmless, but
  do not assume it is capturing anything.
- **Task 6 needs live validation.** The corrective code and all five
  acceptance-gate regressions in `CM07-CORRECTIVE-REVIEW.md` are done, but that
  gate also requires a controlled compartment run and a controlled tenancy run
  against known network objects, with counts reconciled to Console/CLI spot
  checks. Mock success is explicitly not sufficient. Task 6 stays **Partial**
  until those runs are recorded. **No agent session so far has had OCI access**
  (no `oci` CLI, no `~/.oci`, no credentials), so this cannot be closed from a
  session — it needs a human with tenancy access working through
  `TASK6-LIVE-VALIDATION-RUNBOOK.md`. The same is true of the pending live runs
  for Tasks 1, 2, 3, 7, 9 and 10.
- **Only 1 of 10 canonical collectors uses the OCI Python SDK.** `ra05-01` is
  SDK-native; the other nine are Bash + OCI CLI. The SDK requirement in rule 1
  is forward-looking and applies to new or materially rewritten collectors.
  Porting the nine existing ones is roughly 19k lines across seven control
  families and has not been started or requested.

## Branches

Claude develops on `claude/repo-study-u22ntx`; Codex publishes to `main`. Do not
force-push or rebase another agent's branch.

`main` was merged into `claude/repo-study-u22ntx` on 2026-09-02 to pick up the
RA-5 collector. Two conflicts were resolved by keeping both sides: the
`AUDIT.md` dated sections, and the `tests/run.sh` entries for
`tests/test-cp09-01-backup-config.sh` and the RA-5 self-check. If you merge
these branches again, keep both sides of those hunks rather than taking one.
