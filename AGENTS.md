# Agent working agreement

Shared contract for every AI agent working in this repository (Codex, Claude
and any other). Read this before editing. `CLAUDE.md` points here; this file is
the single source of truth.

**Last updated:** 2026-09-02 (revised after the Task 10 RA-5 publication to `main`)

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

## Ownership boundaries — read before you edit

Work is split across agents. Respect these boundaries; if you believe a change
outside your area is required, say so in your summary rather than silently
making it.

| Area | Owner | Status |
|---|---|---|
| Task 10 — vulnerability tracking (RA-5/SI-2) | **Codex** | Delivered to `main` (`030af450`). `ra05-01-vulnerability-tracking.py`, `lib/oci_audit_sdk.py`, `tests/test-ra05-01-vulnerability-tracking.py`, `TASK10-VULNERABILITY-TRACKING-EVIDENCE-GUIDE.md`. Claude did not review it. |
| Task 11 — configuration change tracking | **Codex** (next) | Not started. |
| Tasks 1, 2, 3, 7, 9 collectors | Claude (SDK recheck, 2026-09-02) | See below. Do not revert without reading the rationale. |
| Task 6 — CM07-01 corrective work | Unassigned | Open. See `CM07-CORRECTIVE-REVIEW.md`. |

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
| Volume backup schedules expose `is-retention-lock-enabled` and `is-prevent-deletion-enabled` (the CP-9 WORM evidence) and may express retention as `retention-period` instead of `retention-seconds`. None of these were collected. | `cp09-01-backup-type-config-frequency.sh` | `tests/test-cp09-01-backup-config.sh` (new) |

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

- **Task 6 / CM07-01** still has both defects recorded in
  `CM07-CORRECTIVE-REVIEW.md`: `rule_port_range()` maps every non-TCP/UDP/ANY
  protocol to `0-65535`, so ICMP false-matches port-based restrictions; and
  there is still no `-p/--profile` flag. Task 6 stays **Partial**.
- **Task 2 / SC-8 does not cover MySQL.** `mysql.models.DbSystem` exposes
  `secure_connections` (`certificate-id`, `certificate-generation-type`), which
  is in-transit TLS evidence. SC-28 covers MySQL at rest but SC-8 has no MySQL
  check. Adding one is new service coverage, not a bug fix, so it was left for
  an explicit decision.

## Branches

Claude develops on `claude/repo-study-u22ntx`; Codex publishes to `main`. Do not
force-push or rebase another agent's branch.

`main` was merged into `claude/repo-study-u22ntx` on 2026-09-02 to pick up the
RA-5 collector. Two conflicts were resolved by keeping both sides: the
`AUDIT.md` dated sections, and the `tests/run.sh` entries for
`tests/test-cp09-01-backup-config.sh` and the RA-5 self-check. If you merge
these branches again, keep both sides of those hunks rather than taking one.
