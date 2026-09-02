# Agent working agreement

Shared contract for every AI agent working in this repository (Codex, Claude
and any other). Read this before editing. `CLAUDE.md` points here; this file is
the single source of truth.

**Last updated:** 2026-09-02

## Non-negotiable repository rules

1. `SCRIPT-DESIGN-STANDARD.md` is binding on every new or materially
   redesigned collector. Do not add a collector that skips the
   discovery / double-OCID / pre-scan-plan / exact-`YES` sequence.
2. Collectors are **read-only**. Only OCI `list`/`get` operations. Every
   script's `--selfcheck` greps its own source for mutating verbs; if you add a
   call that trips it, the call is wrong, not the check.
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
| Task 10 — vulnerability tracking | **Codex** | In progress. Claude must not touch it. |
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
| Volume backup schedules expose `is-retention-lock-enabled` and `is-prevent-deletion-enabled` (the CP-9 WORM evidence) and may express retention as `retention-period` instead of `retention-seconds`. None of these were collected. | `cp09-01-backup-type-config-frequency.sh` | `tests/test-cp09-01-backup-config.sh` (new) |

## Mocks must mirror the real SDK model

`tests/mock-oci-task7` previously returned a `software-source-name` field that
the OCI API does not produce. The mock agreed with the bug, so the suite passed
while the collector wrote the wrong value into evidence.

**When you add or change a mock payload, copy the field names from the SDK
model, not from the script you are testing.** Find them with:

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

Claude develops on `claude/repo-study-u22ntx`. Do not force-push or rebase
another agent's branch.
