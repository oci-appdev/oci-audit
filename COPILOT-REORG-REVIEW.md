# Review — `copilot/review-repo` per-task folder reorganization

**Reviewed:** 2026-09-02 by Claude
**Branch reviewed:** `copilot/review-repo` at `50c8f74` (5 commits, base `main` `030af45`)
**Scope:** 52 files changed, 621 insertions, 463 deletions
**Verdict:** structurally sound and worth taking, with three items to fix first.

The reorg moves each collector into a per-task folder (`cp09-01/`, `sc08-02/`,
`cm07-01/`, …) together with its reconciler, mock and tests, and changes `-o` to
namespace output under `<root>/<task-dir>/`.

## Verified working — do not redo this

These were checked by execution, not by reading the diff:

- **`bash tests/run.sh` passes clean** on the branch as pushed.
- **The cross-directory Python import was handled correctly.**
  `cm08-01-reconcile.py` loads `cm02-01-reconcile.py` as a shared core. On
  `main` that used `Path(__file__).with_name(...)`, which breaks the instant the
  two files live in different folders. The branch changes it to
  `Path(__file__).resolve().parents[1] / "cm02-01" / "cm02-01-reconcile.py"`.
  The module was imported directly to confirm it resolves — it does.
- **Shell delegation paths are correct.** `cm02-01` → `../cm08-01/cm08-hw-sw-baseline.sh`,
  `cm08-01` → `../cm02-01/cm02-01-reconcile.py`, every collector →
  `../lib/oci-scope-selector.sh`. `--selfcheck` was run on the moved files and
  passes.
- **README cross-references all resolve** to files that exist at their new paths.
- **`tests/run.sh` was correctly rewritten** for the new `bash -n` and
  `ast.parse` paths.
- **The `-o` change is defensive** — it compares `basename` before appending, so
  passing `-o ./evidence/cp09-01` does not produce `evidence/cp09-01/cp09-01`.

This was careful work, not a find-and-replace.

## Must fix before merge

### 1. Two compiled `.pyc` files are committed

```
__pycache__/ra05-01-vulnerability-tracking.cpython-312.pyc
lib/__pycache__/oci_audit_sdk.cpython-312.pyc
```

Build artifacts, stale the moment their source changes, binary noise in a public
repository's history. Checked for leaked material — there is none; the only
credential-shaped strings are the redaction regexes compiled from the source
itself. Still needs `git rm --cached` on both.

### 2. There is no `.gitignore` anywhere in the repository

This is the proximate cause of item 1 and predates this branch. A `.gitignore`
covering `__pycache__/`, `*.pyc` and `evidence/` has been added on
`claude/repo-study-u22ntx`; take it from there or add an equivalent.

### 3. The reorg silently guts the repository-wide read-only gate

This is the significant one and it is not visible in the diff.

`tests/test-readonly-proof.sh` discovered collectors with a top-level
`Path(".").glob("*.sh")` plus `lib/*.sh`. Every canonical collector moves into a
subdirectory under this reorg, so they stop being discovered. Measured on the
merged tree:

| | Before reorg | After reorg |
|---|---:|---:|
| Shell files scanned | 22 | **12** |
| OCI call sites verified | 252 | **53** |
| Result reported | PASS | **PASS** |

The gate still says PASS while proving nothing about 79% of the call sites it
used to cover, and about none of the nine canonical collectors. No error, no
warning — just a smaller number nobody reads. That is precisely the failure mode
rule 3 of `AGENTS.md` exists to prevent, turned on the safety check itself.

**This is a defect in the gate, not in the reorg** — a check whose coverage can
collapse silently is a bad check regardless of who moves the files. It has been
fixed on `claude/repo-study-u22ntx`:

- discovery is now recursive (`rglob`), excluding `.git`, `__pycache__`,
  `evidence` and test harnesses, so it follows collectors into any layout;
- a coverage floor (18 shell files, 200 call sites) fails loudly if discovery
  ever collapses again, with a message saying to fix discovery rather than lower
  the floor.

Verified: the hardened gate finds all 22 files and 252 sites **under the
reorganized layout as well**, and fails with a clear message on a gutted tree.

**Do not merge the reorg onto a base that lacks this fix.**

## Merge assessment

Better than expected. A dry-run merge of `claude/repo-study-u22ntx` against this
branch produces **7 conflicts**, not the wholesale collision a rename-plus-edit
merge often causes — git's rename detection tracks the moves well.

Conflicts: `tests/run.sh`, `MASTER-TASK-LIST.md`, `HANDOFF.md`,
`cm07-01/CM07-CORRECTIVE-REVIEW.md`, `sc08-02/sc08-02-in-transit-encryption.sh`,
`sc08-02/tests/test-sc08-02-in-transit-encryption.sh`,
`sc28/tests/test-encryption-at-rest.sh`.

Every collector logic fix from `claude/repo-study-u22ntx` was confirmed present
in the auto-merged tree: the PostgreSQL `management-policy.backup-policy`
nesting fix, the WORM retention fields, the scope-automation retrofit, the
Autonomous DB and Base DB external-key custody classification, SC-8 MySQL
coverage, the CM07 portless-ICMP model and cross-compartment resolver, and the
CM-11 `software-sources` fix.

Three of the four newer test gates fail **loudly** under the reorg because they
reference old flat paths — `test-task1-3-automation-contract.sh`,
`cm07-01/tests/test-cm07-01-corrective.sh`, `cp09-01/tests/test-cp09-01-backup-config.sh`. Loud failure is
the safe outcome; they need their paths updated as part of the merge. Only the
read-only proof failed silently, and that is now fixed.

## Minor

- `templates/` stayed flat at the repository root while everything else moved
  into per-task folders. Nothing references it by path, so this is cosmetic
  inconsistency rather than breakage — but it should either move or be stated as
  a deliberate exception.

## Suggested merge order

1. Land the read-only-gate hardening (already on `claude/repo-study-u22ntx`).
2. Remove the two `.pyc` files and add `.gitignore`.
3. Merge the reorg, resolving the 7 conflicts.
4. Update the four test files' hardcoded collector paths.
5. `bash tests/run.sh` must pass, and the read-only proof must still report
   **252 call sites** — if that number has dropped, discovery is broken again.
