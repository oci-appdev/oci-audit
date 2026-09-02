#!/usr/bin/env bash
#
# Repository structure and header-accuracy gate.
#
# Two things drift silently once several agents work in the same tree:
#
#   1. The per-task folder layout. Every canonical collector lives in its own
#      <task-id>/ folder with its reconciler, mock and tests beside it, so a
#      task's evidence, code and proofs stay together. A collector dropped at
#      the repository root still runs, so nothing else would catch it.
#
#   2. The "PYTHON FILES USED" header. A header that lists a .py file which no
#      longer exists, or omits one the script actually calls, is worse than no
#      header: it is documentation that reads as authoritative and is wrong.
#      This checks the header against what the script really invokes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
import pathlib, re, sys

failures = []

# Canonical collector -> the folder it must live in.
COLLECTORS = {
    "cp09-01-backup-type-config-frequency.sh": "cp09-01",
    "cp09-02-backup-access-files-check.sh": "cp09-02",
    "cp09-03-backup-replication-check.sh": "cp09-03",
    "sc08-02-in-transit-encryption.sh": "sc08-02",
    "sc28-oci-encryption-at-rest.sh": "sc28",
    "cm07-01-open-ports-protocols-services.sh": "cm07-01",
    "cm11-01-software-installation-control.sh": "cm11-01",
    "cm02-01-configuration-baseline.sh": "cm02-01",
    "cm08-01-component-inventory-baseline.sh": "cm08-01",
    "cm08-hw-sw-baseline.sh": "cm08-01",
    "ra05-01-vulnerability-tracking.py": "ra05-01",
}

for name, folder in COLLECTORS.items():
    expected = pathlib.Path(folder) / name
    if not expected.is_file():
        failures.append(f"{expected} is missing — every collector lives in its task folder")
        continue
    stray = pathlib.Path(name)
    if stray.is_file():
        failures.append(f"{name} is also at the repository root; there must be exactly one copy")

# Every collector states which Python files it uses, and states them correctly.
for name, folder in COLLECTORS.items():
    path = pathlib.Path(folder) / name
    if not path.is_file():
        continue
    text = path.read_text()
    head = "\n".join(text.split("\n")[:80])
    if "PYTHON FILES USED" not in head:
        failures.append(f"{path}: no 'PYTHON FILES USED' block in its header")
        continue

    block = head.split("PYTHON FILES USED", 1)[1]
    block = block.split("\n#\n", 1)[0]

    declared = set(re.findall(r'([A-Za-z0-9_./-]+\.py)', block))
    for dep in declared:
        if not pathlib.Path(dep).is_file():
            failures.append(f"{path}: header names {dep}, which does not exist")

    # What the script actually invokes, as a repo-relative path.
    actual = set()
    for m in re.findall(r'\$\{?SCRIPT_DIR\}?/([A-Za-z0-9_./-]+\.py)', text):
        resolved = (pathlib.Path(folder) / m)
        try:
            actual.add(str(pathlib.Path(__import__("os").path.normpath(resolved))))
        except Exception:
            actual.add(str(resolved))
    for m in re.findall(r'with_name\(["\']([A-Za-z0-9_.-]+\.py)["\']\)', text):
        actual.add(str(pathlib.Path(folder) / m))

    for dep in actual:
        if dep not in declared:
            failures.append(
                f"{path}: calls {dep} but its 'PYTHON FILES USED' header does not name it")

# Each task folder keeps its own tests beside the collector.
for folder in sorted(set(COLLECTORS.values())):
    tests = pathlib.Path(folder) / "tests"
    if folder in {"cp09-02"}:
        continue  # covered by the shared CP-9 and scope-selection suites
    if not tests.is_dir():
        failures.append(f"{folder}/tests/ is missing — a task keeps its tests beside its code")

if failures:
    print("REPO STRUCTURE: FAILED", file=sys.stderr)
    for f in failures:
        print("  " + f, file=sys.stderr)
    sys.exit(1)

print(f"Verified {len(COLLECTORS)} collectors are in their task folders,")
print("each declares the Python files it uses, and every declaration matches reality.")
PY

echo "PASS: repository structure and PYTHON FILES USED header accuracy"
