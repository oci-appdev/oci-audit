#!/usr/bin/env bash
#
# MANUAL-EVIDENCE-PROCEDURES.md publishes the exact CSV column schema for every
# governance input the collectors validate. Those schemas are the contract an
# operator types against, and a missing column fails a collection run *before*
# scanning -- deliberately, so an input that silently degraded to empty cannot
# report every control as unapproved.
#
# That makes a stale table in the document worse than no table: it sends an
# operator to build a register that the collector will reject, or worse, one
# whose columns no longer mean what the document says. The same reasoning that
# put a template-drift gate on CM07-01.
#
# This gate compares the documented columns against the *_FIELDS constants the
# collectors actually validate against.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
import ast, pathlib, re, sys

DOC = pathlib.Path("MANUAL-EVIDENCE-PROCEDURES.md")
text = DOC.read_text(encoding="utf-8")

# (collector file, constant name, the flag as written in the doc table)
CONTRACTS = [
    ("ca07-01/ca07-01-continuous-monitoring.py", "BASELINE_FIELDS", "--monitoring-baseline"),
    ("ca07-01/ca07-01-continuous-monitoring.py", "REVIEW_FIELDS", "--monthly-review"),
    ("cp02-01/cp02-01-contingency-planning.py", "ISCP_REGISTER_FIELDS", "--iscp-register"),
    ("cp04-01/cp04-01-contingency-plan-testing.py", "TEST_REGISTER_FIELDS", "--test-register"),
]

def constant(path, name):
    tree = ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.AnnAssign):
            targets = [getattr(node.target, "id", "")]
        elif isinstance(node, ast.Assign):
            targets = [getattr(t, "id", "") for t in node.targets]
        if name in targets:
            value = node.value
            if isinstance(value, ast.BinOp):  # FIELDS + ["extra"]
                continue
            return [e.value for e in getattr(value, "elts", [])
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
    return None

# Each documented row is: | collector | `--flag` | `col, col, col` |
rows = {}
for line in text.splitlines():
    if not line.startswith("|"):
        continue
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) != 3:
        continue
    flag = cells[1].strip("`")
    if not flag.startswith("--"):
        continue
    documented = [c.strip() for c in cells[2].strip("`").split(",") if c.strip()]
    rows.setdefault(flag, documented)

failures = []
checked = 0
for path, name, flag in CONTRACTS:
    actual = constant(path, name)
    if actual is None:
        failures.append(f"{path}: constant {name} not found (renamed or restructured?)")
        continue
    documented = rows.get(flag)
    if documented is None:
        failures.append(f"{DOC}: no schema row documents {flag}")
        continue
    if documented != actual:
        missing = [c for c in actual if c not in documented]
        extra = [c for c in documented if c not in actual]
        detail = []
        if missing:
            detail.append(f"undocumented columns: {missing}")
        if extra:
            detail.append(f"documented but absent from {name}: {extra}")
        if not detail:
            detail.append("same columns, different order")
        failures.append(f"{flag}: " + "; ".join(detail))
    checked += 1

# The SI-04 destination map is validated inline rather than by a *_FIELDS
# constant, so it is checked against the literal the loader requires.
si04 = pathlib.Path("si04-01/si04-01-siem-crowdstrike-forwarding.py").read_text(encoding="utf-8")
m = re.search(r'required\s*=\s*\(([^)]*)\)', si04)
if m:
    required = [s for s in re.findall(r'"([a-z_]+)"', m.group(1))]
    documented = rows.get("--siem-destinations", [])
    if sorted(required) != sorted(documented):
        failures.append(f"--siem-destinations: collector requires {required}, "
                        f"document says {documented}")
    checked += 1
else:
    failures.append("si04-01: could not locate the destination-map required columns")

if failures:
    print("DOC SCHEMA DRIFT: FAILED", file=sys.stderr)
    for f in failures:
        print("  " + f, file=sys.stderr)
    print("\nUpdate the schema table in MANUAL-EVIDENCE-PROCEDURES.md to match the "
          "collectors. An operator builds a register from that table; a stale one "
          "sends them to build something the collector rejects.", file=sys.stderr)
    sys.exit(1)

MIN_CHECKED = 5
if checked < MIN_CHECKED:
    print(f"DOC SCHEMA DRIFT: FAILED — only {checked} schemas compared, expected at "
          f"least {MIN_CHECKED}. Coverage has collapsed; fix discovery rather than "
          f"lowering this floor.", file=sys.stderr)
    sys.exit(1)

print(f"Compared {checked} documented governance-input schemas against the "
      f"constants the collectors validate against.")
PY

echo "PASS: MANUAL-EVIDENCE-PROCEDURES.md schemas match the collectors"
