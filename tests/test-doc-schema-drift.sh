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

# Shipped templates must match too. An operator fills in the CSV in templates/,
# so a template whose header drifted from the collector sends them to build
# something that fails validation before scanning -- the same failure the
# document table would cause, one step closer to the operator.
TEMPLATES = [
    ("templates/ca07-01-monitoring-baseline-template.csv",
     "ca07-01/ca07-01-continuous-monitoring.py", "BASELINE_FIELDS"),
    ("templates/ca07-01-monthly-review-template.csv",
     "ca07-01/ca07-01-continuous-monitoring.py", "REVIEW_FIELDS"),
    ("templates/cp02-01-iscp-register-template.csv",
     "cp02-01/cp02-01-contingency-planning.py", "ISCP_REGISTER_FIELDS"),
    ("templates/cp04-01-test-register-template.csv",
     "cp04-01/cp04-01-contingency-plan-testing.py", "TEST_REGISTER_FIELDS"),
]
for rel, collector, name in TEMPLATES:
    path = pathlib.Path(rel)
    if not path.exists():
        failures.append(f"{rel}: shipped template is missing")
        continue
    header = path.read_text(encoding="utf-8").splitlines()[0]
    shipped = [c.strip() for c in header.split(",")]
    actual = constant(collector, name)
    if actual is None:
        failures.append(f"{collector}: constant {name} not found")
        continue
    if shipped != actual:
        failures.append(f"{rel}: header does not match {name} in {collector}")
    checked += 1

# si04-01 validates its destination map inline, so the template is compared to
# the literal the loader requires rather than to a *_FIELDS constant.
dest = pathlib.Path("templates/si04-01-siem-destinations-template.csv")
if not dest.exists():
    failures.append("templates/si04-01-siem-destinations-template.csv: missing")
elif m:
    shipped = [c.strip() for c in dest.read_text(encoding="utf-8").splitlines()[0].split(",")]
    if sorted(shipped) != sorted(required):
        failures.append(f"si04 destinations template header {shipped} != required {required}")
    checked += 1

# MANUAL-PROCESS-INSTRUCTIONS.md hands the operator literal commands. A flag
# that does not exist, or a template path that does not, wastes a scan window
# and reads as a tooling failure rather than a stale document.
RUNBOOK = pathlib.Path("MANUAL-PROCESS-INSTRUCTIONS.md")
if RUNBOOK.exists():
    runbook = RUNBOOK.read_text(encoding="utf-8")
    for rel in sorted(set(re.findall(r'templates/[a-z0-9._-]+\.csv', runbook))):
        if not pathlib.Path(rel).exists():
            failures.append(f"{RUNBOOK}: names a template that does not exist: {rel}")
        checked += 1
    # Flags are checked per collector block, against that collector's argparse.
    for collector in sorted(set(re.findall(r'([a-z0-9-]+/[a-z0-9-]+\.py)', runbook))):
        path = pathlib.Path(collector)
        if not path.exists():
            continue  # Tasks 11-13 live on main; the runbook says so.
        source = path.read_text(encoding="utf-8")
        declared = set(re.findall(r'add_argument\(\s*"(--[a-z0-9-]+)"', source))
        declared |= set(re.findall(r'add_argument\(\s*"-[a-z]",\s*"(--[a-z0-9-]+)"', source))
        # Join backslash continuations first: a multi-line command puts the
        # collector on one line and its flags on the next, so a per-line scan
        # silently checks nothing. Found by injection.
        joined, buf = [], ""
        for raw in runbook.splitlines():
            buf = (buf + " " + raw.strip()) if buf else raw
            if buf.rstrip().endswith("\\"):
                buf = buf.rstrip()[:-1]
                continue
            joined.append(buf)
            buf = ""
        if buf:
            joined.append(buf)
        for line in joined:
            if collector not in line:
                continue
            for flag in re.findall(r'(--[a-z0-9-]+)', line):
                if flag not in declared:
                    failures.append(
                        f"{RUNBOOK}: tells the operator to run {collector} {flag}, "
                        f"which that collector does not accept")
                checked += 1

if failures:
    print("DOC / TEMPLATE / RUNBOOK DRIFT: FAILED", file=sys.stderr)
    for f in failures:
        print("  " + f, file=sys.stderr)
    print("\nUpdate the schema table in MANUAL-EVIDENCE-PROCEDURES.md to match the "
          "collectors. An operator builds a register from that table; a stale one "
          "sends them to build something the collector rejects.", file=sys.stderr)
    sys.exit(1)

MIN_CHECKED = 20
if checked < MIN_CHECKED:
    print(f"DOC SCHEMA DRIFT: FAILED — only {checked} schemas compared, expected at "
          f"least {MIN_CHECKED}. Coverage has collapsed; fix discovery rather than "
          f"lowering this floor.", file=sys.stderr)
    sys.exit(1)

print(f"Compared {checked} documented schemas, shipped templates and runbook "
      f"commands against the collectors.")
PY

echo "PASS: documentation, shipped templates and runbook commands match the collectors"
