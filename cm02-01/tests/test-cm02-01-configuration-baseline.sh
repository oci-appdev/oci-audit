#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/cm02-01/cm02-01-configuration-baseline.sh"
MOCK="$ROOT/cm08-01/tests/mock-oci-task8"
TENANCY="ocid1.tenancy.oc1..task8tenancy"
COMP="ocid1.compartment.oc1..task8config"
TEST_TMP="$(mktemp -d)"
trap 'find "$TEST_TMP" -depth -delete' EXIT
mkdir -p "$TEST_TMP/bin"
ln -s "$MOCK" "$TEST_TMP/bin/oci"

AUTOMATION=(
  --non-interactive
  --confirm-scope-ocid "$COMP"
  --approve-scan YES
)

bash "$SCRIPT" --selfcheck >/dev/null

# The source gate includes the invoked raw inventory engine.
mkdir -p "$TEST_TMP/injected/lib" "$TEST_TMP/injected/cm02-01" "$TEST_TMP/injected/cm08-01"
cp "$SCRIPT" "$TEST_TMP/injected/cm02-01/cm02-01-configuration-baseline.sh"
ln -s "$ROOT/cm08-01/cm08-hw-sw-baseline.sh" "$TEST_TMP/injected/cm08-01/cm08-hw-sw-baseline.sh"
ln -s "$ROOT/lib/oci-scope-selector.sh" "$TEST_TMP/injected/lib/oci-scope-selector.sh"
ln -s "$ROOT/cm02-01/cm02-01-reconcile.py" "$TEST_TMP/injected/cm02-01/cm02-01-reconcile.py"
printf '\noci compute instance terminate --instance-id ocid1.instance.example\n' \
  >> "$TEST_TMP/injected/cm02-01/cm02-01-configuration-baseline.sh"
set +e
bash "$TEST_TMP/injected/cm02-01/cm02-01-configuration-baseline.sh" --selfcheck \
  > "$TEST_TMP/injected.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'prohibited call found' "$TEST_TMP/injected.out"

# One simple command, with no governance inputs or mode flag, produces only the
# technical snapshot, coverage, plan, summary and raw evidence inside the
# collector-specific output folder.
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_LOG="$TEST_TMP/simple.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 -p DOJ-GOV \
    "${AUTOMATION[@]}" -o "$TEST_TMP/simple" > "$TEST_TMP/simple.out"

items="$(find "$TEST_TMP/simple" -name 'cm02-01_configuration_items_*.csv' -print -quit)"
attrs="$(find "$TEST_TMP/simple" -name 'cm02-01_configuration_attributes_*.csv' -print -quit)"
coverage="$(find "$TEST_TMP/simple" -name 'cm02-01_coverage_*.csv' -print -quit)"
summary="$(find "$TEST_TMP/simple" -name 'cm02-01_summary_*.txt' -print -quit)"
plan="$(find "$TEST_TMP/simple" -name 'cm02-01_approved_scan_plan_*.txt' -print -quit)"
[ -n "$items" ] && [ -n "$attrs" ] && [ -n "$coverage" ]
[ -n "$summary" ] && [ -n "$plan" ]
[ -d "$TEST_TMP/simple/cm02-01" ]
! find "$TEST_TMP/simple" -name '*template*.csv' -print -quit | grep -q .
! find "$TEST_TMP/simple" -name '*reconciliation*.csv' -print -quit | grep -q .
grep -q 'Mode            : SIMPLE TECHNICAL COLLECTION' "$plan"
grep -q 'OCI CLI profile : DOJ-GOV' "$plan"
grep -q -- '--profile DOJ-GOV' "$TEST_TMP/simple.log"
grep -q 'COLLECTION STATUS      : COMPLETE' "$summary"
grep -q 'CM02-01 COLLECTION COMPLETE' "$TEST_TMP/simple.out"
! grep -qi 'authorization decision' "$summary"
[ "$(stat -c '%a' "$items")" = "600" ]

python3 - "$items" "$attrs" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

items, attrs = map(rows, sys.argv[1:])
assert {row["resource_type"] for row in items} == {
    "COMPUTE_INSTANCE", "VNIC", "VCN", "SUBNET",
}, items
assert len(items) == 4 and len(attrs) > 30
assert all(row["compartment_ocid"] == "ocid1.compartment.oc1..task8config" for row in items)
assert all(len(row["configuration_hash"]) == 64 for row in items)
PY

# Former governance flags are rejected clearly before workload collection.
: > "$TEST_TMP/legacy.log"
set +e
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_LOG="$TEST_TMP/legacy.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 -g old-register.csv \
    -o "$TEST_TMP/legacy" > "$TEST_TMP/legacy.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'removed from the simple CM02 collector' "$TEST_TMP/legacy.out"
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce) ' "$TEST_TMP/legacy.log"

# A denied read is the only evidence condition that makes this collector exit 3.
set +e
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_DENY_COMPUTE=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" \
  -o "$TEST_TMP/denied" > "$TEST_TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
denied_coverage="$(find "$TEST_TMP/denied" -name 'cm02-01_coverage_*.csv' -print -quit)"
denied_errors="$(find "$TEST_TMP/denied" -name 'cm02-01_collection_errors_*.csv' -print -quit)"
denied_summary="$(find "$TEST_TMP/denied" -name 'cm02-01_summary_*.txt' -print -quit)"
grep -q '"FAILED"' "$denied_coverage"
grep -q 'AUTHZ_OR_ABSENT' "$denied_errors"
grep -q 'COLLECTION STATUS      : INCOMPLETE' "$denied_summary"
grep -q 'CM02-01 COLLECTION INCOMPLETE' "$TEST_TMP/denied.out"
grep -Fq "Review: $denied_coverage" "$TEST_TMP/denied.out"

# OCI-controlled spreadsheet formulas remain neutralized.
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" \
  -o "$TEST_TMP/formula" >/dev/null
grep -q "'=2+3" "$(find "$TEST_TMP/formula" -name 'cm02-01_configuration_items_*.csv' -print -quit)"
grep -q "'=2+3" "$(find "$TEST_TMP/formula" -name 'compute_instances.csv' -print -quit)"

# A Compute image keeps its owner compartment while the instance keeps its own.
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_WITH_IMAGE=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" \
  -o "$TEST_TMP/image-owner" >/dev/null
python3 - "$TEST_TMP/image-owner" "$TENANCY" "$COMP" <<'PY'
import csv
import sys
from pathlib import Path

root, tenancy, comp = sys.argv[1:]
path = next(Path(root).rglob("cm02-01_configuration_items_*.csv"))
with path.open(newline="", encoding="utf-8-sig") as handle:
    items = list(csv.DictReader(handle))
images = [row for row in items if row["resource_type"] == "COMPUTE_IMAGE"]
instances = [row for row in items if row["resource_type"] == "COMPUTE_INSTANCE"]
assert len(images) == 1 and images[0]["compartment_ocid"] == tenancy, images
assert len(instances) == 1 and instances[0]["compartment_ocid"] == comp, instances
PY

# Manual -c still requires the target OCID twice and exact uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TEST_TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
    -o "$TEST_TMP/manual" > "$TEST_TMP/manual.out"
grep -q 'Type exact uppercase YES to run this scan' "$TEST_TMP/manual.out"

# Refusal stops before workload calls and leaves no CSV evidence.
set +e
printf '%s\n%s\n%s\n' "$COMP" "$COMP" no | \
  PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_LOG="$TEST_TMP/refuse.log" bash "$SCRIPT" \
    -c "$COMP" -r us-langley-1 -o "$TEST_TMP/refuse" \
    > "$TEST_TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce) ' "$TEST_TMP/refuse.log"
! find "$TEST_TMP/refuse" -name '*.csv' -print -quit 2>/dev/null | grep -q .

# Default selection supports a compartment or tenancy with double confirmation.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TEST_TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 \
    -o "$TEST_TMP/interactive" > "$TEST_TMP/interactive.out"
grep -q 'Confirmed scope: COMPARTMENT — Configuration' "$TEST_TMP/interactive.out"

printf '%s\n%s\n%s\n' "$TENANCY" "$TENANCY" YES | \
  PATH="$TEST_TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 \
    -o "$TEST_TMP/tenancy" > "$TEST_TMP/tenancy.out"
grep -q 'Scope type      : TENANCY' "$TEST_TMP/tenancy.out"
grep -q 'Compartments    : 2' "$TEST_TMP/tenancy.out"

# Strict automation mismatch fails before workload collection.
set +e
PATH="$TEST_TMP/bin:$PATH" MOCK_TASK8_LOG="$TEST_TMP/auto-refuse.log" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 --non-interactive \
  --confirm-scope-ocid ocid1.compartment.oc1..wrong --approve-scan YES \
  -o "$TEST_TMP/auto-refuse" > "$TEST_TMP/auto-refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce) ' "$TEST_TMP/auto-refuse.log"

echo "PASS: CM02-01 simple collection, scope safety and failure reporting"
