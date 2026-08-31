#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/cm02-01-configuration-baseline.sh"
MOCK="$ROOT/tests/mock-oci-task8"
TENANCY="ocid1.tenancy.oc1..task8tenancy"
COMP="ocid1.compartment.oc1..task8config"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
ln -s "$MOCK" "$TMP/bin/oci"

AUTOMATION=(
  --non-interactive
  --confirm-scope-ocid "$COMP"
  --approve-scan YES
)

bash "$SCRIPT" --selfcheck >/dev/null

# The source-level boundary includes the invoked inventory engine.
mkdir -p "$TMP/injected/lib"
cp "$SCRIPT" "$TMP/injected/cm02-01-configuration-baseline.sh"
ln -s "$ROOT/cm08-hw-sw-baseline.sh" "$TMP/injected/cm08-hw-sw-baseline.sh"
ln -s "$ROOT/lib/oci-scope-selector.sh" "$TMP/injected/lib/oci-scope-selector.sh"
ln -s "$ROOT/lib/cm02-01-reconcile.py" "$TMP/injected/lib/cm02-01-reconcile.py"
printf '\noci compute instance terminate --instance-id ocid1.instance.example\n' \
  >> "$TMP/injected/cm02-01-configuration-baseline.sh"
set +e
bash "$TMP/injected/cm02-01-configuration-baseline.sh" --selfcheck \
  > "$TMP/injected.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'prohibited call found' "$TMP/injected.out"

# Inventory-only generates the CI, baseline and monthly-review templates without
# claiming that organizational approvals were supplied.
PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/inventory.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 -p DOJ-GOV \
    "${AUTOMATION[@]}" --inventory-only -o "$TMP/inventory" \
    > "$TMP/inventory.out"

items="$(find "$TMP/inventory" -name 'cm02-01_configuration_items_*.csv' -print -quit)"
attrs="$(find "$TMP/inventory" -name 'cm02-01_configuration_attributes_*.csv' -print -quit)"
ci_template="$(find "$TMP/inventory" -name 'cm02-01_ci_register_template_*.csv' -print -quit)"
baseline_template="$(find "$TMP/inventory" -name 'cm02-01_baseline_template_*.csv' -print -quit)"
review_template="$(find "$TMP/inventory" -name 'cm02-01_monthly_review_template_*.csv' -print -quit)"
sources="$(find "$TMP/inventory" -name 'cm02-01_input_sources_*.csv' -print -quit)"
coverage="$(find "$TMP/inventory" -name 'cm02-01_coverage_*.csv' -print -quit)"
plan="$(find "$TMP/inventory" -name 'cm02-01_approved_scan_plan_*.txt' -print -quit)"
[ -n "$items" ] && [ -n "$attrs" ] && [ -n "$ci_template" ]
[ -n "$baseline_template" ] && [ -n "$review_template" ] && [ -n "$sources" ]
[ -n "$coverage" ] && [ -n "$plan" ]
grep -q 'SKIPPED-INVENTORY-ONLY' "$sources"
grep -q 'OCI CLI profile : DOJ-GOV' "$plan"
grep -q -- '--profile DOJ-GOV' "$TMP/inventory.log"
[ "$(stat -c '%a' "$items")" = "600" ]

python3 - "$items" "$attrs" "$ci_template" "$baseline_template" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

items, attrs, cis, baseline = map(rows, sys.argv[1:])
assert {row["resource_type"] for row in items} == {"COMPUTE_INSTANCE", "VNIC", "VCN", "SUBNET"}, items
assert len(items) == len(cis) == 4
assert len(attrs) == len(baseline) and len(attrs) > 30
assert all(row["compartment_ocid"] == "ocid1.compartment.oc1..task8config" for row in items)
assert all(row["registration_status"] == "PENDING-REVIEW" for row in cis)
assert all(row["approval_status"] == "PENDING-REVIEW" for row in baseline)
PY

# Build organization-owned approved inputs from the generated review templates.
python3 - "$ci_template" "$TMP/ci-approved.csv" \
  "$baseline_template" "$TMP/baseline-approved.csv" \
  "$review_template" "$TMP/review-approved.csv" <<'PY'
import csv
import sys
from datetime import date

ci_source, ci_target, base_source, base_target, review_source, review_target = sys.argv[1:]
today = date.today().isoformat()

def read(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

def write(path, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)

cis = read(ci_source)
for row in cis:
    row.update({
        "system_name": "OCS", "system_owner": "OCS System Owner",
        "technical_owner": "OCI Platform Team", "criticality": "HIGH",
        "environment": "PROD", "configuration_baseline_id": "OCS-CM02-BASELINE-001",
        "system_design_reference": "OCS-SYSTEM-DESIGN-FORM-2026",
        "review_frequency": "MONTHLY", "registration_status": "APPROVED",
        "approval_id": "CCB-2026-0088", "approved_by": "Configuration Control Board",
        "approval_date": today, "source_reference": "OCS-CI-REGISTER-2026",
    })
write(ci_target, cis)

baseline = read(base_source)
for row in baseline:
    row.update({
        "baseline_id": "OCS-CM02-BASELINE-001", "comparison": "EXACT",
        "approval_status": "APPROVED", "approval_id": "CCB-2026-0088",
        "approval_authority": "Configuration Control Board",
        "approved_by": "Configuration Control Board", "approval_date": today,
        "effective_date": today, "system_design_reference": "OCS-SYSTEM-DESIGN-FORM-2026",
    })
write(base_target, baseline)

reviews = read(review_source)
reviews[0].update({
    "review_id": "CM02-REVIEW-2026-08", "review_date": today,
    "reviewer": "Configuration Manager", "reviewer_role": "CM Lead",
    "baseline_id": "OCS-CM02-BASELINE-001",
    "reconciliation_reference": "CM02-RECON-2026-08",
    "findings_reviewed": "YES", "changes_validated": "YES",
    "exceptions_reviewed": "YES", "corrective_actions": "No open corrective actions",
    "review_status": "APPROVED", "approver": "OCS System Owner",
    "approval_date": today, "evidence_reference": "REMEDY-CM02-2026-08",
})
write(review_target, reviews)
PY

# Complete reconciliation matches every controlled attribute and records input
# hashes and one valid current monthly review.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -g "$TMP/ci-approved.csv" \
  -b "$TMP/baseline-approved.csv" -m "$TMP/review-approved.csv" \
  -o "$TMP/complete" > "$TMP/complete.out"

recon="$(find "$TMP/complete" -name 'cm02-01_baseline_reconciliation_*.csv' -print -quit)"
complete_findings="$(find "$TMP/complete" -name 'cm02-01_findings_*.csv' -print -quit)"
complete_sources="$(find "$TMP/complete" -name 'cm02-01_input_sources_*.csv' -print -quit)"
review_results="$(find "$TMP/complete" -name 'cm02-01_monthly_review_results_*.csv' -print -quit)"
python3 - "$recon" "$complete_findings" "$complete_sources" "$review_results" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

recon, findings, sources, reviews = map(rows, sys.argv[1:])
assert recon and {row["reconciliation_status"] for row in recon} == {"MATCH"}, recon
assert findings == [], findings
assert len(sources) == 3 and all(row["sha256"] for row in sources), sources
assert len(reviews) == 1 and reviews[0]["validation_status"] == "VALID", reviews
PY

# A changed approved value is explicit drift, not an incomplete collection.
python3 - "$TMP/baseline-approved.csv" "$TMP/baseline-drift.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
for row in rows:
    if row["resource_type"] == "VCN" and row["attribute_name"] == "cidr_blocks":
        row["expected_value"] = "10.20.0.0/16"
        break
else:
    raise AssertionError("VCN cidr_blocks baseline row not found")
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(rows)
PY
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -g "$TMP/ci-approved.csv" \
  -b "$TMP/baseline-drift.csv" -m "$TMP/review-approved.csv" \
  -o "$TMP/drift" >/dev/null
grep -q 'CONFIGURATION-DRIFT' "$(find "$TMP/drift" -name 'cm02-01_baseline_reconciliation_*.csv' -print -quit)"
grep -q '"HIGH","CONFIGURATION-DRIFT"' "$(find "$TMP/drift" -name 'cm02-01_findings_*.csv' -print -quit)"

# Omitting a live attribute from the approved baseline is incomplete evidence.
python3 - "$TMP/baseline-approved.csv" "$TMP/baseline-missing.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(rows[:-1])
PY
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -g "$TMP/ci-approved.csv" \
  -b "$TMP/baseline-missing.csv" -m "$TMP/review-approved.csv" \
  -o "$TMP/missing" > "$TMP/missing.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'ATTRIBUTE-NOT-BASELINED' "$(find "$TMP/missing" -name 'cm02-01_findings_*.csv' -print -quit)"

# More than one row for the current review period cannot satisfy the monthly
# approval gate, even if one or both rows are otherwise complete.
python3 - "$TMP/review-approved.csv" "$TMP/review-duplicate.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
duplicate = dict(rows[0])
duplicate["review_id"] = duplicate["review_id"] + "-DUPLICATE"
rows.append(duplicate)
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(rows)
PY
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -g "$TMP/ci-approved.csv" \
  -b "$TMP/baseline-approved.csv" -m "$TMP/review-duplicate.csv" \
  -o "$TMP/review-duplicate" > "$TMP/review-duplicate.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'NO-VALID-CURRENT-REVIEW' \
  "$(find "$TMP/review-duplicate" -name 'cm02-01_collection_errors_*.csv' -print -quit)"

# A denied inventory operation is retained in coverage/errors and forces exit 3.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK8_DENY_COMPUTE=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/denied" > "$TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q '"FAILED"' "$(find "$TMP/denied" -name 'cm02-01_coverage_*.csv' -print -quit)"
grep -q 'AUTHZ_OR_ABSENT' "$(find "$TMP/denied" -name 'cm02-01_collection_errors_*.csv' -print -quit)"

# OCI-controlled spreadsheet formulas are neutralized in canonical and raw CSVs.
PATH="$TMP/bin:$PATH" MOCK_TASK8_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/formula" >/dev/null
grep -q "'=2+3" "$(find "$TMP/formula" -name 'cm02-01_configuration_items_*.csv' -print -quit)"
grep -q "'=2+3" "$(find "$TMP/formula" -name 'compute_instances.csv' -print -quit)"

# Manual -c requires the target OCID twice and exact uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
    --inventory-only -o "$TMP/manual" > "$TMP/manual.out"
grep -q 'Type exact uppercase YES to run this scan' "$TMP/manual.out"

# A refusal stops before every workload-service call and publishes no CSV.
set +e
printf '%s\n%s\n%s\n' "$COMP" "$COMP" no | \
  PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/refuse.log" bash "$SCRIPT" \
    -c "$COMP" -r us-langley-1 --inventory-only -o "$TMP/refuse" \
    > "$TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce) ' "$TMP/refuse.log"
! find "$TMP/refuse" -name '*.csv' -print -quit 2>/dev/null | grep -q .

# Default interactive selection accepts a discovered compartment OCID twice.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 --inventory-only \
    -o "$TMP/interactive" > "$TMP/interactive.out"
grep -q 'DISCOVERED OCI AUDIT SCOPES' "$TMP/interactive.out"
grep -q 'Confirmed scope: COMPARTMENT — Configuration' "$TMP/interactive.out"

# A tenancy selection discloses root plus every active child in the plan.
printf '%s\n%s\n%s\n' "$TENANCY" "$TENANCY" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -i -r us-langley-1 --inventory-only \
    -o "$TMP/tenancy" > "$TMP/tenancy.out"
grep -q 'Scope type      : TENANCY' "$TMP/tenancy.out"
grep -q 'Compartments    : 2' "$TMP/tenancy.out"

# Strict automation mismatch fails before workload collection.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/auto-refuse.log" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 --non-interactive \
  --confirm-scope-ocid ocid1.compartment.oc1..wrong --approve-scan YES \
  --inventory-only -o "$TMP/auto-refuse" > "$TMP/auto-refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce) ' "$TMP/auto-refuse.log"

echo "PASS: CM02-01 scope safety, CI/baseline/monthly reconciliation and failure regression"
