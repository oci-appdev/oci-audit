#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/cm08-01-component-inventory-baseline.sh"
MOCK="$ROOT/tests/mock-oci-task8"
TENANCY="ocid1.tenancy.oc1..task8tenancy"
COMP="ocid1.compartment.oc1..task8config"
TMP="$(mktemp -d)"
trap 'find "$TMP" -depth -delete' EXIT
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
cp "$SCRIPT" "$TMP/injected/cm08-01-component-inventory-baseline.sh"
cp "$ROOT/cm08-hw-sw-baseline.sh" "$TMP/injected/cm08-hw-sw-baseline.sh"
ln -s "$ROOT/lib/oci-scope-selector.sh" "$TMP/injected/lib/oci-scope-selector.sh"
ln -s "$ROOT/lib/cm08-01-reconcile.py" "$TMP/injected/lib/cm08-01-reconcile.py"
ln -s "$ROOT/lib/cm02-01-reconcile.py" "$TMP/injected/lib/cm02-01-reconcile.py"
printf '\nemit unsafe.csv unsafe "." compute instance terminate --instance-id ocid1.instance.example\n' \
  >> "$TMP/injected/cm08-hw-sw-baseline.sh"
set +e
bash "$TMP/injected/cm08-01-component-inventory-baseline.sh" --selfcheck \
  > "$TMP/injected.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'prohibited call found' "$TMP/injected.out"

# Mutation hidden behind the wrapper's discovery helper is also detected.
cp "$ROOT/cm08-hw-sw-baseline.sh" "$TMP/injected/cm08-hw-sw-baseline.sh"
printf '\noci_discover unsafe compute instance terminate --instance-id ocid1.instance.example\n' \
  >> "$TMP/injected/cm08-01-component-inventory-baseline.sh"
set +e
bash "$TMP/injected/cm08-01-component-inventory-baseline.sh" --selfcheck \
  > "$TMP/injected-discovery.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'prohibited call found' "$TMP/injected-discovery.out"

# The broad engine is internal-only and cannot bypass the wrapper approval gate.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/direct-engine.log" \
  bash "$ROOT/cm08-hw-sw-baseline.sh" -c "$COMP" -r us-langley-1 \
  -o "$TMP/direct-engine" > "$TMP/direct-engine.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 2 ]
grep -q 'internal raw engine' "$TMP/direct-engine.out"
[ ! -e "$TMP/direct-engine.log" ]

# Inventory-only collects packages, normalizes stable component identities and
# creates pending approval/review templates without inventing authorization.
PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/inventory.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 -p DOJ-GOV \
    "${AUTOMATION[@]}" --inventory-only -o "$TMP/inventory" \
    > "$TMP/inventory.out"

components="$(find "$TMP/inventory" -name 'cm08-01_component_inventory_*.csv' -print -quit)"
baseline_template="$(find "$TMP/inventory" -name 'cm08-01_approved_inventory_template_*.csv' -print -quit)"
gaps="$(find "$TMP/inventory" -name 'cm08-01_unmanaged_coverage_gaps_*.csv' -print -quit)"
sources="$(find "$TMP/inventory" -name 'cm08-01_input_sources_*.csv' -print -quit)"
coverage="$(find "$TMP/inventory" -name 'cm08-01_coverage_*.csv' -print -quit)"
plan="$(find "$TMP/inventory" -name 'cm08-01_approved_scan_plan_*.txt' -print -quit)"
raw_summary="$(find "$TMP/inventory" -name summary.txt -print -quit)"
[ -n "$components" ] && [ -n "$baseline_template" ] && [ -n "$gaps" ]
[ -n "$sources" ] && [ -n "$coverage" ] && [ -n "$plan" ] && [ -n "$raw_summary" ]
grep -q 'SKIPPED-INVENTORY-ONLY' "$sources"
grep -q 'OCI CLI profile   : DOJ-GOV' "$plan"
grep -q 'Installed packages: INCLUDED' "$plan"
grep -q 'Packages     : included' "$raw_summary"
grep -q -- '--profile DOJ-GOV' "$TMP/inventory.log"
[ "$(stat -c '%a' "$components")" = "600" ]

python3 - "$components" "$baseline_template" "$gaps" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

components, baseline, gaps = map(rows, sys.argv[1:])
assert {row["resource_type"] for row in components} == {"COMPUTE_INSTANCE", "VNIC", "VCN", "SUBNET"}
assert len(components) == len(baseline) == 4
assert all(row["compartment_ocid"] == "ocid1.compartment.oc1..task8config" for row in components)
assert all(row["inventory_fingerprint"] for row in components)
assert all(row["approval_status"] == "PENDING-REVIEW" for row in baseline)
assert {row["gap_type"] for row in gaps} == {
    "IN-GUEST-SOFTWARE-INVENTORY-NOT-PROVEN",
    "PROVIDER-PHYSICAL-HARDWARE-OUTSIDE-OCI-API",
}
PY

# Approve the generated current inventory as the prior-month organizational
# baseline and bind the monthly review to the exact reconciliation counts.
python3 - "$baseline_template" "$TMP/approved.csv" \
  "$TMP/review.csv" "$COMP" <<'PY'
import csv
import sys
from datetime import date

source, approved_target, review_target, scope = sys.argv[1:]
today = date.today().isoformat()
period = date.today().strftime("%Y-%m")
with open(source, newline="", encoding="utf-8-sig") as handle:
    approved = list(csv.DictReader(handle))
for row in approved:
    row.update({
        "system_name": "OCS", "system_owner": "OCS System Owner",
        "technical_owner": "OCI Platform Team", "environment": "PROD",
        "criticality": "HIGH", "inventory_status": "ACTIVE",
        "baseline_id": "OCS-CM08-INVENTORY-2026-08",
        "approval_status": "APPROVED", "approval_id": "ASSET-2026-0088",
        "approval_authority": "OCS System Owner", "approved_by": "OCS System Owner",
        "approval_date": today, "effective_date": today,
        "source_reference": "OCS-ASSET-REGISTER-2026-08",
    })
with open(approved_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(approved[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(approved)

review = [{
    "review_id": "CM08-REVIEW-2026-08", "review_period": period,
    "review_date": today, "reviewer": "Asset Manager", "reviewer_role": "CM-8 Owner",
    "scope_ocid": scope, "baseline_id": "OCS-CM08-INVENTORY-2026-08",
    "reconciliation_reference": "CM08-RECON-2026-08",
    "unchanged_count": "4", "added_count": "0", "removed_count": "0",
    "changed_count": "0", "unmanaged_gap_count": "2",
    "inventory_reviewed": "YES", "changes_dispositioned": "YES",
    "coverage_reviewed": "YES", "corrective_actions": "Guest inventory tracked separately",
    "review_status": "APPROVED", "approver": "OCS System Owner",
    "approval_date": today, "evidence_reference": "REMEDY-CM08-2026-08", "notes": "",
}]
with open(review_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(review[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(review)
PY

# Identical live and approved inventories reconcile cleanly. A disposition file
# is unnecessary when the current month has no additions, removals or changes.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -b "$TMP/approved.csv" -m "$TMP/review.csv" \
  -o "$TMP/complete" > "$TMP/complete.out"
recon="$(find "$TMP/complete" -name 'cm08-01_inventory_reconciliation_*.csv' -print -quit)"
review_results="$(find "$TMP/complete" -name 'cm08-01_monthly_review_results_*.csv' -print -quit)"
complete_sources="$(find "$TMP/complete" -name 'cm08-01_input_sources_*.csv' -print -quit)"
python3 - "$recon" "$review_results" "$complete_sources" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

recon, reviews, sources = map(rows, sys.argv[1:])
assert len(recon) == 4 and {row["reconciliation_status"] for row in recon} == {"UNCHANGED"}
assert len(reviews) == 1 and reviews[0]["validation_status"] == "VALID"
assert sources[1]["input_type"] == "CHANGE-DISPOSITIONS"
assert sources[1]["validation_status"] == "NOT-SUPPLIED"
assert all(row["sha256"] for row in sources if row["validation_status"] == "PROVIDED")
PY

# A non-SHA inventory fingerprint is not accepted as an approved baseline fact.
python3 - "$TMP/approved.csv" "$TMP/invalid-hash.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
rows[0]["inventory_fingerprint"] = "not-a-sha256"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(rows)
PY
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -b "$TMP/invalid-hash.csv" -m "$TMP/review.csv" \
  -o "$TMP/invalid-hash" > "$TMP/invalid-hash.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'APPROVED-INVENTORY-INCOMPLETE' \
  "$(find "$TMP/invalid-hash" -name 'cm08-01_inventory_reconciliation_*.csv' -print -quit)"

# A fingerprint difference is a CHANGED event and fails closed until one exact
# approved disposition and a count-bound current monthly review are supplied.
python3 - "$TMP/approved.csv" "$TMP/changed-approved.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
rows[0]["inventory_fingerprint"] = "0" * 64
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(rows)
PY
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -b "$TMP/changed-approved.csv" \
  -o "$TMP/pending-change" > "$TMP/pending-change.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
pending_recon="$(find "$TMP/pending-change" -name 'cm08-01_inventory_reconciliation_*.csv' -print -quit)"
disposition_template="$(find "$TMP/pending-change" -name 'cm08-01_change_disposition_template_*.csv' -print -quit)"
review_template="$(find "$TMP/pending-change" -name 'cm08-01_monthly_review_template_*.csv' -print -quit)"
grep -q '"CHANGED"' "$pending_recon"
grep -q 'CHANGE-NOT-DISPOSITIONED' "$(find "$TMP/pending-change" -name 'cm08-01_findings_*.csv' -print -quit)"

python3 - "$disposition_template" "$TMP/disposition.csv" \
  "$review_template" "$TMP/changed-review.csv" <<'PY'
import csv
import sys
from datetime import date

disp_source, disp_target, review_source, review_target = sys.argv[1:]
today = date.today().isoformat()

with open(disp_source, newline="", encoding="utf-8-sig") as handle:
    dispositions = list(csv.DictReader(handle))
assert len(dispositions) == 1 and dispositions[0]["change_type"] == "CHANGED"
dispositions[0].update({
    "disposition_id": "CM08-DISP-2026-0001", "disposition_status": "APPROVED",
    "change_reference": "REMEDY-CRQ-2026-0042", "reviewed_by": "Asset Manager",
    "review_date": today, "approval_id": "SO-APPROVAL-2026-0042",
    "approved_by": "OCS System Owner", "approval_date": today,
    "evidence_reference": "REMEDY-CRQ-2026-0042",
})
with open(disp_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(dispositions[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(dispositions)

with open(review_source, newline="", encoding="utf-8-sig") as handle:
    reviews = list(csv.DictReader(handle))
assert reviews[0]["changed_count"] == "1" and reviews[0]["unchanged_count"] == "3"
reviews[0].update({
    "review_id": "CM08-REVIEW-2026-08", "review_date": today,
    "reviewer": "Asset Manager", "reviewer_role": "CM-8 Owner",
    "baseline_id": "OCS-CM08-INVENTORY-2026-08",
    "reconciliation_reference": "CM08-RECON-2026-08-CHANGED",
    "inventory_reviewed": "YES", "changes_dispositioned": "YES",
    "coverage_reviewed": "YES", "corrective_actions": "No open corrective actions",
    "review_status": "APPROVED", "approver": "OCS System Owner",
    "approval_date": today, "evidence_reference": "REMEDY-CM08-2026-08",
})
with open(review_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(reviews[0]), quoting=csv.QUOTE_ALL)
    writer.writeheader(); writer.writerows(reviews)
PY

PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  "${AUTOMATION[@]}" -b "$TMP/changed-approved.csv" \
  -d "$TMP/disposition.csv" -m "$TMP/changed-review.csv" \
  -o "$TMP/dispositioned" > "$TMP/dispositioned.out"
grep -q '"VALID"' "$(find "$TMP/dispositioned" -name 'cm08-01_change_disposition_results_*.csv' -print -quit)"
! grep -q 'CHANGE-NOT-DISPOSITIONED' "$(find "$TMP/dispositioned" -name 'cm08-01_findings_*.csv' -print -quit)"

# Collection denial is retained in coverage/errors and forces exit 3.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK8_DENY_COMPUTE=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/denied" > "$TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q '"FAILED"' "$(find "$TMP/denied" -name 'cm08-01_coverage_*.csv' -print -quit)"
grep -q 'AUTHZ_OR_ABSENT' "$(find "$TMP/denied" -name 'cm08-01_collection_errors_*.csv' -print -quit)"

# OCI-controlled spreadsheet formulas are neutralized in canonical and raw CSV.
PATH="$TMP/bin:$PATH" MOCK_TASK8_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/formula" >/dev/null
grep -q "'=2+3" "$(find "$TMP/formula" -name 'cm08-01_component_inventory_*.csv' -print -quit)"
grep -q "'=2+3" "$(find "$TMP/formula" -name compute_instances.csv -print -quit)"

# Manual -c requires the target OCID twice and exact uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
    --inventory-only -o "$TMP/manual" > "$TMP/manual.out"
grep -q 'Type exact uppercase YES to run this scan' "$TMP/manual.out"

# Refusal and automation mismatch both stop before workload-service calls.
set +e
printf '%s\n%s\n%s\n' "$COMP" "$COMP" no | \
  PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/refuse.log" bash "$SCRIPT" \
    -c "$COMP" -r us-langley-1 --inventory-only -o "$TMP/refuse" \
    > "$TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce|os-management) ' "$TMP/refuse.log"
! find "$TMP/refuse" -name '*.csv' -print -quit 2>/dev/null | grep -q .

set +e
PATH="$TMP/bin:$PATH" MOCK_TASK8_LOG="$TMP/auto-refuse.log" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 --non-interactive \
  --confirm-scope-ocid ocid1.compartment.oc1..wrong --approve-scan YES \
  --inventory-only -o "$TMP/auto-refuse" > "$TMP/auto-refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -Eq '^(compute|network|db|bv|fs|lb|nlb|ce|os-management) ' "$TMP/auto-refuse.log"

# Default interactive selection and tenancy selection both preserve the same
# double-OCID and full-plan requirements.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 --inventory-only \
    -o "$TMP/interactive" > "$TMP/interactive.out"
grep -q 'Confirmed scope: COMPARTMENT — Configuration' "$TMP/interactive.out"

printf '%s\n%s\n%s\n' "$TENANCY" "$TENANCY" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -i -r us-langley-1 --inventory-only \
    -o "$TMP/tenancy" > "$TMP/tenancy.out"
grep -q 'Scope type      : TENANCY' "$TMP/tenancy.out"
grep -q 'Compartments    : 2' "$TMP/tenancy.out"

echo "PASS: CM08-01 exact-scope safety, component reconciliation, dispositions and monthly review"
