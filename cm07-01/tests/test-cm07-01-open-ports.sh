#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/inventory" "$TMP/audit" "$TMP/missing-inputs" \
  "$TMP/denied" "$TMP/bad-shape" "$TMP/interactive" "$TMP/tenancy" \
  "$TMP/refuse" "$TMP/mismatch" "$TMP/formula"
mkdir -p "$TMP/subnet-items" "$TMP/explicit" "$TMP/automation-refuse" \
  "$TMP/future-approval" "$TMP/reversed-dates" "$TMP/no-region" \
  "$TMP/service-incomplete"
ln -s "$ROOT/cm07-01/tests/mock-oci-task6" "$TMP/bin/oci"

SCRIPT="$ROOT/cm07-01/cm07-01-open-ports-protocols-services.sh"
TENANCY='ocid1.tenancy.oc1..task6'
COMP='ocid1.compartment.oc1..vcn'
AUTOMATION_ARGS=(
  --non-interactive
  --confirm-scope-ocid "$COMP"
  --approve-scan YES
)

bash "$SCRIPT" --selfcheck | grep -q 'READ-ONLY SELF-CHECK: PASSED'

# First pass: inventory-only produces a review template without claiming that
# approvals or the restricted list were evaluated.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/inventory" > "$TMP/inventory.out"

inventory_template="$(find "$TMP/inventory" -name 'cm07-01_approval_baseline_template_*.csv' -print -quit)"
service_template="$(find "$TMP/inventory" -name 'cm07-01_service_mapping_template_*.csv' -print -quit)"
inventory_sources="$(find "$TMP/inventory" -name 'cm07-01_input_sources_*.csv' -print -quit)"
[ -n "$inventory_template" ] && [ -n "$service_template" ] && [ -n "$inventory_sources" ]
grep -q 'SKIPPED-INVENTORY-ONLY' "$inventory_sources"

python3 - "$inventory_template" "$TMP/approved.csv" "$service_template" "$TMP/services.csv" <<'PY'
import csv
import sys
from datetime import date, timedelta

source, target, service_source, service_target = sys.argv[1:5]
today = date.today().isoformat()
next_year = (date.today() + timedelta(days=365)).isoformat()
with open(source, newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
fieldnames = list(rows[0].keys())
approved = []
for row in rows:
    if row["destination_port_min"] not in {"443", "1521"}:
        continue
    row.update(
        {
            "approval_status": "APPROVED",
            "approval_id": "CCB-2026-0042",
            "approval_authority": "OCS Change Control Board",
            "approved_by": "PPSM Approver",
            "approval_date": today,
            "expiration_date": next_year,
            "business_function": "Approved application connectivity",
            "justification": "Required by the authorized system design",
            "source_reference": "PPSM-CAL-OCS-2026",
        }
    )
    approved.append(row)
with open(target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(approved)
assert len(rows) == 3, rows
assert len(approved) == 2, approved

with open(service_source, newline="", encoding="utf-8-sig") as handle:
    service_rows = list(csv.DictReader(handle))
service_fields = list(service_rows[0].keys())
service_names = {"22": "SSH administration", "443": "HTTPS application", "1521": "Oracle database"}
for index, row in enumerate(service_rows, start=1):
    port = row["destination_port_min"]
    row.update(
        {
            "mapping_id": f"MAP-{index:03d}",
            "resource_ocid": f"ocid1.instance.oc1..task6{index}",
            "resource_type": "ComputeInstance",
            "resource_name": f"verified-host-{index}",
            "listener_status": "LISTENING",
            "listener_address": f"10.0.0.{10 + index}",
            "listener_port": port,
            "listener_protocol": row["protocol"],
            "service_name": service_names[port],
            "business_function": "Verified application function",
            "justification": "Required by the approved system design",
            "system_owner": "OCS System Owner",
            "verified_by": "Application Administrator",
            "verification_date": today,
            "evidence_reference": f"LISTENER-EVIDENCE-{index}",
            "source_reference": "SYSTEM-DESIGN-OCS-2026",
        }
    )
with open(service_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=service_fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(service_rows)
assert len(service_rows) == 3, service_rows
PY

python3 - "$TMP/restricted.csv" <<'PY'
import csv
import sys
from datetime import date, timedelta

fields = "entry_id protocol port_min port_max direction category service function authority provided_by source_reference effective_date expiration_date notes".split()
row = {
    "entry_id": "SSH-22",
    "protocol": "TCP",
    "port_min": "22",
    "port_max": "22",
    "direction": "INGRESS",
    "category": "RESTRICTED",
    "service": "SSH",
    "function": "Administrative remote access",
    "authority": "OCS PPSM Authority",
    "provided_by": "ISSO",
    "source_reference": "PPSM-CAL-OCS-2026",
    "effective_date": (date.today() - timedelta(days=30)).isoformat(),
    "expiration_date": (date.today() + timedelta(days=365)).isoformat(),
    "notes": "Bastion or approved admin CIDRs only",
}
with open(sys.argv[1], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerow(row)
PY

# Full evidence run: approved 443/1521 rows reconcile, SSH remains unapproved,
# and the authoritative restricted list identifies internet-wide SSH.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress \
  -a "$TMP/approved.csv" -x "$TMP/restricted.csv" -s "$TMP/services.csv" \
  -o "$TMP/audit" > "$TMP/audit.out"

evidence="$(find "$TMP/audit" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
approval="$(find "$TMP/audit" -name 'cm07-01_approval_reconciliation_*.csv' -print -quit)"
restricted="$(find "$TMP/audit" -name 'cm07-01_restricted_findings_*.csv' -print -quit)"
service_results="$(find "$TMP/audit" -name 'cm07-01_service_mapping_reconciliation_*.csv' -print -quit)"
sources="$(find "$TMP/audit" -name 'cm07-01_input_sources_*.csv' -print -quit)"
coverage="$(find "$TMP/audit" -name 'cm07-01_coverage_*.csv' -print -quit)"
[ -n "$evidence" ] && [ -n "$approval" ] && [ -n "$restricted" ] && [ -n "$service_results" ]
[ -n "$sources" ] && [ -n "$coverage" ]
! find "$TMP/audit" -name 'cm07-01_collection_errors_*.csv' -print -quit | grep -q .

python3 - "$evidence" "$approval" "$restricted" "$service_results" "$sources" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

inventory, approvals, restrictions, services, sources = map(rows, sys.argv[1:6])
live = [row for row in inventory if row["collection_status"] == "OK"]
assert len(live) == 3, live
by_port = {row["destination_port_min"]: row for row in live}
assert by_port["443"]["approval_status"] == "APPROVED", by_port["443"]
assert by_port["443"]["restricted_status"] == "NO-LIST-MATCH", by_port["443"]
assert by_port["1521"]["approval_status"] == "APPROVED", by_port["1521"]
assert by_port["22"]["approval_status"] == "UNAPPROVED-DRIFT", by_port["22"]
assert by_port["22"]["restricted_status"] == "RESTRICTED-MATCH", by_port["22"]
assert by_port["22"]["review_result"] == "RESTRICTED-PORT-OR-PROTOCOL", by_port["22"]
assert all(row["service_mapping_status"] == "SERVICE-VERIFIED" for row in live), live
assert {row["mapping_status"] for row in services} == {"SERVICE-VERIFIED"}, services
assert all(row["attachment_count"] == "1" for row in live), live
assert {row["reconciliation_status"] for row in approvals} >= {"APPROVED", "UNAPPROVED-DRIFT"}
assert len(restrictions) == 1, restrictions
assert restrictions[0]["entry_id"] == "SSH-22", restrictions
assert restrictions[0]["severity"] == "HIGH", restrictions
source_by_type = {row["input_type"]: row for row in sources}
assert source_by_type["APPROVAL-BASELINE"]["provided_by"] == "PPSM Approver"
assert source_by_type["RESTRICTED-LIST"]["provided_by"] == "ISSO"
assert source_by_type["RESTRICTED-LIST"]["sha256"]
assert source_by_type["SERVICE-MAPPING"]["authority"] == "OCS System Owner"
assert source_by_type["SERVICE-MAPPING"]["provided_by"] == "Application Administrator"
assert source_by_type["SERVICE-MAPPING"]["sha256"]
PY

grep -q '"SecurityListRule".*"1","OK"' "$coverage"
grep -q '"NSGRule".*"2","OK"' "$coverage"
[ "$(stat -c '%a' "$evidence")" = "600" ]

# Without authoritative inputs the scan still preserves the inventory but exits
# 3 and labels the evidence package incomplete.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress \
  -o "$TMP/missing-inputs" > "$TMP/missing-inputs.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'no approval baseline supplied' "$TMP/missing-inputs.out"
grep -q 'no authoritative restricted list supplied' "$TMP/missing-inputs.out"
grep -q 'no actual service/listener mapping supplied' "$TMP/missing-inputs.out"
missing_sources="$(find "$TMP/missing-inputs" -name 'cm07-01_input_sources_*.csv' -print -quit)"
grep -q 'NOT-PROVIDED' "$missing_sources"

# A denied NSG-rule call is not converted into zero rules. It produces a failed
# coverage row, a failed inventory row, a retained error ledger and exit 3.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK6_DENY_NSG_RULES=1 bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/denied" > "$TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
denied_inventory="$(find "$TMP/denied" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
denied_coverage="$(find "$TMP/denied" -name 'cm07-01_coverage_*.csv' -print -quit)"
denied_errors="$(find "$TMP/denied" -name 'cm07-01_collection_errors_*.csv' -print -quit)"
grep -q 'COLLECTION-FAILED' "$denied_inventory"
grep -q '"NSGRule".*"UNKNOWN","DENIED"' "$denied_coverage"
grep -q '"DENIED".*NSG rule list' "$denied_errors"

# Successful CLI exit with an invalid response shape is incomplete.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK6_BAD_VCN_SHAPE=1 bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/bad-shape" > "$TMP/bad-shape.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
bad_errors="$(find "$TMP/bad-shape" -name 'cm07-01_collection_errors_*.csv' -print -quit)"
grep -q 'unexpected data shape' "$bad_errors"

# OCI-controlled names cannot become spreadsheet formulas.
PATH="$TMP/bin:$PATH" MOCK_TASK6_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/formula" >/dev/null
formula_inventory="$(find "$TMP/formula" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
grep -q "'=2+3" "$formula_inventory"

# Both OCI CLI list shapes must preserve Security List-to-subnet associations.
PATH="$TMP/bin:$PATH" MOCK_TASK6_SUBNET_ITEMS=1 bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/subnet-items" >/dev/null
items_inventory="$(find "$TMP/subnet-items" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
python3 - "$items_inventory" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = [row for row in csv.DictReader(handle) if row["container_type"] == "SecurityList"]
assert rows and all(row["attachment_count"] == "1" for row in rows), rows
assert all("app-subnet" in row["applies_to"] for row in rows), rows
PY

# Supplying -c manually no longer bypasses authorization: the target OCID is
# entered twice and the plan still requires exact uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" 'YES' | \
  PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/explicit.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 -d ingress --inventory-only \
    -o "$TMP/explicit" > "$TMP/explicit.out"
grep -q 'All resolved target OCIDs were confirmed twice.' "$TMP/explicit.out"
grep -q 'Type exact uppercase YES to run this scan.' "$TMP/explicit.out"
grep -q '^network vcn list ' "$TMP/explicit.log"

# Automation requires explicit mode, every resolved OCID and exact YES. A bad
# approval value stops before every Networking call and publishes no CSV.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/automation-refuse.log" bash "$SCRIPT" \
  -c "$COMP" --non-interactive --confirm-scope-ocid "$COMP" \
  --approve-scan yes -r us-langley-1 --inventory-only \
  -o "$TMP/automation-refuse" > "$TMP/automation-refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'automation did not supply exact --approve-scan YES' "$TMP/automation-refuse.out"
! grep -q '^network ' "$TMP/automation-refuse.log"
! find "$TMP/automation-refuse" -name '*.csv' -print -quit | grep -q .

# Evidence cannot use an unknown implicit region.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" --inventory-only \
  -o "$TMP/no-region" > "$TMP/no-region.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'region is required' "$TMP/no-region.out"

# A future approval date or an expiration before approval is invalid evidence.
python3 - "$TMP/approved.csv" "$TMP/future.csv" "$TMP/reversed.csv" <<'PY'
import csv
import sys
from datetime import date, timedelta

with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
fields = list(rows[0].keys())
future = [dict(row) for row in rows]
future[0]["approval_date"] = (date.today() + timedelta(days=1)).isoformat()
reversed_rows = [dict(row) for row in rows]
reversed_rows[0]["approval_date"] = date.today().isoformat()
reversed_rows[0]["expiration_date"] = (date.today() - timedelta(days=1)).isoformat()
for path, payload in ((sys.argv[2], future), (sys.argv[3], reversed_rows)):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(payload)
PY

for date_case in future reversed; do
  input="$TMP/${date_case}.csv"
  output="$TMP/$([ "$date_case" = future ] && printf future-approval || printf reversed-dates)"
  set +e
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
    -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress \
    -a "$input" -x "$TMP/restricted.csv" -s "$TMP/services.csv" \
    -o "$output" > "$TMP/${date_case}.out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 3 ]
done
grep -q 'approval_date cannot be in the future' \
  "$(find "$TMP/future-approval" -name 'cm07-01_collection_errors_*.csv' -print -quit)"
grep -q 'expiration_date precedes approval_date' \
  "$(find "$TMP/reversed-dates" -name 'cm07-01_collection_errors_*.csv' -print -quit)"

# A supplied mapping that omits a live rule is explicit incomplete evidence.
python3 - "$TMP/services.csv" "$TMP/services-incomplete.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8-sig") as handle:
    rows = list(csv.DictReader(handle))
fields = list(rows[0].keys())
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(rows[:-1])
PY
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" "${AUTOMATION_ARGS[@]}" -r us-langley-1 -d ingress \
  -a "$TMP/approved.csv" -x "$TMP/restricted.csv" -s "$TMP/services-incomplete.csv" \
  -o "$TMP/service-incomplete" > "$TMP/service-incomplete.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'SERVICE-MAPPING-MISSING' \
  "$(find "$TMP/service-incomplete" -name 'cm07-01_service_mapping_reconciliation_*.csv' -print -quit)"

# Default/no-scope execution must discover scopes, require the selected OCID
# twice, print the plan and require exact uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" 'YES' | \
  PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/interactive.log" \
  bash "$SCRIPT" -r us-langley-1 -d ingress --inventory-only \
    -o "$TMP/interactive" > "$TMP/interactive.out"
grep -q 'DISCOVERED OCI AUDIT SCOPES' "$TMP/interactive.out"
grep -q 'Confirmed scope: COMPARTMENT — VCN' "$TMP/interactive.out"
grep -q "Confirmed OCID : $COMP" "$TMP/interactive.out"
grep -q 'CM-7 OPEN PPS PRE-SCAN SAFETY SUMMARY' "$TMP/interactive.out"
grep -q 'Type exact uppercase YES to run this scan.' "$TMP/interactive.out"
grep -q 'SCAN APPROVED: starting read-only service collection.' "$TMP/interactive.out"
grep -q '^network vcn list ' "$TMP/interactive.log"

# Selecting the tenancy expands to root plus every active child compartment.
printf '%s\n%s\n%s\n' "$TENANCY" "$TENANCY" 'YES' | \
  PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/tenancy.log" \
  bash "$SCRIPT" -i -r us-langley-1 -d ingress --inventory-only \
    -o "$TMP/tenancy" > "$TMP/tenancy.out"
grep -q 'Confirmed scope: TENANCY — OCS-Tenancy' "$TMP/tenancy.out"
grep -q 'Compartments    : 3' "$TMP/tenancy.out"
grep -q "network vcn list --compartment-id $TENANCY" "$TMP/tenancy.log"
grep -q 'network vcn list --compartment-id ocid1.compartment.oc1..shared' "$TMP/tenancy.log"

# A mismatched second OCID stops before every Networking call and leaves no CSV.
set +e
printf '%s\n%s\n' "$COMP" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/mismatch.log" \
  bash "$SCRIPT" -i -r us-langley-1 -d ingress --inventory-only \
    -o "$TMP/mismatch" > "$TMP/mismatch.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match. Nothing was scanned.' "$TMP/mismatch.out"
! grep -q '^network ' "$TMP/mismatch.log"
! find "$TMP/mismatch" -name '*.csv' -print -quit | grep -q .

# Lowercase yes also refuses the plan before every Networking call.
set +e
printf '%s\n%s\n%s\n' "$COMP" "$COMP" 'yes' | \
  PATH="$TMP/bin:$PATH" MOCK_TASK6_LOG="$TMP/refuse.log" \
  bash "$SCRIPT" -r us-langley-1 -d ingress --inventory-only \
    -o "$TMP/refuse" > "$TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'SCAN NOT STARTED: operator did not enter exact uppercase YES' "$TMP/refuse.out"
! grep -q '^network ' "$TMP/refuse.log"
! find "$TMP/refuse" -name '*.csv' -print -quit | grep -q .

# Interactive mode cannot be mixed with a non-interactive OCID.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  --select-scope -c "$COMP" --inventory-only \
  -o "$TMP/conflict" > "$TMP/conflict.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'cannot be combined with -c or -n' "$TMP/conflict.out"

echo "PASS: CM07-01 inventory, provenance, approval, restricted-list, failure and OCID gates"
