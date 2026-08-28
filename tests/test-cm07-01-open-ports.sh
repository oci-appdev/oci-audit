#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/inventory" "$TMP/audit" "$TMP/missing-inputs" \
  "$TMP/denied" "$TMP/bad-shape" "$TMP/interactive" "$TMP/tenancy" \
  "$TMP/refuse" "$TMP/mismatch" "$TMP/formula"
ln -s "$ROOT/tests/mock-oci-task6" "$TMP/bin/oci"

SCRIPT="$ROOT/cm07-01-open-ports-protocols-services.sh"
TENANCY='ocid1.tenancy.oc1..task6'
COMP='ocid1.compartment.oc1..vcn'

bash "$SCRIPT" --selfcheck | grep -q 'READ-ONLY SELF-CHECK: PASSED'

# First pass: inventory-only produces a review template without claiming that
# approvals or the restricted list were evaluated.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/inventory" > "$TMP/inventory.out"

inventory_template="$(find "$TMP/inventory" -name 'cm07-01_approval_baseline_template_*.csv' -print -quit)"
inventory_sources="$(find "$TMP/inventory" -name 'cm07-01_input_sources_*.csv' -print -quit)"
[ -n "$inventory_template" ] && [ -n "$inventory_sources" ]
grep -q 'SKIPPED-INVENTORY-ONLY' "$inventory_sources"

python3 - "$inventory_template" "$TMP/approved.csv" <<'PY'
import csv
import sys

source, target = sys.argv[1:3]
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
            "approval_date": "2026-08-28",
            "expiration_date": "2027-08-28",
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
PY

printf '%s\n' \
  'entry_id,protocol,port_min,port_max,direction,category,service,function,authority,provided_by,source_reference,effective_date,expiration_date,notes' \
  'SSH-22,TCP,22,22,INGRESS,RESTRICTED,SSH,Administrative remote access,OCS PPSM Authority,ISSO,PPSM-CAL-OCS-2026,2026-01-01,2027-12-31,Bastion or approved admin CIDRs only' \
  > "$TMP/restricted.csv"

# Full evidence run: approved 443/1521 rows reconcile, SSH remains unapproved,
# and the authoritative restricted list identifies internet-wide SSH.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -d ingress \
  -a "$TMP/approved.csv" -x "$TMP/restricted.csv" \
  -o "$TMP/audit" > "$TMP/audit.out"

evidence="$(find "$TMP/audit" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
approval="$(find "$TMP/audit" -name 'cm07-01_approval_reconciliation_*.csv' -print -quit)"
restricted="$(find "$TMP/audit" -name 'cm07-01_restricted_findings_*.csv' -print -quit)"
sources="$(find "$TMP/audit" -name 'cm07-01_input_sources_*.csv' -print -quit)"
coverage="$(find "$TMP/audit" -name 'cm07-01_coverage_*.csv' -print -quit)"
[ -n "$evidence" ] && [ -n "$approval" ] && [ -n "$restricted" ]
[ -n "$sources" ] && [ -n "$coverage" ]
! find "$TMP/audit" -name 'cm07-01_collection_errors_*.csv' -print -quit | grep -q .

python3 - "$evidence" "$approval" "$restricted" "$sources" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

inventory, approvals, restrictions, sources = map(rows, sys.argv[1:5])
live = [row for row in inventory if row["collection_status"] == "OK"]
assert len(live) == 3, live
by_port = {row["destination_port_min"]: row for row in live}
assert by_port["443"]["approval_status"] == "APPROVED", by_port["443"]
assert by_port["443"]["restricted_status"] == "NO-LIST-MATCH", by_port["443"]
assert by_port["1521"]["approval_status"] == "APPROVED", by_port["1521"]
assert by_port["22"]["approval_status"] == "UNAPPROVED-DRIFT", by_port["22"]
assert by_port["22"]["restricted_status"] == "RESTRICTED-MATCH", by_port["22"]
assert by_port["22"]["review_result"] == "RESTRICTED-PORT-OR-PROTOCOL", by_port["22"]
assert all(row["attachment_count"] == "1" for row in live), live
assert {row["reconciliation_status"] for row in approvals} >= {"APPROVED", "UNAPPROVED-DRIFT"}
assert len(restrictions) == 1, restrictions
assert restrictions[0]["entry_id"] == "SSH-22", restrictions
assert restrictions[0]["severity"] == "HIGH", restrictions
source_by_type = {row["input_type"]: row for row in sources}
assert source_by_type["APPROVAL-BASELINE"]["provided_by"] == "PPSM Approver"
assert source_by_type["RESTRICTED-LIST"]["provided_by"] == "ISSO"
assert source_by_type["RESTRICTED-LIST"]["sha256"]
PY

grep -q '"SecurityListRule".*"1","OK"' "$coverage"
grep -q '"NSGRule".*"2","OK"' "$coverage"
[ "$(stat -c '%a' "$evidence")" = "600" ]

# Without authoritative inputs the scan still preserves the inventory but exits
# 3 and labels the evidence package incomplete.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -d ingress \
  -o "$TMP/missing-inputs" > "$TMP/missing-inputs.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'no approval baseline supplied' "$TMP/missing-inputs.out"
grep -q 'no authoritative restricted list supplied' "$TMP/missing-inputs.out"
missing_sources="$(find "$TMP/missing-inputs" -name 'cm07-01_input_sources_*.csv' -print -quit)"
grep -q 'NOT-PROVIDED' "$missing_sources"

# A denied NSG-rule call is not converted into zero rules. It produces a failed
# coverage row, a failed inventory row, a retained error ledger and exit 3.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK6_DENY_NSG_RULES=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -d ingress --inventory-only \
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
  -c "$COMP" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/bad-shape" > "$TMP/bad-shape.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
bad_errors="$(find "$TMP/bad-shape" -name 'cm07-01_collection_errors_*.csv' -print -quit)"
grep -q 'unexpected data shape' "$bad_errors"

# OCI-controlled names cannot become spreadsheet formulas.
PATH="$TMP/bin:$PATH" MOCK_TASK6_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -d ingress --inventory-only \
  -o "$TMP/formula" >/dev/null
formula_inventory="$(find "$TMP/formula" -name 'cm07-01_open_pps_inventory_*.csv' -print -quit)"
grep -q "'=2+3" "$formula_inventory"

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
