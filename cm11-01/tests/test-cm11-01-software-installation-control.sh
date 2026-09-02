#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/inventory" "$TMP/audit" "$TMP/missing" \
  "$TMP/denied" "$TMP/bad-shape" "$TMP/formula" "$TMP/manual" \
  "$TMP/refuse" "$TMP/mismatch" "$TMP/interactive" "$TMP/tenancy" \
  "$TMP/domain-gap" "$TMP/automation-refuse"
mkdir -p "$TMP/unmanaged"
ln -s "$ROOT/cm11-01/tests/mock-oci-task7" "$TMP/bin/oci"

SCRIPT="$ROOT/cm11-01/cm11-01-software-installation-control.sh"
TENANCY='ocid1.tenancy.oc1..task7'
COMP='ocid1.compartment.oc1..app'
AUTOMATION=(
  --non-interactive
  --confirm-scope-ocid "$COMP"
  --approve-scan YES
)

bash "$SCRIPT" --selfcheck | grep -q 'READ-ONLY SELF-CHECK: PASSED'

# Inventory-only creates live inventory and templates without claiming the
# organizational authorization, approval or restriction sources were present.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -p TASK7 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/inventory" > "$TMP/inventory.out"

installer_template="$(find "$TMP/inventory" -name 'cm11-01_authorized_installer_template_*.csv' -print -quit)"
approved_template="$(find "$TMP/inventory" -name 'cm11-01_approved_software_template_*.csv' -print -quit)"
inventory_sources="$(find "$TMP/inventory" -name 'cm11-01_input_sources_*.csv' -print -quit)"
[ -n "$installer_template" ] && [ -n "$approved_template" ] && [ -n "$inventory_sources" ]
grep -q 'SKIPPED-INVENTORY-ONLY' "$inventory_sources"
grep -q 'OCI IAM policies from 2 target/ancestor attachment compartment' "$TMP/inventory.out"
grep -q 'OCI CLI profile: TASK7' "$TMP/inventory.out"

python3 - "$installer_template" "$TMP/authorized.csv" "$approved_template" "$TMP/approved.csv" "$TMP/restricted.csv" <<'PY'
import csv
import sys
from datetime import date, timedelta

installer_source, installer_target, software_source, software_target, restricted_target = sys.argv[1:6]
today = date.today().isoformat()
next_year = (date.today() + timedelta(days=365)).isoformat()

with open(installer_source, newline="", encoding="utf-8-sig") as handle:
    installers = list(csv.DictReader(handle))
installer_fields = list(installers[0].keys())
for index, row in enumerate(installers, start=1):
    row.update(
        {
            "authorization_status": "AUTHORIZED",
            "approval_id": f"IAM-AUTH-{index:03d}",
            "approval_authority": "OCS System Owner",
            "approved_by": "OCS ISSO",
            "approval_date": today,
            "expiration_date": next_year,
            "manager": "Cloud Operations Manager",
            "technical_control": "OCI IAM group and least-privilege policy",
            "request_process": "Remedy access request plus manager and system-owner approval",
            "source_reference": "OCS-AUTHORIZED-INSTALLERS-2026",
        }
    )
with open(installer_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=installer_fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(installers)
assert len(installers) == 6, installers

with open(software_source, newline="", encoding="utf-8-sig") as handle:
    software = list(csv.DictReader(handle))
software_fields = list(software[0].keys())
for index, row in enumerate(software, start=1):
    row.update(
        {
            "approval_status": "APPROVED",
            "approval_id": f"SW-APPROVAL-{index:03d}",
            "approval_authority": "OCS Configuration Control Board",
            "approved_by": "OCS System Owner",
            "approval_date": today,
            "expiration_date": next_year,
            "business_function": "Approved OCS platform/application component",
            "justification": "Required by the approved system design",
            "source_reference": "OCS-APPROVED-SOFTWARE-2026",
        }
    )
with open(software_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=software_fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerows(software)
assert len(software) == 4, software

restricted_fields = "entry_id software_type name_pattern version_pattern architecture_pattern repository_or_publisher_pattern scope_pattern category authority provided_by source_reference effective_date expiration_date restriction notes".split()
restricted = {
    "entry_id": "PROHIBITED-TELNET",
    "software_type": "OS_PACKAGE",
    "name_pattern": "telnet",
    "version_pattern": "*",
    "architecture_pattern": "*",
    "repository_or_publisher_pattern": "*",
    "scope_pattern": "*",
    "category": "PROHIBITED",
    "authority": "OCS Information Security Policy",
    "provided_by": "OCS ISSO",
    "source_reference": "OCS-RESTRICTED-SOFTWARE-2026",
    "effective_date": (date.today() - timedelta(days=30)).isoformat(),
    "expiration_date": next_year,
    "restriction": "Telnet clients and servers are prohibited; use SSH",
    "notes": "Test fixture",
}
with open(restricted_target, "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=restricted_fields, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    writer.writerow(restricted)
PY

# Full evidence run reconciles all three authoritative lists. A prohibited
# entry remains a finding even if it also appears on the approved baseline.
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" \
  -u "$TMP/authorized.csv" -a "$TMP/approved.csv" -x "$TMP/restricted.csv" \
  -o "$TMP/audit" > "$TMP/audit.out"

software="$(find "$TMP/audit" -name 'cm11-01_software_inventory_*.csv' -print -quit)"
entitlements="$(find "$TMP/audit" -name 'cm11-01_installer_entitlements_*.csv' -print -quit)"
reconciliation="$(find "$TMP/audit" -name 'cm11-01_software_reconciliation_*.csv' -print -quit)"
restrictions="$(find "$TMP/audit" -name 'cm11-01_restricted_findings_*.csv' -print -quit)"
controls="$(find "$TMP/audit" -name 'cm11-01_technical_controls_*.csv' -print -quit)"
policies="$(find "$TMP/audit" -name 'cm11-01_iam_policy_statements_*.csv' -print -quit)"
sources="$(find "$TMP/audit" -name 'cm11-01_input_sources_*.csv' -print -quit)"
coverage="$(find "$TMP/audit" -name 'cm11-01_coverage_*.csv' -print -quit)"
[ -n "$software" ] && [ -n "$entitlements" ] && [ -n "$reconciliation" ]
[ -n "$restrictions" ] && [ -n "$controls" ] && [ -n "$policies" ]
[ -n "$sources" ] && [ -n "$coverage" ]
! find "$TMP/audit" -name 'cm11-01_collection_errors_*.csv' -print -quit | grep -q .

python3 - "$software" "$entitlements" "$reconciliation" "$restrictions" "$controls" "$policies" "$sources" <<'PY'
import csv
import sys

def rows(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

software, entitlements, reconciliation, restrictions, controls, policies, sources = map(rows, sys.argv[1:8])
assert len(software) == 4, software
assert {row["software_type"] for row in software} == {"OS_PACKAGE", "COMPUTE_BOOT_IMAGE", "CONTAINER_IMAGE"}
assert len(entitlements) == 6, entitlements
assert all(row["authorization_status"] == "AUTHORIZED" for row in entitlements), entitlements
assert {row["install_capability"] for row in entitlements} == {
    "OS_PACKAGE_INSTALL", "COMPUTE_SOFTWARE_PROVISION", "CONTAINER_IMAGE_PUBLISH"
}
assert all(row["analysis_confidence"] == "CANDIDATE-NOT-EFFECTIVE-PERMISSION" for row in entitlements)
assert len(reconciliation) == 4, reconciliation
# The installed-package software source comes from the softwareSources list in
# the current OSMH model. It must carry the real source name and OCID, not the
# package type.
telnet_pkg = next(row for row in software if row["software_name"] == "telnet")
assert telnet_pkg["repository_or_publisher"] == "ol9_appstream", telnet_pkg
assert telnet_pkg["source_or_image_id"] == "ocid1.ossoftwaresource.oc1..appstream", telnet_pkg
assert telnet_pkg["repository_or_publisher"] != "RPM", telnet_pkg

telnet = next(row for row in reconciliation if row["software_name"] == "telnet")
assert telnet["approval_status"] == "APPROVED", telnet
assert telnet["restriction_status"] == "PROHIBITED-MATCH", telnet
assert telnet["review_result"] == "PROHIBITED-SOFTWARE", telnet
assert len(restrictions) == 1 and restrictions[0]["severity"] == "CRITICAL", restrictions
coverage_control = next(row for row in controls if row["control_type"] == "OSMH-INVENTORY-COVERAGE")
assert coverage_control["control_status"] == "VERIFIED", coverage_control
assert any(row["evidence_source"] == "ORACLE-DOCUMENTATION-BUILTIN" for row in policies), policies
by_type = {row["input_type"]: row for row in sources}
assert by_type["AUTHORIZED-INSTALLERS"]["sha256"]
assert by_type["APPROVED-SOFTWARE"]["authority"] == "OCS Configuration Control Board"
assert by_type["RESTRICTED-SOFTWARE"]["provided_by"] == "OCS ISSO"
PY

grep -q '"OSMHInstalledPackage".*"2","OK"' "$coverage"
grep -q '"ContainerImage".*"1","OK"' "$coverage"
[ "$(stat -c '%a' "$software")" = "600" ]

# Missing authoritative inputs preserve inventory but make the evidence set
# incomplete outside explicit inventory-only mode.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" -o "$TMP/missing" \
  > "$TMP/missing.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
grep -q 'no authorized installer list supplied' "$TMP/missing.out"
grep -q 'no approved software/resource list supplied' "$TMP/missing.out"
grep -q 'no authoritative restricted software/resource list supplied' "$TMP/missing.out"

# A package-inventory denial is retained as a failed software row, failed
# coverage, error ledger and exit 3; it cannot become an empty package list.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK7_DENY_PACKAGES=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/denied" > "$TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
denied_software="$(find "$TMP/denied" -name 'cm11-01_software_inventory_*.csv' -print -quit)"
denied_coverage="$(find "$TMP/denied" -name 'cm11-01_coverage_*.csv' -print -quit)"
denied_errors="$(find "$TMP/denied" -name 'cm11-01_collection_errors_*.csv' -print -quit)"
grep -q '"OS_PACKAGE","UNKNOWN".*"DENIED"' "$denied_software"
grep -q '"OSMHInstalledPackage".*"UNKNOWN","DENIED"' "$denied_coverage"
grep -q '"DENIED".*OSMH installed packages' "$denied_errors"

# Successful CLI exit with an unexpected list shape is incomplete.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK7_BAD_COMPUTE_SHAPE=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/bad-shape" > "$TMP/bad-shape.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
bad_errors="$(find "$TMP/bad-shape" -name 'cm11-01_collection_errors_*.csv' -print -quit)"
grep -q 'unexpected data shape' "$bad_errors"

# OCI-controlled names cannot become spreadsheet formulas.
PATH="$TMP/bin:$PATH" MOCK_TASK7_FORMULA_NAME=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/formula" >/dev/null
formula_software="$(find "$TMP/formula" -name 'cm11-01_software_inventory_*.csv' -print -quit)"
grep -q "'=2+3" "$formula_software"

# Supplying -c manually still requires the exact OCID twice and uppercase YES.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
    --inventory-only -o "$TMP/manual" > "$TMP/manual.out"
grep -q 'All resolved target OCIDs were confirmed twice.' "$TMP/manual.out"
grep -q 'CM-11 SOFTWARE CONTROL PRE-SCAN SAFETY SUMMARY' "$TMP/manual.out"

# Refusal reaches no policy, identity or workload collector and leaves no CSV.
set +e
printf '%s\n%s\n%s\n' "$COMP" "$COMP" no | \
  PATH="$TMP/bin:$PATH" MOCK_TASK7_LOG="$TMP/refuse.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 --inventory-only \
    -o "$TMP/refuse" > "$TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -qE 'iam policy|iam group|iam dynamic-group|iam domain|compute instance|os-management-hub|artifacts' "$TMP/refuse.log"
! find "$TMP/refuse" -name '*.csv' -print -quit | grep -q .

# A mismatched second OCID stops before the safety summary/collector boundary.
set +e
printf '%s\n%s\n' "$COMP" 'ocid1.compartment.oc1..wrong' | \
  PATH="$TMP/bin:$PATH" MOCK_TASK7_LOG="$TMP/mismatch.log" \
  bash "$SCRIPT" -c "$COMP" -r us-langley-1 --inventory-only \
    -o "$TMP/mismatch" > "$TMP/mismatch.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -qE 'iam policy|iam group|iam dynamic-group|iam domain|compute instance|os-management-hub|artifacts' "$TMP/mismatch.log"
! find "$TMP/mismatch" -name '*.csv' -print -quit | grep -q .

# Default no-scope execution discovers and double-confirms a compartment.
printf '%s\n%s\n%s\n' "$COMP" "$COMP" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 --inventory-only \
    -o "$TMP/interactive" > "$TMP/interactive.out"
grep -q 'Selected scope type : COMPARTMENT' "$TMP/interactive.out"
grep -q 'Confirmed OCID  : ocid1.compartment.oc1..app' "$TMP/interactive.out"

# A tenancy OCID is accepted by interactive selection and expands to root plus
# every active discovered child compartment before the final YES gate.
printf '%s\n%s\n%s\n' "$TENANCY" "$TENANCY" YES | \
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 --inventory-only \
    -o "$TMP/tenancy" > "$TMP/tenancy.out"
grep -q 'Scope type      : TENANCY' "$TMP/tenancy.out"
grep -q 'Compartments    : 2' "$TMP/tenancy.out"
grep -q 'WARNING: this selection scans the tenancy root and every active child compartment' "$TMP/tenancy.out"

# Automation fails closed without the exact resolved OCID/YES authorization.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK7_LOG="$TMP/automation-refuse.log" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 --non-interactive --approve-scan yes \
  --inventory-only -o "$TMP/automation-refuse" > "$TMP/automation-refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
! grep -qE 'iam policy|iam group|iam dynamic-group|iam domain|compute instance|os-management-hub|artifacts' "$TMP/automation-refuse.log"

# A referenced identity-domain group cannot be silently represented as a known
# user list. The candidate entitlement is retained and the run exits 3.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK7_IDENTITY_DOMAIN=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" \
  -u "$TMP/authorized.csv" -a "$TMP/approved.csv" -x "$TMP/restricted.csv" \
  -o "$TMP/domain-gap" > "$TMP/domain-gap.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
domain_entitlements="$(find "$TMP/domain-gap" -name 'cm11-01_installer_entitlements_*.csv' -print -quit)"
grep -q 'IDENTITY-DOMAIN-MEMBERSHIP-NOT-COLLECTED' "$domain_entitlements"
grep -q 'Unresolved identity boundaries    : 1' "$TMP/domain-gap.out"

# A Compute host without an exact OSMH managed-instance match is an explicit
# package-inventory gap and cannot produce a collection-complete exit.
set +e
PATH="$TMP/bin:$PATH" MOCK_TASK7_NO_OSMH=1 bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 "${AUTOMATION[@]}" --inventory-only \
  -o "$TMP/unmanaged" > "$TMP/unmanaged.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
unmanaged_controls="$(find "$TMP/unmanaged" -name 'cm11-01_technical_controls_*.csv' -print -quit)"
grep -q '"OSMH-INVENTORY-COVERAGE".*"NOT-VERIFIED"' "$unmanaged_controls"
grep -q 'Compute hosts not OSMH-verified   : 1' "$TMP/unmanaged.out"

# Region is mandatory provenance and mixed scope modes fail before OCI access.
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" --inventory-only >/dev/null 2>&1
no_region_rc=$?
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -i -c "$COMP" -r us-langley-1 --inventory-only >/dev/null 2>&1
mixed_rc=$?
set -e
[ "$no_region_rc" -eq 1 ]
[ "$mixed_rc" -eq 1 ]

echo "PASS: CM11-01 software installation control safety and reconciliation regression"
