#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/success" "$TMP/rotation" "$TMP/denied"
ln -s "$ROOT/tests/mock-oci-task3" "$TMP/bin/oci"

COMPARTMENT='ocid1.compartment.oc1..test'

PATH="$TMP/bin:$PATH" bash "$ROOT/sc28-oci-encryption-at-rest.sh" \
  -c "$COMPARTMENT" -r us-langley-1 -o "$TMP/success" \
  --non-interactive --confirm-scope-ocid "$COMPARTMENT" --approve-scan YES \
  > "$TMP/success.out"

evidence="$(find "$TMP/success" -name 'oci_atrest_encryption_*.csv' ! -name '*coverage*' ! -name '*collection_errors*' -print -quit)"
coverage="$(find "$TMP/success" -name 'oci_atrest_encryption_coverage_*.csv' -print -quit)"
[ -n "$evidence" ]
[ -n "$coverage" ]
if find "$TMP/success" -name '*collection_errors*' | grep -q .; then
  echo "FAIL: clean SC-28 run retained an error ledger" >&2
  exit 1
fi

python3 - "$evidence" "$coverage" <<'PY'
import csv
import sys

evidence_path, coverage_path = sys.argv[1:]
with open(evidence_path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
with open(coverage_path, newline="", encoding="utf-8") as handle:
    coverage = list(csv.DictReader(handle))

def one(service, resource):
    matches = [row for row in rows if row["service"] == service and row["resource"] == resource]
    assert len(matches) == 1, (service, resource, matches)
    return matches[0]

volume = one("BlockVolume", "data-volume")
assert volume["key_management"] == "CUSTOMER-MANAGED"
assert volume["finding"] == "OK-CMK"

boot = one("BootVolume", "boot-volume")
assert boot["key_management"] == "ORACLE-MANAGED"
assert boot["finding"] == "REVIEW-USE-CMK"

mysql = one("MySQL", "mysql1")
assert mysql["key_management"] == "CUSTOMER-MANAGED"
assert mysql["key_ocid_or_detail"] == "ocid1.key.oc1..data"

# Autonomous Database key custody must come from the full current model, not
# from kms-key-id alone. An external-provider or key-store database is
# customer-managed even though it has no kms-key-id.
adb_cmk = one("AutonomousDB", "ADB1")
assert adb_cmk["key_management"] == "CUSTOMER-MANAGED"
assert adb_cmk["finding"] == "OK-CMK"
assert "ocid1.keyversion.oc1..v2" in adb_cmk["key_ocid_or_detail"]

adb_external = one("AutonomousDB", "ADB-EXTERNAL")
assert adb_external["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", adb_external
assert adb_external["finding"] == "MANUAL-VERIFY-EXTERNAL-KEY-CUSTODY"
assert "encryption-key-provider=AWS" in adb_external["key_ocid_or_detail"]

adb_okv = one("AutonomousDB", "ADB-OKV")
assert adb_okv["key_management"] == "CUSTOMER-MANAGED-EXTERNAL", adb_okv
assert "ocid1.keystore.oc1..okv1" in adb_okv["key_ocid_or_detail"]

adb_oracle = one("AutonomousDB", "ADB-ORACLE")
assert adb_oracle["key_management"] == "ORACLE-MANAGED"
assert adb_oracle["finding"] == "REVIEW-USE-CMK"

# A response that establishes no custody either way must not be recorded as
# Oracle-managed, which would be a fabricated negative CMK finding.
adb_silent = one("AutonomousDB", "ADB-SILENT")
assert adb_silent["key_management"] == "UNKNOWN", adb_silent
assert adb_silent["finding"] == "MANUAL-VERIFY-KEY-CUSTODY"

postgres = one("PostgreSQL", "postgres1")
assert postgres["key_management"] == "PLATFORM-MANAGED"
assert postgres["finding"] == "MANUAL-VERIFY-KEY-CUSTODY"
assert "data-key-id-not-exposed" in postgres["key_ocid_or_detail"]

key = one("KMS-Key", "ocs-data-key")
assert key["key_management"] == "HSM"
assert key["key_lifecycle"] == "ENABLED"
assert key["finding"] == "OK-HSM-AUTO-ROTATION"
assert "interval-days=90" in key["key_rotation"]
assert "schedule-start=2026-03-01T00:00:00Z" in key["key_rotation"]
assert "versions=2" in key["key_rotation"]
assert "auto-rotated-versions=1" in key["key_rotation"]
assert "latest-version-state=ENABLED" in key["key_rotation"]
assert "latest-version-created=2026-06-01T00:00:00Z" in key["key_rotation"]

expected = {"BlockVolume", "BootVolume", "ObjectStorage", "FSS", "AutonomousDB", "BaseDB", "MySQL", "PostgreSQL", "Vault", "KMS-Key"}
actual = {row["service"] for row in coverage}
assert expected == actual, (expected - actual, actual - expected)
assert all(row["collection_status"] == "OK" for row in coverage)
PY

grep -q 'RESULT   : COMPLETE' "$TMP/success.out"

MOCK_ROTATION_FAILED=1 PATH="$TMP/bin:$PATH" \
  bash "$ROOT/sc28-oci-encryption-at-rest.sh" -c "$COMPARTMENT" \
    -r us-langley-1 -s vault -o "$TMP/rotation" \
    --non-interactive --confirm-scope-ocid "$COMPARTMENT" --approve-scan YES \
    > "$TMP/rotation.out"
rotation_evidence="$(find "$TMP/rotation" -name 'oci_atrest_encryption_*.csv' ! -name '*coverage*' ! -name '*collection_errors*' -print -quit)"
grep -q 'AUTO-ROTATION-FAILED' "$rotation_evidence"
grep -q 'RESULT   : COMPLETE' "$TMP/rotation.out"

set +e
MOCK_DENY_KEY_LIST=1 PATH="$TMP/bin:$PATH" \
  bash "$ROOT/sc28-oci-encryption-at-rest.sh" -c "$COMPARTMENT" \
    -r us-langley-1 -s vault -o "$TMP/denied" \
    --non-interactive --confirm-scope-ocid "$COMPARTMENT" --approve-scan YES \
    > "$TMP/denied.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]

denied_evidence="$(find "$TMP/denied" -name 'oci_atrest_encryption_*.csv' ! -name '*coverage*' ! -name '*collection_errors*' -print -quit)"
denied_coverage="$(find "$TMP/denied" -name 'oci_atrest_encryption_coverage_*.csv' -print -quit)"
denied_errors="$(find "$TMP/denied" -name 'oci_atrest_encryption_collection_errors_*.csv' -print -quit)"

[ -n "$denied_errors" ]
grep -q '"KMS-Key","<collection:ocs-vault>".*"COLLECTION-FAILED".*"DENIED"' "$denied_evidence"
grep -q '"KMS-Key","0","DENIED"' "$denied_coverage"
grep -q '"DENIED".*list KMS keys in ocs-vault' "$denied_errors"
grep -q 'RESULT   : INCOMPLETE' "$TMP/denied.out"
if grep -q 'NO-KEYS' "$denied_evidence"; then
  echo "FAIL: denied KMS collection was reported as no keys" >&2
  exit 1
fi

echo "PASS: SC-28 data-store, KMS rotation and failure-ledger evidence"
