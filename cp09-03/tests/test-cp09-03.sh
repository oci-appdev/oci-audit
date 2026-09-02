#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { [ -n "${TMP:-}" ] && [ -d "$TMP" ] && rm -rf -- "$TMP"; }
trap cleanup EXIT

mkdir -p "$TMP/bin" "$TMP/success" "$TMP/denied"
cp "$ROOT/tests/mock-oci" "$TMP/bin/oci"
chmod +x "$TMP/bin/oci"
PATH="$TMP/bin:$PATH"
export PATH

evidence_csv() {
  find "$1" -type f -name 'oci_backup_dr_[0-9]*.csv' -print -quit
}

coverage_csv() {
  find "$1" -type f -name 'oci_backup_dr_coverage_*.csv' -print -quit
}

assert_csv_row() {
  local file="$1" expression="$2"
  python3 - "$file" "$expression" <<'PY'
import csv
import sys

path, expression = sys.argv[1:]
rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
if not any(eval(expression, {"__builtins__": {}}, {"row": row}) for row in rows):
    raise SystemExit(f"assertion failed for {path}: {expression}\nrows={rows!r}")
PY
}

# Complete collection: the asset and coverage rows must both be OK.
bash "$ROOT/cp09-03/cp09-03-backup-replication-check.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -o "$TMP/success" \
  --non-interactive --confirm-scope-ocid ocid1.compartment.oc1..test --approve-scan YES \
  >"$TMP/success.stdout" 2>"$TMP/success.stderr"

SUCCESS_EVIDENCE="$(evidence_csv "$TMP/success")"
SUCCESS_COVERAGE="$(coverage_csv "$TMP/success")"
[ -n "$SUCCESS_EVIDENCE" ] && [ -n "$SUCCESS_COVERAGE" ]
assert_csv_row "$SUCCESS_EVIDENCE" \
  'row["service"] == "BlockVolume" and row["resource"] == "volume-a" and row["replicated"] == "YES" and row["collection_status"] == "OK"'
assert_csv_row "$SUCCESS_COVERAGE" \
  'row["service"] == "BlockVolume" and row["assets_found"] == "1" and row["collection_status"] == "OK"'
assert_csv_row "$SUCCESS_EVIDENCE" \
  'row["service"] == "ObjectStorage" and row["resource"] == "backup-bucket" and row["replicated"] == "YES" and row["immutable_worm"] == "LOCKED-WORM" and row["collection_status"] == "OK"'
assert_csv_row "$SUCCESS_EVIDENCE" \
  'row["service"] == "FSS" and row["resource"] == "fss-a" and row["replicated"] == "YES" and row["collection_status"] == "OK"'
assert_csv_row "$SUCCESS_EVIDENCE" \
  'row["service"] == "BaseDB" and row["resource"] == "DB1" and row["replicated"] == "YES" and row["collection_status"] == "OK"'
python3 - "$SUCCESS_EVIDENCE" "$SUCCESS_COVERAGE" <<'PY'
import csv
import sys

evidence = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8")))
coverage = list(csv.DictReader(open(sys.argv[2], newline="", encoding="utf-8")))
expected = {"ObjectStorage", "BlockVolume", "BootVolume", "VolumeBackup",
            "BootVolumeBackup", "FSS", "AutonomousDB", "BaseDB"}
assert {row["service"] for row in evidence} == expected, evidence
assert {row["service"] for row in coverage} == expected, coverage
assert all(row["collection_status"] == "OK" for row in evidence), evidence
assert all(row["collection_status"] == "OK" for row in coverage), coverage
PY
if find "$TMP/success" -type f -name '*collection_errors*' | grep -q .; then
  echo "clean run retained an error file" >&2
  exit 1
fi

# Denied replica collection: do not emit NO-REPLICA. Attribute DENIED to the
# asset row, mark coverage incomplete, retain the error ledger and exit 3.
set +e
MOCK_DENY_REPLICA=1 bash "$ROOT/cp09-03/cp09-03-backup-replication-check.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -s volumes -o "$TMP/denied" \
  --non-interactive --confirm-scope-ocid ocid1.compartment.oc1..test --approve-scan YES \
  >"$TMP/denied.stdout" 2>"$TMP/denied.stderr"
DENIED_RC=$?
set -e
[ "$DENIED_RC" -eq 3 ] || { echo "expected denied run rc=3, got $DENIED_RC" >&2; exit 1; }

DENIED_EVIDENCE="$(evidence_csv "$TMP/denied")"
DENIED_COVERAGE="$(coverage_csv "$TMP/denied")"
DENIED_ERRORS="$(find "$TMP/denied" -type f -name '*collection_errors*' -print -quit)"
[ -n "$DENIED_EVIDENCE" ] && [ -n "$DENIED_COVERAGE" ] && [ -n "$DENIED_ERRORS" ]
assert_csv_row "$DENIED_EVIDENCE" \
  'row["service"] == "BlockVolume" and row["replicated"] == "UNKNOWN" and row["finding"] == "COLLECTION-FAILED" and row["collection_status"] == "DENIED"'
assert_csv_row "$DENIED_COVERAGE" \
  'row["service"] == "BlockVolume" and row["assets_found"] == "1" and row["collection_status"] == "DENIED"'
assert_csv_row "$DENIED_ERRORS" 'row["status"] == "DENIED"'
if grep -q 'NO-VOLUME-REPLICA' "$DENIED_EVIDENCE"; then
  echo "denied collection was misreported as NO-VOLUME-REPLICA" >&2
  exit 1
fi

echo "PASS: cp09-03 success and denied-collection regressions"
