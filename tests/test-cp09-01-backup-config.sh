#!/usr/bin/env bash
#
# CP-9 backup configuration collection regression.
#
# Proves that the block-volume backup policy schedule parser records the
# immutability posture the current VolumeBackupSchedule model exposes
# (is-retention-lock-enabled / is-prevent-deletion-enabled) and that a policy
# expressing retention as retention-period is not reported as blank retention.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/out"
ln -s "$ROOT/tests/mock-oci-cp0901" "$TMP/bin/oci"

COMPARTMENT='ocid1.compartment.oc1..test'

PATH="$TMP/bin:$PATH" bash "$ROOT/cp09-01-backup-type-config-frequency.sh" \
  -c "$COMPARTMENT" -r us-langley-1 -s volumes -o "$TMP/out" \
  --non-interactive --confirm-scope-ocid "$COMPARTMENT" --approve-scan YES \
  > "$TMP/run.out" 2>&1

config="$(find "$TMP/out" -name 'cp09-01_backup_config_config_*.csv' -print -quit)"
coverage="$(find "$TMP/out" -name 'cp09-01_backup_config_coverage_*.csv' -print -quit)"
[ -n "$config" ]
[ -n "$coverage" ]

python3 - "$config" "$coverage" <<'PY'
import csv
import sys

config_path, coverage_path = sys.argv[1:]
with open(config_path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
with open(coverage_path, newline="", encoding="utf-8") as handle:
    coverage = list(csv.DictReader(handle))

def one(name):
    matches = [row for row in rows if row["resource_name"] == name]
    assert len(matches) == 1, (name, matches)
    return matches[0]

# A retention-locked schedule is the WORM evidence CP-9 needs; it must be
# visible in the retention cell, not silently dropped.
worm = one("worm-volume")
assert worm["backup_configured"] == "YES", worm
assert worm["policy_name"] == "gold-worm", worm
assert worm["backup_type"] == "INCREMENTAL", worm
assert "30d (2592000s)" in worm["retention"], worm
assert "retention-lock=true" in worm["retention"], worm
assert "prevent-deletion=true" in worm["retention"], worm
assert worm["last_backup_time"] == "2026-08-30T03:00:00Z", worm
assert worm["backup_count"] == "1", worm
assert worm["collection_status"] == "OK", worm

# A policy that expresses retention as retention-period must not produce an
# empty retention cell that reads as "no retention configured".
period = one("plain-volume")
assert "retention-period=P1Y" in period["retention"], period
assert "retention-lock=false" in period["retention"], period
assert period["backup_count"] == "0", period

assert len(coverage) == 1, coverage
assert coverage[0]["service"] == "BlockVolume"
assert coverage[0]["assets_found"] == "2"
assert coverage[0]["collection_status"] == "OK"
PY

echo "PASS: CP-9 backup schedule retention, immutability and coverage evidence"
