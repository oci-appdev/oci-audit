#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/cp01" "$TMP/cp02" "$TMP/cp03" "$TMP/sc08" \
  "$TMP/sc08-tenancy" "$TMP/sc28" "$TMP/sc28-tenancy" "$TMP/mismatch" \
  "$TMP/mismatch03" "$TMP/mismatch08" "$TMP/mismatch28"
ln -s "$ROOT/tests/mock-oci-scope" "$TMP/bin/oci"

TENANCY='ocid1.tenancy.oc1..scope'
COMPARTMENT='ocid1.compartment.oc1..vcn'

# Script 01: select one discovered compartment with the long option.
printf '%s\n%s\n' "$COMPARTMENT" "$COMPARTMENT" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/cp01.log" \
  bash "$ROOT/cp09-01-backup-type-config-frequency.sh" \
    --select-scope -r us-langley-1 -s '' -o "$TMP/cp01" > "$TMP/cp01.out"

grep -q 'DISCOVERED OCI AUDIT SCOPES' "$TMP/cp01.out"
grep -q 'Confirmed scope: COMPARTMENT — VCN' "$TMP/cp01.out"
grep -q "Confirmed OCID : $COMPARTMENT" "$TMP/cp01.out"
grep -q 'Scope  : 1 compartment(s)' "$TMP/cp01.out"
grep -q 'compartment-id-in-subtree true' "$TMP/cp01.log"

# Script 02: select the tenancy with the short option. This must explicitly
# mean root plus both active child compartments.
printf '%s\n%s\n' "$TENANCY" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/cp02.log" \
  bash "$ROOT/cp09-02-backup-access-files-check.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/cp02" > "$TMP/cp02.out"

grep -q 'WARNING: this selection scans the tenancy root and every active child compartment.' "$TMP/cp02.out"
grep -q 'Confirmed scope: TENANCY — OCS-Tenancy' "$TMP/cp02.out"
grep -q "Confirmed OCID : $TENANCY" "$TMP/cp02.out"
grep -q 'Scope  : 3 compartment(s)' "$TMP/cp02.out"

# Script 03: use the same shared selector and confirm a single compartment.
printf '%s\n%s\n' "$COMPARTMENT" "$COMPARTMENT" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/cp03.log" \
  bash "$ROOT/cp09-03-backup-replication-check.sh" \
    --select-scope -r us-langley-1 -s '' -o "$TMP/cp03" > "$TMP/cp03.out"

grep -q 'Confirmed scope: COMPARTMENT — VCN' "$TMP/cp03.out"
grep -q "Confirmed OCID : $COMPARTMENT" "$TMP/cp03.out"
grep -q 'Auditing DR posture (replication/retention/versioning) across 1 compartment(s)' "$TMP/cp03.out"
grep -q 'compartment-id-in-subtree true' "$TMP/cp03.log"

# SC-8: the encryption collector follows the same confirmed-scope boundary.
printf '%s\n%s\n' "$COMPARTMENT" "$COMPARTMENT" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/sc08.log" \
  bash "$ROOT/in-transit-encryption.sh" \
    --select-scope -r us-langley-1 -s '' -o "$TMP/sc08" > "$TMP/sc08.out"

grep -q 'Confirmed scope: COMPARTMENT — VCN' "$TMP/sc08.out"
grep -q "Confirmed OCID : $COMPARTMENT" "$TMP/sc08.out"
grep -q 'Collecting SC-8 evidence across 1 compartment(s)' "$TMP/sc08.out"
grep -q 'compartment-id-in-subtree true' "$TMP/sc08.log"

# SC-8 tenancy selection must expand to root plus both active children.
printf '%s\n%s\n' "$TENANCY" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/sc08-tenancy.log" \
  bash "$ROOT/in-transit-encryption.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/sc08-tenancy" > "$TMP/sc08-tenancy.out"

grep -q 'WARNING: this selection scans the tenancy root and every active child compartment.' "$TMP/sc08-tenancy.out"
grep -q 'Confirmed scope: TENANCY — OCS-Tenancy' "$TMP/sc08-tenancy.out"
grep -q "Confirmed OCID : $TENANCY" "$TMP/sc08-tenancy.out"
grep -q 'Collecting SC-8 evidence across 3 compartment(s)' "$TMP/sc08-tenancy.out"

# SC-28: encryption-at-rest collection uses the same confirmed-scope boundary.
printf '%s\n%s\n' "$COMPARTMENT" "$COMPARTMENT" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/sc28.log" \
  bash "$ROOT/sc28-oci-encryption-at-rest.sh" \
    --select-scope -r us-langley-1 -s '' -o "$TMP/sc28" > "$TMP/sc28.out"

grep -q 'Confirmed scope: COMPARTMENT — VCN' "$TMP/sc28.out"
grep -q "Confirmed OCID : $COMPARTMENT" "$TMP/sc28.out"
grep -q 'Collecting SC-28 evidence across 1 compartment(s)' "$TMP/sc28.out"
grep -q 'compartment-id-in-subtree true' "$TMP/sc28.log"

# SC-28 tenancy selection means root plus both active child compartments.
printf '%s\n%s\n' "$TENANCY" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/sc28-tenancy.log" \
  bash "$ROOT/sc28-oci-encryption-at-rest.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/sc28-tenancy" > "$TMP/sc28-tenancy.out"

grep -q 'WARNING: this selection scans the tenancy root and every active child compartment.' "$TMP/sc28-tenancy.out"
grep -q 'Confirmed scope: TENANCY — OCS-Tenancy' "$TMP/sc28-tenancy.out"
grep -q "Confirmed OCID : $TENANCY" "$TMP/sc28-tenancy.out"
grep -q 'Collecting SC-28 evidence across 3 compartment(s)' "$TMP/sc28-tenancy.out"

# A mismatched confirmation must stop before the collector loop.
set +e
printf '%s\n%s\n' "$COMPARTMENT" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" bash "$ROOT/cp09-01-backup-type-config-frequency.sh" \
    -i -s '' -o "$TMP/mismatch" > "$TMP/mismatch.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match. Nothing was scanned.' "$TMP/mismatch.out"
grep -q 'Scope selection aborted.' "$TMP/mismatch.out"
if grep -q '^\[[0-9]' "$TMP/mismatch.out"; then
  echo "FAIL: collector loop started after scope confirmation mismatch" >&2
  exit 1
fi

# Script 03 must also fail closed on a mismatched second OCID.
set +e
printf '%s\n%s\n' "$COMPARTMENT" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" bash "$ROOT/cp09-03-backup-replication-check.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/mismatch03" > "$TMP/mismatch03.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match. Nothing was scanned.' "$TMP/mismatch03.out"
grep -q 'Scope selection aborted.' "$TMP/mismatch03.out"
if grep -q 'Auditing DR posture' "$TMP/mismatch03.out" || grep -q '^\[[0-9]' "$TMP/mismatch03.out"; then
  echo "FAIL: script 03 collector loop started after scope confirmation mismatch" >&2
  exit 1
fi

# SC-8 must also fail closed before any encryption or IPSec collection begins.
set +e
printf '%s\n%s\n' "$COMPARTMENT" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" bash "$ROOT/in-transit-encryption.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/mismatch08" > "$TMP/mismatch08.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match. Nothing was scanned.' "$TMP/mismatch08.out"
grep -q 'Scope selection aborted.' "$TMP/mismatch08.out"
if grep -q 'Collecting SC-8 evidence' "$TMP/mismatch08.out" || grep -q '^\[[0-9]' "$TMP/mismatch08.out"; then
  echo "FAIL: SC-8 collector loop started after scope confirmation mismatch" >&2
  exit 1
fi

# SC-28 must fail closed before any encryption-at-rest collection begins.
set +e
printf '%s\n%s\n' "$COMPARTMENT" "$TENANCY" | \
  PATH="$TMP/bin:$PATH" bash "$ROOT/sc28-oci-encryption-at-rest.sh" \
    -i -r us-langley-1 -s '' -o "$TMP/mismatch28" > "$TMP/mismatch28.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match. Nothing was scanned.' "$TMP/mismatch28.out"
grep -q 'Scope selection aborted.' "$TMP/mismatch28.out"
if grep -q 'Collecting SC-28 evidence' "$TMP/mismatch28.out" || grep -q '^\[[0-9]' "$TMP/mismatch28.out"; then
  echo "FAIL: SC-28 collector loop started after scope confirmation mismatch" >&2
  exit 1
fi

# Interactive selection cannot be mixed with non-interactive scope flags.
set +e
PATH="$TMP/bin:$PATH" bash "$ROOT/cp09-02-backup-access-files-check.sh" \
  --select-scope -c "$COMPARTMENT" -s '' -o "$TMP/conflict" > "$TMP/conflict.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'cannot be combined with -c or -n' "$TMP/conflict.out"

set +e
PATH="$TMP/bin:$PATH" bash "$ROOT/in-transit-encryption.sh" \
  --select-scope -c "$COMPARTMENT" -s '' -o "$TMP/conflict08" > "$TMP/conflict08.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'cannot be combined with -c or -n' "$TMP/conflict08.out"

set +e
PATH="$TMP/bin:$PATH" bash "$ROOT/sc28-oci-encryption-at-rest.sh" \
  --select-scope -c "$COMPARTMENT" -s '' -o "$TMP/conflict28" > "$TMP/conflict28.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'cannot be combined with -c or -n' "$TMP/conflict28.out"

echo "PASS: CP-9, SC-8 and SC-28 interactive scope discovery and OCID confirmation"
