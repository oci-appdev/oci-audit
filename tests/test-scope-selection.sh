#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/cp01" "$TMP/cp02" "$TMP/mismatch"
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

# Interactive selection cannot be mixed with non-interactive scope flags.
set +e
PATH="$TMP/bin:$PATH" bash "$ROOT/cp09-02-backup-access-files-check.sh" \
  --select-scope -c "$COMPARTMENT" -s '' -o "$TMP/conflict" > "$TMP/conflict.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'cannot be combined with -c or -n' "$TMP/conflict.out"

echo "PASS: CP-9 interactive scope discovery and OCID confirmation"

