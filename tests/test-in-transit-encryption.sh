#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/success" "$TMP/denied"
ln -s "$ROOT/tests/mock-oci-task2" "$TMP/bin/oci"

PATH="$TMP/bin:$PATH" bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test \
  -r us-langley-1 \
  -o "$TMP/success" >/dev/null

evidence="$(find "$TMP/success" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
coverage="$(find "$TMP/success" -name 'oci_intransit_encryption_coverage_*.csv' -print -quit)"

[ -n "$evidence" ] && [ -n "$coverage" ]
[ ! -e "$(find "$TMP/success" -name '*_collection_errors_*' -print -quit)" ]
grep -q '"LoadBalancerFrontend","app-lb/https","YES","TLSv1.2"' "$evidence"
grep -q '"LoadBalancerBackend","app-lb/app-backends","YES","TLS"' "$evidence"
grep -q '"IPSecConnection","onprem-vpn","CONFIGURED","IKE/IPSec"' "$evidence"
grep -q '"IPSecTunnel","onprem-vpn/tunnel-1","YES","IKE-V2"' "$evidence"
grep -q '"IPSecTunnel","onprem-vpn/tunnel-1".*"OK","SC-8(1)","OK",""' "$evidence"
grep -q '"DRGAttachment","ipsec-attachment","n/a","IPSEC_TUNNEL"' "$evidence"
grep -q '"IPSecTunnel","1","OK",""' "$coverage"
grep -q '"LoadBalancerFrontend","1","OK",""' "$coverage"

set +e
PATH="$TMP/bin:$PATH" MOCK_DENY_TUNNEL=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test \
  -r us-langley-1 \
  -s ipsec \
  -o "$TMP/denied" >/dev/null 2>&1
rc=$?
set -e

[ "$rc" -eq 3 ]
evidence="$(find "$TMP/denied" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
coverage="$(find "$TMP/denied" -name 'oci_intransit_encryption_coverage_*.csv' -print -quit)"
errors="$(find "$TMP/denied" -name 'oci_intransit_encryption_collection_errors_*.csv' -print -quit)"

[ -n "$evidence" ] && [ -n "$coverage" ] && [ -n "$errors" ]
grep -q '"IPSecTunnel","onprem-vpn/<tunnels>","UNKNOWN","UNKNOWN","UNKNOWN","COLLECTION-FAILED","SC-8(1)","DENIED"' "$evidence"
grep -q '"IPSecTunnel","UNKNOWN","DENIED"' "$coverage"
grep -q '"DENIED".*IPSec tunnel list' "$errors"
if grep -Eq 'TUNNEL-DOWN|NO-IPSEC|NO-VPN' "$evidence"; then
  echo "FAIL: denied tunnel collection fabricated a negative VPN finding" >&2
  exit 1
fi

echo "PASS: Task 2 success and denied-IPSec regressions"

