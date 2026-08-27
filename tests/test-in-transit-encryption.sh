#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/success" "$TMP/single-tunnel" "$TMP/denied" \
  "$TMP/bad-shape" "$TMP/formula" "$TMP/backend-verify" "$TMP/missing-volume-field"
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
grep -q '"IPSecTunnel","onprem-vpn/tunnel-2","YES","IKE-V2"' "$evidence"
grep -q '"IPSecTunnel","onprem-vpn/tunnel-2".*"OK","SC-8(1)","OK",""' "$evidence"
grep -q '"DRGAttachment","ipsec-attachment","n/a","IPSEC_TUNNEL"' "$evidence"
grep -q '"IPSecTunnel","2","OK",""' "$coverage"
grep -q '"LoadBalancerFrontend","1","OK",""' "$coverage"
if grep -q 'IPSEC-TUNNEL-PAIR-INCOMPLETE' "$evidence"; then
  echo "FAIL: complete two-tunnel connection was marked incomplete" >&2
  exit 1
fi

# OCI Site-to-Site VPN creates two tunnels per connection. A successful list
# that returns only one is a configuration finding, not a collection failure.
PATH="$TMP/bin:$PATH" MOCK_SINGLE_TUNNEL=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test \
  -r us-langley-1 \
  -s ipsec \
  -o "$TMP/single-tunnel" >/dev/null

single_evidence="$(find "$TMP/single-tunnel" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
single_coverage="$(find "$TMP/single-tunnel" -name 'oci_intransit_encryption_coverage_*.csv' -print -quit)"
[ -n "$single_evidence" ] && [ -n "$single_coverage" ]
grep -q '"IPSecTunnel","onprem-vpn/<tunnel-pair>","UNKNOWN","IKE/IPSec","expected-tunnels=2;discovered-tunnels=1","IPSEC-TUNNEL-PAIR-INCOMPLETE"' "$single_evidence"
grep -q '"IPSecTunnel","1","OK",""' "$single_coverage"

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

# A successful CLI process with an unexpected JSON shape is incomplete, not a
# verified zero-resource result.
set +e
PATH="$TMP/bin:$PATH" MOCK_BAD_SHAPE_LB=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -s lb \
  -o "$TMP/bad-shape" > "$TMP/bad-shape.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 3 ]
bad_evidence="$(find "$TMP/bad-shape" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
bad_coverage="$(find "$TMP/bad-shape" -name 'oci_intransit_encryption_coverage_*.csv' -print -quit)"
bad_errors="$(find "$TMP/bad-shape" -name 'oci_intransit_encryption_collection_errors_*.csv' -print -quit)"
grep -q '"LoadBalancerFrontend","<collection>".*"COLLECTION-FAILED".*"ERROR"' "$bad_evidence"
grep -q '"LoadBalancerFrontend","UNKNOWN","ERROR"' "$bad_coverage"
grep -q 'unexpected data shape' "$bad_errors"

# OCI-controlled names are neutralized before CSV output so opening evidence
# in a spreadsheet cannot execute a leading formula character.
PATH="$TMP/bin:$PATH" MOCK_FORMULA_NAME=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -s lb \
  -o "$TMP/formula" >/dev/null
formula_evidence="$(find "$TMP/formula" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
grep -q '"'"'"'=2+3/https"' "$formula_evidence"
[ "$(stat -c '%a' "$formula_evidence")" = "600" ]

# Backend TLS without peer verification is a review finding, not an OK row.
PATH="$TMP/bin:$PATH" MOCK_BACKEND_VERIFY_FALSE=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -s lb \
  -o "$TMP/backend-verify" >/dev/null
verify_evidence="$(find "$TMP/backend-verify" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
grep -q 'verify-peer-certificate=false","REVIEW-BACKEND-CERT-VERIFY-DISABLED"' "$verify_evidence"

# Missing volume encryption fields remain UNKNOWN and require review; absence
# must not be converted into a false DISABLED assertion.
PATH="$TMP/bin:$PATH" MOCK_VOLUME_FIELD_MISSING=1 bash "$ROOT/in-transit-encryption.sh" \
  -c ocid1.compartment.oc1..test -r us-langley-1 -s volumes \
  -o "$TMP/missing-volume-field" >/dev/null
missing_evidence="$(find "$TMP/missing-volume-field" -name 'oci_intransit_encryption_*.csv' \
  ! -name '*_coverage_*' ! -name '*_collection_errors_*' -print -quit)"
grep -q '"BlockVolumeAttach".*"unknown".*"REVIEW-IN-TRANSIT-ENC-NOT-EXPOSED"' "$missing_evidence"
grep -q '"InstanceBootVol".*"unknown".*"REVIEW-BOOT-IN-TRANSIT-ENC-NOT-EXPOSED"' "$missing_evidence"
if grep -Eq 'IN-TRANSIT-ENC-DISABLED|BOOT-IN-TRANSIT-ENC-DISABLED' "$missing_evidence"; then
  echo "FAIL: missing volume field was reported as disabled" >&2
  exit 1
fi

echo "PASS: Task 2 integrity, TLS/IPSec findings and evidence-file safety regressions"
