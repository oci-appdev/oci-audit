#!/usr/bin/env bash
#
# Strict scope-automation contract regression for the Task 1-3 collectors.
#
# These five scripts previously treated -c/-n as an approved automation path:
# they ran with no OCID confirmation and no approval value. This proves the
# retrofit required by SCRIPT-DESIGN-STANDARD.md:
#
#   - a manual -c run cannot silently become non-interactive;
#   - a mismatched manual confirmation stops before any workload call;
#   - automation fails closed on a missing, wrong or miscounted
#     --confirm-scope-ocid and on any --approve-scan value other than YES;
#   - the automation options are rejected without --non-interactive;
#   - a complete, correct automation invocation still collects.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
ln -s "$ROOT/cp09-01/tests/mock-oci-cp0901" "$TMP/bin/oci"

COMP='ocid1.compartment.oc1..test'
OTHER='ocid1.compartment.oc1..other'
SCRIPT="$ROOT/cp09-01/cp09-01-backup-type-config-frequency.sh"

run() {  # run <label> <expected-rc> -- args...
  local label="$1" want="$2"; shift 3
  local out="$TMP/${label}.out" rc
  set +e
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 -s volumes \
    -o "$TMP/$label" "$@" < /dev/null > "$out" 2>&1
  rc=$?
  set -e
  if [ "$rc" -ne "$want" ]; then
    echo "FAIL: $label expected rc $want, got $rc" >&2
    tail -20 "$out" >&2
    exit 1
  fi
  printf '%s' "$out"
}

# 1. A manual -c run must not proceed on its own. With no operator on stdin the
#    confirmation read fails and the collector stops before any service call.
out="$(run manual-c 1 -- -c "$COMP")"
grep -q 'Resolved command-line scope requires interactive OCID confirmation' "$out"
grep -q 'SCAN NOT STARTED' "$out"

# 2. A manual -c run that confirms the OCID twice but then refuses the plan
#    stops before the first service call.
set +e
printf '%s\n%s\nno\n' "$COMP" "$COMP" | PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -r us-langley-1 -s volumes -o "$TMP/refuse" -c "$COMP" > "$TMP/refuse.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'Type exact uppercase YES' "$TMP/refuse.out"
grep -q 'SCAN NOT STARTED' "$TMP/refuse.out"

# 3. A mismatched second OCID stops the run.
set +e
printf '%s\n%s\n' "$COMP" "$OTHER" | PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -r us-langley-1 -s volumes -o "$TMP/mismatch" -c "$COMP" > "$TMP/mismatch.out" 2>&1
rc=$?
set -e
[ "$rc" -eq 1 ]
grep -q 'scope confirmation did not match' "$TMP/mismatch.out"

# 4. Automation fails closed: no confirmation, wrong confirmation, too many
#    confirmations, wrong approval value, missing approval value.
out="$(run auto-noconfirm 1 -- -c "$COMP" --non-interactive --approve-scan YES)"
grep -q 'expected 1' "$out"

out="$(run auto-wrongconfirm 1 -- -c "$COMP" --non-interactive \
        --confirm-scope-ocid "$OTHER" --approve-scan YES)"
grep -q 'did not match resolved OCID' "$out"

out="$(run auto-toomany 1 -- -c "$COMP" --non-interactive \
        --confirm-scope-ocid "$COMP" --confirm-scope-ocid "$COMP" --approve-scan YES)"
grep -q 'expected 1' "$out"

for bad in yes Yes YES_PLEASE y ''; do
  set +e
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -r us-langley-1 -s volumes \
    -o "$TMP/auto-badapprove" -c "$COMP" --non-interactive \
    --confirm-scope-ocid "$COMP" --approve-scan "$bad" \
    < /dev/null > "$TMP/auto-badapprove.out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 1 ] || { echo "FAIL: --approve-scan '$bad' was accepted" >&2; exit 1; }
done

out="$(run auto-noapprove 1 -- -c "$COMP" --non-interactive --confirm-scope-ocid "$COMP")"
grep -q 'exact --approve-scan YES' "$out"

# 5. The automation options require --non-interactive.
out="$(run needs-ni 1 -- -c "$COMP" --confirm-scope-ocid "$COMP" --approve-scan YES)"
grep -q 'require --non-interactive' "$out"

# 6. --non-interactive requires an explicit scope and cannot be combined with -i.
out="$(run ni-noscope 1 -- --non-interactive --approve-scan YES)"
grep -q 'requires an explicit -c or -n scope' "$out"

out="$(run ni-with-i 1 -- -i --non-interactive -c "$COMP" --approve-scan YES)"
grep -qE 'cannot be combined with' "$out"

# 7. A complete, correct automation invocation still collects.
out="$(run auto-ok 0 -- -c "$COMP" --non-interactive \
        --confirm-scope-ocid "$COMP" --approve-scan YES)"
grep -q 'AUTOMATION APPROVED' "$out"
config="$(find "$TMP/auto-ok" -name 'cp09-01_backup_config_config_*.csv' -print -quit)"
[ -n "$config" ]
grep -q 'worm-volume' "$config"

# 8. Every retrofitted collector exposes the same contract and no longer
#    advertises -c/-n as an approved bypass.
for s in cp09-01/cp09-01-backup-type-config-frequency.sh \
         cp09-02/cp09-02-backup-access-files-check.sh \
         cp09-03/cp09-03-backup-replication-check.sh \
         sc08-02/sc08-02-in-transit-encryption.sh \
         sc28/sc28-oci-encryption-at-rest.sh; do
  for opt in --non-interactive --confirm-scope-ocid --approve-scan; do
    grep -q -- "$opt" "$ROOT/$s" || { echo "FAIL: $s lacks $opt" >&2; exit 1; }
  done
  if grep -q 'approved non-interactive scope supplied with -c or -n' "$ROOT/$s"; then
    echo "FAIL: $s still advertises the -c/-n bypass" >&2
    exit 1
  fi
done

echo "PASS: Task 1-3 strict scope-automation contract and fail-closed gates"
