#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
ln -s "$ROOT/tests/mock-oci-scope" "$TMP/bin/oci"

python3 - "$ROOT/sc08-02-in-transit-encryption.sh" <<'PY'
import re
import shlex
import sys
from pathlib import Path

path = Path(sys.argv[1])
physical = path.read_text(encoding="utf-8").splitlines()
logical = []
buffer = ""
for line in physical:
    stripped = line.rstrip()
    if stripped.endswith("\\"):
        buffer += stripped[:-1] + " "
    else:
        logical.append(buffer + line)
        buffer = ""
if buffer:
    logical.append(buffer)

allowed_actions = {"list", "get"}
mutating = {
    "create", "update", "delete", "change", "move", "restore", "enable",
    "disable", "rotate", "assign", "attach", "detach", "terminate",
    "reboot", "import", "export", "upload", "bulk-upload", "bulk-delete",
    "reset", "activate", "deactivate", "cancel",
}
calls = []
errors = []
for number, line in enumerate(logical, 1):
    if not re.match(r"^\s*oci_capture\s+", line):
        continue
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError as exc:
        errors.append(f"line {number}: cannot parse OCI wrapper call: {exc}")
        continue
    if len(tokens) < 5:
        errors.append(f"line {number}: incomplete OCI wrapper call: {line.strip()}")
        continue
    command_path = []
    for token in tokens[2:]:  # skip oci_capture and its human-readable label
        if token.startswith("-"):
            break
        command_path.append(token)
    if not command_path:
        errors.append(f"line {number}: OCI command path is empty")
        continue
    action = command_path[-1]
    if action not in allowed_actions:
        errors.append(f"line {number}: action is not list/get: {' '.join(command_path)}")
    if mutating.intersection(command_path):
        errors.append(f"line {number}: mutating token found: {' '.join(command_path)}")
    if command_path == ["network", "ip-sec-psk", "get"]:
        errors.append(f"line {number}: IPSec pre-shared-key retrieval is prohibited")
    calls.append((number, command_path))

if len(calls) < 20:
    errors.append(f"expected at least 20 OCI calls, parsed only {len(calls)}")
if "raw-request" in path.read_text(encoding="utf-8"):
    # The source forms this deny-list word in two pieces. A literal occurrence
    # would therefore be an executable/raw source addition.
    errors.append("literal raw-request token found")

if errors:
    raise SystemExit("\n".join(errors))
print(f"Verified {len(calls)} SC-8 OCI wrapper calls: list/get only; no PSK retrieval")
PY

# The source-level self-check must fail if a future edit introduces either a
# mutating OCI call or the read-only-but-secret ip-sec-psk get operation.
for fixture in mutation secret; do
  mkdir -p "$TMP/$fixture/lib"
  cp "$ROOT/sc08-02-in-transit-encryption.sh" "$TMP/$fixture/sc08-02-in-transit-encryption.sh"
  cp "$ROOT/lib/oci-scope-selector.sh" "$TMP/$fixture/lib/oci-scope-selector.sh"
done

sed -i '0,/iam compartment list/s//iam compartment delete/' "$TMP/mutation/sc08-02-in-transit-encryption.sh"
set +e
bash "$TMP/mutation/sc08-02-in-transit-encryption.sh" --selfcheck > "$TMP/mutation.out" 2>&1
mutation_rc=$?
set -e
[ "$mutation_rc" -eq 1 ]
grep -q 'SELF-CHECK: FAILED' "$TMP/mutation.out"

sed -i '0,/iam compartment list/s//network ip-sec-psk get/' "$TMP/secret/sc08-02-in-transit-encryption.sh"
set +e
bash "$TMP/secret/sc08-02-in-transit-encryption.sh" --selfcheck > "$TMP/secret.out" 2>&1
secret_rc=$?
set -e
[ "$secret_rc" -eq 1 ]
grep -q 'SELF-CHECK: FAILED' "$TMP/secret.out"

# Invalid selectors fail before the first OCI call.
set +e
PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/unknown-service.log" \
  bash "$ROOT/sc08-02-in-transit-encryption.sh" -c ocid1.compartment.oc1..vcn \
    -s 'ipsec destroy' -o "$TMP/unknown-service" > "$TMP/unknown-service.out" 2>&1
unknown_rc=$?
set -e
[ "$unknown_rc" -eq 1 ]
grep -q 'unknown service selector: destroy' "$TMP/unknown-service.out"
[ ! -s "$TMP/unknown-service.log" ]

set +e
PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/tenancy-c.log" \
  bash "$ROOT/sc08-02-in-transit-encryption.sh" -c ocid1.tenancy.oc1..scope \
    -s ipsec -o "$TMP/tenancy-c" > "$TMP/tenancy-c.out" 2>&1
tenancy_c_rc=$?
set -e
[ "$tenancy_c_rc" -eq 1 ]
grep -q -- '-c requires a compartment OCID' "$TMP/tenancy-c.out"
[ ! -s "$TMP/tenancy-c.log" ]

# A syntactically valid but unresolvable explicit compartment stops after the
# validation lookup and never reaches a service endpoint.
set +e
PATH="$TMP/bin:$PATH" MOCK_SCOPE_LOG="$TMP/bad-compartment.log" \
  bash "$ROOT/sc08-02-in-transit-encryption.sh" -c ocid1.compartment.oc1..vcn \
    -s ipsec -o "$TMP/bad-compartment" > "$TMP/bad-compartment.out" 2>&1
bad_compartment_rc=$?
set -e
[ "$bad_compartment_rc" -eq 1 ]
grep -q 'SCAN NOT STARTED: explicit compartment validation failed' "$TMP/bad-compartment.out"
grep -q '^iam compartment get ' "$TMP/bad-compartment.log"
if grep -Eq '^(network cpe|network ip-sec|network drg-attachment)' "$TMP/bad-compartment.log"; then
  echo "FAIL: invalid explicit compartment reached an SC-8 service endpoint" >&2
  exit 1
fi

echo "PASS: SC-8 static OCI action, mutation, secret and pre-scan validation gates"
