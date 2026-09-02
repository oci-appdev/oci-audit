#!/usr/bin/env bash
#
# CM07-01 corrective-action acceptance regression.
#
# Covers the gate in CM07-CORRECTIVE-REVIEW.md:
#   - a Security List in a compartment other than the VCN's is inventoried, and
#     an unresolvable reference fails closed instead of vanishing;
#   - subnet associations that a partial scope cannot prove are UNKNOWN, never
#     "unattached";
#   - an ICMP rule does not match a narrow TCP/UDP/ANY port restriction;
#   - exact rule identity is distinguished from container-recreated semantic
#     identity;
#   - a named profile reaches every OCI call.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
ln -s "$ROOT/cm07-01/tests/mock-oci-task6" "$TMP/bin/oci"

COMP='ocid1.compartment.oc1..vcn'
SHARED='ocid1.compartment.oc1..shared'
XSL='ocid1.securitylist.oc1..crosscomp'
SCRIPT="$ROOT/cm07-01/cm07-01-open-ports-protocols-services.sh"

run() {  # run <outdir> [extra args...]
  local out="$1"; shift
  mkdir -p "$TMP/$out"
  PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
    -o "$TMP/$out" --non-interactive --confirm-scope-ocid "$COMP" \
    --approve-scan YES "$@" > "$TMP/$out.log" 2>&1
}

pick() { find "$TMP/$1" -name "$2" -print -quit; }

# ---------------------------------------------------------------------------
# 1. Cross-compartment Security List is resolved and attributed to its owner.
# ---------------------------------------------------------------------------
run inv --inventory-only
inventory="$(pick inv 'cm07-01_open_pps_inventory_*.csv')"
coverage="$(pick inv 'cm07-01_coverage_*.csv')"
summary="$(pick inv 'cm07-01_scan_summary_*.csv')"
[ -n "$inventory" ] && [ -n "$coverage" ] && [ -n "$summary" ]

python3 - "$inventory" "$coverage" "$summary" "$SHARED" "$XSL" <<'PY'
import csv, sys
inv_p, cov_p, sum_p, shared, xsl = sys.argv[1:6]
rows = list(csv.DictReader(open(inv_p, newline="", encoding="utf-8-sig")))
cov = list(csv.DictReader(open(cov_p, newline="", encoding="utf-8-sig")))
summary = {r["metric"]: r["value"] for r in csv.DictReader(open(sum_p, newline="", encoding="utf-8-sig"))}

# The RDP rule lives on a Security List in another compartment, attached to an
# in-scope subnet. Listing per compartment alone would miss it entirely.
xrules = [r for r in rows if r["container_id"] == xsl]
assert len(xrules) == 1, xrules
assert xrules[0]["destination_port_min"] == "3389", xrules[0]
assert xrules[0]["compartment_id"] == shared, xrules[0]
assert xrules[0]["container_type"] == "SecurityList(cross-compartment)", xrules[0]
assert xrules[0]["collection_status"] == "OK", xrules[0]
assert {c["service"] for c in cov} & {"CrossCompartmentSecurityList"}, cov

# The published scan summary carries scope provenance, not just counts.
for key in ("collector", "region", "oci_cli_profile", "scope_type", "scope_ocid",
            "scope_covers_tenancy", "subnet_association_completeness", "rules"):
    assert key in summary, (key, summary)
assert summary["scope_covers_tenancy"] == "NO", summary
assert "PARTIAL SCOPE" in summary["subnet_association_completeness"], summary

# Both identity keys are published and differ (they must, since the semantic
# key drops container_id).
sample = next(r for r in rows if r["collection_status"] == "OK")
assert len(sample["rule_key"]) == 64, sample
assert len(sample["semantic_rule_key"]) == 64, sample
assert sample["rule_key"] != sample["semantic_rule_key"], sample
# peer_type is emitted alongside the legacy source_type name.
assert sample["peer_type"] == sample["source_type"], sample
PY

# ---------------------------------------------------------------------------
# 2. An unresolvable cross-compartment reference fails closed.
# ---------------------------------------------------------------------------
set +e
MOCK_TASK6_DENY_XSL=1 run denied --inventory-only
denied_rc=$?
set -e
[ "$denied_rc" -eq 3 ]
denied_cov="$(pick denied 'cm07-01_coverage_*.csv')"
denied_err="$(pick denied 'cm07-01_collection_errors_*.csv')"
grep -q 'UNRESOLVED-SECURITY-LIST' "$denied_cov"
[ -n "$denied_err" ]
denied_inv="$(pick denied 'cm07-01_open_pps_inventory_*.csv')"
if grep -q '3389' "$denied_inv"; then
  echo "FAIL: denied cross-compartment list still produced rule rows" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. ICMP must not match a narrow port restriction.
# ---------------------------------------------------------------------------
cat > "$TMP/restricted.csv" <<'CSV'
entry_id,protocol,port_min,port_max,icmp_type,icmp_code,direction,category,service,function,authority,provided_by,source_reference,effective_date,expiration_date,notes
R1,ANY,3389,3389,,,INGRESS,PROHIBITED,RDP,remote desktop,PPSM,ISSO,PPSM-2026-01,2026-01-01,,
R2,TCP,443,443,,,INGRESS,RESTRICTED,HTTPS,web,PPSM,ISSO,PPSM-2026-01,2026-01-01,,
CSV
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  -o "$TMP/restrictrun" -x "$TMP/restricted.csv" --non-interactive \
  --confirm-scope-ocid "$COMP" --approve-scan YES > "$TMP/restrictrun.log" 2>&1
set -e
restricted_out="$(pick restrictrun 'cm07-01_restricted_findings_*.csv')"
restricted_inv="$(pick restrictrun 'cm07-01_open_pps_inventory_*.csv')"
[ -n "$restricted_out" ] && [ -n "$restricted_inv" ]

python3 - "$restricted_out" "$restricted_inv" <<'PY'
import csv, sys
findings = list(csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8-sig")))
inv = list(csv.DictReader(open(sys.argv[2], newline="", encoding="utf-8-sig")))

# R1 is protocol ANY but scoped to port 3389. A portless protocol cannot match
# it. Before the fix rule_port_range() returned 0-65535 for ICMP, so the ICMP
# rule matched R1 and was reported PROHIBITED.
icmp = [r for r in inv if r["protocol"] == "ICMP"]
assert len(icmp) == 1, icmp
assert icmp[0]["restricted_status"] not in {"PROHIBITED-MATCH", "RESTRICTED-MATCH"}, icmp[0]
assert not [f for f in findings if f["protocol"] == "ICMP"], findings

# The genuine TCP/3389 rule on the cross-compartment list must still match R1,
# so the fix narrows the match without suppressing real findings.
rdp = [f for f in findings if f["destination_port_min"] == "3389"]
assert len(rdp) == 1, findings
assert rdp[0]["entry_id"] == "R1", rdp[0]
assert rdp[0]["category"] == "PROHIBITED", rdp[0]

# The TCP/443 rule must still match the TCP-scoped R2 entry.
assert any(f["destination_port_min"] == "443" and f["entry_id"] == "R2" for f in findings), findings
PY

# A portless protocol with a port-scoped entry is rejected at input validation.
cat > "$TMP/bad-restricted.csv" <<'CSV'
entry_id,protocol,port_min,port_max,icmp_type,icmp_code,direction,category,service,function,authority,provided_by,source_reference,effective_date,expiration_date,notes
B1,ICMP,3389,3389,,,INGRESS,PROHIBITED,bad,bad,PPSM,ISSO,REF,2026-01-01,,
CSV
set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  -o "$TMP/badrestrict" -x "$TMP/bad-restricted.csv" --non-interactive \
  --confirm-scope-ocid "$COMP" --approve-scan YES > "$TMP/badrestrict.log" 2>&1
bad_rc=$?
set -e
[ "$bad_rc" -eq 3 ]
# Input-validation failures are recorded in the retained error ledger, which is
# the auditable record, rather than only on the operator console.
bad_err="$(pick badrestrict 'cm07-01_collection_errors_*.csv')"
[ -n "$bad_err" ]
grep -q 'no transport ports' "$bad_err"

# ---------------------------------------------------------------------------
# 4. A named profile reaches every OCI call.
# ---------------------------------------------------------------------------
mkdir -p "$TMP/profile"
MOCK_TASK6_PROFILE_LOG="$TMP/profile.log" PATH="$TMP/bin:$PATH" bash "$SCRIPT" \
  -c "$COMP" -r us-langley-1 -p DOJ-GOV-PROFILE -o "$TMP/profile" \
  --inventory-only --non-interactive --confirm-scope-ocid "$COMP" \
  --approve-scan YES > "$TMP/profile.out" 2>&1

[ -s "$TMP/profile.log" ]
if awk -F'\t' '$1 != "DOJ-GOV-PROFILE"' "$TMP/profile.log" | grep -q .; then
  echo "FAIL: some OCI calls did not receive the named profile:" >&2
  awk -F'\t' '$1 != "DOJ-GOV-PROFILE"' "$TMP/profile.log" >&2
  exit 1
fi
grep -q 'DOJ-GOV-PROFILE' "$TMP/profile.out"
profile_summary="$(pick profile 'cm07-01_scan_summary_*.csv')"
grep -q 'DOJ-GOV-PROFILE' "$profile_summary"

# Static proof: the only oci invocation threads both region and profile.
if ! grep -qE 'oci "\$\{REGION_ARG\[@\]\}" "\$\{PROFILE_ARG\[@\]\}"' "$SCRIPT"; then
  echo "FAIL: the OCI wrapper does not thread PROFILE_ARG" >&2
  exit 1
fi
if [ "$(grep -cE '^\s*out="\$\(oci ' "$SCRIPT")" -ne 1 ]; then
  echo "FAIL: more than one oci invocation site; profile threading is unproven" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# 5. A recreated container is distinguishable from genuine permission drift.
# ---------------------------------------------------------------------------
# Build an approval baseline from the live inventory, then rewrite container_id
# so the strict key no longer matches while the semantic key still does. This
# is what a deleted-and-recreated Security List looks like.
python3 - "$inventory" "$TMP/baseline-recreated.csv" "$TMP/baseline-drift.csv" <<'PY'
import csv, sys
src, recreated_path, drift_path = sys.argv[1:4]
rows = [r for r in csv.DictReader(open(src, newline="", encoding="utf-8-sig"))
        if r["collection_status"] == "OK"]
fields = ["compartment_id", "vcn_id", "container_id", "direction", "stateless",
          "protocol", "source_type", "source_or_dest", "source_port_min",
          "source_port_max", "destination_port_min", "destination_port_max",
          "icmp_type", "icmp_code", "approval_status", "approval_id",
          "approval_authority", "approved_by", "approval_date",
          "expiration_date", "business_function", "justification",
          "source_reference"]

def baseline(rows, mutate_container):
    out = []
    for index, row in enumerate(rows, start=1):
        entry = {f: row.get(f, "") for f in fields}
        if mutate_container:
            entry["container_id"] = entry["container_id"] + "-recreated"
        entry.update({
            "approval_status": "APPROVED",
            "approval_id": f"CCB-{index}",
            "approval_authority": "CCB",
            "approved_by": "reviewer",
            "approval_date": "2026-01-01",
            "expiration_date": "2027-01-01",
            "business_function": "audit",
            "justification": "approved for the audit baseline",
            "source_reference": "CCB-2026",
        })
        out.append(entry)
    return out

for path, mutate in ((recreated_path, True), (drift_path, False)):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(baseline(rows, mutate))
PY

set +e
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  -o "$TMP/recreated" -a "$TMP/baseline-recreated.csv" --non-interactive \
  --confirm-scope-ocid "$COMP" --approve-scan YES > "$TMP/recreated.log" 2>&1
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  -o "$TMP/exact" -a "$TMP/baseline-drift.csv" --non-interactive \
  --confirm-scope-ocid "$COMP" --approve-scan YES > "$TMP/exact.log" 2>&1
set -e

python3 - "$(pick recreated 'cm07-01_open_pps_inventory_*.csv')" \
         "$(pick exact 'cm07-01_open_pps_inventory_*.csv')" <<'PY'
import csv, sys
recreated = [r for r in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8-sig"))
             if r["collection_status"] == "OK"]
exact = [r for r in csv.DictReader(open(sys.argv[2], newline="", encoding="utf-8-sig"))
         if r["collection_status"] == "OK"]

# The identical baseline under the real container OCIDs approves cleanly.
assert exact, exact
assert all(r["approval_status"] == "APPROVED" for r in exact), \
    [r["approval_status"] for r in exact]

# The same rules under a different container OCID are neither silently approved
# nor indistinguishable from new unapproved permission.
assert recreated, recreated
statuses = {r["approval_status"] for r in recreated}
assert statuses == {"APPROVED-CONTAINER-RECREATED"}, statuses
assert "UNAPPROVED-DRIFT" not in statuses, statuses
PY

# The recreated case must not be counted as approved.
recreated_summary="$(pick recreated 'cm07-01_scan_summary_*.csv')"
python3 - "$recreated_summary" <<'PY'
import csv, sys
summary = {r["metric"]: r["value"] for r in csv.DictReader(open(sys.argv[1], newline="", encoding="utf-8-sig"))}
assert summary["approved"] == "0", summary
assert int(summary["container_recreated"]) > 0, summary
assert summary["unapproved"] == summary["rules"], summary
PY

# ---------------------------------------------------------------------------
# 6. The retired CM-7 reference scripts refuse to run.
# ---------------------------------------------------------------------------
# They suppress OCI stderr, so a denied call would be recorded as "no rules
# found". A comment header does not stop an operator running one.
for legacy in cm07-openports.sh cm07-ppsm.sh cm07-proof-opened-ports.sh; do
  set +e
  out="$(bash "$ROOT/$legacy" 2>&1)"
  rc=$?
  set -e
  [ "$rc" -eq 2 ] || { echo "FAIL: $legacy did not refuse to run (rc=$rc)" >&2; exit 1; }
  printf '%s' "$out" | grep -q 'retired CM-7 reference script' \
    || { echo "FAIL: $legacy did not explain the refusal" >&2; exit 1; }
done

# The shipped templates must match what the collector generates, or an operator
# fills in a schema the reconciler will not accept.
mkdir -p "$TMP/tmpl"
PATH="$TMP/bin:$PATH" bash "$SCRIPT" -c "$COMP" -r us-langley-1 \
  -o "$TMP/tmpl" --inventory-only --non-interactive \
  --confirm-scope-ocid "$COMP" --approve-scan YES > "$TMP/tmpl.log" 2>&1
for pair in "cm07-01_approval_baseline_template_*.csv:templates/cm07-01-approval-baseline-template.csv" \
            "cm07-01_service_mapping_template_*.csv:templates/cm07-01-service-mapping-template.csv"; do
  gen="$(find "$TMP/tmpl" -name "${pair%%:*}" -print -quit)"
  shipped="$ROOT/${pair#*:}"
  a="$(head -1 "$gen" | tr -d '"')"
  b="$(head -1 "$shipped")"
  [ "$a" = "$b" ] || {
    echo "FAIL: shipped template header differs from generated: $shipped" >&2
    diff <(printf '%s' "$a" | tr ',' '\n') <(printf '%s' "$b" | tr ',' '\n') >&2 || true
    exit 1
  }
done

echo "PASS: CM07-01 cross-compartment, ICMP, semantic identity, profile, legacy and template gates"
