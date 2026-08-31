#!/usr/bin/env bash
#
# cm08-01-component-inventory-baseline.sh
# Collector ID: CM08-01
#
# TASK 9 / CM-8 SYSTEM COMPONENT INVENTORY EVIDENCE
#
# This read-only workflow collects OCI hardware, software and logical cloud
# components, compares them to an organization-approved prior inventory, and
# creates monthly review and change-disposition evidence. It never treats a
# current cloud value or generated template as an approval.
#
# Usage:
#   bash cm08-01-component-inventory-baseline.sh -r us-langley-1 --inventory-only
#   bash cm08-01-component-inventory-baseline.sh -i -r us-langley-1 --inventory-only
#   bash cm08-01-component-inventory-baseline.sh \
#       -c ocid1.compartment... -r us-langley-1 --inventory-only
#   bash cm08-01-component-inventory-baseline.sh \
#       -c ocid1.compartment... -r us-langley-1 \
#       -b approved-component-inventory.csv \
#       -d completed-change-dispositions.csv \
#       -m completed-monthly-review.csv
#   bash cm08-01-component-inventory-baseline.sh \
#       -c ocid1.compartment... -r us-langley-1 --non-interactive \
#       --confirm-scope-ocid ocid1.compartment... --approve-scan YES \
#       --inventory-only
#   bash cm08-01-component-inventory-baseline.sh --selfcheck
#
# Exit codes:
#   0  collection and supplied control-evidence validation completed
#   1  precondition, scope, confirmation or input validation failure
#   3  collection or control evidence is incomplete

set -uo pipefail
umask 077

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/lib/oci-scope-selector.sh"
INVENTORY_ENGINE="$SCRIPT_DIR/cm08-hw-sw-baseline.sh"
POSTPROCESSOR="$SCRIPT_DIR/lib/cm08-01-reconcile.py"
CORE_NORMALIZER="$SCRIPT_DIR/lib/cm02-01-reconcile.py"

readonly_selfcheck() {                                           # selfcheck-exempt
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a paths=("$SCRIPT_PATH" "$SCOPE_HELPER" "$INVENTORY_ENGINE") # selfcheck-exempt
  [ -r "$CORE_NORMALIZER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $CORE_NORMALIZER" >&2; return 1; } # selfcheck-exempt
  for path in "${paths[@]}"; do                                 # selfcheck-exempt
    [ -r "$path" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $path" >&2; return 1; } # selfcheck-exempt
  done                                                           # selfcheck-exempt
  deny='(oci|oci_q|oci_capture|oci_discover|emit)[[:space:]].*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|push|install|remove|refresh|run-now|promote|switch)([[:space:]]|$)' # selfcheck-exempt
  hits="$(grep -nE "$deny" "${paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -v 'fs export list' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  rawpat="raw""-request"                                        # selfcheck-exempt
  raw="$(grep -nE "$rawpat" "${paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"        # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ]; then                   # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — prohibited call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  [ "$#" -eq 1 ] || { echo "ERROR: --selfcheck must be used by itself." >&2; exit 1; }
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED (cm08-01-component-inventory-baseline)"
    echo "CM08-01, its scope helper and CM08 inventory engine contain only OCI list/get operations."
    exit 0
  fi
  exit 1
fi

for command_name in oci jq python3 mktemp sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $command_name" >&2; exit 1;
  }
done
for required_file in "$SCOPE_HELPER" "$INVENTORY_ENGINE" "$POSTPROCESSOR" "$CORE_NORMALIZER"; do
  [ -r "$required_file" ] || { echo "ERROR: required file not found: $required_file" >&2; exit 1; }
done

# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION=""
OUTDIR="."
PROFILE=""
APPROVED_INVENTORY=""
DISPOSITIONS=""
MONTHLY_REVIEW=""
INVENTORY_ONLY=0
SELECT_SCOPE=0
NON_INTERACTIVE=0
APPROVE_SCAN=""
CONFIRM_SCOPE_OCIDS=()

need_value() {
  [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "ERROR: $1 requires a value." >&2; exit 1; }
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -i|--select-scope) SELECT_SCOPE=1; shift ;;
    -c|--compartment-id) need_value "$@"; SINGLE_COMP="$2"; shift 2 ;;
    -n|--compartment-names) need_value "$@"; COMP_NAMES_FILTER="$2"; shift 2 ;;
    -r|--region) need_value "$@"; REGION="$2"; shift 2 ;;
    -o|--output-dir) need_value "$@"; OUTDIR="$2"; shift 2 ;;
    -p|--profile) need_value "$@"; PROFILE="$2"; shift 2 ;;
    -b|--approved-inventory) need_value "$@"; APPROVED_INVENTORY="$2"; shift 2 ;;
    -d|--change-dispositions) need_value "$@"; DISPOSITIONS="$2"; shift 2 ;;
    -m|--monthly-review) need_value "$@"; MONTHLY_REVIEW="$2"; shift 2 ;;
    --inventory-only) INVENTORY_ONLY=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --confirm-scope-ocid) need_value "$@"; CONFIRM_SCOPE_OCIDS+=("$2"); shift 2 ;;
    --approve-scan) need_value "$@"; APPROVE_SCAN="$2"; shift 2 ;;
    -h|--help) grep '^#' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; exit 1 ;;
  esac
done

if [ "$SELECT_SCOPE" -eq 1 ] && { [ -n "$SINGLE_COMP" ] || [ -n "$COMP_NAMES_FILTER" ]; }; then
  echo "ERROR: -i/--select-scope cannot be combined with -c or -n." >&2; exit 1
fi
if [ "$NON_INTERACTIVE" -eq 1 ] && [ "$SELECT_SCOPE" -eq 1 ]; then
  echo "ERROR: --non-interactive cannot be combined with interactive selection." >&2; exit 1
fi
if [ "$NON_INTERACTIVE" -eq 1 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  echo "ERROR: --non-interactive requires an explicit -c or -n scope." >&2; exit 1
fi
if [ "$NON_INTERACTIVE" -eq 0 ] && { [ "${#CONFIRM_SCOPE_OCIDS[@]}" -gt 0 ] || [ -n "$APPROVE_SCAN" ]; }; then
  echo "ERROR: automation confirmation flags require --non-interactive." >&2; exit 1
fi
if [ -n "$SINGLE_COMP" ] && [ -n "$COMP_NAMES_FILTER" ]; then
  echo "ERROR: -c and -n are mutually exclusive." >&2; exit 1
fi
if [ -n "$SINGLE_COMP" ]; then
  case "$SINGLE_COMP" in ocid1.compartment.*) ;; *) echo "ERROR: -c requires a compartment OCID." >&2; exit 1 ;; esac
fi
if [ -z "$REGION" ]; then
  echo "ERROR: -r/--region is required so evidence records the exact OCI region." >&2; exit 1
fi
case "$REGION" in *[!A-Za-z0-9-]*) echo "ERROR: one explicit OCI region is required." >&2; exit 1 ;; esac

if [ "$INVENTORY_ONLY" -eq 1 ] && { [ -n "$APPROVED_INVENTORY" ] || [ -n "$DISPOSITIONS" ] || [ -n "$MONTHLY_REVIEW" ]; }; then
  echo "ERROR: --inventory-only cannot be combined with control-evidence inputs." >&2; exit 1
fi
for input_pair in "approved inventory|$APPROVED_INVENTORY" "change dispositions|$DISPOSITIONS" "monthly review|$MONTHLY_REVIEW"; do
  input_label="${input_pair%%|*}"
  input_path="${input_pair#*|}"
  if [ -n "$input_path" ] && [ ! -r "$input_path" ]; then
    echo "ERROR: $input_label is not readable: $input_path" >&2; exit 1
  fi
done
if [ "$INVENTORY_ONLY" -eq 0 ]; then
  [ -n "$APPROVED_INVENTORY" ] || {
    echo "ERROR: reconciliation mode requires --approved-inventory." >&2
    echo "Run --inventory-only first to generate the approved-inventory template." >&2
    exit 1
  }
  VALIDATE_ARGS=(--validate-only --approved-inventory "$APPROVED_INVENTORY")
  [ -n "$DISPOSITIONS" ] && VALIDATE_ARGS+=(--change-dispositions "$DISPOSITIONS")
  [ -n "$MONTHLY_REVIEW" ] && VALIDATE_ARGS+=(--monthly-review "$MONTHLY_REVIEW")
  python3 "$POSTPROCESSOR" "${VALIDATE_ARGS[@]}" || exit 1
fi

if [ "$SELECT_SCOPE" -eq 0 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  SELECT_SCOPE=1
fi
readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

OCI_GLOBAL=(--region "$REGION")
[ -n "$PROFILE" ] && OCI_GLOBAL+=(--profile "$PROFILE")
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
DISCOVERY_ERR="$TMPDIR/discovery-errors.log"
: > "$DISCOVERY_ERR"

oci_discover() {
  local label="$1"; shift
  local output rc token action=""
  for token in "$@"; do
    [[ "$token" == --* ]] && break
    action="$token"
  done
  case "$action" in
    list|get) ;;
    *) printf 'BLOCKED [%s] :: prohibited OCI action: oci %s\n' "$label" "$*" >> "$DISCOVERY_ERR"; return 97 ;;
  esac
  output="$(oci "${OCI_GLOBAL[@]}" "$@" 2>"$TMPDIR/call.err" </dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'FAILED [%s] rc=%s :: oci %s\n' "$label" "$rc" "$*" >> "$DISCOVERY_ERR"
    sed -E 's/(token|secret|password|private[-_ ]?key)[=: ]+[^ ]+/\1=<redacted>/Ig' \
      "$TMPDIR/call.err" >> "$DISCOVERY_ERR"
    return "$rc"
  fi
  printf '%s' "$output"
}

TENANCY_ID="${OCI_TENANCY:-}"
if [ -z "$TENANCY_ID" ]; then
  TENANCY_ID="$(oci_discover "resolve tenancy" iam availability-domain list \
    | jq -r '.data[0]."compartment-id" // empty')" || true
fi
[ -n "$TENANCY_ID" ] || { echo "ERROR: unable to resolve tenancy OCID." >&2; cat "$DISCOVERY_ERR" >&2; exit 1; }

TENANCY_JSON="$(oci_discover "tenancy get" iam tenancy get --tenancy-id "$TENANCY_ID")" || {
  echo "ERROR: unable to read tenancy metadata." >&2; cat "$DISCOVERY_ERR" >&2; exit 1;
}
TENANCY_NAME="$(printf '%s' "$TENANCY_JSON" | jq -r '.data.name // "tenancy"')"
COMP_JSON="$(oci_discover "active compartment discovery" iam compartment list \
  --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
  --access-level ACCESSIBLE --lifecycle-state ACTIVE --all)" || {
  echo "ERROR: unable to discover active compartments." >&2; cat "$DISCOVERY_ERR" >&2; exit 1;
}
printf '%s' "$COMP_JSON" | jq -e '(.data.items? // .data) | type == "array"' >/dev/null 2>&1 || {
  echo "ERROR: compartment discovery returned an unexpected response shape." >&2; exit 1;
}
COMP_CATALOG="$(printf '%s' "$COMP_JSON" | jq -r '(.data.items? // .data // [])[]? | [.id, .name] | @tsv')"

SELECTED_KIND=""
SELECTED_NAME=""
SELECTED_OCID=""
TARGET_CATALOG=""

if [ "$SELECT_SCOPE" -eq 1 ]; then
  oci_scope_select_interactive "$TENANCY_ID" "$TENANCY_NAME" "$COMP_CATALOG" || exit 1
  SELECTED_KIND="$OCI_SCOPE_SELECTED_KIND"
  SELECTED_NAME="$OCI_SCOPE_SELECTED_NAME"
  SELECTED_OCID="$OCI_SCOPE_SELECTED_OCID"
  if [ "$SELECTED_KIND" = "TENANCY" ]; then
    TARGET_CATALOG="$(printf '%s\t%s\n%s\n' "$TENANCY_ID" "$TENANCY_NAME (root)" "$COMP_CATALOG")"
  else
    TARGET_CATALOG="$(printf '%s\t%s\n' "$SELECTED_OCID" "$SELECTED_NAME")"
  fi
elif [ -n "$SINGLE_COMP" ]; then
  SELECTED_KIND="COMPARTMENT"
  SELECTED_OCID="$SINGLE_COMP"
  SELECTED_NAME="$(awk -F '\t' -v id="$SINGLE_COMP" '$1==id {print $2; found=1} END{if(!found) exit 1}' <<< "$COMP_CATALOG")" || {
    echo "ERROR: requested compartment is not an active discovered compartment: $SINGLE_COMP" >&2; exit 1;
  }
  TARGET_CATALOG="$(printf '%s\t%s\n' "$SELECTED_OCID" "$SELECTED_NAME")"
else
  SELECTED_KIND="COMPARTMENT-SET"
  SELECTED_NAME="$COMP_NAMES_FILTER"
  IFS=',' read -r -a REQUESTED_NAMES <<< "$COMP_NAMES_FILTER"
  for requested in "${REQUESTED_NAMES[@]}"; do
    requested="$(oci_scope_trim "$requested")"
    [ -n "$requested" ] || continue
    matches="$(awk -F '\t' -v name="$requested" '$2==name {print $0}' <<< "$COMP_CATALOG")"
    count="$(awk 'NF {n++} END{print n+0}' <<< "$matches")"
    [ "$count" -eq 1 ] || { echo "ERROR: compartment name must resolve exactly once: $requested" >&2; exit 1; }
    TARGET_CATALOG="${TARGET_CATALOG}${TARGET_CATALOG:+$'\n'}$matches"
  done
  [ -n "$TARGET_CATALOG" ] || { echo "ERROR: -n resolved no compartments." >&2; exit 1; }
  duplicate_count="$(cut -f1 <<< "$TARGET_CATALOG" | sort | uniq -d | wc -l | tr -d ' ')"
  [ "$duplicate_count" -eq 0 ] || { echo "ERROR: -n resolved duplicate compartments." >&2; exit 1; }
  SELECTED_OCID="MULTIPLE-CONFIRMED-OCIDS"
fi

TARGET_COUNT="$(awk 'NF {n++} END{print n+0}' <<< "$TARGET_CATALOG")"
[ "$TARGET_COUNT" -gt 0 ] || { echo "ERROR: no target compartments resolved." >&2; exit 1; }

if [ "$NON_INTERACTIVE" -eq 0 ] && [ "$SELECT_SCOPE" -eq 0 ]; then
  exec 3<&0
  while IFS=$'\t' read -r cid cname; do
    [ -n "$cid" ] || continue
    echo "Enter the exact OCID for ${cname:-<unknown>} to confirm this target."
    IFS= read -r entered <&3 || exit 1
    [ "$(oci_scope_trim "$entered")" = "$cid" ] || { echo "ERROR: scope confirmation did not match. Nothing was scanned." >&2; exit 1; }
    echo "Re-enter the exact same OCID."
    IFS= read -r entered <&3 || exit 1
    [ "$(oci_scope_trim "$entered")" = "$cid" ] || { echo "ERROR: second scope confirmation did not match. Nothing was scanned." >&2; exit 1; }
  done <<< "$TARGET_CATALOG"
  exec 3<&-
fi

if [ "$NON_INTERACTIVE" -eq 1 ]; then
  [ "$APPROVE_SCAN" = "YES" ] || { echo "ERROR: automation requires exact --approve-scan YES." >&2; exit 1; }
  expected="$(cut -f1 <<< "$TARGET_CATALOG" | sort -u)"
  supplied="$(printf '%s\n' "${CONFIRM_SCOPE_OCIDS[@]}" | sed '/^$/d' | sort -u)"
  [ "$expected" = "$supplied" ] || { echo "ERROR: automation confirmation OCIDs do not exactly match resolved targets." >&2; exit 1; }
fi

TS="$(date -u +%Y%m%d_%H%M%SZ)"
PREFIX="cm08-01"
COMPONENTS_OUT="$OUTDIR/${PREFIX}_component_inventory_${TS}.csv"
BASELINE_TEMPLATE_OUT="$OUTDIR/${PREFIX}_approved_inventory_template_${TS}.csv"
RECON_OUT="$OUTDIR/${PREFIX}_inventory_reconciliation_${TS}.csv"
DISPOSITION_TEMPLATE_OUT="$OUTDIR/${PREFIX}_change_disposition_template_${TS}.csv"
DISPOSITION_OUT="$OUTDIR/${PREFIX}_change_disposition_results_${TS}.csv"
REVIEW_TEMPLATE_OUT="$OUTDIR/${PREFIX}_monthly_review_template_${TS}.csv"
REVIEW_OUT="$OUTDIR/${PREFIX}_monthly_review_results_${TS}.csv"
GAPS_OUT="$OUTDIR/${PREFIX}_unmanaged_coverage_gaps_${TS}.csv"
SOURCES_OUT="$OUTDIR/${PREFIX}_input_sources_${TS}.csv"
COVERAGE_OUT="$OUTDIR/${PREFIX}_coverage_${TS}.csv"
FINDINGS_OUT="$OUTDIR/${PREFIX}_findings_${TS}.csv"
ERRORS_OUT="$OUTDIR/${PREFIX}_collection_errors_${TS}.csv"
SUMMARY_OUT="$OUTDIR/${PREFIX}_summary_${TS}.txt"
PLAN_OUT="$OUTDIR/${PREFIX}_approved_scan_plan_${TS}.txt"
RAW_ROOT="$OUTDIR/${PREFIX}_raw_inventory_${TS}"

MODE_LABEL="MONTHLY INVENTORY RECONCILIATION"
[ "$INVENTORY_ONLY" -eq 1 ] && MODE_LABEL="INVENTORY-ONLY TEMPLATE GENERATION"
WORK_ITEMS="Broad OCI hardware/software inventory
OS Management Hub installed-package inventory
Stable component identity and SHA-256 inventory fingerprint
Approved prior-inventory reconciliation (added, removed, changed, unchanged)
Unmanaged/in-guest inventory coverage-gap analysis
Change disposition and count-bound monthly review validation"
OUTPUT_FILES="$PLAN_OUT
$COMPONENTS_OUT
$BASELINE_TEMPLATE_OUT
$RECON_OUT
$DISPOSITION_TEMPLATE_OUT
$DISPOSITION_OUT
$REVIEW_TEMPLATE_OUT
$REVIEW_OUT
$GAPS_OUT
$SOURCES_OUT
$COVERAGE_OUT
$FINDINGS_OUT
$ERRORS_OUT (created only when evidence errors exist)
$SUMMARY_OUT
$RAW_ROOT/"
PLAN_TMP="$TMPDIR/approved-plan.txt"
oci_scope_print_scan_plan \
  "CM-8 SYSTEM COMPONENT INVENTORY" "CM08-01" "CM-8 / CM-8(1) / CM-8(2)" "$REGION" \
  "$SELECTED_KIND" "$SELECTED_NAME" "$SELECTED_OCID" "$TARGET_COUNT" \
  "$TARGET_CATALOG" "Evidence work" "$WORK_ITEMS" "$OUTPUT_FILES" \
  "Sensitive component metadata, OCIDs, package versions, owners and approval references" \
  | tee "$PLAN_TMP"
echo "Mode              : $MODE_LABEL" | tee -a "$PLAN_TMP"
echo "OCI CLI profile   : ${PROFILE:-<default/ambient>}" | tee -a "$PLAN_TMP"
echo "Approved inventory: ${APPROVED_INVENTORY:-<not supplied>}" | tee -a "$PLAN_TMP"
echo "Dispositions      : ${DISPOSITIONS:-<not supplied>}" | tee -a "$PLAN_TMP"
echo "Monthly review    : ${MONTHLY_REVIEW:-<not supplied>}" | tee -a "$PLAN_TMP"
echo "Installed packages: INCLUDED (may be high volume)" | tee -a "$PLAN_TMP"

if [ "$NON_INTERACTIVE" -eq 0 ]; then
  oci_scope_require_final_approval 1 || {
    echo "SCAN NOT STARTED: $OCI_SCOPE_APPROVAL_ERROR. Nothing was scanned." >&2; exit 1;
  }
else
  echo "Approval mode     : strict automation confirmation accepted"
  echo "SCAN APPROVED: starting read-only service collection."
fi

mkdir -p "$OUTDIR" || { echo "ERROR: cannot create output directory: $OUTDIR" >&2; exit 1; }
if find "$OUTDIR" -maxdepth 1 -name "${PREFIX}_*_${TS}.*" -print -quit | grep -q .; then
  echo "ERROR: output collision for timestamp $TS." >&2; exit 1
fi
mkdir -p "$RAW_ROOT"
cp "$PLAN_TMP" "$PLAN_OUT"

CHILD_FAILURES=0
RAW_DIR_ARGS=()
if [ "$SELECTED_KIND" = "TENANCY" ]; then
  raw_dir="$RAW_ROOT/tenancy"
  mkdir -p "$raw_dir"
  RAW_DIR_ARGS+=(--raw-dir "$raw_dir")
  OCI_TENANCY="$TENANCY_ID" OCI_CLI_PROFILE="$PROFILE" \
    OCI_AUDIT_APPROVED_CALLER=CM08-01 OCI_AUDIT_APPROVED_SCOPE_OCID="$TENANCY_ID" \
    OCI_AUDIT_APPROVED_REGION="$REGION" \
    bash "$INVENTORY_ENGINE" -c "$TENANCY_ID" -r "$REGION" -p -o "$raw_dir" \
      > "$raw_dir/collector-console.log" 2>&1
  child_rc=$?
  [ "$child_rc" -eq 0 ] || CHILD_FAILURES=$((CHILD_FAILURES + 1))
else
  index=0
  while IFS=$'\t' read -r cid cname; do
    [ -n "$cid" ] || continue
    index=$((index + 1))
    raw_dir="$RAW_ROOT/target-${index}"
    mkdir -p "$raw_dir"
    RAW_DIR_ARGS+=(--raw-dir "$raw_dir")
    OCI_TENANCY="$TENANCY_ID" OCI_CLI_PROFILE="$PROFILE" OCI_AUDIT_EXACT_SCOPE_ONLY=1 \
      OCI_AUDIT_APPROVED_CALLER=CM08-01 OCI_AUDIT_APPROVED_SCOPE_OCID="$cid" \
      OCI_AUDIT_APPROVED_REGION="$REGION" \
      bash "$INVENTORY_ENGINE" -c "$cid" -r "$REGION" -p -o "$raw_dir" \
        > "$raw_dir/collector-console.log" 2>&1
    child_rc=$?
    [ "$child_rc" -eq 0 ] || CHILD_FAILURES=$((CHILD_FAILURES + 1))
  done <<< "$TARGET_CATALOG"
fi

POST_ARGS=(
  "${RAW_DIR_ARGS[@]}"
  --scope-ocid "$SELECTED_OCID" --scope-kind "$SELECTED_KIND"
  --region "$REGION" --collected-at "$TS"
  --components-out "$COMPONENTS_OUT"
  --baseline-template-out "$BASELINE_TEMPLATE_OUT"
  --reconciliation-out "$RECON_OUT"
  --disposition-template-out "$DISPOSITION_TEMPLATE_OUT"
  --disposition-out "$DISPOSITION_OUT"
  --review-template-out "$REVIEW_TEMPLATE_OUT"
  --review-out "$REVIEW_OUT"
  --gaps-out "$GAPS_OUT"
  --sources-out "$SOURCES_OUT"
  --coverage-out "$COVERAGE_OUT"
  --findings-out "$FINDINGS_OUT"
  --errors-out "$ERRORS_OUT"
  --summary-out "$SUMMARY_OUT"
)
if [ "$INVENTORY_ONLY" -eq 1 ]; then
  POST_ARGS+=(--inventory-only)
else
  POST_ARGS+=(--approved-inventory "$APPROVED_INVENTORY")
  [ -n "$DISPOSITIONS" ] && POST_ARGS+=(--change-dispositions "$DISPOSITIONS")
  [ -n "$MONTHLY_REVIEW" ] && POST_ARGS+=(--monthly-review "$MONTHLY_REVIEW")
fi

python3 "$POSTPROCESSOR" "${POST_ARGS[@]}"
POST_RC=$?

echo
cat "$SUMMARY_OUT" 2>/dev/null || true
echo
echo "Evidence directory: $OUTDIR"

if [ "$CHILD_FAILURES" -gt 0 ] || [ "$POST_RC" -eq 3 ]; then
  echo "CM08-01 evidence is INCOMPLETE. Review coverage, errors, findings and pending approvals." >&2
  exit 3
fi
[ "$POST_RC" -eq 0 ] || exit 1
exit 0
