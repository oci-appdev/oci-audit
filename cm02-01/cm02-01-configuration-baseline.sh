#!/usr/bin/env bash
#
# cm02-01/cm02-01-configuration-baseline.sh
# Collector ID: CM02-01
#
# TASK 8 / CM-2 TECHNICAL CONFIGURATION SNAPSHOT
#
# This is a simple read-only collector. It answers one question: what OCI
# resources and configuration attributes are visible in the confirmed scope
# right now? It does not require governance CSVs and does not perform approval,
# drift, System Design Form or monthly-review reconciliation.
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation, then delegates raw collection to
#   `cm08-01/cm08-hw-sw-baseline.sh`. This Task 8 workflow does not use the OCI Python
#   SDK.
#
# PYTHON FILES USED:
#   cm02-01/cm02-01-reconcile.py   normalizes the raw CM-8 engine output into
#                                  CI/attribute rows, fingerprints and coverage
#
# READ-ONLY CLOUD BOUNDARY: OCI calls are list/get operations. Collection is
# delegated, after approval, to the existing CM-8 inventory engine. Nothing is
# created, updated, attached, detached or deleted in OCI.
#
# Usage:
#   bash cm02-01/cm02-01-configuration-baseline.sh -r us-langley-1 -o ./evidence/cm02
#   bash cm02-01/cm02-01-configuration-baseline.sh -i -r us-langley-1
#   bash cm02-01/cm02-01-configuration-baseline.sh \
#       -c ocid1.compartment... -r us-langley-1 -o ./evidence/cm02
#   bash cm02-01/cm02-01-configuration-baseline.sh \
#       -c ocid1.compartment... -r us-langley-1 \
#       --non-interactive \
#       --confirm-scope-ocid ocid1.compartment... --approve-scan YES \
#       -o ./evidence/cm02
#   bash cm02-01/cm02-01-configuration-baseline.sh --selfcheck
#
# Exit codes:
#   0  technical collection completed
#   1  precondition, scope or confirmation failure
#   3  one or more OCI collection operations failed or returned bad data

set -uo pipefail
umask 077

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/../lib/oci-scope-selector.sh"
INVENTORY_ENGINE="$SCRIPT_DIR/../cm08-01/cm08-hw-sw-baseline.sh"
POSTPROCESSOR="$SCRIPT_DIR/cm02-01-reconcile.py"

readonly_selfcheck() {                                           # selfcheck-exempt
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a paths=("$SCRIPT_PATH" "$SCOPE_HELPER" "$INVENTORY_ENGINE") # selfcheck-exempt
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
  if [ -n "$hits" ] || [ -n "$raw" ]; then                    # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — prohibited call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if [ "$#" -ne 1 ]; then
    echo "ERROR: --selfcheck must be used by itself." >&2
    exit 1
  fi
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED (cm02-01-configuration-baseline)"
    echo "CM02-01, its scope helper and CM08 inventory engine contain only OCI list/get operations."
    exit 0
  fi
  exit 1
fi

for command_name in oci jq python3 mktemp; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "ERROR: required command not found: $command_name" >&2
    exit 1
  }
done
for required_file in "$SCOPE_HELPER" "$INVENTORY_ENGINE" "$POSTPROCESSOR"; do
  [ -r "$required_file" ] || { echo "ERROR: required file not found: $required_file" >&2; exit 1; }
done

# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION=""
OUTDIR="."
TASK_DIR="cm02-01"
PROFILE=""
SELECT_SCOPE=0
NON_INTERACTIVE=0
APPROVE_SCAN=""
CONFIRM_SCOPE_OCIDS=()

need_value() {
  [ "$#" -ge 2 ] && [ -n "$2" ] || {
    echo "ERROR: $1 requires a value." >&2
    exit 1
  }
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -i|--select-scope) SELECT_SCOPE=1; shift ;;
    -c|--compartment-id) need_value "$@"; SINGLE_COMP="$2"; shift 2 ;;
    -n|--compartment-names) need_value "$@"; COMP_NAMES_FILTER="$2"; shift 2 ;;
    -r|--region) need_value "$@"; REGION="$2"; shift 2 ;;
    -o|--output-dir) need_value "$@"; OUTDIR="$2"; shift 2 ;;
    -p|--profile) need_value "$@"; PROFILE="$2"; shift 2 ;;
    --inventory-only) shift ;; # accepted as a compatibility no-op
    -g|--ci-register|-b|--approved-baseline|-m|--monthly-review)
      echo "ERROR: $1 was removed from the simple CM02 collector." >&2
      echo "CM02-01 now collects technical configuration only; approvals are maintained separately." >&2
      exit 1
      ;;
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

if [ "$SELECT_SCOPE" -eq 0 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  SELECT_SCOPE=1
fi

OUTROOT="${OUTDIR%/}"
[ -n "$OUTROOT" ] || OUTROOT="/"
if [ "$(basename -- "$OUTROOT")" != "$TASK_DIR" ]; then
  OUTDIR="$OUTROOT/$TASK_DIR"
else
  OUTDIR="$OUTROOT"
fi
readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

OCI_GLOBAL=(--region "$REGION")
[ -n "$PROFILE" ] && OCI_GLOBAL+=(--profile "$PROFILE")
WORKDIR="$(mktemp -d)"
trap 'find "$WORKDIR" -depth -delete' EXIT
DISCOVERY_ERR="$WORKDIR/discovery-errors.log"
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
  output="$(oci "${OCI_GLOBAL[@]}" "$@" 2>"$WORKDIR/call.err" </dev/null)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    printf 'FAILED [%s] rc=%s :: oci %s\n' "$label" "$rc" "$*" >> "$DISCOVERY_ERR"
    sed -E 's/(token|secret|password|private[-_ ]?key)[=: ]+[^ ]+/\1=<redacted>/Ig' \
      "$WORKDIR/call.err" >> "$DISCOVERY_ERR"
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
COLLECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PREFIX="cm02-01"
ITEMS_OUT="$OUTDIR/${PREFIX}_configuration_items_${TS}.csv"
ATTRS_OUT="$OUTDIR/${PREFIX}_configuration_attributes_${TS}.csv"
COVERAGE_OUT="$OUTDIR/${PREFIX}_coverage_${TS}.csv"
ERRORS_OUT="$OUTDIR/${PREFIX}_collection_errors_${TS}.csv"
SUMMARY_OUT="$OUTDIR/${PREFIX}_summary_${TS}.txt"
PLAN_OUT="$OUTDIR/${PREFIX}_approved_scan_plan_${TS}.txt"
RAW_ROOT="$OUTDIR/${PREFIX}_raw_inventory_${TS}"

WORK_ITEMS="Broad OCI configuration inventory (CM08 engine)
Configuration item normalization and SHA-256 fingerprint
Current configuration attribute snapshot
Per-operation coverage and collection-error summary"
OUTPUT_FILES="$PLAN_OUT
$ITEMS_OUT
$ATTRS_OUT
$COVERAGE_OUT
$ERRORS_OUT (created only when collection errors exist)
$SUMMARY_OUT
$RAW_ROOT/"
PLAN_TMP="$WORKDIR/approved-plan.txt"
oci_scope_print_scan_plan \
  "CM-2 CONFIGURATION BASELINE" "CM02-01" "CM-2 / CM-2(2) / CM-2(3)" "$REGION" \
  "$SELECTED_KIND" "$SELECTED_NAME" "$SELECTED_OCID" "$TARGET_COUNT" \
  "$TARGET_CATALOG" "Evidence work" "$WORK_ITEMS" "$OUTPUT_FILES" \
  "Sensitive configuration metadata, OCIDs, resource names, tags and service settings" \
  | tee "$PLAN_TMP"
echo "Mode            : SIMPLE TECHNICAL COLLECTION" | tee -a "$PLAN_TMP"
echo "OCI CLI profile : ${PROFILE:-<default/ambient>}" | tee -a "$PLAN_TMP"
echo "Cloud boundary  : read-only list/get collection; no OCI changes" | tee -a "$PLAN_TMP"

if [ "$NON_INTERACTIVE" -eq 0 ]; then
  oci_scope_require_final_approval 1 || {
    echo "SCAN NOT STARTED: $OCI_SCOPE_APPROVAL_ERROR. Nothing was scanned." >&2
    exit 1
  }
else
  echo "Approval mode   : strict automation confirmation accepted"
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
    OCI_AUDIT_APPROVED_CALLER=CM02-01 OCI_AUDIT_APPROVED_SCOPE_OCID="$TENANCY_ID" \
    OCI_AUDIT_APPROVED_REGION="$REGION" \
    bash "$INVENTORY_ENGINE" -c "$TENANCY_ID" -r "$REGION" -o "$raw_dir" \
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
      OCI_AUDIT_APPROVED_CALLER=CM02-01 OCI_AUDIT_APPROVED_SCOPE_OCID="$cid" \
      OCI_AUDIT_APPROVED_REGION="$REGION" \
      bash "$INVENTORY_ENGINE" -c "$cid" -r "$REGION" -o "$raw_dir" \
        > "$raw_dir/collector-console.log" 2>&1
    child_rc=$?
    [ "$child_rc" -eq 0 ] || CHILD_FAILURES=$((CHILD_FAILURES + 1))
  done <<< "$TARGET_CATALOG"
fi

POST_ARGS=(
  "${RAW_DIR_ARGS[@]}"
  --scope-ocid "$SELECTED_OCID"
  --scope-kind "$SELECTED_KIND"
  --region "$REGION"
  --collected-at "$COLLECTED_AT"
  --items-out "$ITEMS_OUT"
  --attributes-out "$ATTRS_OUT"
  --ci-template-out "$RAW_ROOT/internal_ci_template.csv"
  --baseline-template-out "$RAW_ROOT/internal_baseline_template.csv"
  --reconciliation-out "$RAW_ROOT/internal_reconciliation.csv"
  --review-template-out "$RAW_ROOT/internal_review_template.csv"
  --review-out "$RAW_ROOT/internal_review_results.csv"
  --sources-out "$RAW_ROOT/internal_sources.csv"
  --coverage-out "$COVERAGE_OUT"
  --findings-out "$RAW_ROOT/internal_findings.csv"
  --errors-out "$ERRORS_OUT"
  --summary-out "$SUMMARY_OUT"
  --inventory-only
)

python3 "$POSTPROCESSOR" "${POST_ARGS[@]}"
POST_RC=$?

echo
cat "$SUMMARY_OUT" 2>/dev/null || true
echo
echo "Evidence directory: $OUTDIR"

if [ "$CHILD_FAILURES" -gt 0 ] || [ "$POST_RC" -eq 3 ]; then
  echo "CM02-01 COLLECTION INCOMPLETE: one or more read-only OCI operations failed." >&2
  echo "Review: $COVERAGE_OUT" >&2
  [ -f "$ERRORS_OUT" ] && echo "Errors: $ERRORS_OUT" >&2
  exit 3
fi
[ "$POST_RC" -eq 0 ] || exit 1
echo "CM02-01 COLLECTION COMPLETE: technical snapshot and coverage were written successfully."
exit 0
