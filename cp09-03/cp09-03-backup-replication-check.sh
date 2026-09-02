#!/usr/bin/env bash
#
# cp09-03/cp09-03-backup-replication-check.sh
#
# CP-9(5) / CP-10 EVIDENCE — Backup replication, retention & versioning
#
# Complements oci_backup_audit.sh (which shows backups EXIST). This script
# reports the three DR dimensions for each backup / data store:
#     REPLICATED  - is there a cross-region / second copy?  (+ target region)
#     RETENTION   - how long kept, and is it IMMUTABLE (WORM / time-locked)?
#     VERSIONING  - where applicable (Object Storage), is versioning on?
#
# Designed for OCI Cloud Shell (uses your delegation token). No API keys.
# READ-ONLY: every call is a list/get. Nothing is created/modified/deleted.
#
# Dimensions collected per service:
#   1. Object Storage  - replication policy (+dest region), versioning,
#                        retention rules (WORM + time-lock), lifecycle
#   2. Block Volumes   - volume replicas (cross-AD/region), backup copies
#   3. Boot Volumes    - boot volume replicas, backup copies
#   4. Volume Backups  - cross-region copies (source-region != current)
#   5. File Storage    - FSS replication targets + snapshot retention
#   6. Autonomous DB   - backup retention + cross-region/Data Guard copy
#   7. Base DB         - backup recovery window + Data Guard association
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation. This Task 1 collector does not use the OCI
#   Python SDK.
#
# PYTHON FILES USED:
#   None. Bash + OCI CLI + jq only.
#
# Usage:
#   ./cp09-03/cp09-03-backup-replication-check.sh                  # interactive scope + approval
#   ./cp09-03/cp09-03-backup-replication-check.sh --select-scope   # discover + confirm scope
#   ./cp09-03/cp09-03-backup-replication-check.sh -i               # short form
#   ./cp09-03/cp09-03-backup-replication-check.sh -c <ocid>        # one compartment
#   ./cp09-03/cp09-03-backup-replication-check.sh -n VCN,CD3       # compartment names
#   ./cp09-03/cp09-03-backup-replication-check.sh -r us-langley-1  # GovCloud region
#   ./cp09-03/cp09-03-backup-replication-check.sh -s "object fss"  # service subset
#   ./cp09-03/cp09-03-backup-replication-check.sh -o ./evidence    # output root; writes into ./evidence/cp09-03/
#   ./cp09-03/cp09-03-backup-replication-check.sh --selfcheck      # prove read-only
#
# Output: three timestamped CSVs + console summary.
#   ..._<ts>.csv                    one row per asset, including collection status
#   ..._coverage_<ts>.csv           compartment x service collection ledger
#   ..._collection_errors_<ts>.csv  failed OCI calls; absent on a clean run
#
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/../lib/oci-scope-selector.sh"

readonly_selfcheck() {                                          # selfcheck-exempt
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")         # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='oci[[:space:]]+([a-z0-9-]+[[:space:]]+)*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|bulk-upload|bulk-delete|reset|activate|deactivate|cancel)([[:space:]]|$)'  # selfcheck-exempt
  hits="$(grep -nE "$deny" "${check_paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"      # selfcheck-exempt
  rawpat="raw""-request"                                       # selfcheck-exempt
  raw="$(grep -nE "$rawpat" "${check_paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ]; then                    # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — mutating call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED"
    echo "All OCI calls in $SCRIPT_PATH are list/get operations."
    exit 0
  fi
  exit 1
fi

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found."; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found."; exit 1; }

[ -r "$SCOPE_HELPER" ] || { echo "ERROR: scope selector not found: $SCOPE_HELPER" >&2; exit 1; }
# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""; COMP_NAMES_FILTER=""; REGION_OVERRIDE=""; OUTDIR="."
TASK_DIR="cp09-03"
SERVICES="object volumes bootvol backups fss adb basedb"
SELECT_SCOPE=0

NON_INTERACTIVE=0
APPROVE_SCAN=""
CONFIRM_SCOPE_OCIDS=()

# Long options are consumed here so getopts only sees short options. The three
# automation options take values, so this loop shifts rather than iterating.
NORMALIZED_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --select-scope) SELECT_SCOPE=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --confirm-scope-ocid)
      [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "ERROR: --confirm-scope-ocid requires a value." >&2; exit 1; }
      CONFIRM_SCOPE_OCIDS+=("$2"); shift 2 ;;
    --approve-scan)
      [ "$#" -ge 2 ] && [ -n "$2" ] || { echo "ERROR: --approve-scan requires a value." >&2; exit 1; }
      APPROVE_SCAN="$2"; shift 2 ;;
    *) NORMALIZED_ARGS+=("$1"); shift ;;
  esac
done
set -- ${NORMALIZED_ARGS[@]+"${NORMALIZED_ARGS[@]}"}

while getopts "ic:n:r:s:o:h" opt; do
  case "$opt" in
    i) SELECT_SCOPE=1 ;;
    c) SINGLE_COMP="$OPTARG" ;;
    n) COMP_NAMES_FILTER="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help"; exit 1 ;;
  esac
done

if [ "$SELECT_SCOPE" -eq 1 ] && { [ -n "$SINGLE_COMP" ] || [ -n "$COMP_NAMES_FILTER" ]; }; then
  echo "ERROR: --select-scope/-i cannot be combined with -c or -n." >&2
  exit 1
fi

if [ "$NON_INTERACTIVE" -eq 1 ] && [ "$SELECT_SCOPE" -eq 1 ]; then
  echo "ERROR: --non-interactive cannot be combined with -i/--select-scope." >&2
  exit 1
fi

if [ "$NON_INTERACTIVE" -eq 1 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  echo "ERROR: --non-interactive requires an explicit -c or -n scope." >&2
  exit 1
fi

if [ "$NON_INTERACTIVE" -eq 0 ] && { [ "${#CONFIRM_SCOPE_OCIDS[@]}" -gt 0 ] || [ -n "$APPROVE_SCAN" ]; }; then
  echo "ERROR: --confirm-scope-ocid and --approve-scan require --non-interactive." >&2
  exit 1
fi

if [ -n "$SINGLE_COMP" ] && [ -n "$COMP_NAMES_FILTER" ]; then
  echo "ERROR: -c and -n are mutually exclusive scope modes." >&2
  exit 1
fi

if [ -n "$SINGLE_COMP" ]; then
  case "$SINGLE_COMP" in
    ocid1.compartment.*) ;;
    *) echo "ERROR: -c requires a compartment OCID. Use interactive mode to select the tenancy." >&2; exit 1 ;;
  esac
fi

# A normal operator run always discovers the tenancy/compartments and asks for
# the exact OCID. Explicit -c/-n select a scope but do not approve a scan: a
# manual -c/-n run still confirms every resolved OCID twice and requires exact
# uppercase YES. Only --non-interactive is an automation path, and it must carry
# its own confirmations.
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

REGION_ARG=(); [ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
mkdir -p -- "$OUTDIR" 2>/dev/null || { echo "ERROR: cannot create output directory: $OUTDIR" >&2; exit 1; }
readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUTDIR/oci_backup_dr_${TS}.csv"
COVERAGE="$OUTDIR/oci_backup_dr_coverage_${TS}.csv"
ERROUT="$OUTDIR/oci_backup_dr_collection_errors_${TS}.csv"
echo "compartment_id,compartment_name,service,resource,replicated,replica_target,retention,immutable_worm,versioning,finding,control,collection_status,collection_error" > "$OUT"
echo "compartment_id,compartment_name,service,assets_found,collection_status,collection_error" > "$COVERAGE"
echo "compartment_id,compartment_name,status,command,error" > "$ERROUT"

abort_before_scan() {
  local reason="$1"
  rm -f -- "$OUT" "$COVERAGE" "$ERROUT" 2>/dev/null
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# OCI wrapper.
#
# This previously discarded stderr entirely (`oci ... 2>/dev/null`). For a
# replication control that is a dangerous false negative: a 403 on, say,
# `bv block-volume-replica list` returned nothing, and nothing was then
# reported as "NO-REPLICA" — an auditor would read a permission problem as
# proof that no DR copy exists.
#
# Every call stores stdout, status and a short error in COLLECT_* globals. Callers
# consume those values in the current shell, avoiding the command-substitution
# subshell bug that previously lost LAST_STATUS and INCOMPLETE assignments.
# ---------------------------------------------------------------------------
INCOMPLETE=0
CUR_COMP="<tenancy>"
COLLECT_OUT=""; COLLECT_STATUS="OK"; COLLECT_ERROR=""
declare -A COMP_NAME

oci_capture() {
  local label="$1"; shift
  local errf out rc err status cname cmd
  errf="$(mktemp 2>/dev/null || echo "/tmp/cp0903.$$.err")"
  out="$(oci "${REGION_ARG[@]}" "$@" 2>"$errf")"; rc=$?
  err="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-300)"
  rm -f "$errf" 2>/dev/null
  if [ "$rc" -eq 0 ]; then
    status="OK"
  else
    if printf '%s' "$err" | grep -qiE 'NotAuthorized|Authorization failed|forbidden|\b403\b'; then
      status="DENIED"
    elif printf '%s' "$err" | grep -qiE 'No such command|no such option|Usage:'; then
      status="CLI_UNSUPPORTED"
    elif printf '%s' "$err" | grep -qiE 'NotFound|does not exist|\b404\b'; then
      status="NOTFOUND"
    else
      status="ERROR"
    fi
    # NOTFOUND is normal for an optional child resource. All other failures
    # make the run incomplete and are retained in the collection-error ledger.
    if [ "$status" != "NOTFOUND" ]; then
      INCOMPLETE=1
      cname="${COMP_NAME[$CUR_COMP]:-<unknown>}"
      cmd="$label :: $*"
      cmd="${cmd//\"/\"\"}"; err="${err//\"/\"\"}"
      printf '"%s","%s","%s","%s","%s"\n' "$CUR_COMP" "$cname" "$status" "$cmd" "$err" >> "$ERROUT"
    fi
  fi
  COLLECT_OUT="$out"
  COLLECT_STATUS="$status"
  COLLECT_ERROR="$err"
}

LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

csv_escape() { local s="$1"; s="${s//\"/\"\"}"; printf '"%s"' "$s"; }

row() {
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local out="" f
  for f in "$comp_id" "$cname" "$@"; do
    f="${f//\"/\"\"}"
    out+="\"${f}\","
  done
  echo "${out%,}" >> "$OUT"
}

coverage_row() {
  local comp_id="$1" service="$2" count="$3" status="$4" error="$5"
  printf '%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$comp_id")" "$(csv_escape "${COMP_NAME[$comp_id]:-<unknown>}")" \
    "$(csv_escape "$service")" "$(csv_escape "$count")" \
    "$(csv_escape "$status")" "$(csv_escape "$error")" >> "$COVERAGE"
}

merge_status() {
  local status_var="$1" error_var="$2" new_status="$3" new_error="$4"
  local current="${!status_var}"
  [ "$new_status" = "OK" ] || [ "$new_status" = "NOTFOUND" ] || {
    if [ "$current" = "OK" ]; then printf -v "$status_var" '%s' "$new_status"; fi
    if [ -n "$new_error" ]; then
      local prior="${!error_var}"
      printf -v "$error_var" '%s' "${prior:+$prior | }$new_error"
    fi
  }
}

collection_failure_row() {
  local comp="$1" service="$2" status="$3" error="$4" control="$5"
  INCOMPLETE=1
  row "$comp" "$service" "<collection>" "UNKNOWN" "UNKNOWN" "UNKNOWN" \
      "UNKNOWN" "UNKNOWN" "COLLECTION-FAILED" "$control" "$status" "$error"
}

# Current region (for detecting cross-region copies)
if [ -n "$REGION_OVERRIDE" ]; then
  CUR_REGION="$REGION_OVERRIDE"
else
  oci_capture "detect home region" iam region-subscription list \
    --query 'data[?"is-home-region"].["region-name"]|[0]' --raw-output
  CUR_REGION="$COLLECT_OUT"
  if [ -z "$CUR_REGION" ] || [ "$CUR_REGION" = "null" ]; then
    oci_capture "detect subscribed region" iam region-subscription list \
      --query 'data[0]."region-name"' --raw-output
    CUR_REGION="$COLLECT_OUT"
  fi
fi

# ---------------------------------------------------------------------------
# Tenancy + compartment enumeration
# ---------------------------------------------------------------------------
oci_capture "resolve tenancy" iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$COLLECT_OUT"
[ -z "$TENANCY_ID" ] || [ "$TENANCY_ID" = "null" ] && {
  echo "ERROR: could not resolve tenancy ($COLLECT_STATUS): $COLLECT_ERROR" >&2
  echo "Collection errors retained in: $ERROUT" >&2
  exit 1
}
CUR_COMP="$TENANCY_ID"
COMP_NAME["$TENANCY_ID"]="root"
echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>} (detected: ${CUR_REGION:-unknown})"
echo "Tenancy: ${TENANCY_ID:-<unknown>}"
echo "Scope  : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'command-line/default')"
echo

if [ "$SELECT_SCOPE" -eq 1 ]; then
  CUR_COMP="$TENANCY_ID"
  oci_capture "discover active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  [ "$COLLECT_STATUS" = "OK" ] || {
    echo "ERROR: compartment discovery failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  }

  scope_catalog="$(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps="${discovered_comps}${cid}"$'\n'
  done <<< "$scope_catalog"

  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  [ "$COLLECT_STATUS" = "OK" ] || {
    echo "ERROR: tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  }
  COMP_NAME["$TENANCY_ID"]="${COLLECT_OUT:-root}"

  if ! oci_scope_select_interactive "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$scope_catalog"; then
    abort_before_scan "scope selection or OCID confirmation failed"
  fi

  if [ "$OCI_SCOPE_SELECTED_KIND" = "TENANCY" ]; then
    COMPS="$TENANCY_ID"$'\n'"$discovered_comps"
  else
    SINGLE_COMP="$OCI_SCOPE_SELECTED_OCID"
    COMPS="$SINGLE_COMP"
  fi
elif [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  CUR_COMP="$SINGLE_COMP"
  oci_capture "get compartment name" iam compartment get --compartment-id "$SINGLE_COMP" \
    --query 'data.name' --raw-output
  cn="$COLLECT_OUT"
  COMP_NAME["$SINGLE_COMP"]="${cn:-<unknown>}"
else
  CUR_COMP="$TENANCY_ID"
  oci_capture "enumerate active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE \
    --all --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  [ "$COLLECT_STATUS" = "OK" ] || {
    echo "ERROR: compartment enumeration failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  }
  while IFS=$'\t' read -r cid cname; do [ -z "$cid" ] && continue; COMP_NAME["$cid"]="$cname"; done \
    < <(echo "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)
  COMPS="$(echo "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"
  if [ -n "$TENANCY_ID" ]; then
    oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
      --query 'data.name' --raw-output
    tname="$COLLECT_OUT"
    COMP_NAME["$TENANCY_ID"]="${tname:-root}"; COMPS="$TENANCY_ID"$'\n'"$COMPS"
  fi
fi

if [ -n "$COMP_NAMES_FILTER" ]; then
  FILTERED_COMPS=""
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    cname="${COMP_NAME[$cid]:-<unknown>}"
    if printf ',%s,' "$COMP_NAMES_FILTER" | grep -Fqi ",${cname},"; then
      FILTERED_COMPS+="${FILTERED_COMPS:+$'\n'}$cid"
    fi
  done <<< "$COMPS"
  COMPS="$FILTERED_COMPS"
fi
COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -eq 0 ] && abort_before_scan "no compartments matched the requested scope"

if [ "$SELECT_SCOPE" -eq 1 ]; then
  PLAN_SCOPE_TYPE="$OCI_SCOPE_SELECTED_KIND"
  PLAN_SCOPE_NAME="$OCI_SCOPE_SELECTED_NAME"
  PLAN_SCOPE_OCID="$OCI_SCOPE_SELECTED_OCID"
elif [ -n "$SINGLE_COMP" ]; then
  PLAN_SCOPE_TYPE="AUTOMATION-COMPARTMENT"
  PLAN_SCOPE_NAME="${COMP_NAME[$SINGLE_COMP]:-<unknown>}"
  PLAN_SCOPE_OCID="$SINGLE_COMP"
else
  PLAN_SCOPE_TYPE="AUTOMATION-NAME-FILTER"
  PLAN_SCOPE_NAME="$COMP_NAMES_FILTER"
  PLAN_SCOPE_OCID="multiple resolved compartment OCIDs"
fi

PLAN_TARGETS=""
while IFS= read -r cid; do
  [ -z "$cid" ] && continue
  PLAN_TARGETS+="${cid}"$'\t'"${COMP_NAME[$cid]:-<unknown>}"$'\n'
done <<< "$COMPS"
PLAN_WORK=""
for svc in $SERVICES; do PLAN_WORK+="${svc}"$'\n'; done

# A manual -c/-n run selected a scope on the command line but has not confirmed
# it. Do that before the plan is printed and before any workload call.
if [ "$SELECT_SCOPE" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
  oci_scope_confirm_resolved_targets "$PLAN_TARGETS" || abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
fi

oci_scope_print_scan_plan \
  "CP-9 BACKUP REPLICATION" "cp09-03/cp09-03-backup-replication-check.sh" \
  "CP-9(5) / CP-10" "${REGION_OVERRIDE:-${CUR_REGION:-<cloud-shell-default>}}" \
  "$PLAN_SCOPE_TYPE" "$PLAN_SCOPE_NAME" "$PLAN_SCOPE_OCID" "$COMP_COUNT" \
  "$PLAN_TARGETS" "Requested service scans" "$PLAN_WORK" \
  "$OUT"$'\n'"$COVERAGE"$'\n'"$ERROUT" \
  "resource OCIDs/names, replicas, retention, WORM and versioning posture"
# Passing 1 rather than $SELECT_SCOPE is the fix: a manual -c/-n run now
# requires exact uppercase YES after the plan instead of proceeding silently.
if [ "$NON_INTERACTIVE" -eq 1 ]; then
  oci_scope_validate_automation "$PLAN_TARGETS" || abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
elif ! oci_scope_require_final_approval 1; then
  abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
fi

echo "Auditing DR posture (replication/retention/versioning) across ${COMP_COUNT} compartment(s)..."
echo

# ---------------------------------------------------------------------------
# 1. Object Storage — the full picture
# ---------------------------------------------------------------------------
check_object() {
  local comp="$1"
  local ns buckets_json buckets count=0 service_status="OK" service_error=""
  oci_capture "Object Storage namespace" os ns get --raw-output --query 'data'
  ns="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ] || [ -z "$ns" ]; then
    if [ "$COLLECT_STATUS" = "OK" ]; then service_status="ERROR"; else service_status="$COLLECT_STATUS"; fi
    service_error="${COLLECT_ERROR:-Object Storage namespace was empty}"
    collection_failure_row "$comp" "ObjectStorage" "$service_status" "$service_error" "CP-9(5)/CP-6"
    coverage_row "$comp" "ObjectStorage" "UNKNOWN" "$service_status" "$service_error"
    INCOMPLETE=1
    return
  fi

  oci_capture "Object Storage bucket list" os bucket list --compartment-id "$comp" \
    --namespace-name "$ns" --all
  buckets_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "ObjectStorage" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-6"
    coverage_row "$comp" "ObjectStorage" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  buckets="$(printf '%s' "$buckets_json" | jq -r "$LIST_ITER | .name" 2>/dev/null)"
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    count=$((count+1))
    local repl repl_target ver rr_json worm ret finding
    local row_status="OK" row_error="" rp bucket_json

    # Replication policy (+ destination region)
    oci_capture "Object Storage replication policies [$b]" os replication \
      list-replication-policies --bucket-name "$b" --namespace-name "$ns" --all
    rp="$COLLECT_OUT"
    merge_status row_status row_error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ] && [ "$COLLECT_STATUS" != "NOTFOUND" ]; then
      repl="UNKNOWN"; repl_target="UNKNOWN"
    elif printf '%s' "$rp" | jq -e '(.data.items? // .data // []) | length > 0' >/dev/null 2>&1; then
      repl="YES"
      repl_target="$(printf '%s' "$rp" | jq -r '[(.data.items? // .data // [])[]? | "\(."destination-region-name"):\(."destination-bucket-name")"] | join("; ")' 2>/dev/null)"
    else
      repl="NO"; repl_target="none"
    fi

    # Versioning
    oci_capture "Object Storage bucket get [$b]" os bucket get --bucket-name "$b" --namespace-name "$ns"
    bucket_json="$COLLECT_OUT"
    merge_status row_status row_error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" = "OK" ]; then
      ver="$(printf '%s' "$bucket_json" | jq -r '.data."versioning" // "Disabled"' 2>/dev/null)"
    else
      ver="UNKNOWN"
    fi

    # Retention rules -> WORM / time-lock
    oci_capture "Object Storage retention rules [$b]" os retention-rule list \
      --bucket-name "$b" --namespace-name "$ns" --all
    rr_json="$COLLECT_OUT"
    merge_status row_status row_error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ] && [ "$COLLECT_STATUS" != "NOTFOUND" ]; then
      worm="UNKNOWN"; ret="UNKNOWN"
    elif printf '%s' "$rr_json" | jq -e '(.data.items? // .data // []) | length > 0' >/dev/null 2>&1; then
      # A rule with a time-locked lock is true immutability
      local locked
      locked="$(printf '%s' "$rr_json" | jq -r '[(.data.items? // .data // [])[]? | select(."time-rule-locked" != null)] | length' 2>/dev/null)"
      if [ "${locked:-0}" -gt 0 ]; then worm="LOCKED-WORM"; else worm="retention-unlocked"; fi
      ret="$(printf '%s' "$rr_json" | jq -r '[(.data.items? // .data // [])[]? | (."duration"."time-amount"|tostring)+" "+(."duration"."time-unit"//"")] | join("; ") // "rule-present"' 2>/dev/null)"
      [ -z "$ret" ] && ret="rule-present"
    else
      worm="NONE"; ret="none"
    fi

    # Finding: a bucket (potential backup store) with no second copy AND no immutability
    if [ "$row_status" != "OK" ]; then
      finding="COLLECTION-FAILED"
    elif [ "$repl" = "NO" ] && [ "$worm" = "NONE" ]; then
      finding="NO-REPLICA-NO-WORM"
    elif [ "$repl" = "NO" ]; then
      finding="NO-REPLICA"
    elif [ "$worm" = "NONE" ]; then
      finding="NO-WORM"
    else
      finding="OK"
    fi

    merge_status service_status service_error "$row_status" "$row_error"
    row "$comp" "ObjectStorage" "$b" "$repl" "$repl_target" "$ret" "$worm" "$ver" \
        "$finding" "CP-9(5)/CP-6" "$row_status" "$row_error"
  done <<< "$buckets"
  coverage_row "$comp" "ObjectStorage" "$count" "$service_status" "$service_error"
}

# ---------------------------------------------------------------------------
# 2. Block Volume replicas (cross-AD/region async replication)
# ---------------------------------------------------------------------------
check_volumes() {
  local comp="$1"
  local volumes_json replicas_json count=0 service_status="OK" service_error=""
  oci_capture "Block Volume list" bv volume list --compartment-id "$comp" --all
  volumes_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "BlockVolume" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-10"
    coverage_row "$comp" "BlockVolume" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi

  oci_capture "Block Volume replica list" bv block-volume-replica list \
    --compartment-id "$comp" --all
  replicas_json="$COLLECT_OUT"
  local replica_status="$COLLECT_STATUS" replica_error="$COLLECT_ERROR"
  merge_status service_status service_error "$replica_status" "$replica_error"

  while IFS= read -r v; do
    [ -z "$v" ] && continue
    count=$((count+1))
    local vid vname reps target finding row_status="OK" row_error=""
    vid="$(echo "$v" | jq -r '.id')"
    vname="$(echo "$v" | jq -r '."display-name" // "volume"')"
    merge_status row_status row_error "$replica_status" "$replica_error"
    if [ "$row_status" != "OK" ]; then
      row "$comp" "BlockVolume" "$vname" "UNKNOWN" "UNKNOWN" "n/a" "n/a" "n/a" \
          "COLLECTION-FAILED" "CP-9(5)/CP-10" "$row_status" "$row_error"
    else
      reps="$(printf '%s' "$replicas_json" | jq -r --arg vid "$vid" \
        '[(.data.items? // .data // [])[]? | select(."block-volume-id"==$vid) | ."availability-domain"] | join("; ")' 2>/dev/null)"
      if [ -n "$reps" ]; then
        finding="OK"; target="$reps"
        row "$comp" "BlockVolume" "$vname" "YES" "$target" "n/a" "n/a" "n/a" \
            "$finding" "CP-9(5)/CP-10" "OK" ""
      else
        row "$comp" "BlockVolume" "$vname" "NO" "none" "n/a" "n/a" "n/a" \
            "NO-VOLUME-REPLICA" "CP-9(5)/CP-10" "OK" ""
      fi
    fi
  done < <(printf '%s' "$volumes_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "BlockVolume" "$count" "$service_status" "$service_error"
}

# ---------------------------------------------------------------------------
# 3. Boot Volume replicas
# ---------------------------------------------------------------------------
check_bootvol() {
  local comp="$1"
  local ads_json ads count=0 service_status="OK" service_error=""
  oci_capture "Availability Domain list for boot volumes" iam availability-domain list \
    --compartment-id "$comp"
  ads_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "BootVolume" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-10"
    coverage_row "$comp" "BootVolume" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  ads="$(printf '%s' "$ads_json" | jq -r "$LIST_ITER | .name" 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local boot_json replica_json boot_status boot_error replica_status replica_error
    oci_capture "Boot Volume list [$ad]" bv boot-volume list --compartment-id "$comp" \
      --availability-domain "$ad" --all
    boot_json="$COLLECT_OUT"; boot_status="$COLLECT_STATUS"; boot_error="$COLLECT_ERROR"
    merge_status service_status service_error "$boot_status" "$boot_error"
    if [ "$boot_status" != "OK" ]; then
      collection_failure_row "$comp" "BootVolume" "$boot_status" "$boot_error" "CP-9(5)/CP-10"
      continue
    fi

    oci_capture "Boot Volume replica list [$ad]" bv boot-volume-replica list \
      --compartment-id "$comp" --availability-domain "$ad" --all
    replica_json="$COLLECT_OUT"; replica_status="$COLLECT_STATUS"; replica_error="$COLLECT_ERROR"
    merge_status service_status service_error "$replica_status" "$replica_error"

    while IFS= read -r v; do
      [ -z "$v" ] && continue
      count=$((count+1))
      local vid vname reps row_status="OK" row_error=""
      vid="$(echo "$v" | jq -r '.id')"
      vname="$(echo "$v" | jq -r '."display-name" // "boot-volume"')"
      merge_status row_status row_error "$replica_status" "$replica_error"
      if [ "$row_status" != "OK" ]; then
        row "$comp" "BootVolume" "$vname" "UNKNOWN" "UNKNOWN" "n/a" "n/a" "n/a" \
            "COLLECTION-FAILED" "CP-9(5)/CP-10" "$row_status" "$row_error"
      else
        reps="$(printf '%s' "$replica_json" | jq -r --arg vid "$vid" \
          '[(.data.items? // .data // [])[]? | select(."boot-volume-id"==$vid) | ."availability-domain"] | join("; ")' 2>/dev/null)"
        if [ -n "$reps" ]; then
          row "$comp" "BootVolume" "$vname" "YES" "$reps" "n/a" "n/a" "n/a" \
              "OK" "CP-9(5)/CP-10" "OK" ""
        else
          row "$comp" "BootVolume" "$vname" "NO" "none" "n/a" "n/a" "n/a" \
              "NO-VOLUME-REPLICA" "CP-9(5)/CP-10" "OK" ""
        fi
      fi
    done < <(printf '%s' "$boot_json" | jq -c "$LIST_ITER" 2>/dev/null)
  done <<< "$ads"
  coverage_row "$comp" "BootVolume" "$count" "$service_status" "$service_error"
}

# ---------------------------------------------------------------------------
# 4. Volume Backups — detect cross-region copies
# ---------------------------------------------------------------------------
check_backups() {
  local comp="$1"
  local backup_json count status error

  # Block volume backups
  oci_capture "Block Volume backup list" bv backup list --compartment-id "$comp" --all
  backup_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"; count=0
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "VolumeBackup" "$status" "$error" "CP-9(5)"
    coverage_row "$comp" "VolumeBackup" "UNKNOWN" "$status" "$error"
  else
  while IFS= read -r bk; do
    [ -z "$bk" ] && continue
    count=$((count+1))
    local name src expires repl
    name="$(echo "$bk" | jq -r '."display-name" // "backup"')"
    # A copied backup has source-volume-backup-id set; region copy shows in source-region if present
    src="$(echo "$bk" | jq -r '."source-volume-backup-id" // empty')"
    expires="$(echo "$bk" | jq -r '."expiration-time" // "no-expiry"')"
    if [ -n "$src" ]; then repl="COPY-OF-ANOTHER"; else repl="PRIMARY"; fi
    row "$comp" "VolumeBackup" "$name" "$repl" "src=${src:0:24}" "expires=$expires" \
        "n/a" "n/a" "INFO" "CP-9(5)" "OK" ""
  done < <(printf '%s' "$backup_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "VolumeBackup" "$count" "OK" ""
  fi

  # Boot volume backups
  oci_capture "Boot Volume backup list" bv boot-volume-backup list --compartment-id "$comp" --all
  backup_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"; count=0
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "BootVolumeBackup" "$status" "$error" "CP-9(5)"
    coverage_row "$comp" "BootVolumeBackup" "UNKNOWN" "$status" "$error"
  else
  while IFS= read -r bk; do
    [ -z "$bk" ] && continue
    count=$((count+1))
    local name src expires repl
    name="$(echo "$bk" | jq -r '."display-name" // "boot-backup"')"
    src="$(echo "$bk" | jq -r '."source-boot-volume-backup-id" // empty')"
    expires="$(echo "$bk" | jq -r '."expiration-time" // "no-expiry"')"
    if [ -n "$src" ]; then repl="COPY-OF-ANOTHER"; else repl="PRIMARY"; fi
    row "$comp" "BootVolumeBackup" "$name" "$repl" "src=${src:0:24}" "expires=$expires" \
        "n/a" "n/a" "INFO" "CP-9(5)" "OK" ""
  done < <(printf '%s' "$backup_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "BootVolumeBackup" "$count" "OK" ""
  fi
}

# ---------------------------------------------------------------------------
# 5. File Storage — replication + snapshot retention
# ---------------------------------------------------------------------------
check_fss() {
  local comp="$1"
  local ads_json ads count=0 service_status="OK" service_error=""
  oci_capture "Availability Domain list for FSS" iam availability-domain list \
    --compartment-id "$comp"
  ads_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "FSS" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-10"
    coverage_row "$comp" "FSS" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  ads="$(printf '%s' "$ads_json" | jq -r "$LIST_ITER | .name" 2>/dev/null)"
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local fs_json replication_json fs_status fs_error repl_status repl_error
    oci_capture "FSS file-system list [$ad]" fs file-system list --compartment-id "$comp" \
      --availability-domain "$ad" --all
    fs_json="$COLLECT_OUT"; fs_status="$COLLECT_STATUS"; fs_error="$COLLECT_ERROR"
    merge_status service_status service_error "$fs_status" "$fs_error"
    if [ "$fs_status" != "OK" ]; then
      collection_failure_row "$comp" "FSS" "$fs_status" "$fs_error" "CP-9(5)/CP-10"
      continue
    fi

    oci_capture "FSS replication list [$ad]" fs replication list --compartment-id "$comp" \
      --availability-domain "$ad" --all
    replication_json="$COLLECT_OUT"; repl_status="$COLLECT_STATUS"; repl_error="$COLLECT_ERROR"
    merge_status service_status service_error "$repl_status" "$repl_error"

    while IFS= read -r f; do
      [ -z "$f" ] && continue
      count=$((count+1))
      local fid fname target row_status="OK" row_error=""
      fid="$(echo "$f" | jq -r '.id')"
      fname="$(echo "$f" | jq -r '."display-name" // "filesystem"')"
      merge_status row_status row_error "$repl_status" "$repl_error"
      if [ "$row_status" != "OK" ]; then
        row "$comp" "FSS" "$fname" "UNKNOWN" "UNKNOWN" "snapshot-policy" "n/a" "n/a" \
            "COLLECTION-FAILED" "CP-9(5)/CP-10" "$row_status" "$row_error"
      else
        target="$(printf '%s' "$replication_json" | jq -r --arg fid "$fid" \
          '[(.data.items? // .data // [])[]? | select(."source-id"==$fid) | ."target-id"] | join("; ")' 2>/dev/null)"
        if [ -n "$target" ]; then
          row "$comp" "FSS" "$fname" "YES" "${target:0:32}" "snapshot-policy" "n/a" "n/a" \
              "OK" "CP-9(5)/CP-10" "OK" ""
        else
          row "$comp" "FSS" "$fname" "NO" "none" "snapshot-policy" "n/a" "n/a" \
              "NO-FSS-REPLICATION" "CP-9(5)/CP-10" "OK" ""
        fi
      fi
    done < <(printf '%s' "$fs_json" | jq -c "$LIST_ITER" 2>/dev/null)
  done <<< "$ads"
  coverage_row "$comp" "FSS" "$count" "$service_status" "$service_error"
}

# ---------------------------------------------------------------------------
# 6. Autonomous DB — retention + cross-region backup / Data Guard
# ---------------------------------------------------------------------------
check_adb() {
  local comp="$1"
  local adb_json count=0
  oci_capture "Autonomous Database list" db autonomous-database list \
    --compartment-id "$comp" --all
  adb_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "AutonomousDB" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-10"
    coverage_row "$comp" "AutonomousDB" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r a; do
    [ -z "$a" ] && continue
    count=$((count+1))
    local name ret dg peers finding
    name="$(echo "$a" | jq -r '."db-name" // "adb"')"
    ret="$(echo "$a" | jq -r '."backup-retention-period-in-days" // "default"')"
    # Cross-region peers / Data Guard
    peers="$(echo "$a" | jq -r '(."peer-db-ids" // []) | length' 2>/dev/null)"
    dg="$(echo "$a" | jq -r '."is-data-guard-enabled" // ."role" // "none"' 2>/dev/null)"
    if [ "${peers:-0}" -gt 0 ] || [ "$dg" = "true" ]; then
      finding="OK"; row "$comp" "AutonomousDB" "$name" "YES" "peers=$peers;dg=$dg" \
        "${ret}d" "n/a" "n/a" "$finding" "CP-9(5)/CP-10" "OK" ""
    else
      row "$comp" "AutonomousDB" "$name" "NO" "none" "${ret}d" "n/a" "n/a" \
        "NO-CROSS-REGION-COPY" "CP-9(5)/CP-10" "OK" ""
    fi
  done < <(printf '%s' "$adb_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "AutonomousDB" "$count" "OK" ""
}

# ---------------------------------------------------------------------------
# 7. Base DB — recovery window + Data Guard association
# ---------------------------------------------------------------------------
check_basedb() {
  local comp="$1"
  local systems_json count=0 service_status="OK" service_error=""
  oci_capture "Base DB system list" db system list --compartment-id "$comp" --all
  systems_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "BaseDB" "$COLLECT_STATUS" "$COLLECT_ERROR" "CP-9(5)/CP-10"
    coverage_row "$comp" "BaseDB" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r sysid; do
    [ -z "$sysid" ] && continue
    local db_json db_status db_error
    oci_capture "Base DB database list [${sysid: -12}]" db database list \
      --compartment-id "$comp" --db-system-id "$sysid" --all
    db_json="$COLLECT_OUT"; db_status="$COLLECT_STATUS"; db_error="$COLLECT_ERROR"
    merge_status service_status service_error "$db_status" "$db_error"
    if [ "$db_status" != "OK" ]; then
      row "$comp" "BaseDB" "db-system:${sysid: -12}" "UNKNOWN" "UNKNOWN" "UNKNOWN" \
          "n/a" "n/a" "COLLECTION-FAILED" "CP-9(5)/CP-10" "$db_status" "$db_error"
      continue
    fi
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      count=$((count+1))
      local name dbid ret dg row_status="OK" row_error=""
      name="$(echo "$d" | jq -r '."db-name" // "db"')"
      dbid="$(echo "$d" | jq -r '.id')"
      ret="$(echo "$d" | jq -r '."db-backup-config"."recovery-window-in-days" // "default"')"
      # Data Guard association = cross-site copy
      oci_capture "Base DB Data Guard list [$name]" db data-guard-association list \
        --database-id "$dbid" --all
      merge_status row_status row_error "$COLLECT_STATUS" "$COLLECT_ERROR"
      merge_status service_status service_error "$COLLECT_STATUS" "$COLLECT_ERROR"
      if [ "$row_status" != "OK" ]; then
        row "$comp" "BaseDB" "$name" "UNKNOWN" "UNKNOWN" "${ret}d" "n/a" "n/a" \
            "COLLECTION-FAILED" "CP-9(5)/CP-10" "$row_status" "$row_error"
        continue
      fi
      dg="$(printf '%s' "$COLLECT_OUT" | jq -r '(.data.items? // .data // []) | length' 2>/dev/null)"
      dg="${dg:-0}"
      if [ "$dg" -gt 0 ]; then
        row "$comp" "BaseDB" "$name" "YES" "data-guard-assoc=$dg" "${ret}d" "n/a" "n/a" \
            "OK" "CP-9(5)/CP-10" "OK" ""
      else
        row "$comp" "BaseDB" "$name" "NO" "none" "${ret}d" "n/a" "n/a" \
            "NO-DATA-GUARD" "CP-9(5)/CP-10" "OK" ""
      fi
    done < <(printf '%s' "$db_json" | jq -c "$LIST_ITER" 2>/dev/null)
  done < <(printf '%s' "$systems_json" | jq -r "$LIST_ITER | .id" 2>/dev/null)
  coverage_row "$comp" "BaseDB" "$count" "$service_status" "$service_error"
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  CUR_COMP="$comp"          # attribute any collection failure to this compartment
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"
  for svc in $SERVICES; do
    case "$svc" in
      object)  check_object  "$comp" ;;
      volumes) check_volumes "$comp" ;;
      bootvol) check_bootvol "$comp" ;;
      backups) check_backups "$comp" ;;
      fss)     check_fss     "$comp" ;;
      adb)     check_adb     "$comp" ;;
      basedb)  check_basedb  "$comp" ;;
      *) echo "    ! unknown service: $svc" ;;
    esac
  done
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "======================================================================"
echo "CP-9(5)/CP-10 BACKUP DR POSTURE SUMMARY"
echo "======================================================================"
TOTAL="$(($(wc -l < "$OUT") - 1))"
NO_REPLICA="$(awk -F',' 'NR>1 {gsub(/"/,"",$10);gsub(/"/,"",$12); if($12=="OK" && $10 ~ /NO-REPLICA|NO-VOLUME-REPLICA|NO-FSS-REPLICATION|NO-CROSS-REGION|NO-DATA-GUARD/) print}' "$OUT" | grep -c . || true)"
NO_WORM="$(awk -F',' 'NR>1 {gsub(/"/,"",$10);gsub(/"/,"",$12); if($12=="OK" && $10 ~ /NO-WORM/) print}' "$OUT" | grep -c . || true)"
BOTH="$(awk -F',' 'NR>1 {gsub(/"/,"",$10);gsub(/"/,"",$12); if($12=="OK" && $10=="NO-REPLICA-NO-WORM") print}' "$OUT" | grep -c . || true)"
INCOMPLETE_ROWS="$(awk -F',' 'NR>1 {gsub(/"/,"",$12); if($12!="OK") print}' "$OUT" | grep -c . || true)"

echo "Total resources evaluated       : $TOTAL"
echo "No second copy / replica        : $NO_REPLICA"
echo "No WORM/immutability (obj store): $NO_WORM"
echo "Neither replica nor WORM (worst): $BOTH"
echo "Rows not completely collected    : $INCOMPLETE_ROWS"
if [ "$BOTH" -gt 0 ]; then
  echo
  echo ">>> HIGHEST RISK — backup store with no replica AND no immutability:"
  awk -F',' 'NR>1 {gsub(/"/,"",$2);gsub(/"/,"",$3);gsub(/"/,"",$4);gsub(/"/,"",$10);
    if($10=="NO-REPLICA-NO-WORM") printf "  [%-16s] %-14s %s\n", $2, $3, $4}' "$OUT"
fi
echo
echo "Evidence CSV written to: $OUT"
echo "Coverage CSV written to: $COVERAGE"
echo
echo "NOTE: 'replicated' means a detectable second copy (Object Storage"
echo "replication policy, volume/boot replica, FSS replication, DB Data Guard"
echo "or ADB cross-region peer). Manual cross-region backup COPIES appear under"
echo "VolumeBackup rows as COPY-OF-ANOTHER. WORM/immutability applies to Object"
echo "Storage retention rules; LOCKED-WORM = time-locked (cannot be shortened)."

ERR_N="$(( $(wc -l < "$ERROUT") - 1 ))"; [ "$ERR_N" -lt 0 ] && ERR_N=0
if [ "$ERR_N" -gt 0 ] || [ "$INCOMPLETE" -ne 0 ] || [ "$INCOMPLETE_ROWS" -gt 0 ]; then
  echo
  echo "======================================================================"
  echo " WARNING — COLLECTION INCOMPLETE: $ERR_N failed call(s), $INCOMPLETE_ROWS affected row(s)"
  echo "======================================================================"
  echo " A failed call returns no rows, and a resource with no rows can look"
  echo " identical to one with no replica. Do NOT read absence as 'not"
  echo " replicated' for anything listed in:"
  echo "   $ERROUT"
  echo
  if [ "$ERR_N" -gt 0 ]; then
    awk -F'","' 'NR>1 {s=$3; c=$2; cmd=$4; if(length(cmd)>58) cmd=substr(cmd,1,55) "...";
          printf "   [%-15s] %-20s %s\n", s, c, cmd}' "$ERROUT" 2>/dev/null | head -20
  fi
  echo "======================================================================"
  exit 3
fi
rm -f "$ERROUT"   # nothing failed; no empty error file left behind
exit 0
