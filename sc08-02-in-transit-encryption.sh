#!/usr/bin/env bash
#
# sc08-02-in-transit-encryption.sh
# Collector ID: SC08-02
#
# SC-8 / SC-8(1) / SC-13 EVIDENCE — Encryption in transit
#
# Read-only OCI configuration sweep for TLS, native transport encryption and
# Site-to-Site VPN/IPSec. Designed for OCI Cloud Shell.
#
# Services:
#   lb       Load Balancer frontend TLS and backend-set SSL
#   nlb      Network Load Balancer passthrough (backend TLS is manual evidence)
#   adb      Autonomous Database TLS/mTLS posture
#   basedb   Base Database inventory (sqlnet.ora remains manual evidence)
#   object   Object Storage HTTPS/public-access posture
#   volumes  Block/boot volume paravirtualized in-transit encryption
#   fss      File Storage mount targets (encrypted mount remains manual evidence)
#   apigw    API Gateway HTTPS endpoint posture
#   oke      OKE Kubernetes API endpoint posture
#   ipsec    CPEs, IPSec connections/tunnels and DRG attachment/route context
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation. This Task 2 collector does not use the OCI
#   Python SDK.
#
# READ-ONLY: every OCI call is a list/get. The script never retrieves an IPSec
# pre-shared key. Nothing is created, modified, attached, detached or deleted.
#
# Usage:
#   bash sc08-02-in-transit-encryption.sh                         # interactive by default
#   bash sc08-02-in-transit-encryption.sh --select-scope
#   bash sc08-02-in-transit-encryption.sh -i
#   bash sc08-02-in-transit-encryption.sh -c <compartment-ocid>   # approved automation
#   bash sc08-02-in-transit-encryption.sh -n 'VCN,Shared Services,CD3' # approved automation
#   bash sc08-02-in-transit-encryption.sh -r us-langley-1
#   bash sc08-02-in-transit-encryption.sh -s 'lb ipsec'
#   bash sc08-02-in-transit-encryption.sh -o ./evidence      # writes into ./evidence/sc08-02/
#   bash sc08-02-in-transit-encryption.sh --selfcheck
#
# Interactive runs:
#   1. Discover the tenancy and active compartments.
#   2. Require the exact selected tenancy/compartment OCID twice.
#   3. Display the final region, scope, target compartments, services, local
#      output files and evidence sensitivity.
#   4. Start service collection only after the operator types exact uppercase
#      YES. Any other response aborts before the first service API call.
#
# Output:
#   sc08-02_intransit_encryption_<ts>.csv
#   sc08-02_intransit_encryption_coverage_<ts>.csv
#   sc08-02_intransit_encryption_collection_errors_<ts>.csv (failed calls only)
#
# Exit codes:
#   0  collection completed; findings still require review
#   1  collector could not start or establish scope
#   3  collection ran but at least one OCI call/evidence row is incomplete
#
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/lib/oci-scope-selector.sh"

readonly_selfcheck() {                                          # selfcheck-exempt
  local deny hits raw rawpat secret secretpat                   # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")         # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='(oci|oci_capture)[[:space:]].*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|bulk-upload|bulk-delete|reset|activate|deactivate|cancel)([[:space:]]|$)'  # selfcheck-exempt
  hits="$(grep -nE "$deny" "${check_paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"      # selfcheck-exempt
  rawpat="raw""-request"                                       # selfcheck-exempt
  raw="$(grep -nE "$rawpat" "${check_paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  secretpat='(oci|oci_capture)[[:space:]].*network[[:space:]]+ip-sec-psk[[:space:]]+get([[:space:]]|$)'  # selfcheck-exempt
  secret="$(grep -nE "$secretpat" "${check_paths[@]}" 2>/dev/null \
            | grep -v 'selfcheck-exempt' \
            | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"    # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ] || [ -n "$secret" ]; then  # selfcheck-exempt
    echo "READ-ONLY/NO-SECRET SELF-CHECK: FAILED — prohibited call found:" >&2
    printf '%s\n%s\n%s\n' "$hits" "$raw" "$secret" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if readonly_selfcheck; then
    echo "READ-ONLY/NO-SECRET SELF-CHECK: PASSED (sc08-02-in-transit-encryption)"
    echo "All OCI calls in $SCRIPT_PATH are list/get operations; ip-sec-psk get is prohibited."
    exit 0
  fi
  exit 1
fi

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found." >&2; exit 1; }
command -v mktemp >/dev/null 2>&1 || { echo "ERROR: mktemp not found." >&2; exit 1; }

[ -r "$SCOPE_HELPER" ] || { echo "ERROR: scope selector not found: $SCOPE_HELPER" >&2; exit 1; }
# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION_OVERRIDE=""
OUTDIR="."
TASK_DIR="sc08-02"
SERVICES="lb nlb adb basedb object volumes fss apigw oke ipsec"
SELECT_SCOPE=0

NORMALIZED_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --select-scope) SELECT_SCOPE=1 ;;
    *) NORMALIZED_ARGS+=("$arg") ;;
  esac
done
set -- "${NORMALIZED_ARGS[@]}"

while getopts "ic:n:r:s:o:h" opt; do
  case "$opt" in
    i) SELECT_SCOPE=1 ;;
    c) SINGLE_COMP="$OPTARG" ;;
    n) COMP_NAMES_FILTER="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help" >&2; exit 1 ;;
  esac
done

if [ "$SELECT_SCOPE" -eq 1 ] && { [ -n "$SINGLE_COMP" ] || [ -n "$COMP_NAMES_FILTER" ]; }; then
  echo "ERROR: --select-scope/-i cannot be combined with -c or -n." >&2
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

# A run without an explicit automation scope is always interactive. This
# prevents an accidental no-argument invocation from sweeping the tenancy.
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

for requested_service in $SERVICES; do
  case "$requested_service" in
    lb|nlb|adb|basedb|object|volumes|fss|apigw|oke|ipsec) ;;
    *) echo "ERROR: unknown service selector: $requested_service" >&2; exit 1 ;;
  esac
done

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
umask 077
mkdir -p -- "$OUTDIR" 2>/dev/null || { echo "ERROR: cannot create output directory: $OUTDIR" >&2; exit 1; }
readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUTDIR/sc08-02_intransit_encryption_${TS}.csv"
COVERAGE="$OUTDIR/sc08-02_intransit_encryption_coverage_${TS}.csv"
ERROUT="$OUTDIR/sc08-02_intransit_encryption_collection_errors_${TS}.csv"

init_output_file() {
  local path="$1" header="$2"
  if ! (set -C; printf '%s\n' "$header" > "$path") 2>/dev/null; then
    echo "ERROR: refusing to overwrite an existing output path: $path" >&2
    exit 1
  fi
}

init_output_file "$OUT" "compartment_id,compartment_name,service,resource,encryption_enabled,protocol_or_min_version,cipher_or_detail,finding,control,collection_status,collection_error"
init_output_file "$COVERAGE" "compartment_id,compartment_name,service,assets_found,collection_status,collection_error"
init_output_file "$ERROUT" "compartment_id,compartment_name,status,command,error"

INCOMPLETE=0
CUR_COMP="<tenancy>"
COLLECT_OUT=""
COLLECT_STATUS="OK"
COLLECT_ERROR=""
TEMP_ERR_FILE=""
declare -A COMP_NAME

cleanup_temp_file() {
  if [ -n "$TEMP_ERR_FILE" ]; then
    rm -f -- "$TEMP_ERR_FILE" 2>/dev/null
    TEMP_ERR_FILE=""
  fi
}
trap cleanup_temp_file EXIT
trap 'cleanup_temp_file; exit 130' INT
trap 'cleanup_temp_file; exit 143' TERM

csv_escape() {
  local value="$1"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/}"
  case "$value" in [=+@-]*) value="'$value" ;; esac
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

has_cli_arg() {
  local wanted="$1"; shift
  local item
  for item in "$@"; do
    [ "$item" = "$wanted" ] && return 0
  done
  return 1
}

oci_capture() {
  local label="$1"; shift
  local errf out rc err status cname cmd action
  errf="$(mktemp "${TMPDIR:-/tmp}/sc8.XXXXXX" 2>/dev/null)" || {
    echo "ERROR: could not create a secure temporary error file." >&2
    exit 1
  }
  TEMP_ERR_FILE="$errf"
  out="$(oci "${REGION_ARG[@]}" "$@" 2>"$errf")"; rc=$?
  err="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-300)"
  rm -f -- "$errf" 2>/dev/null
  TEMP_ERR_FILE=""

  # A successful CLI return with malformed or schema-incompatible JSON must
  # not be counted as a verified zero-resource result.
  if [ "$rc" -eq 0 ] && ! has_cli_arg --raw-output "$@"; then
    if ! printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
      rc=65
      err="OCI CLI returned invalid JSON for: $label"
    else
      action="${3:-}"
      if [ "$action" = "list" ] && ! has_cli_arg --query "$@" && \
         ! printf '%s' "$out" | jq -e \
           '(.data|type)=="array" or ((.data|type)=="object" and (.data.items|type)=="array")' \
           >/dev/null 2>&1; then
        rc=65
        err="OCI CLI list response had an unexpected data shape for: $label"
      elif [ "$action" = "get" ] && ! has_cli_arg --query "$@" && \
           ! printf '%s' "$out" | jq -e 'type=="object" and has("data")' >/dev/null 2>&1; then
        rc=65
        err="OCI CLI get response had no data object for: $label"
      fi
    fi
  fi

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
    INCOMPLETE=1
    cname="${COMP_NAME[$CUR_COMP]:-<unknown>}"
    cmd="$label :: $*"
    printf '%s,%s,%s,%s,%s\n' \
      "$(csv_escape "$CUR_COMP")" "$(csv_escape "$cname")" \
      "$(csv_escape "$status")" "$(csv_escape "$cmd")" \
      "$(csv_escape "$err")" >> "$ERROUT"
  fi
  COLLECT_OUT="$out"
  COLLECT_STATUS="$status"
  COLLECT_ERROR="$err"
}

LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

row() {
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local output="" field escaped
  for field in "$comp_id" "$cname" "$@"; do
    escaped="$(csv_escape "$field")"
    output+="${escaped},"
  done
  echo "${output%,}" >> "$OUT"
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
  local comp="$1" service="$2" resource="$3" status="$4" error="$5" control="$6"
  INCOMPLETE=1
  row "$comp" "$service" "$resource" "UNKNOWN" "UNKNOWN" "UNKNOWN" \
    "COLLECTION-FAILED" "$control" "$status" "$error"
}

abort_before_scan() {
  local reason="$1"
  rm -f -- "$OUT" "$COVERAGE" "$ERROUT" 2>/dev/null
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

sc8_service_label() {
  case "$1" in
    lb) printf 'Load Balancer frontend and backend TLS' ;;
    nlb) printf 'Network Load Balancer passthrough inventory' ;;
    adb) printf 'Autonomous Database TLS/mTLS' ;;
    basedb) printf 'Base Database inventory (sqlnet.ora manual)' ;;
    object) printf 'Object Storage HTTPS/public exposure' ;;
    volumes) printf 'Block/boot volume in-transit encryption' ;;
    fss) printf 'File Storage mount targets (client proof manual)' ;;
    apigw) printf 'API Gateway HTTPS endpoints' ;;
    oke) printf 'OKE Kubernetes API endpoints' ;;
    ipsec) printf 'CPE, IPSec tunnels and DRG context (no PSKs)' ;;
  esac
}

confirm_sc8_scan_plan() {
  local scope_type scope_name scope_ocid approval svc cid
  if [ "$SELECT_SCOPE" -eq 1 ]; then
    scope_type="$OCI_SCOPE_SELECTED_KIND"
    scope_name="$OCI_SCOPE_SELECTED_NAME"
    scope_ocid="$OCI_SCOPE_SELECTED_OCID"
  elif [ -n "$SINGLE_COMP" ]; then
    scope_type="AUTOMATION-COMPARTMENT"
    scope_name="${COMP_NAME[$SINGLE_COMP]:-<unknown>}"
    scope_ocid="$SINGLE_COMP"
  else
    scope_type="AUTOMATION-NAME-FILTER"
    scope_name="$COMP_NAMES_FILTER"
    scope_ocid="multiple resolved compartment OCIDs"
  fi

  echo "======================================================================"
  echo "SC-8 PRE-SCAN SAFETY SUMMARY"
  echo "======================================================================"
  echo "Collector       : sc08-02-in-transit-encryption.sh"
  echo "Controls        : SC-8 / SC-8(1) / SC-13"
  echo "Region          : ${REGION_OVERRIDE:-<cloud-shell-default>}"
  echo "Scope type      : $scope_type"
  echo "Scope name      : $scope_name"
  echo "Confirmed OCID  : $scope_ocid"
  echo "Compartments    : $COMP_COUNT"
  echo "Cloud operations: OCI list/get only; no creates, updates or deletes"
  echo "Secret access   : PROHIBITED — network ip-sec-psk get is never called"
  echo "Local writes    : private CSVs plus ephemeral secure stderr temp files"
  echo "Evidence data   : OCIDs, resource names, endpoints, public CPE IPs,"
  echo "                  routes and negotiated IPSec/TLS configuration"
  echo
  echo "Target compartments:"
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    echo "  - ${COMP_NAME[$cid]:-<unknown>}"
    echo "    $cid"
  done <<< "$COMPS"
  echo
  echo "Requested service scans:"
  if [ -z "$SERVICES" ]; then
    echo "  - <none> (scope/approval test only)"
  else
    for svc in $SERVICES; do
      echo "  - $svc — $(sc8_service_label "$svc")"
    done
  fi
  echo
  echo "Output files:"
  echo "  - $OUT"
  echo "  - $COVERAGE"
  echo "  - $ERROUT (retained only when calls fail)"
  echo "======================================================================"

  if [ "$SELECT_SCOPE" -eq 1 ]; then
    echo "Scope discovery is complete. No SC-8 service scan has started."
    echo "Type exact uppercase YES to run this scan. Any other response aborts."
    IFS= read -r approval || abort_before_scan "approval input was not provided"
    [ "$approval" = "YES" ] || abort_before_scan "operator did not enter exact uppercase YES"
    echo "SCAN APPROVED: starting read-only SC-8 service collection."
    echo
  else
    echo "Approval mode   : approved non-interactive scope supplied with -c or -n"
    echo
  fi
}

# Resolve tenancy and collection scope.
oci_capture "resolve tenancy" iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$COLLECT_OUT"
[ -z "$TENANCY_ID" ] || [ "$TENANCY_ID" = "null" ] && {
  echo "ERROR: could not resolve tenancy ($COLLECT_STATUS): $COLLECT_ERROR" >&2
  echo "Collection errors retained in: $ERROUT" >&2
  exit 1
}
COMP_NAME["$TENANCY_ID"]="root"
CUR_COMP="$TENANCY_ID"

echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: $TENANCY_ID"
echo "Scope  : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'command-line/default')"
echo

if [ "$SELECT_SCOPE" -eq 1 ]; then
  CUR_COMP="$TENANCY_ID"
  oci_capture "discover active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    echo "ERROR: compartment discovery failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  fi

  scope_catalog="$(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps="${discovered_comps}${cid}"$'\n'
  done <<< "$scope_catalog"

  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  if [ "$COLLECT_STATUS" != "OK" ]; then
    echo "ERROR: tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  fi
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
  if [ "$COLLECT_STATUS" != "OK" ]; then
    abort_before_scan "explicit compartment validation failed ($COLLECT_STATUS): $COLLECT_ERROR"
  fi
  COMP_NAME["$SINGLE_COMP"]="${COLLECT_OUT:-<unknown>}"
else
  oci_capture "enumerate active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE \
    --all --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    echo "ERROR: compartment enumeration failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    echo "Collection errors retained in: $ERROUT" >&2
    exit 1
  fi
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
  done < <(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)
  COMPS="$(printf '%s' "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"
  CUR_COMP="$TENANCY_ID"
  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  COMP_NAME["$TENANCY_ID"]="${COLLECT_OUT:-root}"
  COMPS="$TENANCY_ID"$'\n'"$COMPS"
fi

if [ -n "$COMP_NAMES_FILTER" ]; then
  FILTERED_COMPS=""
  IFS=',' read -ra requested_names <<< "$COMP_NAMES_FILTER"
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    cname="${COMP_NAME[$cid]:-<unknown>}"
    for requested_name in "${requested_names[@]}"; do
      requested_name="$(printf '%s' "$requested_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ -n "$requested_name" ] && [ "$(printf '%s' "$cname" | tr '[:upper:]' '[:lower:]')" = "$(printf '%s' "$requested_name" | tr '[:upper:]' '[:lower:]')" ]; then
        FILTERED_COMPS+="${FILTERED_COMPS:+$'\n'}$cid"
        break
      fi
    done
  done <<< "$COMPS"
  COMPS="$FILTERED_COMPS"
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -eq 0 ] && abort_before_scan "no compartments matched the requested scope"

confirm_sc8_scan_plan

echo "Collecting SC-8 evidence across $COMP_COUNT compartment(s)..."
echo

check_lb() {
  local comp="$1" lbs_json count_front=0 count_back=0
  local front_status="OK" front_error="" back_status="OK" back_error=""
  oci_capture "Load Balancer list" lb load-balancer list --compartment-id "$comp" --all
  lbs_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "LoadBalancerFrontend" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    collection_failure_row "$comp" "LoadBalancerBackend" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "LoadBalancerFrontend" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    coverage_row "$comp" "LoadBalancerBackend" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi

  while IFS= read -r lb; do
    [ -z "$lb" ] && continue
    local lbid lbname listeners_json child_status child_error backends_json
    lbid="$(printf '%s' "$lb" | jq -r '.id')"
    lbname="$(printf '%s' "$lb" | jq -r '."display-name" // "load-balancer"')"

    oci_capture "Load Balancer listener list [$lbname]" lb listener list \
      --load-balancer-id "$lbid" --all
    listeners_json="$COLLECT_OUT"; child_status="$COLLECT_STATUS"; child_error="$COLLECT_ERROR"
    merge_status front_status front_error "$child_status" "$child_error"
    if [ "$child_status" != "OK" ]; then
      collection_failure_row "$comp" "LoadBalancerFrontend" "$lbname/<listeners>" "$child_status" "$child_error" "SC-8(1)"
    else
      while IFS= read -r listener; do
        [ -z "$listener" ] && continue
        count_front=$((count_front+1))
        local lname proto ssl minver cipher finding
        lname="$(printf '%s' "$listener" | jq -r '.name // "listener"')"
        proto="$(printf '%s' "$listener" | jq -r '.protocol // "unknown"')"
        ssl="$(printf '%s' "$listener" | jq -r '."ssl-configuration" // empty')"
        if [ -n "$ssl" ]; then
          minver="$(printf '%s' "$listener" | jq -r '(."ssl-configuration".protocols // ["managed"]) | if type=="array" then join(";") else tostring end')"
          cipher="$(printf '%s' "$listener" | jq -r '."ssl-configuration"."cipher-suite-name" // "default"')"
          if printf '%s' "$minver" | grep -Eq 'TLSv1(\.0|\.1)(;|$)'; then finding="WEAK-TLS-VERSION"; else finding="OK"; fi
          row "$comp" "LoadBalancerFrontend" "$lbname/$lname" "YES" "$minver" "$cipher" "$finding" "SC-8(1)" "OK" ""
        else
          row "$comp" "LoadBalancerFrontend" "$lbname/$lname" "NO" "$proto" "no-ssl-configuration" "PLAINTEXT-LISTENER" "SC-8(1)" "OK" ""
        fi
      done < <(printf '%s' "$listeners_json" | jq -c "$LIST_ITER" 2>/dev/null)
    fi

    oci_capture "Load Balancer backend-set list [$lbname]" lb backend-set list \
      --load-balancer-id "$lbid" --all
    backends_json="$COLLECT_OUT"; child_status="$COLLECT_STATUS"; child_error="$COLLECT_ERROR"
    merge_status back_status back_error "$child_status" "$child_error"
    if [ "$child_status" != "OK" ]; then
      collection_failure_row "$comp" "LoadBalancerBackend" "$lbname/<backend-sets>" "$child_status" "$child_error" "SC-8(1)"
    else
      while IFS= read -r backend; do
        [ -z "$backend" ] && continue
        count_back=$((count_back+1))
        local bname ssl verify detail finding
        bname="$(printf '%s' "$backend" | jq -r '.name // "backend-set"')"
        ssl="$(printf '%s' "$backend" | jq -r '."ssl-configuration" // empty')"
        if [ -n "$ssl" ]; then
          verify="$(printf '%s' "$backend" | jq -r '."ssl-configuration"."verify-peer-certificate" // false')"
          detail="verify-peer-certificate=$verify"
          if [ "$verify" = "true" ]; then
            finding="OK"
          else
            finding="REVIEW-BACKEND-CERT-VERIFY-DISABLED"
          fi
          row "$comp" "LoadBalancerBackend" "$lbname/$bname" "YES" "TLS" "$detail" "$finding" "SC-8(1)" "OK" ""
        else
          row "$comp" "LoadBalancerBackend" "$lbname/$bname" "NO" "plaintext" "no-backend-ssl-configuration" "BACKEND-PLAINTEXT" "SC-8(1)" "OK" ""
        fi
      done < <(printf '%s' "$backends_json" | jq -c "$LIST_ITER" 2>/dev/null)
    fi
  done < <(printf '%s' "$lbs_json" | jq -c "$LIST_ITER" 2>/dev/null)

  coverage_row "$comp" "LoadBalancerFrontend" "$count_front" "$front_status" "$front_error"
  coverage_row "$comp" "LoadBalancerBackend" "$count_back" "$back_status" "$back_error"
}

check_nlb() {
  local comp="$1" nlbs_json count=0 service_status="OK" service_error=""
  oci_capture "Network Load Balancer list" nlb network-load-balancer list --compartment-id "$comp" --all
  nlbs_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "NetworkLB" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "NetworkLB" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r nlb; do
    [ -z "$nlb" ] && continue
    local nid nname listeners_json status error
    nid="$(printf '%s' "$nlb" | jq -r '.id')"
    nname="$(printf '%s' "$nlb" | jq -r '."display-name" // "network-lb"')"
    oci_capture "Network Load Balancer listener list [$nname]" nlb listener list \
      --network-load-balancer-id "$nid" --all
    listeners_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
    merge_status service_status service_error "$status" "$error"
    if [ "$status" != "OK" ]; then
      collection_failure_row "$comp" "NetworkLB" "$nname/<listeners>" "$status" "$error" "SC-8(1)"
      continue
    fi
    while IFS= read -r listener; do
      [ -z "$listener" ] && continue
      count=$((count+1))
      local lname proto
      lname="$(printf '%s' "$listener" | jq -r '.name // "listener"')"
      proto="$(printf '%s' "$listener" | jq -r '.protocol // "unknown"')"
      row "$comp" "NetworkLB" "$nname/$lname" "UNKNOWN" "backend-terminated" \
        "listener-protocol=$proto; capture backend TLS evidence" "MANUAL-EVIDENCE-NLB-BACKEND" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$listeners_json" | jq -c "$LIST_ITER" 2>/dev/null)
  done < <(printf '%s' "$nlbs_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "NetworkLB" "$count" "$service_status" "$service_error"
}

check_adb() {
  local comp="$1" json count=0
  oci_capture "Autonomous Database list" db autonomous-database list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "AutonomousDB" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)/SC-13"
    coverage_row "$comp" "AutonomousDB" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r adb; do
    [ -z "$adb" ] && continue
    count=$((count+1))
    local name mtls profiles detail finding
    name="$(printf '%s' "$adb" | jq -r '."db-name" // "autonomous-db"')"
    mtls="$(printf '%s' "$adb" | jq -r '."is-mtls-connection-required" // "unknown"')"
    profiles="$(printf '%s' "$adb" | jq -r '[(."connection-strings".profiles // [])[]? | select(."tls-authentication"=="SERVER" or ."tls-authentication"=="MUTUAL")] | length')"
    if [ "$mtls" = "true" ]; then detail="mTLS-required"; finding="OK"
    elif [ "${profiles:-0}" -gt 0 ]; then detail="TLS-available;mTLS-optional"; finding="OK-REVIEW-MTLS"
    else detail="connection-profile-not-confirmed"; finding="REVIEW-TLS-PROFILE"; fi
    row "$comp" "AutonomousDB" "$name" "YES" "TLS1.2+" "$detail" "$finding" "SC-8(1)/SC-13" "OK" ""
  done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "AutonomousDB" "$count" "OK" ""
}

check_basedb() {
  local comp="$1" json count=0
  oci_capture "Base Database system list" db system list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "BaseDB" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "BaseDB" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r dbs; do
    [ -z "$dbs" ] && continue
    count=$((count+1))
    local name
    name="$(printf '%s' "$dbs" | jq -r '."display-name" // "db-system"')"
    row "$comp" "BaseDB" "$name" "UNKNOWN" "Oracle Net TLS/NNE" \
      "capture sqlnet.ora; require SQLNET.ENCRYPTION_SERVER=REQUIRED or approved TCPS" \
      "MANUAL-EVIDENCE-SQLNET" "SC-8(1)" "OK" ""
  done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "BaseDB" "$count" "OK" ""
}

check_object() {
  local comp="$1" ns buckets_json count=0 service_status="OK" service_error=""
  oci_capture "Object Storage namespace" os ns get --raw-output --query data
  ns="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ] || [ -z "$ns" ]; then
    local status="${COLLECT_STATUS}" error="${COLLECT_ERROR:-Object Storage namespace was empty}"
    [ "$status" = "OK" ] && status="ERROR"
    collection_failure_row "$comp" "ObjectStorage" "<collection>" "$status" "$error" "SC-8/SC-13"
    coverage_row "$comp" "ObjectStorage" "UNKNOWN" "$status" "$error"
    return
  fi
  oci_capture "Object Storage bucket list" os bucket list --compartment-id "$comp" \
    --namespace-name "$ns" --all
  buckets_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "ObjectStorage" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8/SC-13"
    coverage_row "$comp" "ObjectStorage" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r bucket; do
    [ -z "$bucket" ] && continue
    count=$((count+1))
    local name get_json status error public finding
    name="$(printf '%s' "$bucket" | jq -r '.name')"
    oci_capture "Object Storage bucket get [$name]" os bucket get --bucket-name "$name" --namespace-name "$ns"
    get_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
    merge_status service_status service_error "$status" "$error"
    if [ "$status" != "OK" ]; then
      collection_failure_row "$comp" "ObjectStorage" "$name" "$status" "$error" "SC-8/SC-13"
      continue
    fi
    public="$(printf '%s' "$get_json" | jq -r '.data."public-access-type" // "NoPublicAccess"')"
    if [ "$public" = "NoPublicAccess" ]; then finding="OK"; else finding="PUBLIC-ACCESS-REVIEW"; fi
    row "$comp" "ObjectStorage" "$name" "YES" "HTTPS/TLS1.2+" "public-access=$public" "$finding" "SC-8/SC-13" "OK" ""
  done < <(printf '%s' "$buckets_json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "ObjectStorage" "$count" "$service_status" "$service_error"
}

check_volumes() {
  local comp="$1" json count=0
  oci_capture "Block Volume attachment list" compute volume-attachment list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "BlockVolumeAttach" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "BlockVolumeAttach" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  else
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      count=$((count+1))
      local vid iid enabled finding
      vid="$(printf '%s' "$item" | jq -r '."volume-id" // "unknown-volume"')"
      iid="$(printf '%s' "$item" | jq -r '."instance-id" // "unknown-instance"')"
      enabled="$(printf '%s' "$item" | jq -r 'if has("is-pv-encryption-in-transit-enabled") then ."is-pv-encryption-in-transit-enabled" else "unknown" end')"
      if [ "$enabled" = "true" ]; then finding="OK"
      elif [ "$enabled" = "false" ]; then finding="IN-TRANSIT-ENC-DISABLED"
      else finding="REVIEW-IN-TRANSIT-ENC-NOT-EXPOSED"; fi
      row "$comp" "BlockVolumeAttach" "vol:${vid: -12}/inst:${iid: -12}" "$enabled" "PV-in-transit" "attachment" "$finding" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
    coverage_row "$comp" "BlockVolumeAttach" "$count" "OK" ""
  fi

  count=0
  oci_capture "Compute instance list" compute instance list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "InstanceBootVol" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "InstanceBootVol" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  else
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      count=$((count+1))
      local name enabled finding
      name="$(printf '%s' "$item" | jq -r '."display-name" // "instance"')"
      enabled="$(printf '%s' "$item" | jq -r 'if ((."launch-options"|type)=="object" and (."launch-options"|has("is-pv-encryption-in-transit-enabled"))) then ."launch-options"."is-pv-encryption-in-transit-enabled" else "unknown" end')"
      if [ "$enabled" = "true" ]; then finding="OK"
      elif [ "$enabled" = "false" ]; then finding="BOOT-IN-TRANSIT-ENC-DISABLED"
      else finding="REVIEW-BOOT-IN-TRANSIT-ENC-NOT-EXPOSED"; fi
      row "$comp" "InstanceBootVol" "$name" "$enabled" "PV-in-transit" "launch-option" "$finding" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
    coverage_row "$comp" "InstanceBootVol" "$count" "OK" ""
  fi
}

check_fss() {
  local comp="$1" ads_json count=0 service_status="OK" service_error=""
  oci_capture "Availability Domain list for FSS" iam availability-domain list --compartment-id "$comp"
  ads_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "FSS-MountTarget" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "FSS-MountTarget" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    local json status error
    oci_capture "FSS mount-target list [$ad]" fs mount-target list --compartment-id "$comp" \
      --availability-domain "$ad" --all
    json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
    merge_status service_status service_error "$status" "$error"
    if [ "$status" != "OK" ]; then
      collection_failure_row "$comp" "FSS-MountTarget" "$ad/<collection>" "$status" "$error" "SC-8(1)"
      continue
    fi
    while IFS= read -r target; do
      [ -z "$target" ] && continue
      count=$((count+1))
      local name
      name="$(printf '%s' "$target" | jq -r '."display-name" // "mount-target"')"
      row "$comp" "FSS-MountTarget" "$name" "UNKNOWN" "TLS via oci-fss-utils" \
        "capture client mount output and encrypted mount option" "MANUAL-EVIDENCE-FSS-MOUNT" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
  done < <(printf '%s' "$ads_json" | jq -r "$LIST_ITER | .name" 2>/dev/null)
  coverage_row "$comp" "FSS-MountTarget" "$count" "$service_status" "$service_error"
}

check_apigw() {
  local comp="$1" json count=0
  oci_capture "API Gateway list" api-gateway gateway list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "APIGateway" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "APIGateway" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r gw; do
    [ -z "$gw" ] && continue
    count=$((count+1))
    local name host cas
    name="$(printf '%s' "$gw" | jq -r '."display-name" // "gateway"')"
    host="$(printf '%s' "$gw" | jq -r '.hostname // "n/a"')"
    cas="$(printf '%s' "$gw" | jq -r '(."ca-bundles" // []) | length')"
    row "$comp" "APIGateway" "$name" "YES" "HTTPS/TLS1.2+" "endpoint=$host;ca-bundles=$cas" "OK" "SC-8(1)" "OK" ""
  done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "APIGateway" "$count" "OK" ""
}

check_oke() {
  local comp="$1" json count=0
  oci_capture "OKE cluster list" ce cluster list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "OKE-Cluster" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "OKE-Cluster" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r cluster; do
    [ -z "$cluster" ] && continue
    count=$((count+1))
    local name public
    name="$(printf '%s' "$cluster" | jq -r '.name // "cluster"')"
    public="$(printf '%s' "$cluster" | jq -r '."endpoint-config"."is-public-ip-enabled" // "unknown"')"
    row "$comp" "OKE-Cluster" "$name" "YES" "HTTPS/TLS1.2+" "public-endpoint=$public" "OK-REVIEW-EXPOSURE" "SC-8(1)" "OK" ""
  done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
  coverage_row "$comp" "OKE-Cluster" "$count" "OK" ""
}

ipsec_finding() {
  local tunnel="$1" status lifecycle ike p1 p2 parameters
  status="$(printf '%s' "$tunnel" | jq -r '.status // "UNKNOWN"')"
  lifecycle="$(printf '%s' "$tunnel" | jq -r '."lifecycle-state" // .state // "UNKNOWN"')"
  ike="$(printf '%s' "$tunnel" | jq -r '."ike-version" // "UNKNOWN"')"
  p1="$(printf '%s' "$tunnel" | jq -r '."phase-one-details"."is-ike-established" // "unknown"')"
  p2="$(printf '%s' "$tunnel" | jq -r '."phase-two-details"."is-esp-established" // "unknown"')"
  parameters="$(printf '%s' "$tunnel" | jq -r '[
    ."phase-one-details"."negotiated-authentication-algorithm",
    ."phase-one-details"."negotiated-encryption-algorithm",
    ."phase-one-details"."negotiated-dh-group",
    ."phase-two-details"."negotiated-authentication-algorithm",
    ."phase-two-details"."negotiated-encryption-algorithm",
    ."phase-two-details"."negotiated-dh-group"
  ] | map(select(. != null)) | join(";")')"
  if [ "$lifecycle" != "AVAILABLE" ] && [ "$lifecycle" != "UNKNOWN" ]; then
    printf 'TUNNEL-LIFECYCLE-%s' "$lifecycle"
  elif [ "$status" != "UP" ]; then
    printf 'TUNNEL-DOWN'
  elif [ "$p1" = "false" ]; then
    printf 'IKE-NOT-ESTABLISHED'
  elif [ "$p2" = "false" ]; then
    printf 'ESP-NOT-ESTABLISHED'
  elif printf '%s' "$parameters" | grep -qiE '(^|;)(3DES|DES|GROUP2|GROUP5|SHA1|HMAC_SHA1)($|;)'; then
    printf 'WEAK-IPSEC-PARAMETERS'
  elif [ "$ike" = "V1" ]; then
    printf 'IKEV1-REVIEW'
  elif [ "$p1" = "unknown" ] || [ "$p2" = "unknown" ] || [ -z "$parameters" ]; then
    printf 'OK-REVIEW-NEGOTIATED-PARAMETERS'
  else
    printf 'OK'
  fi
}

check_ipsec() {
  local comp="$1" json count=0

  # CPE inventory. The public headend address is evidence-sensitive; store the
  # generated CSV only in the approved restricted evidence location.
  oci_capture "CPE list" network cpe list --compartment-id "$comp" --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "CPE" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "CPE" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  else
    while IFS= read -r cpe; do
      [ -z "$cpe" ] && continue
      count=$((count+1))
      local name ip vendor
      name="$(printf '%s' "$cpe" | jq -r '."display-name" // "cpe"')"
      ip="$(printf '%s' "$cpe" | jq -r '."ip-address" // "unknown"')"
      vendor="$(printf '%s' "$cpe" | jq -r '."cpe-device-shape-id" // "not-recorded"')"
      row "$comp" "CPE" "$name" "CONFIGURED" "IPSec peer" "public-ip=$ip;device-shape=$vendor" "INFO" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
    coverage_row "$comp" "CPE" "$count" "OK" ""
  fi

  # IPSec connections and their two tunnel objects.
  local conns_json conn_count=0 tunnel_count=0
  local conn_status="OK" conn_error="" tunnel_status="OK" tunnel_error="" tunnel_count_unknown=0
  oci_capture "IPSec connection list" network ip-sec-connection list --compartment-id "$comp" --all
  conns_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "IPSecConnection" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    collection_failure_row "$comp" "IPSecTunnel" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "IPSecConnection" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    coverage_row "$comp" "IPSecTunnel" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  else
    while IFS= read -r conn; do
      [ -z "$conn" ] && continue
      conn_count=$((conn_count+1))
      local id name get_json status error drg cpe routes lifecycle tunnels_json connection_tunnel_count=0
      id="$(printf '%s' "$conn" | jq -r '.id')"
      name="$(printf '%s' "$conn" | jq -r '."display-name" // "ipsec-connection"')"
      oci_capture "IPSec connection get [$name]" network ip-sec-connection get --ipsc-id "$id"
      get_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
      merge_status conn_status conn_error "$status" "$error"
      if [ "$status" != "OK" ]; then
        collection_failure_row "$comp" "IPSecConnection" "$name" "$status" "$error" "SC-8(1)"
      else
        drg="$(printf '%s' "$get_json" | jq -r '.data."drg-id" // "unknown"')"
        cpe="$(printf '%s' "$get_json" | jq -r '.data."cpe-id" // "unknown"')"
        routes="$(printf '%s' "$get_json" | jq -r '(.data."static-routes" // []) | join(";")')"
        lifecycle="$(printf '%s' "$get_json" | jq -r '.data."lifecycle-state" // "unknown"')"
        row "$comp" "IPSecConnection" "$name" "CONFIGURED" "IKE/IPSec" \
          "lifecycle=$lifecycle;drg=${drg: -16};cpe=${cpe: -16};static-routes=${routes:-none}" \
          "OK-REVIEW-TUNNELS" "SC-8(1)" "OK" ""
      fi

      oci_capture "IPSec tunnel list [$name]" network ip-sec-tunnel list --ipsc-id "$id" --all
      tunnels_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
      merge_status tunnel_status tunnel_error "$status" "$error"
      if [ "$status" != "OK" ]; then
        tunnel_count_unknown=1
        collection_failure_row "$comp" "IPSecTunnel" "$name/<tunnels>" "$status" "$error" "SC-8(1)"
        continue
      fi
      while IFS= read -r tunnel; do
        [ -z "$tunnel" ] && continue
        tunnel_count=$((tunnel_count+1))
        connection_tunnel_count=$((connection_tunnel_count+1))
        local tname tid ike tstatus tlifecycle routing bgp p1auth p1enc p1dh p2auth p2enc p2dh pfs updated finding enabled detail
        tname="$(printf '%s' "$tunnel" | jq -r '."display-name" // "tunnel"')"
        tid="$(printf '%s' "$tunnel" | jq -r '.id // "unknown"')"
        ike="$(printf '%s' "$tunnel" | jq -r '."ike-version" // "unknown"')"
        tstatus="$(printf '%s' "$tunnel" | jq -r '.status // "UNKNOWN"')"
        tlifecycle="$(printf '%s' "$tunnel" | jq -r '."lifecycle-state" // .state // "UNKNOWN"')"
        routing="$(printf '%s' "$tunnel" | jq -r '.routing // "unknown"')"
        bgp="$(printf '%s' "$tunnel" | jq -r '."bgp-session-info"."bgp-state" // "n/a"')"
        p1auth="$(printf '%s' "$tunnel" | jq -r '."phase-one-details"."negotiated-authentication-algorithm" // ."phase-one-details"."custom-authentication-algorithm" // "default"')"
        p1enc="$(printf '%s' "$tunnel" | jq -r '."phase-one-details"."negotiated-encryption-algorithm" // ."phase-one-details"."custom-encryption-algorithm" // "default"')"
        p1dh="$(printf '%s' "$tunnel" | jq -r '."phase-one-details"."negotiated-dh-group" // ."phase-one-details"."custom-dh-group" // "default"')"
        p2auth="$(printf '%s' "$tunnel" | jq -r '."phase-two-details"."negotiated-authentication-algorithm" // ."phase-two-details"."custom-authentication-algorithm" // "default"')"
        p2enc="$(printf '%s' "$tunnel" | jq -r '."phase-two-details"."negotiated-encryption-algorithm" // ."phase-two-details"."custom-encryption-algorithm" // "default"')"
        p2dh="$(printf '%s' "$tunnel" | jq -r '."phase-two-details"."negotiated-dh-group" // ."phase-two-details"."dh-group" // "default"')"
        pfs="$(printf '%s' "$tunnel" | jq -r '."phase-two-details"."is-pfs-enabled" // "unknown"')"
        updated="$(printf '%s' "$tunnel" | jq -r '."time-status-updated" // "unknown"')"
        finding="$(ipsec_finding "$tunnel")"
        if [ "$tstatus" = "UP" ]; then enabled="YES"; else enabled="NO"; fi
        detail="id=${tid: -16};status=$tstatus;lifecycle=$tlifecycle;routing=$routing;bgp=$bgp;p1=$p1enc/$p1auth/$p1dh;p2=$p2enc/$p2auth/$p2dh;pfs=$pfs;updated=$updated"
        row "$comp" "IPSecTunnel" "$name/$tname" "$enabled" "IKE-$ike" "$detail" "$finding" "SC-8(1)" "OK" ""
      done < <(printf '%s' "$tunnels_json" | jq -c "$LIST_ITER" 2>/dev/null)

      if [ "$connection_tunnel_count" -ne 2 ]; then
        row "$comp" "IPSecTunnel" "$name/<tunnel-pair>" "UNKNOWN" "IKE/IPSec" \
          "expected-tunnels=2;discovered-tunnels=$connection_tunnel_count" \
          "IPSEC-TUNNEL-PAIR-INCOMPLETE" "SC-8(1)" "OK" ""
      fi
    done < <(printf '%s' "$conns_json" | jq -c "$LIST_ITER" 2>/dev/null)
    coverage_row "$comp" "IPSecConnection" "$conn_count" "$conn_status" "$conn_error"
    if [ "$tunnel_count_unknown" -eq 1 ]; then
      coverage_row "$comp" "IPSecTunnel" "UNKNOWN" "$tunnel_status" "$tunnel_error"
    else
      coverage_row "$comp" "IPSecTunnel" "$tunnel_count" "$tunnel_status" "$tunnel_error"
    fi
  fi

  # DRG attachment rows provide the route-table and attached-network context.
  count=0
  oci_capture "DRG attachment list" network drg-attachment list --compartment-id "$comp" \
    --attachment-type ALL --all
  json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "DRGAttachment" "<collection>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-8(1)"
    coverage_row "$comp" "DRGAttachment" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  else
    while IFS= read -r attachment; do
      [ -z "$attachment" ] && continue
      count=$((count+1))
      local name type lifecycle drg route_table network finding
      name="$(printf '%s' "$attachment" | jq -r '."display-name" // "drg-attachment"')"
      type="$(printf '%s' "$attachment" | jq -r '."attachment-type" // ."network-details".type // "unknown"')"
      lifecycle="$(printf '%s' "$attachment" | jq -r '."lifecycle-state" // "unknown"')"
      drg="$(printf '%s' "$attachment" | jq -r '."drg-id" // "unknown"')"
      route_table="$(printf '%s' "$attachment" | jq -r '."drg-route-table-id" // "unknown"')"
      network="$(printf '%s' "$attachment" | jq -r '."network-details".id // ."network-id" // "unknown"')"
      if [ "$lifecycle" = "ATTACHED" ]; then finding="OK"; else finding="ATTACHMENT-NOT-ATTACHED"; fi
      row "$comp" "DRGAttachment" "$name" "n/a" "$type" \
        "lifecycle=$lifecycle;drg=${drg: -16};route-table=${route_table: -16};network=${network: -16}" \
        "$finding" "SC-8(1)" "OK" ""
    done < <(printf '%s' "$json" | jq -c "$LIST_ITER" 2>/dev/null)
    coverage_row "$comp" "DRGAttachment" "$count" "OK" ""
  fi
}

i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  CUR_COMP="$comp"
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"
  for svc in $SERVICES; do
    case "$svc" in
      lb) check_lb "$comp" ;;
      nlb) check_nlb "$comp" ;;
      adb) check_adb "$comp" ;;
      basedb) check_basedb "$comp" ;;
      object) check_object "$comp" ;;
      volumes) check_volumes "$comp" ;;
      fss) check_fss "$comp" ;;
      apigw) check_apigw "$comp" ;;
      oke) check_oke "$comp" ;;
      ipsec) check_ipsec "$comp" ;;
      *)
        INCOMPLETE=1
        collection_failure_row "$comp" "$svc" "<unknown-service>" "ERROR" "unknown service token" "SC-8(1)"
        coverage_row "$comp" "$svc" "UNKNOWN" "ERROR" "unknown service token"
        ;;
    esac
  done
done <<< "$COMPS"

SUMMARY="$(python3 - "$OUT" <<'PY'
import csv, json, sys

hard_tokens = (
    "WEAK", "PLAINTEXT", "DISABLED", "PUBLIC-ACCESS-REVIEW",
    "BACKEND-PLAINTEXT", "TUNNEL-DOWN", "IKE-NOT-ESTABLISHED",
    "ESP-NOT-ESTABLISHED", "IPSEC-TUNNEL-PAIR-INCOMPLETE",
    "ATTACHMENT-NOT-ATTACHED", "TUNNEL-LIFECYCLE-",
)
review_tokens = ("MANUAL-EVIDENCE", "REVIEW")
total = hard = review = incomplete = 0
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    for row in csv.DictReader(handle):
        total += 1
        finding = row["finding"]
        status = row["collection_status"]
        if status != "OK":
            incomplete += 1
        elif any(token in finding for token in hard_tokens):
            hard += 1
        if any(token in finding for token in review_tokens):
            review += 1
print(json.dumps({"total": total, "hard": hard, "review": review, "incomplete": incomplete}))
PY
)"

TOTAL="$(printf '%s' "$SUMMARY" | jq -r '.total')"
FCOUNT="$(printf '%s' "$SUMMARY" | jq -r '.hard')"
MANUAL="$(printf '%s' "$SUMMARY" | jq -r '.review')"
INCOMPLETE_ROWS="$(printf '%s' "$SUMMARY" | jq -r '.incomplete')"

echo
echo "======================================================================"
echo "SC-8 IN-TRANSIT ENCRYPTION EVIDENCE SUMMARY"
echo "======================================================================"
echo "Total evidence rows              : $TOTAL"
echo "Hard findings (action required)  : $FCOUNT"
echo "Manual-evidence / review items   : $MANUAL"
echo "Rows not completely collected    : $INCOMPLETE_ROWS"
echo
echo "Evidence CSV written to: $OUT"
echo "Coverage CSV written to: $COVERAGE"
echo "Manual evidence checklist: TASK2-MANUAL-EVIDENCE-CHECKLIST.md"

if [ "$INCOMPLETE" -eq 0 ]; then
  rm -f "$ERROUT" 2>/dev/null
  echo "Collection integrity: COMPLETE"
  exit 0
fi

echo "Collection errors written to: $ERROUT"
echo "Collection integrity: INCOMPLETE — do not treat missing rows as absence." >&2
exit 3
