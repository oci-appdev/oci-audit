#!/usr/bin/env bash
#
# sc28-oci-encryption-at-rest.sh
#
# SC-28 / SC-28(1) / SC-12 EVIDENCE — Encryption at rest
#
# Read-only OCI configuration sweep for data-store encryption and Vault/KMS
# key custody. Designed for OCI Cloud Shell.
#
# Services:
#   volumes  Block Volumes
#   bootvol  Boot Volumes
#   object   Object Storage buckets
#   fss      File Storage file systems
#   adb      Autonomous Database
#   basedb   Base Database
#   mysql    MySQL HeatWave
#   postgres OCI Database with PostgreSQL
#   vault    Vaults, KMS keys, auto-rotation and key versions
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation. This Task 3 collector does not use the OCI
#   Python SDK.
#
# READ-ONLY: every OCI call is a list/get. The script never retrieves key
# material or secrets and never creates, rotates, changes or deletes a key.
#
# Usage:
#   bash sc28-oci-encryption-at-rest.sh
#   bash sc28-oci-encryption-at-rest.sh --select-scope
#   bash sc28-oci-encryption-at-rest.sh -i
#   bash sc28-oci-encryption-at-rest.sh -c <compartment-ocid>
#   bash sc28-oci-encryption-at-rest.sh -n 'VCN,Shared Services,CD3'
#   bash sc28-oci-encryption-at-rest.sh -r us-langley-1
#   bash sc28-oci-encryption-at-rest.sh -s 'volumes vault'
#   bash sc28-oci-encryption-at-rest.sh -o ./evidence
#   bash sc28-oci-encryption-at-rest.sh --selfcheck
#
# Output:
#   oci_atrest_encryption_<ts>.csv
#   oci_atrest_encryption_coverage_<ts>.csv
#   oci_atrest_encryption_collection_errors_<ts>.csv (failed calls only)
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
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")         # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='oci[[:space:]]+([a-z0-9-]+[[:space:]]+)*(create|update|delete|schedule-deletion|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|bulk-upload|bulk-delete|reset|activate|deactivate|cancel)([[:space:]]|$)'  # selfcheck-exempt
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
    echo "READ-ONLY SELF-CHECK: PASSED (sc28-oci-encryption-at-rest)"
    echo "All OCI calls in $SCRIPT_PATH are list/get operations."
    exit 0
  fi
  exit 1
fi

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found." >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found." >&2; exit 1; }

[ -r "$SCOPE_HELPER" ] || { echo "ERROR: scope selector not found: $SCOPE_HELPER" >&2; exit 1; }
# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION_OVERRIDE=""
OUTDIR="."
SERVICES="volumes bootvol object fss adb basedb mysql postgres vault"
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

# A normal operator run always discovers the tenancy/compartments and asks for
# the exact OCID. Explicit -c/-n remain the approved automation path.
if [ "$SELECT_SCOPE" -eq 0 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  SELECT_SCOPE=1
fi

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")
mkdir -p -- "$OUTDIR" 2>/dev/null || { echo "ERROR: cannot create output directory: $OUTDIR" >&2; exit 1; }
readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUTDIR/oci_atrest_encryption_${TS}.csv"
COVERAGE="$OUTDIR/oci_atrest_encryption_coverage_${TS}.csv"
ERROUT="$OUTDIR/oci_atrest_encryption_collection_errors_${TS}.csv"

echo "compartment_id,compartment_name,service,resource,encrypted,key_management,key_ocid_or_detail,key_lifecycle,key_rotation,finding,control,collection_status,collection_error" > "$OUT"
echo "compartment_id,compartment_name,service,assets_found,collection_status,collection_error" > "$COVERAGE"
echo "compartment_id,compartment_name,status,command,error" > "$ERROUT"

abort_before_scan() {
  local reason="$1"
  rm -f -- "$OUT" "$COVERAGE" "$ERROUT" 2>/dev/null
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

INCOMPLETE=0
CUR_COMP="<tenancy>"
COLLECT_OUT=""
COLLECT_STATUS="OK"
COLLECT_ERROR=""
declare -A COMP_NAME

oci_capture() {
  local label="$1"; shift
  local errf out rc err status cname cmd
  errf="$(mktemp 2>/dev/null || printf '/tmp/sc28.%s.err' "$$")"
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
    if [ "$status" != "NOTFOUND" ]; then
      INCOMPLETE=1
      cname="${COMP_NAME[$CUR_COMP]:-<unknown>}"
      cmd="$label :: $*"
      cmd="${cmd//\"/\"\"}"; err="${err//\"/\"\"}"
      printf '"%s","%s","%s","%s","%s"\n' \
        "$CUR_COMP" "$cname" "$status" "$cmd" "$err" >> "$ERROUT"
    fi
  fi
  COLLECT_OUT="$out"
  COLLECT_STATUS="$status"
  COLLECT_ERROR="$err"
}

LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

csv_escape() {
  local value="$1"
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

row() {
  local comp_id="$1"; shift
  local cname="${COMP_NAME[$comp_id]:-<unknown>}"
  local output="" field
  for field in "$comp_id" "$cname" "$@"; do
    field="${field//\"/\"\"}"
    output+="\"${field}\","
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
    "UNKNOWN" "UNKNOWN" "COLLECTION-FAILED" "$control" "$status" "$error"
}

emit_store_key() {
  local comp="$1" service="$2" resource="$3" encryption="$4" key_id="$5" control="$6"
  if [ -n "$key_id" ] && [ "$key_id" != "null" ]; then
    row "$comp" "$service" "$resource" "$encryption" "CUSTOMER-MANAGED" "$key_id" \
      "REFER-TO-KMS-KEY-ROW" "REFER-TO-KMS-KEY-ROW" "OK-CMK" "$control" "OK" ""
  else
    row "$comp" "$service" "$resource" "$encryption" "ORACLE-MANAGED" "no-kms-key-id" \
      "PLATFORM-MANAGED" "PROVIDER-MANAGED" "REVIEW-USE-CMK" "$control" "OK" ""
  fi
}

# Resolve tenancy and collection scope.
oci_capture "resolve tenancy" iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$COLLECT_OUT"
if [ -z "$TENANCY_ID" ] || [ "$TENANCY_ID" = "null" ]; then
  echo "ERROR: could not resolve tenancy ($COLLECT_STATUS): $COLLECT_ERROR" >&2
  echo "Collection errors retained in: $ERROUT" >&2
  exit 1
fi
COMP_NAME["$TENANCY_ID"]="root"
CUR_COMP="$TENANCY_ID"

echo "Region : ${REGION_OVERRIDE:-<cloud-shell-default>}"
echo "Tenancy: $TENANCY_ID"
echo "Scope  : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'command-line/default')"
echo

if [ "$SELECT_SCOPE" -eq 1 ]; then
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
    exit 1
  fi
  COMP_NAME["$TENANCY_ID"]="${COLLECT_OUT:-root}"

  if ! oci_scope_select_interactive "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$scope_catalog"; then
    abort_before_scan "scope selection or OCID confirmation failed"
  fi
  if [ "$OCI_SCOPE_SELECTED_KIND" = "TENANCY" ]; then
    COMPS="$TENANCY_ID"$'\n'"$discovered_comps"
  else
    COMPS="$OCI_SCOPE_SELECTED_OCID"
  fi
elif [ -n "$SINGLE_COMP" ]; then
  COMPS="$SINGLE_COMP"
  CUR_COMP="$SINGLE_COMP"
  oci_capture "get selected compartment" iam compartment get --compartment-id "$SINGLE_COMP" \
    --query 'data.name' --raw-output
  if [ "$COLLECT_STATUS" != "OK" ]; then
    echo "ERROR: selected compartment lookup failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    exit 1
  fi
  COMP_NAME["$SINGLE_COMP"]="${COLLECT_OUT:-<unknown>}"
else
  CUR_COMP="$TENANCY_ID"
  oci_capture "enumerate active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    echo "ERROR: compartment enumeration failed ($COLLECT_STATUS): $COLLECT_ERROR" >&2
    exit 1
  fi
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps="${discovered_comps}${cid}"$'\n'
  done < <(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)
  COMPS="$TENANCY_ID"$'\n'"$discovered_comps"
fi

if [ -n "$COMP_NAMES_FILTER" ]; then
  filtered=""
  IFS=',' read -ra wanted_names <<< "$COMP_NAMES_FILTER"
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    for wanted in "${wanted_names[@]}"; do
      wanted="$(printf '%s' "$wanted" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      if [ "${COMP_NAME[$cid]:-}" = "$wanted" ]; then
        filtered="${filtered}${cid}"$'\n'
      fi
    done
  done <<< "$COMPS"
  COMPS="$filtered"
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | awk 'NF {n++} END {print n+0}')"
if [ "$COMP_COUNT" -eq 0 ]; then
  abort_before_scan "no compartments matched the requested scope"
fi

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

oci_scope_print_scan_plan \
  "SC-28 ENCRYPTION AT REST" "sc28-oci-encryption-at-rest.sh" \
  "SC-28 / SC-28(1) / SC-12" "${REGION_OVERRIDE:-<cloud-shell-default>}" \
  "$PLAN_SCOPE_TYPE" "$PLAN_SCOPE_NAME" "$PLAN_SCOPE_OCID" "$COMP_COUNT" \
  "$PLAN_TARGETS" "Requested service scans" "$PLAN_WORK" \
  "$OUT"$'\n'"$COVERAGE"$'\n'"$ERROUT" \
  "resource/key OCIDs, encryption mode, Vault lifecycle and rotation posture; no key material"
if ! oci_scope_require_final_approval "$SELECT_SCOPE"; then
  abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
fi

echo "Collecting SC-28 evidence across ${COMP_COUNT} compartment(s)..."
echo

check_volumes() {
  local comp="$1" json status error count=0 name kid
  oci_capture "list block volumes" bv volume list --compartment-id "$comp" --all
  json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "BlockVolume" "<collection>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "BlockVolume" 0 "$status" "$error"
    return
  fi
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    count=$((count+1))
    name="$(jq -r '."display-name" // "volume"' <<< "$item")"
    kid="$(jq -r '."kms-key-id" // empty' <<< "$item")"
    emit_store_key "$comp" "BlockVolume" "$name" "YES(AES-256)" "$kid" "SC-28(1)/SC-12"
  done < <(jq -c "$LIST_ITER" <<< "$json" 2>/dev/null)
  coverage_row "$comp" "BlockVolume" "$count" "OK" ""
}

check_bootvol() {
  local comp="$1" ad_json ad_status ad_error status="OK" error="" count=0 ad item name kid json
  oci_capture "list availability domains for boot volumes" iam availability-domain list --compartment-id "$comp"
  ad_json="$COLLECT_OUT"; ad_status="$COLLECT_STATUS"; ad_error="$COLLECT_ERROR"
  if [ "$ad_status" != "OK" ]; then
    collection_failure_row "$comp" "BootVolume" "<availability-domains>" "$ad_status" "$ad_error" "SC-28(1)/SC-12"
    coverage_row "$comp" "BootVolume" 0 "$ad_status" "$ad_error"
    return
  fi
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    oci_capture "list boot volumes in $ad" bv boot-volume list --compartment-id "$comp" --availability-domain "$ad" --all
    json="$COLLECT_OUT"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "BootVolume" "<collection:$ad>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      count=$((count+1))
      name="$(jq -r '."display-name" // "boot-volume"' <<< "$item")"
      kid="$(jq -r '."kms-key-id" // empty' <<< "$item")"
      emit_store_key "$comp" "BootVolume" "$name" "YES(AES-256)" "$kid" "SC-28(1)/SC-12"
    done < <(jq -c "$LIST_ITER" <<< "$json" 2>/dev/null)
  done < <(jq -r '.data[]?.name' <<< "$ad_json" 2>/dev/null)
  coverage_row "$comp" "BootVolume" "$count" "$status" "$error"
}

check_object() {
  local comp="$1" ns status error list_json count=0 bucket kid
  oci_capture "get Object Storage namespace" os ns get --query data --raw-output
  ns="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ] || [ -z "$ns" ] || [ "$ns" = "null" ]; then
    [ "$status" = "OK" ] && status="ERROR" && error="Object Storage namespace was empty" && INCOMPLETE=1
    collection_failure_row "$comp" "ObjectStorage" "<namespace>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "ObjectStorage" 0 "$status" "$error"
    return
  fi
  oci_capture "list Object Storage buckets" os bucket list --compartment-id "$comp" --namespace-name "$ns" --all
  list_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "ObjectStorage" "<collection>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "ObjectStorage" 0 "$status" "$error"
    return
  fi
  while IFS= read -r bucket; do
    [ -z "$bucket" ] && continue
    count=$((count+1))
    oci_capture "get Object Storage bucket $bucket" os bucket get --bucket-name "$bucket" --namespace-name "$ns"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "ObjectStorage" "$bucket" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi
    kid="$(jq -r '.data."kms-key-id" // empty' <<< "$COLLECT_OUT" 2>/dev/null)"
    emit_store_key "$comp" "ObjectStorage" "$bucket" "YES(AES-256)" "$kid" "SC-28(1)/SC-12"
  done < <(jq -r "$LIST_ITER | .name" <<< "$list_json" 2>/dev/null)
  coverage_row "$comp" "ObjectStorage" "$count" "$status" "$error"
}

check_fss() {
  local comp="$1" ad_json status="OK" error="" count=0 ad json item name kid
  oci_capture "list availability domains for FSS" iam availability-domain list --compartment-id "$comp"
  ad_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    collection_failure_row "$comp" "FSS" "<availability-domains>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
    coverage_row "$comp" "FSS" 0 "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    oci_capture "list FSS file systems in $ad" fs file-system list --compartment-id "$comp" --availability-domain "$ad" --all
    json="$COLLECT_OUT"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "FSS" "<collection:$ad>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      count=$((count+1))
      name="$(jq -r '."display-name" // "file-system"' <<< "$item")"
      kid="$(jq -r '."kms-key-id" // empty' <<< "$item")"
      emit_store_key "$comp" "FSS" "$name" "YES(AES-256)" "$kid" "SC-28(1)/SC-12"
    done < <(jq -c "$LIST_ITER" <<< "$json" 2>/dev/null)
  done < <(jq -r '.data[]?.name' <<< "$ad_json" 2>/dev/null)
  coverage_row "$comp" "FSS" "$count" "$status" "$error"
}

check_adb() {
  local comp="$1" json status error count=0 item name kid
  oci_capture "list Autonomous Databases" db autonomous-database list --compartment-id "$comp" --all
  json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "AutonomousDB" "<collection>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "AutonomousDB" 0 "$status" "$error"
    return
  fi
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    count=$((count+1))
    name="$(jq -r '."db-name" // ."display-name" // "autonomous-db"' <<< "$item")"
    kid="$(jq -r '."kms-key-id" // empty' <<< "$item")"
    emit_store_key "$comp" "AutonomousDB" "$name" "YES(TDE)" "$kid" "SC-28(1)/SC-12"
  done < <(jq -c "$LIST_ITER" <<< "$json" 2>/dev/null)
  coverage_row "$comp" "AutonomousDB" "$count" "OK" ""
}

check_basedb() {
  local comp="$1" system_json status error count=0 system_id db_json item name kid
  oci_capture "list Base DB systems" db system list --compartment-id "$comp" --all
  system_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "BaseDB" "<db-systems>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "BaseDB" 0 "$status" "$error"
    return
  fi
  while IFS= read -r system_id; do
    [ -z "$system_id" ] && continue
    oci_capture "list databases for $system_id" db database list --compartment-id "$comp" --db-system-id "$system_id" --all
    db_json="$COLLECT_OUT"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "BaseDB" "$system_id" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      count=$((count+1))
      name="$(jq -r '."db-name" // "database"' <<< "$item")"
      kid="$(jq -r '."kms-key-id" // empty' <<< "$item")"
      emit_store_key "$comp" "BaseDB" "$name" "YES(TDE)" "$kid" "SC-28(1)/SC-12"
    done < <(jq -c "$LIST_ITER" <<< "$db_json" 2>/dev/null)
  done < <(jq -r "$LIST_ITER | .id" <<< "$system_json" 2>/dev/null)
  coverage_row "$comp" "BaseDB" "$count" "$status" "$error"
}

check_mysql() {
  local comp="$1" list_json status error count=0 system_id full name key_type kid finding
  oci_capture "list MySQL DB systems" mysql db-system list --compartment-id "$comp" --all
  list_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "MySQL" "<collection>" "$status" "$error" "SC-28(1)/SC-12"
    coverage_row "$comp" "MySQL" 0 "$status" "$error"
    return
  fi
  while IFS= read -r system_id; do
    [ -z "$system_id" ] && continue
    count=$((count+1))
    oci_capture "get MySQL DB system $system_id" mysql db-system get --db-system-id "$system_id"
    full="$COLLECT_OUT"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "MySQL" "$system_id" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi
    name="$(jq -r '.data."display-name" // "mysql"' <<< "$full")"
    key_type="$(jq -r '.data."encrypt-data"."key-generation-type" // empty' <<< "$full")"
    kid="$(jq -r '.data."encrypt-data"."key-id" // empty' <<< "$full")"
    if [ "$key_type" = "BYOK" ] && [ -n "$kid" ]; then
      row "$comp" "MySQL" "$name" "YES(AES-256)" "CUSTOMER-MANAGED" "$kid" \
        "REFER-TO-KMS-KEY-ROW" "REFER-TO-KMS-KEY-ROW" "OK-CMK" "SC-28(1)/SC-12" "OK" ""
    elif [ "$key_type" = "SYSTEM" ]; then
      row "$comp" "MySQL" "$name" "YES(AES-256)" "ORACLE-MANAGED" "key-generation-type=SYSTEM" \
        "PLATFORM-MANAGED" "PROVIDER-MANAGED" "REVIEW-USE-CMK" "SC-28(1)/SC-12" "OK" ""
    else
      finding="MANUAL-VERIFY-KEY-CUSTODY"
      row "$comp" "MySQL" "$name" "YES(platform)" "UNKNOWN" \
        "key-generation-type=${key_type:-not-exposed};key-id=${kid:-not-exposed}" \
        "UNKNOWN" "UNKNOWN" "$finding" "SC-28(1)/SC-12" "OK" ""
    fi
  done < <(jq -r "$LIST_ITER | .id" <<< "$list_json" 2>/dev/null)
  coverage_row "$comp" "MySQL" "$count" "$status" "$error"
}

check_postgres() {
  local comp="$1" list_json status error count=0 system_id full name storage_type
  oci_capture "list PostgreSQL DB systems" psql db-system-collection list-db-systems --compartment-id "$comp" --all
  list_json="$COLLECT_OUT"; status="$COLLECT_STATUS"; error="$COLLECT_ERROR"
  if [ "$status" != "OK" ]; then
    collection_failure_row "$comp" "PostgreSQL" "<collection>" "$status" "$error" "SC-28/SC-12"
    coverage_row "$comp" "PostgreSQL" 0 "$status" "$error"
    return
  fi
  while IFS= read -r system_id; do
    [ -z "$system_id" ] && continue
    count=$((count+1))
    oci_capture "get PostgreSQL DB system $system_id" psql db-system get --db-system-id "$system_id"
    full="$COLLECT_OUT"
    merge_status status error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "PostgreSQL" "$system_id" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28/SC-12"
      continue
    fi
    name="$(jq -r '.data."display-name" // "postgresql"' <<< "$full")"
    storage_type="$(jq -r '.data."storage-details"."system-type" // .data."storage-system-type" // "not-exposed"' <<< "$full")"
    row "$comp" "PostgreSQL" "$name" "YES(platform)" "PLATFORM-MANAGED" \
      "data-key-id-not-exposed;storage-system-type=$storage_type" \
      "PLATFORM-MANAGED" "PROVIDER-MANAGED" "MANUAL-VERIFY-KEY-CUSTODY" "SC-28/SC-12" "OK" ""
  done < <(jq -r "$LIST_ITER | .id" <<< "$list_json" 2>/dev/null)
  coverage_row "$comp" "PostgreSQL" "$count" "$status" "$error"
}

check_vault() {
  local comp="$1" vault_json vault_status vault_error vault_count=0 key_count=0
  local overall_key_status="OK" overall_key_error="" vault_item vault_id vault_name vault_type vault_state endpoint deletion vault_finding
  local key_json key_item key_id key_name full versions protection key_state algorithm length auto_enabled interval schedule_start next_rotation last_rotation last_status last_message
  local version_count latest_version latest_version_state latest_version_created auto_version_count pending_version_deletions rotation_detail finding row_status row_error

  oci_capture "list Vaults" kms vault list --compartment-id "$comp" --all
  vault_json="$COLLECT_OUT"; vault_status="$COLLECT_STATUS"; vault_error="$COLLECT_ERROR"
  if [ "$vault_status" != "OK" ]; then
    collection_failure_row "$comp" "Vault" "<collection>" "$vault_status" "$vault_error" "SC-28(1)/SC-12"
    collection_failure_row "$comp" "KMS-Key" "<collection>" "$vault_status" "$vault_error" "SC-28(1)/SC-12"
    coverage_row "$comp" "Vault" 0 "$vault_status" "$vault_error"
    coverage_row "$comp" "KMS-Key" 0 "$vault_status" "$vault_error"
    return
  fi

  while IFS= read -r vault_item; do
    [ -z "$vault_item" ] && continue
    vault_count=$((vault_count+1))
    vault_id="$(jq -r '.id' <<< "$vault_item")"
    vault_name="$(jq -r '."display-name" // "vault"' <<< "$vault_item")"
    vault_type="$(jq -r '."vault-type" // "UNKNOWN"' <<< "$vault_item")"
    vault_state="$(jq -r '."lifecycle-state" // "UNKNOWN"' <<< "$vault_item")"
    endpoint="$(jq -r '."management-endpoint" // empty' <<< "$vault_item")"
    deletion="$(jq -r '."time-of-deletion" // empty' <<< "$vault_item")"
    if [ "$vault_state" != "ACTIVE" ]; then
      vault_finding="VAULT-STATE-$vault_state"
    elif [ "$vault_type" = "VIRTUAL_PRIVATE" ]; then
      vault_finding="OK-PRIVATE-VAULT"
    else
      vault_finding="OK-REVIEW-SHARED-VAULT"
    fi
    row "$comp" "Vault" "$vault_name" "YES" "CUSTOMER-MANAGED-CAPABLE" \
      "vault-id=$vault_id;type=$vault_type;endpoint=${endpoint:-not-exposed};deletion=${deletion:-none}" \
      "$vault_state" "N/A" "$vault_finding" "SC-28(1)/SC-12" "OK" ""

    if [ -z "$endpoint" ]; then
      INCOMPLETE=1
      overall_key_status="ERROR"
      overall_key_error="${overall_key_error:+$overall_key_error | }Vault $vault_id has no management endpoint"
      collection_failure_row "$comp" "KMS-Key" "$vault_name" "ERROR" "Vault management endpoint was not exposed" "SC-28(1)/SC-12"
      continue
    fi

    oci_capture "list KMS keys in $vault_name" kms management key list \
      --endpoint "$endpoint" --compartment-id "$comp" --all
    key_json="$COLLECT_OUT"
    merge_status overall_key_status overall_key_error "$COLLECT_STATUS" "$COLLECT_ERROR"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      collection_failure_row "$comp" "KMS-Key" "<collection:$vault_name>" "$COLLECT_STATUS" "$COLLECT_ERROR" "SC-28(1)/SC-12"
      continue
    fi

    while IFS= read -r key_item; do
      [ -z "$key_item" ] && continue
      key_count=$((key_count+1))
      key_id="$(jq -r '.id' <<< "$key_item")"
      key_name="$(jq -r '."display-name" // "key"' <<< "$key_item")"

      oci_capture "get KMS key $key_name" kms management key get --endpoint "$endpoint" --key-id "$key_id"
      full="$COLLECT_OUT"; row_status="$COLLECT_STATUS"; row_error="$COLLECT_ERROR"
      merge_status overall_key_status overall_key_error "$COLLECT_STATUS" "$COLLECT_ERROR"
      if [ "$row_status" != "OK" ]; then
        collection_failure_row "$comp" "KMS-Key" "$key_name" "$row_status" "$row_error" "SC-28(1)/SC-12"
        continue
      fi

      protection="$(jq -r '.data."protection-mode" // "UNKNOWN"' <<< "$full")"
      key_state="$(jq -r '.data."lifecycle-state" // "UNKNOWN"' <<< "$full")"
      algorithm="$(jq -r '.data."key-shape".algorithm // "UNKNOWN"' <<< "$full")"
      length="$(jq -r '.data."key-shape".length // "UNKNOWN"' <<< "$full")"
      deletion="$(jq -r '.data."time-of-deletion" // empty' <<< "$full")"
      auto_enabled="$(jq -r '.data."is-auto-rotation-enabled" // false' <<< "$full")"
      interval="$(jq -r '.data."auto-key-rotation-details"."rotation-interval-in-days" // empty' <<< "$full")"
      schedule_start="$(jq -r '.data."auto-key-rotation-details"."time-of-schedule-start" // empty' <<< "$full")"
      next_rotation="$(jq -r '.data."auto-key-rotation-details"."time-of-next-rotation" // empty' <<< "$full")"
      last_rotation="$(jq -r '.data."auto-key-rotation-details"."time-of-last-rotation" // empty' <<< "$full")"
      last_status="$(jq -r '.data."auto-key-rotation-details"."last-rotation-status" // empty' <<< "$full")"
      last_message="$(jq -r '.data."auto-key-rotation-details"."last-rotation-message" // empty' <<< "$full" | tr '\n\r' '  ' | cut -c1-120)"

      oci_capture "list KMS key versions for $key_name" kms management key-version list \
        --endpoint "$endpoint" --key-id "$key_id" --all
      versions="$COLLECT_OUT"
      merge_status overall_key_status overall_key_error "$COLLECT_STATUS" "$COLLECT_ERROR"
      if [ "$COLLECT_STATUS" != "OK" ]; then
        row_status="$COLLECT_STATUS"; row_error="$COLLECT_ERROR"
        version_count="UNKNOWN"; latest_version="UNKNOWN"; latest_version_state="UNKNOWN"
        latest_version_created="UNKNOWN"; auto_version_count="UNKNOWN"; pending_version_deletions="UNKNOWN"
        finding="COLLECTION-FAILED"
        INCOMPLETE=1
      else
        version_count="$(jq '[.data[]?] | length' <<< "$versions" 2>/dev/null)"
        latest_version="$(jq -r '[.data[]?] | sort_by(."time-created") | last | .id // "none"' <<< "$versions" 2>/dev/null)"
        latest_version_state="$(jq -r '[.data[]?] | sort_by(."time-created") | last | ."lifecycle-state" // "none"' <<< "$versions" 2>/dev/null)"
        latest_version_created="$(jq -r '[.data[]?] | sort_by(."time-created") | last | ."time-created" // "none"' <<< "$versions" 2>/dev/null)"
        auto_version_count="$(jq '[.data[]? | select(."is-auto-rotated" == true)] | length' <<< "$versions" 2>/dev/null)"
        pending_version_deletions="$(jq '[.data[]? | select(."time-of-deletion" != null)] | length' <<< "$versions" 2>/dev/null)"
        row_status="OK"; row_error=""

        if [ "$key_state" != "ENABLED" ]; then
          finding="KEY-STATE-$key_state"
        elif [ "$protection" != "HSM" ]; then
          finding="REVIEW-SOFTWARE-KEY"
        elif [ "$algorithm" != "AES" ] || [ "$length" != "32" ]; then
          finding="REVIEW-AES-KEY-LENGTH-$algorithm-$length"
        elif [ "$last_status" = "FAILED" ]; then
          finding="AUTO-ROTATION-FAILED"
        elif [ "$auto_enabled" = "true" ] && { [ -z "$interval" ] || [ -z "$next_rotation" ]; }; then
          finding="REVIEW-AUTO-ROTATION-DETAILS"
        elif [ "$auto_enabled" != "true" ]; then
          finding="REVIEW-MANUAL-ROTATION-EVIDENCE"
        elif [ "$version_count" -le 1 ] && [ "$auto_version_count" -eq 0 ]; then
          finding="REVIEW-ROTATION-NOT-CONFIRMED"
        else
          finding="OK-HSM-AUTO-ROTATION"
        fi
      fi

      rotation_detail="auto-enabled=$auto_enabled;interval-days=${interval:-not-exposed};schedule-start=${schedule_start:-not-exposed};last=${last_rotation:-not-exposed};last-status=${last_status:-not-exposed};last-message=${last_message:-none};next=${next_rotation:-not-exposed};versions=$version_count;auto-rotated-versions=$auto_version_count;pending-version-deletions=$pending_version_deletions;latest-version=$latest_version;latest-version-state=$latest_version_state;latest-version-created=$latest_version_created"
      row "$comp" "KMS-Key" "$key_name" "YES" "$protection" \
        "key-id=$key_id;vault-id=$vault_id;algorithm=$algorithm;length-bytes=$length;deletion=${deletion:-none}" \
        "$key_state" "$rotation_detail" "$finding" "SC-28(1)/SC-12" "$row_status" "$row_error"
    done < <(jq -c "$LIST_ITER" <<< "$key_json" 2>/dev/null)
  done < <(jq -c "$LIST_ITER" <<< "$vault_json" 2>/dev/null)

  coverage_row "$comp" "Vault" "$vault_count" "OK" ""
  coverage_row "$comp" "KMS-Key" "$key_count" "$overall_key_status" "$overall_key_error"
}

index=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  index=$((index+1))
  CUR_COMP="$comp"
  echo "[$index/$COMP_COUNT] ${COMP_NAME[$comp]:-<unknown>}"
  for service in $SERVICES; do
    case "$service" in
      volumes) check_volumes "$comp" ;;
      bootvol) check_bootvol "$comp" ;;
      object) check_object "$comp" ;;
      fss) check_fss "$comp" ;;
      adb) check_adb "$comp" ;;
      basedb) check_basedb "$comp" ;;
      mysql) check_mysql "$comp" ;;
      postgres) check_postgres "$comp" ;;
      vault) check_vault "$comp" ;;
      *) echo "WARNING: unknown service selector ignored: $service" >&2 ;;
    esac
  done
done <<< "$COMPS"

echo
python3 - "$OUT" "$COVERAGE" <<'PY'
import csv
import sys

evidence_path, coverage_path = sys.argv[1:]
with open(evidence_path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
with open(coverage_path, newline="", encoding="utf-8") as handle:
    coverage = list(csv.DictReader(handle))

def count(predicate):
    return sum(1 for row in rows if predicate(row))

print("SC-28 encryption-at-rest summary")
print(f"  Evidence rows          : {len(rows)}")
print(f"  Coverage rows          : {len(coverage)}")
print(f"  Customer-managed stores: {count(lambda r: r['key_management'] == 'CUSTOMER-MANAGED')}")
print(f"  Oracle-managed stores  : {count(lambda r: r['key_management'] == 'ORACLE-MANAGED')}")
print(f"  HSM keys               : {count(lambda r: r['service'] == 'KMS-Key' and r['key_management'] == 'HSM')}")
print(f"  Software/unknown keys  : {count(lambda r: r['service'] == 'KMS-Key' and r['key_management'] != 'HSM')}")
print(f"  Hard findings          : {count(lambda r: r['finding'].startswith(('KEY-STATE-', 'VAULT-STATE-', 'AUTO-ROTATION-FAILED')))}")
print(f"  Review/manual findings : {count(lambda r: r['finding'].startswith(('REVIEW-', 'MANUAL-')))}")
print(f"  Incomplete rows        : {count(lambda r: r['collection_status'] not in ('OK', ''))}")
PY

echo
echo "Evidence : $OUT"
echo "Coverage : $COVERAGE"
if [ "$INCOMPLETE" -ne 0 ]; then
  echo "Errors   : $ERROUT"
  echo "RESULT   : INCOMPLETE — resolve every non-OK coverage/error row before audit use." >&2
  exit 3
fi

rm -f "$ERROUT"
echo "Errors   : none (empty error ledger removed)"
echo "RESULT   : COMPLETE — findings and manual evidence still require reviewer disposition."
exit 0
