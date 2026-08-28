#!/usr/bin/env bash
#
# cm07-01-open-ports-protocols-services.sh
# Collector ID: CM07-01
#
# CM-7 / CM-7(1) / PPSM EVIDENCE — Open ports, protocols and services
#
# Read-only OCI inventory of Security List and Network Security Group rules,
# Security List-to-subnet associations, and NSG-to-VNIC associations.
#
# The collector distinguishes:
#   * OCI FACT: packet-filter rule, direction, protocol, ports and peer.
#   * INFERENCE: common service/function associated with a single port.
#   * ORGANIZATIONAL ATTESTATION: business function, justification, approval,
#     approval authority and restricted-list authority supplied in CSV inputs.
#
# IMPORTANT: an OCI rule permits traffic; it does not prove that a process is
# listening or that the endpoint is reachable. Routes, public/private IPs, OCI
# Network Firewall, ZPR, load balancers, host firewalls and application
# listeners require separate reconciliation.
#
# READ-ONLY CLOUD BOUNDARY: every OCI call is list/get. The script never creates,
# updates, deletes, attaches or detaches OCI resources.
#
# Usage:
#   bash cm07-01-open-ports-protocols-services.sh
#       Interactive by default: discover tenancy/compartments, enter the exact
#       selected OCID twice, review the plan, then type exact uppercase YES.
#
#   bash cm07-01-open-ports-protocols-services.sh -i
#   bash cm07-01-open-ports-protocols-services.sh --select-scope
#   bash cm07-01-open-ports-protocols-services.sh -c <compartment-ocid>
#   bash cm07-01-open-ports-protocols-services.sh -n 'VCN,Shared Services,CD3'
#   bash cm07-01-open-ports-protocols-services.sh -r us-langley-1
#   bash cm07-01-open-ports-protocols-services.sh -d ingress
#   bash cm07-01-open-ports-protocols-services.sh -o ./evidence
#   bash cm07-01-open-ports-protocols-services.sh \
#       -a approved_ports.csv -x restricted_ports.csv \
#       -s verified_services.csv
#   bash cm07-01-open-ports-protocols-services.sh \
#       -c <compartment-ocid> --non-interactive \
#       --confirm-scope-ocid <same-compartment-ocid> \
#       --approve-scan YES -r us-langley-1 --inventory-only
#   bash cm07-01-open-ports-protocols-services.sh --inventory-only
#   bash cm07-01-open-ports-protocols-services.sh --selfcheck
#
# Inputs:
#   -a, --approval-baseline FILE
#       Approved rule baseline produced from this collector's template. The
#       approving CCB/PPSM/ISSO authority completes approval ID, provider,
#       business function and justification.
#
#   -x, --restricted-list FILE
#       Authoritative organization/PPSM restricted list. The script intentionally
#       has no built-in list that could be mistaken for current policy.
#
#   -s, --service-mapping FILE
#       System-owner verification of the actual resource, listener, service,
#       function and justification associated with each live rule.
#
#   --non-interactive
#       Explicit automation mode. Requires -c or -n, one
#       --confirm-scope-ocid for every resolved compartment, and exact
#       --approve-scan YES. Merely supplying -c or -n does not bypass prompts.
#
#   --inventory-only
#       Initial discovery mode. Produces inventory and an approval template
#       without requiring approval/restricted inputs. It cannot prove approval.
#
# Output:
#   cm07-01_open_pps_inventory_<ts>.csv
#   cm07-01_approval_baseline_template_<ts>.csv
#   cm07-01_approval_reconciliation_<ts>.csv
#   cm07-01_restricted_findings_<ts>.csv
#   cm07-01_service_mapping_template_<ts>.csv
#   cm07-01_service_mapping_reconciliation_<ts>.csv
#   cm07-01_input_sources_<ts>.csv
#   cm07-01_coverage_<ts>.csv
#   cm07-01_collection_errors_<ts>.csv (failed calls only)
#
# Exit codes:
#   0  collection completed; findings still require human review
#   1  collector could not start, validate inputs or establish scope
#   3  collection/evidence is incomplete, including missing required source lists
#
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/lib/oci-scope-selector.sh"

readonly_selfcheck() {                                           # selfcheck-exempt
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")          # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='(oci|oci_capture)[[:space:]].*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|bulk-upload|bulk-delete|reset|activate|deactivate|cancel)([[:space:]]|$)'  # selfcheck-exempt
  hits="$(grep -nE "$deny" "${check_paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  rawpat="raw""-request"                                        # selfcheck-exempt
  raw="$(grep -nE "$rawpat" "${check_paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"        # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ]; then                       # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — prohibited call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED (cm07-01-open-ports-protocols-services)"
    echo "All OCI calls in $SCRIPT_PATH and $SCOPE_HELPER are list/get operations."
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
DIRECTION="both"
APPROVAL_FILE=""
RESTRICTED_FILE=""
SERVICE_MAPPING_FILE=""
INVENTORY_ONLY=0
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
    -r|--region) need_value "$@"; REGION_OVERRIDE="$2"; shift 2 ;;
    -d|--direction) need_value "$@"; DIRECTION="$2"; shift 2 ;;
    -o|--output-dir) need_value "$@"; OUTDIR="$2"; shift 2 ;;
    -a|--approval-baseline) need_value "$@"; APPROVAL_FILE="$2"; shift 2 ;;
    -x|--restricted-list) need_value "$@"; RESTRICTED_FILE="$2"; shift 2 ;;
    -s|--service-mapping) need_value "$@"; SERVICE_MAPPING_FILE="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --confirm-scope-ocid) need_value "$@"; CONFIRM_SCOPE_OCIDS+=("$2"); shift 2 ;;
    --approve-scan) need_value "$@"; APPROVE_SCAN="$2"; shift 2 ;;
    --inventory-only) INVENTORY_ONLY=1; shift ;;
    --selfcheck)
      echo "ERROR: --selfcheck must be used by itself." >&2
      exit 1
      ;;
    -h|--help) grep '^#' "$SCRIPT_PATH" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ERROR: unknown option: $1" >&2; exit 1 ;;
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
case "$DIRECTION" in
  both|ingress|egress) ;;
  *) echo "ERROR: direction must be ingress, egress or both." >&2; exit 1 ;;
esac
if [ "$INVENTORY_ONLY" -eq 1 ] && { [ -n "$APPROVAL_FILE" ] || [ -n "$RESTRICTED_FILE" ] || [ -n "$SERVICE_MAPPING_FILE" ]; }; then
  echo "ERROR: --inventory-only cannot be combined with approval/restricted/service inputs." >&2
  exit 1
fi
if [ -n "$APPROVAL_FILE" ] && [ ! -r "$APPROVAL_FILE" ]; then
  echo "ERROR: approval baseline is not readable: $APPROVAL_FILE" >&2
  exit 1
fi
if [ -n "$RESTRICTED_FILE" ] && [ ! -r "$RESTRICTED_FILE" ]; then
  echo "ERROR: restricted list is not readable: $RESTRICTED_FILE" >&2
  exit 1
fi
if [ -n "$SERVICE_MAPPING_FILE" ] && [ ! -r "$SERVICE_MAPPING_FILE" ]; then
  echo "ERROR: service mapping is not readable: $SERVICE_MAPPING_FILE" >&2
  exit 1
fi
if [ -z "$REGION_OVERRIDE" ]; then
  echo "ERROR: -r/--region is required so the evidence records the exact OCI region." >&2
  exit 1
fi

# A manual run without -c or -n always requires interactive discovery.
if [ "$SELECT_SCOPE" -eq 0 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  SELECT_SCOPE=1
fi

readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")

umask 077
mkdir -p -- "$OUTDIR" 2>/dev/null || {
  echo "ERROR: cannot create output directory: $OUTDIR" >&2
  exit 1
}

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUTDIR/cm07-01_open_pps_inventory_${TS}.csv"
BASELINE_TEMPLATE="$OUTDIR/cm07-01_approval_baseline_template_${TS}.csv"
APPROVAL_OUT="$OUTDIR/cm07-01_approval_reconciliation_${TS}.csv"
RESTRICTED_OUT="$OUTDIR/cm07-01_restricted_findings_${TS}.csv"
SERVICE_TEMPLATE="$OUTDIR/cm07-01_service_mapping_template_${TS}.csv"
SERVICE_OUT="$OUTDIR/cm07-01_service_mapping_reconciliation_${TS}.csv"
SOURCES_OUT="$OUTDIR/cm07-01_input_sources_${TS}.csv"
COVERAGE="$OUTDIR/cm07-01_coverage_${TS}.csv"
ERROUT="$OUTDIR/cm07-01_collection_errors_${TS}.csv"

for candidate in "$OUT" "$BASELINE_TEMPLATE" "$APPROVAL_OUT" "$RESTRICTED_OUT" \
  "$SERVICE_TEMPLATE" "$SERVICE_OUT" \
  "$SOURCES_OUT" "$COVERAGE" "$ERROUT"; do
  [ ! -e "$candidate" ] || {
    echo "ERROR: refusing to overwrite existing output: $candidate" >&2
    exit 1
  }
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cm07-01.XXXXXX" 2>/dev/null)" || {
  echo "ERROR: could not create a secure temporary directory." >&2
  exit 1
}
RAW="$WORKDIR/raw_inventory.csv"
TMP_COVERAGE="$WORKDIR/coverage.csv"
TMP_ERRORS="$WORKDIR/errors.csv"
TMP_SUMMARY="$WORKDIR/summary.txt"
printf '%s\n' 'compartment_id,compartment_name,vcn_id,vcn_name,container_id,container_name,container_type,attachment_count,applies_to,direction,stateless,protocol,source_type,source_or_dest,source_port_min,source_port_max,destination_port_min,destination_port_max,icmp_type,icmp_code,description,well_known_service,inferred_function,exposure_flag,defined_tags,freeform_tags,collection_status,collection_error' > "$RAW"
printf '%s\n' 'compartment_id,compartment_name,service,parent_id,parent_name,assets_found,collection_status,collection_error' > "$TMP_COVERAGE"
printf '%s\n' 'compartment_id,compartment_name,status,command,error' > "$TMP_ERRORS"

TEMP_ERR_FILE=""
cleanup_all() {
  [ -z "$TEMP_ERR_FILE" ] || rm -f -- "$TEMP_ERR_FILE" 2>/dev/null
  rm -rf -- "$WORKDIR" 2>/dev/null
}
trap cleanup_all EXIT
trap 'cleanup_all; exit 130' INT
trap 'cleanup_all; exit 143' TERM

csv_escape() {
  local value="$1"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/}"
  case "$value" in [=+@-]*) value="'$value" ;; esac
  value="${value//\"/\"\"}"
  printf '"%s"' "$value"
}

declare -A COMP_NAME
INCOMPLETE=0
CUR_COMP="<tenancy>"
COLLECT_OUT=""
COLLECT_STATUS="OK"
COLLECT_ERROR=""

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
  local errf out rc err status cname cmd token action=""
  errf="$(mktemp "$WORKDIR/oci-error.XXXXXX" 2>/dev/null)" || {
    echo "ERROR: could not create a secure temporary error file." >&2
    exit 1
  }
  TEMP_ERR_FILE="$errf"
  out="$(oci "${REGION_ARG[@]}" "$@" 2>"$errf")"; rc=$?
  err="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-500)"
  rm -f -- "$errf" 2>/dev/null
  TEMP_ERR_FILE=""

  for token in "$@"; do
    case "$token" in list|get) action="$token" ;; esac
  done

  if [ "$rc" -eq 0 ] && ! has_cli_arg --raw-output "$@"; then
    if ! printf '%s' "$out" | jq -e . >/dev/null 2>&1; then
      rc=65
      err="OCI CLI returned invalid JSON for: $label"
    elif [ "$action" = "list" ] && ! has_cli_arg --query "$@" && \
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
      "$(csv_escape "$err")" >> "$TMP_ERRORS"
  fi
  COLLECT_OUT="$out"
  COLLECT_STATUS="$status"
  COLLECT_ERROR="$err"
}

LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

coverage_row() {
  local comp="$1" service="$2" parent_id="$3" parent_name="$4"
  local count="$5" status="$6" error="$7"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$comp")" "$(csv_escape "${COMP_NAME[$comp]:-<unknown>}")" \
    "$(csv_escape "$service")" "$(csv_escape "$parent_id")" \
    "$(csv_escape "$parent_name")" "$(csv_escape "$count")" \
    "$(csv_escape "$status")" "$(csv_escape "$error")" >> "$TMP_COVERAGE"
}

raw_row() {
  local output="" field escaped
  for field in "$@"; do
    escaped="$(csv_escape "$field")"
    output+="${escaped},"
  done
  echo "${output%,}" >> "$RAW"
}

collection_failure_row() {
  local comp="$1" service="$2" parent_id="$3" parent_name="$4"
  local status="$5" error="$6"
  raw_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "" "" \
    "$parent_id" "$parent_name" "$service" "UNKNOWN" "UNKNOWN" \
    "UNKNOWN" "UNKNOWN" "UNKNOWN" "UNKNOWN" "UNKNOWN" "" "" "" "" "" "" \
    "" "" "" "UNKNOWN" "" "" "$status" "$error"
}

abort_before_scan() {
  local reason="$1"
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

confirm_resolved_targets_interactive() {
  local targets="$1" cid cname first second
  echo
  echo "Resolved command-line scope requires interactive OCID confirmation."
  while IFS=$'\t' read -r cid cname <&3; do
    [ -n "$cid" ] || continue
    echo
    echo "Target: ${cname:-<unknown>}"
    echo "OCID  : $cid"
    echo "Enter this exact OCID to select the target."
    IFS= read -r first || abort_before_scan "scope OCID was not provided"
    first="$(oci_scope_trim "$first")"
    [ "$first" = "$cid" ] || abort_before_scan "scope OCID did not match $cid"
    echo "Re-enter the exact same OCID to confirm the target."
    IFS= read -r second || abort_before_scan "scope confirmation was not provided"
    second="$(oci_scope_trim "$second")"
    [ "$second" = "$cid" ] || abort_before_scan "scope confirmation did not match $cid"
  done 3<<< "$targets"
  echo
  echo "All resolved target OCIDs were confirmed twice."
}

validate_automation_authorization() {
  local targets="$1" cid cname index=0 expected_count actual_count
  expected_count="$(printf '%s\n' "$targets" | grep -c . || true)"
  actual_count="${#CONFIRM_SCOPE_OCIDS[@]}"
  [ "$actual_count" -eq "$expected_count" ] || {
    abort_before_scan "automation supplied $actual_count scope confirmations; expected $expected_count"
  }
  while IFS=$'\t' read -r cid cname; do
    [ -n "$cid" ] || continue
    [ "${CONFIRM_SCOPE_OCIDS[$index]}" = "$cid" ] || {
      abort_before_scan "automation confirmation $((index+1)) did not match resolved OCID $cid"
    }
    index=$((index+1))
  done <<< "$targets"
  [ "$APPROVE_SCAN" = "YES" ] || {
    abort_before_scan "automation did not supply exact --approve-scan YES"
  }
  echo "AUTOMATION APPROVED: every resolved OCID matched and --approve-scan was exact YES."
  echo
}

validate_csv_header() {
  local kind="$1" path="$2"
  python3 - "$kind" "$path" <<'PY'
import csv
import sys

kind, path = sys.argv[1:3]
required = {
    "approval": {
        "compartment_id", "vcn_id", "container_id", "direction", "stateless",
        "protocol", "source_type", "source_or_dest", "source_port_min",
        "source_port_max", "destination_port_min", "destination_port_max",
        "icmp_type", "icmp_code", "approval_status", "approval_id",
        "approval_authority", "approved_by", "approval_date",
        "expiration_date", "business_function", "justification",
        "source_reference",
    },
    "restricted": {
        "entry_id", "protocol", "port_min", "port_max", "direction",
        "category", "service", "function", "authority", "provided_by",
        "source_reference", "effective_date", "expiration_date", "notes",
    },
    "service": {
        "mapping_id", "rule_key", "resource_ocid", "resource_type",
        "resource_name", "listener_status", "listener_address",
        "listener_port", "listener_protocol", "service_name",
        "business_function", "justification", "system_owner", "verified_by",
        "verification_date", "evidence_reference", "source_reference",
    },
}[kind]
with open(path, newline="", encoding="utf-8-sig") as handle:
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except StopIteration:
        raise SystemExit(f"{kind} input is empty: {path}")
normalized = {value.strip() for value in header}
missing = sorted(required - normalized)
if missing:
    raise SystemExit(f"{kind} input missing columns: {', '.join(missing)}")
PY
}

if [ -n "$APPROVAL_FILE" ]; then
  validate_csv_header approval "$APPROVAL_FILE" || exit 1
fi
if [ -n "$RESTRICTED_FILE" ]; then
  validate_csv_header restricted "$RESTRICTED_FILE" || exit 1
fi
if [ -n "$SERVICE_MAPPING_FILE" ]; then
  validate_csv_header service "$SERVICE_MAPPING_FILE" || exit 1
fi

retain_startup_error() {
  local reason="$1"
  if [ "$(wc -l < "$TMP_ERRORS" | tr -d ' ')" -gt 1 ]; then
    mv -n -- "$TMP_ERRORS" "$ERROUT" 2>/dev/null || true
    chmod 600 "$ERROUT" 2>/dev/null || true
    echo "Collection error retained in: $ERROUT" >&2
  fi
  echo "ERROR: $reason" >&2
  exit 1
}

# Resolve tenancy and the approved collection scope. IAM discovery is allowed
# before final YES; no Networking service call occurs until after approval.
oci_capture "resolve tenancy" iam compartment list --access-level ANY --limit 1 \
  --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$COLLECT_OUT"
if [ "$COLLECT_STATUS" != "OK" ] || [ -z "$TENANCY_ID" ] || [ "$TENANCY_ID" = "null" ]; then
  retain_startup_error "could not resolve the authenticated tenancy ($COLLECT_STATUS): $COLLECT_ERROR"
fi
COMP_NAME["$TENANCY_ID"]="root"
CUR_COMP="$TENANCY_ID"

echo "Region : $REGION_OVERRIDE"
echo "Tenancy: $TENANCY_ID"
echo "Scope  : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'approved command-line automation')"
echo

if [ "$SELECT_SCOPE" -eq 1 ]; then
  oci_capture "discover active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    retain_startup_error "compartment discovery failed ($COLLECT_STATUS): $COLLECT_ERROR"
  fi

  scope_catalog="$(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps+="$cid"$'\n'
  done <<< "$scope_catalog"

  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  if [ "$COLLECT_STATUS" != "OK" ]; then
    retain_startup_error "tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR"
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
    retain_startup_error "explicit compartment validation failed ($COLLECT_STATUS): $COLLECT_ERROR"
  fi
  COMP_NAME["$SINGLE_COMP"]="${COLLECT_OUT:-<unknown>}"
else
  oci_capture "enumerate active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    retain_startup_error "compartment enumeration failed ($COLLECT_STATUS): $COLLECT_ERROR"
  fi

  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
  done < <(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)

  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  if [ "$COLLECT_STATUS" != "OK" ]; then
    retain_startup_error "tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR"
  fi
  COMP_NAME["$TENANCY_ID"]="${COLLECT_OUT:-root}"
  ALL_COMPS="$TENANCY_ID"$'\n'"$(printf '%s' "$comp_pairs" | jq -r '.[]?.id' 2>/dev/null)"

  FILTERED_COMPS=""
  IFS=',' read -ra requested_names <<< "$COMP_NAMES_FILTER"
  for requested_name in "${requested_names[@]}"; do
    requested_name="$(printf '%s' "$requested_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [ -n "$requested_name" ] || abort_before_scan "empty compartment name in -n list"
    match_ids=""
    while IFS= read -r cid; do
      [ -z "$cid" ] && continue
      cname="${COMP_NAME[$cid]:-<unknown>}"
      if [ "$(printf '%s' "$cname" | tr '[:upper:]' '[:lower:]')" = \
           "$(printf '%s' "$requested_name" | tr '[:upper:]' '[:lower:]')" ]; then
        match_ids+="$cid"$'\n'
      fi
    done <<< "$ALL_COMPS"
    match_count="$(printf '%s' "$match_ids" | grep -c . || true)"
    [ "$match_count" -eq 1 ] || {
      abort_before_scan "compartment name '$requested_name' resolved to $match_count OCIDs; use -c or interactive OCID selection"
    }
    FILTERED_COMPS+="$(printf '%s' "$match_ids" | head -n 1)"$'\n'
  done
  COMPS="$FILTERED_COMPS"
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
[ "$COMP_COUNT" -gt 0 ] || abort_before_scan "no compartments matched the requested scope"

TARGET_CATALOG=""
while IFS= read -r cid; do
  [ -z "$cid" ] && continue
  TARGET_CATALOG+="$cid"$'\t'"${COMP_NAME[$cid]:-<unknown>}"$'\n'
done <<< "$COMPS"

if [ "$SELECT_SCOPE" -eq 1 ]; then
  SCOPE_TYPE="$OCI_SCOPE_SELECTED_KIND"
  SCOPE_NAME="$OCI_SCOPE_SELECTED_NAME"
  SCOPE_OCID="$OCI_SCOPE_SELECTED_OCID"
elif [ -n "$SINGLE_COMP" ]; then
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    SCOPE_TYPE="AUTOMATION-COMPARTMENT"
  else
    SCOPE_TYPE="MANUAL-COMPARTMENT"
  fi
  SCOPE_NAME="${COMP_NAME[$SINGLE_COMP]:-<unknown>}"
  SCOPE_OCID="$SINGLE_COMP"
else
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    SCOPE_TYPE="AUTOMATION-NAME-FILTER"
  else
    SCOPE_TYPE="MANUAL-NAME-FILTER"
  fi
  SCOPE_NAME="$COMP_NAMES_FILTER"
  SCOPE_OCID="multiple resolved compartment OCIDs"
fi

if [ "$SELECT_SCOPE" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
  confirm_resolved_targets_interactive "$TARGET_CATALOG"
fi

APPROVAL_INPUT_LABEL="NOT PROVIDED — approval cannot be proven"
RESTRICTED_INPUT_LABEL="NOT PROVIDED — restricted-list evaluation cannot be completed"
SERVICE_INPUT_LABEL="NOT PROVIDED — actual services/listeners cannot be verified"
[ -n "$APPROVAL_FILE" ] && APPROVAL_INPUT_LABEL="$APPROVAL_FILE"
[ -n "$RESTRICTED_FILE" ] && RESTRICTED_INPUT_LABEL="$RESTRICTED_FILE"
[ -n "$SERVICE_MAPPING_FILE" ] && SERVICE_INPUT_LABEL="$SERVICE_MAPPING_FILE"
[ "$INVENTORY_ONLY" -eq 1 ] && {
  APPROVAL_INPUT_LABEL="intentionally skipped in inventory-only mode"
  RESTRICTED_INPUT_LABEL="intentionally skipped in inventory-only mode"
  SERVICE_INPUT_LABEL="intentionally skipped in inventory-only mode"
}

WORK_ITEMS="Security Lists, ingress/egress rules and subnet associations
Network Security Groups, ingress/egress rules and VNIC associations
Direction filter: $DIRECTION
Approval baseline: $APPROVAL_INPUT_LABEL
Restricted list: $RESTRICTED_INPUT_LABEL
Actual service/listener mapping: $SERVICE_INPUT_LABEL"
OUTPUT_FILES="$OUT
$BASELINE_TEMPLATE
$APPROVAL_OUT
$RESTRICTED_OUT
$SERVICE_TEMPLATE
$SERVICE_OUT
$SOURCES_OUT
$COVERAGE
$ERROUT (retained only when OCI calls or post-processing fail)"

oci_scope_print_scan_plan \
  "CM-7 OPEN PPS" \
  "cm07-01-open-ports-protocols-services.sh" \
  "CM-7 / CM-7(1) / PPSM" \
  "$REGION_OVERRIDE" \
  "$SCOPE_TYPE" "$SCOPE_NAME" "$SCOPE_OCID" "$COMP_COUNT" \
  "$TARGET_CATALOG" \
  "Requested evidence work" "$WORK_ITEMS" \
  "$OUTPUT_FILES" \
  "OCIDs, CIDRs, NSG relationships, security rules, tags, approval metadata and restricted-list provenance"

if [ "$NON_INTERACTIVE" -eq 1 ]; then
  validate_automation_authorization "$TARGET_CATALOG"
elif ! oci_scope_require_final_approval 1; then
  abort_before_scan "${OCI_SCOPE_APPROVAL_ERROR:-final approval failed}"
fi

echo "Collecting CM-7/PPSM network-rule evidence across $COMP_COUNT compartment(s)..."
echo

proto_name() {
  case "$1" in
    1) echo "ICMP" ;;
    6) echo "TCP" ;;
    17) echo "UDP" ;;
    58) echo "ICMPV6" ;;
    all|"") echo "ANY" ;;
    *) echo "PROTO-$1" ;;
  esac
}

wellknown() {
  local proto="$1" min="$2" max="$3"
  if [ "$proto" = "ICMP" ]; then
    echo "ICMP|Network control and diagnostics; verify required message types"
    return
  fi
  if [ "$proto" = "ICMPV6" ]; then
    echo "ICMPv6|IPv6 control and diagnostics; verify required message types"
    return
  fi
  if [ -z "$min" ] || [ "$min" != "$max" ]; then
    echo "MULTI/ALL|Port range or all ports; application owner must identify function"
    return
  fi
  case "$min" in
    20) echo "FTP-data|Common cleartext FTP data assignment; verify actual listener" ;;
    21) echo "FTP|Common cleartext FTP control assignment; verify actual listener" ;;
    22) echo "SSH|Common secure-shell assignment; verify administrative function" ;;
    23) echo "Telnet|Common cleartext remote-login assignment; verify actual listener" ;;
    25) echo "SMTP|Common mail-transfer assignment; verify actual listener" ;;
    53) echo "DNS|Common name-resolution assignment; verify actual listener" ;;
    80) echo "HTTP|Common plaintext web assignment; verify redirect/application function" ;;
    110) echo "POP3|Common plaintext mail-retrieval assignment; verify actual listener" ;;
    111) echo "RPCbind|Common RPC portmapper assignment; verify actual listener" ;;
    123) echo "NTP|Common time-synchronization assignment; verify actual listener" ;;
    135) echo "MS-RPC|Common Microsoft RPC assignment; verify actual listener" ;;
    137|138|139) echo "NetBIOS|Common NetBIOS assignment; verify actual listener" ;;
    143) echo "IMAP|Common plaintext mail-access assignment; verify actual listener" ;;
    161) echo "SNMP|Common network-management assignment; verify SNMP version" ;;
    162) echo "SNMP-trap|Common network-management trap assignment; verify SNMP version" ;;
    389) echo "LDAP|Common plaintext directory assignment; verify actual listener" ;;
    443) echo "HTTPS|Common TLS web/API assignment; verify certificate and listener" ;;
    445) echo "SMB|Common Microsoft file-sharing assignment; verify actual listener" ;;
    465) echo "SMTPS|Common implicit-TLS mail assignment; verify actual listener" ;;
    514) echo "Syslog/rsh|Protocol-dependent common assignment; verify actual service" ;;
    587) echo "SMTP-submission|Common mail-submission assignment; verify TLS policy" ;;
    636) echo "LDAPS|Common TLS directory assignment; verify certificate and listener" ;;
    993) echo "IMAPS|Common TLS mail-access assignment; verify actual listener" ;;
    995) echo "POP3S|Common TLS mail-retrieval assignment; verify actual listener" ;;
    1433) echo "MSSQL|Common SQL Server assignment; verify actual listener" ;;
    1521) echo "Oracle-DB|Common Oracle Net assignment; verify TLS and listener" ;;
    1522) echo "Oracle-DB-alt|Common alternate Oracle Net assignment; verify listener" ;;
    2049) echo "NFS|Common Network File System assignment; verify internal-only use" ;;
    2484) echo "Oracle-TCPS|Common Oracle Net TLS assignment; verify listener" ;;
    3306) echo "MySQL|Common MySQL assignment; verify actual listener" ;;
    3389) echo "RDP|Common Windows Remote Desktop assignment; verify bastion controls" ;;
    5432) echo "PostgreSQL|Common PostgreSQL assignment; verify actual listener" ;;
    5800|5900) echo "VNC|Common remote-desktop assignment; verify actual listener" ;;
    6379) echo "Redis|Common Redis assignment; verify authentication and listener" ;;
    6443) echo "Kubernetes-API|Common Kubernetes API assignment; verify admin CIDRs" ;;
    9200) echo "Elasticsearch|Common Elasticsearch API assignment; verify actual listener" ;;
    10250) echo "Kubelet|Common Kubernetes kubelet API assignment; verify exposure" ;;
    11211) echo "Memcached|Common Memcached assignment; verify authentication/exposure" ;;
    27017) echo "MongoDB|Common MongoDB assignment; verify actual listener" ;;
    *) echo "UNMAPPED|No local common-service annotation; application owner must identify function" ;;
  esac
}

emit_rule() {
  local comp="$1" vcn_id="$2" vcn_name="$3" container_id="$4"
  local container_name="$5" container_type="$6" attachment_count="$7"
  local applies_to="$8" direction="$9" defined_tags="${10}"
  local freeform_tags="${11}" rule="${12}"
  local parsed proto_raw proto source_type peer spmin spmax dpmin dpmax
  local icmp_type icmp_code stateless description annotation service function exposure
  local sep=$'\x1f'

  parsed="$(printf '%s' "$rule" | jq -r --arg direction "$direction" '
    def value:
      if . == null then "" else tostring end;
    .protocol as $proto |
    [
      ($proto // "all"),
      (if $direction == "INGRESS" then (.["source-type"] // "CIDR_BLOCK")
       else (.["destination-type"] // "CIDR_BLOCK") end),
      (if $direction == "INGRESS" then (.source // "")
       else (.destination // "") end),
      (if $proto == "6" then (.["tcp-options"]["source-port-range"].min // "")
       elif $proto == "17" then (.["udp-options"]["source-port-range"].min // "")
       else "" end),
      (if $proto == "6" then (.["tcp-options"]["source-port-range"].max // "")
       elif $proto == "17" then (.["udp-options"]["source-port-range"].max // "")
       else "" end),
      (if $proto == "6" then (.["tcp-options"]["destination-port-range"].min // "")
       elif $proto == "17" then (.["udp-options"]["destination-port-range"].min // "")
       else "" end),
      (if $proto == "6" then (.["tcp-options"]["destination-port-range"].max // "")
       elif $proto == "17" then (.["udp-options"]["destination-port-range"].max // "")
       else "" end),
      (.["icmp-options"].type // ""),
      (.["icmp-options"].code // ""),
      (.["is-stateless"] // false),
      (.description // "")
    ] | map(value) | join("\u001f")
  ' 2>/dev/null)" || {
    INCOMPLETE=1
    coverage_row "$comp" "RuleNormalization" "$container_id" "$container_name" \
      "UNKNOWN" "ERROR" "jq could not normalize rule JSON"
    collection_failure_row "$comp" "RuleNormalization" "$container_id" "$container_name" \
      "ERROR" "jq could not normalize rule JSON"
    return
  }

  IFS="$sep" read -r proto_raw source_type peer spmin spmax dpmin dpmax \
    icmp_type icmp_code stateless description <<< "$parsed"
  proto="$(proto_name "$proto_raw")"
  annotation="$(wellknown "$proto" "$dpmin" "$dpmax")"
  service="${annotation%%|*}"
  function="${annotation#*|}"

  if [ "$direction" = "INGRESS" ]; then
    case "$peer" in
      0.0.0.0/0|::/0) exposure="INTERNET-WIDE" ;;
      "") exposure="UNKNOWN" ;;
      *) case "$source_type" in
           NETWORK_SECURITY_GROUP) exposure="NSG-SCOPED" ;;
           SERVICE_CIDR_BLOCK) exposure="OCI-SERVICE-SCOPED" ;;
           *) exposure="SCOPED" ;;
         esac ;;
    esac
  else
    case "$peer" in
      0.0.0.0/0|::/0) exposure="ANY-DESTINATION" ;;
      "") exposure="UNKNOWN" ;;
      *) case "$source_type" in
           NETWORK_SECURITY_GROUP) exposure="NSG-SCOPED" ;;
           SERVICE_CIDR_BLOCK) exposure="OCI-SERVICE-SCOPED" ;;
           *) exposure="SCOPED" ;;
         esac ;;
    esac
  fi

  raw_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$vcn_id" "$vcn_name" \
    "$container_id" "$container_name" "$container_type" "$attachment_count" \
    "$applies_to" "$direction" "$stateless" "$proto" "$source_type" "$peer" \
    "$spmin" "$spmax" "$dpmin" "$dpmax" "$icmp_type" "$icmp_code" \
    "$description" "$service" "$function" "$exposure" "$defined_tags" \
    "$freeform_tags" "OK" ""
}

collect_security_lists() {
  local comp="$1" vcn_id="$2" vcn_name="$3" subnets_json="$4"
  local subnet_status="$5" lists_json count sl sl_id sl_name defined_tags freeform_tags
  local applies attachment_count rule_count=0 direction rule association_error

  oci_capture "Security List list [$vcn_name]" network security-list list \
    --compartment-id "$comp" --vcn-id "$vcn_id" --all
  lists_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    coverage_row "$comp" "SecurityList" "$vcn_id" "$vcn_name" \
      "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    collection_failure_row "$comp" "SecurityList" "$vcn_id" "$vcn_name" \
      "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi

  count="$(printf '%s' "$lists_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
  coverage_row "$comp" "SecurityList" "$vcn_id" "$vcn_name" "$count" "OK" ""

  while IFS= read -r sl; do
    [ -z "$sl" ] && continue
    sl_id="$(printf '%s' "$sl" | jq -r '.id // "<unknown-security-list>"')"
    sl_name="$(printf '%s' "$sl" | jq -r '."display-name" // "<unnamed-security-list>"')"
    defined_tags="$(printf '%s' "$sl" | jq -c '."defined-tags" // {}')"
    freeform_tags="$(printf '%s' "$sl" | jq -c '."freeform-tags" // {}')"

    if [ "$subnet_status" = "OK" ]; then
      association_error=""
      applies="$(printf '%s' "$subnets_json" | jq -r --arg id "$sl_id" '
        [if (.data|type)=="object" then ((.data.items // []) | .[])
         elif (.data|type)=="array" then .data[] else empty end |
         select((.["security-list-ids"] // []) | index($id)) |
          ((.["display-name"] // "<unnamed-subnet>") + " (" + (.id // "<unknown>") + ")")]
        | if length == 0 then "<none>" else join("; ") end
      ' 2>/dev/null)" || association_error="jq could not normalize subnet associations"
      attachment_count="$(printf '%s' "$subnets_json" | jq --arg id "$sl_id" '
        [if (.data|type)=="object" then ((.data.items // []) | .[])
         elif (.data|type)=="array" then .data[] else empty end |
         select((.["security-list-ids"] // []) | index($id))] | length
      ' 2>/dev/null)" || association_error="jq could not count subnet associations"
      if [ -n "$association_error" ]; then
        INCOMPLETE=1
        applies="UNKNOWN — subnet association normalization failed"
        attachment_count="UNKNOWN"
        coverage_row "$comp" "SecurityListAssociation" "$sl_id" "$sl_name" \
          "UNKNOWN" "ERROR" "$association_error"
        collection_failure_row "$comp" "SecurityListAssociation" "$sl_id" "$sl_name" \
          "ERROR" "$association_error"
      fi
    else
      applies="UNKNOWN — subnet association collection failed"
      attachment_count="UNKNOWN"
    fi

    if [ "$DIRECTION" = "both" ] || [ "$DIRECTION" = "ingress" ]; then
      while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        emit_rule "$comp" "$vcn_id" "$vcn_name" "$sl_id" "$sl_name" \
          "SecurityList" "$attachment_count" "$applies" "INGRESS" \
          "$defined_tags" "$freeform_tags" "$rule"
        rule_count=$((rule_count+1))
      done <<< "$(printf '%s' "$sl" | jq -c '(.["ingress-security-rules"] // [])[]?')"
    fi

    if [ "$DIRECTION" = "both" ] || [ "$DIRECTION" = "egress" ]; then
      while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        emit_rule "$comp" "$vcn_id" "$vcn_name" "$sl_id" "$sl_name" \
          "SecurityList" "$attachment_count" "$applies" "EGRESS" \
          "$defined_tags" "$freeform_tags" "$rule"
        rule_count=$((rule_count+1))
      done <<< "$(printf '%s' "$sl" | jq -c '(.["egress-security-rules"] // [])[]?')"
    fi
  done <<< "$(printf '%s' "$lists_json" | jq -c "$LIST_ITER" 2>/dev/null)"

  coverage_row "$comp" "SecurityListRule" "$vcn_id" "$vcn_name" "$rule_count" "OK" ""
}

collect_nsgs() {
  local comp="$1" vcn_id="$2" vcn_name="$3"
  local nsgs_json count nsg nsg_id nsg_name defined_tags freeform_tags
  local vnics_json attachment_count applies rules_json rule_count rule direction

  oci_capture "NSG list [$vcn_name]" network nsg list \
    --compartment-id "$comp" --vcn-id "$vcn_id" --all
  nsgs_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    coverage_row "$comp" "NSG" "$vcn_id" "$vcn_name" \
      "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    collection_failure_row "$comp" "NSG" "$vcn_id" "$vcn_name" \
      "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi

  count="$(printf '%s' "$nsgs_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
  coverage_row "$comp" "NSG" "$vcn_id" "$vcn_name" "$count" "OK" ""

  while IFS= read -r nsg; do
    [ -z "$nsg" ] && continue
    nsg_id="$(printf '%s' "$nsg" | jq -r '.id // "<unknown-nsg>"')"
    nsg_name="$(printf '%s' "$nsg" | jq -r '."display-name" // "<unnamed-nsg>"')"
    defined_tags="$(printf '%s' "$nsg" | jq -c '."defined-tags" // {}')"
    freeform_tags="$(printf '%s' "$nsg" | jq -c '."freeform-tags" // {}')"

    oci_capture "NSG VNIC list [$nsg_name]" network nsg vnics list \
      --nsg-id "$nsg_id" --all
    vnics_json="$COLLECT_OUT"
    if [ "$COLLECT_STATUS" = "OK" ]; then
      attachment_count="$(printf '%s' "$vnics_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
      applies="$(printf '%s' "$vnics_json" | jq -r '
        [if (.data|type)=="object" then ((.data.items // []) | .[])
         elif (.data|type)=="array" then .data[] else empty end |
         (.["vnic-id"] // .id // "<unknown-vnic>")]
        | if length == 0 then "<none>" else join("; ") end
      ')"
      coverage_row "$comp" "NSGVNIC" "$nsg_id" "$nsg_name" "$attachment_count" "OK" ""
    else
      attachment_count="UNKNOWN"
      applies="UNKNOWN — NSG VNIC association collection failed"
      coverage_row "$comp" "NSGVNIC" "$nsg_id" "$nsg_name" \
        "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    fi

    oci_capture "NSG rule list [$nsg_name]" network nsg rules list \
      --nsg-id "$nsg_id" --all
    rules_json="$COLLECT_OUT"
    if [ "$COLLECT_STATUS" != "OK" ]; then
      coverage_row "$comp" "NSGRule" "$nsg_id" "$nsg_name" \
        "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
      collection_failure_row "$comp" "NSGRule" "$nsg_id" "$nsg_name" \
        "$COLLECT_STATUS" "$COLLECT_ERROR"
      continue
    fi

    rule_count=0
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      direction="$(printf '%s' "$rule" | jq -r '.direction // "UNKNOWN"' | tr '[:lower:]' '[:upper:]')"
      if [ "$DIRECTION" = "ingress" ] && [ "$direction" != "INGRESS" ]; then continue; fi
      if [ "$DIRECTION" = "egress" ] && [ "$direction" != "EGRESS" ]; then continue; fi
      emit_rule "$comp" "$vcn_id" "$vcn_name" "$nsg_id" "$nsg_name" \
        "NSG" "$attachment_count" "$applies" "$direction" \
        "$defined_tags" "$freeform_tags" "$rule"
      rule_count=$((rule_count+1))
    done <<< "$(printf '%s' "$rules_json" | jq -c "$LIST_ITER" 2>/dev/null)"
    coverage_row "$comp" "NSGRule" "$nsg_id" "$nsg_name" "$rule_count" "OK" ""
  done <<< "$(printf '%s' "$nsgs_json" | jq -c "$LIST_ITER" 2>/dev/null)"
}

collect_compartment() {
  local comp="$1" vcns_json vcn_count vcn vcn_id vcn_name
  local subnets_json subnet_status subnet_count

  CUR_COMP="$comp"
  echo "[CM-7] ${COMP_NAME[$comp]:-<unknown>} ($comp)"

  oci_capture "VCN list" network vcn list --compartment-id "$comp" --all
  vcns_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    coverage_row "$comp" "VCN" "$comp" "${COMP_NAME[$comp]:-<unknown>}" \
      "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    collection_failure_row "$comp" "VCN" "$comp" "${COMP_NAME[$comp]:-<unknown>}" \
      "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi

  vcn_count="$(printf '%s' "$vcns_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
  coverage_row "$comp" "VCN" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$vcn_count" "OK" ""

  while IFS= read -r vcn; do
    [ -z "$vcn" ] && continue
    vcn_id="$(printf '%s' "$vcn" | jq -r '.id // "<unknown-vcn>"')"
    vcn_name="$(printf '%s' "$vcn" | jq -r '."display-name" // "<unnamed-vcn>"')"

    oci_capture "Subnet list [$vcn_name]" network subnet list \
      --compartment-id "$comp" --vcn-id "$vcn_id" --all
    subnets_json="$COLLECT_OUT"
    subnet_status="$COLLECT_STATUS"
    if [ "$subnet_status" = "OK" ]; then
      subnet_count="$(printf '%s' "$subnets_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
      coverage_row "$comp" "Subnet" "$vcn_id" "$vcn_name" "$subnet_count" "OK" ""
    else
      coverage_row "$comp" "Subnet" "$vcn_id" "$vcn_name" \
        "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
      collection_failure_row "$comp" "Subnet" "$vcn_id" "$vcn_name" \
        "$COLLECT_STATUS" "$COLLECT_ERROR"
    fi

    collect_security_lists "$comp" "$vcn_id" "$vcn_name" "$subnets_json" "$subnet_status"
    collect_nsgs "$comp" "$vcn_id" "$vcn_name"
  done <<< "$(printf '%s' "$vcns_json" | jq -c "$LIST_ITER" 2>/dev/null)"
}

while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  collect_compartment "$comp"
done <<< "$COMPS"

TMP_OUT="$WORKDIR/inventory.csv"
TMP_BASELINE="$WORKDIR/approval_template.csv"
TMP_APPROVAL="$WORKDIR/approval_reconciliation.csv"
TMP_RESTRICTED="$WORKDIR/restricted_findings.csv"
TMP_SERVICE_TEMPLATE="$WORKDIR/service_mapping_template.csv"
TMP_SERVICE="$WORKDIR/service_mapping_reconciliation.csv"
TMP_SOURCES="$WORKDIR/input_sources.csv"
POST_ERROR="$WORKDIR/postprocess.error"

if ! python3 - \
  "$RAW" "$TMP_OUT" "$TMP_BASELINE" "$TMP_APPROVAL" "$TMP_RESTRICTED" \
  "$TMP_SERVICE_TEMPLATE" "$TMP_SERVICE" "$TMP_SOURCES" "$TMP_SUMMARY" \
  "$APPROVAL_FILE" "$RESTRICTED_FILE" "$SERVICE_MAPPING_FILE" \
  "$INVENTORY_ONLY" "$TS" "$REGION_OVERRIDE" \
  2>"$POST_ERROR" <<'PY'
import csv
import hashlib
import json
import os
import sys
from datetime import date, datetime

(
    raw_path,
    inventory_path,
    template_path,
    approval_path,
    restricted_path,
    service_template_path,
    service_path,
    sources_path,
    summary_path,
    approval_input,
    restricted_input,
    service_input,
    inventory_only_raw,
    timestamp,
    region,
) = sys.argv[1:16]
inventory_only = inventory_only_raw == "1"
today = datetime.utcnow().date()

IDENTITY_FIELDS = [
    "compartment_id",
    "vcn_id",
    "container_id",
    "direction",
    "stateless",
    "protocol",
    "source_type",
    "source_or_dest",
    "source_port_min",
    "source_port_max",
    "destination_port_min",
    "destination_port_max",
    "icmp_type",
    "icmp_code",
]

APPROVAL_FIELDS = [
    "approval_status",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "expiration_date",
    "business_function",
    "justification",
    "source_reference",
]

def clean(value):
    if value is None:
        value = ""
    value = str(value).replace("\r", " ").replace("\n", " ")
    if value[:1] in ("=", "+", "-", "@"):
        value = "'" + value
    return value

def write_rows(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        writer.writeheader()
        for row in rows:
            writer.writerow({name: clean(row.get(name, "")) for name in fieldnames})
    os.chmod(path, 0o600)

def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))

def normalized(value):
    return str(value or "").strip()

def identity_key(row):
    canonical = "|".join(normalized(row.get(field)) for field in IDENTITY_FIELDS)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def parse_date(value, field, context):
    value = normalized(value)
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise ValueError(f"{context}: invalid {field} date {value!r}; use YYYY-MM-DD") from exc

def unique_values(rows, field):
    return "; ".join(sorted({normalized(row.get(field)) for row in rows if normalized(row.get(field))}))

raw_rows = read_csv(raw_path)
for row in raw_rows:
    row["rule_key"] = identity_key(row) if row.get("collection_status") == "OK" else ""

approval_rows = read_csv(approval_input) if approval_input else []
approval_by_key = {}
approval_duplicate_keys = set()
for index, row in enumerate(approval_rows, start=2):
    key = identity_key(row)
    if key in approval_by_key:
        approval_duplicate_keys.add(key)
    approval_by_key.setdefault(key, []).append(row)
    status = normalized(row.get("approval_status")).upper()
    if status not in {"APPROVED", "DENIED", "PENDING-REVIEW", "EXPIRED", ""}:
        raise ValueError(f"approval row {index}: unsupported approval_status {status!r}")
    approval_date = parse_date(row.get("approval_date"), "approval_date", f"approval row {index}")
    expiration_date = parse_date(row.get("expiration_date"), "expiration_date", f"approval row {index}")
    if approval_date and approval_date > today:
        raise ValueError(f"approval row {index}: approval_date cannot be in the future")
    if approval_date and expiration_date and expiration_date < approval_date:
        raise ValueError(f"approval row {index}: expiration_date precedes approval_date")

restricted_rows = read_csv(restricted_input) if restricted_input else []
if restricted_input and not restricted_rows:
    raise ValueError("restricted list contains no policy entries")
if approval_input and any(row.get("collection_status") == "OK" for row in raw_rows) and not approval_rows:
    raise ValueError("approval baseline contains no rows for the live rule inventory")
restricted_entries = []
seen_entry_ids = set()

def parse_port(value, default, context):
    text = normalized(value).upper()
    if text in {"", "ALL", "ANY", "*"}:
        return default
    try:
        port = int(text)
    except ValueError as exc:
        raise ValueError(f"{context}: invalid port {value!r}") from exc
    if port < 0 or port > 65535:
        raise ValueError(f"{context}: port outside 0-65535: {port}")
    return port

for index, row in enumerate(restricted_rows, start=2):
    context = f"restricted row {index}"
    entry_id = normalized(row.get("entry_id"))
    if not entry_id:
        raise ValueError(f"{context}: entry_id is required")
    if entry_id in seen_entry_ids:
        raise ValueError(f"{context}: duplicate entry_id {entry_id!r}")
    seen_entry_ids.add(entry_id)

    proto = normalized(row.get("protocol")).upper()
    direction = normalized(row.get("direction")).upper()
    category = normalized(row.get("category")).upper()
    if proto not in {"TCP", "UDP", "ICMP", "ICMPV6", "ANY"}:
        raise ValueError(f"{context}: protocol must be TCP, UDP, ICMP, ICMPV6 or ANY")
    if direction not in {"INGRESS", "EGRESS", "ANY"}:
        raise ValueError(f"{context}: direction must be INGRESS, EGRESS or ANY")
    if category not in {"RESTRICTED", "PROHIBITED"}:
        raise ValueError(f"{context}: category must be RESTRICTED or PROHIBITED")

    port_min = parse_port(row.get("port_min"), 0, context)
    port_max = parse_port(row.get("port_max"), 65535, context)
    if port_min > port_max:
        raise ValueError(f"{context}: port_min exceeds port_max")

    for required in ("authority", "provided_by", "source_reference"):
        if not normalized(row.get(required)):
            raise ValueError(f"{context}: {required} is required to prove list provenance")

    effective = parse_date(row.get("effective_date"), "effective_date", context)
    expiration = parse_date(row.get("expiration_date"), "expiration_date", context)
    if effective and effective > today:
        raise ValueError(f"{context}: restricted entry is not effective until {effective}")
    if expiration and expiration < today:
        raise ValueError(f"{context}: restricted entry expired on {expiration}")
    if effective and expiration and expiration < effective:
        raise ValueError(f"{context}: expiration_date precedes effective_date")

    enriched = dict(row)
    enriched.update(
        {
            "_protocol": proto,
            "_direction": direction,
            "_category": category,
            "_port_min": port_min,
            "_port_max": port_max,
        }
    )
    restricted_entries.append(enriched)

service_rows = read_csv(service_input) if service_input else []
service_by_key = {}
seen_mapping_ids = set()
for index, row in enumerate(service_rows, start=2):
    context = f"service mapping row {index}"
    mapping_id = normalized(row.get("mapping_id"))
    rule_key = normalized(row.get("rule_key"))
    if not mapping_id:
        raise ValueError(f"{context}: mapping_id is required")
    if mapping_id in seen_mapping_ids:
        raise ValueError(f"{context}: duplicate mapping_id {mapping_id!r}")
    seen_mapping_ids.add(mapping_id)
    if len(rule_key) != 64 or any(char not in "0123456789abcdefABCDEF" for char in rule_key):
        raise ValueError(f"{context}: rule_key must be the generated 64-character SHA-256 key")

    listener_status = normalized(row.get("listener_status")).upper()
    if listener_status not in {"LISTENING", "NOT-LISTENING", "NOT-APPLICABLE", "UNKNOWN"}:
        raise ValueError(
            f"{context}: listener_status must be LISTENING, NOT-LISTENING, "
            "NOT-APPLICABLE or UNKNOWN"
        )
    listener_port = normalized(row.get("listener_port"))
    if listener_port:
        parse_port(listener_port, 0, context)
    verification_date = parse_date(row.get("verification_date"), "verification_date", context)
    if verification_date and verification_date > today:
        raise ValueError(f"{context}: verification_date cannot be in the future")

    enriched = dict(row)
    enriched["listener_status"] = listener_status
    service_by_key.setdefault(rule_key.lower(), []).append(enriched)

def complete_service_mapping(row, rule):
    required = [
        "resource_ocid",
        "resource_type",
        "resource_name",
        "listener_status",
        "service_name",
        "business_function",
        "justification",
        "system_owner",
        "verified_by",
        "verification_date",
        "evidence_reference",
        "source_reference",
    ]
    missing = [field for field in required if not normalized(row.get(field))]
    listener_status = normalized(row.get("listener_status")).upper()
    if listener_status == "LISTENING":
        for field in ("listener_address", "listener_port", "listener_protocol"):
            if not normalized(row.get(field)):
                missing.append(field)
    if missing:
        return False, "missing " + ", ".join(sorted(set(missing)))
    if not normalized(row.get("resource_ocid")).startswith("ocid1."):
        return False, "resource_ocid is not an OCI OCID"
    if listener_status == "UNKNOWN":
        return False, "listener status remains UNKNOWN"
    if listener_status == "NOT-APPLICABLE" and normalized(rule.get("attachment_count")) != "0":
        return False, "NOT-APPLICABLE is only valid for an unattached rule container"
    if listener_status == "LISTENING":
        listener_port = int(normalized(row.get("listener_port")))
        rule_min, rule_max = rule_port_range(rule)
        if not rule_min <= listener_port <= rule_max:
            return False, f"listener port {listener_port} is outside live rule range {rule_min}-{rule_max}"
        listener_protocol = normalized(row.get("listener_protocol")).upper()
        rule_protocol = normalized(rule.get("protocol")).upper()
        if rule_protocol != "ANY" and listener_protocol != rule_protocol:
            return False, f"listener protocol {listener_protocol} does not match live rule protocol {rule_protocol}"
    return True, ""

def complete_approval(row):
    required = [
        "approval_id",
        "approval_authority",
        "approved_by",
        "approval_date",
        "business_function",
        "justification",
        "source_reference",
    ]
    missing = [field for field in required if not normalized(row.get(field))]
    expiration = parse_date(row.get("expiration_date"), "expiration_date", "approval")
    if expiration and expiration < today:
        return False, f"approval expired on {expiration}"
    if missing:
        return False, "missing " + ", ".join(missing)
    return True, ""

def match_approval(rule):
    if not approval_input:
        return "NOT-PROVIDED", {}, "No approval baseline supplied"
    key = rule["rule_key"]
    candidates = approval_by_key.get(key, [])
    if not candidates:
        return "UNAPPROVED-DRIFT", {}, "Live rule is absent from the supplied baseline"
    if key in approval_duplicate_keys or len(candidates) != 1:
        return "AMBIGUOUS-BASELINE", {}, "Multiple baseline rows match the live rule"
    row = candidates[0]
    status = normalized(row.get("approval_status")).upper() or "PENDING-REVIEW"
    if status == "APPROVED":
        complete, note = complete_approval(row)
        return ("APPROVED" if complete else "APPROVAL-INCOMPLETE"), row, note
    if status == "DENIED":
        return "DENIED", row, "Baseline explicitly denies this rule"
    if status == "EXPIRED":
        return "EXPIRED", row, "Baseline marks this approval expired"
    return "PENDING-REVIEW", row, "Baseline row is not approved"

def rule_port_range(rule):
    proto = normalized(rule.get("protocol")).upper()
    minimum = parse_port(rule.get("destination_port_min"), 0, "live rule")
    maximum = parse_port(rule.get("destination_port_max"), 65535, "live rule")
    if proto not in {"TCP", "UDP", "ANY"}:
        minimum, maximum = 0, 65535
    return minimum, maximum

def restricted_matches(rule):
    if not restricted_input:
        return []
    rule_proto = normalized(rule.get("protocol")).upper()
    rule_direction = normalized(rule.get("direction")).upper()
    rule_min, rule_max = rule_port_range(rule)
    matches = []
    for entry in restricted_entries:
        if entry["_protocol"] not in {"ANY", rule_proto} and rule_proto != "ANY":
            continue
        if entry["_direction"] not in {"ANY", rule_direction}:
            continue
        if max(rule_min, entry["_port_min"]) <= min(rule_max, entry["_port_max"]):
            matches.append(entry)
    return matches

inventory_fields = [
    "rule_key",
    "compartment_id",
    "compartment_name",
    "vcn_id",
    "vcn_name",
    "container_id",
    "container_name",
    "container_type",
    "attachment_count",
    "applies_to",
    "direction",
    "stateless",
    "protocol",
    "source_type",
    "source_or_dest",
    "source_port_min",
    "source_port_max",
    "destination_port_min",
    "destination_port_max",
    "icmp_type",
    "icmp_code",
    "description",
    "well_known_service",
    "inferred_function",
    "exposure_flag",
    "defined_tags",
    "freeform_tags",
] + APPROVAL_FIELDS + [
    "restricted_status",
    "restricted_entry_ids",
    "restricted_categories",
    "restricted_authorities",
    "restricted_providers",
    "service_mapping_status",
    "mapped_resources",
    "actual_services",
    "listener_statuses",
    "review_result",
    "collection_status",
    "collection_error",
]

approval_output_fields = [
    "reconciliation_status",
    "rule_key",
    "compartment_id",
    "compartment_name",
    "vcn_id",
    "vcn_name",
    "container_id",
    "container_name",
    "container_type",
    "direction",
    "protocol",
    "source_type",
    "source_or_dest",
    "source_port_min",
    "source_port_max",
    "destination_port_min",
    "destination_port_max",
    "icmp_type",
    "icmp_code",
] + APPROVAL_FIELDS + ["note"]

restricted_output_fields = [
    "severity",
    "rule_key",
    "compartment_id",
    "compartment_name",
    "vcn_id",
    "vcn_name",
    "container_id",
    "container_name",
    "container_type",
    "attachment_count",
    "direction",
    "protocol",
    "source_or_dest",
    "destination_port_min",
    "destination_port_max",
    "exposure_flag",
    "entry_id",
    "category",
    "restricted_protocol",
    "restricted_port_min",
    "restricted_port_max",
    "service",
    "function",
    "authority",
    "provided_by",
    "source_reference",
    "effective_date",
    "expiration_date",
    "notes",
]

service_mapping_fields = [
    "mapping_status",
    "mapping_id",
    "rule_key",
    "compartment_id",
    "compartment_name",
    "vcn_id",
    "vcn_name",
    "container_id",
    "container_name",
    "container_type",
    "direction",
    "protocol",
    "source_or_dest",
    "destination_port_min",
    "destination_port_max",
    "resource_ocid",
    "resource_type",
    "resource_name",
    "listener_status",
    "listener_address",
    "listener_port",
    "listener_protocol",
    "service_name",
    "business_function",
    "justification",
    "system_owner",
    "verified_by",
    "verification_date",
    "evidence_reference",
    "source_reference",
    "note",
]

service_template_fields = [field for field in service_mapping_fields if field not in {"mapping_status", "note"}]

template_fields = [
    "rule_key",
    "compartment_id",
    "compartment_name",
    "vcn_id",
    "vcn_name",
    "container_id",
    "container_name",
    "container_type",
    "direction",
    "stateless",
    "protocol",
    "source_type",
    "source_or_dest",
    "source_port_min",
    "source_port_max",
    "destination_port_min",
    "destination_port_max",
    "icmp_type",
    "icmp_code",
    "well_known_service",
    "inferred_function",
    "approval_status",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "expiration_date",
    "business_function",
    "justification",
    "source_reference",
]

inventory_rows = []
approval_output = []
restricted_output = []
service_output = []
service_template_rows = []
template_rows = []
seen_live_keys = set()
counts = {
    "rules": 0,
    "approved": 0,
    "unapproved": 0,
    "restricted": 0,
    "prohibited": 0,
    "internet_wide": 0,
    "inactive": 0,
    "service_verified": 0,
    "service_incomplete": 0,
}

for rule in raw_rows:
    if rule.get("collection_status") != "OK":
        result = dict(rule)
        result.update(
            {
                "approval_status": "NOT-EVALUATED",
                "restricted_status": "NOT-EVALUATED",
                "service_mapping_status": "NOT-EVALUATED",
                "review_result": "COLLECTION-FAILED",
            }
        )
        inventory_rows.append(result)
        continue

    counts["rules"] += 1
    seen_live_keys.add(rule["rule_key"])
    approval_status, approval, approval_note = match_approval(rule)
    matches = restricted_matches(rule)
    mappings = service_by_key.get(rule["rule_key"].lower(), [])
    mapping_notes = []
    if inventory_only:
        service_status = "SKIPPED-INVENTORY-ONLY"
    elif not service_input:
        service_status = "SERVICE-MAPPING-NOT-PROVIDED"
        mapping_notes.append("No actual service/listener mapping was supplied")
    elif not mappings:
        service_status = "SERVICE-MAPPING-MISSING"
        mapping_notes.append("No service mapping row matches this live rule")
    else:
        for mapping in mappings:
            complete, note = complete_service_mapping(mapping, rule)
            if not complete:
                mapping_notes.append(f"{normalized(mapping.get('mapping_id'))}: {note}")
        service_status = "SERVICE-VERIFIED" if not mapping_notes else "SERVICE-MAPPING-INCOMPLETE"
    if service_status == "SERVICE-VERIFIED":
        counts["service_verified"] += 1
    elif not inventory_only:
        counts["service_incomplete"] += 1
    categories = {entry["_category"] for entry in matches}
    if "PROHIBITED" in categories:
        restricted_status = "PROHIBITED-MATCH"
        counts["prohibited"] += 1
    elif "RESTRICTED" in categories:
        restricted_status = "RESTRICTED-MATCH"
        counts["restricted"] += 1
    elif restricted_input:
        restricted_status = "NO-LIST-MATCH"
    else:
        restricted_status = "NOT-PROVIDED"

    if approval_status == "APPROVED":
        counts["approved"] += 1
    else:
        counts["unapproved"] += 1
    if rule.get("exposure_flag") == "INTERNET-WIDE":
        counts["internet_wide"] += 1
    if normalized(rule.get("attachment_count")) == "0":
        counts["inactive"] += 1

    if restricted_status == "PROHIBITED-MATCH":
        review_result = "PROHIBITED-PORT-OR-PROTOCOL"
    elif restricted_status == "RESTRICTED-MATCH":
        review_result = "RESTRICTED-PORT-OR-PROTOCOL"
    elif service_status != "SERVICE-VERIFIED" and not inventory_only:
        review_result = service_status
    elif approval_status != "APPROVED" and not inventory_only:
        review_result = approval_status
    elif rule.get("exposure_flag") == "INTERNET-WIDE":
        review_result = "REVIEW-INTERNET-EXPOSURE"
    elif normalized(rule.get("attachment_count")) == "0":
        review_result = "REVIEW-INACTIVE-CONTAINER"
    elif inventory_only:
        review_result = "INVENTORY-ONLY-NOT-APPROVED"
    else:
        review_result = "NO-LIST-EXCEPTION-DETECTED"

    output = dict(rule)
    for field in APPROVAL_FIELDS:
        output[field] = approval.get(field, "") if approval else ""
    output["approval_status"] = approval_status
    output.update(
        {
            "restricted_status": restricted_status,
            "restricted_entry_ids": "; ".join(normalized(x.get("entry_id")) for x in matches),
            "restricted_categories": "; ".join(sorted(categories)),
            "restricted_authorities": unique_values(matches, "authority"),
            "restricted_providers": unique_values(matches, "provided_by"),
            "service_mapping_status": service_status,
            "mapped_resources": unique_values(mappings, "resource_ocid"),
            "actual_services": unique_values(mappings, "service_name"),
            "listener_statuses": unique_values(mappings, "listener_status"),
            "review_result": review_result,
        }
    )
    inventory_rows.append(output)

    approval_row = dict(rule)
    approval_row.update(approval)
    approval_row["reconciliation_status"] = approval_status
    approval_row["approval_status"] = approval_status
    approval_row["note"] = approval_note
    approval_output.append(approval_row)

    template = {field: rule.get(field, "") for field in template_fields}
    template.update(
        {
            "approval_status": "PENDING-REVIEW",
            "approval_id": "",
            "approval_authority": "",
            "approved_by": "",
            "approval_date": "",
            "expiration_date": "",
            "business_function": "",
            "justification": "",
            "source_reference": "",
        }
    )
    template_rows.append(template)

    service_template = {field: rule.get(field, "") for field in service_template_fields}
    service_template.update(
        {
            "mapping_id": "",
            "resource_ocid": "",
            "resource_type": "",
            "resource_name": "",
            "listener_status": "UNKNOWN",
            "listener_address": "",
            "listener_port": "",
            "listener_protocol": "",
            "service_name": "",
            "business_function": "",
            "justification": "",
            "system_owner": "",
            "verified_by": "",
            "verification_date": "",
            "evidence_reference": "",
            "source_reference": "",
        }
    )
    service_template_rows.append(service_template)

    if mappings:
        for mapping in mappings:
            complete, note = complete_service_mapping(mapping, rule)
            service_record = {field: rule.get(field, "") for field in service_mapping_fields}
            service_record.update(mapping)
            service_record["mapping_status"] = "SERVICE-VERIFIED" if complete else "SERVICE-MAPPING-INCOMPLETE"
            service_record["note"] = note
            service_output.append(service_record)
    elif not inventory_only:
        service_record = {field: rule.get(field, "") for field in service_mapping_fields}
        service_record["mapping_status"] = service_status
        service_record["note"] = "; ".join(mapping_notes)
        service_output.append(service_record)

    for entry in matches:
        if entry["_category"] == "PROHIBITED" and rule.get("exposure_flag") == "INTERNET-WIDE":
            severity = "CRITICAL"
        elif entry["_category"] == "PROHIBITED":
            severity = "HIGH"
        elif rule.get("exposure_flag") == "INTERNET-WIDE":
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        finding = {field: rule.get(field, "") for field in restricted_output_fields}
        finding.update(
            {
                "severity": severity,
                "entry_id": entry.get("entry_id", ""),
                "category": entry["_category"],
                "restricted_protocol": entry["_protocol"],
                "restricted_port_min": entry["_port_min"],
                "restricted_port_max": entry["_port_max"],
                "service": entry.get("service", ""),
                "function": entry.get("function", ""),
                "authority": entry.get("authority", ""),
                "provided_by": entry.get("provided_by", ""),
                "source_reference": entry.get("source_reference", ""),
                "effective_date": entry.get("effective_date", ""),
                "expiration_date": entry.get("expiration_date", ""),
                "notes": entry.get("notes", ""),
            }
        )
        restricted_output.append(finding)

# Approved baseline entries that are no longer live remain visible.
for key, candidates in approval_by_key.items():
    if key in seen_live_keys:
        continue
    for baseline in candidates:
        if normalized(baseline.get("approval_status")).upper() != "APPROVED":
            continue
        missing = dict(baseline)
        missing["reconciliation_status"] = "APPROVED-NOT-LIVE"
        missing["rule_key"] = key
        missing["note"] = "Approved baseline rule was not found in live OCI configuration"
        approval_output.append(missing)

# Service mappings that no longer correspond to a live rule remain visible so
# stale attestations cannot silently survive a configuration change.
for key, mappings in service_by_key.items():
    if key in {value.lower() for value in seen_live_keys}:
        continue
    for mapping in mappings:
        stale = dict(mapping)
        stale["mapping_status"] = "SERVICE-MAPPING-NOT-LIVE"
        stale["note"] = "Mapped rule was not found in live OCI configuration"
        service_output.append(stale)

write_rows(inventory_path, inventory_fields, inventory_rows)
write_rows(template_path, template_fields, template_rows)
write_rows(approval_path, approval_output_fields, approval_output)
write_rows(restricted_path, restricted_output_fields, restricted_output)
write_rows(service_template_path, service_template_fields, service_template_rows)
write_rows(service_path, service_mapping_fields, service_output)

source_fields = [
    "input_type",
    "status",
    "file_name",
    "sha256",
    "row_count",
    "authority",
    "provided_by",
    "source_reference",
    "effective_dates",
    "expiration_dates",
    "collector_timestamp",
    "region",
]
source_rows = []

def source_row(kind, path, rows, authority_field, provider_field):
    if inventory_only:
        return {
            "input_type": kind,
            "status": "SKIPPED-INVENTORY-ONLY",
            "collector_timestamp": timestamp,
            "region": region,
        }
    if not path:
        return {
            "input_type": kind,
            "status": "NOT-PROVIDED",
            "collector_timestamp": timestamp,
            "region": region,
        }
    with open(path, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    if kind == "RESTRICTED-LIST":
        date_field = "effective_date"
    elif kind == "SERVICE-MAPPING":
        date_field = "verification_date"
    else:
        date_field = "approval_date"
    return {
        "input_type": kind,
        "status": "PROVIDED",
        "file_name": os.path.basename(path),
        "sha256": digest,
        "row_count": len(rows),
        "authority": unique_values(rows, authority_field),
        "provided_by": unique_values(rows, provider_field),
        "source_reference": unique_values(rows, "source_reference"),
        "effective_dates": unique_values(rows, date_field),
        "expiration_dates": unique_values(rows, "expiration_date"),
        "collector_timestamp": timestamp,
        "region": region,
    }

source_rows.append(
    source_row("APPROVAL-BASELINE", approval_input, approval_rows, "approval_authority", "approved_by")
)
source_rows.append(
    source_row("RESTRICTED-LIST", restricted_input, restricted_rows, "authority", "provided_by")
)
source_rows.append(
    source_row("SERVICE-MAPPING", service_input, service_rows, "system_owner", "verified_by")
)
write_rows(sources_path, source_fields, source_rows)

with open(summary_path, "w", encoding="utf-8") as handle:
    for key, value in counts.items():
        handle.write(f"{key}={value}\n")
    handle.write(f"approval_input={'PROVIDED' if approval_input else ('SKIPPED' if inventory_only else 'NOT-PROVIDED')}\n")
    handle.write(f"restricted_input={'PROVIDED' if restricted_input else ('SKIPPED' if inventory_only else 'NOT-PROVIDED')}\n")
    handle.write(f"service_input={'PROVIDED' if service_input else ('SKIPPED' if inventory_only else 'NOT-PROVIDED')}\n")
PY
then
  POST_MESSAGE="$(tr '\n\r' '  ' < "$POST_ERROR" | sed 's/  */ /g' | cut -c1-800)"
  [ -n "$POST_MESSAGE" ] || POST_MESSAGE="unknown post-processing error"
  INCOMPLETE=1
  printf '%s,%s,%s,%s,%s\n' \
    "$(csv_escape "$TENANCY_ID")" "$(csv_escape "${COMP_NAME[$TENANCY_ID]:-root}")" \
    "$(csv_escape "ERROR")" "$(csv_escape "local CSV post-processing")" \
    "$(csv_escape "$POST_MESSAGE")" >> "$TMP_ERRORS"

  cp -- "$RAW" "$TMP_OUT"
  printf '%s\n' 'status,error' > "$TMP_BASELINE"
  printf '%s,%s\n' "$(csv_escape "POSTPROCESS-FAILED")" "$(csv_escape "$POST_MESSAGE")" >> "$TMP_BASELINE"
  cp -- "$TMP_BASELINE" "$TMP_APPROVAL"
  cp -- "$TMP_BASELINE" "$TMP_RESTRICTED"
  cp -- "$TMP_BASELINE" "$TMP_SERVICE_TEMPLATE"
  cp -- "$TMP_BASELINE" "$TMP_SERVICE"
  cp -- "$TMP_BASELINE" "$TMP_SOURCES"
  printf '%s\n' 'rules=UNKNOWN' > "$TMP_SUMMARY"
fi

if [ "$INVENTORY_ONLY" -eq 0 ]; then
  if [ -z "$APPROVAL_FILE" ]; then
    INCOMPLETE=1
    echo "WARNING: no approval baseline supplied; approval proof is incomplete." >&2
  fi
  if [ -z "$RESTRICTED_FILE" ]; then
    INCOMPLETE=1
    echo "WARNING: no authoritative restricted list supplied; restricted-list evaluation is incomplete." >&2
  fi
  if [ -z "$SERVICE_MAPPING_FILE" ]; then
    INCOMPLETE=1
    echo "WARNING: no actual service/listener mapping supplied; service proof is incomplete." >&2
  fi
fi

SERVICE_GAPS="$(awk -F= '$1 == "service_incomplete" {print $2}' "$TMP_SUMMARY" 2>/dev/null | tail -n 1)"
if [ -n "$SERVICE_GAPS" ] && [ "$SERVICE_GAPS" -gt 0 ] 2>/dev/null; then
  INCOMPLETE=1
  echo "WARNING: $SERVICE_GAPS live rule(s) lack complete actual-service/listener verification." >&2
fi

for pair in \
  "$TMP_OUT|$OUT" \
  "$TMP_BASELINE|$BASELINE_TEMPLATE" \
  "$TMP_APPROVAL|$APPROVAL_OUT" \
  "$TMP_RESTRICTED|$RESTRICTED_OUT" \
  "$TMP_SERVICE_TEMPLATE|$SERVICE_TEMPLATE" \
  "$TMP_SERVICE|$SERVICE_OUT" \
  "$TMP_SOURCES|$SOURCES_OUT" \
  "$TMP_COVERAGE|$COVERAGE"; do
  src="${pair%%|*}"
  dst="${pair#*|}"
  mv -n -- "$src" "$dst" || {
    echo "ERROR: could not publish evidence file: $dst" >&2
    exit 1
  }
  if [ -e "$src" ]; then
    echo "ERROR: output appeared during collection; refusing to overwrite: $dst" >&2
    exit 1
  fi
  chmod 600 "$dst" 2>/dev/null || true
done

if [ "$(wc -l < "$TMP_ERRORS" | tr -d ' ')" -gt 1 ]; then
  mv -n -- "$TMP_ERRORS" "$ERROUT"
  if [ -e "$TMP_ERRORS" ]; then
    echo "ERROR: refusing to overwrite collection error ledger: $ERROUT" >&2
    exit 1
  fi
  chmod 600 "$ERROUT" 2>/dev/null || true
fi

echo
echo "CM-7 / PPSM COLLECTION SUMMARY"
echo "==============================="
if [ -r "$TMP_SUMMARY" ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      rules) echo "Live OCI rules                 : $value" ;;
      approved) echo "Approved live rules            : $value" ;;
      unapproved) echo "Not approved/unevaluated rules : $value" ;;
      restricted) echo "Restricted-list matches        : $value" ;;
      prohibited) echo "Prohibited-list matches        : $value" ;;
      internet_wide) echo "Internet-wide ingress rules    : $value" ;;
      inactive) echo "Rules in unattached containers : $value" ;;
      service_verified) echo "Rules with verified services  : $value" ;;
      service_incomplete) echo "Rules missing service proof    : $value" ;;
      approval_input) echo "Approval baseline              : $value" ;;
      restricted_input) echo "Restricted list                : $value" ;;
      service_input) echo "Service/listener mapping       : $value" ;;
    esac
  done < "$TMP_SUMMARY"
fi
echo
echo "Inventory                    : $OUT"
echo "Approval template            : $BASELINE_TEMPLATE"
echo "Approval reconciliation      : $APPROVAL_OUT"
echo "Restricted findings          : $RESTRICTED_OUT"
echo "Service mapping template     : $SERVICE_TEMPLATE"
echo "Service mapping results      : $SERVICE_OUT"
echo "Input-source provenance      : $SOURCES_OUT"
echo "Coverage                     : $COVERAGE"
[ ! -e "$ERROUT" ] || echo "Collection errors            : $ERROUT"
echo
echo "Reminder: OCI rules are packet-filter permissions, not proof of a listening"
echo "service or end-to-end reachability. Complete the Task 6 manual checklist."

if [ "$INCOMPLETE" -ne 0 ]; then
  echo "RESULT: INCOMPLETE — review missing inputs, coverage and collection errors." >&2
  exit 3
fi

echo "RESULT: COLLECTION COMPLETE — findings and approvals still require review."
exit 0
