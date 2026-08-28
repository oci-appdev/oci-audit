#!/usr/bin/env bash
#
# cm11-01-software-installation-control.sh
# Collector ID: CM11-01
#
# CM-11 / CM-11(1) EVIDENCE — Software installation control
#
# Read-only OCI evidence for three distinct questions:
#   1. Who has candidate technical capability to install/provision software?
#   2. Which installed or deployable software resources are approved?
#   3. Which software resources are restricted or prohibited?
#
# OCI IAM does not expose a fully evaluated effective-permissions API. Policy
# statements are therefore reported as CANDIDATE ENTITLEMENTS, expanded to
# classic IAM group members when possible, then reconciled to an authoritative
# installer authorization input. Identity-domain membership, host SSH/sudo,
# break-glass access and software installed outside OS Management Hub remain
# explicit evidence boundaries.
#
# READ-ONLY CLOUD BOUNDARY: every OCI call is list/get. The script never
# installs, updates, removes, pushes, creates, attaches or deletes software or
# OCI resources.
#
# Usage:
#   bash cm11-01-software-installation-control.sh -r us-langley-1
#       Interactive by default: discover tenancy/compartments, enter the exact
#       selected OCID twice, review the plan, then type exact uppercase YES.
#
#   bash cm11-01-software-installation-control.sh -i -r us-langley-1
#   bash cm11-01-software-installation-control.sh \
#       -c <compartment-ocid> -r us-langley-1 --inventory-only
#   bash cm11-01-software-installation-control.sh \
#       -n 'VCN,Shared Services,CD3' -r us-langley-1 \
#       -p DOJ-GOV-PROFILE \
#       -u authorized_installers.csv -a approved_software.csv \
#       -x restricted_software.csv
#   bash cm11-01-software-installation-control.sh \
#       -c <compartment-ocid> -r us-langley-1 --non-interactive \
#       --confirm-scope-ocid <same-compartment-ocid> \
#       --approve-scan YES --inventory-only
#   bash cm11-01-software-installation-control.sh --selfcheck
#
# Inputs:
#   -u, --authorized-installers FILE
#       Organizationally approved people/principals and permitted installation
#       capabilities, including approval, manager, request process and control.
#
#   -a, --approved-software FILE
#       Approved OS packages, compute images and container images/resources.
#
#   -x, --restricted-software FILE
#       Current authoritative restricted/prohibited software list. No built-in
#       restriction list is supplied because policy ownership and currency must
#       be attributable to the organization.
#
#   --inventory-only
#       Discovery pass that produces live inventory plus review templates. It
#       intentionally does not claim authorization, approval or restrictions.
#
# Output:
#   cm11-01_software_inventory_<ts>.csv
#   cm11-01_authorized_installer_template_<ts>.csv
#   cm11-01_installer_entitlements_<ts>.csv
#   cm11-01_approved_software_template_<ts>.csv
#   cm11-01_software_reconciliation_<ts>.csv
#   cm11-01_restricted_findings_<ts>.csv
#   cm11-01_technical_controls_<ts>.csv
#   cm11-01_iam_policy_statements_<ts>.csv
#   cm11-01_identity_membership_<ts>.csv
#   cm11-01_input_sources_<ts>.csv
#   cm11-01_coverage_<ts>.csv
#   cm11-01_collection_errors_<ts>.csv (failed calls only)
#
# Exit codes:
#   0  collection completed; findings still require human review
#   1  collector could not start, validate inputs or establish scope
#   3  evidence is incomplete, including missing required source lists

set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/lib/oci-scope-selector.sh"
POSTPROCESSOR="$SCRIPT_DIR/lib/cm11-01-reconcile.py"

readonly_selfcheck() {                                           # selfcheck-exempt
  local deny hits raw rawpat                                    # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")          # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='(oci|oci_capture)[[:space:]].*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|push|install|remove|refresh|run-now|promote|switch)([[:space:]]|$)'  # selfcheck-exempt
  hits="$(grep -nE "$deny" "${check_paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  rawpat="raw""-request"                                        # selfcheck-exempt
  raw="$(grep -nE "$rawpat" "${check_paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"        # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ]; then                     # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — prohibited call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED (cm11-01-software-installation-control)"
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
[ -r "$POSTPROCESSOR" ] || { echo "ERROR: CM-11 post-processor not found: $POSTPROCESSOR" >&2; exit 1; }

# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION_OVERRIDE=""
OUTDIR="."
PROFILE=""
AUTHORIZED_FILE=""
APPROVED_FILE=""
RESTRICTED_FILE=""
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
    -o|--output-dir) need_value "$@"; OUTDIR="$2"; shift 2 ;;
    -p|--profile) need_value "$@"; PROFILE="$2"; shift 2 ;;
    -u|--authorized-installers) need_value "$@"; AUTHORIZED_FILE="$2"; shift 2 ;;
    -a|--approved-software) need_value "$@"; APPROVED_FILE="$2"; shift 2 ;;
    -x|--restricted-software) need_value "$@"; RESTRICTED_FILE="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --confirm-scope-ocid) need_value "$@"; CONFIRM_SCOPE_OCIDS+=("$2"); shift 2 ;;
    --approve-scan) need_value "$@"; APPROVE_SCAN="$2"; shift 2 ;;
    --inventory-only) INVENTORY_ONLY=1; shift ;;
    --selfcheck) echo "ERROR: --selfcheck must be used by itself." >&2; exit 1 ;;
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
if [ "$INVENTORY_ONLY" -eq 1 ] && { [ -n "$AUTHORIZED_FILE" ] || [ -n "$APPROVED_FILE" ] || [ -n "$RESTRICTED_FILE" ]; }; then
  echo "ERROR: --inventory-only cannot be combined with authorization/approval/restriction inputs." >&2
  exit 1
fi
for input_pair in \
  "authorized installer list|$AUTHORIZED_FILE" \
  "approved software list|$APPROVED_FILE" \
  "restricted software list|$RESTRICTED_FILE"; do
  input_label="${input_pair%%|*}"
  input_path="${input_pair#*|}"
  if [ -n "$input_path" ] && [ ! -r "$input_path" ]; then
    echo "ERROR: $input_label is not readable: $input_path" >&2
    exit 1
  fi
done
if [ -z "$REGION_OVERRIDE" ]; then
  echo "ERROR: -r/--region is required so the evidence records the exact OCI region." >&2
  exit 1
fi

# A manual run without -c or -n always requires interactive discovery.
if [ "$SELECT_SCOPE" -eq 0 ] && [ -z "$SINGLE_COMP" ] && [ -z "$COMP_NAMES_FILTER" ]; then
  SELECT_SCOPE=1
fi

readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

validate_csv_header() {
  local kind="$1" path="$2"
  python3 - "$kind" "$path" <<'PY'
import csv
import sys

kind, path = sys.argv[1:3]
required = {
    "authorized": {
        "entry_id", "principal_type", "principal_name", "principal_ocid",
        "user_name", "user_ocid", "install_capability", "scope",
        "authorization_status", "approval_id", "approval_authority",
        "approved_by", "approval_date", "expiration_date", "manager",
        "technical_control", "request_process", "source_reference", "notes",
    },
    "approved": {
        "entry_id", "software_type", "name_pattern", "version_pattern",
        "architecture_pattern", "repository_or_publisher_pattern",
        "scope_pattern", "approval_status", "approval_id",
        "approval_authority", "approved_by", "approval_date",
        "expiration_date", "business_function", "justification",
        "source_reference", "notes",
    },
    "restricted": {
        "entry_id", "software_type", "name_pattern", "version_pattern",
        "architecture_pattern", "repository_or_publisher_pattern",
        "scope_pattern", "category", "authority", "provided_by",
        "source_reference", "effective_date", "expiration_date",
        "restriction", "notes",
    },
}[kind]
with open(path, newline="", encoding="utf-8-sig") as handle:
    reader = csv.reader(handle)
    try:
        header = next(reader)
    except StopIteration:
        raise SystemExit(f"{kind} input is empty: {path}")
missing = sorted(required - {value.strip() for value in header})
if missing:
    raise SystemExit(f"{kind} input missing columns: {', '.join(missing)}")
PY
}

[ -z "$AUTHORIZED_FILE" ] || validate_csv_header authorized "$AUTHORIZED_FILE" || exit 1
[ -z "$APPROVED_FILE" ] || validate_csv_header approved "$APPROVED_FILE" || exit 1
[ -z "$RESTRICTED_FILE" ] || validate_csv_header restricted "$RESTRICTED_FILE" || exit 1

REGION_ARG=(--region "$REGION_OVERRIDE")
PROFILE_ARG=()
[ -z "$PROFILE" ] || PROFILE_ARG=(--profile "$PROFILE")
umask 077
mkdir -p -- "$OUTDIR" 2>/dev/null || {
  echo "ERROR: cannot create output directory: $OUTDIR" >&2
  exit 1
}

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SOFTWARE_OUT="$OUTDIR/cm11-01_software_inventory_${TS}.csv"
INSTALLER_TEMPLATE_OUT="$OUTDIR/cm11-01_authorized_installer_template_${TS}.csv"
ENTITLEMENT_OUT="$OUTDIR/cm11-01_installer_entitlements_${TS}.csv"
APPROVED_TEMPLATE_OUT="$OUTDIR/cm11-01_approved_software_template_${TS}.csv"
RECONCILIATION_OUT="$OUTDIR/cm11-01_software_reconciliation_${TS}.csv"
RESTRICTED_OUT="$OUTDIR/cm11-01_restricted_findings_${TS}.csv"
CONTROLS_OUT="$OUTDIR/cm11-01_technical_controls_${TS}.csv"
POLICIES_OUT="$OUTDIR/cm11-01_iam_policy_statements_${TS}.csv"
MEMBERSHIP_OUT="$OUTDIR/cm11-01_identity_membership_${TS}.csv"
SOURCES_OUT="$OUTDIR/cm11-01_input_sources_${TS}.csv"
COVERAGE_OUT="$OUTDIR/cm11-01_coverage_${TS}.csv"
ERRORS_OUT="$OUTDIR/cm11-01_collection_errors_${TS}.csv"

OUTPUT_CANDIDATES=(
  "$SOFTWARE_OUT" "$INSTALLER_TEMPLATE_OUT" "$ENTITLEMENT_OUT"
  "$APPROVED_TEMPLATE_OUT" "$RECONCILIATION_OUT" "$RESTRICTED_OUT"
  "$CONTROLS_OUT" "$POLICIES_OUT" "$MEMBERSHIP_OUT" "$SOURCES_OUT"
  "$COVERAGE_OUT" "$ERRORS_OUT"
)
for candidate in "${OUTPUT_CANDIDATES[@]}"; do
  [ ! -e "$candidate" ] || {
    echo "ERROR: refusing to overwrite existing output: $candidate" >&2
    exit 1
  }
done

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/cm11-01.XXXXXX" 2>/dev/null)" || {
  echo "ERROR: could not create a secure temporary directory." >&2
  exit 1
}
RAW_SOFTWARE="$WORKDIR/raw_software.csv"
RAW_POLICIES="$WORKDIR/raw_policies.csv"
RAW_MEMBERSHIP="$WORKDIR/raw_membership.csv"
RAW_CONTROLS="$WORKDIR/raw_controls.csv"
TMP_COVERAGE="$WORKDIR/coverage.csv"
TMP_ERRORS="$WORKDIR/errors.csv"
TMP_SUMMARY="$WORKDIR/summary.txt"

printf '%s\n' 'compartment_id,compartment_name,resource_type,resource_id,resource_name,software_type,software_name,software_version,architecture,repository_or_publisher,artifact_digest,source_or_image_id,software_time,software_time_basis,lifecycle_state,management_status,defined_tags,freeform_tags,collection_status,collection_error' > "$RAW_SOFTWARE"
printf '%s\n' 'attachment_compartment_id,attachment_compartment_name,policy_id,policy_name,policy_lifecycle_state,statement_index,statement,evidence_source,collection_status,collection_error' > "$RAW_POLICIES"
printf '%s\n' 'identity_system,domain_name,principal_type,principal_id,principal_name,user_id,user_name,user_lifecycle_state,membership_detail,collection_status,collection_error' > "$RAW_MEMBERSHIP"
printf '%s\n' 'compartment_id,compartment_name,control_type,resource_id,resource_name,control_status,scope,configuration,evidence_interpretation,collection_status,collection_error' > "$RAW_CONTROLS"
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

raw_row() {
  local output="" field escaped
  for field in "$@"; do
    escaped="$(csv_escape "$field")"
    output+="${escaped},"
  done
  printf '%s\n' "${output%,}"
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
  for item in "$@"; do [ "$item" = "$wanted" ] && return 0; done
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
  out="$(oci "${REGION_ARG[@]}" "${PROFILE_ARG[@]}" "$@" 2>"$errf")"; rc=$?
  err="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-500)"
  rm -f -- "$errf" 2>/dev/null
  TEMP_ERR_FILE=""

  for token in "$@"; do
    case "$token" in list|list-*) action="list" ;; get|get-*) action="get" ;; esac
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
    raw_row "$CUR_COMP" "$cname" "$status" "$cmd" "$err" >> "$TMP_ERRORS"
  fi
  COLLECT_OUT="$out"
  COLLECT_STATUS="$status"
  COLLECT_ERROR="$err"
}

LIST_ITER='if (.data|type)=="object" then ((.data.items // []) | .[]) elif (.data|type)=="array" then (.data[]) else empty end'

coverage_row() {
  local comp="$1" service="$2" parent_id="$3" parent_name="$4" count="$5" status="$6" error="$7"
  raw_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$service" "$parent_id" \
    "$parent_name" "$count" "$status" "$error" >> "$TMP_COVERAGE"
}

software_row() { raw_row "$@" >> "$RAW_SOFTWARE"; }
policy_row() { raw_row "$@" >> "$RAW_POLICIES"; }
membership_row() { raw_row "$@" >> "$RAW_MEMBERSHIP"; }
control_row() { raw_row "$@" >> "$RAW_CONTROLS"; }

abort_before_scan() {
  echo "SCAN NOT STARTED: $1" >&2
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
  [ "$APPROVE_SCAN" = "YES" ] || abort_before_scan "automation did not supply exact --approve-scan YES"
  echo "AUTOMATION APPROVED: every resolved OCID matched and --approve-scan was exact YES."
  echo
}

retain_startup_error() {
  local reason="$1"
  if [ "$(wc -l < "$TMP_ERRORS" | tr -d ' ')" -gt 1 ]; then
    mv -n -- "$TMP_ERRORS" "$ERRORS_OUT" 2>/dev/null || true
    chmod 600 "$ERRORS_OUT" 2>/dev/null || true
    echo "Collection error retained in: $ERRORS_OUT" >&2
  fi
  echo "ERROR: $reason" >&2
  exit 1
}

# Scope discovery and validation use IAM list/get only. No policy, identity,
# Compute, OS Management Hub or Artifacts collection occurs before final YES.
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
echo "Scope  : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'resolved command-line scope')"
echo

if [ "$SELECT_SCOPE" -eq 1 ]; then
  oci_capture "discover active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "compartment discovery failed ($COLLECT_STATUS): $COLLECT_ERROR"

  scope_catalog="$(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps+="$cid"$'\n'
  done <<< "$scope_catalog"

  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR"
  COMP_NAME["$TENANCY_ID"]="${COLLECT_OUT:-root}"

  oci_scope_select_interactive "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$scope_catalog" || \
    abort_before_scan "scope selection or OCID confirmation failed"
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
  [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "explicit compartment validation failed ($COLLECT_STATUS): $COLLECT_ERROR"
  COMP_NAME["$SINGLE_COMP"]="${COLLECT_OUT:-<unknown>}"
else
  oci_capture "enumerate active compartments" iam compartment list \
    --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
    --access-level ANY --lifecycle-state ACTIVE --all \
    --query 'data[].{id:id,name:name}'
  comp_pairs="$COLLECT_OUT"
  [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "compartment enumeration failed ($COLLECT_STATUS): $COLLECT_ERROR"
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
  done < <(printf '%s' "$comp_pairs" | jq -r '.[]? | [.id, .name] | @tsv' 2>/dev/null)
  oci_capture "get tenancy name" iam compartment get --compartment-id "$TENANCY_ID" \
    --query 'data.name' --raw-output
  [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "tenancy name lookup failed ($COLLECT_STATUS): $COLLECT_ERROR"
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
    [ "$match_count" -eq 1 ] || abort_before_scan "compartment name '$requested_name' resolved to $match_count OCIDs; use -c or interactive OCID selection"
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
  [ "$NON_INTERACTIVE" -eq 1 ] && SCOPE_TYPE="AUTOMATION-COMPARTMENT" || SCOPE_TYPE="MANUAL-COMPARTMENT"
  SCOPE_NAME="${COMP_NAME[$SINGLE_COMP]:-<unknown>}"
  SCOPE_OCID="$SINGLE_COMP"
else
  [ "$NON_INTERACTIVE" -eq 1 ] && SCOPE_TYPE="AUTOMATION-NAME-FILTER" || SCOPE_TYPE="MANUAL-NAME-FILTER"
  SCOPE_NAME="$COMP_NAMES_FILTER"
  SCOPE_OCID="multiple resolved compartment OCIDs"
fi

if [ "$SELECT_SCOPE" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
  confirm_resolved_targets_interactive "$TARGET_CATALOG"
fi

# Resolve the policy attachment boundary. Policies attached to the tenancy or
# an ancestor can affect a selected child compartment, so ancestor attachment
# compartments are included without expanding workload inventory scope.
declare -A POLICY_SCOPE_SEEN
POLICY_CATALOG=""
add_policy_scope() {
  local id="$1" name="$2"
  [ -n "$id" ] || return 0
  [ -z "${POLICY_SCOPE_SEEN[$id]:-}" ] || return 0
  POLICY_SCOPE_SEEN["$id"]=1
  COMP_NAME["$id"]="${name:-${COMP_NAME[$id]:-<unknown>}}"
  POLICY_CATALOG+="$id"$'\t'"${COMP_NAME[$id]}"$'\n'
}
add_policy_scope "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}"
if [ "$SCOPE_TYPE" = "TENANCY" ]; then
  while IFS=$'\t' read -r cid cname; do [ -z "$cid" ] || add_policy_scope "$cid" "$cname"; done <<< "$TARGET_CATALOG"
else
  while IFS=$'\t' read -r target_id target_name; do
    [ -n "$target_id" ] || continue
    current_id="$target_id"
    current_name="$target_name"
    ancestor_guard=0
    while [ "$current_id" != "$TENANCY_ID" ]; do
      add_policy_scope "$current_id" "$current_name"
      CUR_COMP="$current_id"
      oci_capture "resolve policy ancestor" iam compartment get --compartment-id "$current_id"
      [ "$COLLECT_STATUS" = "OK" ] || retain_startup_error "could not resolve policy ancestors for $current_id ($COLLECT_STATUS): $COLLECT_ERROR"
      current_name="$(printf '%s' "$COLLECT_OUT" | jq -r '.data.name // "<unknown>"')"
      COMP_NAME["$current_id"]="$current_name"
      current_id="$(printf '%s' "$COLLECT_OUT" | jq -r '.data."compartment-id" // empty')"
      [ -n "$current_id" ] || retain_startup_error "compartment parent was missing while resolving policy ancestors"
      ancestor_guard=$((ancestor_guard+1))
      [ "$ancestor_guard" -le 20 ] || retain_startup_error "compartment ancestry exceeded 20 levels"
    done
  done <<< "$TARGET_CATALOG"
fi
POLICY_SCOPE_COUNT="$(printf '%s\n' "$POLICY_CATALOG" | grep -c . || true)"
CUR_COMP="$TENANCY_ID"

AUTHORIZED_LABEL="NOT PROVIDED — installer authorization cannot be proven"
APPROVED_LABEL="NOT PROVIDED — approved software cannot be proven"
RESTRICTED_LABEL="NOT PROVIDED — restricted software cannot be evaluated"
[ -z "$AUTHORIZED_FILE" ] || AUTHORIZED_LABEL="$AUTHORIZED_FILE"
[ -z "$APPROVED_FILE" ] || APPROVED_LABEL="$APPROVED_FILE"
[ -z "$RESTRICTED_FILE" ] || RESTRICTED_LABEL="$RESTRICTED_FILE"
if [ "$INVENTORY_ONLY" -eq 1 ]; then
  AUTHORIZED_LABEL="intentionally skipped in inventory-only mode"
  APPROVED_LABEL="intentionally skipped in inventory-only mode"
  RESTRICTED_LABEL="intentionally skipped in inventory-only mode"
fi

WORK_ITEMS="OCI IAM policies from $POLICY_SCOPE_COUNT target/ancestor attachment compartment(s)
OCI CLI profile: ${PROFILE:-ambient/default profile}
Classic IAM groups and group members; dynamic groups and identity-domain boundary
Compute instance boot images in the confirmed workload scope
OS Management Hub managed instances, installed packages and enforcement resources
Container Registry repositories and images/resources
Authorized installers: $AUTHORIZED_LABEL
Approved software/resources: $APPROVED_LABEL
Restricted/prohibited software/resources: $RESTRICTED_LABEL"
OUTPUT_FILES="$SOFTWARE_OUT
$INSTALLER_TEMPLATE_OUT
$ENTITLEMENT_OUT
$APPROVED_TEMPLATE_OUT
$RECONCILIATION_OUT
$RESTRICTED_OUT
$CONTROLS_OUT
$POLICIES_OUT
$MEMBERSHIP_OUT
$SOURCES_OUT
$COVERAGE_OUT
$ERRORS_OUT (retained only when OCI calls or post-processing fail)"

oci_scope_print_scan_plan \
  "CM-11 SOFTWARE CONTROL" \
  "cm11-01-software-installation-control.sh" \
  "CM-11 / CM-11(1)" \
  "$REGION_OVERRIDE" \
  "$SCOPE_TYPE" "$SCOPE_NAME" "$SCOPE_OCID" "$COMP_COUNT" \
  "$TARGET_CATALOG" \
  "Requested evidence work" "$WORK_ITEMS" \
  "$OUTPUT_FILES" \
  "User/group names, policy statements, full OCIDs, package/image names and versions, approval metadata and restriction provenance"

if [ "$NON_INTERACTIVE" -eq 1 ]; then
  validate_automation_authorization "$TARGET_CATALOG"
elif ! oci_scope_require_final_approval 1; then
  abort_before_scan "${OCI_SCOPE_APPROVAL_ERROR:-final approval failed}"
fi

echo "Collecting CM-11 evidence across $COMP_COUNT compartment(s)..."
echo

collect_identities() {
  local groups_json group_count group group_id group_name users_json user_count user
  local dynamic_json dynamic_count dynamic domains_json domain_count domain
  CUR_COMP="$TENANCY_ID"

  oci_capture "classic IAM group list" iam group list --compartment-id "$TENANCY_ID" --all
  groups_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    group_count="$(printf '%s' "$groups_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$TENANCY_ID" "IAMGroup" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$group_count" "OK" ""
    while IFS= read -r group; do
      [ -n "$group" ] || continue
      group_id="$(printf '%s' "$group" | jq -r '.id // "<unknown-group>"')"
      group_name="$(printf '%s' "$group" | jq -r '.name // "<unnamed-group>"')"
      oci_capture "classic IAM group members [$group_name]" iam group list-users \
        --group-id "$group_id" --compartment-id "$TENANCY_ID" --all
      users_json="$COLLECT_OUT"
      if [ "$COLLECT_STATUS" = "OK" ]; then
        user_count="$(printf '%s' "$users_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
        coverage_row "$TENANCY_ID" "IAMGroupMember" "$group_id" "$group_name" "$user_count" "OK" ""
        if [ "$user_count" = "0" ]; then
          membership_row "OCI-IAM" "" "GROUP" "$group_id" "$group_name" "" "" "" "NO-MEMBERS" "OK" ""
        else
          while IFS= read -r user; do
            [ -n "$user" ] || continue
            membership_row "OCI-IAM" "" "GROUP" "$group_id" "$group_name" \
              "$(printf '%s' "$user" | jq -r '.id // ""')" \
              "$(printf '%s' "$user" | jq -r '.name // ."display-name" // "<unnamed-user>"')" \
              "$(printf '%s' "$user" | jq -r '."lifecycle-state" // "UNKNOWN"')" \
              "DIRECT-GROUP-MEMBERSHIP" "OK" ""
          done <<< "$(printf '%s' "$users_json" | jq -c "$LIST_ITER" 2>/dev/null)"
        fi
      else
        coverage_row "$TENANCY_ID" "IAMGroupMember" "$group_id" "$group_name" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
        membership_row "OCI-IAM" "" "GROUP" "$group_id" "$group_name" "" "" "" \
          "MEMBERSHIP-NOT-COLLECTED" "$COLLECT_STATUS" "$COLLECT_ERROR"
      fi
    done <<< "$(printf '%s' "$groups_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$TENANCY_ID" "IAMGroup" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    membership_row "OCI-IAM" "" "GROUP" "" "<collection-failed>" "" "" "" \
      "MEMBERSHIP-NOT-COLLECTED" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi

  oci_capture "dynamic group list" iam dynamic-group list --compartment-id "$TENANCY_ID" --all
  dynamic_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    dynamic_count="$(printf '%s' "$dynamic_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$TENANCY_ID" "IAMDynamicGroup" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$dynamic_count" "OK" ""
    while IFS= read -r dynamic; do
      [ -n "$dynamic" ] || continue
      membership_row "OCI-IAM" "" "DYNAMIC_GROUP" \
        "$(printf '%s' "$dynamic" | jq -r '.id // ""')" \
        "$(printf '%s' "$dynamic" | jq -r '.name // "<unnamed-dynamic-group>"')" \
        "" "" "" \
        "$(printf '%s' "$dynamic" | jq -r '."matching-rule" // "<rule-not-returned>"')" \
        "OK" ""
    done <<< "$(printf '%s' "$dynamic_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$TENANCY_ID" "IAMDynamicGroup" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi

  oci_capture "identity domain list" iam domain list --compartment-id "$TENANCY_ID" --all
  domains_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    domain_count="$(printf '%s' "$domains_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$TENANCY_ID" "IAMIdentityDomain" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "$domain_count" "OK" ""
    while IFS= read -r domain; do
      [ -n "$domain" ] || continue
      membership_row "OCI-IDENTITY-DOMAIN" \
        "$(printf '%s' "$domain" | jq -r '."display-name" // .name // "<unnamed-domain>"')" \
        "IDENTITY_DOMAIN" "$(printf '%s' "$domain" | jq -r '.id // ""')" \
        "$(printf '%s' "$domain" | jq -r '.name // ."display-name" // "<unnamed-domain>"')" \
        "" "" "$(printf '%s' "$domain" | jq -r '."lifecycle-state" // "UNKNOWN"')" \
        "GROUP-MEMBERSHIP-REQUIRES-IDENTITY-DOMAIN-EXPORT" "BOUNDARY" \
        "Identity-domain group/user membership is not returned by iam group list-users"
    done <<< "$(printf '%s' "$domains_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$TENANCY_ID" "IAMIdentityDomain" "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi
}

collect_policies() {
  local attachment_id attachment_name policies_json policy_count policy policy_id policy_name state
  local index statement_count statement
  while IFS=$'\t' read -r attachment_id attachment_name; do
    [ -n "$attachment_id" ] || continue
    CUR_COMP="$attachment_id"
    oci_capture "IAM policy list [$attachment_name]" iam policy list \
      --compartment-id "$attachment_id" --lifecycle-state ACTIVE --all
    policies_json="$COLLECT_OUT"
    if [ "$COLLECT_STATUS" = "OK" ]; then
      policy_count="$(printf '%s' "$policies_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
      coverage_row "$attachment_id" "IAMPolicy" "$attachment_id" "$attachment_name" "$policy_count" "OK" ""
      while IFS= read -r policy; do
        [ -n "$policy" ] || continue
        policy_id="$(printf '%s' "$policy" | jq -r '.id // "<unknown-policy>"')"
        policy_name="$(printf '%s' "$policy" | jq -r '.name // "<unnamed-policy>"')"
        state="$(printf '%s' "$policy" | jq -r '."lifecycle-state" // "UNKNOWN"')"
        statement_count="$(printf '%s' "$policy" | jq '(.statements // []) | length' 2>/dev/null || echo UNKNOWN)"
        coverage_row "$attachment_id" "IAMPolicyStatement" "$policy_id" "$policy_name" "$statement_count" "OK" ""
        index=0
        while IFS= read -r statement; do
          index=$((index+1))
          policy_row "$attachment_id" "$attachment_name" "$policy_id" "$policy_name" \
            "$state" "$index" "$statement" "OCI-API" "OK" ""
        done <<< "$(printf '%s' "$policy" | jq -r '.statements[]?')"
      done <<< "$(printf '%s' "$policies_json" | jq -c "$LIST_ITER" 2>/dev/null)"
    else
      coverage_row "$attachment_id" "IAMPolicy" "$attachment_id" "$attachment_name" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
      policy_row "$attachment_id" "$attachment_name" "" "<collection-failed>" "UNKNOWN" "" "" \
        "OCI-API" "$COLLECT_STATUS" "$COLLECT_ERROR"
    fi
  done <<< "$POLICY_CATALOG"

  # Oracle documents an immutable built-in Administrators grant. This row is
  # explicitly provenance-labeled and is never represented as an OCI API row.
  policy_row "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" \
    "ORACLE-BUILTIN-ADMINISTRATORS" "Administrators built-in grant" "ACTIVE" "1" \
    "Allow group Administrators to manage all-resources in tenancy" \
    "ORACLE-DOCUMENTATION-BUILTIN" "DOCUMENTED" "Verify the current Administrators membership"
}

collect_compute() {
  local comp="$1" instances_json count instance iid iname image_id image_json
  local image_name image_version image_os image_state shape lifecycle tags free_tags
  CUR_COMP="$comp"
  oci_capture "Compute instance list" compute instance list --compartment-id "$comp" --all
  instances_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" != "OK" ]; then
    coverage_row "$comp" "ComputeInstance" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "ComputeInstance" "" "<collection-failed>" \
      "COMPUTE_BOOT_IMAGE" "UNKNOWN" "" "" "" "" "" "" "" "UNKNOWN" "UNKNOWN" "" "" "$COLLECT_STATUS" "$COLLECT_ERROR"
    return
  fi
  count="$(printf '%s' "$instances_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
  coverage_row "$comp" "ComputeInstance" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$count" "OK" ""
  while IFS= read -r instance; do
    [ -n "$instance" ] || continue
    iid="$(printf '%s' "$instance" | jq -r '.id // "<unknown-instance>"')"
    iname="$(printf '%s' "$instance" | jq -r '."display-name" // "<unnamed-instance>"')"
    image_id="$(printf '%s' "$instance" | jq -r '."image-id" // ""')"
    shape="$(printf '%s' "$instance" | jq -r '.shape // ""')"
    lifecycle="$(printf '%s' "$instance" | jq -r '."lifecycle-state" // "UNKNOWN"')"
    tags="$(printf '%s' "$instance" | jq -c '."defined-tags" // {}')"
    free_tags="$(printf '%s' "$instance" | jq -c '."freeform-tags" // {}')"
    image_name="$image_id"; image_version=""; image_os=""; image_state="UNKNOWN"
    if [ -n "$image_id" ]; then
      oci_capture "Compute image get [$iname]" compute image get --image-id "$image_id"
      image_json="$COLLECT_OUT"
      if [ "$COLLECT_STATUS" = "OK" ]; then
        image_name="$(printf '%s' "$image_json" | jq -r '.data."display-name" // .data.id // "<unnamed-image>"')"
        image_version="$(printf '%s' "$image_json" | jq -r '.data."operating-system-version" // ""')"
        image_os="$(printf '%s' "$image_json" | jq -r '.data."operating-system" // ""')"
        image_state="$(printf '%s' "$image_json" | jq -r '.data."lifecycle-state" // "UNKNOWN"')"
      else
        image_name="$image_id"
      fi
    else
      COLLECT_STATUS="ERROR"; COLLECT_ERROR="instance image-id was not returned"; INCOMPLETE=1
      raw_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "ERROR" "Compute image id [$iname]" "$COLLECT_ERROR" >> "$TMP_ERRORS"
    fi
    software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "ComputeInstance" "$iid" "$iname" \
      "COMPUTE_BOOT_IMAGE" "$image_name" "$image_version" "" "$image_os" "" "$image_id" \
      "" "" "$image_state" "Instance=$lifecycle; shape=$shape" "$tags" "$free_tags" "$COLLECT_STATUS" "$COLLECT_ERROR"
    control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "COMPUTE-IMAGE-PINNING" "$iid" "$iname" \
      "$lifecycle" "$comp" "image_id=$image_id; image_name=$image_name; os=$image_os; version=$image_version" \
      "Compare the exact image OCID to the approved software/resource baseline" "$COLLECT_STATUS" "$COLLECT_ERROR"
  done <<< "$(printf '%s' "$instances_json" | jq -c "$LIST_ITER" 2>/dev/null)"
}

collect_osmh() {
  local comp="$1" managed_json count managed mid mname mstatus os arch location sources packages_json pcount pkg
  local controls_json ccount item id name status config type
  local -a cmd
  CUR_COMP="$comp"
  oci_capture "OSMH managed instance list" os-management-hub managed-instance list \
    --compartment-id "$comp" --all
  managed_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    count="$(printf '%s' "$managed_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$comp" "OSMHManagedInstance" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$count" "OK" ""
    while IFS= read -r managed; do
      [ -n "$managed" ] || continue
      mid="$(printf '%s' "$managed" | jq -r '.id // "<unknown-managed-instance>"')"
      mname="$(printf '%s' "$managed" | jq -r '."display-name" // .name // "<unnamed-managed-instance>"')"
      mstatus="$(printf '%s' "$managed" | jq -r '.status // ."lifecycle-state" // "UNKNOWN"')"
      os="$(printf '%s' "$managed" | jq -r '."os-family" // ."os-name" // ""')"
      arch="$(printf '%s' "$managed" | jq -r '."architecture-type" // ."arch-type" // .architecture // ""')"
      location="$(printf '%s' "$managed" | jq -r '.location // ""')"
      sources="$(printf '%s' "$managed" | jq -c '."software-source-ids" // ."software-sources" // []')"
      control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMH-MANAGED-INSTANCE" "$mid" "$mname" \
        "$mstatus" "$comp" "os=$os; architecture=$arch; location=$location; software_sources=$sources" \
        "OS Management Hub enrollment and attached sources constrain centralized package operations" "OK" ""

      oci_capture "OSMH installed packages [$mname]" os-management-hub managed-instance list-installed-packages \
        --managed-instance-id "$mid" --all
      packages_json="$COLLECT_OUT"
      if [ "$COLLECT_STATUS" = "OK" ]; then
        pcount="$(printf '%s' "$packages_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
        coverage_row "$comp" "OSMHInstalledPackage" "$mid" "$mname" "$pcount" "OK" ""
        while IFS= read -r pkg; do
          [ -n "$pkg" ] || continue
          software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMHManagedInstance" "$mid" "$mname" \
            "OS_PACKAGE" \
            "$(printf '%s' "$pkg" | jq -r '.name // ."display-name" // ."package-name" // "<unnamed-package>"')" \
            "$(printf '%s' "$pkg" | jq -r '.version // ."installed-version" // ""')" \
            "$(printf '%s' "$pkg" | jq -r '.architecture // ."arch-type" // ""')" \
            "$(printf '%s' "$pkg" | jq -r '."software-source-name" // .vendor // .type // ""')" \
            "" "$(printf '%s' "$pkg" | jq -r '."software-source-id" // ""')" \
            "$(printf '%s' "$pkg" | jq -r '."time-installed" // ""')" \
            "PACKAGE_TIME_INSTALLED" "INSTALLED" "OSMH=$mstatus; OS=$os; location=$location" "" "" "OK" ""
        done <<< "$(printf '%s' "$packages_json" | jq -c "$LIST_ITER" 2>/dev/null)"
      else
        coverage_row "$comp" "OSMHInstalledPackage" "$mid" "$mname" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
        software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMHManagedInstance" "$mid" "$mname" \
          "OS_PACKAGE" "UNKNOWN" "" "$arch" "" "" "" "" "" "UNKNOWN" "OSMH=$mstatus" "" "" "$COLLECT_STATUS" "$COLLECT_ERROR"
      fi
    done <<< "$(printf '%s' "$managed_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$comp" "OSMHManagedInstance" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMHManagedInstance" "" "<collection-failed>" \
      "OS_PACKAGE" "UNKNOWN" "" "" "" "" "" "" "" "UNKNOWN" "UNKNOWN" "" "" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi

  for type in SoftwareSource ManagedInstanceGroup LifecycleEnvironment ScheduledJob; do
    case "$type" in
      SoftwareSource) cmd=(os-management-hub software-source list --compartment-id "$comp" --all) ;;
      ManagedInstanceGroup) cmd=(os-management-hub managed-instance-group list --compartment-id "$comp" --all) ;;
      LifecycleEnvironment) cmd=(os-management-hub lifecycle-environment list --compartment-id "$comp" --all) ;;
      ScheduledJob) cmd=(os-management-hub scheduled-job list --compartment-id "$comp" --all) ;;
    esac
    oci_capture "OSMH $type list" "${cmd[@]}"
    controls_json="$COLLECT_OUT"
    if [ "$COLLECT_STATUS" = "OK" ]; then
      ccount="$(printf '%s' "$controls_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
      coverage_row "$comp" "OSMH$type" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$ccount" "OK" ""
      while IFS= read -r item; do
        [ -n "$item" ] || continue
        id="$(printf '%s' "$item" | jq -r '.id // ""')"
        name="$(printf '%s' "$item" | jq -r '."display-name" // .name // "<unnamed>"')"
        status="$(printf '%s' "$item" | jq -r '."lifecycle-state" // .status // ."overall-state" // "UNKNOWN"')"
        config="$(printf '%s' "$item" | jq -c 'del(."defined-tags", ."freeform-tags")')"
        control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMH-${type}" "$id" "$name" "$status" "$comp" \
          "$config" "Review as technical enforcement for approved sources, staged content, grouping and scheduled change" "OK" ""
      done <<< "$(printf '%s' "$controls_json" | jq -c "$LIST_ITER" 2>/dev/null)"
    else
      coverage_row "$comp" "OSMH$type" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
      control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "OSMH-${type}" "" "<collection-failed>" "UNKNOWN" "$comp" "" \
        "Technical-control collection failed" "$COLLECT_STATUS" "$COLLECT_ERROR"
    fi
  done
}

collect_artifacts() {
  local comp="$1" repos_json repo_count repo images_json image_count img
  CUR_COMP="$comp"
  oci_capture "Container repository list" artifacts container repository list --compartment-id "$comp" --all
  repos_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    repo_count="$(printf '%s' "$repos_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$comp" "ContainerRepository" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$repo_count" "OK" ""
    while IFS= read -r repo; do
      [ -n "$repo" ] || continue
      control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "CONTAINER-REPOSITORY" \
        "$(printf '%s' "$repo" | jq -r '.id // ""')" \
        "$(printf '%s' "$repo" | jq -r '."display-name" // "<unnamed-repository>"')" \
        "$(printf '%s' "$repo" | jq -r '."lifecycle-state" // "UNKNOWN"')" "$comp" \
        "$(printf '%s' "$repo" | jq -c '{is_public:(."is-public" // null), image_count:(."image-count" // null), layers_size:(."layers-size-in-bytes" // null)}')" \
        "Private repositories and IAM push permissions are technical installation/deployment controls" "OK" ""
    done <<< "$(printf '%s' "$repos_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$comp" "ContainerRepository" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    control_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "CONTAINER-REPOSITORY" "" "<collection-failed>" "UNKNOWN" "$comp" "" \
      "Repository control collection failed" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi

  oci_capture "Container image list" artifacts container image list --compartment-id "$comp" --all
  images_json="$COLLECT_OUT"
  if [ "$COLLECT_STATUS" = "OK" ]; then
    image_count="$(printf '%s' "$images_json" | jq "[$LIST_ITER] | length" 2>/dev/null || echo UNKNOWN)"
    coverage_row "$comp" "ContainerImage" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$image_count" "OK" ""
    while IFS= read -r img; do
      [ -n "$img" ] || continue
      software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "ContainerRepository" \
        "$(printf '%s' "$img" | jq -r '."repository-id" // ""')" \
        "$(printf '%s' "$img" | jq -r '."repository-name" // "<unnamed-repository>"')" \
        "CONTAINER_IMAGE" \
        "$(printf '%s' "$img" | jq -r '."display-name" // ."repository-name" // "<unnamed-image>"')" \
        "$(printf '%s' "$img" | jq -r '."version" // ."image-version" // ""')" \
        "$(printf '%s' "$img" | jq -r '.architecture // ""')" \
        "$(printf '%s' "$img" | jq -r '."repository-name" // ""')" \
        "$(printf '%s' "$img" | jq -r '.digest // ."image-digest" // ""')" \
        "$(printf '%s' "$img" | jq -r '.id // ""')" \
        "$(printf '%s' "$img" | jq -r '."time-created" // ""')" \
        "IMAGE_TIME_CREATED" \
        "$(printf '%s' "$img" | jq -r '."lifecycle-state" // "UNKNOWN"')" \
        "AVAILABLE-IN-REGISTRY" "" "" "OK" ""
    done <<< "$(printf '%s' "$images_json" | jq -c "$LIST_ITER" 2>/dev/null)"
  else
    coverage_row "$comp" "ContainerImage" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "UNKNOWN" "$COLLECT_STATUS" "$COLLECT_ERROR"
    software_row "$comp" "${COMP_NAME[$comp]:-<unknown>}" "ContainerRepository" "" "<collection-failed>" \
      "CONTAINER_IMAGE" "UNKNOWN" "" "" "" "" "" "" "" "UNKNOWN" "UNKNOWN" "" "" "$COLLECT_STATUS" "$COLLECT_ERROR"
  fi
}

collect_identities
collect_policies
while IFS= read -r comp; do
  [ -n "$comp" ] || continue
  echo "[CM-11] ${COMP_NAME[$comp]:-<unknown>} ($comp)"
  collect_compute "$comp"
  collect_osmh "$comp"
  collect_artifacts "$comp"
done <<< "$COMPS"

POST_ERROR="$WORKDIR/postprocess.error"
if ! python3 "$POSTPROCESSOR" \
  --raw-software "$RAW_SOFTWARE" \
  --raw-policies "$RAW_POLICIES" \
  --raw-membership "$RAW_MEMBERSHIP" \
  --raw-controls "$RAW_CONTROLS" \
  --software-out "$SOFTWARE_OUT" \
  --installer-template-out "$INSTALLER_TEMPLATE_OUT" \
  --entitlement-out "$ENTITLEMENT_OUT" \
  --approved-template-out "$APPROVED_TEMPLATE_OUT" \
  --reconciliation-out "$RECONCILIATION_OUT" \
  --restricted-out "$RESTRICTED_OUT" \
  --controls-out "$CONTROLS_OUT" \
  --policies-out "$POLICIES_OUT" \
  --membership-out "$MEMBERSHIP_OUT" \
  --sources-out "$SOURCES_OUT" \
  --summary-out "$TMP_SUMMARY" \
  --authorized-input "$AUTHORIZED_FILE" \
  --approved-input "$APPROVED_FILE" \
  --restricted-input "$RESTRICTED_FILE" \
  --inventory-only "$INVENTORY_ONLY" \
  --timestamp "$TS" \
  --region "$REGION_OVERRIDE" \
  2>"$POST_ERROR"; then
  INCOMPLETE=1
  post_error="$(tr '\n\r' '  ' < "$POST_ERROR" | sed 's/  */ /g' | cut -c1-500)"
  raw_row "$TENANCY_ID" "${COMP_NAME[$TENANCY_ID]}" "ERROR" "CM-11 post-processing" "$post_error" >> "$TMP_ERRORS"
  printf '%s\n' 'software_records=UNKNOWN' > "$TMP_SUMMARY"
fi

if [ "$INVENTORY_ONLY" -eq 0 ]; then
  if [ -z "$AUTHORIZED_FILE" ]; then echo "WARNING: no authorized installer list supplied; who-can-install proof is incomplete." >&2; INCOMPLETE=1; fi
  if [ -z "$APPROVED_FILE" ]; then echo "WARNING: no approved software/resource list supplied; approval proof is incomplete." >&2; INCOMPLETE=1; fi
  if [ -z "$RESTRICTED_FILE" ]; then echo "WARNING: no authoritative restricted software/resource list supplied; restriction evaluation is incomplete." >&2; INCOMPLETE=1; fi
fi

if [ -r "$TMP_SUMMARY" ]; then
  IDENTITY_GAPS="$(awk -F= '$1 == "identity_gaps" {print $2}' "$TMP_SUMMARY" | tail -n 1)"
  [ -z "$IDENTITY_GAPS" ] || [ "$IDENTITY_GAPS" = "0" ] || INCOMPLETE=1
  UNMANAGED_COMPUTE="$(awk -F= '$1 == "unmanaged_compute" {print $2}' "$TMP_SUMMARY" | tail -n 1)"
  [ -z "$UNMANAGED_COMPUTE" ] || [ "$UNMANAGED_COMPUTE" = "0" ] || INCOMPLETE=1
fi

if [ -e "$COVERAGE_OUT" ]; then
  echo "ERROR: output appeared during collection; refusing to overwrite: $COVERAGE_OUT" >&2
  exit 1
fi
mv -- "$TMP_COVERAGE" "$COVERAGE_OUT"
chmod 600 "$COVERAGE_OUT" 2>/dev/null || true

if [ "$(wc -l < "$TMP_ERRORS" | tr -d ' ')" -gt 1 ]; then
  [ ! -e "$ERRORS_OUT" ] || { echo "ERROR: refusing to overwrite collection error ledger: $ERRORS_OUT" >&2; exit 1; }
  mv -- "$TMP_ERRORS" "$ERRORS_OUT"
  chmod 600 "$ERRORS_OUT" 2>/dev/null || true
fi

echo
echo "CM-11 SOFTWARE INSTALLATION CONTROL SUMMARY"
echo "============================================="
if [ -r "$TMP_SUMMARY" ]; then
  while IFS='=' read -r key value; do
    case "$key" in
      software_records) echo "Live software/resource rows       : $value" ;;
      approved) echo "Approved live rows                : $value" ;;
      unapproved) echo "Unapproved/unevaluated live rows  : $value" ;;
      restricted) echo "Restricted matches                : $value" ;;
      prohibited) echo "Prohibited matches                : $value" ;;
      candidate_entitlements) echo "Candidate installer entitlements : $value" ;;
      authorized_entitlements) echo "Authorized entitlement rows       : $value" ;;
      unauthorized_entitlements) echo "Unauthorized/unevaluated rows     : $value" ;;
      identity_gaps) echo "Unresolved identity boundaries    : $value" ;;
      unmanaged_compute) echo "Compute hosts not OSMH-verified   : $value" ;;
      authorized_input) echo "Authorized installer source       : $value" ;;
      approved_input) echo "Approved software source          : $value" ;;
      restricted_input) echo "Restricted software source        : $value" ;;
    esac
  done < "$TMP_SUMMARY"
fi
echo
echo "Software inventory             : $SOFTWARE_OUT"
echo "Authorized-installer template  : $INSTALLER_TEMPLATE_OUT"
echo "Installer entitlement results  : $ENTITLEMENT_OUT"
echo "Approved-software template     : $APPROVED_TEMPLATE_OUT"
echo "Software reconciliation        : $RECONCILIATION_OUT"
echo "Restricted findings            : $RESTRICTED_OUT"
echo "Technical controls             : $CONTROLS_OUT"
echo "IAM policy statements          : $POLICIES_OUT"
echo "Identity membership            : $MEMBERSHIP_OUT"
echo "Input-source provenance        : $SOURCES_OUT"
echo "Coverage                       : $COVERAGE_OUT"
[ ! -e "$ERRORS_OUT" ] || echo "Collection errors              : $ERRORS_OUT"
echo
echo "Reminder: candidate IAM policy parsing is not an effective-permissions API."
echo "Complete identity-domain, SSH/sudo, break-glass and unmanaged-host evidence."

if [ "$INCOMPLETE" -ne 0 ]; then
  echo "RESULT: INCOMPLETE — review missing inputs, identity boundaries, coverage and errors." >&2
  exit 3
fi

echo "RESULT: COLLECTION COMPLETE — findings and authorizations still require review."
exit 0
