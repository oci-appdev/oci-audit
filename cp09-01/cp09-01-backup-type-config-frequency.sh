#!/usr/bin/env bash
#
# cp09-01/cp09-01-backup-type-config-frequency.sh
#
# CP-9 EVIDENCE — BACKUP TYPE, CONFIGURATION & FREQUENCY
#
# For every backup-capable asset in the tenancy, reports:
#   IS IT BACKED UP?  by which policy?  what TYPE (FULL/INCREMENTAL)?
#   how OFTEN?        what RETENTION?   and when did a backup last actually run?
#
# Sibling scripts in the CP-9 family:
#   cp09-01 (this)  backup type / configuration / frequency
#   cp09-02         who can access the backup files
#   cp09-03         backup replication, retention & versioning (DR)
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation. This Task 1 collector does not use the OCI
#   Python SDK.
#
# PYTHON FILES USED:
#   None. This collector is Bash + the OCI CLI + jq only; there is no Python
#   step, so nothing here depends on a Python runtime beyond the test suite.
#
# READ-ONLY. Every OCI call is list/get. Nothing is created, modified, or
# deleted. Verified against this file's own source at startup; --selfcheck
# reproduces that proof on its own.
#
# Auth: OCI Cloud Shell delegation token by default (the same auth that makes
#       `oci iam compartment list` work). Outside Cloud Shell pass -p PROFILE.
#
# Usage:
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh                  # interactive scope + approval
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh --select-scope   # discover + confirm scope
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -i               # short form
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -c <ocid>        # one compartment
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -n VCN,CD3       # by compartment NAME
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -r us-langley-1  # region override
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -p AUDITOR       # config-file profile
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -s "volumes fss" # subset of services
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh -o ./evidence    # output root; writes into ./evidence/cp09-01/
#   ./cp09-01/cp09-01-backup-type-config-frequency.sh --selfcheck      # prove read-only, exit
#
# Services (-s): volumes bootvol volgroup fss object basedb adb mysql postgres
#
# Output: three timestamped CSVs + console summary.
#   ..._config_<ts>.csv     one row per asset per schedule: type/frequency/retention
#   ..._coverage_<ts>.csv   compartment x service ledger, so "no assets" is
#                           distinguishable from "never collected"
#   ..._findings_<ts>.csv   assets with no backup configured, severity-ranked
#
# Exit codes: 0 = clean run, 3 = ran but one or more collections were incomplete
#             1 = could not start (missing dependency, no compartments)
#
# ---------------------------------------------------------------------------
# 2026-08-27 REWRITE. The previous version drove collection through showoci and
# joined the results by regex-guessing CSV filenames and column headers. Review
# found that approach unsound, and two FSS blockers on top of it:
#   * `oci fs snapshot-policy list` is not a real command (it is
#     `fs filesystem-snapshot-policy`), so every FSS row errored; and the code
#     behind it read `schedules` off the LIST summary, which never carries them
#     — so fixing only the command name would have produced silent false-clean
#     NO_SCHEDULES rows. Both are fixed here.
#   * per-asset policy linkage now uses the authoritative API
#     (`bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment`)
#     instead of a showoci column that may not exist.
# showoci is no longer required. Base DB, Autonomous DB, MySQL and PostgreSQL
# are now covered. Compartment NAMES are recorded so evidence is filterable by
# VCN / Shared Services / CD3.
# ---------------------------------------------------------------------------
#
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/../lib/oci-scope-selector.sh"

# ---------------------------------------------------------------------------
# Read-only self-verification
# ---------------------------------------------------------------------------
readonly_selfcheck() {                                          # selfcheck-exempt
  local deny hits                                               # selfcheck-exempt
  local -a check_paths=("$SCRIPT_PATH" "$SCOPE_HELPER")         # selfcheck-exempt
  [ -r "$SCOPE_HELPER" ] || { echo "READ-ONLY SELF-CHECK: FAILED — missing $SCOPE_HELPER" >&2; return 1; }  # selfcheck-exempt
  deny='oci[[:space:]]+([a-z0-9-]+[[:space:]]+)*(create|update|delete|change|move|restore|enable|disable|rotate|assign|attach|detach|terminate|reboot|import|export|upload|bulk-upload|bulk-delete|reset|activate|deactivate|cancel)([[:space:]]|$)'  # selfcheck-exempt
  hits="$(grep -nE "$deny" "${check_paths[@]}" 2>/dev/null \
          | grep -v 'selfcheck-exempt' \
          | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"      # selfcheck-exempt
  local raw rawpat                                              # selfcheck-exempt
  rawpat="raw""-request"   # split literal so this line is not its own match
  raw="$(grep -nE "$rawpat" "${check_paths[@]}" 2>/dev/null \
         | grep -viE 'http-method[[:space:]=]+GET' \
         | grep -v 'selfcheck-exempt' \
         | grep -vE '(^|:)[0-9]+:[[:space:]]*#' || true)"       # selfcheck-exempt
  if [ -n "$hits" ] || [ -n "$raw" ]; then                      # selfcheck-exempt
    echo "READ-ONLY SELF-CHECK: FAILED — mutating call found:" >&2
    printf '%s\n%s\n' "$hits" "$raw" >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selfcheck" ]; then
  if readonly_selfcheck; then
    echo "READ-ONLY SELF-CHECK: PASSED"
    echo "No create/update/delete/change/restore/... subcommand appears in $SCRIPT_PATH"
    echo "All OCI calls are list/get. Local CSV output only."
    exit 0
  fi
  exit 1
fi

command -v oci >/dev/null 2>&1 || { echo "ERROR: oci CLI not found." >&2; exit 1; }
command -v jq  >/dev/null 2>&1 || { echo "ERROR: jq not found." >&2; exit 1; }

[ -r "$SCOPE_HELPER" ] || { echo "ERROR: scope selector not found: $SCOPE_HELPER" >&2; exit 1; }
# shellcheck source=lib/oci-scope-selector.sh
source "$SCOPE_HELPER"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
SINGLE_COMP=""
COMP_NAMES_FILTER=""
REGION_OVERRIDE=""
PROFILE=""
OUTDIR="."
TASK_DIR="cp09-01"
SERVICES="volumes bootvol volgroup fss object basedb adb mysql postgres"
SELECT_SCOPE=0

# Normalize the readable long option before getopts handles short options.
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

while getopts "ic:n:r:p:o:s:h" opt; do
  case "$opt" in
    i) SELECT_SCOPE=1 ;;
    c) SINGLE_COMP="$OPTARG" ;;
    n) COMP_NAMES_FILTER="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    p) PROFILE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    s) SERVICES="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Use -h for help" >&2; exit 1 ;;
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

has_svc() { case " $SERVICES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

mkdir -p -- "$OUTDIR" 2>/dev/null || { echo "ERROR: cannot create output dir: $OUTDIR" >&2; exit 1; }

AUTH_ARG=(); [ -n "$PROFILE" ] && AUTH_ARG=(--profile "$PROFILE")
REGION_ARG=(); [ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")

readonly_selfcheck || { echo "Refusing to run." >&2; exit 1; }

# ---------------------------------------------------------------------------
# OCI invocation wrapper.
#
# stderr is captured, never discarded: a permission denial must never be
# rendered as "this asset has no backup configured".
# ---------------------------------------------------------------------------
INCOMPLETE=0
OCI_OUT=""; OCI_RC=0; OCI_ERR=""; OCI_STATUS="OK"

oci_try() {
  local errf
  errf="$(mktemp 2>/dev/null || echo "/tmp/cp0901.$$.err")"
  # ${arr[@]+"${arr[@]}"} keeps empty arrays safe under `set -u` on bash < 4.4
  OCI_OUT="$(oci ${REGION_ARG[@]+"${REGION_ARG[@]}"} ${AUTH_ARG[@]+"${AUTH_ARG[@]}"} "$@" 2>"$errf")"
  OCI_RC=$?
  OCI_ERR="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-300)"
  rm -f "$errf" 2>/dev/null

  if [ "$OCI_RC" -eq 0 ]; then
    OCI_STATUS="OK"
  elif printf '%s' "$OCI_ERR" | grep -qiE 'NotAuthorized|Authorization failed|forbidden|\b403\b'; then
    OCI_STATUS="DENIED"; INCOMPLETE=1
  elif printf '%s' "$OCI_ERR" | grep -qiE 'No such command|no such option|Usage:'; then
    OCI_STATUS="CLI_UNSUPPORTED"; INCOMPLETE=1
  elif printf '%s' "$OCI_ERR" | grep -qiE 'NotFound|does not exist|\b404\b'; then
    OCI_STATUS="NOTFOUND"
  else
    OCI_STATUS="ERROR"; INCOMPLETE=1
  fi
  # In JSON a literal CR inside a string must be escaped, so a bare 0x0D can
  # only be line-ending noise. Left in, it lands inside CSV cells and map keys.
  OCI_OUT="${OCI_OUT//$'\r'/}"
  [ -z "$OCI_OUT" ] && OCI_OUT='{"data":[]}'
  return 0
}

jqd() { printf '%s' "$OCI_OUT" | jq -r "$1" 2>/dev/null | tr -d '\r'; }
num() { case "${1:-}" in ''|*[!0-9]*) printf '0' ;; *) printf '%s' "$1" ;; esac; }

# ---------------------------------------------------------------------------
# CSV output (RFC 4180 + formula-injection neutralisation)
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="$OUTDIR/cp09-01_backup_config"
CFG_CSV="${BASE}_config_${TS}.csv"
COV_CSV="${BASE}_coverage_${TS}.csv"
FIND_CSV="${BASE}_findings_${TS}.csv"

csv_row() {
  local file="$1"; shift
  local out="" first=1 f
  for f in "$@"; do
    f="${f//$'\n'/ }"; f="${f//$'\r'/}"
    case "$f" in [=+@-]*) f="'$f" ;; esac
    f="${f//\"/\"\"}"
    if [ "$first" -eq 1 ]; then first=0; else out+=","; fi
    out+="\"${f}\""
  done
  printf '%s\n' "$out" >> "$file"
}

printf '%s\n' 'compartment_id,compartment_name,service,resource_type,resource_name,resource_id,backup_configured,policy_source,policy_name,policy_id,backup_type,frequency,retention,time_zone,last_backup_time,backup_count,collection_status,collection_error' > "$CFG_CSV"
printf '%s\n' 'compartment_id,compartment_name,service,assets_found,collection_status,collection_error' > "$COV_CSV"
printf '%s\n' 'severity,category,compartment_id,compartment_name,service,resource,detail,recommendation' > "$FIND_CSV"

abort_before_scan() {
  local reason="$1"
  rm -f -- "$CFG_CSV" "$COV_CSV" "$FIND_CSV" 2>/dev/null
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

FINDING_COUNT=0
finding() {  # severity category comp service resource detail recommendation
  csv_row "$FIND_CSV" "$1" "$2" "$3" "${COMP_NAME[$3]:-<unknown>}" "$4" "$5" "$6" "$7"
  FINDING_COUNT=$((FINDING_COUNT+1))
}

cfg_row() {  # comp svc rtype rname rid configured psource pname pid btype freq ret tz last count status err
  csv_row "$CFG_CSV" "$1" "${COMP_NAME[$1]:-<unknown>}" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" \
          "${10}" "${11}" "${12}" "${13}" "${14}" "${15}" "${16}" "${17}"
}

cov_row() {  # comp svc count status err
  csv_row "$COV_CSV" "$1" "${COMP_NAME[$1]:-<unknown>}" "$2" "$3" "$4" "$5"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo "======================================================================"
echo " CP-9 BACKUP TYPE / CONFIGURATION / FREQUENCY EVIDENCE"
echo "======================================================================"
echo " read-only : verified against own source (--selfcheck to reproduce)"
echo " region    : ${REGION_OVERRIDE:-<cloud-shell / config default>}"
echo " auth      : ${PROFILE:-<delegation token / DEFAULT>}"
echo " scope     : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'command-line/default')"
echo " services  : $SERVICES"
echo " output    : $OUTDIR"
echo "======================================================================"
echo

# ---------------------------------------------------------------------------
# Tenancy + compartments (id AND name)
# ---------------------------------------------------------------------------
declare -A COMP_NAME

oci_try iam compartment list --access-level ANY --limit 1 --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$OCI_OUT"
case "$TENANCY_ID" in ocid1.tenancy.*) : ;; *) TENANCY_ID="" ;; esac
[ -z "$TENANCY_ID" ] && { echo "ERROR: could not resolve tenancy OCID ($OCI_STATUS): $OCI_ERR" >&2; exit 1; }
echo "Tenancy: $TENANCY_ID"

COMPS=""
if [ "$SELECT_SCOPE" -eq 1 ]; then
  oci_try iam compartment list --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
          --access-level ANY --lifecycle-state ACTIVE --all
  [ "$OCI_STATUS" != "OK" ] && { echo "ERROR: compartment discovery failed ($OCI_STATUS): $OCI_ERR" >&2; exit 1; }

  scope_json="$OCI_OUT"
  scope_catalog="$(printf '%s' "$scope_json" | jq -r '.data[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps="${discovered_comps}${cid}"$'\n'
  done <<< "$scope_catalog"

  oci_try iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output
  [ "$OCI_STATUS" = "OK" ] || { echo "ERROR: tenancy name lookup failed ($OCI_STATUS): $OCI_ERR" >&2; exit 1; }
  COMP_NAME["$TENANCY_ID"]="${OCI_OUT:-root}"

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
  oci_try iam compartment get --compartment-id "$SINGLE_COMP" --query 'data.name' --raw-output
  COMP_NAME["$SINGLE_COMP"]="${OCI_OUT:-<unknown>}"
else
  oci_try iam compartment list --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
          --access-level ANY --lifecycle-state ACTIVE --all
  [ "$OCI_STATUS" != "OK" ] && { echo "ERROR: compartment enumeration failed ($OCI_STATUS): $OCI_ERR" >&2; exit 1; }
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    COMPS="${COMPS}${cid}"$'\n'
  done < <(printf '%s' "$OCI_OUT" | jq -r '.data[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r')
  oci_try iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output
  COMP_NAME["$TENANCY_ID"]="${OCI_OUT:-root}"
  COMPS="$TENANCY_ID"$'\n'"$COMPS"
fi

if [ -n "$COMP_NAMES_FILTER" ]; then
  filtered=""
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    nm="$(printf '%s' "${COMP_NAME[$cid]:-}" | tr 'A-Z' 'a-z')"
    IFS=',' read -ra wanted <<< "$COMP_NAMES_FILTER"
    for w in "${wanted[@]}"; do
      w="$(printf '%s' "$w" | sed 's/^ *//;s/ *$//' | tr 'A-Z' 'a-z')"
      [ -z "$w" ] && continue
      [ "$nm" = "$w" ] && { filtered="${filtered}${cid}"$'\n'; break; }
    done
  done <<< "$COMPS"
  COMPS="$filtered"
  if [ "$(num "$(printf '%s\n' "$COMPS" | grep -c . || true)")" -eq 0 ]; then
    echo "ERROR: no compartment matched -n '$COMP_NAMES_FILTER'." >&2
    echo "Available:" >&2
    for k in "${!COMP_NAME[@]}"; do echo "  ${COMP_NAME[$k]}" >&2; done
    exit 1
  fi
fi

COMP_COUNT="$(num "$(printf '%s\n' "$COMPS" | grep -c . || true)")"
[ "$COMP_COUNT" -eq 0 ] && abort_before_scan "no compartments matched the requested scope"
echo "Scope  : $COMP_COUNT compartment(s)"
echo

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
  "CP-9 BACKUP CONFIGURATION" "cp09-01/cp09-01-backup-type-config-frequency.sh" \
  "CP-9 / CP-9(1)" "${REGION_OVERRIDE:-<cloud-shell / config default>}" \
  "$PLAN_SCOPE_TYPE" "$PLAN_SCOPE_NAME" "$PLAN_SCOPE_OCID" "$COMP_COUNT" \
  "$PLAN_TARGETS" "Requested service scans" "$PLAN_WORK" \
  "$CFG_CSV"$'\n'"$COV_CSV"$'\n'"$FIND_CSV" \
  "resource OCIDs/names, backup policies, schedules, retention and backup times"
# Passing 1 rather than $SELECT_SCOPE is the fix: a manual -c/-n run now
# requires exact uppercase YES after the plan instead of proceeding silently.
if [ "$NON_INTERACTIVE" -eq 1 ]; then
  oci_scope_validate_automation "$PLAN_TARGETS" || abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
elif ! oci_scope_require_final_approval 1; then
  abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
fi

OS_NS=""
if has_svc object; then
  oci_try os ns get --query 'data' --raw-output
  [ "$OCI_STATUS" = "OK" ] && OS_NS="$OCI_OUT"
fi

# ---------------------------------------------------------------------------
# Block volume backup policy schedules.
#
# Policy details are fetched once per policy id and cached: Oracle-defined
# bronze/silver/gold are assigned to most volumes in the tenancy, so without a
# cache this is one API call per volume.
# ---------------------------------------------------------------------------
declare -A POLICY_NAME_CACHE
declare -A POLICY_SCHED_CACHE   # id -> schedule lines, \x1e-separated
declare -A POLICY_STATUS_CACHE

load_bv_policy() {  # $1 = policy id
  local pid="$1"
  [ -n "${POLICY_STATUS_CACHE[$pid]:-}" ] && return 0
  oci_try bv volume-backup-policy get --policy-id "$pid"
  POLICY_STATUS_CACHE["$pid"]="$OCI_STATUS"
  if [ "$OCI_STATUS" != "OK" ]; then
    POLICY_NAME_CACHE["$pid"]=""
    POLICY_SCHED_CACHE["$pid"]=""
    return 1
  fi
  POLICY_NAME_CACHE["$pid"]="$(jqd '.data."display-name" // ""')"
  local acc="" line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    acc="${acc}${line}"$'\x1e'
  done < <(jqd '
    .data.schedules[]? |
    [ (."backup-type"//"") ,
      ( (."period"//"") +
        (if ."hour-of-day"   != null then " hour=" + (."hour-of-day"|tostring) else "" end) +
        (if ."day-of-week"   != null then " dow="  + (."day-of-week"|tostring)  else "" end) +
        (if ."day-of-month"  != null then " dom="  + (."day-of-month"|tostring) else "" end) +
        (if ."month"         != null then " month="+ (."month"|tostring)        else "" end) +
        (if ."offset-type"   != null then " offset=" + (."offset-type"|tostring) else "" end)
      ),
      ( (if ."retention-seconds" != null
           then ((."retention-seconds"/86400)|floor|tostring) + "d (" + (."retention-seconds"|tostring) + "s)"
           elif ."retention-period" != null
           then "retention-period=" + (."retention-period"|tostring)
           else "" end) +
        (if ."is-retention-lock-enabled" != null
           then ";retention-lock=" + (."is-retention-lock-enabled"|tostring) else "" end) +
        (if ."is-prevent-deletion-enabled" != null
           then ";prevent-deletion=" + (."is-prevent-deletion-enabled"|tostring) else "" end)
      ),
      (."time-zone"//"")
    ] | @tsv')
  POLICY_SCHED_CACHE["$pid"]="$acc"
  return 0
}

# Emit one config row per schedule in a block/boot volume policy.
emit_bv_schedules() {  # comp svc rtype rname rid psource pid last count
  local comp="$1" svc="$2" rtype="$3" rname="$4" rid="$5" psource="$6" pid="$7" last="$8" cnt="$9"
  load_bv_policy "$pid"
  local st="${POLICY_STATUS_CACHE[$pid]:-ERROR}"
  local pname="${POLICY_NAME_CACHE[$pid]:-}"
  if [ "$st" != "OK" ]; then
    cfg_row "$comp" "$svc" "$rtype" "$rname" "$rid" "POLICY_LOOKUP_FAILED" "$psource" "$pname" "$pid" \
            "" "" "" "" "$last" "$cnt" "$st" "$OCI_ERR"
    return
  fi
  local sched="${POLICY_SCHED_CACHE[$pid]:-}"
  if [ -z "$sched" ]; then
    cfg_row "$comp" "$svc" "$rtype" "$rname" "$rid" "YES-NO_SCHEDULES" "$psource" "$pname" "$pid" \
            "" "" "" "" "$last" "$cnt" "OK" ""
    finding "HIGH" "policy-without-schedule" "$comp" "$svc" "$rname" \
            "Assigned backup policy '$pname' has no schedules — no backup will ever run." \
            "Add a schedule to the policy or assign a policy that has one."
    return
  fi
  local rec
  while IFS= read -r rec; do
    [ -z "$rec" ] && continue
    local btype freq ret tz
    IFS=$'\t' read -r btype freq ret tz <<< "$rec"
    cfg_row "$comp" "$svc" "$rtype" "$rname" "$rid" "YES" "$psource" "$pname" "$pid" \
            "$btype" "$freq" "$ret" "$tz" "$last" "$cnt" "OK" ""
  done < <(printf '%s' "${sched//$'\x1e'/$'\n'}")
}

# ---------------------------------------------------------------------------
# Block volumes
# ---------------------------------------------------------------------------
check_volumes() {
  local comp="$1"
  oci_try bv volume list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "BlockVolume" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  # Capture before any further oci_try call overwrites OCI_OUT.
  local vols="$OCI_OUT"
  local n; n="$(num "$(printf '%s' "$vols" | jq -r '[.data[]?] | length' 2>/dev/null)")"
  cov_row "$comp" "BlockVolume" "$n" "OK" ""
  [ "$n" -eq 0 ] && return

  # One backup listing per compartment, reused for every volume in it.
  oci_try bv backup list --compartment-id "$comp" --all
  local bk_json="$OCI_OUT" bk_ok="$OCI_STATUS"

  while IFS=$'\t' read -r vid vname; do
    [ -z "$vid" ] && continue
    local last="" cnt="0"
    if [ "$bk_ok" = "OK" ]; then
      cnt="$(num "$(printf '%s' "$bk_json" | jq -r --arg v "$vid" '[.data[]? | select(."volume-id"==$v)] | length' 2>/dev/null)")"
      last="$(printf '%s' "$bk_json" | jq -r --arg v "$vid" '[.data[]? | select(."volume-id"==$v) | ."time-created"] | sort | last // ""' 2>/dev/null | tr -d '\r')"
    fi
    oci_try bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --asset-id "$vid"
    if [ "$OCI_STATUS" != "OK" ]; then
      cfg_row "$comp" "BlockVolume" "Volume" "$vname" "$vid" "UNKNOWN" "assignment-lookup" "" "" \
              "" "" "" "" "$last" "$cnt" "$OCI_STATUS" "$OCI_ERR"
      continue
    fi
    local pid; pid="$(jqd '.data[0]."policy-id" // ""')"
    if [ -z "$pid" ]; then
      cfg_row "$comp" "BlockVolume" "Volume" "$vname" "$vid" "NO" "assignment-lookup" "" "" \
              "" "" "" "" "$last" "$cnt" "OK" ""
      finding "HIGH" "no-backup-policy" "$comp" "BlockVolume" "$vname" \
              "Block volume has no backup policy assigned (verified via policy-asset-assignment API). Existing backups: $cnt" \
              "Assign a backup policy, or document the risk acceptance if the volume is genuinely ephemeral."
      continue
    fi
    emit_bv_schedules "$comp" "BlockVolume" "Volume" "$vname" "$vid" "assignment-lookup" "$pid" "$last" "$cnt"
  done < <(printf '%s' "$vols" | jq -r '.data[]? | [.id, (."display-name"//"")] | @tsv' 2>/dev/null | tr -d '\r')
}

# ---------------------------------------------------------------------------
# Boot volumes (require an availability domain to list)
# ---------------------------------------------------------------------------
check_bootvol() {
  local comp="$1"
  oci_try iam availability-domain list --compartment-id "$comp"
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "BootVolume" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local ads total=0; ads="$(jqd '.data[]?.name')"

  oci_try bv boot-volume-backup list --compartment-id "$comp" --all
  local bk_json="$OCI_OUT" bk_ok="$OCI_STATUS"

  local ad
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    oci_try bv boot-volume list --compartment-id "$comp" --availability-domain "$ad" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      cov_row "$comp" "BootVolume" "0" "$OCI_STATUS" "$OCI_ERR"; continue
    fi
    local bvols="$OCI_OUT"
    while IFS=$'\t' read -r bid bname; do
      [ -z "$bid" ] && continue
      total=$((total+1))
      local last="" cnt="0"
      if [ "$bk_ok" = "OK" ]; then
        cnt="$(num "$(printf '%s' "$bk_json" | jq -r --arg v "$bid" '[.data[]? | select(."boot-volume-id"==$v)] | length' 2>/dev/null)")"
        last="$(printf '%s' "$bk_json" | jq -r --arg v "$bid" '[.data[]? | select(."boot-volume-id"==$v) | ."time-created"] | sort | last // ""' 2>/dev/null | tr -d '\r')"
      fi
      oci_try bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --asset-id "$bid"
      if [ "$OCI_STATUS" != "OK" ]; then
        cfg_row "$comp" "BootVolume" "BootVolume" "$bname" "$bid" "UNKNOWN" "assignment-lookup" "" "" \
                "" "" "" "" "$last" "$cnt" "$OCI_STATUS" "$OCI_ERR"; continue
      fi
      local pid; pid="$(jqd '.data[0]."policy-id" // ""')"
      if [ -z "$pid" ]; then
        cfg_row "$comp" "BootVolume" "BootVolume" "$bname" "$bid" "NO" "assignment-lookup" "" "" \
                "" "" "" "" "$last" "$cnt" "OK" ""
        finding "HIGH" "no-backup-policy" "$comp" "BootVolume" "$bname" \
                "Boot volume has no backup policy assigned. Existing backups: $cnt" \
                "Assign a backup policy; an unprotected boot volume means the instance cannot be rebuilt from backup."
        continue
      fi
      emit_bv_schedules "$comp" "BootVolume" "BootVolume" "$bname" "$bid" "assignment-lookup" "$pid" "$last" "$cnt"
    done < <(printf '%s' "$bvols" | jq -r '.data[]? | [.id, (."display-name"//"")] | @tsv' 2>/dev/null | tr -d '\r')
  done <<< "$ads"
  cov_row "$comp" "BootVolume" "$total" "OK" ""
}

# ---------------------------------------------------------------------------
# Volume groups — a group-level policy protects all member volumes
# ---------------------------------------------------------------------------
check_volgroup() {
  local comp="$1"
  oci_try bv volume-group list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "VolumeGroup" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local n; n="$(num "$(jqd '[.data[]?] | length')")"
  cov_row "$comp" "VolumeGroup" "$n" "OK" ""
  [ "$n" -eq 0 ] && return
  local vgs="$OCI_OUT"
  while IFS=$'\t' read -r gid gname members; do
    [ -z "$gid" ] && continue
    oci_try bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --asset-id "$gid"
    local pid=""
    [ "$OCI_STATUS" = "OK" ] && pid="$(jqd '.data[0]."policy-id" // ""')"
    if [ -z "$pid" ]; then
      cfg_row "$comp" "VolumeGroup" "VolumeGroup" "$gname (${members} members)" "$gid" "NO" "assignment-lookup" "" "" \
              "" "" "" "" "" "0" "${OCI_STATUS}" "$OCI_ERR"
    else
      emit_bv_schedules "$comp" "VolumeGroup" "VolumeGroup" "$gname (${members} members)" "$gid" "assignment-lookup" "$pid" "" "0"
    fi
  done < <(printf '%s' "$vgs" | jq -r '.data[]? | [.id, (."display-name"//""), ([.["volume-ids"][]?]|length)] | @tsv' 2>/dev/null | tr -d '\r')
}

# ---------------------------------------------------------------------------
# File Storage.
#
# Both prior blockers live here. The command group is
# `fs filesystem-snapshot-policy` (NOT `fs snapshot-policy`), and `schedules`
# is absent from the LIST summary — it only appears on GET, so each policy is
# fetched individually. Reading schedules off the list would silently report
# NO_SCHEDULES for every policy that actually has one.
# ---------------------------------------------------------------------------
declare -A FSSP_NAME_CACHE
declare -A FSSP_SCHED_CACHE
declare -A FSSP_STATUS_CACHE

load_fss_policy() {  # $1 = filesystem-snapshot-policy id
  local pid="$1"
  [ -n "${FSSP_STATUS_CACHE[$pid]:-}" ] && return 0
  oci_try fs filesystem-snapshot-policy get --filesystem-snapshot-policy-id "$pid"
  FSSP_STATUS_CACHE["$pid"]="$OCI_STATUS"
  if [ "$OCI_STATUS" != "OK" ]; then
    FSSP_NAME_CACHE["$pid"]=""; FSSP_SCHED_CACHE["$pid"]=""; return 1
  fi
  FSSP_NAME_CACHE["$pid"]="$(jqd '.data."display-name" // ""')"
  local acc="" line
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    acc="${acc}${line}"$'\x1e'
  done < <(jqd '
    .data.schedules[]? |
    [ ("SNAPSHOT"),
      ( (."period"//"") +
        (if ."hour-of-day"  != null then " hour=" + (."hour-of-day"|tostring) else "" end) +
        (if ."day-of-week"  != null then " dow="  + (."day-of-week"|tostring)  else "" end) +
        (if ."day-of-month" != null then " dom="  + (."day-of-month"|tostring) else "" end) +
        (if ."month"        != null then " month="+ (."month"|tostring)        else "" end)
      ),
      (if ."retention-duration-in-seconds" != null
         then ((."retention-duration-in-seconds"/86400)|floor|tostring) + "d (" + (."retention-duration-in-seconds"|tostring) + "s)"
         else "" end),
      (."time-zone"//"")
    ] | @tsv')
  FSSP_SCHED_CACHE["$pid"]="$acc"
  return 0
}

check_fss() {
  local comp="$1"
  oci_try iam availability-domain list --compartment-id "$comp"
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "FSS" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local ads total=0; ads="$(jqd '.data[]?.name')"
  local ad
  while IFS= read -r ad; do
    [ -z "$ad" ] && continue
    oci_try fs file-system list --compartment-id "$comp" --availability-domain "$ad" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      cov_row "$comp" "FSS" "0" "$OCI_STATUS" "$OCI_ERR"; continue
    fi
    local fsl="$OCI_OUT"
    while IFS=$'\t' read -r fid fname pid; do
      [ -z "$fid" ] && continue
      total=$((total+1))

      # Manual snapshots still constitute recovery points; count them either way.
      oci_try fs snapshot list --file-system-id "$fid" --all
      local snap_ok="$OCI_STATUS" cnt="0" last=""
      if [ "$snap_ok" = "OK" ]; then
        cnt="$(num "$(jqd '[.data[]?] | length')")"
        last="$(jqd '[.data[]? | ."time-created"] | sort | last // ""')"
      fi

      if [ -z "$pid" ] || [ "$pid" = "null" ]; then
        if [ "$cnt" -gt 0 ]; then
          cfg_row "$comp" "FSS" "FileSystem" "$fname" "$fid" "MANUAL-ONLY" "filesystem-snapshot-policy-id" "" "" \
                  "MANUAL" "on-demand only" "" "" "$last" "$cnt" "OK" ""
          finding "MEDIUM" "manual-snapshots-only" "$comp" "FSS" "$fname" \
                  "File system has $cnt snapshot(s) but no snapshot policy — protection depends on someone remembering." \
                  "Attach a filesystem snapshot policy so snapshots are scheduled rather than ad hoc."
        else
          cfg_row "$comp" "FSS" "FileSystem" "$fname" "$fid" "NO" "filesystem-snapshot-policy-id" "" "" \
                  "" "" "" "" "" "0" "OK" ""
          finding "HIGH" "no-backup-policy" "$comp" "FSS" "$fname" \
                  "File system has no snapshot policy and zero snapshots." \
                  "Attach a filesystem snapshot policy."
        fi
        continue
      fi

      load_fss_policy "$pid"
      local st="${FSSP_STATUS_CACHE[$pid]:-ERROR}"
      local pname="${FSSP_NAME_CACHE[$pid]:-}"
      if [ "$st" != "OK" ]; then
        cfg_row "$comp" "FSS" "FileSystem" "$fname" "$fid" "POLICY_LOOKUP_FAILED" "filesystem-snapshot-policy-id" \
                "$pname" "$pid" "" "" "" "" "$last" "$cnt" "$st" "$OCI_ERR"
        continue
      fi
      local sched="${FSSP_SCHED_CACHE[$pid]:-}"
      if [ -z "$sched" ]; then
        cfg_row "$comp" "FSS" "FileSystem" "$fname" "$fid" "YES-NO_SCHEDULES" "filesystem-snapshot-policy-id" \
                "$pname" "$pid" "" "" "" "" "$last" "$cnt" "OK" ""
        finding "HIGH" "policy-without-schedule" "$comp" "FSS" "$fname" \
                "Snapshot policy '$pname' is attached but defines no schedules — no snapshot will ever be taken." \
                "Add a schedule to the snapshot policy."
        continue
      fi
      local rec
      while IFS= read -r rec; do
        [ -z "$rec" ] && continue
        local btype freq ret tz
        IFS=$'\t' read -r btype freq ret tz <<< "$rec"
        cfg_row "$comp" "FSS" "FileSystem" "$fname" "$fid" "YES" "filesystem-snapshot-policy-id" \
                "$pname" "$pid" "$btype" "$freq" "$ret" "$tz" "$last" "$cnt" "OK" ""
      done < <(printf '%s' "${sched//$'\x1e'/$'\n'}")
    done < <(printf '%s' "$fsl" | jq -r '.data[]? | [.id, (."display-name"//""), (."filesystem-snapshot-policy-id"//"")] | @tsv' 2>/dev/null | tr -d '\r')
  done <<< "$ads"
  cov_row "$comp" "FSS" "$total" "OK" ""
}

# ---------------------------------------------------------------------------
# Object Storage — no backup policy concept; protection is versioning +
# lifecycle + retention rules. Recorded as configuration, not as a schedule.
# ---------------------------------------------------------------------------
check_object() {
  local comp="$1"
  if [ -z "$OS_NS" ]; then
    cov_row "$comp" "ObjectStorage" "0" "NOT_COLLECTED" "namespace unavailable"; return
  fi
  oci_try os bucket list --compartment-id "$comp" --namespace-name "$OS_NS" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "ObjectStorage" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local n; n="$(num "$(jqd '[.data[]?] | length')")"
  cov_row "$comp" "ObjectStorage" "$n" "OK" ""
  [ "$n" -eq 0 ] && return
  local b
  while IFS= read -r b; do
    [ -z "$b" ] && continue
    oci_try os bucket get --bucket-name "$b" --namespace-name "$OS_NS"
    if [ "$OCI_STATUS" != "OK" ]; then
      cfg_row "$comp" "ObjectStorage" "Bucket" "$b" "$b" "UNKNOWN" "bucket-get" "" "" \
              "" "" "" "" "" "0" "$OCI_STATUS" "$OCI_ERR"; continue
    fi
    local ver; ver="$(jqd '.data.versioning // "Disabled"')"

    oci_try os object-lifecycle-policy get --bucket-name "$b" --namespace-name "$OS_NS"
    local lc="0"
    [ "$OCI_STATUS" = "OK" ] && lc="$(num "$(jqd '[(.data.items? // .data)[]?] | length')")"

    oci_try os retention-rule list --bucket-name "$b" --namespace-name "$OS_NS" --all
    local rr="0"
    [ "$OCI_STATUS" = "OK" ] && rr="$(num "$(jqd '[(.data.items? // .data)[]?] | length')")"

    local configured="NO" detail="versioning=$ver lifecycle_rules=$lc retention_rules=$rr"
    if [ "$ver" != "Disabled" ] || [ "$rr" -gt 0 ]; then configured="YES"; fi
    cfg_row "$comp" "ObjectStorage" "Bucket" "$b" "$b" "$configured" "bucket-config" "" "" \
            "OBJECT-VERSIONING/RETENTION" "$detail" "${rr} retention rule(s)" "" "" "0" "OK" ""
    if [ "$configured" = "NO" ]; then
      finding "MEDIUM" "bucket-unprotected" "$comp" "ObjectStorage" "$b" \
              "Bucket has versioning disabled and no retention rules — an overwrite or delete is unrecoverable. $detail" \
              "Enable versioning, and add a retention rule if the bucket holds backup or record data."
    fi
  done < <(jqd '.data[]?.name')
}

# ---------------------------------------------------------------------------
# Base DB systems
# ---------------------------------------------------------------------------
check_basedb() {
  local comp="$1"
  oci_try db system list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "BaseDB" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local sys="$OCI_OUT" total=0 sysid
  while IFS= read -r sysid; do
    [ -z "$sysid" ] && continue
    oci_try db database list --compartment-id "$comp" --db-system-id "$sysid" --all
    [ "$OCI_STATUS" != "OK" ] && continue
    local dbs="$OCI_OUT"
    while IFS=$'\t' read -r dbid dbname en win ret; do
      [ -z "$dbid" ] && continue
      total=$((total+1))
      if [ "$en" = "true" ]; then
        cfg_row "$comp" "BaseDB" "Database" "$dbname" "$dbid" "YES" "db-backup-config" "automatic-backup" "" \
                "FULL+INCREMENTAL (managed)" "daily automatic (window=${win:-default})" "${ret:-default} day recovery window" "" "" "0" "OK" ""
      else
        cfg_row "$comp" "BaseDB" "Database" "$dbname" "$dbid" "NO" "db-backup-config" "" "" \
                "" "" "" "" "" "0" "OK" ""
        finding "HIGH" "no-backup-policy" "$comp" "BaseDB" "$dbname" \
                "Automatic backup is disabled on this database." \
                "Enable automatic backup and set a recovery window meeting the RPO in the ISCP."
      fi
    done < <(printf '%s' "$dbs" | jq -r '.data[]? | [.id, (."db-name"//""), ((."db-backup-config"."auto-backup-enabled")//false|tostring), ((."db-backup-config"."auto-backup-window")//""), ((."db-backup-config"."recovery-window-in-days")//""|tostring)] | @tsv' 2>/dev/null | tr -d '\r')
  done < <(printf '%s' "$sys" | jq -r '.data[]?.id' 2>/dev/null | tr -d '\r')
  cov_row "$comp" "BaseDB" "$total" "OK" ""
}

# ---------------------------------------------------------------------------
# Autonomous Database
# ---------------------------------------------------------------------------
check_adb() {
  local comp="$1"
  oci_try db autonomous-database list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "AutonomousDB" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local n; n="$(num "$(jqd '[.data[]?] | length')")"
  cov_row "$comp" "AutonomousDB" "$n" "OK" ""
  [ "$n" -eq 0 ] && return
  while IFS=$'\t' read -r aid aname en ret; do
    [ -z "$aid" ] && continue
    if [ "$en" = "true" ]; then
      cfg_row "$comp" "AutonomousDB" "AutonomousDatabase" "$aname" "$aid" "YES" "is-automatic-backup-enabled" \
              "automatic-backup" "" "FULL (managed)" "daily automatic" "${ret:-n/a} days" "" "" "0" "OK" ""
    else
      cfg_row "$comp" "AutonomousDB" "AutonomousDatabase" "$aname" "$aid" "NO" "is-automatic-backup-enabled" \
              "" "" "" "" "${ret:-n/a} days" "" "" "0" "OK" ""
      finding "HIGH" "no-backup-policy" "$comp" "AutonomousDB" "$aname" \
              "Automatic backup is disabled on this Autonomous Database." \
              "Enable automatic backup."
    fi
  done < <(jqd '.data[]? | [.id, (."db-name"//""), ((."is-automatic-backup-enabled")//false|tostring), ((."backup-retention-period-in-days")//""|tostring)] | @tsv')
}

# ---------------------------------------------------------------------------
# MySQL HeatWave
# ---------------------------------------------------------------------------
check_mysql() {
  local comp="$1"
  oci_try mysql db-system list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "MySQL" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local ids; ids="$(jqd '(.data.items? // .data)[]?.id')"
  local total=0 sid
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    total=$((total+1))
    oci_try mysql db-system get --db-system-id "$sid"
    if [ "$OCI_STATUS" != "OK" ]; then
      cfg_row "$comp" "MySQL" "DbSystem" "" "$sid" "UNKNOWN" "backup-policy" "" "" "" "" "" "" "" "0" "$OCI_STATUS" "$OCI_ERR"
      continue
    fi
    local name en win ret
    name="$(jqd '.data."display-name" // ""')"
    en="$(jqd '.data."backup-policy"."is-enabled" // false | tostring')"
    win="$(jqd '.data."backup-policy"."window-start-time" // ""')"
    ret="$(jqd '.data."backup-policy"."retention-in-days" // "" | tostring')"
    if [ "$en" = "true" ]; then
      cfg_row "$comp" "MySQL" "DbSystem" "$name" "$sid" "YES" "backup-policy" "automatic-backup" "" \
              "FULL (managed)" "daily automatic (window=${win:-default})" "${ret:-default} days" "" "" "0" "OK" ""
    else
      cfg_row "$comp" "MySQL" "DbSystem" "$name" "$sid" "NO" "backup-policy" "" "" "" "" "" "" "" "0" "OK" ""
      finding "HIGH" "no-backup-policy" "$comp" "MySQL" "$name" \
              "MySQL backup policy is disabled on this DB system." "Enable the backup policy."
    fi
  done <<< "$ids"
  cov_row "$comp" "MySQL" "$total" "OK" ""
}

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
check_postgres() {
  local comp="$1"
  oci_try psql db-system list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    cov_row "$comp" "PostgreSQL" "0" "$OCI_STATUS" "$OCI_ERR"; return
  fi
  local ids; ids="$(jqd '(.data.items? // .data)[]?.id')"
  local total=0 sid
  while IFS= read -r sid; do
    [ -z "$sid" ] && continue
    total=$((total+1))
    oci_try psql db-system get --db-system-id "$sid"
    if [ "$OCI_STATUS" != "OK" ]; then
      cfg_row "$comp" "PostgreSQL" "DbSystem" "" "$sid" "UNKNOWN" "backup-policy" "" "" "" "" "" "" "" "0" "$OCI_STATUS" "$OCI_ERR"
      continue
    fi
    # The backup policy is nested under management-policy in the current psql
    # DbSystem model. Reading .data."backup-policy" directly always yielded an
    # empty kind, which made every PostgreSQL system look unprotected and
    # raised a HIGH no-backup-policy finding against correctly backed-up
    # systems. The flat path is kept as a trailing fallback only.
    local name kind ret days start
    name="$(jqd '.data."display-name" // ""')"
    kind="$(jqd '(.data."management-policy"."backup-policy" // .data."backup-policy" // {})."kind" // ""')"
    ret="$(jqd '(.data."management-policy"."backup-policy" // .data."backup-policy" // {})."retention-days" // "" | tostring')"
    days="$(jqd '(.data."management-policy"."backup-policy" // .data."backup-policy" // {}) | (."days-of-the-month" // ."days-of-the-week" // "") | tostring')"
    start="$(jqd '(.data."management-policy"."backup-policy" // .data."backup-policy" // {})."backup-start" // "" | tostring')"
    if [ -n "$kind" ] && [ "$kind" != "NONE" ]; then
      cfg_row "$comp" "PostgreSQL" "DbSystem" "$name" "$sid" "YES" "management-policy.backup-policy" "$kind" "" \
              "FULL (managed)" "$kind ${days}${start:+ start=$start}" "${ret:-default} days" "" "" "0" "OK" ""
    else
      if [ -z "$kind" ]; then
        # The response carried no policy object at all. That does not establish
        # that backups are off, so it must not become a no-backup finding.
        cfg_row "$comp" "PostgreSQL" "DbSystem" "$name" "$sid" "UNKNOWN" \
                "management-policy.backup-policy" "" "" "" "" "" "" "" "0" "OK" \
                "backup policy not present in the db-system response"
        finding "MEDIUM" "backup-policy-not-exposed" "$comp" "PostgreSQL" "$name" \
                "The PostgreSQL db-system response did not expose management-policy.backup-policy, so backup configuration could not be read." \
                "Verify the backup policy in the Console or with a read-only API call and record the result manually."
      else
        cfg_row "$comp" "PostgreSQL" "DbSystem" "$name" "$sid" "NO" \
                "management-policy.backup-policy" "$kind" "" "" "" "" "" "" "0" "OK" ""
        finding "HIGH" "no-backup-policy" "$comp" "PostgreSQL" "$name" \
                "PostgreSQL backup policy kind is NONE." "Configure a backup policy."
      fi
    fi
  done <<< "$ids"
  cov_row "$comp" "PostgreSQL" "$total" "OK" ""
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"
  has_svc volumes  && check_volumes  "$comp"
  has_svc bootvol  && check_bootvol  "$comp"
  has_svc volgroup && check_volgroup "$comp"
  has_svc fss      && check_fss      "$comp"
  has_svc object   && check_object   "$comp"
  has_svc basedb   && check_basedb   "$comp"
  has_svc adb      && check_adb      "$comp"
  has_svc mysql    && check_mysql    "$comp"
  has_svc postgres && check_postgres "$comp"
done <<< "$COMPS"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
rows() { local f="$1"; [ -f "$f" ] || { printf '0'; return; }; local n; n=$(( $(wc -l < "$f") - 1 )); [ "$n" -lt 0 ] && n=0; printf '%s' "$n"; }

CFG_N="$(rows "$CFG_CSV")"
PROT="$(num "$(grep -c '","YES' "$CFG_CSV" 2>/dev/null || true)")"
UNPROT="$(num "$(grep -c '","NO","' "$CFG_CSV" 2>/dev/null || true)")"
UNK="$(num "$(grep -c '","UNKNOWN","' "$CFG_CSV" 2>/dev/null || true)")"
CRIT="$(num "$(grep -c '^"CRITICAL"' "$FIND_CSV" 2>/dev/null || true)")"
HIGH="$(num "$(grep -c '^"HIGH"' "$FIND_CSV" 2>/dev/null || true)")"
MED="$(num "$(grep -c '^"MEDIUM"' "$FIND_CSV" 2>/dev/null || true)")"

echo
echo "======================================================================"
echo " CP-9 BACKUP CONFIGURATION SUMMARY"
echo "======================================================================"
echo " Compartments in scope        : $COMP_COUNT"
echo " Config rows (asset+schedule) : $CFG_N"
echo "   backed up                  : $PROT"
echo "   NOT backed up              : $UNPROT"
echo "   undetermined               : $UNK"
echo
echo " Findings — CRITICAL: $CRIT   HIGH: $HIGH   MEDIUM: $MED"
if [ "$HIGH" -gt 0 ] || [ "$CRIT" -gt 0 ]; then
  echo
  echo " >>> ASSETS WITH NO BACKUP CONFIGURED:"
  awk -F'","' 'NR>1 && ($1 ~ /CRITICAL/ || $1 ~ /HIGH/) {
        s=$1; gsub(/^"/,"",s); c=$4; sv=$5; r=$6;
        printf "   [%-8s] %-20s %-14s %s\n", s, c, sv, r
      }' "$FIND_CSV" 2>/dev/null | head -30
fi
echo
echo " Evidence files:"
echo "   config   : $CFG_CSV"
echo "   coverage : $COV_CSV   <-- proves which compartments/services were visited"
echo "   findings : $FIND_CSV"
echo
echo "----------------------------------------------------------------------"
echo " SCOPE AND LIMITATIONS — read before citing this as evidence"
echo "----------------------------------------------------------------------"
cat <<'LIMITS'
 * Point in time, single region per run. Re-run with -r for each subscribed
   region; policy assignments and schedules are regional.
 * Any row whose collection_status is not OK means NOT COLLECTED, not "no
   backup configured". Check the coverage CSV before reading absence as
   compliance: it lists every compartment/service pair actually visited.
 * This script reports backup CONFIGURATION and the most recent backup seen.
   It does not verify a backup is restorable — only a restore test does that
   (see the ISCP test plan, CP-4).
 * Managed database services (Base DB, ADB, MySQL, PostgreSQL) expose a policy
   flag and retention window rather than a schedule object; "daily automatic"
   reflects the service behaviour, not a user-defined cron.
 * Object Storage has no backup-policy concept. Versioning, lifecycle and
   retention rules are reported instead; replication is covered by cp09-03.
 * Who can reach these backups is cp09-02; replication/DR posture is cp09-03.
LIMITS
echo "----------------------------------------------------------------------"

if [ "$INCOMPLETE" -ne 0 ]; then
  echo
  echo " WARNING: one or more collections were incomplete (DENIED / ERROR /"
  echo " CLI_UNSUPPORTED rows present). Review collection_status in the CSVs"
  echo " before concluding that any asset is or is not backed up."
  exit 3
fi
exit 0
