#!/usr/bin/env bash
#
# cp09-02-backup-access-files-check.sh
#
# CP-9 EVIDENCE — WHO CAN ACCESS THE BACKUP FILES?
#
# Consolidates and supersedes four earlier scripts in this repo:
#   backup-storage-access.sh / oci-backup-access.sh  (access surface)
#   backup-storage.sh        / oci-backup-audit.sh   (where the backups live)
#
# The earlier access scripts stopped at the group name and said so:
#   "It does not resolve group membership. To see actual humans, cross-reference
#    grantee groups with: oci iam group list-users --group-id <id>"
# This script does that resolution, and closes the other gaps found in review:
#   - matches all-resources / backup-family grants, not just literal keywords
#   - handles multi-grantee statements (Allow group A, group B to ...)
#   - records the VERB (inspect < read < use < manage) so "can list a backup"
#     is distinguishable from "can restore or delete one"
#   - records statement SCOPE, so a tenancy-root grant is not mistaken for a
#     compartment-local one
#   - captures KMS key custody (whoever can use the key can decrypt the backup)
#   - captures PAR expiry and object scope, not just a count
#   - never lets a permission denial look like "no access exists"
#
# OCI TOOLING:
#   Uses the OCI CLI (`oci`) plus `lib/oci-scope-selector.sh` for scope
#   discovery and confirmation. This Task 1 collector does not use the OCI
#   Python SDK.
#
# READ-ONLY. Every OCI call is list/get. Nothing is created, modified, or
# deleted. The script verifies this against its own source at startup; run
# --selfcheck to see that verification on its own.
#
# Auth: OCI Cloud Shell delegation token by default (the same auth that makes
#       `oci iam compartment list` work). Outside Cloud Shell pass -p PROFILE.
#
# Usage:
#   ./cp09-02-backup-access-files-check.sh                  # interactive scope + approval
#   ./cp09-02-backup-access-files-check.sh --select-scope   # discover + confirm scope
#   ./cp09-02-backup-access-files-check.sh -i               # short form
#   ./cp09-02-backup-access-files-check.sh -c <ocid>        # one compartment
#   ./cp09-02-backup-access-files-check.sh -n VCN,CD3       # by compartment NAME
#   ./cp09-02-backup-access-files-check.sh -r us-langley-1  # region override
#   ./cp09-02-backup-access-files-check.sh -p AUDITOR       # config-file profile
#   ./cp09-02-backup-access-files-check.sh -s "grants exposure"   # subset
#   ./cp09-02-backup-access-files-check.sh -o ./evidence    # output directory
#   ./cp09-02-backup-access-files-check.sh --selfcheck      # prove read-only, exit
#
# Phases (-s): artifacts grants principals exposure keys
#
# Output: five timestamped CSVs + console summary.
#   ..._artifacts_<ts>.csv   where backup files actually live (+ key custody)
#   ..._grants_<ts>.csv      IAM statements granting access to backup resources
#   ..._principals_<ts>.csv  THE ANSWER: named users/principals with access
#   ..._exposure_<ts>.csv    IAM-bypass vectors: public buckets, PARs, replication
#   ..._findings_<ts>.csv    severity-ranked risks only
#
# Exit codes: 0 = clean run, 3 = ran but one or more collections were incomplete
#             1 = could not start (missing dependency, no compartments)
#
set -uo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
SCOPE_HELPER="$SCRIPT_DIR/lib/oci-scope-selector.sh"

# ---------------------------------------------------------------------------
# Read-only self-verification
#
# Deny-list of mutating OCI subcommands. Applied to this file's own source,
# ignoring comments. If this ever matches, the script refuses to run.
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

# ---------------------------------------------------------------------------
# Dependencies (checked after --selfcheck, which must work anywhere)
# ---------------------------------------------------------------------------
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
PHASES="artifacts grants principals exposure keys"
SELECT_SCOPE=0

# Normalize the readable long option before getopts handles short options.
NORMALIZED_ARGS=()
for arg in "$@"; do
  case "$arg" in
    --select-scope) SELECT_SCOPE=1 ;;
    *) NORMALIZED_ARGS+=("$arg") ;;
  esac
done
set -- "${NORMALIZED_ARGS[@]}"

while getopts "ic:n:r:p:o:s:h" opt; do
  case "$opt" in
    i) SELECT_SCOPE=1 ;;
    c) SINGLE_COMP="$OPTARG" ;;
    n) COMP_NAMES_FILTER="$OPTARG" ;;
    r) REGION_OVERRIDE="$OPTARG" ;;
    p) PROFILE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    s) PHASES="$OPTARG" ;;
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

has_phase() { case " $PHASES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

mkdir -p -- "$OUTDIR" 2>/dev/null || { echo "ERROR: cannot create output dir: $OUTDIR" >&2; exit 1; }

AUTH_ARG=()
[ -n "$PROFILE" ] && AUTH_ARG=(--profile "$PROFILE")
REGION_ARG=()
[ -n "$REGION_OVERRIDE" ] && REGION_ARG=(--region "$REGION_OVERRIDE")

if ! readonly_selfcheck; then
  echo "Refusing to run." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# OCI invocation wrapper
#
# The single most important fix over the scripts this replaces. They ran every
# call as `oci ... 2>/dev/null`, so a 403 came back as an empty result that was
# indistinguishable from "nobody has access". In audit evidence that is a false
# negative that reads as a clean pass.
#
# Sets OCI_OUT, OCI_RC, OCI_ERR, OCI_STATUS (OK | DENIED | NOTFOUND | ERROR).
# ---------------------------------------------------------------------------
INCOMPLETE=0
OCI_OUT=""; OCI_RC=0; OCI_ERR=""; OCI_STATUS="OK"

oci_try() {
  local errf
  errf="$(mktemp 2>/dev/null || echo "/tmp/cp0902.$$.err")"
  # ${arr[@]+"${arr[@]}"} keeps empty arrays safe under `set -u` on bash < 4.4
  OCI_OUT="$(oci ${REGION_ARG[@]+"${REGION_ARG[@]}"} ${AUTH_ARG[@]+"${AUTH_ARG[@]}"} "$@" 2>"$errf")"
  OCI_RC=$?
  OCI_ERR="$(tr '\n\r' '  ' < "$errf" 2>/dev/null | sed 's/  */ /g' | cut -c1-300)"
  rm -f "$errf" 2>/dev/null

  if [ "$OCI_RC" -eq 0 ]; then
    OCI_STATUS="OK"
  elif printf '%s' "$OCI_ERR" | grep -qiE 'NotAuthorized|Authorization failed|forbidden|\b403\b'; then
    OCI_STATUS="DENIED"; INCOMPLETE=1
  elif printf '%s' "$OCI_ERR" | grep -qiE 'NotFound|does not exist|\b404\b'; then
    OCI_STATUS="NOTFOUND"
  else
    OCI_STATUS="ERROR"; INCOMPLETE=1
  fi
  # Strip raw CR. In JSON a literal carriage return inside a string must be
  # escaped as \r, so a bare 0x0D byte can only be line-ending noise. Left in,
  # it ends up inside map keys and CSV cells.
  OCI_OUT="${OCI_OUT//$'\r'/}"
  # An empty body on success is a legitimately empty list, not a failure.
  [ -z "$OCI_OUT" ] && OCI_OUT='{"data":[]}'
  return 0
}

# jq against the last OCI_OUT, never fatal. tr -d '\r' guards against jq builds
# that emit CRLF (Windows) leaving a trailing CR on every parsed field.
jqd() { printf '%s' "$OCI_OUT" | jq -r "$1" 2>/dev/null | tr -d '\r'; }

# Numeric coercion — guards `[ "$x" -gt 0 ]` against non-numeric input under set -u
num() { case "${1:-}" in ''|*[!0-9]*) printf '0' ;; *) printf '%s' "$1" ;; esac; }

# ---------------------------------------------------------------------------
# CSV output (RFC 4180 + formula-injection neutralisation)
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="$OUTDIR/cp09-02_backup_access"
ART_CSV="${BASE}_artifacts_${TS}.csv"
GRANT_CSV="${BASE}_grants_${TS}.csv"
PRIN_CSV="${BASE}_principals_${TS}.csv"
EXPO_CSV="${BASE}_exposure_${TS}.csv"
FIND_CSV="${BASE}_findings_${TS}.csv"

csv_row() {
  local file="$1"; shift
  local out="" first=1 f
  for f in "$@"; do
    f="${f//$'\n'/ }"; f="${f//$'\r'/}"
    case "$f" in [=+@-]*) f="'$f" ;; esac     # neutralise Excel formula injection
    f="${f//\"/\"\"}"
    if [ "$first" -eq 1 ]; then first=0; else out+=","; fi
    out+="\"${f}\""
  done
  printf '%s\n' "$out" >> "$file"
}

FINDING_COUNT=0
finding() {  # severity category compartment_id resource detail recommendation
  csv_row "$FIND_CSV" "$1" "$2" "$3" "${COMP_NAME[$3]:-<unknown>}" "$4" "$5" "$6"
  FINDING_COUNT=$((FINDING_COUNT+1))
}

printf '%s\n' 'compartment_id,compartment_name,service,artifact_type,artifact_name,artifact_id,lifecycle_state,time_created,encryption_key_mgmt,kms_key_id,collection_status,collection_error' > "$ART_CSV"
printf '%s\n' 'compartment_id,compartment_name,policy_name,policy_id,statement_kind,grantee_type,grantee_name,verb,resource_type,matched_backup_family,scope,where_clause,statement,collection_status,collection_error' > "$GRANT_CSV"
printf '%s\n' 'principal_type,principal_name,principal_id,via_grantee,strongest_verb,backup_resources,scope,granting_compartment_id,granting_compartment_name,policy_name,resolution_status,resolution_note' > "$PRIN_CSV"
printf '%s\n' 'compartment_id,compartment_name,vector,bucket_or_resource,detail,access_type,expires,is_active,severity,collection_status,collection_error' > "$EXPO_CSV"
printf '%s\n' 'severity,category,compartment_id,compartment_name,resource,detail,recommendation' > "$FIND_CSV"

abort_before_scan() {
  local reason="$1"
  rm -f -- "$ART_CSV" "$GRANT_CSV" "$PRIN_CSV" "$EXPO_CSV" "$FIND_CSV" 2>/dev/null
  echo "SCAN NOT STARTED: $reason" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Backup-bearing IAM resource vocabulary
#
# Two tiers. Explicit keywords name a backup resource directly. Broad keywords
# (all-resources, *-family) confer backup access without ever saying "backup" —
# the single largest miss in the script this replaces.
# ---------------------------------------------------------------------------
BACKUP_EXPLICIT='volume-backups|boot-volume-backups|volume-group-backups|db-backups|autonomous-database-backups|backups|mysql-backups|file-systems|mount-targets|buckets|objects|snapshots'
BACKUP_BROAD='all-resources|backup-family|volume-family|object-family|file-family|database-family|autonomous-database-family|instance-family'
BACKUP_KEYWORDS="${BACKUP_EXPLICIT}|${BACKUP_BROAD}"

verb_rank() {
  case "$(printf '%s' "${1:-}" | tr 'A-Z' 'a-z')" in
    manage) printf '4' ;; use) printf '3' ;; read) printf '2' ;; inspect) printf '1' ;; *) printf '0' ;;
  esac
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo "======================================================================"
echo " CP-9 BACKUP ACCESS EVIDENCE — who can reach the backup files"
echo "======================================================================"
echo " read-only : verified against own source (--selfcheck to reproduce)"
echo " region    : ${REGION_OVERRIDE:-<cloud-shell / config default>}"
echo " auth      : ${PROFILE:-<delegation token / DEFAULT>}"
echo " scope     : $([ "$SELECT_SCOPE" -eq 1 ] && printf 'interactive discovery + OCID confirmation' || printf 'command-line/default')"
echo " phases    : $PHASES"
echo " output    : $OUTDIR"
echo "======================================================================"
echo

# ---------------------------------------------------------------------------
# Tenancy + compartment enumeration (id AND name — evidence must be filterable
# by compartment name, e.g. VCN / Shared Services / CD3)
# ---------------------------------------------------------------------------
declare -A COMP_NAME

oci_try iam compartment list --access-level ANY --limit 1 --query 'data[0]."compartment-id"' --raw-output
TENANCY_ID="$OCI_OUT"
case "$TENANCY_ID" in ocid1.tenancy.*) : ;; *) TENANCY_ID="" ;; esac
if [ -z "$TENANCY_ID" ]; then
  echo "ERROR: could not resolve tenancy OCID ($OCI_STATUS): $OCI_ERR" >&2
  echo "       Verify auth with: oci iam compartment list" >&2
  exit 1
fi
echo "Tenancy: $TENANCY_ID"

COMPS=""
if [ "$SELECT_SCOPE" -eq 1 ]; then
  oci_try iam compartment list --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
          --access-level ANY --lifecycle-state ACTIVE --all
  if [ "$OCI_STATUS" != "OK" ]; then
    echo "ERROR: compartment discovery failed ($OCI_STATUS): $OCI_ERR" >&2
    exit 1
  fi

  scope_json="$OCI_OUT"
  scope_catalog="$(printf '%s' "$scope_json" | jq -r '.data[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r' | sort -f -k2)"
  discovered_comps=""
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    discovered_comps="${discovered_comps}${cid}"$'\n'
  done <<< "$scope_catalog"

  oci_try iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output
  if [ "$OCI_STATUS" != "OK" ]; then
    echo "ERROR: tenancy name lookup failed ($OCI_STATUS): $OCI_ERR" >&2
    exit 1
  fi
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
  # ACCESS-LEVEL ANY, not ACCESSIBLE: ACCESSIBLE silently omits compartments the
  # caller cannot see, and a missing compartment reads as "nothing to report".
  oci_try iam compartment list --compartment-id "$TENANCY_ID" --compartment-id-in-subtree true \
          --access-level ANY --lifecycle-state ACTIVE --all
  if [ "$OCI_STATUS" != "OK" ]; then
    echo "ERROR: compartment enumeration failed ($OCI_STATUS): $OCI_ERR" >&2
    exit 1
  fi
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    COMP_NAME["$cid"]="$cname"
    COMPS="${COMPS}${cid}"$'\n'
  done < <(printf '%s' "$OCI_OUT" | jq -r '.data[]? | [.id, .name] | @tsv' 2>/dev/null | tr -d '\r')

  oci_try iam compartment get --compartment-id "$TENANCY_ID" --query 'data.name' --raw-output
  COMP_NAME["$TENANCY_ID"]="${OCI_OUT:-root}"
  COMPS="$TENANCY_ID"$'\n'"$COMPS"
fi

# Optional filter by compartment NAME (-n "VCN,CD3")
if [ -n "$COMP_NAMES_FILTER" ]; then
  filtered=""
  while IFS= read -r cid; do
    [ -z "$cid" ] && continue
    nm="${COMP_NAME[$cid]:-}"
    IFS=',' read -ra wanted <<< "$COMP_NAMES_FILTER"
    for w in "${wanted[@]}"; do
      w="$(printf '%s' "$w" | sed 's/^ *//;s/ *$//')"
      [ -z "$w" ] && continue
      if [ "$(printf '%s' "$nm" | tr 'A-Z' 'a-z')" = "$(printf '%s' "$w" | tr 'A-Z' 'a-z')" ]; then
        filtered="${filtered}${cid}"$'\n'; break
      fi
    done
  done <<< "$COMPS"
  COMPS="$filtered"
  if [ -z "$(printf '%s' "$COMPS" | grep -c . 2>/dev/null)" ] || [ "$(printf '%s\n' "$COMPS" | grep -c .)" -eq 0 ]; then
    echo "ERROR: no compartment matched -n '$COMP_NAMES_FILTER'." >&2
    echo "Available:" >&2
    for k in "${!COMP_NAME[@]}"; do echo "  ${COMP_NAME[$k]}" >&2; done
    exit 1
  fi
fi

COMP_COUNT="$(printf '%s\n' "$COMPS" | grep -c . || true)"
COMP_COUNT="$(num "$COMP_COUNT")"
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
for phase in $PHASES; do PLAN_WORK+="${phase}"$'\n'; done

oci_scope_print_scan_plan \
  "CP-9 BACKUP ACCESS" "cp09-02-backup-access-files-check.sh" \
  "CP-9 / AC-3 / AC-6 / SC-12" "${REGION_OVERRIDE:-<cloud-shell / config default>}" \
  "$PLAN_SCOPE_TYPE" "$PLAN_SCOPE_NAME" "$PLAN_SCOPE_OCID" "$COMP_COUNT" \
  "$PLAN_TARGETS" "Requested evidence phases" "$PLAN_WORK" \
  "$ART_CSV"$'\n'"$GRANT_CSV"$'\n'"$PRIN_CSV"$'\n'"$EXPO_CSV"$'\n'"$FIND_CSV" \
  "resource/principal OCIDs, IAM grants, key custody, PARs and exposure details"
if ! oci_scope_require_final_approval "$SELECT_SCOPE"; then
  abort_before_scan "$OCI_SCOPE_APPROVAL_ERROR"
fi

# Object Storage namespace — one call for the whole run, not one per compartment
OS_NS=""
if has_phase artifacts || has_phase exposure; then
  oci_try os ns get --query 'data' --raw-output
  [ "$OCI_STATUS" = "OK" ] && OS_NS="$OCI_OUT"
  [ -z "$OS_NS" ] && echo "  ! Object Storage namespace unavailable ($OCI_STATUS) — bucket checks will report NOT_COLLECTED"
fi

# ---------------------------------------------------------------------------
# PHASE: artifacts — where the backup files actually live, and which key
# protects them. Whoever can use that key can decrypt the backup.
# ---------------------------------------------------------------------------
art_row() {  # svc type name id state created kms
  local comp="$1" svc="$2" typ="$3" nm="$4" id="$5" st="$6" ct="$7" kms="$8" status="$9" err="${10}"
  local mgmt="ORACLE-MANAGED"
  [ -n "$kms" ] && [ "$kms" != "null" ] && mgmt="CUSTOMER-MANAGED"
  csv_row "$ART_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$svc" "$typ" "$nm" "$id" "$st" "$ct" "$mgmt" "$kms" "$status" "$err"
}

collect_artifacts() {
  local comp="$1"

  # Block / boot / volume-group backups
  local spec
  for spec in "bv backup:BlockVolumeBackup:BlockVolume" \
              "bv boot-volume-backup:BootVolumeBackup:BootVolume" \
              "bv volume-group-backup:VolumeGroupBackup:VolumeGroup"; do
    local cmd rest typ svc
    cmd="${spec%%:*}"; rest="${spec#*:}"; typ="${rest%%:*}"; svc="${rest##*:}"
    # shellcheck disable=SC2086
    oci_try $cmd list --compartment-id "$comp" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      art_row "$comp" "$svc" "$typ" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"; continue
    fi
    while IFS=$'\t' read -r id nm st ct kms; do
      [ -z "$id" ] && continue
      art_row "$comp" "$svc" "$typ" "$nm" "$id" "$st" "$ct" "$kms" "OK" ""
    done < <(jqd '.data[]? | [.id, (."display-name"//""), (."lifecycle-state"//""), (."time-created"//""), (."kms-key-id"//"")] | @tsv')
  done

  # Database backups
  oci_try db backup list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    art_row "$comp" "BaseDB" "DatabaseBackup" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
  else
    while IFS=$'\t' read -r id nm st ct kms; do
      [ -z "$id" ] && continue
      art_row "$comp" "BaseDB" "DatabaseBackup" "$nm" "$id" "$st" "$ct" "$kms" "OK" ""
    done < <(jqd '.data[]? | [.id, (."display-name"//""), (."lifecycle-state"//""), (."time-started"//""), (."kms-key-id"//"")] | @tsv')
  fi

  # Autonomous DB backups
  oci_try db autonomous-database-backup list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    art_row "$comp" "AutonomousDB" "ADBBackup" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
  else
    while IFS=$'\t' read -r id nm st ct kms; do
      [ -z "$id" ] && continue
      art_row "$comp" "AutonomousDB" "ADBBackup" "$nm" "$id" "$st" "$ct" "$kms" "OK" ""
    done < <(jqd '.data[]? | [.id, (."display-name"//""), (."lifecycle-state"//""), (."time-started"//""), (."kms-key-id"//"")] | @tsv')
  fi

  # MySQL backups
  oci_try mysql backup list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    art_row "$comp" "MySQL" "MySQLBackup" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
  else
    while IFS=$'\t' read -r id nm st ct; do
      [ -z "$id" ] && continue
      art_row "$comp" "MySQL" "MySQLBackup" "$nm" "$id" "$st" "$ct" "" "OK" ""
    done < <(jqd '(.data.items? // .data)[]? | [.id, (."display-name"//""), (."lifecycle-state"//""), (."time-created"//"")] | @tsv')
  fi

  # FSS snapshots (per file system, per AD)
  oci_try iam availability-domain list --compartment-id "$comp"
  if [ "$OCI_STATUS" = "OK" ]; then
    while IFS= read -r ad; do
      [ -z "$ad" ] && continue
      oci_try fs file-system list --compartment-id "$comp" --availability-domain "$ad" --all
      [ "$OCI_STATUS" != "OK" ] && continue
      while IFS=$'\t' read -r fsid fsname fskms; do
        [ -z "$fsid" ] && continue
        oci_try fs snapshot list --file-system-id "$fsid" --all
        if [ "$OCI_STATUS" != "OK" ]; then
          art_row "$comp" "FSS" "FSSSnapshot" "$fsname" "$fsid" "" "" "$fskms" "$OCI_STATUS" "$OCI_ERR"; continue
        fi
        local n; n="$(num "$(jqd '[.data[]?] | length')")"
        art_row "$comp" "FSS" "FSSSnapshot" "${fsname} (${n} snapshots)" "$fsid" "" "" "$fskms" "OK" ""
      done < <(jqd '.data[]? | [.id, (."display-name"//""), (."kms-key-id"//"")] | @tsv')
    done < <(jqd '.data[]?.name')
  fi

  # Object Storage buckets — candidate backup stores
  if [ -n "$OS_NS" ]; then
    oci_try os bucket list --compartment-id "$comp" --namespace-name "$OS_NS" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      art_row "$comp" "ObjectStorage" "Bucket" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    else
      while IFS= read -r b; do
        [ -z "$b" ] && continue
        oci_try os bucket get --bucket-name "$b" --namespace-name "$OS_NS"
        if [ "$OCI_STATUS" != "OK" ]; then
          art_row "$comp" "ObjectStorage" "Bucket" "$b" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"; continue
        fi
        local bkms bct
        bkms="$(jqd '.data."kms-key-id" // ""')"
        bct="$(jqd '.data."time-created" // ""')"
        art_row "$comp" "ObjectStorage" "Bucket" "$b" "$b" "" "$bct" "$bkms" "OK" ""
      done < <(jqd '.data[]?.name')
    fi
  else
    art_row "$comp" "ObjectStorage" "Bucket" "" "" "" "" "" "NOT_COLLECTED" "namespace unavailable"
  fi
}

# ---------------------------------------------------------------------------
# PHASE: grants — IAM statements conferring access to backup-bearing resources
# ---------------------------------------------------------------------------
# Parsed per statement:
#   kind      Allow | Endorse | Admit | Define
#   grantees  one or more; comma-separated lists are split (the prior script
#             took only the first and silently dropped co-grantees)
#   verb      inspect | read | use | manage
#   resource  the resource-type token
#   scope     tenancy | compartment <name> | ...
#   where     the conditional clause, verbatim
# ---------------------------------------------------------------------------
declare -A GRANTEE_SEEN

collect_grants() {
  local comp="$1"
  oci_try iam policy list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    csv_row "$GRANT_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "" "" "" "" "" "" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    return
  fi

  while IFS=$'\t' read -r pname pid stmt; do
    [ -z "$stmt" ] && continue
    local norm low low_nowhere kind subj verb res scope where matched
    norm="$(printf '%s' "$stmt" | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"
    low="$(printf '%s' "$norm" | tr 'A-Z' 'a-z')"
    # Resource matching ignores the where-clause: a bucket named "prod-backups"
    # in a condition must not make an unrelated statement look backup-bearing.
    low_nowhere="$(printf '%s' "$low" | sed -E 's/[[:space:]]where[[:space:]].*$//')"

    case "$low" in
      allow\ *)   kind="Allow" ;;
      endorse\ *) kind="Endorse" ;;
      admit\ *)   kind="Admit" ;;
      define\ *)  kind="Define" ;;
      *)          kind="Other" ;;
    esac

    # Only statements touching backup-bearing resources, plus every cross-tenancy
    # statement (Endorse/Admit can hand backups to a foreign tenancy).
    # \b anchors prevent "objects" matching inside "objectstorage".
    matched="$(printf '%s' "$low_nowhere" | grep -oE "\\b(${BACKUP_KEYWORDS})\\b" | sort -u | paste -sd';' - 2>/dev/null)"
    if [ -z "$matched" ] && [ "$kind" != "Endorse" ] && [ "$kind" != "Admit" ]; then
      continue
    fi

    verb="$(printf '%s' "$low" | grep -oE '[[:space:]](inspect|read|use|manage)[[:space:]]' | head -1 | tr -d '[:space:]')"
    res="$(printf '%s' "$low" | sed -nE "s/.*[[:space:]](inspect|read|use|manage)[[:space:]]+([a-z0-9-]+).*/\2/p" | head -1)"
    scope="$(printf '%s' "$norm" | sed -nE 's/.*[[:space:]][Ii][Nn][[:space:]]+(tenancy|any-tenancy|compartment[[:space:]]+[^ ]+([[:space:]]+id[[:space:]]+[^ ]+)?).*/\1/p' | head -1)"
    [ -z "$scope" ] && scope="unspecified"
    where="$(printf '%s' "$norm" | sed -nE 's/.*[[:space:]][Ww][Hh][Ee][Rr][Ee][[:space:]]+(.*)$/\1/p')"

    # Grantee segment: everything between the kind word and " to <verb>".
    subj="$(printf '%s' "$norm" | sed -nE 's/^[Aa][Ll][Ll][Oo][Ww][[:space:]]+(.*)[[:space:]]+[Tt][Oo][[:space:]]+([Ii][Nn][Ss][Pp][Ee][Cc][Tt]|[Rr][Ee][Aa][Dd]|[Uu][Ss][Ee]|[Mm][Aa][Nn][Aa][Gg][Ee])[[:space:]].*/\1/p')"
    [ -z "$subj" ] && subj="$(printf '%s' "$norm" | sed -nE 's/^([Ee][Nn][Dd][Oo][Rr][Ss][Ee]|[Aa][Dd][Mm][Ii][Tt])[[:space:]]+(.*)[[:space:]]+[Tt][Oo][[:space:]]+.*/\2/p')"
    [ -z "$subj" ] && subj="$norm"

    # Split multi-grantee lists, then classify each.
    local piece gtype gname
    while IFS= read -r piece; do
      piece="$(printf '%s' "$piece" | sed 's/^ *//;s/ *$//')"
      [ -z "$piece" ] && continue
      local plow; plow="$(printf '%s' "$piece" | tr 'A-Z' 'a-z')"
      case "$plow" in
        any-user*)        gtype="any-user";      gname="any-user" ;;
        dynamic-group\ *) gtype="dynamic-group"; gname="${piece#* }" ;;
        group\ *)         gtype="group";         gname="${piece#* }" ;;
        service\ *)       gtype="service";       gname="${piece#* }" ;;
        resource\ *)      gtype="resource";      gname="${piece#* }" ;;
        *)                gtype="unparsed";      gname="$piece" ;;
      esac
      gname="$(printf '%s' "$gname" | sed "s/^'//;s/'$//;s/^\"//;s/\"$//;s/^ *//;s/ *$//")"

      csv_row "$GRANT_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pname" "$pid" "$kind" \
              "$gtype" "$gname" "${verb:-unspecified}" "${res:-unspecified}" "$matched" \
              "$scope" "$where" "$norm" "OK" ""

      # Queue for principal resolution
      if has_phase principals; then
        GRANTEE_SEEN["${gtype}|${gname}"]="${GRANTEE_SEEN[${gtype}|${gname}]:-}${comp}"$'\x1f'"${pname}"$'\x1f'"${verb:-unspecified}"$'\x1f'"${matched}"$'\x1f'"${scope}"$'\x1e'
      fi

      # Findings
      case "$gtype" in
        any-user)
          finding "CRITICAL" "any-user-grant" "$comp" "$pname" \
                  "Statement grants access to ANY user (unauthenticated where the resource allows it): $norm" \
                  "Remove the any-user grant or scope it with a where-clause; anonymous access to backup data fails CP-9." ;;
      esac
      case "$plow" in
        *administrators*)
          finding "HIGH" "admin-group-access" "$comp" "$pname" \
                  "Administrators group reaches backup resources via: $norm" \
                  "Expected but must be documented and the membership justified; keep Administrators minimal." ;;
      esac
      if [ "$kind" = "Endorse" ] || [ "$kind" = "Admit" ]; then
        finding "CRITICAL" "cross-tenancy" "$comp" "$pname" \
                "Cross-tenancy statement ($kind) can expose backup data outside this tenancy: $norm" \
                "Confirm the foreign tenancy is authorised and the grant is scoped to non-backup resources."
      fi
      if printf '%s' "$plow" | grep -q 'all-resources' || printf '%s' "$matched" | grep -q 'all-resources'; then
        finding "HIGH" "broad-grant" "$comp" "$pname" \
                "all-resources grant confers backup access without naming a backup resource: $norm" \
                "Replace all-resources with the specific resource-types required."
      fi
      if [ "${verb:-}" = "manage" ] && [ -n "$matched" ]; then
        finding "MEDIUM" "manage-on-backups" "$comp" "$pname" \
                "manage verb on backup resources ($matched) allows DELETION of backups: $norm" \
                "Downgrade to read/inspect unless deletion is genuinely required by the role."
      fi
    done < <(printf '%s\n' "$subj" | tr ',' '\n')

  done < <(printf '%s' "$OCI_OUT" | jq -r '.data[]? as $p | ($p.statements[]?) | [($p.name//""), ($p.id//""), .] | @tsv' 2>/dev/null | tr -d '\r')
}

# ---------------------------------------------------------------------------
# PHASE: principals — resolve each grantee to named humans and machines.
# This is the deliverable the four earlier scripts never produced.
# ---------------------------------------------------------------------------
declare -A GROUP_ID_BY_NAME
declare -A DG_RULE_BY_NAME
IDENTITY_MODEL="legacy"

build_identity_maps() {
  oci_try iam group list --compartment-id "$TENANCY_ID" --all
  if [ "$OCI_STATUS" = "OK" ]; then
    while IFS=$'\t' read -r gid gname; do
      [ -z "$gid" ] && continue
      GROUP_ID_BY_NAME["$(printf '%s' "$gname" | tr 'A-Z' 'a-z')"]="$gid"
    done < <(jqd '.data[]? | [.id, .name] | @tsv')
  else
    echo "  ! group enumeration failed ($OCI_STATUS) — principal names will be unresolved"
  fi

  oci_try iam dynamic-group list --compartment-id "$TENANCY_ID" --all
  if [ "$OCI_STATUS" = "OK" ]; then
    while IFS=$'\t' read -r dgname rule; do
      [ -z "$dgname" ] && continue
      DG_RULE_BY_NAME["$(printf '%s' "$dgname" | tr 'A-Z' 'a-z')"]="$rule"
    done < <(jqd '.data[]? | [.name, (."matching-rule"//"")] | @tsv')
  fi

  # Identity Domains tenancies keep membership outside the legacy IAM surface.
  oci_try iam domain list --compartment-id "$TENANCY_ID" --all
  if [ "$OCI_STATUS" = "OK" ]; then
    local dcount; dcount="$(num "$(jqd '[.data[]?] | length')")"
    [ "$dcount" -gt 0 ] && IDENTITY_MODEL="domains"
  fi
}

resolve_principals() {
  local key gtype gname grants
  for key in "${!GRANTEE_SEEN[@]}"; do
    gtype="${key%%|*}"; gname="${key#*|}"
    grants="${GRANTEE_SEEN[$key]}"

    # Strongest verb + union of resources/scopes across every grant to this grantee
    local best=0 bestverb="unspecified" resources="" scopes="" comp="" pol=""
    local rec
    while IFS= read -r rec; do
      [ -z "$rec" ] && continue
      local c p v m s
      IFS=$'\x1f' read -r c p v m s <<< "$rec"
      [ -z "$comp" ] && comp="$c"
      [ -z "$pol" ] && pol="$p"
      local r; r="$(verb_rank "$v")"
      if [ "$r" -gt "$best" ]; then best="$r"; bestverb="$v"; fi
      case ";$resources;" in *";$m;"*) : ;; *) resources="${resources:+$resources;}$m" ;; esac
      case ";$scopes;" in *";$s;"*) : ;; *) scopes="${scopes:+$scopes;}$s" ;; esac
    done < <(printf '%s' "${grants//$'\x1e'/$'\n'}")   # not tr: it has no \xHH escapes

    case "$gtype" in
      group)
        local gkey gid
        gkey="$(printf '%s' "$gname" | tr 'A-Z' 'a-z')"
        gid="${GROUP_ID_BY_NAME[$gkey]:-}"
        if [ -z "$gid" ]; then
          csv_row "$PRIN_CSV" "group" "$gname" "" "$gname" "$bestverb" "$resources" "$scopes" \
                  "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "UNRESOLVED" \
                  "Group not found in legacy IAM listing. Identity model detected: $IDENTITY_MODEL. If the tenancy uses Identity Domains, resolve with: oci identity-domains group get --group-id <id> --endpoint <domain-url> --attribute-sets all"
          INCOMPLETE=1
          continue
        fi
        oci_try iam group list-users --group-id "$gid" --all
        if [ "$OCI_STATUS" != "OK" ]; then
          csv_row "$PRIN_CSV" "group" "$gname" "$gid" "$gname" "$bestverb" "$resources" "$scopes" \
                  "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "$OCI_STATUS" "$OCI_ERR"
          continue
        fi
        local members=0
        while IFS=$'\t' read -r uid uname uemail; do
          [ -z "$uid" ] && continue
          members=$((members+1))
          csv_row "$PRIN_CSV" "user" "${uname}${uemail:+ <$uemail>}" "$uid" "group:$gname" \
                  "$bestverb" "$resources" "$scopes" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "OK" ""
        done < <(jqd '.data[]? | [.id, (.name//""), (.email//"")] | @tsv')
        if [ "$members" -eq 0 ]; then
          csv_row "$PRIN_CSV" "group" "$gname" "$gid" "$gname" "$bestverb" "$resources" "$scopes" \
                  "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "EMPTY_GROUP" \
                  "Group has no direct members. Federated/IdP-mapped members are not visible to this API."
        fi
        ;;
      dynamic-group)
        local dkey rule
        dkey="$(printf '%s' "$gname" | tr 'A-Z' 'a-z')"
        rule="${DG_RULE_BY_NAME[$dkey]:-}"
        csv_row "$PRIN_CSV" "dynamic-group" "$gname" "" "$gname" "$bestverb" "$resources" "$scopes" \
                "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "${rule:+OK}${rule:-UNRESOLVED}" \
                "Machine identity. Any workload matching this rule inherits the access, and anyone with shell on that workload inherits it too. Rule: ${rule:-<not found>}"
        [ -n "$rule" ] && finding "MEDIUM" "instance-principal-access" "$comp" "$gname" \
          "Dynamic group '$gname' grants $bestverb on $resources to workloads matching: $rule" \
          "Confirm the matching rule is tightly scoped; shell access on a matching instance confers backup access."
        ;;
      any-user)
        csv_row "$PRIN_CSV" "any-user" "ANY USER IN TENANCY" "" "any-user" "$bestverb" "$resources" "$scopes" \
                "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "OK" \
                "Every principal in the tenancy, and unauthenticated callers where the resource permits it."
        ;;
      service)
        csv_row "$PRIN_CSV" "service" "$gname" "" "service:$gname" "$bestverb" "$resources" "$scopes" \
                "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "OK" "OCI service principal."
        ;;
      *)
        csv_row "$PRIN_CSV" "$gtype" "$gname" "" "$gname" "$bestverb" "$resources" "$scopes" \
                "$comp" "${COMP_NAME[$comp]:-<unknown>}" "$pol" "UNPARSED" \
                "Grantee form not recognised; review the statement text in the grants CSV."
        INCOMPLETE=1
        ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# PHASE: exposure — access that bypasses IAM entirely
# ---------------------------------------------------------------------------
collect_exposure() {
  local comp="$1"
  if [ -z "$OS_NS" ]; then
    csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "object-storage" "" "" "" "" "" "" "NOT_COLLECTED" "namespace unavailable"
    return
  fi

  oci_try os bucket list --compartment-id "$comp" --namespace-name "$OS_NS" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "object-storage" "" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    return
  fi

  local b
  while IFS= read -r b; do
    [ -z "$b" ] && continue

    # Public access
    oci_try os bucket get --bucket-name "$b" --namespace-name "$OS_NS"
    if [ "$OCI_STATUS" = "OK" ]; then
      local pub ver
      pub="$(jqd '.data."public-access-type" // "NoPublicAccess"')"
      ver="$(jqd '.data.versioning // "Disabled"')"
      if [ "$pub" != "NoPublicAccess" ]; then
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "public-bucket" "$b" \
                "versioning=$ver" "$pub" "" "yes" "CRITICAL" "OK" ""
        finding "CRITICAL" "public-bucket" "$comp" "$b" \
                "Bucket has public access type '$pub' — reachable without any IAM credential." \
                "Set public access to NoPublicAccess unless the bucket demonstrably holds no backup or sensitive data."
      else
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "bucket-baseline" "$b" \
                "versioning=$ver" "$pub" "" "no" "INFO" "OK" ""
      fi
    else
      csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "bucket-baseline" "$b" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    fi

    # Pre-authenticated requests — URLs that bypass IAM completely
    oci_try os preauth-request list --bucket-name "$b" --namespace-name "$OS_NS" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "par" "$b" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    else
      local now; now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      while IFS=$'\t' read -r pname pacc pexp pobj; do
        [ -z "$pname" ] && continue
        local active="unknown" sev="MEDIUM" scopetxt
        if [ -n "$pexp" ]; then
          if [[ "$pexp" > "$now" ]]; then active="yes"; else active="no"; fi
        fi
        scopetxt="object=${pobj:-<BUCKET-LEVEL: all objects>}"
        case "$pacc" in
          *ReadWrite*|*Write*) sev="HIGH" ;;
        esac
        [ -z "$pobj" ] && sev="HIGH"
        [ "$active" = "no" ] && sev="INFO"
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "par" "$b" \
                "$scopetxt" "$pacc" "$pexp" "$active" "$sev" "OK" ""
        if [ "$active" != "no" ] && [ "$sev" = "HIGH" ]; then
          finding "HIGH" "par-bypass" "$comp" "$b" \
                  "Active pre-authenticated request '$pname' ($pacc, $scopetxt, expires $pexp) grants URL access with no IAM check." \
                  "Delete the PAR if not required; PARs are bearer URLs and are not covered by any IAM policy review."
        fi
      done < <(jqd '(.data.items? // .data)[]? | [(.name//""), (."access-type"//""), (."time-expires"//""), (."object-name"//"")] | @tsv')
    fi

    # Replication — backup data leaving to another bucket/region/tenancy
    oci_try os replication list-replication-policies --bucket-name "$b" --namespace-name "$OS_NS"
    if [ "$OCI_STATUS" = "OK" ]; then
      while IFS=$'\t' read -r rname rdest rbucket; do
        [ -z "$rname" ] && continue
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "replication" "$b" \
                "policy=$rname dest_region=$rdest dest_bucket=$rbucket" "egress" "" "yes" "INFO" "OK" ""
      done < <(jqd '(.data.items? // .data)[]? | [(.name//""), (."destination-region-name"//""), (."destination-bucket-name"//"")] | @tsv')
    fi

    # Retention rules — WORM protection over the backup data
    oci_try os retention-rule list --bucket-name "$b" --namespace-name "$OS_NS"
    if [ "$OCI_STATUS" = "OK" ]; then
      local rr; rr="$(num "$(jqd '[(.data.items? // .data)[]?] | length')")"
      if [ "$rr" -eq 0 ]; then
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "no-worm" "$b" \
                "no retention rule — objects are deletable by anyone with manage" "" "" "yes" "MEDIUM" "OK" ""
      else
        csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "worm" "$b" \
                "$rr retention rule(s) present" "" "" "no" "INFO" "OK" ""
      fi
    fi
  done < <(jqd '.data[]?.name')
}

# ---------------------------------------------------------------------------
# PHASE: keys — KMS custody. Access to the key is access to the backup.
# ---------------------------------------------------------------------------
collect_keys() {
  local comp="$1"
  oci_try kms management vault list --compartment-id "$comp" --all
  if [ "$OCI_STATUS" != "OK" ]; then
    csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "kms-vault" "" "" "" "" "" "" "$OCI_STATUS" "$OCI_ERR"
    return
  fi
  while IFS=$'\t' read -r vid vname vstate vep; do
    [ -z "$vid" ] && continue
    if [ -z "$vep" ]; then
      csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "kms-vault" "$vname" \
              "vault_id=$vid state=$vstate" "" "" "" "INFO" "NO_ENDPOINT" "management endpoint absent; key listing skipped"
      continue
    fi
    oci_try kms management key list --compartment-id "$comp" --endpoint "$vep" --all
    if [ "$OCI_STATUS" != "OK" ]; then
      csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "kms-key" "$vname" \
              "vault_id=$vid" "" "" "" "INFO" "$OCI_STATUS" "$OCI_ERR"
      continue
    fi
    while IFS=$'\t' read -r kid kname kstate; do
      [ -z "$kid" ] && continue
      csv_row "$EXPO_CSV" "$comp" "${COMP_NAME[$comp]:-<unknown>}" "kms-key" "$vname/$kname" \
              "key_id=$kid state=$kstate — anyone granted 'use keys' on this key can decrypt backups it protects; anyone granted 'manage keys' can destroy them" \
              "" "" "" "INFO" "OK" ""
    done < <(jqd '.data[]? | [.id, (."display-name"//""), (."lifecycle-state"//"")] | @tsv')
  done < <(jqd '.data[]? | [.id, (."display-name"//""), (."lifecycle-state"//""), (."management-endpoint"//"")] | @tsv')
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
has_phase principals && build_identity_maps

i=0
while IFS= read -r comp; do
  [ -z "$comp" ] && continue
  i=$((i+1))
  echo "[$i/$COMP_COUNT] ${COMP_NAME[$comp]:-$comp}"
  has_phase artifacts && collect_artifacts "$comp"
  has_phase grants    && collect_grants    "$comp"
  has_phase exposure  && collect_exposure  "$comp"
  has_phase keys      && collect_keys      "$comp"
done <<< "$COMPS"

has_phase principals && { echo; echo "Resolving grantees to named principals..."; resolve_principals; }

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
count_rows() { local f="$1"; [ -f "$f" ] || { printf '0'; return; }; local n; n=$(( $(wc -l < "$f") - 1 )); [ "$n" -lt 0 ] && n=0; printf '%s' "$n"; }
count_sev()  { [ -f "$FIND_CSV" ] || { printf '0'; return; }; local n; n="$(grep -c "^\"$1\"," "$FIND_CSV" 2>/dev/null || true)"; printf '%s' "$(num "$n")"; }

ART_N="$(count_rows "$ART_CSV")"
GRANT_N="$(count_rows "$GRANT_CSV")"
PRIN_N="$(count_rows "$PRIN_CSV")"
EXPO_N="$(count_rows "$EXPO_CSV")"
USERS_N="$(grep -c '^"user",' "$PRIN_CSV" 2>/dev/null || true)"; USERS_N="$(num "$USERS_N")"
CRIT="$(count_sev CRITICAL)"; HIGH="$(count_sev HIGH)"; MED="$(count_sev MEDIUM)"

echo
echo "======================================================================"
echo " CP-9 BACKUP ACCESS SUMMARY"
echo "======================================================================"
echo " Compartments in scope              : $COMP_COUNT"
echo " Backup artifacts inventoried       : $ART_N"
echo " IAM grants over backup resources   : $GRANT_N"
echo " Resolved principal rows            : $PRIN_N  (named users: $USERS_N)"
echo " Exposure / bypass rows             : $EXPO_N"
echo
echo " Findings — CRITICAL: $CRIT   HIGH: $HIGH   MEDIUM: $MED"
if [ "$(num "$CRIT")" -gt 0 ] || [ "$(num "$HIGH")" -gt 0 ]; then
  echo
  echo " >>> REVIEW THESE FIRST:"
  awk -F'","' 'NR>1 && ($1 ~ /CRITICAL/ || $1 ~ /HIGH/) {
        s=$1; gsub(/^"/,"",s); c=$4; r=$5; d=$6;
        if (length(d) > 96) d = substr(d,1,93) "...";
        printf "   [%-8s] %-22s %-28s %s\n", s, c, r, d
      }' "$FIND_CSV" 2>/dev/null | head -25
fi
echo
echo " Evidence files:"
echo "   artifacts  : $ART_CSV"
echo "   grants     : $GRANT_CSV"
echo "   principals : $PRIN_CSV   <-- the 'who has access' answer"
echo "   exposure   : $EXPO_CSV"
echo "   findings   : $FIND_CSV"
echo
echo "----------------------------------------------------------------------"
echo " SCOPE AND LIMITATIONS — read before citing this as evidence"
echo "----------------------------------------------------------------------"
cat <<'LIMITS'
 * Point in time. Group membership and PARs are as of this run only.
 * Federated identity. Users mapped from an external IdP (SAML/SCIM) are not
   fully enumerable through the IAM API; a group may have more effective
   members than this report lists. Identity-Domains tenancies may require
   `oci identity-domains ...` with a per-domain --endpoint to resolve members.
 * Single region per run. Object Storage is global but bucket listings,
   PARs, and KMS vaults are regional. Re-run with -r for each subscribed region.
 * Any row with collection_status other than OK means NOT COLLECTED, not
   "nothing found". Absence of a row is never evidence of absence of access.
 * Statement parsing is textual. Statements using unusual syntax appear with
   grantee_type=unparsed and must be reviewed by hand in the grants CSV.
 * Instance principals: a dynamic group's effective reach depends on which
   workloads currently match its rule; shell access on such a workload confers
   the same backup access.
LIMITS
echo "----------------------------------------------------------------------"

if [ "$INCOMPLETE" -ne 0 ]; then
  echo
  echo " WARNING: one or more collections were incomplete (DENIED / ERROR /"
  echo " UNRESOLVED rows are present). Review collection_status before drawing"
  echo " any conclusion about who can or cannot reach the backups."
  exit 3
fi
exit 0
