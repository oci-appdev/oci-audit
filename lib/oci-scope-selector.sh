#!/usr/bin/env bash
#
# Shared interactive scope selector for OCI audit collectors.
#
# The caller performs read-only OCI discovery, then passes:
#   $1 tenancy OCID
#   $2 tenancy name
#   $3 active-compartment catalog as: OCID<TAB>name, one row per compartment
#
# On success the function sets:
#   OCI_SCOPE_SELECTED_OCID
#   OCI_SCOPE_SELECTED_NAME
#   OCI_SCOPE_SELECTED_KIND  (TENANCY or COMPARTMENT)
#
# This helper makes no OCI calls and performs no cloud or local writes.

OCI_SCOPE_SELECTOR_VERSION="1.1"
OCI_SCOPE_SELECTED_OCID=""
OCI_SCOPE_SELECTED_NAME=""
OCI_SCOPE_SELECTED_KIND=""
OCI_SCOPE_APPROVAL_ERROR=""

oci_scope_trim() {
  printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

oci_scope_print_catalog() {
  local tenancy_id="$1" tenancy_name="$2" catalog="$3"
  local cid cname count=0

  echo
  echo "======================================================================"
  echo " DISCOVERED OCI AUDIT SCOPES"
  echo "======================================================================"
  echo "TENANCY — selecting this scans root plus every active child compartment"
  echo "  Name : ${tenancy_name:-root}"
  echo "  OCID : $tenancy_id"

  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    count=$((count+1))
    echo
    echo "COMPARTMENT $count"
    echo "  Name : ${cname:-<unnamed>}"
    echo "  OCID : $cid"
  done <<< "$catalog"

  echo "======================================================================"
  echo "Active child compartments discovered: $count"
  echo
}

oci_scope_select_interactive() {
  local tenancy_id="$1" tenancy_name="$2" catalog="$3"
  local selected confirm cid cname

  OCI_SCOPE_SELECTED_OCID=""
  OCI_SCOPE_SELECTED_NAME=""
  OCI_SCOPE_SELECTED_KIND=""

  oci_scope_print_catalog "$tenancy_id" "$tenancy_name" "$catalog"

  echo "Enter the exact tenancy or compartment OCID to scan."
  IFS= read -r selected || {
    echo "ERROR: no scope OCID was provided." >&2
    return 2
  }
  selected="$(oci_scope_trim "$selected")"

  if [ "$selected" = "$tenancy_id" ]; then
    OCI_SCOPE_SELECTED_OCID="$tenancy_id"
    OCI_SCOPE_SELECTED_NAME="${tenancy_name:-root}"
    OCI_SCOPE_SELECTED_KIND="TENANCY"
  else
    while IFS=$'\t' read -r cid cname; do
      [ -z "$cid" ] && continue
      if [ "$selected" = "$cid" ]; then
        OCI_SCOPE_SELECTED_OCID="$cid"
        OCI_SCOPE_SELECTED_NAME="${cname:-<unnamed>}"
        OCI_SCOPE_SELECTED_KIND="COMPARTMENT"
        break
      fi
    done <<< "$catalog"
  fi

  if [ -z "$OCI_SCOPE_SELECTED_OCID" ]; then
    echo "ERROR: the entered OCID is not the discovered tenancy or an active discovered compartment." >&2
    return 2
  fi

  echo
  echo "Selected scope type : $OCI_SCOPE_SELECTED_KIND"
  echo "Selected scope name : $OCI_SCOPE_SELECTED_NAME"
  echo "Selected scope OCID : $OCI_SCOPE_SELECTED_OCID"
  if [ "$OCI_SCOPE_SELECTED_KIND" = "TENANCY" ]; then
    echo "WARNING: this selection scans the tenancy root and every active child compartment."
  fi
  echo
  echo "Re-enter the exact same OCID to confirm this scan scope."
  IFS= read -r confirm || {
    echo "ERROR: scope confirmation was not provided." >&2
    return 2
  }
  confirm="$(oci_scope_trim "$confirm")"

  if [ "$confirm" != "$OCI_SCOPE_SELECTED_OCID" ]; then
    echo "ERROR: scope confirmation did not match. Nothing was scanned." >&2
    OCI_SCOPE_SELECTED_OCID=""
    OCI_SCOPE_SELECTED_NAME=""
    OCI_SCOPE_SELECTED_KIND=""
    return 2
  fi

  echo
  echo "Confirmed scope: $OCI_SCOPE_SELECTED_KIND — $OCI_SCOPE_SELECTED_NAME"
  echo "Confirmed OCID : $OCI_SCOPE_SELECTED_OCID"
  echo
  return 0
}

# Print the resolved plan after IAM discovery/double-OCID confirmation and
# before the caller starts any workload-service collection. Multiline catalog,
# work-item and output arguments are printed one line at a time.
oci_scope_print_scan_plan() {
  local heading="$1" collector="$2" controls="$3" region="$4"
  local scope_type="$5" scope_name="$6" scope_ocid="$7" target_count="$8"
  local target_catalog="$9" work_label="${10}" work_items="${11}"
  local output_files="${12}" evidence_note="${13}"
  local cid cname item

  echo "======================================================================"
  echo " $heading PRE-SCAN SAFETY SUMMARY"
  echo "======================================================================"
  echo "Collector       : $collector"
  echo "Controls        : $controls"
  echo "Region          : $region"
  echo "Scope type      : $scope_type"
  echo "Scope name      : $scope_name"
  echo "Confirmed OCID  : $scope_ocid"
  echo "Compartments    : $target_count"
  echo "Cloud operations: OCI list/get only; no creates, updates or deletes"
  echo "Local writes    : CSV evidence files plus temporary stderr capture"
  echo "Evidence data   : $evidence_note"
  echo
  echo "Target compartments:"
  while IFS=$'\t' read -r cid cname; do
    [ -z "$cid" ] && continue
    echo "  - ${cname:-<unknown>}"
    echo "    $cid"
  done <<< "$target_catalog"
  echo
  echo "$work_label:"
  if [ -z "$work_items" ]; then
    echo "  - <none> (scope/approval test only)"
  else
    while IFS= read -r item; do
      [ -z "$item" ] && continue
      echo "  - $item"
    done <<< "$work_items"
  fi
  echo
  echo "Output files:"
  while IFS= read -r item; do
    [ -z "$item" ] && continue
    echo "  - $item"
  done <<< "$output_files"
  echo "======================================================================"
}

# Every prompted run requires exact uppercase YES.
#
# This used to accept 0 to mean "explicit -c/-n is an approved non-interactive
# path", which let a -c/-n run start collecting with no OCID confirmation and no
# approval value. That bypass is removed: automation now goes through
# oci_scope_validate_automation, and passing 0 here fails closed rather than
# silently approving a scan.
oci_scope_require_final_approval() {
  local interactive="$1" approval
  OCI_SCOPE_APPROVAL_ERROR=""

  if [ "$interactive" -ne 1 ]; then
    OCI_SCOPE_APPROVAL_ERROR="final approval was requested in a non-prompting mode; use oci_scope_validate_automation for automation"
    return 2
  fi

  if [ "$interactive" -eq 1 ]; then
    echo "Scope discovery is complete. No workload-service scan has started."
    echo "Type exact uppercase YES to run this scan. Any other response aborts."
    if ! IFS= read -r approval; then
      OCI_SCOPE_APPROVAL_ERROR="approval input was not provided"
      return 2
    fi
    if [ "$approval" != "YES" ]; then
      OCI_SCOPE_APPROVAL_ERROR="operator did not enter exact uppercase YES"
      return 2
    fi
    echo "SCAN APPROVED: starting read-only service collection."
    echo
  fi
  return 0
}

# Confirm every resolved target OCID twice for a manual -c/-n run.
#
# Supplying -c or -n selects a scope; it is not evidence that the scan was
# approved. A manual run using those flags must therefore confirm each resolved
# compartment OCID exactly, twice, before the plan is printed.
#
# Argument: the resolved target catalog as OCID<TAB>name, one row per target.
# On refusal or mismatch this sets OCI_SCOPE_APPROVAL_ERROR and returns 2; the
# caller aborts before any workload-service call so it can remove its own
# header-only outputs.
oci_scope_confirm_resolved_targets() {
  local catalog="$1" cid cname first second
  OCI_SCOPE_APPROVAL_ERROR=""

  echo
  echo "Resolved command-line scope requires interactive OCID confirmation."
  while IFS=$'\t' read -r cid cname <&3; do
    [ -n "$cid" ] || continue
    echo
    echo "Target: ${cname:-<unknown>}"
    echo "OCID  : $cid"
    echo "Enter this exact OCID to select the target."
    if ! IFS= read -r first; then
      OCI_SCOPE_APPROVAL_ERROR="scope OCID was not provided"
      return 2
    fi
    first="$(oci_scope_trim "$first")"
    if [ "$first" != "$cid" ]; then
      OCI_SCOPE_APPROVAL_ERROR="scope OCID did not match $cid"
      return 2
    fi
    echo "Re-enter the exact same OCID to confirm the target."
    if ! IFS= read -r second; then
      OCI_SCOPE_APPROVAL_ERROR="scope confirmation was not provided"
      return 2
    fi
    second="$(oci_scope_trim "$second")"
    if [ "$second" != "$cid" ]; then
      OCI_SCOPE_APPROVAL_ERROR="scope confirmation did not match $cid"
      return 2
    fi
  done 3<<< "$catalog"

  echo
  echo "All resolved target OCIDs were confirmed twice."
  return 0
}

# Validate an explicit --non-interactive automation run.
#
# Scheduled runs cannot prompt, so the approved job definition must carry one
# exact --confirm-scope-ocid for every resolved target and an exact
# --approve-scan YES. Both are validated only after the plan is printed, and
# both fail closed.
#
# Argument: the resolved target catalog as OCID<TAB>name.
# Reads the caller's CONFIRM_SCOPE_OCIDS array and APPROVE_SCAN variable.
oci_scope_validate_automation() {
  local catalog="$1" cid cname index=0 expected actual
  OCI_SCOPE_APPROVAL_ERROR=""

  expected="$(printf '%s\n' "$catalog" | grep -c . || true)"
  actual="${#CONFIRM_SCOPE_OCIDS[@]}"
  if [ "$actual" -ne "$expected" ]; then
    OCI_SCOPE_APPROVAL_ERROR="automation supplied $actual scope confirmations; expected $expected"
    return 2
  fi

  while IFS=$'\t' read -r cid cname; do
    [ -n "$cid" ] || continue
    if [ "${CONFIRM_SCOPE_OCIDS[$index]}" != "$cid" ]; then
      OCI_SCOPE_APPROVAL_ERROR="automation confirmation $((index+1)) did not match resolved OCID $cid"
      return 2
    fi
    index=$((index+1))
  done <<< "$catalog"

  if [ "$APPROVE_SCAN" != "YES" ]; then
    OCI_SCOPE_APPROVAL_ERROR="automation did not supply exact --approve-scan YES"
    return 2
  fi

  echo "AUTOMATION APPROVED: every resolved OCID matched and --approve-scan was exact YES."
  echo
  return 0
}
