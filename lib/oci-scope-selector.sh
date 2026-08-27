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

OCI_SCOPE_SELECTOR_VERSION="1.0"
OCI_SCOPE_SELECTED_OCID=""
OCI_SCOPE_SELECTED_NAME=""
OCI_SCOPE_SELECTED_KIND=""

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

