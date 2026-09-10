#!/usr/bin/env python3
#
# lib/oci_audit_inventory.py
#
# Shared resource enumeration for the CM-2 and CM-8 collectors.
#
# PYTHON FILES USED:
#   lib/oci_audit_sdk.py   sdk_list_items / sdk_get and the runtime allowlist
#
# CM-8 asks what exists and CM-2 asks whether what exists matches an approved
# baseline. Both start from the same enumeration, so it lives here once.
#
# Two things this module exists to get right:
#
# 1. Resource Search is an INDEX, not the services themselves. search_resources
#    issues POST -- the query travels in the body -- which is a genuine read,
#    but the index is eventually consistent and covers only the resource types
#    the service knows about. A newly created resource can be missing from it.
#    An inventory built on it is therefore evidence of what the index reported
#    at a point in time, and must say so. list_resource_types is read alongside
#    it so the coverage ledger can state how many types were actually queryable
#    rather than implying the inventory is exhaustive.
#
# 2. Instance metadata must never be dumped. Instance.metadata and
#    extended_metadata routinely carry ssh_authorized_keys and user_data, and
#    user_data is a base64 cloud-init script that commonly contains bootstrap
#    credentials. Read-only does not make it safe to write into evidence. Only
#    the KEY NAMES ever leave this module; metadata_key_summary is the only
#    supported way to report metadata, and it never returns a value.

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set

from oci_audit_sdk import ScopeItem, sdk_list_items, response_items

# Methods this module calls. A collector must union these into its own
# allowlist; the runtime check refuses anything absent from it.
INVENTORY_READ_METHODS: Set[str] = {
    "list_resource_types",
}

# search_resources is named separately because it is the one call in this
# module that is not list_*/get_*. It is a POST-shaped read: the SDK sends the
# query in the request body. tests/test-readonly-proof.sh permits a search_
# prefix and then screens the name for sensitivity, which this passes.
SEARCH_METHOD = "search_resources"

# Metadata keys whose VALUES are credential material. The key name is evidence
# ("this instance was provisioned with cloud-init"); the value never is.
SECRET_METADATA_KEYS = {
    "user_data", "ssh_authorized_keys", "authorized_keys", "password",
    "oke-tenancy-id", "oke-token",
}


def metadata_key_summary(*sources: Any) -> str:
    """Report which metadata keys are set, never what they contain.

    Instance.metadata carries ssh_authorized_keys and user_data; user_data is a
    cloud-init payload that routinely embeds bootstrap credentials. Returning
    key names lets an assessor see that an instance is cloud-init provisioned
    and compare that against a baseline, without putting a secret into a CSV.
    """
    keys: List[str] = []
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        for key in source:
            name = str(key)
            keys.append(f"{name}(redacted)" if name in SECRET_METADATA_KEYS else name)
    return ";".join(sorted(set(keys))) or "none"


def searchable_types(oci: Any, client: Any, allowed: Set[str]) -> List[str]:
    """Every resource type the search index can return, for coverage honesty."""
    items = sdk_list_items(oci, client, "list_resource_types", allowed)
    return sorted(str(getattr(item, "name", "")) for item in items
                  if getattr(item, "name", None))


def search_compartment(oci: Any, client: Any, allowed: Set[str],
                       compartment_id: str, *,
                       resource_types: Sequence[str] | None = None) -> List[Any]:
    """Enumerate a compartment through the search index.

    The runtime allowlist is enforced here exactly as sdk_list_items does it,
    because search_resources is not a list_*/get_* name and would otherwise
    bypass the check that every other cloud call in this repository passes.
    """
    if SEARCH_METHOD not in allowed:
        raise RuntimeError(
            "blocked SDK method outside the read-only allowlist: " + SEARCH_METHOD)

    # The structured query language names the types up front; there is no
    # resourceType predicate to filter on afterwards.
    subject = ",".join(resource_types) if resource_types else "all"
    clause = f"query {subject} resources where compartmentId = '{compartment_id}'"

    details = oci.resource_search.models.StructuredSearchDetails(
        query=clause, type="Structured",
        matching_context_type="NONE")

    method = getattr(client, SEARCH_METHOD)
    response = oci.pagination.list_call_get_all_results(
        method, details, retry_strategy=oci.retry.DEFAULT_RETRY_STRATEGY)
    return response_items(response)


def resource_row(target: ScopeItem, item: Any) -> Dict[str, Any]:
    """Normalise a ResourceSummary into the fields both collectors share."""
    def text(name: str, default: str = "") -> str:
        value = getattr(item, name, None)
        return default if value is None else str(value)

    defined = getattr(item, "defined_tags", None) or {}
    freeform = getattr(item, "freeform_tags", None) or {}
    tag_names = []
    if isinstance(defined, Mapping):
        for namespace, entries in defined.items():
            if isinstance(entries, Mapping):
                tag_names.extend(f"{namespace}.{k}" for k in entries)
    if isinstance(freeform, Mapping):
        tag_names.extend(str(k) for k in freeform)

    return {
        "compartment_id": target.ocid,
        "compartment_name": target.name,
        "resource_type": text("resource_type", "UNKNOWN"),
        "resource_name": text("display_name", "unnamed"),
        "resource_ocid": text("identifier"),
        "lifecycle_state": text("lifecycle_state", "UNKNOWN"),
        "availability_domain": text("availability_domain", "regional"),
        "time_created": text("time_created", "not-exposed"),
        "tag_keys": ";".join(sorted(set(tag_names))) or "none",
    }
