#!/usr/bin/env python3
"""Post-process CM11-01 read-only OCI facts and authoritative input lists."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import hashlib
import os
import re
import sys
from collections import defaultdict
from datetime import date, datetime
from pathlib import Path


SOFTWARE_TYPES = {"OS_PACKAGE", "COMPUTE_BOOT_IMAGE", "CONTAINER_IMAGE"}
CAPABILITIES = {
    "OS_PACKAGE_INSTALL",
    "COMPUTE_SOFTWARE_PROVISION",
    "CONTAINER_IMAGE_PUBLISH",
}

AUTHORIZED_FIELDS = [
    "entry_id",
    "principal_type",
    "principal_name",
    "principal_ocid",
    "user_name",
    "user_ocid",
    "install_capability",
    "scope",
    "authorization_status",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "expiration_date",
    "manager",
    "technical_control",
    "request_process",
    "source_reference",
    "notes",
]

APPROVED_FIELDS = [
    "entry_id",
    "software_type",
    "name_pattern",
    "version_pattern",
    "architecture_pattern",
    "repository_or_publisher_pattern",
    "scope_pattern",
    "approval_status",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "expiration_date",
    "business_function",
    "justification",
    "source_reference",
    "notes",
]

RESTRICTED_FIELDS = [
    "entry_id",
    "software_type",
    "name_pattern",
    "version_pattern",
    "architecture_pattern",
    "repository_or_publisher_pattern",
    "scope_pattern",
    "category",
    "authority",
    "provided_by",
    "source_reference",
    "effective_date",
    "expiration_date",
    "restriction",
    "notes",
]

POLICY_PARSED_FIELDS = [
    "statement_key",
    "effect",
    "principal_type",
    "principal_name",
    "verb_or_permissions",
    "resource_expression",
    "scope_expression",
    "condition_expression",
    "candidate_capabilities",
    "analysis_status",
    "analysis_confidence",
    "analysis_note",
]

ENTITLEMENT_FIELDS = [
    "entitlement_key",
    "statement_key",
    "attachment_compartment_id",
    "attachment_compartment_name",
    "policy_id",
    "policy_name",
    "statement",
    "evidence_source",
    "principal_type",
    "principal_id",
    "principal_name",
    "user_id",
    "user_name",
    "user_lifecycle_state",
    "membership_status",
    "install_capability",
    "scope_expression",
    "condition_expression",
    "analysis_confidence",
    "authorization_status",
    "authorization_entry_id",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "expiration_date",
    "manager",
    "technical_control",
    "request_process",
    "source_reference",
    "review_result",
    "review_note",
]

RECONCILIATION_FIELDS = [
    "approval_status",
    "approval_entry_id",
    "approval_id",
    "approval_authority",
    "approved_by",
    "approval_date",
    "approval_expiration_date",
    "business_function",
    "justification",
    "approval_source_reference",
    "restriction_status",
    "restriction_entry_ids",
    "restriction_authorities",
    "restriction_sources",
    "restriction_text",
    "review_result",
    "review_note",
]

SOURCE_FIELDS = [
    "input_type",
    "path",
    "status",
    "row_count",
    "sha256",
    "authority",
    "provided_by",
    "source_reference",
    "dates",
    "generated_at_utc",
    "region",
    "note",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    for name in ("raw-software", "raw-policies", "raw-membership", "raw-controls"):
        parser.add_argument(f"--{name}", required=True)
    for name in (
        "software-out",
        "installer-template-out",
        "entitlement-out",
        "approved-template-out",
        "reconciliation-out",
        "restricted-out",
        "controls-out",
        "policies-out",
        "membership-out",
        "sources-out",
        "summary-out",
    ):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--authorized-input", default="")
    parser.add_argument("--approved-input", default="")
    parser.add_argument("--restricted-input", default="")
    parser.add_argument("--inventory-only", choices=("0", "1"), required=True)
    parser.add_argument("--timestamp", required=True)
    parser.add_argument("--region", required=True)
    return parser.parse_args()


def normalized(value: object) -> str:
    return str(value or "").strip()


def casefold(value: object) -> str:
    return normalized(value).casefold()


def clean(value: object) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    if text[:1] in ("=", "+", "-", "@"):
        text = "'" + text
    return text


def sha256_text(parts: list[str]) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: str) -> tuple[list[str], list[dict[str, str]]]:
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def atomic_write_rows(path: str, fields: list[str], rows: list[dict[str, object]]) -> None:
    target = Path(path)
    temp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    if target.exists():
        raise ValueError(f"refusing to overwrite existing output: {target}")
    try:
        with open(temp, "x", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=fields,
                extrasaction="ignore",
                quoting=csv.QUOTE_ALL,
                lineterminator="\n",
            )
            writer.writeheader()
            for row in rows:
                writer.writerow({field: clean(row.get(field, "")) for field in fields})
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def atomic_write_text(path: str, content: str) -> None:
    target = Path(path)
    temp = target.with_name(f".{target.name}.tmp.{os.getpid()}")
    if target.exists():
        raise ValueError(f"refusing to overwrite existing output: {target}")
    try:
        with open(temp, "x", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def parse_date(value: object, field: str, context: str) -> date | None:
    text = normalized(value)
    if not text:
        return None
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise ValueError(f"{context}: invalid {field} date {text!r}; use YYYY-MM-DD") from exc


def validate_date_range(row: dict[str, str], context: str, start_field: str, end_field: str) -> tuple[date | None, date | None]:
    today = datetime.utcnow().date()
    start = parse_date(row.get(start_field), start_field, context)
    end = parse_date(row.get(end_field), end_field, context)
    if start and start > today:
        raise ValueError(f"{context}: {start_field} cannot be in the future")
    if start and end and end < start:
        raise ValueError(f"{context}: {end_field} precedes {start_field}")
    return start, end


def require_unique_ids(rows: list[dict[str, str]], kind: str) -> None:
    seen: set[str] = set()
    for index, row in enumerate(rows, start=2):
        entry_id = normalized(row.get("entry_id"))
        if not entry_id:
            raise ValueError(f"{kind} row {index}: entry_id is required")
        if entry_id in seen:
            raise ValueError(f"{kind} row {index}: duplicate entry_id {entry_id!r}")
        seen.add(entry_id)


def validate_authorized(rows: list[dict[str, str]]) -> None:
    require_unique_ids(rows, "authorized installer")
    today = datetime.utcnow().date()
    for index, row in enumerate(rows, start=2):
        context = f"authorized installer row {index}"
        status = normalized(row.get("authorization_status")).upper()
        if status not in {"AUTHORIZED", "DENIED", "PENDING-REVIEW", "EXPIRED"}:
            raise ValueError(f"{context}: unsupported authorization_status {status!r}")
        ptype = normalized(row.get("principal_type")).upper()
        if not ptype:
            raise ValueError(f"{context}: principal_type is required")
        if not normalized(row.get("principal_name")) and not normalized(row.get("principal_ocid")):
            raise ValueError(f"{context}: principal_name or principal_ocid is required")
        capability = normalized(row.get("install_capability")).upper()
        if capability not in CAPABILITIES | {"ANY"}:
            raise ValueError(f"{context}: unsupported install_capability {capability!r}")
        start, end = validate_date_range(row, context, "approval_date", "expiration_date")
        if status == "AUTHORIZED":
            required = (
                "approval_id",
                "approval_authority",
                "approved_by",
                "approval_date",
                "manager",
                "technical_control",
                "request_process",
                "source_reference",
            )
            missing = [field for field in required if not normalized(row.get(field))]
            if missing:
                raise ValueError(f"{context}: AUTHORIZED row missing {', '.join(missing)}")
            if end and end < today:
                raise ValueError(f"{context}: AUTHORIZED row expired on {end}")
            if not start:
                raise ValueError(f"{context}: AUTHORIZED row requires approval_date")


def validate_approved(rows: list[dict[str, str]]) -> None:
    require_unique_ids(rows, "approved software")
    today = datetime.utcnow().date()
    for index, row in enumerate(rows, start=2):
        context = f"approved software row {index}"
        stype = normalized(row.get("software_type")).upper()
        if stype not in SOFTWARE_TYPES | {"ANY"}:
            raise ValueError(f"{context}: unsupported software_type {stype!r}")
        if not normalized(row.get("name_pattern")):
            raise ValueError(f"{context}: name_pattern is required")
        status = normalized(row.get("approval_status")).upper()
        if status not in {"APPROVED", "DENIED", "PENDING-REVIEW", "EXPIRED"}:
            raise ValueError(f"{context}: unsupported approval_status {status!r}")
        start, end = validate_date_range(row, context, "approval_date", "expiration_date")
        if status == "APPROVED":
            required = (
                "approval_id",
                "approval_authority",
                "approved_by",
                "approval_date",
                "business_function",
                "justification",
                "source_reference",
            )
            missing = [field for field in required if not normalized(row.get(field))]
            if missing:
                raise ValueError(f"{context}: APPROVED row missing {', '.join(missing)}")
            if end and end < today:
                raise ValueError(f"{context}: APPROVED row expired on {end}")
            if not start:
                raise ValueError(f"{context}: APPROVED row requires approval_date")


def validate_restricted(rows: list[dict[str, str]]) -> None:
    require_unique_ids(rows, "restricted software")
    today = datetime.utcnow().date()
    for index, row in enumerate(rows, start=2):
        context = f"restricted software row {index}"
        stype = normalized(row.get("software_type")).upper()
        if stype not in SOFTWARE_TYPES | {"ANY"}:
            raise ValueError(f"{context}: unsupported software_type {stype!r}")
        if not normalized(row.get("name_pattern")):
            raise ValueError(f"{context}: name_pattern is required")
        category = normalized(row.get("category")).upper()
        if category not in {"RESTRICTED", "PROHIBITED"}:
            raise ValueError(f"{context}: category must be RESTRICTED or PROHIBITED")
        for field in ("authority", "provided_by", "source_reference", "restriction"):
            if not normalized(row.get(field)):
                raise ValueError(f"{context}: {field} is required")
        effective, expiration = validate_date_range(row, context, "effective_date", "expiration_date")
        if not effective:
            raise ValueError(f"{context}: effective_date is required")
        if expiration and expiration < today:
            raise ValueError(f"{context}: restricted entry expired on {expiration}")


def software_key(row: dict[str, str]) -> str:
    fields = (
        "compartment_id",
        "resource_type",
        "resource_id",
        "software_type",
        "software_name",
        "software_version",
        "architecture",
        "repository_or_publisher",
        "artifact_digest",
        "source_or_image_id",
    )
    return sha256_text([normalized(row.get(field)) for field in fields])


def split_policy(statement: str) -> dict[str, str]:
    result = {
        "effect": "",
        "principal_type": "",
        "principal_name": "",
        "verb_or_permissions": "",
        "resource_expression": "",
        "scope_expression": "",
        "condition_expression": "",
        "candidate_capabilities": "",
        "analysis_status": "UNPARSED",
        "analysis_confidence": "HEURISTIC",
        "analysis_note": "Policy language requires human effective-permission review",
    }
    text = " ".join(normalized(statement).split())
    if not text:
        result["analysis_note"] = "Empty policy statement"
        return result

    any_match = re.match(
        r"^(allow|deny|endorse|admit)\s+(any-user|any-group)\s+to\s+(.+?)\s+in\s+(.+?)(?:\s+where\s+(.+))?$",
        text,
        flags=re.IGNORECASE,
    )
    named_match = re.match(
        r"^(allow|deny|endorse|admit)\s+(group|dynamic-group|service)\s+(.+?)\s+to\s+(.+?)\s+in\s+(.+?)(?:\s+where\s+(.+))?$",
        text,
        flags=re.IGNORECASE,
    )
    if any_match:
        effect, ptype, action, scope, condition = any_match.groups()
        pname = ptype
    elif named_match:
        effect, ptype, pname, action, scope, condition = named_match.groups()
    else:
        effect_guess = text.split(maxsplit=1)[0] if text else "allow"
        capabilities = classify_capabilities(effect_guess, text)
        if capabilities:
            result.update(
                {
                    "effect": effect_guess.upper(),
                    "principal_type": "UNKNOWN",
                    "principal_name": "<unparsed-principal>",
                    "candidate_capabilities": ";".join(capabilities),
                    "analysis_status": "UNPARSED-POTENTIAL-INSTALL-STATEMENT",
                    "analysis_note": "Potential install capability was retained, but the principal/scope grammar requires manual IAM review",
                }
            )
        else:
            result["analysis_note"] = "Statement was preserved but did not match the supported Allow/Deny/Endorse/Admit grammar"
        return result

    action = normalized(action)
    first = action.split(maxsplit=1)
    verb = first[0] if first else ""
    resource = first[1] if len(first) > 1 else ""
    capabilities = classify_capabilities(effect, action)
    result.update(
        {
            "effect": effect.upper(),
            "principal_type": ptype.upper().replace("-", "_"),
            "principal_name": normalized(pname),
            "verb_or_permissions": verb,
            "resource_expression": resource,
            "scope_expression": normalized(scope),
            "condition_expression": normalized(condition),
            "candidate_capabilities": ";".join(capabilities),
            "analysis_status": "CANDIDATE-INSTALL-ENTITLEMENT" if capabilities else "PRESERVED-NON-INSTALL-STATEMENT",
        }
    )
    if result["effect"] == "DENY":
        result["candidate_capabilities"] = ""
        result["analysis_status"] = "DENY-STATEMENT-PRESERVED"
        result["analysis_note"] = "Deny may constrain other grants; this collector does not calculate effective permissions"
    elif capabilities:
        result["analysis_note"] = "Candidate capability only; evaluate statement combinations, conditions, inheritance and deny policies"
    return result


def classify_capabilities(effect: str, action: str) -> list[str]:
    if effect.casefold() == "deny":
        return []
    value = action.casefold()
    capabilities: set[str] = set()
    if re.search(r"\bmanage\s+all-resources\b", value):
        capabilities.update(CAPABILITIES)
    if re.search(r"\b(?:use|manage)\s+osmh-managed-instances?\b", value) or re.search(
        r"\b(?:use|manage)\s+osmh-managed-instance-groups?\b", value
    ):
        capabilities.add("OS_PACKAGE_INSTALL")
    if any(
        token in value
        for token in (
            "osmh_managed_instance_install_package",
            "osmh_managed_instance_install_update",
            "osmh_managed_instance_group_install_package",
            "osmh_managed_instance_group_install_update",
        )
    ):
        capabilities.add("OS_PACKAGE_INSTALL")
    if re.search(r"\bmanage\s+(?:instance-family|instances)\b", value) or "instance_create" in value:
        capabilities.add("COMPUTE_SOFTWARE_PROVISION")
    if re.search(r"\bmanage\s+repos\b", value) or "repository_update" in value:
        capabilities.add("CONTAINER_IMAGE_PUBLISH")
    return sorted(capabilities)


def principal_names(value: str) -> list[str]:
    names: list[str] = []
    for item in value.split(","):
        candidate = re.sub(r"^\s*(?:group|dynamic-group|service)\s+", "", item, flags=re.IGNORECASE).strip()
        if candidate:
            names.append(candidate)
    return names or [normalized(value)]


def wild(pattern: object, value: object) -> bool:
    actual_pattern = normalized(pattern) or "*"
    return fnmatch.fnmatchcase(casefold(value), actual_pattern.casefold())


def software_matches(pattern: dict[str, str], row: dict[str, str]) -> bool:
    stype = normalized(pattern.get("software_type")).upper() or "ANY"
    if stype not in {"ANY", normalized(row.get("software_type")).upper()}:
        return False
    scope = f"{row.get('compartment_name', '')}|{row.get('compartment_id', '')}|{row.get('resource_name', '')}|{row.get('resource_id', '')}"
    return all(
        (
            wild(pattern.get("name_pattern"), row.get("software_name")),
            wild(pattern.get("version_pattern"), row.get("software_version")),
            wild(pattern.get("architecture_pattern"), row.get("architecture")),
            wild(pattern.get("repository_or_publisher_pattern"), row.get("repository_or_publisher")),
            wild(pattern.get("scope_pattern"), scope),
        )
    )


def authorization_matches(baseline: dict[str, str], entitlement: dict[str, str]) -> bool:
    requested_type = normalized(baseline.get("principal_type")).upper().replace("-", "_")
    if requested_type not in {"ANY", normalized(entitlement.get("principal_type")).upper()}:
        return False
    requested_capability = normalized(baseline.get("install_capability")).upper()
    if requested_capability not in {"ANY", normalized(entitlement.get("install_capability")).upper()}:
        return False
    if normalized(baseline.get("principal_ocid")):
        if normalized(baseline.get("principal_ocid")) != normalized(entitlement.get("principal_id")):
            return False
    elif casefold(baseline.get("principal_name")) != casefold(entitlement.get("principal_name")):
        return False
    if normalized(baseline.get("user_ocid")):
        if normalized(baseline.get("user_ocid")) != normalized(entitlement.get("user_id")):
            return False
    elif normalized(baseline.get("user_name")):
        if casefold(baseline.get("user_name")) != casefold(entitlement.get("user_name")):
            return False
    scope = f"{entitlement.get('attachment_compartment_name', '')}|{entitlement.get('attachment_compartment_id', '')}|{entitlement.get('scope_expression', '')}"
    return wild(baseline.get("scope"), scope)


def entitlement_members(
    principal_type: str,
    principal_name: str,
    memberships: list[dict[str, str]],
) -> tuple[list[dict[str, str]], str]:
    ptype = principal_type.upper()
    if ptype == "GROUP":
        if "/" in principal_name:
            return [], "IDENTITY-DOMAIN-MEMBERSHIP-NOT-COLLECTED"
        matches = [
            row
            for row in memberships
            if row.get("principal_type") == "GROUP"
            and (
                casefold(row.get("principal_name")) == casefold(principal_name)
                or normalized(row.get("principal_id")) == normalized(principal_name.removeprefix("id "))
            )
        ]
        if not matches:
            return [], "GROUP-NOT-RESOLVED"
        failures = [row for row in matches if row.get("collection_status") not in {"OK", "DOCUMENTED"}]
        if failures:
            return failures, "GROUP-MEMBERSHIP-COLLECTION-INCOMPLETE"
        return matches, "GROUP-MEMBERSHIP-RESOLVED"
    if ptype == "DYNAMIC_GROUP":
        matches = [
            row
            for row in memberships
            if row.get("principal_type") == "DYNAMIC_GROUP"
            and (
                casefold(row.get("principal_name")) == casefold(principal_name)
                or normalized(row.get("principal_id")) == normalized(principal_name.removeprefix("id "))
            )
        ]
        return matches, "DYNAMIC-GROUP-RULE-RESOLVED" if matches else "DYNAMIC-GROUP-NOT-RESOLVED"
    return [], "NON-GROUP-PRINCIPAL"


def source_row(
    input_type: str,
    path: str,
    rows: list[dict[str, str]],
    inventory_only: bool,
    region: str,
    timestamp: str,
) -> dict[str, str]:
    if path:
        if input_type == "AUTHORIZED-INSTALLERS":
            authority_field, provider_field, date_fields = "approval_authority", "approved_by", ("approval_date", "expiration_date")
        elif input_type == "APPROVED-SOFTWARE":
            authority_field, provider_field, date_fields = "approval_authority", "approved_by", ("approval_date", "expiration_date")
        else:
            authority_field, provider_field, date_fields = "authority", "provided_by", ("effective_date", "expiration_date")
        values = lambda field: "; ".join(sorted({normalized(row.get(field)) for row in rows if normalized(row.get(field))}))
        date_values = "; ".join(sorted({normalized(row.get(field)) for row in rows for field in date_fields if normalized(row.get(field))}))
        return {
            "input_type": input_type,
            "path": os.path.abspath(path),
            "status": "PROVIDED",
            "row_count": str(len(rows)),
            "sha256": sha256_file(path),
            "authority": values(authority_field),
            "provided_by": values(provider_field),
            "source_reference": values("source_reference"),
            "dates": date_values,
            "generated_at_utc": timestamp,
            "region": region,
            "note": "Validate file custody and signatures in the approved evidence location",
        }
    return {
        "input_type": input_type,
        "path": "",
        "status": "SKIPPED-INVENTORY-ONLY" if inventory_only else "NOT-PROVIDED",
        "row_count": "0",
        "sha256": "",
        "authority": "",
        "provided_by": "",
        "source_reference": "",
        "dates": "",
        "generated_at_utc": timestamp,
        "region": region,
        "note": "Inventory-only cannot prove the control" if inventory_only else "Required authoritative input is missing",
    }


def main() -> int:
    args = parse_args()
    inventory_only = args.inventory_only == "1"
    today = datetime.utcnow().date()

    software_fields, software_rows = read_csv(args.raw_software)
    policy_fields, policy_rows = read_csv(args.raw_policies)
    membership_fields, membership_rows = read_csv(args.raw_membership)
    control_fields, control_rows = read_csv(args.raw_controls)

    _, authorized_rows = read_csv(args.authorized_input) if args.authorized_input else ([], [])
    _, approved_rows = read_csv(args.approved_input) if args.approved_input else ([], [])
    _, restricted_rows = read_csv(args.restricted_input) if args.restricted_input else ([], [])
    if args.authorized_input and not authorized_rows:
        raise ValueError("authorized installer list contains no entries")
    if args.approved_input and not approved_rows:
        raise ValueError("approved software list contains no entries")
    if args.restricted_input and not restricted_rows:
        raise ValueError("restricted software list contains no entries")
    validate_authorized(authorized_rows)
    validate_approved(approved_rows)
    validate_restricted(restricted_rows)

    for row in software_rows:
        row["software_key"] = software_key(row) if row.get("collection_status") == "OK" else ""

    parsed_policies: list[dict[str, str]] = []
    for row in policy_rows:
        parsed = split_policy(row.get("statement", ""))
        statement_key = sha256_text(
            [
                normalized(row.get("attachment_compartment_id")),
                normalized(row.get("policy_id")),
                normalized(row.get("statement_index")),
                normalized(row.get("statement")),
            ]
        )
        output = dict(row)
        output["statement_key"] = statement_key
        output.update(parsed)
        parsed_policies.append(output)

    entitlements: list[dict[str, str]] = []
    identity_gaps = 0
    for policy in parsed_policies:
        capabilities = [value for value in policy.get("candidate_capabilities", "").split(";") if value]
        if not capabilities:
            continue
        unparsed_install = policy.get("analysis_status") == "UNPARSED-POTENTIAL-INSTALL-STATEMENT"
        if unparsed_install:
            identity_gaps += 1
        for pname in principal_names(policy.get("principal_name", "")):
            members, member_status = entitlement_members(policy.get("principal_type", ""), pname, membership_rows)
            if unparsed_install:
                member_status = "POLICY-PRINCIPAL-OR-SCOPE-UNPARSED"
            if member_status in {
                "IDENTITY-DOMAIN-MEMBERSHIP-NOT-COLLECTED",
                "GROUP-NOT-RESOLVED",
                "GROUP-MEMBERSHIP-COLLECTION-INCOMPLETE",
                "DYNAMIC-GROUP-NOT-RESOLVED",
            }:
                identity_gaps += 1
            if not members:
                members = [
                    {
                        "principal_id": "",
                        "user_id": "",
                        "user_name": "",
                        "user_lifecycle_state": "",
                        "membership_detail": "",
                    }
                ]
            for member in members:
                for capability in capabilities:
                    entitlement = {
                        "statement_key": policy["statement_key"],
                        "attachment_compartment_id": policy.get("attachment_compartment_id", ""),
                        "attachment_compartment_name": policy.get("attachment_compartment_name", ""),
                        "policy_id": policy.get("policy_id", ""),
                        "policy_name": policy.get("policy_name", ""),
                        "statement": policy.get("statement", ""),
                        "evidence_source": policy.get("evidence_source", ""),
                        "principal_type": policy.get("principal_type", ""),
                        "principal_id": member.get("principal_id", ""),
                        "principal_name": pname,
                        "user_id": member.get("user_id", ""),
                        "user_name": member.get("user_name", ""),
                        "user_lifecycle_state": member.get("user_lifecycle_state", ""),
                        "membership_status": member_status,
                        "install_capability": capability,
                        "scope_expression": policy.get("scope_expression", ""),
                        "condition_expression": policy.get("condition_expression", ""),
                        "analysis_confidence": "CANDIDATE-NOT-EFFECTIVE-PERMISSION",
                    }
                    entitlement["entitlement_key"] = sha256_text(
                        [
                            entitlement["statement_key"],
                            pname,
                            entitlement["user_id"],
                            capability,
                        ]
                    )
                    matches = [row for row in authorized_rows if authorization_matches(row, entitlement)]
                    if inventory_only:
                        status, baseline, result, note = (
                            "SKIPPED-INVENTORY-ONLY",
                            {},
                            "NOT-EVALUATED",
                            "Complete and approve the generated authorized-installer template",
                        )
                    elif not args.authorized_input:
                        status, baseline, result, note = (
                            "NOT-PROVIDED",
                            {},
                            "UNAUTHORIZED-OR-UNEVALUATED",
                            "No authoritative installer list was supplied",
                        )
                    elif not matches:
                        status, baseline, result, note = (
                            "NO-AUTHORIZATION-MATCH",
                            {},
                            "UNAUTHORIZED-ENTITLEMENT",
                            "Candidate technical capability has no authorization-list match",
                        )
                    elif len(matches) > 1:
                        status, baseline, result, note = (
                            "AMBIGUOUS-AUTHORIZATION",
                            {},
                            "AUTHORIZATION-REVIEW-REQUIRED",
                            "Multiple installer authorization entries match this entitlement",
                        )
                    else:
                        baseline = matches[0]
                        status = normalized(baseline.get("authorization_status")).upper()
                        expiration = parse_date(baseline.get("expiration_date"), "expiration_date", "authorization")
                        if status == "AUTHORIZED" and expiration and expiration < today:
                            status = "EXPIRED"
                        if status == "AUTHORIZED":
                            result, note = "AUTHORIZED-CANDIDATE-ENTITLEMENT", "Authorization matched; effective-permission review remains required"
                        else:
                            result, note = "UNAUTHORIZED-ENTITLEMENT", f"Authorization baseline status is {status}"
                    entitlement.update(
                        {
                            "authorization_status": status,
                            "authorization_entry_id": baseline.get("entry_id", ""),
                            "review_result": result,
                            "review_note": note,
                        }
                    )
                    for field in (
                        "approval_id",
                        "approval_authority",
                        "approved_by",
                        "approval_date",
                        "expiration_date",
                        "manager",
                        "technical_control",
                        "request_process",
                        "source_reference",
                    ):
                        entitlement[field] = baseline.get(field, "")
                    entitlements.append(entitlement)

    installer_template: list[dict[str, str]] = []
    seen_installer_templates: set[tuple[str, ...]] = set()
    for entitlement in entitlements:
        identity = (
            entitlement.get("principal_type", ""),
            entitlement.get("principal_name", ""),
            entitlement.get("principal_id", ""),
            entitlement.get("user_name", ""),
            entitlement.get("user_id", ""),
            entitlement.get("install_capability", ""),
            entitlement.get("scope_expression", ""),
        )
        if identity in seen_installer_templates:
            continue
        seen_installer_templates.add(identity)
        installer_template.append(
            {
                "entry_id": f"AUTH-{sha256_text(list(identity))[:16]}",
                "principal_type": identity[0],
                "principal_name": identity[1],
                "principal_ocid": identity[2],
                "user_name": identity[3],
                "user_ocid": identity[4],
                "install_capability": identity[5],
                "scope": f"*{identity[6]}*" if identity[6] else "*",
                "authorization_status": "PENDING-REVIEW",
                "notes": "Candidate policy entitlement; verify effective access and organizational need",
            }
        )

    approved_template: list[dict[str, str]] = []
    seen_software_templates: set[tuple[str, ...]] = set()
    for row in software_rows:
        if row.get("collection_status") != "OK":
            continue
        identity = (
            row.get("software_type", ""),
            row.get("software_name", ""),
            row.get("software_version", "") or "*",
            row.get("architecture", "") or "*",
            row.get("repository_or_publisher", "") or "*",
            row.get("compartment_id", ""),
        )
        if identity in seen_software_templates:
            continue
        seen_software_templates.add(identity)
        approved_template.append(
            {
                "entry_id": f"SW-{sha256_text(list(identity))[:16]}",
                "software_type": identity[0],
                "name_pattern": identity[1],
                "version_pattern": identity[2],
                "architecture_pattern": identity[3],
                "repository_or_publisher_pattern": identity[4],
                "scope_pattern": f"*{identity[5]}*",
                "approval_status": "PENDING-REVIEW",
                "notes": "Generated from live OCI inventory; owner must validate and approve",
            }
        )

    reconciled: list[dict[str, str]] = []
    restricted_findings: list[dict[str, str]] = []
    for software in software_rows:
        output = dict(software)
        if software.get("collection_status") != "OK":
            output.update(
                {
                    "approval_status": "NOT-EVALUATED",
                    "restriction_status": "NOT-EVALUATED",
                    "review_result": "COLLECTION-INCOMPLETE",
                    "review_note": software.get("collection_error", "Collection failed"),
                }
            )
            reconciled.append(output)
            continue

        matches = [row for row in approved_rows if software_matches(row, software)]
        if inventory_only:
            approval_status, approval, approval_note = (
                "SKIPPED-INVENTORY-ONLY",
                {},
                "Complete and approve the generated software template",
            )
        elif not args.approved_input:
            approval_status, approval, approval_note = "NOT-PROVIDED", {}, "No approved software list was supplied"
        elif not matches:
            approval_status, approval, approval_note = "UNAPPROVED-DRIFT", {}, "No approved software entry matched"
        elif len(matches) > 1:
            approval_status, approval, approval_note = "AMBIGUOUS-APPROVAL", {}, "Multiple approved software entries matched"
        else:
            approval = matches[0]
            approval_status = normalized(approval.get("approval_status")).upper()
            expiration = parse_date(approval.get("expiration_date"), "expiration_date", "approval")
            if approval_status == "APPROVED" and expiration and expiration < today:
                approval_status = "EXPIRED"
            approval_note = "Exact/pattern baseline match" if approval_status == "APPROVED" else f"Baseline status is {approval_status}"

        restrictions = [row for row in restricted_rows if software_matches(row, software)]
        if inventory_only:
            restriction_status = "SKIPPED-INVENTORY-ONLY"
        elif not args.restricted_input:
            restriction_status = "NOT-PROVIDED"
        elif any(normalized(row.get("category")).upper() == "PROHIBITED" for row in restrictions):
            restriction_status = "PROHIBITED-MATCH"
        elif restrictions:
            restriction_status = "RESTRICTED-MATCH"
        else:
            restriction_status = "NO-LIST-MATCH"

        output.update(
            {
                "approval_status": approval_status,
                "approval_entry_id": approval.get("entry_id", ""),
                "approval_id": approval.get("approval_id", ""),
                "approval_authority": approval.get("approval_authority", ""),
                "approved_by": approval.get("approved_by", ""),
                "approval_date": approval.get("approval_date", ""),
                "approval_expiration_date": approval.get("expiration_date", ""),
                "business_function": approval.get("business_function", ""),
                "justification": approval.get("justification", ""),
                "approval_source_reference": approval.get("source_reference", ""),
                "restriction_status": restriction_status,
                "restriction_entry_ids": "; ".join(row.get("entry_id", "") for row in restrictions),
                "restriction_authorities": "; ".join(sorted({row.get("authority", "") for row in restrictions if row.get("authority")})),
                "restriction_sources": "; ".join(sorted({row.get("source_reference", "") for row in restrictions if row.get("source_reference")})),
                "restriction_text": "; ".join(row.get("restriction", "") for row in restrictions if row.get("restriction")),
            }
        )
        if restriction_status == "PROHIBITED-MATCH":
            output["review_result"] = "PROHIBITED-SOFTWARE"
            output["review_note"] = "Remove/block or document an approved exception immediately"
        elif restriction_status == "RESTRICTED-MATCH":
            output["review_result"] = "RESTRICTED-SOFTWARE-REVIEW"
            output["review_note"] = "Verify the restriction, approved exception and technical control"
        elif approval_status == "APPROVED":
            output["review_result"] = "APPROVED-SOFTWARE"
            output["review_note"] = approval_note
        elif inventory_only:
            output["review_result"] = "NOT-EVALUATED"
            output["review_note"] = approval_note
        else:
            output["review_result"] = "UNAPPROVED-SOFTWARE"
            output["review_note"] = approval_note
        reconciled.append(output)

        for restriction in restrictions:
            finding = dict(software)
            finding.update(restriction)
            finding["restriction_status"] = f"{normalized(restriction.get('category')).upper()}-MATCH"
            finding["severity"] = "CRITICAL" if normalized(restriction.get("category")).upper() == "PROHIBITED" else "HIGH"
            restricted_findings.append(finding)

    # Add an explicit Compute-to-OSMH coverage control. A mismatch is not proof
    # that the agent is absent; it is a verification gap requiring host evidence.
    compute_rows = [
        row
        for row in software_rows
        if row.get("software_type") == "COMPUTE_BOOT_IMAGE" and row.get("collection_status") == "OK"
    ]
    managed_ids = {
        row.get("resource_id", "")
        for row in control_rows
        if row.get("control_type") == "OSMH-MANAGED-INSTANCE" and row.get("collection_status") == "OK"
    }
    unmanaged_compute = 0
    for row in compute_rows:
        verified = row.get("resource_id", "") in managed_ids
        if not verified:
            unmanaged_compute += 1
        control_rows.append(
            {
                "compartment_id": row.get("compartment_id", ""),
                "compartment_name": row.get("compartment_name", ""),
                "control_type": "OSMH-INVENTORY-COVERAGE",
                "resource_id": row.get("resource_id", ""),
                "resource_name": row.get("resource_name", ""),
                "control_status": "VERIFIED" if verified else "NOT-VERIFIED",
                "scope": row.get("compartment_id", ""),
                "configuration": "Compute instance matched an OSMH managed-instance ID" if verified else "No exact OSMH managed-instance ID match",
                "evidence_interpretation": "OSMH package inventory coverage" if verified else "Obtain OS package inventory and installation-control evidence from the host/alternate management platform",
                "collection_status": "OK",
                "collection_error": "",
            }
        )

    source_rows = [
        source_row("AUTHORIZED-INSTALLERS", args.authorized_input, authorized_rows, inventory_only, args.region, args.timestamp),
        source_row("APPROVED-SOFTWARE", args.approved_input, approved_rows, inventory_only, args.region, args.timestamp),
        source_row("RESTRICTED-SOFTWARE", args.restricted_input, restricted_rows, inventory_only, args.region, args.timestamp),
    ]

    software_output_fields = ["software_key"] + software_fields
    policy_output_fields = policy_fields + POLICY_PARSED_FIELDS
    reconciliation_output_fields = software_output_fields + RECONCILIATION_FIELDS
    restriction_output_fields = software_output_fields + RESTRICTED_FIELDS + ["restriction_status", "severity"]

    atomic_write_rows(args.software_out, software_output_fields, software_rows)
    atomic_write_rows(args.installer_template_out, AUTHORIZED_FIELDS, installer_template)
    atomic_write_rows(args.entitlement_out, ENTITLEMENT_FIELDS, entitlements)
    atomic_write_rows(args.approved_template_out, APPROVED_FIELDS, approved_template)
    atomic_write_rows(args.reconciliation_out, reconciliation_output_fields, reconciled)
    atomic_write_rows(args.restricted_out, restriction_output_fields, restricted_findings)
    atomic_write_rows(args.controls_out, control_fields, control_rows)
    atomic_write_rows(args.policies_out, policy_output_fields, parsed_policies)
    atomic_write_rows(args.membership_out, membership_fields, membership_rows)
    atomic_write_rows(args.sources_out, SOURCE_FIELDS, source_rows)

    live = [row for row in reconciled if row.get("collection_status") == "OK"]
    summary = {
        "software_records": len(live),
        "approved": sum(row.get("approval_status") == "APPROVED" for row in live),
        "unapproved": sum(row.get("approval_status") != "APPROVED" for row in live),
        "restricted": sum(row.get("restriction_status") == "RESTRICTED-MATCH" for row in live),
        "prohibited": sum(row.get("restriction_status") == "PROHIBITED-MATCH" for row in live),
        "candidate_entitlements": len(entitlements),
        "authorized_entitlements": sum(row.get("authorization_status") == "AUTHORIZED" for row in entitlements),
        "unauthorized_entitlements": sum(row.get("authorization_status") != "AUTHORIZED" for row in entitlements),
        "identity_gaps": identity_gaps,
        "unmanaged_compute": unmanaged_compute,
        "authorized_input": "PROVIDED" if args.authorized_input else ("SKIPPED" if inventory_only else "NOT-PROVIDED"),
        "approved_input": "PROVIDED" if args.approved_input else ("SKIPPED" if inventory_only else "NOT-PROVIDED"),
        "restricted_input": "PROVIDED" if args.restricted_input else ("SKIPPED" if inventory_only else "NOT-PROVIDED"),
    }
    atomic_write_text(args.summary_out, "".join(f"{key}={value}\n" for key, value in summary.items()))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, csv.Error) as exc:
        print(f"CM11-01 post-processing failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
