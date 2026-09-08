#!/usr/bin/env python3
"""Verify the secret-read blocklist against the real SDK, in both directions.

SECRET_SDK_METHODS was hand-maintained, and a hand-maintained list drifts two
ways. It can be too broad -- blocking an operation whose response model has no
secret field to leak, which is how a legitimate AC-2 credential inventory got
denied the only API that enumerates a user's credentials. And it can be too
narrow -- missing an operation that does return one.

The rule this enforces is checkable rather than a judgement:

    an operation is blocked iff its response model DECLARES a field that can
    carry credential material.

Scoped to oci.identity.IdentityClient, which is where the AC-2/IA-2 collectors
live and where the 2026-09-08 narrowing was made. Needs the oci package; skips
loudly when it is absent, never silently.
"""
from __future__ import annotations

import inspect
import os
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if os.environ.get("OCI_SDK_PATH"):
    sys.path.insert(0, os.environ["OCI_SDK_PATH"])
try:
    import oci  # noqa: E402
except ImportError:
    print("SKIPPED: verify-secret-blocklist needs the oci package.", file=sys.stderr)
    print("         python3 -m pip install -r ra05-01/requirements-oci-sdk.txt",
          file=sys.stderr)
    print("         Set OCI_SDK_PATH to point at a vendored copy.", file=sys.stderr)
    sys.exit(0)

# A field name that can hold credential material. key_value is ApiKey's PEM;
# fingerprint, id and name are identifiers and deliberately not matched.
SECRET_FIELD = re.compile(r'^(.*_)?(secret|token|password|private_key|key_value)$', re.I)

gate = (REPO / "tests" / "test-readonly-proof.sh").read_text(encoding="utf-8")
block = re.search(r'SECRET_SDK_METHODS = \{(.*?)\n\}', gate, re.S)
if not block:
    print("FAIL: could not locate SECRET_SDK_METHODS in the read-only gate", file=sys.stderr)
    sys.exit(1)
body = "\n".join(l for l in block.group(1).splitlines() if not l.strip().startswith("#"))
blocked = set(re.findall(r'"([a-z_][a-z0-9_]*)"', body))


def response_model(client, method):
    try:
        src = inspect.getsource(getattr(client, method))
    except (OSError, TypeError, AttributeError):
        return None
    m = re.search(r'response_type="(?:list\[)?(\w+)', src)
    return m.group(1) if m else None


def declared_fields(model):
    snake = re.sub(r'(?<!^)(?=[A-Z])', '_', model).lower().replace('__', '_')
    for base in ("identity", "identity_domains"):
        path = pathlib.Path(oci.__file__).parent / base / "models" / f"{snake}.py"
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r'self\.attribute_map\s*=\s*\{(.*?)\n        \}', text, re.S)
            if m:
                return re.findall(r"'(\w+)':", m.group(1))
    return None


client = oci.identity.IdentityClient
operations = sorted(m for m in dir(client) if m.startswith("list_") and not m.startswith("_"))

too_broad, too_narrow, checked = [], [], 0
for method in operations:
    model = response_model(client, method)
    if not model:
        continue
    fields = declared_fields(model)
    if fields is None:
        continue
    checked += 1
    hot = [f for f in fields if SECRET_FIELD.match(f)]
    if method in blocked and not hot:
        too_broad.append(f"{method} -> {model} declares no secret field; "
                         f"blocking it denies a legitimate read")
    if method not in blocked and hot:
        too_narrow.append(f"{method} -> {model} declares {hot} but is NOT blocked")

problems = too_broad + too_narrow
if problems:
    print("SECRET BLOCKLIST: FAILED", file=sys.stderr)
    for p in too_narrow:
        print("  GAP        " + p, file=sys.stderr)
    for p in too_broad:
        print("  OVER-BROAD " + p, file=sys.stderr)
    print("\nAn operation is blocked iff its response model declares a field that can\n"
          "carry credential material. Fix the list, or -- if the operation is genuinely\n"
          "needed and its model does declare such a field -- add a field-level guard in\n"
          "the collector proving it never reads that attribute, as ca07-01 does for\n"
          "subscription endpoints.", file=sys.stderr)
    sys.exit(1)

MIN_CHECKED = 20
if checked < MIN_CHECKED:
    print(f"SECRET BLOCKLIST: FAILED — only {checked} IdentityClient list operations "
          f"were resolved, expected at least {MIN_CHECKED}. Fix discovery rather than "
          f"lowering this floor.", file=sys.stderr)
    sys.exit(1)

print(f"Checked {checked} IdentityClient list operations against their response models.")
print(f"The blocklist names {len(blocked)} operations; none is over-broad and none is "
      f"missing on this client.")
print("PASS: secret-read blocklist matches the SDK models")
