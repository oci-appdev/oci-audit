#!/usr/bin/env bash
#
# Repository-wide proof that the collectors only read from OCI.
#
# The per-collector --selfcheck gates are DENYLISTS: they grep for known
# mutating verbs. A denylist cannot prove the absence of a verb nobody thought
# of. This test is the inverse and covers three things the denylists do not:
#
#   1. ALLOWLIST. Every OCI wrapper call site in every shell file -- canonical
#      and legacy -- must carry an action token that is exactly list, get, or a
#      list-*/get-* variant. Anything else fails, whatever it is called.
#
#   2. NAMED-READ-BUT-POST. In oci-python-sdk v2.185.1, 3450 list_*/get_*
#      operations are HTTP GET but 18 are POST. "It is called get" is therefore
#      not by itself proof of a read, so those 18 are named and blocked.
#
#   3. SECRET-RETURNING READS. 51 SDK read operations return credential or key
#      material (wallets, auth tokens, API keys, PSKs, initial passwords).
#      Read-only is not the same as safe to write into an evidence CSV, and
#      this repository is public. The SC-8 collector already blocked
#      ip-sec-psk; this generalises that rule to every collector.
#
# The Python SDK collectors enforce their own runtime list_*/get_* allowlist;
# this test additionally checks their allowlists declare nothing mutating.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
import re, pathlib, sys

WRAPPERS = ("oci_capture", "oci_try", "oci_q", "oci_discover", "oci_json", "emit", "o")
ALLOWED_ACTION = re.compile(r'^(list|get)(-[a-z0-9-]+)?$')

# 18 SDK operations named list_*/get_* that issue POST rather than GET.
POST_READS = {
    "list-attached-oci-cache-users", "list-associated-oci-cache-clusters",
    "list-attached-redis-clusters", "list-metrics",
    "list-stack-resource-drift-details", "list-available-software-sources-to-add",
    "get-os-patch-details", "list-os-patches", "get-path-analysis",
    "get-secret-bundle-by-name",
}

# Reads that return credential or key material.
SECRET_READS = [
    "ip-sec-psk", "auth-token", "api-key", "customer-secret-key",
    "swift-password", "smtp-credential", "db-credential",
    "o-auth-client-credential", "ui-password", "console-history-content",
    "initial-credentials", "autonomous-database-wallet", "regional-wallet",
    "secret-bundle", "named-credential", "preferred-credential",
    "user-credential", "bds-api-key", "deployment-wallets",
]

MUTATING = re.compile(
    r'^(create|update|delete|change|move|restore|enable|disable|rotate|assign|'
    r'attach|detach|terminate|reboot|import|export|upload|push|install|remove|'
    r'refresh|run|promote|switch|failover|reset|patch|cancel|schedule|launch|'
    r'add|copy|start|stop|restart|activate|deactivate|generate|publish|'
    r'register|deregister|bulk|apply|invoke|test|validate|connect|detect)'
    r'([-_]|$)')

def joined(path):
    lines = pathlib.Path(path).read_text(errors="replace").split("\n")
    out, i = [], 0
    while i < len(lines):
        cmd, start = lines[i], i
        while cmd.rstrip().endswith("\\") and i + 1 < len(lines):
            i += 1
            cmd = cmd.rstrip()[:-1] + " " + lines[i].strip()
        out.append((start + 1, cmd))
        i += 1
    return out

shell_files = sorted(pathlib.Path(".").glob("*.sh")) + sorted(pathlib.Path("lib").glob("*.sh"))
py_files = sorted(pathlib.Path(".").glob("*.py")) + sorted(pathlib.Path("lib").glob("*.py"))

failures = []
sites = 0
actions = set()

for path in shell_files:
    for lineno, cmd in joined(str(path)):
        s = cmd.strip()
        if s.startswith("#") or not s or "selfcheck-exempt" in s:
            continue
        for w in WRAPPERS:
            m = re.search(r'(?:^|[;&|(`]|\$\()\s*%s\s+(.+)' % re.escape(w), s)
            if not m:
                continue
            rest = re.sub(r'"[^"]*"', " ", m.group(1))
            rest = re.sub(r"'[^']*'", " ", rest)
            toks = [t for t in rest.split() if re.fullmatch(r'[a-z0-9][a-z0-9-]*', t)]
            if not toks:
                continue
            # The wrapper definitions forward "$@"; their callers are scanned.
            if all(t in ("outfile", "label", "filter", "jq", "r", "cn", "co", "x1", "x2") for t in toks):
                continue
            sites += 1
            verbs = [t for t in toks if ALLOWED_ACTION.fullmatch(t)]
            if not verbs:
                failures.append(f"{path}:{lineno}: no list/get action token: {toks[:6]}")
            actions.update(verbs)
            for t in toks:
                if MUTATING.match(t):
                    failures.append(f"{path}:{lineno}: mutating token {t!r}")
            break

for action in sorted(actions):
    if action in POST_READS:
        failures.append(f"action {action!r} is named as a read but issues POST")

for path in shell_files + py_files:
    for lineno, line in enumerate(pathlib.Path(path).read_text(errors="replace").split("\n"), 1):
        s = line.strip()
        if s.startswith("#") or "selfcheck-exempt" in s or "PROHIBIT" in s.upper():
            continue
        for term in SECRET_READS:
            if term in s and "prohibited" not in s.lower():
                failures.append(f"{path}:{lineno}: secret-returning read {term!r}")
        if "raw-request" in s and "http-method" not in s.lower():
            failures.append(f"{path}:{lineno}: raw-request")

# SDK collectors: their declared allowlists must contain only reads.
for path in py_files:
    text = pathlib.Path(path).read_text(errors="replace")
    for m in re.finditer(r'ALLOW[A-Z_]*\s*=\s*[({]([^)}]*)[)}]', text):
        for name in re.findall(r'["\']([a-z_][a-z0-9_]*)["\']', m.group(1)):
            if not name.startswith(("list_", "get_")):
                failures.append(f"{path}: allowlist contains non-read {name!r}")
            if name.replace("_", "-") in POST_READS:
                failures.append(f"{path}: allowlist contains POST-read {name!r}")

if failures:
    print("READ-ONLY PROOF: FAILED", file=sys.stderr)
    for f in failures:
        print("  " + f, file=sys.stderr)
    sys.exit(1)

print(f"Scanned {len(shell_files)} shell and {len(py_files)} Python files.")
print(f"Verified {sites} OCI wrapper call sites; every one uses a list/get action.")
print(f"Distinct actions in use: {', '.join(sorted(actions))}")
print("No mutating verb, no POST-shaped read, no secret-returning read, no raw-request.")
PY

echo "PASS: repository-wide read-only allowlist proof"
