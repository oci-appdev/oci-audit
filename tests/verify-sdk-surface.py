#!/usr/bin/env python3
"""Cross-check every SDK collector's cloud surface against the installed SDK.

PYTHON FILES USED:
  (none -- this reads the collectors as source and the installed oci package)

Run by tests/run.sh when the SDK is importable. It is the only gate that can
compare a collector's declared allowlist against what Oracle actually ships:
the per-collector --selfcheck proves a method NAME looks like a read, and
tests/test-readonly-proof.sh proves it is not on a blocklist, but neither can
tell that a method does not exist, or sits on a different client, or is
declared and never called.

That last case matters for evidence integrity rather than safety: the pre-scan
plan prints the allowlist to the approver as "Read-only SDK operations", so an
entry the collector never performs overstates what the operator is approving.

For each collector: extract the (namespace, class) pairs it constructs clients
from, extract every SDK method name it calls, and confirm each method exists on
at least one of those clients. Also confirm the declared allowlist and the
actually-called set agree in both directions -- a method in the allowlist that
is never called is dead surface, and a call not in the allowlist would be
refused at runtime.
"""
import ast, os, pathlib, sys

REPO = pathlib.Path(__file__).resolve().parents[1]
# Allow a vendored copy (as this environment uses) without requiring one.
for extra in filter(None, [os.environ.get("OCI_SDK_PATH")]):
    sys.path.insert(0, extra)
try:
    import oci
except ImportError:
    # Loud, not silent. A skipped check must never read as a passed one.
    print("SKIPPED: SDK surface verification — the oci package is not importable.",
          file=sys.stderr)
    print("         Install it with: python3 -m pip install -r "
          "ra05-01/requirements-oci-sdk.txt", file=sys.stderr)
    print("         This gate is the only one that can prove a declared SDK "
          "method actually exists.", file=sys.stderr)
    sys.exit(0)
# Discovered, never hand-listed. A fixed list means a collector added later is
# silently never surface-checked, and this gate is the only one that can prove a
# declared method exists -- so it would report PASS while covering nothing new.
# The signal for "this is an SDK collector" is that it declares the runtime
# allowlist; nothing else in the repository does.
def _discover():
    found = []
    for path in sorted(REPO.rglob("*.py")):
        parts = path.relative_to(REPO).parts
        if len(parts) < 2 or parts[0] in {"lib", "tests", "templates"}:
            continue
        if "tests" in parts or "__pycache__" in parts or ".git" in parts:
            continue
        if "SDK_READ_METHODS" in path.read_text(encoding="utf-8", errors="replace"):
            found.append("/".join(parts))
    return found


COLLECTORS = _discover()

# A gate that stops covering collectors still prints PASS. This floor is below
# the current count so ordinary additions do not trip it; if it fires, fix
# discovery rather than lowering it.
MIN_COLLECTORS = 10
if len(COLLECTORS) < MIN_COLLECTORS:
    print(f"FAIL: SDK surface verification discovered only {len(COLLECTORS)} collectors, "
          f"expected at least {MIN_COLLECTORS}. Coverage has collapsed; fix discovery "
          f"rather than lowering this floor.", file=sys.stderr)
    sys.exit(1)
# Methods provided by the shared library rather than named in the collector.
SHARED = {"get_compartment", "list_compartments"}
SHARED_CLIENTS = [("identity", "IdentityClient")]

# Names the shared library declares on the collector's behalf.
EXTERNAL_SETS = {
    "INVENTORY_READ_METHODS": {"list_resource_types"},
    "SEARCH_METHOD": {"search_resources"},
}
# Calls made inside lib/oci_audit_inventory.py for a collector that imports it.
EXTRA_CALLED = {
    "cm08-01/cm08-01-component-inventory.py": {"list_resource_types", "search_resources"},
}

problems = []
for rel in COLLECTORS:
    path = REPO / rel
    tree = ast.parse(path.read_text(encoding="utf-8"))

    # Declared allowlist. Some collectors build it as {...} | SHARED_SET, which
    # is a BinOp rather than a plain Set literal -- walk into both sides.
    def literals(node):
        out = set()
        if node is None:
            return out
        if isinstance(node, ast.BinOp):
            return literals(node.left) | literals(node.right)
        for elt in getattr(node, "elts", []) or []:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                out.add(elt.value)
            elif isinstance(elt, ast.Name):
                # A named constant used as a set member, e.g. SEARCH_METHOD.
                out |= EXTERNAL_SETS.get(elt.id, set())
        if isinstance(node, ast.Name):
            out |= EXTERNAL_SETS.get(node.id, set())
        return out

    declared = set()
    for node in ast.walk(tree):
        target_names = []
        if isinstance(node, ast.AnnAssign):
            target_names = [getattr(node.target, "id", "")]
        elif isinstance(node, ast.Assign):
            target_names = [getattr(t, "id", "") for t in node.targets]
        if "SDK_READ_METHODS" in target_names:
            declared |= literals(node.value)

    # Clients constructed: build_client(..., "ns", "Class") and self.client(k,"ns","Class")
    clients = set(SHARED_CLIENTS)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        consts = [a.value for a in node.args if isinstance(a, ast.Constant)
                  and isinstance(a.value, str)]
        if name == "build_client" and len(consts) >= 2:
            clients.add((consts[-2], consts[-1]))
        elif name == "client" and len(consts) >= 3:
            clients.add((consts[-2], consts[-1]))
        # Direct construction: self.oci.key_management.KmsManagementClient(...)
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr.endswith("Client"):
            owner = func.value
            if isinstance(owner, ast.Attribute):
                clients.add((owner.attr, func.attr))

    # Methods actually passed to sdk_list_items / sdk_get / sdk_list. Some are
    # supplied from a loop tuple -- ("list_volume_backups", "VolumeBackup") --
    # so a name bound by a for-loop over such tuples counts as called too.
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name in ("sdk_list_items", "sdk_get", "sdk_list"):
                # Signature is (oci, client, method_name, allowlist, *args): only
                # the third positional is the method. Taking every string
                # constant also swept up call arguments such as "_Audit".
                if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant) \
                        and isinstance(node.args[2].value, str):
                    called.add(node.args[2].value)
        if isinstance(node, ast.For):
            for elt in ast.walk(node.iter):
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str) \
                        and elt.value.startswith(("list_", "get_", "search_")):
                    called.add(elt.value)

    # Local wrappers. RA05-01 routes every read through
    # collection_list(oci, client, method, ...), which forwards `method` to
    # sdk_list -- so the literal lives at the wrapper's call site, not at
    # sdk_list's. Without resolving that, the gate sees called=0 and reports
    # every declared method as dead surface. Resolve the forwarding parameter
    # by position rather than counting every string constant, which would blunt
    # the dead-surface check for every other collector.
    wrappers = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        params = [a.arg for a in node.args.args]
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            fname = getattr(inner.func, "id", None) or getattr(inner.func, "attr", None)
            if fname not in ("sdk_list_items", "sdk_get", "sdk_list"):
                continue
            if len(inner.args) >= 3 and isinstance(inner.args[2], ast.Name) \
                    and inner.args[2].id in params:
                wrappers[node.name] = params.index(inner.args[2].id)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
        index = wrappers.get(fname)
        if index is not None and len(node.args) > index \
                and isinstance(node.args[index], ast.Constant) \
                and isinstance(node.args[index].value, str):
            called.add(node.args[index].value)

    called |= EXTRA_CALLED.get(rel, set())

    # Resolve client classes.
    resolved, missing_clients = [], []
    for ns, cls in sorted(clients):
        mod = getattr(oci, ns, None)
        klass = getattr(mod, cls, None) if mod is not None else None
        if klass is None:
            missing_clients.append(f"{ns}.{cls}")
        else:
            resolved.append((f"{ns}.{cls}", klass))

    for c in missing_clients:
        problems.append(f"{rel}: client does not exist: oci.{c}")

    # Every declared method must exist on some constructed client.
    for method in sorted(declared):
        if method in SHARED:
            continue
        if not any(hasattr(k, method) for _, k in resolved):
            where = ", ".join(n for n, _ in resolved) or "(no clients resolved)"
            problems.append(f"{rel}: '{method}' exists on none of: {where}")

    # A call not in the allowlist is refused at runtime.
    for method in sorted(called - declared):
        problems.append(f"{rel}: calls '{method}' but it is NOT in SDK_READ_METHODS")

    # Declared but never called: dead surface that overstates the plan.
    dead = sorted(declared - called - SHARED)
    if dead:
        problems.append(f"{rel}: declared but never called: {', '.join(dead)}")

    print(f"{rel:52} clients={len(resolved)} declared={len(declared)} called={len(called)}")

print()
if problems:
    print(f"=== {len(problems)} PROBLEM(S) ===")
    for p in problems:
        print("  " + p)
    sys.exit(1)
print(f"PASS: SDK surface verification — {len(COLLECTORS)} collectors checked "
      f"against oci {getattr(oci, '__version__', 'unknown')}; every declared "
      f"method exists on a constructed client, every call is allowlisted, and "
      f"no allowlist entry is unused")
