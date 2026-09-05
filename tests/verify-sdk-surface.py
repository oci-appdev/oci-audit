#!/usr/bin/env python3
"""Cross-check every Python SDK collector's cloud surface against the installed OCI SDK.

Run by tests/run.sh when the oci package is importable.  This is the only gate
that can prove a declared SDK method actually exists on a client the collector
constructs.  The per-collector --selfcheck proves a name looks like a read;
test-readonly-proof.sh proves it is not on a mutating blocklist; neither can
catch a method that does not exist, sits on the wrong client, or is declared in
the allowlist but never called.

That last case matters for evidence integrity: the pre-scan plan prints
SDK_READ_METHODS to the operator as the approved cloud-operation boundary.
Declaring methods the collector never calls overstates that boundary.

For each collector: resolve every Set name that contributes to SDK_READ_METHODS
(handling BinOp unions like CLASSIC_METHODS | SCIM_METHODS), confirm each
declared method exists on at least one client the collector constructs, and
confirm the declared set matches the set actually passed to sdk_list / sdk_get /
sdk_scim_list / sdk_resources_page_list (no dead surface, no unchecked call).
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
    print("         Install it with: python3 -m pip install -r requirements-oci-sdk.txt",
          file=sys.stderr)
    print("         This gate is the only one that can prove a declared SDK "
          "method actually exists.", file=sys.stderr)
    sys.exit(0)

# Python SDK collectors at repo root (Tasks 10-14).
COLLECTORS = [
    "ra05-01-vulnerability-tracking.py",
    "cm03-01-configuration-change-tracking.py",
    "ac02-01-account-management.py",
    "ia02-01-federation-configuration.py",
    "si04-01-siem-crowdstrike-forwarding.py",
]

# discover_scope in lib/oci_audit_sdk.py calls these on behalf of every collector.
SHARED = {"get_compartment", "list_compartments"}
SHARED_CLIENTS = [("identity", "IdentityClient")]

# Wrapper functions in lib/oci_audit_sdk.py that accept a method-name string arg.
SDK_CALLERS = {"sdk_list", "sdk_get", "sdk_scim_list", "sdk_resources_page_list",
               "sdk_list_items"}

# Named set constants that contribute to SDK_READ_METHODS via BinOp union.
# Populated per-collector during parsing so literals() can resolve Name nodes.
EXTERNAL_SETS: dict = {}

# Methods called by shared lib helpers on behalf of certain collectors.
EXTRA_CALLED: dict = {}

problems = []
for rel in COLLECTORS:
    path = REPO / rel
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    # Pre-resolve named set constants (e.g. CLASSIC_METHODS, SCIM_METHODS)
    # so the literals() BinOp resolver can expand Name nodes.
    EXTERNAL_SETS.clear()
    for node in ast.walk(tree):
        target_names: list = []
        if isinstance(node, ast.AnnAssign):
            target_names = [getattr(node.target, "id", "")]
        elif isinstance(node, ast.Assign):
            target_names = [getattr(t, "id", "") for t in node.targets]
        for tname in target_names:
            if not tname or tname == "SDK_READ_METHODS":
                continue
            val = node.value
            if isinstance(val, ast.Set):
                EXTERNAL_SETS[tname] = {
                    elt.value for elt in val.elts
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                }
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

    # Methods actually passed to any SDK caller wrapper as a literal string arg.
    # For-loop tuples ("list_x", ...) also count as called.
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if fname in SDK_CALLERS:
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        called.add(a.value)
        if isinstance(node, ast.For):
            for elt in ast.walk(node.iter):
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str) \
                        and elt.value.startswith(("list_", "get_", "search_")):
                    called.add(elt.value)
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
