#!/usr/bin/env python3
"""Explain an evidence run that produced no resource rows.

An empty evidence CSV has several very different causes and they are not
distinguishable from the evidence file itself. The coverage ledger does
distinguish them: every collector writes one row per compartment per service,
carrying what the read returned and whether it succeeded.

  reads succeeded, everything zero -> the scope really is empty: wrong region,
                                      or a compartment whose resources live in
                                      a child compartment that was not a target
  reads refused                    -> the principal lacks an IAM policy
  reads failed                     -> endpoint, network or credential fault
  no coverage rows at all          -> the scan never reached a target

Usage:
  python3 tools/diagnose-evidence.py <evidence-directory>
  python3 tools/diagnose-evidence.py <coverage.csv> [errors.csv]

OCIDs are truncated so the output can be pasted into an issue.
"""

from __future__ import annotations

import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

OK_STATES = {"OK"}
DENIED_STATES = {"DENIED", "NOT-FOUND"}


def short(ocid: str) -> str:
    ocid = (ocid or "").strip()
    if len(ocid) <= 14:
        return ocid or "<none>"
    return f"{ocid[:14]}...{ocid[-6:]}"


def read_rows(path: Path) -> List[Dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def find_files(target: Path) -> Tuple[Path, Optional[Path]]:
    """Accept a directory or an explicit coverage file."""
    if target.is_file():
        return target, None
    coverage = sorted(target.glob("*coverage*.csv"))
    if not coverage:
        raise SystemExit(
            f"no coverage CSV found in {target}\n"
            "The coverage ledger is what explains an empty run. If the collector "
            "wrote no coverage file at all it exited before scanning; re-run and "
            "read the message on stderr."
        )
    errors = sorted(target.glob("*collection_errors*.csv"))
    return coverage[-1], (errors[-1] if errors else None)


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    target = Path(argv[1]).expanduser()
    if not target.exists():
        raise SystemExit(f"path does not exist: {target}")

    coverage_path, errors_path = find_files(target)
    if len(argv) > 2:
        errors_path = Path(argv[2]).expanduser()

    rows = read_rows(coverage_path)
    print(f"Coverage ledger : {coverage_path.name}")
    print(f"Rows            : {len(rows)}")

    if not rows:
        print("\nVERDICT: the collector wrote an empty coverage ledger.")
        print("It never reached a compartment. Nothing was scanned, so the empty")
        print("evidence file is not a finding about your tenancy.")
        return 1

    by_status: Counter = Counter()
    assets_by_service: Dict[str, int] = defaultdict(int)
    zero_ok: List[Tuple[str, str]] = []
    problems: List[Tuple[str, str, str, str]] = []
    compartments = set()

    for row in rows:
        status = (row.get("collection_status") or "").strip().upper() or "?"
        service = (row.get("service") or "?").strip()
        name = (row.get("compartment_name") or "?").strip()
        ocid = row.get("compartment_ocid") or ""
        compartments.add((name, ocid))
        by_status[status] += 1
        raw = (row.get("assets_found") or "").strip()
        try:
            found = int(raw)
        except ValueError:
            found = 0
        if status in OK_STATES:
            assets_by_service[service] += found
            if found == 0:
                zero_ok.append((name, service))
        else:
            problems.append((name, service, status,
                             (row.get("collection_error") or "")[:120]))

    print(f"Compartments    : {len(compartments)}")
    print("Statuses        : " + ", ".join(f"{k}={v}" for k, v in by_status.most_common()))

    total_assets = sum(assets_by_service.values())
    print(f"Resources found : {total_assets}")
    if total_assets:
        print("\nBy service:")
        for service, count in sorted(assets_by_service.items(), key=lambda kv: -kv[1]):
            if count:
                print(f"  {count:>6}  {service}")

    if problems:
        print(f"\nReads that did not succeed ({len(problems)}):")
        for name, service, status, message in problems[:25]:
            print(f"  {status:<14} {service:<16} {name}")
            if message:
                print(f"                 {message}")
        if len(problems) > 25:
            print(f"  ... and {len(problems) - 25} more")

    print("\nScanned compartments:")
    for name, ocid in sorted(compartments)[:20]:
        print(f"  {name:<28} {short(ocid)}")
    if len(compartments) > 20:
        print(f"  ... and {len(compartments) - 20} more")

    print()
    denied = sum(v for k, v in by_status.items() if k in DENIED_STATES)
    failed = sum(v for k, v in by_status.items()
                 if k not in OK_STATES and k not in DENIED_STATES)

    if total_assets == 0 and denied and not failed:
        print("VERDICT: every read was refused. This is an IAM policy gap, not an")
        print("empty tenancy. The principal needs read/inspect on these services in")
        print("these compartments. The empty evidence file must NOT be read as an")
        print("observed negative.")
        return 1
    if total_assets == 0 and failed:
        print("VERDICT: reads failed outright. Check the region spelling first -- it")
        print("must be a full identifier such as us-ashburn-1, never a short code")
        print("such as iad -- then credentials and network reachability.")
        print("Read the errors CSV for the service codes.")
        return 1
    if total_assets == 0 and not problems:
        print("VERDICT: every read succeeded and every one returned zero.")
        print("The reads worked, so this is a scope question, in this order:")
        print("  1. REGION. Resources are regional. A collector scans the one region")
        print("     given with -r. Resources in any other region are invisible to it.")
        print("     Run 'oci iam region-subscription list' and re-run per region.")
        print("  2. COMPARTMENT. -c scans exactly the compartments named, not their")
        print("     children. Selecting the tenancy interactively scans root plus")
        print("     every active compartment; that is the way to prove absence.")
        print("  3. Only once both are right does zero mean the resource type is")
        print("     genuinely not deployed.")
        return 1

    print("VERDICT: resources were collected. If a specific service is zero, check")
    print("it against the two scope questions above before reading it as absence.")
    if errors_path is not None and errors_path.is_file():
        print(f"\nAn error ledger exists: {errors_path.name} -- partial coverage.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
