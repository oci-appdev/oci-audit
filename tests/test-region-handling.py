#!/usr/bin/env python3
"""Region identifiers must be validated once and compared normalized.

Two defects motivated this gate and both are regressions worth catching:

  * -r/--region was validated only for its characters, so a short code such as
    "iad" was accepted. No OCI service reports a short code back, so every
    comparison against a region the service returns silently fails.

  * cp09-03 decides whether a backup replica is off-site by comparing the
    scanned region to the destination region the service reports. Comparing raw
    strings makes that verdict depend on how the operator typed -r: a
    same-region destination reads as off-site, passing CP-9(1) on evidence that
    does not support it. A false pass is the wrong direction for an audit.
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from oci_audit_sdk import (  # noqa: E402
    normalize_region,
    same_region,
    validate_argument_combination,
)

FAILURES = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(name)
        print(f"  FAIL  {name}" + (f" — {detail}" if detail else ""))


def args_for(region: str) -> SimpleNamespace:
    return SimpleNamespace(
        region=region, non_interactive=False, confirm_scope_ocid=[],
        approve_scan="", compartment_id=[], compartment_names="",
    )


def rejects(region: str) -> bool:
    try:
        validate_argument_combination(args_for(region))
    except ValueError:
        return True
    return False


def main() -> int:
    print("Region identifier validation")
    # Real identifiers across realms, including the four-segment government ones.
    for region in ("us-ashburn-1", "us-phoenix-1", "ap-sydney-1",
                   "eu-frankfurt-1", "me-jeddah-1", "us-langley-1",
                   "uk-gov-london-1", "us-gov-ashburn-1"):
        check(f"accepts {region}", not rejects(region))

    # A short code is what an operator reaches for and is exactly what breaks
    # every downstream comparison, so it must be refused, not expanded.
    for region in ("iad", "phx", "lhr", "yyz"):
        check(f"rejects short code {region!r}", rejects(region))

    for region in ("", "us-ashburn1", "us--1", "ashburn-1", "us-ashburn-x"):
        check(f"rejects malformed {region!r}", rejects(region))

    print("\nNormalization is written back onto args")
    args = args_for("US-Ashburn-1")
    validate_argument_combination(args)
    check("region is normalized in place", args.region == "us-ashburn-1",
          f"got {args.region!r}")

    print("\nnormalize_region")
    check("case-folds and trims", normalize_region("  US-ASHBURN-1 ") == "us-ashburn-1")
    check("empty stays empty", normalize_region("") == "")
    check("None is tolerated", normalize_region(None) == "")

    print("\nsame_region — the off-site verdict depends on this")
    check("same region, different case, is the same region",
          same_region("US-ASHBURN-1", "us-ashburn-1"))
    check("same region with whitespace is the same region",
          same_region(" us-ashburn-1 ", "us-ashburn-1"))
    check("different regions are different",
          not same_region("us-ashburn-1", "us-phoenix-1"))
    # An unknown destination must not be judged equal to the home region, and
    # must not be judged different from it either. The caller decides what
    # UNKNOWN means; same_region only refuses to guess.
    check("empty destination never matches", not same_region("us-ashburn-1", ""))
    check("empty home never matches", not same_region("", "us-ashburn-1"))
    check("two empties never match", not same_region("", ""))

    print()
    if FAILURES:
        print(f"FAILED: {len(FAILURES)} check(s): " + ", ".join(FAILURES))
        return 1
    print("PASS: region identifier validation, normalization and comparison")
    return 0


if __name__ == "__main__":
    sys.exit(main())
