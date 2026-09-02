# CM07-01 Corrective Review

**Review date:** 2026-08-28

**Status:** corrective patch and controlled live validation required before
`cm07-01/cm07-01-open-ports-protocols-services.sh` can be promoted again as the
canonical Task 6 evidence collector.

## Operator-reported result

- `cm07-openports.sh` produced useful live output.
- `cm07-01/cm07-01-open-ports-protocols-services.sh` did not work in the operator's
  environment.
- `cm07-ppsm.sh` and `cm07-proof-opened-ports.sh` did not work.

The legacy scripts remain reference implementations only. Their successful or
failed execution does not override their known error-handling and scope-
authorization limitations.

## Confirmed material findings

### 1. Partial-scope collection can miss cross-compartment network objects

For a `-c` or `-n` scope, the collector lists VCNs, subnets, Security Lists and
NSGs only from each selected compartment. OCI permits related network objects
and attachments to cross compartment boundaries. A referenced Security List or
subnet outside the enumerated compartments can therefore be absent from the
inventory. The incomplete association set can also make a live rule appear
unattached and inactive.

This is a high-severity evidence-completeness defect because the current
coverage rows can still say `OK`. The correction must either resolve all
referenced object OCIDs across the tenancy with read-only `get` calls or fail
closed with explicit `UNRESOLVED-SECURITY-LIST`, `UNRESOLVED-SUBNET` or
equivalent coverage rows. Any related-scope expansion must be disclosed in the
pre-scan plan before the operator approves collection.

### 2. ICMP rules can false-match port-based restrictions

The current `rule_port_range()` maps every non-TCP/UDP/ANY rule to `0-65535`.
`restricted_matches()` can consequently match an ICMP rule to a restricted
entry such as protocol `ANY`, port `3389`, even though ICMP has no transport
ports.

The correction must model portless protocols separately. ICMP/ICMPv6 must not
use TCP/UDP port overlap. Protocol-specific ICMP restrictions may use ICMP type
and code; a policy entry intentionally covering every protocol must have
unambiguous schema semantics and tests.

## Required hardening

1. Add `-p/--profile`, pass it to every OCI CLI call and show it in the approved
   plan and evidence provenance.
2. Keep the strict container-bound `rule_key` for exact approval identity, but
   also emit a semantic key excluding `container_id`. A recreated container
   with identical rules should be labeled as a semantic match requiring review,
   never silently approved and never indistinguishable from permission drift.
3. Rename or version-migrate the egress-misleading `source_type` field to
   `peer_type` (or distinct source/destination type fields) without silently
   invalidating existing baselines.
4. Publish the scan summary and counts in the evidence package, not only on the
   console.
5. Hoist the normalized live-key set outside the stale-mapping loop.

`lib/oci-scope-selector.sh` is committed in the repository, so the reported
missing-helper concern is already resolved and is not a current defect.

## Acceptance gate

Task 6 remains **Partial** until all of the following pass:

- unit/mocked regression for a subnet and Security List in compartments other
  than the VCN compartment, including fail-closed unresolved-reference rows;
- regression proving an ICMP rule does not match a narrow TCP/UDP/ANY port
  restriction;
- regression distinguishing exact rule identity from container-recreated
  semantic identity;
- named-profile regression and static proof that every OCI call receives it;
- full repository test suite;
- a controlled compartment run and a controlled tenancy run against known
  network objects, with the approved pre-scan plan retained;
- reconciliation of counts against OCI Console/CLI spot checks and documented
  reviewer disposition.

Mock success alone is not sufficient to close this corrective action.
