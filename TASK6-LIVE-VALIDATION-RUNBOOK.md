# Task 6 CM07-01 — Live Validation Runbook

**Purpose:** close the two remaining items in the `CM07-CORRECTIVE-REVIEW.md`
acceptance gate. Everything else in that gate is done and covered by
`tests/test-cm07-01-corrective.sh`; these two require a real tenancy and cannot
be satisfied by mock success.

Remaining gate items:

- [ ] a controlled compartment run and a controlled tenancy run against known
      network objects, with the approved pre-scan plan retained;
- [ ] reconciliation of counts against OCI Console/CLI spot checks and
      documented reviewer disposition.

Run this whole runbook in one sitting and keep every output. Task 6 stays
**Partial** until Part 5 is signed.

## Before you start

**The collector only reads.** `bash tests/test-readonly-proof.sh` verifies, over
every shell and Python file in the repository, that all 252 OCI call sites use a
`list`/`get` action, that none is one of the 18 SDK operations that are named
like a read but issue POST, that none is one of the 51 reads that return
credential or key material, and that no `raw-request` is used. Run it before
you run anything against the tenancy:

```bash
bash tests/run.sh                     # full suite, includes the proof
bash cm07-01-open-ports-protocols-services.sh --selfcheck
```

You need:

- an OCI CLI authenticated to the target tenancy with **read-only** IAM;
- the region under audit (`us-langley-1` unless told otherwise);
- the tenancy OCID and the VCN compartment OCID;
- at least one **known** network object to check the collector against — pick
  these from the Console before you run anything, and write them down:

| What | Value | Where you read it |
|---|---|---|
| VCN compartment OCID | | Console |
| A Security List OCID in that compartment | | Console |
| Its exact ingress + egress rule count | | Console |
| A subnet in that compartment | | Console |
| The Security List OCIDs that subnet attaches | | Console |
| An NSG OCID and its rule count | | Console |
| **A Security List in a DIFFERENT compartment that an in-scope subnet attaches** | | Console |

That last row is the whole point of the cross-compartment fix. If the tenancy
has no such object, say so in Part 5 — the fix is then untested against live
data and Task 6 should stay Partial until an object exists or one is created in
a test compartment.

## Part 1 — controlled compartment run

```bash
REGION=us-langley-1
COMP=ocid1.compartment.oc1..<vcn-compartment>
OUT=./evidence/task6-live/compartment-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT"

bash cm07-01-open-ports-protocols-services.sh \
  -r "$REGION" -c "$COMP" --inventory-only -o "$OUT" \
  2>&1 | tee "$OUT/console.log"
```

This prompts. You will be asked for the compartment OCID **twice**, then shown
the full plan, then asked for exact uppercase `YES`.

**Retain `$OUT/console.log` — it contains the approved pre-scan plan.** Confirm
the plan shows:

- [ ] the region you passed, not `default`;
- [ ] `OCI CLI profile:` (ambient, or the `-p` profile you passed);
- [ ] the compartment you intend, by OCID;
- [ ] the line beginning `Related-scope expansion:`;
- [ ] `PARTIAL SCOPE: subnet associations outside the target compartments ...`.

Expected exit code `0`. Exit `3` means at least one call failed — read
`cm07-01_collection_errors_*.csv` before continuing.

## Part 2 — reconcile the compartment run

```bash
cd "$OUT"
INV=$(ls cm07-01_open_pps_inventory_*.csv)
COV=$(ls cm07-01_coverage_*.csv)
SUM=$(ls cm07-01_scan_summary_*.csv)

# Rule count per container, to compare against the Console.
python3 -c "
import csv,collections,sys
rows=[r for r in csv.DictReader(open('$INV')) if r['collection_status']=='OK']
c=collections.Counter((r['container_type'],r['container_name']) for r in rows)
for k,v in sorted(c.items()): print(f'{v:4d}  {k[0]:32s} {k[1]}')
print('total OK rules:', len(rows))
"

# Anything the collector could not proveent
grep -v ',"OK",' "$COV" | head -20
cat "$SUM"
```

Check each box:

- [ ] every Security List rule count matches the Console for that list;
- [ ] every NSG rule count matches;
- [ ] the subnet association column (`applies_to`) names the subnets the
      Console shows, **or** is `UNKNOWN` with an `UNRESOLVED-SUBNET-ASSOCIATION`
      coverage row — under a compartment scope, `UNKNOWN` is the correct answer,
      not a defect;
- [ ] no container shows `attachment_count` of `0` (a partial scope must never
      claim that);
- [ ] the cross-compartment Security List you noted above **appears** in the
      inventory with `container_type` `SecurityList(cross-compartment)` and
      `compartment_id` equal to its owning compartment. **This is the fix. If it
      is absent, stop and report.**
- [ ] `cm07-01_scan_summary_*.csv` records `scope_covers_tenancy=NO`;
- [ ] every coverage row is `OK`, or the non-OK rows are explained by a denial
      you can account for in the read-only policy.

## Part 3 — controlled tenancy run

```bash
OUT2=./evidence/task6-live/tenancy-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$OUT2"

bash cm07-01-open-ports-protocols-services.sh \
  -r "$REGION" --inventory-only -o "$OUT2" \
  2>&1 | tee "$OUT2/console.log"
```

With no `-c`/`-n` this discovers the tenancy and every active compartment.
Select the **tenancy** OCID, enter it twice, and confirm. The plan must warn
that this scans the root plus every active child compartment.

- [ ] the plan now shows `Subnet associations resolvable across all
      compartments (tenancy scope)`;
- [ ] `cm07-01_scan_summary_*.csv` records `scope_covers_tenancy=YES`;
- [ ] the cross-compartment Security List now appears as an ordinary
      `SecurityList` in its own compartment, not as
      `SecurityList(cross-compartment)`;
- [ ] `attachment_count` is now a real number, and matches the Console;
- [ ] the tenancy run's rule count is **greater than or equal to** the
      compartment run's. A smaller number means something is being dropped —
      stop and report.

## Part 4 — targeted checks for the two corrected defects

**ICMP.** If the tenancy has an ICMP Security List or NSG rule, confirm in the
inventory that its `protocol` is `ICMP`, its `destination_port_min/max` are
blank, and its `icmp_type`/`icmp_code` are populated. Then supply a restricted
list containing a port-scoped entry, for example protocol `ANY` ports
`3389-3389`, rerun without `--inventory-only`, and confirm the ICMP rule is
**not** in `cm07-01_restricted_findings_*.csv` while any genuine TCP/3389 rule
**is**.

**Named profile.** If the approved run uses a named CLI profile:

```bash
bash cm07-01-open-ports-protocols-services.sh \
  -r "$REGION" -c "$COMP" -p <PROFILE> --inventory-only -o "$OUT3"
```

- [ ] the plan prints `OCI CLI profile: <PROFILE>`;
- [ ] `cm07-01_scan_summary_*.csv` records `oci_cli_profile=<PROFILE>`;
- [ ] the run authenticates as that profile's principal, not the default.

## Part 5 — reviewer disposition

Complete and retain this with the evidence. Task 6 stays **Partial** until it is
signed and the two gate boxes at the top of this file are ticked.

| Field | Value |
|---|---|
| Region | |
| Tenancy OCID | |
| Compartment run output path | |
| Tenancy run output path | |
| Compartment-run exit code | |
| Tenancy-run exit code | |
| Console rule counts matched? | |
| Cross-compartment Security List present in compartment run? | |
| Cross-compartment object existed in the tenancy at all? | |
| ICMP restricted-match check performed? Result | |
| Named-profile check performed? Result | |
| Non-OK coverage rows, and disposition of each | |
| Reviewer name | |
| Review date | |
| Disposition (ACCEPT / REJECT / ACCEPT-WITH-EXCEPTION) | |
| Exception reference, if any | |

**Evidence handling.** These outputs contain OCIDs, network rules and
compartment structure. Store them in the approved restricted evidence location
and record the immutable reference here. Do not commit them to this repository —
it is public.
