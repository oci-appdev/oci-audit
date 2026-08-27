# OCI Backup Audit Script — Read-Only Posture Review

**Script:** `oci_backup_audit.py`  
**Date:** 2026-07-14  
**Reviewer:** Copilot Audit Agent

---

## Summary

The script is a **tenancy-wide backup/snapshot posture audit** tool. Its stated design is read-only: it iterates all active compartments and **reports** on backup/snapshot configuration across multiple OCI services. It produces a console summary and a timestamped CSV file written locally.

---

## ✅ Read-Only Operations (expected)

The script reports on the following services using only `list_*` / `get_*` OCI SDK calls (HTTP GET — no side effects):

| Service | What Is Read |
|---|---|
| Block / Boot Volumes | Backup policies, policy asset assignments |
| Base DB Systems | Backup configs, backup schedules |
| Autonomous DB | Backup configs |
| File Storage (FSS) | Snapshot policies |
| Object Storage | Lifecycle policies, replication rules, retention rules |
| MySQL | Backup configs |
| PostgreSQL | Backup configs |

---

## ⚠️ Verification Checklist

Before running in any environment, confirm the following in the script source:

- [ ] Only `list_*`, `get_*`, `search_*` OCI SDK methods are used — no `create_*`, `update_*`, `delete_*`, `change_*`, or `restore_*` calls
- [ ] No OCI CLI sub-commands that write (e.g., `backup create`, `restore`, `update`) are shelled out
- [ ] File output is local only (timestamped CSV) — no writes to OCI Object Storage or other cloud resources
- [ ] `get_volume_backup_policy_asset_assignment` is used (read-only), NOT `create_volume_backup_policy_assignment` (write)

---

## 🔒 Recommended IAM Policy (Least Privilege)

Run the script under a principal with only the following OCI IAM policies to enforce read-only at the cloud level — this provides a hard enforcement boundary even if the script code contains an accidental write call:

```
Allow group AuditGroup to inspect all-resources in tenancy
Allow group AuditGroup to read backup-policies in tenancy
Allow group AuditGroup to read volume-backups in tenancy
Allow group AuditGroup to read db-backups in tenancy
Allow group AuditGroup to read autonomous-backups in tenancy
Allow group AuditGroup to read file-systems in tenancy
Allow group AuditGroup to read buckets in tenancy
Allow group AuditGroup to read mysql-backups in tenancy
```

With these policies in place, OCI will reject any write operation with a `403 Authorization failed` error, regardless of what the script attempts.

---

## Conclusion

The script's **stated purpose and design are read-only**. To confirm fully, review every SDK/CLI call in the source against the verification checklist above. Coupling that review with the least-privilege IAM policy above provides defense in depth and ensures no changes are made to the tenancy.

---

## CP-9 family — current state

| Script | Dimension | Status |
|---|---|---|
| `cp09-01-backup-type-config-frequency.sh` | backup type / configuration / frequency | rewritten 2026-08-27, blockers fixed |
| `cp09-02-backup-access-files-check.sh` | who can access the backup files | new 2026-08-27 |
| `cp09-03-backup-replication-check.sh` | replication, retention, versioning (DR) | collection-failure reporting fixed 2026-08-27 |

All three are read-only, record compartment names, and refuse to let a failed
collection look like a clean result. `cp09-01` and `cp09-02` carry a
`--selfcheck` flag that proves read-only-ness against their own source.

Together these cover the evidence line item *"Backup type/frequency, access,
replication — all OCS assets (VCN, Shared Services, CD3)"*.

---

## 2026-08-27 — cp09-01 coverage review (blockers found — now fixed, see below)

A 7-lens review of `cp09-01-backup-type-config-frequency.sh` against the CP-9 evidence requirement "Backup type/frequency, access, replication — all OCS assets (VCN, Shared Services, CD3)" found several **blocker**-severity defects still open:

- `oci fs snapshot-policy list` is not a real CLI command — every FSS row fails. The correct command (used by `backup-storage.sh`) is `oci fs filesystem-snapshot-policy list`.
- FSS schedules are read off the `list` response, which never carries `schedules` — every FSS policy reports `NO_SCHEDULES` even when one exists.
- The default config path is `/.oci/config` instead of `$HOME/.oci/config`, so config-auth mode aborts on a normal workstation.
- The volume→policy linkage relies on an unverified showoci CSV column instead of calling `oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment`.
- No compartment **name** is ever recorded (only OCID), so output cannot be broken out by VCN / Shared Services / CD3.
- No coverage of Base DB, Autonomous DB, MySQL, or PostgreSQL.
- "Access" and "replication" dimensions are entirely absent from this script's output — see the next section for where that evidence now lives.

**Remediated 2026-08-27** — see the rewrite section below.

---

## 2026-08-27 — cp09-01 rewritten as a direct-CLI collector

Patching the individual bugs would have left the architecture intact, and the architecture was the problem: collection ran through showoci and the join guessed CSV filenames and column headers. Rewritten in the same house style as `cp09-02`/`cp09-03`. showoci and the embedded Python workers are no longer required.

### Blockers fixed

- **`oci fs snapshot-policy list` does not exist** — the command group is `oci fs filesystem-snapshot-policy`. Every FSS row previously errored.
- **FSS schedules are not in the LIST response** — they appear only on GET. Fixing only the command name would have converted hard errors into *silent false-clean* `NO_SCHEDULES` rows, so both were fixed together and each policy is now fetched by id. Regression-tested with a mock whose list response deliberately omits `schedules`.
- **Per-asset policy linkage** now uses the authoritative `bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment` rather than a showoci column that may not exist.
- **Compartment names** are recorded, so evidence is filterable by VCN / Shared Services / CD3.
- **Coverage added** for Base DB, Autonomous DB, MySQL, PostgreSQL and volume groups.
- **Denials no longer read as "no backup configured"** — stderr is captured, every row carries `collection_status`, and the run exits 3 if any collection was incomplete.
- A new **coverage CSV** records every compartment/service pair actually visited, so "no assets" is distinguishable from "never collected".
- `last_backup_time` and `backup_count` show whether schedules actually **fire**, not merely that they are configured.

### Bug found during end-to-end testing

`check_volumes` captured the volume list *after* the backup-list call had already overwritten the shared output variable, so the loop iterated over backups and **no block volume was ever processed**. Static reading did not catch this; running against a mock did.

---

## 2026-08-27 — cp09-03 collection-failure reporting

`cp09-03` had the same defect as the retired access scripts: `o() { oci ... 2>/dev/null; }` discarded all stderr. For a replication control this is the worst possible failure mode — a 403 on `bv block-volume-replica list` returns nothing, and nothing is then reported as `NO-REPLICA`. An auditor would read a permissions problem as proof that no DR copy exists.

The wrapper now captures stderr, classifies the failure (DENIED / CLI_UNSUPPORTED / NOTFOUND / ERROR), writes it to a companion `oci_backup_dr_collection_errors_<ts>.csv`, prints a prominent warning, and exits 3.

**Subtlety worth remembering:** most call sites invoke `o()` inside `$( ... )`, which is a subshell, so an `INCOMPLETE=1` set inside it never reaches the parent scope. The verdict is therefore derived from the error file's row count — file appends survive the subshell, variable assignments do not. The first version of this fix deleted the error file precisely because it trusted the variable.

Still outstanding for `cp09-03`: per-row `collection_status`. Attributing a status to each row means threading it through all seven check functions; the current fix makes failures impossible to miss but does not yet mark *which* row is affected.

---

## 2026-08-27 — cp09-02-backup-access-files-check.sh (new script)

Added to fill the empty slot between `cp09-01` (type/frequency) and `cp09-03` (replication): **who can access the backup files**, resolved down to named users rather than stopping at a group name.

**Consolidated and removed** (superseded, no unique content lost — verified by diff before deletion):
- `oci-backup-access.sh` — older duplicate of `backup-storage-access.sh`
- `oci-backup-audit.sh` — older duplicate of `backup-storage.sh`
- `backup-storage-access.sh` — fully superseded by `cp09-02`

**Kept:** `backup-storage.sh` — its Base DB / ADB / MySQL / PostgreSQL backup-posture coverage (configured? schedule? retention?) is not yet provided anywhere else in this repo.

### Gaps closed vs. the scripts it replaces

| Gap | Why it mattered |
|---|---|
| `all-resources` grants | Confers full backup access without naming a backup keyword — the old keyword filter missed it entirely |
| Multi-grantee statements | `Allow group A, group B to ...` — old regex `head -1`'d and dropped co-grantees |
| Verb capture | `inspect` (can see it exists) vs `manage` (can delete it) are different audit answers |
| Statement scope | A tenancy-root grant is no longer mistaken for compartment-local |
| KMS key custody | Whoever can `use` the key decrypts backups; `manage` destroys them |
| PAR expiry + scope | Old script emitted a count only; now distinguishes an active bucket-level `AnyObjectReadWrite` PAR from an expired object-level one |
| Cross-tenancy `Endorse`/`Admit` | Flags a foreign tenancy reading this tenancy's backups |
| Denials ≠ absence | Old wrapper piped stderr to `/dev/null`, so a 403 read identically to "nobody has access". Every row now carries `collection_status`; the run exits 3 if anything was incomplete |

### Read-only guarantee

`--selfcheck` greps the script's own source against a deny-list of mutating OCI subcommands and refuses to run if one is found. Verified by injecting `oci bv backup delete` into a test copy — caught correctly. Works without the OCI CLI installed.

### Bugs found and fixed during end-to-end testing (mocked OCI CLI)

Static review missed all five of these; they only surfaced running the script against realistic mock responses:

- `tr '\x1e' '\n'` — GNU `tr` has no `\xHH` escapes; it was translating the literal characters `\`, `x`, `1`, `e`, truncating every OCID at its first `1`. Fixed with bash parameter expansion instead.
- `(.data.items // .data)` in jq — errors (not null) when `.data` is an array, so `//` never caught it and PAR/replication rows were silently dropped. Fixed to `.data.items?`.
- `printf '%s' "$x" | while read` — no trailing newline, so single-grantee policy statements (the common case) produced zero grantee rows. Fixed to `printf '%s\n'`.
- `objects` substring-matched inside `objectstorage`; `backups` matched inside a `where ...='prod-backups'` clause value. Fixed with `\b` word boundaries and stripping the where-clause before resource matching.
- `local a=... b="${a...}"` — `a` isn't visible to `b`'s expansion within the same `local` statement under `set -u`. Split into separate assignment lines.

Also fixed: jq builds that emit CRLF (seen on Windows) were leaving a trailing `\r` inside parsed field values and map keys, breaking group-name lookups and padding CSV cells.
