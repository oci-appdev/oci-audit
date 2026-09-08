# Review — Codex's Tasks 11, 12 and 13 collectors

**Reviewed:** 2026-09-08 by Claude, against `oci==2.185.1`
**Subjects:** `cm03-01-configuration-change-tracking.py` (CM-3),
`ac02-01-account-management.py` (AC-2), `ia02-01-federation-configuration.py`
(IA-2), all published flat on `main` at `915cc12` and never previously reviewed.
**Status:** they remain **Codex's**. Nothing below has been changed in them.

## Summary

These three are in materially better shape than Task 14 was at the same stage.
The defect classes that have bitten this repository before — a declared method
that does not exist, a `*Summary` missing the field the control turns on, a
failed call becoming a negative finding — are all absent. Two findings need a
decision before the collectors can merge, and one of them is about **this
repository's gate, not Codex's code**.

## What was checked, and what passed

| Check | Result |
|---|---|
| Every declared method exists on a constructed client | **Pass.** All 28 across the three resolve. No `oci.logging_management`-style phantom. |
| Summary-vs-full model trap | **Not applicable.** IAM `list_users` returns full `User` objects carrying `capabilities`, `is_mfa_activated` and `last_successful_login_time`; there is no summary/full split to fall into. |
| Rule 3 — a failed call never becomes a negative finding | **Pass** in all three. Failures produce a `FAILED` coverage row, an error-ledger row, and a non-zero exit. |
| Secret material written into evidence | **Pass.** Verified field-by-field against the models; see below. |
| OCI Audit retention boundary (CM-3) | **Pass, and handled well.** `cm03-01` reads the real `retention_period_days` from `get_configuration`, validates it is 90–365, records `within_retention`, and refuses a window over 365 days. Querying past retention would otherwise return nothing and read as "no changes". |
| Identity Domains `App.client_secret` (IA-2) | **Pass, and handled well.** See below. |
| AC-2(3) inactive accounts | **Pass.** Reads `last_successful_login_time`, supports `--inactivity-policy` with thresholds, and carries an explicit `UNKNOWN` activity state rather than assuming inactivity. |

### The App client-secret hazard, and why IA-2 avoids it

`oci.identity_domains.models.App` has 117 fields, two of which are
`client_secret` and `hashed_client_secret`. The SDK documents `client_secret` as
"the credential of this App, which this App supplies as a password", and its
SCIM properties say **`idcsSensitive: none`** — Identity Domains does not mask
it. `ia02-01` calls `list_apps`, so this was the sharpest thing to check.

It passes an explicit `attributes=` allowlist naming 17 fields, and
`clientSecret` is not among them. The secret is never requested and never
returned. That is the correct pattern and it should be preserved in any
refactor.

One hardening suggestion, not a defect: nothing currently prevents someone
adding `clientSecret` to that attribute string later. A behavioural test that
plants a client secret in the mock and asserts it reaches no output file would
lock the property down, the way CA07-01's webhook-token test does.

## Finding 1 — AC-2 collides with the repository read-only gate

`ac02-01`'s `CLASSIC_METHODS` declares five operations that
`tests/test-readonly-proof.sh` and `lib/oci_audit_sdk.py` block by name:

```
list_api_keys  list_auth_tokens  list_customer_secret_keys
list_db_credentials  list_smtp_credentials
```

Staged into the tree, it fails the gate. **It cannot merge as written.**

**It is not a leak.** `CREDENTIAL_FIELDS` is
`credential_key, account_key, account_id, account_name, credential_type,
credential_id_or_fingerprint, lifecycle_state, time_created, time_expires,
description` — identifiers, states and dates. No `key_value`, no `token`. The
collector even prints "Credential values, passwords, private keys, MFA seeds and
recovery data are never exported", and it has a `--disable` mechanism for these
calls. What it builds is a per-user credential *inventory*, which is exactly the
AC-2 evidence the control asks for.

**And the blocklist is over-broad for four of the five.** Checked against the
models rather than assumed:

| Operation | What the list response actually carries |
|---|---|
| `list_auth_tokens` | `AuthToken.token` exists, but the SDK docstring states the value "is available only in the response for `CreateAuthToken`, and not for `ListAuthTokens`". |
| `list_customer_secret_keys` | Returns `CustomerSecretKeySummary` — **no secret field at all**. |
| `list_smtp_credentials` | Returns `SmtpCredentialSummary` — no password field. |
| `list_db_credentials` | Returns `DbCredentialSummary` — no credential field. |
| `list_api_keys` | `ApiKey.key_value` is populated — but it is the **public** half of the keypair, the PEM the user uploaded. |

So the gate blocks by operation name, while the confidentiality risk lives in
specific *fields*, most of which these list operations do not return.

**This needs a decision and is not mine to make unilaterally**, because either
route changes something owned elsewhere:

- **Option A — narrow the blocklist.** Remove the four operations whose list
  responses carry no secret, keeping `get_*` singular reads and anything that
  returns a value. Most correct, and it unblocks a legitimate AC-2 control. But
  it loosens a safety gate on the strength of this analysis, and AGENTS.md rule
  6 says "Do not add an exemption to get a call past this gate."
- **Option B — leave the gate, change AC-2.** Drop the five calls and collect
  credential inventory some other way. Loses real AC-2(1)/(3) evidence; there is
  no other API that enumerates a user's credentials.
- **Option C — split the list.** Keep one blocklist for operations that return
  secrets and a second, softer one for credential-adjacent reads that must
  additionally prove they write no sensitive field. Most work, most precise.

**Recommendation: Option A, narrowed to exactly the four verified-clean
operations, with `list_api_keys` retained on the blocklist** — its response does
carry key material, and public or not, an evidence CSV full of PEM blocks in a
public-repo workflow is not worth the argument. AC-2 can count API keys by
fingerprint without it.

## Finding 2 — IA-2 exits 2 on an incomplete collection, not 3

`ia02-01` line 917:

```python
if not collection_complete:
    return 2
return 0 if tenancy_complete and governance_complete else 3
```

AGENTS.md rule 3 fixes the contract: a failed or ambiguous call becomes a
non-OK coverage row, a retained error ledger **and exit code 3**. Every other
collector in the repository follows it. In this repository `2` already means
something else — the three retired CM-7 scripts exit `2` to refuse to run.

Fails safe (it is non-zero), so this is a consistency defect rather than a
safety one, but automation checking `rc == 3` for "incomplete evidence" will
not classify it correctly. One-line fix, Codex's to make.

## Finding 3 — a failed read records `item_count` 0, not UNKNOWN

All three call `add_coverage(..., "FAILED", 0, ...)`. Elsewhere in the
repository a failed read records `UNKNOWN`, because `0` in a count column reads
as "none found" when it means "we do not know". The `status` column
disambiguates it, so this is cosmetic — but it is the same distinction that
makes CP02-01 report `member_count=UNKNOWN` rather than `0` when a get fails.

## Finding 4 — layout

All three are flat at the repository root, with their tests in `tests/`. The
per-task folder layout requires `cm03-01/`, `ac02-01/`, `ia02-01/` each holding
its collector and its own `tests/`. Moving them means fixing the `lib/` path
insert and each test's `parents[1]` → `parents[2]`, exactly as si04-01 needed.

## What this review changed in the repository

Nothing in Codex's collectors. One thing in ours, because reviewing AC-2 exposed
it:

**`tests/test-readonly-proof.sh`'s allowlist branch had never inspected
anything.** It matched constants named `ALLOW*` by regex, and every SDK
collector here names its allowlist `SDK_READ_METHODS`. Staging `ac02-01` — with
five blocklisted reads in its allowlist — produced a clean PASS, and so did
injecting `get_auth_token` into a live collector. Fixed in `6a87b0f`: parsed
with `ast`, following `A | B` unions, with a `MIN_ALLOWLIST_ENTRIES` floor so
the branch cannot go dead silently again. Coverage went from 0 entries to 140.

That is the finding with the longest reach. Finding 1 is only visible *because*
the gate now works.
