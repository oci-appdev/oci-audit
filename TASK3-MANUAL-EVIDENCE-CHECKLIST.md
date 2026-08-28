# Task 3 Manual Evidence Checklist — Encryption at Rest

Use this checklist with `sc28-oci-encryption-at-rest.sh`. The collector proves
what the OCI APIs expose; this checklist closes the ownership, procedure,
review and approval boundaries required for SC-28/SC-28(1)/SC-12.

Do not store live OCI output, screenshots, OCIDs, key-administrator identities
or secrets in this public repository. Store them in the approved restricted
evidence location and record only the immutable evidence reference in the
audit package.

## 1. Run identification and scope

- [ ] Record system/application, environment, operator and UTC collection time.
- [ ] Record OCI region and authenticated tenancy OCID in the restricted package.
- [ ] Identify the exact VCN, Shared Services and CD3 compartments in scope.
- [ ] Run `bash sc28-oci-encryption-at-rest.sh --selfcheck` and retain the result.
- [ ] For an operator run, use the default interactive path (or `-i` /
      `--select-scope`), retain both matching OCID entries and the complete
      pre-scan summary, and enter exact uppercase `YES`. For automation, retain
      the approved job definition containing the explicit `-c` or `-n` scope.
- [ ] Repeat the run for every subscribed region containing an in-scope asset.
- [ ] Require exit code `0`. Resolve and rerun every exit `3`, non-OK coverage
      row, `COLLECTION-FAILED` row and error-ledger entry.
- [ ] Reconcile each expected compartment/service pair to the coverage CSV.
- [ ] Calculate and retain SHA-256 hashes for the collector, evidence CSV and
      coverage CSV.

## 2. Data-store encryption and CMK reconciliation

- [ ] Review Block Volume, Boot Volume, Object Storage, FSS, Autonomous DB,
      Base DB, MySQL and PostgreSQL evidence rows.
- [ ] Reconcile every `CUSTOMER-MANAGED` data-store key OCID to one collected
      `KMS-Key` row or document why the key is outside the selected scope.
- [ ] Disposition every `REVIEW-USE-CMK` result against the approved data
      classification and key-custody requirement.
- [ ] Confirm MySQL console/API evidence agrees with `encrypt-data` key
      generation type (`SYSTEM` or `BYOK`) and key OCID when BYOK is used.
- [ ] For OCI Database with PostgreSQL, retain the service encryption-at-rest
      proof and document the approved key-custody decision. Do not manufacture
      a customer-key OCID when the current API does not expose one.

## 3. Vault and key protection

- [ ] For every in-scope vault, retain vault type, lifecycle state, management
      endpoint and deletion schedule evidence.
- [ ] Treat any vault or key in `PENDING_DELETION`, `DELETED`, `DISABLED` or an
      unexpected lifecycle state as a control failure pending disposition;
      scheduling deletion is not proof of completed secure destruction.
- [ ] Confirm production/customer-managed keys use HSM protection unless an
      approved exception explicitly permits software-protected keys.
- [ ] Confirm symmetric data-encryption keys use the approved algorithm and
      AES-256 key length (OCI reports 32 bytes).
- [ ] Reconcile key administrators and key users to the approved IAM groups,
      named owners, least-privilege policy and current access review.

## 4. Rotation evidence

- [ ] For keys with automatic rotation, retain enabled status, interval,
      schedule start (if configured), last rotation time/status and next
      rotation time.
- [ ] Review key-version history and confirm the latest expected rotation
      created a new enabled version; reconcile auto-rotated version markers.
- [ ] Retain OCI Audit log evidence for at least one successful production key
      rotation, including actor/service, target key, UTC time and result.
- [ ] Resolve every `AUTO-ROTATION-FAILED`, missing schedule detail or
      `REVIEW-ROTATION-NOT-CONFIRMED` result.
- [ ] For manually rotated keys, retain the approved rotation procedure,
      required frequency, ticket/change record, most recent execution proof and
      next due date.
- [ ] Confirm the procedure covers dependent-resource validation, rollback,
      incident handling and separation of duties.

## 5. Evidence integrity and reviewer sign-off

- [ ] Verify the package contains no key material, private keys, passphrases,
      database credentials, IPSec PSKs or other secrets.
- [ ] Record every finding's disposition, risk owner, remediation/exception
      reference and due date.
- [ ] Record evidence-location URI/reference, package hashes and retention rule.
- [ ] Operator name/date: ________________________________________________
- [ ] Security reviewer name/date: _______________________________________
- [ ] System owner approval/date: ________________________________________
- [ ] Final result: `PASS` / `PASS WITH APPROVED EXCEPTIONS` / `FAIL`

The collector's exit code proves collection completeness only. It does not
convert review findings into a passing control and does not replace approval.
