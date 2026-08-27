#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09-01-backup-type-config-frequency.sh \
  cp09-02-backup-access-files-check.sh \
  cp09-03-backup-replication-check.sh \
  in-transit-encryption.sh \
  sc28-oci-encryption-at-rest.sh \
  lib/oci-scope-selector.sh \
  tests/mock-oci \
  tests/mock-oci-task2 \
  tests/mock-oci-task3 \
  tests/mock-oci-scope \
  tests/test-cp09-03.sh \
  tests/test-in-transit-encryption.sh \
  tests/test-encryption-at-rest.sh \
  tests/test-scope-selection.sh

bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
bash in-transit-encryption.sh --selfcheck
bash sc28-oci-encryption-at-rest.sh --selfcheck
bash tests/test-cp09-03.sh
bash tests/test-in-transit-encryption.sh
bash tests/test-encryption-at-rest.sh
bash tests/test-scope-selection.sh

echo "PASS: CP-9, SC-8 and SC-28 static, read-only and mock test suite"
