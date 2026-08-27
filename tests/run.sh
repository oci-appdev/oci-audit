#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09-01-backup-type-config-frequency.sh \
  cp09-02-backup-access-files-check.sh \
  cp09-03-backup-replication-check.sh \
  in-transit-encryption.sh \
  tests/mock-oci \
  tests/mock-oci-task2 \
  tests/test-cp09-03.sh \
  tests/test-in-transit-encryption.sh

bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
bash in-transit-encryption.sh --selfcheck
bash tests/test-cp09-03.sh
bash tests/test-in-transit-encryption.sh

echo "PASS: CP-9 and SC-8 static, read-only and mock test suite"
