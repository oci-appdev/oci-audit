#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09-01-backup-type-config-frequency.sh \
  cp09-02-backup-access-files-check.sh \
  cp09-03-backup-replication-check.sh \
  tests/mock-oci \
  tests/test-cp09-03.sh

bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
bash tests/test-cp09-03.sh

echo "PASS: CP-9 static, read-only and mock test suite"
