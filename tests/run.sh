#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09/cp09-01/cp09-01-backup-type-config-frequency.sh \
  cp09/cp09-02/cp09-02-backup-access-files-check.sh \
  cp09/cp09-03/cp09-03-backup-replication-check.sh \
  sc08-02/sc08-02-in-transit-encryption.sh \
  sc28/sc28-oci-encryption-at-rest.sh \
  cm07-01/cm07-01-open-ports-protocols-services.sh \
  cm11-01/cm11-01-software-installation-control.sh \
  cm02-01/cm02-01-configuration-baseline.sh \
  cm08-01/cm08-01-component-inventory-baseline.sh \
  cm08-01/cm08-hw-sw-baseline.sh \
  lib/oci-scope-selector.sh \
  tests/mock-oci \
  sc08-02/tests/mock-oci-task2 \
  sc28/tests/mock-oci-task3 \
  cm07-01/tests/mock-oci-task6 \
  cm11-01/tests/mock-oci-task7 \
  cm08-01/tests/mock-oci-task8 \
  tests/mock-oci-scope \
  cp09/cp09-03/tests/test-cp09-03.sh \
  sc08-02/tests/test-sc08-02-in-transit-encryption.sh \
  sc08-02/tests/test-sc8-safety.sh \
  sc28/tests/test-encryption-at-rest.sh \
  tests/test-scope-selection.sh \
  cm07-01/tests/test-cm07-01-open-ports.sh \
  cm11-01/tests/test-cm11-01-software-installation-control.sh \
  cm02-01/tests/test-cm02-01-configuration-baseline.sh \
  cm08-01/tests/test-cm08-01-component-inventory.sh

python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm11-01/cm11-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm02-01/cm02-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm08-01/cm08-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01/lib/oci_audit_sdk.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01/ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01/tests/test-ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'

bash cp09/cp09-01/cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09/cp09-02/cp09-02-backup-access-files-check.sh --selfcheck
bash cp09/cp09-03/cp09-03-backup-replication-check.sh --selfcheck
bash sc08-02/sc08-02-in-transit-encryption.sh --selfcheck
bash sc28/sc28-oci-encryption-at-rest.sh --selfcheck
bash cm07-01/cm07-01-open-ports-protocols-services.sh --selfcheck
bash cm11-01/cm11-01-software-installation-control.sh --selfcheck
bash cm02-01/cm02-01-configuration-baseline.sh --selfcheck
bash cm08-01/cm08-01-component-inventory-baseline.sh --selfcheck
python3 ra05-01/ra05-01-vulnerability-tracking.py --selfcheck
bash cp09/cp09-03/tests/test-cp09-03.sh
bash sc08-02/tests/test-sc8-safety.sh
bash sc08-02/tests/test-sc08-02-in-transit-encryption.sh
bash sc28/tests/test-encryption-at-rest.sh
bash tests/test-scope-selection.sh
bash cm07-01/tests/test-cm07-01-open-ports.sh
bash cm11-01/tests/test-cm11-01-software-installation-control.sh
bash cm02-01/tests/test-cm02-01-configuration-baseline.sh
bash cm08-01/tests/test-cm08-01-component-inventory.sh
python3 ra05-01/tests/test-ra05-01-vulnerability-tracking.py

echo "PASS: CP-9, SC-8, SC-28, CM-7, CM-11, CM-2, CM-8 and RA-5 static, read-only and mock test suite"
