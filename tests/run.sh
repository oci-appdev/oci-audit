#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09-01-backup-type-config-frequency.sh \
  cp09-02-backup-access-files-check.sh \
  cp09-03-backup-replication-check.sh \
  sc08-02-in-transit-encryption.sh \
  sc28-oci-encryption-at-rest.sh \
  cm07-01-open-ports-protocols-services.sh \
  cm11-01-software-installation-control.sh \
  cm02-01-configuration-baseline.sh \
  cm08-01-component-inventory-baseline.sh \
  cm08-hw-sw-baseline.sh \
  lib/oci-scope-selector.sh \
  tests/mock-oci \
  tests/mock-oci-task2 \
  tests/mock-oci-task3 \
  tests/mock-oci-task6 \
  tests/mock-oci-task7 \
  tests/mock-oci-task8 \
  tests/mock-oci-scope \
  tests/test-cp09-03.sh \
  tests/test-sc08-02-in-transit-encryption.sh \
  tests/test-sc8-safety.sh \
  tests/test-encryption-at-rest.sh \
  tests/test-scope-selection.sh \
  tests/test-cm07-01-open-ports.sh \
  tests/test-cm11-01-software-installation-control.sh \
  tests/test-cm02-01-configuration-baseline.sh \
  tests/test-cm08-01-component-inventory.sh

python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/cm11-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/cm02-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/cm08-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/oci_audit_sdk.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("tests/test-ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm03-01-configuration-change-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("tests/test-cm03-01-configuration-change-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ac02-01-account-management.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("tests/test-ac02-01-account-management.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ia02-01-federation-configuration.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("tests/test-ia02-01-federation-configuration.py").read_text(encoding="utf-8"))'

bash cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03-backup-replication-check.sh --selfcheck
bash sc08-02-in-transit-encryption.sh --selfcheck
bash sc28-oci-encryption-at-rest.sh --selfcheck
bash cm07-01-open-ports-protocols-services.sh --selfcheck
bash cm11-01-software-installation-control.sh --selfcheck
bash cm02-01-configuration-baseline.sh --selfcheck
bash cm08-01-component-inventory-baseline.sh --selfcheck
python3 ra05-01-vulnerability-tracking.py --selfcheck
python3 cm03-01-configuration-change-tracking.py --selfcheck
python3 ac02-01-account-management.py --selfcheck
python3 ia02-01-federation-configuration.py --selfcheck
bash tests/test-cp09-03.sh
bash tests/test-sc8-safety.sh
bash tests/test-sc08-02-in-transit-encryption.sh
bash tests/test-encryption-at-rest.sh
bash tests/test-scope-selection.sh
bash tests/test-cm07-01-open-ports.sh
bash tests/test-cm11-01-software-installation-control.sh
bash tests/test-cm02-01-configuration-baseline.sh
bash tests/test-cm08-01-component-inventory.sh
python3 tests/test-ra05-01-vulnerability-tracking.py
python3 tests/test-cm03-01-configuration-change-tracking.py
python3 tests/test-ac02-01-account-management.py
python3 tests/test-ia02-01-federation-configuration.py

echo "PASS: CP-9, SC-8, SC-28, CM-7, CM-11, CM-2, CM-8, RA-5, CM-3, AC-2 and IA-2 static, read-only and mock test suite"
