#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash -n \
  cp09-01/cp09-01-backup-type-config-frequency.sh \
  cp09-02/cp09-02-backup-access-files-check.sh \
  cp09-03/cp09-03-backup-replication-check.sh \
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
  cp09-01/tests/mock-oci-cp0901 \
  cp09-01/tests/test-cp09-01-backup-config.sh \
  cp09-03/tests/test-cp09-03.sh \
  sc08-02/tests/test-sc08-02-in-transit-encryption.sh \
  sc08-02/tests/test-sc8-safety.sh \
  sc28/tests/test-encryption-at-rest.sh \
  cm07-01/tests/test-cm07-01-open-ports.sh \
  cm07-01/tests/test-cm07-01-corrective.sh \
  cm11-01/tests/test-cm11-01-software-installation-control.sh \
  cm02-01/tests/test-cm02-01-configuration-baseline.sh \
  cm08-01/tests/test-cm08-01-component-inventory.sh \
  tests/test-readonly-proof.sh \
  tests/test-doc-schema-drift.sh \
  tests/test-repo-structure.sh \
  tests/test-task1-3-automation-contract.sh \
  tests/test-scope-selection.sh

python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm11-01/cm11-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm02-01/cm02-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm08-01/cm08-01-reconcile.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/oci_audit_sdk.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01/ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ra05-01/tests/test-ra05-01-vulnerability-tracking.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("sc28/sc28-oci-encryption-at-rest.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("sc28/tests/test-sc28-encryption-at-rest.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-01/cp09-01-backup-configuration.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-01/tests/test-cp09-01-backup-configuration.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-02/cp09-02-backup-access.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-02/tests/test-cp09-02-backup-access.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-03/cp09-03-backup-replication.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp09-03/tests/test-cp09-03-backup-replication.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("sc08-02/sc08-02-in-transit-encryption.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("sc08-02/tests/test-sc08-02-in-transit.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("lib/oci_audit_inventory.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm08-01/cm08-01-component-inventory.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm02-01/cm02-01-configuration-baseline.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm02-01/tests/test-cm02-cm08-baseline-inventory.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm11-01/cm11-01-software-installation-control.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm11-01/tests/test-cm11-01-software-control.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm07-01/cm07-01-open-ports.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cm07-01/tests/test-cm07-01-open-ports.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("si04-01/si04-01-siem-crowdstrike-forwarding.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("ca07-01/ca07-01-continuous-monitoring.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp02-01/cp02-01-contingency-planning.py").read_text(encoding="utf-8"))'
python3 -c 'import ast, pathlib; ast.parse(pathlib.Path("cp04-01/cp04-01-contingency-plan-testing.py").read_text(encoding="utf-8"))'

bash cp09-01/cp09-01-backup-type-config-frequency.sh --selfcheck
bash cp09-02/cp09-02-backup-access-files-check.sh --selfcheck
bash cp09-03/cp09-03-backup-replication-check.sh --selfcheck
bash sc08-02/sc08-02-in-transit-encryption.sh --selfcheck
bash sc28/sc28-oci-encryption-at-rest.sh --selfcheck
bash cm07-01/cm07-01-open-ports-protocols-services.sh --selfcheck
bash cm11-01/cm11-01-software-installation-control.sh --selfcheck
bash cm02-01/cm02-01-configuration-baseline.sh --selfcheck
bash cm08-01/cm08-01-component-inventory-baseline.sh --selfcheck
python3 ra05-01/ra05-01-vulnerability-tracking.py --selfcheck
python3 sc28/sc28-oci-encryption-at-rest.py --selfcheck
python3 cp09-01/cp09-01-backup-configuration.py --selfcheck
python3 cp09-02/cp09-02-backup-access.py --selfcheck
python3 cp09-03/cp09-03-backup-replication.py --selfcheck
python3 sc08-02/sc08-02-in-transit-encryption.py --selfcheck
python3 cm08-01/cm08-01-component-inventory.py --selfcheck
python3 cm02-01/cm02-01-configuration-baseline.py --selfcheck
python3 cm11-01/cm11-01-software-installation-control.py --selfcheck
python3 cm07-01/cm07-01-open-ports.py --selfcheck
python3 si04-01/si04-01-siem-crowdstrike-forwarding.py --selfcheck
python3 ca07-01/ca07-01-continuous-monitoring.py --selfcheck
python3 cp02-01/cp02-01-contingency-planning.py --selfcheck
python3 cp04-01/cp04-01-contingency-plan-testing.py --selfcheck

# Repository-wide gates first: the read-only proof must cover every collector
# in whatever layout the tree currently has.
bash tests/test-repo-structure.sh
bash tests/test-readonly-proof.sh
# The documented governance-input schemas must match what the collectors validate.
bash tests/test-doc-schema-drift.sh
# Proves declared SDK methods actually exist. Skips loudly, and only
# when the oci package is absent -- never silently.
python3 tests/verify-sdk-surface.py
# Proves the secret-read blocklist matches the SDK models in both directions:
# nothing blocked that has no secret to leak, nothing missed that does.
python3 tests/verify-secret-blocklist.py
bash tests/test-scope-selection.sh
bash tests/test-task1-3-automation-contract.sh

# Per-task suites, in worksheet order.
bash cp09-01/tests/test-cp09-01-backup-config.sh
python3 cp09-01/tests/test-cp09-01-backup-configuration.py
bash cp09-03/tests/test-cp09-03.sh
python3 cp09-02/tests/test-cp09-02-backup-access.py
python3 cp09-03/tests/test-cp09-03-backup-replication.py
bash sc08-02/tests/test-sc8-safety.sh
bash sc08-02/tests/test-sc08-02-in-transit-encryption.sh
python3 sc08-02/tests/test-sc08-02-in-transit.py
bash sc28/tests/test-encryption-at-rest.sh
python3 sc28/tests/test-sc28-encryption-at-rest.py
bash cm07-01/tests/test-cm07-01-open-ports.sh
bash cm07-01/tests/test-cm07-01-corrective.sh
python3 cm07-01/tests/test-cm07-01-open-ports.py
python3 si04-01/tests/test-si04-01-siem-crowdstrike-forwarding.py
bash cm11-01/tests/test-cm11-01-software-installation-control.sh
python3 cm11-01/tests/test-cm11-01-software-control.py
bash cm02-01/tests/test-cm02-01-configuration-baseline.sh
bash cm08-01/tests/test-cm08-01-component-inventory.sh
python3 cm02-01/tests/test-cm02-cm08-baseline-inventory.py
python3 ra05-01/tests/test-ra05-01-vulnerability-tracking.py
python3 ca07-01/tests/test-ca07-01-continuous-monitoring.py
python3 cp02-01/tests/test-cp02-01-contingency-planning.py
python3 cp04-01/tests/test-cp04-01-contingency-plan-testing.py

echo "PASS: CP-9, CP-2, CP-4, SC-8, SC-28, CM-7, CM-11, CM-2, CM-8, RA-5, SI-4 and CA-7 static, read-only and mock test suite"
