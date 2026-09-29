#!/usr/bin/env python3
"""Focused regressions for the OCI network gap collector."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_DIR = ROOT / "python-sdk" / "environment-gap-analysis"
sys.path.insert(0, str(COLLECTOR_DIR))
sys.path.insert(0, str(ROOT / "lib"))

import gap_common as common  # noqa: E402


def load_collector():
    spec = importlib.util.spec_from_file_location(
        "oci_network_gap", COLLECTOR_DIR / "oci-network-gap-analysis.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load collector")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gap = load_collector()


class NetworkGapTests(unittest.TestCase):
    def setUp(self):
        self.old = gap.parse_networks(["172.16.0.0/16"], "old")
        self.new = gap.parse_networks(["10.0.0.0/8"], "new")

    def test_selfcheck_and_method_boundary(self):
        self.assertTrue(
            gap.source_selfcheck(gap.SCRIPT_PATH, gap.COLLECTOR, gap.SDK_READ_METHODS)
        )
        self.assertTrue(
            all(name.startswith(("list_", "get_")) for name in gap.SDK_READ_METHODS)
        )

    def test_old_new_and_mixed_network_classification(self):
        self.assertEqual(
            gap.classify_values(["172.16.20.0/24"], [], self.old, self.new)[0],
            "OLD-172.16",
        )
        self.assertEqual(
            gap.classify_values([], ["10.22.1.9"], self.old, self.new)[0],
            "NEW-10",
        )
        self.assertEqual(
            gap.classify_values(
                ["172.16.1.0/24", "10.2.0.0/16"], [], self.old, self.new
            )[0],
            "MIXED-OLD-NEW",
        )

    def test_custom_cidr_validation(self):
        with self.assertRaisesRegex(ValueError, "invalid old CIDR"):
            gap.parse_networks(["172.16-not-a-cidr"], "old")
        self.assertEqual(
            str(gap.parse_networks(["172.16.32.0/20"], "old")[0]), "172.16.32.0/20"
        )
        with self.assertRaisesRegex(ValueError, "overlaps"):
            gap.validate_network_sets(
                gap.parse_networks(["10.0.0.0/8"], "old"),
                gap.parse_networks(["10.20.0.0/16"], "new"),
            )

    def test_requested_work_has_an_exact_sdk_plan(self):
        methods = gap.methods_for_work(["load-balancers"])
        self.assertTrue(gap.IDENTITY_SCOPE_METHODS.issubset(methods))
        self.assertTrue(gap.LB_METHODS.issubset(methods))
        self.assertNotIn("list_db_systems", methods)
        self.assertNotIn("list_mount_targets", methods)
        self.assertNotIn("get_vnic", gap.methods_for_work(["core-network"]))
        self.assertIn("get_vnic", gap.methods_for_work(["compute"]))

    def test_keyword_only_nsg_and_required_fss_availability_domain_calls(self):
        scope = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")

        class FakeRuntime:
            def __init__(self):
                self.context = SimpleNamespace(tenancy_id=scope.ocid)
                self.calls = []

            def client(self, namespace, class_name):
                return (namespace, class_name)

            def list_items(self, scan_scope, service, client, method, *args, **kwargs):
                self.calls.append((method, args, kwargs))
                if method == "list_vcns":
                    return [
                        SimpleNamespace(
                            id="ocid1.vcn.oc1..vcn",
                            display_name="vcn",
                            compartment_id=scope.ocid,
                            cidr_block="172.16.0.0/16",
                            cidr_blocks=["172.16.0.0/16"],
                        )
                    ]
                if method == "list_availability_domains":
                    return [SimpleNamespace(name="TEST-AD-1")]
                return []

        runtime = FakeRuntime()
        inventory = gap.Inventory({scope.ocid: scope.name})
        gap.collect_core_network(runtime, inventory, [scope])
        nsg_call = next(
            call for call in runtime.calls if call[0] == "list_network_security_groups"
        )
        self.assertEqual(nsg_call[1], ())
        self.assertEqual(nsg_call[2], {"compartment_id": scope.ocid})

        runtime.calls.clear()
        gap.collect_platform(runtime, inventory, [scope])
        fss_call = next(
            call for call in runtime.calls if call[0] == "list_mount_targets"
        )
        self.assertEqual(fss_call[1], (scope.ocid, "TEST-AD-1"))

    def test_refused_plan_makes_no_workload_client_and_no_evidence(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        compartment = gap.ScopeItem(
            "ocid1.compartment.oc1..app", "App", "COMPARTMENT", tenancy.ocid
        )
        context = SimpleNamespace(
            auth_label="TEST", profile="DEFAULT", tenancy_id=tenancy.ocid
        )
        clients = []

        def fake_client(oci, auth, namespace, class_name, **kwargs):
            clients.append((namespace, class_name))
            return object()

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "not-created"
            with (
                patch.object(common, "load_oci", return_value=object()),
                patch.object(common, "build_auth_context", return_value=context),
                patch.object(common, "build_client", side_effect=fake_client),
                patch.object(
                    common, "discover_scope", return_value=[tenancy, compartment]
                ),
                patch(
                    "builtins.input",
                    side_effect=[
                        compartment.ocid,
                        compartment.ocid,
                        compartment.ocid,
                        compartment.ocid,
                        "no",
                    ],
                ),
            ):
                result = gap.main(
                    [
                        "--region",
                        "us-test-1",
                        "--compartment-id",
                        compartment.ocid,
                        "--output-dir",
                        str(output),
                        "--old-landing-zone-compartment-id",
                        compartment.ocid,
                    ]
                )
            self.assertEqual(result, 2)
            self.assertEqual(clients, [("identity", "IdentityClient")])
            self.assertFalse(output.exists())

    def test_automation_requires_old_landing_zone_confirmation(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        compartment = gap.ScopeItem(
            "ocid1.compartment.oc1..old", "Old LZ", "COMPARTMENT", tenancy.ocid
        )
        context = SimpleNamespace(
            auth_label="TEST", profile="DEFAULT", tenancy_id=tenancy.ocid
        )
        clients = []

        def fake_client(oci, auth, namespace, class_name, **kwargs):
            clients.append((namespace, class_name))
            return object()

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "not-created"
            with (
                patch.object(common, "load_oci", return_value=object()),
                patch.object(common, "build_auth_context", return_value=context),
                patch.object(common, "build_client", side_effect=fake_client),
                patch.object(
                    common, "discover_scope", return_value=[tenancy, compartment]
                ),
            ):
                result = gap.main(
                    [
                        "--region",
                        "us-test-1",
                        "--compartment-id",
                        compartment.ocid,
                        "--non-interactive",
                        "--confirm-scope-ocid",
                        compartment.ocid,
                        "--approve-scan",
                        "YES",
                        "--old-landing-zone-compartment-id",
                        compartment.ocid,
                        "--output-dir",
                        str(output),
                    ]
                )
            self.assertEqual(result, 2)
            self.assertEqual(clients, [("identity", "IdentityClient")])
            self.assertFalse(output.exists())

    def test_automation_accepts_exact_old_landing_zone_confirmation(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        compartment = gap.ScopeItem(
            "ocid1.compartment.oc1..old", "Old LZ", "COMPARTMENT", tenancy.ocid
        )
        context = SimpleNamespace(
            auth_label="TEST", profile="DEFAULT", tenancy_id=tenancy.ocid
        )
        args = SimpleNamespace(
            region="us-test-1",
            auth="config",
            profile="DEFAULT",
            output_dir="",
            compartment_id=[compartment.ocid],
            compartment_names="",
            tenancy_scope=False,
            select_scope=False,
            non_interactive=True,
            confirm_scope_ocid=[compartment.ocid],
            approve_scan="YES",
        )
        with tempfile.TemporaryDirectory() as temp:
            args.output_dir = str(Path(temp) / "evidence")
            plan_path = str(Path(args.output_dir) / "approved-plan.txt")
            with (
                patch.object(common, "load_oci", return_value=object()),
                patch.object(common, "build_auth_context", return_value=context),
                patch.object(common, "build_client", return_value=object()),
                patch.object(
                    common, "discover_scope", return_value=[tenancy, compartment]
                ),
            ):
                _, _, _, selected, targets = common.begin_run(
                    args,
                    collector="TEST",
                    controls="TEST",
                    title="TEST",
                    work=("core-network",),
                    methods={"list_vcns"},
                    outputs={"plan": plan_path},
                    extra_scope_ocids=[compartment.ocid],
                    extra_confirm_ocids=[compartment.ocid],
                    extra_scope_label="old landing-zone compartment",
                    require_extra_descendants_in_targets=True,
                )
            self.assertEqual(selected.ocid, compartment.ocid)
            self.assertEqual([item.ocid for item in targets], [compartment.ocid])
            self.assertTrue(Path(plan_path).is_file())

    def test_old_landing_zone_requires_discovered_descendants_in_scan(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        landing = gap.ScopeItem(
            "ocid1.compartment.oc1..landing",
            "Old LZ",
            "COMPARTMENT",
            tenancy.ocid,
        )
        child = gap.ScopeItem(
            "ocid1.compartment.oc1..child",
            "Child",
            "COMPARTMENT",
            landing.ocid,
        )
        context = SimpleNamespace(
            auth_label="TEST", profile="DEFAULT", tenancy_id=tenancy.ocid
        )
        args = SimpleNamespace(
            region="us-test-1",
            auth="config",
            profile="DEFAULT",
            output_dir="unused",
            compartment_id=[landing.ocid],
            compartment_names="",
            tenancy_scope=False,
            select_scope=False,
            non_interactive=False,
            confirm_scope_ocid=[],
            approve_scan="",
        )
        with (
            patch.object(common, "load_oci", return_value=object()),
            patch.object(common, "build_auth_context", return_value=context),
            patch.object(common, "build_client", return_value=object()),
            patch.object(
                common, "discover_scope", return_value=[tenancy, landing, child]
            ),
            patch("builtins.input", side_effect=[landing.ocid, landing.ocid]),
        ):
            with self.assertRaisesRegex(ValueError, "omit discovered descendants"):
                common.begin_run(
                    args,
                    collector="TEST",
                    controls="TEST",
                    title="TEST",
                    work=("core-network",),
                    methods={"list_vcns"},
                    outputs={"plan": "unused"},
                    extra_scope_ocids=[landing.ocid],
                    extra_scope_label="old landing-zone compartment",
                    require_extra_descendants_in_targets=True,
                )

    def test_cutoff_is_strictly_before_2026(self):
        cutoff = gap.parse_cutoff("2026-01-01")
        self.assertEqual(
            gap.age_status("2025-12-31T23:59:59Z", cutoff), ("YES", "PRE-CUTOFF")
        )
        self.assertEqual(
            gap.age_status("2026-01-01T00:00:00Z", cutoff), ("NO", "AT-OR-AFTER-CUTOFF")
        )
        self.assertEqual(gap.age_status(None, cutoff), ("UNKNOWN", "UNKNOWN"))

    def test_destroy_candidate_requires_complete_tenancy_scan(self):
        args = dict(
            network_class="OLD-172.16",
            before_cutoff="YES",
            unresolved=False,
            tenancy_wide=True,
            collection_complete=True,
        )
        self.assertEqual(
            gap.suggested_disposition(**args)[0], "REVIEW-DESTROY-CANDIDATE"
        )
        args["tenancy_wide"] = False
        self.assertEqual(gap.suggested_disposition(**args)[0], "HOLD-PARTIAL-SCOPE")
        args["tenancy_wide"] = True
        args["collection_complete"] = False
        self.assertEqual(
            gap.suggested_disposition(**args)[0], "HOLD-INCOMPLETE-COVERAGE"
        )
        args["collection_complete"] = True
        args["unresolved"] = True
        self.assertEqual(
            gap.suggested_disposition(**args)[0], "HOLD-UNRESOLVED-DEPENDENCY"
        )

    def test_new_and_shared_resources_are_kept(self):
        common = dict(
            before_cutoff="YES",
            unresolved=False,
            tenancy_wide=True,
            collection_complete=True,
        )
        self.assertEqual(
            gap.suggested_disposition("NEW-10", **common)[0], "KEEP-CANDIDATE"
        )
        self.assertEqual(
            gap.suggested_disposition("MIXED-OLD-NEW", **common)[0], "KEEP-SHARED"
        )
        self.assertEqual(
            gap.suggested_disposition("OLD-172.16-WITH-OTHER", **common)[0],
            "HOLD-OLD-AND-OTHER-NETWORK",
        )

    def test_old_landing_zone_includes_descendants_but_new_network_stays_keep(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        landing = gap.ScopeItem(
            "ocid1.compartment.oc1..landing",
            "Old Landing Zone",
            "COMPARTMENT",
            tenancy.ocid,
        )
        child = gap.ScopeItem(
            "ocid1.compartment.oc1..child",
            "Application",
            "COMPARTMENT",
            landing.ocid,
        )
        other = gap.ScopeItem(
            "ocid1.compartment.oc1..other",
            "Other",
            "COMPARTMENT",
            tenancy.ocid,
        )
        membership = gap.landing_zone_membership(
            [tenancy, landing, child, other], [landing.ocid]
        )
        self.assertEqual(membership[landing.ocid], {landing.ocid})
        self.assertEqual(membership[child.ocid], {landing.ocid})
        self.assertNotIn(other.ocid, membership)

        common_args = dict(
            before_cutoff="YES",
            unresolved=False,
            tenancy_wide=True,
            collection_complete=True,
            old_landing_zone=True,
        )
        self.assertEqual(
            gap.suggested_disposition("UNRESOLVED", **common_args)[0],
            "REVIEW-OLD-LANDING-ZONE-CANDIDATE",
        )
        self.assertEqual(
            gap.suggested_disposition("NEW-10", **common_args)[0],
            "KEEP-CANDIDATE",
        )

    def test_dependency_propagation_and_unresolved_hold(self):
        scope = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        inventory = gap.Inventory({scope.ocid: scope.name})
        vcn = SimpleNamespace(
            id="ocid1.vcn.oc1..old",
            display_name="old-vcn",
            compartment_id=scope.ocid,
            lifecycle_state="AVAILABLE",
            time_created=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
        subnet = SimpleNamespace(
            id="ocid1.subnet.oc1..old",
            display_name="old-subnet",
            compartment_id=scope.ocid,
            lifecycle_state="AVAILABLE",
            time_created=datetime(2024, 2, 1, tzinfo=timezone.utc),
        )
        instance = SimpleNamespace(
            id="ocid1.instance.oc1..old",
            display_name="old-instance",
            compartment_id=scope.ocid,
            lifecycle_state="RUNNING",
            time_created=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        inventory.add("VCN", vcn, scope, cidrs=("172.16.0.0/16",))
        inventory.add(
            "SUBNET", subnet, scope, vcn_ocids=(vcn.id,), cidrs=("172.16.1.0/24",)
        )
        instance_resource = inventory.add("COMPUTE_INSTANCE", instance, scope)
        inventory.link(instance_resource.key, "USES-SUBNET", subnet.id)
        gap.resolve_networks(inventory, self.old, self.new)
        self.assertEqual(
            inventory.resources[instance_resource.key].network_class, "OLD-172.16"
        )

        missing = SimpleNamespace(
            id="ocid1.instance.oc1..missing",
            display_name="missing-dependency",
            compartment_id=scope.ocid,
            lifecycle_state="RUNNING",
            time_created=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        missing_resource = inventory.add("COMPUTE_INSTANCE", missing, scope)
        inventory.link(
            missing_resource.key, "USES-SUBNET", "ocid1.subnet.oc1..not-visible"
        )
        gap.resolve_networks(inventory, self.old, self.new)
        rows, _, unresolved, _ = gap.build_rows(
            inventory,
            gap.parse_cutoff("2026-01-01"),
            tenancy_wide=True,
            collection_complete=True,
        )
        by_id = {row["resource_ocid"]: row for row in rows}
        self.assertEqual(
            by_id[missing.id]["suggested_disposition"],
            "HOLD-UNRESOLVED-DEPENDENCY",
        )
        self.assertEqual(len(unresolved), 1)

    def test_any_unresolved_reference_closes_the_global_destroy_gate(self):
        scope = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        inventory = gap.Inventory({scope.ocid: scope.name})
        old_vcn = SimpleNamespace(
            id="ocid1.vcn.oc1..old",
            display_name="old-vcn",
            compartment_id=scope.ocid,
            time_created=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        unrelated = SimpleNamespace(
            id="ocid1.instance.oc1..unresolved",
            display_name="unresolved-instance",
            compartment_id=scope.ocid,
            time_created=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        inventory.add("VCN", old_vcn, scope, cidrs=("172.16.0.0/16",))
        unrelated_resource = inventory.add("COMPUTE_INSTANCE", unrelated, scope)
        inventory.link(
            unrelated_resource.key,
            "USES-SUBNET",
            "ocid1.subnet.oc1..not-visible",
        )
        gap.resolve_networks(inventory, self.old, self.new)
        complete = gap.decision_gate_complete(inventory, gap.WORK, [])
        self.assertFalse(complete)
        rows, _, _, _ = gap.build_rows(
            inventory,
            gap.parse_cutoff("2026-01-01"),
            tenancy_wide=True,
            collection_complete=complete,
        )
        by_id = {row["resource_ocid"]: row for row in rows}
        self.assertEqual(
            by_id[old_vcn.id]["suggested_disposition"],
            "HOLD-INCOMPLETE-COVERAGE",
        )

    def test_compute_resolves_cross_compartment_volume_and_fetches_vnic_once(self):
        tenancy = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        app = gap.ScopeItem(
            "ocid1.compartment.oc1..app", "App", "COMPARTMENT", tenancy.ocid
        )
        storage = gap.ScopeItem(
            "ocid1.compartment.oc1..storage",
            "Storage",
            "COMPARTMENT",
            tenancy.ocid,
        )
        instance_id = "ocid1.instance.oc1..instance"
        volume_id = "ocid1.volume.oc1..volume"
        vnic_id = "ocid1.vnic.oc1..vnic"

        class FakeRuntime:
            def __init__(self):
                self.context = SimpleNamespace(tenancy_id=tenancy.ocid)
                self.get_calls = []

            def client(self, namespace, class_name):
                return (namespace, class_name)

            def list_items(self, scope, service, client, method, *args, **kwargs):
                if method == "list_availability_domains":
                    return []
                if method == "list_volumes" and scope.ocid == storage.ocid:
                    return [
                        SimpleNamespace(
                            id=volume_id,
                            display_name="volume",
                            compartment_id=storage.ocid,
                        )
                    ]
                if method == "list_instances" and scope.ocid == app.ocid:
                    return [
                        SimpleNamespace(
                            id=instance_id,
                            display_name="instance",
                            compartment_id=app.ocid,
                        )
                    ]
                if method == "list_volume_attachments" and scope.ocid == app.ocid:
                    return [
                        SimpleNamespace(volume_id=volume_id, instance_id=instance_id)
                    ]
                if method == "list_vnic_attachments" and scope.ocid == app.ocid:
                    return [SimpleNamespace(vnic_id=vnic_id, instance_id=instance_id)]
                return []

            def get_item(self, scope, service, client, method, *args, **kwargs):
                self.get_calls.append((method, args, kwargs))
                return SimpleNamespace(
                    id=vnic_id,
                    display_name="vnic",
                    compartment_id=app.ocid,
                    private_ip="172.16.1.10",
                )

        runtime = FakeRuntime()
        inventory = gap.Inventory(
            {item.ocid: item.name for item in (tenancy, app, storage)}
        )
        gap.collect_compute(runtime, inventory, [app, storage])
        self.assertEqual(len(runtime.get_calls), 1)
        volume_key = inventory.ocid_to_key[volume_id]
        self.assertIn(
            gap.Link(
                volume_key,
                "BLOCK-VOLUME-ATTACHED-TO-INSTANCE",
                instance_id,
            ),
            inventory.links,
        )

    def test_missing_fss_relationships_are_explicitly_unresolved(self):
        scope = gap.ScopeItem("ocid1.tenancy.oc1..root", "root", "TENANCY")
        export_id = "ocid1.export.oc1..export"
        file_system_id = "ocid1.filesystem.oc1..missing"
        export_set_id = "ocid1.exportset.oc1..missing"

        class FakeRuntime:
            def __init__(self):
                self.context = SimpleNamespace(tenancy_id=scope.ocid)

            def client(self, namespace, class_name):
                return (namespace, class_name)

            def list_items(self, scan_scope, service, client, method, *args, **kwargs):
                if method == "list_availability_domains":
                    return []
                if method == "list_exports":
                    return [
                        SimpleNamespace(
                            id=export_id,
                            display_name="export",
                            compartment_id=scope.ocid,
                            file_system_id=file_system_id,
                            export_set_id=export_set_id,
                        )
                    ]
                return []

        inventory = gap.Inventory({scope.ocid: scope.name})
        gap.collect_platform(FakeRuntime(), inventory, [scope])
        gap.resolve_networks(inventory, self.old, self.new)
        export = inventory.resources[inventory.ocid_to_key[export_id]]
        self.assertEqual(
            export.unresolved_refs,
            {file_system_id, export_set_id},
        )


if __name__ == "__main__":
    unittest.main()
