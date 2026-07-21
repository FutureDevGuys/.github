from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / ".github/scripts/security_contract_governance.py"
SPEC = importlib.util.spec_from_file_location("security_contract_governance", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SOURCE}")
governance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = governance
SPEC.loader.exec_module(governance)

FIXTURE = json.loads(
    (
        REPO_ROOT
        / ".github/tests/fixtures/security-contract-governance-live.json"
    ).read_text(encoding="utf-8")
)
POLICY_PATH = REPO_ROOT / ".github/security-contract-governance.json"
TEST_REVISION = "HEAD"

# The fixture models the live API shape, while its default-branch SHA belongs to
# the exact checkout under test. This keeps the contract valid for PR merge
# commits and future main commits without weakening the production audit's
# explicit origin/main latch.
FIXTURE["main_ref"]["object"]["sha"] = governance.exact_revision(
    REPO_ROOT, TEST_REVISION
)


class FixtureClient:
    def __init__(self, fixture=None, *, missing_release=False):
        self.fixture = copy.deepcopy(fixture or FIXTURE)
        self.missing_release = missing_release
        self.calls = []

    def api(self, endpoint, *, method="GET", payload=None):
        self.calls.append((method, endpoint, payload))
        if endpoint == "repos/FutureDevGuys/.github":
            return self.fixture["repository"]
        if endpoint.endswith("/git/ref/heads/main"):
            return self.fixture["main_ref"]
        if endpoint.endswith("/git/ref/heads/security-contract-v1"):
            if self.missing_release:
                raise governance.ApiError(endpoint, 404)
            return self.fixture["release_ref"]
        if endpoint.endswith("/commits/032d7dc24158b3c7fe52c393028b71d5c030ffdd"):
            return self.fixture["release_commit"]
        if "/compare/" in endpoint:
            return self.fixture["ancestry"]
        if endpoint.endswith("/protection/required_signatures"):
            return self.fixture["required_signatures"]
        if endpoint.endswith("/protection"):
            return self.fixture["protection"]
        raise AssertionError(f"unexpected endpoint: {method} {endpoint}")


class FailingBootstrapClient(FixtureClient):
    def __init__(self):
        super().__init__(missing_release=True)

    def api(self, endpoint, *, method="GET", payload=None):
        if method == "POST" and endpoint.endswith("/git/refs"):
            self.calls.append((method, endpoint, payload))
            self.missing_release = False
            return self.fixture["release_ref"]
        if method == "PUT" and endpoint.endswith(
            "/branches/security-contract-v1/protection"
        ):
            self.calls.append((method, endpoint, payload))
            return self.fixture["protection"]
        if method == "POST" and endpoint.endswith(
            "/branches/security-contract-v1/protection/required_signatures"
        ):
            self.calls.append((method, endpoint, payload))
            raise governance.ApiError(endpoint, 503)
        return super().api(endpoint, method=method, payload=payload)


class MissingSignatureProtectionClient(FixtureClient):
    def api(self, endpoint, *, method="GET", payload=None):
        if method == "GET" and endpoint.endswith("/protection/required_signatures"):
            self.calls.append((method, endpoint, payload))
            raise governance.ApiError(endpoint, 404)
        return super().api(endpoint, method=method, payload=payload)


class GovernanceContractTests(unittest.TestCase):
    def setUp(self):
        self.policy = governance.load_policy(POLICY_PATH)
        self.resolution = governance.resolve_bundle(
            REPO_ROOT, self.policy, TEST_REVISION
        )

    def test_live_fixture_proves_exact_signed_protected_authority(self):
        authority, findings = governance.audit_authority(
            FixtureClient(), self.policy, self.resolution
        )
        self.assertEqual(findings, [])
        self.assertTrue(authority["default_ref_exact"])
        self.assertTrue(authority["release_ref_exact"])
        self.assertTrue(authority["release_commit_signature_verified"])
        self.assertTrue(authority["release_ancestor_of_default"])
        self.assertTrue(authority["default_protection"]["contract_exact"])
        self.assertTrue(authority["release_protection"]["contract_exact"])
        self.assertEqual(
            authority["release_protection"]["required_status_checks"], "absent"
        )

    def test_resolver_selects_newest_manifest_closed_bundle_commit(self):
        self.assertEqual(
            self.resolution["release_revision"],
            "032d7dc24158b3c7fe52c393028b71d5c030ffdd",
        )
        self.assertTrue(self.resolution["manifest_closed"])
        self.assertEqual(
            {item["path"] for item in self.resolution["files"]},
            set(self.policy.paths),
        )
        self.assertTrue(all(item["mode"] == "100644" for item in self.resolution["files"]))

    def test_automerge_authority_resolves_the_immutable_protected_release(self):
        resolution, authority, findings = governance.audit_approved_release(
            FixtureClient(), REPO_ROOT, self.policy
        )
        self.assertEqual(findings, [])
        self.assertEqual(
            resolution["release_revision"],
            "032d7dc24158b3c7fe52c393028b71d5c030ffdd",
        )
        self.assertEqual(
            resolution["default_revision"],
            governance.exact_revision(REPO_ROOT, TEST_REVISION),
        )
        self.assertTrue(resolution["manifest_closed"])
        self.assertTrue(authority["release_ref_exact"])
        self.assertTrue(authority["release_commit_signature_verified"])
        self.assertTrue(authority["release_protection"]["contract_exact"])

    def test_automerge_authority_rejects_release_movement_between_checks(self):
        resolution, _, findings = governance.audit_approved_release(
            FixtureClient(), REPO_ROOT, self.policy, "1" * 40
        )
        self.assertEqual(
            resolution["release_revision"],
            "032d7dc24158b3c7fe52c393028b71d5c030ffdd",
        )
        self.assertIn(
            "approved_release_advanced", {item["code"] for item in findings}
        )

    def test_automerge_authority_rejects_a_malformed_expected_revision(self):
        with self.assertRaisesRegex(governance.GovernanceError, "exact commit SHA"):
            governance.audit_approved_release(
                FixtureClient(), REPO_ROOT, self.policy, "security-contract-v1"
            )

    def test_missing_release_ref_fails_visibly(self):
        authority, findings = governance.audit_authority(
            FixtureClient(missing_release=True), self.policy, self.resolution
        )
        self.assertFalse(authority["release_ref_exact"])
        self.assertIn("release_ref_missing", {item["code"] for item in findings})

    def test_wrong_release_revision_fails_visibly(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture["release_ref"]["object"]["sha"] = "1" * 40
        authority, findings = governance.audit_authority(
            FixtureClient(fixture), self.policy, self.resolution
        )
        self.assertFalse(authority["release_ref_exact"])
        self.assertIn("release_ref_drift", {item["code"] for item in findings})

    def test_remote_main_movement_invalidates_the_audit_snapshot(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture["main_ref"]["object"]["sha"] = "1" * 40
        authority, findings = governance.audit_authority(
            FixtureClient(fixture), self.policy, self.resolution
        )
        self.assertFalse(authority["default_ref_exact"])
        self.assertIn("default_ref_drift", {item["code"] for item in findings})

    def test_unsigned_release_commit_fails_visibly(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture["release_commit"]["commit"]["verification"] = {
            "verified": False,
            "reason": "unsigned",
        }
        authority, findings = governance.audit_authority(
            FixtureClient(fixture), self.policy, self.resolution
        )
        self.assertFalse(authority["release_commit_signature_verified"])
        self.assertIn("release_commit_unverified", {item["code"] for item in findings})

    def test_non_ancestor_release_fails_visibly(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture["ancestry"]["status"] = "diverged"
        authority, findings = governance.audit_authority(
            FixtureClient(fixture), self.policy, self.resolution
        )
        self.assertFalse(authority["release_ancestor_of_default"])
        self.assertIn("release_not_ancestor", {item["code"] for item in findings})

    def test_every_protection_dimension_fails_closed(self):
        mutations = (
            ("required_signatures", "enabled", False),
            ("protection.enforce_admins", "enabled", False),
            ("protection.required_linear_history", "enabled", False),
            ("protection.allow_force_pushes", "enabled", True),
            ("protection.allow_deletions", "enabled", True),
        )
        for dotted, field, value in mutations:
            with self.subTest(dotted=dotted):
                fixture = copy.deepcopy(FIXTURE)
                target = fixture
                for part in dotted.split("."):
                    target = target[part]
                target[field] = value
                authority, findings = governance.audit_authority(
                    FixtureClient(fixture), self.policy, self.resolution
                )
                self.assertFalse(authority["release_protection"]["contract_exact"])
                self.assertIn(
                    "branch_protection_drift", {item["code"] for item in findings}
                )

    def test_missing_required_signatures_endpoint_means_disabled_not_unknown(self):
        authority, findings = governance.audit_authority(
            MissingSignatureProtectionClient(), self.policy, self.resolution
        )
        self.assertFalse(authority["release_protection"]["required_signatures"])
        self.assertIn("branch_protection_drift", {item["code"] for item in findings})

    def test_configured_status_checks_are_not_claimed_while_billing_blocks_jobs(self):
        fixture = copy.deepcopy(FIXTURE)
        fixture["protection"]["required_status_checks"] = {
            "strict": True,
            "contexts": ["security-contract"],
        }
        authority, findings = governance.audit_authority(
            FixtureClient(fixture), self.policy, self.resolution
        )
        self.assertEqual(
            authority["release_protection"]["required_status_checks"], "configured"
        )
        self.assertIn("branch_protection_drift", {item["code"] for item in findings})

    def test_dynamic_and_undeclared_local_imports_fail_closed(self):
        with self.assertRaisesRegex(governance.GovernanceError, "dynamic imports"):
            governance.python_dependencies(
                ".github/scripts/example.py",
                b"import importlib\nimportlib.import_module('hidden')\n",
                {"hidden": ".github/scripts/hidden.py"},
            )
        dependencies = governance.python_dependencies(
            ".github/scripts/example.py",
            b"import hidden\n",
            {"hidden": ".github/scripts/hidden.py"},
        )
        self.assertEqual(dependencies, {".github/scripts/hidden.py"})
        self.assertNotIn(".github/scripts/hidden.py", self.policy.paths)

    def test_audit_receipt_detects_report_tampering(self):
        authority, findings = governance.audit_authority(
            FixtureClient(), self.policy, self.resolution
        )
        report = governance.build_report(
            self.policy, self.resolution, authority, findings
        )
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            receipt_path = Path(temporary) / "receipt.json"
            governance.write_atomic(report_path, report)
            governance.write_atomic(
                receipt_path,
                governance.build_receipt(self.policy, report_path, report),
            )
            self.assertEqual(
                governance.validate_evidence(self.policy, report_path, receipt_path),
                [],
            )
            report["authority"]["release_ref_exact"] = False
            governance.write_atomic(report_path, report)
            errors = governance.validate_evidence(
                self.policy, report_path, receipt_path
            )
            self.assertIn("report authority does not prove release_ref_exact", errors)
            self.assertIn("receipt artifact digest does not match", errors)

    def test_release_plan_is_digest_bound_and_noops_the_existing_ref(self):
        plan = governance.make_release_plan(
            FixtureClient(), REPO_ROOT, self.policy, TEST_REVISION
        )
        governance.validate_plan(plan, self.policy, plan["plan_digest"])
        names = [operation["operation"] for operation in plan["operations"]]
        self.assertNotIn("create_release_ref", names)
        self.assertNotIn("fast_forward_release_ref", names)
        self.assertEqual(names, ["audit_postcondition"])
        with self.assertRaisesRegex(governance.GovernanceError, "approved digest"):
            governance.validate_plan(plan, self.policy, "0" * 64)

    def test_bootstrap_plan_creates_then_protects_and_audits_release_ref(self):
        plan = governance.make_release_plan(
            FixtureClient(missing_release=True), REPO_ROOT, self.policy, TEST_REVISION
        )
        names = [operation["operation"] for operation in plan["operations"]]
        self.assertEqual(
            names,
            [
                "create_release_ref",
                "protect_branch",
                "require_signatures",
                "audit_postcondition",
            ],
        )
        self.assertLess(names.index("create_release_ref"), names.index("audit_postcondition"))

    def test_approved_noop_apply_still_requires_the_remote_postcondition(self):
        client = FixtureClient()
        plan = governance.make_release_plan(
            client, REPO_ROOT, self.policy, TEST_REVISION
        )
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "apply-receipt.json"
            self.assertEqual(
                governance.apply_release_plan(
                    client, REPO_ROOT, self.policy, plan, receipt
                ),
                0,
            )
            evidence = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(evidence["result"], {"status": "pass", "error_code": None})
        self.assertEqual(
            evidence["completed_operations"],
            [{"operation": "audit_postcondition", "status": "completed"}],
        )
        self.assertTrue(all(method == "GET" for method, _, _ in client.calls))

    def test_apply_rejects_a_digest_valid_but_noncanonical_operation_list(self):
        client = FixtureClient()
        plan = governance.make_release_plan(
            client, REPO_ROOT, self.policy, TEST_REVISION
        )
        unsigned = {key: value for key, value in plan.items() if key != "plan_digest"}
        unsigned["operations"] = [
            {"operation": "protect_branch", "branch": "unexpected"},
            {"operation": "audit_postcondition"},
        ]
        tampered = {
            **unsigned,
            "plan_digest": governance.sha256(governance.canonical_json(unsigned)),
        }
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "apply-receipt.json"
            self.assertEqual(
                governance.apply_release_plan(
                    client, REPO_ROOT, self.policy, tampered, receipt
                ),
                1,
            )
            evidence = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(evidence["result"]["status"], "fail")
        self.assertEqual(evidence["completed_operations"], [])

    def test_bootstrap_failure_after_ref_creation_is_retained_not_silent(self):
        client = FailingBootstrapClient()
        plan = governance.make_release_plan(
            client, REPO_ROOT, self.policy, TEST_REVISION
        )
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "apply-receipt.json"
            self.assertEqual(
                governance.apply_release_plan(
                    client, REPO_ROOT, self.policy, plan, receipt
                ),
                1,
            )
            evidence = json.loads(receipt.read_text(encoding="utf-8"))
        self.assertEqual(evidence["result"]["status"], "fail")
        self.assertEqual(
            evidence["completed_operations"],
            [
                {"operation": "create_release_ref", "status": "completed"},
                {"operation": "protect_branch", "status": "completed"},
            ],
        )

    def test_workflow_is_read_only_and_retains_validated_receipts(self):
        workflow = (
            REPO_ROOT / ".github/workflows/security-contract.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(workflow.count("security_contract_governance.py"), 2)
        self.assertIn("\n          audit\n", workflow)
        self.assertIn("\n          validate\n", workflow)
        self.assertIn("if-no-files-found: error", workflow)
        self.assertIn("security-contract-governance-receipt.json", workflow)
        self.assertIn("fetch-depth: 0", workflow)
        self.assertNotIn("apply-release", workflow)


if __name__ == "__main__":
    unittest.main()
