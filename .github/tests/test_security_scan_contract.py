from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, relative_path: str):
    path = REPO_ROOT / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


builder = load_module("build_scan_result", ".github/scripts/build_scan_result.py")
validator = load_module("validate_scan_result", ".github/scripts/validate_scan_result.py")
adoption = load_module(
    "audit_security_scan_adoption",
    ".github/scripts/audit_security_scan_adoption.py",
)


class ScanResultContractTests(unittest.TestCase):
    def receipt(
        self,
        root: Path,
        *,
        outcome: str = "success",
        report_fixture: str = "trivy-clean.json",
    ):
        report = root / "trivy-results.json"
        fixture = REPO_ROOT / ".github/tests/fixtures" / report_fixture
        report.write_bytes(fixture.read_bytes())
        config = root / "trivy.yaml"
        config.write_text("severity: [HIGH, CRITICAL]\n", encoding="utf-8")
        ignore = root / ".trivyignore.yaml"
        ignore.write_text("# intentionally empty\n", encoding="utf-8")
        args = argparse.Namespace(
            report=report,
            scan_outcome=outcome,
            tool_version="Version: 1.2.3",
            repository="FutureDevGuys/example",
            ref="refs/heads/main",
            commit="1" * 40,
            event="push",
            workflow_revision="2" * 40,
            config=config,
            ignore_file=ignore,
        )
        return builder.build_receipt(args), report

    def test_real_clean_report_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            self.assertEqual(validator.validate_receipt(receipt, report), [])

    def test_executed_false_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            receipt["executed"] = False
            self.assertIn("executed must be true", validator.validate_receipt(receipt, report))

    def test_skipped_scan_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp), outcome="skipped")
            errors = validator.validate_receipt(receipt, report)
            self.assertIn("executed must be true", errors)
            self.assertIn("scan result is not clean: skipped", errors)

    def test_missing_report_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            report.unlink()
            errors = validator.validate_receipt(receipt, report)
            self.assertTrue(any("report file is missing" in error for error in errors))

    def test_report_digest_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            report.write_text(
                '{"SchemaVersion": 2, "Results": [{"Target": "changed"}]}\n',
                encoding="utf-8",
            )
            errors = validator.validate_receipt(receipt, report)
            self.assertIn("report digest does not match the uploaded report", errors)

    def test_empty_object_report_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(
                Path(temp), report_fixture="trivy-empty-object.json"
            )
            errors = validator.validate_receipt(receipt, report)
            self.assertIn("report.schema_version must be 2", errors)
            self.assertIn("report Results must be a list", errors)
            self.assertIn("scan result is not clean: error", errors)

    def test_wrong_trivy_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(
                Path(temp), report_fixture="trivy-wrong-schema.json"
            )
            errors = validator.validate_receipt(receipt, report)
            self.assertIn("report.schema_version must be 2", errors)
            self.assertIn("report SchemaVersion must be 2", errors)
            self.assertIn("scan result is not clean: error", errors)

    def test_non_commit_input_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            receipt["input"]["commit"] = "main"
            self.assertIn(
                "input.commit must be an exact 40-character lowercase commit SHA",
                validator.validate_receipt(receipt, report),
            )

    def test_workflow_revision_is_bound_to_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            self.assertEqual(receipt["input"]["workflow_revision"], "2" * 40)
            receipt["input"]["workflow_revision"] = "main"
            self.assertIn(
                "input.workflow_revision must be an exact 40-character lowercase commit SHA",
                validator.validate_receipt(receipt, report),
            )

    def test_workflow_context_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            expected = {
                "repository": "FutureDevGuys/example",
                "ref": "refs/heads/main",
                "commit": "1" * 40,
                "event": "push",
                "workflow_revision": "3" * 40,
            }
            self.assertIn(
                "input.workflow_revision does not match the workflow context",
                validator.validate_receipt(receipt, report, expected),
            )

    def test_receipt_cannot_hide_findings_in_uploaded_report(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["Results"].append(
                {
                    "Target": "forged-clean-result",
                    "Vulnerabilities": [{"Severity": "HIGH"}],
                }
            )
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
            report.write_bytes(raw)
            receipt["report"].update(
                {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size_bytes": len(raw),
                    "results_count": len(payload["Results"]),
                }
            )
            errors = validator.validate_receipt(receipt, report)
            self.assertIn("result.high does not match the uploaded report", errors)

    def test_failed_misconfiguration_is_counted_but_pass_is_not(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt, report = self.receipt(Path(temp))
            self.assertEqual(receipt["result"]["critical"], 0)
            payload = json.loads(report.read_text(encoding="utf-8"))
            payload["Results"][0]["Misconfigurations"][0]["Status"] = "FAIL"
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
            report.write_bytes(raw)
            receipt["report"].update(
                {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size_bytes": len(raw),
                }
            )
            errors = validator.validate_receipt(receipt, report)
            self.assertIn(
                "result.critical does not match the uploaded report",
                errors,
            )

    def test_workflows_enforce_all_scanners_with_current_config_schema(self):
        for relative_path in (
            ".github/workflows/security-scan.yml",
            ".github/workflows/security-contract.yml",
        ):
            text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
            self.assertIn("scanners: vuln,misconfig,secret,license", text)
            self.assertIn("severity: HIGH,CRITICAL", text)
            self.assertIn("ignore-unfixed: true", text)

        default_workflow = (
            REPO_ROOT / ".github/workflows/security-scan.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("          vulnerability:\n", default_workflow)
        self.assertIn("          scan:\n", default_workflow)
        self.assertIn("            scanners:\n", default_workflow)


class CallerContractTests(unittest.TestCase):
    def test_adoption_cli_requires_approved_release_revision(self):
        with patch.object(sys, "argv", ["audit-security-scan-adoption"]), patch(
            "sys.stderr", new_callable=io.StringIO
        ):
            with self.assertRaises(SystemExit) as raised:
                adoption.parse_args()
        self.assertEqual(raised.exception.code, 2)

    def test_checked_in_caller_fixture_passes(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        self.assertEqual(adoption.validate_caller(fixture.read_text(encoding="utf-8")), [])

    def test_dependency_bot_skip_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8") + "\n# is_dependency_bot_pr\n"
        self.assertIn(
            "caller must not skip dependency-bot pull requests",
            adoption.validate_caller(text),
        )

    def test_mismatched_revision_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            'workflow_revision: "1111111111111111111111111111111111111111"',
            'workflow_revision: "2222222222222222222222222222222222222222"',
        )
        self.assertIn(
            "workflow_revision must equal the SHA in jobs.trivy.uses",
            adoption.validate_caller(text),
        )

    def test_stale_org_revision_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        errors = adoption.validate_caller(
            fixture.read_text(encoding="utf-8"),
            required_revision="2" * 40,
        )
        self.assertIn(
            "caller revision 1111111111111111111111111111111111111111 does not match required org revision 2222222222222222222222222222222222222222",
            errors,
        )

    def test_trigger_names_outside_on_block_do_not_pass(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "  schedule:\n    - cron: \"0 7 * * 0\"\n",
            "",
        )
        text += "\nnot_on:\n  schedule: {}\n"
        self.assertIn(
            "caller is missing the schedule trigger",
            adoption.validate_caller(text),
        )

    def test_push_main_must_be_in_push_block(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "  push:\n    branches: [main]\n",
            "  push:\n    branches: [develop]\n",
        )
        self.assertIn(
            "caller must constrain its push trigger to main",
            adoption.validate_caller(text),
        )

    def test_push_paths_ignore_cannot_neutralize_the_main_scan(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "  push:\n    branches: [main]\n",
            "  push:\n    branches: [main]\n    paths-ignore: ['**']\n",
        )
        self.assertIn(
            "caller bytes must exactly match the approved organization artifact",
            adoption.validate_caller(text),
        )

    def test_extra_control_cannot_hide_behind_semantically_valid_triggers(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "name: security-scan\n",
            "name: security-scan\nrun-name: harmless-looking override\n",
        )
        self.assertIn(
            "caller bytes must exactly match the approved organization artifact",
            adoption.validate_caller(text),
        )

    def test_conditional_trivy_job_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "  trivy:\n",
            "  trivy:\n    if: false\n",
        )
        self.assertIn(
            "caller trivy job must not have a conditional skip",
            adoption.validate_caller(text),
        )

    def test_revision_outside_with_block_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "    with:\n"
            '      workflow_revision: "1111111111111111111111111111111111111111"\n',
            "    env:\n"
            '      workflow_revision: "1111111111111111111111111111111111111111"\n',
        )
        errors = adoption.validate_caller(text)
        self.assertIn(
            "caller must pass workflow_revision in jobs.trivy.with",
            errors,
        )

    def test_additional_permissions_are_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "permissions:\n  contents: read\n",
            "permissions:\n  contents: read\n  actions: write\n",
            1,
        )
        self.assertIn(
            "workflow permissions must contain only contents: read",
            adoption.validate_caller(text),
        )

    def test_secret_inheritance_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "    permissions:\n      contents: read\n",
            "    permissions:\n      contents: read\n    secrets: inherit\n",
        )
        self.assertIn(
            "caller trivy job must not pass repository secrets",
            adoption.validate_caller(text),
        )

    def test_pull_request_filters_are_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "  pull_request:\n",
            "  pull_request:\n    paths-ignore: ['**/renovate.json']\n",
        )
        self.assertIn(
            "caller pull_request trigger must not filter dependency update PRs",
            adoption.validate_caller(text),
        )

    def test_incomplete_pull_request_types_are_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8").replace(
            "types: [opened, synchronize, reopened, ready_for_review]",
            "types: [opened, reopened]",
        )
        self.assertIn(
            "caller pull_request types must include opened, synchronize, reopened, and ready_for_review",
            adoption.validate_caller(text),
        )

    def test_duplicate_trivy_job_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8")
        duplicate = text + (
            "\n  trivy:\n"
            "    if: false\n"
            "    uses: FutureDevGuys/.github/.github/workflows/security-scan.yml@"
            + "2" * 40
            + "\n"
        )
        self.assertIn(
            "caller jobs mapping must contain exactly one trivy job",
            adoption.validate_caller(duplicate),
        )

    def test_extra_job_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8") + (
            "\n  bypass:\n    runs-on: ubuntu-latest\n    steps: []\n"
        )
        self.assertIn(
            "caller jobs mapping must contain exactly one trivy job",
            adoption.validate_caller(text),
        )

    def test_duplicate_control_mapping_is_rejected(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        text = fixture.read_text(encoding="utf-8") + (
            "\non:\n  pull_request:\n    paths-ignore: ['**']\n"
        )
        self.assertIn(
            "caller must declare on, permissions, and jobs exactly once",
            adoption.validate_caller(text),
        )


class LocalRenovateContractTests(unittest.TestCase):
    def test_label_only_local_config_passes(self):
        text = json.dumps(
            {
                "platformAutomerge": False,
                "packageRules": [
                    {
                        "automerge": False,
                        "addLabels": ["edge"],
                    }
                ],
            }
        )
        self.assertEqual(adoption.validate_renovate_config(text), [])

    def test_local_config_cannot_assign_org_candidate_label(self):
        errors = adoption.validate_renovate_config(
            '{"packageRules": [{"addLabels": ["automerge-candidate"]}]}'
        )
        self.assertIn(
            "renovate.packageRules[0].addLabels must not assign automerge-candidate; the org preset owns merge eligibility",
            errors,
        )

    def test_local_config_cannot_inherit_an_unreviewed_preset(self):
        errors = adoption.validate_renovate_config(
            '{"extends": ["github>attacker/preset:default"]}'
        )
        self.assertIn(
            "renovate.extends must be absent or empty; repository policy cannot inherit unapproved presets",
            errors,
        )

    def test_local_config_cannot_ignore_the_organization_preset(self):
        errors = adoption.validate_renovate_config(
            '{"ignorePresets": ["github>FutureDevGuys/.github:renovate-config"]}'
        )
        self.assertIn(
            "renovate.ignorePresets must not be present; the organization preset is mandatory",
            errors,
        )

    def test_local_config_cannot_hide_preset_controls_in_nested_scopes(self):
        cases = (
            (
                {"extends": ["github>attacker/preset:default"]},
                "renovate.packageRules[0].extends must be absent or empty; repository policy cannot inherit unapproved presets",
            ),
            (
                {"ignorePresets": ["github>FutureDevGuys/.github:renovate-config"]},
                "renovate.packageRules[0].ignorePresets must not be present; the organization preset is mandatory",
            ),
            (
                {"globalExtends": ["github>attacker/preset:default"]},
                "renovate.packageRules[0].globalExtends must not be present; repository policy cannot change preset resolution",
            ),
        )
        for nested, expected in cases:
            with self.subTest(control=next(iter(nested))):
                errors = adoption.validate_renovate_config(
                    json.dumps({"packageRules": [nested]})
                )
                self.assertIn(expected, errors)

    def test_local_extends_null_is_not_treated_as_absent(self):
        self.assertIn(
            "renovate.extends must be absent or empty; repository policy cannot inherit unapproved presets",
            adoption.validate_renovate_config('{"extends": null}'),
        )

    def test_local_config_cannot_remove_org_block_label(self):
        errors = adoption.validate_renovate_config(
            '{"packageRules": [{"removeLabels": ["migration-required"]}]}'
        )
        self.assertIn(
            "renovate.packageRules[0].removeLabels must not remove reserved org automation labels: migration-required",
            errors,
        )

    def test_local_config_can_add_fail_closed_block_labels(self):
        text = json.dumps(
            {
                "packageRules": [
                    {"addLabels": ["manual-review", "migration-required", "database"]}
                ]
            }
        )
        self.assertEqual(adoption.validate_renovate_config(text), [])

    def test_nested_automerge_true_is_rejected(self):
        errors = adoption.validate_renovate_config(
            '{"packageRules": [{"automerge": true}]}'
        )
        self.assertIn(
            "renovate.packageRules[0].automerge must not enable Renovate merging",
            errors,
        )

    def test_platform_automerge_true_is_rejected(self):
        self.assertIn(
            "renovate.platformAutomerge must not enable Renovate merging",
            adoption.validate_renovate_config('{"platformAutomerge": true}'),
        )

    def test_merge_execution_keys_are_rejected_even_when_automerge_is_false(self):
        errors = adoption.validate_renovate_config(
            '{"packageRules": [{"automerge": false, "automergeType": "pr"}]}'
        )
        self.assertIn(
            "renovate.packageRules[0].automergeType must not be present; the org sweep owns merge execution",
            errors,
        )

    def test_malformed_config_is_rejected(self):
        errors = adoption.validate_renovate_config('{"automerge":')
        self.assertTrue(any("not valid JSON" in error for error in errors))

    def test_effective_config_proof_binds_shared_and_local_policy(self):
        shared = (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        proof, errors = adoption.effective_config_proof(
            shared,
            '{"packageRules": [{"automerge": false, "addLabels": ["edge"]}]}',
        )
        self.assertEqual(errors, [])
        self.assertTrue(proof["shared_extends_allowlist_exact"])
        self.assertTrue(proof["local_extends_closed"])
        self.assertTrue(proof["major_manual_review_invariant"])

    def test_effective_config_proof_rejects_inherited_candidate_bypass(self):
        shared = (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        proof, errors = adoption.effective_config_proof(
            shared,
            '{"extends": ["github>attacker/preset:default"], "removeLabels": ["major"], "addLabels": ["automerge-candidate"]}',
        )
        self.assertTrue(errors)
        self.assertFalse(proof["local_extends_closed"])
        self.assertFalse(proof["local_candidate_label_forbidden"])
        self.assertFalse(proof["reserved_label_removal_forbidden"])

    def test_effective_config_proof_rejects_nested_preset_neutralizers(self):
        shared = (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        for control in ("extends", "ignorePresets", "globalExtends"):
            with self.subTest(control=control):
                proof, errors = adoption.effective_config_proof(
                    shared,
                    json.dumps(
                        {
                            "packageRules": [
                                {
                                    control: [
                                        "github>attacker/preset:default"
                                    ]
                                }
                            ]
                        }
                    ),
                )
                self.assertTrue(errors)
                self.assertFalse(proof["local_extends_closed"])

    def test_shared_preset_cannot_enable_merge_or_add_escape_hatches(self):
        shared = json.loads(
            (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        )
        shared["ignorePresets"] = ["config:recommended"]
        shared["packageRules"].append({"automerge": True})
        _, errors = adoption.validate_shared_preset(json.dumps(shared))
        self.assertIn(
            "shared.ignorePresets must not be present; shared preset resolution is closed",
            errors,
        )
        self.assertTrue(
            any(
                error.startswith("shared.packageRules[")
                and error.endswith(".automerge must not enable Renovate merging")
                for error in errors
            )
        )

    def test_shared_preset_cannot_hide_inheritance_in_package_rules(self):
        shared = json.loads(
            (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        )
        shared["packageRules"].append(
            {
                "extends": ["github>attacker/preset:default"],
                "ignorePresets": ["config:recommended"],
                "globalExtends": ["github>attacker/global:default"],
            }
        )
        _, errors = adoption.validate_shared_preset(json.dumps(shared))
        index = len(shared["packageRules"]) - 1
        self.assertIn(
            f"shared.packageRules[{index}].extends must not be present; nested shared preset inheritance is forbidden",
            errors,
        )
        self.assertIn(
            f"shared.packageRules[{index}].ignorePresets must not be present; shared preset resolution is closed",
            errors,
        )
        self.assertIn(
            f"shared.packageRules[{index}].globalExtends must not be present; shared preset resolution is closed",
            errors,
        )


class AdoptionWorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (
            REPO_ROOT / ".github/workflows/security-contract.yml"
        ).read_text(encoding="utf-8")

    def test_pull_requests_run_fixture_audits_without_private_credentials(self):
        pull_request = adoption.indented_block(self.workflow, "pull_request", 2)
        self.assertEqual(pull_request, "")
        fixture_job = adoption.indented_block(
            self.workflow, "adoption-fixture-audit", 2
        )
        self.assertIsNotNone(fixture_job)
        assert fixture_job is not None
        self.assertIn("--inventory-fixture", fixture_job)
        self.assertIn("security-scan-adoption-fixture-receipt.json", fixture_job)
        self.assertIn("if-no-files-found: error", fixture_job)
        self.assertNotIn("SECURITY_AUDIT_TOKEN", fixture_job)
        self.assertNotIn("GH_TOKEN", fixture_job)

    def test_live_audit_is_held_to_schedule_or_dispatch_and_retains_failures(self):
        live_job = adoption.indented_block(self.workflow, "adoption-audit", 2)
        self.assertIsNotNone(live_job)
        assert live_job is not None
        self.assertIn(
            "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
            live_job,
        )
        self.assertIn("SECURITY_AUDIT_TOKEN", live_job)
        self.assertIn("continue-on-error: true", live_job)
        self.assertIn("if: always()", live_job)
        self.assertIn("security-scan-adoption-receipt.json", live_job)
        self.assertIn("if-no-files-found: error", live_job)


class AdoptionInventoryTests(unittest.TestCase):
    policy = REPO_ROOT / ".github/security-scan-adopters.json"
    fixture = (
        REPO_ROOT
        / ".github/tests/fixtures/security-scan-adoption-inventory.json"
    )

    def audit(self, fixture: Path | None = None):
        return adoption.audit_adoption(
            adoption.FixtureProvider(fixture or self.fixture),
            self.policy,
            "1" * 40,
            REPO_ROOT / "renovate-config.json",
        )

    def test_paginated_fixture_classifies_shellrc_active(self):
        report = self.audit()
        self.assertEqual(report["result"], {"status": "pass", "finding_count": 0})
        self.assertTrue(report["visibility"]["complete"])
        rows = {row["full_name"]: row for row in report["repositories"]}
        self.assertEqual(rows["FutureDevGuys/.github"]["lifecycle"], "authority")
        self.assertEqual(rows["FutureDevGuys/openclaw"]["lifecycle"], "archived")
        self.assertEqual(rows["FutureDevGuys/shellrc.d"]["lifecycle"], "active")
        self.assertEqual(
            rows["FutureDevGuys/shellrc.d"]["default_revision"], "c" * 40
        )
        self.assertEqual(rows["FutureDevGuys/shellrc.d"]["security_scan"], "pass")

    def test_active_repository_requires_one_immutable_default_revision(self):
        fixture = json.loads(self.fixture.read_text(encoding="utf-8"))
        fixture["repositories"][2]["default_revision"] = "main"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            report = self.audit(path)
        row = next(
            row
            for row in report["repositories"]
            if row["full_name"] == "FutureDevGuys/shellrc.d"
        )
        self.assertIsNone(row["default_revision"])
        self.assertEqual(row["security_scan"], "unknown")
        self.assertEqual(report["result"]["status"], "fail")

    def test_visibility_count_mismatch_fails_closed(self):
        fixture = json.loads(self.fixture.read_text(encoding="utf-8"))
        fixture["organization"]["total_private_repos"] = 3
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "inventory.json"
            path.write_text(json.dumps(fixture), encoding="utf-8")
            report = self.audit(path)
        self.assertFalse(report["visibility"]["complete"])
        self.assertIn(
            "paginated repository count does not match organization totals",
            report["findings"],
        )

    def test_receipt_binds_inventory_and_report_bytes(self):
        report = self.audit()
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "adoption-report.json"
            receipt_path = Path(temporary) / "adoption-receipt.json"
            adoption.write_atomic(report_path, report)
            adoption.write_atomic(
                receipt_path,
                adoption.build_receipt(report_path, report),
            )
            self.assertEqual(
                adoption.validate_evidence(report_path, receipt_path), []
            )
            report["repositories"][2]["lifecycle"] = "archived"
            adoption.write_atomic(report_path, report)
            self.assertIn(
                "receipt artifact digest does not match",
                adoption.validate_evidence(report_path, receipt_path),
            )


if __name__ == "__main__":
    unittest.main()
