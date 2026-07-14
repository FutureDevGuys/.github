from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import unittest
from copy import deepcopy
from pathlib import Path


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


outcomes = load_module("automerge_outcomes", ".github/scripts/automerge_outcomes.py")
candidate = load_module(
    "validate_automerge_candidate",
    ".github/scripts/validate_automerge_candidate.py",
)


class RenovatePolicyTests(unittest.TestCase):
    def test_runtime_and_preset_are_exact_and_retry_is_bounded(self):
        workflow = (REPO_ROOT / ".github/workflows/renovate.yml").read_text(
            encoding="utf-8"
        )
        pins = re.findall(r"renovatebot/github-action@([0-9a-f]{40})", workflow)
        self.assertEqual(len(pins), 2)
        self.assertEqual(len(set(pins)), 1)
        self.assertEqual(pins[0], "22e0a16091fc706b04affe6ae53d5e3358ac4023")
        runtime_pins = re.findall(
            r"renovate-version:\s*([0-9]+(?:\.[0-9]+){2}@sha256:[0-9a-f]{64})",
            workflow,
        )
        self.assertEqual(
            runtime_pins,
            [
                "43.263.3@sha256:dbdb501ad9a2558ab8f99538b1d4be0a8768cf8c3383aaa33a35ed981dfe3464",
                "43.263.3@sha256:dbdb501ad9a2558ab8f99538b1d4be0a8768cf8c3383aaa33a35ed981dfe3464",
            ],
        )
        self.assertEqual(
            workflow.count("# renovate: datasource=docker depName=renovate/renovate"),
            2,
        )
        self.assertIn(
            "github>FutureDevGuys/.github:renovate-config#${{ github.sha }}",
            workflow,
        )
        self.assertIn("repos/FutureDevGuys/.github/contents/renovate-config.json", workflow)

    def test_runtime_config_rejects_mutable_shared_preset(self):
        command = [
            "node",
            "-e",
            "process.stdout.write(JSON.stringify(require('./.github/renovate-config.js').globalExtends))",
        ]
        valid_env = {
            **os.environ,
            "RENOVATE_CONFIG_PRESET": (
                "github>FutureDevGuys/.github:renovate-config#" + "1" * 40
            ),
        }
        valid = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=valid_env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            json.loads(valid.stdout),
            [valid_env["RENOVATE_CONFIG_PRESET"]],
        )

        mutable_env = {
            **os.environ,
            "RENOVATE_CONFIG_PRESET": "github>FutureDevGuys/.github:renovate-config",
        }
        mutable = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=mutable_env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(mutable.returncode, 0)
        self.assertIn("exact 40-character commit SHA", mutable.stderr)

    def test_runtime_force_disables_renovate_merge_execution(self):
        env = {
            **os.environ,
            "RENOVATE_CONFIG_PRESET": (
                "github>FutureDevGuys/.github:renovate-config#" + "1" * 40
            ),
        }
        completed = subprocess.run(
            [
                "node",
                "-e",
                "process.stdout.write(JSON.stringify(require('./.github/renovate-config.js').force))",
            ],
            cwd=REPO_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {"automerge": False, "platformAutomerge": False},
        )

    def test_immutable_digest_rule_has_no_release_age(self):
        preset = json.loads((REPO_ROOT / "renovate-config.json").read_text())
        digest_rule = preset["packageRules"][-1]
        self.assertEqual(digest_rule["matchUpdateTypes"], ["digest", "pinDigest"])
        self.assertIsNone(digest_rule["minimumReleaseAge"])
        self.assertEqual(digest_rule["internalChecksFilter"], "strict")

    def test_security_workflow_revision_updates_atomically(self):
        preset = json.loads((REPO_ROOT / "renovate-config.json").read_text())
        manager = next(
            manager
            for manager in preset["customManagers"]
            if manager.get("depNameTemplate") == "FutureDevGuys/.github"
        )
        self.assertEqual(manager["datasourceTemplate"], "github-digest")
        self.assertEqual(manager["currentValueTemplate"], "main")
        self.assertEqual(manager["packageNameTemplate"], "FutureDevGuys/.github")
        pattern = manager["matchStrings"][0].replace(
            "(?<currentDigest>",
            "(?P<currentDigest>",
        )
        fixture = (
            REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        ).read_text(encoding="utf-8")
        match = re.search(pattern, fixture)
        self.assertIsNotNone(match)
        self.assertEqual(match.group("currentDigest"), "1" * 40)
        replacement = manager["autoReplaceStringTemplate"].replace(
            "{{{newDigest}}}",
            "2" * 40,
        )
        updated = re.sub(pattern, replacement, fixture, count=1)
        self.assertEqual(updated.count("2" * 40), 2)
        self.assertNotIn("1" * 40, updated)

    def test_renovate_only_labels_and_never_merges(self):
        preset = json.loads((REPO_ROOT / "renovate-config.json").read_text())
        self.assertFalse(preset["platformAutomerge"])
        for rule in preset["packageRules"]:
            self.assertIsNot(rule.get("automerge"), True)
        self.assertNotIn("automergeType", json.dumps(preset))
        self.assertNotIn("automergeStrategy", json.dumps(preset))

    def test_automerge_refuses_partial_repository_visibility(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("refusing a partial-success sweep", workflow)
        self.assertNotIn("auth/permissions?); skipping repo", workflow)

    def test_automerge_policy_matches_truthful_security_adopters(self):
        policy = json.loads(
            (REPO_ROOT / ".github/automerge-policy.json").read_text(encoding="utf-8")
        )
        adopters = json.loads(
            (REPO_ROOT / ".github/security-scan-adopters.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(policy["repositories"]), set(adopters["repositories"]))
        self.assertEqual(
            set(adopters["renovate_config_repositories"]),
            {
                "FutureDevGuys/docker-configs",
                "FutureDevGuys/homelab-iac",
                "FutureDevGuys/personal-containers",
            },
        )
        self.assertLessEqual(
            set(adopters["renovate_config_repositories"]),
            set(adopters["repositories"]),
        )
        for repository in policy["repositories"].values():
            names = {check["name"] for check in repository["required_checks"]}
            self.assertIn("trivy / trivy", names)
        docker_names = {
            check["name"]
            for check in policy["repositories"]["FutureDevGuys/docker-configs"][
                "required_checks"
            ]
        }
        self.assertIn("contract-and-history", docker_names)


class AutomergeCandidateTests(unittest.TestCase):
    repository = "FutureDevGuys/personal-containers"
    revision = "1" * 40

    def setUp(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/automerge"
        self.policy = json.loads(
            (REPO_ROOT / ".github/automerge-policy.json").read_text(encoding="utf-8")
        )
        self.pull_request = json.loads(
            (fixture / "pr-trusted.json").read_text(encoding="utf-8")
        )
        self.commits = json.loads(
            (fixture / "commits-trusted.json").read_text(encoding="utf-8")
        )
        self.checks = json.loads(
            (fixture / "checks-success.json").read_text(encoding="utf-8")
        )
        self.statuses = json.loads(
            (fixture / "statuses-success.json").read_text(encoding="utf-8")
        )
        caller = (
            REPO_ROOT / ".github/tests/fixtures/security-scan-caller.yml"
        ).read_text(encoding="utf-8")
        self.caller = caller.replace("1" * 40, self.revision)

    def evaluate(self, **overrides):
        values = {
            "repository": self.repository,
            "policy": self.policy,
            "pull_request": self.pull_request,
            "commits": self.commits,
            "checks": self.checks,
            "statuses": self.statuses,
            "caller_text": self.caller,
            "required_security_revision": self.revision,
        }
        values.update(overrides)
        return candidate.evaluate_candidate(**values)

    def test_trusted_current_head_with_all_required_checks_passes(self):
        result = self.evaluate()
        self.assertTrue(result["eligible"])
        self.assertEqual(result["reason"], "eligible")

    def test_same_prefix_untrusted_author_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["author"] = {
            "login": "renovate-lookalike",
            "id": "U_attacker",
            "is_bot": True,
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "untrusted_renovate_identity")

    def test_fork_head_with_trusted_branch_name_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["headRepository"] = {
            "id": "R_fork",
            "nameWithOwner": "someone/personal-containers",
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertEqual(result["reason"], "untrusted_head_repository")

    def test_non_renovate_commit_identity_is_blocked(self):
        commits = deepcopy(self.commits)
        commits[0]["commit"]["author"]["email"] = "attacker@example.invalid"
        result = self.evaluate(commits=commits)
        self.assertEqual(result["reason"], "untrusted_commit_identity")

    def test_missing_trivy_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"] = [
            check for check in checks["check_runs"] if check["name"] != "trivy / trivy"
        ]
        checks["total_count"] = len(checks["check_runs"])
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "required_check_missing")

    def test_docker_candidate_without_owner_contract_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["headRepository"] = {
            "id": self.policy["repositories"]["FutureDevGuys/docker-configs"][
                "head_repository_id"
            ],
            "nameWithOwner": "FutureDevGuys/docker-configs",
        }
        result = self.evaluate(
            repository="FutureDevGuys/docker-configs",
            pull_request=pull_request,
        )
        self.assertEqual(result["reason"], "required_check_missing")
        self.assertIn("contract-and-history", result["detail"])

    def test_duplicate_required_check_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"].append(deepcopy(checks["check_runs"][-1]))
        checks["total_count"] = len(checks["check_runs"])
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "required_check_ambiguous")

    def test_partially_paginated_check_evidence_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["total_count"] += 1
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "check_evidence_incomplete")

    def test_pending_check_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"][0]["status"] = "in_progress"
        checks["check_runs"][0]["conclusion"] = None
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "check_pending")

    def test_skipped_check_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"][0]["conclusion"] = "skipped"
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "check_skipped")

    def test_failed_check_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"][0]["conclusion"] = "failure"
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "check_not_successful")

    def test_stale_head_check_is_blocked(self):
        checks = deepcopy(self.checks)
        checks["check_runs"][0]["head_sha"] = "b" * 40
        result = self.evaluate(checks=checks)
        self.assertEqual(result["reason"], "stale_check_run")

    def test_pending_status_is_blocked(self):
        statuses = deepcopy(self.statuses)
        statuses["statuses"][0]["state"] = "pending"
        result = self.evaluate(statuses=statuses)
        self.assertEqual(result["reason"], "status_pending")

    def test_partially_paginated_status_evidence_is_blocked(self):
        statuses = deepcopy(self.statuses)
        statuses["total_count"] += 1
        result = self.evaluate(statuses=statuses)
        self.assertEqual(result["reason"], "status_evidence_incomplete")

    def test_duplicate_status_context_is_blocked(self):
        statuses = deepcopy(self.statuses)
        statuses["statuses"].append(deepcopy(statuses["statuses"][0]))
        statuses["total_count"] = len(statuses["statuses"])
        result = self.evaluate(statuses=statuses)
        self.assertEqual(result["reason"], "status_context_ambiguous")

    def test_stale_or_mutable_security_caller_is_blocked(self):
        result = self.evaluate(caller_text=self.caller.replace(self.revision, "2" * 40))
        self.assertEqual(result["reason"], "invalid_security_caller")


class AutomergeOutcomeTests(unittest.TestCase):
    def test_record_calculates_reason_age(self):
        record = outcomes.build_record(
            repository="FutureDevGuys/example",
            pull_request=7,
            created_at="2026-07-13T06:00:00Z",
            observed_at="2026-07-14T06:00:00Z",
            outcome="skipped",
            reason="checks_not_ready",
            detail="required checks failed",
            blocks_progress=True,
        )
        self.assertEqual(record["age_hours"], 24.0)
        self.assertEqual(record["reason"], "checks_not_ready")

    def test_stale_zero_progress_is_degraded(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/automerge-outcomes.jsonl"
        summary = outcomes.summarize_records(
            outcomes.load_records(fixture), degrade_after_hours=24.0
        )
        self.assertTrue(summary["degraded"])
        self.assertEqual(summary["stale_progress_blockers"], 1)
        self.assertEqual(
            summary["skip_reasons"],
            {"blocked_label": 1, "checks_not_ready": 1},
        )

    def test_any_progress_prevents_zero_progress_degradation(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/automerge-outcomes.jsonl"
        records = outcomes.load_records(fixture)
        records.append(
            {
                "schema_version": 1,
                "outcome": "merged",
                "reason": "merged",
                "age_hours": 1.0,
                "blocks_progress": False,
            }
        )
        summary = outcomes.summarize_records(records, degrade_after_hours=24.0)
        self.assertFalse(summary["degraded"])


if __name__ == "__main__":
    unittest.main()
