from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
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
refresh = load_module(
    "validate_automerge_refresh",
    ".github/scripts/validate_automerge_refresh.py",
)
refresh_postcondition = load_module(
    "validate_automerge_refresh_postcondition",
    ".github/scripts/validate_automerge_refresh_postcondition.py",
)
merge_postcondition = load_module(
    "validate_automerge_merge_postcondition",
    ".github/scripts/validate_automerge_merge_postcondition.py",
)
repository_visibility = load_module(
    "validate_automerge_repository_visibility",
    ".github/scripts/validate_automerge_repository_visibility.py",
)


class RenovatePolicyTests(unittest.TestCase):
    def test_docker_artifact_lock_regeneration_is_exactly_allowlisted(self):
        preset = json.loads(
            (REPO_ROOT / "renovate-config.json").read_text(encoding="utf-8")
        )
        probe = subprocess.run(
            [
                "node",
                "-e",
                "const c=require('./.github/renovate-config.js');"
                "const r=c.packageRules.find(x=>x.matchRepositories?.includes('FutureDevGuys/docker-configs'));"
                "const cmd=r.postUpgradeTasks.commands[0];"
                "console.log(JSON.stringify({cmd,pattern:c.allowedCommands[0],matches:new RegExp(c.allowedCommands[0]).test(cmd),shell:c.allowShellExecutorForPostUpgradeCommands,files:r.postUpgradeTasks.fileFilters,mode:r.postUpgradeTasks.executionMode}));",
            ],
            cwd=REPO_ROOT,
            env={
                **os.environ,
                "RENOVATE_CONFIG_PRESET": (
                    "github>FutureDevGuys/.github:renovate-config#" + "1" * 40
                ),
            },
            check=True,
            capture_output=True,
            text=True,
        )
        contract = json.loads(probe.stdout)
        self.assertTrue(contract["matches"])
        self.assertFalse(contract["shell"])
        self.assertEqual(contract["files"], ["contracts/artifact-lock.v2.json"])
        self.assertEqual(contract["mode"], "branch")
        self.assertIn("python3 -I -c", contract["cmd"])
        self.assertIn("os.environ.clear()", contract["cmd"])
        self.assertIn(
            "96265e8d6e741353dfa0651a16d13f4d552ba1e1516d8d1ec637420342aedf2e",
            contract["cmd"],
        )
        self.assertNotIn("RENOVATE_TOKEN", contract["cmd"])
        self.assertFalse(
            any("postUpgradeTasks" in rule for rule in preset["packageRules"])
        )
        global_config = (REPO_ROOT / ".github/renovate-config.js").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("dockerMaxPages", global_config)
        self.assertNotIn("dockerMaxPages", preset)

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
                "43.269.1@sha256:2d55099f3cd26c0e91fdf69b8a7d904adb7cf0f3039ad33b94b1856d3cf928b4",
                "43.269.1@sha256:2d55099f3cd26c0e91fdf69b8a7d904adb7cf0f3039ad33b94b1856d3cf928b4",
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
        self.assertIn("validate_automerge_repository_visibility.py", workflow)
        self.assertIn("RENOVATE_TOKEN cannot prove", workflow)
        self.assertIn("automerge-repository-visibility.json", workflow)
        self.assertNotIn("auth/permissions?); skipping repo", workflow)

    def test_automerge_paginates_all_open_pull_requests(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pulls?state=open&per_page=100", workflow)
        self.assertIn("--paginate --slurp", workflow)
        self.assertNotIn("gh pr list", workflow)

    def test_mutating_automerge_has_no_manual_ref_dispatch(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("workflow_dispatch", workflow)
        self.assertNotIn("DRY_RUN", workflow)

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
            self.assertIsInstance(repository["repository_id"], int)
            self.assertGreater(repository["repository_id"], 0)
            self.assertRegex(repository["head_repository_id"], r"^R_")
            names = {check["name"] for check in repository["required_checks"]}
            self.assertIn("trivy / trivy", names)
        docker_names = {
            check["name"]
            for check in policy["repositories"]["FutureDevGuys/docker-configs"][
                "required_checks"
            ]
        }
        self.assertIn("contract-and-history", docker_names)


class AutomergeRepositoryVisibilityTests(unittest.TestCase):
    organization = "FutureDevGuys"

    def setUp(self):
        self.policy = json.loads(
            (REPO_ROOT / ".github/automerge-policy.json").read_text(encoding="utf-8")
        )
        owner = self.policy["organization"]
        self.discovered = [
            {
                "full_name": name,
                "id": repository["repository_id"],
                "node_id": repository["head_repository_id"],
                "archived": False,
                "owner": {
                    "login": owner["login"],
                    "id": owner["id"],
                    "node_id": owner["node_id"],
                },
            }
            for name, repository in self.policy["repositories"].items()
        ]

    def evaluate(self, **overrides):
        values = {
            "organization": self.organization,
            "policy": self.policy,
            "discovered": self.discovered,
        }
        values.update(overrides)
        return repository_visibility.evaluate_repository_visibility(**values)

    def test_all_adopted_repositories_are_visible_with_exact_ids(self):
        result = self.evaluate()
        self.assertTrue(result["eligible"])
        self.assertEqual(
            result["repositories"], sorted(self.policy["repositories"])
        )

    def test_missing_private_adopted_repository_fails_closed(self):
        omitted = self.discovered[0]["full_name"]
        discovered = self.discovered[1:]
        result = self.evaluate(discovered=discovered)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "adopted_repository_not_visible")
        self.assertIn(omitted, result["detail"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            discovered_path = root / "discovered.json"
            output_path = root / "result.json"
            policy_path.write_text(json.dumps(self.policy), encoding="utf-8")
            discovered_path.write_text(json.dumps(discovered), encoding="utf-8")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(
                        REPO_ROOT
                        / ".github/scripts/validate_automerge_repository_visibility.py"
                    ),
                    "--organization",
                    self.organization,
                    "--policy",
                    str(policy_path),
                    "--discovered",
                    str(discovered_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8"))["reason"],
                "adopted_repository_not_visible",
            )

    def test_same_name_with_wrong_repository_id_fails_closed(self):
        discovered = deepcopy(self.discovered)
        discovered[0]["id"] += 1
        result = self.evaluate(discovered=discovered)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "repository_identity_mismatch")

    def test_wrong_organization_identity_fails_closed(self):
        discovered = deepcopy(self.discovered)
        discovered[0]["owner"]["node_id"] = "O_attacker"
        result = self.evaluate(discovered=discovered)
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "repository_visibility_invalid")

    def test_non_object_policy_fails_cleanly(self):
        result = self.evaluate(policy=[])
        self.assertFalse(result["eligible"])
        self.assertEqual(result["reason"], "invalid_policy")


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

    def test_partial_or_over_cap_commit_evidence_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["commitCount"] = 2
        self.assertEqual(
            self.evaluate(pull_request=pull_request)["reason"],
            "commit_evidence_incomplete",
        )
        pull_request["commitCount"] = 251
        commits = deepcopy(self.commits) * 251
        commits[-1]["sha"] = pull_request["headRefOid"]
        self.assertEqual(
            self.evaluate(pull_request=pull_request, commits=commits)["reason"],
            "commit_evidence_incomplete",
        )

    def test_policy_bound_refresh_committer_is_allowed(self):
        commits = deepcopy(self.commits)
        identity = self.policy["trusted_renovate_identity"]
        commits[0]["commit"]["committer"] = {
            "name": identity["refresh_committer_name"],
            "email": identity["refresh_committer_email"],
        }
        self.assertTrue(self.evaluate(commits=commits)["eligible"])

    def test_arbitrary_refresh_committer_is_blocked(self):
        commits = deepcopy(self.commits)
        commits[0]["commit"]["committer"] = {
            "name": "Other User",
            "email": "other@example.invalid",
        }
        self.assertEqual(
            self.evaluate(commits=commits)["reason"],
            "untrusted_commit_identity",
        )

    def test_missing_refresh_identity_is_invalid_policy(self):
        policy = deepcopy(self.policy)
        del policy["trusted_renovate_identity"]["refresh_committer_email"]
        self.assertEqual(self.evaluate(policy=policy)["reason"], "invalid_policy")

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


class AutomergeRefreshTests(unittest.TestCase):
    repository = "FutureDevGuys/personal-containers"
    head_sha = "a" * 40
    current_base_sha = "b" * 40
    recorded_base_sha = "c" * 40

    def setUp(self):
        fixture = REPO_ROOT / ".github/tests/fixtures/automerge"
        self.policy = json.loads(
            (REPO_ROOT / ".github/automerge-policy.json").read_text(encoding="utf-8")
        )
        self.pull_request = json.loads(
            (fixture / "pr-trusted.json").read_text(encoding="utf-8")
        )
        self.pull_request.update(
            {
                "baseRefName": "main",
                "baseRefOid": self.recorded_base_sha,
                "changedFiles": 1,
            }
        )
        self.commits = json.loads(
            (fixture / "commits-trusted.json").read_text(encoding="utf-8")
        )
        self.changed_files = [{"filename": "compose/example.yml"}]
        self.comparison = {
            "status": "diverged",
            "ahead_by": 1,
            "behind_by": 3,
            "base_commit": {"sha": self.current_base_sha},
            "merge_base_commit": {"sha": self.recorded_base_sha},
            "commits": [{"sha": self.head_sha}],
        }

    def evaluate(self, **overrides):
        values = {
            "repository": self.repository,
            "policy": self.policy,
            "pull_request": self.pull_request,
            "commits": self.commits,
            "changed_files": self.changed_files,
            "comparison": self.comparison,
            "current_base_sha": self.current_base_sha,
        }
        values.update(overrides)
        return refresh.evaluate_refresh_candidate(**values)

    def test_trusted_stale_branch_requests_refresh_but_not_merge(self):
        result = self.evaluate()
        self.assertEqual(result["action"], "refresh")
        self.assertTrue(result["refresh_eligible"])
        self.assertNotIn("eligible", result)

    def test_current_branch_continues_to_separate_merge_gate(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["baseRefOid"] = self.current_base_sha
        comparison = deepcopy(self.comparison)
        comparison.update({"status": "ahead", "behind_by": 0})
        comparison["merge_base_commit"]["sha"] = self.current_base_sha
        result = self.evaluate(pull_request=pull_request, comparison=comparison)
        self.assertEqual(result["action"], "continue")
        self.assertFalse(result["refresh_eligible"])

    def test_same_prefix_untrusted_author_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["author"] = {
            "login": "renovate-lookalike",
            "id": "U_attacker",
            "is_bot": True,
        }
        self.assertEqual(
            self.evaluate(pull_request=pull_request)["reason"],
            "untrusted_renovate_identity",
        )

    def test_fork_is_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["headRepository"] = {
            "id": "R_fork",
            "nameWithOwner": "attacker/personal-containers",
        }
        self.assertEqual(
            self.evaluate(pull_request=pull_request)["reason"],
            "untrusted_head_repository",
        )

    def test_non_renovate_commit_is_blocked(self):
        commits = deepcopy(self.commits)
        commits[0]["commit"]["committer"]["email"] = "attacker@example.invalid"
        self.assertEqual(
            self.evaluate(commits=commits)["reason"],
            "untrusted_commit_identity",
        )

    def test_policy_bound_rebase_committer_continues_when_branch_is_current(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["baseRefOid"] = self.current_base_sha
        commits = deepcopy(self.commits)
        identity = self.policy["trusted_renovate_identity"]
        commits[0]["commit"]["committer"] = {
            "name": identity["refresh_committer_name"],
            "email": identity["refresh_committer_email"],
        }
        comparison = deepcopy(self.comparison)
        comparison.update({"status": "ahead", "behind_by": 0})
        comparison["merge_base_commit"]["sha"] = self.current_base_sha
        result = self.evaluate(
            pull_request=pull_request,
            commits=commits,
            comparison=comparison,
        )
        self.assertEqual(result["action"], "continue")

    def test_security_or_ci_contract_change_is_never_refreshed(self):
        changed_files = [{"filename": ".github/workflows/security-scan.yml"}]
        self.assertEqual(
            self.evaluate(changed_files=changed_files)["reason"],
            "protected_caller_changed",
        )

    def test_current_original_renovate_ci_update_reaches_merge_gate(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["baseRefOid"] = self.current_base_sha
        changed_files = [{"filename": ".github/workflows/example.yml"}]
        comparison = deepcopy(self.comparison)
        comparison.update({"status": "ahead", "behind_by": 0})
        comparison["merge_base_commit"]["sha"] = self.current_base_sha
        result = self.evaluate(
            pull_request=pull_request,
            changed_files=changed_files,
            comparison=comparison,
        )
        self.assertEqual(result["action"], "continue")

    def test_rebased_ci_update_is_blocked_even_when_current(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["baseRefOid"] = self.current_base_sha
        commits = deepcopy(self.commits)
        identity = self.policy["trusted_renovate_identity"]
        commits[0]["commit"]["committer"] = {
            "name": identity["refresh_committer_name"],
            "email": identity["refresh_committer_email"],
        }
        changed_files = [{"filename": ".github/workflows/example.yml"}]
        comparison = deepcopy(self.comparison)
        comparison.update({"status": "ahead", "behind_by": 0})
        comparison["merge_base_commit"]["sha"] = self.current_base_sha
        result = self.evaluate(
            pull_request=pull_request,
            commits=commits,
            changed_files=changed_files,
            comparison=comparison,
        )
        self.assertEqual(result["reason"], "refresh_committer_protected_change")

    def test_partially_paginated_changed_files_are_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["changedFiles"] = 2
        self.assertEqual(
            self.evaluate(pull_request=pull_request)["reason"],
            "changed_file_evidence_incomplete",
        )

    def test_duplicate_changed_files_are_blocked(self):
        pull_request = deepcopy(self.pull_request)
        pull_request["changedFiles"] = 2
        changed_files = [
            {"filename": "compose/example.yml"},
            {"filename": "compose/example.yml"},
        ]
        self.assertEqual(
            self.evaluate(
                pull_request=pull_request, changed_files=changed_files
            )["reason"],
            "changed_file_evidence_ambiguous",
        )

    def test_stale_comparison_head_is_blocked(self):
        comparison = deepcopy(self.comparison)
        comparison["commits"][-1]["sha"] = "d" * 40
        self.assertEqual(
            self.evaluate(comparison=comparison)["reason"],
            "comparison_evidence_stale",
        )

    def test_stale_comparison_base_is_blocked(self):
        comparison = deepcopy(self.comparison)
        comparison["base_commit"]["sha"] = "d" * 40
        self.assertEqual(
            self.evaluate(comparison=comparison)["reason"],
            "comparison_evidence_stale",
        )

    def test_workflow_uses_expected_head_rebase_and_holds_merge(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        refresh_start = workflow.index('if [ "${refresh_action}" = "refresh" ]')
        merge_start = workflow.index("# Only a current branch reaches merge validation")
        refresh_block = workflow[refresh_start:merge_start]
        self.assertIn('-f "expected_head_sha=${head_sha}"', refresh_block)
        self.assertIn("-f update_method=rebase", refresh_block)
        self.assertIn("continue", refresh_block)
        self.assertNotIn("gh pr merge", refresh_block)

    def test_workflow_compare_and_swaps_validated_head_at_merge(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'merge_args=(--squash --match-head-commit "${head_sha}")',
            workflow,
        )
        self.assertIn("candidate_changed_since_validation", workflow)
        self.assertNotIn("mergeable=UNKNOWN; refreshing", workflow)

    def test_workflow_hard_restricts_merge_method_to_squash(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('if [ "${MERGE_METHOD}" != "squash" ]', workflow)
        self.assertIn(
            'merge_args=(--squash --match-head-commit "${head_sha}")',
            workflow,
        )
        self.assertNotIn("merge|squash|rebase", workflow)
        self.assertNotIn('--"${MERGE_METHOD}"', workflow)

    def test_workflow_refetches_and_revalidates_ci_at_final_merge_boundary(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        premerge_start = workflow.index('premerge_evidence_ok="true"')
        merge_start = workflow.index('if gh pr merge --repo "${REPO}"')
        premerge_block = workflow[premerge_start:merge_start]
        self.assertIn("premerge-pr.json", premerge_block)
        self.assertIn("premerge-commits.json", premerge_block)
        self.assertIn("premerge-checks.json", premerge_block)
        self.assertIn("premerge-statuses.json", premerge_block)
        self.assertIn("premerge-security-scan.yml", premerge_block)
        self.assertIn("validate_automerge_candidate.py", premerge_block)
        self.assertEqual(workflow.count("validate_automerge_candidate.py"), 2)
        self.assertLess(
            workflow.index(
                '> "${candidate_dir}/premerge-statuses.json"',
                premerge_start,
                merge_start,
            ),
            workflow.rindex("validate_automerge_candidate.py", premerge_start, merge_start),
        )
        self.assertLess(
            workflow.rindex("validate_automerge_candidate.py", premerge_start, merge_start),
            merge_start,
        )


class AutomergeRefreshPostconditionTests(unittest.TestCase):
    old_head_sha = "a" * 40
    new_head_sha = "b" * 40
    base_sha = "c" * 40

    def evaluate(self, **overrides):
        values = {
            "old_head_sha": self.old_head_sha,
            "current_base_sha": self.base_sha,
            "pull_request": {
                "baseRefName": "main",
                "baseRefOid": self.base_sha,
                "headRefOid": self.new_head_sha,
            },
            "comparison": {
                "status": "ahead",
                "ahead_by": 1,
                "behind_by": 0,
                "base_commit": {"sha": self.base_sha},
                "merge_base_commit": {"sha": self.base_sha},
                "commits": [{"sha": self.new_head_sha}],
            },
        }
        values.update(overrides)
        return refresh_postcondition.evaluate_refresh_postcondition(**values)

    def test_changed_current_head_is_verified(self):
        result = self.evaluate()
        self.assertTrue(result["verified"])
        self.assertEqual(result["reason"], "refresh_verified")

    def test_accepted_but_unchanged_head_is_not_progress(self):
        pull_request = {
            "baseRefName": "main",
            "baseRefOid": self.base_sha,
            "headRefOid": self.old_head_sha,
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "refresh_pending")

    def test_changed_head_that_is_still_behind_is_not_progress(self):
        comparison = {
            "status": "diverged",
            "ahead_by": 1,
            "behind_by": 1,
            "base_commit": {"sha": self.base_sha},
            "merge_base_commit": {"sha": "d" * 40},
            "commits": [{"sha": self.new_head_sha}],
        }
        result = self.evaluate(comparison=comparison)
        self.assertFalse(result["verified"])
        self.assertIn(
            result["reason"], {"refresh_comparison_stale", "refresh_still_behind"}
        )

    def test_new_head_bound_to_stale_base_is_not_progress(self):
        pull_request = {
            "baseRefName": "main",
            "baseRefOid": "d" * 40,
            "headRefOid": self.new_head_sha,
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "refreshed_base_mismatch")

    def test_workflow_does_not_count_request_acceptance_as_refresh(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        request_start = workflow.index('if gh api --method PUT \\\n')
        request_end = workflow.index("# Only a current branch reaches merge validation")
        request_block = workflow[request_start:request_end]
        self.assertIn("validate_automerge_refresh_postcondition.py", request_block)
        self.assertIn("branch_refresh_postcondition_unknown", request_block)
        self.assertIn("refreshed refresh_verified", request_block)
        self.assertNotIn("refreshed branch_refresh_requested", request_block)


class AutomergeMergePostconditionTests(unittest.TestCase):
    head_sha = "a" * 40
    merge_sha = "b" * 40
    base_sha = "c" * 40
    current_base_sha = "d" * 40

    def evaluate(self, **overrides):
        values = {
            "authorized_head_sha": self.head_sha,
            "authorized_base_sha": self.base_sha,
            "current_base_sha": self.current_base_sha,
            "pull_request": {
                "state": "MERGED",
                "mergedAt": "2026-07-15T07:00:00Z",
                "mergeCommit": {"oid": self.merge_sha},
                "headRefOid": self.head_sha,
                "baseRefName": "main",
            },
            "merge_commit": {
                "sha": self.merge_sha,
                "parents": [{"sha": self.base_sha}],
            },
            "comparison": {
                "status": "ahead",
                "ahead_by": 1,
                "behind_by": 0,
                "base_commit": {"sha": self.merge_sha},
                "merge_base_commit": {"sha": self.merge_sha},
                "commits": [{"sha": self.current_base_sha}],
            },
        }
        values.update(overrides)
        return merge_postcondition.evaluate_merge_postcondition(**values)

    def test_exact_authorized_merge_reachable_from_main_is_verified(self):
        result = self.evaluate()
        self.assertTrue(result["verified"])
        self.assertEqual(result["reason"], "merge_verified")

    def test_successful_cli_request_without_merged_state_is_not_merged(self):
        pull_request = {
            "state": "OPEN",
            "mergedAt": None,
            "mergeCommit": None,
            "headRefOid": self.head_sha,
            "baseRefName": "main",
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "merge_pending_or_mismatched")

    def test_different_head_is_not_merged(self):
        pull_request = {
            "state": "MERGED",
            "mergedAt": "2026-07-15T07:00:00Z",
            "mergeCommit": {"oid": self.merge_sha},
            "headRefOid": "d" * 40,
            "baseRefName": "main",
        }
        result = self.evaluate(pull_request=pull_request)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "merge_pending_or_mismatched")

    def test_unreachable_merge_commit_is_not_merged(self):
        comparison = {
            "status": "diverged",
            "ahead_by": 2,
            "behind_by": 1,
            "base_commit": {"sha": self.merge_sha},
            "merge_base_commit": {"sha": "d" * 40},
            "commits": [{"sha": self.current_base_sha}],
        }
        result = self.evaluate(comparison=comparison)
        self.assertFalse(result["verified"])
        self.assertIn(
            result["reason"],
            {"merge_reachability_stale", "merge_not_reachable_from_base"},
        )

    def test_merge_on_unapproved_new_base_is_self_announcing(self):
        merge_commit = {
            "sha": self.merge_sha,
            "parents": [{"sha": "e" * 40}],
        }
        result = self.evaluate(merge_commit=merge_commit)
        self.assertFalse(result["verified"])
        self.assertEqual(result["reason"], "merge_parent_mismatch")

    def test_workflow_does_not_treat_merge_exit_zero_as_completion(self):
        workflow = (REPO_ROOT / ".github/workflows/automerge.yml").read_text(
            encoding="utf-8"
        )
        merge_start = workflow.index('if gh pr merge --repo "${REPO}"')
        merge_block = workflow[merge_start:]
        self.assertIn("validate_automerge_merge_postcondition.py", merge_block)
        self.assertIn("merge_postcondition_unknown", merge_block)
        self.assertIn("merged merge_verified", merge_block)
        self.assertNotIn("merged merged", merge_block)


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

    def test_branch_refresh_is_progress_without_claiming_merge(self):
        refreshed = outcomes.build_record(
            repository="FutureDevGuys/example",
            pull_request=7,
            created_at="2026-07-13T06:00:00Z",
            observed_at="2026-07-14T06:00:00Z",
            outcome="refreshed",
            reason="branch_refresh_requested",
            detail="exact head refreshed; merge held",
            blocks_progress=False,
        )
        stale = outcomes.build_record(
            repository="FutureDevGuys/example",
            pull_request=8,
            created_at="2026-07-13T06:00:00Z",
            observed_at="2026-07-14T06:00:00Z",
            outcome="skipped",
            reason="required_check_missing",
            detail="waiting for CI",
            blocks_progress=True,
        )
        summary = outcomes.summarize_records(
            [refreshed, stale], degrade_after_hours=24.0
        )
        self.assertTrue(summary["degraded"])
        self.assertEqual(summary["outcomes"]["refreshed"], 1)

    def test_progress_does_not_hide_aged_actionable_blocker(self):
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
        self.assertTrue(summary["degraded"])
        self.assertEqual(summary["progress_count"], 1)


if __name__ == "__main__":
    unittest.main()
