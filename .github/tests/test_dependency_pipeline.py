from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".github/scripts"))
import merge_dependencies as merger
import private_artifacts as artifacts
import run_renovate as runner
import resolve_dependency_automation_adopters as adoption


class FakeGitHub:
    def __init__(self):
        self.repository = "FutureDevGuys/personal-containers"
        self.head, self.base, self.merge = "a" * 40, "b" * 40, "d" * 40
        fixture = ROOT / ".github/tests/fixtures/automerge"
        self.policy = json.loads((fixture / "policy.json").read_text())
        self.commits = json.loads((fixture / "commits-trusted.json").read_text())
        self.commits[0]["sha"] = self.head
        self.commits[0]["commit"]["verification"] = {"verified": True}
        identity = self.policy["trusted_renovate_identity"]
        self.pr = {
            "number": 1, "state": "open", "draft": False, "merged": False,
            "base": {"ref": "main", "sha": self.base},
            "head": {"ref": "renovate/test", "sha": self.head, "repo": {"full_name": self.repository, "node_id": self.policy["repositories"][self.repository]["head_repository_id"], "owner": {"login": "FutureDevGuys"}}},
            "user": {"login": identity["login"], "node_id": identity["id"], "type": "User"},
            "commits": 1, "changed_files": 1, "labels": [{"name": "automerge-candidate"}],
            "mergeable": True, "mergeable_state": "clean", "merged_at": None, "merge_commit_sha": None,
        }
        self.operations = []
        self.checks = {"total_count": 0, "check_runs": []}
        self.authority = "c" * 40
        self.change_labels_at_boundary = False
        self.pr_reads = 0
        self.behind = False
        self.refresh_conflict = False
        self.refreshed = False
        self.permission = "write"
        self.reviews = []
        self.events = []
        self.branch_advanced = False

    def pages(self, path):
        if path.endswith("/commits"):
            return deepcopy(self.commits)
        if path.endswith("/files"):
            return [{"filename": "compose.yaml"}]
        if path.endswith("/reviews"):
            return self.reviews
        if path.endswith("/events"):
            return self.events
        raise AssertionError(path)

    def api(self, path, method="GET", data=None):
        self.operations.append((method, path, deepcopy(data)))
        if path == "repos/FutureDevGuys/.github/commits/main":
            return {"sha": self.authority}
        if path.endswith("/permission"):
            return {"permission": self.permission}
        if path.endswith("/labels") and method == "POST":
            self.pr["labels"].extend({"name": name} for name in data["labels"])
            return []
        if path.endswith("/update-branch"):
            if self.refresh_conflict:
                raise merger.ApiError(422)
            self.head = "e" * 40
            self.pr["head"]["sha"] = self.head
            self.pr["base"]["sha"] = self.base
            self.commits[0]["sha"] = self.head
            self.behind = False
            self.refreshed = True
            return {"message": "Updating"}
        if path.endswith("/pulls/1"):
            self.pr_reads += 1
            if self.change_labels_at_boundary and self.pr_reads >= 2:
                self.pr["labels"] = [{"name": "do-not-merge"}]
            return deepcopy(self.pr)
        if path.endswith("/commits/main"):
            return {"sha": self.merge if self.pr["merged"] else self.base}
        if "/compare/" in path:
            left, right = path.rsplit("/", 1)[1].split("...")
            if left == right:
                return {"base_commit": {"sha": left}, "merge_base_commit": {"sha": left}, "status": "identical", "ahead_by": 0, "behind_by": 0, "commits": []}
            return {"base_commit": {"sha": left}, "merge_base_commit": {"sha": self.pr["base"]["sha"]}, "status": "diverged" if self.behind else "ahead", "ahead_by": 1, "behind_by": 1 if self.behind else 0, "commits": [{"sha": right}]}
        if "/check-runs?" in path:
            return self.checks
        if "/status?" in path:
            return {"sha": self.head, "total_count": 0, "statuses": []}
        if path.endswith("/merge") and method == "PUT":
            self.assert_expected_merge = data == {"sha": self.head, "merge_method": "squash"}
            self.pr.update(merged=True, state="closed", merged_at="2026-09-26T12:00:00Z", merge_commit_sha=self.merge)
            return {"merged": True, "sha": self.merge}
        if path.endswith("/commits/" + self.merge):
            return {"sha": self.merge, "parents": [{"sha": self.base}]}
        if "/git/ref/" in path:
            return {"object": {"sha": "f" * 40 if self.branch_advanced else self.head}}
        if "/git/refs/" in path and method == "DELETE":
            return None
        raise AssertionError((method, path, data))


class MergePipelineTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()
        self.env = patch.dict(os.environ, {"GITHUB_REPOSITORY": "FutureDevGuys/.github", "GITHUB_SHA": "c" * 40})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.sweep = merger.Sweep(self.api, self.api.policy, Path("unused"))

    def run_candidate(self):
        with patch.object(merger.time, "sleep"):
            self.sweep.process(self.api.repository, 1, "main")

    def test_signed_candidate_without_ci_is_merged_with_exact_head_and_postcondition(self):
        self.run_candidate()
        self.assertTrue(self.api.assert_expected_merge)
        self.assertEqual(self.sweep.records[-1]["reason"], "merge_verified")

    def test_failed_checks_prevent_merge(self):
        self.api.checks = {"total_count": 1, "check_runs": [{"name": "test", "head_sha": self.api.head, "status": "completed", "conclusion": "failure"}]}
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])
        self.assertEqual(self.sweep.records[-1]["reason"], "check_not_successful")

    def test_unsigned_legacy_branch_requests_only_one_signed_rebuild(self):
        self.api.pr["mergeable_state"] = "blocked"
        self.api.commits[0]["commit"]["verification"]["verified"] = False
        self.run_candidate()
        self.run_candidate()
        self.assertEqual(len([op for op in self.api.operations if op[1].endswith("/labels")]), 1)
        self.assertEqual(self.sweep.recovery, {self.api.repository})
        self.assertFalse(self.api.pr["merged"])

    def test_manual_hold_is_rebuilt_before_requiring_current_head_approval(self):
        self.api.pr["labels"].append({"name": "manual-review"})
        self.api.pr["mergeable_state"] = "blocked"
        self.api.commits[0]["commit"]["verification"]["verified"] = False
        self.run_candidate()
        self.assertEqual(self.sweep.records[-1]["reason"], "signed_rebuild_required")
        self.assertEqual(self.sweep.recovery, {self.api.repository})
        self.assertFalse(self.api.pr["merged"])

    def test_unsigned_native_rebase_is_not_a_global_merge_blocker(self):
        self.api.commits[0]["commit"]["verification"]["verified"] = False
        self.run_candidate()
        self.assertTrue(self.api.pr["merged"])
        self.assertEqual(self.sweep.records[-1]["reason"], "merge_verified")

    def test_refreshed_candidate_is_revalidated_and_merged_in_same_sweep(self):
        self.api.behind = True
        self.api.pr["base"]["sha"] = "9" * 40
        self.run_candidate()
        self.assertTrue(self.api.refreshed)
        self.assertTrue(self.api.pr["merged"])

    def test_rebase_conflict_requests_native_renovate_reconstruction(self):
        self.api.behind = True
        self.api.pr["base"]["sha"] = "9" * 40
        self.api.refresh_conflict = True
        self.run_candidate()
        self.assertEqual(self.sweep.records[-1]["reason"], "rebase_conflict")
        self.assertEqual(self.sweep.recovery, {self.api.repository})

    def test_late_hold_revokes_merge(self):
        self.api.change_labels_at_boundary = True
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])
        self.assertEqual(self.sweep.records[-1]["reason"], "explicit_hold")

    def test_central_authority_change_revokes_merge(self):
        self.api.authority = "f" * 40
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])
        self.assertEqual(self.sweep.records[-1]["reason"], "central_authority_advanced")

    def test_advanced_branch_is_not_deleted_after_merge(self):
        self.api.branch_advanced = True
        self.run_candidate()
        self.assertTrue(self.api.pr["merged"])
        self.assertFalse(any(op[0] == "DELETE" for op in self.api.operations))

    def test_platform_auto_deletion_race_is_successful_cleanup(self):
        original = self.api.api
        deleted = False

        def api(path, method="GET", data=None):
            nonlocal deleted
            if method == "DELETE":
                deleted = True
                raise merger.ApiError(422)
            if deleted and "/git/ref/" in path:
                raise merger.ApiError(404)
            return original(path, method, data)

        self.api.api = api
        self.run_candidate()
        self.assertTrue(self.api.pr["merged"])
        self.assertEqual([row["reason"] for row in self.sweep.records], ["merge_verified"])

    def test_current_head_maintainer_approval_releases_manual_hold(self):
        self.api.pr["labels"].append({"name": "manual-review"})
        self.api.reviews = [{"state": "APPROVED", "commit_id": self.api.head, "user": {"login": "maintainer"}}]
        self.run_candidate()
        self.assertTrue(self.api.pr["merged"])

    def test_stale_or_read_only_approval_does_not_release_hold(self):
        self.api.pr["labels"].append({"name": "manual-review"})
        self.api.reviews = [{"state": "APPROVED", "commit_id": "f" * 40, "user": {"login": "reader"}}]
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])
        self.api.reviews[0]["commit_id"] = self.api.head
        self.api.permission = "read"
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])

    def test_revoked_review_before_merge_is_not_authorization(self):
        self.api.pr["labels"].append({"name": "manual-review"})
        self.api.reviews = [{"state": "APPROVED", "commit_id": self.api.head, "user": {"login": "maintainer"}}]
        original = self.api.api

        def api(path, method="GET", data=None):
            result = original(path, method, data)
            if path.endswith("/pulls/1") and self.api.pr_reads >= 2:
                self.api.reviews[0]["state"] = "DISMISSED"
            return result

        self.api.api = api
        self.run_candidate()
        self.assertFalse(self.api.pr["merged"])
        self.assertEqual(self.sweep.records[-1]["reason"], "approval_required")

    def test_label_approval_is_bound_to_current_head_and_authorized_actor(self):
        marker = "merge:" + self.api.head
        self.api.pr["labels"] += [{"name": "manual-review"}, {"name": marker}]
        self.api.events = [{"event": "labeled", "label": {"name": marker}, "actor": {"login": "maintainer", "type": "User"}}]
        self.run_candidate()
        self.assertTrue(self.api.pr["merged"])

    def test_public_summary_excludes_repo_names_prs_and_patches(self):
        data = merger.public_summary([{"repository": "private/sensitive", "pull_request": 99, "patch": "SECRET SOURCE", "outcome": "human", "reason": "approval_required"}], 10, 4990, 0)
        text = json.dumps(data)
        for value in ("private/sensitive", "SECRET SOURCE", "pull_request"):
            self.assertNotIn(value, text)
        self.assertEqual(data["operational_failures"], 0)


class GenericPolicyTests(unittest.TestCase):
    def runtime(self, **environment):
        env = {"PATH": os.environ["PATH"], "RENOVATE_CONFIG_PRESET": "github>FutureDevGuys/.github:renovate-config#" + "1" * 40, **environment}
        return json.loads(subprocess.check_output(["node", "-e", "console.log(JSON.stringify(require('./.github/renovate-config.js')))"], cwd=ROOT, env=env, text=True))

    def test_runtime_contains_no_workload_or_repository_specific_rules(self):
        config = self.runtime()
        self.assertEqual(config.get("packageRules", []), [])
        self.assertEqual(json.loads((ROOT / ".github/automerge-policy.json").read_text())["repositories"], {})

    def test_github_lookups_have_explicit_authentication(self):
        config = self.runtime(GITHUB_COM_TOKEN="test-fixture-token")
        rule = next(row for row in config["hostRules"] if row["matchHost"] == "api.github.com")
        self.assertEqual(rule["token"], "test-fixture-token")
        self.assertLessEqual(rule["concurrentRequestLimit"], 4)

    def test_signed_commits_use_configured_private_key_without_publishing_it(self):
        config = self.runtime(RENOVATE_GIT_PRIVATE_KEY="fixture-key", RENOVATE_GIT_AUTHOR="Bot <bot@example.test>")
        self.assertEqual(config["gitPrivateKey"], "fixture-key")
        self.assertEqual(config["gitAuthor"], "Bot <bot@example.test>")

    def test_hash_verified_hooks_allow_only_fixed_command_shape(self):
        pattern = self.runtime()["allowedCommands"][0]
        import re
        command = 'python3 -I -c "import hashlib,os,pathlib,runpy,sys; p=\'scripts/render.py\'; e=\'' + "a" * 64 + '\'; a=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(); a==e or sys.exit(\'post-upgrade script hash mismatch\'); os.environ.clear(); os.environ.update(HOME=\'/nonexistent\',PATH=\'/usr/bin:/bin\',LANG=\'C.UTF-8\',LC_ALL=\'C.UTF-8\'); sys.argv=[p,\'render\']; runpy.run_path(p,run_name=\'__main__\')"'
        self.assertRegex(command, pattern)
        for modified in (command + "; echo injected", command.replace("scripts/render.py", "../render.py"), command.replace("os.environ.clear(); ", ""), command.replace("a" * 64, "unverified")):
            self.assertIsNone(re.fullmatch(pattern, modified))

    def test_non_docker_digest_updates_are_candidates(self):
        preset = json.loads((ROOT / "renovate-config.json").read_text())
        rules = [row for row in preset["packageRules"] if "digest" in row.get("matchUpdateTypes", []) and "automerge-candidate" in row.get("addLabels", [])]
        self.assertTrue(any("matchManagers" not in row and "matchDatasources" not in row for row in rules))
        major = next(row for row in preset["packageRules"] if "major" in row.get("matchUpdateTypes", []))
        self.assertTrue(major["dependencyDashboardApproval"])
        self.assertNotIn("manual-review", major["addLabels"])

    def test_existing_assertions_follow_repository_id_through_rename(self):
        base = json.loads((ROOT / ".github/tests/fixtures/automerge/policy.json").read_text())
        item = base["repositories"]["FutureDevGuys/docker-configs"]
        item["required_checks"] = [{"name": "test", "app_slug": "github-actions"}]
        receipt = {"organization": "FutureDevGuys", "repositories": [{"repository": "FutureDevGuys/renamed", **item, "default_branch": "trunk"}]}
        result = adoption.build_effective_policy(base, receipt)
        self.assertEqual(result["repositories"]["FutureDevGuys/renamed"]["required_checks"], item["required_checks"])
        self.assertEqual(result["repositories"]["FutureDevGuys/renamed"]["default_branch"], "trunk")

    def test_auth_and_configuration_failures_are_not_blindly_retried(self):
        self.assertEqual(runner.classify_failure("config-presets-invalid"), "configuration_or_authentication")
        self.assertEqual(runner.classify_failure("Rate limit exceeded"), "rate_limit")
        self.assertEqual(runner.classify_failure("ECONNRESET"), "transient_provider_failure")

    def test_six_hour_run_and_one_bounded_recovery_chain(self):
        renovate = (ROOT / ".github/workflows/renovate.yml").read_text()
        merge = (ROOT / ".github/workflows/automerge.yml").read_text()
        self.assertIn('cron: "17 */6 * * *"', renovate)
        self.assertIn('cron: "37 * * * *"', merge)
        self.assertIn('ALLOW_RECOVERY: ${{ !inputs.recovery }}', renovate)
        self.assertIn('inputs.allowRecovery', merge)
        self.assertNotIn('inputs.allowRecovery == null', merge)
        self.assertIn("github.event_name == 'schedule' || inputs.allowRecovery", merge)
        self.assertIn('-f recovery=true', merge)
        self.assertIn('Retain only two encrypted cache snapshots', renovate)
        self.assertIn('reverse | .[2:][] | .id', renovate)
        for text in (renovate, merge):
            self.assertNotIn('path: automerge-candidates/', text)
            self.assertNotIn('path: dependency-automation-adopters.json', text)


@unittest.skipUnless(shutil.which("gpg"), "GnuPG is required for artifact encryption")
class PrivateArtifactTests(unittest.TestCase):
    def test_encrypted_roundtrip_and_wrong_key_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "private.json").write_text('{"source":"private fixture"}')
            encrypted = root / "cache.gpg"
            with patch.dict(os.environ, {"ARTIFACT_ENCRYPTION_KEY": "fixture-only-not-a-real-token"}):
                artifacts.pack(source, encrypted)
                self.assertNotIn(b"private fixture", encrypted.read_bytes())
                artifacts.unpack(encrypted, root / "restored")
            self.assertEqual((root / "restored/private.json").read_text(), (source / "private.json").read_text())
            with patch.dict(os.environ, {"ARTIFACT_ENCRYPTION_KEY": "wrong-fixture-key"}):
                with self.assertRaises(ValueError):
                    artifacts.unpack(encrypted, root / "invalid")
            self.assertFalse((root / "invalid").exists())

    def test_archive_symlink_is_rejected_before_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "escape").symlink_to("/etc/passwd")
            with patch.dict(os.environ, {"ARTIFACT_ENCRYPTION_KEY": "fixture-key"}):
                artifacts.pack(source, root / "archive.gpg")
                with self.assertRaises(ValueError):
                    artifacts.unpack(root / "archive.gpg", root / "destination")


if __name__ == "__main__":
    unittest.main()
