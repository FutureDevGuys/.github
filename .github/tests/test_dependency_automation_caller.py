#!/usr/bin/env python3
"""Contract tests for the repository-local dependency-automation marker."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/resolve_dependency_automation_adopters.py"
FIXTURE = ROOT / ".github/tests/fixtures/dependency-automation-caller.yml"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "resolve_dependency_automation_adopters", SCRIPT
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_module()
        cls.valid = FIXTURE.read_text(encoding="utf-8")

    def assert_rejected(self, text: str, expected: str) -> None:
        with self.assertRaisesRegex(self.contract.ContractError, expected):
            self.contract.parse_caller(text)

    def test_exact_minimal_caller_is_accepted(self) -> None:
        parsed = self.contract.parse_caller(self.valid)
        self.assertEqual(parsed.revision, "1" * 40)

    def test_mutable_reusable_workflow_ref_is_rejected(self) -> None:
        self.assert_rejected(self.valid.replace("@" + "1" * 40, "@main"), "SHA")

    def test_additional_automatic_trigger_is_rejected(self) -> None:
        self.assert_rejected(
            self.valid.replace(
                "  workflow_dispatch:\n", "  workflow_dispatch:\n  push:\n"
            ),
            "byte-exact",
        )

    def test_permission_expansion_is_rejected(self) -> None:
        self.assert_rejected(
            self.valid.replace("  contents: read\n", "  contents: write\n", 1),
            "byte-exact",
        )

    def test_inline_business_logic_is_rejected(self) -> None:
        self.assert_rejected(
            self.valid
            + "  business-logic:\n"
            + "    runs-on: ubuntu-latest\n"
            + "    steps:\n"
            + "      - run: echo forbidden\n",
            "byte-exact",
        )

    def test_job_condition_or_inputs_are_rejected(self) -> None:
        self.assert_rejected(
            self.valid.replace(
                "    permissions:\n",
                "    if: always()\n"
                "    with:\n"
                "      mode: unsafe\n"
                "    permissions:\n",
            ),
            "byte-exact",
        )

    def test_wrong_shared_workflow_is_rejected(self) -> None:
        self.assert_rejected(
            self.valid.replace(
                "dependency-automation-marker.yml", "security-scan.yml"
            ),
            "shared dependency-automation marker",
        )


class AdoptionSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = load_module()
        cls.valid = FIXTURE.read_text(encoding="utf-8")

    def test_policy_owner_and_only_valid_markers_are_selected(self) -> None:
        repositories = [
            {
                "full_name": "FutureDevGuys/.github",
                "id": 1,
                "node_id": "R_owner",
                "archived": False,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
            },
            {
                "full_name": "FutureDevGuys/adopter",
                "id": 2,
                "node_id": "R_adopter",
                "archived": False,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
            },
            {
                "full_name": "FutureDevGuys/unmarked",
                "id": 3,
                "node_id": "R_unmarked",
                "archived": False,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
            },
            {
                "full_name": "FutureDevGuys/archived",
                "id": 4,
                "node_id": "R_archived",
                "archived": True,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
            },
        ]

        def marker(repository: dict[str, object]) -> tuple[str, str] | None:
            if repository["full_name"] == "FutureDevGuys/adopter":
                return ("a" * 40, self.valid)
            return None

        receipt = self.contract.resolve_adopters(
            "FutureDevGuys", repositories, marker
        )
        self.assertEqual(
            [row["repository"] for row in receipt["repositories"]],
            ["FutureDevGuys/.github", "FutureDevGuys/adopter"],
        )
        self.assertTrue(receipt["repositories"][0]["policy_owner"])
        self.assertFalse(receipt["repositories"][1]["policy_owner"])
        self.assertEqual(receipt["repositories"][1]["caller_revision"], "1" * 40)

    def test_invalid_present_marker_fails_the_whole_resolution(self) -> None:
        repositories = [
            {
                "full_name": "FutureDevGuys/broken",
                "id": 2,
                "node_id": "R_broken",
                "archived": False,
                "disabled": False,
                "fork": False,
                "default_branch": "main",
            }
        ]
        with self.assertRaisesRegex(self.contract.ContractError, "broken"):
            self.contract.resolve_adopters(
                "FutureDevGuys",
                repositories,
                lambda _repository: ("a" * 40, "name: not-the-contract\n"),
            )

    def test_public_and_private_inventory_counts_must_be_complete(self) -> None:
        repositories = [
            {"full_name": "FutureDevGuys/public", "private": False},
            {"full_name": "FutureDevGuys/private", "private": True},
        ]
        self.contract.validate_inventory_completeness(
            {"login": "FutureDevGuys", "public_repos": 1, "total_private_repos": 1},
            "FutureDevGuys",
            repositories,
        )
        with self.assertRaisesRegex(self.contract.ContractError, "incomplete"):
            self.contract.validate_inventory_completeness(
                {
                    "login": "FutureDevGuys",
                    "public_repos": 1,
                    "total_private_repos": 2,
                },
                "FutureDevGuys",
                repositories,
            )

    def test_effective_policy_allows_new_adopter_but_rejects_known_id_drift(self) -> None:
        base = {
            "schema_version": 1,
            "organization": {"login": "FutureDevGuys"},
            "trusted_renovate_identity": {"login": "renovate"},
            "repositories": {},
        }
        receipt = {
            "organization": "FutureDevGuys",
            "repositories": [
                {
                    "repository": "FutureDevGuys/new",
                    "repository_id": 7,
                    "head_repository_id": "R_new",
                }
            ]
        }
        effective = self.contract.build_effective_policy(base, receipt)
        self.assertEqual(
            effective["repositories"]["FutureDevGuys/new"],
            {
                "repository_id": 7,
                "head_repository_id": "R_new",
                "required_checks": [],
            },
        )
        base["repositories"]["FutureDevGuys/new"] = {
            "repository_id": 8,
            "head_repository_id": "R_new",
            "required_checks": [],
        }
        with self.assertRaisesRegex(self.contract.ContractError, "identity conflicts"):
            self.contract.build_effective_policy(base, receipt)


if __name__ == "__main__":
    unittest.main()
