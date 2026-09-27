#!/usr/bin/env python3
"""Merge eligible dependency PRs with fresh evidence and bounded native recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from resolve_dependency_automation_adopters import build_effective_policy
from validate_automerge_candidate import evaluate_candidate
from validate_automerge_refresh import evaluate_refresh_candidate
from validate_automerge_refresh_postcondition import evaluate_refresh_postcondition
from validate_automerge_merge_postcondition import evaluate_merge_postcondition


HARD_HOLDS = {"do-not-merge", "contract-failing"}
REVIEW_HOLDS = {"manual-review", "migration-required", "database", "stateful"}
SHA = re.compile(r"[a-f0-9]{40}")


class ApiError(Exception):
    def __init__(self, status: int):
        self.status = status
        super().__init__(f"GitHub API request failed ({status})")


class GitHub:
    def __init__(self):
        self.token = os.environ["GH_TOKEN"]
        self.calls = 0
        self.remaining = None

    def api(self, path, method="GET", data=None):
        if self.remaining is not None and self.remaining < 200:
            raise ApiError(429)
        for attempt in range(3):
            request = Request(
                "https://api.github.com/" + path,
                data=json.dumps(data).encode() if data is not None else None,
                method=method,
                headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            )
            self.calls += 1
            try:
                with urlopen(request, timeout=30) as response:
                    if response.headers.get("X-RateLimit-Remaining"):
                        self.remaining = int(response.headers["X-RateLimit-Remaining"])
                    raw = response.read()
                    return json.loads(raw) if raw else None
            except HTTPError as error:
                if method != "GET" or error.code not in {500, 502, 503, 504} or attempt == 2:
                    raise ApiError(error.code) from None
            except URLError:
                if method != "GET" or attempt == 2:
                    raise ApiError(0) from None
            time.sleep(2 ** attempt)

    def pages(self, path):
        result = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 101):
            rows = self.api(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(rows, list):
                raise ValueError("GitHub pagination returned a non-list")
            result.extend(rows)
            if len(rows) < 100:
                return result
        raise ValueError("GitHub pagination exceeded its bounded limit")


def normalized_pr(pr):
    head = pr.get("head", {})
    repository = head.get("repo") or {}
    owner = repository.get("owner") or {}
    author = pr.get("user") or {}
    return {
        "number": pr["number"], "state": "MERGED" if pr.get("merged") else pr["state"].upper(),
        "isDraft": pr.get("draft", False), "baseRefName": pr["base"]["ref"], "baseRefOid": pr["base"]["sha"],
        "headRefName": head.get("ref"), "headRefOid": head.get("sha"),
        "headRepository": {"nameWithOwner": repository.get("full_name"), "id": repository.get("node_id")},
        "headRepositoryOwner": {"login": owner.get("login")},
        "author": {"login": author.get("login"), "id": author.get("node_id"), "is_bot": author.get("type") == "Bot"},
        "commitCount": pr.get("commits"), "changedFiles": pr.get("changed_files"),
        "mergedAt": pr.get("merged_at"), "mergeCommit": {"oid": pr.get("merge_commit_sha")},
    }


def authorization_surface(pr):
    normalized = normalized_pr(pr)
    normalized["labels"] = sorted(label["name"] for label in pr.get("labels", []))
    return normalized


def public_summary(records, calls, remaining, failures):
    from collections import Counter
    return {"schema_version": 1, "outcomes": dict(Counter(row["outcome"] for row in records)), "reasons": dict(Counter(row["reason"] for row in records)), "api_requests": calls, "api_remaining": remaining, "operational_failures": failures}


def human_approved(api, repository, pr):
    """Approval binds to this exact head; a later commit needs a new approval."""
    head = pr["head"]["sha"]
    reviews = api.pages(f"repos/{repository}/pulls/{pr['number']}/reviews")
    latest = {}
    for review in reviews:
        if review.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[review["user"]["login"]] = review
    actors = {review["user"]["login"] for review in latest.values() if review.get("state") == "APPROVED" and review.get("commit_id") == head}
    marker = f"merge:{head}"
    if any(label["name"] == marker for label in pr.get("labels", [])):
        events = api.pages(f"repos/{repository}/issues/{pr['number']}/events")
        for event in reversed(events):
            if event.get("event") == "labeled" and event.get("label", {}).get("name") == marker:
                actor = event.get("actor", {})
                if actor.get("type") == "User":
                    actors.add(actor["login"])
                break
    for actor in actors:
        permission = api.api(f"repos/{repository}/collaborators/{quote(actor, safe='')}/permission")
        if permission.get("permission") in {"admin", "write", "maintain"}:
            return True
    return False


class Sweep:
    def __init__(self, api, policy, private):
        self.api = api
        self.policy = policy
        self.private = private
        self.records = []
        self.recovery = set()
        self.authority = os.environ["GITHUB_REPOSITORY"]
        self.authority_sha = os.environ["GITHUB_SHA"]

    def record(self, repository, number, outcome, reason):
        self.records.append({"repository": repository, "pull_request": number, "outcome": outcome, "reason": reason})

    def request_rebuild(self, repository, pr, reason):
        labels = {label["name"] for label in pr.get("labels", [])}
        if "rebase" not in labels:
            self.api.api(f"repos/{repository}/issues/{pr['number']}/labels", "POST", {"labels": ["rebase"]})
            self.recovery.add(repository)
        self.record(repository, pr["number"], "recovery", reason)

    def process(self, repository, number, default_branch):
        api = self.api
        prefix = f"repos/{repository}"
        for refresh_pass in range(3):
            pr = api.api(f"{prefix}/pulls/{number}")
            if pr["state"] != "open" or pr.get("draft") or pr["base"]["ref"] != default_branch or not pr["head"]["ref"].startswith("renovate/"):
                return
            labels = {label["name"] for label in pr.get("labels", [])}
            if labels & HARD_HOLDS:
                self.record(repository, number, "human", "explicit_hold")
                return
            if labels & REVIEW_HOLDS or "automerge-candidate" not in labels:
                if not human_approved(api, repository, pr):
                    self.record(repository, number, "human", "approval_required")
                    return
            head = pr["head"]["sha"]
            base = api.api(f"{prefix}/commits/{quote(default_branch, safe='')}")["sha"]
            commits = api.pages(f"{prefix}/pulls/{number}/commits")
            files = api.pages(f"{prefix}/pulls/{number}/files")
            comparison = api.api(f"{prefix}/compare/{base}...{head}")
            normalized = normalized_pr(pr)
            refresh = evaluate_refresh_candidate(repository=repository, policy=self.policy, pull_request=normalized, commits=commits, changed_files=files, comparison=comparison, current_base_sha=base)
            if refresh["action"] == "block":
                if refresh["reason"] in {"comparison_evidence_stale", "protected_caller_changed", "refresh_committer_protected_change"}:
                    self.request_rebuild(repository, pr, refresh["reason"])
                else:
                    self.record(repository, number, "blocked", refresh["reason"])
                return
            # Unsigned legacy commits are rebuilt by Renovate using its configured signing key.
            if any(not commit.get("commit", {}).get("verification", {}).get("verified") for commit in commits):
                self.request_rebuild(repository, pr, "signed_rebuild_required")
                return
            if refresh["action"] == "refresh":
                if refresh_pass == 2:
                    self.record(repository, number, "pending", "base_kept_advancing")
                    return
                try:
                    api.api(f"{prefix}/pulls/{number}/update-branch", "PUT", {"expected_head_sha": head, "update_method": "rebase"})
                except ApiError as error:
                    if error.status == 422:
                        self.request_rebuild(repository, pr, "rebase_conflict")
                        return
                    raise
                for _ in range(5):
                    time.sleep(2)
                    updated = api.api(f"{prefix}/pulls/{number}")
                    new_head = updated["head"]["sha"]
                    if new_head == head:
                        continue
                    new_base = api.api(f"{prefix}/commits/{quote(default_branch, safe='')}")["sha"]
                    new_comparison = api.api(f"{prefix}/compare/{new_base}...{new_head}")
                    verified = evaluate_refresh_postcondition(old_head_sha=head, current_base_sha=new_base, pull_request=normalized_pr(updated), comparison=new_comparison, default_branch=default_branch)
                    if verified["verified"]:
                        break
                else:
                    self.record(repository, number, "pending", "refresh_in_progress")
                    return
                continue
            checks = api.api(f"{prefix}/commits/{head}/check-runs?per_page=100")
            statuses = api.api(f"{prefix}/commits/{head}/status?per_page=100")
            candidate = evaluate_candidate(repository=repository, policy=self.policy, pull_request=normalized, commits=commits, checks=checks, statuses=statuses)
            if not candidate["eligible"]:
                reason = candidate["reason"]
                self.record(repository, number, "pending" if reason in {"check_pending", "status_pending"} else "blocked", reason)
                return
            # Reread the authorization and all observed checks at the merge boundary.
            current = api.api(f"{prefix}/pulls/{number}")
            current_base = api.api(f"{prefix}/commits/{quote(default_branch, safe='')}")["sha"]
            if authorization_surface(current) != authorization_surface(pr) or current_base != base:
                continue
            final_checks = api.api(f"{prefix}/commits/{head}/check-runs?per_page=100")
            final_statuses = api.api(f"{prefix}/commits/{head}/status?per_page=100")
            final = evaluate_candidate(repository=repository, policy=self.policy, pull_request=normalized_pr(current), commits=commits, checks=final_checks, statuses=final_statuses)
            if not final["eligible"]:
                self.record(repository, number, "pending", final["reason"])
                return
            if current.get("mergeable") is not True or current.get("mergeable_state") not in {"clean", "has_hooks"}:
                if current.get("mergeable_state") == "dirty":
                    self.request_rebuild(repository, current, "merge_conflict")
                else:
                    self.record(repository, number, "pending", "branch_protection_or_mergeability")
                return
            authority = api.api(f"repos/{self.authority}/commits/main")["sha"]
            if authority != self.authority_sha:
                self.record(repository, number, "pending", "central_authority_advanced")
                return
            try:
                response = api.api(f"{prefix}/pulls/{number}/merge", "PUT", {"sha": head, "merge_method": "squash"})
            except ApiError as error:
                if error.status in {405, 409, 422}:
                    self.record(repository, number, "pending", "merge_rejected")
                    return
                raise
            if response.get("merged") is not True:
                self.record(repository, number, "pending", "merge_not_completed")
                return
            merged = api.api(f"{prefix}/pulls/{number}")
            merge_sha = merged.get("merge_commit_sha", "")
            if not SHA.fullmatch(merge_sha):
                self.record(repository, number, "blocked", "merge_postcondition_unknown")
                return
            merged_commit = api.api(f"{prefix}/commits/{merge_sha}")
            latest_base = api.api(f"{prefix}/commits/{quote(default_branch, safe='')}")["sha"]
            merged_comparison = api.api(f"{prefix}/compare/{merge_sha}...{latest_base}")
            verified = evaluate_merge_postcondition(authorized_head_sha=head, authorized_base_sha=base, current_base_sha=latest_base, pull_request=normalized_pr(merged), merge_commit=merged_commit, comparison=merged_comparison, default_branch=default_branch)
            if not verified["verified"]:
                self.record(repository, number, "blocked", "merge_postcondition_unknown")
                return
            self.record(repository, number, "merged", "merge_verified")
            ref = "heads/" + pr["head"]["ref"]
            try:
                existing = api.api(f"{prefix}/git/ref/{ref}")
                if existing.get("object", {}).get("sha") == head:
                    api.api(f"{prefix}/git/refs/{ref}", "DELETE")
            except ApiError as error:
                if error.status != 404:
                    self.record(repository, number, "pending", "branch_cleanup_required")
            return
        self.record(repository, number, "pending", "candidate_changed_during_validation")


def main() -> int:
    private = Path(os.environ["RUNNER_TEMP"]) / "dependency-private"
    private.mkdir(mode=0o700, exist_ok=True)
    receipt = json.loads(Path("dependency-automation-adopters.json").read_text())
    base = json.loads(Path(".github/automerge-policy.json").read_text())
    policy = build_effective_policy(base, receipt)
    api = GitHub()
    sweep = Sweep(api, policy, private)
    failures = 0
    for row in receipt["repositories"]:
        repository = row["repository"]
        try:
            prs = api.pages(f"repos/{repository}/pulls?state=open&base={quote(row['default_branch'], safe='')}")
            for pr in prs:
                if pr["head"]["ref"].startswith("renovate/") and not pr.get("draft"):
                    sweep.process(repository, pr["number"], row["default_branch"])
        except (ApiError, ValueError, KeyError) as error:
            failures += 1
            sweep.record(repository, 0, "blocked", f"api_{error.status}" if isinstance(error, ApiError) else "evidence_invalid")
            if isinstance(error, ApiError) and error.status in {403, 429}:
                break
    (private / "outcomes.json").write_text(json.dumps(sweep.records, indent=2) + "\n")
    (private / "recovery-repositories.json").write_text(json.dumps(sorted(sweep.recovery)) + "\n")
    summary = public_summary(sweep.records, api.calls, api.remaining, failures)
    Path("automerge-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 1 if failures or any(row["outcome"] == "blocked" for row in sweep.records) else 0


if __name__ == "__main__":
    raise SystemExit(main())
