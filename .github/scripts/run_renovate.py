#!/usr/bin/env python3
"""Run the pinned native Renovate image with private logs and bounded recovery."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import time


ENVIRONMENT = (
    "RENOVATE_TOKEN", "GITHUB_COM_TOKEN", "RENOVATE_CONFIG_PRESET", "RENOVATE_REPOSITORIES",
    "RENOVATE_DRY_RUN", "RENOVATE_REPOSITORY_CACHE", "RENOVATE_GIT_PRIVATE_KEY", "RENOVATE_GIT_AUTHOR",
    "RENOVATE_GIT_IGNORED_AUTHORS",
    "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GHCR_USERNAME", "GHCR_TOKEN",
)


def classify_failure(log: str) -> str:
    text = log.lower()
    if any(value in text for value in ("rate limit", "rate-limit", "toomanyrequests", "http 429")):
        return "rate_limit"
    if any(value in text for value in ("config-validation", "config-presets-invalid", "invalid token", "bad credentials", "unauthorized")):
        return "configuration_or_authentication"
    if any(value in text for value in ("etimedout", "econnreset", "socket hang up", "external-host-error", "status code 500", "status code 502", "status code 503", "status code 504")):
        return "transient_provider_failure"
    return "execution_failure"


def main() -> int:
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    private = Path(os.environ["RUNNER_TEMP"]) / "dependency-private"
    private.mkdir(mode=0o700, exist_ok=True)
    cache = Path("/tmp/renovate/cache")
    image = os.environ["RENOVATE_IMAGE"]
    if not re.fullmatch(r"renovate/renovate:[0-9]+\.[0-9]+\.[0-9]+@sha256:[a-f0-9]{64}", image):
        raise ValueError("Renovate runtime must have an exact tag and digest")
    receipt = json.loads((workspace / "dependency-automation-adopters.json").read_text())
    os.environ["RENOVATE_REPOSITORIES"] = ",".join(receipt["selected_repositories"])
    os.environ["GITHUB_COM_TOKEN"] = os.environ.get("GITHUB_COM_TOKEN") or os.environ["RENOVATE_TOKEN"]
    os.environ["GH_TOKEN"] = os.environ["RENOVATE_TOKEN"]
    last_failure = "execution_failure"
    for attempt in (1, 2):
        limits = json.loads(subprocess.check_output(["gh", "api", "rate_limit"], text=True))
        budgets = [limits["resources"][key] for key in ("core", "graphql")]
        if any(budget["remaining"] < 500 for budget in budgets):
            print("GitHub API budget is low; preserving cache and deferring to the next scheduled run.")
            return 1
        name = f"renovate-{os.environ['GITHUB_RUN_ID']}-{attempt}"
        command = ["docker", "run", "--rm", "--init", "--name", name, "--user", "12021:0"]
        command += ["--volume", f"{cache}:/tmp/renovate/cache"]
        command += ["--volume", f"{workspace / '.github/renovate-config.js'}:/opt/renovate/config.js:ro"]
        for variable in ENVIRONMENT:
            if os.environ.get(variable):
                command += ["--env", variable]
        command += ["--env", "RENOVATE_CONFIG_FILE=/opt/renovate/config.js", "--env", "LOG_LEVEL=info", image]
        path = private / f"renovate-attempt-{attempt}.log"
        with path.open("wb") as log:
            path.chmod(0o600)
            try:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2400)
                status = result.returncode
            except subprocess.TimeoutExpired:
                subprocess.run(["docker", "stop", "--time", "10", name], capture_output=True)
                status = 124
        if status == 0:
            print(f"Renovate completed successfully on attempt {attempt}; detailed logs are encrypted.")
            return 0
        last_failure = "execution_timeout" if status == 124 else classify_failure(path.read_text(errors="replace"))
        print(f"Renovate attempt {attempt} failed: {last_failure}.")
        if last_failure != "transient_provider_failure" or attempt == 2:
            break
        time.sleep(30)
    print("Renovate did not complete; cache and private diagnostics will be preserved for recovery.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
