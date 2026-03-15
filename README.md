# FutureDevGuys Org Automation

This repository is the shared automation home for `FutureDevGuys`.

## Renovate

- Shared baseline: `.github/renovate-config.js`
- Scheduled runtime: `.github/workflows/renovate.yml`
- Scope: org autodiscovery for `FutureDevGuys/*`

Repo-specific policy remains in each repository's own `renovate.json`.

Current examples:

- `docker-configs/renovate.json` for Docker-VM-specific image review rules
- `homelab-iac/renovate.json` for shell pin managers
- `personal-containers/renovate.json` for submodule policy

## Required Actions secrets

- `RENOVATE_TOKEN`
- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` when private Docker Hub access is needed
- `GHCR_USERNAME` and `GHCR_TOKEN` when private GHCR access is needed

The optional manual Docker runner in `FutureDevGuys/docker-configs` fetches this
repo at runtime so there is only one checked-in shared Renovate baseline.
