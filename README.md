# FutureDevGuys Org Automation

This repository is the shared automation home for `FutureDevGuys`.

## Renovate

- Shared baseline: `.github/renovate-config.js`
- Scheduled runtime: `.github/workflows/renovate.yml`
- Scope: org autodiscovery for `FutureDevGuys/*`

Repo-specific policy remains in each repository's own `renovate.json` (e.g.
Docker image review rules, version pin managers, submodule pointer policy).

### Version pin annotations

The shared baseline includes a generic regex manager that tracks
`# renovate:` comment annotations in any YAML file across the org.
To pin a version and let Renovate auto-bump it, add this pattern:

```yaml
# renovate: datasource=github-releases depName=owner/repo
my_tool_version: "v1.2.3"
```

The variable must end with `_version` and the value must be quoted.
Supported `datasource` values include `github-releases`, `github-tags`,
`pypi`, `npm`, etc. — see [Renovate datasources](https://docs.renovatebot.com/modules/datasource/).

No per-repo `renovate.json` change is needed to use this — the org
baseline picks it up automatically.

## Required Actions secrets

- `RENOVATE_TOKEN`
- `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` when private Docker Hub access is needed
- `GHCR_USERNAME` and `GHCR_TOKEN` when private GHCR access is needed

An optional manual Docker runner can fetch this repo at runtime so there is
only one checked-in shared Renovate baseline.
