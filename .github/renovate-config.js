const dockerHostRules = [
  ['docker.io', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['index.docker.io', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['registry-1.docker.io', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['auth.docker.io', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['registry.hub.docker.com', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['hub.docker.com', process.env.DOCKERHUB_USERNAME, process.env.DOCKERHUB_TOKEN],
  ['ghcr.io', process.env.GHCR_USERNAME, process.env.GHCR_TOKEN],
]
  .filter(([, username, password]) => typeof username === 'string' && username.length > 0
    && typeof password === 'string' && password.length > 0)
  .map(([matchHost, username, password]) => ({
    hostType: 'docker',
    matchHost,
    username,
    password,
  }));

module.exports = {
  dockerMaxPages: 3,
  platformAutomerge: false,
  rebaseWhen: 'behind-base-branch',
  dependencyDashboard: true,
  timezone: 'America/Phoenix',
  onboarding: false,
  requireConfig: 'optional',
  platform: 'github',
  autodiscover: true,
  autodiscoverFilter: ['FutureDevGuys/*'],
  gitAuthor: 'Renovate Bot <bot@lablabland.com>',
  ignorePaths: ['archived/**', '**/archived/**'],
  cacheDir: '/cache',
  repositoryCache: 'enabled',
  hostRules: dockerHostRules,

  extends: [
    'config:recommended',
    ':automergeDigest',
    ':label(renovate)',
    ':semanticCommits',
    'docker:pinDigests',
    'group:allNonMajor',
    'helpers:pinGitHubActionDigests',
    'mergeConfidence:all-badges',
    ':automergeMinor',
  ],

  prConcurrentLimit: 12,
  prHourlyLimit: 6,

  packageRules: [
    {
      matchFileNames: ['archived/**', '**/archived/**'],
      enabled: false,
    },
    {
      matchDatasources: ['docker'],
      matchPackageNames: ['/^[^.:/]+([/][^/]+)*$/'],
      minimumReleaseAge: '3 days',
      internalChecksFilter: 'strict',
    },
    {
      matchDatasources: ['docker'],
      matchPackageNames: ['eceasy/cli-proxy-api'],
      minimumReleaseAge: null,
    },
    {
      matchDatasources: ['docker'],
      matchUpdateTypes: ['digest'],
      groupName: 'docker-digests',
      automerge: true,
      automergeType: 'pr',
    },
    {
      matchManagers: ['dockerfile', 'docker-compose'],
      matchUpdateTypes: ['patch', 'minor'],
      groupName: 'docker-base-images',
      automerge: true,
      automergeType: 'pr',
    },
    {
      matchManagers: ['dockerfile', 'docker-compose'],
      matchUpdateTypes: ['major'],
      groupName: 'docker-base-images',
      automerge: false,
    },
    {
      matchManagers: ['github-actions'],
      groupName: 'github-actions',
      automerge: true,
      automergeType: 'pr',
    },
    {
      matchManagers: ['github-actions'],
      matchUpdateTypes: ['patch'],
      groupName: 'gha-patches',
      automerge: true,
      automergeStrategy: 'auto',
      automergeType: 'pr',
    },
  ],
};
