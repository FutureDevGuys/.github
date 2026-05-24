const parseList = (value) => (value || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

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

const repositories = parseList(process.env.RENOVATE_REPOSITORIES);
const autodiscoverFilter = parseList(
  process.env.RENOVATE_AUTODISCOVER_FILTER || 'FutureDevGuys/*',
);

const config = {
  platform: process.env.RENOVATE_PLATFORM || 'github',
  endpoint: process.env.RENOVATE_ENDPOINT || 'https://api.github.com',
  onboarding: false,
  requireConfig: 'optional',
  globalExtends: [
    process.env.RENOVATE_CONFIG_PRESET || 'github>FutureDevGuys/.github:renovate-config',
  ],
  gitAuthor: 'Renovate Bot <bot@lablabland.com>',
  timezone: process.env.RENOVATE_TIMEZONE || 'America/Phoenix',
  cacheDir: process.env.RENOVATE_CACHE_DIR || '/tmp/renovate/cache',
  repositoryCache: process.env.RENOVATE_REPOSITORY_CACHE || 'enabled',
  hostRules: dockerHostRules,
};

if (repositories.length > 0) {
  config.repositories = repositories;
  config.autodiscover = false;
} else {
  config.autodiscover = process.env.RENOVATE_AUTODISCOVER !== 'false';
  if (autodiscoverFilter.length > 0) {
    config.autodiscoverFilter = autodiscoverFilter;
  }
}

module.exports = config;
