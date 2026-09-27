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
const preset = process.env.RENOVATE_CONFIG_PRESET || '';
const exactPresetPattern = /^github>[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+:renovate-config#[0-9a-f]{40}$/;
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Optional repo-owned hooks must verify an exact source hash before execution.
// The command form is fixed; only a relative Python path, SHA-256 and one argument vary.
const hookCommand = `python3 -I -c "import hashlib,os,pathlib,runpy,sys; p='HOOK_PATH'; e='HOOK_SHA256'; a=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(); a==e or sys.exit('post-upgrade script hash mismatch'); os.environ.clear(); os.environ.update(HOME='/nonexistent',PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8'); sys.argv=[p,'HOOK_ARGUMENT']; runpy.run_path(p,run_name='__main__')"`;
const hookPattern = '^' + escapeRegExp(hookCommand)
  .replace('HOOK_PATH', '(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\\.py')
  .replace('HOOK_SHA256', '[a-f0-9]{64}')
  .replace('HOOK_ARGUMENT', '[A-Za-z0-9_-]+') + '$';
const githubToken = process.env.GITHUB_COM_TOKEN || process.env.RENOVATE_TOKEN;

if (!exactPresetPattern.test(preset)) {
  throw new Error(
    'RENOVATE_CONFIG_PRESET must pin the shared renovate-config preset to an exact 40-character commit SHA',
  );
}

const config = {
  platform: process.env.RENOVATE_PLATFORM || 'github',
  endpoint: process.env.RENOVATE_ENDPOINT || 'https://api.github.com',
  onboarding: false,
  requireConfig: 'optional',
  globalExtends: [
    preset,
  ],
  force: {
    automerge: false,
    platformAutomerge: false,
  },
  allowedCommands: [hookPattern],
  allowShellExecutorForPostUpgradeCommands: false,
  ...(process.env.RENOVATE_GIT_AUTHOR ? {gitAuthor: process.env.RENOVATE_GIT_AUTHOR} : {}),
  ...(process.env.RENOVATE_GIT_PRIVATE_KEY ? {gitPrivateKey: process.env.RENOVATE_GIT_PRIVATE_KEY} : {}),
  ...(process.env.RENOVATE_GIT_IGNORED_AUTHORS ? {gitIgnoredAuthors: JSON.parse(process.env.RENOVATE_GIT_IGNORED_AUTHORS)} : {}),
  timezone: process.env.RENOVATE_TIMEZONE || 'America/Phoenix',
  cacheDir: process.env.RENOVATE_CACHE_DIR || '/tmp/renovate/cache',
  repositoryCache: process.env.RENOVATE_REPOSITORY_CACHE || 'enabled',
  hostRules: [
    ...dockerHostRules,
    ...(githubToken ? [{hostType: 'github', matchHost: 'api.github.com', token: githubToken, concurrentRequestLimit: 4}] : []),
  ],
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
