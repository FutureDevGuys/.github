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
const exactPresetPattern = /^github>FutureDevGuys\/\.github:renovate-config#[0-9a-f]{40}$/;
const artifactLockRendererSha256 = '96265e8d6e741353dfa0651a16d13f4d552ba1e1516d8d1ec637420342aedf2e';
const dockerArtifactLockCommand = `python3 -I -c "import hashlib,os,pathlib,runpy,sys; p='scripts/artifact_lock.py'; e='${artifactLockRendererSha256}'; a=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(); a==e or sys.exit(f'artifact_lock.py digest {a} != policy {e}'); os.environ.clear(); os.environ.update(HOME='/nonexistent',PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8'); sys.argv=[p,'render']; runpy.run_path(p,run_name='__main__')"`;
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

if (!exactPresetPattern.test(preset)) {
  throw new Error(
    'RENOVATE_CONFIG_PRESET must pin github>FutureDevGuys/.github:renovate-config to an exact 40-character commit SHA',
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
  allowedCommands: [
    `^${escapeRegExp(dockerArtifactLockCommand)}$`,
  ],
  allowShellExecutorForPostUpgradeCommands: false,
  packageRules: [
    {
      description: 'Regenerate the Docker owner artifact lock with a policy-pinned, credential-stripped renderer.',
      matchRepositories: ['FutureDevGuys/docker-configs'],
      postUpgradeTasks: {
        commands: [dockerArtifactLockCommand],
        fileFilters: ['contracts/artifact-lock.v2.json'],
        executionMode: 'branch',
      },
    },
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
