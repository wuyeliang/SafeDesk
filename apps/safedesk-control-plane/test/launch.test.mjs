import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { Launcher, buildLaunchCommand, workspaceAllowed } from '../src/launch.mjs';
import { compileManifest } from '../src/policy.mjs';

const makeManifest = (id = 'sbx-launch01', overrides = {}) => {
  const sandbox = {
    id, name: 'launch-test', agent: 'claude-code', policyId: 'balanced',
    workspace: '/srv/work/demo', packages: ['wasmer/bash@latest'],
    credentials: ['github-read'], mcpServers: ['github'],
    status: 'running', createdAt: '2026-10-24T00:00:00.000Z', ...overrides,
  };
  const plan = compileManifest(sandbox);
  if (sandbox.egressToken) plan.egress = { token: sandbox.egressToken };
  return plan;
};

test('dry-run mode when wasmer missing', () => {
  const { argv, mode } = buildLaunchCommand(makeManifest(), { wasmer: 'wasmer-does-not-exist-xyz' });
  assert.equal(mode, 'dry-run');
  assert.equal(argv[0], 'sleep');
});

test('wasmer command contains sandbox env and volume when binary present', () => {
  const plan = makeManifest('sbx-launch01', { egressToken: 'abc123' });
  plan.environment = { 'github-read': '{{SD_CRED_sbx-launch01_x}}' };
  const { argv, mode } = buildLaunchCommand(plan, { wasmer: 'sh', proxyUrl: 'http://127.0.0.1:9000' });
  if (mode === 'dry-run') return;
  const joined = argv.join(' ');
  assert.ok(joined.includes('SAFEDESK_SANDBOX_ID=sbx-launch01'));
  assert.ok(argv.includes('--volume'));
  assert.ok(joined.includes('http://127.0.0.1:9000'));
  assert.ok(joined.includes('SAFEDESK_EGRESS_AUTH=sbx-launch01:abc123'));
});

test('workspace whitelist', () => {
  assert.ok(workspaceAllowed('/srv/work/app', []));
  assert.ok(workspaceAllowed('/srv/work/app', ['/srv']));
  assert.ok(!workspaceAllowed('/etc/passwd', ['/srv']));
  assert.ok(!workspaceAllowed('/srv/../etc', ['/srv']));
  assert.ok(!workspaceAllowed('relative/path', []));
});

function makeLauncher() {
  const dir = mkdtempSync(join(tmpdir(), 'safedesk-launch-'));
  return { dir, launcher: new Launcher(join(dir, 'runners')) };
}

const sleep = (ms) => new Promise((resolveFn) => setTimeout(resolveFn, ms));

test('start info pause resume stop lifecycle', async () => {
  const { dir, launcher } = makeLauncher();
  const info = launcher.start({ id: 'sbx-launch01', policyId: 'balanced' }, makeManifest());
  assert.ok(info.pid > 0);
  assert.ok(launcher.isAlive('sbx-launch01'));
  assert.ok(launcher.pause('sbx-launch01'));
  await sleep(100);
  assert.ok(launcher.isAlive('sbx-launch01'));
  assert.ok(launcher.resume('sbx-launch01'));
  await sleep(100);
  assert.ok(launcher.isAlive('sbx-launch01'));
  assert.ok(launcher.stop('sbx-launch01'));
  await sleep(200);
  assert.ok(!launcher.isAlive('sbx-launch01'));
  rmSync(dir, { recursive: true, force: true });
});

test('stop on unknown sandbox returns false', async () => {
  const { dir, launcher } = makeLauncher();
  launcher.start({ id: 'sbx-launch02', policyId: 'balanced' }, makeManifest('sbx-launch02'));
  assert.ok(launcher.stop('sbx-launch02'));
  assert.ok(!launcher.stop('sbx-unknown'));
  await sleep(300);
  rmSync(dir, { recursive: true, force: true });
});

test('log path recorded', async () => {
  const { dir, launcher } = makeLauncher();
  const info = launcher.start({ id: 'sbx-launch03', policyId: 'balanced' }, makeManifest('sbx-launch03'));
  assert.ok(info.logPath.includes('sbx-launch03'));
  launcher.stop('sbx-launch03');
  await sleep(300);
  rmSync(dir, { recursive: true, force: true });
});

test('reap orphans terminates untracked processes', async () => {
  const { dir, launcher } = makeLauncher();
  launcher.start({ id: 'sbx-launch04', policyId: 'balanced' }, makeManifest('sbx-launch04'));
  await sleep(100);
  const dead = launcher.reapOrphans([]);
  assert.ok(dead.includes('sbx-launch04'));
  launcher.stop('sbx-launch04');
  await sleep(300);
  rmSync(dir, { recursive: true, force: true });
});

import { writeFileSync } from 'node:fs';

test('readLog is incremental and clamps beyond eof', () => {
  const { dir, launcher } = makeLauncher();
  const logPath = join(dir, 'runners', 'sbx-log01.log');
  writeFileSync(logPath, 'first\n');
  const first = launcher.readLog('sbx-log01', 0);
  assert.equal(first.content, 'first\n');
  assert.equal(first.offset, 'first\n'.length);
  assert.equal(first.alive, false);
  assert.equal(first.mode, 'final');
  writeFileSync(logPath, 'first\nsecond\n');
  const second = launcher.readLog('sbx-log01', first.offset);
  assert.equal(second.content, 'second\n');
  const tail = launcher.readLog('sbx-log01', 9999);
  assert.equal(tail.content, '');
  assert.equal(tail.offset, 'first\nsecond\n'.length);
  rmSync(dir, { recursive: true, force: true });
});

test('readLog on unknown sandbox is empty final', () => {
  const { dir, launcher } = makeLauncher();
  const result = launcher.readLog('sbx-unknown');
  assert.equal(result.content, '');
  assert.equal(result.offset, 0);
  assert.equal(result.alive, false);
  rmSync(dir, { recursive: true, force: true });
});
