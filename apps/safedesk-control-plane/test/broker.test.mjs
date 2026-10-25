import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { CredentialBroker, MAX_CREDENTIALS_PER_SANDBOX, PLACEHOLDER_PREFIX } from '../src/broker.mjs';

const makeSandbox = (id = 'sbx-broker01', overrides = {}) => ({ id, credentials: ['github-read'], status: 'running', ...overrides });

async function makeBroker() {
  const dir = mkdtempSync(join(tmpdir(), 'safedesk-broker-'));
  const broker = new CredentialBroker(join(dir, 'credentials.json'));
  // Initialization must finish before even synchronous-only tests can tear down.
  await broker.listMasked();
  return { dir, broker };
}

async function teardown(dir) {
  rmSync(dir, { recursive: true, force: true });
}

test('put masks value and persists to 0600 file', async () => {
  const { dir, broker } = await makeBroker();
  const entry = await broker.put('github-read', 'ghp_secretvalue123456', ['api.github.com']);
  assert.equal(entry.masked, 'ghp_****');
  assert.ok(!entry.masked.includes('ghp_secretvalue123456'));
  const reloaded = new CredentialBroker(join(dir, 'credentials.json'));
  const listed = await reloaded.listMasked();
  assert.equal(listed[0].masked, 'ghp_****');
  assert.equal(statSync(join(dir, 'credentials.json')).mode & 0o777, 0o600);
  await teardown(dir);
});

test('put requires allowlisted hosts', async () => {
  const { dir, broker } = await makeBroker();
  await assert.rejects(() => broker.put('github-read', 'secret', []), /允许的目的地/);
  await teardown(dir);
});

test('placeholders are unique per issue', async () => {
  const { dir, broker } = await makeBroker();
  const first = broker.issuePlaceholders(makeSandbox('sbx-a1'));
  const second = broker.issuePlaceholders(makeSandbox('sbx-a1'));
  assert.ok(first['github-read'].startsWith(PLACEHOLDER_PREFIX));
  assert.notEqual(first['github-read'], second['github-read']);
  await teardown(dir);
});

test('placeholders respect quota', async () => {
  const { dir, broker } = await makeBroker();
  const names = Array.from({ length: MAX_CREDENTIALS_PER_SANDBOX + 4 }, (_, idx) => `cred-${idx}`);
  const mapping = broker.issuePlaceholders(makeSandbox('sbx-bq', { credentials: names }));
  assert.equal(Object.keys(mapping).length, MAX_CREDENTIALS_PER_SANDBOX);
  await teardown(dir);
});

test('resolve returns value only for allowed host on running sandbox', async () => {
  const { dir, broker } = await makeBroker();
  await broker.put('github-read', 'ghp_secretvalue123456', ['api.github.com']);
  assert.equal(await broker.resolve(makeSandbox(), 'github-read', 'api.github.com'), 'ghp_secretvalue123456');
  assert.equal(await broker.resolve(makeSandbox(), 'github-read', 'evil.example.com'), null);
  assert.equal(await broker.resolve(makeSandbox('sbx-broker01', { status: 'paused' }), 'github-read', 'api.github.com'), null);
  assert.equal(await broker.resolve(makeSandbox('sbx-broker01', { status: 'terminated' }), 'github-read', 'api.github.com'), null);
  assert.equal(await broker.resolve(makeSandbox('sbx-broker01', { credentials: ['other'] }), 'github-read', 'api.github.com'), null);
  await teardown(dir);
});

test('wildcard host matching', () => {
  assert.ok(CredentialBroker.hostAllowed('api.example.com', ['*.example.com']));
  assert.ok(CredentialBroker.hostAllowed('example.com', ['*.example.com']));
  assert.ok(!CredentialBroker.hostAllowed('notexample.com', ['*.example.com']));
});

test('rotate and remove', async () => {
  const { dir, broker } = await makeBroker();
  await broker.put('github-read', 'ghp_secretvalue123456', ['api.github.com']);
  const before = (await broker.get('github-read')).digest;
  const rotated = await broker.rotate('github-read', 'ghp_newsecret778899');
  assert.equal(rotated.masked, 'ghp_****');
  assert.notEqual(before, (await broker.get('github-read')).digest);
  assert.equal(await broker.remove('github-read'), true);
  assert.equal(await broker.remove('github-read'), false);
  await assert.rejects(() => broker.rotate('github-read', 'x'), /未知凭据/);
  await teardown(dir);
});
