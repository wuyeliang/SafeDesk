import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';

import { MAX_TRAVELERS_PER_SANDBOX, TRAVELER_FIELDS, TravelerRegistry } from '../src/travelers.mjs';

const CARD = {
  handle: 'traveller-li',
  name: '李雷',
  idCard: '110101199003071234',
  phone: '13812345678',
  passport: 'E12345678',
  allowedHosts: ['api.ctrip.demo.local'],
};

const makeSandbox = (id = 'sbx-trip01', overrides = {}) => ({ id, travelerCards: ['traveller-li'], status: 'running', ...overrides });

async function makeRegistry() {
  const dir = mkdtempSync(join(tmpdir(), 'safedesk-travelers-'));
  const registry = new TravelerRegistry(join(dir, 'travelers.json'));
  // Validation can reject before the constructor's asynchronous I/O completes.
  await registry.listMasked();
  return { dir, registry };
}

test('register masks values and persists 0600', async () => {
  const { dir, registry } = await makeRegistry();
  const card = await registry.register(CARD.handle, CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts, CARD.passport);
  assert.equal(card.phone, '138****5678');
  assert.equal(card.name, '李*');
  assert.ok(card.idCard.startsWith('1101'));
  assert.ok(!card.idCard.includes(CARD.idCard));
  const listed = await (new TravelerRegistry(join(dir, 'travelers.json'))).listMasked();
  assert.equal(listed[0].phone, '138****5678');
  assert.equal(statSync(join(dir, 'travelers.json')).mode & 0o777, 0o600);
  rmSync(dir, { recursive: true, force: true });
});

test('validation errors', async () => {
  const { dir, registry } = await makeRegistry();
  await assert.rejects(() => registry.register('x', CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts));
  await assert.rejects(() => registry.register('traveller-li', CARD.name, '123', CARD.phone, CARD.allowedHosts));
  await assert.rejects(() => registry.register('traveller-li', CARD.name, CARD.idCard, '12345', CARD.allowedHosts));
  await assert.rejects(() => registry.register('traveller-li', CARD.name, CARD.idCard, CARD.phone, []));
  rmSync(dir, { recursive: true, force: true });
});

test('upsert and remove', async () => {
  const { dir, registry } = await makeRegistry();
  await registry.register(CARD.handle, CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts, CARD.passport);
  const card = await registry.register(CARD.handle, CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts, null);
  assert.equal(card.passport, null);
  assert.equal(await registry.remove('traveller-li'), true);
  assert.equal(await registry.remove('traveller-li'), false);
  rmSync(dir, { recursive: true, force: true });
});

test('placeholders cover all traveler fields with quota', async () => {
  const { dir, registry } = await makeRegistry();
  await registry.register(CARD.handle, CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts, CARD.passport);
  const mapping = registry.issuePlaceholders(makeSandbox());
  for (const field of TRAVELER_FIELDS) {
    assert.ok(mapping['traveller-li'][field].startsWith(`{{SD_TRV_sbx-trip01_traveller-li_${field}_`));
  }
  const names = Array.from({ length: MAX_TRAVELERS_PER_SANDBOX + 2 }, (_, idx) => `traveller-${idx}`);
  const mappingQuota = registry.issuePlaceholders(makeSandbox('sbx-q1', { travelerCards: names }));
  assert.equal(Object.keys(mappingQuota).length, MAX_TRAVELERS_PER_SANDBOX);
  rmSync(dir, { recursive: true, force: true });
});

test('resolve injections returns real values only for known cards', async () => {
  const { dir, registry } = await makeRegistry();
  await registry.register(CARD.handle, CARD.name, CARD.idCard, CARD.phone, CARD.allowedHosts, CARD.passport);
  const sbx = makeSandbox();
  sbx.travelerPlaceholders = registry.issuePlaceholders(sbx);
  const injections = await registry.resolveInjections(sbx);
  const namePlaceholder = sbx.travelerPlaceholders['traveller-li'].name;
  const idPlaceholder = sbx.travelerPlaceholders['traveller-li'].idCard;
  assert.equal(injections[namePlaceholder].value, '李雷');
  assert.equal(injections[idPlaceholder].value, CARD.idCard);
  assert.deepEqual(injections[namePlaceholder].hosts, CARD.allowedHosts);
  const ghost = { ...sbx, travelerPlaceholders: { ghost: { name: '{{SD_TRV_x}}' } } };
  assert.deepEqual(await registry.resolveInjections(ghost), {});
  rmSync(dir, { recursive: true, force: true });
});
