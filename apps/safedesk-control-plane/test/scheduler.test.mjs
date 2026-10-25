import test from 'node:test';
import assert from 'node:assert/strict';
import { Scheduler, stateLock, validateLimits, withPositions } from '../src/scheduler.mjs';

function fixture() {
  const processes = new Map();
  const started = [], released = [];
  const settings = { maxConcurrent: 1, maxQueued: 2 };
  const items = Array.from({ length: 4 }, (_, i) => ({ id: `sbx-${i}`, name: String(i), ownerId: String(i), status: 'pending_approval' }));
  const scheduler = new Scheduler({ info: (id) => processes.get(id) || { alive: false } }, async (s) => {
    await new Promise((resolve) => setImmediate(resolve));
    if (s.bad) throw new Error('invalid workspace');
    started.push(s.id);
    processes.set(s.id, { alive: true });
    return { mode: 'test' };
  }, (id) => released.push(id), () => {});
  const approve = async (i) => { scheduler.enqueue(items, items[i], settings, 'admin'); await scheduler.tick(items, settings); };
  return { items, settings, processes, started, released, scheduler, approve };
}

test('global cap covers admin and FIFO across owners; queue has no process', async () => {
  const f = fixture();
  for (const i of [0, 1, 2]) await f.approve(i);
  assert.deepEqual(f.started, ['sbx-0']);
  assert.deepEqual(withPositions(f.items).slice(0, 3).map((s) => s.queuePosition), [null, 1, 2]);
  f.processes.set('sbx-0', { alive: false, exitCode: 0 });
  await f.scheduler.tick(f.items, f.settings);
  assert.deepEqual(f.started, ['sbx-0', 'sbx-1']);
  assert.equal(f.items[0].status, 'completed');
  assert.deepEqual(f.released, ['sbx-0']);
});

test('pause reserves a slot; lowering does not kill and raising fills slots', async () => {
  const f = fixture();
  f.settings.maxConcurrent = 2;
  await f.approve(0); await f.approve(1);
  f.items[0].status = 'paused';
  f.settings.maxConcurrent = 1;
  await f.approve(2);
  assert.deepEqual(f.started, ['sbx-0', 'sbx-1']);
  f.settings.maxConcurrent = 3;
  await f.scheduler.tick(f.items, f.settings);
  assert.equal(f.started.at(-1), 'sbx-2');
});

test('queue overflow and repeat approval leave states intact', async () => {
  const f = fixture();
  for (const i of [0, 1, 2]) await f.approve(i);
  assert.throws(() => f.scheduler.enqueue(f.items, f.items[3], f.settings, 'admin'), /排队上限/);
  assert.equal(f.items[3].status, 'pending_approval');
  assert.throws(() => f.scheduler.enqueue(f.items, f.items[1], f.settings, 'admin'), /待审批/);
});

test('nonzero exit and failed start release slots and do not block FIFO', async () => {
  const f = fixture();
  await f.approve(0);
  f.items[1].bad = true;
  await f.approve(1); await f.approve(2);
  f.processes.set('sbx-0', { alive: false, exitCode: 7 });
  await f.scheduler.tick(f.items, f.settings);
  assert.deepEqual(f.items.slice(0, 3).map((s) => s.status), ['failed', 'failed', 'running']);
});

test('recovered unknown process retains its slot', async () => {
  const f = fixture();
  await f.approve(0); await f.approve(1);
  f.processes.clear();
  await f.scheduler.tick(f.items, f.settings);
  assert.equal(f.items[0].runtime.recoveryRequired, true);
  assert.equal(f.items[1].status, 'queued');
});

test('persisted FIFO does not depend on display order', async () => {
  const f = fixture();
  for (const i of [0, 1, 2]) await f.approve(i);
  f.items[0].status = 'terminated';
  f.items.reverse();
  await f.scheduler.tick(f.items, f.settings);
  assert.equal(f.started.at(-1), 'sbx-1');
});

test('invalid settings never become quotas', () => {
  for (const [key, values] of [['maxConcurrent', [true, 0, 65, 1.5, '2', null]], ['maxQueued', [false, 0, 10001, '1']]]) {
    for (const value of values) assert.throws(() => validateLimits({ maxConcurrent: 1, maxQueued: 2, [key]: value }));
  }
});

test('state lock prevents async approval oversubscription and survives rejection', async () => {
  const f = fixture(), lock = stateLock();
  await assert.rejects(lock(() => { throw new Error('bad request'); }));
  await Promise.all([0, 1, 2].map((i) => lock(() => f.approve(i))));
  assert.deepEqual(f.started, ['sbx-0']);
  assert.equal(f.items.filter((s) => s.status === 'queued').length, 2);
});
