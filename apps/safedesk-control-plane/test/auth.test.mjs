import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

let port;
let base;
let dataDir;
let child;

async function waitForServer() {
  for (let i = 0; i < 50; i += 1) {
    try {
      const response = await fetch(`${base}/api/auth/config`);
      if (response.ok) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('auth server did not start');
}

async function request(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { response, data: await response.json() };
}

test.before(async () => {
  port = await freePort();
  base = `http://127.0.0.1:${port}`;
  dataDir = await mkdtemp(join(tmpdir(), 'safedesk-auth-'));
  child = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      PORT: String(port),
      SAFEDESK_DATA_DIR: dataDir,
      SAFEDESK_DATA_FILE: join(dataDir, 'sandboxes.json'),
      SAFEDESK_AUTH: '1',
      SAFEDESK_DEMO: '1',
      SAFEDESK_ADMIN_USERNAME: 'admin',
      SAFEDESK_ADMIN_PASSWORD: 'SafeDesk@Admin',
    },
    stdio: 'ignore',
  });
  await waitForServer();
});

test.after(async () => {
  child.kill();
  await rm(dataDir, { recursive: true, force: true });
});

test('protected APIs require a session', async () => {
  const { response } = await request('/api/bootstrap');
  assert.equal(response.status, 401);
});

test('admin account can sign in and approve sandboxes', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  assert.equal(login.response.status, 200);
  assert.equal(login.data.user.role, 'admin');
  const token = login.data.token;

  const created = await request('/api/sandboxes', {
    method: 'POST',
    token,
    body: { name: 'admin-box', agent: 'codex', policyId: 'review', workspace: '/tmp/admin' },
  });
  assert.equal(created.response.status, 201);
  const approved = await request(`/api/sandboxes/${created.data.sandbox.id}/approve`, { method: 'POST', token });
  assert.equal(approved.response.status, 200);
  assert.equal(approved.data.sandbox.status, 'running');
});

test('phone OTP login is isolated from other users and cannot approve', async () => {
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13800138000' } });
  assert.equal(send.response.status, 200);
  assert.match(send.data.demoCode, /^\d{6}$/);
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13800138000', token: send.data.demoCode } });
  assert.equal(verify.response.status, 200);
  assert.equal(verify.data.user.role, 'user');
  const userToken = verify.data.token;

  const created = await request('/api/sandboxes', {
    method: 'POST',
    token: userToken,
    body: { name: 'user-box', agent: 'dsh', policyId: 'balanced', workspace: '/tmp/user' },
  });
  assert.equal(created.response.status, 201);

  const forbidden = await request(`/api/sandboxes/${created.data.sandbox.id}/approve`, { method: 'POST', token: userToken });
  assert.equal(forbidden.response.status, 403);

  const events = await request('/api/events', { token: userToken });
  assert.equal(events.response.status, 403);

  const otherSend = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13900139000' } });
  const other = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13900139000', token: otherSend.data.demoCode } });
  const otherView = await request('/api/sandboxes', { token: other.data.token });
  assert.equal(otherView.response.status, 200);
  assert.equal(otherView.data.sandboxes.some((item) => item.id === created.data.sandbox.id), false);
});

test('rejects invalid mainland phone numbers before sending OTP', async () => {
  const { response, data } = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '1380013800' } });
  assert.equal(response.status, 400);
  assert.equal(data.error, '请输入正确的 11 位手机号');
});

test('admin can reject, pause, resume and filter sandboxes', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  const token = login.data.token;
  const created = await request('/api/sandboxes', {
    method: 'POST',
    token,
    body: { name: 'pause-me', agent: 'codex', policyId: 'review', workspace: '/tmp/pause', purpose: '审阅依赖' },
  });
  assert.equal(created.data.sandbox.risk, '低风险');
  const approved = await request(`/api/sandboxes/${created.data.sandbox.id}/approve`, { method: 'POST', token });
  assert.equal(approved.data.sandbox.status, 'running');
  const paused = await request(`/api/sandboxes/${created.data.sandbox.id}/pause`, { method: 'POST', token });
  assert.equal(paused.data.sandbox.status, 'paused');
  const resumed = await request(`/api/sandboxes/${created.data.sandbox.id}/resume`, { method: 'POST', token });
  assert.equal(resumed.data.sandbox.status, 'running');
  const pending = await request('/api/sandboxes', {
    method: 'POST',
    token,
    body: { name: 'reject-me', agent: 'dsh', policyId: 'build', workspace: '/tmp/reject' },
  });
  const rejected = await request(`/api/sandboxes/${pending.data.sandbox.id}/reject`, { method: 'POST', token, body: { reason: '超出构建范围' } });
  assert.equal(rejected.data.sandbox.status, 'rejected');
  const filtered = await request('/api/sandboxes?status=rejected&q=reject', { token });
  assert.ok(filtered.data.sandboxes.some((item) => item.id === pending.data.sandbox.id));
  const overview = await request('/api/overview', { token });
  assert.ok(overview.data.overview.total >= 2);
  const settings = await request('/api/settings', { method: 'POST', token, body: { orgName: 'SafeDesk 演示中心', maxConcurrent: 12 } });
  assert.equal(settings.data.settings.orgName, 'SafeDesk 演示中心');
});

test('admin can change the default password through the API', async () => {
  const isolatedPort = await freePort();
  const isolatedBase = `http://127.0.0.1:${isolatedPort}`;
  const isolatedDir = await mkdtemp(join(tmpdir(), 'safedesk-auth-change-'));
  const isolated = spawn(process.execPath, ['server.mjs'], {
    cwd: new URL('..', import.meta.url),
    env: {
      ...process.env,
      PORT: String(isolatedPort),
      SAFEDESK_DATA_DIR: isolatedDir,
      SAFEDESK_DATA_FILE: join(isolatedDir, 'sandboxes.json'),
      SAFEDESK_AUTH: '1',
      SAFEDESK_DEMO: '1',
      SAFEDESK_ADMIN_USERNAME: 'admin',
      SAFEDESK_ADMIN_PASSWORD: 'SafeDesk@Admin',
    },
    stdio: 'ignore',
  });
  const call = async (path, { method = 'GET', body, token } = {}) => {
    const headers = {};
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (token) headers.Authorization = `Bearer ${token}`;
    for (let i = 0; i < 50; i += 1) {
      try {
        const response = await fetch(`${isolatedBase}${path}`, {
          method,
          headers,
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        return { response, data: await response.json() };
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    throw new Error('isolated auth server did not start');
  };
  try {
    const login = await call('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
    const token = login.data.token;
    assert.equal(login.data.user.mustChangePassword, true);
    const forbidden = await call('/api/auth/password', { method: 'POST', body: { currentPassword: 'SafeDesk@Admin', newPassword: 'NewDesk@Pass1' } });
    assert.equal(forbidden.response.status, 401);
    const tooShort = await call('/api/auth/password', { method: 'POST', token, body: { currentPassword: 'SafeDesk@Admin', newPassword: 'short' } });
    assert.equal(tooShort.response.status, 400);
    const changed = await call('/api/auth/password', { method: 'POST', token, body: { currentPassword: 'SafeDesk@Admin', newPassword: 'NewDesk@Pass1' } });
    assert.equal(changed.response.status, 200);
    assert.equal(changed.data.user.mustChangePassword, false);
    const oldLogin = await call('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
    assert.equal(oldLogin.response.status, 400);
    const nextLogin = await call('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'NewDesk@Pass1' } });
    assert.equal(nextLogin.response.status, 200);
  } finally {
    isolated.kill();
    await rm(isolatedDir, { recursive: true, force: true });
  }
});

test('auth config advertises the three login methods', async () => {
  const { response, data } = await request('/api/auth/config');
  assert.equal(response.status, 200);
  assert.deepEqual(data.methods, ['phone', 'wechat', 'wecom', 'admin']);
  assert.equal(data.wechatMode, 'local-qr');
  assert.equal(data.wecomMode, 'local-qr');
});

test('admin me endpoint returns the signed-in user', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  const me = await request('/api/auth/me', { token: login.data.token });
  assert.equal(me.response.status, 200);
  assert.equal(me.data.user.role, 'admin');
  assert.equal(me.data.authEnabled, true);
});

test('logout invalidates the bearer token', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  const out = await request('/api/auth/logout', { method: 'POST', token: login.data.token });
  assert.equal(out.response.status, 200);
  const me = await request('/api/auth/me', { token: login.data.token });
  assert.equal(me.response.status, 401);
});

test('regular user cannot update organization settings', async () => {
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13700000001' } });
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13700000001', token: send.data.demoCode } });
  const forbidden = await request('/api/settings', { method: 'POST', token: verify.data.token, body: { orgName: 'hijack' } });
  assert.equal(forbidden.response.status, 403);
});

test('regular user cannot reject a sandbox', async () => {
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13700000002' } });
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13700000002', token: send.data.demoCode } });
  const created = await request('/api/sandboxes', {
    method: 'POST',
    token: verify.data.token,
    body: { name: 'no-reject', agent: 'codex', policyId: 'review', workspace: '/tmp/no-reject' },
  });
  const forbidden = await request(`/api/sandboxes/${created.data.sandbox.id}/reject`, { method: 'POST', token: verify.data.token, body: { reason: 'x' } });
  assert.equal(forbidden.response.status, 403);
});

test('pending tasks do not consume concurrency', async () => {
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  await request('/api/settings', { method: 'POST', token: login.data.token, body: { maxConcurrent: 1 } });
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13700000003' } });
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13700000003', token: send.data.demoCode } });
  const first = await request('/api/sandboxes', {
    method: 'POST',
    token: verify.data.token,
    body: { name: 'cap-one', agent: 'codex', policyId: 'review', workspace: '/tmp/cap-one' },
  });
  assert.equal(first.response.status, 201);
  const second = await request('/api/sandboxes', {
    method: 'POST',
    token: verify.data.token,
    body: { name: 'cap-two', agent: 'codex', policyId: 'review', workspace: '/tmp/cap-two' },
  });
  assert.equal(second.response.status, 201);
});

test('admin can see another users sandbox', async () => {
  const send = await request('/api/auth/phone/send', { method: 'POST', body: { phone: '13700000004' } });
  const verify = await request('/api/auth/phone/verify', { method: 'POST', body: { phone: '13700000004', token: send.data.demoCode } });
  const created = await request('/api/sandboxes', {
    method: 'POST',
    token: verify.data.token,
    body: { name: 'visible-to-admin', agent: 'dsh', policyId: 'balanced', workspace: '/tmp/visible' },
  });
  const login = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'SafeDesk@Admin' } });
  const list = await request('/api/sandboxes', { token: login.data.token });
  assert.ok(list.data.sandboxes.some((item) => item.id === created.data.sandbox.id));
});

test('wrong admin password is rejected', async () => {
  const { response } = await request('/api/auth/admin/login', { method: 'POST', body: { username: 'admin', password: 'nope' } });
  assert.equal(response.status, 400);
});

test('wecom QR ticket can be confirmed into a user session', async () => {
  const started = await request('/api/auth/wecom/start', { method: 'POST' });
  assert.equal(started.response.status, 200);
  const confirmed = await request('/api/auth/wecom/confirm', { method: 'POST', body: { ticket: started.data.ticket } });
  assert.equal(confirmed.response.status, 200);
  const polled = await request(`/api/auth/wecom/poll?ticket=${started.data.ticket}`);
  assert.equal(polled.data.status, 'confirmed');
  assert.equal(polled.data.user.provider, 'wecom');
  assert.equal(polled.data.user.role, 'user');
});

test('wechat QR ticket can be confirmed into a user session', async () => {
  const started = await request('/api/auth/wechat/start', { method: 'POST' });
  assert.equal(started.response.status, 200);
  const confirmed = await request('/api/auth/wechat/confirm', { method: 'POST', body: { ticket: started.data.ticket } });
  assert.equal(confirmed.response.status, 200);
  const polled = await request(`/api/auth/wechat/poll?ticket=${started.data.ticket}`);
  assert.equal(polled.data.status, 'confirmed');
  assert.equal(polled.data.user.provider, 'wechat');
  assert.equal(polled.data.user.role, 'user');
});
