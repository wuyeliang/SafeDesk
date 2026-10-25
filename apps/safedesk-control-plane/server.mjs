import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, stat, rename } from 'node:fs/promises';
import { join, normalize, extname, dirname } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import { allowedAgents, compileManifest, policies } from './src/policy.mjs';
import { AuthStore } from './src/auth.mjs';
import { AuditLog } from './src/audit.mjs';
import { CredentialBroker } from './src/broker.mjs';
import { Launcher, workspaceAllowed } from './src/launch.mjs';
import { EgressPolicy, ProxyRuntime, serve as serveProxy } from './src/proxy.mjs';
import { aliasProfile } from './src/privacy.mjs';
import { TravelerRegistry } from './src/travelers.mjs';
import { defaultSettings, defaultTemplates, catalog, enrichSandbox, filterEvents, filterSandboxes, mergeSettings, overview as productOverview, riskFor } from './src/product.mjs';
import { activeStates, terminalStates, Scheduler, stateLock, validateLimits, withPositions } from './src/scheduler.mjs';

const withStateLock = stateLock();

const PORT = Number(process.env.PORT ?? 8022);
const HOST = process.env.HOST ?? '0.0.0.0';
const AUTH_ENABLED = process.env.SAFEDESK_AUTH !== '0';
const root = new URL('.', import.meta.url).pathname;
const staticRoot = join(root, 'static');
const dataDir = process.env.SAFEDESK_DATA_DIR ?? join(root, 'data');
const dataFile = process.env.SAFEDESK_DATA_FILE ?? join(dataDir, 'sandboxes.json');
const settingsFile = join(dataDir, 'settings.json');
const auth = new AuthStore(dataDir);
const auditLog = new AuditLog(join(dataDir, 'audit.jsonl'));
const broker = new CredentialBroker(join(dataDir, 'credentials.json'));
const travelers = new TravelerRegistry(join(dataDir, 'travelers.json'));
const launcher = new Launcher(join(dataDir, 'runners'));
const proxyRuntime = new ProxyRuntime();
const PROXY_PORT = Number(process.env.SAFEDESK_EGRESS_PROXY_PORT ?? 0);
let proxyServer = null;

const securityEvents = [
  { id: 'evt-001', level: 'info', action: '策略编译', detail: 'policy/balanced 已签名并下发至本地执行器', at: '2026-10-23T10:12:00.000Z' },
  { id: 'evt-002', level: 'allow', action: '凭据代签', detail: 'github-read 通过 Host Credential Broker 注入 Authorization 头', at: '2026-10-23T10:14:00.000Z' },
  { id: 'evt-003', level: 'block', action: '外联拦截', detail: '沙箱请求 untrusted.example 被默认拒绝', at: '2026-10-23T10:17:00.000Z' },
];

async function ensureStore() {
  await mkdir(dirname(dataFile), { recursive: true });
  try { await stat(dataFile); } catch { await writeFile(dataFile, '[]\n'); }
}

async function loadSandboxes() {
  await ensureStore();
  return withPositions(JSON.parse(await readFile(dataFile, 'utf8')));
}

async function saveSandboxes(items) {
  await atomicJson(dataFile, items.map(({ queuePosition, ...s }) => s));
}

async function atomicJson(path, value) {
  await writeFile(`${path}.tmp`, `${JSON.stringify(value, null, 2)}\n`);
  await rename(`${path}.tmp`, path);
}

async function loadSettings() {
  await mkdir(dataDir, { recursive: true });
  try {
    return mergeSettings(JSON.parse(await readFile(settingsFile, 'utf8')));
  } catch {
    const settings = mergeSettings(defaultSettings);
    await writeFile(settingsFile, `${JSON.stringify(settings, null, 2)}\n`);
    return settings;
  }
}

async function saveSettings(input) {
  const settings = mergeSettings({ ...await loadSettings(), ...input });
  validateLimits(settings);
  await atomicJson(settingsFile, settings);
  return settings;
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  let body = '';
  for await (const chunk of req) body += chunk;
  try { return JSON.parse(body || '{}'); } catch { throw Object.assign(new Error('请求体不是合法 JSON'), { statusCode: 400 }); }
}

function event(level, action, detail, actor) {
  const record = { id: randomUUID(), level, action, detail, actor, at: new Date().toISOString() };
  securityEvents.unshift(record);
  securityEvents.splice(40);
  auditLog.append(record).catch(() => {});
}

proxyRuntime.onEvent = (level, detail) => event(level, '网络决策', detail, 'egress-proxy');

function ensureProxy() {
  if (proxyServer) return Promise.resolve(true);
  return new Promise((accept) => {
    const candidate = serveProxy(proxyRuntime, '127.0.0.1', PROXY_PORT);
    candidate.on('error', () => accept(false));
    candidate.on('listening', () => {
      proxyServer = candidate;
      launcher.proxyUrl = `http://127.0.0.1:${candidate.address().port}`;
      accept(true);
    });
  });
}

function policyKey(sandbox) {
  const key = String(sandbox.policyId || 'balanced');
  return policies[key] ? key : 'balanced';
}

async function startSandbox(sandbox) {
  const settings = await loadSettings();
  if (!workspaceAllowed(sandbox.workspace, settings.workspaceRoots || [])) throw new Error('工作区不在允许的根目录内');
  const manifest = compileManifest(sandbox);
  if (policies[policyKey(sandbox)].networkMode !== 'disabled') {
    if (!(await ensureProxy())) throw new Error('外联代理启动失败');
    const token = randomBytes(12).toString('hex');
    sandbox.egressToken = token;
    const allowed = new Set();
    const injections = {};
    for (const capability of sandbox.credentials || []) {
      const item = await broker.get(capability);
      if (item) {
        for (const hostName of item.allowedHosts || []) allowed.add(hostName);
        const placeholder = (sandbox.credentialPlaceholders || {})[capability];
        if (placeholder) injections[placeholder] = { value: item.value, hosts: item.allowedHosts };
      }
    }
    Object.assign(injections, await travelers.resolveInjections(sandbox));
    const alias = sandbox.privacyCurtain ? aliasProfile(sandbox.id) : null;
    proxyRuntime.register(sandbox.id, token, new EgressPolicy([...allowed], injections, alias));
    manifest.egress = { token };
  }
  return launcher.start(sandbox, manifest);
}

const scheduler = new Scheduler(launcher, startSandbox, (id) => proxyRuntime.unregister(id), event);

async function scheduleOnce() {
  const items = await loadSandboxes();
  if (await scheduler.tick(items, await loadSettings())) await saveSandboxes(items);
}

function safeName(name) {
  return String(name ?? '').trim().replace(/[^\w\u4e00-\u9fa5-]/g, '-').slice(0, 48);
}

function bearer(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() || null : null;
}

async function currentUser(req) {
  if (!AUTH_ENABLED) return { id: 'local-dev', role: 'admin', displayName: '本地开发', provider: 'disabled' };
  await auth.ready;
  return auth.sessionUser(bearer(req));
}

function visibleSandboxes(items, user) {
  if (!AUTH_ENABLED || user?.role === 'admin') return items;
  return items.filter((item) => item.ownerId === user?.id);
}

function canAccess(user, sandbox) {
  return user.role === 'admin' || sandbox.ownerId === user.id;
}

function queryTicket(url) {
  return url.searchParams.get('ticket') || '';
}

async function api(req, res, url) {
  const pathname = url.pathname;
  if (req.method === 'GET' && pathname === '/api/auth/config') return json(res, 200, auth.publicConfig());
  if (req.method === 'GET' && pathname === '/api/auth/wechat/poll') {
    await auth.ready;
    return json(res, 200, await auth.pollWechat(queryTicket(url)));
  }
  if (req.method === 'GET' && pathname === '/api/auth/wecom/poll') {
    await auth.ready;
    return json(res, 200, await auth.pollWecom(queryTicket(url)));
  }
  if (req.method === 'POST' && pathname === '/api/auth/phone/send') {
    try {
      const input = await readBody(req);
      return json(res, 200, auth.sendPhoneOtp(String(input.phone || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/phone/verify') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.verifyPhoneOtp(String(input.phone || '').trim(), String(input.token || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/wechat/start') {
    await auth.ready;
    return json(res, 200, auth.startWechat());
  }
  if (req.method === 'POST' && pathname === '/api/auth/wechat/confirm') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.confirmWechat(String(input.ticket || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/wecom/start') {
    await auth.ready;
    return json(res, 200, auth.startWecom());
  }
  if (req.method === 'POST' && pathname === '/api/auth/wecom/confirm') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.confirmWecom(String(input.ticket || '').trim()));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/admin/login') {
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.loginAdmin(String(input.username || '').trim(), String(input.password || '')));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    await auth.ready;
    await auth.revoke(bearer(req));
    return json(res, 200, { ok: true });
  }
  if (req.method === 'POST' && pathname === '/api/auth/password') {
    const user = await currentUser(req);
    if (!user) return json(res, 401, { error: '请先登录' });
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    try {
      const input = await readBody(req);
      await auth.ready;
      return json(res, 200, await auth.changePassword(
        user,
        String(input.currentPassword || ''),
        String(input.newPassword || ''),
        bearer(req),
      ));
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }

  const user = await currentUser(req);
  if (pathname === '/api/auth/me') {
    if (!user) return json(res, 401, { error: '请先登录' });
    return json(res, 200, { user: AUTH_ENABLED ? auth.publicUser(user) : user, authEnabled: AUTH_ENABLED });
  }
  if (!user) return json(res, 401, { error: '请先登录' });

  if (req.method === 'GET' && pathname === '/api/bootstrap') {
    const sandboxes = visibleSandboxes(await loadSandboxes(), user).map(enrichSandbox);
    const events = user.role === 'admin' ? securityEvents : [];
    return json(res, 200, {
      user: AUTH_ENABLED ? auth.publicUser(user) : user,
      overview: productOverview(sandboxes, securityEvents, user),
      catalog: catalog(),
      templates: defaultTemplates,
      settings: await loadSettings(),
      policies: Object.values(policies),
      agents: Object.entries(allowedAgents).map(([id, item]) => ({ id, ...item })),
      sandboxes,
      securityEvents: events,
    });
  }
  if (req.method === 'GET' && pathname === '/api/overview') {
    const sandboxes = visibleSandboxes(await loadSandboxes(), user);
    return json(res, 200, { overview: productOverview(sandboxes, securityEvents, user) });
  }
  if (req.method === 'GET' && pathname === '/api/catalog') return json(res, 200, catalog());
  if (req.method === 'GET' && pathname === '/api/templates') return json(res, 200, { templates: defaultTemplates });
  if (req.method === 'GET' && pathname === '/api/settings') return json(res, 200, { settings: await loadSettings() });
  if (req.method === 'GET' && pathname === '/api/sandboxes') {
    return json(res, 200, { sandboxes: filterSandboxes(visibleSandboxes(await loadSandboxes(), user), Object.fromEntries(url.searchParams)) });
  }
  if (req.method === 'GET' && pathname === '/api/travelers') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    return json(res, 200, { travelers: await travelers.listMasked() });
  }
  if (req.method === 'POST' && pathname === '/api/travelers') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    try {
      const input = await readBody(req);
      const hosts = Array.isArray(input.allowedHosts) ? input.allowedHosts : [];
      if (!Array.isArray(input.allowedHosts)) throw Object.assign(new Error('allowedHosts 必须是数组'), { statusCode: 400 });
      const card = await travelers.register(
        String(input.handle || '').trim(), String(input.name || ''), String(input.idCard || ''),
        String(input.phone || ''), hosts, input.passport ? String(input.passport) : null,
      );
      event('allow', '登记出行人卡片', `${card.handle} 已登记（目的地白名单 ${card.allowedHosts.length} 条）`, user.id);
      return json(res, 200, { traveler: card });
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/travelers/delete') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    try {
      const input = await readBody(req);
      const removed = await travelers.remove(String(input.handle || '').trim());
      if (!removed) return json(res, 404, { error: '未找到出行人卡片' });
      event('info', '注销出行人卡片', `${String(input.handle || '').trim()} 已删除`, user.id);
      return json(res, 200, { ok: true });
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'GET' && pathname === '/api/credentials') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    return json(res, 200, { credentials: await broker.listMasked() });
  }
  if (req.method === 'POST' && pathname === '/api/credentials') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    try {
      const input = await readBody(req);
      const hosts = Array.isArray(input.allowedHosts) ? input.allowedHosts : [];
      if (!Array.isArray(input.allowedHosts)) throw Object.assign(new Error('allowedHosts 必须是数组'), { statusCode: 400 });
      const entry = await broker.put(String(input.name || '').trim(), String(input.value || ''), hosts);
      event('allow', '注册凭据', `${entry.name} 已登记，目的地白名单 ${hosts.length} 条`, user.id);
      return json(res, 200, { credential: entry });
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'POST' && pathname === '/api/credentials/delete') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    try {
      const input = await readBody(req);
      const removed = await broker.remove(String(input.name || '').trim());
      if (!removed) return json(res, 404, { error: '未找到凭据' });
      event('info', '注销凭据', `${String(input.name || '').trim()} 已删除`, user.id);
      return json(res, 200, { ok: true });
    } catch (error) {
      return json(res, error.statusCode ?? 400, { error: error.message });
    }
  }
  if (req.method === 'GET' && pathname === '/api/events') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    if (url.searchParams.get('history') === '1') {
      const limit = Number(url.searchParams.get('limit') ?? 100);
      const offset = Number(url.searchParams.get('offset') ?? 0);
      const events = await auditLog.query({
        keyword: url.searchParams.get('q') ?? '',
        level: url.searchParams.get('level') ?? '',
        action: url.searchParams.get('action') ?? '',
        since: url.searchParams.get('since'),
        limit: Number.isNaN(limit) ? 100 : limit,
        offset: Number.isNaN(offset) ? 0 : offset,
      });
      return json(res, 200, { events, size: events.length });
    }
    return json(res, 200, { events: filterEvents(securityEvents, Object.fromEntries(url.searchParams)) });
  }
  if (req.method === 'POST' && pathname === '/api/sandboxes') {
    let input;
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
    const policyId = String(input.policyId ?? 'balanced');
    const agent = String(input.agent ?? 'claude-code');
    if (!policies[policyId]) return json(res, 400, { error: '未知策略' });
    if (!allowedAgents[agent]) return json(res, 400, { error: '仅支持 Claude Code、Codex 或 DSH' });
    const workspace = String(input.workspace ?? '').trim();
    if (!workspace.startsWith('/')) return json(res, 400, { error: '工作区必须为绝对路径' });
    const currentSettings = await loadSettings();
    if (!workspaceAllowed(workspace, Array.isArray(currentSettings.workspaceRoots) ? currentSettings.workspaceRoots : [])) {
      return json(res, 400, { error: '工作区不在允许的根目录内' });
    }
    const sandbox = {
      id: `sbx-${randomUUID().slice(0, 8)}`,
      name: safeName(input.name) || `agent-${agent}`,
      agent, policyId, workspace,
      packages: Array.isArray(input.packages) && input.packages.length ? input.packages.slice(0, 8) : ['wasmer/bash@latest'],
      credentials: Array.isArray(input.credentials) ? input.credentials.slice(0, 8) : [],
      mcpServers: Array.isArray(input.mcpServers) ? input.mcpServers.slice(0, 12) : [],
      purpose: String(input.purpose || '').trim().slice(0, 160),
      notes: String(input.notes || '').trim().slice(0, 240),
      privacyCurtain: Boolean(input.privacy),
      travelerCards: Array.isArray(input.travelerCards) ? input.travelerCards.map(String).slice(0, 4) : [],
      risk: riskFor(policyId),
      status: 'pending_approval', createdAt: new Date().toISOString(),
      ownerId: user.id, ownerName: user.displayName || user.username || user.id,
    };
    const unknownTravelers = [];
    for (const handle of sandbox.travelerCards) {
      if (!(await travelers.get(handle))) unknownTravelers.push(handle);
    }
    if (unknownTravelers.length) return json(res, 400, { error: `未知出行人卡片：${unknownTravelers.join(',')}` });
    sandbox.travelerPlaceholders = travelers.issuePlaceholders(sandbox);
    sandbox.credentialPlaceholders = broker.issuePlaceholders(sandbox);
    const sandboxes = await loadSandboxes();
    sandboxes.unshift(sandbox);
    await saveSandboxes(sandboxes);
    event('info', '创建待审批沙箱', `${sandbox.name} 使用 ${policies[policyId].label} 策略`, user.id);
    return json(res, 201, { sandbox: enrichSandbox(sandbox), manifest: compileManifest(sandbox) });
  }
  if (pathname === '/api/settings' && req.method === 'POST') {
    if (user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    let input;
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
    let settings;
    try { settings = await saveSettings(input); } catch (error) { return json(res, 400, { error: error.message }); }
    await scheduleOnce();
    event('info', '更新组织设置', `${settings.orgName} 已保存并发上限 ${settings.maxConcurrent}`, user.id);
    return json(res, 200, { settings });
  }
  const match = pathname.match(/^\/api\/sandboxes\/(sbx-[\w-]+)\/(approve|reject|pause|resume|terminate|manifest|activity|logs)$/);
  if (match) {
    const [, id, action] = match;
    if (['approve', 'reject'].includes(action) && user.role !== 'admin') return json(res, 403, { error: '仅管理员可以执行此操作' });
    const sandboxes = await loadSandboxes();
    const sandbox = sandboxes.find((item) => item.id === id);
    if (!sandbox || !canAccess(user, sandbox)) return json(res, 404, { error: '未找到沙箱' });
    if (action === 'manifest' && req.method === 'GET') return json(res, 200, { manifest: compileManifest(sandbox) });
    if (action === 'activity' && req.method === 'GET') return json(res, 200, { events: securityEvents.filter((item) => String(item.detail || '').includes(sandbox.name)) });
    if (action === 'logs' && req.method === 'GET') {
      const offset = Number(url.searchParams.get('offset') ?? 0);
      return json(res, 200, launcher.readLog(id, Number.isNaN(offset) ? 0 : offset));
    }
    if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });
    let input = {};
    try { input = await readBody(req); } catch (error) { return json(res, error.statusCode ?? 400, { error: error.message }); }
    if (action === 'approve') {
      if (sandbox.status !== 'pending_approval') return json(res, 409, { error: '沙箱不是待审批状态' });
      try {
        scheduler.enqueue(sandboxes, sandbox, await loadSettings(), user.id);
      } catch (error) {
        return json(res, 409, { error: error.message });
      }
    }
    if (action === 'reject') {
      if (sandbox.status !== 'pending_approval') return json(res, 409, { error: '沙箱不是待审批状态' });
      sandbox.status = 'rejected'; sandbox.rejectedAt = new Date().toISOString(); sandbox.rejectedBy = user.id;
      sandbox.rejectReason = String(input.reason || '不符合安全策略').trim().slice(0, 160);
      event('block', '拒绝启动', `${sandbox.name} 被拒绝：${sandbox.rejectReason}`, user.id);
    }
    if (action === 'pause') {
      if (sandbox.status !== 'running') return json(res, 409, { error: '仅运行中的沙箱可以暂停' });
      if (!launcher.pause(id)) return json(res, 409, { error: '进程状态待确认，请核对执行器' });
      proxyRuntime.setPaused(id, true);
      sandbox.status = 'paused'; sandbox.pausedAt = new Date().toISOString(); sandbox.pausedBy = user.id;
      event('info', '暂停沙箱', `${sandbox.name} 已暂停，外联和会话凭据冻结`, user.id);
    }
    if (action === 'resume') {
      if (sandbox.status !== 'paused') return json(res, 409, { error: '仅暂停中的沙箱可以恢复' });
      if (!launcher.resume(id)) return json(res, 409, { error: '进程状态待确认，请核对执行器' });
      proxyRuntime.setPaused(id, false);
      sandbox.status = 'running'; sandbox.resumedAt = new Date().toISOString(); sandbox.resumedBy = user.id;
      event('allow', '恢复沙箱', `${sandbox.name} 已恢复运行`, user.id);
    }
    if (action === 'terminate') {
      if (terminalStates.has(sandbox.status)) return json(res, 409, { error: '沙箱已结束' });
      if (activeStates.has(sandbox.status) && !(await launcher.stopAndWait(id))) return json(res, 409, { error: '进程状态待确认，请核对执行器' });
      proxyRuntime.unregister(id);
      delete sandbox.egressToken;
      sandbox.status = 'terminated'; sandbox.terminatedAt = new Date().toISOString(); sandbox.terminatedBy = user.id;
      event('block', '终止沙箱', `${sandbox.name} 已终止，短期会话凭据失效`, user.id);
    }
    await scheduler.tick(sandboxes, await loadSettings());
    await saveSandboxes(sandboxes);
    const result = withPositions(sandboxes).find((s) => s.id === id);
    const status = result.status === 'queued' ? 202 : action === 'approve' && result.status === 'failed' ? 502 : 200;
    return json(res, status, { sandbox: enrichSandbox(result) });
  }
  return json(res, 404, { error: 'Not found' });
}

const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json; charset=utf-8' };
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    if (url.pathname.startsWith('/api/')) {
      if (/^\/api\/(sandboxes|settings|bootstrap|overview)(\/|$)/.test(url.pathname)) {
        return await withStateLock(() => api(req, res, url));
      }
      return await api(req, res, url);
    }
    const requested = url.pathname === '/' ? '/index.html' : url.pathname;
    const target = normalize(join(staticRoot, requested));
    if (!target.startsWith(staticRoot)) return json(res, 403, { error: 'Forbidden' });
    const content = await readFile(target);
    res.writeHead(200, { 'Content-Type': mime[extname(target)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(content);
  } catch (error) {
    json(res, error.code === 'ENOENT' ? 404 : 500, { error: error.message });
  }
});

await withStateLock(async () => {
  const settings = await loadSettings();
  auditLog.retentionDays = Number(settings.retainAuditDays || 30);
  const existing = await auditLog.load();
  if (!existing.length) {
    for (const seed of securityEvents) await auditLog.append(seed);
  }
  await auditLog.prune();
  await scheduleOnce();
});

let ticking = false;
setInterval(() => {
  if (ticking) return;
  ticking = true;
  withStateLock(scheduleOnce).catch((error) => console.error('scheduler:', error.message)).finally(() => { ticking = false; });
}, 500).unref();

server.listen(PORT, HOST, () => {
  console.log(`SafeDesk control plane listening on http://${HOST}:${PORT}`);
});
