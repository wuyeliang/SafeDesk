import test from 'node:test';
import assert from 'node:assert/strict';
import {
  catalog,
  defaultSettings,
  defaultTemplates,
  enrichSandbox,
  filterEvents,
  filterSandboxes,
  mergeSettings,
  overview,
  riskFor,
  statusLabels,
} from '../src/product.mjs';
import { allowedAgents, policies } from '../src/policy.mjs';

// ---- riskFor ----
for (const [policyId, expected] of [['review', '低风险'], ['balanced', '中风险'], ['build', '高风险']]) {
  test(`riskFor maps ${policyId} to ${expected}`, () => {
    assert.equal(riskFor(policyId), expected);
  });
}
test('riskFor falls back to 待评估 for unknown policies', () => {
  assert.equal(riskFor('everything-allowed'), '待评估');
});

// ---- statusLabels ----
test('statusLabels covers queue and terminal states', () => {
  assert.deepEqual(Object.keys(statusLabels).sort(), ['completed', 'failed', 'paused', 'pending_approval', 'queued', 'rejected', 'running', 'terminated']);
});

// ---- defaultSettings ----
test('defaultSettings requires approval by default', () => {
  assert.equal(defaultSettings.requireApproval, true);
});
test('defaultSettings has a positive concurrency cap', () => {
  assert.ok(Number.isInteger(defaultSettings.maxConcurrent) && defaultSettings.maxConcurrent > 0);
});
test('defaultSettings keeps the never-inject-secrets notice', () => {
  assert.match(defaultSettings.notice, /密钥/);
});
test('defaultSettings enables all three login methods by default', () => {
  assert.equal(defaultSettings.allowPhoneLogin, true);
  assert.equal(defaultSettings.allowWechatLogin, true);
  assert.equal(defaultSettings.allowAdminLogin, true);
});

// ---- defaultTemplates ----
test('defaultTemplates contains exactly four templates', () => {
  assert.equal(defaultTemplates.length, 5);
});
for (const template of defaultTemplates) {
  test(`template ${template.id} references a known policy and agent`, () => {
    assert.ok(policies[template.policyId], `policy ${template.policyId}`);
    assert.ok(allowedAgents[template.agent], `agent ${template.agent}`);
  });
  test(`template ${template.id} uses an absolute workspace path`, () => {
    assert.ok(template.workspace.startsWith('/'));
  });
}

// ---- enrichSandbox ----
test('enrichSandbox resolves labels for known policy and agent', () => {
  const enriched = enrichSandbox({ policyId: 'build', agent: 'dsh', status: 'running' });
  assert.equal(enriched.policyLabel, '受限构建');
  assert.equal(enriched.agentLabel, 'DSH');
});
test('enrichSandbox falls back to the raw id for an unknown policy', () => {
  assert.equal(enrichSandbox({ policyId: 'mystery' }).policyLabel, 'mystery');
});
test('enrichSandbox falls back to the raw id for an unknown agent', () => {
  assert.equal(enrichSandbox({ agent: 'gpt-shell' }).agentLabel, 'gpt-shell');
});
for (const [status, label] of [['pending_approval', '待审批'], ['running', '运行中'], ['paused', '已暂停'], ['rejected', '已拒绝'], ['terminated', '已终止']]) {
  test(`enrichSandbox labels status ${status} as ${label}`, () => {
    assert.equal(enrichSandbox({ status }).statusLabel, label);
  });
}
test('enrichSandbox computes risk from the policy when missing', () => {
  assert.equal(enrichSandbox({ policyId: 'review' }).risk, '低风险');
});
test('enrichSandbox preserves an explicitly stored risk', () => {
  assert.equal(enrichSandbox({ policyId: 'review', risk: '高风险' }).risk, '高风险');
});
test('enrichSandbox defaults purpose and notes to empty strings', () => {
  const enriched = enrichSandbox({});
  assert.equal(enriched.purpose, '');
  assert.equal(enriched.notes, '');
});

// ---- filterSandboxes ----
const samples = [
  { id: 'sbx-1', name: 'alpha', agent: 'codex', policyId: 'review', workspace: '/srv/alpha', ownerId: 'u1', ownerName: '张三', purpose: '审阅依赖', status: 'running' },
  { id: 'sbx-2', name: 'beta', agent: 'dsh', policyId: 'build', workspace: '/srv/beta', ownerId: 'u2', ownerName: '李四', purpose: '夜间构建', status: 'pending_approval' },
  { id: 'sbx-3', name: 'gamma', agent: 'claude-code', policyId: 'balanced', workspace: '/srv/gamma', ownerId: 'u1', ownerName: '张三', purpose: '', status: 'paused' },
];
const keywordCases = [
  ['sbx-1', 1, 'id'],
  ['Alpha', 1, 'name（大小写不敏感）'],
  ['/srv/beta', 1, 'workspace'],
  ['李四', 1, 'ownerName'],
  ['审阅', 1, 'purpose'],
];
for (const [keyword, count, field] of keywordCases) {
  test(`filterSandboxes keyword matches ${field}`, () => {
    assert.equal(filterSandboxes(samples, { q: keyword }).length, count);
  });
}
test('filterSandboxes keyword with no match returns empty', () => {
  assert.equal(filterSandboxes(samples, { q: '不存在的词' }).length, 0);
});
test('filterSandboxes filters by status', () => {
  assert.deepEqual(filterSandboxes(samples, { status: 'paused' }).map((i) => i.id), ['sbx-3']);
});
test('filterSandboxes filters by agent', () => {
  assert.equal(filterSandboxes(samples, { agent: 'dsh' }).length, 1);
});
test('filterSandboxes filters by policyId', () => {
  assert.equal(filterSandboxes(samples, { policyId: 'review' }).length, 1);
});
test('filterSandboxes combines keyword and status filters', () => {
  const result = filterSandboxes(samples, { q: 'srv', status: 'running' });
  assert.deepEqual(result.map((i) => i.id), ['sbx-1']);
});
test('filterSandboxes with empty query returns all items enriched', () => {
  const result = filterSandboxes(samples, {});
  assert.equal(result.length, 3);
  assert.ok(result.every((item) => item.statusLabel && item.policyLabel));
});

// ---- overview ----
const overviewItems = [
  { status: 'running', ownerId: 'u1', policyId: 'review' },
  { status: 'pending_approval', ownerId: 'u1', policyId: 'balanced' },
  { status: 'paused', ownerId: 'u2', policyId: 'build' },
  { status: 'rejected', ownerId: 'u2', policyId: 'review' },
  { status: 'terminated', ownerId: 'u2', policyId: 'build' },
];
const overviewEvents = [
  { level: 'block', at: '2026-10-24T01:00:00.000Z' },
  { level: 'allow', at: '2026-10-24T00:00:00.000Z' },
];
const ov = overview(overviewItems, overviewEvents, { role: 'admin' });
for (const [field, expected] of [['total', 5], ['running', 1], ['pendingApproval', 1], ['paused', 1], ['rejected', 1], ['terminated', 1]]) {
  test(`overview counts ${field}`, () => {
    assert.equal(ov[field], expected);
  });
}
test('overview counts blocked and allowed events', () => {
  assert.equal(ov.blockedEvents, 1);
  assert.equal(ov.allowEvents, 1);
});
test('overview deduplicates active users by ownerId', () => {
  assert.equal(ov.activeUsers, 2);
});
test('overview ignores items without ownerId for active users', () => {
  const result = overview([{ status: 'running' }], [], {});
  assert.equal(result.activeUsers, 0);
});
test('overview echoes the user role', () => {
  assert.equal(ov.role, 'admin');
});
test('overview falls back to guest role', () => {
  assert.equal(overview([], [], null).role, 'guest');
});
test('overview flags attention while approvals are pending', () => {
  assert.equal(ov.health, 'attention');
});
test('overview reports healthy with no pending approvals', () => {
  assert.equal(overview([{ status: 'running' }], [], {}).health, 'healthy');
});
test('overview uses the newest event time as lastAuditAt', () => {
  assert.equal(ov.lastAuditAt, '2026-10-24T01:00:00.000Z');
});
test('overview has null lastAuditAt without events', () => {
  assert.equal(overview([], [], {}).lastAuditAt, null);
});
for (const [bucket, expected] of [['低风险', 2], ['中风险', 1], ['高风险', 1]]) {
  test(`overview riskMix counts ${expected} ${bucket} non-terminated sandbox`, () => {
    assert.equal(ov.riskMix[bucket], expected);
  });
}

// ---- mergeSettings ----
test('mergeSettings with null returns the defaults', () => {
  assert.deepEqual(mergeSettings(null), defaultSettings);
});
test('mergeSettings applies a partial override and keeps defaults', () => {
  const merged = mergeSettings({ maxConcurrent: 16 });
  assert.equal(merged.maxConcurrent, 16);
  assert.equal(merged.orgName, defaultSettings.orgName);
});
test('mergeSettings preserves new keys from the payload', () => {
  assert.equal(mergeSettings({ customField: 'x' }).customField, 'x');
});

// ---- filterEvents ----
const eventSamples = [
  { level: 'block', action: '外联拦截', detail: '请求 untrusted.example 被拒绝', actor: 'admin' },
  { level: 'allow', action: '人工审批', detail: 'alpha 已启动', actor: 'admin' },
  { level: 'info', action: '创建待审批沙箱', detail: 'beta 使用标准研发策略', actor: 'phone-user' },
];
test('filterEvents keyword matches action', () => {
  assert.equal(filterEvents(eventSamples, { q: '人工审批' }).length, 1);
});
test('filterEvents keyword matches detail case-insensitively', () => {
  assert.equal(filterEvents(eventSamples, { q: 'UNTRUSTED' }).length, 1);
});
test('filterEvents keyword matches actor', () => {
  assert.equal(filterEvents(eventSamples, { q: 'phone-user' }).length, 1);
});
test('filterEvents filters by level', () => {
  assert.deepEqual(filterEvents(eventSamples, { level: 'block' }).map((e) => e.action), ['外联拦截']);
});
test('filterEvents filters by action exactly', () => {
  assert.equal(filterEvents(eventSamples, { action: '人工审批' }).length, 1);
});
test('filterEvents combines level and keyword', () => {
  assert.equal(filterEvents(eventSamples, { level: 'info', q: 'beta' }).length, 1);
  assert.equal(filterEvents(eventSamples, { level: 'block', q: 'beta' }).length, 0);
});
test('filterEvents with empty query returns everything', () => {
  assert.equal(filterEvents(eventSamples, {}).length, 3);
});

// ---- catalog ----
const cat = catalog();
test('catalog exposes all three policies with risk labels', () => {
  assert.equal(cat.policies.length, 3);
  assert.ok(cat.policies.every((policy) => ['低风险', '中风险', '高风险'].includes(policy.risk)));
});
for (const policyId of ['review', 'balanced', 'build']) {
  test(`catalog policy ${policyId} includes suitability guidance`, () => {
    const policy = cat.policies.find((item) => item.id === policyId);
    assert.ok(policy.suitableFor.length > 0);
  });
}
test('catalog marks all agents as supported', () => {
  assert.ok(cat.agents.length === 3 && cat.agents.every((agent) => agent.supported === true));
});
test('catalog lists credential profiles', () => {
  assert.ok(cat.capabilities.credentials.includes('github-read'));
});
test('catalog lists available MCP servers', () => {
  assert.ok(cat.capabilities.mcpServers.includes('github'));
});
test('catalog defaultPackage is text', () => {
  assert.equal(typeof catalog().defaultPackage, 'string');
});
test('catalog defaultPackage honors SAFEDESK_DEFAULT_PACKAGE', () => {
  const previous = process.env.SAFEDESK_DEFAULT_PACKAGE;
  process.env.SAFEDESK_DEFAULT_PACKAGE = '/opt/wasmer-images/safedesk-agent-python.webc';
  try {
    assert.equal(catalog().defaultPackage, '/opt/wasmer-images/safedesk-agent-python.webc');
  } finally {
    if (previous === undefined) delete process.env.SAFEDESK_DEFAULT_PACKAGE;
    else process.env.SAFEDESK_DEFAULT_PACKAGE = previous;
  }
});
