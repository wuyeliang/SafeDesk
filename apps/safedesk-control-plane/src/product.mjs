import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { allowedAgents, policies } from './policy.mjs';

export const statusLabels = {
  pending_approval: '待审批',
  running: '运行中',
  paused: '已暂停',
  rejected: '已拒绝',
  terminated: '已终止',
};

export const defaultSettings = {
  orgName: 'SafeDesk 安全运营中心',
  requireApproval: true,
  maxConcurrent: 8,
  sessionTimeoutMin: 240,
  allowPhoneLogin: true,
  allowWechatLogin: true,
  allowWecomLogin: true,
  allowAdminLogin: true,
  retainAuditDays: 30,
  workspaceRoots: [],
  notice: '密钥永不进入沙箱。所有外联必须经主机凭据代理。',
};

export const defaultTemplates = [
  {
    id: 'tpl-review',
    name: '依赖安全审阅',
    agent: 'codex',
    policyId: 'review',
    workspace: '/srv/audit/webapp',
    credentials: [],
    mcpServers: [],
    purpose: '只读审计第三方依赖，禁止写盘和出网。',
  },
  {
    id: 'tpl-dev',
    name: '功能分支研发',
    agent: 'claude-code',
    policyId: 'balanced',
    workspace: '/srv/workspaces/pay-service',
    credentials: ['github-read', 'anthropic-proxy'],
    mcpServers: ['github', 'docs'],
    purpose: '日常改代码，凭据由主机代签。',
  },
  {
    id: 'tpl-build',
    name: '夜间受限构建',
    agent: 'dsh',
    policyId: 'build',
    workspace: '/srv/build/cache',
    credentials: ['internal-mcp'],
    mcpServers: [],
    purpose: '临时工作区构建，出网必须走白名单。',
  },
  {
    id: 'tpl-takeout',
    name: '外卖隐私下单',
    agent: 'dsh',
    policyId: 'balanced',
    workspace: '/srv/orders/takeout',
    credentials: ['meituan-proxy'],
    mcpServers: [],
    privacy: true,
    purpose: '隐私保护下单：姓名/手机号/地址用沙箱别名替身，支付凭据主机代签，平台拿到的信息全部脱敏。',
  },
  {
    id: 'tpl-ctrip',
    name: '携程公务出行订票',
    agent: 'dsh',
    policyId: 'balanced',
    workspace: '/srv/travel/bookings',
    credentials: ['ctrip-pay'],
    mcpServers: [],
    privacy: true,
    travelerCards: [],
    purpose: '出行人卡片托管：实名出票信息主机侧登记，沙箱只持占位符，平台拿到票但不知为哪位员工且拿不到支付渠道。',
  },
];

export function riskFor(policyId) {
  return { review: '低风险', balanced: '中风险', build: '高风险' }[policyId] || '待评估';
}

export function defaultPackage() {
  const configured = String(process.env.SAFEDESK_DEFAULT_PACKAGE || '').trim();
  if (configured) return configured;
  const candidates = [
    '/opt/wasmer-images/safedesk-agent-python.webc',
    join(homedir(), 'wasmer-images', 'safedesk-agent-python.webc'),
  ];
  return candidates.find((path) => existsSync(path)) || '';
}

export function catalog() {
  return {
    policies: Object.values(policies).map((policy) => ({
      ...policy,
      risk: riskFor(policy.id),
      suitableFor: {
        review: '安全审阅、依赖检查、只读分析',
        balanced: '日常研发、Issue 修复、受控联网',
        build: 'CI 构建、依赖安装、临时产物',
      }[policy.id],
    })),
    agents: Object.entries(allowedAgents).map(([id, value]) => ({ id, ...value, supported: true })),
    defaultPackage: defaultPackage(),
    capabilities: {
      credentials: ['github-read', 'gitlab-read', 'openai-proxy', 'anthropic-proxy', 'internal-mcp', 'meituan-proxy', 'ctrip-pay'],
      mcpServers: ['github', 'gitlab', 'jira', 'confluence', 'browser', 'docs'],
    },
  };
}

export function enrichSandbox(sandbox) {
  const policy = policies[sandbox.policyId] || {};
  const agent = allowedAgents[sandbox.agent] || {};
  return {
    ...sandbox,
    policyLabel: policy.label || sandbox.policyId,
    agentLabel: agent.label || sandbox.agent,
    risk: sandbox.risk || riskFor(sandbox.policyId),
    statusLabel: statusLabels[sandbox.status] || sandbox.status,
    purpose: sandbox.purpose || '',
    notes: sandbox.notes || '',
  };
}

export function filterSandboxes(items, query = {}) {
  const keyword = String(query.q || '').trim().toLowerCase();
  const status = String(query.status || '').trim();
  const agent = String(query.agent || '').trim();
  const policyId = String(query.policyId || '').trim();
  return items.filter((item) => {
    const haystack = [item.id, item.name, item.workspace, item.ownerName, item.purpose].join(' ').toLowerCase();
    if (keyword && !haystack.includes(keyword)) return false;
    if (status && item.status !== status) return false;
    if (agent && item.agent !== agent) return false;
    if (policyId && item.policyId !== policyId) return false;
    return true;
  }).map(enrichSandbox);
}

export function overview(items, events, user) {
  return {
    total: items.length,
    running: items.filter((item) => item.status === 'running').length,
    pendingApproval: items.filter((item) => item.status === 'pending_approval').length,
    paused: items.filter((item) => item.status === 'paused').length,
    rejected: items.filter((item) => item.status === 'rejected').length,
    terminated: items.filter((item) => item.status === 'terminated').length,
    blockedEvents: events.filter((item) => item.level === 'block').length,
    allowEvents: events.filter((item) => item.level === 'allow').length,
    activeUsers: new Set(items.map((item) => item.ownerId).filter(Boolean)).size,
    role: user?.role || 'guest',
    health: items.some((item) => item.status === 'pending_approval') ? 'attention' : 'healthy',
    lastAuditAt: events[0]?.at || null,
    riskMix: {
      低风险: items.filter((item) => riskFor(item.policyId) === '低风险' && item.status !== 'terminated').length,
      中风险: items.filter((item) => riskFor(item.policyId) === '中风险' && item.status !== 'terminated').length,
      高风险: items.filter((item) => riskFor(item.policyId) === '高风险' && item.status !== 'terminated').length,
    },
  };
}

export function mergeSettings(current) {
  return { ...defaultSettings, ...(current || {}) };
}

export function filterEvents(events, query = {}) {
  const keyword = String(query.q || '').trim().toLowerCase();
  const level = String(query.level || '').trim();
  const action = String(query.action || '').trim();
  return events.filter((item) => {
    const haystack = [item.action, item.detail, item.actor].join(' ').toLowerCase();
    if (keyword && !haystack.includes(keyword)) return false;
    if (level && item.level !== level) return false;
    if (action && item.action !== action) return false;
    return true;
  });
}
