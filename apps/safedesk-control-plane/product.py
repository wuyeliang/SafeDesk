"""Enterprise product helpers: overview, filters, templates, and settings."""
from __future__ import annotations

import os
from pathlib import Path

from policy import ALLOWED_AGENTS, POLICIES

STATUS_LABELS = {
    "pending_approval": "待审批",
    "running": "运行中",
    "paused": "已暂停",
    "rejected": "已拒绝",
    "terminated": "已终止",
}

DEFAULT_SETTINGS = {
    "orgName": "SafeDesk 安全运营中心",
    "requireApproval": True,
    "maxConcurrent": 8,
    "sessionTimeoutMin": 240,
    "allowPhoneLogin": True,
    "allowWechatLogin": True,
    "allowWecomLogin": True,
    "allowAdminLogin": True,
    "retainAuditDays": 30,
    "workspaceRoots": [],
    "notice": "密钥永不进入沙箱。所有外联必须经主机凭据代理。",
}

DEFAULT_TEMPLATES = [
    {
        "id": "tpl-review",
        "name": "依赖安全审阅",
        "agent": "codex",
        "policyId": "review",
        "workspace": "/srv/audit/webapp",
        "credentials": [],
        "mcpServers": [],
        "purpose": "只读审计第三方依赖，禁止写盘和出网。",
    },
    {
        "id": "tpl-dev",
        "name": "功能分支研发",
        "agent": "claude-code",
        "policyId": "balanced",
        "workspace": "/srv/workspaces/pay-service",
        "credentials": ["github-read", "anthropic-proxy"],
        "mcpServers": ["github", "docs"],
        "purpose": "日常改代码，凭据由主机代签。",
    },
    {
        "id": "tpl-build",
        "name": "夜间受限构建",
        "agent": "dsh",
        "policyId": "build",
        "workspace": "/srv/build/cache",
        "credentials": ["internal-mcp"],
        "mcpServers": [],
        "purpose": "临时工作区构建，出网必须走白名单。",
    },
    {
        "id": "tpl-takeout",
        "name": "外卖隐私下单",
        "agent": "dsh",
        "policyId": "balanced",
        "workspace": "/srv/orders/takeout",
        "credentials": ["meituan-proxy"],
        "mcpServers": [],
        "privacy": True,
        "purpose": "隐私保护下单：姓名/手机号/地址用沙箱别名替身，支付凭据主机代签，平台拿到的信息全部脱敏。",
    },
    {
        "id": "tpl-ctrip",
        "name": "携程公务出行订票",
        "agent": "dsh",
        "policyId": "balanced",
        "workspace": "/srv/travel/bookings",
        "credentials": ["ctrip-pay"],
        "mcpServers": [],
        "privacy": True,
        "travelerCards": [],
        "purpose": "出行人卡片托管：实名出票信息主机侧登记，沙箱只持占位符，订理过程平台见账名但其不知为哪位员工且拿不到支付渠道。",
    },
]


def risk_for(policy_id: str) -> str:
    return {"review": "低风险", "balanced": "中风险", "build": "高风险"}.get(policy_id, "待评估")


def default_package() -> str:
    """Local sandbox image to prefill in the console. Empty means wasmer/bash@latest."""
    configured = os.getenv("SAFEDESK_DEFAULT_PACKAGE", "").strip()
    if configured:
        return configured
    candidates = [
        Path("/opt/wasmer-images/safedesk-agent-python.webc"),
        Path.home() / "wasmer-images" / "safedesk-agent-python.webc",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return ""


def catalog() -> dict:
    return {
        "policies": [
            {
                **policy,
                "risk": risk_for(policy["id"]),
                "suitableFor": {
                    "review": "安全审阅、依赖检查、只读分析",
                    "balanced": "日常研发、Issue 修复、受控联网",
                    "build": "CI 构建、依赖安装、临时产物",
                }[policy["id"]],
            }
            for policy in POLICIES.values()
        ],
        "agents": [{"id": key, **value, "supported": True} for key, value in ALLOWED_AGENTS.items()],
        "defaultPackage": default_package(),
        "capabilities": {
            "credentials": ["github-read", "gitlab-read", "openai-proxy", "anthropic-proxy", "internal-mcp", "meituan-proxy", "ctrip-pay"],
            "mcpServers": ["github", "gitlab", "jira", "confluence", "browser", "docs"],
        },
    }


def enrich_sandbox(sandbox: dict) -> dict:
    item = dict(sandbox)
    policy = POLICIES.get(item.get("policyId"), {})
    agent = ALLOWED_AGENTS.get(item.get("agent"), {})
    item["policyLabel"] = policy.get("label", item.get("policyId"))
    item["agentLabel"] = agent.get("label", item.get("agent"))
    item["risk"] = item.get("risk") or risk_for(item.get("policyId", ""))
    item["statusLabel"] = STATUS_LABELS.get(item.get("status"), item.get("status"))
    item["purpose"] = item.get("purpose") or ""
    item["notes"] = item.get("notes") or ""
    return item


def filter_sandboxes(items: list[dict], query: dict) -> list[dict]:
    keyword = str(query.get("q") or "").strip().lower()
    status = str(query.get("status") or "").strip()
    agent = str(query.get("agent") or "").strip()
    policy_id = str(query.get("policyId") or "").strip()
    result = []
    for item in items:
        haystack = " ".join([
            str(item.get("id", "")),
            str(item.get("name", "")),
            str(item.get("workspace", "")),
            str(item.get("ownerName", "")),
            str(item.get("purpose", "")),
        ]).lower()
        if keyword and keyword not in haystack:
            continue
        if status and item.get("status") != status:
            continue
        if agent and item.get("agent") != agent:
            continue
        if policy_id and item.get("policyId") != policy_id:
            continue
        result.append(enrich_sandbox(item))
    return result


def overview(items: list[dict], events: list[dict], user: dict | None) -> dict:
    running = sum(item.get("status") == "running" for item in items)
    pending = sum(item.get("status") == "pending_approval" for item in items)
    paused = sum(item.get("status") == "paused" for item in items)
    rejected = sum(item.get("status") == "rejected" for item in items)
    terminated = sum(item.get("status") == "terminated" for item in items)
    return {
        "total": len(items),
        "running": running,
        "pendingApproval": pending,
        "paused": paused,
        "rejected": rejected,
        "terminated": terminated,
        "blockedEvents": sum(item.get("level") == "block" for item in events),
        "allowEvents": sum(item.get("level") == "allow" for item in events),
        "activeUsers": len({item.get("ownerId") for item in items if item.get("ownerId")}),
        "role": (user or {}).get("role", "guest"),
        "health": "attention" if pending else "healthy",
        "lastAuditAt": events[0].get("at") if events else None,
        "riskMix": {
            "低风险": sum(risk_for(item.get("policyId", "")) == "低风险" and item.get("status") != "terminated" for item in items),
            "中风险": sum(risk_for(item.get("policyId", "")) == "中风险" and item.get("status") != "terminated" for item in items),
            "高风险": sum(risk_for(item.get("policyId", "")) == "高风险" and item.get("status") != "terminated" for item in items),
        },
    }


def merge_settings(current: dict | None) -> dict:
    merged = dict(DEFAULT_SETTINGS)
    if current:
        merged.update({key: current[key] for key in DEFAULT_SETTINGS if key in current})
    return merged


def filter_events(events: list[dict], query: dict) -> list[dict]:
    keyword = str(query.get("q") or "").strip().lower()
    level = str(query.get("level") or "").strip()
    action = str(query.get("action") or "").strip()
    result = []
    for item in events:
        haystack = " ".join([str(item.get("action", "")), str(item.get("detail", "")), str(item.get("actor", ""))]).lower()
        if keyword and keyword not in haystack:
            continue
        if level and item.get("level") != level:
            continue
        if action and item.get("action") != action:
            continue
        result.append(item)
    return result
