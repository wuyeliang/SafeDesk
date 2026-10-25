"""Unit tests for product helpers: overview, filters, catalog, settings."""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from policy import ALLOWED_AGENTS, POLICIES  # noqa: E402
from product import (  # noqa: E402
    DEFAULT_SETTINGS,
    DEFAULT_TEMPLATES,
    STATUS_LABELS,
    catalog,
    enrich_sandbox,
    filter_events,
    filter_sandboxes,
    merge_settings,
    overview,
    risk_for,
)


SAMPLES = [
    {"id": "sbx-1", "name": "alpha", "agent": "codex", "policyId": "review", "workspace": "/srv/alpha", "ownerId": "u1", "ownerName": "张三", "purpose": "审阅依赖", "status": "running"},
    {"id": "sbx-2", "name": "beta", "agent": "dsh", "policyId": "build", "workspace": "/srv/beta", "ownerId": "u2", "ownerName": "李四", "purpose": "夜间构建", "status": "pending_approval"},
    {"id": "sbx-3", "name": "gamma", "agent": "claude-code", "policyId": "balanced", "workspace": "/srv/gamma", "ownerId": "u1", "ownerName": "张三", "purpose": "", "status": "paused"},
]


class RiskForTest(unittest.TestCase):
    def test_review_is_low(self):
        self.assertEqual(risk_for("review"), "低风险")

    def test_balanced_is_medium(self):
        self.assertEqual(risk_for("balanced"), "中风险")

    def test_build_is_high(self):
        self.assertEqual(risk_for("build"), "高风险")

    def test_unknown_policy_is_pending_eval(self):
        self.assertEqual(risk_for("everything-allowed"), "待评估")


class StatusLabelsTest(unittest.TestCase):
    def test_covers_five_lifecycle_states(self):
        self.assertEqual(sorted(STATUS_LABELS), ["paused", "pending_approval", "rejected", "running", "terminated"])

    def test_pending_label(self):
        self.assertEqual(STATUS_LABELS["pending_approval"], "待审批")

    def test_running_label(self):
        self.assertEqual(STATUS_LABELS["running"], "运行中")

    def test_paused_label(self):
        self.assertEqual(STATUS_LABELS["paused"], "已暂停")

    def test_rejected_label(self):
        self.assertEqual(STATUS_LABELS["rejected"], "已拒绝")

    def test_terminated_label(self):
        self.assertEqual(STATUS_LABELS["terminated"], "已终止")


class DefaultSettingsTest(unittest.TestCase):
    def test_requires_approval(self):
        self.assertTrue(DEFAULT_SETTINGS["requireApproval"])

    def test_positive_concurrency_cap(self):
        self.assertGreater(DEFAULT_SETTINGS["maxConcurrent"], 0)

    def test_notice_mentions_secrets(self):
        self.assertIn("密钥", DEFAULT_SETTINGS["notice"])

    def test_phone_login_enabled(self):
        self.assertTrue(DEFAULT_SETTINGS["allowPhoneLogin"])

    def test_wechat_login_enabled(self):
        self.assertTrue(DEFAULT_SETTINGS["allowWechatLogin"])

    def test_admin_login_enabled(self):
        self.assertTrue(DEFAULT_SETTINGS["allowAdminLogin"])

    def test_session_timeout_is_positive(self):
        self.assertGreater(DEFAULT_SETTINGS["sessionTimeoutMin"], 0)

    def test_audit_retention_is_positive(self):
        self.assertGreater(DEFAULT_SETTINGS["retainAuditDays"], 0)


class TemplatesTest(unittest.TestCase):
    def test_exactly_four_templates(self):
        self.assertEqual(len(DEFAULT_TEMPLATES), 5)

    def test_review_template_policy(self):
        self.assertEqual(DEFAULT_TEMPLATES[0]["policyId"], "review")

    def test_dev_template_policy(self):
        self.assertEqual(DEFAULT_TEMPLATES[1]["policyId"], "balanced")

    def test_build_template_policy(self):
        self.assertEqual(DEFAULT_TEMPLATES[2]["policyId"], "build")

    def test_templates_use_known_agents(self):
        for template in DEFAULT_TEMPLATES:
            self.assertIn(template["agent"], ALLOWED_AGENTS)

    def test_templates_use_known_policies(self):
        for template in DEFAULT_TEMPLATES:
            self.assertIn(template["policyId"], POLICIES)

    def test_templates_use_absolute_workspaces(self):
        for template in DEFAULT_TEMPLATES:
            self.assertTrue(template["workspace"].startswith("/"))


class EnrichSandboxTest(unittest.TestCase):
    def test_resolves_known_labels(self):
        enriched = enrich_sandbox({"policyId": "build", "agent": "dsh", "status": "running"})
        self.assertEqual(enriched["policyLabel"], "受限构建")
        self.assertEqual(enriched["agentLabel"], "DSH")

    def test_unknown_policy_falls_back_to_id(self):
        self.assertEqual(enrich_sandbox({"policyId": "mystery"}).get("policyLabel"), "mystery")

    def test_unknown_agent_falls_back_to_id(self):
        self.assertEqual(enrich_sandbox({"agent": "gpt-shell"}).get("agentLabel"), "gpt-shell")

    def test_status_pending(self):
        self.assertEqual(enrich_sandbox({"status": "pending_approval"})["statusLabel"], "待审批")

    def test_status_running(self):
        self.assertEqual(enrich_sandbox({"status": "running"})["statusLabel"], "运行中")

    def test_status_paused(self):
        self.assertEqual(enrich_sandbox({"status": "paused"})["statusLabel"], "已暂停")

    def test_status_rejected(self):
        self.assertEqual(enrich_sandbox({"status": "rejected"})["statusLabel"], "已拒绝")

    def test_status_terminated(self):
        self.assertEqual(enrich_sandbox({"status": "terminated"})["statusLabel"], "已终止")

    def test_computes_risk_from_policy(self):
        self.assertEqual(enrich_sandbox({"policyId": "review"})["risk"], "低风险")

    def test_preserves_explicit_risk(self):
        self.assertEqual(enrich_sandbox({"policyId": "review", "risk": "高风险"})["risk"], "高风险")

    def test_defaults_purpose_and_notes(self):
        enriched = enrich_sandbox({})
        self.assertEqual(enriched["purpose"], "")
        self.assertEqual(enriched["notes"], "")


class FilterSandboxesTest(unittest.TestCase):
    def test_keyword_id(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"q": "sbx-1"})), 1)

    def test_keyword_name_case_insensitive(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"q": "Alpha"})), 1)

    def test_keyword_workspace(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"q": "/srv/beta"})), 1)

    def test_keyword_owner(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"q": "李四"})), 1)

    def test_keyword_purpose(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"q": "审阅"})), 1)

    def test_keyword_no_match(self):
        self.assertEqual(filter_sandboxes(SAMPLES, {"q": "不存在的词"}), [])

    def test_filter_by_status(self):
        self.assertEqual([item["id"] for item in filter_sandboxes(SAMPLES, {"status": "paused"})], ["sbx-3"])

    def test_filter_by_agent(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"agent": "dsh"})), 1)

    def test_filter_by_policy(self):
        self.assertEqual(len(filter_sandboxes(SAMPLES, {"policyId": "review"})), 1)

    def test_combined_keyword_and_status(self):
        result = filter_sandboxes(SAMPLES, {"q": "srv", "status": "running"})
        self.assertEqual([item["id"] for item in result], ["sbx-1"])

    def test_empty_query_returns_all_enriched(self):
        result = filter_sandboxes(SAMPLES, {})
        self.assertEqual(len(result), 3)
        self.assertTrue(all(item.get("statusLabel") and item.get("policyLabel") for item in result))


class OverviewTest(unittest.TestCase):
    def setUp(self):
        self.items = [
            {"status": "running", "ownerId": "u1", "policyId": "review"},
            {"status": "pending_approval", "ownerId": "u1", "policyId": "balanced"},
            {"status": "paused", "ownerId": "u2", "policyId": "build"},
            {"status": "rejected", "ownerId": "u2", "policyId": "review"},
            {"status": "terminated", "ownerId": "u2", "policyId": "build"},
        ]
        self.events = [
            {"level": "block", "at": "2026-10-24T01:00:00.000Z"},
            {"level": "allow", "at": "2026-10-24T00:00:00.000Z"},
        ]
        self.ov = overview(self.items, self.events, {"role": "admin"})

    def test_total(self):
        self.assertEqual(self.ov["total"], 5)

    def test_running(self):
        self.assertEqual(self.ov["running"], 1)

    def test_pending(self):
        self.assertEqual(self.ov["pendingApproval"], 1)

    def test_paused(self):
        self.assertEqual(self.ov["paused"], 1)

    def test_rejected(self):
        self.assertEqual(self.ov["rejected"], 1)

    def test_terminated(self):
        self.assertEqual(self.ov["terminated"], 1)

    def test_event_counts(self):
        self.assertEqual(self.ov["blockedEvents"], 1)
        self.assertEqual(self.ov["allowEvents"], 1)

    def test_active_users_deduped(self):
        self.assertEqual(self.ov["activeUsers"], 2)

    def test_ignores_missing_owner(self):
        self.assertEqual(overview([{"status": "running"}], [], {})["activeUsers"], 0)

    def test_echoes_role(self):
        self.assertEqual(self.ov["role"], "admin")

    def test_guest_role_fallback(self):
        self.assertEqual(overview([], [], None)["role"], "guest")

    def test_attention_while_pending(self):
        self.assertEqual(self.ov["health"], "attention")

    def test_healthy_without_pending(self):
        self.assertEqual(overview([{"status": "running"}], [], {})["health"], "healthy")

    def test_last_audit_from_newest_event(self):
        self.assertEqual(self.ov["lastAuditAt"], "2026-10-24T01:00:00.000Z")

    def test_last_audit_none_without_events(self):
        self.assertIsNone(overview([], [], {})["lastAuditAt"])

    def test_risk_mix_low(self):
        self.assertEqual(self.ov["riskMix"]["低风险"], 2)

    def test_risk_mix_medium(self):
        self.assertEqual(self.ov["riskMix"]["中风险"], 1)

    def test_risk_mix_high_excludes_terminated(self):
        self.assertEqual(self.ov["riskMix"]["高风险"], 1)


class MergeSettingsTest(unittest.TestCase):
    def test_null_returns_defaults(self):
        self.assertEqual(merge_settings(None), DEFAULT_SETTINGS)

    def test_partial_override_keeps_defaults(self):
        merged = merge_settings({"maxConcurrent": 16})
        self.assertEqual(merged["maxConcurrent"], 16)
        self.assertEqual(merged["orgName"], DEFAULT_SETTINGS["orgName"])

    def test_unknown_keys_are_ignored(self):
        self.assertNotIn("customField", merge_settings({"customField": "x"}))


class FilterEventsTest(unittest.TestCase):
    EVENTS = [
        {"level": "block", "action": "外联拦截", "detail": "请求 untrusted.example 被拒绝", "actor": "admin"},
        {"level": "allow", "action": "人工审批", "detail": "alpha 已启动", "actor": "admin"},
        {"level": "info", "action": "创建待审批沙箱", "detail": "beta 使用标准研发策略", "actor": "phone-user"},
    ]

    def test_keyword_action(self):
        self.assertEqual(len(filter_events(self.EVENTS, {"q": "人工审批"})), 1)

    def test_keyword_detail_case_insensitive(self):
        self.assertEqual(len(filter_events(self.EVENTS, {"q": "UNTRUSTED"})), 1)

    def test_keyword_actor(self):
        self.assertEqual(len(filter_events(self.EVENTS, {"q": "phone-user"})), 1)

    def test_filter_by_level(self):
        self.assertEqual([e["action"] for e in filter_events(self.EVENTS, {"level": "block"})], ["外联拦截"])

    def test_filter_by_action(self):
        self.assertEqual(len(filter_events(self.EVENTS, {"action": "人工审批"})), 1)

    def test_combined_level_and_keyword(self):
        self.assertEqual(len(filter_events(self.EVENTS, {"level": "info", "q": "beta"})), 1)
        self.assertEqual(len(filter_events(self.EVENTS, {"level": "block", "q": "beta"})), 0)

    def test_empty_query_returns_all(self):
        self.assertEqual(len(filter_events(self.EVENTS, {})), 3)


class CatalogTest(unittest.TestCase):
    def setUp(self):
        self.cat = catalog()

    def test_three_policies_with_risk(self):
        self.assertEqual(len(self.cat["policies"]), 3)
        self.assertTrue(all(p["risk"] in {"低风险", "中风险", "高风险"} for p in self.cat["policies"]))

    def test_review_suitability(self):
        policy = next(p for p in self.cat["policies"] if p["id"] == "review")
        self.assertTrue(policy["suitableFor"])

    def test_balanced_suitability(self):
        policy = next(p for p in self.cat["policies"] if p["id"] == "balanced")
        self.assertTrue(policy["suitableFor"])

    def test_build_suitability(self):
        policy = next(p for p in self.cat["policies"] if p["id"] == "build")
        self.assertTrue(policy["suitableFor"])

    def test_agents_supported(self):
        self.assertEqual(len(self.cat["agents"]), 3)
        self.assertTrue(all(agent["supported"] is True for agent in self.cat["agents"]))

    def test_credential_profiles(self):
        self.assertIn("github-read", self.cat["capabilities"]["credentials"])

    def test_mcp_servers(self):
        self.assertIn("github", self.cat["capabilities"]["mcpServers"])

    def test_default_package_is_text(self):
        self.assertIsInstance(self.cat["defaultPackage"], str)

    def test_default_package_honors_env(self):
        with patch.dict(os.environ, {"SAFEDESK_DEFAULT_PACKAGE": "/opt/wasmer-images/safedesk-agent-python.webc"}):
            self.assertEqual(catalog()["defaultPackage"], "/opt/wasmer-images/safedesk-agent-python.webc")


if __name__ == "__main__":
    unittest.main()
