#!/usr/bin/env python3
"""SafeDesk control plane: standard-library deployment server for restricted hosts."""
from __future__ import annotations

import json
import os
import re
import secrets
import ssl
import threading
from datetime import datetime, timezone
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from audit import AuditLog
from auth import AuthStore
from broker import CredentialBroker
from launcher import Launcher, workspace_allowed
from policy import ALLOWED_AGENTS, POLICIES, compile_manifest
from privacy import alias_profile
from product import DEFAULT_TEMPLATES, catalog, enrich_sandbox, filter_events, filter_sandboxes, merge_settings, overview as product_overview, risk_for
from proxy import EgressPolicy, ProxyRuntime, serve as serve_proxy
from travelers import TravelerRegistry
from scheduler import ACTIVE, TERMINAL, Scheduler, validate_limits, with_positions

ROOT = Path(__file__).resolve().parent
STATIC_ROOT = ROOT / "static"
DATA_DIR = Path(os.environ["SAFEDESK_DATA_DIR"]) if os.getenv("SAFEDESK_DATA_DIR") else ROOT / "data"
DATA_FILE = Path(os.environ["SAFEDESK_DATA_FILE"]) if os.getenv("SAFEDESK_DATA_FILE") else DATA_DIR / "sandboxes.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
LOCK = threading.Lock()
AUTH_ENABLED = os.getenv("SAFEDESK_AUTH", "1") != "0"
AUTH = AuthStore(DATA_DIR)
EVENTS = [
    {"id": "evt-001", "level": "info", "action": "策略编译", "detail": "policy/balanced 已签名并下发至本地执行器", "at": "2026-10-23T10:12:00.000Z"},
    {"id": "evt-002", "level": "allow", "action": "凭据代签", "detail": "github-read 通过 Host Credential Broker 注入 Authorization 头", "at": "2026-10-23T10:14:00.000Z"},
    {"id": "evt-003", "level": "block", "action": "外联拦截", "detail": "沙箱请求 untrusted.example 被默认拒绝", "at": "2026-10-23T10:17:00.000Z"},
]
AUDIT_LOG = None  # initialized after load_settings()
BROKER = CredentialBroker(DATA_DIR / "credentials.json")
TRAVELERS = TravelerRegistry(DATA_DIR / "travelers.json")
LAUNCHER = Launcher(DATA_DIR / "runners")
PROXY_RT = ProxyRuntime()
PROXY_SERVER = None
PROXY_PORT = int(os.getenv("SAFEDESK_EGRESS_PROXY_PORT", "0"))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_sandboxes() -> list[dict]:
    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text("[]\n", encoding="utf-8")
    return with_positions(json.loads(DATA_FILE.read_text(encoding="utf-8")))


def save_sandboxes(sandboxes: list[dict]) -> None:
    atomic_json(DATA_FILE, [{k: v for k, v in s.items() if k != "queuePosition"} for s in sandboxes])


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_settings() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SETTINGS_FILE.exists():
        SETTINGS_FILE.write_text(json.dumps(merge_settings(None), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return merge_settings(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))


def save_settings(settings: dict) -> dict:
    merged = merge_settings({**load_settings(), **settings})
    validate_limits(merged)
    atomic_json(SETTINGS_FILE, merged)
    return merged


AUDIT_LOG = AuditLog(DATA_DIR / "audit.jsonl", int(load_settings().get("retainAuditDays") or 30))
if not AUDIT_LOG.load():
    for seed in EVENTS:
        AUDIT_LOG.append(seed)
AUDIT_LOG.prune()


def security_event(level: str, action: str, detail: str, actor: str | None = None) -> None:
    event = {"id": str(uuid4()), "level": level, "action": action, "detail": detail, "actor": actor, "at": iso_now()}
    EVENTS.insert(0, event)
    del EVENTS[40:]
    AUDIT_LOG.append(event)


PROXY_RT.on_event = lambda level, detail: security_event(level, "网络决策", detail, "egress-proxy")


def policy_key(sandbox: dict) -> str:
    key = str(sandbox.get("policyId") or "balanced")
    return key if key in POLICIES else "balanced"


def ensure_proxy() -> bool:
    """Start the ingress-side egress proxy once (REQ-NW-015 联动 launcher)."""
    global PROXY_SERVER
    if PROXY_SERVER is None:
        try:
            PROXY_SERVER = serve_proxy(PROXY_RT, "127.0.0.1", PROXY_PORT)
            LAUNCHER.proxy_url = f"http://127.0.0.1:{PROXY_SERVER.server_port}"
        except OSError:
            return False
    return True


def safe_name(value: object) -> str:
    return re.sub(r"[^\w\u4e00-\u9fff-]", "-", str(value or "").strip())[:48]


def start_sandbox(sandbox):
    settings = load_settings()
    if not workspace_allowed(sandbox["workspace"], settings.get("workspaceRoots") or []):
        raise ValueError("工作区不在允许的根目录内")
    manifest = compile_manifest(sandbox)
    sandbox_id = sandbox["id"]
    if POLICIES[policy_key(sandbox)]["networkMode"] != "disabled":
        if not ensure_proxy():
            raise ValueError("外联代理启动失败")
        token = secrets.token_hex(12)
        sandbox["egressToken"] = token
        allowed, injections = set(), {}
        for capability in sandbox.get("credentials") or []:
            item = BROKER.get(capability)
            if item:
                allowed.update(item.get("allowedHosts", []))
                placeholder = (sandbox.get("credentialPlaceholders") or {}).get(capability)
                if placeholder:
                    injections[placeholder] = {"value": item["value"], "hosts": item["allowedHosts"]}
        injections.update(TRAVELERS.resolve_injections(sandbox))
        alias = alias_profile(sandbox_id) if sandbox.get("privacyCurtain") else None
        PROXY_RT.register(sandbox_id, token, EgressPolicy(sorted(allowed), injections, alias))
        manifest["egress"] = {"token": token}
    return LAUNCHER.start(sandbox, manifest)


SCHEDULER = Scheduler(LAUNCHER, start_sandbox, PROXY_RT.unregister, security_event)


def schedule_once():
    with LOCK:
        items = load_sandboxes()
        if SCHEDULER.tick(items, load_settings()):
            save_sandboxes(items)


def scheduler_loop():
    while True:
        try:
            schedule_once()
        except Exception as error:
            print(f"scheduler: {error}", flush=True)
        threading.Event().wait(0.5)


def visible_sandboxes(user: dict | None) -> list[dict]:
    items = load_sandboxes()
    if not AUTH_ENABLED or (user and user.get("role") == "admin"):
        return items
    owner = user["id"] if user else ""
    return [item for item in items if item.get("ownerId") == owner]


def query_map(path: str) -> dict:
    return {key: values[0] for key, values in parse_qs(urlsplit(path).query).items()}


class ApiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_ROOT), **kwargs)

    def send_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def body(self) -> dict:
        size = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(size) or b"{}")
        except json.JSONDecodeError as error:
            raise ValueError("请求体不是合法 JSON") from error

    def bearer(self) -> str | None:
        header = self.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[7:].strip() or None
        return None

    def current_user(self) -> dict | None:
        if not AUTH_ENABLED:
            return {"id": "local-dev", "role": "admin", "displayName": "本地开发", "provider": "disabled"}
        with LOCK:
            return AUTH.session_user(self.bearer())

    def require_user(self) -> dict | None:
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "请先登录"})
            return None
        return user

    def require_admin(self) -> dict | None:
        user = self.require_user()
        if user is None:
            return None
        if user.get("role") != "admin":
            self.send_json(403, {"error": "仅管理员可以执行此操作"})
            return None
        return user

    def can_access(self, user: dict, sandbox: dict) -> bool:
        return user.get("role") == "admin" or sandbox.get("ownerId") == user["id"]

    def do_GET(self) -> None:
        if self.path == "/api/auth/config":
            self.send_json(200, AUTH.public_config())
            return
        if urlsplit(self.path).path == "/api/auth/wechat/poll":
            ticket = (parse_qs(urlsplit(self.path).query).get("ticket") or [""])[0]
            with LOCK:
                self.send_json(200, AUTH.poll_wechat(ticket))
            return
        if urlsplit(self.path).path == "/api/auth/wecom/poll":
            ticket = (parse_qs(urlsplit(self.path).query).get("ticket") or [""])[0]
            with LOCK:
                self.send_json(200, AUTH.poll_wecom(ticket))
            return
        if self.path == "/api/auth/me":
            user = self.current_user()
            if not user:
                self.send_json(401, {"error": "请先登录"})
                return
            self.send_json(200, {"user": AUTH.public_user(user) if AUTH_ENABLED else user, "authEnabled": AUTH_ENABLED})
            return
        if urlsplit(self.path).path == "/api/bootstrap":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                items = [enrich_sandbox(item) for item in visible_sandboxes(user)]
                events = EVENTS if user.get("role") == "admin" else []
                self.send_json(200, {
                    "user": AUTH.public_user(user) if AUTH_ENABLED else user,
                    "overview": product_overview(items, events or EVENTS, user),
                    "catalog": catalog(),
                    "templates": DEFAULT_TEMPLATES,
                    "settings": load_settings(),
                    "policies": list(POLICIES.values()),
                    "agents": [{"id": key, **value} for key, value in ALLOWED_AGENTS.items()],
                    "sandboxes": items,
                    "securityEvents": events,
                })
            return
        if urlsplit(self.path).path == "/api/overview":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                items = visible_sandboxes(user)
                self.send_json(200, {"overview": product_overview(items, EVENTS, user)})
            return
        if urlsplit(self.path).path == "/api/catalog":
            user = self.require_user()
            if user is None:
                return
            self.send_json(200, catalog())
            return
        if urlsplit(self.path).path == "/api/templates":
            user = self.require_user()
            if user is None:
                return
            self.send_json(200, {"templates": DEFAULT_TEMPLATES})
            return
        if urlsplit(self.path).path == "/api/settings":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                self.send_json(200, {"settings": load_settings()})
            return
        if urlsplit(self.path).path == "/api/sandboxes":
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                self.send_json(200, {"sandboxes": filter_sandboxes(visible_sandboxes(user), query_map(self.path))})
            return
        if urlsplit(self.path).path == "/api/events":
            user = self.require_admin()
            if user is None:
                return
            query = query_map(self.path)
            if str(query.get("history")) == "1":
                try:
                    limit = int(query.get("limit") or 100)
                    offset = int(query.get("offset") or 0)
                except ValueError:
                    limit, offset = 100, 0
                events = AUDIT_LOG.query(query.get("q", ""), query.get("level", ""), query.get("action", ""), query.get("since"), limit, offset)
                self.send_json(200, {"events": events, "size": len(events)})
            else:
                self.send_json(200, {"events": filter_events(EVENTS, query)})
            return
        if urlsplit(self.path).path == "/api/credentials":
            user = self.require_admin()
            if user is None:
                return
            self.send_json(200, {"credentials": BROKER.list_masked()})
            return
        if urlsplit(self.path).path == "/api/travelers":
            user = self.require_admin()
            if user is None:
                return
            self.send_json(200, {"travelers": TRAVELERS.list_masked()})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)(?:/(manifest|activity|logs))?", urlsplit(self.path).path)
        if match and match.group(2) in (None, "manifest", "activity", "logs"):
            user = self.require_user()
            if user is None:
                return
            with LOCK:
                sandbox = next((item for item in load_sandboxes() if item["id"] == match.group(1)), None)
                if not sandbox or not self.can_access(user, sandbox):
                    self.send_json(404, {"error": "未找到沙箱"})
                    return
                if match.group(2) == "activity":
                    self.send_json(200, {"events": [item for item in EVENTS if sandbox["name"] in str(item.get("detail", ""))]})
                    return
                if match.group(2) == "logs":
                    query = query_map(self.path)
                    try:
                        offset = int(query.get("offset") or 0)
                    except ValueError:
                        offset = 0
                    self.send_json(200, LAUNCHER.read_log(sandbox["id"], offset=offset))
                    return
                if match.group(2) in (None, "manifest"):
                    payload = {"sandbox": enrich_sandbox(sandbox)}
                    if match.group(2) == "manifest" or match.group(2) is None:
                        payload["manifest"] = compile_manifest(sandbox)
                    if match.group(2) == "manifest":
                        self.send_json(200, {"manifest": payload["manifest"]})
                    else:
                        self.send_json(200, payload)
            return
        if self.path.startswith("/api/"):
            self.send_json(404, {"error": "Not found"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path == "/api/auth/phone/send":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.send_phone_otp(str(payload.get("phone", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/phone/verify":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.verify_phone_otp(str(payload.get("phone", "")).strip(), str(payload.get("token", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/wechat/start":
            with LOCK:
                self.send_json(200, AUTH.start_wechat())
            return
        if self.path == "/api/auth/wechat/confirm":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.confirm_wechat(str(payload.get("ticket", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/wecom/start":
            with LOCK:
                self.send_json(200, AUTH.start_wecom())
            return
        if self.path == "/api/auth/wecom/confirm":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.confirm_wecom(str(payload.get("ticket", "")).strip()))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/admin/login":
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.login_admin(str(payload.get("username", "")).strip(), str(payload.get("password", ""))))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/auth/logout":
            with LOCK:
                AUTH.revoke(self.bearer())
            self.send_json(200, {"ok": True})
            return
        if self.path == "/api/auth/password":
            user = self.require_admin()
            if user is None:
                return
            if not user.get("passwordHash"):
                self.send_json(403, {"error": "仅管理员账户可以修改密码"})
                return
            try:
                payload = self.body()
                with LOCK:
                    self.send_json(200, AUTH.change_password(
                        user,
                        str(payload.get("currentPassword", "")),
                        str(payload.get("newPassword", "")),
                        self.bearer(),
                    ))
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/travelers":
            user = self.require_admin()
            if user is None:
                return
            try:
                payload = self.body()
                hosts = payload.get("allowedHosts") or []
                if not isinstance(hosts, list):
                    raise ValueError("allowedHosts 必须是数组")
                card = TRAVELERS.register(
                    str(payload.get("handle", "")).strip(),
                    str(payload.get("name", "")),
                    str(payload.get("idCard", "")),
                    str(payload.get("phone", "")),
                    hosts,
                    passport=str(payload.get("passport", "")).strip() or None,
                )
                security_event("allow", "登记出行人", f"{card['handle']} 出行人卡片已登记（掩码展示）", user["id"])
                self.send_json(200, {"traveler": card})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/travelers/delete":
            user = self.require_admin()
            if user is None:
                return
            try:
                payload = self.body()
                handle = str(payload.get("handle", "")).strip()
                if not TRAVELERS.remove(handle):
                    self.send_json(404, {"error": "未找到出行人卡片"})
                    return
                security_event("info", "注销出行人", f"{handle} 出行人卡片已删除", user["id"])
                self.send_json(200, {"ok": True})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/credentials":
            user = self.require_admin()
            if user is None:
                return
            try:
                payload = self.body()
                name = str(payload.get("name", "")).strip()
                value = str(payload.get("value", ""))
                hosts = payload.get("allowedHosts") or []
                if not isinstance(hosts, list):
                    raise ValueError("allowedHosts 必须是数组")
                entry = BROKER.put(name, value, hosts)
                security_event("allow", "注册凭据", f"{name} 已登记，目的地白名单 {len(hosts)} 条", user["id"])
                self.send_json(200, {"credential": entry})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/credentials/delete":
            user = self.require_admin()
            if user is None:
                return
            try:
                payload = self.body()
                name = str(payload.get("name", "")).strip()
                if not BROKER.remove(name):
                    self.send_json(404, {"error": "未找到凭据"})
                    return
                security_event("info", "注销凭据", f"{name} 已删除", user["id"])
                self.send_json(200, {"ok": True})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/sandboxes":
            user = self.require_user()
            if user is None:
                return
            try:
                payload = self.body()
                policy_id = str(payload.get("policyId", "balanced"))
                agent = str(payload.get("agent", "claude-code"))
                workspace = str(payload.get("workspace", "")).strip()
                if policy_id not in POLICIES:
                    self.send_json(400, {"error": "未知策略"}); return
                if agent not in ALLOWED_AGENTS:
                    self.send_json(400, {"error": "仅支持 Claude Code、Codex 或 DSH"}); return
                if not workspace.startswith("/"):
                    self.send_json(400, {"error": "工作区必须为绝对路径"}); return
                current_settings = load_settings()
                if not workspace_allowed(workspace, list(current_settings.get("workspaceRoots") or [])):
                    self.send_json(400, {"error": "工作区不在允许的根目录内"}); return
                sandbox = {
                    "id": f"sbx-{uuid4().hex[:8]}", "name": safe_name(payload.get("name")) or f"agent-{agent}",
                    "agent": agent, "policyId": policy_id, "workspace": workspace,
                    "packages": list(payload.get("packages") or ["wasmer/bash@latest"])[:8],
                    "credentials": list(payload.get("credentials") or [])[:8],
                    "mcpServers": list(payload.get("mcpServers") or [])[:12],
                    "purpose": str(payload.get("purpose") or "").strip()[:160],
                    "notes": str(payload.get("notes") or "").strip()[:240],
                    "privacyCurtain": bool(payload.get("privacy", False)),
                    "travelerCards": [str(handle) for handle in list(payload.get("travelerCards") or [])[:4]],
                    "risk": risk_for(policy_id),
                    "status": "pending_approval", "createdAt": iso_now(),
                    "ownerId": user["id"], "ownerName": user.get("displayName") or user.get("username") or user["id"],
                }
                unknown_travelers = [handle for handle in sandbox["travelerCards"] if not TRAVELERS.get(handle)]
                if unknown_travelers:
                    self.send_json(400, {"error": f"未知出行人卡片：{','.join(unknown_travelers)}"}); return
                sandbox["travelerPlaceholders"] = TRAVELERS.issue_placeholders(sandbox)
                sandbox["credentialPlaceholders"] = BROKER.issue_placeholders(sandbox)
                with LOCK:
                    sandboxes = load_sandboxes(); sandboxes.insert(0, sandbox); save_sandboxes(sandboxes)
                    security_event("info", "创建待审批沙箱", f"{sandbox['name']} 使用 {POLICIES[policy_id]['label']} 策略", user["id"])
                self.send_json(201, {"sandbox": enrich_sandbox(sandbox), "manifest": compile_manifest(sandbox)})
            except ValueError as error:
                self.send_json(400, {"error": str(error)})
            return
        if self.path == "/api/settings":
            user = self.require_admin()
            if user is None:
                return
            try:
                payload = self.body()
            except ValueError as error:
                self.send_json(400, {"error": str(error)}); return
            with LOCK:
                try:
                    settings = save_settings(payload)
                except ValueError as error:
                    self.send_json(400, {"error": str(error)}); return
                sandboxes = load_sandboxes()
                if SCHEDULER.tick(sandboxes, settings):
                    save_sandboxes(sandboxes)
                security_event("info", "更新组织设置", f"{settings['orgName']} 已保存并发上限 {settings['maxConcurrent']}", user["id"])
            self.send_json(200, {"settings": settings})
            return
        match = re.fullmatch(r"/api/sandboxes/(sbx-[\w-]+)/(approve|reject|pause|resume|terminate)", self.path)
        if not match:
            self.send_json(404, {"error": "Not found"}); return
        sandbox_id, action = match.groups()
        user = self.require_admin() if action in {"approve", "reject"} else self.require_user()
        if user is None:
            return
        try:
            payload = self.body() if int(self.headers.get("Content-Length", "0")) else {}
        except ValueError as error:
            self.send_json(400, {"error": str(error)}); return
        with LOCK:
            sandboxes = load_sandboxes()
            sandbox = next((item for item in sandboxes if item["id"] == sandbox_id), None)
            if not sandbox or not self.can_access(user, sandbox):
                self.send_json(404, {"error": "未找到沙箱"}); return
            if action == "approve":
                if sandbox["status"] != "pending_approval":
                    self.send_json(409, {"error": "沙箱不是待审批状态"}); return
                try:
                    SCHEDULER.enqueue(sandboxes, sandbox, load_settings(), user["id"])
                except ValueError as error:
                    self.send_json(409, {"error": str(error)}); return
            elif action == "reject":
                if sandbox["status"] != "pending_approval":
                    self.send_json(409, {"error": "沙箱不是待审批状态"}); return
                sandbox["status"] = "rejected"; sandbox["rejectedAt"] = iso_now(); sandbox["rejectedBy"] = user["id"]
                sandbox["rejectReason"] = str(payload.get("reason") or "不符合安全策略").strip()[:160]
                security_event("block", "拒绝启动", f"{sandbox['name']} 被拒绝：{sandbox['rejectReason']}", user["id"])
            elif action == "pause":
                if sandbox["status"] != "running":
                    self.send_json(409, {"error": "仅运行中的沙箱可以暂停"}); return
                if not LAUNCHER.pause(sandbox_id):
                    self.send_json(409, {"error": "进程状态待确认，请核对执行器"}); return
                PROXY_RT.set_paused(sandbox_id, True)
                sandbox["status"] = "paused"; sandbox["pausedAt"] = iso_now(); sandbox["pausedBy"] = user["id"]
                security_event("info", "暂停沙箱", f"{sandbox['name']} 已暂停，外联和会话凭据冻结", user["id"])
            elif action == "resume":
                if sandbox["status"] != "paused":
                    self.send_json(409, {"error": "仅暂停中的沙箱可以恢复"}); return
                if not LAUNCHER.resume(sandbox_id):
                    self.send_json(409, {"error": "进程状态待确认，请核对执行器"}); return
                PROXY_RT.set_paused(sandbox_id, False)
                sandbox["status"] = "running"; sandbox["resumedAt"] = iso_now(); sandbox["resumedBy"] = user["id"]
                security_event("allow", "恢复沙箱", f"{sandbox['name']} 已恢复运行", user["id"])
            else:
                if sandbox["status"] in TERMINAL:
                    self.send_json(409, {"error": "沙箱已结束"}); return
                if sandbox["status"] in ACTIVE and not LAUNCHER.stop(sandbox_id):
                    self.send_json(409, {"error": "进程状态待确认，请核对执行器"}); return
                PROXY_RT.unregister(sandbox_id)
                sandbox.pop("egressToken", None)
                sandbox["status"] = "terminated"; sandbox["terminatedAt"] = iso_now(); sandbox["terminatedBy"] = user["id"]
                security_event("block", "终止沙箱", f"{sandbox['name']} 已终止，短期会话凭据失效", user["id"])
            SCHEDULER.tick(sandboxes, load_settings())
            save_sandboxes(sandboxes)
            sandbox = next(s for s in with_positions(sandboxes) if s["id"] == sandbox_id)
            status = 202 if sandbox["status"] == "queued" else 502 if action == "approve" and sandbox["status"] == "failed" else 200
            self.send_json(status, {"sandbox": enrich_sandbox(sandbox)})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:
        return


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8022"))
    host = os.getenv("HOST", "0.0.0.0")
    cert = os.getenv("SAFEDESK_TLS_CERT")
    key = os.getenv("SAFEDESK_TLS_KEY")
    server = ThreadingHTTPServer((host, port), ApiHandler)
    scheme = "http"
    if cert and key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print(f"SafeDesk control plane listening on {scheme}://{host}:{port}")
    server.serve_forever()
