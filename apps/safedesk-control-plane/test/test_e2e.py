"""SafeDesk control plane end-to-end suite (auth enabled).

E2E-01  admin login -> forced password change -> old session revoked -> relogin
E2E-02  phone OTP full flow (send, resend throttle, wrong code, right code)
E2E-03  wechat QR flow (start -> poll pending -> confirm -> poll confirmed)
E2E-04  unauthenticated requests -> 401; logout -> 401 afterwards
E2E-05  per-user data isolation vs admin-wide visibility
E2E-06  full sandbox lifecycle: create -> approve -> pause -> resume -> terminate
E2E-07  global runtime quota -> approved tasks queue and automatically fill freed slots
E2E-08  credential broker: masked listing, manifest/data file never leak secrets
E2E-09  egress proxy: auth, SSRF guard, allowlist, pause freeze
E2E-10  audit history persistence (audit.jsonl + history query + non-admin 403)

Business-scenario round:
E2E-11  task templates -> correct policy manifests per template
E2E-12  sandbox search & filters (q/status/agent/policyId combinations)
E2E-13  overview metrics consistent with sandbox states + riskMix + health
E2E-14  bootstrap role difference: user gets empty securityEvents, admin full
E2E-15  workspaceRoots governance: outside/root-escape rejected, settings persisted
E2E-16  rejection flow: reason, rejectedBy, block event, terminal rejected state
E2E-17  egress credential lifecycle: wildcard allowlist, token dies on terminate
E2E-18  audit retention prune at startup (old + corrupted lines dropped)
E2E-19  SAFEDESK_ADMIN_PHONES phone-to-admin role, no password change for it
E2E-20  restart business continuity: sandboxes/users/settings/password/sessions

Run: python3 -m unittest test.test_e2e -v
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Local test traffic must never go through a proxy configured via *_PROXY env vars.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class E2EBase(unittest.TestCase):
    """Spins up server.py once with SAFEDESK_AUTH=1 and an isolated data dir."""

    @classmethod
    def extra_env(cls) -> dict:
        """Subclass hook: additional env vars for the spawned server."""
        return {}

    @classmethod
    def prepare_data_dir(cls, data_dir: Path) -> None:
        """Subclass hook: seed files into the data dir before the server starts."""

    @classmethod
    def _spawn(cls) -> None:
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"],
            cwd=ROOT,
            env=cls.env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        cls.wait_ready()

    @classmethod
    def wait_ready(cls) -> None:
        for _ in range(60):
            try:
                cls.request("GET", "/api/auth/config")
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("server did not start")

    @classmethod
    def respawn(cls) -> None:
        """Kill the current server and start a new one against the same data dir."""
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)
        time.sleep(0.2)
        cls._spawn()

    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-e2e-"))
        cls.port = free_port()
        cls.proxy_port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls.env = {
            **os.environ,
            "PORT": str(cls.port),
            "HOST": "127.0.0.1",
            "SAFEDESK_DATA_DIR": str(cls.data_dir),
            "SAFEDESK_AUTH": "1",
            "SAFEDESK_DEMO": "1",
            "SAFEDESK_EGRESS_PROXY_PORT": str(cls.proxy_port),
            **cls.extra_env(),
        }
        cls.prepare_data_dir(cls.data_dir)
        try:
            cls._spawn()
        except RuntimeError:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    # -- helpers -----------------------------------------------------------

    @classmethod
    def request(cls, method: str, path: str, body=None, token: str | None = None):
        payload = None
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(cls.base + path, data=payload, headers=headers, method=method)
        try:
            with OPENER.open(request, timeout=8) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    @classmethod
    def admin_login(cls, password: str = "SafeDesk@Admin") -> tuple[int, dict]:
        return cls.request("POST", "/api/auth/admin/login", {"username": "admin", "password": password})

    @classmethod
    def phone_login(cls, phone: str) -> str:
        status, sent = cls.request("POST", "/api/auth/phone/send", {"phone": phone})
        assert status == 200 and sent.get("demoCode"), (status, sent)
        status, session = cls.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        assert status == 200, (status, session)
        return session["token"]

    @classmethod
    def create_sandbox(cls, token: str, **overrides):
        payload = {
            "name": "e2e-box",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/e2e-project",
            "credentials": [],
            "mcpServers": [],
        }
        payload.update(overrides)
        return cls.request("POST", "/api/sandboxes", payload, token=token)

    @classmethod
    def sandboxes_on_disk(cls) -> list[dict]:
        return json.loads((cls.data_dir / "sandboxes.json").read_text(encoding="utf-8"))

    @classmethod
    def users_on_disk(cls) -> list[dict]:
        return json.loads((cls.data_dir / "users.json").read_text(encoding="utf-8"))

    @classmethod
    def proxy_request(cls, method: str, target: str, auth: str | None = None) -> int:
        conn = http.client.HTTPConnection("127.0.0.1", cls.proxy_port, timeout=8)
        headers = {"Proxy-Authorization": f"Basic {auth}"} if auth else {}
        conn.request(method, target, headers=headers)
        try:
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()


class TestE2E01AdminPasswordFlow(E2EBase):
    """E2E-01: admin login -> mustChangePassword -> change -> old sessions die -> relogin."""

    def test_e2e_01(self):
        status, session1 = self.admin_login()
        self.assertEqual(status, 200)
        self.assertTrue(session1["user"]["mustChangePassword"], "默认密码登录必须标记强制改密")
        token1 = session1["token"]

        status, session2 = self.admin_login()
        self.assertEqual(status, 200)
        token2 = session2["token"]

        # 错误当前密码 / 弱新密码都被拒绝
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "wrong", "newPassword": "NewPassw0rd!"}, token=token1)
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "short"}, token=token1)
        self.assertEqual(status, 400)
        status, _ = self.request("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "SafeDesk@Admin"}, token=token1)
        self.assertEqual(status, 400, "不允许继续用默认密码")

        status, changed = self.request(
            "POST", "/api/auth/password",
            {"currentPassword": "SafeDesk@Admin", "newPassword": "E2E-NewPassw0rd"},
            token=token1,
        )
        self.assertEqual(status, 200)
        self.assertTrue(changed["ok"])
        self.assertFalse(changed["user"]["mustChangePassword"])

        # 落盘：users.json 已更新且不再标记强制改密
        admin_record = next(u for u in self.users_on_disk() if u.get("username") == "admin")
        self.assertFalse(admin_record["mustChangePassword"])
        self.assertIn("passwordChangedAt", admin_record)

        # 其他会话被吊销，仅当前会话保留
        status, _ = self.request("GET", "/api/auth/me", token=token2)
        self.assertEqual(status, 401, "改密后其他会话必须失效")
        status, me = self.request("GET", "/api/auth/me", token=token1)
        self.assertEqual(status, 200)
        self.assertFalse(me["user"]["mustChangePassword"])

        # 旧密码登录失败，新密码登录成功
        status, _ = self.admin_login()
        self.assertEqual(status, 400)
        status, relogin = self.admin_login(password="E2E-NewPassw0rd")
        self.assertEqual(status, 200)
        self.assertFalse(relogin["user"]["mustChangePassword"])


class TestE2E02PhoneOtp(E2EBase):
    """E2E-02: phone OTP send -> throttle -> wrong code -> right code -> session."""

    def test_e2e_02(self):
        phone = "13900000001"
        status, sent = self.request("POST", "/api/auth/phone/send", {"phone": "12345"})
        self.assertEqual(status, 400, "非手机号必须 400")

        status, sent = self.request("POST", "/api/auth/phone/send", {"phone": phone})
        self.assertEqual(status, 200)
        self.assertIn("demoCode", sent, "演示模式必须回显验证码")

        status, _ = self.request("POST", "/api/auth/phone/send", {"phone": phone})
        self.assertEqual(status, 400, "60 秒内重复发送必须被限频")

        status, _ = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": "000000"})
        self.assertTrue(status == 400, "错误验证码必须 400")

        status, session = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        self.assertEqual(status, 200)
        self.assertEqual(session["user"]["role"], "user")
        self.assertEqual(session["user"]["provider"], "phone")
        self.assertIn("****", session["user"]["displayName"])

        status, me = self.request("GET", "/api/auth/me", token=session["token"])
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["id"], f"phone-{phone}")

        # 验证码一次性：已消费的 code 不可再次使用
        status, _ = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        self.assertEqual(status, 400)


class TestE2E03WechatQr(E2EBase):
    """E2E-03: wechat QR start -> poll pending -> confirm -> poll confirmed -> token."""

    def test_e2e_03(self):
        status, started = self.request("POST", "/api/auth/wechat/start")
        self.assertEqual(status, 200)
        ticket = started["ticket"]
        self.assertGreater(started["expiresIn"], 0)

        status, poll = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(poll["status"], "pending")

        status, _ = self.request("POST", "/api/auth/wechat/confirm", {"ticket": "bogus-ticket"})
        self.assertEqual(status, 400)

        status, confirmed = self.request("POST", "/api/auth/wechat/confirm", {"ticket": ticket})
        self.assertEqual(status, 200)
        self.assertTrue(confirmed["ok"])

        status, poll = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(poll["status"], "confirmed")
        self.assertIn("token", poll)
        self.assertEqual(poll["user"]["provider"], "wechat")

        # ticket 一次性消费
        status, again = self.request("GET", f"/api/auth/wechat/poll?ticket={ticket}")
        self.assertEqual(status, 200)
        self.assertEqual(again["status"], "expired")

        status, me = self.request("GET", "/api/auth/me", token=poll["token"])
        self.assertEqual(status, 200)
        self.assertTrue(me["user"]["id"].startswith("wechat-"))

        # 企业微信同款链路
        status, started = self.request("POST", "/api/auth/wecom/start")
        self.assertEqual(status, 200)
        status, _ = self.request("POST", "/api/auth/wecom/confirm", {"ticket": started["ticket"]})
        self.assertEqual(status, 200)
        status, poll = self.request("GET", f"/api/auth/wecom/poll?ticket={started['ticket']}")
        self.assertEqual(poll["status"], "confirmed")
        self.assertEqual(poll["user"]["provider"], "wecom")


class TestE2E04AuthGate(E2EBase):
    """E2E-04: protected endpoints reject anonymous callers; logout invalidates the token."""

    def test_e2e_04(self):
        for method, path in [
            ("GET", "/api/bootstrap"),
            ("GET", "/api/sandboxes"),
            ("GET", "/api/overview"),
            ("GET", "/api/events"),
            ("GET", "/api/credentials"),
            ("POST", "/api/sandboxes"),
            ("POST", "/api/settings"),
        ]:
            body = {} if method == "POST" else None
            status, _ = self.request(method, path, body)
            self.assertEqual(status, 401, f"{method} {path}")

        # 伪造 token 同样是 401
        status, _ = self.request("GET", "/api/bootstrap", token="forged-token")
        self.assertEqual(status, 401)

        token = self.phone_login("13900000002")
        status, _ = self.request("GET", "/api/bootstrap", token=token)
        self.assertEqual(status, 200)

        status, out = self.request("POST", "/api/auth/logout", token=token)
        self.assertEqual(status, 200)
        self.assertTrue(out["ok"])
        status, _ = self.request("GET", "/api/bootstrap", token=token)
        self.assertEqual(status, 401, "注销后 token 必须失效")


class TestE2E05DataIsolation(E2EBase):
    """E2E-05: a user only sees their own sandboxes; admin sees everything."""

    def test_e2e_05(self):
        alice = self.phone_login("13900000003")
        bob = self.phone_login("13900000004")
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, created = self.create_sandbox(alice, name="alice-secret-box")
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        self.assertEqual(created["sandbox"]["ownerId"], "phone-13900000003")

        status, listing = self.request("GET", "/api/sandboxes", token=bob)
        self.assertEqual(status, 200)
        self.assertFalse(any(item["id"] == sandbox_id for item in listing["sandboxes"]), "B 用户不得看到 A 用户的沙箱")

        status, _ = self.request("GET", f"/api/sandboxes/{sandbox_id}/manifest", token=bob)
        self.assertEqual(status, 404, "跨用户访问沙箱清单必须 404")

        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=bob)
        self.assertEqual(status, 404, "跨用户操作沙箱必须 404")

        status, listing = self.request("GET", "/api/sandboxes", token=admin_token)
        self.assertEqual(status, 200)
        self.assertTrue(any(item["id"] == sandbox_id for item in listing["sandboxes"]), "管理员必须看到全部沙箱")

        status, detail = self.request("GET", f"/api/sandboxes/{sandbox_id}", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(detail["sandbox"]["id"], sandbox_id)


class TestE2E06Lifecycle(E2EBase):
    """E2E-06: create -> approve -> running -> pause -> resume -> terminate, with events."""

    def test_e2e_06(self):
        owner = self.phone_login("13900000005")
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, created = self.create_sandbox(owner, name="e2e-lifecycle", policyId="balanced")
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        self.assertEqual(created["sandbox"]["status"], "pending_approval")

        # 审批/拒绝仅限管理员
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=owner)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/reject", token=owner)
        self.assertEqual(status, 403)

        # 未运行时不能暂停/恢复
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=owner)
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=owner)
        self.assertEqual(status, 409)

        status, approved = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(approved["sandbox"]["status"], "running")
        self.assertIn("startedAt", approved["sandbox"])
        self.assertEqual(approved["sandbox"]["approvedBy"], "admin")

        # 重复审批 -> 409
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 409)

        # 运行中的沙箱进程真实存在（dry-run sleep 或 wasmer）
        stored = next(s for s in self.sandboxes_on_disk() if s["id"] == sandbox_id)
        self.assertIn("runtime", stored)
        self.assertGreater(stored["runtime"]["pid"], 0)

        status, paused = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(paused["sandbox"]["status"], "paused")
        self.assertEqual(paused["sandbox"]["pausedBy"], "phone-13900000005")

        status, resumed = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(resumed["sandbox"]["status"], "running")

        status, terminated = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=owner)
        self.assertEqual(status, 200)
        self.assertEqual(terminated["sandbox"]["status"], "terminated")

        # 终止是终态
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=owner)
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 409)

        # 生命周期事件齐全且含暂停/恢复/终止
        status, events = self.request("GET", "/api/events", token=admin_token)
        self.assertEqual(status, 200)
        actions = [e["action"] for e in events["events"]]
        for expected in ("创建待审批沙箱", "人工审批", "暂停沙箱", "恢复沙箱", "终止沙箱"):
            self.assertIn(expected, actions)


class TestE2E07Quota(E2EBase):
    """E2E-07: approval queues work for all users, including administrators."""

    def test_e2e_07(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        _, original = self.request("GET", "/api/settings", token=admin_token)
        saved = dict(original["settings"])
        try:
            status, updated = self.request("POST", "/api/settings", {**saved, "maxConcurrent": 1}, token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(updated["settings"]["maxConcurrent"], 1)

            user = self.phone_login("13900000006")
            status, first = self.create_sandbox(user, name="quota-one")
            self.assertEqual(status, 201)
            status, second = self.create_sandbox(user, name="quota-two")
            self.assertEqual(status, 201)
            first_id, second_id = first["sandbox"]["id"], second["sandbox"]["id"]
            status, started = self.request("POST", f"/api/sandboxes/{first_id}/approve", token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(started["sandbox"]["status"], "running")
            status, waiting = self.request("POST", f"/api/sandboxes/{second_id}/approve", token=admin_token)
            self.assertEqual(status, 202)
            self.assertEqual(waiting["sandbox"]["queuePosition"], 1)

            status, third = self.create_sandbox(admin_token, name="quota-admin")
            self.assertEqual(status, 201)
            status, waiting = self.request("POST", f"/api/sandboxes/{third['sandbox']['id']}/approve", token=admin_token)
            self.assertEqual(status, 202)
            self.assertEqual(waiting["sandbox"]["queuePosition"], 2)

            status, _ = self.request("POST", f"/api/sandboxes/{first_id}/terminate", token=user)
            self.assertEqual(status, 200)
            _, running = self.request("GET", f"/api/sandboxes/{second_id}", token=user)
            self.assertEqual(running["sandbox"]["status"], "running")
        finally:
            self.request("POST", "/api/settings", saved, token=admin_token)


class TestE2E08CredentialBroker(E2EBase):
    """E2E-08: secrets stay on the host — masked lists, no plaintext anywhere downstream."""

    SECRET = "ghp_e2e_super_secret_token_987"

    def test_e2e_08(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, _ = self.request("POST", "/api/credentials", {"name": "github-e2e", "value": self.SECRET, "allowedHosts": []}, token=admin_token)
        self.assertEqual(status, 400, "没有目的地白名单必须 400")

        status, registered = self.request(
            "POST", "/api/credentials",
            {"name": "github-e2e", "value": self.SECRET, "allowedHosts": ["api.github.com"]},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        self.assertNotIn(self.SECRET, json.dumps(registered), "注册响应不得回显明文")

        status, listing = self.request("GET", "/api/credentials", token=admin_token)
        self.assertEqual(status, 200)
        entry = next(item for item in listing["credentials"] if item["name"] == "github-e2e")
        self.assertTrue(entry["masked"].startswith("ghp_"), "掩码应保留前缀")
        self.assertNotIn(self.SECRET, entry["masked"])
        self.assertEqual(entry["allowedHosts"], ["api.github.com"])

        # 普通用户拿不到凭据列表
        user = self.phone_login("13900000007")
        status, _ = self.request("GET", "/api/credentials", token=user)
        self.assertEqual(status, 403)
        status, _ = self.request("POST", "/api/credentials", {"name": "x", "value": "y", "allowedHosts": ["a.b"]}, token=user)
        self.assertEqual(status, 403)

        # 创建使用凭据的沙箱：响应与磁盘文件都不得出现明文
        status, created = self.create_sandbox(user, name="broker-e2e", credentials=["github-e2e"])
        self.assertEqual(status, 201)
        payload = json.dumps(created, ensure_ascii=False)
        self.assertNotIn(self.SECRET, payload, "沙箱创建响应不得包含明文凭据")
        self.assertIn("{{SD_CRED_", payload, "环境变量必须是占位符")

        sandbox_id = created["sandbox"]["id"]
        status, manifest = self.request("GET", f"/api/sandboxes/{sandbox_id}/manifest", token=user)
        self.assertNotIn(self.SECRET, json.dumps(manifest, ensure_ascii=False), "启动清单不得包含明文凭据")
        self.assertFalse(manifest["manifest"]["credentialBroker"]["exposedValues"])

        disk_body = (self.data_dir / "sandboxes.json").read_text(encoding="utf-8")
        self.assertNotIn(self.SECRET, disk_body, "数据文件不得落入明文凭据")


class TestE2E09EgressProxy(E2EBase):
    """E2E-09: egress proxy auth, SSRF guard, allowlist, pause freeze."""

    def test_e2e_09(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        _, cred = self.request(
            "POST", "/api/credentials",
            {"name": "github-proxy-e2e", "value": "ghp_proxy_secret", "allowedHosts": ["api.github.test"]},
            token=admin_token,
        )
        status, created = self.create_sandbox(
            admin_token, name="proxy-e2e", policyId="balanced", credentials=["github-proxy-e2e"],
        )
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)

        stored = next(s for s in self.sandboxes_on_disk() if s["id"] == sandbox_id)
        token = stored.get("egressToken")
        self.assertTrue(token, "审批后必须生成 egressToken")
        auth = base64.b64encode(f"{sandbox_id}:{token}".encode()).decode()

        try:
            # 无鉴权 / 错鉴权 -> 407
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/"), 407)
            wrong = base64.b64encode(f"{sandbox_id}:wrong".encode()).decode()
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/", auth=wrong), 407)

            # SSRF：回环/元数据端点硬拒绝
            self.assertEqual(self.proxy_request("CONNECT", "localhost:443", auth), 403)
            self.assertEqual(self.proxy_request("CONNECT", "127.0.0.1:443", auth), 403)
            self.assertEqual(self.proxy_request("GET", "http://169.254.169.254/latest", auth), 403)

            # 仅允许 443 隧道
            self.assertEqual(self.proxy_request("CONNECT", "example.com:80", auth), 403)

            # 白名单外的公网目标 -> 403
            code = self.proxy_request("GET", "http://untrusted.invalid/", auth)
            self.assertEqual(code, 403)

            # 白名单内目标：鉴权与策略全部通过，上游不可达 -> 502
            code = self.proxy_request("GET", "http://api.github.test/user", auth)
            self.assertEqual(code, 502, "白名单内目标应通过策略检查，失败应在上游连接阶段")

            # 暂停期间外联冻结
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause", token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 403)
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume", token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 502, "恢复后重新走到上游连接")

            # 代理健康检查可匿名
            conn = http.client.HTTPConnection("127.0.0.1", self.proxy_port, timeout=5)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            body = json.loads(resp.read())
            conn.close()
            self.assertEqual(resp.status, 200)
            self.assertTrue(body["ok"])
        finally:
            self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=admin_token)


class TestE2E10AuditHistory(E2EBase):
    """E2E-10: audit log persists to audit.jsonl and serves history queries to admins only."""

    def test_e2e_10(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        marker = "audit-marker-e2e-10"
        status, created = self.create_sandbox(admin_token, name=marker)
        self.assertEqual(status, 201)
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=admin_token)
        self.assertEqual(status, 200)

        # 文件落盘可检索
        audit_file = self.data_dir / "audit.jsonl"
        self.assertTrue(audit_file.exists())
        lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(any(marker in str(line.get("detail", "")) for line in lines), "audit.jsonl 必须记录本次操作")
        self.assertTrue(all("at" in line and "action" in line for line in lines))

        # history 查询：分页 + 关键字过滤 + 最新在前
        status, history = self.request("GET", "/api/events?history=1&limit=50", token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreater(history["size"], 0)
        ats = [e["at"] for e in history["events"]]
        self.assertEqual(ats, sorted(ats, reverse=True), "历史事件必须最新在前")
        self.assertTrue(any(marker in str(e.get("detail", "")) for e in history["events"]))

        status, filtered = self.request("GET", f"/api/events?history=1&q={marker}", token=admin_token)
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(filtered["events"]), 2, "创建 + 终止两条事件")
        self.assertTrue(all(marker in e["detail"] for e in filtered["events"]))

        status, paged = self.request("GET", f"/api/events?history=1&q={marker}&limit=1&offset=1", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(len(paged["events"]), 1, "分页参数必须生效")

        # 非管理员无权查看任何事件
        user = self.phone_login("13900000008")
        status, _ = self.request("GET", "/api/events", token=user)
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/events?history=1", token=user)
        self.assertEqual(status, 403)


class TestE2E11TaskTemplates(E2EBase):
    """E2E-11: sandbox creation from task templates yields the right policy manifest."""

    def test_e2e_11(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        status, body = self.request("GET", "/api/templates", token=admin_token)
        self.assertEqual(status, 200)
        templates = {t["id"]: t for t in body["templates"]}
        self.assertGreaterEqual(len(templates), 3)

        status, catalog = self.request("GET", "/api/catalog", token=admin_token)
        self.assertEqual(status, 200)
        self.assertIn("github-read", catalog["capabilities"]["credentials"])

        expectations = {
            "tpl-review": ("ro", "disabled", "低风险", "codex"),
            "tpl-dev": ("rw", "brokered", "中风险", "claude-code"),
            "tpl-build": ("ephemeral", "allowlist", "高风险", "dsh"),
        }
        for tpl_id, (fs_mode, network, risk, agent) in expectations.items():
            tpl = templates[tpl_id]
            status, created = self.create_sandbox(
                admin_token,
                name=f"from-{tpl_id}",
                agent=tpl["agent"],
                policyId=tpl["policyId"],
                workspace=tpl["workspace"],
                credentials=tpl["credentials"],
                mcpServers=tpl["mcpServers"],
                purpose=tpl["purpose"],
            )
            self.assertEqual(status, 201, tpl_id)
            sandbox = created["sandbox"]
            manifest = created["manifest"]
            self.assertEqual(sandbox["agent"], agent, tpl_id)
            self.assertEqual(sandbox["risk"], risk, tpl_id)
            self.assertEqual(manifest["filesystem"]["mode"], fs_mode, tpl_id)
            self.assertEqual(manifest["runtime"]["network"], network, tpl_id)
            self.assertEqual(manifest["filesystem"]["workspace"], tpl["workspace"], tpl_id)
            self.assertEqual(manifest["credentialBroker"]["profiles"], tpl["credentials"], tpl_id)
            self.assertFalse(manifest["credentialBroker"]["exposedValues"], tpl_id)


class TestE2E12SearchAndFilters(E2EBase):
    """E2E-12: combined q/status/agent/policyId filters hit and miss as expected."""

    def test_e2e_12(self):
        _, admin = self.admin_login()
        token = admin["token"]

        _, one = self.create_sandbox(token, name="alpha-pay", purpose="支付网关改造", agent="codex", policyId="balanced")
        alpha = one["sandbox"]["id"]
        _, two = self.create_sandbox(token, name="beta-search", purpose="检索服务", agent="claude-code", policyId="build")
        beta = two["sandbox"]["id"]
        self.create_sandbox(token, name="gamma-note", purpose="无关沙箱", agent="dsh", policyId="review")

        def ids(query: str) -> set[str]:
            status, body = self.request("GET", f"/api/sandboxes{query}", token=token)
            assert status == 200
            return {item["id"] for item in body["sandboxes"]}

        # 关键字：命中 name / purpose，大小写与中文均可
        self.assertIn(alpha, ids("?q=alpha"))
        self.assertIn(alpha, ids("?q=%E6%94%AF%E4%BB%98"))  # 支付
        self.assertNotIn(beta, ids("?q=%E6%94%AF%E4%BB%98"))

        # 状态 / 代理 / 策略 单维过滤
        self.assertEqual({alpha, beta} | ids("?status=pending_approval"), ids("?status=pending_approval"))
        self.assertIn(beta, ids("?agent=claude-code"))
        self.assertNotIn(alpha, ids("?agent=claude-code"))
        self.assertIn(beta, ids("?policyId=build"))
        self.assertNotIn(alpha, ids("?policyId=build"))

        # 组合过滤：只保留同时满足的
        self.assertIn(alpha, ids("?status=pending_approval&agent=codex&policyId=balanced&q=alpha"))
        self.assertNotIn(beta, ids("?status=pending_approval&agent=codex&q=beta"))

        # 变更状态后筛选跟随变化
        self.request("POST", f"/api/sandboxes/{alpha}/approve", token=token)
        self.assertNotIn(alpha, ids("?status=pending_approval"))
        self.assertIn(alpha, ids("?status=running"))


class TestE2E13OverviewMetrics(E2EBase):
    """E2E-13: overview counters match real sandbox states, riskMix ignores terminated."""

    def test_e2e_13(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]
        user = self.phone_login("13900000010")

        _, a = self.create_sandbox(user, name="ov-pending")                                # pending
        _, b = self.create_sandbox(user, name="ov-running")                                # running
        _, c = self.create_sandbox(user, name="ov-paused")                                 # paused
        _, d = self.create_sandbox(user, name="ov-rejected")                               # rejected
        _, e = self.create_sandbox(user, name="ov-terminated")                             # terminated
        self.request("POST", f"/api/sandboxes/{b['sandbox']['id']}/approve", token=admin_token)
        self.request("POST", f"/api/sandboxes/{c['sandbox']['id']}/approve", token=admin_token)
        self.request("POST", f"/api/sandboxes/{c['sandbox']['id']}/pause", token=user)
        self.request("POST", f"/api/sandboxes/{d['sandbox']['id']}/reject", {"reason": "指标测试"}, token=admin_token)
        self.request("POST", f"/api/sandboxes/{e['sandbox']['id']}/terminate", token=user)

        status, body = self.request("GET", "/api/overview", token=admin_token)
        self.assertEqual(status, 200)
        ov = body["overview"]
        self.assertEqual(ov["total"], 5)
        self.assertEqual(ov["pendingApproval"], 1)
        self.assertEqual(ov["running"], 1)
        self.assertEqual(ov["paused"], 1)
        self.assertEqual(ov["rejected"], 1)
        self.assertEqual(ov["terminated"], 1)
        self.assertEqual(ov["health"], "attention", "有待审批沙箱时必须 attention")
        self.assertEqual(sum(ov["riskMix"].values()), 4, "riskMix 不计已终止")
        self.assertEqual(ov["riskMix"]["低风险"], 4, "默认 review 策略全部是低风险")
        self.assertEqual(ov["activeUsers"], 1)
        self.assertEqual(ov["role"], "admin")

        # 全清后 health 回到 healthy
        for sid in (a["sandbox"]["id"], b["sandbox"]["id"], c["sandbox"]["id"]):
            self.request("POST", f"/api/sandboxes/{sid}/terminate", token=admin_token)
        _, body = self.request("GET", "/api/overview", token=admin_token)
        self.assertEqual(body["overview"]["health"], "healthy")
        self.assertEqual(body["overview"]["pendingApproval"], 0)


class TestE2E14BootstrapRoleView(E2EBase):
    """E2E-14: /api/bootstrap shape is complete; non-admin sees no security events."""

    def test_e2e_14(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]
        user = self.phone_login("13900000011")
        self.create_sandbox(user, name="bootstrap-box")

        for expected_key in ("user", "overview", "catalog", "templates", "settings", "policies", "agents", "sandboxes", "securityEvents"):
            _, boot = self.request("GET", "/api/bootstrap", token=user)
            self.assertIn(expected_key, boot, f"普通用户 bootstrap 缺 {expected_key}")

        _, boot_user = self.request("GET", "/api/bootstrap", token=user)
        self.assertEqual(boot_user["securityEvents"], [], "普通用户不得看到安全事件流")
        self.assertEqual(boot_user["overview"]["total"], 1, "普通用户只看到自有沙箱指标")
        self.assertEqual([p["id"] for p in sorted(boot_user["policies"], key=lambda p: p["id"])], ["balanced", "build", "review"])
        self.assertEqual(len(boot_user["templates"]), 5)
        self.assertIn("workspaceRoots", boot_user["settings"])

        _, boot_admin = self.request("GET", "/api/bootstrap", token=admin_token)
        self.assertGreaterEqual(len(boot_admin["securityEvents"]), 1, "管理员必须看到安全事件")
        self.assertTrue(all("at" in e and "action" in e for e in boot_admin["securityEvents"]))
        self.assertEqual(boot_admin["overview"]["role"], "admin")


class TestE2E15WorkspaceRoots(E2EBase):
    """E2E-15: workspaceRoots confines workspaces; root escape via ../ is blocked."""

    def test_e2e_15(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]
        user = self.phone_login("13900000012")

        # 非管理员不能改组织设置
        status, _ = self.request("POST", "/api/settings", {"workspaceRoots": ["/srv/allowed"]}, token=user)
        self.assertEqual(status, 403)

        _, original = self.request("GET", "/api/settings", token=admin_token)
        saved = dict(original["settings"])
        try:
            status, updated = self.request("POST", "/api/settings", {**saved, "workspaceRoots": ["/srv/allowed"]}, token=admin_token)
            self.assertEqual(status, 200)
            self.assertEqual(updated["settings"]["workspaceRoots"], ["/srv/allowed"])

            # 落盘持久化
            settings_file = json.loads((self.data_dir / "settings.json").read_text(encoding="utf-8"))
            self.assertEqual(settings_file["workspaceRoots"], ["/srv/allowed"])

            # 根目录之外一律 400（含根兄弟目录与 ../ 逃逸）
            status, _ = self.create_sandbox(user, name="ws-out", workspace="/tmp/project")
            self.assertEqual(status, 400)
            status, _ = self.create_sandbox(user, name="ws-sibling", workspace="/srv/allowed-evil")
            self.assertEqual(status, 400, "兄弟目录前缀不得被误认为根内")
            status, _ = self.create_sandbox(user, name="ws-escape", workspace="/srv/allowed/../evil")
            self.assertEqual(status, 400, "../ 逃逸必须被 realpath 拦截")

            # 根本身与根内子目录放行
            status, _ = self.create_sandbox(user, name="ws-root", workspace="/srv/allowed")
            self.assertEqual(status, 201)
            status, created = self.create_sandbox(user, name="ws-inner", workspace="/srv/allowed/team/proj")
            self.assertEqual(status, 201)
            self.assertEqual(created["sandbox"]["workspace"], "/srv/allowed/team/proj")
        finally:
            self.request("POST", "/api/settings", saved, token=admin_token)


class TestE2E16RejectionFlow(E2EBase):
    """E2E-16: rejection records reason/actor, emits a block event, and is terminal."""

    def test_e2e_16(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]
        user = self.phone_login("13900000013")

        _, created = self.create_sandbox(user, name="reject-target", purpose="越权数据抓取")
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/reject", token=user)
        self.assertEqual(status, 403, "拒绝也是管理员专属动作")

        status, rejected = self.request("POST", f"/api/sandboxes/{sandbox_id}/reject", {"reason": "用途超出批准范围"}, token=admin_token)
        self.assertEqual(status, 200)
        box = rejected["sandbox"]
        self.assertEqual(box["status"], "rejected")
        self.assertEqual(box["rejectReason"], "用途超出批准范围")
        self.assertEqual(box["rejectedBy"], "admin")
        self.assertIn("rejectedAt", box)
        self.assertEqual(box["statusLabel"], "已拒绝")

        # 终态：不可再次审批/拒绝/暂停/恢复
        for action in ("approve", "reject", "pause", "resume"):
            status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/{action}", token=admin_token)
            self.assertEqual(status, 409, f"rejected 后 {action} 必须 409")

        # 拒绝产生 block 级安全事件
        _, events = self.request("GET", "/api/events?level=block", token=admin_token)
        self.assertTrue(any(e["action"] == "拒绝启动" and "用途超出批准范围" in e["detail"] for e in events["events"]))

        # 不带 reason 走默认文案
        _, second = self.create_sandbox(user, name="reject-default-2")
        _, body = self.request("POST", f"/api/sandboxes/{second['sandbox']['id']}/reject", {}, token=admin_token)
        self.assertEqual(body["sandbox"]["rejectReason"], "不符合安全策略")


class TestE2E17EgressCredentialLifecycle(E2EBase):
    """E2E-17: wildcard allowlist hosts pass policy; terminate invalidates the egress token."""

    def test_e2e_17(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        self.request(
            "POST", "/api/credentials",
            {"name": "multi-host-e2e", "value": "mhe_secret", "allowedHosts": ["*.github.test", "api.corp.test"]},
            token=admin_token,
        )
        _, created = self.create_sandbox(admin_token, name="egress-lifecycle", policyId="balanced", credentials=["multi-host-e2e"])
        sandbox_id = created["sandbox"]["id"]
        status, approved = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)

        stored = next(s for s in self.sandboxes_on_disk() if s["id"] == sandbox_id)
        auth = base64.b64encode(f"{sandbox_id}:{stored['egressToken']}".encode()).decode()

        # 通配符白名单：子域与域根都放行（走到上游 502），白名单外 403
        self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 502)
        self.assertEqual(self.proxy_request("GET", "http://deep.api.github.test/x", auth), 502)
        self.assertEqual(self.proxy_request("GET", "http://github.test/x", auth), 502)
        self.assertEqual(self.proxy_request("GET", "http://api.corp.test/x", auth), 502)
        self.assertEqual(self.proxy_request("GET", "http://notgithub.test/x", auth), 403)
        self.assertEqual(self.proxy_request("GET", "http://github.test.evil.test/x", auth), 403)

        # 终止 → 凭据与代理注册即刻失效
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=admin_token)
        self.assertEqual(status, 200)
        self.assertEqual(self.proxy_request("GET", "http://api.github.test/user", auth), 407,
                         "终止后旧 egressToken 必须失效")

        # 事件流中出现 allow 决策（白名单内转发时记录）
        _, events = self.request("GET", "/api/events?q=github.test", token=admin_token)
        self.assertGreaterEqual(len(events["events"]), 1)


class TestE2E18AuditRetentionPrune(E2EBase):
    """E2E-18: startup prunes audit entries older than retainAuditDays and drops bad lines."""

    OLD_MARK = "prune-old-marker-e2e18"
    FRESH_MARK = "prune-fresh-marker-e2e18"

    @classmethod
    def prepare_data_dir(cls, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        old_at = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat().replace("+00:00", "Z")
        fresh_at = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat().replace("+00:00", "Z")
        lines = [
            json.dumps({"id": "a", "level": "info", "action": "旧事件", "detail": cls.OLD_MARK, "at": old_at}, ensure_ascii=False),
            json.dumps({"id": "b", "level": "info", "action": "新事件", "detail": cls.FRESH_MARK, "at": fresh_at}, ensure_ascii=False),
            "{corrupted-line",
        ]
        (data_dir / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_e2e_18(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]

        # 40 天前的旧事件在启动时被 prune；2 天前的保留
        status, history = self.request("GET", "/api/events?history=1&limit=200", token=admin_token)
        self.assertEqual(status, 200)
        details = json.dumps(history["events"], ensure_ascii=False)
        self.assertNotIn(self.OLD_MARK, details, "超出保留期的事件必须被清理")
        self.assertIn(self.FRESH_MARK, details, "保留期内的事件必须可查")

        # 文件已被重写：无损坏行、无旧行，剩余行全部可解析
        body = (self.data_dir / "audit.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("{corrupted-line", body)
        self.assertNotIn(self.OLD_MARK, body)
        for line in body.splitlines():
            json.loads(line)


class TestE2E19PhoneAdmin(E2EBase):
    """E2E-19: SAFEDESK_ADMIN_PHONES upgrades the phone login to admin, without password."""

    @classmethod
    def extra_env(cls) -> dict:
        return {"SAFEDESK_ADMIN_PHONES": "13900000099"}

    def test_e2e_19(self):
        admin_phone_token = self.phone_login("13900000099")
        status, me = self.request("GET", "/api/auth/me", token=admin_phone_token)
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["role"], "admin", "白名单手机号必须获得管理员角色")
        self.assertFalse(me["user"]["mustChangePassword"])
        self.assertFalse(me["user"]["canChangePassword"], "手机号管理员无密码可改")

        # 手机号管理员确实拥有管理权限
        status, _ = self.request("GET", "/api/events", token=admin_phone_token)
        self.assertEqual(status, 200)
        status, _ = self.request("GET", "/api/credentials", token=admin_phone_token)
        self.assertEqual(status, 200)

        # 但没有密码散列，不允许走密码修改通道
        status, body = self.request(
            "POST", "/api/auth/password",
            {"currentPassword": "x", "newPassword": "Whatever123"},
            token=admin_phone_token,
        )
        self.assertEqual(status, 403)
        self.assertIn("仅管理员账户", body["error"])

        # 非白名单手机号依旧是普通用户
        user = self.phone_login("13900000098")
        status, me = self.request("GET", "/api/auth/me", token=user)
        self.assertEqual(me["user"]["role"], "user")
        status, _ = self.request("GET", "/api/events", token=user)
        self.assertEqual(status, 403)


class TestE2E20RestartContinuity(E2EBase):
    """E2E-20: after a restart, sandboxes/settings/password change/sessions all survive."""

    def test_e2e_20(self):
        _, admin = self.admin_login()
        admin_token = admin["token"]
        user_token = self.phone_login("13900000020")

        _, created = self.create_sandbox(user_token, name="restart-box")
        sandbox_id = created["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve", token=admin_token)
        self.assertEqual(status, 200)

        status, changed = self.request(
            "POST", "/api/auth/password",
            {"currentPassword": "SafeDesk@Admin", "newPassword": "Restart-Keep-9pass"},
            token=admin_token,
        )
        self.assertEqual(status, 200)
        _, settings = self.request("GET", "/api/settings", token=admin_token)
        self.request("POST", "/api/settings", {**settings["settings"], "orgName": "重启验证组织"}, token=admin_token)

        # 管理员改密会吊销其他全部会话（含用户态），用户需重新登录
        status, _ = self.request("GET", "/api/sandboxes", token=user_token)
        self.assertEqual(status, 401, "改密应吊销用户态会话")
        user_token = self.phone_login("13900000020")

        self.respawn()

        # 改后的管理员密码生效，默认密码不再有效
        status, _ = self.admin_login()
        self.assertEqual(status, 400, "重启后默认密码不得复活")
        status, relogin = self.admin_login(password="Restart-Keep-9pass")
        self.assertEqual(status, 200)
        self.assertFalse(relogin["user"]["mustChangePassword"])

        # 重启前签发的用户会话仍有效，沙箱数据完整可见
        status, listing = self.request("GET", "/api/sandboxes", token=user_token)
        self.assertEqual(status, 200, "重启不得踢掉未过期会话")
        stored = next(item for item in listing["sandboxes"] if item["id"] == sandbox_id)
        self.assertEqual(stored["status"], "running")
        self.assertEqual(stored["name"], "restart-box")

        # 组织设置持久化
        _, settings = self.request("GET", "/api/settings", token=relogin["token"])
        self.assertEqual(settings["settings"]["orgName"], "重启验证组织")

        # 新 Launcher 无法确认旧进程归属，不能释放配额或盲目信任磁盘 PID。
        status, result = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate", token=user_token)
        self.assertEqual(status, 409)
        self.assertIn("进程状态待确认", result["error"])


if __name__ == "__main__":
    unittest.main()
