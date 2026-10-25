"""Auth and tenant isolation tests for the Python control plane."""
from __future__ import annotations

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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class AuthApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-auth-"))
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {
            **os.environ,
            "PORT": str(cls.port),
            "SAFEDESK_DATA_DIR": str(cls.data_dir),
            "SAFEDESK_DATA_FILE": str(cls.data_dir / "sandboxes.json"),
            "SAFEDESK_AUTH": "1",
            "SAFEDESK_DEMO": "1",
            "SAFEDESK_ADMIN_USERNAME": "admin",
            "SAFEDESK_ADMIN_PASSWORD": "SafeDesk@Admin",
        }
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                cls.request("GET", "/api/auth/config")
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError("auth server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    @classmethod
    def request(cls, method: str, path: str, body=None, token: str | None = None):
        payload = None
        headers = {}
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(cls.base + path, data=payload, headers=headers, method=method)
        try:
            with OPENER.open(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    def test_bootstrap_requires_login(self):
        status, data = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 401)
        self.assertIn("登录", data["error"])

    def test_admin_login_and_approval(self):
        status, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        self.assertEqual(status, 200)
        self.assertEqual(login["user"]["role"], "admin")
        token = login["token"]
        status, created = self.request("POST", "/api/sandboxes", {
            "name": "admin-box",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/admin",
        }, token)
        self.assertEqual(status, 201)
        status, approved = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/approve", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(approved["sandbox"]["status"], "running")

    def test_phone_user_cannot_approve_or_see_others(self):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13800138000"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13800138000", "token": sent["demoCode"]})
        user_token = verify["token"]
        _, created = self.request("POST", "/api/sandboxes", {
            "name": "user-box",
            "agent": "dsh",
            "policyId": "balanced",
            "workspace": "/tmp/user",
        }, user_token)
        status, _ = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/approve", token=user_token)
        self.assertEqual(status, 403)
        status, _ = self.request("GET", "/api/events", token=user_token)
        self.assertEqual(status, 403)
        _, other_sent = self.request("POST", "/api/auth/phone/send", {"phone": "13900139000"})
        _, other = self.request("POST", "/api/auth/phone/verify", {"phone": "13900139000", "token": other_sent["demoCode"]})
        _, visible = self.request("GET", "/api/sandboxes", token=other["token"])
        self.assertFalse(any(item["id"] == created["sandbox"]["id"] for item in visible["sandboxes"]))

    def test_invalid_phone_is_rejected_locally(self):
        status, data = self.request("POST", "/api/auth/phone/send", {"phone": "1380013800"})
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "请输入正确的 11 位手机号")

    def test_admin_can_reject_pause_resume_and_filter(self):
        _, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        token = login["token"]
        _, created = self.request("POST", "/api/sandboxes", {
            "name": "pause-me",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/pause",
            "purpose": "审阅依赖",
        }, token)
        self.assertEqual(created["sandbox"]["risk"], "低风险")
        _, approved = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/approve", token=token)
        self.assertEqual(approved["sandbox"]["status"], "running")
        _, paused = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/pause", token=token)
        self.assertEqual(paused["sandbox"]["status"], "paused")
        _, resumed = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/resume", token=token)
        self.assertEqual(resumed["sandbox"]["status"], "running")
        _, pending = self.request("POST", "/api/sandboxes", {
            "name": "reject-me",
            "agent": "dsh",
            "policyId": "build",
            "workspace": "/tmp/reject",
        }, token)
        _, rejected = self.request("POST", f"/api/sandboxes/{pending['sandbox']['id']}/reject", {"reason": "超出构建范围"}, token)
        self.assertEqual(rejected["sandbox"]["status"], "rejected")
        _, filtered = self.request("GET", "/api/sandboxes?status=rejected&q=reject", token=token)
        self.assertTrue(any(item["id"] == pending["sandbox"]["id"] for item in filtered["sandboxes"]))
        _, overview = self.request("GET", "/api/overview", token=token)
        self.assertGreaterEqual(overview["overview"]["total"], 2)
        _, settings = self.request("POST", "/api/settings", {"orgName": "SafeDesk 演示中心", "maxConcurrent": 12}, token)
        self.assertEqual(settings["settings"]["orgName"], "SafeDesk 演示中心")
        self.assertEqual(settings["settings"]["maxConcurrent"], 12)

    def test_admin_can_change_default_password(self):
        isolated_dir = Path(tempfile.mkdtemp(prefix="safedesk-auth-change-"))
        port = free_port()
        env = {
            **os.environ,
            "PORT": str(port),
            "SAFEDESK_DATA_DIR": str(isolated_dir),
            "SAFEDESK_DATA_FILE": str(isolated_dir / "sandboxes.json"),
            "SAFEDESK_AUTH": "1",
            "SAFEDESK_DEMO": "1",
            "SAFEDESK_ADMIN_USERNAME": "admin",
            "SAFEDESK_ADMIN_PASSWORD": "SafeDesk@Admin",
        }
        server = subprocess.Popen([sys.executable, "server.py"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        base = f"http://127.0.0.1:{port}"
        def call(method, path, body=None, token=None):
            payload = None
            headers = {}
            if body is not None:
                payload = json.dumps(body).encode("utf-8")
                headers["Content-Type"] = "application/json"
            if token:
                headers["Authorization"] = f"Bearer {token}"
            request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
            for _ in range(50):
                try:
                    with OPENER.open(request, timeout=5) as response:
                        return response.status, json.loads(response.read() or b"{}")
                except urllib.error.HTTPError as error:
                    return error.code, json.loads(error.read() or b"{}")
                except OSError:
                    time.sleep(0.1)
            raise RuntimeError("isolated auth server did not start")
        try:
            status, login = call("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
            self.assertEqual(status, 200)
            self.assertTrue(login["user"]["mustChangePassword"])
            status, _ = call("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "NewDesk@Pass1"})
            self.assertEqual(status, 401)
            status, too_short = call("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "short"}, login["token"])
            self.assertEqual(status, 400)
            self.assertIn("至少 8 位", too_short["error"])
            status, changed = call("POST", "/api/auth/password", {"currentPassword": "SafeDesk@Admin", "newPassword": "NewDesk@Pass1"}, login["token"])
            self.assertEqual(status, 200)
            self.assertFalse(changed["user"]["mustChangePassword"])
            status, old_login = call("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
            self.assertEqual(status, 400)
            status, next_login = call("POST", "/api/auth/admin/login", {"username": "admin", "password": "NewDesk@Pass1"})
            self.assertEqual(status, 200)
            self.assertFalse(next_login["user"]["mustChangePassword"])
        finally:
            server.terminate()
            server.wait(timeout=5)
            shutil.rmtree(isolated_dir, ignore_errors=True)

    def test_auth_config_methods(self):
        status, data = self.request("GET", "/api/auth/config")
        self.assertEqual(status, 200)
        self.assertEqual(data["methods"], ["phone", "wechat", "wecom", "admin"])
        self.assertEqual(data["wechatMode"], "local-qr")
        self.assertEqual(data["wecomMode"], "local-qr")

    def test_admin_me_endpoint(self):
        _, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        status, me = self.request("GET", "/api/auth/me", token=login["token"])
        self.assertEqual(status, 200)
        self.assertEqual(me["user"]["role"], "admin")
        self.assertTrue(me["authEnabled"])

    def test_logout_invalidates_token(self):
        _, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        status, _ = self.request("POST", "/api/auth/logout", token=login["token"])
        self.assertEqual(status, 200)
        status, _ = self.request("GET", "/api/auth/me", token=login["token"])
        self.assertEqual(status, 401)

    def test_user_cannot_update_settings(self):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13700000001"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13700000001", "token": sent["demoCode"]})
        status, _ = self.request("POST", "/api/settings", {"orgName": "hijack"}, verify["token"])
        self.assertEqual(status, 403)

    def test_user_cannot_reject(self):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13700000002"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13700000002", "token": sent["demoCode"]})
        _, created = self.request("POST", "/api/sandboxes", {
            "name": "no-reject",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/no-reject",
        }, verify["token"])
        status, _ = self.request("POST", f"/api/sandboxes/{created['sandbox']['id']}/reject", {"reason": "x"}, verify["token"])
        self.assertEqual(status, 403)

    def test_pending_tasks_do_not_consume_concurrency(self):
        _, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        self.request("POST", "/api/settings", {"maxConcurrent": 1}, login["token"])
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13700000003"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13700000003", "token": sent["demoCode"]})
        status, _ = self.request("POST", "/api/sandboxes", {
            "name": "cap-one",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/cap-one",
        }, verify["token"])
        self.assertEqual(status, 201)
        status, _ = self.request("POST", "/api/sandboxes", {
            "name": "cap-two",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/cap-two",
        }, verify["token"])
        self.assertEqual(status, 201)

    def test_admin_can_see_other_users_sandbox(self):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": "13700000004"})
        _, verify = self.request("POST", "/api/auth/phone/verify", {"phone": "13700000004", "token": sent["demoCode"]})
        _, created = self.request("POST", "/api/sandboxes", {
            "name": "visible-to-admin",
            "agent": "dsh",
            "policyId": "balanced",
            "workspace": "/tmp/visible",
        }, verify["token"])
        _, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "SafeDesk@Admin"})
        _, listed = self.request("GET", "/api/sandboxes", token=login["token"])
        self.assertTrue(any(item["id"] == created["sandbox"]["id"] for item in listed["sandboxes"]))

    def test_wrong_admin_password(self):
        status, _ = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "nope"})
        self.assertEqual(status, 400)

    def test_wecom_qr_becomes_user_session(self):
        _, started = self.request("POST", "/api/auth/wecom/start")
        status, _ = self.request("POST", "/api/auth/wecom/confirm", {"ticket": started["ticket"]})
        self.assertEqual(status, 200)
        _, polled = self.request("GET", f"/api/auth/wecom/poll?ticket={started['ticket']}")
        self.assertEqual(polled["status"], "confirmed")
        self.assertEqual(polled["user"]["provider"], "wecom")
        self.assertEqual(polled["user"]["role"], "user")

    def test_wechat_qr_becomes_user_session(self):
        _, started = self.request("POST", "/api/auth/wechat/start")
        status, _ = self.request("POST", "/api/auth/wechat/confirm", {"ticket": started["ticket"]})
        self.assertEqual(status, 200)
        _, polled = self.request("GET", f"/api/auth/wechat/poll?ticket={started['ticket']}")
        self.assertEqual(polled["status"], "confirmed")
        self.assertEqual(polled["user"]["provider"], "wechat")
        self.assertEqual(polled["user"]["role"], "user")


if __name__ == "__main__":
    unittest.main()
