"""Shared HTTP contract for both servers, with real, disposable helper processes.

Set SAFEDESK_TEST_NODE to a Node 20+ executable to include the Node backend.
The helper named wasmer is a test double, not a Wasm isolation/security test.
"""
import concurrent.futures
import json
import os
import shutil
import signal
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
NODE = os.getenv("SAFEDESK_TEST_NODE") or shutil.which("node")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class QueueContract:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="safedesk-queue-")
        self.directory_path = Path(self.directory.name)
        self.data_dir = self.directory_path / "store"
        self.bin_dir = self.directory_path / "bin"
        self.bin_dir.mkdir()
        helper = self.bin_dir / "wasmer"
        helper.write_text(
            f"#!{sys.executable}\nimport sys,time\n"
            "if 'exit0' in sys.argv or 'exit7' in sys.argv:\n"
            "    time.sleep(0.5)\n    sys.exit(7 if 'exit7' in sys.argv else 0)\n"
            "time.sleep(60)\n", encoding="utf-8")
        helper.chmod(0o755)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        self.base = f"http://127.0.0.1:{port}"
        self.environment = {
            **os.environ, "PATH": str(self.bin_dir) + os.pathsep + os.environ.get("PATH", ""),
            "PORT": str(port), "HOST": "127.0.0.1", "SAFEDESK_DATA_DIR": str(self.data_dir),
            "SAFEDESK_DATA_FILE": str(self.data_dir / "sandboxes.json"),
            "SAFEDESK_AUTH": "1", "SAFEDESK_DEMO": "1", "SAFEDESK_OTP_ECHO": "1",
            "SAFEDESK_ADMIN_USERNAME": "admin", "SAFEDESK_ADMIN_PASSWORD": "QueueTest@2026",
        }
        self.pids = set()
        self.log = (self.directory_path / "server.log").open("ab")
        self.admin = None
        self.spawn_server()
        status, login = self.request("POST", "/api/auth/admin/login", {"username": "admin", "password": "QueueTest@2026"})
        self.assertEqual(status, 200)
        self.admin = login["token"]
        self.assertEqual(self.request("POST", "/api/settings", {"maxConcurrent": 1})[0], 200)

    def spawn_server(self):
        self.server = subprocess.Popen(self.command, cwd=ROOT, env=self.environment, stdout=self.log, stderr=self.log)
        for _ in range(100):
            try:
                if self.request("GET", "/api/auth/config")[0] == 200:
                    return
            except OSError:
                pass
            if self.server.poll() is not None:
                break
            time.sleep(0.05)
        raise RuntimeError((self.directory_path / "server.log").read_text())

    def stop_server(self):
        self.server.terminate()
        self.server.wait(timeout=10)

    def tearDown(self):
        try:
            if self.server.poll() is None:
                self.rows()
                self.stop_server()
        finally:
            for pid in self.pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            self.log.close()
            self.directory.cleanup()

    def request(self, method, path, body=None, token=None):
        headers = {"Content-Type": "application/json"}
        token = token or self.admin
        if token:
            headers["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, method=method, headers=headers,
                                     data=None if body is None else json.dumps(body).encode())
        try:
            with OPENER.open(req, timeout=15) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.load(error)

    def create(self, token=None, **overrides):
        status, body = self.request("POST", "/api/sandboxes", {
            "name": "queue-case", "agent": "codex", "policyId": "review",
            "workspace": "/queue/work", "packages": ["hold"], **overrides,
        }, token)
        self.assertEqual(status, 201, body)
        return body["sandbox"]["id"]

    def action(self, sid, action, token=None):
        result = self.request("POST", f"/api/sandboxes/{sid}/{action}", token=token)
        pid = result[1].get("sandbox", {}).get("runtime", {}).get("pid")
        if pid:
            self.pids.add(pid)
        return result

    def rows(self, token=None):
        status, body = self.request("GET", "/api/sandboxes", token=token)
        self.assertEqual(status, 200, body)
        for row in body["sandboxes"]:
            if row.get("runtime", {}).get("pid"):
                self.pids.add(row["runtime"]["pid"])
        return {row["id"]: row for row in body["sandboxes"]}

    def wait_status(self, sid, expected):
        for _ in range(100):
            rows = self.rows()
            if rows[sid]["status"] == expected:
                return rows[sid]
            time.sleep(0.05)
        self.fail(f"{sid}: expected {expected}, got {rows[sid]}")

    def phone(self, phone):
        _, sent = self.request("POST", "/api/auth/phone/send", {"phone": phone})
        _, result = self.request("POST", "/api/auth/phone/verify", {"phone": phone, "token": sent["demoCode"]})
        return result["token"]

    def test_pending_does_not_consume_global_admin_cap(self):
        user = self.phone("13900000001")
        first, second = self.create(token=user), self.create()
        self.assertEqual(self.action(first, "approve")[0], 200)
        code, waiting = self.action(second, "approve")
        self.assertEqual(code, 202)
        self.assertEqual(waiting["sandbox"]["queuePosition"], 1)
        self.assertNotIn("runtime", waiting["sandbox"])
        self.assertNotIn("egressToken", waiting["sandbox"])
        self.assertEqual(self.action(second, "approve")[0], 409)

    def test_parallel_creates_and_approvals_never_overbook(self):
        self.request("POST", "/api/settings", {"maxConcurrent": 2})
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            ids = list(pool.map(lambda _: self.create(), range(10)))
            codes = list(pool.map(lambda sid: self.action(sid, "approve")[0], ids))
        self.assertEqual(codes.count(200), 2)
        self.assertEqual(codes.count(202), 8)
        rows = self.rows()
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(s["status"] == "running" for s in rows.values()), 2)
        self.assertEqual(sorted(s["queuePosition"] for s in rows.values() if s["status"] == "queued"), list(range(1, 9)))

    def test_fifo_and_cancel_queued_then_release(self):
        ids = [self.create() for _ in range(4)]
        for sid in ids:
            self.action(sid, "approve")
        self.assertEqual(self.action(ids[2], "terminate")[0], 200)
        self.assertEqual(self.action(ids[0], "terminate")[0], 200)
        rows = self.rows()
        self.assertEqual(rows[ids[1]]["status"], "running")
        self.assertEqual(rows[ids[3]]["queuePosition"], 1)
        self.assertNotIn("runtime", rows[ids[2]])

    def test_pause_reserves_capacity_and_resume_does_not_bypass(self):
        first, second = self.create(), self.create()
        self.action(first, "approve")
        self.assertEqual(self.action(first, "pause")[0], 200)
        self.assertEqual(self.action(second, "approve")[0], 202)
        self.assertEqual(self.action(first, "resume")[0], 200)
        self.assertEqual(self.rows()[second]["status"], "queued")
        self.action(first, "pause")
        self.assertEqual(self.action(first, "terminate")[0], 200)
        self.assertEqual(self.rows()[second]["status"], "running")

    def test_background_reaps_success_and_error_without_lifecycle_request(self):
        for exit_code in (0, 7):
            first = self.create(packages=[f"exit{exit_code}"])
            second = self.create()
            self.action(first, "approve")
            self.action(second, "approve")
            row = self.wait_status(first, "completed" if exit_code == 0 else "failed")
            self.assertEqual(row["exitCode"], exit_code)
            self.assertIn("finishedAt", row)
            self.wait_status(second, "running")
            self.action(second, "terminate")

    def test_queue_bound_invalid_settings_and_partial_update(self):
        self.request("POST", "/api/settings", {"maxQueued": 1})
        ids = [self.create() for _ in range(3)]
        self.action(ids[0], "approve")
        self.action(ids[1], "approve")
        self.assertEqual(self.action(ids[2], "approve")[0], 409)
        self.assertEqual(self.rows()[ids[2]]["status"], "pending_approval")
        for key, bad in (("maxConcurrent", 0), ("maxConcurrent", True), ("maxConcurrent", 1.5), ("maxConcurrent", "2"), ("maxQueued", -1), ("maxQueued", 10001)):
            self.assertEqual(self.request("POST", "/api/settings", {key: bad})[0], 400)
        _, saved = self.request("POST", "/api/settings", {"notice": "queue test"})
        self.assertEqual(saved["settings"]["maxConcurrent"], 1)
        self.assertEqual(saved["settings"]["maxQueued"], 1)

    def test_dynamic_limits_fill_without_killing_existing_tasks(self):
        ids = [self.create() for _ in range(3)]
        for sid in ids:
            self.action(sid, "approve")
        self.request("POST", "/api/settings", {"maxConcurrent": 2})
        self.assertEqual(self.rows()[ids[1]]["status"], "running")
        self.request("POST", "/api/settings", {"maxConcurrent": 1})
        self.action(ids[0], "terminate")
        self.assertEqual(self.rows()[ids[2]]["status"], "queued")
        self.action(ids[1], "terminate")
        self.assertEqual(self.rows()[ids[2]]["status"], "running")

    def test_latest_workspace_policy_can_fail_queue_head_without_blocking_next(self):
        first, bad, good = self.create(), self.create(), self.create(workspace="/allowed/work")
        for sid in (first, bad, good):
            self.action(sid, "approve")
        self.request("POST", "/api/settings", {"workspaceRoots": ["/allowed"]})
        self.action(first, "terminate")
        rows = self.rows()
        self.assertEqual(rows[bad]["status"], "failed")
        self.assertIn("工作区", rows[bad]["failureReason"])
        self.assertEqual(rows[good]["status"], "running")

    def test_permissions_and_owner_queue_cancellation(self):
        owner, stranger = self.phone("13900000002"), self.phone("13900000003")
        first, waiting = self.create(), self.create(token=owner)
        self.action(first, "approve")
        self.assertEqual(self.action(waiting, "approve", token=owner)[0], 403)
        self.action(waiting, "approve")
        self.assertEqual(self.action(waiting, "terminate", token=stranger)[0], 404)
        self.assertNotIn(waiting, self.rows(token=stranger))
        self.assertEqual(self.action(waiting, "terminate", token=owner)[0], 200)

    def test_restart_keeps_unknown_process_reserved_and_queue_persisted(self):
        first, waiting = self.create(), self.create()
        self.action(first, "approve")
        self.action(waiting, "approve")
        self.stop_server()
        self.spawn_server()
        for _ in range(30):
            rows = self.rows()
            if rows[first]["runtime"].get("recoveryRequired"):
                break
            time.sleep(0.05)
        self.assertTrue(rows[first]["runtime"]["recoveryRequired"])
        self.assertEqual(rows[waiting]["status"], "queued")
        self.assertEqual(rows[waiting]["queuePosition"], 1)
        self.assertEqual(self.action(first, "terminate")[0], 409)


class PythonQueueApiTest(QueueContract, unittest.TestCase):
    command = [sys.executable, "server.py"]


@unittest.skipUnless(NODE, "set SAFEDESK_TEST_NODE to include the Node API contract")
class NodeQueueApiTest(QueueContract, unittest.TestCase):
    command = [NODE, "server.mjs"]
