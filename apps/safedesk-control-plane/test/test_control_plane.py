"""Integration and unit tests for the SafeDesk Python control plane.

Run with: python3 -m unittest discover -s test -p "test_*.py" -v
Standard library only: spawns server.py on an ephemeral port with an
isolated SAFEDESK_DATA_FILE, then exercises the HTTP API over urllib.
"""
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
sys.path.insert(0, str(ROOT))

from policy import ALLOWED_AGENTS, POLICIES, SECRET_PATHS, compile_manifest  # noqa: E402

# Local test traffic must not go through a proxy configured via *_PROXY env vars.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class CompileManifestTest(unittest.TestCase):
    def sample(self, **overrides) -> dict:
        sandbox = {
            "id": "sbx-test1234",
            "name": "unit-test",
            "agent": "claude-code",
            "policyId": "balanced",
            "workspace": "/srv/work/demo",
            "packages": ["wasmer/bash@latest"],
            "credentials": ["github-read"],
            "mcpServers": ["github"],
            "status": "pending_approval",
            "createdAt": "2026-10-23T00:00:00.000Z",
        }
        sandbox.update(overrides)
        return sandbox

    def test_policy_catalog(self):
        self.assertEqual(sorted(POLICIES), ["balanced", "build", "review"])
        self.assertEqual(sorted(ALLOWED_AGENTS), ["claude-code", "codex", "dsh"])

    def test_balanced_policy_mapping(self):
        manifest = compile_manifest(self.sample())
        self.assertEqual(manifest["apiVersion"], "safedesk.io/v1")
        self.assertEqual(manifest["kind"], "SandboxLaunchPlan")
        self.assertEqual(manifest["id"], "sbx-test1234")
        self.assertEqual(manifest["runtime"]["network"], "brokered")
        self.assertEqual(manifest["runtime"]["volume"], "/srv/work/demo:/workspace")
        self.assertEqual(manifest["filesystem"]["mode"], "rw")
        self.assertEqual(manifest["enforcement"]["approval"], "destructive")
        self.assertEqual(manifest["enforcement"]["maxCpu"], 2)

    def test_review_policy_is_read_only_without_network(self):
        manifest = compile_manifest(self.sample(policyId="review"))
        self.assertEqual(manifest["filesystem"]["mode"], "ro")
        self.assertEqual(manifest["runtime"]["network"], "disabled")

    def test_build_policy_uses_ephemeral_workspace(self):
        manifest = compile_manifest(self.sample(policyId="build"))
        self.assertEqual(manifest["filesystem"]["mode"], "ephemeral")
        self.assertEqual(manifest["runtime"]["network"], "allowlist")
        self.assertEqual(manifest["enforcement"]["maxMemoryMb"], 8192)

    def test_credential_broker_never_exposes_secret_values(self):
        manifest = compile_manifest(self.sample())
        self.assertTrue(manifest["credentialBroker"]["enabled"])
        self.assertFalse(manifest["credentialBroker"]["exposedValues"])
        self.assertEqual(manifest["credentialBroker"]["profiles"], ["github-read"])

    def test_secret_paths_cover_common_secret_files(self):
        manifest = compile_manifest(self.sample())
        self.assertEqual(manifest["filesystem"]["secretPaths"], SECRET_PATHS)
        for expected in ["/.env", "/.ssh/**", "/.aws/**", "/.npmrc"]:
            self.assertIn(expected, SECRET_PATHS)


class ControlPlaneApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = Path(tempfile.mkdtemp(prefix="safedesk-test-"))
        cls.data_file = cls.data_dir / "sandboxes.json"
        cls.port = free_port()
        cls.base = f"http://127.0.0.1:{cls.port}"
        env = {**os.environ, "PORT": str(cls.port), "SAFEDESK_DATA_DIR": str(cls.data_dir), "SAFEDESK_DATA_FILE": str(cls.data_file), "SAFEDESK_AUTH": "0"}
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"],
            cwd=ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(50):
            try:
                cls.request("GET", "/api/bootstrap")
                break
            except OSError:
                time.sleep(0.1)
        else:
            cls.tearDownClass()
            raise RuntimeError("server did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=5)
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    @classmethod
    def request(cls, method: str, path: str, body=None):
        payload = None
        headers = {}
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(cls.base + path, data=payload, headers=headers, method=method)
        try:
            with OPENER.open(request, timeout=5) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read() or b"{}")

    @classmethod
    def create_sandbox(cls, **overrides):
        payload = {
            "name": "audit-run",
            "agent": "codex",
            "policyId": "review",
            "workspace": "/tmp/project",
            "credentials": ["github-read"],
            "mcpServers": ["github"],
        }
        payload.update(overrides)
        return cls.request("POST", "/api/sandboxes", payload)

    def test_bootstrap_returns_catalogs_and_events(self):
        status, data = self.request("GET", "/api/bootstrap")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(p["id"] for p in data["policies"]), ["balanced", "build", "review"])
        self.assertEqual(sorted(a["id"] for a in data["agents"]), ["claude-code", "codex", "dsh"])
        self.assertTrue(any(e["level"] == "block" for e in data["securityEvents"]))
        self.assertIn("overview", data)
        self.assertEqual(len(data["catalog"]["policies"]), 3)
        self.assertGreaterEqual(len(data["templates"]), 3)

    def test_create_pending_sandbox_without_exposing_secrets(self):
        status, data = self.create_sandbox()
        self.assertEqual(status, 201)
        self.assertEqual(data["sandbox"]["status"], "pending_approval")
        self.assertEqual(data["sandbox"]["id"], data["manifest"]["id"])
        self.assertFalse(data["manifest"]["credentialBroker"]["exposedValues"])
        self.assertEqual(data["manifest"]["filesystem"]["mode"], "ro")
        self.assertEqual(data["manifest"]["runtime"]["network"], "disabled")

    def test_reject_invalid_inputs_with_400(self):
        for overrides in [
            {"policyId": "everything-allowed"},
            {"agent": "gpt-shell"},
            {"workspace": "relative/project"},
        ]:
            status, _ = self.create_sandbox(**overrides)
            self.assertEqual(status, 400, str(overrides))
        status, data = self.request("POST", "/api/sandboxes", b"{not-json")
        self.assertEqual(status, 400)
        self.assertIn("JSON", data["error"])

    def test_sandbox_name_sanitized_and_defaulted(self):
        _, data = self.create_sandbox(name="my <script> box \u6d4b\u8bd5")
        self.assertEqual(data["sandbox"]["name"], "my--script--box-\u6d4b\u8bd5")
        _, fallback = self.create_sandbox(name="   ")
        self.assertEqual(fallback["sandbox"]["name"], "agent-codex")

    def test_created_sandbox_persisted_to_data_file(self):
        _, data = self.create_sandbox(name="persisted")
        stored = json.loads(self.data_file.read_text(encoding="utf-8"))
        self.assertTrue(any(item["id"] == data["sandbox"]["id"] for item in stored))

    def test_approve_flow_and_conflict(self):
        _, data = self.create_sandbox(name="approve-me")
        sandbox_id = data["sandbox"]["id"]
        status, approved = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve")
        self.assertEqual(status, 200)
        self.assertEqual(approved["sandbox"]["status"], "running")
        self.assertIn("startedAt", approved["sandbox"])
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve")
        self.assertEqual(status, 409)

    def test_terminate_blocks_further_lifecycle_actions(self):
        _, data = self.create_sandbox(name="terminate-me")
        sandbox_id = data["sandbox"]["id"]
        status, terminated = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate")
        self.assertEqual(status, 200)
        self.assertEqual(terminated["sandbox"]["status"], "terminated")
        self.assertIn("terminatedAt", terminated["sandbox"])
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate")
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve")
        self.assertEqual(status, 409)

    def test_manifest_endpoint_for_existing_sandbox(self):
        _, data = self.create_sandbox(name="manifest-me", policyId="build")
        status, body = self.request("GET", f"/api/sandboxes/{data['sandbox']['id']}/manifest")
        self.assertEqual(status, 200)
        self.assertEqual(body["manifest"]["id"], data["sandbox"]["id"])
        self.assertEqual(body["manifest"]["runtime"]["network"], "allowlist")
        self.assertEqual(body["manifest"]["filesystem"]["mode"], "ephemeral")
        self.assertFalse(body["manifest"]["credentialBroker"]["exposedValues"])

    def test_unknown_sandbox_returns_404(self):
        for action in ["approve", "terminate", "manifest"]:
            method = "GET" if action == "manifest" else "POST"
            status, _ = self.request(method, f"/api/sandboxes/sbx-missing/{action}")
            self.assertEqual(status, 404, action)

    def test_logs_endpoint_shape_and_offset(self):
        _, data = self.create_sandbox(name="logs-me", policyId="build", credentials=[])
        sandbox_id = data["sandbox"]["id"]
        status, approved = self.request("POST", f"/api/sandboxes/{sandbox_id}/approve")
        self.assertEqual(status, 200, approved.get("error"))
        self.assertEqual(approved["sandbox"]["status"], "running")
        time.sleep(0.5)
        status, first = self.request("GET", f"/api/sandboxes/{sandbox_id}/logs")
        self.assertEqual(status, 200)
        for key in ("content", "offset", "size", "alive"):
            self.assertIn(key, first)
        self.assertGreaterEqual(first["size"], 0)
        status, second = self.request("GET", f"/api/sandboxes/{sandbox_id}/logs?offset={first['offset']}")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(second["offset"], first["offset"])
        self.request("POST", f"/api/sandboxes/{sandbox_id}/terminate")
        time.sleep(0.3)
        status, tail = self.request("GET", f"/api/sandboxes/{sandbox_id}/logs?offset={second['offset']}")
        self.assertEqual(status, 200, "终止后日志仍可读")
        self.assertIn("mode", tail)

    def test_logs_endpoint_unknown_sandbox_404(self):
        status, _ = self.request("GET", "/api/sandboxes/sbx-missing/logs")
        self.assertEqual(status, 404)

    def test_lifecycle_events_recorded(self):
        _, data = self.create_sandbox(name="eventful")
        self.request("POST", f"/api/sandboxes/{data['sandbox']['id']}/approve")
        status, body = self.request("GET", "/api/events")
        self.assertEqual(status, 200)
        actions = [e["action"] for e in body["events"]]
        self.assertIn("人工审批", actions)
        self.assertIn("创建待审批沙箱", actions)
        self.assertLessEqual(len(body["events"]), 40)

    def test_created_sandbox_owned_by_local_dev(self):
        _, data = self.create_sandbox(name="owned")
        self.assertEqual(data["sandbox"]["ownerId"], "local-dev")
        self.assertEqual(data["sandbox"]["statusLabel"], "待审批")
        self.assertEqual(data["sandbox"]["risk"], "低风险")

    def test_purpose_and_notes_truncated(self):
        _, data = self.create_sandbox(name="limits", purpose="p" * 200, notes="n" * 300)
        self.assertEqual(len(data["sandbox"]["purpose"]), 160)
        self.assertEqual(len(data["sandbox"]["notes"]), 240)

    def test_pause_resume_require_running(self):
        _, data = self.create_sandbox(name="pause-flow")
        sandbox_id = data["sandbox"]["id"]
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause")
        self.assertEqual(status, 409)
        status, _ = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume")
        self.assertEqual(status, 409)
        self.request("POST", f"/api/sandboxes/{sandbox_id}/approve")
        _, paused = self.request("POST", f"/api/sandboxes/{sandbox_id}/pause")
        self.assertEqual(paused["sandbox"]["status"], "paused")
        _, resumed = self.request("POST", f"/api/sandboxes/{sandbox_id}/resume")
        self.assertEqual(resumed["sandbox"]["status"], "running")

    def test_reject_records_reason(self):
        _, data = self.create_sandbox(name="reject-flow")
        status, rejected = self.request("POST", f"/api/sandboxes/{data['sandbox']['id']}/reject", {"reason": "超出范围"})
        self.assertEqual(status, 200)
        self.assertEqual(rejected["sandbox"]["status"], "rejected")
        self.assertEqual(rejected["sandbox"]["rejectReason"], "超出范围")
        status, _ = self.request("POST", f"/api/sandboxes/{data['sandbox']['id']}/approve")
        self.assertEqual(status, 409)

    def test_reject_default_reason(self):
        _, data = self.create_sandbox(name="reject-default")
        _, rejected = self.request("POST", f"/api/sandboxes/{data['sandbox']['id']}/reject", {})
        self.assertEqual(rejected["sandbox"]["rejectReason"], "不符合安全策略")

    def test_catalog_and_templates(self):
        status, catalog = self.request("GET", "/api/catalog")
        self.assertEqual(status, 200)
        self.assertEqual(len(catalog["policies"]), 3)
        status, templates = self.request("GET", "/api/templates")
        self.assertEqual(status, 200)
        self.assertEqual(len(templates["templates"]), 5)

    def test_overview_counts_created_sandboxes(self):
        self.create_sandbox(name="overview-box")
        status, body = self.request("GET", "/api/overview")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["overview"]["total"], 1)
        self.assertEqual(body["overview"]["role"], "admin")

    def test_sandbox_filters(self):
        _, data = self.create_sandbox(name="filter-target", purpose="专门给筛选用")
        _, filtered = self.request("GET", "/api/sandboxes?status=pending_approval&q=%E7%AD%9B%E9%80%89")
        self.assertTrue(any(item["id"] == data["sandbox"]["id"] for item in filtered["sandboxes"]))
        _, none = self.request("GET", "/api/sandboxes?status=terminated&q=%E7%AD%9B%E9%80%89")
        self.assertFalse(any(item["id"] == data["sandbox"]["id"] for item in none["sandboxes"]))

    def test_events_filter_by_level(self):
        _, body = self.request("GET", "/api/events?level=block")
        self.assertGreaterEqual(len(body["events"]), 1)
        self.assertTrue(all(item["level"] == "block" for item in body["events"]))

    def test_activity_mentions_sandbox_name(self):
        _, data = self.create_sandbox(name="activity-box")
        _, body = self.request("GET", f"/api/sandboxes/{data['sandbox']['id']}/activity")
        self.assertTrue(any("activity-box" in str(item.get("detail", "")) for item in body["events"]))

    def test_settings_persist(self):
        status, body = self.request("POST", "/api/settings", {"orgName": "测试组织", "maxConcurrent": 3})
        self.assertEqual(status, 200)
        self.assertEqual(body["settings"]["orgName"], "测试组织")
        _, loaded = self.request("GET", "/api/settings")
        self.assertEqual(loaded["settings"]["orgName"], "测试组织")

    def test_unknown_api_path(self):
        status, body = self.request("GET", "/api/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("Not found", body["error"])

    def test_static_root_does_not_leak_source_files(self):
        # GET / serves static HTML, not JSON — read it raw instead of via request()
        with OPENER.open(self.base + "/", timeout=5) as response:
            self.assertEqual(response.status, 200)
        for path in ["/../server.py", "/%2e%2e/server.py", "/..%2fserver.py"]:
            request = urllib.request.Request(self.base + path, method="GET")
            try:
                with OPENER.open(request, timeout=5) as response:
                    body = response.read().decode("utf-8", "replace")
                    self.fail(f"{path} returned 200 and leaked source: {body[:80]}")
            except urllib.error.HTTPError as error:
                self.assertIn(error.code, (400, 403, 404), path)
            except urllib.error.URLError:
                # urllib rejects some malformed traversal URLs before sending — also acceptable
                pass


if __name__ == "__main__":
    unittest.main()
