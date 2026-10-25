"""Tests for the isolation runtime launcher (REQ-EX-001, 003..007, 009, 010)."""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from launcher import Launcher, build_launch_command, workspace_allowed  # noqa: E402
from policy import compile_manifest  # noqa: E402


def manifest(tmp_id: str = "sbx-launch01", **overrides) -> dict:
    sandbox = {
        "id": tmp_id, "name": "launch-test", "agent": "claude-code", "policyId": "balanced",
        "workspace": "/srv/work/demo", "packages": ["wasmer/bash@latest"],
        "credentials": ["github-read"], "mcpServers": ["github"],
        "status": "running", "createdAt": "2026-10-24T00:00:00.000Z",
    }
    sandbox.update(overrides)
    plan = compile_manifest(sandbox)
    if "egressToken" in sandbox:
        plan["egress"] = {"token": sandbox["egressToken"]}
    return plan


class BuildCommandTest(unittest.TestCase):
    def test_dry_run_mode_when_wasmer_missing(self):
        cmd, mode = build_launch_command(manifest(), wasmer="wasmer-does-not-exist-xyz")
        self.assertEqual(mode, "dry-run")
        self.assertEqual(cmd[0], "sleep")

    def test_wasmer_command_contains_sandbox_env_and_volume(self):
        plan = manifest(egressToken="abc123")
        plan["environment"] = {"github-read": "{{SD_CRED_sbx-launch01_x}}"}
        cmd, mode = build_launch_command(plan, wasmer="sh", dry_run=False, proxy_url="http://127.0.0.1:9000")
        if mode == "dry-run":
            self.skipTest("no wasmer binary")
        joined = " ".join(cmd)
        self.assertIn("SAFEDESK_SANDBOX_ID=sbx-launch01", joined)
        self.assertIn("--volume", cmd)
        self.assertIn("http://127.0.0.1:9000", joined)
        self.assertIn("SAFEDESK_EGRESS_AUTH=sbx-launch01:abc123", joined)
        self.assertIn("{{SD_CRED_sbx-launch01_x}}", joined)

    def test_workspace_whitelist(self):
        self.assertTrue(workspace_allowed("/srv/work/app", []))
        self.assertTrue(workspace_allowed("/srv/work/app", ["/srv"]))
        self.assertFalse(workspace_allowed("/etc/passwd", ["/srv"]))
        self.assertFalse(workspace_allowed("/srv/../etc", ["/srv"]))
        self.assertFalse(workspace_allowed("relative/path", []))


class LauncherLifecycleTest(unittest.TestCase):
    def setUp(self):
        suffix = next(tempfile._get_candidate_names())
        self.dir = Path(tempfile.gettempdir()) / f"safedesk-launcher-{suffix}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.launcher = Launcher(self.dir / "runners")

    def tearDown(self):
        for sandbox_id in list(self.launcher._procs):
            self.launcher.stop(sandbox_id)
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_start_info_pause_resume_stop(self):
        info = self.launcher.start({"id": "sbx-launch01", "policyId": "balanced"}, manifest())
        self.assertTrue(info["pid"] > 0)
        self.assertTrue(self.launcher.is_alive("sbx-launch01"))
        self.assertTrue(self.launcher.pause("sbx-launch01"))
        time.sleep(0.1)
        self.assertTrue(self.launcher.is_alive("sbx-launch01"))
        self.assertTrue(self.launcher.resume("sbx-launch01"))
        time.sleep(0.1)
        self.assertTrue(self.launcher.is_alive("sbx-launch01"))
        self.assertTrue(self.launcher.stop("sbx-launch01"))
        time.sleep(0.1)
        self.assertFalse(self.launcher.is_alive("sbx-launch01"))

    def test_stop_terminated_process_returns_true(self):
        self.launcher.start({"id": "sbx-launch02", "policyId": "balanced"}, manifest("sbx-launch02"))
        self.assertTrue(self.launcher.stop("sbx-launch02"))
        self.assertFalse(self.launcher.stop("sbx-unknown"))

    def test_log_path_recorded(self):
        info = self.launcher.start({"id": "sbx-launch03", "policyId": "balanced"}, manifest("sbx-launch03"))
        self.assertIn("sbx-launch03", info["logPath"])
        self.launcher.stop("sbx-launch03")

    def test_reap_orphans(self):
        self.launcher.start({"id": "sbx-launch04", "policyId": "balanced"}, manifest("sbx-launch04"))
        dead = self.launcher.reap_orphans(live_ids=[])
        self.assertIn("sbx-launch04", dead)

    def test_read_log_incremental_and_final(self):
        launcher = self.launcher
        log_path = self.dir / "runners" / "sbx-log01.log"
        log_path.write_text("first\n", encoding="utf-8")
        first = launcher.read_log("sbx-log01", offset=0)
        self.assertEqual(first["content"], "first\n")
        self.assertEqual(first["offset"], len("first\n"))
        self.assertFalse(first["alive"])
        self.assertEqual(first["mode"], "final")
        # second write arrives later, continue from offset
        with open(log_path, "a", encoding="utf-8") as handle:
            handle.write("second\n")
        second = launcher.read_log("sbx-log01", offset=first["offset"])
        self.assertEqual(second["content"], "second\n")
        # offset beyond eof clamps
        tail = launcher.read_log("sbx-log01", offset=999)
        self.assertEqual(tail["content"], "")
        self.assertEqual(tail["offset"], len("first\nsecond\n"))

    def test_read_log_empty_when_no_log(self):
        result = self.launcher.read_log("sbx-unknown")
        self.assertEqual(result["content"], "")
        self.assertEqual(result["offset"], 0)
        self.assertFalse(result["alive"])


if __name__ == "__main__":
    unittest.main()
