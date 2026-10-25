"""Deterministic scheduler tests; no model, network, or runtime dependency."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scheduler import Scheduler, validate_limits, with_positions


class SchedulerTest(unittest.TestCase):
    def setUp(self):
        self.processes, self.started, self.released = {}, [], []
        self.settings = {"maxConcurrent": 1, "maxQueued": 2}
        self.items = [{"id": f"sbx-{i}", "name": str(i), "status": "pending_approval", "ownerId": str(i)} for i in range(4)]
        self.scheduler = Scheduler(self, self.start, self.released.append, lambda *args: None)

    def info(self, sandbox_id):
        return self.processes.get(sandbox_id, {"alive": False})

    def start(self, sandbox):
        if sandbox.get("bad"):
            raise ValueError("invalid workspace")
        self.started.append(sandbox["id"])
        self.processes[sandbox["id"]] = {"alive": True}
        return {"mode": "test"}

    def approve(self, i):
        self.scheduler.enqueue(self.items, self.items[i], self.settings, "admin")
        self.scheduler.tick(self.items, self.settings)

    def test_global_cap_admin_fifo_and_no_start_for_queued(self):
        for i in (0, 1, 2):
            self.approve(i)
        self.assertEqual(self.started, ["sbx-0"])
        self.assertEqual([s["queuePosition"] for s in with_positions(self.items)[:3]], [None, 1, 2])
        self.processes["sbx-0"] = {"alive": False, "exitCode": 0}
        self.scheduler.tick(self.items, self.settings)
        self.assertEqual(self.started, ["sbx-0", "sbx-1"])
        self.assertEqual(self.items[0]["status"], "completed")
        self.assertEqual(self.released, ["sbx-0"])

    def test_paused_retains_slot_and_lower_limit_does_not_kill(self):
        self.settings["maxConcurrent"] = 2
        self.approve(0)
        self.approve(1)
        self.items[0]["status"] = "paused"
        self.settings["maxConcurrent"] = 1
        self.approve(2)
        self.assertEqual(self.started, ["sbx-0", "sbx-1"])
        self.assertEqual(self.items[0]["status"], "paused")
        self.settings["maxConcurrent"] = 3
        self.scheduler.tick(self.items, self.settings)
        self.assertEqual(self.started[-1], "sbx-2")

    def test_full_queue_and_duplicate_approval_do_not_change_state(self):
        for i in (0, 1, 2):
            self.approve(i)
        with self.assertRaisesRegex(ValueError, "排队上限"):
            self.approve(3)
        self.assertEqual(self.items[3]["status"], "pending_approval")
        with self.assertRaisesRegex(ValueError, "待审批"):
            self.approve(1)

    def test_failed_start_does_not_block_next_task(self):
        self.approve(0)
        self.items[1]["bad"] = True
        self.approve(1)
        self.approve(2)
        self.processes["sbx-0"] = {"alive": False, "exitCode": 7}
        self.scheduler.tick(self.items, self.settings)
        self.assertEqual([s["status"] for s in self.items[:3]], ["failed", "failed", "running"])
        self.assertEqual(self.items[0]["exitCode"], 7)
        self.assertIn("invalid workspace", self.items[1]["failureReason"])

    def test_restart_unknown_process_retains_reservation(self):
        self.approve(0)
        self.approve(1)
        self.processes.clear()
        self.scheduler.tick(self.items, self.settings)
        self.assertTrue(self.items[0]["runtime"]["recoveryRequired"])
        self.assertEqual(self.items[1]["status"], "queued")
        self.assertEqual(len(self.started), 1)

    def test_restart_queue_uses_persisted_order(self):
        self.approve(0)
        self.approve(1)
        self.approve(2)
        self.items[0]["status"] = "terminated"
        self.items.reverse()
        replacement = Scheduler(self, self.start, self.released.append, lambda *args: None)
        replacement.tick(self.items, self.settings)
        self.assertEqual(self.started[-1], "sbx-1")

    def test_invalid_limits_rejected(self):
        for key, values in {"maxConcurrent": [True, 0, 65, 1.5, "2", None], "maxQueued": [False, 0, 10001, "1"]}.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    validate_limits({**self.settings, key: value})
