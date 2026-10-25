"""Single-process FIFO scheduling; callers hold the control-plane state lock."""
from datetime import datetime, timezone

ACTIVE = {"running", "paused"}
TERMINAL = {"completed", "failed", "rejected", "terminated"}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def validate_limits(settings):
    for key, maximum in (("maxConcurrent", 64), ("maxQueued", 10000)):
        value = settings[key]
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{key} 必须为 1–{maximum} 的整数")


def queued(items):
    return sorted((s for s in items if s["status"] == "queued"),
                  key=lambda s: (s.get("queueOrder", 0), s.get("queuedAt", ""), s["id"]))


def with_positions(items):
    positions = {s["id"]: i + 1 for i, s in enumerate(queued(items))}
    return [{**s, "queuePosition": positions.get(s["id"])} for s in items]


class Scheduler:
    def __init__(self, launcher, start, release, event):
        self.launcher, self.start, self.release, self.event = launcher, start, release, event

    def enqueue(self, items, sandbox, settings, actor):
        validate_limits(settings)
        if sandbox["status"] != "pending_approval":
            raise ValueError("沙箱不是待审批状态")
        if len(queued(items)) >= settings["maxQueued"]:
            raise ValueError("已达到排队上限，请稍后审批")
        order = max((s.get("queueOrder", 0) for s in items), default=0) + 1
        sandbox.update(status="queued", queueOrder=order, queuedAt=now(),
                       approvedAt=now(), approvedBy=actor)
        self.event("info", "人工审批", f"{sandbox['name']} 已审批并入队", actor)

    def tick(self, items, settings):
        validate_limits(settings)
        changed = False
        for sandbox in items:
            if sandbox["status"] not in ACTIVE:
                continue
            info = self.launcher.info(sandbox["id"])
            if info.get("alive"):
                continue
            if "exitCode" not in info:
                runtime = sandbox.setdefault("runtime", {})
                if not runtime.get("recoveryRequired"):
                    runtime["recoveryRequired"] = True
                    changed = True
                continue  # Unknown processes retain their reservation after restart.
            code = info["exitCode"]
            sandbox.update(status="completed" if code == 0 else "failed",
                           exitCode=code, finishedAt=now())
            sandbox.pop("egressToken", None)
            self.release(sandbox["id"])
            self.event("info", "任务结束", f"{sandbox['name']} 退出码 {code}", "scheduler")
            changed = True
        active = sum(s["status"] in ACTIVE for s in items)
        for sandbox in queued(items):
            if active >= settings["maxConcurrent"]:
                break
            try:
                runtime = self.start(sandbox)
            except (ValueError, OSError) as error:
                self.release(sandbox["id"])
                sandbox.pop("egressToken", None)
                sandbox.update(status="failed", finishedAt=now(), failureReason=str(error)[:160])
                self.event("block", "启动失败", f"{sandbox['name']} 启动失败", "scheduler")
            else:
                sandbox.update(status="running", startedAt=now(), runtime=runtime)
                active += 1
                self.event("allow", "调度启动", f"{sandbox['name']} 已启动（{runtime.get('mode')} 模式）", "scheduler")
            changed = True
        return changed
