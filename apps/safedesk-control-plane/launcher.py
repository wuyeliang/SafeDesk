"""Isolation runtime launcher: compiles SandboxLaunchPlan into a real process (REQ-EX-001..007, 009..012).

When a `wasmer` binary is available the plan is executed with hardened flags;
otherwise a dry-run placeholder process keeps the full lifecycle testable.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path

from policy import POLICIES

START_TIMEOUT_SEC = int(os.getenv("SAFEDESK_START_TIMEOUT", "30"))


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_launch_command(manifest: dict, wasmer: str = "wasmer",
                         dry_run: bool = False, proxy_url: str | None = None) -> tuple[list[str], str]:
    """Assemble the sandbox process argv from a launch plan. Returns (argv, mode)."""
    use_dry_run = dry_run or not shutil.which(wasmer)
    if use_dry_run:
        return ["sleep", str(START_TIMEOUT_SEC * 20)], "dry-run"
    runtime = manifest["runtime"]
    agent = manifest["agent"]["command"]
    cmd = [shutil.which(wasmer) or wasmer, "run"]
    for package in runtime.get("packages", []):
        cmd.append(str(package))
    cmd += ["--env", f"SAFEDESK_SANDBOX_ID={manifest['id']}"]
    if proxy_url:
        token_pair = manifest.get("egress", {})
        auth = f"{manifest['id']}:{token_pair.get('token', '')}"
        cmd += ["--env", f"HTTP_PROXY={proxy_url}", "--env", f"HTTPS_PROXY={proxy_url}",
                "--env", f"SAFEDESK_EGRESS_AUTH={auth}"]
    for key, value in (manifest.get("environment") or {}).items():
        cmd += ["--env", f"{key}={value}"]
    if runtime.get("network") == "disabled":
        cmd += ["--env", "SAFEDESK_NETWORK=disabled"]
    if runtime.get("volume"):
        cmd += ["--volume", str(runtime["volume"])]
    cmd += ["--", agent]
    return cmd, "wasmer"


def workspace_allowed(workspace: str, roots: list[str]) -> bool:
    """REQ-EX-008/REQ-PL-004: workspace must stay under an allowed root (when configured)."""
    if not roots:
        return bool(workspace and workspace.startswith("/"))
    resolved = os.path.realpath(workspace)
    return any(resolved == os.path.realpath(root) or resolved.startswith(os.path.realpath(root) + os.sep) for root in roots)


class Launcher:
    """Owns the running sandbox processes and their signal semantics."""

    def __init__(self, state_dir: Path, proxy_url: str | None = None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.proxy_url = proxy_url
        self._lock = threading.Lock()
        self._procs: dict[str, subprocess.Popen] = {}

    def _limits(self, sandbox: dict):  # pragma: no cover - platform dependent
        policy = POLICIES.get(sandbox.get("policyId", ""), {})
        cpu = int(policy.get("maxCpu", 1))
        # NOTE: do not clamp RLIMIT_AS here. wasmer reserves large virtual
        # address space for WASM linear memories and fails to spawn under an
        # address-space cap (verified on Ubuntu 24.04, os error 12). Memory
        # ceilings belong to Wasm memory pages / cgroup enforcement instead.

        def apply():
            import resource
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
                target = cpu * 60
                if hard != resource.RLIM_INFINITY and (target <= 0 or target > hard):
                    target = hard
                resource.setrlimit(resource.RLIMIT_CPU, (target if target > 0 else soft, hard))
            except (OSError, ValueError):
                pass  # host does not support this rlimit
        return apply

    def start(self, sandbox: dict, manifest: dict) -> dict:
        with self._lock:
            existing = self._procs.get(sandbox["id"])
            if existing and existing.poll() is None:
                return self.info(sandbox["id"])
            cmd, mode = build_launch_command(manifest, proxy_url=self.proxy_url)
            log_path = self.state_dir / f"{sandbox['id']}.log"
            log = log_path.open("ab")
            preexec = self._limits(sandbox) if os.name == "posix" else None
            try:
                proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, preexec_fn=preexec)
            except OSError as error:
                log.close()
                raise ValueError(f"启动沙箱失败：{error}") from error
            self._procs[sandbox["id"]] = proc
            log.close()
            return {
                "mode": mode, "pid": proc.pid, "logPath": str(log_path), "startedAt": iso_now(),
                "command": cmd[0],
            }

    def info(self, sandbox_id: str) -> dict:
        proc = self._procs.get(sandbox_id)
        if not proc:
            return {"alive": False}
        code = proc.poll()
        return {"alive": code is None, "pid": proc.pid, "exitCode": code}

    def is_alive(self, sandbox_id: str) -> bool:
        return bool(self.info(sandbox_id).get("alive"))

    def read_log(self, sandbox_id: str, offset: int = 0, limit: int = 65536) -> dict:
        """Incremental read of the sandbox process log (REQ-EX-011 real-time build output)."""
        state = self.info(sandbox_id)
        path = self.state_dir / f"{sandbox_id}.log"
        size = path.stat().st_size if path.exists() else 0
        seek = max(0, min(int(offset or 0), size))
        content = ""
        read_bytes = 0
        if seek < size:
            with open(path, "rb") as handle:
                handle.seek(seek)
                raw = handle.read(min(limit, size - seek))
                read_bytes = len(raw)
                content = raw.decode("utf-8", "replace")
        return {
            "content": content,
            "offset": seek + read_bytes,
            "size": size,
            "alive": bool(state.get("alive")),
            "pid": state.get("pid"),
            "exitCode": state.get("exitCode"),
            "mode": "live" if self._procs.get(sandbox_id) else "final",
        }

    def pause(self, sandbox_id: str) -> bool:
        proc = self._procs.get(sandbox_id)
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGSTOP)
            return True
        return False

    def resume(self, sandbox_id: str) -> bool:
        proc = self._procs.get(sandbox_id)
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGCONT)
            return True
        return False

    def stop(self, sandbox_id: str, timeout: float = 5.0) -> bool:
        proc = self._procs.get(sandbox_id)
        if not proc:
            return False
        if proc.poll() is None:
            proc.send_signal(signal.SIGCONT)
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        return True

    def reap_orphans(self, live_ids: list[str]) -> list[str]:
        """Mark removed-process entries; control plane reconciles sandbox status (REQ-EX-007)."""
        dead = []
        with self._lock:
            for sandbox_id, proc in list(self._procs.items()):
                if sandbox_id not in live_ids and proc.poll() is None:
                    try:
                        proc.terminate()
                    except OSError:
                        pass
                    dead.append(sandbox_id)
                if proc.poll() is not None:
                    self._procs.pop(sandbox_id, None)
        return dead
