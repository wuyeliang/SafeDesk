import { execFileSync, spawn } from 'node:child_process';
import { closeSync, createWriteStream, mkdirSync, openSync, readSync, statSync } from 'node:fs';
import { join, resolve as resolvePath } from 'node:path';

/** Isolation runtime launcher: compiles SandboxLaunchPlan into a real process (REQ-EX-001..007, 009..012). */
const START_TIMEOUT_SEC = Number(process.env.SAFEDESK_START_TIMEOUT || 30);

function which(binary) {
  try {
    return execFileSync('which', [binary], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim() || null;
  } catch {
    return null;
  }
}

export function buildLaunchCommand(manifest, { wasmer = 'wasmer', dryRun = false, proxyUrl = null } = {}) {
  const resolved = which(wasmer);
  if (dryRun || !resolved) {
    return { argv: ['sleep', String(START_TIMEOUT_SEC * 20)], mode: 'dry-run' };
  }
  const argv = [resolved, 'run'];
  for (const pkg of manifest.runtime.packages || []) argv.push(String(pkg));
  argv.push('--env', `SAFEDESK_SANDBOX_ID=${manifest.id}`);
  if (proxyUrl) {
    const token = manifest.egress?.token ?? '';
    argv.push('--env', `HTTP_PROXY=${proxyUrl}`, '--env', `HTTPS_PROXY=${proxyUrl}`, '--env', `SAFEDESK_EGRESS_AUTH=${manifest.id}:${token}`);
  }
  for (const [key, value] of Object.entries(manifest.environment || {})) argv.push('--env', `${key}=${value}`);
  if (manifest.runtime.network === 'disabled') argv.push('--env', 'SAFEDESK_NETWORK=disabled');
  if (manifest.runtime.volume) argv.push('--volume', String(manifest.runtime.volume));
  argv.push('--', manifest.agent.command);
  return { argv, mode: 'wasmer' };
}

/** REQ-EX-008 / REQ-PL-004: workspace must stay under an allowed root (when configured). */
export function workspaceAllowed(workspace, roots = []) {
  if (!roots.length) return Boolean(workspace && workspace.startsWith('/'));
  const target = resolvePath(workspace);
  return roots.some((root) => target === resolvePath(root) || target.startsWith(`${resolvePath(root)}/`));
}

export class Launcher {
  constructor(stateDir, proxyUrl = null) {
    this.stateDir = stateDir;
    this.proxyUrl = proxyUrl;
    this._procs = new Map();
    mkdirSync(stateDir, { recursive: true });
  }

  start(sandbox, manifest) {
    const existing = this._procs.get(sandbox.id);
    if (existing && this._alive(existing)) return this.info(sandbox.id);
    const { argv, mode } = buildLaunchCommand(manifest, { proxyUrl: this.proxyUrl });
    const logPath = join(this.stateDir, `${sandbox.id}.log`);
    const stream = createWriteStream(logPath, { flags: 'a' });
    const child = spawn(argv[0], argv.slice(1), { stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.pipe(stream);
    child.stderr.pipe(stream);
    this._procs.set(sandbox.id, child);
    return { mode, pid: child.pid, logPath, startedAt: new Date().toISOString(), command: argv[0] };
  }

  _alive(child) {
    return child.exitCode === null && child.signalCode === null;
  }

  info(sandboxId) {
    const child = this._procs.get(sandboxId);
    if (!child) return { alive: false };
    const alive = this._alive(child);
    return { alive, pid: child.pid, exitCode: alive ? null : (child.exitCode ?? child.signalCode) };
  }

  isAlive(sandboxId) {
    return Boolean(this.info(sandboxId).alive);
  }

  /** Incremental read of the sandbox process log (REQ-EX-011 real-time build output). */
  readLog(sandboxId, offset = 0, limit = 65536) {
    const state = this.info(sandboxId);
    const path = join(this.stateDir, `${sandboxId}.log`);
    let size = 0;
    try { size = statSync(path).size; } catch { /* no log yet */ }
    const seek = Math.max(0, Math.min(Number(offset) || 0, size));
    let content = '';
    let readBytes = 0;
    if (seek < size) {
      const handle = openSync(path, 'r');
      try {
        const buffer = Buffer.alloc(Math.min(limit, size - seek));
        readBytes = readSync(handle, buffer, 0, buffer.length, seek);
        content = buffer.subarray(0, readBytes).toString('utf8');
      } finally {
        closeSync(handle);
      }
    }
    return {
      content,
      offset: seek + readBytes,
      size,
      alive: Boolean(state.alive),
      pid: state.pid ?? null,
      exitCode: state.exitCode ?? null,
      mode: this._procs.get(sandboxId) ? 'live' : 'final',
    };
  }

  pause(sandboxId) {
    const child = this._procs.get(sandboxId);
    if (child && this._alive(child)) {
      child.kill('SIGSTOP');
      return true;
    }
    return false;
  }

  resume(sandboxId) {
    const child = this._procs.get(sandboxId);
    if (child && this._alive(child)) {
      child.kill('SIGCONT');
      return true;
    }
    return false;
  }

  stop(sandboxId, timeoutMs = 5000) {
    const child = this._procs.get(sandboxId);
    if (!child) return false;
    if (this._alive(child)) {
      child.kill('SIGTERM');
      setTimeout(() => {
        if (this._alive(child)) child.kill('SIGKILL');
      }, timeoutMs).unref();
    }
    return true;
  }

  reapOrphans(liveIds) {
    const dead = [];
    for (const [sandboxId, child] of this._procs) {
      const alive = this._alive(child);
      if (!liveIds.includes(sandboxId) && alive) {
        try { child.kill('SIGTERM'); } catch { /* already gone */ }
        dead.push(sandboxId);
      }
      if (!alive) this._procs.delete(sandboxId);
    }
    return dead;
  }
}
