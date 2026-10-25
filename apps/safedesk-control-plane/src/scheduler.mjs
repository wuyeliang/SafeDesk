/** Single-process FIFO scheduling. Serialize every state transaction with withStateLock. */
export const activeStates = new Set(['running', 'paused']);
export const terminalStates = new Set(['completed', 'failed', 'rejected', 'terminated']);

export function validateLimits(settings) {
  for (const [key, maximum] of [['maxConcurrent', 64], ['maxQueued', 10000]]) {
    if (!Number.isInteger(settings[key]) || settings[key] < 1 || settings[key] > maximum) {
      throw new Error(`${key} 必须为 1–${maximum} 的整数`);
    }
  }
}

export function queued(items) {
  return items.filter((s) => s.status === 'queued').sort((a, b) =>
    (a.queueOrder || 0) - (b.queueOrder || 0) || (a.queuedAt || '').localeCompare(b.queuedAt || '') || a.id.localeCompare(b.id));
}

export function withPositions(items) {
  const positions = new Map(queued(items).map((s, i) => [s.id, i + 1]));
  return items.map((s) => ({ ...s, queuePosition: positions.get(s.id) ?? null }));
}

export function stateLock() {
  let tail = Promise.resolve();
  return (fn) => {
    const result = tail.then(fn);
    tail = result.catch(() => {});
    return result;
  };
}

export class Scheduler {
  constructor(launcher, start, release, event) {
    Object.assign(this, { launcher, start, release, event });
  }

  enqueue(items, sandbox, settings, actor) {
    validateLimits(settings);
    if (sandbox.status !== 'pending_approval') throw new Error('沙箱不是待审批状态');
    if (queued(items).length >= settings.maxQueued) throw new Error('已达到排队上限，请稍后审批');
    const order = Math.max(0, ...items.map((s) => s.queueOrder || 0)) + 1;
    Object.assign(sandbox, { status: 'queued', queueOrder: order, queuedAt: new Date().toISOString(), approvedAt: new Date().toISOString(), approvedBy: actor });
    this.event('info', '人工审批', `${sandbox.name} 已审批并入队`, actor);
  }

  async tick(items, settings) {
    validateLimits(settings);
    let changed = false;
    for (const sandbox of items) {
      if (!activeStates.has(sandbox.status)) continue;
      const info = this.launcher.info(sandbox.id);
      if (info.alive) continue;
      if (!Object.hasOwn(info, 'exitCode')) {
        sandbox.runtime ??= {};
        if (!sandbox.runtime.recoveryRequired) {
          sandbox.runtime.recoveryRequired = true;
          changed = true;
        }
        continue;
      }
      Object.assign(sandbox, { status: info.exitCode === 0 ? 'completed' : 'failed', exitCode: info.exitCode, finishedAt: new Date().toISOString() });
      delete sandbox.egressToken;
      this.release(sandbox.id);
      this.event('info', '任务结束', `${sandbox.name} 退出码 ${info.exitCode}`, 'scheduler');
      changed = true;
    }
    let active = items.filter((s) => activeStates.has(s.status)).length;
    for (const sandbox of queued(items)) {
      if (active >= settings.maxConcurrent) break;
      try {
        const runtime = await this.start(sandbox);
        Object.assign(sandbox, { status: 'running', startedAt: new Date().toISOString(), runtime });
        active += 1;
        this.event('allow', '调度启动', `${sandbox.name} 已启动（${runtime.mode} 模式）`, 'scheduler');
      } catch (error) {
        this.release(sandbox.id);
        delete sandbox.egressToken;
        Object.assign(sandbox, { status: 'failed', finishedAt: new Date().toISOString(), failureReason: error.message.slice(0, 160) });
        this.event('block', '启动失败', `${sandbox.name} 启动失败`, 'scheduler');
      }
      changed = true;
    }
    return changed;
  }
}
