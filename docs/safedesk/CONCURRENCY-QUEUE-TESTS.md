# 并发限制与排队测试记录

执行日期：2026-10-25（Asia/Shanghai）。设计见
[CONCURRENCY-QUEUE.md](CONCURRENCY-QUEUE.md)。基线为 `6c1740c`。
环境为 macOS、Python 3.9.6、Node.js 24.19.0；无需安装第三方包。
以下命令在仓库根目录执行，`node` 指向 Node.js 20+ 可执行文件。

## 用例与预期

`test/test_queue_api.py` 对 Python 和 Node 使用同一套真实 HTTP 合约，
每个用例创建独立数据目录、临时服务及可终止的辅助进程。

| 编号 / 测试名 | 场景与关键断言 | Python / Node |
| --- | --- | --- |
| CQ-01 `pending_does_not_consume_global_admin_cap` | 普通用户待审批任务不占配额；管理员与用户共享上限；满额审批返回 202、排队第 1 位且无 runtime/token；重复审批 409 | 通过 / 通过 |
| CQ-02 `parallel_creates_and_approvals_never_overbook` | 8 个 HTTP 客户端并发创建和审批 10 个任务，上限 2；最终恰好 2 个运行、8 个排队、无丢失且队列位置为 1–8 | 通过 / 通过 |
| CQ-03 `fifo_and_cancel_queued_then_release` | 取消队列中间任务不创建进程；终止运行任务后最早入队者补位；剩余位置重新计算 | 通过 / 通过 |
| CQ-04 `pause_reserves_capacity_and_resume_does_not_bypass` | 暂停仍占名额；恢复不绕过限额；终止暂停任务后下一项启动 | 通过 / 通过 |
| CQ-05 `background_reaps_success_and_error_without_lifecycle_request` | 辅助进程自然退出 0/7；无需生命周期写请求，后台自动记录 completed/failed、退出码和结束时间并补位 | 通过 / 通过 |
| CQ-06 `queue_bound_invalid_settings_and_partial_update` | 排队上限 1 时第二项入队返回 409，保持待审批；非法配额返回 400；部分更新保留旧配额 | 通过 / 通过 |
| CQ-07 `dynamic_limits_fill_without_killing_existing_tasks` | 提高运行上限立即补位；降低不杀已有任务，直到占用低于上限才继续启动 | 通过 / 通过 |
| CQ-08 `latest_workspace_policy_can_fail_queue_head_without_blocking_next` | 排队后收紧工作区白名单；队首启动前按最新设置检查并 failed，后续合法任务继续运行 | 通过 / 通过 |
| CQ-09 `permissions_and_owner_queue_cancellation` | 普通用户审批 403；陌生用户不可见也不能取消他人任务（404）；所有者可取消排队 | 通过 / 通过 |
| CQ-10 `restart_keeps_unknown_process_reserved_and_queue_persisted` | 重启保留队列和位置；无法确认的运行进程设置 recoveryRequired 并占名额；终止返回 409 | 通过 / 通过 |

调度器单元测试另覆盖：持久化队列顺序不依赖展示顺序、启动失败释放能力且不
阻塞后续任务、非零退出、暂停名额、动态限额、队列满/重复审批、非法设置。
Node 额外验证 Promise 锁在异步审批时不超配，且一次操作拒绝后仍能继续工作。

## 执行命令与实际结果

```bash
python3 -m unittest discover -s apps/safedesk-control-plane/test -p test_scheduler.py -v
node --test apps/safedesk-control-plane/test/scheduler.test.mjs

SAFEDESK_TEST_NODE="$(command -v node)" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s apps/safedesk-control-plane/test -p test_queue_api.py -v

SAFEDESK_TEST_NODE="$(command -v node)" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s apps/safedesk-control-plane/test -p 'test_*.py'

node --test apps/safedesk-control-plane/test/scheduler.test.mjs \
  apps/safedesk-control-plane/test/product.test.mjs \
  apps/safedesk-control-plane/test/auth.test.mjs \
  apps/safedesk-control-plane/test/control-plane.test.mjs \
  apps/safedesk-control-plane/test/launch.test.mjs

node --test apps/safedesk-control-plane/test/*.test.mjs
```

| 检查 | 实际结果 |
| --- | --- |
| Python 调度器 | 7 项通过 |
| Node 调度器 | 8 项通过 |
| 双实现 HTTP 合约 | 20 项全部通过，22.194 秒 |
| Python discover（含双实现 HTTP 合约和 E2E） | 最终 273 项全部通过，86.757 秒 |
| Node 本次涉及模块专项回归 | 135 项全部通过，6.079 秒 |
| Node 全套（初次） | 225 项通过，2 个测试文件失败；详情如下 |
| Node 全套（CI 排查修复后） | 225 项通过，0 失败，5.977 秒 |
| Python py_compile / Node --check / 控制台内嵌脚本语法 | 通过 |
| git diff --check | 通过 |
| make lint | 未完成：本机缺少 rustc、yamlfmt，默认 PATH 也无 node；在 lint-yamlfmt 阶段退出 |

Python 完整回归最初发现 E2E-20 沿用旧版的“重启后直接终止遗留进程”断言。
已改为验证返回 409，符合无法确认进程时保留配额的恢复设计，最终全套通过。

Node 全套的 `broker.test.mjs`、`travelers.test.mjs` 断言均通过，但部分用例在
异步初始化完成前删除临时目录，随后触发 ENOENT/unhandledRejection，使这两个
测试文件失败。使用 `git archive 6c1740c apps/safedesk-control-plane` 导出未修改
基线，在相同环境单独运行这两个文件，复现相同的 12 项通过、2 个文件失败。
后续 CI 排查已修复该测试竞争：两个测试工厂先通过 `listMasked()` 等待初始化
完成，再把实例交给用例。重新运行 Node 全套，225 项全部通过，且无后台
ENOENT/unhandledRejection；没有通过忽略异常或延时来规避问题。

沙箱环境最初禁止绑定本机端口，HTTP 测试曾出现 EPERM；允许临时本机服务后
重新运行，以上结果均为实际执行结果，不将权限失败作为功能失败计数。

## 验证边界

HTTP 测试中的 `wasmer` 是启动真实辅助子进程的 test double，用于验证进程
退出、暂停、终止、状态持久化及并发调度；不是 Wasm 隔离或 CPU/内存压测。
没有连接真实模型服务，没有使用真实 API Key，也没有重新构建 Rust CLI。
未在已有远端测试环境部署本次变更，未进行浏览器视觉验收。

本功能只支持一个控制面进程管理一份数据。跨实例并发、宿主崩溃后进程重附着、
进程启动与 JSON 保存的 exactly-once 保证及进程树资源限额均不在覆盖范围内。
