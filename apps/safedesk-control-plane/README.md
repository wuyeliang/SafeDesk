# SafeDesk Control Plane

企业级 Agent 安全沙箱的控制面。它不把密钥写进沙箱，也不让用户面对底层运行时参数。用户只选择 Agent、项目目录和能力，其余由策略编译器生成启动清单。

The enterprise control plane for SafeDesk. Secrets never enter the sandbox, and users never configure low-level runtime flags. They only choose the agent, workspace, and capabilities; the policy compiler produces the launch plan.

## 产品原则 / Product principles

1. **安全优先 / Security first**：默认拒绝文件系统、网络和环境变量；密钥永远留在主机凭据代理。
2. **最终用户友好 / End-user friendly**：配置只问“谁来跑、能碰哪、要哪些能力”。
3. **主流 Agent 可运行 / Mainstream agents**：Claude Code、Codex、DSH 走同一套沙箱生命周期。
4. **MCP 不填敏感信息 / No secrets in MCP config**：沙箱内只看到占位符和网关地址，真实 API Key / Password 由主机代签。

## 本地运行 / Local run

推荐在具备 Node.js 20+ 的环境运行：

```bash
cd apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 node server.mjs
```

当前开发机未安装 Node.js，使用零依赖 Python 控制面：

```bash
cd /opt/safedesk/apps/safedesk-control-plane
PORT=8022 HOST=0.0.0.0 python3 server.py
```

开发机公网入口 / public endpoints（HTTPS，自签证书）：

- https://218.11.5.249:10648/
- https://111.62.156.213:10645/

两者都映射到内网 `8022`。控制面默认开启登录：手机号验证码、微信扫码（本地二维码工单）和管理员账户。普通用户只能看到自己的沙箱，审批与安全事件仅管理员可见。工作台还提供总览指标、任务模板、搜索筛选、审批拒绝、暂停恢复和组织设置。

默认管理员 / default admin：`admin` / `SafeDesk@Admin`（首次登录后可在控制台修改，重启不会恢复默认密码）

可用环境变量覆盖：`SAFEDESK_ADMIN_USERNAME`、`SAFEDESK_ADMIN_PASSWORD`、`SAFEDESK_ADMIN_PHONES`。`SAFEDESK_ADMIN_PASSWORD` 只用于首次创建管理员账户。

若公网入口已配置 TLS 证书，设置：

```bash
SAFEDESK_TLS_CERT=/etc/safedesk/tls/cert.pem
SAFEDESK_TLS_KEY=/etc/safedesk/tls/key.pem
```

## 验证 / Tests

```bash
cd apps/safedesk-control-plane
node --test test/*.test.mjs
```

底层隔离运行时说明见 [docs/safedesk/RUNTIME.md](../../docs/safedesk/RUNTIME.md)。

组织级并发上限默认 8（暂停任务保留名额），管理员也遵守；审批通过后按 FIFO
排队，默认最多排队 100 项。待审批任务不占运行名额。设置、状态转换、重启
恢复及回滚规则见[并发与排队设计](../../docs/safedesk/CONCURRENCY-QUEUE.md)，
执行命令和用例结果见[测试记录](../../docs/safedesk/CONCURRENCY-QUEUE-TESTS.md)。
