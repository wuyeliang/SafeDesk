# SafeDesk Demos / 演示案例

演示场景覆盖 SafeDesk 控制面的沙箱生命周期与安全边界。各案例标注前置条件、可运行步骤和待实现能力。

Scenarios covering the SafeDesk sandbox lifecycle and security guardrails, with prerequisites, reproducible steps, and implementation gaps documented per case.

| Demo | 场景 | 看点 |
| ---- | ---- | ---- |
| [01-readonly-review](./01-readonly-review.md) | 只读审阅 | `review` 策略：工作区只读、网络禁用，适合依赖审计 |
| [02-balanced-dev](./02-balanced-dev.md) | 标准研发 | `balanced` 策略：凭据 Broker 代签 + MCP 网关白名单 |
| [03-restricted-build](./03-restricted-build.md) | 受限构建 | `build` 策略：临时工作区 + 出网白名单复核 |
| [04-guardrails](./04-guardrails.md) | 防护与拒绝路径 | 400 / 404 / 409：不合法输入与非法状态跳转被拒 |
| [05-private-takeout](./05-private-takeout.md) | 外卖隐私下单 | 隐私帘：别名替身 + PII 脱敏 + 支付凭据代签，平台拿不到真实身份和支付信息 |
| [06-ctrip-corporate-travel](./06-ctrip-corporate-travel.md) | 携程公务出行订票 | 出行人卡片：实名出票信息主机侧托管，仅对携程白名单解析注入，平台拿不到员工账户画像和支付渠道 |
| [07-codex-key-injection](./07-codex-key-injection.md) | Codex 修复金额计算 | 官方 CLI + 主机侧 Key 注入的设计与验收任务；Linux 执行器和模型网关待实现 |

## 前置条件 / Prerequisites

1. 启动控制面（三选一）：

```bash
# 本机 Node.js 20+
cd apps/safedesk-control-plane
PORT=18022 HOST=0.0.0.0 node server.mjs
```

```bash
# 本机零依赖 Python
cd apps/safedesk-control-plane
PORT=18022 HOST=0.0.0.0 python3 server.py
```

```bash
# 或直接用已部署的开发机
# 不需要启动任何东西，下一步把 BASE 指向公网入口即可
```

2. 设置请求根地址（每条 demo 的第一步都假设它已设置）：

```bash
# 本机
BASE=http://127.0.0.1:18022

# 开发机公网入口（任选其一，HTTPS 自签证书）
BASE=https://218.11.5.249:10648
BASE=https://111.62.156.213:10645
```

3. 登录管理员并导出 token（后续命令都带这个头）：

```bash
curl -s -X POST $BASE/api/auth/admin/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"SafeDesk@Admin"}'
TOKEN=<返回的 token>
```

管理员可在控制台组织设置中修改默认密码；改密后重启服务不会恢复默认值。API 示例：

```bash
curl -s -X POST $BASE/api/auth/password \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"currentPassword":"SafeDesk@Admin","newPassword":"<new-password>"}'
```

4. 确认服务存活：

```bash
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/bootstrap | head -c 200
```

预期返回以 `{"user":` 开头的 JSON，包含 `balanced` / `review` / `build` 三个策略。未登录访问应返回 HTTP 401。

## 说明

- 每个 demo 的第一步都是创建沙箱，返回的 `sandbox.id` 形如 `sbx-xxxxxxxx`，后续命令把该值代入 `<SBX>`。
- 所有写操作都会在内置安全事件流里留下记录，可用 `curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/events` 随时查看。
- 演示只调用 HTTP API，不会在本机真正拉起隔离沙箱；审批 = 授权执行器按清单启动。
- 普通用户（手机号 / 微信）只能看到自己的沙箱，不能审批；管理员才能审批和查看安全事件。
