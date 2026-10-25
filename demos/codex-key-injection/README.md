# Codex 金额计算修复任务

此目录包含故意有错的输入项目、18 个验收测试、任务提示词和 Codex 配置模板。
仅需 Python 3.9+ 即可复现业务测试；检查 TOML 需 Python 3.11+ 的 `tomllib`。
完整的 [Case 07](../07-codex-key-injection.md) 还要求隔离执行器、模型网关和
Responses API 服务，这些运行能力不包含在此测试素材中。

## 无 Key 验证初始素材

在仓库根目录执行：

```bash
python3 demos/tools/check_codex_fixture.py
```

成功退出码为 0，表示 18 个测试中 3 个通过、15 个方法按预期失败。
此检查不调用模型，也不验证 Key 注入。
可选 [CI 模板](ci-workflow.yaml.example) 会运行同一检查并解析 TOML，
不会将故意失败的业务测试当作 CI 回归。模板当前未启用；有工作流管理
权限的维护者可将其复制为 `.github/workflows/codex-case.yaml`。

## 为每次修复准备独立工作区

在仓库根目录执行；工作区不能放入控制面凭据或其他项目文件：

```bash
CASE_DIR="$PWD/demos/codex-key-injection"
CASE_WORKSPACE=$(mktemp -d "${TMPDIR:-/tmp}/safedesk-codex.XXXXXX")
cp "$CASE_DIR/fixture/pricing.py" "$CASE_DIR/fixture/test_pricing.py" "$CASE_WORKSPACE/"
cd "$CASE_WORKSPACE"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_pricing.py
```

最后一条命令应退出 1：业务实现故意忽略数量、将折扣当作加价、未验证输入。
将工作区交给隔离执行器，并使用 `prompt.txt`；不要直接将整个仓库挂给 Agent。
`test_pricing.py` 和提示词应只读，只有 `pricing.py` 允许修改。

## 修复后的外部验收

在同一个隔离运行环境中，由执行器核对测试文件未变，再独立运行测试：

```bash
cmp "$CASE_DIR/fixture/test_pricing.py" "$CASE_WORKSPACE/test_pricing.py"
diff -u "$CASE_DIR/fixture/pricing.py" "$CASE_WORKSPACE/pricing.py"
cd "$CASE_WORKSPACE"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v test_pricing.py
```

预期 `cmp` 退出 0，`diff` 退出 1 且只显示业务修复，最后 unittest 退出 0、
18 个测试全部通过。`diff` 的 1 表示有差异，不能被流水线当作验收命令失败。
执行器应在 Agent 运行环境外保留可信测试副本，并确保比较失败时中止验收。
上面是逐条运行的步骤，不是遇错自动停止的脚本。不要在持有凭据的主机上
直接执行不可信的修复结果；Python 测试运行本身不提供隔离。

测试涵盖：数量、十进制精度、0/100% 和小数折扣、只舍入最终总额、
ROUND_HALF_UP、非法数量、负价、非有限值与折扣越界。它们验证约定的金额
行为，不证明实现一定使用 Decimal，也不证明模型调用和凭据隔离。

## 运行记录

每轮保留 CLI 版本、镜像 digest、任务 ID、测试前后结果、测试文件哈希、
`pricing.py` diff、Codex 退出码/完成事件和网关请求状态。禁止记录真实 Key、
任务 token 或 Authorization。完整安全验收见 Case 07 的验收表。
