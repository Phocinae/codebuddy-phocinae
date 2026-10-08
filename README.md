# codebuddy-phocinae

**斑海豹（Phocinae Largha-150M-v1）本地非生成式决策模型 × CodeBuddy 插件**：
Bash 命令审批门（PreToolUse 硬门，deny 优先、fail-closed、全程本地无外联）+
决策提问技能 + 可选 phocinae-mcp 挂载。

> 状态：本地开发包（未发布、未推送）。许可：Apache-2.0。
> 斑海豹是决策模型而非生成模型：它只输出结构化判定与概率，不能当 chat 后端
> 塞进「自定义模型」栏位——请勿混淆。

## 1. 目录结构

```
codebuddy-phocinae/
├── .codebuddy-plugin/          # 仅放 manifest 与市场清单（Claude Code 插件同构规范）
│   ├── plugin.json             # name/version/license + hooks/skills 声明
│   └── marketplace.json        # 自建市场清单（phocinae/codebuddy-marketplace）
├── hooks/
│   ├── hooks.json              # PreToolUse(Bash) → phocinae_gate.py
│   └── phocinae_gate.py        # 审批门 hook（stdlib-only，guard/http 双后端）
├── skills/phocinae-gate/       # 决策提问技能（SKILL.md，与 Claude Code 插件同构）
├── .mcp.json                   # phocinae-mcp stdio 占位模板（可选，见 §5 限制）
├── tests/                      # JSON 校验 + 良性/危险命令自测
├── README.md / LICENSE / CHANGELOG.md
```

## 2. 工作原理

```
Bash 命令
  ├─ L0 确定性表（guard.py 内置；黑名单 deny-wins，白名单放行，~0ms）
  ├─ L1 斑海豹裁决（POST /v1/systemone：guard_noul + guard_score，GPU p50 18.6ms）
  └─ 阈值映射：score≥7 或 noul=false → deny；score≥4 / noul 摇摆 → ask；否则 allow
不可变式：只有 allow 能过门；deny/ask 非零退出；后端崩溃/超时 → exit 2 硬阻断
（fail-closed，绝不自动放行）。
```

hook 层在权限系统之上：即使 bypass/yolo 模式，PreToolUse 的 deny 依然拦截
（OGR 实测结论）。判定理由回注给模型（permissionDecisionReason），引导它改方案
而非原地重试。

## 3. 安装

前置：`python3`（≥3.8）；phocinae-guard（默认
`/home/hermes/dev/phocinae-guard/guard.py`，可经 `PHOCINAE_GATE_GUARD` 改路径）；
可选 phocinae-server（127.0.0.1:8155，起服务后灰区命令才走模型裁决）。

- 方式一 · 本地开发：CodeBuddy 插件目录直接指向本仓（`/plugin` 本地目录加载），
  hooks 与 skills 随插件启用即生效。
- 方式二 · 自建市场（待发布后）：发布到
  `phocinae/codebuddy-marketplace` 后，
  `/plugin marketplace add phocinae/codebuddy-marketplace` →
  `/plugin install codebuddy-phocinae@phocinae-codebuddy-marketplace`。

## 4. 配置

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `PHOCINAE_GATE_MODE` | `guard` | 裁决后端：`guard`（L0+L1+fail-closed）或 `http`（直连 /v1/systemone，仅 L1） |
| `PHOCINAE_GATE_GUARD` | `/home/hermes/dev/phocinae-guard/guard.py` | guard 脚本路径 |
| `PHOCINAE_GATE_SERVER` | `http://127.0.0.1:8155` | L1 服务基地址 |
| `PHOCINAE_GATE_TIMEOUT` | `2.0` | http 模式超时秒数 |
| `PHOCINAE_GATE_NOUL_THRESHOLD` | `0.65` | noul 放行阈值 |
| `PHOCINAE_GATE_DENY_AT` / `_ASK_AT` | `7.0` / `4.0` | score 风险线 |

guard 模式透传 `PHOCINAE_GUARD_*` 全部环境变量（L1 开关、fail-closed 策略、
审计路径、自定义 L0 表等——见 phocinae-guard README）。

## 5. 安全声明与已知限制

- **deny 优先**：L0 黑名单 deny-wins；hook deny 在任何阈值下不可覆盖。
- **fail-closed**：guard/http 崩溃、超时、应答畸形 → exit 2 硬阻断，绝不静默放行。
- **本地**：服务仅监听 127.0.0.1；无外联；审计 JSONL 本地落盘（默认
  `<cwd>/phocinae-guard.audit.jsonl`）。
- **L1 默认关闭**：150M 权重未做命令审批域校准（实测信号≈噪声），灰区一律
  fail-closed=deny——这是保守策略，不是故障；需要模型裁决时由管理员显式开
  `PHOCINAE_GUARD_L1_ENABLED=true`（P1 需领域微调 + 标定电池）。
- **时延**：L0 毫秒级；L1 本机 GPU p50 18.6ms / CPU 数十至数百 ms（blocking hook
  预算 <~150ms 时建议 GPU 或收紧白名单）。
- **`.mcp.json` 为占位模板**：phocinae-mcp（对应 seal-mcp 仓）尚未发布，
  实际包名以发布为准；为避免插件启用即拉起未发布包，plugin.json 暂未声明
  `mcpServers` 字段——seal-mcp 落地后在 plugin.json 补 `"mcpServers": "./.mcp.json"`
  即可生效。
- 斑海豹拒绝 ≠ 终止：升级路径 = 人工确认 / 更强模型复核。

## 6. 自测

```bash
bash tests/run_tests.sh
```

含：全部 JSON 解析校验；hook 自测（良性命令=allow/exit 0，危险命令=deny/exit 1，
灰区=不自动放行）；8155 服务在线时追加 http 模式与 guard-L1 冒烟。

## 7. License

Apache-2.0（见 LICENSE）。模型权重许可另案（HF `Phocinae/` 命名空间模型卡）。
