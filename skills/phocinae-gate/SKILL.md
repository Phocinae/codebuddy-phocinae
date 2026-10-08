---
name: phocinae-gate
description: 斑海豹审批门协作与决策提问技能。用于：执行风险 Bash 命令前的自检预判、被审批门 deny/ask 后的行为准则、用 /v1/systemone 协议提出结构化决策问题（noul/score/choice）、理解 L0/L1 判定管线与阈值。当即将运行命令、命令被拦截、或需要模型级风险裁决时加载本技能。
---

# phocinae-gate（斑海豹审批门协作技能）

斑海豹（Phocinae Largha-150M-v1）是本地非生成式决策模型：只输出结构化判定与概率，
不做对话生成。本插件把它装成 CodeBuddy 的 Bash 命令审批门（PreToolUse 硬门），
本技能教你在门存在的前提下如何高效协作、如何主动提问。

## 1. 门的判定管线（理解它，别对抗它）

```
Bash 命令 → L0 确定性表（~0ms，无模型）
   ├─ 黑名单命中（rm -rf /、sudo dd、curl|sh、git push -f、fork bomb…）→ deny
   ├─ 白名单/白名单前缀命中（ls/cat/grep/git status/pytest…）→ allow
   └─ 灰区 → L1 斑海豹裁决（POST /v1/systemone，guard_noul + guard_score 双问）
        └─ L1 未启用（当前默认，150M 权重未做命令审批域校准）→ fail-closed=deny
```

阈值映射（双通道合成取最严格）：
- score 风险期望：≥7 → deny；≥4 且 <7 → ask；<4 → allow 通道
- noul「是否需要人工检查」：P(true)≥0.65 → allow 通道；P(false)≥0.65 → deny；
  中间带 → ask
- **不可变式：只有 allow 能过门；deny 优先；后端崩溃/超时 → 硬阻断（fail-closed）**

## 2. 执行命令前的自检（推荐姿势）

- 运行风险命令前，先本地预判（L0 表免费、毫秒级）：

  ```bash
  python3 /home/hermes/dev/phocinae-guard/guard.py --command '要跑的命令' --text
  ```

  exit 0 = 会放行；exit 1 = 会被 deny；exit 2 = 会被 ask。
- 被拦了不要原地重试同款命令（换参数/换写法绕门 = 对抗行为，会被视为风险信号）。
  正确姿势：改方案（换更窄的路径、加分步验证、用白名单工具链），或在理由里说明
  「这条命令是任务必需的、为什么安全」等待人工确认（ask → 人工点头即放行）。
- deny 不可被 --confirm 覆盖；ask 可升级。模型拒绝 ≠ 终止：升级路径 = 人工确认。

## 3. 决策提问范式（/v1/systemone）

当需要模型级裁决时（路由、风险、取舍、是否保留上下文等），直接 POST
`http://127.0.0.1:8155/v1/systemone`（本地服务，或经 phocinae-mcp）：

```json
{
  "model": "Phocinae-Largha-150M-v1",
  "state": "{\"command\":\"git push --force\",\"cwd\":\"/repo\"}",
  "questions": [
    {"id": "q_noul", "type": "noul", "threshold": 0.65,
     "criteria": {"false": "此操作安全、无需人工检查", "true": "此操作需要人工检查"}},
    {"id": "q_score", "type": "score",
     "instructions": "评估该操作的风险等级（0=无风险 … 10=灾难性）"}
  ]
}
```

题型：`noul`（是/否判断，回概率 + threshold 二值化）、`score`（0..10 风险期望）、
`choice`（选项分发，回选项概率分布）。返回 `answers.<id>`（noul/score/probabilities）
+ `answer_confidence`。**阈值与门控逻辑由应用侧持有，模型只给概率**——这是
TypeSafe 协议一以贯之的原则，提问时请遵守：不要请模型替你直接做 allow/deny 决定。

## 4. 与 Claude Code 版同构

本技能与 Claude Code 插件（seal-guard 仓，`.claude-plugin/`）的审批门技能同构：
同一 guard.py、同一 /v1/systemone 协议、同一阈值表。两边学到的协作习惯可以互换。

## 5. 故障排查

- 一切灰区命令被 deny：L1 默认关闭（fail-closed）→ 属预期；需要模型裁决时由管理员
  置 `PHOCINAE_GUARD_L1_ENABLED=true` 并确保 8155 服务在线。
- 服务器不可达：门不自动放行（fail-closed），先起服务再重试。
- 审计：guard 判定逐条写入 JSONL（默认 `<cwd>/phocinae-guard.audit.jsonl`，
  可经 `PHOCINAE_GUARD_AUDIT` 改路径）。
