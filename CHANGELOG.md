# Changelog

本文件按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 维护；
版本号遵循语义化版本。

## [Unreleased]

### Fixed
- guard.py 路径不再硬编码作者机器上的绝对路径。解析顺序：
  `PHOCINAE_GATE_GUARD` → 插件根自带/同级副本（`CODEBUDDY_PLUGIN_ROOT` 或
  `__file__` 上溯）→ 本地 HTTP 服务（stderr 明示 L0 表未生效）→ exit 2 并给出
  可复制的设置示例。显式设置的路径若不存在则直接阻断，不静默改用别的 guard。
- hook 不再往用户项目目录写审计文件：未显式设置时落到用户级
  `~/.phocinae-guard/audit.jsonl`（`PHOCINAE_GATE_AUDIT=off|<路径>` 可控，
  guard 原生的 `PHOCINAE_GUARD_AUDIT` 优先）。
- `hooks/hooks.json` 的命令以 `|| exit 2` 收尾：解释器缺失在上游是「非阻断错误」
  （fail-open，工具调用照常执行），现在变成 exit 2 硬阻断；README 给出 Windows
  （`python` / `py -3`）与 POSIX 的确切配置。
- 文档串与实际协议不符：判定经 stdout JSON 的 `permissionDecision` 传递
  （allow/deny/ask 都可能配 exit 0），exit 2 只表示「本 hook 无法裁决」。代码不变，
  注释与 README 已对齐。
- guard 子进程 stdout/stderr 固定 UTF-8（`PYTHONIOENCODING`）：Windows 默认按
  ANSI 代码页写，text 模式读取会在读线程抛 UnicodeDecodeError，判定理由丢失、只剩
  退出码。hook 自身 stdout/stderr 也固定 UTF-8，避免上游按 UTF-8 解出乱码。

### Added
- `tests/test_gate_hook.py`：上述缺陷的常驻回归（B7 路径解析 / B8 审计位置 /
  B9 解释器 fail-closed / B20 协议），默认不写用户目录。
- `tests/run_tests.sh`：解释器探测（`PHOCINAE_GATE_PYTHON` → `python3`/`python`/`py`），
  并接入上面的回归套件。

## [0.1.0] - 2026-10-08

### Added
- `.codebuddy-plugin/plugin.json`：插件 manifest（name/version/license + hooks/skills 声明）。
- `.codebuddy-plugin/marketplace.json`：自建市场清单（phocinae/codebuddy-marketplace 规范）。
- `hooks/hooks.json` + `hooks/phocinae_gate.py`：PreToolUse(Bash) 审批门 hook，
  guard / http 双裁决后端，fail-closed（exit 2 硬阻断）。
- `skills/phocinae-gate/SKILL.md`：决策提问技能（与 Claude Code 插件同构）。
- `.mcp.json`：phocinae-mcp stdio 挂载模板。
- `tests/validate_json.py` + `tests/run_tests.sh`：JSON 校验与良性/危险命令自测。
- README.md（中文）与 Apache-2.0 LICENSE。

### 说明
- 本地开发包：未发布、未推送（红线约束）。
- 组件目录位于插件根（`hooks/`、`skills/`），`.codebuddy-plugin/` 内仅 manifest 与
  marketplace 清单——与 Claude Code 插件目录规范同构。
