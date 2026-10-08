# Changelog

本文件按 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 维护；
版本号遵循语义化版本。

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
