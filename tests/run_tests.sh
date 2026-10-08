#!/usr/bin/env bash
# codebuddy-phocinae 本地自测（纯 CPU；不推送、不发布）。
# 用法：bash tests/run_tests.sh
# 可选：起真实 phocinae-server 于 127.0.0.1:8155 后，追加 http 模式与 guard-L1 冒烟。
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
PASS=0
FAIL=0
# 测试态不向仓库目录写审计文件（真实 hook 运行不受影响）
export PHOCINAE_GUARD_AUDIT=off

step() {  # step <名称> <命令...>
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    PASS=$((PASS + 1)); echo "PASS  $name"
  else
    FAIL=$((FAIL + 1)); echo "FAIL  $name"
  fi
}

echo "== 1. 全部 JSON 解析 + manifest 断言 =="
step "validate_json" python3 tests/validate_json.py

echo "== 2. hook 自测（guard 模式）：良性=allow / 危险=deny / 灰区=不自动放行 =="
step "hook_self_test_guard" python3 hooks/phocinae_gate.py --self-test

echo "== 3. hook 端到端（合成 PreToolUse 载荷走 stdin；断言 rc + permissionDecision）=="
# hook 协议：进程 rc=0 表示裁决送达（JSON 里给 permissionDecision）；rc=2=硬阻断。
hook_res() {  # hook_res <command> → "rc decision"
  local out rc dec
  out="$(printf '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"%s"}' \
    "$1" "$ROOT" | python3 hooks/phocinae_gate.py 2>/dev/null)"
  rc=$?
  dec="$(printf '%s' "$out" | python3 -c 'import sys, json
try:
    print(json.load(sys.stdin).get("hookSpecificOutput", {}).get("permissionDecision", "?"))
except Exception:
    print("?")')"
  echo "$rc $dec"
}
BENIGN="$(hook_res "git status")"
if [ "$BENIGN" = "0 allow" ]; then
  PASS=$((PASS + 1)); echo "PASS  e2e 良性 git status → rc=0 allow"
else
  FAIL=$((FAIL + 1)); echo "FAIL  e2e 良性 git status → 「$BENIGN」（期望 0 allow）"
fi
DANGER="$(hook_res "rm -rf /")"
if [ "$DANGER" = "0 deny" ]; then
  PASS=$((PASS + 1)); echo "PASS  e2e 危险 rm -rf / → rc=0 deny"
else
  FAIL=$((FAIL + 1)); echo "FAIL  e2e 危险 rm -rf / → 「$DANGER」（期望 0 deny）"
fi
GRAY="$(hook_res "python3 app.py")"
case "$GRAY" in
  "0 deny"|"0 ask"|"2 ?"|"2 ") PASS=$((PASS + 1)); echo "PASS  e2e 灰区 python3 app.py → 「$GRAY」（不自动放行）";;
  *) FAIL=$((FAIL + 1)); echo "FAIL  e2e 灰区 python3 app.py → 「$GRAY」（期望 deny/ask/阻断）";;
esac
BLOCK="$(PHOCINAE_GATE_GUARD=/nonexistent/guard.py hook_res "git status" | cut -d' ' -f1)"
if [ "$BLOCK" = "2" ]; then
  PASS=$((PASS + 1)); echo "PASS  e2e fail-closed：guard 不存在 → rc=2 硬阻断"
else
  FAIL=$((FAIL + 1)); echo "FAIL  e2e fail-closed：guard 不存在 → rc=$BLOCK（期望 2）"
fi

echo "== 4. 可选：8155 服务在线时的 http 模式与 guard-L1 冒烟 =="
if curl -s -m 2 http://127.0.0.1:8155/health >/dev/null 2>&1; then
  echo "检测到 127.0.0.1:8155 服务在线，运行 http 模式自测（报告型）"
  PHOCINAE_GATE_MODE=http python3 hooks/phocinae_gate.py --self-test
  HTTP_SELF=$?
  if [ "$HTTP_SELF" = "0" ]; then
    PASS=$((PASS + 1)); echo "PASS  hook_self_test_http"
  else
    FAIL=$((FAIL + 1)); echo "FAIL  hook_self_test_http（exit $HTTP_SELF）"
  fi
  echo "guard-L1 冒烟（PHOCINAE_GUARD_L1_ENABLED=true，灰区命令走模型）"
  PHOCINAE_GUARD_L1_ENABLED=true python3 hooks/phocinae_gate.py --self-test
  L1_SELF=$?
  if [ "$L1_SELF" = "0" ]; then
    PASS=$((PASS + 1)); echo "PASS  hook_self_test_guard_l1"
  else
    FAIL=$((FAIL + 1)); echo "FAIL  hook_self_test_guard_l1（exit $L1_SELF）"
  fi
else
  echo "SKIP 127.0.0.1:8155 无服务：跳过 http/L1 冒烟（起 phocinae-server 后重跑）"
fi

echo ""
echo "== 汇总：PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" = "0" ]
