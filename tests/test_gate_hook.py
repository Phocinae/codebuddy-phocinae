#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""codebuddy-phocinae hook 回归自测（B7 / B8 / B9 / B20）。

纯标准库、跨平台（Windows 与 POSIX 都能跑）：

    python tests/test_gate_hook.py          # Windows / 通用
    python3 tests/test_gate_hook.py         # POSIX

不写用户目录：每次跑 hook 都把 HOME / USERPROFILE 指向临时目录，审计只落在
临时目录里；真实用户目录与仓库目录都不会被写入。

exit 0 = 全部通过；非 0 = 有失败项。
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
HOOK = os.path.join(REPO, "hooks", "phocinae_gate.py")
HOOKS_JSON = os.path.join(REPO, "hooks", "hooks.json")

CHECKS = []   # (name, ok, detail)
TMP = None

# Windows 控制台默认 GBK：把 stdout/stderr 固定成 utf-8，免得中文/替换字符
# 让「测试结果打印」本身抛 UnicodeEncodeError。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def chk(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))


def skip(name, detail):
    CHECKS.append((name, None, detail))


def hook_env(extra=None, home=None):
    env = dict(os.environ)
    for key in ("PHOCINAE_GATE_GUARD", "PHOCINAE_GATE_MODE", "PHOCINAE_GATE_SERVER",
                "PHOCINAE_GATE_AUDIT", "PHOCINAE_GUARD_AUDIT",
                "CODEBUDDY_PLUGIN_ROOT", "CLAUDE_PLUGIN_ROOT"):
        env.pop(key, None)
    if home:
        # os.path.expanduser('~') 认这两个变量：POSIX 用 HOME，Windows 用 USERPROFILE
        env["HOME"] = home
        env["USERPROFILE"] = home
    if extra:
        env.update(extra)
    return env


def run_hook(command, cwd, env, script=HOOK):
    payload = json.dumps({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": cwd,
    })
    # encoding 固定 utf-8：Windows 默认按 ANSI 代码页解码，中文报错会直接抛
    # UnicodeDecodeError（把回归测试变成环境事故）。
    proc = subprocess.run([sys.executable, script], input=payload,
                          encoding="utf-8", errors="replace",
                          capture_output=True, env=env, cwd=cwd, timeout=60)
    decision = None
    try:
        decision = json.loads(proc.stdout or "{}").get(
            "hookSpecificOutput", {}).get("permissionDecision")
    except ValueError:
        decision = None
    return proc.returncode, decision, proc.stdout or "", proc.stderr or ""


STUB_GUARD = '''\
import json, os, sys


def _force_utf8_stdio():
    """把 stdout/stderr 固定为 UTF-8。

    本脚本会打印中文诊断；Windows 上 Python 默认用控制台代码页
    （GitHub Actions runner 是 cp1252/437，本机可能是 cp936），
    非 ASCII 直接抛 UnicodeEncodeError 让整个步骤失败。
    这里不依赖调用方设 PYTHONUTF8：自己兜住。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


_force_utf8_stdio()


def main(argv):
    cmd, cwd = "", ""
    for i, arg in enumerate(argv):
        if arg == "--command" and i + 1 < len(argv):
            cmd = argv[i + 1]
        elif arg == "--cwd" and i + 1 < len(argv):
            cwd = argv[i + 1]
    if "rm -rf /" in cmd or "| sh" in cmd or cmd.strip().startswith("del "):
        decision, rc = "deny", 1
    elif cmd.strip() == "git status" or cmd.strip().startswith("git status "):
        decision, rc = "allow", 0
    else:
        decision, rc = "ask", 2
    path = os.environ.get("PHOCINAE_GUARD_AUDIT", "")
    if path and path.lower() not in ("off", "none"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"command": cmd, "cwd": cwd,
                                 "decision": decision, "layer": "L0",
                                 "reason": "stub"}) + "\\n")
    sys.stdout.write(json.dumps({"decision": decision,
                                 "reason": "stub:" + decision}) + "\\n")
    return rc

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def _shell_works(argv):
    """真实跑一次「什么都没做」的命令，确认这个 shell 在本环境下可用。

    为什么要探测：Windows + Git-for-Windows 的 sh 在 HOME 被设成非 POSIX
    路径（例如测试把 HOME 重定向到临时目录）时，启动阶段就会退出 1，
    根本不会解析后面的命令。那样测的就不是 hook 契约，而是环境。
    """
    try:
        proc = subprocess.run(argv + ["exit 0"], capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


def shell_available():
    """返回 (argv 前缀, 说明) 用于把命令字符串交给一个真实 shell。

    Windows 上优先用原生 cmd.exe：它一定存在，且不受 HOME/MSYS 路径影响。
    POSIX 上用 sh。两条路都先探测可用性，避免把环境问题当成契约回归。
    """
    candidates = []
    if os.name == "nt":
        comspec = os.environ.get("ComSpec") or shutil.which("cmd")
        if comspec:
            candidates.append(([comspec, "/d", "/s", "/c"], "cmd"))
    for name in ("sh", "bash"):
        exe = shutil.which(name)
        if exe:
            candidates.append(([exe, "-c"], name))
    for argv, label in candidates:
        if _shell_works(argv):
            return argv, label
    return None, ""


def manifest_command():
    with open(HOOKS_JSON, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    return manifest[0]["hooks"][0]["command"]


def script_path_from_command(command):
    """从 manifest 命令里取出 $CODEBUDDY_PLUGIN_ROOT/ 之后的脚本相对路径。"""
    marker = "$CODEBUDDY_PLUGIN_ROOT/"
    if marker not in command:
        return None
    tail = command.split(marker, 1)[1]
    for quote in ('"', "'"):
        if quote in tail:
            tail = tail.split(quote, 1)[0]
    return tail.strip() or None


def audit_files(directory):
    return [name for name in os.listdir(directory) if "audit" in name.lower()]


def main():
    global TMP
    TMP = tempfile.mkdtemp(prefix="cbc-phocinae-hook-", dir=tempfile.gettempdir())
    try:
        check_manifest()
        check_b7_resolution()
        check_b8_audit()
        check_b9_interpreter()
        check_b20_protocol()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)

    fails = 0
    skipped = 0
    for name, ok, detail in CHECKS:
        label = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        print("%-4s %-44s %s" % (label, name, "" if ok else detail))
        fails += (ok is False)
        skipped += (ok is None)
    print("test_gate_hook: %d/%d 通过（%d 跳过）"
          % (len(CHECKS) - fails - skipped, len(CHECKS) - skipped, skipped))
    return 1 if fails else 0


# ------------------------------------------------------------------ manifest

def check_manifest():
    command = manifest_command()
    rel = script_path_from_command(command)
    chk("hook.command 引用脚本存在",
        rel is not None and os.path.isfile(os.path.join(REPO, rel)),
        "command=%r → %r" % (command, rel))
    # B9：解释器找不到在上游是「非阻断错误」＝放行，所以必须以 exit 2 收尾。
    chk("hook.command 解释器缺失时 fail-closed（|| exit 2）",
        command.rstrip().endswith("|| exit 2"),
        "command=%r（必须以 `|| exit 2` 结尾，否则 spawn 失败会 fail-open）" % command)
    chk("hook.command 不含作者机器路径",
        "/home/" not in command and "C:\\Users\\" not in command, command)

    shell, label = shell_available()
    if shell is None:
        skip("hook.command 缺解释器 → 真实 shell 退出码 2", "no sh/cmd available")
        return
    # 把命令里的解释器换成一个必然不存在的名字，模拟「机器上没有这个解释器」。
    broken = re.sub(r"^\S+", "phocinae-no-such-interpreter-xyz", command)
    broken = broken.replace("$CODEBUDDY_PLUGIN_ROOT", REPO)
    # 该断言考的是「shell 解析到 `||` 并把缺失解释器变成 exit 2」这一语义。
    # shell_available() 已按可用性探测（Windows 优先原生 cmd.exe），所以正常
    # 情况下一次就过；这里保留少量重试只为吸收进程创建的偶发抖动，
    # 真正的语义回归（稳定非 2）依然会失败。
    attempts = []
    for _ in range(3):
        proc = subprocess.run(shell + [broken], encoding="utf-8", errors="replace",
                              capture_output=True, cwd=TMP, timeout=60)
        attempts.append(proc.returncode)
        if proc.returncode == 2:
            break
        time.sleep(0.3)
    chk("hook.command 缺解释器 → 真实 shell 退出码 2（%s）" % label,
        attempts[-1] == 2,
        "rc attempts=%r stdout=%r stderr=%r" % (attempts, (proc.stdout or "")[:120],
                                                (proc.stderr or "")[:200]))


# ------------------------------------------------------------------------ B7

def check_b7_resolution():
    stub = os.path.join(TMP, "stub_guard.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write(STUB_GUARD)
    home = os.path.join(TMP, "home")
    work = os.path.join(TMP, "project")
    os.makedirs(home, exist_ok=True)
    os.makedirs(work, exist_ok=True)

    # 1) 显式环境变量优先
    rc, decision, _, err = run_hook("git status", work,
                                    hook_env({"PHOCINAE_GATE_GUARD": stub}, home))
    chk("B7 显式 PHOCINAE_GATE_GUARD 生效",
        rc == 0 and decision == "allow",
        "rc=%r decision=%r stderr=%r" % (rc, decision, err[:200]))

    # 2) 显式设了但文件不存在 → 阻断并点名环境变量（不静默换 guard）
    rc, decision, out, err = run_hook(
        "git status", work,
        hook_env({"PHOCINAE_GATE_GUARD": os.path.join(TMP, "nope", "guard.py")}, home))
    chk("B7 显式路径不存在 → exit 2 且点名 PHOCINAE_GATE_GUARD",
        rc == 2 and decision is None and "PHOCINAE_GATE_GUARD" in err,
        "rc=%r decision=%r stderr=%r" % (rc, decision, err[:200]))

    # 3) 完全没有 guard、没有任何环境变量（模拟别人机器上的插件安装）：
    #    要么成功裁决，要么给出可复制的设置指引 + 非零退出；绝不静默放行。
    fake_root = os.path.join(TMP, "installed", "codebuddy-phocinae")
    os.makedirs(os.path.join(fake_root, "hooks"), exist_ok=True)
    shutil.copy2(HOOK, os.path.join(fake_root, "hooks", "phocinae_gate.py"))
    installed_hook = os.path.join(fake_root, "hooks", "phocinae_gate.py")
    rc, decision, out, err = run_hook("git status", work, hook_env(None, home),
                                      script=installed_hook)
    actionable = ("PHOCINAE_GATE_GUARD" in err and "export PHOCINAE_GATE_GUARD"
                  in err)
    ok = (rc == 0 and decision in ("allow", "deny", "ask")) or (rc != 0 and actionable)
    chk("B7 无环境变量：要么裁决成功，要么 exit≠0 + 可复制指引",
        ok and not (rc == 0 and decision is None),
        "rc=%r decision=%r stderr=%r" % (rc, decision, err[:300]))
    if rc != 0:
        chk("B7 设置示例含 PowerShell 与 bash 两种写法",
            "PowerShell" in err and "bash/zsh" in err, err[:300])

    # 4) 作者机器路径泄漏回归
    needle = "/home/" + "hermes"
    leaks = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            path = os.path.join(root, name)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    if needle in fh.read():
                        leaks.append(os.path.relpath(path, REPO))
            except OSError:
                pass
    chk("B7 仓库内无 /home/<author> 机器路径", not leaks, "命中: %s" % leaks)


# ------------------------------------------------------------------------ B8

def check_b8_audit():
    stub = os.path.join(TMP, "stub_guard.py")
    home = os.path.join(TMP, "home")
    work = os.path.join(TMP, "project")
    user_audit = os.path.join(home, ".phocinae-guard", "audit.jsonl")

    before = audit_files(work)
    rc, decision, _, err = run_hook("git status", work,
                                    hook_env({"PHOCINAE_GATE_GUARD": stub}, home))
    chk("B8 运行 hook 不在项目目录产生审计文件",
        not audit_files(work) and rc == 0,
        "rc=%r 之前=%r 之后=%r stderr=%r"
        % (rc, before, audit_files(work), err[:200]))
    chk("B8 审计落到用户级 ~/.phocinae-guard/audit.jsonl",
        os.path.isfile(user_audit),
        "缺少 %s（目录内容: %r）" % (user_audit, os.listdir(home)))
    if os.path.isfile(user_audit):
        with open(user_audit, "r", encoding="utf-8") as fh:
            body = fh.read()
        chk("B8 用户级审计记录了命令与判定",
            "git status" in body and "allow" in body, body[:200])

    # PHOCINAE_GATE_AUDIT=off → 不再新增
    size_before = os.path.getsize(user_audit) if os.path.isfile(user_audit) else 0
    run_hook("git status", work,
             hook_env({"PHOCINAE_GATE_GUARD": stub, "PHOCINAE_GATE_AUDIT": "off"}, home))
    size_after = os.path.getsize(user_audit) if os.path.isfile(user_audit) else 0
    chk("B8 PHOCINAE_GATE_AUDIT=off 生效", size_after == size_before,
        "%d → %d" % (size_before, size_after))

    # guard.py 自己的变量优先（用户显式指定就别改）
    explicit = os.path.join(TMP, "explicit-audit.jsonl")
    run_hook("git status", work,
             hook_env({"PHOCINAE_GATE_GUARD": stub,
                       "PHOCINAE_GUARD_AUDIT": explicit}, home))
    chk("B8 用户显式 PHOCINAE_GUARD_AUDIT 优先", os.path.isfile(explicit),
        "缺少 %s" % explicit)

    # 真实 guard.py 在的话，再跑一遍端到端（审计同样不得落进项目目录）
    real = None
    for rel in (os.path.join("phocinae-guard", "guard.py"),):
        candidate = os.path.abspath(os.path.join(REPO, os.pardir, rel))
        if os.path.isfile(candidate):
            real = candidate
    if real is None:
        skip("B8 真实 guard.py 端到端：项目目录无审计文件", "未找到同级 phocinae-guard")
        return
    work2 = os.path.join(TMP, "project-real")
    os.makedirs(work2, exist_ok=True)
    for name in os.listdir(work2):
        os.remove(os.path.join(work2, name))
    rc, decision, _, err = run_hook("git status", work2,
                                    hook_env({"PHOCINAE_GATE_GUARD": real}, home))
    chk("B8 真实 guard.py 端到端：项目目录无审计文件",
        not audit_files(work2),
        "rc=%r 目录=%r stderr=%r" % (rc, audit_files(work2), err[:200]))


# ------------------------------------------------------------------------ B9

def check_b9_interpreter():
    import importlib.util
    spec = importlib.util.spec_from_file_location("phocinae_gate_under_test", HOOK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    chk("B9 解释器版本自检存在", callable(getattr(module, "require_interpreter", None)))
    if not callable(getattr(module, "require_interpreter", None)):
        return
    chk("B9 当前解释器通过自检", module.require_interpreter() is None,
        "require_interpreter()=%r" % (module.require_interpreter(),))

    # 模拟 Python 3.7：必须返回「阻断原因」，而不是继续跑到一半再炸
    real_version = sys.version_info
    try:
        sys.version_info = (3, 7, 0)
        message = module.require_interpreter()
    finally:
        sys.version_info = real_version
    chk("B9 低版本解释器 → fail-closed 提示（含 3.8 与 hooks.json 改法）",
        isinstance(message, str) and "3.8" in message and "hooks.json" in message,
        "message=%r" % (message,))


# ----------------------------------------------------------------------- B20

def check_b20_protocol():
    stub = os.path.join(TMP, "stub_guard.py")
    home = os.path.join(TMP, "home")
    work = os.path.join(TMP, "project")

    # 协议真相：deny/ask 也走 exit 0 + permissionDecision，退出码不是判定值。
    for command, want in (("git status", "allow"), ("rm -rf /", "deny"),
                          ("python3 app.py", "ask")):
        rc, decision, _, err = run_hook(command, work,
                                        hook_env({"PHOCINAE_GATE_GUARD": stub}, home))
        chk("B20 %-12s → exit 0 + permissionDecision=%s" % (command, want),
            rc == 0 and decision == want,
            "rc=%r decision=%r stderr=%r" % (rc, decision, err[:200]))

    with open(HOOK, "r", encoding="utf-8") as fh:
        source = fh.read()
    doc = source.split('"""')[1] if source.count('"""') >= 2 else ""
    stale = "只有 allow 能过门（exit 0）"
    chk("B20 文档串描述真实协议（permissionDecision，且无旧说法）",
        "permissionDecision" in doc and stale not in doc,
        "docstring 仍称退出码即判定值时，集成方会写错 hook")


if __name__ == "__main__":
    sys.exit(main())
