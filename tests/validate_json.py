#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""codebuddy-phocinae 交付校验：全部 JSON 可解析 + manifest 关键字段/引用路径断言。

用法：python3 tests/validate_json.py [--repo-root /path/to/codebuddy-phocinae]
exit 0 = 全部通过；非 0 = 有失败项。
"""
import json
import os
import sys

REPO = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
if "--repo-root" in sys.argv:
    REPO = os.path.abspath(sys.argv[sys.argv.index("--repo-root") + 1])

CHECKS = []  # (name, ok, detail)


def chk(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))


def load_json(rel):
    path = os.path.join(REPO, rel)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        chk("json:%s" % rel, False, "无法读取: %s" % exc)
    except ValueError as exc:
        chk("json:%s" % rel, False, "JSON 解析失败: %s" % exc)
    return None


def main():
    p = load_json(".codebuddy-plugin/plugin.json")
    if p is not None:
        chk("plugin.name", p.get("name") == "codebuddy-phocinae",
            "name=%r" % p.get("name"))
        chk("plugin.version", p.get("version") == "0.1.0",
            "version=%r" % p.get("version"))
        chk("plugin.license", p.get("license") == "Apache-2.0",
            "license=%r" % p.get("license"))
        chk("plugin.hooks 声明", bool(p.get("hooks")), "hooks=%r" % p.get("hooks"))
        chk("plugin.skills 声明", bool(p.get("skills")), "skills=%r" % p.get("skills"))
        for key in ("hooks", "skills"):
            rel = p.get(key)
            if rel:
                path = os.path.join(REPO, rel.lstrip("./"))
                chk("plugin.%s 引用路径存在" % key, os.path.exists(path),
                    "%s → %s" % (rel, path))

    m = load_json(".codebuddy-plugin/marketplace.json")
    if m is not None:
        chk("marketplace.name", bool(m.get("name")), "name=%r" % m.get("name"))
        chk("marketplace.owner", isinstance(m.get("owner"), dict)
            and bool(m["owner"].get("name")), "owner=%r" % m.get("owner"))
        plugs = m.get("plugins")
        chk("marketplace.plugins 非空数组", isinstance(plugs, list) and bool(plugs),
            "plugins=%r" % plugs)
        if plugs:
            e0 = plugs[0]
            chk("marketplace.entry.name", e0.get("name") == "codebuddy-phocinae",
                "name=%r" % e0.get("name"))
            src = e0.get("source")
            chk("marketplace.entry.source", isinstance(src, dict)
                and bool(src.get("repo")), "source=%r" % src)

    h = load_json("hooks/hooks.json")
    if h is not None:
        chk("hooks.json 数组", isinstance(h, list) and bool(h),
            "type=%s" % type(h).__name__)
        if isinstance(h, list) and h:
            e0 = h[0]
            chk("hook.event=PreToolUse", e0.get("event") == "PreToolUse",
                "event=%r" % e0.get("event"))
            chk("hook.matcher=Bash", e0.get("matcher") == "Bash",
                "matcher=%r" % e0.get("matcher"))
            cmds = e0.get("hooks") or []
            chk("hook.command 存在", bool(cmds) and cmds[0].get("type") == "command",
                "hooks=%r" % cmds)
            if cmds:
                cmd = cmds[0].get("command") or ""
                rel = cmd.split("$CODEBUDDY_PLUGIN_ROOT/")[-1].strip('"')
                path = os.path.join(REPO, rel)
                chk("hook.command 引用脚本存在", os.path.exists(path),
                    "%s → %s" % (cmd, path))

    c = load_json(".mcp.json")
    if c is not None:
        srv = (c.get("mcpServers") or {}).get("phocinae-mcp")
        chk(".mcp.json phocinae-mcp 条目", isinstance(srv, dict)
            and bool(srv.get("command")), "entry=%r" % srv)

    chk("skills/SKILL.md 存在",
        os.path.isfile(os.path.join(REPO, "skills/phocinae-gate/SKILL.md")))
    chk("hooks/phocinae_gate.py 存在",
        os.path.isfile(os.path.join(REPO, "hooks/phocinae_gate.py")))
    chk("README.md 存在", os.path.isfile(os.path.join(REPO, "README.md")))
    chk("LICENSE 存在", os.path.isfile(os.path.join(REPO, "LICENSE")))

    fails = 0
    for name, ok, detail in CHECKS:
        print("%-4s %-42s %s" % ("PASS" if ok else "FAIL", name,
                                 "" if ok else detail))
        fails += (not ok)
    print("validate_json: %d/%d 通过" % (len(CHECKS) - fails, len(CHECKS)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
