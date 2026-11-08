"""nuwa CLI：R1 子命令。"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from nuwa import graph, registry, txn, runner, dispatch as dispatch_mod  # type: ignore
    from nuwa import evidence, fairness, metrics, plugins as plugins_mod, policy, soak as soak_mod, migrate as migrate_mod, night as night_mod  # type: ignore
    from nuwa.ledger import Ledger  # type: ignore
    from nuwa.journal import Journal  # type: ignore
    from nuwa.paths import find_project, pointer_path  # type: ignore
else:
    from . import graph, registry, txn, runner, dispatch as dispatch_mod
    from . import evidence, fairness, metrics, plugins as plugins_mod, policy, soak as soak_mod, migrate as migrate_mod, night as night_mod
    from .ledger import Ledger
    from .journal import Journal
    from .paths import find_project, pointer_path


def _print(obj, as_json: bool) -> None:
    if as_json:
        print(json.dumps(obj, ensure_ascii=False, indent=2))
    else:
        print(obj)


def cmd_ls(args) -> int:
    items = registry.rebuild()
    if args.json:
        print(json.dumps({"registry_schema": 1, "items": items}, ensure_ascii=False, indent=2))
        return 0
    if not items:
        print("(no projects)")
        return 0
    print(f"{'NAME':<24} {'RUN':<5} {'STATUS':<10} {'ROUND':>5} {'TURNS':>5}  ROOT")
    for it in items:
        print(f"{it['name']:<24} {'yes' if it['running'] else 'no':<5} "
              f"{it['status']:<10} {it['round']:>5} {it['turns']:>5}  {it['root']}")
    return 0


def cmd_status(args) -> int:
    items = registry.rebuild()
    if args.json:
        print(json.dumps({"items": items}, ensure_ascii=False, indent=2))
        return 0
    for it in items:
        print(f"{it['name']}: running={it['running']} status={it['status']} "
              f"round={it['round']} turns={it['turns']}")
        print(f"  root={it['root']}")
    return 0


def cmd_attach(args) -> int:
    item = registry.find(args.name)
    if not item:
        print(f"nuwa: 未找到项目 {args.name}", file=sys.stderr)
        return 2
    p = pointer_path()
    p.write_text(json.dumps({"root": item["root"], "sessionId": "", "ts": __import__("time").time() * 1000}),
                 encoding="utf-8")
    print(f"attached: {item['name']} -> {item['root']}")
    return 0


def cmd_budget(args) -> int:
    led = Ledger()
    if args.set is not None:
        led.set_cap(int(args.set))
    if args.add is not None:
        led.set_cap(led.cap() + int(args.add))
    s = led.summary()
    if args.json:
        print(json.dumps(s, ensure_ascii=False, indent=2))
    else:
        print(f"cap={s['cap']} settled={s['settled_total']} reserved={s['reserved']} "
              f"remaining={s['remaining_global']} outstanding={len(s['outstanding'])}")
    return 0


def cmd_commit(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    key = None if args.key == "auto" else args.key
    try:
        res = txn.commit(root, args.intent, args.fact, key,
                         kind=args.kind, doc=args.doc)
    except (txn.CommitError, FileNotFoundError) as exc:
        print(f"nuwa: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(res, ensure_ascii=False))
    return 0


def _ensure_project(target: str, name: str | None) -> Path:
    """URL → 建项目；否则按项目名查找。"""
    if target.startswith(("http://", "https://")):
        import urllib.parse
        u = urllib.parse.urlparse(target)
        host = u.hostname or "target"
        port = u.port or (443 if u.scheme == "https" else 80)
        pname = name or f"nuwa-{time.strftime('%m%d-%H%M')}-{os.getpid()}"
        root = Path(os.environ.get("SAPPER_HOME", str(Path.home() / "sapper-lab"))) / pname
        root.mkdir(parents=True, exist_ok=True)
        if not (root / ".sapper" / "project.json").exists():
            r = graph.sapper(root, ["setup", "--goal", f"对 {target} 做完整渗透评估并拿到 flag", "--agents"])
            if r.returncode != 0:
                raise RuntimeError((r.stdout + r.stderr)[:300])
            r = graph.sapper(root, ["fact", f"靶标已授权且可达：{target}", "-t", "靶标确认",
                                    "-k", "host", "-d", f"ip={host}", "-d", f"port={port}",
                                    "-d", f"url={target}"])
            if r.returncode != 0:
                raise RuntimeError((r.stdout + r.stderr)[:300])
        return root
    item = registry.find(target)
    if not item:
        raise FileNotFoundError(f"项目不存在: {target}")
    return Path(item["root"])


def cmd_run(args) -> int:
    try:
        root = Path(args.root).resolve() if args.root else _ensure_project(args.target, args.name)
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"nuwa: {exc}", file=sys.stderr)
        return 2
    code = runner.run(root, minutes=args.minutes, parallel=args.parallel,
                      model=args.model, resume=args.resume)
    return code


def cmd_dispatch(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    try:
        res = dispatch_mod.dispatch(root, args.intent, model=args.model,
                                    timeout=args.timeout)
    except Exception as exc:  # noqa: BLE001
        print(f"nuwa: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(res, ensure_ascii=False))
    return 0


def cmd_metrics(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    data = metrics.compute(root)
    if args.html:
        Path(args.html).write_text(metrics.render_html(data), encoding="utf-8")
        print(args.html)
        return 0
    print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def cmd_report(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    out = Path(args.out)
    out.write_text(metrics.render_html(metrics.compute(root)), encoding="utf-8")
    print(str(out))
    return 0


def cmd_verify(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    fact = graph.get_fact(root, args.fact)
    if not fact:
        print(f"nuwa: fact 不存在: {args.fact}", file=sys.stderr)
        return 2
    stdout = Path(args.stdout).read_bytes() if args.stdout else None
    code, msg = evidence.verify(fact, stdout)
    ev = fact.get("x-nuwa-evidence") or fact.get("evidence") or {}
    print(json.dumps({"code": code, "message": msg,
                      "confidence": evidence.confidence(ev)}, ensure_ascii=False))
    return 0 if code == 0 else code


def cmd_policy(args) -> int:
    if args.action == "check":
        ok, rule = policy.check_command(args.command)
        print(json.dumps({"allowed": ok, "rule": rule}, ensure_ascii=False))
        return 0 if ok else 1
    print(policy.redact(args.text))
    return 0


def cmd_fairness(args) -> int:
    parts = args.weights.split(":")
    weights = {f"p{i}": int(w) for i, w in enumerate(parts)}
    shares = fairness.schedule(weights, slots=max(100, args.seconds * 10))
    print(json.dumps({"weights": weights, "shares": shares}, ensure_ascii=False, indent=2))
    return 0


def cmd_plugin(args) -> int:
    found = plugins_mod.discover(args.dir)
    print(json.dumps({"api_version": plugins_mod.API_VERSION,
                      "plugins": [{"name": p["name"], "api_version": p["api_version"]}
                                  for p in found]}, ensure_ascii=False, indent=2))
    return 0


def cmd_soak(args) -> int:
    roots = args.project or [i["root"] for i in registry.load()]
    if not roots:
        print("nuwa: 没有可跑的项目", file=sys.stderr)
        return 2
    summary = soak_mod.soak(roots, minutes=args.minutes, interval=args.interval,
                            parallel=args.parallel, model=args.model)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if all(summary["verdict"].values()) else 1


def cmd_soak_night(args) -> int:
    res = night_mod.run(args.base, args.minutes, args.projects,
                        interval=args.interval, model=args.model)
    print(json.dumps({k: res[k] for k in ("mode", "minutes", "samples", "facts",
                                          "rss_growth_kb", "fd_growth", "verdict",
                                          "commit")}, ensure_ascii=False, indent=2))
    return 0 if all(res["verdict"].values()) else 1


def cmd_flag(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    cmd = ["flag", args.value]
    if args.challenge:
        cmd += ["-c", args.challenge]
    r = graph.sapper(root, cmd)
    if r.returncode != 0:
        print((r.stdout + r.stderr).strip()[:400], file=sys.stderr)
        return 1
    Journal(root).append("flag_recorded", value=args.value, challenge=args.challenge or "")
    print(json.dumps({"flag": args.value, "challenge": args.challenge or ""},
                     ensure_ascii=False))
    return 0


def cmd_complete(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    ids = [x for x in re.split(r"[,\s]+", args.from_fact.strip()) if x]
    if not ids:
        print("nuwa: --from 为空", file=sys.stderr)
        return 2
    kinds = {}
    for fid in ids:
        fact = graph.get_fact(root, fid)
        if not fact:
            print(f"nuwa: fact 不存在: {fid}", file=sys.stderr)
            return 2
        kind = fact.get("kind")
        if kind not in ("flag", "vuln", "loot"):
            print(f"nuwa: 证据类型不足: {fid}={kind}（需要 flag/vuln/loot）", file=sys.stderr)
            return 3
        desc = fact.get("description") or ""
        for marker in re.findall(r"\[nuwa:(sha256:[0-9a-f]{64})\]", desc):
            if not any(marker in (f.get("description") or "")
                       for f in graph.facts(root)):
                print(f"nuwa: 证据键无法回溯: {marker}", file=sys.stderr)
                return 4
        kinds[fid] = kind
    joined = ",".join(ids)
    r = graph.sapper(root, ["complete", "--from", joined])
    if r.returncode != 0:
        print((r.stdout + r.stderr).strip()[:400], file=sys.stderr)
        return 1
    Journal(root).append("project_completed", fact=joined, kind=",".join(sorted(set(kinds.values()))))
    print(json.dumps({"completed": True, "from": joined, "kinds": kinds},
                     ensure_ascii=False))
    return 0


def cmd_soak_verify(args) -> int:
    res = night_mod.verify(args.base, expect_commit=args.expect_commit)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("ok") else 1


def cmd_migrate(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    detected = {}
    if root:
        for name in ("run.json", "journal.jsonl"):
            p = root / ".nuwa" / name
            if p.exists():
                detected[name] = "present"
        proj = root / ".sapper" / "project.json"
        if proj.exists():
            detected["graph"] = "sapper-managed"
    result = migrate_mod.migrate_loop_state(write=not args.dry_run)
    print(json.dumps({"from": args.source, "dry_run": args.dry_run,
                      "detected": detected, "loop_state": result},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_recover(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    if args.repair:
        print(json.dumps(txn.repair(root), ensure_ascii=False, indent=2))
    res = txn.recover(root)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_adopt(args) -> int:
    root = Path(args.root).resolve() if args.root else find_project()
    if not root:
        print("nuwa: 不在 sapper 项目内", file=sys.stderr)
        return 2
    res = txn.adopt(root)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nuwa")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("ls")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_ls)

    s = sub.add_parser("status")
    s.add_argument("--all", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("attach")
    s.add_argument("name")
    s.set_defaults(func=cmd_attach)

    s = sub.add_parser("budget")
    s.add_argument("--json", action="store_true")
    s.add_argument("--set", type=int, default=None)
    s.add_argument("--add", type=int, default=None)
    s.set_defaults(func=cmd_budget)

    s = sub.add_parser("flag")
    s.add_argument("value")
    s.add_argument("--challenge", "-c", default=None)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_flag)

    s = sub.add_parser("complete")
    s.add_argument("--from", dest="from_fact", required=True)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_complete)

    s = sub.add_parser("commit")
    s.add_argument("--key", required=True)
    s.add_argument("--intent", required=True)
    s.add_argument("--fact", required=True)
    s.add_argument("--kind", default="note")
    s.add_argument("--doc", default=None)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_commit)

    s = sub.add_parser("run")
    s.add_argument("target")
    s.add_argument("--name", default=None)
    s.add_argument("--minutes", type=int, default=60)
    s.add_argument("--parallel", type=int, default=2)
    s.add_argument("--model", default="deepseek-flash")
    s.add_argument("--resume", action="store_true")
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_run)

    s = sub.add_parser("dispatch")
    s.add_argument("intent")
    s.add_argument("--model", default="deepseek-flash")
    s.add_argument("--timeout", type=int, default=300)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_dispatch)

    s = sub.add_parser("metrics")
    s.add_argument("--json", action="store_true")
    s.add_argument("--html", default=None)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_metrics)

    s = sub.add_parser("report")
    s.add_argument("--out", required=True)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("verify")
    s.add_argument("fact")
    s.add_argument("--stdout", default=None)
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("policy")
    s.add_argument("action", choices=["check", "redact"])
    s.add_argument("--command", default="")
    s.add_argument("--text", default="")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("fairness")
    s.add_argument("--weights", default="2:1:1")
    s.add_argument("--seconds", type=int, default=60)
    s.set_defaults(func=cmd_fairness)

    s = sub.add_parser("plugin")
    s.add_argument("--dir", default="nuwa_plugins")
    s.set_defaults(func=cmd_plugin)

    s = sub.add_parser("soak")
    s.add_argument("--minutes", type=float, default=1)
    s.add_argument("--interval", type=float, default=5)
    s.add_argument("--parallel", type=int, default=2)
    s.add_argument("--model", default="deepseek-flash")
    s.add_argument("--project", action="append", default=None)
    s.set_defaults(func=cmd_soak)

    s = sub.add_parser("soak-night")
    s.add_argument("--base", required=True)
    s.add_argument("--minutes", type=float, default=4320)
    s.add_argument("--projects", type=int, default=4)
    s.add_argument("--interval", type=float, default=30)
    s.add_argument("--model", default="deepseek-flash")
    s.set_defaults(func=cmd_soak_night)

    s = sub.add_parser("soak-verify")
    s.add_argument("base")
    s.add_argument("--expect-commit", default=None)
    s.set_defaults(func=cmd_soak_verify)

    s = sub.add_parser("migrate")
    s.add_argument("--from", dest="source", default="auto")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_migrate)

    s = sub.add_parser("recover")
    s.add_argument("--root", default=None)
    s.add_argument("--repair", action="store_true")
    s.set_defaults(func=cmd_recover)

    s = sub.add_parser("adopt")
    s.add_argument("--root", default=None)
    s.set_defaults(func=cmd_adopt)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
