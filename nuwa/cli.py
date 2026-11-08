"""nuwa CLI：R1 子命令。"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from nuwa import graph, registry, txn, runner, dispatch as dispatch_mod  # type: ignore
    from nuwa.ledger import Ledger  # type: ignore
    from nuwa.paths import find_project, pointer_path  # type: ignore
else:
    from . import graph, registry, txn, runner, dispatch as dispatch_mod
    from .ledger import Ledger
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
    try:
        res = txn.commit(root, args.intent, args.fact, args.key,
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
