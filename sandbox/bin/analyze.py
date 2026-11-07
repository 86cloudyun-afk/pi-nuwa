#!/usr/bin/env python3
"""
数据分析：把压力测试、靶场访问日志、会话块日志合成一份 Markdown 报告。

输入：
  reports/stress-*/raw.json + metrics.json
  logs/nuwa-t*/access.jsonl
  state/agent-c/cache/nuwa-loop/log/*.jsonl

输出：
  reports/ANALYSIS.md
  reports/summary.json
"""
from __future__ import annotations

import glob
import json
import os
import statistics
import sys
from collections import Counter
from pathlib import Path

SANDBOX = Path(os.environ.get("NUWA_SANDBOX", "/srv/nuwa-sandbox"))
REPORTS = SANDBOX / "reports"


def load_jsonl(p: str) -> list[dict]:
    out = []
    try:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    except OSError:
        pass
    return out


def pct(vals: list[float], q: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = min(len(s) - 1, max(0, int(round(q * (len(s) - 1)))))
    return s[idx]


def analyze_stress() -> dict:
    rows = []
    for d in sorted(glob.glob(str(REPORTS / "stress-*"))):
        raw = Path(d) / "raw.json"
        met = Path(d) / "metrics.json"
        if not raw.exists():
            continue
        try:
            data = json.loads(raw.read_text())
            metrics = json.loads(met.read_text()) if met.exists() else {}
        except json.JSONDecodeError:
            continue
        rows.append({"dir": os.path.basename(d), "runs": data, "metrics": metrics})

    all_dur = [r["dur"] for g in rows for r in g["runs"]]
    rc = Counter(r["rc"] for g in rows for r in g["runs"])
    events = Counter()
    for g in rows:
        for r in g["runs"]:
            for e in r.get("event_kinds", []):
                events[e] += 1
    return {
        "groups": len(rows),
        "runs": sum(len(g["runs"]) for g in rows),
        "rc": dict(rc),
        "dur_avg": round(statistics.mean(all_dur), 2) if all_dur else 0,
        "dur_p50": round(pct(all_dur, 0.5), 2),
        "dur_p95": round(pct(all_dur, 0.95), 2),
        "dur_max": round(max(all_dur), 2) if all_dur else 0,
        "dispatches": sum(r["dispatch"] for g in rows for r in g["runs"]),
        "reasons": sum(r["reason"] for g in rows for r in g["runs"]),
        "lock_left": sum(1 for g in rows for r in g["runs"] if r.get("lock_left")),
        "lock_by_group": {
            g["dir"]: sum(1 for r in g["runs"] if r.get("lock_left")) for g in rows
        },
        "event_kinds": dict(events),
        "group_detail": [
            {"name": g["dir"], "metrics": g["metrics"]} for g in rows
        ],
    }


def analyze_targets() -> dict:
    out = {}
    for d in sorted(glob.glob(str(SANDBOX / "logs" / "nuwa-t*"))):
        name = os.path.basename(d)
        recs = load_jsonl(os.path.join(d, "access.jsonl"))
        if not recs:
            out[name] = {"requests": 0}
            continue
        paths = Counter(r.get("url", "") for r in recs)
        uas = Counter((r.get("ua") or "").split("/")[0] for r in recs)
        ts = [r.get("ts", 0) for r in recs if r.get("ts")]
        out[name] = {
            "requests": len(recs),
            "unique_paths": len(paths),
            "top_paths": paths.most_common(8),
            "top_uas": uas.most_common(5),
            "span_sec": round((max(ts) - min(ts)) / 1000, 2) if len(ts) > 1 else 0,
            "rps": round(len(recs) / max(0.001, (max(ts) - min(ts)) / 1000), 2) if len(ts) > 1 else 0,
        }
    return out


def analyze_sessions() -> dict:
    logs = glob.glob(str(SANDBOX / "state" / "agent-c" / "cache" / "nuwa-loop" / "log" / "*.jsonl"))
    out = []
    for p in logs:
        recs = load_jsonl(p)
        if not recs:
            continue
        kinds = Counter(r.get("event") for r in recs)
        blocks = [r for r in recs if r.get("event") == "block"]
        turns = [r.get("turn") for r in blocks]
        gaps = []
        for a, b in zip(blocks, blocks[1:]):
            gaps.append((b.get("ts", 0) - a.get("ts", 0)) / 1000)
        out.append({
            "file": os.path.basename(p),
            "records": len(recs),
            "events": dict(kinds),
            "blocks": len(blocks),
            "turns": turns,
            "turn_increasing": turns == sorted(turns) and len(set(turns)) == len(turns),
            "gap_avg_sec": round(statistics.mean(gaps), 2) if gaps else 0,
            "tokens": [r.get("spentTokens") for r in blocks if r.get("spentTokens") is not None],
        })
    return {"sessions": out}


def analyze_soak() -> dict:
    rows = []
    for p in sorted(glob.glob(str(REPORTS / "soak-*" / "summary.json"))):
        try:
            d = json.loads(Path(p).read_text())
        except (OSError, json.JSONDecodeError):
            continue
        rows.append({"name": Path(p).parent.name, **d})
    return {"runs": rows}


def render(stress: dict, targets: dict, sessions: dict, soak: dict) -> str:
    L = []
    L.append("# 女娲沙盒测试报告\n")
    L.append("## 1. 压力测试（bin/nuwa + fake-sapper）\n")
    L.append(f"- 批次: {stress['groups']}，实例总数: {stress['runs']}")
    L.append(f"- 退出码分布: {stress['rc']}")
    L.append(f"- 耗时 avg/p50/p95/max: {stress['dur_avg']} / {stress['dur_p50']} / {stress['dur_p95']} / {stress['dur_max']} s")
    L.append(f"- dispatch 总数: {stress['dispatches']}，reason 总数: {stress['reasons']}")
    L.append(f"- 残留锁: {stress['lock_left']}（按批次: {stress.get('lock_by_group', {})}）")
    L.append(f"- 事件种类: {stress['event_kinds']}\n")

    L.append("## 2. 靶场访问（真实 HTTP）\n")
    L.append("| 目标 | 请求数 | 唯一路径 | 时间跨度 | RPS | 主要 UA |")
    L.append("|---|---|---|---|---|---|")
    for name, v in targets.items():
        if not v.get("requests"):
            L.append(f"| {name} | 0 | - | - | - | - |")
            continue
        ua = ", ".join(f"{u or '(none)'}:{c}" for u, c in v["top_uas"][:2])
        L.append(f"| {name} | {v['requests']} | {v['unique_paths']} | {v['span_sec']}s | {v['rps']} | {ua} |")
    L.append("")

    L.append("## 3. 会话续跑（nuwa-loop）\n")
    if sessions["sessions"]:
        for s in sessions["sessions"]:
            L.append(f"- `{s['file']}`: blocks={s['blocks']} turns={s['turns']} "
                     f"递增={s['turn_increasing']} 轮间隔均值={s['gap_avg_sec']}s")
            L.append(f"  - 事件: {s['events']}")
    else:
        L.append("- 暂无会话日志")
    L.append("")

    L.append("## 4. 小长测\n")
    if soak["runs"]:
        L.append("| 批次 | 时长 | 实例 | 模式 | RSS 斜率 | FD 斜率 | 每 fact 字节 | 事件 KB/min | 判定 |")
        L.append("|---|---|---|---|---|---|---|---|---|")
        for r in soak["runs"]:
            v = r.get("verdict", {})
            ok = all(v.values()) if v else False
            L.append("| {n} | {m}m | {i} | {mode} | {rss} KB/min | {fd}/min | {bpf} | {ek} | {ok} |".format(
                n=r["name"], m=r.get("minutes"), i=r.get("instances"), mode=r.get("mode"),
                rss=r.get("rss_slope_kb_per_min"), fd=r.get("fd_slope_per_min"),
                bpf=r.get("bytes_per_fact"), ek=r.get("event_kb_per_min"),
                ok="PASS" if ok else "FAIL"))
    else:
        L.append("- 暂无小长测数据")
    L.append("")

    L.append("## 5. 结论\n")
    ok = stress["rc"].get(0, 0)
    total = stress["runs"] or 1
    L.append(f"- 压力实例成功率: {ok}/{total} = {ok / total:.0%}")
    L.append(f"- 平均耗时 {stress['dur_avg']}s，p95 {stress['dur_p95']}s")
    if stress["rc"].get(5):
        L.append(f"- 锁竞争拦截 {stress['rc'][5]} 次（预期行为）")
    if stress["lock_left"]:
        L.append(f"- 残留锁 {stress['lock_left']} 个（需检查退出路径）")
    L.append("")
    return "\n".join(L)


def main() -> int:
    stress = analyze_stress()
    targets = analyze_targets()
    sessions = analyze_sessions()
    soak = analyze_soak()
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "summary.json").write_text(
        json.dumps({"stress": stress, "targets": targets, "sessions": sessions, "soak": soak},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (REPORTS / "ANALYSIS.md").write_text(render(stress, targets, sessions, soak), encoding="utf-8")
    print(json.dumps({
        "stress_runs": stress["runs"],
        "rc": stress["rc"],
        "dispatches": stress["dispatches"],
        "target_requests": sum(v.get("requests", 0) for v in targets.values()),
        "sessions": len(sessions["sessions"]),
        "soak_runs": len(soak["runs"]),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
