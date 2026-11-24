"""R4 指标、离线报告、告警。"""
from __future__ import annotations

import html
import json
import statistics
import urllib.request
from pathlib import Path

from .journal import Journal


def compute(root: str | Path) -> dict:
    recs = Journal(root).read()
    events: dict[str, int] = {}
    durations: list[float] = []
    tokens = 0
    for r in recs:
        ev = r.get("event", "?")
        events[ev] = events.get(ev, 0) + 1
        if ev == "executed":
            if r.get("duration_ms") is not None:
                durations.append(float(r["duration_ms"]))
            tokens += int(r.get("tokens", 0) or 0)
    p50 = statistics.median(durations) if durations else 0
    p95 = 0
    if durations:
        s = sorted(durations)
        p95 = s[min(len(s) - 1, int(len(s) * 0.95))]
    return {
        "metrics_schema": 1,
        "project": Path(root).name,
        "events": events,
        "dispatches": events.get("executed", 0),
        "commits": events.get("commit_done", 0),
        "rejects": events.get("completion_rejected", 0),
        "stalls": events.get("stall_stop", 0),
        "tokens": tokens,
        "duration_ms": {"p50": round(p50, 1), "p95": round(p95, 1)},
        "last_seq": recs[-1].get("seq", 0) if recs else 0,
    }


def render_html(data: dict) -> str:
    rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>" for k, v in sorted(data["events"].items())
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>nuwa report - {html.escape(data['project'])}</title>
<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse}}
td,th{{border:1px solid #ccc;padding:.3rem .6rem}}</style></head><body>
<h1>{html.escape(data['project'])}</h1>
<p>dispatches={data['dispatches']} commits={data['commits']} tokens={data['tokens']}
 p50={data['duration_ms']['p50']}ms p95={data['duration_ms']['p95']}ms</p>
<table><tr><th>event</th><th>count</th></tr>{rows}</table>
</body></html>"""


def alert(webhook: str, payload: dict, timeout: int = 5) -> bool:
    body = json.dumps(payload, ensure_ascii=False).encode()
    req = urllib.request.Request(webhook, data=body,
                                 headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:  # noqa: BLE001
        return False
