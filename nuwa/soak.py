"""R7 小长测：多项目并发 + 资源采样。"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from . import graph, runner


def _rss_kb() -> int:
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        pass
    return 0


def _fd_count() -> int:
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return 0


def soak(projects: list[str | Path], minutes: float = 1, interval: float = 5,
         parallel: int = 2, model: str = "deepseek-flash") -> dict:
    results: dict[str, int] = {}
    errors: dict[str, str] = {}

    def work(root: Path) -> None:
        try:
            results[str(root)] = runner.run(root, minutes=minutes,
                                            parallel=parallel, model=model)
        except Exception as exc:  # noqa: BLE001
            errors[str(root)] = str(exc)[:200]

    threads = [threading.Thread(target=work, args=(Path(p),)) for p in projects]
    t0 = time.time()
    for t in threads:
        t.start()

    samples = []
    # 至少采两个点：短跑时 runner 可能在第一次 interval 前就结束。
    while any(t.is_alive() for t in threads) or len(samples) < 2:
        facts = sum(len(graph.facts(p)) for p in projects)
        samples.append({"t": round(time.time() - t0, 1), "rss_kb": _rss_kb(),
                        "fds": _fd_count(), "facts": facts})
        if not any(t.is_alive() for t in threads) and len(samples) >= 2:
            break
        time.sleep(interval)

    for t in threads:
        t.join()

    rss = [s["rss_kb"] for s in samples]
    fd = [s["fds"] for s in samples]
    warm = max(1, len(samples) // 5)
    steady_rss = rss[warm:] or rss
    steady_fd = fd[warm:] or fd
    rss_growth = (max(steady_rss) - min(steady_rss)) if steady_rss else 0
    # FD 取稳态最小值：并发的子进程/管道是瞬时句柄，峰值不代表泄漏
    fd_base = min(steady_fd[:3]) if steady_fd else 0
    fd_end = min(steady_fd[-3:]) if steady_fd else 0
    fd_growth = max(0, fd_end - fd_base)
    total_facts = sum(len(graph.facts(p)) for p in projects)
    return {
        "soak_schema": 1,
        "projects": [str(p) for p in projects],
        "minutes": minutes,
        "samples": len(samples),
        "samples_raw": samples,
        "exit_codes": results,
        "errors": errors,
        "facts": total_facts,
        "rss_growth_kb": rss_growth,
        "fd_growth": fd_growth,
        "verdict": {
            "all_zero": all(v == 0 for v in results.values()) and not errors,
            "rss_ok": rss_growth < 100 * 1024,
            "fd_ok": fd_growth <= 2,
            "facts_ok": total_facts > 0,
        },
    }


def write_report(summary: dict, out: str | Path) -> Path:
    p = Path(out)
    p.mkdir(parents=True, exist_ok=True)
    (p / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                    encoding="utf-8")
    return p
