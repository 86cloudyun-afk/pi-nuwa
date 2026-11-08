"""R2 加权公平调度（确定性模拟，用于验收与容量评估）。"""
from __future__ import annotations


def schedule(weights: dict[str, int], slots: int = 600) -> dict[str, float]:
    """按权重做确定性轮转，返回各项目占比。"""
    if not weights or any(w <= 0 for w in weights.values()):
        raise ValueError("weights must be positive")
    seq: list[str] = []
    names = list(weights)
    while len(seq) < slots:
        for name in names:
            seq.extend([name] * weights[name])
    seq = seq[:slots]
    counts = {name: seq.count(name) for name in names}
    total = sum(counts.values())
    return {name: round(counts[name] / total, 4) for name in names}


def check(weights: dict[str, int], expected: dict[str, float], tolerance: float = 0.05) -> tuple[bool, dict]:
    shares = schedule(weights)
    ok = all(abs(shares[k] - expected[k]) <= tolerance for k in expected)
    return ok, shares
