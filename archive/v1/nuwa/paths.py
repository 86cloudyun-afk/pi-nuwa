"""路径与项目发现。"""
from __future__ import annotations

import os
from pathlib import Path


def sapper_home() -> Path:
    return Path(os.environ.get("SAPPER_HOME", str(Path.home() / "sapper-lab")))


def agent_home() -> Path:
    env = os.environ.get("PI_AGENT_HOME")
    if env:
        return Path(env)
    omp = Path.home() / ".omp" / "agent"
    return omp if omp.exists() else Path.home() / ".pi" / "agent"


def find_project(start: str | Path | None = None) -> Path | None:
    d = Path(start or os.getcwd()).resolve()
    while True:
        if (d / ".sapper" / "project.json").exists():
            return d
        if d.parent == d:
            return None
        d = d.parent


def nuwa_dir(root: str | Path) -> Path:
    return Path(root) / ".nuwa"


def ensure_nuwa(root: str | Path) -> Path:
    nd = nuwa_dir(root)
    for sub in ("inflight", "artifacts"):
        (nd / sub).mkdir(parents=True, exist_ok=True)
    return nd


def budget_dir() -> Path:
    d = sapper_home() / "budget"
    d.mkdir(parents=True, exist_ok=True)
    return d


def registry_path() -> Path:
    return sapper_home() / "registry.json"


def pointer_path() -> Path:
    p = agent_home() / "cache"
    p.mkdir(parents=True, exist_ok=True)
    return p / "nuwa-current"
