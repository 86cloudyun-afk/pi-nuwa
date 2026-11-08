"""R6 引擎/目标插件加载。"""
from __future__ import annotations

import importlib.util
from pathlib import Path

API_VERSION = "1"


class PluginError(RuntimeError):
    pass


def load(path: str | Path) -> dict:
    p = Path(path)
    spec = importlib.util.spec_from_file_location(f"nuwa_plugin_{p.stem}", p)
    if not spec or not spec.loader:
        raise PluginError(f"无法加载: {p}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plugin = getattr(module, "PLUGIN", None)
    if not isinstance(plugin, dict):
        raise PluginError(f"{p.name}: 缺少 PLUGIN 字典")
    for key in ("name", "api_version", "run"):
        if key not in plugin:
            raise PluginError(f"{p.name}: 缺少字段 {key}")
    if str(plugin["api_version"]) != API_VERSION:
        raise PluginError(f"{p.name}: api_version={plugin['api_version']} 不兼容 (需要 {API_VERSION})")
    if not callable(plugin["run"]):
        raise PluginError(f"{p.name}: run 不可调用")
    return plugin


def discover(directory: str | Path) -> list[dict]:
    d = Path(directory)
    out = []
    if not d.exists():
        return out
    for p in sorted(d.glob("*.py")):
        if p.name.startswith("_"):
            continue
        try:
            out.append(load(p))
        except PluginError:
            continue
    return out


def run(plugin: dict, prompt: str, opts: dict | None = None) -> str:
    return plugin["run"](prompt, opts or {})
