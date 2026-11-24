"""引擎调用。"""
from __future__ import annotations

import json
import os
import subprocess


class EngineError(RuntimeError):
    def __init__(self, msg: str, partial: str = ""):
        super().__init__(msg)
        self.partial = partial


def call(prompt: str, model: str = "deepseek-flash", timeout: int = 300,
         system: str | None = None, engine: str | None = None,
         pass_fds: tuple[int, ...] = ()) -> str:
    eng = engine or os.environ.get("NUWA_ENGINE", "omp-claude")
    cmd = [eng, "-p", "--output-format", "json", "--model", model]
    if system:
        cmd += ["--append-system-prompt", system]
    try:
        p = subprocess.run(cmd, input=prompt, text=True, capture_output=True,
                            timeout=timeout, pass_fds=pass_fds,
                            encoding="utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        raise EngineError(f"engine timeout after {timeout}s", partial=partial) from exc
    if p.returncode != 0:
        raise EngineError((p.stdout + p.stderr).strip()[:400], partial=p.stdout)
    return p.stdout
