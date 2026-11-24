"""R3 证据：采集、校验、置信度。"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
FRESH_SECONDS = 1800


def normalize(data: bytes) -> bytes:
    text = data.decode("utf-8", "replace")
    text = ANSI.sub("", text)
    return text.replace("\r\n", "\n").encode("utf-8")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or __import__("time").time(), timezone.utc).isoformat(
        timespec="milliseconds")


def capture(command: str, cwd: str, exit_code: int, stdout: bytes, stderr: bytes,
            target: dict, intent_id: str, project_id: str,
            assertion: dict | None = None, source: str = "executor-hook",
            duration_ms: int = 0, captured_at: float | None = None) -> dict:
    norm = normalize(stdout)
    return {
        "schema": 1,
        "command": command,
        "cwd": cwd,
        "exit_code": exit_code,
        "hash_spec": "v1",
        "raw_sha256": sha(stdout),
        "norm_sha256": sha(norm),
        "artifact": {"stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
                     "truncated": False},
        "captured_at": _iso(captured_at),
        "duration_ms": duration_ms,
        "target": target,
        "intent_id": intent_id,
        "project_id": project_id,
        "source": source,
        "assertion": assertion,
    }


def _parse_ts(text: str) -> float:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def _assert(assertion: dict, stdout: bytes | None) -> bool:
    if stdout is None:
        return False
    text = normalize(stdout).decode("utf-8", "replace")
    op = assertion.get("op")
    value = str(assertion.get("value", ""))
    if op == "contains":
        return value in text
    if op == "regex":
        return re.search(value, text) is not None
    if op == "eq":
        return text.strip() == value
    if op == "gt":
        try:
            return float(text.strip()) > float(value)
        except ValueError:
            return False
    if op == "lt":
        try:
            return float(text.strip()) < float(value)
        except ValueError:
            return False
    return False


def verify(fact: dict, stdout: bytes | None = None, now: float | None = None) -> tuple[int, str]:
    """返回 (code, message)；0 通过，10-14 对应五类拒绝。"""
    ev = fact.get("x-nuwa-evidence") or fact.get("evidence")
    if not isinstance(ev, dict) or not ev.get("command"):
        return 10, "no_command"
    if ev.get("source") not in ("executor-hook", "subagent-hook"):
        return 10, "untrusted_source"
    try:
        ts = _parse_ts(ev["captured_at"])
    except (KeyError, ValueError):
        return 12, "bad_timestamp"
    if (now or __import__("time").time()) - ts > FRESH_SECONDS:
        return 12, "stale"
    if stdout is not None and sha(normalize(stdout)) != ev.get("norm_sha256"):
        return 13, "hash_mismatch"
    assertion = ev.get("assertion")
    if assertion and not _assert(assertion, stdout):
        return 11, "assertion_false"
    expect = fact.get("x-nuwa-target") or {}
    target = ev.get("target") or {}
    if expect and any(expect.get(k) != target.get(k) for k in ("host", "port", "scheme")):
        return 14, "target_mismatch"
    return 0, "ok"


def confidence(ev: dict, now: float | None = None) -> float:
    assertion = ev.get("assertion") or {}
    op = assertion.get("op")
    strength = {"eq": 0.40, "contains": 0.35, "regex": 0.35, "gt": 0.30, "lt": 0.30}.get(op, 0.0)
    try:
        age = (now or __import__("time").time()) - _parse_ts(ev["captured_at"])
        fresh = 0.30 if age <= 300 else 0.20 if age <= 1800 else 0.0
    except (KeyError, ValueError):
        fresh = 0.0
    repro = 0.0
    if ev.get("command") and ev.get("exit_code") == 0 and ev.get("norm_sha256"):
        repro = 0.30
    elif ev.get("command"):
        repro = 0.10
    return round(min(1.0, strength + fresh + repro), 2)
