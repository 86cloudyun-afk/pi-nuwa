"""R5 执行策略与脱敏。"""
from __future__ import annotations

import hmac
import hashlib
import re

DENY_RULES = [
    (r"rm\s+-rf\s+/(\s|$)", "P-001"),
    (r"mkfs\.", "P-002"),
    (r"dd\s+.*of=/dev/[sh]d", "P-003"),
    (r"curl[^\n]*--noproxy[^\n]*\b(169\.254|127\.0\.0\.1)", "P-004"),
]

ALLOW_RULES = [
    (r"^(nmap|curl|dig|whois|python3|sapper|nuwa)\b", "A-001"),
]

REDACT_RULES = [
    (re.compile(r"sk-[A-Za-z0-9]{8,}"), "sk-***"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1***"),
    (re.compile(r"(?i)((?:token|api[_-]?key|secret|password)\s*[=:]\s*)\S+"), r"\1***"),
]


class PolicyError(RuntimeError):
    pass


def check_command(command: str) -> tuple[bool, str | None]:
    for pattern, rule_id in DENY_RULES:
        if re.search(pattern, command):
            return False, rule_id
    return True, None


def check_prompt(prompt: str) -> tuple[bool, str | None]:
    """在派发前扫描渲染提示，拦截被注入的危险命令模式。"""
    for pattern, rule_id in DENY_RULES:
        if re.search(pattern, prompt):
            return False, rule_id
    return True, None


def allowed_by_allowlist(command: str) -> bool:
    return any(re.search(pattern, command) for pattern, _ in ALLOW_RULES)


def redact(text: str) -> str:
    out = text
    for pattern, repl in REDACT_RULES:
        out = pattern.sub(repl, out)
    return out


def sign(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def verify_signature(data: bytes, key: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(data, key), signature)


def load_key(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read().strip()
