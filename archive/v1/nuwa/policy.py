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

# 提交所有权：fact 只能经 nuwa commit 产生。分隔符覆盖 ; & | ( ) 换行引号反引号，
# 允许反斜杠转义与 $() 包装；带 --from <fact> 的 complete 是证据入账后的合法完成。
GLOBAL_OPT_RE = re.compile(
    r'(^|[;&|()\n]|\bsapper\s+)(\s*)((?:(?:--store|-s)(?:=(?:\"[^\"]*\"|\'[^\']*\'|[^\s;&|()]+)|\s+(?:\"[^\"]*\"|\'[^\']*\'|[^\s;&|()]+)|[^\s;&|()]+)?\s*)+)')


def strip_global_options(cmd: str) -> str:
    return GLOBAL_OPT_RE.sub(r"\1\2", cmd)


PROMPT_RULES = [
    (r"(?:^|[;&|()\n\r\t\"'`\s]|\$\()\s*\\?(?:\S*[\\/])?sapper\s+"
     r"(?:done\s+\S+|dispatch\s+i\d+|complete\b)", "P-006"),
]

# 写类工具的目标路径：图与权威状态只能由 CLI 改（路径需先归一为绝对路径）。
PATH_RULES = [
    (r"(^|[\\/])\.sapper[\\/](facts|intents)(?:[\\/]|$)", "P-005"),
    (r"(^|[\\/])\.sapper[\\/]project\.json$", "P-009"),
    (r"(^|[\\/])\.nuwa[\\/](journal[^\\/]*\.jsonl|checkpoint[^\\/]*\.json|CURRENT|global[^\\/]*\.jsonl)$", "P-007"),
    (r"(^|[\\/])budget[\\/][^\\/]*\.jsonl$", "P-007"),
]

REDACT_RULES = [
    (re.compile(r"sk-[A-Za-z0-9]{8,}"), "sk-***"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"), r"\1***"),
    (re.compile(r"(?i)((?:token|api[_-]?key|secret|password)\s*[=:]\s*)\S+"), r"\1***"),
]


class PolicyError(RuntimeError):
    pass


def check_command(command: str) -> tuple[bool, str | None]:
    """工具层命令检查：危险命令 + 提交所有权。"""
    for pattern, rule_id in DENY_RULES:
        if re.search(pattern, command):
            return False, rule_id
    if re.search(r"\bsapper\b[^\n]*?[$`]", command):
        return False, "P-006"
    for pattern, rule_id in PROMPT_RULES:
        if re.search(pattern, strip_global_options(command)):
            return False, rule_id
    return True, None


def check_prompt(prompt: str) -> tuple[bool, str | None]:
    """渲染提示注入门：只查危险命令，不查提交所有权。

    sapper 自己的 dry-run 模板会提到 `sapper done` 等动作；把 P-006 放进这里
    会让正常派发被自身提示中止（审计 M9）。
    """
    for pattern, rule_id in DENY_RULES:
        if re.search(pattern, prompt):
            return False, rule_id
    return True, None


def check_path(path: str) -> tuple[bool, str | None]:
    """写类工具的路径闸门：图与权威状态目录只允许 CLI 写入。"""
    for pattern, rule_id in PATH_RULES:
        if re.search(pattern, path):
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
