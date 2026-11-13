"""dispatch 前的本地知识库注入：CVE / 产品卡 / FTS 兜底。

设计约束：
- 默认关闭，bin/nuwa 入口显式 export NUWA_KB=1；程序化 dispatch 与测试保持 4000 预算不变。
- 只读 kb.db；任何异常都退化为空块，不影响派单。
- 输出包在 <kb-data trust="reference-only"> 里，且逐行过滤危险命令，避免 PoC 文本触发 P-001..P-004。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path

DEFAULT_DB = "/data/nuwa-kb/kb.db"
DENY_RULES = [
    r"rm\s+-rf\s+/(\s|$)",
    r"mkfs\.",
    r"dd\s+.*of=/dev/[sh]d",
    r"curl[^\n]*--noproxy[^\n]*\b(169\.254|127\.0\.0\.1)",
]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.+-]{4,}")
STOP = {
    "target", "service", "server", "http", "https", "please", "using", "check",
    "which", "there", "these", "those", "with", "from", "that", "this", "have",
    "into", "about", "after", "before", "scan", "probe", "intent", "fact",
}

ALIASES = {
    "tomcat": ("apache", "tomcat"),
    "weblogic": ("oracle", "weblogic_server"),
    "exchange": ("microsoft", "exchange_server"),
    "sharepoint": ("microsoft", "sharepoint_server"),
    "confluence": ("atlassian", "confluence"),
    "jira": ("atlassian", "jira"),
    "gitlab": ("gitlab", "gitlab"),
    "jenkins": ("jenkins", "jenkins"),
    "vcenter": ("vmware", "vcenter_server"),
    "esxi": ("vmware", "esxi"),
    "fortigate": ("fortinet", "fortios"),
    "fortios": ("fortinet", "fortios"),
    "citrix": ("citrix", "application_delivery_controller"),
    "nginx": ("nginx", "nginx"),
    "struts": ("apache", "struts"),
    "log4j": ("apache", "log4j"),
    "solr": ("apache", "solr"),
    "wordpress": ("wordpress", "wordpress"),
    "zimbra": ("zimbra", "zimbra_collaboration_suite"),
}


def db_path() -> Path:
    return Path(os.environ.get("NUWA_KB_DB", DEFAULT_DB))


def enabled() -> bool:
    return os.environ.get("NUWA_KB") == "1" and db_path().exists()


def budget() -> int:
    try:
        return max(200, int(os.environ.get("NUWA_KB_TOKENS", "1200")))
    except ValueError:
        return 1200


def estimate_tokens(text: str) -> int:
    cjk = len(re.findall(r"[\u4e00-\u9fff]", text))
    return cjk + max(1, (len(text) - cjk) // 4)


def sanitize(text: str) -> str:
    out = []
    for line in text.splitlines():
        if any(re.search(p, line) for p in DENY_RULES):
            continue
        out.append(line)
    return "\n".join(out)


def _connect():
    con = sqlite3.connect(str(db_path()))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    return con


def _facts_text(root: str | Path | None) -> str:
    if not root:
        return ""
    parts = []
    for p in sorted((Path(root) / ".sapper" / "facts").glob("*.json")):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for k in ("description", "detail", "data"):
            v = d.get(k)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                parts.extend(str(x) for x in v.values() if isinstance(x, str))
    return "\n".join(parts)


def _cve_lines(con, cid: str) -> list[str]:
    row = con.execute("SELECT cve_id,cvss,severity,descr FROM cve WHERE cve_id=?",
                      (cid,)).fetchone()
    if not row:
        return []
    kev = con.execute("SELECT 1 FROM kev WHERE cve_id=?", (cid,)).fetchone()
    epss = con.execute("SELECT score FROM epss WHERE cve_id=?", (cid,)).fetchone()
    line = (f"[{row['cve_id']}] CVSS {row['cvss']} {row['severity']} "
            f"KEV={1 if kev else 0} EPSS={epss['score'] if epss else '-'} | "
            f"{(row['descr'] or '').replace(chr(10), ' ')[:180]}")
    out = [line]
    tpls = [r["path"] for r in con.execute(
        "SELECT t.path FROM template t JOIN template_cve_map m ON m.template_id=t.id "
        "WHERE m.cve_id=? LIMIT 2", (cid,))]
    for t in tpls:
        out.append(f"  nuclei: {t}")
    poc = con.execute("SELECT url FROM poc WHERE cve_id=? LIMIT 1", (cid,)).fetchone()
    if poc:
        out.append(f"  poc: {poc['url']}")
    return out


def _card_lines(con, key: str) -> list[str]:
    row = con.execute("SELECT title,body FROM card WHERE key=?", (key,)).fetchone()
    if not row:
        return []
    body = "\n".join("  " + ln for ln in (row["body"] or "").splitlines()[:10])
    return [f"[card {key}] {row['title']}", body]


def enrich(prompt: str, root: str | Path | None = None,
           budget_tokens: int | None = None) -> str:
    if not enabled():
        return ""
    limit = budget_tokens or budget()
    try:
        con = _connect()
        lines: list[str] = []
        text = prompt + "\n" + _facts_text(root)

        for cid in list(dict.fromkeys(CVE_RE.findall(prompt)))[:3]:
            lines += _cve_lines(con, cid.upper())

        lower = text.lower()
        hits = []
        for alias, key in ALIASES.items():
            if re.search(rf"\b{re.escape(alias)}\b", lower):
                hits.append(key)
        for key in list(dict.fromkeys(hits))[:2]:
            lines += _card_lines(con, f"{key[0]}:{key[1]}")

        if not lines:
            terms = [t.lower() for t in TOKEN_RE.findall(prompt) if t.lower() not in STOP][:3]
            if terms:
                q = " AND ".join(terms)
                rows = con.execute(
                    "SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ? "
                    "ORDER BY bm25(cve_fts) LIMIT 3", (q,)).fetchall()
                for r in rows:
                    lines += _cve_lines(con, r["cve_id"])

        if not lines:
            return ""
        lines = sanitize("\n".join(lines)).splitlines()
        while lines and estimate_tokens("\n".join(lines)) > limit - 20:
            lines.pop()
        if not lines:
            return ""
        block = ('<kb-data source="local:kb.db" trust="reference-only">\n'
                 + "\n".join(lines) + "\n</kb-data>")
        return block
    except Exception:  # noqa: BLE001  知识库异常不影响派单
        return ""
