"""意图级 worker 包装器：先加锁、写 ready、fork+wait 业务命令、写 result。"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nuwa.locks import FileLock  # noqa: E402


def _starttime(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        return int(fields[21])
    except (OSError, ValueError, IndexError):
        return 0


def _atomic(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", required=True)
    ap.add_argument("--ready", required=True)
    ap.add_argument("--result", required=True)
    ap.add_argument("--stdout", required=True)
    ap.add_argument("--stderr", required=True)
    ap.add_argument("--intent", required=True)
    ap.add_argument("--attempt", type=int, default=0)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        print("worker: missing command", file=sys.stderr)
        return 2

    lock = FileLock(args.lock, blocking=True)
    with lock:
        pid = os.getpid()
        _atomic(Path(args.ready), {
            "pid": pid, "starttime": _starttime(pid),
            "attempt": args.attempt, "ts": time.time(),
        })
        started = time.time()
        with open(args.stdout, "wb") as out, open(args.stderr, "wb") as err:
            proc = subprocess.Popen(cmd, stdin=sys.stdin.buffer, stdout=out, stderr=err,
                                    pass_fds=(lock.fd,))
            rc = proc.wait()
        _atomic(Path(args.result), {
            "exit_code": rc, "started_at": started, "finished_at": time.time(),
            "attempt": args.attempt, "pid": pid,
        })
    return rc


if __name__ == "__main__":
    sys.exit(main())
