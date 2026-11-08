"""文件锁：run.lock / txn.lock / inflight/<intent>.lock。"""
from __future__ import annotations

import fcntl
import os
from pathlib import Path


class LockTimeout(RuntimeError):
    pass


class FileLock:
    """flock 封装；blocking=False 时拿不到立即抛 LockTimeout。"""

    def __init__(self, path: str | Path, blocking: bool = False, create: bool = True):
        self.path = Path(path)
        self.blocking = blocking
        self.create = create
        self._fd: int | None = None

    def __enter__(self) -> "FileLock":
        if self.create:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | (os.O_CREAT if self.create else 0)
        self._fd = os.open(self.path, flags, 0o600)
        try:
            fcntl.flock(self._fd, fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            os.close(self._fd)
            self._fd = None
            raise LockTimeout(f"locked: {self.path}")
        return self

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise RuntimeError("lock not acquired")
        return self._fd

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


def is_locked(path: str | Path) -> bool:
    """True 表示当前有进程持有该文件的 flock。"""
    p = Path(path)
    if not p.exists():
        return False
    try:
        fd = os.open(p, os.O_RDWR)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


def try_acquire(path: str | Path) -> FileLock | None:
    lock = FileLock(path, blocking=False)
    try:
        return lock.__enter__()
    except LockTimeout:
        return None
