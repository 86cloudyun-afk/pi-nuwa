"""女娲包入口（兼容转发已归档的 v1 Python 模块至 archive/v1/nuwa/）。"""
from pathlib import Path as _Path

__version__ = "1.2.2"

_ARCHIVE_NUWA = _Path(__file__).resolve().parent.parent / "archive" / "v1" / "nuwa"
if _ARCHIVE_NUWA.is_dir():
    _archive_str = str(_ARCHIVE_NUWA)
    if _archive_str not in __path__:
        __path__.append(_archive_str)
