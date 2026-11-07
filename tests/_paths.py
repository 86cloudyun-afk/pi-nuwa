"""测试路径解析：仓库内运行与沙盒内运行共用一套。"""
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _work() -> Path:
    env = os.environ.get("NUWA_WORK")
    if env:
        return Path(env)
    if (HERE.parent / "bin" / "nuwa").exists():
        return HERE.parent
    return Path("/tmp/nuwa-work")


WORK = _work()
NUWA = Path(os.environ.get("NUWA_BIN", WORK / "bin" / "nuwa"))
EXT = Path(os.environ.get("NUWA_EXT", WORK / "extensions" / "nuwa-loop" / "index.ts"))
INSTALL = Path(os.environ.get("NUWA_INSTALL", WORK / "install.sh"))
BIN = HERE
FAKE_CLAUDE = HERE / "fake-claude"
LAYER_A = HERE if (HERE / "sapper").exists() else HERE.parent
