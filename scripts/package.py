"""Build dist/logpulse.zip: only the files the Function App needs.

Azure installs requirements.txt during deployment (remote build), so the zip
holds source code only: no .venv, tests, samples or local data.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INCLUDE_FILES = ["function_app.py", "host.json", "requirements.txt"]
INCLUDE_DIRS = ["logpulse"]
SKIP_PARTS = {"__pycache__", ".pytest_cache"}


def build(out: Path = ROOT / "dist" / "logpulse.zip") -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in INCLUDE_FILES:
            z.write(ROOT / name, name)
        for d in INCLUDE_DIRS:
            for path in sorted((ROOT / d).rglob("*")):
                if path.is_file() and not SKIP_PARTS & set(path.parts) and path.suffix != ".pyc":
                    z.write(path, path.relative_to(ROOT).as_posix())
    return out


if __name__ == "__main__":
    zip_path = build()
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
    print(f"built {zip_path} ({zip_path.stat().st_size // 1024} KB, {len(names)} files)")
    sys.exit(0)
