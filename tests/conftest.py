from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from logpulse.store import LocalReportStore, set_store  # noqa: E402

SAMPLES = ROOT / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture
def sample_text():
    def load(relative: str) -> str:
        return (SAMPLES / relative).read_text(encoding="utf-8")

    return load


@pytest.fixture
def local_store(tmp_path):
    store = LocalReportStore(tmp_path / "db")
    set_store(store)
    yield store
    set_store(None)
