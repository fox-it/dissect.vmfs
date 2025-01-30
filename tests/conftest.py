from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


@pytest.fixture
def vmfs5() -> Iterator[BinaryIO]:
    name = "data/vmfs5.bin.gz"
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh


@pytest.fixture
def vmfs6() -> Iterator[BinaryIO]:
    name = "data/vmfs6.bin.gz"
    with gzip.GzipFile(absolute_path(name), "rb") as fh:
        yield fh
