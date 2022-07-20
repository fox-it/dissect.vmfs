import os
import gzip
import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


@pytest.fixture
def vmfs5():
    name = "data/vmfs5.bin.gz"
    with gzip.GzipFile(absolute_path(name), "rb") as f:
        yield f


@pytest.fixture
def vmfs6():
    name = "data/vmfs6.bin.gz"
    with gzip.GzipFile(absolute_path(name), "rb") as f:
        yield f
