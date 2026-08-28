# -*- coding: utf-8 -*-
"""共享 fixture：黄金向量（tests/fixtures/crypto-vectors.json，禁手改）。"""
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))

_VECTORS_PATH = os.path.join(HERE, "fixtures", "crypto-vectors.json")
with open(_VECTORS_PATH, "r", encoding="utf-8") as _f:
    VECTORS = json.load(_f)


@pytest.fixture(scope="session")
def vectors():
    return VECTORS


@pytest.fixture(scope="session")
def vec_keys():
    return VECTORS["keys"]
