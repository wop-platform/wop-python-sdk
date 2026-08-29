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


# ---------- formatRules 三件套哨兵（spec:A2）----------
# 已知 id 全集按消费端分域：header-* 由 test_digest 消费（check_digest_header 格式层），
# b64url-* 由 test_encoding 消费（b64url_decode）。真源向量增删/改名时，
# 两个消费端的"未知 id 哨兵 + 条数哨兵"都会先炸，强制测试侧显式接入（禁止静默跳过）。
HEADER_RULE_IDS = frozenset(
    {
        "header-rsa-ok",
        "header-sm2-ok",
        "header-crossfamily",
        "header-double-space",
        "header-uppercase-hex",
        "header-wrong-hex-len",
    }
)
B64URL_RULE_IDS = frozenset(
    {
        "b64url-with-padding",
        "b64url-illegal-char",
        "b64url-trailing-bits-noncanonical-2",
        "b64url-trailing-bits-canonical-2",
        "b64url-trailing-bits-noncanonical-3",
        "b64url-trailing-bits-canonical-3",
    }
)
ALL_FORMAT_RULE_IDS = HEADER_RULE_IDS | B64URL_RULE_IDS
FORMAT_RULES_COUNT = 12

@pytest.fixture(scope="session")
def vec_keys():
    return VECTORS["keys"]
