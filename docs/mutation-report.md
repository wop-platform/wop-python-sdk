# 变异测试报告（wop-python-sdk）

- 工具：`scripts/mutation_test.py`（自研 token 级变异器，PIT 不适用 Python）
- 生成：2026-08-29 20:09:22
- 变异体：866（击杀 861 / 存活 5，另有 6 个无覆盖行变异点被排除）
- **击杀率：99.42%**（目标 ≥90%）

## 按算子

| 算子 | 击杀/总数 | 击杀率 |
|---|---|---|
| cmp-eq-neg | 51/51 | 100.0% |
| cmp-boundary | 12/12 | 100.0% |
| bool-and-or | 29/29 | 100.0% |
| not-drop | 20/20 | 100.0% |
| arith-add-sub | 59/59 | 100.0% |
| arith-mul-div | 29/29 | 100.0% |
| bitwise-and-or | 7/7 | 100.0% |
| bitwise-xor | 8/8 | 100.0% |
| num-inc | 132/134 | 98.5% |
| num-zero | 123/123 | 100.0% |
| str-mut | 234/237 | 98.7% |
| bool-flip | 11/11 | 100.0% |
| return-none | 69/69 | 100.0% |
| raise-drop | 77/77 | 100.0% |

## 存活变异体（5）

| 文件:行 | 算子 | 原文 → 变异 |
|---|---|---|
| src/wop_sdk/encoding.py:17 | str-mut | `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm → "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm` |
| src/wop_sdk/sm2crypto.py:19 | num-inc | `16 → 17` |
| src/wop_sdk/sm2crypto.py:24 | num-inc | `256 → 257` |
| src/wop_sdk/transports/httpx_transport.py:40 | str-mut | `"HttpxTransport" → "HttpxTransport!"` |
| src/wop_sdk/transports/requests_transport.py:43 | str-mut | `"RequestsTransport" → "RequestsTransport!"` |

## 存活体等价性分析（全部 5 个均为等价变异，无测试缺口）

| 文件:行 | 等价性论证 |
|---|---|
| encoding.py:17 | 字母表字符串尾部追加 `"!"` → `_B64URL_INDEX` 仅多一个永不查询的键 `"!"→64`；字母表正则先于查表拒绝非 base64url 字符，行为不可观测 |
| sm2crypto.py:19 | `int(default_ecc_table["n"], 16) → int(…, 17)`：十六进制数字 0-9a-f 全部合法 base-17 数字，解析结果同值 |
| sm2crypto.py:24 | `_MAX_K_RETRY 256 → 257`：CSPRNG 采样越界重试上界，二者均以 ≈1-2^-2048 概率首轮命中，行为不可区分 |
| httpx_transport.py:40 | `def __enter__(self) -> "HttpxTransport"` 返回类型注解字符串，惰性求值，运行时不可观测 |
| requests_transport.py:43 | 同上（`"RequestsTransport"` 注解字符串） |

补杀记录（tests/test_mutation_gaps.py，6 用例）：WopConfig/Sm2PublicKey frozen 契约、
SM2 私钥标量 d∈[1,n) 双侧边界（独立硬编码曲线阶，防镜像期望）、SM4-GCM 空 AAD 默认字节合同。
前三轮教训存档：首轮按字符偏移切字节导致变异体落入中文注释（假存活/假击杀，整轮作废），
已修复为 `ByteOffsetMap` 字节偏移并全量重跑；第三轮因回退测试集未含补杀文件重复第二轮结论，已修正。
