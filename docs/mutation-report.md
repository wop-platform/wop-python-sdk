# 变异测试报告（wop-python-sdk）

- 工具：`scripts/mutation_test.py`（自研 token 级变异器，PIT 不适用 Python）
- 生成：2026-08-31 10:41:54
- 变异体：863（击杀 858 / 存活 0 / 等价（白名单）5，另有 6 个无覆盖行变异点被排除）
- **击杀率：100.00%**（= 击杀 858 / 计分基数 858；等价体已从分母剔除）

## 按算子（等价体不计入）

| 算子 | 击杀/计分 | 击杀率 |
|---|---|---|
| cmp-eq-neg | 51/51 | 100.0% |
| cmp-boundary | 12/12 | 100.0% |
| bool-and-or | 29/29 | 100.0% |
| not-drop | 20/20 | 100.0% |
| arith-add-sub | 56/56 | 100.0% |
| arith-mul-div | 27/27 | 100.0% |
| bitwise-and-or | 7/7 | 100.0% |
| bitwise-xor | 8/8 | 100.0% |
| num-inc | 134/134 | 100.0% |
| num-zero | 125/125 | 100.0% |
| str-mut | 233/233 | 100.0% |
| bool-flip | 11/11 | 100.0% |
| return-none | 68/68 | 100.0% |
| raise-drop | 77/77 | 100.0% |

## 等价变异体（5，白名单自动标注）

| 文件:行 | 算子 | 原文 → 变异 |
|---|---|---|
| src/wop_sdk/encoding.py:17 | str-mut | `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm → "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm` |
| src/wop_sdk/sm2crypto.py:19 | num-inc | `16 → 17` |
| src/wop_sdk/sm2crypto.py:24 | num-inc | `256 → 257` |
| src/wop_sdk/transports/httpx_transport.py:40 | str-mut | `"HttpxTransport" → "HttpxTransport!"` |
| src/wop_sdk/transports/requests_transport.py:43 | str-mut | `"RequestsTransport" → "RequestsTransport!"` |
