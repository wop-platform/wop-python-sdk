# 变异测试报告（wop-python-sdk）

- 工具：`scripts/mutation_test.py`（自研 token 级变异器，PIT 不适用 Python）
- 生成：2026-08-31 13:18:14
- 变异体：865（击杀 862 / 存活 0 / 等价（白名单）3，另有 4 个无覆盖行变异点被排除）
- **击杀率：100.00%**（= 击杀 862 / 计分基数 862；等价体已从分母剔除）

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
| num-inc | 136/136 | 100.0% |
| num-zero | 125/125 | 100.0% |
| str-mut | 234/234 | 100.0% |
| bool-flip | 11/11 | 100.0% |
| return-none | 68/68 | 100.0% |
| raise-drop | 78/78 | 100.0% |

## 等价变异体（3，白名单自动标注，论证随单一来源生成）

| 文件:行 | 算子 | 原文 → 变异 | 论证 |
|---|---|---|---|
| src/wop_sdk/encoding.py:17 | str-mut | `"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm → "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm` | 字母表字符串尾部追加 → _B64URL_INDEX 仅多一个永不查询的键，且字母表正则先于查表拒绝非 base64url 字符，行为不可观测 |
| src/wop_sdk/transports/httpx_transport.py:40 | str-mut | `"HttpxTransport" → "HttpxTransport!"` | def __enter__(self) -> "HttpxTransport"：惰性求值返回类型注解字符串，运行时不可观测 |
| src/wop_sdk/transports/requests_transport.py:43 | str-mut | `"RequestsTransport" → "RequestsTransport!"` | 同上（"RequestsTransport" 注解字符串） |
