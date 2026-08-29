# WOP Python SDK 交付报告

- 仓库：`github.com/wop-platform/wop-python-sdk`（分支 main，共 12 commits，未推送）
- 任务：`/tmp/wop-task-python.md` + 公共段 `/tmp/wop-sdk-common.md`
- 真源：`gtsp-wop-gateway/docs/wop-sdk-spec.md`（v1.0-ratified）、`docs/crypto-strategy-spec.md`（v0.3-reviewed）、
  `docs/crypto-vectors.json`（字节级拷贝至 `tests/fixtures/crypto-vectors.json`，`cmp` 验证一致）
- 环境：Python 3.9.6（macOS ARM64）；cryptography 46.0.3、gmssl 3.2.2、pytest 8.4.2、coverage 7.x

## 1. 验收证据

### 1.1 全量测试绿（含向量 conformance 套件）

```
$ python3 -m pytest --cov=wop_sdk --cov-branch --cov-fail-under=98
214 passed in 2.18s
```

### 1.2 覆盖率原文（行 + 分支双 100%，门禁 ≥98%）

```
================================ tests coverage ================================
_______________ coverage: platform darwin, python 3.9.6-final-0 ________________

Name                                           Stmts   Miss Branch BrPart    Cover   Missing
--------------------------------------------------------------------------------------------
src/wop_sdk/__init__.py                            5      0      0      0 100.00%
src/wop_sdk/canonical.py                          12      0      4      0 100.00%
src/wop_sdk/client.py                            145      0     48      0 100.00%
src/wop_sdk/digest.py                             33      0     14      0 100.00%
src/wop_sdk/encoding.py                           34      0     18      0 100.00%
src/wop_sdk/envelope.py                          107      0     24      0 100.00%
src/wop_sdk/errors.py                             13      0      0      0 100.00%
src/wop_sdk/keys.py                               70      0     20      0 100.00%
src/wop_sdk/signature.py                          33      0     12      0 100.00%
src/wop_sdk/sm2crypto.py                          61      0     14      0 100.00%
src/wop_sdk/sm4gcm.py                             49      0     14      0 100.00%
src/wop_sdk/suites.py                             37      0     12      0 100.00%
src/wop_sdk/transports/__init__.py                15      0      0      0 100.00%
src/wop_sdk/transports/httpx_transport.py         16      0      0      0 100.00%
src/wop_sdk/transports/requests_transport.py      16      0      0      0 100.00%
src/wop_sdk/transports/urllib_transport.py        14      0      2      0 100.00%
--------------------------------------------------------------------------------------------
TOTAL                                            660      0    182      0 100.00%
Required test coverage of 98% reached. Total coverage: 100.00%
```

行覆盖 660/660 = 100%，分支覆盖 182/182 = 100%（A3/A4 达标）。仅 2 处 `pragma: no cover`
（CSPRNG 连续 256 次不可用采样 ≈2^-2048、KDF 全零 ≈2^-128，均不可确定性构造）。

### 1.3 README 双语存在性（A5）

```
$ ls README.md README.en.md LICENSE .github/workflows/ci.yml tests/fixtures/crypto-vectors.json
README.en.md
README.md
LICENSE
.github/workflows/ci.yml
tests/fixtures/crypto-vectors.json
```

四段必备齐备：快速开始 / 密钥准备（D12）/ L0+L2 示例 / 向量自测说明；`pip install -e .` 零错误零警告（A7）。

### 1.4 git log（全 conventional commits）

```
e66547d docs(readme): 中英双语四段(快速开始/密钥/L0L2/向量自测) + ci 3.9/3.12 矩阵与覆盖率门禁
6fc146f feat(transports): Transport 协议 + urllib/httpx/requests 适配器; test: 覆盖率缺口闭合至 100% 行+分支
92e4099 feat(client): buildRequest/verifyResponse F6 顺序编排 + I1/D2/F9 + L0/L2 roundtrip
05b0ab4 feat(envelope): AES/SM4-GCM + OAEP双SHA256 + SM2 C1C3C2 + DEK/I3/I7 (F5/D8/D10/A1/A2)
75f1a46 feat(signature): RSA PKCS1v15 + SM3withSM2 裸r||s 向量级实现 (F3/D9/A1/A2)
b826232 feat(digest): D2 恰一空格/小写hex/跨族拒绝 + SHA256/SM3 向量 (F4/I5)
e8a2dbb feat(keys): RSA SPKI/PKCS8 与 SM2 65B/32B 解析 + I5 曲线校验 (D12)
6642db2 feat(canonical): 5 段 canonicalRequest 与 Java 语义对齐 (F2)
47a986a fix(suites): 补回注册表闭合括号
d325631 fix(suites): 族标识统一为 RSA/SM
e65f143 feat(suites): securityReq 三套件解析与跨族拒绝 (F1/I5)
7ccae7f feat(encoding): base64url 严格无填充/小写 hex/Java URLEncoder 语义 (F2/F5/F7)
```

## 2. spec 条款 → 测试名反向核对矩阵

测试代码内以 `# spec:<ID>` 注释建 grep 索引；`grep -rn "spec:" tests/` 可复核。

| 条款 | 语义 | 测试（文件 :: 用例） |
|------|------|----------------------|
| F1 | securityReq 三套件解析/跨族/非法拒 | test_suites :: 全部（test_cross_family_rejected 标 I5） |
| F2 | canonicalRequest 5 段 + Java URLEncoder 语义 | test_canonical :: test_five_segments；test_encoding :: TestJavaUrlEncode 全部 |
| F3 | 结构化 x-wop-sign 商户私钥加签 | test_client :: test_sign_header_structure；test_signature :: 各 sign 向量 |
| F4 | digest header 恰一空格/随族/无body缺席/必入签 | test_digest :: 全部；test_client :: test_get_without_body_digest_absent、test_header_set_and_digest_signed |
| F5 | L2 信封 AES/SM4-GCM + OAEP/SM2 包装 | test_envelope :: 全部（含 seal/open roundtrip） |
| F6 | 验签→digest复核→DEK解包→族比对→bulk解密固定序 | test_client :: test_tampered_signed_header_fails_sign_first(①)、test_tampered_body_hits_digest_check(②)、test_digest_over_cipher_wire、test_dek_blurred_before_consistency_check_order(③)、test_verify_callback_same_flow |
| F7 | base64url 无填充拒 '='；SM2 裸 r‖s；SM2 C1C3C2；SPKI/点 | test_encoding :: test_reject_padding_char 等；test_client :: test_digest_b64_padding_signature_rejected |
| F8 | 向量字节级 + 负向量必拒 | 见 A1/A2 行 |
| F9 | CSPRNG nonce/毫秒时间戳/expiredSeconds | test_client :: test_header_set_and_digest_signed、test_expired_seconds_custom、test_deterministic_replay |
| A1 | 11 条正向量字节级 | test_digest :: digest-sha256/sm3；test_envelope :: aesgcm/sm4gcm/oaep3072/oaep4096/oaep-roundtrip/sm2-encrypt-fixedk/dek-rsa/dek-sm2；test_signature :: rsa3072/rsa4096/sm2-sign-fixedk |
| A2 | 负向量全部拒绝 | tamper（test_signature :: test_tampered_signature_rejected/test_tampered_r_rejected；test_envelope :: test_tampered_tag_*）、63B/65B（test_signature :: test_63b_rejected/test_65b_rejected）、DER（test_der_rejected）、带=（test_encoding :: test_reject_padding_char）、C1C2C3（test_envelope :: test_sm2_c1c2c3_mismatch_rejected）、MGF1-SHA1 陷阱（test_mgf1_sha1_trap_rejected）、跨族（test_suites/test_digest/test_envelope） |
| D2 | 恰一空格/小写hex/跨族/无body缺席/有body必传/摘要对象=wire字节 | test_digest :: TestFormatRules 全套；test_client :: D2 系列含 L2 密文载体 |
| D8/I3 | DEK alg 族比对在解包后、bulk 解密前 | test_envelope :: test_alg_cross_family_rejected_before_decrypt；test_client :: test_dek_blurred_before_consistency_check_order |
| D9 | SM2 三钉（r‖s/C1C3C2/禁 ASN.1） | test_signature :: test_sm2_fixedk_byte_exact、test_der_rejected；test_envelope :: test_sm2_c1c2c3_mismatch_rejected |
| D10 | OAEP 显式双 SHA-256+空 label | test_envelope :: test_oaep3072_unwrap、test_mgf1_sha1_trap_rejected |
| D12 | RSA=SPKI/PKCS8、SM2=65B点/32B d | test_keys :: 全部 |
| I1 | digest 必入 signedHeaders | test_client :: test_header_set_and_digest_signed（断言 signedNames 含 digest） |
| I2 | 先验签后解密 | test_client :: test_tampered_signed_header_fails_sign_first（签内头篡改先撞签名） |
| I4 | IV 生成点收敛/CSPRNG/永不复用 | 结构：全部随机经唯一 csprng 注入点；test_envelope :: test_seal_uses_fresh_iv_per_call；test_signature :: test_sign_k_out_of_range_resampled |
| I5 | 族互斥贯穿三处 + SM2 曲线校验 | suites（组合）、digest（标签）、dek（alg）、test_keys :: test_public_not_on_curve_rejected、test_client :: test_key_family_mismatch_rejected |
| I7 | 验签/解密失败对外模糊 | test_envelope :: test_wrong_key_same_blurred_message（不同原因同消息"解密失败"）；test_client :: F6 顺序用例断言模糊文案 |
| 10.2 | 错误分类明确/模糊分界 | errors.py 分类；test_digest :: test_mismatch_raises_integrity（完整性类明确） |

## 3. 实现要点与对 gmssl 缺陷的刻意偏离

1. **SM4-GCM 自研**（sm4gcm.py）：gmssl 3.2.2 无 GCM。以 gmssl `one_round`（无 padding 单块原语）
   为分组函数实现 SP 800-38D GCM（CTR+GHASH），`sm4gcm-encrypt` 向量字节级锚定（D11）。
   修复过一个真实 bug：GHASH 在解密方向必须作用于输入密文而非 CTR 输出（红-绿循环捕获）。
2. **SM2 层自研组装**（sm2crypto.py）：
   - gmssl `CryptSM2.__init__` 对 `public_key.lstrip("04")` 会以 ≈1/8 概率损坏合法密钥
     （X 以 '0'/'4' 字符开头）→ `Sm2Ops` 覆写 public_key 规避；
   - gmssl `decrypt` 计算摘要 u 却从不比对 C3 → 自研解密补 C3 完整性校验，
     C1C2C3 旧国标顺序负向量在此必然失败；
   - gmssl `encrypt`/`random_hex` 用 `random.choice`（非 CSPRNG）→ k 一律由调用方注入
     （生产 os.urandom，测试固定向量，I4 生成点收敛）。
3. **OAEP 显式参数**：`OAEP(mgf=MGF1(SHA256()), algorithm=SHA256(), label=None)`，MGF1-SHA1
   陷阱向量证明拒绝路径（D10/F2 头号跨语言漂移源）。
4. **canonicalRequest**：断言逐条移植网关 `CanonicalRequestBuilderTest`（Java），Java URLEncoder
   语义（safe = `[A-Za-z0-9._*-]`、空格→%20、UTF-8 大写 %XX）精确复刻。
5. **formatRules 语义澄清**：`header-rsa-ok`（`sha-256` 标签配 SM3 hex）判定为格式层 accept、
   值层必拒 → API 拆 `check_digest_header`（格式）与 `verify_digest_header`（值）两层。
6. **Transport 层**：`Transport` Protocol + `send_draft`；stdlib urllib 适配器随主包，
   httpx/requests peer 适配器惰性导入（未装时给出 extras 安装指引），主依赖面仅
   cryptography + gmssl（任务书白名单）。

## 4. 工程约定

- src 布局 + pyproject.toml，Python ≥3.9，版本 0.1.0，MIT；
- extras：`wop-sdk[httpx]`、`wop-sdk[requests]`；
- CI（.github/workflows/ci.yml）：3.9/3.12 矩阵，coverage 行+分支 ≥98% 门禁；
- 向量 fixture 与真源 `cmp` 字节级一致，禁手改；
- 未推送（按任务书纪律）。
