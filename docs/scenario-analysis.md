# WOP 商户 SDK 使用场景分析与测试用例矩阵

> 版本：2026-08-29 · 依据：`wop-specs/sdk/wop-sdk-spec.md`（v1.0-ratified + 附录 D1–D5）
> 范围：wop-python-sdk 协议核心 + HTTP 适配层，从**商户接入生命周期**出发推导测试面，
> 并映射到现有测试 / Gherkin 场景（`tests/features/`）/ 变异测试防线。

## 1. 商户使用场景（自底向上：接入 → 出向 → 入向 → 运维）

SDK 的网关定位（spec §1）：商户**无需理解** canonicalRequest、套件推导与线上字节格式即可安全对接。
因此场景分析以"商户会做什么、会在哪一步犯错、平台会怎么攻击/出错"为主线：

| # | 使用场景 | 商户动作 | 涉及功能 | 主要风险（不测则漏） |
|---|---------|---------|---------|---------------------|
| S1 | 密钥与套件配置 | 拿到 appKey + 商户私钥 + 平台公钥，拼 `securityReq` 字符串 | F1, D12 | 跨族/非法套件被静默接受；密钥格式错误报错不明确 |
| S2 | 发起 L0 明文请求 | `build_request(method, path, body)`，把 draft 交给自己的 HTTP 栈 | F2, F3, F4, F9 | digest 缺席/不入签；nonce/timestamp 不齐；canonical 编码漂移（空格/中文/排序） |
| S3 | 发起 L2 加密请求 | 敏感字段全报文加密 | F5, F7 | 信封格式/DEK 载荷漂移；IV 复用；线上字节与网关不互认 |
| S4 | 重试/对账（确定性） | 网络超时重发、本地留痕对账 | §2 确定性 | 同输入不同输出导致对账失败、联调无法复现 |
| S5 | 校验平台响应（L0） | `verify_response(headers, body, path)` | F3, F4, F6, F7 | 验签顺序错（先解密后验签）；拒绝原因泄密（I7 oracle） |
| S6 | 校验平台响应（L2） | 验签 → digest → DEK 解包 → 族比对 → 解密 | F5, F6, I2/I3 | 篡改密文/跨族 DEK 被接受；错误分类不遵 D8/I7 |
| S7 | 校验平台回调 | `verify_callback(headers, body, callback_path)` | F6 | 回调 path 参与验签的语义与响应不一致 |
| S8 | 上线前向量自检 | README「向量自测」跑黄金向量 | F8, D2 三件套 | fixture 与真源漂移；负向量（tamper/`=`/跨族）不拒 |
| S9 | 错误处理与分类 | 按 `VerifyResult.error` / 异常类型编程 | I7, §10.2 | 模糊类泄密、明确类含糊，商户无法区分配置错 vs 攻击 |
| S10 | 传输接入与防护 | urllib/httpx/requests 任选；大响应 | Q1, D4 | 11MB 限额被整体缓冲架空；peer 适配器未装时提示不清 |

## 2. 测试用例矩阵（场景 × 用例 → 落点）

落点代号：`T:*` = 既有 pytest 文件；`B:*` = Gherkin 场景（tests/features/wop_merchant.feature）；
变异防线 = 变异测试对应该条的算子压力（`scripts/mutation_test.py`）。

### S1 配置

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S1-01 RSA3072/RSA4096 套件解析出全算法上下文（族/位长/tag/包装） | 逐字段断言 | T:test_suites.py | 常量/字典值变异 |
| S1-02 三段式格式错（前缀/段数/空串/None）→ SuiteParseError（明确） | 异常类型+消息 | T:test_suites.py, B:非法套件字符串被明确拒绝 | cmp/str 变异 |
| S1-03 未知密钥/摘要算法 → UnsupportedSuiteError | 明确 | T:test_suites.py, B:同上 | cmp 变异 |
| S1-04 跨族组合（WOP-RSA3072-SM3 / WOP-SM2-SHA256）→ 拒绝（I5） | 明确 | T:test_suites.py, B:跨族套件被拒绝 | cmp/bool 变异 |
| S1-05 密钥材料：PEM/单行 Base64、SPKI/PKCS8、SM2 点/标量；曲线/范围校验 | KeyMaterialError 分类 | T:test_keys.py | num/cmp 变异 |
| S1-06 appKey 空白 → WopSdkError | 配置期拒绝 | T:test_client.py | str/cmp 变异 |

### S2 L0 出向

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S2-01 POST 有 body：协议头齐全；digest `alg hex` 恰一空格且**入签**（I1/D2） | 结构+内容 | T:test_client.py, B:发起L0下单请求 | str/cmp 变异 |
| S2-02 GET 无 body：digest **缺席**、wire_body=None（D2 否定式） | 缺席合法 | T:test_client.py, B:无body查询请求不携带digest | bool/cmp 变异 |
| S2-03 canonical：header 名小写排序、值 trimall+Java-URLEncoder（空格→%20、中文/UTF-8） | 字节级对照 | T:test_canonical.py, T:test_encoding.py | str/算术变异 |
| S2-04 x-wop-sign 结构：`suite v1/expired/signedHeaders/sig` 四段、RSA3072=512 字符 | 结构 | T:test_client.py, B:L0请求签名头结构完整 | num 变异 |
| S2-05 expired_seconds 自定义入 authString | 生效 | T:test_client.py | num 变异 |
| S2-06 extra_headers：x-wop- 保留前缀覆盖协议头，应用头入 canonical 不覆盖协议头 | 边界 | T:test_client.py | cmp 变异 |
| S2-07 method 大小写/空白容忍（strip+upper） | 归一 | T:test_client.py, T:test_canonical.py | str 变异 |

### S3 L2 出向

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S3-01 L2 请求：`x-wop-encrypt: L2;dek=<b64url>` + JSON 信封体；digest 仍入签 | 结构 | T:test_client.py, T:test_envelope.py, B:发起L2加密请求 | str/cmp 变异 |
| S3-02 DEK 载荷 `alg$key$iv` 三段、alg 随套件族（AES-256-GCM/SM4-GCM） | 字节级（向量） | T:test_envelope.py（黄金向量） | 算术/常量变异 |
| S3-03 RSA-OAEP 显式双 SHA-256+空 label；SM2 C1C3C2 裸拼接 | 字节级（向量） | T:test_envelope.py, T:test_interop.py | 位运算/算术变异（MGF1/XOR） |
| S3-04 body 类型：bytes/str/dict；None→ValueError；其他→TypeError | 分类 | T:test_client.py | cmp/str 变异 |
| S3-05 IV/CEK 由 csprng 注入；nonce 池消费顺序合同 | 确定性流 | T:test_interop.py | 返回值变异 |

### S4 确定性/重放

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S4-01 同 timestamp+nonce+csprng → 草稿**逐字节一致**（幂等） | 字节级 | T:test_client.py, B:确定性重放逐字节一致 | 返回值/常量变异 |
| S4-02 未注入时 nonce 走 CSPRNG（16B hex、两次不同） | 存在性+随机 | T:test_client.py, B:L0请求携带防重放字段 | num/cmp 变异 |

### S5 入向 L0（F6 顺序：结构前置→验签→digest 复核）

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S5-01 合法响应：ok=True、plaintext=body | 通过 | T:test_client.py, B:平台L0响应验签通过 | 返回值变异 |
| S5-02 签名被篡改 → SignatureVerifyError，reason 模糊（I7） | 模糊 | T:test_client.py, B:响应签名被篡改时模糊拒绝 | str/cmp 变异 |
| S5-03 digest 与 body 不符 → DigestMismatchError（明确） | 明确 | T:test_client.py, B:响应摘要不匹配时明确拒绝 | cmp 变异 |
| S5-04 有 body 无 digest / 无 body 带 digest → 拒绝（D2 双向） | 明确 | T:test_client.py, B:响应体缺失digest被拒绝 | bool/cmp 变异 |
| S5-05 digest 未列入 signedHeaders → 拒绝（I1） | 明确 | T:test_client.py, T:test_interop.py | cmp 变异 |
| S5-06 签名长度前置校验（RSA3072≠384B、SM2≠64B、DER 拒） | 解析类先于密码学 | T:test_signature.py | num/cmp 变异 |
| S5-07 签名 b64url 带 `=` / 非法字符 / 非规范尾随位 → 拒（F7/D1） | 解析类 | T:test_encoding.py, B:带填充的签名编码被拒绝 | 位运算/cmp 变异 |
| S5-08 signedHeaders 声明的头缺席 / x-wop-sign 缺席 / 版本非 v1 / 段数错 | 解析类 | T:test_client.py, B:签名头缺失时明确拒绝 | cmp/num 变异 |
| S5-09 响应声明套件 ≠ 商户配置 → UnsupportedSuiteError | 明确 | T:test_client.py, B:响应套件与配置不符被拒绝 | cmp 变异 |
| S5-10 path/query 参与验签：错 path、错 qs 必拒 | 完整性 | T:test_client.py | str 变异 |

### S6 入向 L2

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S6-01 合法 L2 响应 roundtrip：解密得原文 | ok+plaintext | T:test_client.py, B:平台L2响应解密成功 | 返回值变异 |
| S6-02 密文/DEK 篡改 → DecryptError 模糊（I7） | 模糊 | T:test_client.py, T:test_envelope.py, B:密文被篡改时模糊拒绝 | str/cmp 变异 |
| S6-03 DEK alg 跨族 → DekConsistencyError（明确，D8 顺序：解包后、解密前） | 明确 | T:test_envelope.py, T:test_interop.py | cmp 变异 |
| S6-04 信封 JSON：未知字段容忍、非 JSON/缺 encrypted → 解析类明确（D3） | 明确 | T:test_envelope.py | str/cmp 变异 |
| S6-05 GCM tag 错 / SM2 C3 错 / OAEP 错 → 一律"解密失败" | 模糊 | T:test_envelope.py, T:test_sm2crypto 系 | 位运算变异 |

### S7 回调

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S7-01 合法回调（method 恒 POST、URI 取回调 path）→ ok | 通过 | T:test_client.py, B:平台回调验签通过 | str 变异 |
| S7-02 回调签名错 → 模糊拒绝 | 模糊 | T:test_client.py | cmp 变异 |

### S8 向量自检（F8/D2 三件套）

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S8-01 digest/signature/keyEncrypt/dekPayload 黄金向量字节级一致 | byte-exact | T:test_digest/test_signature/test_envelope | 全算子 |
| S8-02 formatRules 12 条全量循环+未知 id 哨兵+条数哨兵 | 三件套 | T:test_digest/test_encoding | num 变异 |
| S8-03 负向量：tamper/跨族/错长度/带 `=`/非规范尾随位全拒 | 拒绝 | T:test_*（各文件负例） | cmp/位运算变异 |
| S8-04 interop/v1 29 条样本（真源独立构造） | 合同 | T:test_interop.py | 全算子 |

### S9 错误分类（I7/§10.2）

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S9-01 模糊类（验签/解密）对外恒定文案，不泄原因细节 | 模糊 | T:test_client/test_envelope, B:篡改场景×3 | str 变异 |
| S9-02 明确类（解析/完整性/一致性/配置/支持）给出可行动信息 | 明确 | T:test_suites/test_keys/test_client | str 变异 |
| S9-03 VerifyResult.error 携带原始分类异常供编程处理 | 结构 | T:test_client.py | 返回值变异 |

### S10 传输与限额（Q1/D4）

| 用例 | 期望 | 落点 | 变异防线 |
|------|------|------|---------|
| S10-01 read_capped 流式累计，恰 11MB 通过、超 1 字节即断 | 边界 | T:test_transports.py | num/cmp 变异 |
| S10-02 urllib/httpx/requests 适配器：URL 拼接、头归一小写、4xx/5xx 走 body | 行为 | T:test_transports.py, T:test_transports_real.py | str 变异 |
| S10-03 peer 未安装 → ImportError 带安装指引 | 提示 | T:test_transports.py | str 变异 |
| S10-04 send_draft URL=base+path（rstrip 斜杠） | 拼接 | T:test_transports.py | str 变异 |

## 3. D5 纪律执行说明（入向测试的平台侧构造）

- **RSA L0/L2 平台响应**：BDD 步骤内以 `cryptography` 原语**独立组装**（PKCS1v15 签名、AESGCM、
  OAEP(双 SHA-256/空 label)、手工 5 段 canonical），不复用 `wop_sdk.client` 出向路径。
- **SM2 L2 平台响应**：以 `sm2crypto`/`sm4gcm` **底层原语**手工组装（C1C3C2、DEK 载荷自拼），
  不复用 `seal_l2`/`build_request` 组合层；底层原语本身已被黄金向量字节级锚定（S8-01），
  镜像偏差风险由向量测试独立兜底。
- 既有 pytest 已按同原则编写（test_interop 消费 wop-specs 真源样本）。

## 4. 三层防线关系

1. **pytest 单元/合同测试**（283 用例）：锁行为与字节；
2. **Gherkin 场景**（tests/features/wop_merchant.feature，21 场景）：以商户旅程为纲做验收级回归，
   覆盖 S1–S10 主路径与关键负路径；
3. **变异测试**（scripts/mutation_test.py，14 类算子）：在 1+2 全绿基础上度量测试集**杀伤力**
   （条件/数学/返回值/常量/控制流），报告见 docs/mutation-report.md。
