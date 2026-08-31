# WOP Python SDK

[![PyPI](https://img.shields.io/pypi/v/wop-python-sdk)](https://pypi.org/project/wop-python-sdk/) [![Python 3.9+](https://img.shields.io/pypi/pyversions/wop-python-sdk)](https://pypi.org/project/wop-python-sdk/) [![Release](https://img.shields.io/github/v/release/wop-platform/wop-python-sdk)](https://github.com/wop-platform/wop-python-sdk/releases)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/wop-platform/wop-python-sdk?utm_source=oss&utm_medium=github&utm_campaign=wop-platform%2Fwop-python-sdk&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)


WOP 网关商户侧官方 Python 客户端库：封装协议核心（套件解析 / 结构化签名 / 内容摘要 /
L2 数字信封 / 验签解密）与可插拔 HTTP 适配层，使商户无需理解 canonicalRequest、
算法套件推导与线上字节格式即可安全对接网关。

- 协议真源：[crypto-strategy-spec.md](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-strategy-spec.md)（v0.3-reviewed）+ [wop-sdk-spec.md](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)（v1.0-ratified）
- 向量真源：[crypto-vectors.json](https://github.com/wop-platform/wop-specs/blob/main/crypto/crypto-vectors.json)（本仓 fixture 为字节级副本，禁手改）
- Python ≥ 3.9
- 三套件全支持：`WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`
- 密码依赖（唯一指定路径）：`cryptography`（RSA/AES）+ `gmssl ≥ 3.2.2`（SM2/SM3/SM4）
- 主包零额外依赖；HTTP 适配器以 peer 依赖交付（`wop-python-sdk[httpx]` / `wop-python-sdk[requests]`）

## 快速开始

```bash
pip install wop-python-sdk            # 或从源码：pip install -e .
pip install 'wop-python-sdk[httpx]'   # 可选：httpx peer 适配器（另含 requests extras）
```

```python
from wop_sdk import WopClient, WopConfig
from wop_sdk.transports import UrllibTransport, send_draft

client = WopClient(WopConfig(
    app_key="app_10012481831",
    suite="WOP-RSA3072-SHA256",            # 或 WOP-RSA4096-SHA256 / WOP-SM2-SM3
    merchant_private_key=MERCHANT_PRIV_PEM,  # 商户私钥（PEM 或 Base64 单行）
    platform_public_key=PLATFORM_PUB_PEM,    # 平台公钥（PEM 或 Base64 单行）
    gateway_base_url="https://wop.example.com",
))

# L0 明文请求
draft = client.build_request("POST", "/gateway/order.create", {"orderId": 42})

# 发送（任意 HTTP 栈；此处 stdlib urllib 适配器）
resp = send_draft(UrllibTransport(), client._config.gateway_base_url, draft)

# 校验平台响应（F6 固定顺序：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密）
result = client.verify_response(resp.headers, resp.body, "/gateway/order.create")
if result.ok:
    print(result.plaintext)
else:
    print(result.reason)  # 验签/解密失败对外模糊（I7），格式/完整性/一致性类明确
```

## 密钥准备

密钥入参为字符串（PEM 或 Base64 单行），SDK 内部解析（D12 分发契约）：

| 套件 | 商户私钥 | 平台公钥 | 约束 |
|------|----------|----------|------|
| `WOP-RSA3072-SHA256` | PKCS#8 DER，Base64/PEM | X.509 SPKI DER，Base64/PEM | 密钥必须 3072 位 |
| `WOP-RSA4096-SHA256` | 同上 | 同上 | 密钥必须 4096 位 |
| `WOP-SM2-SM3` | `d` 标量 32 字节，Base64 | 未压缩点 `04‖X‖Y` 65 字节，Base64 | 点必须在 sm2p256v1 曲线上（I5） |

- RSA 公钥与私钥均接受 PEM 包装（`-----BEGIN PUBLIC KEY-----`）或裸 Base64；
- SM2 材料喂给 RSA 套件（或反向）在配置期即拒绝；跨族算法组合（如 `WOP-RSA3072-SM3`）
  在套件解析期拒绝。

## L0 / L2 示例

### L0（明文，摘要为唯一完整性防线）

```python
draft = client.build_request("POST", "/gateway/order.query", {"orderId": 42})
# 有 body 必产 x-wop-content-digest 且必入 signedHeaders（D2/I1）；GET 无 body 则缺席
```

### L2（数字信封：AES-256-GCM / SM4-GCM 全文加密）

```python
draft = client.build_request("POST", "/gateway/order.create", {"card": "6222..."}, level="L2")
# wire_body = {"encrypted":"<base64url(ciphertext||tag)>"}
# x-wop-encrypt: L2;dek=<base64url(OAEP/SM2 包装的 DEK 载荷)>
# DEK 与 IV 每次调用 CSPRNG 新生成（I4：同一密钥下 IV 永不复用）

result = client.verify_response(resp.headers, resp.body, "/gateway/order.create")
# result.plaintext = 解密后的业务报文

# 回调校验（URI 取回调 path，方法恒 POST）
cb = client.verify_callback(cb_headers, cb_body, "/callback/notify")
```

线上字节格式（F7/D9/D10）：全部 base64url **无填充**（严格拒收 `=`）；
RSA 签名 = PKCS#1 v1.5；SM2 签名 = 裸 `r‖s` 64 字节（禁 DER）；
SM2 密文 = `C1C3C2` 裸拼接（C1 = 未压缩点 65B）；RSA-OAEP = 显式双 SHA-256 + 空 label。

## 向量自测

黄金向量 fixture 位于 `tests/fixtures/crypto-vectors.json`（与网关真源字节级一致，
禁手改）。本地复跑 conformance 套件：

```bash
pip install -e '.[httpx]' coverage
python3 -m pytest --cov=wop_sdk --cov-branch --cov-fail-under=98
```

覆盖：RSA3072/4096 与 SM2 签名字节级断言、OAEP 包装/解包、AES-256-GCM 与 SM4-GCM
密文字节级断言、SM3/SHA-256 摘要、DEK 载荷组装、digest 头全部格式规则；负向量含
tamper / 跨族 / 63B、65B 签名 / 带 `=` 的 base64url / C1C2C3 旧国标顺序 /
MGF1-SHA1 陷阱密文，全部必须拒绝。CI（3.9–3.14 × linux/macOS 矩阵）执行同一命令。

另消费 `wop-specs` 组织级 interop 样本集（`tests/fixtures/interop-cases.json` 字节
副本，sha256 哨兵钉死）：build 方向按冻结输入复现 draft（RSA byte-exact；SM2 按
opaque 剥离签名/包装段），verify 方向 23 条冻结样本逐条对账明文与错误分类
（canonical class 映射表见 `tests/test_interop.py`）。

## 错误处理与模糊化

- **明确**（公开协议知识，帮助集成自查）：套件格式/跨族、密钥材料、digest 头格式、
  缺失与不匹配（D2/I1 结构前置校验）、信封 JSON 形态与各 base64url 段（F7）、
  DEK alg 与套件族不符；
- **模糊**（依赖密钥参与，防 oracle，I7）：签名验证失败、解密失败——对外消息不区分
  tag 失败 / 密钥不符等原因细节；DEK 载荷（解包后明文）结构畸形除 alg 跨族外一律
  归入解密失败（interop 合同 n13 / 故障注入手册 P3）。
