# WOP Python SDK

The official merchant-side Python client library for the WOP gateway. It encapsulates
the protocol core (suite parsing / structured signing / content digest / L2 digital
envelope / verify-and-decrypt) plus a pluggable HTTP adapter layer, so merchants can
integrate securely without understanding canonicalRequest, suite derivation or the
wire byte formats.

- Python ≥ 3.9
- All three suites supported: `WOP-RSA3072-SHA256` / `WOP-RSA4096-SHA256` / `WOP-SM2-SM3`
- Crypto dependencies (the single designated path): `cryptography` (RSA/AES) +
  `gmssl ≥ 3.2.2` (SM2/SM3/SM4)
- Zero extra runtime dependencies in the core; HTTP adapters ship as peer
  dependencies (`wop-sdk[httpx]` / `wop-sdk[requests]`)

## Quick Start

```bash
pip install wop-sdk            # or from source: pip install -e .
pip install 'wop-sdk[httpx]'   # optional: httpx peer adapter (requests extras also available)
```

```python
from wop_sdk import WopClient, WopConfig
from wop_sdk.transports import UrllibTransport, send_draft

client = WopClient(WopConfig(
    app_key="app_10012481831",
    suite="WOP-RSA3072-SHA256",            # or WOP-RSA4096-SHA256 / WOP-SM2-SM3
    merchant_private_key=MERCHANT_PRIV_PEM,  # merchant private key (PEM or single-line Base64)
    platform_public_key=PLATFORM_PUB_PEM,    # platform public key (PEM or single-line Base64)
    gateway_base_url="https://wop.example.com",
))

# L0 plaintext request
draft = client.build_request("POST", "/gateway/order.create", {"orderId": 42})

# Send with any HTTP stack; here the stdlib urllib adapter
resp = send_draft(UrllibTransport(), client._config.gateway_base_url, draft)

# Verify the platform response (fixed F6 order: verify signature → digest recheck →
# DEK unwrap → alg family comparison → bulk decrypt)
result = client.verify_response(resp.headers, resp.body, "/gateway/order.create")
if result.ok:
    print(result.plaintext)
else:
    print(result.reason)  # signature/decrypt failures are blurred (I7); format /
                          # integrity / consistency errors are explicit
```

## Key Preparation

Keys are passed as strings (PEM or single-line Base64) and parsed inside the SDK
(D12 distribution contract):

| Suite | Merchant private key | Platform public key | Constraint |
|-------|----------------------|---------------------|------------|
| `WOP-RSA3072-SHA256` | PKCS#8 DER, Base64/PEM | X.509 SPKI DER, Base64/PEM | must be 3072-bit |
| `WOP-RSA4096-SHA256` | same | same | must be 4096-bit |
| `WOP-SM2-SM3` | scalar `d`, 32 bytes, Base64 | uncompressed point `04‖X‖Y`, 65 bytes, Base64 | the point must lie on sm2p256v1 (I5) |

- RSA keys accept both PEM wrappers (`-----BEGIN PUBLIC KEY-----`) and bare Base64;
- SM2 material fed to an RSA suite (or vice versa) is rejected at configuration time;
  cross-family suite combinations (e.g. `WOP-RSA3072-SM3`) are rejected at parse time.

## L0 / L2 Examples

### L0 (plaintext; the digest is the only integrity line of defense)

```python
draft = client.build_request("POST", "/gateway/order.query", {"orderId": 42})
# With a body, x-wop-content-digest is always produced and always enters
# signedHeaders (D2/I1); with no body (GET) the header is absent.
```

### L2 (digital envelope: full-body AES-256-GCM / SM4-GCM encryption)

```python
draft = client.build_request("POST", "/gateway/order.create", {"card": "6222..."}, level="L2")
# wire_body = {"encrypted":"<base64url(ciphertext||tag)>"}
# x-wop-encrypt: L2;dek=<base64url(OAEP/SM2-wrapped DEK payload)>
# DEK and IV are freshly generated via CSPRNG on every call (I4: an IV is never
# reused under the same key).

result = client.verify_response(resp.headers, resp.body, "/gateway/order.create")
# result.plaintext = the decrypted business payload

# Callback verification (URI is the callback path; method is always POST)
cb = client.verify_callback(cb_headers, cb_body, "/callback/notify")
```

Wire formats (F7/D9/D10): everything is base64url **without padding** (`=` strictly
rejected); RSA signatures are PKCS#1 v1.5; SM2 signatures are raw `r‖s` 64 bytes
(DER forbidden); SM2 ciphertext is bare `C1C3C2` (C1 = uncompressed point, 65B);
RSA-OAEP uses explicit double SHA-256 with an empty label.

## Vector Self-Test

The golden vector fixture lives at `tests/fixtures/crypto-vectors.json` (byte-identical
to the gateway source of truth; do not edit). Re-run the conformance suite locally:

```bash
pip install -e '.[httpx]' coverage
python3 -m pytest --cov=wop_sdk --cov-branch --cov-fail-under=98
```

Covered: byte-exact RSA3072/4096 and SM2 signatures, OAEP wrap/unwrap, byte-exact
AES-256-GCM and SM4-GCM ciphertexts, SM3/SHA-256 digests, DEK payload assembly, and
every digest-header format rule. Negative vectors include tampering, cross-family
material, 63-byte / 65-byte signatures, base64url with `=`, the legacy C1C2C3
ordering, and the MGF1-SHA1 trap ciphertext — all must be rejected. CI runs the
same command on a 3.9–3.14 matrix.

## Error Handling and Blurring

- **Explicit** (public protocol knowledge, to help integration debugging): suite
  format/cross-family errors, key material errors, digest header format and mismatch,
  DEK alg vs suite family inconsistency;
- **Blurred** (key-dependent decisions, oracle-resistant, I7): "签名验证失败"
  (signature verification failed) and "解密失败" (decryption failed) — external
  messages never distinguish tag failure from wrong key or similar details.
