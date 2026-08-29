# 贡献指南

## 1. 欢迎与定位

本仓库是 WOP 网关**商户侧官方 Python SDK**（`wop-python-sdk`），实现协议核心（套件解析 /
结构化签名 / 内容摘要 / L2 数字信封 / 验签解密）与可插拔 HTTP 适配层。所有协议行为
以 [WOP 商户 SDK 规格 v1.0（ratified）](https://github.com/wop-platform/wop-specs/blob/main/sdk/wop-sdk-spec.md)
为准（功能面 F1–F9、验收 A1–A7、工程约定 §4）；规格与本实现冲突时，先在规格仓库
提出议题，再动代码。

## 2. 开发环境

- Python ≥ 3.9（CI 矩阵：3.9 / 3.12，两个版本都必须过）
- 运行时依赖白名单（仅此两项，见任务书 E5）：`cryptography >= 41`、`gmssl >= 3.2.2`
- HTTP 适配器为 peer 依赖：`httpx >= 0.24` / `requests >= 2.28`（extras，不进核心依赖面）
- 测试工具链：`pytest` + `pytest-bdd` + `pytest-cov` + `coverage[toml]`（py<3.11 需 tomli 才能读
  pyproject 的 coverage 配置）
- 包管理：pip + pyproject.toml（setuptools 后端）

## 3. 构建与测试

命令与 `.github/workflows/ci.yml` 完全一致（本地请用干净虚拟环境复现）：

```bash
python -m pip install --upgrade pip
pip install -e '.[httpx]' pytest pytest-bdd pytest-cov 'coverage[toml]'

# 测试 + 覆盖率门禁（行 + 分支双维度 ≥ 98%，向量合规测试必须全绿）
python -m pytest --cov=wop_sdk --cov-branch --cov-fail-under=98

# 查看逐行明细（含未覆盖行号）
python -m coverage report --show-missing

# 构建发布产物（sdist + wheel）
pip install --group dev   # 或直接 pip install build
python -m build
```

覆盖率门禁：CI 以 `--cov-fail-under=98` 强制**行与分支**同时 ≥ 98%，未达标即失败。
门禁是下限不是目标——新增代码应按 100% 覆盖设计（负向分支同样要测到）。

## 4. 黄金向量纪律

`tests/fixtures/crypto-vectors.json` 是协议正确性的**唯一锚**，与网关真源字节级一致，
**禁止手改**。

- 新增/变更协议行为时：必须先在网关侧更新向量真源，再全量同步本仓库 fixture，
  并保证全量消费测试通过；
- 负向量（tamper 篡改 / 跨族算法组合 / 错误格式：63B/65B 签名、带 `=` 的 base64url、
  C1C2C3 旧国标顺序、MGF1-SHA1 陷阱密文等）必须有对应测试且**全部拒绝**——
  "错误输入被正确拒绝"与"正确输入被接受"同等重要；
- 任何"向量过不了就改向量"的 PR 一律拒绝。

## 5. 编码规范

- 遵循 PEP 8；类型标注随代码提交（公网 API 必须完整标注）；
- 运行时依赖白名单之外**零新增**（新增密码原语必须先过规格评审）；
- 协议实现必须对齐规格功能面：
  - **F1** 套件解析：三套件（RSA3072/4096-SHA256、SM2-SM3），跨族组合在解析期拒绝；
  - **F2** canonicalRequest：结构化规范化，字段集合与顺序不得偏离规格；
  - **F3** 签名：RSA = PKCS#1 v1.5；SM2 = 裸 `r‖s` 64 字节（禁 DER）；
  - **F4** 内容摘要：有 body 必产 `x-wop-content-digest` 且必入 signedHeaders（D2/I1），
    GET 无 body 则该头缺席合法；
  - **F5** 数字信封：DEK 每次调用 CSPRNG 新生成，IV 永不复用（I4）；
  - **F6** 校验顺序固定：验签 → digest 复核 → DEK 解包 → alg 族比对 → bulk 解密；
  - **F7** 字节格式：全部 base64url **无填充**（严格拒收 `=`）；SM2 密文 = C1C3C2
    裸拼接；RSA-OAEP = 显式双 SHA-256 + 空 label；
  - **F9** 防重放：时间戳/nonce 语义按规格实现；
  - **I7** 错误模糊化：签名验证失败与解密失败对外消息不区分原因细节（防 oracle）；
    格式/完整性/一致性类错误保持明确。

## 6. 提交规范

Conventional Commits：`feat` / `fix` / `test` / `docs` / `chore`（必要时 `refactor`）。
subject 用英文小写祈使句，body 用中文说明动机与影响面，涉及规格条款的在 body 中
引用条款号（如 `D2`、`F6`、`I7`）。

```
fix(sm2): reject DER-encoded signature per F7

裸 r‖s 64 字节为唯一合法格式（spec F7），DER 编码签名现于解析期拒绝。
负向量：tests/test_signature.py::test_sm2_der_rejected
```

## 7. PR 流程

- 目标分支 `main`；提交前本地跑完 §3 全部命令；
- CI 必须全绿：3.9 / 3.12 双矩阵 + 覆盖率门禁（行+分支 ≥ 98%）+ 向量合规全绿；
- 涉及 fixture 变更的 PR 必须在描述中附网关真源同步证据（commit/链接）；
- 至少一名 reviewer 复核通过后合并；squash 合并，commit message 按 §6 规范。

## 8. 发布流程

1. 确认 `pyproject.toml` 的 `version` 已更新为目标版本 `X.Y.Z`；
2. 打 tag 并推送：`git tag vX.Y.Z && git push origin vX.Y.Z`；
3. tag `v*` 触发 `.github/workflows/release.yml`：checkout → **tag 与 pyproject 版本
   一致性校验（不一致即 fail）** → 装依赖 → **完整复跑 CI 同款测试与覆盖率门禁** →
   `python -m build` → `pypa/gh-action-pypi-publish` 发布到 PyPI；
4. 发布凭证走 GitHub Secrets（`PYPI_TOKEN`，配置于仓库 `wop-python-sdk` 环境或仓库级
   Secrets），**绝不写入仓库明文**；发布步骤位于测试全绿之后，失败不留半发布状态。

发布产物：PyPI `wop-python-sdk`（sdist + wheel）。
