# Linux 远程 Attestation / Verifier 信任链计划

## 1. 目标

把当前 Linux 仅有的本机 `quote/checkquote` baseline，升级为可分离 verifier 的远程证明链，保证：

- Agent 侧能生成结构化 attestation bundle
- Verifier 侧能离线验证 quote / PCR / qualification / AK public
- 设备证书 / CSR 与 attestation 结果形成统一信任包
- `aegis-agentd --diagnose` 与自检结果能反映 verifier-ready 状态，而不是只反映本机工具可用

## 2. 当前缺口

- 当前只有本地 `generate_attestation_quote()` / `verify_attestation_quote()`，没有可交付的 verifier bundle/contract。
- 文档要求 Provisioning/Rotation/Revocation 的设备证书链，但仓库里没有 Linux 侧 enrollment/verifier 工具链。
- `linux_tpm_attestation_status_from_config()` 只表达本机工具/路径可用性，无法表达远端 verifier 信任链是否成立。

## 3. 不妥协约束

- 不接受继续把本机 `checkquote` 通过写成“远程 attestation 已完成”。
- 不接受 verifier 与 agent 共用隐式状态；必须通过 bundle + trust root 显式交接。
- 不接受只生成 quote，不绑定设备身份/CSR/证书。
- 不接受 verifier 失败时静默降级为通过。

## 4. 研发范围

### 4.1 Agent 侧 attestation bundle

- 新增 Linux attestation bundle 结构：
  - AK public
  - PCR selection
  - qualification / nonce
  - quote message / signature / PCR blob
  - device CSR / device certificate metadata
- 新增脚本或命令生成 bundle，并可供 `--diagnose` / validate 引用

### 4.2 Verifier 侧链路

- 新增 verifier 脚本：
  - 校验证书链 / trust root
  - 调用 `tpm2_checkquote`
  - 校验 qualification / nonce / PCR selection
  - 输出结构化 receipt
- verifier 与 agent 允许部署在不同主机，输入输出只通过 bundle / receipt 交互

### 4.3 Enrollment / certificate contract

- 新增本地 CA / verifier demo contract，用于仓库内验证：
  - device key / CSR 生成
  - signing receipt
  - verifier receipt
- `DiagnoseCertificateStatus` / attestation 诊断字段扩展 verifier-ready 维度

### 4.4 验证

- 本地单测覆盖 bundle 编解码与 verifier receipt
- Linux 测试机验证：
  - bundle 生成
  - verifier receipt 通过
  - nonce 错误时 verifier 严格失败

## 5. 交付物

- `crates/aegis-core/src/linux_tpm.rs`
- `crates/aegis-core/src/self_protection.rs`
- `crates/aegis-agentd/src/main.rs`
- `scripts/linux-tpm-attestation-bundle.sh`
- `scripts/linux-tpm-attestation-verify.sh`

## 6. 完成判定

- Linux agent 可生成 attestation bundle
- verifier 可独立验证 bundle 并输出 receipt
- 错误 nonce / trust root / quote 任一失败都会显式报错
- Linux 测试机完成正反向验收
