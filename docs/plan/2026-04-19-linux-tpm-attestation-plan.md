# Linux TPM Attestation / Policy 实施计划

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
>
> 说明：
> 仓库现有计划文档统一位于 `docs/plan/`，本计划继续沿用该目录，不引入新的 `docs/plans/` 层级。

**Goal:** 在 `192.168.1.6` Linux 测试机上补齐当前可落地的 TPM 能力：`quote/checkquote` 真机闭环，以及 PCR 绑定的 sealed-object policy session 闭环。

**Architecture:** 第一阶段在 `aegis-core` 中补齐 TPM quote 生成/校验能力，并提供远端真机验证脚本与诊断状态。第二阶段在 sealed-object 主密钥路径中加入 PCR policy 支持，使主密钥可被当前 PCR 状态约束，同时提供正反两条真机验证链路。

**Tech Stack:** Rust、`tpm2-tools`、Ubuntu 24.04、TPM 2.0、Bash、`sshpass`

---

## 0. 范围约束

本轮只做 **可在单台 Linux 测试机 + 当前开发机** 上闭合的功能：

- TPM quote 生成
- `tpm2_checkquote` 校验
- PCR 绑定 policy digest
- PCR policy session 解封 sealed object
- 诊断状态与真机验证脚本

本轮**不纳入**：

- 依赖独立 verifier / CA / 远端证明服务的完整 remote attestation 信任链
- Secure Boot / IMA / EVM 全链路加固
- 发行工程、签名与上线流程

## 1. 工作包拆分

### 工作包 A：Linux TPM quote / checkquote 闭环

**目标**

- `aegis-core` 具备生成 quote 与本地校验 quote 的能力
- Linux 测试机 `192.168.1.6` 可完成 `createek/createak/quote/checkquote`
- 诊断面可表达 attestation readiness

**涉及文件**

- 修改：`crates/aegis-core/src/config.rs`
- 修改：`crates/aegis-core/src/linux_tpm.rs`
- 修改：`crates/aegis-core/src/upgrade.rs`
- 修改：`crates/aegis-agentd/src/main.rs`
- 新增：`scripts/linux-tpm-quote-verify.sh`
- 更新：`docs/plan/aegis-sensor-rd-status.md`
- 更新：`docs/plan/aegis-sensor-rd-plan-audit.md`
- 更新：`docs/plan/2026-04-19-linux-platform-runtime-closure.md`
- 更新：`docs/plan/2026-04-19-linux-remaining-rd-plan.md`

**实施步骤**

1. 在 `SecurityConfig` 中新增 attestation 相关配置项
   - `linux_tpm_attestation_ak_path`
   - `linux_tpm_attestation_pcrs`
2. 在 `linux_tpm.rs` 中新增 quote tool/runtime 探测
   - `tpm2_createek`
   - `tpm2_createak`
   - `tpm2_quote`
   - `tpm2_checkquote`
3. 实现 quote 生成函数
   - 创建 EK / AK
   - 生成 quote message / signature / PCR blob
4. 实现 quote 校验函数
   - 用 `tpm2_checkquote` 验证签名、nonce 与 PCR 输出
5. 为 fake TPM harness 补齐 quote 相关工具模拟
6. 增加单元测试
   - quote 成功 roundtrip
   - 缺少 quote 工具时 runtime 正确降级
7. 新增远端真机脚本 `scripts/linux-tpm-quote-verify.sh`
8. 在 `192.168.1.6` 上执行真机验收
9. 代码提交一次
10. 更新相关文档并单独提交一次

**验证命令**

- `cargo test -p aegis-core linux_tpm -- --nocapture`
- `bash -n scripts/linux-tpm-quote-verify.sh`
- `AEGIS_LINUX_HOST=192.168.1.6 AEGIS_LINUX_USER=ubuntu AEGIS_LINUX_PASSWORD=ubuntu ./scripts/linux-tpm-quote-verify.sh`

**代码提交要求**

- 中文提交信息，聚焦 quote 能力本身

**文档提交要求**

- 中文提交信息，说明 Linux 剩余项与状态文档已更新

### 工作包 B：PCR policy session 绑定的 sealed-object 主密钥路径

**目标**

- sealed-object 主密钥可选绑定到指定 PCR 集合
- 解封路径通过 policy session 满足 PCR policy
- Linux 测试机 `192.168.1.6` 可完成正向解封与错误 PCR 负向校验

**涉及文件**

- 修改：`crates/aegis-core/src/config.rs`
- 修改：`crates/aegis-core/src/linux_tpm.rs`
- 新增：`scripts/linux-tpm-policy-verify.sh`
- 更新：`docs/plan/aegis-sensor-rd-status.md`
- 更新：`docs/plan/aegis-sensor-rd-plan-audit.md`
- 更新：`docs/plan/2026-04-19-linux-platform-runtime-closure.md`
- 更新：`docs/plan/2026-04-19-linux-remaining-rd-plan.md`

**实施步骤**

1. 在 `SecurityConfig` 中新增 sealed-object PCR policy 配置项
   - `linux_tpm_master_key_pcrs`
2. 在 `linux_tpm.rs` 中新增 policy session tool/runtime 探测
   - `tpm2_createpolicy`
   - `tpm2_startauthsession`
   - `tpm2_policypcr`
3. 在 sealed object create 路径中：
   - 生成 PCR policy digest
   - 用 `-L policy.dat` 创建带 policy 的对象
4. 在 sealed object unseal 路径中：
   - 启动 policy session
   - 执行 `tpm2_policypcr`
   - 用 `-p session:<session.ctx>` 解封
5. 扩展 fake TPM harness
   - policy digest
   - policy session
   - 错误 PCR 时解封失败
6. 增加单元测试
   - PCR policy 成功 roundtrip
   - 错误 PCR policy 失败
7. 新增远端真机脚本 `scripts/linux-tpm-policy-verify.sh`
8. 在 `192.168.1.6` 上执行真机验收
9. 代码提交一次
10. 更新相关文档并单独提交一次

**验证命令**

- `cargo test -p aegis-core linux_tpm -- --nocapture`
- `bash -n scripts/linux-tpm-policy-verify.sh`
- `AEGIS_LINUX_HOST=192.168.1.6 AEGIS_LINUX_USER=ubuntu AEGIS_LINUX_PASSWORD=ubuntu ./scripts/linux-tpm-policy-verify.sh`

**代码提交要求**

- 中文提交信息，聚焦 PCR policy session / sealed-object 能力本身

**文档提交要求**

- 中文提交信息，说明 Linux 剩余项与状态文档已更新

## 2. 执行顺序

按以下顺序执行并提交：

1. 建立本计划文档
2. 完成工作包 A 代码并提交
3. 完成工作包 A 文档并提交
4. 完成工作包 B 代码并提交
5. 完成工作包 B 文档并提交
6. 全量验证
7. 合并到 `main`
8. 推送 `main`

## 3. 完成定义

仅当以下条件全部满足，才可认为本轮 Linux 测试机可闭合能力已完成：

- `linux-tpm-quote-verify.sh` 在 `192.168.1.6` 上通过
- `linux-tpm-policy-verify.sh` 在 `192.168.1.6` 上通过
- `cargo test -p aegis-core`
- `cargo test -p aegis-platform`
- 所有新增脚本 `bash -n` 通过
- 文档中的 Linux 剩余差距已明确缩减为：
  - attestation / quote 的更高阶远端信任链
  - Secure Boot / IMA / EVM 等更强测量链
  - 更高阶生产部署或发行工程项
