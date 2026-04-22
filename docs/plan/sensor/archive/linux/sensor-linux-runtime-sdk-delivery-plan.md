# Linux Runtime SDK / Cloud Connector 多语言交付计划

## 1. 目标

把当前仅有 Rust example 的 Runtime SDK / Cloud Connector 样例升级为可交付多语言参考实现，保证：

- 至少覆盖 `Python / Node.js / Go / Java` 四种运行时参考 SDK
- 每种 SDK 都能构造与发送 `RuntimeSdkEvent` / `RuntimeHeartbeat`
- 提供 Cloud API Connector 参考契约与最小运行样例
- 提供统一验证脚本，而不是只留静态 JSON 样例

## 2. 当前缺口

- 当前仓库只有 Rust example 和 contract JSON，距离文档承诺的 Runtime SDK / Cloud API 实际交付仍有明显差距。
- 没有多语言参考实现，也没有对这些参考实现的统一校验入口。
- 当前 `scripts/linux-container-validate.sh` 只验证 Rust example，不验证多语言交付。

## 3. 不妥协约束

- 不接受只堆示例 JSON，不提供代码。
- 不接受多语言目录只有 README 没有可运行样例。
- 不接受 Cloud Connector 只存在文档说明，没有最小运行代码。
- 不接受验证脚本只检查文件存在，不执行样例。

## 4. 研发范围

### 4.1 Runtime SDK 多语言样例

- 新增：
  - `packaging/linux/runtime-sdk/python/`
  - `packaging/linux/runtime-sdk/node/`
  - `packaging/linux/runtime-sdk/go/`
  - `packaging/linux/runtime-sdk/java/`
- 每种语言都提供：
  - event model
  - heartbeat model
  - 最小发送样例

### 4.2 Cloud API Connector 样例

- 新增多云 connector 参考样例
- 最小覆盖：
  - `AWS CloudTrail`
  - `Azure Activity Log`
  - `GCP Audit Log`

### 4.3 验证

- 扩展 `scripts/linux-container-validate.sh`
- 真实执行：
  - Python
  - Node.js
  - Go
  - Java
  - Rust example

## 5. 交付物

- `packaging/linux/runtime-sdk/`
- `scripts/linux-container-validate.sh`
- `docs/plan/sensor/sensor-linux-plan.md`

## 6. 完成判定

- 四种语言 SDK 样例全部入仓
- Cloud Connector 参考样例全部入仓
- 验证脚本真实执行各语言样例并返回 `required_failures=[]`
- 文档状态同步更新

## 7. 实际交付

- 代码提交：`b3432f0 feat(linux): 完成多语言 runtime sdk 交付链`
- 补充代码清理：`ebde41b chore(linux): 清理 runtime sdk 生成工件`
- 已新增：
  - `packaging/linux/runtime-sdk/python/`
  - `packaging/linux/runtime-sdk/node/`
  - `packaging/linux/runtime-sdk/go/`
  - `packaging/linux/runtime-sdk/java/`
  - `packaging/linux/runtime-sdk/dotnet/`
  - `packaging/linux/runtime-sdk/cloud-connector.aws-cloudtrail.contract.json`
  - `packaging/linux/runtime-sdk/cloud-connector.azure-monitor.contract.json`
  - `packaging/linux/runtime-sdk/cloud-connector.gcp-audit-log.contract.json`
- 已完成：
  - `Python / Node.js / Go / Java / .NET` 五种运行时参考 SDK 样例入仓
  - Rust Runtime SDK example 与多语言样例统一进入 `scripts/linux-container-validate.sh`
  - Cloud Connector 参考合同覆盖 `AWS CloudTrail / Azure Monitor / GCP Audit Log`

## 8. 验证结果

本地已完成：

- `bash scripts/linux-container-validate.sh`

关键结果：

- `runtime_rust_output="runtime_event=... first_flush=false second_flush=true buffered_events=1 emitted_batches=1"`
- `runtime_multilang_outputs.python.language=python`
- `runtime_multilang_outputs.node.language=node`
- `runtime_multilang_outputs.go.language=go`
- `runtime_multilang_outputs.java.language=java`
- `runtime_multilang_outputs.dotnet.language=dotnet`
- `required_failures=[]`

## 9. 结论

- `L15` 已完成代码、验证与文档闭环。
- 当前仓库范围内，Linux 剩余未完成项已清零。
