# Linux Runtime SDK / Cloud Connector 多语言样例

本目录提供 Runtime SDK / Cloud API Connector 的多语言参考实现：

- 顶层 contract / sample：
  - `runtime-event.sample.json`
  - `runtime-heartbeat.sample.json`
  - `runtime-policy.contract.json`
  - `cloud-connector.contract.json`
  - `cloud-connector.aws-cloudtrail.contract.json`
  - `cloud-connector.azure-monitor.contract.json`
  - `cloud-connector.gcp-audit-log.contract.json`
- 多语言 SDK：
  - `python/`
  - `node/`
  - `go/`
  - `java/`
  - `dotnet/`
- Rust 参考运行：
  - `run-example.sh`

本地统一校验入口：

```bash
bash scripts/linux-container-validate.sh
```

该脚本会真实执行：

- Python example
- Node.js example
- Go example
- Java example
- .NET example
- Rust `runtime_sdk_connector`
