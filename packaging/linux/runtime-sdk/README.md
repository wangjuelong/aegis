# Linux Runtime SDK / Cloud Connector 样例

本目录提供 Runtime SDK / Cloud API Connector 的最小交付样例：

- `runtime-event.sample.json`
- `runtime-heartbeat.sample.json`
- `runtime-policy.contract.json`
- `cloud-connector.contract.json`
- `run-example.sh`

复跑方式：

```bash
bash packaging/linux/runtime-sdk/run-example.sh
```

脚本会执行：

```bash
cargo run -p aegis-core --example runtime_sdk_connector
```

输出应包含：

- `runtime_event=...`
- `first_flush=false`
- `second_flush=true`
- `buffered_events=1`
- `emitted_batches=1`
