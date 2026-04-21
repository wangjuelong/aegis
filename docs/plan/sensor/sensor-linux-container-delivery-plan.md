# Linux 容器 / Sidecar 交付计划

## 1. 目标

把当前容器与 sidecar 仅有的契约/测试基线升级为可交付形态，保证：

- Host Agent DaemonSet 有可部署 manifest 与校验入口
- Sidecar Lite 有可部署 manifest、socket/缓存卷约束与验收
- Runtime SDK / Cloud API Connector 有最小交付样例与验证脚本

## 2. 当前缺口

- `container_mode.rs` 只定义了 contract 与测试，没有交付用 manifest。
- 文档承诺 Host Agent、Sidecar Lite、Runtime SDK / Cloud API Connector 三种模式，但仓库里缺少 Linux 侧部署产物与 validate 入口。
- 没有 Kubernetes/容器环境验收脚本。

## 3. 不妥协约束

- 不接受只有 Rust contract，没有实际部署文件。
- 不接受 manifest 与 contract 语义漂移。
- 不接受 sidecar / daemonset 权限超出文档约束。
- 不接受 runtime SDK / cloud connector 只存在 example，不进入交付目录。

## 4. 研发范围

### 4.1 Host Agent DaemonSet

- 新增最小权限 DaemonSet manifest
- 显式 securityContext / volumes / socket / bpffs / proc mount
- 提供 contract 校验脚本

### 4.2 Sidecar Lite

- 新增 sidecar deployment snippet / volume / unix socket contract
- 提供 sidecar validate 脚本

### 4.3 Runtime SDK / Cloud API Connector

- 把现有 runtime SDK / cloud connector example 组装成交付样例目录
- 提供 sample config / sample event / sample connector contract

### 4.4 验证

- 本地 contract + manifest 校验
- Linux 测试机或容器环境执行最小 smoke test

## 5. 交付物

- `packaging/linux/kubernetes/`
- `packaging/linux/runtime-sdk/`
- `scripts/linux-container-validate.sh`
- `crates/aegis-core/src/container_mode.rs`
- `crates/aegis-core/examples/runtime_sdk_connector.rs`

## 6. 完成判定

- Host Agent / Sidecar Lite / Runtime SDK / Cloud API Connector 都有交付目录
- manifest 与 contract 校验通过
- 最小 smoke test 可复跑
