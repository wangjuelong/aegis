# Linux 容器交付目录

本目录提供 Linux 容器 / 云原生交付产物：

- `daemonset-host-agent.yaml`
  - 宿主机 Agent + eBPF 的最小权限 DaemonSet
  - 默认读取 `containerd.sock`
- `sidecar-lite-pod.yaml`
  - 应用 Pod 中嵌入 Sidecar Lite 的最小示例

约束：

- Host Agent 默认 `hostPID=true`、`hostNetwork=false`、`privileged=false`
- Host Agent 采用 `drop ALL` 后仅回加文档要求的 6 个 capability
- Sidecar Lite 不直接访问云端，只通过 unix socket 与宿主机 Agent 通信

如果集群使用 `CRI-O` 而不是 `containerd`，请把 `daemonset-host-agent.yaml` 中的
`/var/run/containerd/containerd.sock` 替换为对应 `CRI-O` socket 路径。
