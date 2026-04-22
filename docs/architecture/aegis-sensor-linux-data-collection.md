# Aegis Sensor Linux 数据采集清单

> 版本：1.0  
> 日期：2026-04-22  
> 状态：生效  
> 分类：内部 / 机密  
> 口径：仅描述当前仓库代码已经实现并进入 Linux Sensor 运行链的采集能力，不沿用终态方案中的未落地项。

---

## 1. 文档范围

本文档基于当前 Linux 平台实现，整理 `aegis-platform` 中已经接入 `poll_events()` 运行链的数据采集能力，聚焦两件事：

1. 采集的数据源
2. 采集到的数据维度

本文档只覆盖当前已经持续上送的主链能力，不把代码里尚未激活的 fallback provider 或方案层终态能力写成已交付能力。

---

## 2. 采集的数据源

| 数据域 | 当前数据源 | 采集方式 | 当前输出的关键字段 |
|--------|------------|----------|--------------------|
| 进程 | `/proc` 进程视图 | 遍历 `/proc/<pid>` 做快照差分，并读取 `/proc/<pid>/comm` / `/proc/<pid>/cmdline` | `pid`、`comm` 或 `cmdline` |
| 容器标签 | `/proc/<pid>/cgroup` | 从 cgroup 路径中提取容器 ID，作为进程/文件/网络事件标签 | `container_id` |
| 文件 | Linux eBPF pinned map `observed_file_events` | 用户态通过 `bpftool -j map dump pinned` 拉取文件事件 map | `seen_ns`、`pid`、`op`、`blocked`、`identity`、`inode`、`comm`、`path` |
| 文件观测 Hook | `sys_enter_openat` / `sys_enter_openat2` / `sys_enter_execve` / `lsm/file_open` / `lsm/bprm_check_security` | eBPF 侧写入文件事件 map | 同上 |
| 网络 | Linux eBPF pinned map `observed_ipv4_connect_events` | 用户态通过 `bpftool -j map dump pinned` 拉取网络事件 map | `seen_ns`、`pid`、`op`、`blocked`、`daddr`、`dport`、`family`、`comm` |
| 网络观测 Hook | `tracepoint/sock/inet_sock_set_state` / `kprobe/tcp_v4_connect` / `lsm/socket_connect` | eBPF 侧写入网络事件 map | 同上 |
| 认证 | `/var/log/auth.log`、`/var/log/secure` | 增量读取日志文件尾部 | 原始日志行 |
| 设备控制 | `lsblk -J -o NAME,PATH,RM,TRAN,MOUNTPOINT,VENDOR,MODEL,SERIAL` | 周期性快照差分 | `path`、`name`、`tran`、`removable`、`mountpoint`、`vendor`、`model`、`serial` |

---

## 3. 采集到的数据维度

### 3.1 进程

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 进程创建 | `process-start` | `/proc` 快照差分 | `pid`、`comm` 或 `cmdline`、`container_id` |
| 进程终止 | `process-exit` | `/proc` 快照差分 | `pid`、`container_id` |

说明：

- 当 `/proc/<pid>/comm` 可读时，事件主体形如 `pid=<pid> comm=<name>`。
- 当 `comm` 不可用时，退化为 `pid=<pid> cmd=<cmdline>`。
- 如果进程处于容器内，会额外补充 `container_id` 标签。

### 3.2 文件

Linux 文件事件当前由 eBPF map 持续上送，用户态统一编码为 `file-*`。

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 文件打开 | `file-open` | eBPF 文件事件 map | `pid`、`op=open`、`blocked=false`、`identity`、`inode`、`path`、`comm`、`container_id` |
| 文件打开阻断 | `file-open-block` | eBPF 文件事件 map | `pid`、`op=open`、`blocked=true`、`identity`、`inode`、`path`、`comm`、`container_id` |
| 文件执行 | `file-exec` | eBPF 文件事件 map | `pid`、`op=exec`、`blocked=false`、`identity`、`inode`、`path`、`comm`、`container_id` |
| 文件执行阻断 | `file-exec-block` | eBPF 文件事件 map | `pid`、`op=exec`、`blocked=true`、`identity`、`inode`、`path`、`comm`、`container_id` |

说明：

- `file-open` 来自 `openat/openat2` 观测与 `lsm/file_open` 阻断视图。
- `file-exec` 来自 `execve` 观测与 `lsm/bprm_check_security` 阻断视图。
- 如果 eBPF 记录里没有直接带出路径，用户态会尝试通过 `/proc/<pid>/exe` 与 `/proc/<pid>/fd/*` 反查路径。

### 3.3 网络

Linux 网络事件当前由 eBPF map 持续上送，用户态统一编码为 `network-*`。

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| IPv4 连接建立/连接观测 | `network-connect` | eBPF 网络事件 map | `pid`、`op=connect`、`blocked=false`、`dst=<ip:port>`、`family`、`comm`、`container_id` |
| IPv4 连接阻断 | `network-block` | eBPF 网络事件 map | `pid`、`op=connect`、`blocked=true`、`dst=<ip:port>`、`family`、`comm`、`container_id` |

说明：

- `network-connect` 由 `inet_sock_set_state` 和 `tcp_v4_connect` 共同补足连接观测。
- `network-block` 来自 `lsm/socket_connect` 的阻断结果。
- 当前实现只覆盖 IPv4 连接维度，输出协议语义固定为 `tcp`。

### 3.4 认证

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 认证日志增量 | `auth-log` | `/var/log/auth.log`、`/var/log/secure` | 原始日志行 |

说明：

- 当前实现按偏移量增量读取认证日志。
- 每次轮询最多取新增的 32 行非空日志。

### 3.5 设备控制

| 采集维度 | 当前 operation | 来源 | 关键字段 |
|----------|----------------|------|----------|
| 可移动设备接入 | `device-attach` | `lsblk` 差分 | `path`、`name`、`tran`、`removable`、`mountpoint`、`vendor`、`model`、`serial` |
| 可移动设备移除 | `device-detach` | `lsblk` 差分 | 同上 |
| 新增挂载点 | `mount-add` | `lsblk` 差分 | 同上 |
| 移除挂载点 | `mount-remove` | `lsblk` 差分 | 同上 |
| 挂载点变化 | `mount-change` | `lsblk` 差分 | 同上 |

说明：

- 当前只跟踪 `removable=true`、`tran=usb`，或挂载点位于 `/media/`、`/run/media/` 下的设备。
- 设备事件不带 `container_id`。

---

## 4. 当前未纳入持续采集文档的项

以下能力不应在当前 Linux 版本对外表述为“已持续采集”：

- 独立的 `auditd` syscall 事件流
- 独立的 `fanotify` 文件事件流
- 独立的 `ContainerMetadata` provider 事件流
- 注册表类数据
- AMSI 类脚本扫描数据

这些项要么属于 Linux 平台不适用能力，要么在当前代码中未作为独立持续上送源落地。
