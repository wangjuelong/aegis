# Windows hash/pid/path 真实阻断研发计划

## 1. 目标

把当前 Windows 上 audit-only 的 `block_hash`、`block_pid`、`block_path`，升级为真正的内核/过滤器阻断链路：

- 用户态写入真实 block entry
- Minifilter 持有权威 block map
- `IRP_MJ_CREATE` / `IRP_MJ_WRITE` / `IRP_MJ_SET_INFORMATION` 在 pre-op 实时判定
- `hash-block`、`pid-block`、`path-block` 都有真实 TTL、生效状态与清空能力
- 工件、状态快照、验收脚本全部以真实阻断结果为准

## 2. 当前缺口

- `windows.rs` 的 `block_hash` / `block_pid` / `block_path` 只写 `userspace-ledger` 工件。
- Minifilter 只支持 `protect_path`，没有 block map、TTL、hash/pid 规则。
- `clear_all_blocks` 只清理防火墙 block，对 hash/pid/path 没有内核清空链路。
- 运行时与文档宣称已有 preemptive block 架构，但代码没有对应控制面。

## 3. 不妥协设计

- 不接受继续用 lease 代表阻断。
- 不接受把 `path-block` 继续偷换成 `protect_files`。
- 不接受只有“写入成功”没有“实际拒绝”的伪执行链。
- 不接受 TTL 只存在用户态；权威 TTL 必须在 Minifilter 状态面内生效。

## 4. 研发范围

### 4.1 Minifilter 协议升级

- 在 `aegis_file_minifilter_protocol.h` 增加命令：
  - `SET_BLOCK_ENTRY`
  - `CLEAR_BLOCK_ENTRIES`
  - `QUERY_BLOCK_STATE`
- 新增结构：
  - block 写入请求（kind / target / ttl_secs）
  - block 状态响应（路径数、block 数、各类型计数）
- 现有状态响应增加：
  - `BlockEntryCount`
  - `HashBlockCount`
  - `PidBlockCount`
  - `PathBlockCount`

### 4.2 Minifilter 数据面

- 维护固定容量、可过期的 block entry 表
- block 类型：
  - `hash-block`
  - `pid-block`
  - `path-block`
- 行为约束：
  - `hash-block`：在 `IRP_MJ_CREATE` 阶段对目标文件做 SHA-256，命中即拒绝至少执行/写入意图的打开
  - `pid-block`：当前 PID 的 create/write/rename/delete 全部拒绝
  - `path-block`：路径前缀命中的 create/write/rename/delete 全部拒绝
- 每次判定前清理过期 entry
- 命中时写入 `block-hash` / `block-pid` / `block-path` 事件

### 4.3 用户态桥接

- 新增 `scripts/windows-configure-preemptive-block.ps1`
- 新增 `scripts/windows-query-preemptive-block.ps1`
- `windows.rs` 的 `block_hash` / `block_pid` / `block_path` 改为真实调用 minifilter
- `write_windows_block_artifact()` 的 `enforced`/`enforcement_plane` 改为真实状态
- `clear_all_blocks()` 统一清空：
  - firewall block
  - minifilter block entry

### 4.4 平台状态与测试

- `WindowsHostCapabilities` 收口 block 状态详情
- `PlatformExecutionSnapshot.active_blocks` 继续保留租约视图，但来源必须与 minifilter 权威状态一致
- Rust 单元测试覆盖：
  - block artifact 为 `enforced=true`
  - clear 会清空非 network block
  - block state 工件/状态字段正确

### 4.5 真机验收

- 在 `192.168.2.222` 上新增 `preemptive_blocking` 必选步骤：
  - `block_pid` 后目标进程对测试文件写入失败
  - `block_path` 后对受阻路径的创建/写入/删除失败
  - `block_hash` 后命中 hash 的测试文件打开失败
  - 查询 minifilter 事件流能看到对应 `block-*`

## 5. 交付物

- `crates/aegis-platform/src/windows.rs`
- `windows/minifilter/include/aegis_file_minifilter_protocol.h`
- `windows/minifilter/src/aegis_file_minifilter.c`
- `scripts/windows-configure-preemptive-block.ps1`
- `scripts/windows-query-file-events.ps1`
- `scripts/windows-runtime-verify.ps1`

## 6. 完成判定

- `block_hash` / `block_pid` / `block_path` 工件显示 `enforced=true`
- Minifilter 状态查询能返回真实 block 计数
- `clear_all_blocks()` 会清空 firewall 与 minifilter block 状态
- 真机 `192.168.2.222` 上三类阻断均可复现实效拒绝
- 相关文档不再把 audit-only 行为描述为真实阻断
