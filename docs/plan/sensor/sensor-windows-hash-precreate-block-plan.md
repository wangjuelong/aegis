# Windows hash 严格 pre-create 阻断计划

## 1. 目标

把当前 `block_hash` 的“post-create + `FltCancelFileOpen`”实现收口为严格的 create 入口阻断，保证：

- 命中 hash 的文件在请求者句柄创建前被拒绝
- `block_hash` 不再依赖 post-op 取消返回结果
- 审计与文档中的“preemptive block”口径与内核真实时序一致

## 2. 当前缺口

- 当前 `block_hash` 在 `AegisFilePostCreate` 中做 SHA-256，再调用 `FltCancelFileOpen`。
- 这意味着 create 已完成，只是在句柄返回前取消，不是严格的 pre-create gate。
- 当前文档把 `block_hash/pid/path` 统一描述为真实 pre-op 阻断，和实际时序不一致。

## 3. 不妥协约束

- 不接受继续使用 post-create 取消并在文档里写成 pre-op。
- 不接受为了避免递归而放弃真实 hash 阻断。
- 不接受对写入意图、执行意图和普通读取语义混成一类不加区分。
- 不接受只在验收脚本里观察“访问被拒绝”，不修正内核时序。

## 4. 研发范围

### 4.1 pre-create hash 计算链

- 在 `IRP_MJ_CREATE` pre-op 中引入受控的文件内容读取路径
- 对现有文件在句柄创建前完成 SHA-256 计算与 block map 匹配
- 为避免自递归，引入专用 kernel open / recursion guard

### 4.2 语义边界

- 新建文件、不存在文件、不具备可读内容的目标路径需给出显式判定
- 命中 hash 时统一返回 `STATUS_ACCESS_DENIED`
- 未命中时不再落入 post-op cancel 路径

### 4.3 事件与状态

- `block-hash` 事件保留，但来源改为 pre-create
- 清理 `AegisFilePostCreate` 中仅为 hash block 服务的残留逻辑
- 文档与工件不再把 post-op 行为描述为 pre-op

### 4.4 验证

- Rust 单测覆盖：
  - hash 命中时工件仍为 `enforced=true`
  - 不再依赖 post-create cancel 语义
- 真机 `192.168.2.222` 覆盖：
  - 命中 hash 的文件 create/open 在句柄返回前被拒绝
  - 事件流仍能命中 `block-hash`

## 5. 交付物

- `windows/minifilter/src/aegis_file_minifilter.c`
- `windows/minifilter/include/aegis_file_minifilter_protocol.h`
- `crates/aegis-platform/src/windows.rs`
- `scripts/windows-runtime-verify.ps1`

## 6. 完成判定

- `block_hash` 不再依赖 `AegisFilePostCreate + FltCancelFileOpen`
- 命中 hash 的文件在 create 返回前被拒绝
- 真机 `192.168.2.222` 验收通过且 `required_failures=[]`
