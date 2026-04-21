# Windows 受保护目录目标路径阻断收口计划

## 1. 目标

收口当前 Windows 文件保护链中“从未受保护目录 rename/move 进入受保护目录可绕过”的缺口，保证：

- `protect_files` 与 `block_path` 同时覆盖源路径与目标路径
- rename / move / link 进入受保护目录在内核 pre-op 阶段被拒绝
- 事件流与审计工件能准确反映“命中的是目标路径保护”，不再只依赖源路径

## 2. 当前缺口

- Minifilter 目前只通过 `TargetFileObject` 当前路径判断 `block-path` / `protect_files`，没有解析 rename 目标路径。
- `IRP_MJ_SET_INFORMATION` 里仅对 `FileRenameInformation` / `FileRenameInformationEx` 做源路径检查，导致从外部目录 move 进受保护目录时可绕过。
- 当前真机验收只覆盖“在受保护目录内 write/rename/delete 被拒绝”，没有覆盖“外部文件重命名进入受保护目录”。

## 3. 不妥协约束

- 不接受只在文档里收紧口径，不改内核判定逻辑。
- 不接受只拦截 rename，不处理 link / rename-ex 这类同族目标路径写入语义。
- 不接受只记录事件不阻断；目标路径命中时必须返回 `STATUS_ACCESS_DENIED`。
- 不接受把 `protect_files` 和 `block_path` 分裂成两套目标路径判定逻辑。

## 4. 研发范围

### 4.1 Minifilter 目标路径解析

- 为 `IRP_MJ_SET_INFORMATION` 新增统一目标路径解析 helper
- 覆盖：
  - `FileRenameInformation`
  - `FileRenameInformationEx`
  - `FileLinkInformation`
  - `FileLinkInformationEx`
- 使用 `FltGetDestinationFileNameInformation` / 兼容 fallback 获取目标路径

### 4.2 阻断判定收口

- `protect_files` 命中目标路径时返回 `block-rename-target` / `block-link-target`
- `block_path` 命中目标路径时返回 `block-path`
- 目标路径阻断与源路径阻断共用统一前缀匹配逻辑

### 4.3 事件与审计

- 事件 subject 必须能区分源路径与目标路径命中
- 运行时验收记录“外部文件 move 进入受保护目录”被拒绝
- 不改变现有保护面工件语义，但补充目标路径阻断证据

### 4.4 验证

- Rust 单测覆盖 rename/link 目标路径命中
- 真机 `192.168.2.222` 新增：
  - 外部文件 move 到受保护目录失败
  - 外部文件 hard link / rename-ex 进入受保护目录失败
  - 事件流命中目标路径阻断事件

## 5. 交付物

- `windows/minifilter/src/aegis_file_minifilter.c`
- `scripts/windows-runtime-verify.ps1`
- `scripts/windows-runtime-verify.sh`
- `crates/aegis-platform/src/windows.rs`

## 6. 完成判定

- 外部文件无法通过 rename/move/link 进入受保护目录
- `protect_files` 与 `block_path` 在目标路径命中时都能阻断
- 事件流中能看到目标路径阻断事件
- 真机 `192.168.2.222` 验收通过且 `required_failures=[]`
