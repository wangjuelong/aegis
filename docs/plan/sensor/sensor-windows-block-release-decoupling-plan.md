# Windows block 清理平面解耦计划

## 1. 目标

收口当前 `clear_all_blocks()` 的耦合设计，保证：

- Windows 防火墙 block 与 Minifilter block entry 分平面清理
- 某一平面失效时，另一平面仍然能完成 release
- 返回结果和审计工件显式暴露各平面的成功/失败状态

## 2. 当前缺口

- 只要本地仍有非 network block 且 Minifilter 控制口不可用，`clear_all_blocks()` 会直接失败。
- 这会连带阻塞已独立存在的 Windows 防火墙规则释放。
- 当前清理工件只有总数，没有按平面记录清理结果与残留状态。

## 3. 不妥协约束

- 不接受 Minifilter 故障时连 network release 也失败。
- 不接受“部分成功但对外表现成全部失败/全部成功”的模糊状态。
- 不接受清空后把本地 `active_blocks` 全部抹掉，却没有反映实际仍残留的平面。
- 不接受 break-glass release 被 unrelated plane 连带卡死。

## 4. 研发范围

### 4.1 清理执行顺序

- 将 firewall 与 Minifilter block 清理拆成两个独立步骤
- 两步都必须尽力执行，不允许前一步失败直接短路后一步
- 按执行结果分别更新：
  - network lease
  - non-network block lease

### 4.2 状态与工件

- 扩展 clear artifact：
  - `firewall_cleared_rule_groups`
  - `minifilter_blocks_cleared`
  - `firewall_clear_error`
  - `minifilter_clear_error`
  - `remaining_blocks`
- `PlatformExecutionSnapshot.active_blocks` 只删除真实已清掉的平面

### 4.3 错误语义

- 若任一平面失败，函数返回错误，但不得回滚已成功释放的平面
- 错误信息需包含分平面状态
- health / diagnose 输出需能反映“部分 release 成功”

### 4.4 验证

- Rust 单测覆盖：
  - Minifilter 不可用时仍可清空 firewall block
  - firewall 清理失败时 non-network block 仍可清空
  - artifact 能反映部分成功
- 真机 `192.168.2.222` 覆盖：
  - 正常双平面清空
  - 受控模拟 Minifilter 不可用时 network release 仍生效

## 5. 交付物

- `crates/aegis-platform/src/windows.rs`
- `scripts/windows-runtime-verify.ps1`
- `docs/plan/sensor/sensor-windows-validation-matrix.md`

## 6. 完成判定

- `clear_all_blocks()` 不再因单一平面故障阻塞另一平面的 release
- clear artifact 能反映分平面成功/失败与残留状态
- Rust 单测与真机验收全部通过
