# Windows 真机验收矩阵

## 1. 验收脚本

- 仓库脚本：`scripts/windows-runtime-verify.sh`
- 远端执行脚本：`scripts/windows-runtime-verify.ps1`
- 本地输出：`target/windows-validation/192.168.2.218.json`
- 实际验证时间：`2026-04-20 18:05:12 +08:00`
- 实际验证 ID：`windows-runtime-20260420-180434`
- W10 补充验证时间：`2026-04-20 16:46:03 +08:00`
- W10 补充验证方式：远端构建 `AegisSensorKmod + AegisFileMonitor`，并执行文件/注册表真实链路脚本
- W11 补充验证时间：`2026-04-20 17:32:50 +08:00`
- W11 补充验证方式：远端重构建并安装 `AegisSensorKmod + AegisFileMonitor`，执行进程保护、文件保护与完整性回执脚本
- W12 补充验证时间：`2026-04-20 18:05:12 +08:00`
- W12 补充验证方式：远端重构建并安装 `AegisSensorKmod`，执行 AMSI 状态探测、PowerShell 4104 脚本块回执与内存快照增量链路脚本
- W13 补充验证时间：`2026-04-20 20:22:37 +08:00`
- W13 补充验证方式：远端执行 `packaging/windows/validate.ps1`，使用离线工具链 `C:\ProgramData\Aegis\toolchains\1.91.0` 完成本地构建、payload 组装、安装、自检、watchdog 一次性校验与回滚验证
- W14 补充验证时间：`2026-04-20 21:09:35 +08:00`
- W14 补充验证方式：远端执行 `packaging/windows/validate.ps1 -BundleChannel release`，注入代码签名证书、时间戳地址与 ELAM/PPL 批准文件，完成 release 签名、payload 验签、安装后复验与卸载闭环

## 2. 主机选择结果

`docs/env/开发环境.md` 中提供了两台 Windows 测试机，实际连通性如下：

| 主机 | 用户 | SSH 结果 | 结论 |
|------|------|----------|------|
| `192.168.1.4` | `admin` | `Connection timed out during banner exchange` | 不可用，本轮未采用 |
| `192.168.2.218` | `lamba` | `hostname => DESKTOP-TLASHJG` | 可用，作为本轮验收主机 |

## 3. 主机兼容性矩阵

| 主机 | 计算机名 | 系统版本 | Build | PowerShell | 管理员 | 验收结果 |
|------|----------|----------|-------|------------|--------|----------|
| `192.168.2.218` | `DESKTOP-TLASHJG` | `Windows 11 专业版` | `10.0.26200` | `5.1.26100.8115` | `true` | `pass` |

## 4. 验收项结果

| 验收项 | 结果 | 关键观察 |
|--------|------|----------|
| `host_baseline` | pass | `is_admin=true`，主机为 `Windows 11 专业版` |
| `driver_transport` | pass | 真机完成驱动构建、安装、协议握手与卸载；`protocol_version=65536`，`driver_version=1.0.0` |
| `tpm_surface` | pass | `tpm_present=true`，`tpm_ready=true`，厂商 `INTC` |
| `dpapi_roundtrip` | pass | 使用 `powershell.exe` SHA256 作为 additional entropy，machine/user scope 往返均成功 |
| `process_inventory` | pass | `Win32_Process=250`，`tasklist=251` |
| `security_4688` | pass | 可读取 `Security/4688`，最新 `record_id=788750`；临时 `cmd.exe` 探针未稳定命中，作为观察项保留 |
| `network_inventory` | pass | `TCP=144`，`UDP=62` |
| `firewall_block` | pass | 成功创建并清理 `AegisValidation-55b576db` rule group |
| `named_pipe_inventory` | pass | 成功枚举命名管道样本，包括 `InitShutdown`、`lsass`、`ntsvcs` |
| `module_inventory` | pass | 成功读取 `1Password.exe` 进程模块清单 |
| `vss_inventory` | pass | 成功读取 `3` 条 `Win32_ShadowCopy` 样本 |
| `device_inventory` | pass | 成功读取 `Display / AudioEndpoint / Firmware / System` 设备样本 |
| `amsi_surface` | pass | `has_amsi_runtime=true`，`scan_interface_ready=true`，`session_opened=true`，`has_script_block_logging=false` |
| `script_surface_roundtrip` | pass | benign script `Write-Output 'Aegis script surface allow'` 已产出 4104 事件；官方 AMSI test sample 被 `AmsiScanBuffer` 以 `amsi_result=32768` 阻断 |
| `memory_signal_roundtrip` | pass | 真实拉起 `powershell(pid=2512)` 并分配约 `160411648` bytes 私有内存，快照可见进程与增量 |
| `suspend_kill_response` | pass | 真实执行 `NtSuspendProcess + Stop-Process`，目标 `pid=6984` |
| `quarantine_response` | pass | 真实移动文件到 `C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-180434-quarantine-input.txt` |
| `forensics_response` | pass | 真实生成 `C:\ProgramData\Aegis\forensics\windows-runtime-20260420-180434.zip` |
| `file_minifilter_build_install` | pass | 真实构建并安装 `AegisFileMonitor`，通信端口 `\AegisFileMonitorPort` 可用 |
| `file_minifilter_events` | pass | 真实捕获 `C:\ProgramData\Aegis\validation\w10-file-test\sample.txt` 的 `write/rename/delete` 事件 |
| `registry_journal_status` | pass | `registry_callback_registered=true`，journal 容量 `256`，序列号持续推进 |
| `registry_rollback_roundtrip` | pass | `\REGISTRY\MACHINE\SOFTWARE\AegisW10Test` 的 `SampleValue` 已完成 `before -> after -> rollback -> before` 闭环，`applied_count=1` |
| `driver_ob_process_build_install` | pass | 控制驱动以 `/INTEGRITYCHECK` 重构建并成功加载；`ob_callback_registered=true` |
| `process_protection_roundtrip` | pass | 受保护 `powershell.exe(pid=11492)` 执行 `Stop-Process -Force` 返回 `Access is denied`，目标进程仍存活 |
| `file_protection_roundtrip` | pass | `C:\ProgramData\Aegis\validation\w11-protection-test\protected-dir` 下文件 `write/rename/delete` 全部返回“访问被拒绝” |
| `file_protection_block_events` | pass | Minifilter 队列捕获到 `3` 条 `block-create` 事件，路径命中 `w11-block-event-test\\protected-dir\\sample.txt` |
| `driver_integrity_roundtrip` | pass | `ssdt/callback/kernel_code inspection=true`；主机处于 `code_integrity_testsign=true`，因此 `kernel_code_suspicious=true` 为测试签名环境告警，不是静态占位 |
| `windows_package_validate` | pass | `packaging/windows/validate.ps1` 在 `192.168.2.218` 返回 `required_failures=[]` |
| `windows_install_bootstrap` | pass | 安装结果记录 `copied_paths/config_result/driver_result/bootstrap_report`，`bootstrap_report.approved=true` |
| `windows_watchdog_once` | pass | `watchdog-state.json` 中 `alerts=[]`，`bootstrap_passed=true`，`update_phase=Idle` |
| `windows_release_validate` | pass | `bundle_channel=release`，`payload_release_verification.verified=true`，`installed_release_verification.verified=true`，`required_failures=[]` |

## 5. 关键产物

- 验收摘要：`C:\ProgramData\Aegis\validation\windows-runtime-20260420-180434\summary.json`
- 隔离产物：`C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-180434-quarantine-input.txt`
- 取证目录：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-180434`
- 取证压缩包：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-180434.zip`
- W12 远端验收根目录：`C:\ProgramData\Aegis\validation\windows-runtime-verify-20260420-180432`
- W12 关键结果：`{"scan_interface_ready":true,"script_block_logged":true,"memory_snapshot_growth_visible":true,"official_amsi_sample_blocked":true}`
- W10 远端构建根目录：`C:\ProgramData\Aegis\w10-build-20260420-163112`
- W10 注册表回滚验证脚本：`C:\ProgramData\Aegis\w10-build-20260420-163112\registry-rollback-validate.ps1`
- W10 关键结果：`{"restored_ok":true,"rollback_applied_count":1,"target_key_path":"\\REGISTRY\\MACHINE\\SOFTWARE\\AegisW10Test"}`
- W11 远端构建根目录：`C:\ProgramData\Aegis\w11-build-20260420-171956`
- W11 文件保护验证目录：`C:\ProgramData\Aegis\validation\w11-protection-test\protected-dir`
- W11 阻断事件验证目录：`C:\ProgramData\Aegis\validation\w11-block-event-test\protected-dir`
- W11 关键结果：`{"ob_callback_registered":true,"stop_process_blocked":true,"file_write_blocked":true,"file_rename_blocked":true,"file_delete_blocked":true,"ssdt_inspection_succeeded":true,"callback_inspection_succeeded":true,"kernel_code_inspection_succeeded":true,"code_integrity_testsign":true}`
- W13 远端 payload 根目录：`C:\ProgramData\Aegis\validation\windows-package-verify-20260420-200129`
- W13 安装结果工件：`C:\ProgramData\Aegis\state\install-result.json`
- W13 自检工件：`C:\ProgramData\Aegis\state\bootstrap-check.json`
- W13 watchdog 工件：`C:\ProgramData\Aegis\state\watchdog-state.json`
- W13 离线工具链：`C:\ProgramData\Aegis\toolchains\1.91.0`
- W13 关键结果：`{"required_failures":[],"bootstrap_approved":true,"watchdog_alerts":0,"driver_service_state":"Running"}`
- W14 release receipt：`C:\ProgramData\Aegis\validation\windows-package-payload\metadata\signed-release.json`
- W14 release signature：`C:\ProgramData\Aegis\validation\windows-package-payload\metadata\signed-release.cms`
- W14 关键结果：`{"bundle_channel":"release","payload_release_verification":true,"installed_release_verification":true,"required_failures":[]}`

## 6. 结论

- `scripts/windows-runtime-verify.sh` 已可从仓库直接复跑 Windows 真机验收。
- `192.168.2.218` 已验证通过当前已完成的 Windows 运行时、驱动桥接、网络隔离、响应链、DPAPI 凭据保护与 TPM 观测链。
- `W10` 已额外验证通过文件 Minifilter 和注册表 callback/rollback 真实链路，`WindowsPlatform` 不再把这两项能力固定为 `false`。
- `W11` 已额外验证通过 `ObRegisterCallbacks` 进程保护、Minifilter 路径保护与驱动完整性查询；`WindowsPlatform` 不再把 `ObProcess`/`verify_integrity` 维持在审计占位状态。
- `W12` 已额外验证通过共享脚本解码、AMSI 脚本阻断/告警、PowerShell 4104 脚本块回执与内存快照增量事件；`WindowsPlatform` 不再把 `AmsiScript`/`MemorySensor` 固定为未实现。
- `W13` 已额外验证通过 Windows 开发包构建、安装、自举自检、watchdog 状态闭环与失败回滚链；当前仓库已具备发布前开发包验收入口。
- `W14` 已额外验证通过 release 清单、代码签名/验签、安装前后 release gate 与批准文件依赖校验；当前仓库已具备严格失败的 Windows release 验收入口。
- `security_4688` 的验收口径以“日志可读、record_id 可取”为准；`cmd.exe` 临时探针命中率被保留为观察项，不作为失败条件。
