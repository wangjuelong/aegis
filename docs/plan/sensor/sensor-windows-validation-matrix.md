# Windows 真机验收矩阵

## 1. 验收脚本

- 仓库脚本：`scripts/windows-runtime-verify.sh`
- 远端执行脚本：`scripts/windows-runtime-verify.ps1`
- 本地输出：`target/windows-validation/192.168.2.218.json`
- 实际验证时间：`2026-04-20 16:07:16 +08:00`
- 实际验证 ID：`windows-runtime-20260420-160648`
- W10 补充验证时间：`2026-04-20 16:46:03 +08:00`
- W10 补充验证方式：远端构建 `AegisSensorKmod + AegisFileMonitor`，并执行文件/注册表真实链路脚本

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
| `process_inventory` | pass | `Win32_Process=259`，`tasklist=260` |
| `security_4688` | pass | 可读取 `Security/4688`，最新 `record_id=788750`；临时 `cmd.exe` 探针未稳定命中，作为观察项保留 |
| `network_inventory` | pass | `TCP=218`，`UDP=62` |
| `firewall_block` | pass | 成功创建并清理 `AegisValidation-9771f39b` rule group |
| `named_pipe_inventory` | pass | 成功枚举命名管道样本，包括 `InitShutdown`、`lsass`、`ntsvcs` |
| `module_inventory` | pass | 成功读取 `1Password.exe` 进程模块清单 |
| `vss_inventory` | pass | 成功读取 `3` 条 `Win32_ShadowCopy` 样本 |
| `device_inventory` | pass | 成功读取 `Display / AudioEndpoint / Firmware / System` 设备样本 |
| `amsi_surface` | pass | `has_amsi_runtime=true`，`has_powershell_operational_log=true`，`has_script_block_logging=false` |
| `suspend_kill_response` | pass | 真实执行 `NtSuspendProcess + Stop-Process`，目标 `pid=6532` |
| `quarantine_response` | pass | 真实移动文件到 `C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-160648-quarantine-input.txt` |
| `forensics_response` | pass | 真实生成 `C:\ProgramData\Aegis\forensics\windows-runtime-20260420-160648.zip` |
| `file_minifilter_build_install` | pass | 真实构建并安装 `AegisFileMonitor`，通信端口 `\AegisFileMonitorPort` 可用 |
| `file_minifilter_events` | pass | 真实捕获 `C:\ProgramData\Aegis\validation\w10-file-test\sample.txt` 的 `write/rename/delete` 事件 |
| `registry_journal_status` | pass | `registry_callback_registered=true`，journal 容量 `256`，序列号持续推进 |
| `registry_rollback_roundtrip` | pass | `\REGISTRY\MACHINE\SOFTWARE\AegisW10Test` 的 `SampleValue` 已完成 `before -> after -> rollback -> before` 闭环，`applied_count=1` |

## 5. 关键产物

- 验收摘要：`C:\ProgramData\Aegis\validation\windows-runtime-20260420-160648\summary.json`
- 隔离产物：`C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-160648-quarantine-input.txt`
- 取证目录：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-160648`
- 取证压缩包：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-160648.zip`
- W10 远端构建根目录：`C:\ProgramData\Aegis\w10-build-20260420-163112`
- W10 注册表回滚验证脚本：`C:\ProgramData\Aegis\w10-build-20260420-163112\registry-rollback-validate.ps1`
- W10 关键结果：`{"restored_ok":true,"rollback_applied_count":1,"target_key_path":"\\REGISTRY\\MACHINE\\SOFTWARE\\AegisW10Test"}`

## 6. 结论

- `scripts/windows-runtime-verify.sh` 已可从仓库直接复跑 Windows 真机验收。
- `192.168.2.218` 已验证通过当前已完成的 Windows 运行时、驱动桥接、网络隔离、响应链、DPAPI 凭据保护与 TPM 观测链。
- `W10` 已额外验证通过文件 Minifilter 和注册表 callback/rollback 真实链路，`WindowsPlatform` 不再把这两项能力固定为 `false`。
- `security_4688` 的验收口径以“日志可读、record_id 可取”为准；`cmd.exe` 临时探针命中率被保留为观察项，不作为失败条件。
