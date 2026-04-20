# Windows 真机验收矩阵

## 1. 验收脚本

- 仓库脚本：`scripts/windows-runtime-verify.sh`
- 远端执行脚本：`scripts/windows-runtime-verify.ps1`
- 本地输出：`target/windows-validation/192.168.2.218.json`
- 实际验证时间：`2026-04-20 14:25:37 +08:00`
- 实际验证 ID：`windows-runtime-20260420-142537`

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
| `process_inventory` | pass | `Win32_Process=256`，`tasklist=257` |
| `security_4688` | pass | 可读取 `Security/4688`，最新 `record_id=788750`；临时 `cmd.exe` 探针未稳定命中，作为观察项保留 |
| `network_inventory` | pass | `TCP=196`，`UDP=61` |
| `firewall_block` | pass | 成功创建并清理 `AegisValidation-e9cacbd5` rule group |
| `named_pipe_inventory` | pass | 成功枚举命名管道样本，包括 `InitShutdown`、`lsass`、`ntsvcs` |
| `module_inventory` | pass | 成功读取 `1Password.exe` 进程模块清单 |
| `vss_inventory` | pass | 成功读取 `3` 条 `Win32_ShadowCopy` 样本 |
| `device_inventory` | pass | 成功读取 `Display / AudioEndpoint / Firmware / System` 设备样本 |
| `amsi_surface` | pass | `has_amsi_runtime=true`，`has_powershell_operational_log=true`，`has_script_block_logging=false` |
| `suspend_kill_response` | pass | 真实执行 `NtSuspendProcess + Stop-Process`，目标 `pid=4720` |
| `quarantine_response` | pass | 真实移动文件到 `C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-142537-quarantine-input.txt` |
| `forensics_response` | pass | 真实生成 `C:\ProgramData\Aegis\forensics\windows-runtime-20260420-142537.zip` |

## 5. 关键产物

- 验收摘要：`C:\ProgramData\Aegis\validation\windows-runtime-20260420-142537\summary.json`
- 隔离产物：`C:\ProgramData\Aegis\quarantine\windows-runtime-20260420-142537-quarantine-input.txt`
- 取证目录：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-142537`
- 取证压缩包：`C:\ProgramData\Aegis\forensics\windows-runtime-20260420-142537.zip`

## 6. 结论

- `scripts/windows-runtime-verify.sh` 已可从仓库直接复跑 Windows 真机验收。
- `192.168.2.218` 已验证通过当前已完成的 Windows 运行时、网络隔离、响应链和验收链。
- `security_4688` 的验收口径以“日志可读、record_id 可取”为准；`cmd.exe` 临时探针命中率被保留为观察项，不作为失败条件。
