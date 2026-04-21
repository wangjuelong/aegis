param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "driver"),
    [string]$MinifilterRoot = (Join-Path $PSScriptRoot "minifilter"),
    [string]$BuildScriptPath = (Join-Path $PSScriptRoot "windows-build-driver.ps1"),
    [string]$BuildMinifilterScriptPath = (Join-Path $PSScriptRoot "windows-build-minifilter.ps1"),
    [string]$InstallScriptPath = (Join-Path $PSScriptRoot "windows-install-driver.ps1"),
    [string]$UninstallScriptPath = (Join-Path $PSScriptRoot "windows-uninstall-driver.ps1"),
    [string]$InstallMinifilterScriptPath = (Join-Path $PSScriptRoot "windows-install-minifilter.ps1"),
    [string]$UninstallMinifilterScriptPath = (Join-Path $PSScriptRoot "windows-uninstall-minifilter.ps1"),
    [string]$AmsiScanScriptPath = (Join-Path $PSScriptRoot "windows-scan-script-with-amsi.ps1"),
    [string]$ScriptEventQueryPath = (Join-Path $PSScriptRoot "windows-query-script-events.ps1"),
    [string]$MemorySnapshotScriptPath = (Join-Path $PSScriptRoot "windows-query-memory-snapshot.ps1"),
    [string]$FileEventQueryPath = (Join-Path $PSScriptRoot "windows-query-file-events.ps1"),
    [string]$FileProtectionScriptPath = (Join-Path $PSScriptRoot "windows-configure-file-protection.ps1"),
    [string]$RegistryEventQueryPath = (Join-Path $PSScriptRoot "windows-query-registry-events.ps1"),
    [string]$RegistryProtectionScriptPath = (Join-Path $PSScriptRoot "windows-configure-registry-protection.ps1"),
    [string]$PreemptiveBlockScriptPath = (Join-Path $PSScriptRoot "windows-configure-preemptive-block.ps1"),
    [string]$DriverServiceName = "AegisSensorKmod",
    [string]$MinifilterServiceName = "AegisFileMonitor"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisValidation.ProcessControl" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace AegisValidation {
    public static class ProcessControl {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtSuspendProcess(IntPtr processHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@ | Out-Null
}

$validationId = "windows-runtime-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")
$validationRoot = Join-Path $env:ProgramData "Aegis\validation\$validationId"
$quarantineRoot = Join-Path $env:ProgramData "Aegis\quarantine"
$forensicsRoot = Join-Path $env:ProgramData "Aegis\forensics"

New-Item -ItemType Directory -Path $validationRoot -Force | Out-Null
New-Item -ItemType Directory -Path $quarantineRoot -Force | Out-Null
New-Item -ItemType Directory -Path $forensicsRoot -Force | Out-Null

$results = [ordered]@{}
$requiredFailures = New-Object System.Collections.Generic.List[string]
$driverInstallState = [ordered]@{
    ready = $false
    build = $null
    install = $null
}
$minifilterInstallState = [ordered]@{
    ready = $false
    build = $null
    install = $null
}

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        throw "missing ${Description}: ${Path}"
    }

    $resolved.Path
}

function Invoke-ValidationStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [bool]$Required = $true,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Body
    )

    try {
        $value = & $Body
        $results[$Name] = [ordered]@{
            status = "pass"
            required = $Required
            value = $value
        }
    } catch {
        $results[$Name] = [ordered]@{
            status = "fail"
            required = $Required
            error = $_.Exception.Message
        }
        if ($Required) {
            $requiredFailures.Add($Name) | Out-Null
        }
    }
}

function Invoke-JsonScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [hashtable]$Arguments
    )

    $resolvedScript = Resolve-ExistingPath -Path $ScriptPath -Description "script"
    $invokeArgs = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $resolvedScript
    )

    foreach ($entry in $Arguments.GetEnumerator()) {
        $invokeArgs += "-$($entry.Key)"
        $invokeArgs += [string]$entry.Value
    }

    $output = & powershell @invokeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "script failed: $resolvedScript (exit code $LASTEXITCODE)"
    }

    $jsonLine = @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Last 1)
    if ($jsonLine.Count -ne 1) {
        throw "script did not emit a terminal JSON line: $resolvedScript"
    }

    $jsonLine[0] | ConvertFrom-Json -ErrorAction Stop
}

function Get-ScriptBlockLoggingEnabled {
    try {
        $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction Stop
        return [int]$policy.EnableScriptBlockLogging -eq 1
    } catch {
        return $false
    }
}

function Get-ScriptBlockLoggingState {
    try {
        $policy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -ErrorAction Stop
        return [ordered]@{
            exists = $true
            value = [int]$policy.EnableScriptBlockLogging
        }
    } catch {
        return [ordered]@{
            exists = $false
            value = $null
        }
    }
}

function Set-ScriptBlockLoggingEnabled {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Enabled
    )

    $keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    New-Item -ItemType Directory -Path $keyPath -Force | Out-Null
    if ($Enabled) {
        New-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -PropertyType DWord -Value 1 -Force | Out-Null
    } else {
        $item = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
        if ($null -ne $item -and @($item.Property) -contains "EnableScriptBlockLogging") {
            Remove-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        }
    }
}

function Restore-ScriptBlockLoggingState {
    param(
        [Parameter(Mandatory = $true)]
        $State
    )

    $keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if ($State.exists) {
        New-Item -ItemType Directory -Path $keyPath -Force | Out-Null
        New-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -PropertyType DWord -Value ([int]$State.value) -Force | Out-Null
    } else {
        $item = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
        if ($null -ne $item -and @($item.Property) -contains "EnableScriptBlockLogging") {
            Remove-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        }
        $item = Get-Item -LiteralPath $keyPath -ErrorAction SilentlyContinue
        if ($null -ne $item -and $item.Property.Count -eq 0) {
            Remove-Item -LiteralPath $keyPath -Force
        }
    }
}

function Get-LatestScriptBlockRecordId {
    $event = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
    } -MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $event) {
        return [uint64]0
    }

    [uint64]$event.RecordId
}

function Get-EventDataMap {
    param(
        [Parameter(Mandatory = $true)]
        [xml]$Xml
    )

    $eventData = @{}
    foreach ($item in $Xml.Event.EventData.Data) {
        if ($item.Name) {
            $eventData[$item.Name] = [string]$item.InnerText
        }
    }
    $eventData
}

function Suspend-ProcessWithNt {
    param(
        [Parameter(Mandatory = $true)]
        [uint32]$ProcessId
    )

    $PROCESS_SUSPEND_RESUME = 0x0800
    $handle = [AegisValidation.ProcessControl]::OpenProcess($PROCESS_SUSPEND_RESUME, $false, $ProcessId)
    if ($handle -eq [IntPtr]::Zero) {
        throw "OpenProcess failed for PID $ProcessId"
    }

    try {
        $status = [AegisValidation.ProcessControl]::NtSuspendProcess($handle)
        if ($status -ne 0) {
            throw ("NtSuspendProcess failed with NTSTATUS=0x{0:X8}" -f $status)
        }
    } finally {
        [void][AegisValidation.ProcessControl]::CloseHandle($handle)
    }
}

function Convert-HexStringToByteArray {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hex
    )

    if (($Hex.Length % 2) -ne 0) {
        throw "hex string length must be even"
    }

    $buffer = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $buffer.Length; $i++) {
        $buffer[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    $buffer
}

Invoke-ValidationStep -Name "host_baseline" -Body {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    [ordered]@{
        computer_name = $env:COMPUTERNAME
        user_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        caption = [string]$os.Caption
        version = [string]$os.Version
        build_number = [string]$os.BuildNumber
        architecture = [string]$os.OSArchitecture
        powershell_version = $PSVersionTable.PSVersion.ToString()
    }
}

Invoke-ValidationStep -Name "driver_transport" -Body {
    $resolvedDriverRoot = Resolve-ExistingPath -Path $DriverRoot -Description "driver root"
    $resolvedBuildScript = Resolve-ExistingPath -Path $BuildScriptPath -Description "driver build script"
    $resolvedInstallScript = Resolve-ExistingPath -Path $InstallScriptPath -Description "driver install script"
    $resolvedUninstallScript = Resolve-ExistingPath -Path $UninstallScriptPath -Description "driver uninstall script"

    try {
        Invoke-JsonScript -ScriptPath $resolvedUninstallScript -Arguments @{
            ServiceName = $DriverServiceName
        } | Out-Null
    } catch {
    }

    $buildResult = Invoke-JsonScript -ScriptPath $resolvedBuildScript -Arguments @{
        DriverRoot = $resolvedDriverRoot
        Configuration = "Release"
        Platform = "x64"
    }

    $installResult = Invoke-JsonScript -ScriptPath $resolvedInstallScript -Arguments @{
        DriverRoot = $resolvedDriverRoot
        Configuration = "Release"
        Platform = "x64"
        ServiceName = $DriverServiceName
    }

    $protocolVersion = [int]$installResult.driver_query.protocol_version
    if ($protocolVersion -ne 65536) {
        throw "driver protocol mismatch: $protocolVersion"
    }

    $driverInstallState.ready = $true
    $driverInstallState.build = $buildResult
    $driverInstallState.install = $installResult

    [ordered]@{
        build = $buildResult
        install = $installResult
    }
}

Invoke-ValidationStep -Name "minifilter_transport" -Body {
    $resolvedMinifilterRoot = Resolve-ExistingPath -Path $MinifilterRoot -Description "minifilter root"
    $resolvedBuildMinifilterScript = Resolve-ExistingPath -Path $BuildMinifilterScriptPath -Description "minifilter build script"
    $resolvedInstallMinifilterScript = Resolve-ExistingPath -Path $InstallMinifilterScriptPath -Description "minifilter install script"
    $resolvedUninstallMinifilterScript = Resolve-ExistingPath -Path $UninstallMinifilterScriptPath -Description "minifilter uninstall script"
    $resolvedFileEventQuery = Resolve-ExistingPath -Path $FileEventQueryPath -Description "file event query script"

    try {
        Invoke-JsonScript -ScriptPath $resolvedUninstallMinifilterScript -Arguments @{
            ServiceName = $MinifilterServiceName
        } | Out-Null
    } catch {
    }

    $buildResult = Invoke-JsonScript -ScriptPath $resolvedBuildMinifilterScript -Arguments @{
        DriverRoot = $resolvedMinifilterRoot
        Configuration = "Release"
        Platform = "x64"
    }

    $installResult = Invoke-JsonScript -ScriptPath $resolvedInstallMinifilterScript -Arguments @{
        DriverRoot = $resolvedMinifilterRoot
        Configuration = "Release"
        Platform = "x64"
        ServiceName = $MinifilterServiceName
    }

    $status = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
        Mode = "status"
    }
    if ([uint32]$status.protocol_version -ne 65536) {
        throw "minifilter protocol mismatch: $([uint32]$status.protocol_version)"
    }

    $minifilterInstallState.ready = $true
    $minifilterInstallState.build = $buildResult
    $minifilterInstallState.install = $installResult

    [ordered]@{
        build = $buildResult
        install = $installResult
        status = $status
    }
}

Invoke-ValidationStep -Name "tpm_surface" -Required $false -Body {
    if ((Get-Command Get-Tpm -ErrorAction SilentlyContinue) -eq $null) {
        throw "Get-Tpm is unavailable"
    }

    $tpm = Get-Tpm -ErrorAction Stop
    [ordered]@{
        tpm_present = [bool]$tpm.TpmPresent
        tpm_ready = [bool]$tpm.TpmReady
        managed_auth_level = [string]$tpm.ManagedAuthLevel
        auto_provisioning = [string]$tpm.AutoProvisioning
        manufacturer_id = [string]$tpm.ManufacturerIdTxt
    }
}

Invoke-ValidationStep -Name "dpapi_roundtrip" -Body {
    Add-Type -AssemblyName System.Security | Out-Null

    $entropySource = Join-Path $PSHOME "powershell.exe"
    if (-not (Test-Path -LiteralPath $entropySource)) {
        throw "missing entropy source: $entropySource"
    }

    $entropyHash = Get-FileHash -LiteralPath $entropySource -Algorithm SHA256 -ErrorAction Stop
    $entropyBytes = Convert-HexStringToByteArray -Hex $entropyHash.Hash
    $plaintext = [System.Text.Encoding]::UTF8.GetBytes("aegis-windows-dpapi-validation::$validationId")

    $machineCipher = [System.Security.Cryptography.ProtectedData]::Protect(
        $plaintext,
        $entropyBytes,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    $machinePlain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $machineCipher,
        $entropyBytes,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )

    $userCipher = [System.Security.Cryptography.ProtectedData]::Protect(
        $plaintext,
        $entropyBytes,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    $userPlain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $userCipher,
        $entropyBytes,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    $plaintextBase64 = [Convert]::ToBase64String($plaintext)
    if ([Convert]::ToBase64String($machinePlain) -ne $plaintextBase64) {
        throw "machine-scope DPAPI roundtrip mismatch"
    }
    if ([Convert]::ToBase64String($userPlain) -ne $plaintextBase64) {
        throw "user-scope DPAPI roundtrip mismatch"
    }

    [ordered]@{
        entropy_source = $entropySource
        entropy_sha256 = $entropyHash.Hash.ToLowerInvariant()
        machine_scope_roundtrip = $true
        machine_ciphertext_length = $machineCipher.Length
        user_scope_roundtrip = $true
        user_ciphertext_length = $userCipher.Length
    }
}

Invoke-ValidationStep -Name "process_inventory" -Body {
    $wmiRows = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    $tasklistRows = @(
        tasklist /FO CSV /NH |
            Where-Object { $_ -and $_.Trim() -ne "" } |
            ConvertFrom-Csv -Header "ImageName", "PID", "SessionName", "SessionNumber", "MemUsage"
    )
    if ($wmiRows.Count -lt 1) {
        throw "Win32_Process returned no rows"
    }
    if ($tasklistRows.Count -lt 1) {
        throw "tasklist returned no rows"
    }
    [ordered]@{
        win32_process_count = $wmiRows.Count
        tasklist_count = $tasklistRows.Count
        sample = $wmiRows | Select-Object -First 3 ProcessId, ParentProcessId, Name, CommandLine
    }
}

Invoke-ValidationStep -Name "security_4688" -Body {
    $marker = (Get-Date).AddSeconds(-2)
    $probe = Start-Process -FilePath $env:ComSpec -ArgumentList "/c", "exit 0" -PassThru -WindowStyle Hidden
    $probe.WaitForExit()
    $deadline = (Get-Date).AddSeconds(15)
    $probeCmdSeen = $false

    do {
        $rows = @()
        try {
            $rows = @(Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4688; StartTime = $marker } -MaxEvents 64 -ErrorAction Stop)
        } catch {
            $rows = @()
        }

        $probeCmdSeen = $rows |
            ForEach-Object {
                $xml = [xml]$_.ToXml()
                $eventData = Get-EventDataMap -Xml $xml
                [string]$eventData["NewProcessName"]
            } |
            Where-Object { $_ -match "cmd\.exe$" } |
            Select-Object -First 1

        if ($probeCmdSeen) {
            break
        }

        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    $latestEvent = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4688 } -MaxEvents 1 -ErrorAction Stop | Select-Object -First 1
    if ($null -eq $latestEvent) {
        throw "Security 4688 log is unreadable"
    }

    $xml = [xml]$latestEvent.ToXml()
    $eventData = Get-EventDataMap -Xml $xml

    [ordered]@{
        latest_record_id = [uint64]$latestEvent.RecordId
        latest_time_created = $latestEvent.TimeCreated.ToString("o")
        latest_process_name = $eventData["NewProcessName"]
        latest_command_line = $eventData["ProcessCommandLine"]
        probe_cmd_seen = [bool]$probeCmdSeen
    }
}

Invoke-ValidationStep -Name "network_inventory" -Body {
    if ((Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) -eq $null) {
        throw "Get-NetTCPConnection is unavailable"
    }
    if ((Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) -eq $null) {
        throw "Get-NetUDPEndpoint is unavailable"
    }

    $tcpRows = @(Get-NetTCPConnection -ErrorAction Stop)
    $udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop)

    [ordered]@{
        tcp_count = $tcpRows.Count
        udp_count = $udpRows.Count
        sample_tcp = $tcpRows | Select-Object -First 3 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        sample_udp = $udpRows | Select-Object -First 3 LocalAddress, LocalPort, OwningProcess
    }
}

Invoke-ValidationStep -Name "firewall_block" -Body {
    if ((Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -eq $null) {
        throw "Get-NetFirewallRule is unavailable"
    }
    if ((Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue) -eq $null) {
        throw "New-NetFirewallRule is unavailable"
    }

    $ruleGroup = "AegisValidation-{0}" -f ([Guid]::NewGuid().ToString("N").Substring(0, 8))
    $ruleName = "$ruleGroup-outbound"
    New-NetFirewallRule -DisplayName $ruleName -Group $ruleGroup -Direction Outbound -Action Block -RemoteAddress "10.10.10.10" -Enabled True -Profile Any -ErrorAction Stop | Out-Null
    $created = @(Get-NetFirewallRule -Group $ruleGroup -ErrorAction Stop)
    if ($created.Count -lt 1) {
        throw "firewall rule group was not created"
    }

    Remove-NetFirewallRule -Group $ruleGroup -ErrorAction Stop | Out-Null
    $remaining = @(Get-NetFirewallRule -Group $ruleGroup -ErrorAction SilentlyContinue)
    if ($remaining.Count -ne 0) {
        throw "firewall rule group cleanup failed"
    }

    [ordered]@{
        rule_group = $ruleGroup
        created_count = $created.Count
        cleaned = $true
    }
}

Invoke-ValidationStep -Name "registry_protection" -Body {
    $resolvedRegistryEventQuery = Resolve-ExistingPath -Path $RegistryEventQueryPath -Description "registry event query script"
    $resolvedRegistryProtectionScript = Resolve-ExistingPath -Path $RegistryProtectionScriptPath -Description "registry protection script"
    $validationKey = "HKLM:\SOFTWARE\AegisValidation\RegistryProtection\$validationId"
    $kernelKey = "\REGISTRY\MACHINE\SOFTWARE\AegisValidation\RegistryProtection\$validationId"
    $warmupKey = "HKLM:\SOFTWARE\AegisValidation\RegistryWarmup\$validationId"

    & reg.exe delete "HKLM\SOFTWARE\AegisValidation\RegistryProtection\$validationId" /f | Out-Null
    & reg.exe delete "HKLM\SOFTWARE\AegisValidation\RegistryWarmup\$validationId" /f | Out-Null
    New-Item -Path $validationKey -Force | Out-Null
    New-ItemProperty -Path $validationKey -Name "AllowedBeforeProtect" -Value "baseline" -PropertyType String -Force | Out-Null

    try {
        $clearResult = Invoke-JsonScript -ScriptPath $resolvedRegistryProtectionScript -Arguments @{
            Mode = "clear"
            ServiceName = $DriverServiceName
        }
        $protectResult = Invoke-JsonScript -ScriptPath $resolvedRegistryProtectionScript -Arguments @{
            Mode = "protect"
            ServiceName = $DriverServiceName
            KeyPath = $validationKey
        }

        New-Item -Path $warmupKey -Force | Out-Null
        New-ItemProperty -Path $warmupKey -Name "Warmup" -Value "warm" -PropertyType String -Force | Out-Null
        Remove-ItemProperty -Path $warmupKey -Name "Warmup" -ErrorAction SilentlyContinue

        $statusBefore = Invoke-JsonScript -ScriptPath $resolvedRegistryEventQuery -Arguments @{
            Mode = "status"
            ServiceName = $DriverServiceName
        }
        $lastSequence = [uint32]$statusBefore.current_sequence

        $blockedWriteSucceeded = $false
        $blockedWriteError = $null
        try {
            New-ItemProperty -Path $validationKey -Name "BlockedValue" -Value "blocked" -PropertyType String -Force -ErrorAction Stop | Out-Null
            $blockedWriteSucceeded = $true
        } catch {
            $blockedWriteError = $_.Exception.Message
        }
        if ($blockedWriteSucceeded) {
            throw "registry protected key accepted a write"
        }

        $allRegistryEvents = @()
        $registryCursor = [uint32]$lastSequence
        for ($page = 0; $page -lt 16; $page++) {
            $eventsPayload = Invoke-JsonScript -ScriptPath $resolvedRegistryEventQuery -Arguments @{
                Mode = "events"
                ServiceName = $DriverServiceName
                LastSequence = [string]$registryCursor
                MaxEntries = "128"
            }
            $pageEvents = @($eventsPayload.events)
            if ($pageEvents.Count -gt 0) {
                $allRegistryEvents += $pageEvents
                $registryCursor = [uint32]($pageEvents | Select-Object -Last 1).sequence
            } else {
                $registryCursor = [uint32]$eventsPayload.current_sequence
            }
            if ([uint32]$eventsPayload.returned_count -eq 0 -or
                $registryCursor -ge [uint32]$eventsPayload.current_sequence) {
                break
            }
        }

        $blockedEvents = @($allRegistryEvents | Where-Object {
                [bool]$_.blocked -and
                [string]$_.key_path -eq $kernelKey -and
                [string]$_.operation -eq "set"
            })
        if ($blockedEvents.Count -lt 1) {
            $registryEventSample = ($allRegistryEvents | Select-Object -First 12 operation, key_path, blocked | ConvertTo-Json -Compress)
            throw "registry block event was not captured: $registryEventSample"
        }

        [ordered]@{
            clear = $clearResult
            protect = $protectResult
            blocked_write_error = $blockedWriteError
            blocked_events = $blockedEvents | Select-Object -First 1
        }
    } finally {
        Invoke-JsonScript -ScriptPath $resolvedRegistryProtectionScript -Arguments @{
            Mode = "clear"
            ServiceName = $DriverServiceName
        } | Out-Null
        & reg.exe delete "HKLM\SOFTWARE\AegisValidation\RegistryProtection\$validationId" /f | Out-Null
        & reg.exe delete "HKLM\SOFTWARE\AegisValidation\RegistryWarmup\$validationId" /f | Out-Null
    }
}

Invoke-ValidationStep -Name "file_target_path_protection" -Body {
    $resolvedFileEventQuery = Resolve-ExistingPath -Path $FileEventQueryPath -Description "file event query script"
    $resolvedFileProtectionScript = Resolve-ExistingPath -Path $FileProtectionScriptPath -Description "file protection script"
    $validationRootPath = Join-Path $validationRoot "file-target-protection"
    $protectedRoot = Join-Path $validationRootPath "protected"
    $sourceRoot = Join-Path $validationRootPath "source"
    $warmupRoot = Join-Path $validationRootPath "warmup"
    $moveSourceFile = Join-Path $sourceRoot "move-source.txt"
    $moveTargetFile = Join-Path $protectedRoot "moved.txt"
    $linkSourceFile = Join-Path $sourceRoot "link-source.txt"
    $linkTargetFile = Join-Path $protectedRoot "linked.txt"
    $warmupSourceFile = Join-Path $warmupRoot "warmup-source.txt"
    $warmupMoveTargetFile = Join-Path $warmupRoot "warmup-moved.txt"
    $warmupLinkTargetFile = Join-Path $warmupRoot "warmup-linked.txt"
    $nativeHelperType = @"
using System;
using System.Runtime.InteropServices;
namespace AegisValidation {
    public static class FileOps {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool MoveFileEx(string existingFileName, string newFileName, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateHardLink(string fileName, string existingFileName, IntPtr securityAttributes);
    }
}
"@

    if (-not ("AegisValidation.FileOps" -as [type])) {
        Add-Type -TypeDefinition $nativeHelperType | Out-Null
    }

    function Get-TargetProtectionFileEvents {
        param(
            [Parameter(Mandatory = $true)]
            [uint32]$AfterSequence
        )

        $events = @()
        $cursor = [uint32]$AfterSequence
        for ($page = 0; $page -lt 16; $page++) {
            $payload = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
                Mode = "events"
                LastSequence = [string]$cursor
                MaxEntries = "256"
            }
            $pageEvents = @($payload.events)
            if ($pageEvents.Count -gt 0) {
                $events += $pageEvents
                $cursor = [uint32]($pageEvents | Select-Object -Last 1).sequence
            } else {
                $cursor = [uint32]$payload.current_sequence
            }
            if ([uint32]$payload.returned_count -eq 0 -or $cursor -ge [uint32]$payload.current_sequence) {
                break
            }
        }

        @($events)
    }

    New-Item -ItemType Directory -Path $protectedRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $sourceRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $warmupRoot -Force | Out-Null
    Set-Content -LiteralPath $moveSourceFile -Value "move-source" -Encoding UTF8
    Set-Content -LiteralPath $linkSourceFile -Value "link-source" -Encoding UTF8
    Set-Content -LiteralPath $warmupSourceFile -Value "warmup-source" -Encoding UTF8

    try {
        Invoke-JsonScript -ScriptPath $resolvedFileProtectionScript -Arguments @{
            Mode = "clear"
        } | Out-Null

        $protectResult = Invoke-JsonScript -ScriptPath $resolvedFileProtectionScript -Arguments @{
            Mode = "protect"
            Path = $protectedRoot
        }

        if (-not [AegisValidation.FileOps]::MoveFileEx($warmupSourceFile, $warmupMoveTargetFile, [uint32]0)) {
            throw ("warmup MoveFileEx failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        if (-not [AegisValidation.FileOps]::CreateHardLink($warmupLinkTargetFile, $warmupMoveTargetFile, [IntPtr]::Zero)) {
            throw ("warmup CreateHardLink failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }

        $statusBefore = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
            Mode = "status"
        }
        $lastSequence = [uint32]$statusBefore.current_sequence

        $moveCommand = @"
Add-Type -TypeDefinition @'
$nativeHelperType
'@ | Out-Null
if ([AegisValidation.FileOps]::MoveFileEx('$moveSourceFile', '$moveTargetFile', [uint32]0)) {
    exit 0
}
exit [Runtime.InteropServices.Marshal]::GetLastWin32Error()
"@
        $moveProc = Start-Process -FilePath "powershell" -ArgumentList "-NoProfile", "-NonInteractive", "-Command", $moveCommand -PassThru -WindowStyle Hidden
        $moveProc.WaitForExit()
        $moveSucceeded = Test-Path -LiteralPath $moveTargetFile
        $moveError = ("MoveFileEx helper exit={0}; source_exists={1}; target_exists={2}" -f $moveProc.ExitCode, (Test-Path -LiteralPath $moveSourceFile), (Test-Path -LiteralPath $moveTargetFile))

        $linkCommand = @"
Add-Type -TypeDefinition @'
$nativeHelperType
'@ | Out-Null
if ([AegisValidation.FileOps]::CreateHardLink('$linkTargetFile', '$linkSourceFile', [IntPtr]::Zero)) {
    exit 0
}
exit [Runtime.InteropServices.Marshal]::GetLastWin32Error()
"@
        $linkProc = Start-Process -FilePath "powershell" -ArgumentList "-NoProfile", "-NonInteractive", "-Command", $linkCommand -PassThru -WindowStyle Hidden
        $linkProc.WaitForExit()
        $linkSucceeded = Test-Path -LiteralPath $linkTargetFile
        $linkError = ("CreateHardLink helper exit={0}; target_exists={1}" -f $linkProc.ExitCode, (Test-Path -LiteralPath $linkTargetFile))

        $allFileEvents = @(Get-TargetProtectionFileEvents -AfterSequence $lastSequence)
        $moveTargetName = [System.IO.Path]::GetFileName($moveTargetFile)
        $linkTargetName = [System.IO.Path]::GetFileName($linkTargetFile)
        $moveEvents = @($allFileEvents | Where-Object {
                [string]$_.operation -like "block-*" -and
                [uint32]$_.process_id -eq [uint32]$moveProc.Id -and
                [string]$_.path -like "*$moveTargetName"
            })
        $linkEvents = @($allFileEvents | Where-Object {
                [string]$_.operation -like "block-*" -and
                [uint32]$_.process_id -eq [uint32]$linkProc.Id -and
                [string]$_.path -like "*$linkTargetName"
            })
        if ($moveSucceeded) {
            $sample = ($allFileEvents | Where-Object {
                    [uint32]$_.process_id -eq [uint32]$moveProc.Id
                } | Select-Object -First 32 operation, path, process_id | ConvertTo-Json -Compress)
            throw "move into protected directory succeeded unexpectedly: $sample"
        }
        if ($linkSucceeded) {
            $sample = ($allFileEvents | Where-Object {
                    [uint32]$_.process_id -eq [uint32]$linkProc.Id
                } | Select-Object -First 32 operation, path, process_id | ConvertTo-Json -Compress)
            throw "hardlink into protected directory succeeded unexpectedly: $sample"
        }
        [ordered]@{
            protect = $protectResult
            move_error = $moveError
            hardlink_error = $linkError
            events = [ordered]@{
                move = $moveEvents | Select-Object -First 1
                hardlink = $linkEvents | Select-Object -First 1
            }
        }
    } finally {
        Invoke-JsonScript -ScriptPath $resolvedFileProtectionScript -Arguments @{
            Mode = "clear"
        } | Out-Null
        Remove-Item -LiteralPath $moveTargetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $linkTargetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $moveSourceFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $linkSourceFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $warmupLinkTargetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $warmupMoveTargetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $warmupSourceFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $validationRootPath -Force -Recurse -ErrorAction SilentlyContinue
    }
}

Invoke-ValidationStep -Name "preemptive_blocking" -Body {
    $resolvedFileEventQuery = Resolve-ExistingPath -Path $FileEventQueryPath -Description "file event query script"
    $resolvedPreemptiveBlockScript = Resolve-ExistingPath -Path $PreemptiveBlockScriptPath -Description "preemptive block script"
    $pathBlockRoot = Join-Path $validationRoot "preemptive-path"
    $pathExistingFile = Join-Path $pathBlockRoot "existing.txt"
    $pathCreateFile = Join-Path $pathBlockRoot "create.txt"
    $pathRenameFile = Join-Path $pathBlockRoot "renamed.txt"
    $pathWarmupRoot = Join-Path $validationRoot "preemptive-path-warmup"
    $pathWarmupFile = Join-Path $pathWarmupRoot "warmup.txt"
    $pathWarmupRenamed = Join-Path $pathWarmupRoot "warmup-renamed.txt"
    $pidTargetFile = Join-Path $validationRoot "pid-target.txt"
    $hashTargetFile = Join-Path $validationRoot "hash-target.txt"
    $pidProc = $null

    function Get-PreemptiveFileEvents {
        param(
            [Parameter(Mandatory = $true)]
            [uint32]$AfterSequence
        )

        $events = @()
        $cursor = [uint32]$AfterSequence
        for ($page = 0; $page -lt 16; $page++) {
            $payload = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
                Mode = "events"
                LastSequence = [string]$cursor
                MaxEntries = "256"
            }
            $pageEvents = @($payload.events)
            if ($pageEvents.Count -gt 0) {
                $events += $pageEvents
                $cursor = [uint32]($pageEvents | Select-Object -Last 1).sequence
            } else {
                $cursor = [uint32]$payload.current_sequence
            }
            if ([uint32]$payload.returned_count -eq 0 -or $cursor -ge [uint32]$payload.current_sequence) {
                break
            }
        }

        @($events)
    }

    New-Item -ItemType Directory -Path $pathBlockRoot -Force | Out-Null
    New-Item -ItemType Directory -Path $pathWarmupRoot -Force | Out-Null
    Set-Content -LiteralPath $pathExistingFile -Value "baseline" -Encoding UTF8
    Set-Content -LiteralPath $pidTargetFile -Value "baseline" -Encoding UTF8
    Set-Content -LiteralPath $hashTargetFile -Value "Aegis hash block sample" -Encoding UTF8

    try {
        Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "clear"
        } | Out-Null

        $pathBlock = Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "block-path"
            Path = $pathBlockRoot
            TtlSeconds = "300"
        }

        [System.IO.File]::WriteAllText($pathWarmupFile, "warmup")
        [System.IO.File]::Move($pathWarmupFile, $pathWarmupRenamed)
        [System.IO.File]::Delete($pathWarmupRenamed)

        $pathCreateStatus = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
            Mode = "status"
        }
        $pathCreateSequence = [uint32]$pathCreateStatus.current_sequence

        $pathCreateError = $null
        try {
            [System.IO.File]::WriteAllText($pathCreateFile, "blocked-create")
            throw "path block allowed file creation"
        } catch {
            $pathCreateError = $_.Exception.Message
        }

        $pathRenameError = $null
        try {
            [System.IO.File]::Move($pathExistingFile, $pathRenameFile)
            throw "path block allowed rename"
        } catch {
            $pathRenameError = $_.Exception.Message
        }

        $pathDeleteError = $null
        try {
            [System.IO.File]::Delete($pathExistingFile)
            throw "path block allowed delete"
        } catch {
            $pathDeleteError = $_.Exception.Message
        }

        $pathEvents = @(Get-PreemptiveFileEvents -AfterSequence $pathCreateSequence | Where-Object {
                [string]$_.operation -eq "block-path"
            })
        if ($pathEvents.Count -lt 1) {
            $pathEventSample = (Get-PreemptiveFileEvents -AfterSequence $pathCreateSequence | Select-Object -First 12 operation, path, process_id | ConvertTo-Json -Compress)
            throw "path block event was not captured: create=$pathCreateError; rename=$pathRenameError; delete=$pathDeleteError; events=$pathEventSample"
        }

        Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "clear"
        } | Out-Null

        $pidStatusBefore = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
            Mode = "status"
        }
        $pidSequence = [uint32]$pidStatusBefore.current_sequence

        $pidCommand = "timeout /t 2 /nobreak >nul & echo blocked-write>>`"$pidTargetFile`""
        $pidProc = Start-Process -FilePath $env:ComSpec -ArgumentList "/c", $pidCommand -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 500

        $pidBlock = Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "block-pid"
            ProcessId = [string]$pidProc.Id
            TtlSeconds = "300"
        }

        $pidProc.WaitForExit()
        if ($pidProc.ExitCode -eq 0) {
            throw "pid block allowed target process write"
        }
        $pidTargetContent = Get-Content -LiteralPath $pidTargetFile -Raw -ErrorAction Stop
        if ($pidTargetContent -ne "baseline`r`n" -and $pidTargetContent -ne "baseline") {
            throw "pid block mutated target file contents"
        }

        $pidEvents = @(Get-PreemptiveFileEvents -AfterSequence $pidSequence | Where-Object {
                [string]$_.operation -eq "block-pid" -and
                [uint32]$_.process_id -eq [uint32]$pidProc.Id
            })
        if ($pidEvents.Count -lt 1) {
            $pidEventSample = (Get-PreemptiveFileEvents -AfterSequence $pidSequence | Select-Object -First 12 operation, path, process_id | ConvertTo-Json -Compress)
            throw "pid block event was not captured: events=$pidEventSample"
        }

        Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "clear"
        } | Out-Null

        $hashStatusBefore = Invoke-JsonScript -ScriptPath $resolvedFileEventQuery -Arguments @{
            Mode = "status"
        }
        $hashSequence = [uint32]$hashStatusBefore.current_sequence

        $hashValue = (Get-FileHash -LiteralPath $hashTargetFile -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        $hashBlock = Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "block-hash"
            Hash = $hashValue
            TtlSeconds = "300"
        }

        $hashReadError = $null
        try {
            Get-Content -LiteralPath $hashTargetFile -ErrorAction Stop | Out-Null
            throw "hash block allowed file open"
        } catch {
            $hashReadError = $_.Exception.Message
        }

        $hashEvents = @(Get-PreemptiveFileEvents -AfterSequence $hashSequence | Where-Object {
                [string]$_.operation -eq "block-hash" -and
                [string]$_.path -like "*hash-target.txt"
            })
        if ($hashEvents.Count -lt 1) {
            $hashEventSample = (Get-PreemptiveFileEvents -AfterSequence $hashSequence | Select-Object -First 12 operation, path, process_id | ConvertTo-Json -Compress)
            throw "hash block event was not captured: events=$hashEventSample"
        }

        $finalClear = Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "clear"
        }
        $finalStatus = Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "status"
        }
        if ([uint32]$finalStatus.block_entry_count -ne 0) {
            throw "preemptive block state was not cleared"
        }

        [ordered]@{
            path_block = $pathBlock
            path_create_error = $pathCreateError
            path_rename_error = $pathRenameError
            path_delete_error = $pathDeleteError
            pid_block = $pidBlock
            pid_process_id = [uint32]$pidProc.Id
            hash_block = $hashBlock
            hash = $hashValue
            hash_read_error = $hashReadError
            events = [ordered]@{
                path = $pathEvents | Select-Object -First 1
                pid = $pidEvents | Select-Object -First 1
                hash = $hashEvents | Select-Object -First 1
            }
            final_clear = $finalClear
            final_status = $finalStatus
        }
    } finally {
        Invoke-JsonScript -ScriptPath $resolvedPreemptiveBlockScript -Arguments @{
            Mode = "clear"
        } | Out-Null
        if ($null -ne $pidProc -and -not $pidProc.HasExited) {
            Stop-Process -Id $pidProc.Id -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $pathRenameFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathCreateFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathExistingFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathBlockRoot -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathWarmupRenamed -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathWarmupFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pathWarmupRoot -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $pidTargetFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $hashTargetFile -Force -ErrorAction SilentlyContinue
    }
}

Invoke-ValidationStep -Name "named_pipe_inventory" -Body {
    $pipes = @(Get-ChildItem -Path "\\.\pipe\" -ErrorAction Stop | Select-Object -First 5 Name)
    if ($pipes.Count -lt 1) {
        throw "named pipe inventory returned no rows"
    }
    [ordered]@{
        sample_count = $pipes.Count
        sample = $pipes
    }
}

Invoke-ValidationStep -Name "module_inventory" -Body {
    $probeProcess = Get-Process -ErrorAction Stop | Where-Object { $_.Path } | Select-Object -First 1
    if ($null -eq $probeProcess) {
        throw "no process with module path visibility available"
    }

    $modules = @($probeProcess.Modules | Where-Object { $_.FileName } | Select-Object -First 5 ModuleName, FileName)
    if ($modules.Count -lt 1) {
        throw "module inventory returned no rows"
    }

    [ordered]@{
        process_name = $probeProcess.ProcessName
        process_id = $probeProcess.Id
        sample_modules = $modules
    }
}

Invoke-ValidationStep -Name "vss_inventory" -Body {
    $snapshots = @(Get-CimInstance Win32_ShadowCopy -ErrorAction Stop | Select-Object -First 5 ID, VolumeName)
    [ordered]@{
        snapshot_count = $snapshots.Count
        sample = $snapshots
    }
}

Invoke-ValidationStep -Name "device_inventory" -Body {
    if ((Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) -eq $null) {
        throw "Get-PnpDevice is unavailable"
    }

    $devices = @(Get-PnpDevice -ErrorAction Stop | Select-Object -First 5 Class, FriendlyName, InstanceId, Status)
    if ($devices.Count -lt 1) {
        throw "device inventory returned no rows"
    }

    [ordered]@{
        device_count = $devices.Count
        sample = $devices
    }
}

Invoke-ValidationStep -Name "amsi_surface" -Body {
    $resolvedAmsiScript = Resolve-ExistingPath -Path $AmsiScanScriptPath -Description "amsi scan script"
    $status = Invoke-JsonScript -ScriptPath $resolvedAmsiScript -Arguments @{
        Mode = "status"
    }

    [ordered]@{
        has_amsi_runtime = [bool]$status.has_amsi_runtime
        scan_interface_ready = [bool]$status.scan_interface_ready
        session_opened = [bool]$status.session_opened
        amsi_result = [uint32]$status.amsi_result
        has_powershell_operational_log = (Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction Stop) -ne $null
        has_script_block_logging = Get-ScriptBlockLoggingEnabled
    }
}

Invoke-ValidationStep -Name "script_surface_roundtrip" -Body {
    $resolvedAmsiScript = Resolve-ExistingPath -Path $AmsiScanScriptPath -Description "amsi scan script"
    $resolvedScriptEventQuery = Resolve-ExistingPath -Path $ScriptEventQueryPath -Description "script event query script"
    $previousState = Get-ScriptBlockLoggingState
    $beforeRecordId = Get-LatestScriptBlockRecordId

    try {
        Set-ScriptBlockLoggingEnabled -Enabled $true
        Start-Sleep -Milliseconds 300

        $allowScript = "Write-Output 'Aegis script surface allow'"
        $allowResult = Invoke-JsonScript -ScriptPath $resolvedAmsiScript -Arguments @{
            Mode = "execute"
            ContentName = "AegisAllow.ps1"
            ScriptContentBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($allowScript))
        }
        if (-not [bool]$allowResult.executed) {
            throw "expected benign script to execute"
        }

        $scriptEvents = @()
        $matched = @()
        $deadline = (Get-Date).AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 500
            $scriptEvents = @(
                Invoke-JsonScript -ScriptPath $resolvedScriptEventQuery -Arguments @{
                    AfterRecordId = [string]$beforeRecordId
                    MaxEntries = "256"
                }
            )
            $matched = @($scriptEvents | Where-Object { $_.script_text -like "*Aegis script surface allow*" })
            if ($matched.Count -gt 0) {
                break
            }
        } while ((Get-Date) -lt $deadline)
        if ($matched.Count -lt 1) {
            throw "no script block logging event captured for benign script"
        }

        $blockValidation = [ordered]@{
            skipped = $false
            reason = $null
            result = $null
        }
        if (-not [bool]$allowResult.scan_interface_ready) {
            $blockValidation.skipped = $true
            $blockValidation.reason = "host_amsi_scan_interface_unavailable"
            return [ordered]@{
                allow = $allowResult
                benign_event = $matched | Select-Object -First 1
                block = $blockValidation
            }
        }

        # Build the official AMSI test sample at runtime so the verifier itself is not signature-blocked on upload.
        $amsiSample = -join ((@(
            65,77,83,73,32,84,101,115,116,32,83,97,109,112,108,101,58,32,
            55,101,55,50,99,51,99,101,45,56,54,49,98,45,52,51,51,57,45,56,55,52,48,45,48,97,99,49,52,56,52,99,49,51,56,54
        )) | ForEach-Object { [char]$_ })
        $blockScript = "`$null = '$amsiSample'"
        $blockResult = Invoke-JsonScript -ScriptPath $resolvedAmsiScript -Arguments @{
            Mode = "execute"
            ContentName = "AegisBlock.ps1"
            ScriptContentBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($blockScript))
        }
        if (-not [bool]$blockResult.blocked -or [bool]$blockResult.executed) {
            throw "expected suspicious script to be blocked before execution"
        }
        $blockValidation.result = $blockResult

        [ordered]@{
            allow = $allowResult
            benign_event = $matched | Select-Object -First 1
            block = $blockValidation
        }
    } finally {
        Restore-ScriptBlockLoggingState -State $previousState
    }
}

Invoke-ValidationStep -Name "memory_signal_roundtrip" -Body {
    $resolvedMemoryScript = Resolve-ExistingPath -Path $MemorySnapshotScriptPath -Description "memory snapshot script"
    $before = Invoke-JsonScript -ScriptPath $resolvedMemoryScript -Arguments @{}
    $memoryProc = Start-Process -FilePath "powershell" -ArgumentList "-NoProfile", "-NonInteractive", "-Command", "[byte[]]`$buffer = New-Object byte[] (96MB); Start-Sleep -Seconds 15" -PassThru
    try {
        Start-Sleep -Seconds 2
        $after = Invoke-JsonScript -ScriptPath $resolvedMemoryScript -Arguments @{}
        $sample = @($after | Where-Object { [uint32]$_.process_id -eq [uint32]$memoryProc.Id } | Select-Object -First 1)
        if ($sample.Count -ne 1) {
            throw "memory snapshot did not include validation process"
        }
        if ([uint64]$sample[0].private_memory_bytes -lt 67108864) {
            throw "memory snapshot did not capture expected private memory growth"
        }

        [ordered]@{
            pid = $memoryProc.Id
            before_count = @($before).Count
            after_count = @($after).Count
            sample = $sample[0]
        }
    } finally {
        Stop-Process -Id $memoryProc.Id -Force -ErrorAction SilentlyContinue
    }
}

Invoke-ValidationStep -Name "suspend_kill_response" -Body {
    $proc = Start-Process -FilePath "powershell" -ArgumentList "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 300" -PassThru
    try {
        Start-Sleep -Milliseconds 500
        Suspend-ProcessWithNt -ProcessId ([uint32]$proc.Id)
        Stop-Process -Id $proc.Id -Force -ErrorAction Stop

        $deadline = (Get-Date).AddSeconds(5)
        do {
            $alive = Get-Process -Id $proc.Id -ErrorAction SilentlyContinue
            if ($null -eq $alive) {
                break
            }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)

        if ($null -ne $alive) {
            throw "process is still alive after kill"
        }

        [ordered]@{
            pid = $proc.Id
            suspend = $true
            kill = $true
        }
    } finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

Invoke-ValidationStep -Name "quarantine_response" -Body {
    $sourcePath = Join-Path $validationRoot "quarantine-input.txt"
    $destinationPath = Join-Path $quarantineRoot ("{0}-quarantine-input.txt" -f $validationId)
    "aegis quarantine validation" | Set-Content -LiteralPath $sourcePath -Encoding Ascii
    $sha256 = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    Move-Item -LiteralPath $sourcePath -Destination $destinationPath -Force

    if (Test-Path -LiteralPath $sourcePath) {
        throw "source file still exists after quarantine move"
    }
    if (-not (Test-Path -LiteralPath $destinationPath)) {
        throw "quarantine destination was not created"
    }

    [ordered]@{
        sha256 = $sha256
        destination = $destinationPath
    }
}

Invoke-ValidationStep -Name "forensics_response" -Body {
    if ((Get-Command Compress-Archive -ErrorAction SilentlyContinue) -eq $null) {
        throw "Compress-Archive is unavailable"
    }

    $bundleRoot = Join-Path $forensicsRoot $validationId
    $bundleZip = "$bundleRoot.zip"
    New-Item -ItemType Directory -Path $bundleRoot -Force | Out-Null

    $processPath = Join-Path $bundleRoot "processes.json"
    $networkPath = Join-Path $bundleRoot "network.json"
    $registryPath = Join-Path $bundleRoot "run-key.reg"
    $manifestPath = Join-Path $bundleRoot "manifest.json"

    Get-CimInstance Win32_Process -ErrorAction Stop |
        Sort-Object ProcessId |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath $processPath -Encoding UTF8

    $tcpRows = @(Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 64 LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)
    $udpRows = @(Get-NetUDPEndpoint -ErrorAction Stop | Select-Object -First 64 LocalAddress, LocalPort, OwningProcess)
    [ordered]@{
        tcp = $tcpRows
        udp = $udpRows
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $networkPath -Encoding UTF8

    & reg.exe export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" $registryPath /y | Out-Null
    if (-not (Test-Path -LiteralPath $registryPath)) {
        throw "registry export file was not created"
    }

    [ordered]@{
        validation_id = $validationId
        bundle_root = $bundleRoot
        collected = @(
            [ordered]@{ kind = "processes"; path = $processPath }
            [ordered]@{ kind = "network"; path = $networkPath }
            [ordered]@{ kind = "registry"; path = $registryPath }
        )
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    if (Test-Path -LiteralPath $bundleZip) {
        Remove-Item -LiteralPath $bundleZip -Force
    }
    Compress-Archive -LiteralPath @($processPath, $networkPath, $registryPath, $manifestPath) -DestinationPath $bundleZip -Force
    if (-not (Test-Path -LiteralPath $bundleZip)) {
        throw "forensics archive was not created"
    }

    [ordered]@{
        bundle_root = $bundleRoot
        bundle_zip = $bundleZip
        manifest = $manifestPath
    }
}

Invoke-ValidationStep -Name "driver_cleanup" -Body {
    if ([bool]$minifilterInstallState.ready) {
        $resolvedUninstallMinifilterScript = Resolve-ExistingPath -Path $UninstallMinifilterScriptPath -Description "minifilter uninstall script"
        $minifilterUninstallResult = Invoke-JsonScript -ScriptPath $resolvedUninstallMinifilterScript -Arguments @{
            ServiceName = $MinifilterServiceName
        }
        $minifilterInstallState.ready = $false
        if ($null -ne $results["minifilter_transport"] -and $results["minifilter_transport"].status -eq "pass") {
            $results["minifilter_transport"].value["uninstall"] = $minifilterUninstallResult
        }
    }

    if (-not [bool]$driverInstallState.ready) {
        return [ordered]@{
            skipped = $true
        }
    }

    $resolvedUninstallScript = Resolve-ExistingPath -Path $UninstallScriptPath -Description "driver uninstall script"
    $uninstallResult = Invoke-JsonScript -ScriptPath $resolvedUninstallScript -Arguments @{
        ServiceName = $DriverServiceName
    }
    $driverInstallState.ready = $false
    if ($null -ne $results["driver_transport"] -and $results["driver_transport"].status -eq "pass") {
        $results["driver_transport"].value["uninstall"] = $uninstallResult
    }

    $uninstallResult
}

$summary = [ordered]@{
    validation_id = $validationId
    validation_root = $validationRoot
    generated_at = (Get-Date).ToString("o")
    required_failures = @($requiredFailures)
    results = $results
}

$summaryPath = Join-Path $validationRoot "summary.json"
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
$summary["summary_path"] = $summaryPath

$summary | ConvertTo-Json -Depth 8 -Compress | Write-Output

if ($requiredFailures.Count -gt 0) {
    [Console]::Error.WriteLine("validation failed: {0}" -f ($requiredFailures -join ", "))
    [Environment]::Exit(1)
}
