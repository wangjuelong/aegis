param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "driver"),
    [string]$BuildScriptPath = (Join-Path $PSScriptRoot "windows-build-driver.ps1"),
    [string]$InstallScriptPath = (Join-Path $PSScriptRoot "windows-install-driver.ps1"),
    [string]$UninstallScriptPath = (Join-Path $PSScriptRoot "windows-uninstall-driver.ps1"),
    [string]$DriverServiceName = "AegisSensorKmod"
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

    $buildResult = Invoke-JsonScript -ScriptPath $resolvedBuildScript -Arguments @{
        DriverRoot = $resolvedDriverRoot
        Configuration = "Release"
        Platform = "x64"
    }

    $installResult = $null
    $uninstallResult = $null
    try {
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
    } finally {
        $uninstallResult = Invoke-JsonScript -ScriptPath $resolvedUninstallScript -Arguments @{
            ServiceName = $DriverServiceName
        }
    }

    [ordered]@{
        build = $buildResult
        install = $installResult
        uninstall = $uninstallResult
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
    $amsiDll = Join-Path $env:WINDIR "System32\amsi.dll"
    [ordered]@{
        has_amsi_runtime = (Test-Path -LiteralPath $amsiDll) -and ($null -ne [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils"))
        has_powershell_operational_log = (Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -ErrorAction Stop) -ne $null
        has_script_block_logging = Get-ScriptBlockLoggingEnabled
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
