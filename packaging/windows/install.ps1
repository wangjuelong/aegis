param(
    [string]$PayloadRoot = $PSScriptRoot,
    [string]$ManifestPath = (Join-Path $PayloadRoot "manifest.json"),
    [string]$InstallRoot,
    [string]$StateRoot,
    [switch]$PayloadAlreadyInstalled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

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

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $Path
}

function Normalize-Path {
    param([Parameter(Mandatory = $true)][string]$Path)
    [System.IO.Path]::GetFullPath($Path)
}

function Get-Manifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-ExistingPath -Path $Path -Description "windows install manifest"
    $manifest = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.schema_version -ne 1) {
        throw "unsupported windows install manifest schema version: $($manifest.schema_version)"
    }
    if ($null -eq $manifest.components -or $manifest.components.Count -lt 1) {
        throw "windows install manifest has no components"
    }
    $manifest
}

function Get-Component {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $component = @($Manifest.components | Where-Object { $_.name -eq $Name })
    if ($component.Count -ne 1) {
        throw "component ${Name} is not uniquely defined in manifest"
    }
    $component[0]
}

function Get-InstalledComponentPath {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string]$InstallRoot,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $component = Get-Component -Manifest $Manifest -Name $Name
    Join-Path $InstallRoot $component.install_relative_path
}

function Copy-BundleComponent {
    param(
        [Parameter(Mandatory = $true)]$Component,
        [Parameter(Mandatory = $true)][string]$PayloadRoot,
        [Parameter(Mandatory = $true)][string]$InstallRoot
    )

    $source = Join-Path $PayloadRoot $Component.source_relative_path
    if (-not (Test-Path -LiteralPath $source)) {
        throw "payload component is missing: $source"
    }

    $destination = Join-Path $InstallRoot $Component.install_relative_path
    $destinationParent = Split-Path -Path $destination -Parent
    if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
        Ensure-Directory -Path $destinationParent | Out-Null
    }

    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }

    $item = Get-Item -LiteralPath $source -ErrorAction Stop
    if ($item.PSIsContainer) {
        Copy-Item -LiteralPath $source -Destination $destination -Recurse -Force
    } else {
        Copy-Item -LiteralPath $source -Destination $destination -Force
    }
    $destination
}

function Copy-RelativeArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$DestinationRoot,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $source = Join-Path $SourceRoot $RelativePath
    if (-not (Test-Path -LiteralPath $source)) {
        throw "${Description} is missing: $source"
    }

    $destination = Join-Path $DestinationRoot $RelativePath
    $destinationParent = Split-Path -Path $destination -Parent
    if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
        Ensure-Directory -Path $destinationParent | Out-Null
    }

    Copy-Item -LiteralPath $source -Destination $destination -Force
    $destination
}

function Invoke-JsonCommand {
    param([Parameter(Mandatory = $true)][string[]]$Command)

    $commandPath = $Command[0]
    $arguments = @()
    if ($Command.Count -gt 1) {
        $arguments = $Command[1..($Command.Count - 1)]
    }
    $output = & $commandPath @arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $message = ($output | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = "exit code $LASTEXITCODE"
        }
        throw "command failed: $commandPath $($arguments -join ' ') :: $message"
    }

    $raw = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) {
        throw "command returned empty output: $commandPath"
    }
    $raw | ConvertFrom-Json -ErrorAction Stop
}

$payloadRoot = Resolve-ExistingPath -Path $PayloadRoot -Description "payload root"
$manifest = Get-Manifest -Path $ManifestPath
$resolvedManifestPath = Resolve-ExistingPath -Path $ManifestPath -Description "windows install manifest"

if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
    $InstallRoot = [string]$manifest.install_root
}
if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    $StateRoot = [string]$manifest.state_root
}
$payloadRoot = Normalize-Path -Path $payloadRoot
$InstallRoot = Normalize-Path -Path $InstallRoot
$StateRoot = Normalize-Path -Path $StateRoot

$copiedPaths = New-Object System.Collections.Generic.List[string]
$installReceiptPath = Join-Path $StateRoot "install-result.json"
$driverInstalled = $false
$payloadReleaseVerification = $null
$installedReleaseVerification = $null
$releaseVerifierScript = Join-Path $PSScriptRoot "verify-release.ps1"

foreach ($component in @($manifest.components)) {
    $source = Join-Path $payloadRoot $component.source_relative_path
    if (-not (Test-Path -LiteralPath $source)) {
        throw "payload component is missing before install: $source"
    }
}

try {
    Ensure-Directory -Path $InstallRoot | Out-Null
    Ensure-Directory -Path $StateRoot | Out-Null

    if ($manifest.bundle_channel -eq "release") {
        $payloadReleaseVerification = Invoke-JsonCommand -Command @(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $releaseVerifierScript,
            "-BundleRoot",
            $payloadRoot,
            "-ManifestPath",
            $resolvedManifestPath
        )
    }

    $installedManifestPath = Join-Path $InstallRoot "manifest.json"
    $installedInstallScriptPath = Join-Path $InstallRoot "install.ps1"
    $installedUninstallScriptPath = Join-Path $InstallRoot "uninstall.ps1"
    $installedReleaseVerifierScriptPath = Join-Path $InstallRoot "verify-release.ps1"

    if (-not $PayloadAlreadyInstalled) {
        foreach ($component in @($manifest.components)) {
            $copiedPaths.Add((Copy-BundleComponent -Component $component -PayloadRoot $payloadRoot -InstallRoot $InstallRoot)) | Out-Null
        }

        foreach ($dependency in @($manifest.release_dependencies)) {
            if ([string]::IsNullOrWhiteSpace([string]$dependency.install_relative_path)) {
                continue
            }
            $payloadDependencyPath = Join-Path $payloadRoot $dependency.install_relative_path
            if (Test-Path -LiteralPath $payloadDependencyPath) {
                $copiedPaths.Add((Copy-RelativeArtifact `
                        -SourceRoot $payloadRoot `
                        -RelativePath ([string]$dependency.install_relative_path) `
                        -DestinationRoot $InstallRoot `
                        -Description "release dependency artifact")) | Out-Null
            } elseif ([bool]$dependency.required) {
                throw "required release dependency artifact is missing from payload: $payloadDependencyPath"
            }
        }

        Copy-Item -LiteralPath $resolvedManifestPath -Destination $installedManifestPath -Force
        $copiedPaths.Add($installedManifestPath) | Out-Null
        Copy-Item -LiteralPath $MyInvocation.MyCommand.Path -Destination $installedInstallScriptPath -Force
        $copiedPaths.Add($installedInstallScriptPath) | Out-Null
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot "uninstall.ps1") -Destination $installedUninstallScriptPath -Force
        $copiedPaths.Add($installedUninstallScriptPath) | Out-Null
        Copy-Item -LiteralPath $releaseVerifierScript -Destination $installedReleaseVerifierScriptPath -Force
        $copiedPaths.Add($installedReleaseVerifierScriptPath) | Out-Null
    } else {
        foreach ($requiredPath in @(
                $installedManifestPath,
                $installedInstallScriptPath,
                $installedUninstallScriptPath,
                $installedReleaseVerifierScriptPath
            )) {
            if (-not (Test-Path -LiteralPath $requiredPath)) {
                throw "msi-staged install is missing required installed artifact: $requiredPath"
            }
        }
    }

    $agentPath = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "agentd"
    $watchdogPath = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "watchdog"
    $driverRoot = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "driver_tree"
    $driverInstallScriptPath = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "driver_install_script"
    $driverUninstallScriptPath = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "driver_uninstall_script"

    if ($manifest.bundle_channel -eq "release") {
        $installedReleaseVerification = Invoke-JsonCommand -Command @(
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            $installedReleaseVerifierScriptPath,
            "-BundleRoot",
            $InstallRoot,
            "-ManifestPath",
            $installedManifestPath
        )
    }

    $configResult = Invoke-JsonCommand -Command @(
        $agentPath,
        "--write-default-config",
        "--state-root",
        $StateRoot
    )

    $driverResult = Invoke-JsonCommand -Command @(
        "powershell",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $driverInstallScriptPath,
        "-DriverRoot",
        $driverRoot,
        "-ServiceName",
        [string]$manifest.driver_service_name
    )
    $driverInstalled = $true

    $bootstrapReport = Invoke-JsonCommand -Command @(
        $agentPath,
        "--bootstrap-check",
        "--state-root",
        $StateRoot,
        "--install-root",
        $InstallRoot,
        "--manifest",
        $installedManifestPath
    )
    if (-not $bootstrapReport.approved) {
        throw "bootstrap check did not approve the bundle"
    }

    $watchdogReport = Invoke-JsonCommand -Command @(
        $watchdogPath,
        "--once",
        "--state-root",
        $StateRoot
    )
    if (-not $watchdogReport.bootstrap_passed) {
        throw "watchdog reported bootstrap_passed=false"
    }
    if ($watchdogReport.alerts.Count -gt 0) {
        throw "watchdog reported stale alerts"
    }

    $receipt = [ordered]@{
        installed_at = (Get-Date).ToString("o")
        install_root = $InstallRoot
        state_root = $StateRoot
        install_mode = if ($PayloadAlreadyInstalled) { "msi" } else { "payload" }
        manifest_path = $installedManifestPath
        install_result_path = $installReceiptPath
        copied_paths = @($copiedPaths)
        payload_release_verification = $payloadReleaseVerification
        installed_release_verification = $installedReleaseVerification
        config_result = $configResult
        driver_result = $driverResult
        bootstrap_report_path = (Join-Path $StateRoot "bootstrap-check.json")
        bootstrap_report = $bootstrapReport
        watchdog_snapshot_path = (Join-Path $StateRoot "watchdog-state.json")
        watchdog_report = $watchdogReport
        rollback_plan = @{
            uninstall_script = $installedUninstallScriptPath
            driver_uninstall_script = $driverUninstallScriptPath
            preserve_state_root = $true
        }
    }
    $receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $installReceiptPath -Encoding UTF8
    $receipt | ConvertTo-Json -Depth 8
}
catch {
    $failure = $_
    if (Test-Path -LiteralPath $StateRoot) {
        $failureReceipt = [ordered]@{
            installed_at = (Get-Date).ToString("o")
            install_root = $InstallRoot
            state_root = $StateRoot
            manifest_path = $resolvedManifestPath
            bundle_channel = $manifest.bundle_channel
            copied_paths = @($copiedPaths)
            driver_installed = $driverInstalled
            error = $failure.Exception.Message
        }
        Ensure-Directory -Path $StateRoot | Out-Null
        $failureReceipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $installReceiptPath -Encoding UTF8
    }

    $rollbackManifestPath = if (Test-Path -LiteralPath (Join-Path $InstallRoot "manifest.json")) {
        Join-Path $InstallRoot "manifest.json"
    } else {
        $resolvedManifestPath
    }
    $uninstallScriptPath = Join-Path $PSScriptRoot "uninstall.ps1"
    if (Test-Path -LiteralPath $uninstallScriptPath) {
        & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $uninstallScriptPath `
            -InstallRoot $InstallRoot `
            -StateRoot $StateRoot `
            -ManifestPath $rollbackManifestPath | Out-Null
    }
    throw $failure
}
