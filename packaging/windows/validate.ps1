param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [ValidateSet("development", "release")]
    [string]$BundleChannel = "development",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$PayloadRoot = "C:\ProgramData\Aegis\validation\windows-package-payload",
    [string]$InstallRoot = "C:\Program Files\Aegis",
    [string]$StateRoot = "C:\ProgramData\Aegis\state",
    [string]$RustToolchain = "1.91.0",
    [string]$ToolchainRoot,
    [string]$SigningCertificateThumbprint,
    [string]$SigningCertificateStorePath = "Cert:\CurrentUser\My",
    [string]$TimestampServer,
    [string]$ElamApprovalPath,
    [string]$WatchdogPplApprovalPath
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

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @(),
        [Parameter(Mandatory = $false)][string]$WorkingDirectory
    )

    if ($WorkingDirectory) {
        Push-Location $WorkingDirectory
    }
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
        }
    } finally {
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Get-RustcVersion {
    param(
        [Parameter(Mandatory = $false)]
        [string]$RustcPath = "rustc"
    )

    $versionOutput = & $RustcPath --version
    if ($LASTEXITCODE -ne 0) {
        throw "$RustcPath --version failed with exit code $LASTEXITCODE"
    }
    $match = [regex]::Match($versionOutput, 'rustc (\d+\.\d+\.\d+)')
    if (-not $match.Success) {
        throw "unable to parse rustc version: $versionOutput"
    }
    [version]$match.Groups[1].Value
}

function Resolve-CargoBuildArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequiredToolchain,
        [Parameter(Mandatory = $true)]
        [bool]$UseVendoredSources,
        [Parameter(Mandatory = $false)]
        [string]$RustcPath = "rustc"
    )

    $requiredVersion = [version]$RequiredToolchain
    $currentVersion = Get-RustcVersion -RustcPath $RustcPath
    $buildArguments = New-Object System.Collections.Generic.List[string]

    if ($currentVersion -lt $requiredVersion) {
        $rustupCommand = Get-Command rustup -ErrorAction SilentlyContinue
        if ($null -eq $rustupCommand) {
            throw "rustc $currentVersion is below required toolchain $requiredVersion and rustup is unavailable"
        }

        $installedToolchains = & $rustupCommand.Source toolchain list
        if ($LASTEXITCODE -ne 0) {
            throw "rustup toolchain list failed with exit code $LASTEXITCODE"
        }

        $hasRequiredToolchain = $false
        foreach ($toolchainLine in @($installedToolchains)) {
            if ($toolchainLine -match "^$([regex]::Escape($RequiredToolchain))([-\s]|$)") {
                $hasRequiredToolchain = $true
                break
            }
        }
        if (-not $hasRequiredToolchain) {
            Invoke-External -FilePath $rustupCommand.Source -Arguments @("toolchain", "install", $RequiredToolchain, "--profile", "minimal")
        }

        $buildArguments.Add("+$RequiredToolchain") | Out-Null
    }

    $buildArguments.Add("build") | Out-Null
    if ($UseVendoredSources) {
        $buildArguments.Add("--offline") | Out-Null
    }
    $buildArguments.Add("--release") | Out-Null
    $buildArguments.Add("-p") | Out-Null
    $buildArguments.Add("aegis-agentd") | Out-Null
    $buildArguments.Add("-p") | Out-Null
    $buildArguments.Add("aegis-watchdog") | Out-Null
    $buildArguments.Add("-p") | Out-Null
    $buildArguments.Add("aegis-updater") | Out-Null
    @($buildArguments)
}

$resolvedRepoRoot = Resolve-ExistingPath -Path $RepoRoot -Description "repo root"
$manifestTemplatePath = if ($BundleChannel -eq "release") {
    Join-Path $resolvedRepoRoot "packaging\windows\manifest.release.json"
} else {
    Join-Path $resolvedRepoRoot "packaging\windows\manifest.json"
}
$manifestSource = Resolve-ExistingPath -Path $manifestTemplatePath -Description "windows packaging manifest"
$installScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "packaging\windows\install.ps1") -Description "windows install script"
$uninstallScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "packaging\windows\uninstall.ps1") -Description "windows uninstall script"
$releaseVerifierScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "packaging\windows\verify-release.ps1") -Description "windows release verifier"
$driverBuildScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows-build-driver.ps1") -Description "windows driver build script"
$driverInstallScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows-install-driver.ps1") -Description "windows driver install script"
$driverUninstallScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows-uninstall-driver.ps1") -Description "windows driver uninstall script"
$releaseSignScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows-sign-driver.ps1") -Description "windows release signing script"
$driverSourceRoot = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "windows\driver") -Description "windows driver source"
$vendoredCargoConfigPath = Join-Path $resolvedRepoRoot ".cargo\config.toml"
$vendoredCargoRoot = Join-Path $resolvedRepoRoot "vendor"
$useVendoredSources = (Test-Path -LiteralPath $vendoredCargoConfigPath) -and (Test-Path -LiteralPath $vendoredCargoRoot)
$cargoExecutable = "cargo"
$rustcExecutable = "rustc"
$rustdocExecutable = $null
$toolchainBinPath = $null
if ($ToolchainRoot) {
    $resolvedToolchainRoot = Resolve-ExistingPath -Path $ToolchainRoot -Description "offline rust toolchain root"
    $cargoExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\cargo.exe") -Description "offline cargo executable"
    $rustcExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\rustc.exe") -Description "offline rustc executable"
    $rustdocExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\rustdoc.exe") -Description "offline rustdoc executable"
    $toolchainBinPath = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin") -Description "offline toolchain bin directory"
}

if ($BundleChannel -eq "release") {
    if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        throw "release bundle validation requires SigningCertificateThumbprint"
    }
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) {
        throw "release bundle validation requires TimestampServer"
    }
    if ([string]::IsNullOrWhiteSpace($ElamApprovalPath)) {
        throw "release bundle validation requires ElamApprovalPath"
    }
    if ([string]::IsNullOrWhiteSpace($WatchdogPplApprovalPath)) {
        throw "release bundle validation requires WatchdogPplApprovalPath"
    }
}
$cargoBuildArguments = Resolve-CargoBuildArguments -RequiredToolchain $RustToolchain -UseVendoredSources $useVendoredSources -RustcPath $rustcExecutable

$defaultCargoHome = Join-Path $env:USERPROFILE ".cargo"
$defaultCargoConfigPath = Join-Path $defaultCargoHome "config.toml"
$backupCargoConfigPath = Join-Path $defaultCargoHome "config.toml.aegis-validation.bak"
$cargoTargetRoot = Join-Path $resolvedRepoRoot "target\windows-package-validate\$RustToolchain"
$originalPath = $env:PATH
$originalRustcEnv = $env:RUSTC
$originalRustdocEnv = $env:RUSTDOC
$originalCargoTargetDirEnv = $env:CARGO_TARGET_DIR
if (Test-Path Env:CARGO_HOME) {
    Remove-Item Env:CARGO_HOME
}
if (Test-Path -LiteralPath $backupCargoConfigPath) {
    Remove-Item -LiteralPath $backupCargoConfigPath -Force
}
try {
    if (-not $useVendoredSources -and (Test-Path -LiteralPath $defaultCargoConfigPath)) {
        Move-Item -LiteralPath $defaultCargoConfigPath -Destination $backupCargoConfigPath -Force
    }
    Ensure-Directory -Path $cargoTargetRoot | Out-Null
    $env:CARGO_TARGET_DIR = $cargoTargetRoot
    if ($toolchainBinPath) {
        $env:PATH = "$toolchainBinPath;$originalPath"
        $env:RUSTC = $rustcExecutable
        $env:RUSTDOC = $rustdocExecutable
    }
    if (-not $useVendoredSources) {
        $env:CARGO_REGISTRIES_CRATES_IO_PROTOCOL = "git"
        $env:CARGO_NET_GIT_FETCH_WITH_CLI = "true"
        $env:CARGO_HTTP_MULTIPLEXING = "false"
    }
    Invoke-External -FilePath $cargoExecutable -Arguments $cargoBuildArguments -WorkingDirectory $resolvedRepoRoot
} finally {
    if (Test-Path Env:CARGO_REGISTRIES_CRATES_IO_PROTOCOL) {
        Remove-Item Env:CARGO_REGISTRIES_CRATES_IO_PROTOCOL
    }
    if (Test-Path Env:CARGO_NET_GIT_FETCH_WITH_CLI) {
        Remove-Item Env:CARGO_NET_GIT_FETCH_WITH_CLI
    }
    if (Test-Path Env:CARGO_HTTP_MULTIPLEXING) {
        Remove-Item Env:CARGO_HTTP_MULTIPLEXING
    }
    $env:PATH = $originalPath
    if ($null -ne $originalRustcEnv) {
        $env:RUSTC = $originalRustcEnv
    } elseif (Test-Path Env:RUSTC) {
        Remove-Item Env:RUSTC
    }
    if ($null -ne $originalRustdocEnv) {
        $env:RUSTDOC = $originalRustdocEnv
    } elseif (Test-Path Env:RUSTDOC) {
        Remove-Item Env:RUSTDOC
    }
    if ($null -ne $originalCargoTargetDirEnv) {
        $env:CARGO_TARGET_DIR = $originalCargoTargetDirEnv
    } elseif (Test-Path Env:CARGO_TARGET_DIR) {
        Remove-Item Env:CARGO_TARGET_DIR
    }
    if (Test-Path -LiteralPath $backupCargoConfigPath) {
        if (Test-Path -LiteralPath $defaultCargoConfigPath) {
            Remove-Item -LiteralPath $defaultCargoConfigPath -Force
        }
        Move-Item -LiteralPath $backupCargoConfigPath -Destination $defaultCargoConfigPath -Force
    }
}

if (Test-Path -LiteralPath $PayloadRoot) {
    Remove-Item -LiteralPath $PayloadRoot -Recurse -Force
}
Ensure-Directory -Path $PayloadRoot | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "bin") | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "scripts") | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "metadata") | Out-Null

Copy-Item -LiteralPath $manifestSource -Destination (Join-Path $PayloadRoot "manifest.json") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-agentd.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-agentd.exe") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-watchdog.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-watchdog.exe") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-updater.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-updater.exe") -Force
Copy-Item -LiteralPath $driverInstallScriptPath -Destination (Join-Path $PayloadRoot "scripts\windows-install-driver.ps1") -Force
Copy-Item -LiteralPath $driverUninstallScriptPath -Destination (Join-Path $PayloadRoot "scripts\windows-uninstall-driver.ps1") -Force
Copy-Item -LiteralPath $driverSourceRoot -Destination (Join-Path $PayloadRoot "driver") -Recurse -Force

Invoke-External -FilePath "powershell" -Arguments @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $driverBuildScriptPath,
    "-DriverRoot",
    (Join-Path $PayloadRoot "driver"),
    "-Configuration",
    $Configuration,
    "-Platform",
    $Platform
)

$releaseSignResult = $null
$payloadReleaseVerification = $null
if ($BundleChannel -eq "release") {
    $releaseSignResult = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $releaseSignScriptPath `
        -BundleRoot $PayloadRoot `
        -ManifestPath (Join-Path $PayloadRoot "manifest.json") `
        -CertificateThumbprint $SigningCertificateThumbprint `
        -CertificateStorePath $SigningCertificateStorePath `
        -TimestampServer $TimestampServer `
        -ElamApprovalPath $ElamApprovalPath `
        -WatchdogPplApprovalPath $WatchdogPplApprovalPath
    if ($LASTEXITCODE -ne 0) {
        throw "windows release signing failed"
    }
    $releaseSignResult = $releaseSignResult | ConvertFrom-Json -ErrorAction Stop

    $payloadReleaseVerification = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $releaseVerifierScriptPath `
        -BundleRoot $PayloadRoot `
        -ManifestPath (Join-Path $PayloadRoot "manifest.json") `
        -ExpectedCertificateThumbprint $SigningCertificateThumbprint
    if ($LASTEXITCODE -ne 0) {
        throw "windows release verification failed before install"
    }
    $payloadReleaseVerification = $payloadReleaseVerification | ConvertFrom-Json -ErrorAction Stop
}

$installJson = & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $installScriptPath `
    -PayloadRoot $PayloadRoot `
    -InstallRoot $InstallRoot `
    -StateRoot $StateRoot
if ($LASTEXITCODE -ne 0) {
    throw "windows install validation failed"
}
$installResult = $installJson | ConvertFrom-Json -ErrorAction Stop

$bootstrapReportPath = Join-Path $StateRoot "bootstrap-check.json"
$watchdogSnapshotPath = Join-Path $StateRoot "watchdog-state.json"
$installResultPath = Join-Path $StateRoot "install-result.json"
$bootstrapReport = Get-Content -LiteralPath $bootstrapReportPath -Raw | ConvertFrom-Json -ErrorAction Stop
$watchdogSnapshot = Get-Content -LiteralPath $watchdogSnapshotPath -Raw | ConvertFrom-Json -ErrorAction Stop

$requiredFailures = New-Object System.Collections.Generic.List[string]
if (-not $bootstrapReport.approved) {
    $requiredFailures.Add("bootstrap_report") | Out-Null
}
if (-not $watchdogSnapshot.bootstrap_passed) {
    $requiredFailures.Add("watchdog_bootstrap") | Out-Null
}
if ($watchdogSnapshot.alerts.Count -gt 0) {
    $requiredFailures.Add("watchdog_alerts") | Out-Null
}

& powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $uninstallScriptPath `
    -InstallRoot $InstallRoot `
    -StateRoot $StateRoot `
    -RemoveStateRoot | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "windows uninstall validation failed"
}

[ordered]@{
    bundle_channel = $BundleChannel
    validated_at = (Get-Date).ToString("o")
    repo_root = $resolvedRepoRoot
    payload_root = $PayloadRoot
    install_root = $InstallRoot
    state_root = $StateRoot
    install_result_path = $installResultPath
    bootstrap_report_path = $bootstrapReportPath
    watchdog_snapshot_path = $watchdogSnapshotPath
    release_sign_result = $releaseSignResult
    payload_release_verification = $payloadReleaseVerification
    install_result = $installResult
    bootstrap_report = $bootstrapReport
    watchdog_snapshot = $watchdogSnapshot
    required_failures = @($requiredFailures)
} | ConvertTo-Json -Depth 8
