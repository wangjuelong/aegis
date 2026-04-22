param(
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [ValidateSet("development", "release")]
    [string]$BundleChannel = "development",
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$PayloadRoot = "C:\ProgramData\Aegis\package-build\windows-payload",
    [string]$OutputRoot = "C:\ProgramData\Aegis\package-build\windows-output",
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

    $stdoutPath = Join-Path $env:TEMP "aegis-package-$([guid]::NewGuid().ToString('N')).stdout.log"
    $stderrPath = Join-Path $env:TEMP "aegis-package-$([guid]::NewGuid().ToString('N')).stderr.log"
    if ($WorkingDirectory) {
        Push-Location $WorkingDirectory
    }
    try {
        $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments -Wait -PassThru `
            -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
        $stdout = if (Test-Path -LiteralPath $stdoutPath) {
            Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue
        } else {
            ""
        }
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        } else {
            ""
        }
        if ($process.ExitCode -ne 0) {
            $message = (@($stderr, $stdout) | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } | Out-String).Trim()
            if ([string]::IsNullOrWhiteSpace($message)) {
                $message = "command failed with exit code $($process.ExitCode): $FilePath $($Arguments -join ' ')"
            }
            throw $message
        }
        $combinedOutput = (@($stdout, $stderr) | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } | Out-String).Trim()
        if (-not [string]::IsNullOrWhiteSpace($combinedOutput)) {
            [Console]::Error.WriteLine($combinedOutput)
        }
    } finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Get-RustcVersion {
    param([string]$RustcPath = "rustc")

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
$buildMsiScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows\build-msi.ps1") -Description "windows msi build script"
$driverBuildScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows\build-driver.ps1") -Description "windows driver build script"
$driverInstallScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows\install-driver.ps1") -Description "windows driver install script"
$driverUninstallScriptPath = Resolve-ExistingPath -Path (Join-Path $resolvedRepoRoot "scripts\windows\uninstall-driver.ps1") -Description "windows driver uninstall script"
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
} else {
    $candidateOfflineRoot = "C:\ProgramData\Aegis\toolchains\$RustToolchain"
    if (Test-Path -LiteralPath $candidateOfflineRoot) {
        $resolvedToolchainRoot = Resolve-ExistingPath -Path $candidateOfflineRoot -Description "detected offline rust toolchain root"
        $cargoExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\cargo.exe") -Description "detected offline cargo executable"
        $rustcExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\rustc.exe") -Description "detected offline rustc executable"
        $rustdocExecutable = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin\rustdoc.exe") -Description "detected offline rustdoc executable"
        $toolchainBinPath = Resolve-ExistingPath -Path (Join-Path $resolvedToolchainRoot "bin") -Description "detected offline toolchain bin directory"
        $ToolchainRoot = $resolvedToolchainRoot
    }
}

if ($BundleChannel -eq "release") {
    if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
        throw "release package build requires SigningCertificateThumbprint"
    }
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) {
        throw "release package build requires TimestampServer"
    }
    if ([string]::IsNullOrWhiteSpace($ElamApprovalPath)) {
        throw "release package build requires ElamApprovalPath"
    }
    if ([string]::IsNullOrWhiteSpace($WatchdogPplApprovalPath)) {
        throw "release package build requires WatchdogPplApprovalPath"
    }
}

$cargoBuildArguments = Resolve-CargoBuildArguments -RequiredToolchain $RustToolchain -UseVendoredSources $useVendoredSources -RustcPath $rustcExecutable
$defaultCargoHome = Join-Path $env:USERPROFILE ".cargo"
$defaultCargoConfigPath = Join-Path $defaultCargoHome "config.toml"
$backupCargoConfigPath = Join-Path $defaultCargoHome "config.toml.aegis-build-package.bak"
$cargoTargetRoot = Join-Path $resolvedRepoRoot "target\windows-package-build\$RustToolchain"
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
if (Test-Path -LiteralPath $OutputRoot) {
    Remove-Item -LiteralPath $OutputRoot -Recurse -Force
}
Ensure-Directory -Path $PayloadRoot | Out-Null
Ensure-Directory -Path $OutputRoot | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "bin") | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "scripts") | Out-Null
Ensure-Directory -Path (Join-Path $PayloadRoot "metadata") | Out-Null

Copy-Item -LiteralPath $manifestSource -Destination (Join-Path $PayloadRoot "manifest.json") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-agentd.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-agentd.exe") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-watchdog.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-watchdog.exe") -Force
Copy-Item -LiteralPath (Join-Path $cargoTargetRoot "release\aegis-updater.exe") -Destination (Join-Path $PayloadRoot "bin\aegis-updater.exe") -Force
Copy-Item -LiteralPath $driverInstallScriptPath -Destination (Join-Path $PayloadRoot "scripts\windows-install-driver.ps1") -Force
Copy-Item -LiteralPath $driverUninstallScriptPath -Destination (Join-Path $PayloadRoot "scripts\windows-uninstall-driver.ps1") -Force
Copy-Item -LiteralPath $installScriptPath -Destination (Join-Path $PayloadRoot "install.ps1") -Force
Copy-Item -LiteralPath $uninstallScriptPath -Destination (Join-Path $PayloadRoot "uninstall.ps1") -Force
Copy-Item -LiteralPath $releaseVerifierScriptPath -Destination (Join-Path $PayloadRoot "verify-release.ps1") -Force
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
        throw "windows release verification failed before msi build"
    }
    $payloadReleaseVerification = $payloadReleaseVerification | ConvertFrom-Json -ErrorAction Stop
}

$buildMsiArguments = @(
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-File",
    $buildMsiScriptPath,
    "-PayloadRoot",
    $PayloadRoot,
    "-OutputRoot",
    $OutputRoot,
    "-BundleChannel",
    $BundleChannel
)
if ($BundleChannel -eq "release") {
    $buildMsiArguments += @(
        "-SigningCertificateThumbprint",
        $SigningCertificateThumbprint,
        "-SigningCertificateStorePath",
        $SigningCertificateStorePath,
        "-TimestampServer",
        $TimestampServer
    )
}
$msiBuildJson = & powershell @buildMsiArguments
if ($LASTEXITCODE -ne 0) {
    throw "windows msi build failed"
}
$msiBuildResult = $msiBuildJson | ConvertFrom-Json -ErrorAction Stop

[ordered]@{
    bundle_channel = $BundleChannel
    built_at = (Get-Date).ToString("o")
    repo_root = $resolvedRepoRoot
    payload_root = $PayloadRoot
    output_root = $OutputRoot
    manifest_path = (Join-Path $PayloadRoot "manifest.json")
    release_sign_result = $releaseSignResult
    payload_release_verification = $payloadReleaseVerification
    msi_build_result = $msiBuildResult
    package_path = [string]$msiBuildResult.msi_path
} | ConvertTo-Json -Depth 8
