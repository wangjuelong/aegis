param(
    [string]$InstallRoot = "C:\Program Files\Aegis",
    [string]$StateRoot = "C:\ProgramData\Aegis\state",
    [string]$ManifestPath = (Join-Path $InstallRoot "manifest.json"),
    [switch]$RemoveStateRoot
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

function Get-Manifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-ExistingPath -Path $Path -Description "windows install manifest"
    Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -ErrorAction Stop
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

$manifest = Get-Manifest -Path $ManifestPath
$removedPaths = New-Object System.Collections.Generic.List[string]
$driverUninstallScriptPath = Get-InstalledComponentPath -Manifest $manifest -InstallRoot $InstallRoot -Name "driver_uninstall_script"

if (Test-Path -LiteralPath $driverUninstallScriptPath) {
    & powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $driverUninstallScriptPath `
        -ServiceName ([string]$manifest.driver_service_name) | Out-Null
}

$components = @($manifest.components | Sort-Object {
    ([string]$_.install_relative_path).Length
} -Descending)
foreach ($component in $components) {
    $installedPath = Join-Path $InstallRoot $component.install_relative_path
    if (Test-Path -LiteralPath $installedPath) {
        Remove-Item -LiteralPath $installedPath -Recurse -Force
        $removedPaths.Add($installedPath) | Out-Null
    }
}

$dependencies = @($manifest.release_dependencies | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_.install_relative_path)
} | Sort-Object {
    ([string]$_.install_relative_path).Length
} -Descending)
foreach ($dependency in $dependencies) {
    $installedDependencyPath = Join-Path $InstallRoot $dependency.install_relative_path
    if (Test-Path -LiteralPath $installedDependencyPath) {
        Remove-Item -LiteralPath $installedDependencyPath -Force
        $removedPaths.Add($installedDependencyPath) | Out-Null
    }
}

$installedManifestPath = Join-Path $InstallRoot "manifest.json"
if (Test-Path -LiteralPath $installedManifestPath) {
    Remove-Item -LiteralPath $installedManifestPath -Force
    $removedPaths.Add($installedManifestPath) | Out-Null
}

foreach ($scriptName in @("install.ps1", "uninstall.ps1", "verify-release.ps1")) {
    $installedScriptPath = Join-Path $InstallRoot $scriptName
    if (Test-Path -LiteralPath $installedScriptPath) {
        Remove-Item -LiteralPath $installedScriptPath -Force
        $removedPaths.Add($installedScriptPath) | Out-Null
    }
}

foreach ($candidate in @(
    (Join-Path $InstallRoot "bin"),
    (Join-Path $InstallRoot "scripts"),
    (Join-Path $InstallRoot "driver"),
    (Join-Path $InstallRoot "metadata"),
    $InstallRoot
)) {
    if ((Test-Path -LiteralPath $candidate) -and
        (@(Get-ChildItem -LiteralPath $candidate -Force -ErrorAction SilentlyContinue)).Count -eq 0) {
        Remove-Item -LiteralPath $candidate -Force
    }
}

if ($RemoveStateRoot -and (Test-Path -LiteralPath $StateRoot)) {
    Remove-Item -LiteralPath $StateRoot -Recurse -Force
}

[ordered]@{
    removed_at = (Get-Date).ToString("o")
    install_root = $InstallRoot
    state_root = $StateRoot
    remove_state_root = [bool]$RemoveStateRoot
    removed_paths = @($removedPaths)
} | ConvertTo-Json -Depth 5
