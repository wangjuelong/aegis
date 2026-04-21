param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "..\windows\minifilter"),
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64"
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

function Resolve-ProjectPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $defaultProject = Join-Path $Root "AegisFileMonitor.vcxproj"
    if (Test-Path -LiteralPath $defaultProject) {
        return (Resolve-ExistingPath -Path $defaultProject -Description "minifilter project")
    }

    $projects = @(Get-ChildItem -LiteralPath $Root -Filter "*.vcxproj" -File -ErrorAction Stop)
    if ($projects.Count -ne 1) {
        throw "unable to resolve unique minifilter project under $Root"
    }
    $projects[0].FullName
}

function Resolve-InfPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root
    )

    $defaultInf = Join-Path $Root "AegisFileMonitor.inf"
    if (Test-Path -LiteralPath $defaultInf) {
        return (Resolve-ExistingPath -Path $defaultInf -Description "minifilter INF")
    }

    $infFiles = @(Get-ChildItem -LiteralPath $Root -Filter "*.inf" -File -ErrorAction Stop)
    if ($infFiles.Count -ne 1) {
        throw "unable to resolve unique minifilter INF under $Root"
    }
    $infFiles[0].FullName
}

function Get-VsWherePath {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    Resolve-ExistingPath -Path $vswhere -Description "vswhere.exe"
}

function Get-VisualStudioInstallationPath {
    $vswhere = Get-VsWherePath
    $installationPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($installationPath)) {
        throw "Visual Studio installationPath was not found by vswhere"
    }
    $installationPath
}

function Get-MsBuildPath {
    $vswhere = Get-VsWherePath
    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($msbuild)) {
        throw "MSBuild.exe was not found by vswhere"
    }
    $msbuild
}

function Get-LatestWindowsSdkVersion {
    param([Parameter(Mandatory = $true)][string]$Platform)

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    $includeRoot = Join-Path $kitsRoot "Include"
    $versions = @(Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending)

    foreach ($candidate in $versions) {
        $version = $candidate.Name
        $requiredPaths = @(
            (Join-Path $kitsRoot "Include\$version\um\Windows.h"),
            (Join-Path $kitsRoot "Lib\$version\um\$Platform\kernel32.lib")
        )
        if (@($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -eq 0) {
            return $version
        }
    }

    throw "no usable Windows SDK was found under $kitsRoot for platform $Platform"
}

function Get-LatestWdkVersion {
    param([Parameter(Mandatory = $true)][string]$Platform)

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    $includeRoot = Join-Path $kitsRoot "Include"
    $versions = @(Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending)

    foreach ($candidate in $versions) {
        $version = $candidate.Name
        $requiredPaths = @(
            (Join-Path $kitsRoot "Include\$version\km\fltkernel.h"),
            (Join-Path $kitsRoot "Lib\$version\km\$Platform\FltMgr.lib")
        )
        if (@($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_) }).Count -eq 0) {
            return $version
        }
    }

    throw "no usable WDK was found under $kitsRoot for platform $Platform"
}

function Get-WdkTasksVisualStudioVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$WdkVersion
    )

    $wdkBuildBin = "${env:ProgramFiles(x86)}\Windows Kits\10\build\$WdkVersion\bin"
    $taskDlls = @(Get-ChildItem -LiteralPath $wdkBuildBin -Filter "*.dll" -ErrorAction Stop |
        Where-Object { $_.BaseName -match '^Microsoft\.DriverKit\.Build\.Tasks\.\d+\.\d+$' } |
        Sort-Object {
            [version](($_.BaseName -replace '^Microsoft\.DriverKit\.Build\.Tasks\.', ''))
        } -Descending)
    if ($taskDlls.Count -lt 1) {
        throw "Microsoft.DriverKit.Build.Tasks.*.dll is unavailable under $wdkBuildBin"
    }

    ($taskDlls[0].BaseName -replace '^Microsoft\.DriverKit\.Build\.Tasks\.', '')
}

$driverRoot = Resolve-ExistingPath -Path $DriverRoot -Description "minifilter root"
$projectPath = Resolve-ProjectPath -Root $driverRoot
$infPath = Resolve-InfPath -Root $driverRoot
$projectName = [System.IO.Path]::GetFileNameWithoutExtension($projectPath)
$visualStudioInstallationPath = Get-VisualStudioInstallationPath
$msbuildPath = Get-MsBuildPath
$sdkVersion = Get-LatestWindowsSdkVersion -Platform $Platform
$wdkVersion = Get-LatestWdkVersion -Platform $Platform
$wdkTasksVisualStudioVersion = Get-WdkTasksVisualStudioVersion -WdkVersion $wdkVersion
$vcvarsPath = Resolve-ExistingPath -Path (Join-Path $visualStudioInstallationPath "VC\Auxiliary\Build\vcvars64.bat") -Description "vcvars64.bat"

$buildCommand = @(
    "call `"$vcvarsPath`" >nul",
    "`"$msbuildPath`" `"$projectPath`" /t:Build /p:Configuration=$Configuration /p:Platform=$Platform /p:WindowsTargetPlatformVersion=$sdkVersion /p:VisualStudioVersion=$wdkTasksVisualStudioVersion /p:SkipPackageVerification=true /m /nologo"
) -join " && "

cmd.exe /d /s /c $buildCommand
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

$buildOutputRoot = Join-Path $driverRoot "build\$Configuration\$Platform"
$sysPath = Resolve-ExistingPath -Path (Join-Path $buildOutputRoot "$projectName.sys") -Description "built minifilter binary"
$packageDir = Resolve-ExistingPath -Path (Join-Path $buildOutputRoot $projectName) -Description "minifilter package directory"
$packageInfPath = Resolve-ExistingPath -Path (Join-Path $packageDir "$projectName.inf") -Description "packaged minifilter INF"
$catPath = Resolve-ExistingPath -Path (Join-Path $packageDir "$projectName.cat") -Description "packaged minifilter CAT"
$cerPath = Resolve-ExistingPath -Path (Join-Path $buildOutputRoot "$projectName.cer") -Description "minifilter certificate"

[ordered]@{
    driver_root = $driverRoot
    project_path = $projectPath
    configuration = $Configuration
    platform = $Platform
    build_output_root = $buildOutputRoot
    package_dir = $packageDir
    sdk_version = $sdkVersion
    wdk_version = $wdkVersion
    wdk_tasks_visual_studio_version = $wdkTasksVisualStudioVersion
    visual_studio_installation_path = $visualStudioInstallationPath
    msbuild_path = $msbuildPath
    vcvars_path = $vcvarsPath
    inf_path = $infPath
    package_inf_path = $packageInfPath
    sys_path = $sysPath
    cat_path = $catPath
    certificate_path = $cerPath
} | ConvertTo-Json -Compress
