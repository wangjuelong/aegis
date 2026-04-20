param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "..\windows\driver"),
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [switch]$GenerateCatalog
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

function Get-LatestWindowsSdkVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )

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
        $missingPaths = @($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_) })
        if ($missingPaths.Count -eq 0) {
            return $version
        }
    }

    throw "no usable Windows SDK was found under $kitsRoot for platform $Platform"
}

function Get-LatestWdkVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )

    $kitsRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
    $includeRoot = Join-Path $kitsRoot "Include"
    $versions = @(Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction Stop |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object { [version]$_.Name } -Descending)

    foreach ($candidate in $versions) {
        $version = $candidate.Name
        $requiredPaths = @(
            (Join-Path $kitsRoot "Include\$version\km\ntddk.h"),
            (Join-Path $kitsRoot "Lib\$version\km\$Platform\ntoskrnl.lib")
        )
        $missingPaths = @($requiredPaths | Where-Object { -not (Test-Path -LiteralPath $_) })
        if ($missingPaths.Count -eq 0) {
            return $version
        }
    }

    throw "no usable WDK was found under $kitsRoot for platform $Platform"
}

function Get-MsBuildPath {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "vswhere.exe is unavailable: $vswhere"
    }

    $msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($msbuild)) {
        throw "MSBuild.exe was not found by vswhere"
    }
    $msbuild
}

function Get-VisualStudioInstallationPath {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path -LiteralPath $vswhere)) {
        throw "vswhere.exe is unavailable: $vswhere"
    }

    $installationPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath |
        Select-Object -First 1
    if ([string]::IsNullOrWhiteSpace($installationPath)) {
        throw "Visual Studio installationPath was not found by vswhere"
    }
    $installationPath
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

function Get-LatestMsvcToolVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VisualStudioInstallationPath
    )

    $msvcRoot = Join-Path $VisualStudioInstallationPath "VC\Tools\MSVC"
    $toolVersions = @(Get-ChildItem -LiteralPath $msvcRoot -Directory -ErrorAction Stop |
        Sort-Object { [version]$_.Name } -Descending)
    if ($toolVersions.Count -lt 1) {
        throw "no MSVC toolset was found under $msvcRoot"
    }

    $toolVersions[0].Name
}

function Get-MsvcToolBinPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VisualStudioInstallationPath,
        [Parameter(Mandatory = $true)]
        [string]$MsvcToolVersion,
        [Parameter(Mandatory = $true)]
        [string]$Platform
    )

    $candidateBins = @(
        (Join-Path $VisualStudioInstallationPath "VC\Tools\MSVC\$MsvcToolVersion\bin\HostX64\$Platform"),
        (Join-Path $VisualStudioInstallationPath "VC\Tools\MSVC\$MsvcToolVersion\bin\HostX86\$Platform")
    )

    foreach ($candidate in $candidateBins) {
        if ((Test-Path -LiteralPath (Join-Path $candidate "link.exe")) -and
            (Test-Path -LiteralPath (Join-Path $candidate "cl.exe"))) {
            return $candidate
        }
    }

    throw "no usable MSVC tool bin path was found for platform $Platform under $VisualStudioInstallationPath"
}

$driverRoot = Resolve-ExistingPath -Path $DriverRoot -Description "driver root"
$projectPath = Resolve-ExistingPath -Path (Join-Path $driverRoot "AegisSensorKmod.vcxproj") -Description "driver project"
$infPath = Resolve-ExistingPath -Path (Join-Path $driverRoot "AegisSensorKmod.inf") -Description "driver INF"

$sdkVersion = Get-LatestWindowsSdkVersion -Platform $Platform
$wdkVersion = Get-LatestWdkVersion -Platform $Platform
$wdkTasksVisualStudioVersion = Get-WdkTasksVisualStudioVersion -WdkVersion $wdkVersion
$visualStudioInstallationPath = Get-VisualStudioInstallationPath
$msvcToolVersion = Get-LatestMsvcToolVersion -VisualStudioInstallationPath $visualStudioInstallationPath
$msvcToolBinPath = Get-MsvcToolBinPath `
    -VisualStudioInstallationPath $visualStudioInstallationPath `
    -MsvcToolVersion $msvcToolVersion `
    -Platform $Platform
$msbuildPath = Get-MsBuildPath
$wdkLibRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\Lib\$wdkVersion\km\$Platform"
$wdkBinRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\$wdkVersion\$Platform"
$wdkBinX64Root = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\$wdkVersion\x64"
$wdkBinX86Root = "${env:ProgramFiles(x86)}\Windows Kits\10\bin\$wdkVersion\x86"
$ntoskrnlLib = Resolve-ExistingPath -Path (Join-Path $wdkLibRoot "ntoskrnl.lib") -Description "ntoskrnl.lib"
$stampInf = Resolve-ExistingPath -Path (Join-Path $wdkBinRoot "stampinf.exe") -Description "stampinf.exe"
$driverSignTool = Resolve-ExistingPath -Path (Join-Path $wdkBinX86Root "signtool.exe") -Description "signtool.exe"
$inf2CatTool = Resolve-ExistingPath -Path (Join-Path $wdkBinX86Root "inf2cat.exe") -Description "inf2cat.exe"
$drvCatTool = Resolve-ExistingPath -Path (Join-Path $wdkBinX64Root "drvcat.exe") -Description "drvcat.exe"

$env:Path = "$msvcToolBinPath;$wdkBinX64Root;$wdkBinX86Root;$env:Path"

$msbuildArgs = @(
    $projectPath,
    "/t:Build",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/p:WindowsTargetPlatformVersion=$sdkVersion",
    "/p:VisualStudioVersion=$wdkTasksVisualStudioVersion",
    "/p:SkipPackageVerification=true",
    "/m",
    "/nologo"
)

& $msbuildPath @msbuildArgs
if ($LASTEXITCODE -ne 0) {
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

$sysPath = Join-Path $driverRoot "build\$Configuration\$Platform\AegisSensorKmod.sys"
$sysPath = Resolve-ExistingPath -Path $sysPath -Description "built driver binary"

$output = [ordered]@{
    driver_root = $driverRoot
    project_path = $projectPath
    configuration = $Configuration
    platform = $Platform
    sdk_version = $sdkVersion
    wdk_version = $wdkVersion
    wdk_tasks_visual_studio_version = $wdkTasksVisualStudioVersion
    visual_studio_installation_path = $visualStudioInstallationPath
    msvc_tool_version = $msvcToolVersion
    msvc_tool_bin_path = $msvcToolBinPath
    skip_package_verification = $true
    msbuild_path = $msbuildPath
    ntoskrnl_lib = $ntoskrnlLib
    stampinf_path = $stampInf
    signtool_path = $driverSignTool
    inf2cat_path = $inf2CatTool
    drvcat_path = $drvCatTool
    inf_path = $infPath
    sys_path = $sysPath
}

if ($GenerateCatalog) {
    & $inf2CatTool /driver:$driverRoot /os:10_X64
    if ($LASTEXITCODE -ne 0) {
        throw "Inf2Cat failed with exit code $LASTEXITCODE"
    }
    $catPath = Resolve-ExistingPath -Path (Join-Path $driverRoot "AegisSensorKmod.cat") -Description "generated CAT file"
    $output["cat_path"] = $catPath
}

$output | ConvertTo-Json -Compress
