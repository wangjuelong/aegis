param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "..\windows\minifilter"),
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$ServiceName = "AegisFileMonitor"
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

function Ensure-CertificateInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath
    )

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
    $thumbprint = $certificate.Thumbprint
    foreach ($storePath in @("Cert:\LocalMachine\Root", "Cert:\LocalMachine\TrustedPublisher")) {
        $existing = @(Get-ChildItem -Path $storePath -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $thumbprint })
        if ($existing.Count -eq 0) {
            Import-Certificate -FilePath $CertificatePath -CertStoreLocation $storePath -ErrorAction Stop | Out-Null
        }
    }

    $thumbprint
}

function Get-LoadedFilter {
    param([string]$Name)

    $line = fltmc filters | Select-String -Pattern ("^\s*" + [regex]::Escape($Name) + "\s+") |
        Select-Object -First 1
    if ($null -eq $line) {
        return $null
    }
    $line.Line.Trim()
}

$driverRoot = Resolve-ExistingPath -Path $DriverRoot -Description "minifilter root"
$certificatePath = Resolve-ExistingPath -Path (Join-Path $driverRoot "build\$Configuration\$Platform\$ServiceName.cer") -Description "minifilter certificate"
$packageRoot = Resolve-ExistingPath -Path (Join-Path $driverRoot "build\$Configuration\$Platform\$ServiceName") -Description "minifilter package directory"
$infPath = Resolve-ExistingPath -Path (Join-Path $packageRoot "$ServiceName.inf") -Description "minifilter INF"
$sysPath = Resolve-ExistingPath -Path (Join-Path $packageRoot "$ServiceName.sys") -Description "minifilter SYS"
$catPath = Resolve-ExistingPath -Path (Join-Path $packageRoot "$ServiceName.cat") -Description "minifilter CAT"
$certificateThumbprint = Ensure-CertificateInstalled -CertificatePath $certificatePath

pnputil /add-driver $infPath /install | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "pnputil /add-driver failed with exit code $LASTEXITCODE"
}

fltmc load $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "fltmc load failed with exit code $LASTEXITCODE"
}

Start-Sleep -Seconds 1
$filterState = Get-LoadedFilter -Name $ServiceName
if ($null -eq $filterState) {
    throw "minifilter is not loaded after installation"
}

[ordered]@{
    service_name = $ServiceName
    package_root = $packageRoot
    certificate_path = $certificatePath
    certificate_thumbprint = $certificateThumbprint
    inf_path = $infPath
    sys_path = $sysPath
    cat_path = $catPath
    filter_state = $filterState
} | ConvertTo-Json -Compress
