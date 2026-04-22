param(
    [string]$DriverRoot = (Join-Path $PSScriptRoot "..\windows\driver"),
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [ValidateSet("x64")]
    [string]$Platform = "x64",
    [string]$ServiceName = "AegisSensorKmod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisInstall.DriverBridge" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace AegisInstall {
    public static class DriverBridge {
        public static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            IntPtr device,
            uint ioControlCode,
            byte[] inBuffer,
            uint inBufferSize,
            byte[] outBuffer,
            uint outBufferSize,
            out uint bytesReturned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@ | Out-Null
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

function Get-ServiceState {
    param([string]$Name)
    try {
        return [string](Get-Service -Name $Name -ErrorAction Stop).Status
    } catch {
        return $null
    }
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

function Invoke-DriverQuery {
    [uint32]$GENERIC_READ_WRITE = 3221225472
    [uint32]$FILE_SHARE_READ_WRITE = 3
    [uint32]$OPEN_EXISTING = 3
    $devicePath = "\\.\AegisSensor"
    $handle = [AegisInstall.DriverBridge]::CreateFile(
        $devicePath,
        $GENERIC_READ_WRITE,
        $FILE_SHARE_READ_WRITE,
        [IntPtr]::Zero,
        $OPEN_EXISTING,
        [uint32]0,
        [IntPtr]::Zero
    )
    if ($handle -eq [AegisInstall.DriverBridge]::InvalidHandleValue) {
        throw "CreateFile($devicePath) failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    try {
        $buffer = New-Object byte[] 512
        $bytesReturned = [uint32]0
        $ok = [AegisInstall.DriverBridge]::DeviceIoControl(
            $handle,
            [uint32]0x00222000,
            $null,
            0,
            $buffer,
            [uint32]$buffer.Length,
            [ref]$bytesReturned,
            [IntPtr]::Zero
        )
        if (-not $ok) {
            throw "DeviceIoControl(0x00222000) failed: Win32=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        if ($bytesReturned -lt 1) {
            throw "driver query returned empty payload"
        }

        $rawPayload = [System.Text.Encoding]::ASCII.GetString($buffer, 0, [int]$bytesReturned).Trim([char]0)
        if ([string]::IsNullOrWhiteSpace($rawPayload)) {
            throw "driver query returned blank payload"
        }
        $rawPayload | ConvertFrom-Json -ErrorAction Stop
    } finally {
        [void][AegisInstall.DriverBridge]::CloseHandle($handle)
    }
}

$driverRoot = Resolve-ExistingPath -Path $DriverRoot -Description "driver root"
$sysPath = Resolve-ExistingPath -Path (Join-Path $driverRoot "build\$Configuration\$Platform\AegisSensorKmod.sys") -Description "driver sys"
$certificatePath = Resolve-ExistingPath -Path (Join-Path $driverRoot "build\$Configuration\$Platform\AegisSensorKmod.cer") -Description "driver certificate"
$serviceBinary = "$env:SystemRoot\System32\drivers\AegisSensorKmod.sys"
$certificateThumbprint = Ensure-CertificateInstalled -CertificatePath $certificatePath

$existingState = Get-ServiceState -Name $ServiceName
if ($null -ne $existingState) {
    if ($existingState -eq "Running") {
        & sc.exe stop $ServiceName | Out-Null
        Start-Sleep -Seconds 1
    }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

Copy-Item -LiteralPath $sysPath -Destination $serviceBinary -Force

& sc.exe create $ServiceName type= kernel start= demand error= normal binPath= $serviceBinary | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe create failed with exit code $LASTEXITCODE"
}

& sc.exe start $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "sc.exe start failed with exit code $LASTEXITCODE"
}

Start-Sleep -Seconds 1
$serviceState = Get-ServiceState -Name $ServiceName
if ($serviceState -ne "Running") {
    throw "kernel driver service is not running after start: $serviceState"
}

$query = Invoke-DriverQuery

[ordered]@{
    service_name = $ServiceName
    service_state = $serviceState
    service_binary = $serviceBinary
    certificate_path = $certificatePath
    certificate_thumbprint = $certificateThumbprint
    driver_query = $query
} | ConvertTo-Json -Depth 5 -Compress
