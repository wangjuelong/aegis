param(
    [ValidateSet("status", "protect", "clear")]
    [string]$Mode = "status",
    [string]$ServiceName = "AegisSensorKmod",
    [string]$KeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisRegistryProtectionBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisRegistryProtectionBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverStatusResponse {
        public UInt32 ProtocolVersion;
        public UInt32 RegistryCallbackRegistered;
        public UInt32 JournalCapacity;
        public UInt32 JournalCount;
        public UInt32 OldestSequence;
        public UInt32 CurrentSequence;
        public UInt32 ObCallbackRegistered;
        public UInt32 ProtectedProcessCount;
        public UInt32 ProtectedRegistryPathCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct RegistryProtectRequest {
        public UInt32 ProtocolVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string KeyPath;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RegistryProtectResponse {
        public UInt32 ProtocolVersion;
        public UInt32 ProtectedPathCount;
    }

    public static class Native {
        public static readonly IntPtr InvalidHandleValue = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFile(
            string fileName,
            UInt32 desiredAccess,
            UInt32 shareMode,
            IntPtr securityAttributes,
            UInt32 creationDisposition,
            UInt32 flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            IntPtr device,
            UInt32 ioControlCode,
            byte[] inBuffer,
            UInt32 inBufferSize,
            byte[] outBuffer,
            UInt32 outBufferSize,
            out UInt32 bytesReturned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }

    public static class MarshalHelpers {
        public static byte[] StructureToBytes<T>(T value) where T : struct {
            int size = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(value, ptr, false);
                byte[] buffer = new byte[size];
                Marshal.Copy(ptr, buffer, 0, size);
                return buffer;
            } finally {
                Marshal.FreeHGlobal(ptr);
            }
        }

        public static object BytesToStructure(byte[] buffer, int offset, Type type) {
            int size = Marshal.SizeOf(type);
            IntPtr ptr = Marshal.AllocHGlobal(size);
            try {
                Marshal.Copy(buffer, offset, ptr, size);
                return Marshal.PtrToStructure(ptr, type);
            } finally {
                Marshal.FreeHGlobal(ptr);
            }
        }
    }
}
"@ | Out-Null
}

function Resolve-AegisRegistryKeyPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selector
    )

    $normalized = ($Selector -replace '/', '\').Trim()
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        throw "registry selector is empty"
    }
    if ($normalized.ToUpperInvariant().StartsWith('\REGISTRY\')) {
        return $normalized.TrimEnd('\')
    }

    $currentUserRoot = '\REGISTRY\USER\' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $patterns = @(
        [ordered]@{ Prefix = 'HKLM:\'; KernelRoot = '\REGISTRY\MACHINE' },
        [ordered]@{ Prefix = 'HKLM\'; KernelRoot = '\REGISTRY\MACHINE' },
        [ordered]@{ Prefix = 'HKEY_LOCAL_MACHINE:\'; KernelRoot = '\REGISTRY\MACHINE' },
        [ordered]@{ Prefix = 'HKEY_LOCAL_MACHINE\'; KernelRoot = '\REGISTRY\MACHINE' },
        [ordered]@{ Prefix = 'HKCU:\'; KernelRoot = $currentUserRoot },
        [ordered]@{ Prefix = 'HKCU\'; KernelRoot = $currentUserRoot },
        [ordered]@{ Prefix = 'HKEY_CURRENT_USER:\'; KernelRoot = $currentUserRoot },
        [ordered]@{ Prefix = 'HKEY_CURRENT_USER\'; KernelRoot = $currentUserRoot }
    )

    foreach ($pattern in $patterns) {
        if ($normalized.StartsWith($pattern.Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $suffix = $normalized.Substring($pattern.Prefix.Length).TrimStart('\')
            if ([string]::IsNullOrWhiteSpace($suffix)) {
                return $pattern.KernelRoot
            }
            return ($pattern.KernelRoot + '\' + $suffix).TrimEnd('\')
        }
    }

    throw "unsupported windows registry selector: $Selector"
}

[uint32]$ProtocolVersion = 65536
[uint32]$IoctlQueryStatus = 2236420
[uint32]$IoctlProtectRegistryPath = 2236440
[uint32]$IoctlClearProtectedRegistryPaths = 2236444
[uint32]$GenericReadWrite = 3221225472
[uint32]$FileShareReadWrite = 3
[uint32]$OpenExisting = 3
$devicePath = "\\.\AegisSensor"

$handle = [AegisRegistryProtectionBridge.Native]::CreateFile(
    $devicePath,
    $GenericReadWrite,
    $FileShareReadWrite,
    [IntPtr]::Zero,
    $OpenExisting,
    [uint32]0,
    [IntPtr]::Zero
)
if ($handle -eq [AegisRegistryProtectionBridge.Native]::InvalidHandleValue) {
    throw ("CreateFile({0}) failed: Win32={1}" -f $devicePath, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

try {
    if ($Mode -eq "status") {
        $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRegistryProtectionBridge.DriverStatusResponse")
        $outputBuffer = New-Object byte[] $responseSize
        [uint32]$bytesReturned = 0
        $ok = [AegisRegistryProtectionBridge.Native]::DeviceIoControl(
            $handle,
            $IoctlQueryStatus,
            $null,
            [uint32]0,
            $outputBuffer,
            [uint32]$outputBuffer.Length,
            [ref]$bytesReturned,
            [IntPtr]::Zero
        )
        if (-not $ok) {
            throw ("DeviceIoControl(QUERY_STATUS) failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
        if ($bytesReturned -lt $responseSize) {
            throw "registry protection status response is truncated"
        }

        $status = [AegisRegistryProtectionBridge.DriverStatusResponse][AegisRegistryProtectionBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            0,
            [type]"AegisRegistryProtectionBridge.DriverStatusResponse"
        )
        [ordered]@{
            service_name = $ServiceName
            mode = $Mode
            protocol_version = [uint32]$status.ProtocolVersion
            registry_callback_registered = ([uint32]$status.RegistryCallbackRegistered) -ne 0
            journal_capacity = [uint32]$status.JournalCapacity
            journal_count = [uint32]$status.JournalCount
            oldest_sequence = [uint32]$status.OldestSequence
            current_sequence = [uint32]$status.CurrentSequence
            protected_path_count = [uint32]$status.ProtectedRegistryPathCount
        } | ConvertTo-Json -Compress
        return
    }

    $resolvedPath = $null
    $request = New-Object AegisRegistryProtectionBridge.RegistryProtectRequest
    $request.ProtocolVersion = $ProtocolVersion
    if ($Mode -eq "protect") {
        if ([string]::IsNullOrWhiteSpace($KeyPath)) {
            throw "protect mode requires -KeyPath"
        }
        $resolvedPath = Resolve-AegisRegistryKeyPath -Selector $KeyPath
        $request.KeyPath = $resolvedPath
    } else {
        $request.KeyPath = ""
    }

    $requestBytes = [AegisRegistryProtectionBridge.MarshalHelpers]::StructureToBytes($request)
    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRegistryProtectionBridge.RegistryProtectResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0

    $ok = [AegisRegistryProtectionBridge.Native]::DeviceIoControl(
        $handle,
        $(if ($Mode -eq "protect") { $IoctlProtectRegistryPath } else { $IoctlClearProtectedRegistryPaths }),
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        throw ("DeviceIoControl({0}) failed: Win32={1}" -f $Mode.ToUpperInvariant(), [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($bytesReturned -lt $responseSize) {
        throw "registry protection response is truncated"
    }

    $response = [AegisRegistryProtectionBridge.RegistryProtectResponse][AegisRegistryProtectionBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisRegistryProtectionBridge.RegistryProtectResponse"
    )

    [ordered]@{
        service_name = $ServiceName
        mode = $Mode
        input_key_path = if ($Mode -eq "protect") { $KeyPath } else { $null }
        resolved_path = $resolvedPath
        protocol_version = [uint32]$response.ProtocolVersion
        protected_path_count = [uint32]$response.ProtectedPathCount
    } | ConvertTo-Json -Compress
} finally {
    if ($handle -ne [AegisRegistryProtectionBridge.Native]::InvalidHandleValue) {
        [void][AegisRegistryProtectionBridge.Native]::CloseHandle($handle)
    }
}
