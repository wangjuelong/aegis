param(
    [Parameter(Mandatory = $true)]
    [string]$KeyPath,
    [string]$ServiceName = "AegisSensorKmod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisRollbackBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisRollbackBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct RegistryRollbackRequest {
        public UInt32 ProtocolVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string KeyPath;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RegistryRollbackResponse {
        public UInt32 ProtocolVersion;
        public UInt32 AppliedCount;
        public UInt32 CurrentSequence;
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

[uint32]$ProtocolVersion = 65536
[uint32]$IoctlRollbackRegistryKey = 2236428
[uint32]$GenericReadWrite = 3221225472
[uint32]$FileShareReadWrite = 3
[uint32]$OpenExisting = 3
$devicePath = "\\.\AegisSensor"

$handle = [AegisRollbackBridge.Native]::CreateFile(
    $devicePath,
    $GenericReadWrite,
    $FileShareReadWrite,
    [IntPtr]::Zero,
    $OpenExisting,
    [uint32]0,
    [IntPtr]::Zero
)
if ($handle -eq [AegisRollbackBridge.Native]::InvalidHandleValue) {
    throw ("CreateFile({0}) failed: Win32={1}" -f $devicePath, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

try {
    $request = New-Object AegisRollbackBridge.RegistryRollbackRequest
    $request.ProtocolVersion = $ProtocolVersion
    $request.KeyPath = $KeyPath
    $requestBytes = [AegisRollbackBridge.MarshalHelpers]::StructureToBytes($request)

    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRollbackBridge.RegistryRollbackResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0
    $ok = [AegisRollbackBridge.Native]::DeviceIoControl(
        $handle,
        $IoctlRollbackRegistryKey,
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        throw ("DeviceIoControl(ROLLBACK_REGISTRY_KEY) failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($bytesReturned -lt $responseSize) {
        throw "registry rollback response is truncated"
    }

    $response = [AegisRollbackBridge.RegistryRollbackResponse][AegisRollbackBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisRollbackBridge.RegistryRollbackResponse"
    )
    [ordered]@{
        service_name = $ServiceName
        key_path = $KeyPath
        protocol_version = [uint32]$response.ProtocolVersion
        applied_count = [uint32]$response.AppliedCount
        current_sequence = [uint32]$response.CurrentSequence
    } | ConvertTo-Json -Depth 5 -Compress
} finally {
    [void][AegisRollbackBridge.Native]::CloseHandle($handle)
}
