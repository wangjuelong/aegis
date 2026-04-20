param(
    [Parameter(Mandatory = $true)]
    [uint32]$ProcessId,
    [string]$ServiceName = "AegisSensorKmod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisProcessProtectionBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisProcessProtectionBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ProcessProtectRequest {
        public UInt32 ProtocolVersion;
        public UInt32 ProcessId;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ProcessProtectResponse {
        public UInt32 ProtocolVersion;
        public UInt32 ObCallbackRegistered;
        public UInt32 ProtectedProcessCount;
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
[uint32]$IoctlProtectProcess = 2236432
[uint32]$GenericReadWrite = 3221225472
[uint32]$FileShareReadWrite = 3
[uint32]$OpenExisting = 3
$devicePath = "\\.\AegisSensor"

$handle = [AegisProcessProtectionBridge.Native]::CreateFile(
    $devicePath,
    $GenericReadWrite,
    $FileShareReadWrite,
    [IntPtr]::Zero,
    $OpenExisting,
    [uint32]0,
    [IntPtr]::Zero
)
if ($handle -eq [AegisProcessProtectionBridge.Native]::InvalidHandleValue) {
    throw ("CreateFile({0}) failed: Win32={1}" -f $devicePath, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

try {
    $request = New-Object AegisProcessProtectionBridge.ProcessProtectRequest
    $request.ProtocolVersion = $ProtocolVersion
    $request.ProcessId = $ProcessId
    $requestBytes = [AegisProcessProtectionBridge.MarshalHelpers]::StructureToBytes($request)

    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisProcessProtectionBridge.ProcessProtectResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0
    $ok = [AegisProcessProtectionBridge.Native]::DeviceIoControl(
        $handle,
        $IoctlProtectProcess,
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        throw ("DeviceIoControl(PROTECT_PROCESS) failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($bytesReturned -lt $responseSize) {
        throw "protect process response is truncated"
    }

    $response = [AegisProcessProtectionBridge.ProcessProtectResponse][AegisProcessProtectionBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisProcessProtectionBridge.ProcessProtectResponse"
    )

    [ordered]@{
        service_name = $ServiceName
        process_id = $ProcessId
        protocol_version = [uint32]$response.ProtocolVersion
        ob_callback_registered = ([uint32]$response.ObCallbackRegistered) -ne 0
        protected_process_count = [uint32]$response.ProtectedProcessCount
    } | ConvertTo-Json -Compress
} finally {
    if ($handle -ne [AegisProcessProtectionBridge.Native]::InvalidHandleValue) {
        [void][AegisProcessProtectionBridge.Native]::CloseHandle($handle)
    }
}
