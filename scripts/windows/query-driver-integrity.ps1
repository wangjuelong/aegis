param(
    [string]$ServiceName = "AegisSensorKmod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisDriverIntegrityBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisDriverIntegrityBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverIntegrityResponse {
        public UInt32 ProtocolVersion;
        public UInt32 ObCallbackRegistered;
        public UInt32 ProtectedProcessCount;
        public UInt32 SsdtInspectionSucceeded;
        public UInt32 SsdtSuspicious;
        public UInt32 CallbackInspectionSucceeded;
        public UInt32 CallbackSuspicious;
        public UInt32 KernelCodeInspectionSucceeded;
        public UInt32 KernelCodeSuspicious;
        public UInt32 CodeIntegrityOptions;
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

[uint32]$IoctlQueryIntegrity = 2236436
[uint32]$GenericReadWrite = 3221225472
[uint32]$FileShareReadWrite = 3
[uint32]$OpenExisting = 3
[uint32]$CodeIntegrityEnabled = 0x00000001
[uint32]$CodeIntegrityTestSign = 0x00000002
[uint32]$CodeIntegrityKmciEnabled = 0x00000400
$devicePath = "\\.\AegisSensor"

$handle = [AegisDriverIntegrityBridge.Native]::CreateFile(
    $devicePath,
    $GenericReadWrite,
    $FileShareReadWrite,
    [IntPtr]::Zero,
    $OpenExisting,
    [uint32]0,
    [IntPtr]::Zero
)
if ($handle -eq [AegisDriverIntegrityBridge.Native]::InvalidHandleValue) {
    throw ("CreateFile({0}) failed: Win32={1}" -f $devicePath, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

try {
    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisDriverIntegrityBridge.DriverIntegrityResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0
    $ok = [AegisDriverIntegrityBridge.Native]::DeviceIoControl(
        $handle,
        $IoctlQueryIntegrity,
        $null,
        [uint32]0,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        throw ("DeviceIoControl(QUERY_INTEGRITY) failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($bytesReturned -lt $responseSize) {
        throw "driver integrity response is truncated"
    }

    $response = [AegisDriverIntegrityBridge.DriverIntegrityResponse][AegisDriverIntegrityBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisDriverIntegrityBridge.DriverIntegrityResponse"
    )

    $codeIntegrityOptions = [uint32]$response.CodeIntegrityOptions
    [ordered]@{
        service_name = $ServiceName
        protocol_version = [uint32]$response.ProtocolVersion
        ob_callback_registered = ([uint32]$response.ObCallbackRegistered) -ne 0
        protected_process_count = [uint32]$response.ProtectedProcessCount
        ssdt_inspection_succeeded = ([uint32]$response.SsdtInspectionSucceeded) -ne 0
        ssdt_suspicious = ([uint32]$response.SsdtSuspicious) -ne 0
        callback_inspection_succeeded = ([uint32]$response.CallbackInspectionSucceeded) -ne 0
        callback_suspicious = ([uint32]$response.CallbackSuspicious) -ne 0
        kernel_code_inspection_succeeded = ([uint32]$response.KernelCodeInspectionSucceeded) -ne 0
        kernel_code_suspicious = ([uint32]$response.KernelCodeSuspicious) -ne 0
        code_integrity_options = $codeIntegrityOptions
        code_integrity_enabled = ($codeIntegrityOptions -band $CodeIntegrityEnabled) -ne 0
        code_integrity_testsign = ($codeIntegrityOptions -band $CodeIntegrityTestSign) -ne 0
        code_integrity_kmci_enabled = ($codeIntegrityOptions -band $CodeIntegrityKmciEnabled) -ne 0
    } | ConvertTo-Json -Compress
} finally {
    if ($handle -ne [AegisDriverIntegrityBridge.Native]::InvalidHandleValue) {
        [void][AegisDriverIntegrityBridge.Native]::CloseHandle($handle)
    }
}
