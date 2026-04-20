param(
    [ValidateSet("status", "protect", "clear")]
    [string]$Mode = "status",
    [string]$PortName = "\AegisFileMonitorPort",
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisFileProtectionBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AegisFileProtectionBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileQueryRequest {
        public UInt32 ProtocolVersion;
        public UInt32 Command;
        public UInt32 LastSequence;
        public UInt32 MaxEntries;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileQueryResponse {
        public UInt32 ProtocolVersion;
        public UInt32 QueueCapacity;
        public UInt32 OldestSequence;
        public UInt32 CurrentSequence;
        public UInt32 ReturnedCount;
        public UInt32 Overflowed;
        public UInt32 ProtectedPathCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct FileProtectionRequest {
        public UInt32 ProtocolVersion;
        public UInt32 Command;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string Path;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileProtectionResponse {
        public UInt32 ProtocolVersion;
        public UInt32 ProtectedPathCount;
    }

    public static class Native {
        [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
        public static extern Int32 FilterConnectCommunicationPort(
            string lpPortName,
            UInt32 dwOptions,
            IntPtr lpContext,
            UInt16 wSizeOfContext,
            IntPtr lpSecurityAttributes,
            out IntPtr hPort);

        [DllImport("fltlib.dll")]
        public static extern Int32 FilterSendMessage(
            IntPtr hPort,
            byte[] inBuffer,
            UInt32 inBufferSize,
            byte[] outBuffer,
            UInt32 outBufferSize,
            out UInt32 bytesReturned);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            UInt32 ucchMax);

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

function Resolve-AegisProtectedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalizedInput = ($Path -replace '/', '\')
    $resolvedItem = Resolve-Path -LiteralPath $normalizedInput -ErrorAction SilentlyContinue
    if ($null -eq $resolvedItem) {
        throw "protected path does not exist: $Path"
    }

    $resolved = [System.IO.Path]::GetFullPath($resolvedItem.Path)
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root) -or $root.Length -lt 2) {
        throw "unable to resolve drive root for protected path: $resolved"
    }

    $drive = $root.TrimEnd('\')
    $builder = New-Object System.Text.StringBuilder 1024
    $queryResult = [AegisFileProtectionBridge.Native]::QueryDosDevice(
        $drive,
        $builder,
        [uint32]$builder.Capacity
    )
    if ($queryResult -eq 0) {
        throw ("QueryDosDevice({0}) failed: Win32={1}" -f $drive, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }

    $devicePrefix = $builder.ToString().Split([char]0)[0]
    if ([string]::IsNullOrWhiteSpace($devicePrefix)) {
        throw "QueryDosDevice returned an empty target for $drive"
    }

    $suffix = $resolved.Substring($drive.Length).TrimStart('\')
    if ([string]::IsNullOrWhiteSpace($suffix)) {
        return $devicePrefix.TrimEnd('\')
    }

    return ($devicePrefix.TrimEnd('\') + '\' + $suffix)
}

[uint32]$ProtocolVersion = 0x00010000
[uint32]$CommandQueryStatus = 1
[uint32]$CommandProtectPath = 3
[uint32]$CommandClearProtectedPaths = 4

$portHandle = [IntPtr]::Zero
$connectHr = [AegisFileProtectionBridge.Native]::FilterConnectCommunicationPort(
    $PortName,
    [uint32]0,
    [IntPtr]::Zero,
    [uint16]0,
    [IntPtr]::Zero,
    [ref]$portHandle
)
if ($connectHr -ne 0) {
    throw ("FilterConnectCommunicationPort({0}) failed: HRESULT=0x{1}" -f $PortName, $connectHr.ToString("X8"))
}

try {
    if ($Mode -eq "status") {
        $request = New-Object AegisFileProtectionBridge.FileQueryRequest
        $request.ProtocolVersion = $ProtocolVersion
        $request.Command = $CommandQueryStatus
        $request.LastSequence = 0
        $request.MaxEntries = 0
        $requestBytes = [AegisFileProtectionBridge.MarshalHelpers]::StructureToBytes($request)
        $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisFileProtectionBridge.FileQueryResponse")
        $outputBuffer = New-Object byte[] $responseSize
        [uint32]$bytesReturned = 0

        $sendHr = [AegisFileProtectionBridge.Native]::FilterSendMessage(
            $portHandle,
            $requestBytes,
            [uint32]$requestBytes.Length,
            $outputBuffer,
            [uint32]$outputBuffer.Length,
            [ref]$bytesReturned
        )
        if ($sendHr -ne 0) {
            throw ("FilterSendMessage(status) failed: HRESULT=0x{0}" -f $sendHr.ToString("X8"))
        }
        if ($bytesReturned -lt $responseSize) {
            throw "file protection status response is truncated"
        }

        $response = [AegisFileProtectionBridge.FileQueryResponse][AegisFileProtectionBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            0,
            [type]"AegisFileProtectionBridge.FileQueryResponse"
        )
        [ordered]@{
            port_name = $PortName
            protocol_version = [uint32]$response.ProtocolVersion
            queue_capacity = [uint32]$response.QueueCapacity
            current_sequence = [uint32]$response.CurrentSequence
            protected_path_count = [uint32]$response.ProtectedPathCount
        } | ConvertTo-Json -Compress
        return
    }

    $request = New-Object AegisFileProtectionBridge.FileProtectionRequest
    $request.ProtocolVersion = $ProtocolVersion
    $request.Command = if ($Mode -eq "protect") { $CommandProtectPath } else { $CommandClearProtectedPaths }
    $resolvedPath = $null
    if ($Mode -eq "protect") {
        if ([string]::IsNullOrWhiteSpace($Path)) {
            throw "protect mode requires -Path"
        }
        $resolvedPath = Resolve-AegisProtectedPath -Path $Path
        $request.Path = $resolvedPath
    } else {
        $request.Path = ""
    }

    $requestBytes = [AegisFileProtectionBridge.MarshalHelpers]::StructureToBytes($request)
    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisFileProtectionBridge.FileProtectionResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0

    $sendHr = [AegisFileProtectionBridge.Native]::FilterSendMessage(
        $portHandle,
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned
    )
    if ($sendHr -ne 0) {
        throw ("FilterSendMessage({0}) failed: HRESULT=0x{1}" -f $Mode, $sendHr.ToString("X8"))
    }
    if ($bytesReturned -lt $responseSize) {
        throw "file protection response is truncated"
    }

    $response = [AegisFileProtectionBridge.FileProtectionResponse][AegisFileProtectionBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisFileProtectionBridge.FileProtectionResponse"
    )

    [ordered]@{
        port_name = $PortName
        mode = $Mode
        input_path = if ($Mode -eq "protect") { $Path } else { $null }
        resolved_path = $resolvedPath
        protocol_version = [uint32]$response.ProtocolVersion
        protected_path_count = [uint32]$response.ProtectedPathCount
    } | ConvertTo-Json -Compress
} finally {
    if ($portHandle -ne [IntPtr]::Zero) {
        [void][AegisFileProtectionBridge.Native]::CloseHandle($portHandle)
    }
}
