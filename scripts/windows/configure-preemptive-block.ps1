param(
    [ValidateSet("status", "block-hash", "block-pid", "block-path", "clear")]
    [string]$Mode = "status",
    [string]$PortName = "\AegisFileMonitorPort",
    [string]$Hash,
    [uint32]$ProcessId,
    [string]$Path,
    [uint32]$TtlSeconds = 300,
    [uint32]$MaxEntries = 128
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisPreemptiveBlockBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AegisPreemptiveBlockBridge {
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
        public UInt32 BlockEntryCount;
        public UInt32 HashBlockCount;
        public UInt32 PidBlockCount;
        public UInt32 PathBlockCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct FileBlockRequest {
        public UInt32 ProtocolVersion;
        public UInt32 Command;
        public UInt32 BlockKind;
        public UInt32 TtlSeconds;
        public UInt32 ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string Target;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct FileBlockResponse {
        public UInt32 ProtocolVersion;
        public UInt32 BlockEntryCount;
        public UInt32 HashBlockCount;
        public UInt32 PidBlockCount;
        public UInt32 PathBlockCount;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct FileBlockEntryRecord {
        public UInt32 BlockKind;
        public UInt32 ProcessId;
        public UInt32 TtlSecondsRemaining;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string Target;
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

function Normalize-AegisHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Hash
    )

    $normalized = ($Hash -replace '\s+', '').ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw "hash block requires a 64-char SHA-256 hex string"
    }
    $normalized
}

function Resolve-AegisPathBlockTarget {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $normalizedInput = ($Path -replace '/', '\')
    $resolved = [System.IO.Path]::GetFullPath($normalizedInput)
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root) -or $root.Length -lt 2) {
        throw "unable to resolve drive root for blocked path: $resolved"
    }

    $drive = $root.TrimEnd('\')
    $builder = New-Object System.Text.StringBuilder 1024
    $queryResult = [AegisPreemptiveBlockBridge.Native]::QueryDosDevice(
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

function Convert-AegisBlockKind {
    param([uint32]$Kind)

    switch ($Kind) {
        1 { "hash" }
        2 { "pid" }
        3 { "path" }
        default { "unknown" }
    }
}

[uint32]$ProtocolVersion = 0x00010000
[uint32]$CommandQueryBlockState = 5
[uint32]$CommandSetBlockEntry = 6
[uint32]$CommandClearBlockEntries = 7
[uint32]$KindHash = 1
[uint32]$KindPid = 2
[uint32]$KindPath = 3

$portHandle = [IntPtr]::Zero
$connectHr = [AegisPreemptiveBlockBridge.Native]::FilterConnectCommunicationPort(
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
        $request = New-Object AegisPreemptiveBlockBridge.FileQueryRequest
        $request.ProtocolVersion = $ProtocolVersion
        $request.Command = $CommandQueryBlockState
        $request.LastSequence = 0
        $request.MaxEntries = $MaxEntries
        $requestBytes = [AegisPreemptiveBlockBridge.MarshalHelpers]::StructureToBytes($request)
        $responseHeaderSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisPreemptiveBlockBridge.FileQueryResponse")
        $entrySize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisPreemptiveBlockBridge.FileBlockEntryRecord")
        $outputBuffer = New-Object byte[] ($responseHeaderSize + ($entrySize * $MaxEntries))
        [uint32]$bytesReturned = 0

        $sendHr = [AegisPreemptiveBlockBridge.Native]::FilterSendMessage(
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
        if ($bytesReturned -lt $responseHeaderSize) {
            throw "preemptive block status response is truncated"
        }

        $header = [AegisPreemptiveBlockBridge.FileQueryResponse][AegisPreemptiveBlockBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            0,
            [type]"AegisPreemptiveBlockBridge.FileQueryResponse"
        )
        $entries = @()
        for ($i = 0; $i -lt $header.ReturnedCount; $i++) {
            $offset = $responseHeaderSize + ($i * $entrySize)
            if (($offset + $entrySize) -gt $bytesReturned) {
                throw "preemptive block status response has truncated entries"
            }
            $entry = [AegisPreemptiveBlockBridge.FileBlockEntryRecord][AegisPreemptiveBlockBridge.MarshalHelpers]::BytesToStructure(
                $outputBuffer,
                $offset,
                [type]"AegisPreemptiveBlockBridge.FileBlockEntryRecord"
            )
            $entries += [ordered]@{
                kind = Convert-AegisBlockKind -Kind ([uint32]$entry.BlockKind)
                process_id = [uint32]$entry.ProcessId
                ttl_seconds_remaining = [uint32]$entry.TtlSecondsRemaining
                target = ([string]$entry.Target).Trim([char]0)
            }
        }

        [ordered]@{
            port_name = $PortName
            protocol_version = [uint32]$header.ProtocolVersion
            block_entry_count = [uint32]$header.BlockEntryCount
            hash_block_count = [uint32]$header.HashBlockCount
            pid_block_count = [uint32]$header.PidBlockCount
            path_block_count = [uint32]$header.PathBlockCount
            entries = $entries
        } | ConvertTo-Json -Depth 6 -Compress
        return
    }

    $request = New-Object AegisPreemptiveBlockBridge.FileBlockRequest
    $request.ProtocolVersion = $ProtocolVersion
    $request.Command = if ($Mode -eq "clear") { $CommandClearBlockEntries } else { $CommandSetBlockEntry }
    $request.BlockKind = 0
    $request.TtlSeconds = $TtlSeconds
    $request.ProcessId = 0
    $request.Target = ""
    $resolvedTarget = $null

    switch ($Mode) {
        "block-hash" {
            if ([string]::IsNullOrWhiteSpace($Hash)) {
                throw "block-hash mode requires -Hash"
            }
            $request.BlockKind = $KindHash
            $resolvedTarget = Normalize-AegisHash -Hash $Hash
            $request.Target = $resolvedTarget
        }
        "block-pid" {
            if ($ProcessId -eq 0) {
                throw "block-pid mode requires -ProcessId"
            }
            $request.BlockKind = $KindPid
            $request.ProcessId = $ProcessId
        }
        "block-path" {
            if ([string]::IsNullOrWhiteSpace($Path)) {
                throw "block-path mode requires -Path"
            }
            $request.BlockKind = $KindPath
            $resolvedTarget = Resolve-AegisPathBlockTarget -Path $Path
            $request.Target = $resolvedTarget
        }
        "clear" {
        }
    }

    $requestBytes = [AegisPreemptiveBlockBridge.MarshalHelpers]::StructureToBytes($request)
    $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisPreemptiveBlockBridge.FileBlockResponse")
    $outputBuffer = New-Object byte[] $responseSize
    [uint32]$bytesReturned = 0

    $sendHr = [AegisPreemptiveBlockBridge.Native]::FilterSendMessage(
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
        throw "preemptive block response is truncated"
    }

    $response = [AegisPreemptiveBlockBridge.FileBlockResponse][AegisPreemptiveBlockBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisPreemptiveBlockBridge.FileBlockResponse"
    )

    [ordered]@{
        port_name = $PortName
        mode = $Mode
        hash = if ($Mode -eq "block-hash") { $resolvedTarget } else { $null }
        process_id = if ($Mode -eq "block-pid") { $ProcessId } else { $null }
        input_path = if ($Mode -eq "block-path") { $Path } else { $null }
        resolved_target = $resolvedTarget
        ttl_seconds = if ($Mode -eq "clear") { $null } else { $TtlSeconds }
        protocol_version = [uint32]$response.ProtocolVersion
        block_entry_count = [uint32]$response.BlockEntryCount
        hash_block_count = [uint32]$response.HashBlockCount
        pid_block_count = [uint32]$response.PidBlockCount
        path_block_count = [uint32]$response.PathBlockCount
    } | ConvertTo-Json -Depth 6 -Compress
} finally {
    if ($portHandle -ne [IntPtr]::Zero) {
        [void][AegisPreemptiveBlockBridge.Native]::CloseHandle($portHandle)
    }
}
