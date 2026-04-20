param(
    [ValidateSet("status", "events")]
    [string]$Mode = "events",
    [string]$PortName = "\AegisFileMonitorPort",
    [uint32]$LastSequence = 0,
    [uint32]$MaxEntries = 64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisFileBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisFileBridge {
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
    public struct FileEventRecord {
        public UInt32 Sequence;
        public Int64 Timestamp;
        public UInt32 ProcessId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
        public string Operation;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string Path;
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

[uint32]$ProtocolVersion = 0x00010000
[uint32]$CommandQueryStatus = 1
[uint32]$CommandQueryEvents = 2

$request = New-Object AegisFileBridge.FileQueryRequest
$request.ProtocolVersion = $ProtocolVersion
$request.Command = if ($Mode -eq "status") { $CommandQueryStatus } else { $CommandQueryEvents }
$request.LastSequence = $LastSequence
$request.MaxEntries = $MaxEntries
$requestBytes = [AegisFileBridge.MarshalHelpers]::StructureToBytes($request)

$portHandle = [IntPtr]::Zero
$connectHr = [AegisFileBridge.Native]::FilterConnectCommunicationPort(
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
    $responseHeaderSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisFileBridge.FileQueryResponse")
    $eventRecordSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisFileBridge.FileEventRecord")
    $outputBufferSize = if ($Mode -eq "status") {
        $responseHeaderSize
    } else {
        $responseHeaderSize + ($eventRecordSize * $MaxEntries)
    }
    $outputBuffer = New-Object byte[] $outputBufferSize
    [uint32]$bytesReturned = 0

    $sendHr = [AegisFileBridge.Native]::FilterSendMessage(
        $portHandle,
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned
    )
    if ($sendHr -ne 0) {
        throw ("FilterSendMessage failed: HRESULT=0x{0}" -f $sendHr.ToString("X8"))
    }
    if ($bytesReturned -lt $responseHeaderSize) {
        throw "minifilter query returned truncated header"
    }

    $header = [AegisFileBridge.FileQueryResponse][AegisFileBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisFileBridge.FileQueryResponse"
    )
    $records = @()
    for ($i = 0; $i -lt $header.ReturnedCount; $i++) {
        $offset = $responseHeaderSize + ($i * $eventRecordSize)
        if (($offset + $eventRecordSize) -gt $bytesReturned) {
            throw "minifilter query returned truncated event payload"
        }
        $eventRecord = [AegisFileBridge.FileEventRecord][AegisFileBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            $offset,
            [type]"AegisFileBridge.FileEventRecord"
        )
        $records += [ordered]@{
            sequence = [uint32]$eventRecord.Sequence
            timestamp = [int64]$eventRecord.Timestamp
            process_id = [uint32]$eventRecord.ProcessId
            operation = ([string]$eventRecord.Operation).Trim([char]0)
            path = ([string]$eventRecord.Path).Trim([char]0)
        }
    }

    [ordered]@{
        port_name = $PortName
        protocol_version = [uint32]$header.ProtocolVersion
        queue_capacity = [uint32]$header.QueueCapacity
        oldest_sequence = [uint32]$header.OldestSequence
        current_sequence = [uint32]$header.CurrentSequence
        returned_count = [uint32]$header.ReturnedCount
        overflowed = ([uint32]$header.Overflowed) -ne 0
        protected_path_count = [uint32]$header.ProtectedPathCount
        events = $records
    } | ConvertTo-Json -Depth 6 -Compress
} finally {
    if ($portHandle -ne [IntPtr]::Zero) {
        [void][AegisFileBridge.Native]::CloseHandle($portHandle)
    }
}
