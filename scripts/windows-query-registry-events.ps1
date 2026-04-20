param(
    [ValidateSet("status", "events")]
    [string]$Mode = "events",
    [string]$ServiceName = "AegisSensorKmod",
    [uint32]$LastSequence = 0,
    [uint32]$MaxEntries = 64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisRegistryBridge.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

namespace AegisRegistryBridge {
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct DriverStatusResponse {
        public UInt32 ProtocolVersion;
        public UInt32 RegistryCallbackRegistered;
        public UInt32 JournalCapacity;
        public UInt32 JournalCount;
        public UInt32 OldestSequence;
        public UInt32 CurrentSequence;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RegistryEventQueryRequest {
        public UInt32 ProtocolVersion;
        public UInt32 LastSequence;
        public UInt32 MaxEntries;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct RegistryEventQueryResponse {
        public UInt32 ProtocolVersion;
        public UInt32 OldestSequence;
        public UInt32 CurrentSequence;
        public UInt32 ReturnedCount;
        public UInt32 Overflowed;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct RegistryEventRecord {
        public UInt32 Sequence;
        public Int64 Timestamp;
        public UInt32 Operation;
        public UInt32 ValueType;
        public UInt32 OldDataSize;
        public UInt32 NewDataSize;
        public UInt32 OldValuePresent;
        public UInt32 NewValuePresent;
        public UInt32 OldDataTruncated;
        public UInt32 NewDataTruncated;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)]
        public string KeyPath;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string ValueName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        public byte[] OldData;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1024)]
        public byte[] NewData;
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
[uint32]$IoctlQueryStatus = 2236420
[uint32]$IoctlQueryRegistryEvents = 2236424
[uint32]$GenericReadWrite = 3221225472
[uint32]$FileShareReadWrite = 3
[uint32]$OpenExisting = 3
$devicePath = "\\.\AegisSensor"

function Convert-RegistryData {
    param(
        [uint32]$ValueType,
        [byte[]]$Data,
        [uint32]$DataSize
    )

    if ($DataSize -eq 0) {
        return $null
    }

    $slice = New-Object byte[] $DataSize
    [Array]::Copy($Data, 0, $slice, 0, [int]$DataSize)
    switch ($ValueType) {
        1 { return [System.Text.Encoding]::Unicode.GetString($slice).TrimEnd([char]0) }
        2 { return [System.Text.Encoding]::Unicode.GetString($slice).TrimEnd([char]0) }
        4 {
            if ($DataSize -lt 4) { return $null }
            return ([BitConverter]::ToUInt32($slice, 0)).ToString()
        }
        11 {
            if ($DataSize -lt 8) { return $null }
            return ([BitConverter]::ToUInt64($slice, 0)).ToString()
        }
        default { return [Convert]::ToBase64String($slice) }
    }
}

$handle = [AegisRegistryBridge.Native]::CreateFile(
    $devicePath,
    $GenericReadWrite,
    $FileShareReadWrite,
    [IntPtr]::Zero,
    $OpenExisting,
    [uint32]0,
    [IntPtr]::Zero
)
if ($handle -eq [AegisRegistryBridge.Native]::InvalidHandleValue) {
    throw ("CreateFile({0}) failed: Win32={1}" -f $devicePath, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}

try {
    if ($Mode -eq "status") {
        $responseSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRegistryBridge.DriverStatusResponse")
        $outputBuffer = New-Object byte[] $responseSize
        [uint32]$bytesReturned = 0
        $ok = [AegisRegistryBridge.Native]::DeviceIoControl(
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
            throw "registry status response is truncated"
        }

        $status = [AegisRegistryBridge.DriverStatusResponse][AegisRegistryBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            0,
            [type]"AegisRegistryBridge.DriverStatusResponse"
        )
        [ordered]@{
            service_name = $ServiceName
            protocol_version = [uint32]$status.ProtocolVersion
            registry_callback_registered = ([uint32]$status.RegistryCallbackRegistered) -ne 0
            journal_capacity = [uint32]$status.JournalCapacity
            journal_count = [uint32]$status.JournalCount
            oldest_sequence = [uint32]$status.OldestSequence
            current_sequence = [uint32]$status.CurrentSequence
        } | ConvertTo-Json -Depth 5 -Compress
        return
    }

    $request = New-Object AegisRegistryBridge.RegistryEventQueryRequest
    $request.ProtocolVersion = $ProtocolVersion
    $request.LastSequence = $LastSequence
    $request.MaxEntries = $MaxEntries
    $requestBytes = [AegisRegistryBridge.MarshalHelpers]::StructureToBytes($request)

    $responseHeaderSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRegistryBridge.RegistryEventQueryResponse")
    $recordSize = [Runtime.InteropServices.Marshal]::SizeOf([type]"AegisRegistryBridge.RegistryEventRecord")
    $outputBuffer = New-Object byte[] ($responseHeaderSize + ($recordSize * $MaxEntries))
    [uint32]$bytesReturned = 0
    $ok = [AegisRegistryBridge.Native]::DeviceIoControl(
        $handle,
        $IoctlQueryRegistryEvents,
        $requestBytes,
        [uint32]$requestBytes.Length,
        $outputBuffer,
        [uint32]$outputBuffer.Length,
        [ref]$bytesReturned,
        [IntPtr]::Zero
    )
    if (-not $ok) {
        throw ("DeviceIoControl(QUERY_REGISTRY_EVENTS) failed: Win32={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    }
    if ($bytesReturned -lt $responseHeaderSize) {
        throw "registry event response is truncated"
    }

    $header = [AegisRegistryBridge.RegistryEventQueryResponse][AegisRegistryBridge.MarshalHelpers]::BytesToStructure(
        $outputBuffer,
        0,
        [type]"AegisRegistryBridge.RegistryEventQueryResponse"
    )
    $records = @()
    for ($i = 0; $i -lt $header.ReturnedCount; $i++) {
        $offset = $responseHeaderSize + ($i * $recordSize)
        if (($offset + $recordSize) -gt $bytesReturned) {
            throw "registry event record payload is truncated"
        }
        $record = [AegisRegistryBridge.RegistryEventRecord][AegisRegistryBridge.MarshalHelpers]::BytesToStructure(
            $outputBuffer,
            $offset,
            [type]"AegisRegistryBridge.RegistryEventRecord"
        )
        $records += [ordered]@{
            sequence = [uint32]$record.Sequence
            timestamp = [int64]$record.Timestamp
            operation = switch ([uint32]$record.Operation) {
                1 { "set" }
                2 { "delete" }
                default { "unknown" }
            }
            key_path = ([string]$record.KeyPath).Trim([char]0)
            value_name = ([string]$record.ValueName).Trim([char]0)
            value_type = [uint32]$record.ValueType
            old_value_present = ([uint32]$record.OldValuePresent) -ne 0
            new_value_present = ([uint32]$record.NewValuePresent) -ne 0
            old_data_truncated = ([uint32]$record.OldDataTruncated) -ne 0
            new_data_truncated = ([uint32]$record.NewDataTruncated) -ne 0
            old_value = Convert-RegistryData -ValueType ([uint32]$record.ValueType) -Data $record.OldData -DataSize ([uint32]$record.OldDataSize)
            new_value = Convert-RegistryData -ValueType ([uint32]$record.ValueType) -Data $record.NewData -DataSize ([uint32]$record.NewDataSize)
        }
    }

    [ordered]@{
        service_name = $ServiceName
        protocol_version = [uint32]$header.ProtocolVersion
        oldest_sequence = [uint32]$header.OldestSequence
        current_sequence = [uint32]$header.CurrentSequence
        returned_count = [uint32]$header.ReturnedCount
        overflowed = ([uint32]$header.Overflowed) -ne 0
        events = $records
    } | ConvertTo-Json -Depth 6 -Compress
} finally {
    [void][AegisRegistryBridge.Native]::CloseHandle($handle)
}
