param(
    [int]$MaxRegions = 128,
    [int]$SampleBytes = 512
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

if (-not ("AegisMemoryProbe.Native" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AegisMemoryProbe {
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public UInt32 AllocationProtect;
        public UIntPtr RegionSize;
        public UInt32 State;
        public UInt32 Protect;
        public UInt32 Type;
    }

    public static class Native {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(UInt32 desiredAccess, bool inheritHandle, UInt32 processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualQueryEx(
            IntPtr processHandle,
            IntPtr address,
            out MEMORY_BASIC_INFORMATION buffer,
            UIntPtr length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            byte[] buffer,
            int size,
            out IntPtr bytesRead);

        [DllImport("psapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 GetMappedFileName(
            IntPtr processHandle,
            IntPtr address,
            StringBuilder fileName,
            UInt32 size);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
"@ | Out-Null
}

$PROCESS_QUERY_INFORMATION = 0x0400
$PROCESS_VM_READ = 0x0010
$MEM_COMMIT = 0x1000
$PAGE_GUARD = 0x100
$PAGE_NOACCESS = 0x01

function Test-ExecutableProtect {
    param([uint32]$Protect)
    ($Protect -band 0x10) -ne 0 -or
    ($Protect -band 0x20) -ne 0 -or
    ($Protect -band 0x40) -ne 0 -or
    ($Protect -band 0x80) -ne 0
}

function Resolve-ProtectName {
    param([uint32]$Protect)
    switch ($Protect -band 0xff) {
        0x10 { "EXECUTE" }
        0x20 { "EXECUTE_READ" }
        0x40 { "EXECUTE_READWRITE" }
        0x80 { "EXECUTE_WRITECOPY" }
        0x04 { "READWRITE" }
        0x08 { "WRITECOPY" }
        0x02 { "READONLY" }
        default { ("0x{0:x}" -f $Protect) }
    }
}

function Resolve-TypeName {
    param([uint32]$Type)
    switch ($Type) {
        0x20000 { "private" }
        0x40000 { "mapped" }
        0x1000000 { "image" }
        default { ("0x{0:x}" -f $Type) }
    }
}

$results = New-Object System.Collections.Generic.List[object]
$mbiSize = [System.UIntPtr]::new([uint64][System.Runtime.InteropServices.Marshal]::SizeOf([type]'AegisMemoryProbe.MEMORY_BASIC_INFORMATION'))

foreach ($process in Get-Process -ErrorAction SilentlyContinue) {
    if ($results.Count -ge $MaxRegions) {
        break
    }

    $handle = [AegisMemoryProbe.Native]::OpenProcess(
        [uint32]($PROCESS_QUERY_INFORMATION -bor $PROCESS_VM_READ),
        $false,
        [uint32]$process.Id
    )
    if ($handle -eq [IntPtr]::Zero) {
        continue
    }

    try {
        $address = [IntPtr]::Zero
        while ($results.Count -lt $MaxRegions) {
            $mbi = New-Object AegisMemoryProbe.MEMORY_BASIC_INFORMATION
            $queryResult = [AegisMemoryProbe.Native]::VirtualQueryEx($handle, $address, [ref]$mbi, $mbiSize)
            if ($queryResult -eq [IntPtr]::Zero) {
                break
            }

            $regionSize = [uint64]$mbi.RegionSize.ToUInt64()
            if ($regionSize -eq 0) {
                break
            }

            $protect = [uint32]$mbi.Protect
            $state = [uint32]$mbi.State
            if ($state -eq $MEM_COMMIT -and (Test-ExecutableProtect $protect) -and ($protect -band $PAGE_GUARD) -eq 0 -and ($protect -band $PAGE_NOACCESS) -eq 0) {
                $mappedPath = $null
                $builder = New-Object System.Text.StringBuilder 1024
                $mappedLength = [AegisMemoryProbe.Native]::GetMappedFileName($handle, $mbi.BaseAddress, $builder, [uint32]$builder.Capacity)
                if ($mappedLength -gt 0) {
                    $mappedPath = $builder.ToString()
                }

                $sampleLength = [Math]::Min([int]$SampleBytes, [int][Math]::Min($regionSize, [uint64]$SampleBytes))
                $sampleBase64 = $null
                if ($sampleLength -gt 0) {
                    $buffer = New-Object byte[] $sampleLength
                    $bytesRead = [IntPtr]::Zero
                    if ([AegisMemoryProbe.Native]::ReadProcessMemory($handle, $mbi.BaseAddress, $buffer, $sampleLength, [ref]$bytesRead)) {
                        $actual = [Math]::Min($sampleLength, [int]$bytesRead.ToInt64())
                        if ($actual -gt 0) {
                            if ($actual -lt $buffer.Length) {
                                $buffer = $buffer[0..($actual - 1)]
                            }
                            $sampleBase64 = [Convert]::ToBase64String($buffer)
                        }
                    }
                }

                $results.Add([ordered]@{
                    process_id = [uint32]$process.Id
                    process_name = [string]$process.ProcessName
                    base_address = [uint64]$mbi.BaseAddress.ToInt64()
                    region_size = $regionSize
                    protection = Resolve-ProtectName $protect
                    memory_type = Resolve-TypeName ([uint32]$mbi.Type)
                    mapped_path = $mappedPath
                    sample_base64 = $sampleBase64
                }) | Out-Null
            }

            $nextAddress = $mbi.BaseAddress.ToInt64() + [int64]$regionSize
            if ($nextAddress -le $mbi.BaseAddress.ToInt64()) {
                break
            }
            $address = [IntPtr]$nextAddress
        }
    } finally {
        [void][AegisMemoryProbe.Native]::CloseHandle($handle)
    }
}

$results.ToArray() | ConvertTo-Json -Depth 6 -Compress
