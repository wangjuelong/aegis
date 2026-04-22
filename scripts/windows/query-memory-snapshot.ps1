Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$rows = @(
    Get-Process -ErrorAction Stop |
        Sort-Object Id |
        ForEach-Object {
            [ordered]@{
                process_id = [uint32]$_.Id
                process_name = [string]$_.ProcessName
                working_set_bytes = [uint64]$_.WorkingSet64
                private_memory_bytes = [uint64]$_.PrivateMemorySize64
                virtual_memory_bytes = [uint64]$_.VirtualMemorySize64
                paged_memory_bytes = [uint64]$_.PagedMemorySize64
                path = if ($_.Path) { [string]$_.Path } else { $null }
            }
        }
)

@($rows) | ConvertTo-Json -Depth 5 -Compress
