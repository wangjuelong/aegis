param(
    [uint64]$AfterRecordId = 0,
    [uint32]$MaxEntries = 64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$rows = @(
    Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-PowerShell/Operational"
        Id = 4104
    } -ErrorAction SilentlyContinue |
        Where-Object { [uint64]$_.RecordId -gt $AfterRecordId } |
        Sort-Object RecordId |
        Select-Object -First $MaxEntries |
        ForEach-Object {
            $xml = [xml]$_.ToXml()
            $eventData = @{}
            foreach ($item in $xml.Event.EventData.Data) {
                if ($item.Name) {
                    $eventData[$item.Name] = [string]$item.InnerText
                }
            }

            $processId = $null
            if ($null -ne $xml.Event.System.Execution -and $xml.Event.System.Execution.ProcessID) {
                $processId = [uint32]$xml.Event.System.Execution.ProcessID
            }

            [ordered]@{
                record_id = [uint64]$_.RecordId
                process_id = $processId
                script_block_id = if ($eventData.ContainsKey("ScriptBlockId")) { [string]$eventData["ScriptBlockId"] } else { $null }
                message_number = if ($eventData.ContainsKey("MessageNumber") -and $eventData["MessageNumber"]) { [uint32]$eventData["MessageNumber"] } else { $null }
                message_total = if ($eventData.ContainsKey("MessageTotal") -and $eventData["MessageTotal"]) { [uint32]$eventData["MessageTotal"] } else { $null }
                path = if ($eventData.ContainsKey("Path") -and $eventData["Path"]) { [string]$eventData["Path"] } else { $null }
                script_text = if ($eventData.ContainsKey("ScriptBlockText")) { [string]$eventData["ScriptBlockText"] } else { "" }
            }
        }
)

@($rows) | ConvertTo-Json -Depth 5 -Compress
