param(
    [string]$ServiceName = "AegisFileMonitor"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Resolve-PublishedDriverName {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OriginalInfName
    )

    $drivers = @(Get-WindowsDriver -Online -ErrorAction Stop |
        Where-Object {
            $_.OriginalFileName -and
            ([System.IO.Path]::GetFileName($_.OriginalFileName)).Equals($OriginalInfName, [System.StringComparison]::OrdinalIgnoreCase)
        })
    if ($drivers.Count -eq 0) {
        return $null
    }

    ($drivers | Sort-Object Driver -Descending | Select-Object -First 1).Driver
}

fltmc unload $ServiceName | Out-Null
$publishedInf = Resolve-PublishedDriverName -OriginalInfName "$ServiceName.inf"
if ($null -ne $publishedInf) {
    pnputil /delete-driver $publishedInf /uninstall /force | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "pnputil /delete-driver failed with exit code $LASTEXITCODE"
    }
}

[ordered]@{
    service_name = $ServiceName
    published_inf = $publishedInf
} | ConvertTo-Json -Compress
