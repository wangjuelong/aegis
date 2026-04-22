param(
    [string]$ServiceName = "AegisSensorKmod"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Get-ServiceState {
    param([string]$Name)
    try {
        return [string](Get-Service -Name $Name -ErrorAction Stop).Status
    } catch {
        return $null
    }
}

$serviceBinary = "$env:SystemRoot\System32\drivers\AegisSensorKmod.sys"
$stateBefore = Get-ServiceState -Name $ServiceName

if ($null -ne $stateBefore -and $stateBefore -eq "Running") {
    & sc.exe stop $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe stop failed with exit code $LASTEXITCODE"
    }
    Start-Sleep -Seconds 1
}

if ($null -ne (Get-ServiceState -Name $ServiceName)) {
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe delete failed with exit code $LASTEXITCODE"
    }
    Start-Sleep -Seconds 1
}

if (Test-Path -LiteralPath $serviceBinary) {
    Remove-Item -LiteralPath $serviceBinary -Force
}

[ordered]@{
    service_name = $ServiceName
    state_before = $stateBefore
    state_after = (Get-ServiceState -Name $ServiceName)
    removed_binary = -not (Test-Path -LiteralPath $serviceBinary)
} | ConvertTo-Json -Compress
