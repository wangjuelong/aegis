param(
    [ValidateSet("status", "scan", "execute")]
    [string]$Mode = "status",
    [string]$ContentName = "AegisScript.ps1",
    [string]$ScriptContentBase64 = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Ensure-AmsiBridge {
    if ("AegisAmsi.Bridge" -as [type]) {
        return
    }

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace AegisAmsi {
    public static class Bridge {
        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll")]
        public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr session);

        [DllImport("amsi.dll")]
        public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr session);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode)]
        public static extern int AmsiScanBuffer(
            IntPtr amsiContext,
            byte[] buffer,
            uint length,
            string contentName,
            IntPtr session,
            out uint result);
    }
}
"@ | Out-Null
}

function Convert-Base64ToUtf8String {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
}

function Invoke-AmsiScan {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Content
    )

    Ensure-AmsiBridge

    $context = [IntPtr]::Zero
    $session = [IntPtr]::Zero
    $sessionOpened = $false
    $result = [uint32]0
    $scanReady = $false
    $status = [AegisAmsi.Bridge]::AmsiInitialize("AegisSensor", [ref]$context)

    try {
        if ($status -eq 0 -and $context -ne [IntPtr]::Zero) {
            $openStatus = [AegisAmsi.Bridge]::AmsiOpenSession($context, [ref]$session)
            $sessionOpened = $openStatus -eq 0 -and $session -ne [IntPtr]::Zero

            $bytes = [System.Text.Encoding]::Unicode.GetBytes($Content)
            $status = [AegisAmsi.Bridge]::AmsiScanBuffer(
                $context,
                $bytes,
                [uint32]$bytes.Length,
                $Name,
                $session,
                [ref]$result
            )
            $scanReady = $status -eq 0
        }
    } finally {
        if ($session -ne [IntPtr]::Zero -and $context -ne [IntPtr]::Zero) {
            [AegisAmsi.Bridge]::AmsiCloseSession($context, $session)
        }
        if ($context -ne [IntPtr]::Zero) {
            [AegisAmsi.Bridge]::AmsiUninitialize($context)
        }
    }

    [ordered]@{
        content_name = $Name
        app_name = "AegisSensor"
        amsi_result = [uint32]$result
        blocked_by_admin = [uint32]$result -ge 16384 -and [uint32]$result -lt 32768
        malware = [uint32]$result -ge 32768
        should_block = [uint32]$result -ge 16384
        session_opened = $sessionOpened
        scan_interface_ready = $scanReady
    }
}

$hasAmsiRuntime = $false
try {
    $amsiDll = Join-Path $env:WINDIR "System32\amsi.dll"
    $hasAmsiRuntime = Test-Path -LiteralPath $amsiDll
} catch {
    $hasAmsiRuntime = $false
}

switch ($Mode) {
    "status" {
        $scan = Invoke-AmsiScan -Name "AegisProbe.ps1" -Content "Write-Output 'Aegis AMSI probe'"
        [ordered]@{
            has_amsi_runtime = $hasAmsiRuntime
            scan_interface_ready = [bool]$scan.scan_interface_ready
            session_opened = [bool]$scan.session_opened
            amsi_result = [uint32]$scan.amsi_result
        } | ConvertTo-Json -Depth 5 -Compress
    }
    "scan" {
        if ([string]::IsNullOrWhiteSpace($ScriptContentBase64)) {
            throw "ScriptContentBase64 is required when Mode=scan"
        }

        $content = Convert-Base64ToUtf8String -Value $ScriptContentBase64
        $scan = Invoke-AmsiScan -Name $ContentName -Content $content

        [ordered]@{
            content_name = [string]$scan.content_name
            app_name = [string]$scan.app_name
            amsi_result = [uint32]$scan.amsi_result
            blocked_by_admin = [bool]$scan.blocked_by_admin
            malware = [bool]$scan.malware
            should_block = [bool]$scan.should_block
            session_opened = [bool]$scan.session_opened
            scan_interface_ready = [bool]$scan.scan_interface_ready
        } | ConvertTo-Json -Depth 5 -Compress
    }
    "execute" {
        if ([string]::IsNullOrWhiteSpace($ScriptContentBase64)) {
            throw "ScriptContentBase64 is required when Mode=execute"
        }

        $content = Convert-Base64ToUtf8String -Value $ScriptContentBase64
        $scan = Invoke-AmsiScan -Name $ContentName -Content $content

        if ($scan.should_block) {
            [ordered]@{
                decision = "block"
                blocked = $true
                executed = $false
                amsi_result = [uint32]$scan.amsi_result
                blocked_by_admin = [bool]$scan.blocked_by_admin
                malware = [bool]$scan.malware
                session_opened = [bool]$scan.session_opened
                scan_interface_ready = [bool]$scan.scan_interface_ready
            } | ConvertTo-Json -Depth 5 -Compress
            return
        }

        $output = @(& ([scriptblock]::Create($content)) 2>&1 | ForEach-Object { [string]$_ })
        [ordered]@{
            decision = "allow"
            blocked = $false
            executed = $true
            amsi_result = [uint32]$scan.amsi_result
            blocked_by_admin = [bool]$scan.blocked_by_admin
            malware = [bool]$scan.malware
            session_opened = [bool]$scan.session_opened
            scan_interface_ready = [bool]$scan.scan_interface_ready
            output = $output
            output_count = @($output).Count
        } | ConvertTo-Json -Depth 5 -Compress
    }
}
