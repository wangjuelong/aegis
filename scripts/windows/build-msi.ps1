param(
    [Parameter(Mandatory = $true)]
    [string]$PayloadRoot,
    [string]$OutputRoot = (Join-Path $PayloadRoot "msi"),
    [string]$ProductVersion = "0.1.0",
    [string]$ProductName = "Aegis Sensor",
    [string]$Manufacturer = "Aegis",
    [string]$UpgradeCode = "{D7A75DCC-86E1-4F75-BFE6-7C612A4A4D09}",
    [ValidateSet("development", "release")]
    [string]$BundleChannel = "development",
    [string]$SigningCertificateThumbprint,
    [string]$SigningCertificateStorePath = "Cert:\CurrentUser\My",
    [string]$TimestampServer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

function Resolve-ExistingPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $resolved) {
        throw "missing ${Description}: ${Path}"
    }
    $resolved.Path
}

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    $Path
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @(),
        [Parameter(Mandatory = $false)][string]$WorkingDirectory
    )

    if ($WorkingDirectory) {
        Push-Location $WorkingDirectory
    }
    try {
        $output = & $FilePath @Arguments 2>&1
        if ($LASTEXITCODE -ne 0) {
            $message = ($output | Out-String).Trim()
            if ([string]::IsNullOrWhiteSpace($message)) {
                $message = "command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
            }
            throw $message
        }
        $output
    } finally {
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Resolve-WixExecutable {
    $wixCommand = Get-Command wix -ErrorAction SilentlyContinue
    if ($null -ne $wixCommand) {
        return $wixCommand.Source
    }

    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($null -eq $winget) {
        throw "wix is unavailable and winget is not installed"
    }

    Invoke-External -FilePath $winget.Source -Arguments @(
        "install",
        "-e",
        "--id", "WiXToolset.WiXCLI",
        "--accept-source-agreements",
        "--accept-package-agreements",
        "--silent"
    ) | Out-Null

    $refreshCandidates = @(
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\wix.exe",
        "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\wix.exe"
    )
    foreach ($candidate in $refreshCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $wixCommand = Get-Command wix -ErrorAction SilentlyContinue
    if ($null -ne $wixCommand) {
        return $wixCommand.Source
    }

    throw "failed to resolve wix executable after installation"
}

function Accept-WixLicense {
    param([Parameter(Mandatory = $true)][string]$WixPath)

    Invoke-External -FilePath $WixPath -Arguments @("eula", "accept", "wix7") | Out-Null
}

function Get-WixVersion {
    param([Parameter(Mandatory = $true)][string]$WixPath)

    $versionOutput = Invoke-External -FilePath $WixPath -Arguments @("--version")
    $match = [regex]::Match(($versionOutput | Out-String), '(\d+\.\d+\.\d+)')
    if (-not $match.Success) {
        throw "unable to parse wix version: $($versionOutput | Out-String)"
    }
    $match.Groups[1].Value
}

function Ensure-WixUtilExtension {
    param([Parameter(Mandatory = $true)][string]$WixPath)

    Accept-WixLicense -WixPath $WixPath
    $wixVersion = Get-WixVersion -WixPath $WixPath
    $extensionRef = "WixToolset.Util.wixext/$wixVersion"
    $listOutput = Invoke-External -FilePath $WixPath -Arguments @("extension", "list", "-g")
    if (($listOutput | Out-String) -match "WixToolset\.Util\.wixext/$([regex]::Escape($wixVersion))") {
        return
    }
    Invoke-External -FilePath $WixPath -Arguments @("extension", "add", "-g", $extensionRef) | Out-Null
}

function Convert-ToMsiVersion {
    param([Parameter(Mandatory = $true)][string]$Version)

    $parts = $Version.Split(".")
    while ($parts.Count -lt 3) {
        $parts += "0"
    }
    "{0}.{1}.{2}" -f ([int]$parts[0]), ([int]$parts[1]), ([int]$parts[2])
}

function New-WixId {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][string]$Value
    )

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = [System.BitConverter]::ToString(
            $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
        ).Replace("-", "")
    } finally {
        $sha256.Dispose()
    }
    $sanitized = ($Value -replace '[^A-Za-z0-9_]', '_')
    if ([string]::IsNullOrWhiteSpace($sanitized)) {
        $sanitized = "item"
    }
    if ($sanitized[0] -match '[0-9]') {
        $sanitized = "_$sanitized"
    }
    $trimmed = if ($sanitized.Length -gt 36) { $sanitized.Substring(0, 36) } else { $sanitized }
    "${Prefix}_${trimmed}_$($hash.Substring(0, 12))"
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootUri = [System.Uri]((Resolve-ExistingPath -Path $Root -Description "root") + [IO.Path]::DirectorySeparatorChar)
    $pathUri = [System.Uri](Resolve-ExistingPath -Path $Path -Description "path")
    [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString()).Replace('/', '\')
}

function Add-TreeNode {
    param(
        [Parameter(Mandatory = $true)]$Node,
        [Parameter(Mandatory = $true)][string[]]$Segments
    )

    if ($Segments.Count -eq 0) {
        return $Node
    }
    $segment = $Segments[0]
    if (-not $Node.Children.Contains($segment)) {
        $child = [pscustomobject]@{
            Name = $segment
            RelativePath = if ([string]::IsNullOrWhiteSpace($Node.RelativePath)) { $segment } else { Join-Path $Node.RelativePath $segment }
            Children = New-Object System.Collections.ArrayList
            Files = New-Object System.Collections.ArrayList
        }
        [void]$Node.Children.Add($child)
    }
    $next = @($Node.Children | Where-Object { $_.Name -eq $segment })[0]
    Add-TreeNode -Node $next -Segments $Segments[1..($Segments.Count - 1)]
}

function Find-OrCreateDirectoryNode {
    param(
        [Parameter(Mandatory = $true)]$RootNode,
        [Parameter(Mandatory = $true)][string]$RelativeDirectory
    )

    if ([string]::IsNullOrWhiteSpace($RelativeDirectory)) {
        return $RootNode
    }

    $segments = $RelativeDirectory -split '[\\/]'
    $node = $RootNode
    foreach ($segment in $segments) {
        $existing = @($node.Children | Where-Object { $_.Name -eq $segment })
        if ($existing.Count -eq 0) {
            $child = [pscustomobject]@{
                Name = $segment
                RelativePath = if ([string]::IsNullOrWhiteSpace($node.RelativePath)) { $segment } else { Join-Path $node.RelativePath $segment }
                Children = New-Object System.Collections.ArrayList
                Files = New-Object System.Collections.ArrayList
            }
            [void]$node.Children.Add($child)
            $node = $child
        } else {
            $node = $existing[0]
        }
    }
    $node
}

function Write-DirectoryTreeXml {
    param(
        [Parameter(Mandatory = $true)][System.Xml.XmlWriter]$Writer,
        [Parameter(Mandatory = $true)]$Node
    )

    foreach ($child in ($Node.Children | Sort-Object Name)) {
        $directoryId = New-WixId -Prefix "DIR" -Value $child.RelativePath
        $Writer.WriteStartElement("Directory", "http://wixtoolset.org/schemas/v4/wxs")
        $Writer.WriteAttributeString("Id", $directoryId)
        $Writer.WriteAttributeString("Name", $child.Name)
        Write-DirectoryTreeXml -Writer $Writer -Node $child
        $Writer.WriteEndElement()
    }
}

function Resolve-CodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    $normalizedThumbprint = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    $certificates = @(
        Get-ChildItem -Path $StorePath -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $normalizedThumbprint }
    )
    if ($certificates.Count -ne 1) {
        throw "unable to resolve unique code signing certificate: $normalizedThumbprint"
    }
    $certificates[0]
}

function Resolve-SignToolPath {
    $kitsBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $versions = @(
        Get-ChildItem -LiteralPath $kitsBinRoot -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version]$_.Name } -Descending
    )
    foreach ($version in $versions) {
        foreach ($arch in @("x64", "x86")) {
            $candidate = Join-Path $version.FullName "$arch\signtool.exe"
            if (Test-Path -LiteralPath $candidate) {
                return (Resolve-ExistingPath -Path $candidate -Description "signtool.exe")
            }
        }
    }
    throw "signtool.exe is unavailable under $kitsBinRoot"
}

function Sign-MsiPackage {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
        [Parameter(Mandatory = $true)][string]$CertificateStorePath,
        [Parameter(Mandatory = $true)][string]$TimestampServer
    )

    $certificate = Resolve-CodeSigningCertificate -Thumbprint $CertificateThumbprint -StorePath $CertificateStorePath
    $signTool = Resolve-SignToolPath
    Invoke-External -FilePath $signTool -Arguments @(
        "sign",
        "/fd", "SHA256",
        "/t", $TimestampServer,
        "/sha1", $certificate.Thumbprint,
        $Path
    ) | Out-Null

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "invalid MSI Authenticode signature for ${Path}: $($signature.Status)"
    }
}

$resolvedPayloadRoot = Resolve-ExistingPath -Path $PayloadRoot -Description "payload root"
$resolvedOutputRoot = Ensure-Directory -Path $OutputRoot
$resolvedManifestPath = Resolve-ExistingPath -Path (Join-Path $resolvedPayloadRoot "manifest.json") -Description "staged windows manifest"
$manifest = Get-Content -LiteralPath $resolvedManifestPath -Raw | ConvertFrom-Json -ErrorAction Stop

foreach ($required in @(
        "manifest.json",
        "install.ps1",
        "uninstall.ps1",
        "verify-release.ps1",
        "bin\aegis-agentd.exe",
        "bin\aegis-watchdog.exe",
        "bin\aegis-updater.exe",
        "scripts\windows-install-driver.ps1",
        "scripts\windows-uninstall-driver.ps1"
    )) {
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedPayloadRoot $required))) {
        throw "missing staged MSI artifact: $(Join-Path $resolvedPayloadRoot $required)"
    }
}

$rootNode = [pscustomobject]@{
    Name = ""
    RelativePath = ""
    Children = New-Object System.Collections.ArrayList
    Files = New-Object System.Collections.ArrayList
}

$components = New-Object System.Collections.Generic.List[object]
$files = Get-ChildItem -LiteralPath $resolvedPayloadRoot -Recurse -File -ErrorAction Stop | Sort-Object FullName
foreach ($file in $files) {
    if ($file.FullName.StartsWith($resolvedOutputRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        continue
    }
    $relativePath = Get-RelativePath -Root $resolvedPayloadRoot -Path $file.FullName
    $relativeDirectory = Split-Path -Path $relativePath -Parent
    if ($relativeDirectory -eq ".") {
        $relativeDirectory = ""
    }
    $directoryNode = if ([string]::IsNullOrWhiteSpace($relativeDirectory)) {
        $rootNode
    } else {
        Find-OrCreateDirectoryNode -RootNode $rootNode -RelativeDirectory $relativeDirectory
    }
    [void]$directoryNode.Files.Add([pscustomobject]@{
            FullPath = $file.FullName
            RelativePath = $relativePath
        })
    $directoryId = if ([string]::IsNullOrWhiteSpace($relativeDirectory)) { "INSTALLDIR" } else { New-WixId -Prefix "DIR" -Value $relativeDirectory }
    $components.Add([pscustomobject]@{
            ComponentId = New-WixId -Prefix "CMP" -Value $relativePath
            FileId = New-WixId -Prefix "FIL" -Value $relativePath
            DirectoryId = $directoryId
            SourcePath = $file.FullName
        }) | Out-Null
}

$wxsPath = Join-Path $resolvedOutputRoot "AegisSensor.generated.wxs"
$msiVersion = Convert-ToMsiVersion -Version $ProductVersion
$msiName = "AegisSensor-$BundleChannel-x64.msi"
$msiPath = Join-Path $resolvedOutputRoot $msiName

$settings = New-Object System.Xml.XmlWriterSettings
$settings.Indent = $true
$settings.OmitXmlDeclaration = $false
$writer = [System.Xml.XmlWriter]::Create($wxsPath, $settings)
try {
    $writer.WriteStartDocument()
    $writer.WriteStartElement("Wix", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteStartElement("Package", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Name", $ProductName)
    $writer.WriteAttributeString("Manufacturer", $Manufacturer)
    $writer.WriteAttributeString("Version", $msiVersion)
    $writer.WriteAttributeString("UpgradeCode", $UpgradeCode)
    $writer.WriteAttributeString("Language", "1033")
    $writer.WriteAttributeString("InstallerVersion", "500")
    $writer.WriteAttributeString("Scope", "perMachine")
    $writer.WriteAttributeString("Compressed", "yes")

    $writer.WriteStartElement("MediaTemplate", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteEndElement()

    $writer.WriteStartElement("Property", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "AegisStateRoot")
    $writer.WriteAttributeString("Value", [string]$manifest.state_root)
    $writer.WriteEndElement()

    $writer.WriteStartElement("Property", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "ARPNOREPAIR")
    $writer.WriteAttributeString("Value", "1")
    $writer.WriteEndElement()

    $writer.WriteStartElement("StandardDirectory", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "ProgramFiles64Folder")
    $writer.WriteStartElement("Directory", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "INSTALLDIR")
    $writer.WriteAttributeString("Name", "Aegis")
    Write-DirectoryTreeXml -Writer $writer -Node $rootNode
    $writer.WriteEndElement()
    $writer.WriteEndElement()

    $writer.WriteStartElement("ComponentGroup", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "ProductComponents")
    foreach ($component in $components) {
        $writer.WriteStartElement("Component", "http://wixtoolset.org/schemas/v4/wxs")
        $writer.WriteAttributeString("Id", $component.ComponentId)
        $writer.WriteAttributeString("Guid", "*")
        $writer.WriteAttributeString("Directory", $component.DirectoryId)
        $writer.WriteStartElement("File", "http://wixtoolset.org/schemas/v4/wxs")
        $writer.WriteAttributeString("Id", $component.FileId)
        $writer.WriteAttributeString("Source", $component.SourcePath)
        $writer.WriteAttributeString("KeyPath", "yes")
        $writer.WriteEndElement()
        $writer.WriteEndElement()
    }
    $writer.WriteEndElement()

    $writer.WriteStartElement("Feature", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "MainFeature")
    $writer.WriteAttributeString("Title", $ProductName)
    $writer.WriteAttributeString("Level", "1")
    $writer.WriteStartElement("ComponentGroupRef", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "ProductComponents")
    $writer.WriteEndElement()
    $writer.WriteEndElement()

    $installCommand = ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}install.ps1" -PayloadRoot "{1}." -ManifestPath "{1}manifest.json" -InstallRoot "{1}." -StateRoot "{2}" -PayloadAlreadyInstalled' -f '[System64Folder]WindowsPowerShell\v1.0\powershell.exe', '[INSTALLDIR]', '[AegisStateRoot]')
    $writer.WriteStartElement("SetProperty", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "AegisFinalizeInstall")
    $writer.WriteAttributeString("Value", $installCommand)
    $writer.WriteAttributeString("Before", "AegisFinalizeInstall")
    $writer.WriteAttributeString("Condition", "NOT Installed")
    $writer.WriteAttributeString("Sequence", "execute")
    $writer.WriteEndElement()

    $writer.WriteStartElement("CustomAction", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "AegisFinalizeInstall")
    $writer.WriteAttributeString("BinaryRef", "Wix4UtilCA_X64")
    $writer.WriteAttributeString("DllEntry", "WixQuietExec")
    $writer.WriteAttributeString("Execute", "deferred")
    $writer.WriteAttributeString("Impersonate", "no")
    $writer.WriteAttributeString("Return", "check")
    $writer.WriteEndElement()

    $uninstallCommand = ('"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}uninstall.ps1" -InstallRoot "{1}." -StateRoot "{2}" -ManifestPath "{1}manifest.json" -RemoveStateRoot -SkipInstallRootCleanup' -f '[System64Folder]WindowsPowerShell\v1.0\powershell.exe', '[INSTALLDIR]', '[AegisStateRoot]')
    $writer.WriteStartElement("SetProperty", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "AegisFinalizeUninstall")
    $writer.WriteAttributeString("Value", $uninstallCommand)
    $writer.WriteAttributeString("Before", "AegisFinalizeUninstall")
    $writer.WriteAttributeString("Condition", 'REMOVE="ALL"')
    $writer.WriteAttributeString("Sequence", "execute")
    $writer.WriteEndElement()

    $writer.WriteStartElement("CustomAction", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Id", "AegisFinalizeUninstall")
    $writer.WriteAttributeString("BinaryRef", "Wix4UtilCA_X64")
    $writer.WriteAttributeString("DllEntry", "WixQuietExec")
    $writer.WriteAttributeString("Execute", "deferred")
    $writer.WriteAttributeString("Impersonate", "no")
    $writer.WriteAttributeString("Return", "check")
    $writer.WriteEndElement()

    $writer.WriteStartElement("InstallExecuteSequence", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteStartElement("Custom", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Action", "AegisFinalizeInstall")
    $writer.WriteAttributeString("After", "InstallFiles")
    $writer.WriteAttributeString("Condition", "NOT Installed")
    $writer.WriteEndElement()
    $writer.WriteStartElement("Custom", "http://wixtoolset.org/schemas/v4/wxs")
    $writer.WriteAttributeString("Action", "AegisFinalizeUninstall")
    $writer.WriteAttributeString("Before", "RemoveFiles")
    $writer.WriteAttributeString("Condition", 'REMOVE="ALL"')
    $writer.WriteEndElement()
    $writer.WriteEndElement()

    $writer.WriteEndElement()
    $writer.WriteEndElement()
    $writer.WriteEndDocument()
} finally {
    $writer.Dispose()
}

$wixPath = Resolve-WixExecutable
Ensure-WixUtilExtension -WixPath $wixPath

Invoke-External -FilePath $wixPath -Arguments @(
    "build",
    $wxsPath,
    "-arch", "x64",
    "-ext", "WixToolset.Util.wixext",
    "-o", $msiPath
) | Out-Null

Invoke-External -FilePath $wixPath -Arguments @(
    "msi",
    "validate",
    $msiPath
) | Out-Null

if (-not (Test-Path -LiteralPath $msiPath)) {
    throw "msi build did not produce $msiPath"
}

if (-not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
    if ([string]::IsNullOrWhiteSpace($TimestampServer)) {
        throw "MSI signing requires TimestampServer"
    }
    Sign-MsiPackage -Path $msiPath -CertificateThumbprint $SigningCertificateThumbprint -CertificateStorePath $SigningCertificateStorePath -TimestampServer $TimestampServer
}

[ordered]@{
    built_at = (Get-Date).ToString("o")
    payload_root = $resolvedPayloadRoot
    wxs_path = $wxsPath
    msi_path = $msiPath
    bundle_channel = $BundleChannel
    product_version = $msiVersion
    wix_path = $wixPath
    signed = -not [string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)
} | ConvertTo-Json -Depth 5
