param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,
    [string]$ManifestPath = (Join-Path $BundleRoot "manifest.json"),
    [Parameter(Mandatory = $true)]
    [string]$CertificateThumbprint,
    [string]$CertificateStorePath = "Cert:\CurrentUser\My",
    [Parameter(Mandatory = $true)]
    [string]$TimestampServer,
    [Parameter(Mandatory = $true)]
    [string]$ElamApprovalPath,
    [Parameter(Mandatory = $true)]
    [string]$WatchdogPplApprovalPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Security

trap {
    if ($_.Exception -and -not [string]::IsNullOrWhiteSpace($_.Exception.Message)) {
        Write-Error $_.Exception.Message
    }
    if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
        Write-Error $_.InvocationInfo.PositionMessage
    }
    throw
}

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

function Get-Manifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-ExistingPath -Path $Path -Description "windows install manifest"
    $manifest = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.bundle_channel -ne "release") {
        throw "windows signing requires release manifest, got bundle_channel=$($manifest.bundle_channel)"
    }
    if ($null -eq $manifest.components -or $manifest.components.Count -lt 1) {
        throw "windows install manifest has no components"
    }
    $manifest
}

function Normalize-Thumbprint {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    ($Thumbprint -replace '\s', '').ToUpperInvariant()
}

function Resolve-CodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$Thumbprint,
        [Parameter(Mandatory = $true)][string]$StorePath
    )

    $normalizedThumbprint = Normalize-Thumbprint -Thumbprint $Thumbprint
    $certificates = @(
        Get-ChildItem -Path $StorePath -ErrorAction Stop |
            Where-Object { $_.Thumbprint -eq $normalizedThumbprint }
    )
    if ($certificates.Count -ne 1) {
        throw "unable to resolve unique code signing certificate: $normalizedThumbprint"
    }

    $certificate = $certificates[0]
    if (-not $certificate.HasPrivateKey) {
        throw "certificate $normalizedThumbprint does not expose a private key"
    }

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $hasCodeSigningUsage = $false
    foreach ($extension in $certificate.Extensions) {
        if ($extension -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            foreach ($eku in $extension.EnhancedKeyUsages) {
                if ($eku.Value -eq $codeSigningOid) {
                    $hasCodeSigningUsage = $true
                    break
                }
            }
        }
        if ($hasCodeSigningUsage) {
            break
        }
    }
    if (-not $hasCodeSigningUsage) {
        throw "certificate $normalizedThumbprint is not valid for code signing"
    }

    $certificate
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

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-RelativeBundlePath {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$AbsolutePath
    )

    $resolvedBundleRoot = Resolve-ExistingPath -Path $BundleRoot -Description "bundle root"
    $resolvedAbsolutePath = Resolve-ExistingPath -Path $AbsolutePath -Description "bundle artifact"

    $bundleRootWithSeparator = $resolvedBundleRoot
    if (-not $bundleRootWithSeparator.EndsWith('\') -and -not $bundleRootWithSeparator.EndsWith('/')) {
        $bundleRootWithSeparator += '\'
    }

    $bundleUri = New-Object System.Uri($bundleRootWithSeparator)
    $artifactUri = New-Object System.Uri($resolvedAbsolutePath)
    $relativeUri = $bundleUri.MakeRelativeUri($artifactUri)
    [System.Uri]::UnescapeDataString($relativeUri.ToString()).Replace('\', '/')
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $false)][string[]]$Arguments = @()
    )

    $commandOutput = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        $message = ($commandOutput | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($message)) {
            $message = "command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
        }
        throw $message
    }
}

function Test-AuthenticodeSignatureValid {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "invalid Authenticode signature for ${Path}: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "missing signer certificate for ${Path}"
    }
    if ((Normalize-Thumbprint -Thumbprint $signature.SignerCertificate.Thumbprint) -ne
        (Normalize-Thumbprint -Thumbprint $Certificate.Thumbprint)) {
        throw "signature thumbprint mismatch for ${Path}"
    }
}

function Sign-PortableExecutable {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$SignToolPath,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$TimestampServer
    )

    Invoke-External -FilePath $SignToolPath -Arguments @(
        "sign",
        "/fd", "SHA256",
        "/t", $TimestampServer,
        "/sha1", $Certificate.Thumbprint,
        $Path
    )
    Test-AuthenticodeSignatureValid -Path $Path -Certificate $Certificate
}

function Sign-PowerShellScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$TimestampServer
    )

    $signature = Set-AuthenticodeSignature -FilePath $Path -Certificate $Certificate -TimestampServer $TimestampServer -HashAlgorithm SHA256
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "invalid PowerShell signature for ${Path}: $($signature.Status)"
    }
    Test-AuthenticodeSignatureValid -Path $Path -Certificate $Certificate
}

function Add-ArtifactRecord {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Collection,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$RequiresAuthenticode
    )

    $Collection.Add([ordered]@{
            name = $Name
            kind = $Kind
            relative_path = Get-RelativeBundlePath -BundleRoot $BundleRoot -AbsolutePath $Path
            sha256 = Get-FileSha256 -Path $Path
            requires_authenticode = $RequiresAuthenticode
        }) | Out-Null
}

function Add-DriverArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$DriverRoot,
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$SignToolPath,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$TimestampServer,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Artifacts
    )

    $driverFiles = @(Get-ChildItem -LiteralPath $DriverRoot -Recurse -File -ErrorAction Stop)
    $sysFiles = @($driverFiles | Where-Object { $_.Extension -ieq ".sys" })
    $catFiles = @($driverFiles | Where-Object { $_.Extension -ieq ".cat" })
    $infFiles = @($driverFiles | Where-Object { $_.Extension -ieq ".inf" })

    if ($sysFiles.Count -lt 1) {
        throw "driver bundle is missing .sys artifacts under $DriverRoot"
    }
    if ($catFiles.Count -lt 1) {
        throw "driver bundle is missing .cat artifacts under $DriverRoot"
    }

    foreach ($file in $sysFiles) {
        Sign-PortableExecutable -Path $file.FullName -SignToolPath $SignToolPath -Certificate $Certificate -TimestampServer $TimestampServer
        Add-ArtifactRecord -Collection $Artifacts -Name $file.BaseName -Kind "driver-binary" -BundleRoot $BundleRoot -Path $file.FullName -RequiresAuthenticode $true
    }
    foreach ($file in $catFiles) {
        Sign-PortableExecutable -Path $file.FullName -SignToolPath $SignToolPath -Certificate $Certificate -TimestampServer $TimestampServer
        Add-ArtifactRecord -Collection $Artifacts -Name $file.BaseName -Kind "driver-catalog" -BundleRoot $BundleRoot -Path $file.FullName -RequiresAuthenticode $true
    }
    foreach ($file in $infFiles) {
        Add-ArtifactRecord -Collection $Artifacts -Name $file.BaseName -Kind "driver-inf" -BundleRoot $BundleRoot -Path $file.FullName -RequiresAuthenticode $false
    }
}

function Copy-ApprovalRecord {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Approvals
    )

    $resolvedSource = Resolve-ExistingPath -Path $SourcePath -Description "$Name approval"
    $content = Get-Content -LiteralPath $resolvedSource -Raw
    if ([string]::IsNullOrWhiteSpace($content)) {
        throw "approval file is empty: $resolvedSource"
    }

    $destinationParent = Split-Path -Path $DestinationPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($destinationParent)) {
        Ensure-Directory -Path $destinationParent | Out-Null
    }
    Copy-Item -LiteralPath $resolvedSource -Destination $DestinationPath -Force

    $Approvals.Add([ordered]@{
            name = $Name
            relative_path = Get-RelativeBundlePath -BundleRoot $BundleRoot -AbsolutePath $DestinationPath
            sha256 = Get-FileSha256 -Path $DestinationPath
        }) | Out-Null
}

function Write-CmsDetachedSignature {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Content,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $contentInfoConstructor = [System.Security.Cryptography.Pkcs.ContentInfo].GetConstructor(@([byte[]]))
    $signedCmsConstructor = [System.Security.Cryptography.Pkcs.SignedCms].GetConstructor(@([System.Security.Cryptography.Pkcs.ContentInfo], [bool]))
    $cmsSignerConstructor = [System.Security.Cryptography.Pkcs.CmsSigner].GetConstructor(@([System.Security.Cryptography.X509Certificates.X509Certificate2]))
    if ($null -eq $contentInfoConstructor -or $null -eq $signedCmsConstructor -or $null -eq $cmsSignerConstructor) {
        throw "required CMS constructors are unavailable on this PowerShell host"
    }

    try {
        $contentInfo = $contentInfoConstructor.Invoke(@(,[byte[]]$Content))
    } catch {
        throw "failed to create CMS content info: $($_.Exception.Message)"
    }
    try {
        $signedCms = $signedCmsConstructor.Invoke(@($contentInfo, $true))
    } catch {
        throw "failed to create SignedCms instance: $($_.Exception.Message)"
    }
    try {
        $cmsSigner = $cmsSignerConstructor.Invoke(@($Certificate))
    } catch {
        throw "failed to create CmsSigner instance: $($_.Exception.Message)"
    }
    $cmsSigner.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::EndCertOnly
    try {
        $signedCms.ComputeSignature($cmsSigner)
    } catch {
        throw "failed to compute CMS signature: $($_.Exception.Message)"
    }
    [System.IO.File]::WriteAllBytes($OutputPath, $signedCms.Encode())
}

$resolvedBundleRoot = Resolve-ExistingPath -Path $BundleRoot -Description "bundle root"
$resolvedManifestPath = Resolve-ExistingPath -Path $ManifestPath -Description "windows install manifest"
$manifest = Get-Manifest -Path $resolvedManifestPath
$certificate = Resolve-CodeSigningCertificate -Thumbprint $CertificateThumbprint -StorePath $CertificateStorePath
$signToolPath = Resolve-SignToolPath
$metadataRoot = Ensure-Directory -Path (Join-Path $resolvedBundleRoot "metadata")
$artifacts = New-Object System.Collections.Generic.List[object]
$approvals = New-Object System.Collections.Generic.List[object]

Add-ArtifactRecord -Collection $artifacts -Name "manifest" -Kind "manifest" -BundleRoot $resolvedBundleRoot -Path $resolvedManifestPath -RequiresAuthenticode $false

foreach ($component in @($manifest.components)) {
    $componentPath = Resolve-ExistingPath -Path (Join-Path $resolvedBundleRoot $component.source_relative_path) -Description "bundle component $($component.name)"
    switch ([string]$component.kind) {
        "binary" {
            Sign-PortableExecutable -Path $componentPath -SignToolPath $signToolPath -Certificate $certificate -TimestampServer $TimestampServer
            Add-ArtifactRecord -Collection $artifacts -Name $component.name -Kind "binary" -BundleRoot $resolvedBundleRoot -Path $componentPath -RequiresAuthenticode $true
        }
        "script" {
            Sign-PowerShellScript -Path $componentPath -Certificate $certificate -TimestampServer $TimestampServer
            Add-ArtifactRecord -Collection $artifacts -Name $component.name -Kind "script" -BundleRoot $resolvedBundleRoot -Path $componentPath -RequiresAuthenticode $true
        }
        "driver" {
            Add-DriverArtifacts -DriverRoot $componentPath -BundleRoot $resolvedBundleRoot -SignToolPath $signToolPath -Certificate $certificate -TimestampServer $TimestampServer -Artifacts $artifacts
        }
        default {
            throw "unsupported manifest component kind for signing: $($component.kind)"
        }
    }
}

Copy-ApprovalRecord `
    -SourcePath $ElamApprovalPath `
    -DestinationPath (Join-Path $metadataRoot "elam-approved.txt") `
    -Name "elam_approval" `
    -BundleRoot $resolvedBundleRoot `
    -Approvals $approvals
Copy-ApprovalRecord `
    -SourcePath $WatchdogPplApprovalPath `
    -DestinationPath (Join-Path $metadataRoot "ppl-approved.txt") `
    -Name "watchdog_ppl_approval" `
    -BundleRoot $resolvedBundleRoot `
    -Approvals $approvals

$receiptPath = Join-Path $metadataRoot "signed-release.json"
$receiptSignaturePath = Join-Path $metadataRoot "signed-release.cms"
$artifactRecords = @($artifacts | ForEach-Object { [pscustomobject]$_ })
$approvalRecords = @($approvals | ForEach-Object { [pscustomobject]$_ })
$receipt = [pscustomobject]@{
    schema_version = 1
    bundle_channel = "release"
    generated_at = (Get-Date).ToString("o")
    certificate_subject = $certificate.Subject
    certificate_thumbprint = (Normalize-Thumbprint -Thumbprint $certificate.Thumbprint)
    timestamp_server = $TimestampServer
    artifacts = $artifactRecords
    approvals = $approvalRecords
}
$receiptJson = $receipt | ConvertTo-Json -Depth 8
$utf8Encoding = New-Object System.Text.UTF8Encoding -ArgumentList $false
$receiptBytes = $utf8Encoding.GetBytes($receiptJson)
[System.IO.File]::WriteAllBytes($receiptPath, $receiptBytes)
Write-CmsDetachedSignature -Content $receiptBytes -Certificate $certificate -OutputPath $receiptSignaturePath

[pscustomobject]@{
    signed_at = (Get-Date).ToString("o")
    bundle_root = $resolvedBundleRoot
    manifest_path = $resolvedManifestPath
    certificate_subject = $certificate.Subject
    certificate_thumbprint = (Normalize-Thumbprint -Thumbprint $certificate.Thumbprint)
    timestamp_server = $TimestampServer
    signtool_path = $signToolPath
    release_receipt_path = $receiptPath
    release_signature_path = $receiptSignaturePath
    artifact_count = $artifacts.Count
    approval_count = $approvals.Count
    artifacts = $artifactRecords
    approvals = $approvalRecords
} | ConvertTo-Json -Depth 8
