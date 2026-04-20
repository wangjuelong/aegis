param(
    [Parameter(Mandatory = $true)]
    [string]$BundleRoot,
    [string]$ManifestPath = (Join-Path $BundleRoot "manifest.json"),
    [string]$ExpectedCertificateThumbprint
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

function Normalize-Thumbprint {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)
    ($Thumbprint -replace '\s', '').ToUpperInvariant()
}

function Get-Manifest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = Resolve-ExistingPath -Path $Path -Description "windows install manifest"
    $manifest = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($manifest.bundle_channel -ne "release") {
        throw "release verification requires bundle_channel=release, got $($manifest.bundle_channel)"
    }
    $manifest
}

function Get-FileSha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Resolve-BundleRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$BundleRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Resolve-ExistingPath -Path (Join-Path $BundleRoot $RelativePath) -Description $Description
}

function Load-ReleaseReceipt {
    param([Parameter(Mandatory = $true)][string]$ReceiptPath)

    $receipt = Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json -ErrorAction Stop
    if ($receipt.schema_version -ne 1) {
        throw "unsupported release receipt schema version: $($receipt.schema_version)"
    }
    if ($receipt.bundle_channel -ne "release") {
        throw "release receipt bundle_channel mismatch: $($receipt.bundle_channel)"
    }
    if ($null -eq $receipt.artifacts -or $receipt.artifacts.Count -lt 1) {
        throw "release receipt has no artifacts"
    }
    $receipt
}

function Verify-CmsSignature {
    param(
        [Parameter(Mandatory = $true)][string]$ReceiptPath,
        [Parameter(Mandatory = $true)][string]$SignaturePath
    )

    $receiptBytes = [System.IO.File]::ReadAllBytes($ReceiptPath)
    $signatureBytes = [System.IO.File]::ReadAllBytes($SignaturePath)
    $contentInfoConstructor = [System.Security.Cryptography.Pkcs.ContentInfo].GetConstructor(@([byte[]]))
    $signedCmsConstructor = [System.Security.Cryptography.Pkcs.SignedCms].GetConstructor(@([System.Security.Cryptography.Pkcs.ContentInfo], [bool]))
    if ($null -eq $contentInfoConstructor -or $null -eq $signedCmsConstructor) {
        throw "required CMS constructors are unavailable on this PowerShell host"
    }

    try {
        $contentInfo = $contentInfoConstructor.Invoke(@(,[byte[]]$receiptBytes))
    } catch {
        throw "failed to create CMS content info: $($_.Exception.Message)"
    }
    try {
        $signedCms = $signedCmsConstructor.Invoke(@($contentInfo, $true))
    } catch {
        throw "failed to create SignedCms instance: $($_.Exception.Message)"
    }
    try {
        $signedCms.Decode($signatureBytes)
    } catch {
        throw "failed to decode CMS signature: $($_.Exception.Message)"
    }
    try {
        $signedCms.CheckSignature($true)
    } catch {
        throw "failed to validate CMS signature: $($_.Exception.Message)"
    }

    if ($signedCms.SignerInfos.Count -ne 1) {
        throw "release receipt must contain exactly one signer"
    }
    $signerCertificate = $signedCms.SignerInfos[0].Certificate
    if ($null -eq $signerCertificate) {
        throw "release receipt is missing signer certificate"
    }
    $signerCertificate
}

function Verify-AuthenticodeArtifact {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "invalid Authenticode signature for ${Path}: $($signature.Status)"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "missing signer certificate for ${Path}"
    }
    $actualThumbprint = Normalize-Thumbprint -Thumbprint $signature.SignerCertificate.Thumbprint
    if ($actualThumbprint -ne $ExpectedThumbprint) {
        throw "signature thumbprint mismatch for ${Path}: expected ${ExpectedThumbprint}, got ${actualThumbprint}"
    }
    [ordered]@{
        status = "Valid"
        certificate_thumbprint = $actualThumbprint
        certificate_subject = $signature.SignerCertificate.Subject
    }
}

$resolvedBundleRoot = Resolve-ExistingPath -Path $BundleRoot -Description "bundle root"
$resolvedManifestPath = Resolve-ExistingPath -Path $ManifestPath -Description "windows install manifest"
$manifest = Get-Manifest -Path $resolvedManifestPath
$receiptPath = Resolve-BundleRelativePath -BundleRoot $resolvedBundleRoot -RelativePath "metadata/signed-release.json" -Description "release receipt"
$signaturePath = Resolve-BundleRelativePath -BundleRoot $resolvedBundleRoot -RelativePath "metadata/signed-release.cms" -Description "release receipt signature"
$receipt = Load-ReleaseReceipt -ReceiptPath $receiptPath
$signerCertificate = Verify-CmsSignature -ReceiptPath $receiptPath -SignaturePath $signaturePath
$signerThumbprint = Normalize-Thumbprint -Thumbprint $signerCertificate.Thumbprint

if (-not [string]::IsNullOrWhiteSpace($ExpectedCertificateThumbprint)) {
    $normalizedExpectedThumbprint = Normalize-Thumbprint -Thumbprint $ExpectedCertificateThumbprint
    if ($signerThumbprint -ne $normalizedExpectedThumbprint) {
        throw "release signer thumbprint mismatch: expected ${normalizedExpectedThumbprint}, got ${signerThumbprint}"
    }
}

if ($signerThumbprint -ne (Normalize-Thumbprint -Thumbprint $receipt.certificate_thumbprint)) {
    throw "release receipt thumbprint does not match CMS signer"
}

$artifactReports = New-Object System.Collections.Generic.List[object]
foreach ($artifact in @($receipt.artifacts)) {
    $resolvedArtifactPath = Resolve-BundleRelativePath `
        -BundleRoot $resolvedBundleRoot `
        -RelativePath ([string]$artifact.relative_path) `
        -Description "release artifact $($artifact.name)"
    $actualHash = Get-FileSha256 -Path $resolvedArtifactPath
    if ($actualHash -ne ([string]$artifact.sha256).ToLowerInvariant()) {
        throw "release artifact hash mismatch: $($artifact.relative_path)"
    }

    $signatureReport = $null
    if ([bool]$artifact.requires_authenticode) {
        $signatureReport = Verify-AuthenticodeArtifact -Path $resolvedArtifactPath -ExpectedThumbprint $signerThumbprint
    }

    $artifactReports.Add([ordered]@{
            name = $artifact.name
            kind = $artifact.kind
            relative_path = $artifact.relative_path
            sha256 = $artifact.sha256
            requires_authenticode = [bool]$artifact.requires_authenticode
            signature = $signatureReport
        }) | Out-Null
}

$approvalReports = New-Object System.Collections.Generic.List[object]
foreach ($approval in @($receipt.approvals)) {
    $resolvedApprovalPath = Resolve-BundleRelativePath `
        -BundleRoot $resolvedBundleRoot `
        -RelativePath ([string]$approval.relative_path) `
        -Description "release approval $($approval.name)"
    $approvalContent = Get-Content -LiteralPath $resolvedApprovalPath -Raw
    if ([string]::IsNullOrWhiteSpace($approvalContent)) {
        throw "release approval is empty: $($approval.relative_path)"
    }
    $actualHash = Get-FileSha256 -Path $resolvedApprovalPath
    if ($actualHash -ne ([string]$approval.sha256).ToLowerInvariant()) {
        throw "release approval hash mismatch: $($approval.relative_path)"
    }

    $approvalReports.Add([ordered]@{
            name = $approval.name
            relative_path = $approval.relative_path
            sha256 = $approval.sha256
        }) | Out-Null
}

$dependencyReports = New-Object System.Collections.Generic.List[object]
foreach ($dependency in @($manifest.release_dependencies)) {
    if ([string]::IsNullOrWhiteSpace([string]$dependency.install_relative_path)) {
        throw "release dependency $($dependency.name) is missing install_relative_path"
    }
    $resolvedDependencyPath = Resolve-BundleRelativePath `
        -BundleRoot $resolvedBundleRoot `
        -RelativePath ([string]$dependency.install_relative_path) `
        -Description "release dependency $($dependency.name)"
    $dependencyReports.Add([ordered]@{
            name = $dependency.name
            required = [bool]$dependency.required
            relative_path = $dependency.install_relative_path
            exists = $true
            detail = if ($dependency.detail) { $dependency.detail } else { $resolvedDependencyPath }
        }) | Out-Null
}

$artifactReportRecords = @($artifactReports | ForEach-Object { [pscustomobject]$_ })
$approvalReportRecords = @($approvalReports | ForEach-Object { [pscustomobject]$_ })
$dependencyReportRecords = @($dependencyReports | ForEach-Object { [pscustomobject]$_ })

[pscustomobject]@{
    validated_at = (Get-Date).ToString("o")
    bundle_root = $resolvedBundleRoot
    manifest_path = $resolvedManifestPath
    receipt_path = $receiptPath
    receipt_signature_path = $signaturePath
    certificate_subject = $signerCertificate.Subject
    certificate_thumbprint = $signerThumbprint
    artifact_count = $artifactReportRecords.Count
    approval_count = $approvalReportRecords.Count
    dependency_count = $dependencyReportRecords.Count
    artifacts = $artifactReportRecords
    approvals = $approvalReportRecords
    release_dependencies = $dependencyReportRecords
    verified = $true
} | ConvertTo-Json -Depth 8
