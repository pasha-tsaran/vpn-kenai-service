[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath
)

$ErrorActionPreference = 'Stop'
$serviceName = 'KenaiVpnService'
$resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
if ([System.IO.Path]::GetExtension($resolvedBinary) -ne '.exe') {
    throw 'BinaryPath must point to a Windows executable.'
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$payloadSource = Join-Path $repoRoot 'third_party\wireguard\windows\amd64'
$payloadDestination = Join-Path (Split-Path -Parent $resolvedBinary) 'wireguard\amd64'
$expectedHashes = @{
    'tunnel.dll' = '5533cf9cb741d5e9daa7f429aa1c56beba4a500934877c9d072f721f512583ca'
    'wireguard.dll' = 'b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3'
}
foreach ($name in $expectedHashes.Keys) {
    $source = Join-Path $payloadSource $name
    $actual = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expectedHashes[$name]) {
        throw "WireGuard payload hash mismatch: $name"
    }
}
$driverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $payloadSource 'wireguard.dll')
if ($driverSignature.Status -ne 'Valid' -or
    $driverSignature.SignerCertificate.Subject -notmatch 'CN=WireGuard LLC') {
    throw 'wireguard.dll does not have the expected valid WireGuard LLC signature.'
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this development installation script from an elevated PowerShell session.'
}

if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "$serviceName already exists. Remove it explicitly before reinstalling."
}

if ($PSCmdlet.ShouldProcess($serviceName, "Install service from $resolvedBinary")) {
    New-Item -ItemType Directory -Path $payloadDestination -Force | Out-Null
    foreach ($name in $expectedHashes.Keys) {
        Copy-Item -LiteralPath (Join-Path $payloadSource $name) `
            -Destination (Join-Path $payloadDestination $name) -Force
    }
    New-Service `
        -Name $serviceName `
        -DisplayName 'Kenai VPN Service (Development)' `
        -Description 'Typed local control boundary for the Kenai VPN WireGuard engine.' `
        -BinaryPathName ('"{0}"' -f $resolvedBinary) `
        -StartupType Manual | Out-Null
    Write-Output "$serviceName installed with Manual startup. It was not started."
}
