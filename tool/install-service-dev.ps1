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
    New-Service `
        -Name $serviceName `
        -DisplayName 'Kenai VPN Service (Development)' `
        -Description 'Typed local control boundary for Kenai VPN; VPN engines are not installed.' `
        -BinaryPathName ('"{0}"' -f $resolvedBinary) `
        -StartupType Manual | Out-Null
    Write-Output "$serviceName installed with Manual startup. It was not started."
}
