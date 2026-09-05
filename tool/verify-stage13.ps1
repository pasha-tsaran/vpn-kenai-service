$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$RepoRoot = Split-Path -Parent $PSScriptRoot
$PayloadRoot = Join-Path $RepoRoot 'third_party\amneziawg\windows\amd64'
$Expected = @{
    'amneziawg.exe' = '5b00905ed02619fe149ceafc898e79993d4455a0cdfa92072b3bb9aee7b2d537'
    'awg.exe' = '26ac0be14a8353eacf2f933736f6f7912f89ec7c59c4190cc990492934c74537'
    'wintun.dll' = 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce'
}
foreach ($Name in $Expected.Keys) {
    $Path = Join-Path $PayloadRoot $Name
    if (-not (Test-Path -LiteralPath $Path)) { throw "Missing AmneziaWG payload: $Name" }
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Expected[$Name]) {
        throw "AmneziaWG payload hash mismatch: $Name"
    }
    $Signature = Get-AuthenticodeSignature -LiteralPath $Path
    $Signer = if ($Name -eq 'wintun.dll') { 'CN=WireGuard LLC' } else { 'Privacy Technologies OU' }
    if ($Signature.Status -ne 'Valid' -or $Signature.SignerCertificate.Subject -notmatch $Signer) {
        throw "AmneziaWG payload signature mismatch: $Name"
    }
}
function Require-Text([string]$Path, [string]$Pattern) {
    $Resolved = Join-Path $RepoRoot $Path
    if (-not (Select-String -LiteralPath $Resolved -Pattern $Pattern -Quiet)) { throw "Missing stage 13 marker: $Path" }
}
Require-Text 'crates/vpn_contracts/src/lib.rs' 'CONTRACT_VERSION: u32 = [34]'
Require-Text 'services/windows_vpn_service/src/amneziawg_engine.rs' 'AmneziaWGTunnel\$KenaiAwg'
Require-Text 'services/windows_vpn_service/src/amneziawg_engine.rs' '"/tunnelservice"'
Require-Text 'services/windows_vpn_service/src/windows_backend.rs' 'self\.wireguard\.disconnect'
Require-Text 'apps/desktop/lib/src/infrastructure/windows_vpn_engine.dart' 'VpnProtocol\.amneziaWg'
Require-Text 'packages/kenai_core/lib/src/application/secure_account_repository.dart' 'amneziaWgProfileHandle'
Require-Text 'docs/architecture/0011-amneziawg-2-windows-engine.md' 'does not translate the'
Write-Host 'Stage 13 AmneziaWG 2.0 verification passed.'
