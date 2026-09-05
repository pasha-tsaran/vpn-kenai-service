# AmneziaWG 2.0 Windows engine

Stage 13 adds AmneziaWG as a distinct engine. It does not translate the
profile to WireGuard and does not reuse the WireGuard tunnel implementation.

## Trust and privilege boundary

The Flutter GUI parses the server profile into a bounded, typed IPC v3
message. It cannot select an executable, service name, path, command, route or
DNS command. The elevated `KenaiVpnService` validates the profile again,
encrypts it with machine DPAPI, and returns only an opaque `awg-...` handle.
Activation keys, private keys and complete profiles are never logged.

On connect, the Windows service loads the encrypted profile and renders a
short-lived fixed `%ProgramData%\KenaiVPN\runtime\KenaiAwg.conf`. It verifies
the pinned hashes, creates only `AmneziaWGTunnel$KenaiAwg`, and starts the
official signed `amneziawg.exe /tunnelservice` process through SCM. The config
is deleted after the service reaches Running. Disconnect, startup recovery and
failed-connect cleanup stop/delete that exact service and remove fixed runtime
files. WireGuard and AmneziaWG are mutually exclusive in the service backend.

Statistics come from the fixed, hash-verified `awg.exe show KenaiAwg dump`
query. Arguments are constants; no GUI or caller-selected process invocation
is accepted. Output is bounded and only counters/handshake time cross IPC.

## Supported AWG 2.0 fields

The v3 contract extends WireGuard network fields only with `Jc`, `Jmin`,
`Jmax`, `S1`-`S4`, `H1`-`H4` and optional `I1`-`I5`. Unknown directives,
duplicate scalar fields, invalid ranges, control characters and oversized
values are rejected at both boundaries. Kill switch remains disabled for this
MVP rather than being shown as supported without an independently verified
implementation.

## Supply chain

The committed amd64 files are extracted from the official 2.0.0 MSI. Their
release, source commit, hashes, signatures and licenses are recorded in
`third_party/amneziawg/README.md` and checked by `tool/verify-stage13.ps1`.
The installer must preserve this side-by-side directory; clean-machine
installation testing remains stage 16.
