# AmneziaWG Windows payload

Kenai VPN pins the official AmneziaWG Windows 2.0.0 amd64 payload. The
application does not download or replace these files at runtime.

- Upstream: https://github.com/amnezia-vpn/amneziawg-windows-client
- Tag and source commit: `2.0.0` / `54fa022e2c40ed6d51f757e0871158372fb14977`
- Release asset: `amneziawg-amd64-2.0.0.msi`
- Published and locally verified MSI SHA-256:
  `8a6b4eb62a0bb8663ee50ba4253f5221da87f5b750640ddcf42f414dbef79933`
- MSI Authenticode signer: `Privacy Technologies OU` (valid when acquired)

Pinned extracted files:

| File | SHA-256 | Authenticode signer |
| --- | --- | --- |
| `amneziawg.exe` | `5b00905ed02619fe149ceafc898e79993d4455a0cdfa92072b3bb9aee7b2d537` | Privacy Technologies OU |
| `awg.exe` | `26ac0be14a8353eacf2f933736f6f7912f89ec7c59c4190cc990492934c74537` | Privacy Technologies OU |
| `wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` | WireGuard LLC |

`LICENSE-amneziawg-windows.txt` is the upstream MIT license. `LICENSE-wintun.txt`
is the license shipped with the pinned Wintun binary. Redistribution of Wintun
is only as a component used through its permitted API; do not redistribute it
as a standalone payload.
