# Xray-core Windows payload

Kenai VPN pins the official Xray-core Windows x64 release. The application
does not download or replace these files at runtime.

- Upstream: https://github.com/XTLS/Xray-core
- Release: `v26.3.27`
- Release asset: `Xray-windows-64.zip`
- Official archive SHA-256:
  `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad`
- Source tag: https://github.com/XTLS/Xray-core/tree/v26.3.27

Pinned extracted files:

| File | SHA-256 | Authenticode |
| --- | --- | --- |
| `xray.exe` | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` | Not signed upstream; trust is the pinned official release digest and verified GitHub release tag |
| `wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` | Valid, WireGuard LLC |

`LICENSE-xray-core.txt` is the upstream Mozilla Public License 2.0.
`LICENSE-wintun.txt` is the license shipped with the release. Wintun is
redistributed only as a component used through its permitted API, not as a
standalone product.
