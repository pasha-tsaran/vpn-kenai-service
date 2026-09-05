# Xray VLESS + REALITY Windows engine

Stage 14 adds Xray-core as the third independent Windows VPN engine. It uses
Xray's Windows TUN inbound and a VLESS `xtls-rprx-vision` outbound protected by
REALITY. It is not represented as WireGuard or AmneziaWG.

## Data and privilege boundaries

The production activation response contains the server-issued VLESS URI. The
unprivileged Flutter adapter accepts only the server contract's exact fields:
`type=raw`, `security=reality`, `flow=xtls-rprx-vision`, `sni`, `fp=chrome`,
`pbk` and `sid`. UUID, hosts, port, REALITY password and short ID are validated
and sent through typed IPC v4. Arbitrary paths, commands, arguments and extra
query fields are rejected.

The elevated service validates the typed profile again, encrypts it with
machine DPAPI under the service-only profile directory and returns an opaque
`xray-...` handle. Activation and sign-out rollback delete the handle. The GUI
does not persist the VLESS URI after provisioning. Debug output redacts the
UUID and REALITY password; Xray logging is disabled.

## Process, routing and cleanup

The service verifies pinned SHA-256 hashes and starts only the fixed
side-by-side `xray/amd64/xray.exe` with constant `run -config` arguments. The
configuration path is service-selected under `%ProgramData%\KenaiVPN\runtime`
with a SYSTEM/Administrators ACL. Xray first validates it with `run -test`.

The fixed TUN policy supplies IPv4 and IPv6 gateways, Cloudflare DNS,
`0.0.0.0/0` and `::/0` system routes, and automatic outbound-interface
selection to avoid routing the proxy transport back into its own TUN. The
plaintext runtime configuration is deleted after startup and on every failure
or disconnect.

Xray is assigned to a Windows Job Object with `KILL_ON_JOB_CLOSE`. Explicit
disconnect terminates and waits for the job; service crash or shutdown closes
the last job handle and Windows terminates Xray. The common backend disconnects
WireGuard and AmneziaWG before starting Xray, so only one Kenai tunnel can be
active.

Kill switch remains unavailable until a separately leak-tested WFP policy is
implemented. Xray's statistics API is not exposed in this minimal stage, so a
running Xray connection reports zero byte counters and no handshake timestamp;
the UI must not interpret those counters as measured traffic. Actual endpoint,
external-IP, DNS and sleep/restart tests remain part of the clean-VM MVP gate.

## Supply chain

The official Xray-core `v26.3.27` Windows x64 release is pinned. `xray.exe` is
not Authenticode-signed upstream, so the project does not claim that it is;
trust is based on the official published archive digest, exact executable hash
and verified release tag. The bundled Wintun DLL has a valid WireGuard LLC
signature. Provenance, hashes and MPL-2.0/Wintun license notices are recorded
in `third_party/xray/README.md` and enforced by `tool/verify-stage14.ps1`.
