# Kenai VPN Client

Windows-first, cross-platform-ready client scaffold for Kenai VPN.

Этап 6 добавляет локальные журналы, централизованную редакцию секретов,
диагностический отчёт и ручной ZIP-экспорт. Автоматической отправки логов нет.

Этапы 0–9 включают архитектурное решение, доменные модели, ports,
детерминированные mocks, Flutter-навигацию, экраны «Серверы», «Аккаунт» и
«Тарифы», минимальную Windows-службу, защищённый типизированный IPC и
production HTTPS-активацию, реальный WireGuard for Windows, AmneziaWG 2.0 и
VLESS + REALITY/Xray. Release-клиент создаёт туннель выбранного протокола через системную службу, но пока не
является готовым установщиком и не проводит оплату. HTTPS-клиент
активации обращается к production API только в release-сборке с явно заданным
`KENAI_API_BASE_URL`.

## Архитектура

- Flutter/Dart: presentation, navigation и непривилегированные use cases.
- Rust: общий service contract/state machine и привилегированная Windows-служба.
- WireGuard, AmneziaWG 2.0 и VLESS + REALITY/Xray реализованы отдельными адаптерами.
- Системная служба, а не UI, владеет tunnel lifecycle, routes и DNS.
- Секреты доступны только через реализацию `SecureStorage` для конкретной ОС.

Документы:

- [Выбор платформы и технологий](docs/architecture/0001-platform-and-technology.md)
- [Каркас этапа 1](docs/architecture/0002-stage-1-scaffold.md)
- [Экран «Серверы» и production-граница mocks](docs/architecture/0003-servers-screen.md)
- [Аккаунт, ключ и подписка](docs/architecture/0004-account-activation.md)
- [Требуемые изменения серверного API для этапа 3](docs/server-changes-required-stage3.md)
- [Тарифы и mock-оплата](docs/architecture/0005-tariffs-and-payments.md)
- [Требуемый серверный платёжный контракт](docs/server-payments-required-stage4.md)
- [Порядок этапов до минимально рабочего MVP](docs/continuation-prompts.md)
- [Настройки и mock VPN-адаптеры](docs/architecture/0006-vpn-settings-and-adapters.md)
- [Threat model VPN-движков](docs/security/vpn-engine-threat-model.md)
- [Минимальная Windows-служба](docs/architecture/windows-privileged-service.md)
- [Отчёт этапа 8: Windows-служба и IPC](docs/stage8-windows-service-report.md)
- [Production-активация этапа 9](docs/architecture/0008-production-activation.md)
- [Реальная граница server API](docs/server-api-boundary.md)
- [Production GUI и VPN IPC этапа 12](docs/architecture/0011-production-gui-ipc.md)
- [Логи, redaction pipeline и ZIP-экспорт](docs/architecture/0007-logs-and-diagnostics.md)
- [Релизный аудит этапа 7](docs/release-audit-stage7.md)
- [Требования к production-обновлениям, speed test и публичным ссылкам](docs/client-release-requirements.md)

## Структура

```text
apps/desktop/                 Flutter navigation shell
packages/kenai_core/          Domain, ports and deterministic mocks
packages/kenai_ui/            Shared design tokens
crates/vpn_contracts/         Versioned service messages
crates/vpn_service_core/      Pure finite-state machine
services/windows_vpn_service/ Windows SCM host and secured local named pipe
apps/desktop/windows/         Standard Flutter Windows runner
proto/                        Reference schema; Rust wire codec is authoritative for v4
docs/                         Architecture and API inventory
tool/                         Bootstrap and boundary verification
```

## Требования для разработки

- Flutter stable с Windows desktop support
- Dart SDK из Flutter
- Rust stable с rustfmt и clippy
- Git

Стандартный Windows host уже включён. Если generated-папка была удалена, её
можно восстановить после установки Flutter:

```powershell
powershell -NoProfile -File tool/bootstrap-windows.ps1
```

## Проверки

```powershell
flutter pub get
dart format --output=none --set-exit-if-changed apps packages
dart analyze .
flutter test packages/kenai_core
flutter test apps/desktop
cd apps/desktop
flutter build windows --debug
cd ../..
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
powershell -NoProfile -File tool/verify-stage1.ps1
powershell -NoProfile -File tool/verify-stage7.ps1
powershell -NoProfile -File tool/verify-stage9.ps1
powershell -NoProfile -File tool/verify-stage10.ps1
powershell -NoProfile -File tool/verify-stage11.ps1
powershell -NoProfile -File tool/verify-stage12.ps1
powershell -NoProfile -File tool/verify-stage13.ps1
powershell -NoProfile -File tool/verify-stage14.ps1
```

Stage 10 adds strict WireGuard configuration parsing plus typed profile
provisioning into the Windows service. Profiles are stored only as
DPAPI-encrypted blobs under a SYSTEM/Administrators-only directory and are
addressed by random opaque handles. The real tunnel engine was intentionally
disabled through stage 10.

Stage 11 integrates the official WireGuard for Windows embeddable service.
The privileged service verifies pinned DLL hashes, controls one fixed tunnel,
removes temporary plaintext after startup, and exposes traffic/handshake data
through bounded IPC.

Stage 12 connects the release GUI to the typed Windows VPN IPC. A successful
12-digit activation provisions an opaque service-side profile handle; only then
can the GUI request a real WireGuard connection. Payment, speed test and other
unfinished sections are hidden from the minimal release.

Stage 13 adds the separately pinned, signed AmneziaWG Windows 2.0.0 engine.
Activation provisions its AWG-only fields through IPC v3 into the service DPAPI
vault; the GUI retains only an opaque handle. The service owns its fixed SCM
tunnel lifecycle, DNS/routes, cleanup, recovery and safe traffic statistics.
Stage 14 adds the separately pinned Xray-core VLESS + REALITY engine through
IPC v4. The service owns its TUN routes, DNS, fixed process lifecycle and
DPAPI-encrypted profile. The GUI retains only an opaque handle. The upstream
Xray executable is not Authenticode-signed; its official-release provenance
and exact hashes are documented and enforced instead.

Запуск mock UI после bootstrap:

```powershell
cd apps/desktop
flutter run -d windows
```

Для проверки многосерверного UI в debug/profile-сборке:

```powershell
cd apps/desktop
flutter run -d windows --dart-define=KENAI_ENABLE_TEST_SERVERS=true
```

Дополнительные серверы имеют метку «Тестовый» и условно исключаются из release,
даже если при сборке ошибочно передан этот флаг.

В development mock UI кнопка подключения меняет только состояние в памяти. Системные
настройки, production-сервер и платёжные сервисы не затрагиваются.

Release-сборка production-активации требует HTTPS API URL:

```powershell
cd apps/desktop
flutter build windows --release --dart-define=KENAI_API_BASE_URL=https://api.example.com
```

Без `KENAI_API_BASE_URL` приложение собирается, но активация закрывается
безопасной ошибкой и не обращается к mock API.
