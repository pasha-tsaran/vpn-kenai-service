# Kenai VPN Client

Windows-first, cross-platform-ready client scaffold for Kenai VPN.

Этап 6 добавляет локальные журналы, централизованную редакцию секретов,
диагностический отчёт и ручной ZIP-экспорт. Автоматической отправки логов нет.

Этапы 0–9 включают архитектурное решение, доменные модели, ports,
детерминированные mocks, Flutter-навигацию, экраны «Серверы», «Аккаунт» и
«Тарифы», минимальную Windows-службу, защищённый типизированный IPC и
production HTTPS-активацию для WireGuard-first MVP.
Проект пока **не создаёт VPN-туннель и не проводит оплату**. HTTPS-клиент
активации обращается к production API только в release-сборке с явно заданным
`KENAI_API_BASE_URL`.

## Архитектура

- Flutter/Dart: presentation, navigation и непривилегированные use cases.
- Rust: общий service contract/state machine и минимальная Windows-служба без VPN-движка.
- Будущие WireGuard, AmneziaWG и Xray реализации — независимые адаптеры.
- Системная служба, а не UI, будет владеть tunnel lifecycle, routes, DNS и WFP.
- Секреты доступны только через реализацию `SecureStorage` для конкретной ОС.

Документы:

- [Выбор платформы и технологий](docs/architecture/0001-platform-and-technology.md)
- [Каркас этапа 1](docs/architecture/0002-stage-1-scaffold.md)
- [Экран «Серверы» и production-граница mocks](docs/architecture/0003-servers-screen.md)
- [Аккаунт, ключ и подписка](docs/architecture/0004-account-activation.md)
- [Требуемые изменения серверного API для этапа 3](docs/server-changes-required-stage3.md)
- [Тарифы и mock-оплата](docs/architecture/0005-tariffs-and-payments.md)
- [Требуемый серверный платёжный контракт](docs/server-payments-required-stage4.md)
- [Порядок этапов до WireGuard-first MVP](docs/continuation-prompts.md)
- [Настройки и mock VPN-адаптеры](docs/architecture/0006-vpn-settings-and-adapters.md)
- [Threat model VPN-движков](docs/security/vpn-engine-threat-model.md)
- [Минимальная Windows-служба](docs/architecture/windows-privileged-service.md)
- [Отчёт этапа 8: Windows-служба и IPC](docs/stage8-windows-service-report.md)
- [Production-активация этапа 9](docs/architecture/0008-production-activation.md)
- [Реальная граница server API](docs/server-api-boundary.md)
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
proto/                        Reference schema; Rust wire codec is authoritative for v1
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
```

Stage 10 adds strict WireGuard configuration parsing plus typed profile
provisioning into the Windows service. Profiles are stored only as
DPAPI-encrypted blobs under a SYSTEM/Administrators-only directory and are
addressed by random opaque handles. The real tunnel engine was intentionally
disabled through stage 10.

Stage 11 integrates the official WireGuard for Windows embeddable service.
The privileged service verifies pinned DLL hashes, controls one fixed tunnel,
removes temporary plaintext after startup, and exposes traffic/handshake data
through bounded IPC. AmneziaWG and VLESS remain explicitly unavailable until
their separate engine stages.

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
