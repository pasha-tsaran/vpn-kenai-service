import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kenai_core/kenai_core.dart';
import 'package:kenai_vpn_desktop/bootstrap.dart';

void main() {
  testWidgets('opens servers and navigates to settings', (
    WidgetTester tester,
  ) async {
    final ({AppDependencies dependencies, MockVpnEngine engine}) fixture =
        _fixture(includeTestServers: false);
    addTearDown(fixture.engine.dispose);
    await tester.pumpWidget(buildKenaiApp(dependencies: fixture.dependencies));
    await tester.pumpAndSettle();

    expect(find.text('Серверы'), findsWidgets);
    expect(find.text('Армения, Ереван'), findsWidgets);
    expect(find.byKey(const Key('mock-api-badge')), findsOneWidget);

    await tester.tap(find.byIcon(Icons.settings_outlined));
    await tester.pumpAndSettle();

    expect(find.text('Параметры'), findsWidgets);
    expect(find.byKey(const Key('application-version')), findsOneWidget);
  });

  testWidgets('development catalog supports search, countries and favorites', (
    WidgetTester tester,
  ) async {
    _useWideWindow(tester);
    final ({AppDependencies dependencies, MockVpnEngine engine}) fixture =
        _fixture();
    addTearDown(fixture.engine.dispose);
    await tester.pumpWidget(buildKenaiApp(dependencies: fixture.dependencies));
    await tester.pumpAndSettle();

    expect(find.text('Mock API · тестовые серверы'), findsOneWidget);
    expect(find.text('Yerevan S1'), findsWidgets);
    expect(_visibleServer('de-fra-test-01'), findsOneWidget);
    expect(find.text('Тестовый'), findsWidgets);
    expect(find.text('Рекомендуемый'), findsWidgets);

    await tester.enterText(find.byKey(const Key('server-search')), 'Герм');
    await tester.pumpAndSettle();
    expect(_visibleServer('de-fra-test-01'), findsOneWidget);
    expect(_visibleServer('am-evn-01'), findsNothing);

    await tester.enterText(find.byKey(const Key('server-search')), '');
    await tester.tap(find.byKey(const Key('country-DE')));
    await tester.pumpAndSettle();
    expect(_visibleServer('de-fra-test-01'), findsOneWidget);
    expect(_visibleServer('nl-ams-test-01'), findsNothing);

    await tester.tap(find.byKey(const Key('country-all')));
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const Key('favorite-am-evn-01')).hitTestable().first,
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('favorites-filter')));
    await tester.pumpAndSettle();
    expect(find.text('Yerevan S1'), findsWidgets);
    expect(_visibleServer('de-fra-test-01'), findsOneWidget);
    expect(_visibleServer('jp-tyo-test-01'), findsNothing);
  });

  testWidgets('selected server shows protocol, ping and availability', (
    WidgetTester tester,
  ) async {
    _useWideWindow(tester);
    final ({AppDependencies dependencies, MockVpnEngine engine}) fixture =
        _fixture();
    addTearDown(fixture.engine.dispose);
    await tester.pumpWidget(buildKenaiApp(dependencies: fixture.dependencies));
    await tester.pumpAndSettle();

    expect(find.text('WireGuard'), findsOneWidget);
    expect(find.text('38 ms'), findsWidgets);
    await tester.tap(find.byKey(const Key('ping-button')));
    await tester.pumpAndSettle();
    expect(find.text('36 ms'), findsWidgets);

    final Finder tokyo = find
        .byKey(
          const Key('server-jp-tyo-test-01'),
        )
        .first;
    await tester.ensureVisible(tokyo);
    await tester.pumpAndSettle();
    await tester.tap(tokyo);
    await tester.pumpAndSettle();
    expect(find.text('Тестовый сервер'), findsOneWidget);
    expect(find.text('Недоступен'), findsWidgets);
    final FilledButton connectButton = tester.widget<FilledButton>(
      find.byKey(const Key('connect-button')),
    );
    expect(connectButton.onPressed, isNull);
  });

  testWidgets('connect button shows lifecycle, time and traffic', (
    WidgetTester tester,
  ) async {
    _useWideWindow(tester);
    final ({AppDependencies dependencies, MockVpnEngine engine}) fixture =
        _fixture();
    await tester.pumpWidget(
      buildKenaiApp(dependencies: fixture.dependencies),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const Key('connect-button')));
    await tester.pump();
    expect(_phaseText(tester), 'Проверяем профиль');

    await tester.pump(const Duration(milliseconds: 81));
    expect(_phaseText(tester), 'Подключаемся');

    await tester.pump(const Duration(milliseconds: 81));
    expect(_phaseText(tester), 'VPN подключён');
    await tester.pump(const Duration(seconds: 1));
    expect(find.byKey(const Key('connection-time')), findsOneWidget);
    expect(
      find.descendant(
        of: find.byKey(const Key('traffic-received')),
        matching: find.text('0 Б'),
      ),
      findsNothing,
    );

    await tester.tap(find.byKey(const Key('connect-button')));
    await tester.pump();
    expect(_phaseText(tester), 'Отключаем VPN');
    await tester.pump(const Duration(milliseconds: 81));
    expect(_phaseText(tester), 'VPN не подключён');
    expect(find.text('0 Б'), findsWidgets);
    await fixture.engine.dispose();
  });

  testWidgets('renders every connection state without internal error details', (
    WidgetTester tester,
  ) async {
    _useWideWindow(tester);
    final ({AppDependencies dependencies, MockVpnEngine engine}) fixture =
        _fixture();
    await tester.pumpWidget(
      buildKenaiApp(dependencies: fixture.dependencies),
    );
    await tester.pumpAndSettle();

    final Map<VpnConnectionPhase, String> titles = <VpnConnectionPhase, String>{
      VpnConnectionPhase.disconnected: 'VPN не подключён',
      VpnConnectionPhase.validating: 'Проверяем профиль',
      VpnConnectionPhase.connecting: 'Подключаемся',
      VpnConnectionPhase.connected: 'VPN подключён',
      VpnConnectionPhase.reconnecting: 'Восстанавливаем соединение',
      VpnConnectionPhase.disconnecting: 'Отключаем VPN',
      VpnConnectionPhase.blockedBySubscription: 'Подключение приостановлено',
      VpnConnectionPhase.noNetwork: 'Нет подключения к интернету',
      VpnConnectionPhase.serverUnavailable: 'Сервер временно недоступен',
      VpnConnectionPhase.error: 'Не удалось подключиться',
    };

    for (final MapEntry<VpnConnectionPhase, String> entry in titles.entries) {
      fixture.engine.simulateState(
        VpnConnectionState(
          phase: entry.key,
          serverId: 'am-evn-01',
          protocol: VpnProtocol.wireGuard,
          connectedAt:
              entry.key == VpnConnectionPhase.connected ? DateTime.now() : null,
          errorCode: 'INTERNAL_SECRET_DETAIL',
        ),
      );
      await tester.pump();
      expect(_phaseText(tester), entry.value);
      expect(find.textContaining('INTERNAL_SECRET_DETAIL'), findsNothing);
    }

    fixture.engine.simulateState(const VpnConnectionState.disconnected());
    await tester.pump();
    await fixture.engine.dispose();
  });
}

({AppDependencies dependencies, MockVpnEngine engine}) _fixture({
  bool includeTestServers = true,
}) {
  final MockApiClient api = MockApiClient(
    includeTestServers: includeTestServers,
  );
  final MockVpnEngine engine = MockVpnEngine();
  final InMemorySecureStorage secureStorage = InMemorySecureStorage();
  return (
    dependencies: AppDependencies(
      apiClient: api,
      secureStorage: secureStorage,
      accountRepository: SecureAccountRepository(
        apiClient: MockActivationApiClient(),
        secureStorage: secureStorage,
      ),
      vpnEngine: engine,
      serverRepository: MockServerRepository(apiClient: api),
      settingsRepository: MockSettingsRepository(),
      platformCapabilities: const ClientPlatformCapabilities.unavailable(),
      subscriptionRepository: MockSubscriptionRepository(),
      paymentProvider: MockPaymentProvider(),
      speedTestEngine: MockSpeedTestEngine(),
      updateProvider: MockUpdateProvider(),
      buildInfo: const ClientBuildInfo(
        version: '0.1.0',
        buildNumber: '1',
        platform: DevicePlatform.windows,
      ),
      diagnosticLogger: RedactingDiagnostics(
        store: InMemoryDiagnosticLogStore(),
      ),
      diagnosticExporter: MockDiagnosticExporter(),
      diagnosticArchiveSaver: InMemoryDiagnosticArchiveSaver(),
    ),
    engine: engine,
  );
}

String? _phaseText(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const Key('connection-phase'))).data;

void _useWideWindow(WidgetTester tester) {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(1440, 900);
  addTearDown(tester.view.reset);
}

Finder _visibleServer(String id) => find.byKey(Key('server-$id')).hitTestable();
