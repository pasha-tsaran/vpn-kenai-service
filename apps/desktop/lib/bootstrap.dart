import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:kenai_core/kenai_core.dart';

import 'src/app.dart';
import 'src/infrastructure/platform_diagnostics.dart';
import 'src/infrastructure/platform_secure_storage.dart';
import 'src/infrastructure/production_api.dart';
import 'src/infrastructure/windows_profile_provisioner.dart';

const bool _testServersFromEnvironment = bool.fromEnvironment(
  'KENAI_ENABLE_TEST_SERVERS',
);
const String _productionApiUrl = String.fromEnvironment(
  'KENAI_API_BASE_URL',
);

Widget buildKenaiApp({
  bool? includeTestServers,
  AppDependencies? dependencies,
}) {
  if (dependencies != null) return KenaiApp(dependencies: dependencies);
  final bool testServersRequested =
      includeTestServers ?? _testServersFromEnvironment;
  final bool testServersEnabled = !kReleaseMode && testServersRequested;
  final SecureStorage secureStorage = PlatformSecureStorage();
  final ApiClient apiClient;
  final ActivationApiClient activationApiClient;
  final VpnEngine vpnEngine;
  final ServerRepository serverRepository;
  final SubscriptionRepository subscriptionRepository;
  if (kReleaseMode) {
    final Uri? baseUri = validatedProductionApiBaseUri(_productionApiUrl);
    apiClient = baseUri == null
        ? const UnavailableApiClient()
        : DartIoApiClient(baseUri: baseUri);
    activationApiClient = ProductionActivationApiClient(apiClient: apiClient);
    vpnEngine = UnavailableVpnEngine();
    serverRepository = ArmeniaMvpServerRepository();
    subscriptionRepository = const UnavailableSubscriptionRepository();
  } else {
    final MockApiClient mockApiClient = MockApiClient(
      includeTestServers: testServersEnabled,
    );
    apiClient = mockApiClient;
    activationApiClient = MockActivationApiClient();
    vpnEngine = MockVpnEngine();
    serverRepository = MockServerRepository(apiClient: mockApiClient);
    subscriptionRepository = MockSubscriptionRepository();
  }
  final PaymentProvider paymentProvider =
      kReleaseMode ? UnavailablePaymentProvider() : MockPaymentProvider();
  final SpeedTestEngine speedTestEngine =
      kReleaseMode ? UnavailableSpeedTestEngine() : MockSpeedTestEngine();
  final UpdateProvider updateProvider = kReleaseMode
      ? UnavailableUpdateProvider(currentVersion: '0.1.0')
      : MockUpdateProvider();
  final RedactingDiagnostics diagnostics = RedactingDiagnostics(
    store: JsonLinesDiagnosticLogStore.forCurrentUser(),
  );
  unawaited(
    diagnostics
        .log(
          const DiagnosticLogInput(
            category: DiagnosticCategory.application,
            level: DiagnosticSeverity.info,
            code: 'APP_STARTED',
            message: 'Kenai VPN client started.',
          ),
        )
        .onError((Object _, StackTrace __) {}),
  );
  return KenaiApp(
    dependencies: AppDependencies(
      apiClient: apiClient,
      secureStorage: secureStorage,
      accountRepository: SecureAccountRepository(
        apiClient: activationApiClient,
        secureStorage: secureStorage,
        profileProvisioner:
            kReleaseMode ? WindowsVpnProfileProvisioner() : null,
      ),
      vpnEngine: vpnEngine,
      serverRepository: serverRepository,
      settingsRepository: StoredSettingsRepository(
        secureStorage: secureStorage,
      ),
      platformCapabilities: const ClientPlatformCapabilities.unavailable(),
      subscriptionRepository: subscriptionRepository,
      paymentProvider: paymentProvider,
      speedTestEngine: speedTestEngine,
      updateProvider: updateProvider,
      buildInfo: const ClientBuildInfo(
        version: '0.1.0',
        buildNumber: '1',
        platform: DevicePlatform.windows,
      ),
      diagnosticLogger: diagnostics,
      diagnosticExporter: diagnostics,
      diagnosticArchiveSaver: DownloadsDiagnosticArchiveSaver(),
    ),
  );
}

final class AppDependencies {
  const AppDependencies({
    required this.apiClient,
    required this.secureStorage,
    required this.accountRepository,
    required this.vpnEngine,
    required this.serverRepository,
    required this.settingsRepository,
    required this.platformCapabilities,
    required this.subscriptionRepository,
    required this.paymentProvider,
    required this.speedTestEngine,
    required this.updateProvider,
    required this.buildInfo,
    required this.diagnosticLogger,
    required this.diagnosticExporter,
    required this.diagnosticArchiveSaver,
  });

  final ApiClient apiClient;
  final SecureStorage secureStorage;
  final AccountRepository accountRepository;
  final VpnEngine vpnEngine;
  final ServerRepository serverRepository;
  final SettingsRepository settingsRepository;
  final ClientPlatformCapabilities platformCapabilities;
  final SubscriptionRepository subscriptionRepository;
  final PaymentProvider paymentProvider;
  final SpeedTestEngine speedTestEngine;
  final UpdateProvider updateProvider;
  final ClientBuildInfo buildInfo;
  final DiagnosticLogger diagnosticLogger;
  final DiagnosticExporter diagnosticExporter;
  final DiagnosticArchiveSaver diagnosticArchiveSaver;
}
