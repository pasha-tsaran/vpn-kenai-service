import 'dart:async';

import '../domain/models.dart';
import '../ports/ports.dart';

/// Fail-closed transport used when a release was built without an API URL.
final class UnavailableApiClient implements ApiClient {
  const UnavailableApiClient();

  @override
  Future<ApiResponse> send(ApiRequest request) =>
      throw const ApiClientException(ApiTransportFailure.unavailable);
}

final class UnavailableSubscriptionRepository
    implements SubscriptionRepository {
  const UnavailableSubscriptionRepository();

  @override
  Future<Subscription> getSubscription() =>
      throw StateError('Subscription API is unavailable');
}

/// Honest release fallback until the Windows IPC engine is connected.
final class UnavailableVpnEngine implements VpnEngine {
  final StreamController<VpnConnectionState> _states =
      StreamController<VpnConnectionState>.broadcast(sync: true);
  VpnConnectionState _state = const VpnConnectionState.disconnected();

  @override
  bool get isMock => false;

  @override
  Set<VpnProtocol> get supportedProtocols => const <VpnProtocol>{};

  @override
  Stream<VpnConnectionState> get states => _states.stream;

  @override
  VpnAdapterCapabilities capabilitiesFor(VpnProtocol protocol) =>
      VpnAdapterCapabilities(
        protocol: protocol,
        isMock: false,
        supportsKillSwitch: false,
        supportsDns: false,
        supportsNetworkChangeReconnect: false,
        supportsSleepRecovery: false,
      );

  @override
  Future<void> connect(ConnectionRequest request) async {
    _state = VpnConnectionState(
      phase: VpnConnectionPhase.error,
      serverId: request.profile.serverId,
      protocol: request.profile.protocol,
      errorCode: 'ENGINE_NOT_INSTALLED',
    );
    _states.add(_state);
  }

  @override
  Future<void> disconnect({required String operationId}) async {
    _state = const VpnConnectionState.disconnected();
    _states.add(_state);
  }

  @override
  Future<VpnConnectionState> status() async => _state;

  @override
  Future<VpnStatistics> statistics() async => VpnStatistics(
        bytesReceived: 0,
        bytesSent: 0,
        measuredAt: DateTime.now(),
      );

  @override
  Future<ProfileValidation> validateProfile(VpnProfile profile) async =>
      const ProfileValidation(
        isValid: false,
        errorCode: 'ENGINE_NOT_INSTALLED',
      );

  @override
  Future<EngineDiagnostics> collectDiagnostics() async => EngineDiagnostics(
        phase: _state.phase,
        serviceAvailable: false,
        networkAvailable: true,
        codes: const <String>['ENGINE_NOT_INSTALLED'],
      );
}

/// One-server production repository for the WireGuard-first MVP.
final class ArmeniaMvpServerRepository implements ServerRepository {
  ArmeniaMvpServerRepository();

  VpnServer _server = VpnServer(
    id: 'armenia-1',
    countryCode: 'AM',
    countryName: 'Армения',
    city: 'Ереван',
    name: 'Армения',
    protocols: const <VpnProtocol>{VpnProtocol.wireGuard},
    status: ServerStatus(
      operational: ServerOperationalStatus.operational,
      internetReachability: InternetReachability.reachable,
      lastUpdatedAt: DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
    ),
    isRecommended: true,
  );

  @override
  bool get isMock => false;

  @override
  Future<List<VpnServer>> getServers({
    String query = '',
    ServerSort sort = ServerSort.recommended,
    String? countryCode,
    bool favoritesOnly = false,
  }) async {
    final String normalized = query.trim().toLowerCase();
    final bool matchesQuery = normalized.isEmpty ||
        _server.countryName.toLowerCase().contains(normalized) ||
        _server.city.toLowerCase().contains(normalized);
    final bool matchesCountry =
        countryCode == null || _server.countryCode == countryCode;
    final bool matchesFavorite = !favoritesOnly || _server.isFavorite;
    return matchesQuery && matchesCountry && matchesFavorite
        ? <VpnServer>[_server]
        : const <VpnServer>[];
  }

  @override
  Future<VpnServer?> getSelectedServer() async => _server;

  @override
  Future<void> selectServer(String serverId) async {
    _requireCurrent(serverId);
  }

  @override
  Future<void> toggleFavorite(String serverId) async {
    _requireCurrent(serverId);
    _server = _server.copyWith(isFavorite: !_server.isFavorite);
  }

  @override
  Future<Duration?> ping(String serverId) async {
    _requireCurrent(serverId);
    return null;
  }

  void _requireCurrent(String serverId) {
    if (serverId != _server.id) {
      throw ArgumentError.value(serverId, 'serverId', 'Unknown server');
    }
  }
}
