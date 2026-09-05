import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:kenai_core/kenai_core.dart';

import 'windows_profile_provisioner.dart';

/// Production VPN engine backed only by the typed Kenai Windows service IPC.
///
/// It never receives a configuration or secret. The privileged service resolves
/// the opaque profile handle created after successful account activation.
final class WindowsVpnEngine implements VpnEngine {
  WindowsVpnEngine({
    required SecureStorage secureStorage,
    ProfileIpcTransport transport = const WindowsNamedPipeProfileTransport(),
    Random? random,
  })  : _secureStorage = secureStorage,
        _transport = transport,
        _random = random ?? Random.secure();

  final SecureStorage _secureStorage;
  final ProfileIpcTransport _transport;
  final Random _random;
  final StreamController<VpnConnectionState> _states =
      StreamController<VpnConnectionState>.broadcast(sync: true);

  VpnConnectionState _state = const VpnConnectionState.disconnected();
  bool _operationInFlight = false;
  String? _serverId;
  VpnProtocol? _protocol;
  DateTime? _connectedAt;

  @override
  bool get isMock => false;

  @override
  Set<VpnProtocol> get supportedProtocols => const <VpnProtocol>{
        VpnProtocol.wireGuard,
        VpnProtocol.amneziaWg,
        VpnProtocol.vlessReality,
      };

  @override
  Stream<VpnConnectionState> get states => _states.stream;

  @override
  VpnAdapterCapabilities capabilitiesFor(VpnProtocol protocol) =>
      VpnAdapterCapabilities(
        protocol: protocol,
        isMock: false,
        supportsKillSwitch: false,
        supportsDns: protocol == VpnProtocol.wireGuard ||
            protocol == VpnProtocol.amneziaWg ||
            protocol == VpnProtocol.vlessReality,
        supportsNetworkChangeReconnect: false,
        supportsSleepRecovery: false,
      );

  @override
  Future<void> connect(ConnectionRequest request) async {
    if (_operationInFlight || _state.phase.isBusy) {
      throw StateError('VPN operation is already in progress');
    }
    _operationInFlight = true;
    _serverId = request.profile.serverId;
    _protocol = request.profile.protocol;
    try {
      if (!supportedProtocols.contains(request.profile.protocol)) {
        _emitFailure('UNSUPPORTED_PROTOCOL');
        return;
      }
      if (request.killSwitch) {
        _emitFailure('UNSUPPORTED_FEATURE');
        return;
      }
      _emit(VpnConnectionPhase.validating);
      final _AccountAccess access = await _accountAccess();
      if (!access.active) {
        _emitFailure('SUBSCRIPTION_REQUIRED');
        return;
      }
      final String? profileHandle = switch (request.profile.protocol) {
        VpnProtocol.wireGuard => access.profileHandle,
        VpnProtocol.amneziaWg => access.amneziaWgProfileHandle,
        VpnProtocol.vlessReality => access.vlessProfileHandle,
      };
      if (profileHandle == null || !_validIdentifier(profileHandle)) {
        _emitFailure('PROFILE_NOT_FOUND');
        return;
      }
      _emit(VpnConnectionPhase.connecting);
      final VpnIpcResponse response = await _exchange(
        2,
        Uint8List.fromList(<int>[
          ..._identifierBytes(request.operationId),
          ..._identifierBytes(profileHandle),
          switch (request.profile.protocol) {
            VpnProtocol.wireGuard => 1,
            VpnProtocol.amneziaWg => 2,
            VpnProtocol.vlessReality => 3,
          },
          0,
        ]),
      );
      _apply(response);
    } on ProfileProvisioningException catch (error) {
      _emitFailure(error.code);
    } on Object {
      _emitFailure('ENGINE_FAILED');
    } finally {
      _operationInFlight = false;
    }
  }

  @override
  Future<void> disconnect({required String operationId}) async {
    if (_operationInFlight || _state.phase.isBusy) {
      throw StateError('VPN operation is already in progress');
    }
    _operationInFlight = true;
    try {
      _emit(VpnConnectionPhase.disconnecting);
      final VpnIpcResponse response = await _exchange(
        3,
        _identifierBytes(operationId),
      );
      _apply(response);
      if (response.phase != 0) {
        throw ProfileProvisioningException(response.code);
      }
    } on ProfileProvisioningException catch (error) {
      _emitFailure(error.code);
      rethrow;
    } on Object {
      _emitFailure('ENGINE_FAILED');
      rethrow;
    } finally {
      _operationInFlight = false;
    }
  }

  @override
  Future<VpnConnectionState> status() async {
    if (_operationInFlight) return _state;
    try {
      final VpnIpcResponse response = await _exchange(1, Uint8List(0));
      _apply(response);
    } on ProfileProvisioningException catch (error) {
      _emitFailure(error.code);
    } on Object {
      _emitFailure('ENGINE_FAILED');
    }
    return _state;
  }

  @override
  Future<VpnStatistics> statistics() async {
    if (_state.phase != VpnConnectionPhase.connected) {
      return _emptyStatistics();
    }
    try {
      final VpnIpcResponse response = await _exchange(7, Uint8List(0));
      if (response.code != 'OK' ||
          response.bytesReceived == null ||
          response.bytesSent == null) {
        return _emptyStatistics();
      }
      return VpnStatistics(
        bytesReceived: response.bytesReceived!,
        bytesSent: response.bytesSent!,
        measuredAt: DateTime.now(),
      );
    } on Object {
      return _emptyStatistics();
    }
  }

  @override
  Future<ProfileValidation> validateProfile(VpnProfile profile) async {
    if (!supportedProtocols.contains(profile.protocol)) {
      return const ProfileValidation(
        isValid: false,
        errorCode: 'UNSUPPORTED_PROTOCOL',
      );
    }
    final _AccountAccess access = await _accountAccess();
    final String? handle = switch (profile.protocol) {
      VpnProtocol.wireGuard => access.profileHandle,
      VpnProtocol.amneziaWg => access.amneziaWgProfileHandle,
      VpnProtocol.vlessReality => access.vlessProfileHandle,
    };
    return ProfileValidation(
      isValid: access.active && handle != null,
      errorCode: !access.active
          ? 'SUBSCRIPTION_REQUIRED'
          : handle == null
              ? 'PROFILE_NOT_FOUND'
              : null,
    );
  }

  @override
  Future<EngineDiagnostics> collectDiagnostics() async => EngineDiagnostics(
        phase: _state.phase,
        serviceAvailable: _state.errorCode != 'SERVICE_UNAVAILABLE',
        networkAvailable: _state.phase != VpnConnectionPhase.noNetwork,
        codes: _state.errorCode == null
            ? const <String>[]
            : <String>[_state.errorCode!],
      );

  Future<VpnIpcResponse> _exchange(int opcode, Uint8List commandBody) async {
    final String requestId = _identifier('request');
    final Uint8List body = Uint8List.fromList(<int>[
      ..._identifierBytes(requestId),
      ...commandBody,
    ]);
    final Uint8List response = await _transport.exchange(
      encodeVpnIpcFrame(opcode, body),
    );
    return decodeVpnIpcResponse(response, requestId);
  }

  Future<_AccountAccess> _accountAccess() async {
    final String? encoded =
        await _secureStorage.read(SecureAccountStorageKeys.session);
    final String? handle =
        await _secureStorage.read(SecureAccountStorageKeys.profileHandle);
    final String? amneziaWgHandle = await _secureStorage
        .read(SecureAccountStorageKeys.amneziaWgProfileHandle);
    final String? vlessHandle =
        await _secureStorage.read(SecureAccountStorageKeys.vlessProfileHandle);
    if (encoded == null) return const _AccountAccess(active: false);
    try {
      final Object? decoded = jsonDecode(encoded);
      if (decoded is! Map<String, Object?>) {
        return const _AccountAccess(active: false);
      }
      final Object? subscription = decoded['subscription'];
      final bool active = subscription is Map<String, Object?> &&
          subscription['status'] == SubscriptionStatus.active.name;
      return _AccountAccess(
          active: active,
          profileHandle: handle,
          amneziaWgProfileHandle: amneziaWgHandle,
          vlessProfileHandle: vlessHandle);
    } on FormatException {
      return const _AccountAccess(active: false);
    }
  }

  void _apply(VpnIpcResponse response) {
    final VpnConnectionPhase phase = _phase(response.phase);
    if (phase == VpnConnectionPhase.connected) {
      _connectedAt ??= DateTime.now();
    } else if (phase == VpnConnectionPhase.disconnected) {
      _connectedAt = null;
      _serverId = null;
      _protocol = null;
    }
    _state = VpnConnectionState(
      phase: phase,
      serverId: phase == VpnConnectionPhase.disconnected ? null : _serverId,
      protocol: phase == VpnConnectionPhase.disconnected ? null : _protocol,
      connectedAt: phase == VpnConnectionPhase.connected ? _connectedAt : null,
      killSwitchActive: response.killSwitchActive,
      errorCode: phase.isFailure ? response.code : null,
    );
    _states.add(_state);
  }

  void _emit(VpnConnectionPhase phase) {
    _state = VpnConnectionState(
      phase: phase,
      serverId: _serverId,
      protocol: _protocol,
      connectedAt: phase == VpnConnectionPhase.connected ? _connectedAt : null,
    );
    _states.add(_state);
  }

  void _emitFailure(String code) {
    final VpnConnectionPhase phase = switch (code) {
      'NO_NETWORK' => VpnConnectionPhase.noNetwork,
      'SERVER_UNAVAILABLE' => VpnConnectionPhase.serverUnavailable,
      'SUBSCRIPTION_REQUIRED' ||
      'PROFILE_NOT_FOUND' =>
        VpnConnectionPhase.blockedBySubscription,
      _ => VpnConnectionPhase.error,
    };
    _state = VpnConnectionState(
      phase: phase,
      serverId: _serverId,
      protocol: _protocol,
      errorCode: code,
    );
    _states.add(_state);
  }

  String _identifier(String prefix) {
    final StringBuffer value = StringBuffer('$prefix-');
    for (var index = 0; index < 16; index += 1) {
      value.write(_random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return value.toString();
  }

  static Uint8List _identifierBytes(String value) {
    if (!_validIdentifier(value)) {
      throw const ProfileProvisioningException('INVALID_IDENTIFIER');
    }
    return Uint8List.fromList(<int>[value.length, ...value.codeUnits]);
  }

  static bool _validIdentifier(String value) =>
      value.isNotEmpty &&
      value.length <= 64 &&
      RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value);

  static VpnConnectionPhase _phase(int value) => switch (value) {
        0 => VpnConnectionPhase.disconnected,
        1 => VpnConnectionPhase.validating,
        2 => VpnConnectionPhase.connecting,
        3 => VpnConnectionPhase.connected,
        4 => VpnConnectionPhase.reconnecting,
        5 => VpnConnectionPhase.disconnecting,
        6 => VpnConnectionPhase.blockedBySubscription,
        7 => VpnConnectionPhase.noNetwork,
        8 => VpnConnectionPhase.serverUnavailable,
        9 => VpnConnectionPhase.error,
        _ => throw const ProfileProvisioningException('INVALID_RESPONSE'),
      };

  static VpnStatistics _emptyStatistics() => VpnStatistics(
        bytesReceived: 0,
        bytesSent: 0,
        measuredAt: DateTime.now(),
      );
}

final class _AccountAccess {
  const _AccountAccess(
      {required this.active,
      this.profileHandle,
      this.amneziaWgProfileHandle,
      this.vlessProfileHandle});

  final bool active;
  final String? profileHandle;
  final String? amneziaWgProfileHandle;
  final String? vlessProfileHandle;
}
