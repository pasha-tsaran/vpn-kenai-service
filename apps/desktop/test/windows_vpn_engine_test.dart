import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:kenai_core/kenai_core.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/windows_profile_provisioner.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/windows_vpn_engine.dart';

void main() {
  late InMemorySecureStorage storage;
  late _VpnTransport transport;
  late WindowsVpnEngine engine;

  setUp(() {
    storage = InMemorySecureStorage();
    transport = _VpnTransport();
    engine = WindowsVpnEngine(
      secureStorage: storage,
      transport: transport,
      random: Random(1),
    );
  });

  test('requires an activated 12-digit account before service access',
      () async {
    final List<VpnConnectionState> states = <VpnConnectionState>[];
    final subscription = engine.states.listen(states.add);

    await engine.connect(_request());

    expect(states.map((state) => state.phase), <VpnConnectionPhase>[
      VpnConnectionPhase.validating,
      VpnConnectionPhase.blockedBySubscription,
    ]);
    expect(states.last.errorCode, 'SUBSCRIPTION_REQUIRED');
    expect(transport.opcodes, isEmpty);
    await subscription.cancel();
  });

  test('connects by opaque profile handle and never sends activation key',
      () async {
    await _activateStorage(storage);
    final List<VpnConnectionState> states = <VpnConnectionState>[];
    final subscription = engine.states.listen(states.add);

    await engine.connect(_request());

    expect(transport.opcodes, <int>[2]);
    expect(states.map((state) => state.phase), <VpnConnectionPhase>[
      VpnConnectionPhase.validating,
      VpnConnectionPhase.connecting,
      VpnConnectionPhase.connected,
    ]);
    expect(
      String.fromCharCodes(transport.lastRequest),
      contains(_VpnTransport.profileHandle),
    );
    expect(String.fromCharCodes(transport.lastRequest), isNot(contains(_key)));
    expect((await engine.status()).phase, VpnConnectionPhase.connected);
    await subscription.cancel();
  });

  test('reports service counters and disconnects through typed IPC', () async {
    await _activateStorage(storage);
    await engine.connect(_request());

    final VpnStatistics statistics = await engine.statistics();
    expect(statistics.bytesReceived, 200);
    expect(statistics.bytesSent, 100);

    await engine.disconnect(operationId: 'disconnect-1');
    expect(transport.opcodes, <int>[2, 7, 3]);
    expect((await engine.status()).phase, VpnConnectionPhase.disconnected);
  });

  test('claims only implemented production protocols and no kill switch', () {
    expect(engine.supportedProtocols, <VpnProtocol>{
      VpnProtocol.wireGuard,
      VpnProtocol.amneziaWg,
    });
    expect(
      engine.capabilitiesFor(VpnProtocol.wireGuard).supportsKillSwitch,
      isFalse,
    );
    expect(
      engine.capabilitiesFor(VpnProtocol.amneziaWg).supportsDns,
      isTrue,
    );
  });

  test('connects AmneziaWG with its separate opaque handle and protocol',
      () async {
    await _activateStorage(storage);
    await storage.write(
      key: SecureAccountStorageKeys.amneziaWgProfileHandle,
      value: _VpnTransport.awgProfileHandle,
    );
    await engine.connect(const ConnectionRequest(
      operationId: 'connect-awg',
      profile: VpnProfile(
        id: 'ui-awg',
        deviceId: 'windows-device',
        serverId: 'armenia-1',
        protocol: VpnProtocol.amneziaWg,
      ),
      killSwitch: false,
    ));
    expect(transport.lastRequest,
        containsAllInOrder(_VpnTransport.awgProfileHandle.codeUnits));
    expect(transport.lastRequest.last, 0);
    expect(transport.lastRequest[transport.lastRequest.length - 2], 2);
  });
}

const String _key = '123456789012';

Future<void> _activateStorage(InMemorySecureStorage storage) async {
  await storage.write(
    key: SecureAccountStorageKeys.activationKey,
    value: _key,
  );
  await storage.write(
    key: SecureAccountStorageKeys.session,
    value: jsonEncode(<String, Object?>{
      'subscription': <String, Object?>{'status': 'active'},
    }),
  );
  await storage.write(
    key: SecureAccountStorageKeys.profileHandle,
    value: _VpnTransport.profileHandle,
  );
}

ConnectionRequest _request() => const ConnectionRequest(
      operationId: 'connect-1',
      profile: VpnProfile(
        id: 'ui-profile',
        deviceId: 'windows-device',
        serverId: 'armenia-1',
        protocol: VpnProtocol.wireGuard,
      ),
      killSwitch: false,
    );

final class _VpnTransport implements ProfileIpcTransport {
  static const String profileHandle = 'wg-00112233445566778899aabbccddeeff';
  static const String awgProfileHandle = 'awg-00112233445566778899aabbccddeeff';
  final List<int> opcodes = <int>[];
  Uint8List lastRequest = Uint8List(0);
  bool connected = false;

  @override
  Future<Uint8List> exchange(Uint8List request) async {
    lastRequest = request;
    final int opcode = request[6];
    opcodes.add(opcode);
    if (opcode == 2) connected = true;
    if (opcode == 3) connected = false;
    final int requestIdLength = request[12];
    final List<int> requestId = request.sublist(13, 13 + requestIdLength);
    final int phase = connected ? 3 : 0;
    return _response(
      requestId,
      phase: phase,
      code: opcode == 3 ? 'DISCONNECTED' : 'OK',
      statistics: opcode == 7,
    );
  }

  static Uint8List _response(
    List<int> requestId, {
    required int phase,
    required String code,
    required bool statistics,
  }) {
    final BytesBuilder body = BytesBuilder(copy: false)
      ..addByte(requestId.length)
      ..add(requestId)
      ..addByte(phase)
      ..addByte(0)
      ..addByte(0)
      ..addByte(code.length)
      ..add(code.codeUnits)
      ..addByte(statistics ? 1 : 0);
    if (statistics) {
      final Uint8List counters = Uint8List(17);
      ByteData.sublistView(counters)
        ..setUint64(0, 200, Endian.little)
        ..setUint64(8, 100, Endian.little)
        ..setUint8(16, 0);
      body.add(counters);
    }
    return encodeVpnIpcFrame(0x81, body.takeBytes());
  }
}
