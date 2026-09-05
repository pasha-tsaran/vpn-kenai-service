import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/windows_profile_provisioner.dart';

void main() {
  final String privateKey = base64Encode(List<int>.filled(32, 3));
  final String publicKey = base64Encode(List<int>.filled(32, 5));
  late _FakeTransport transport;
  late WindowsVpnProfileProvisioner provisioner;

  setUp(() {
    transport = _FakeTransport();
    provisioner = WindowsVpnProfileProvisioner(
      transport: transport,
      random: Random(1),
    );
  });

  test('imports typed profile and returns only opaque handle', () async {
    final String profileId = await provisioner.provisionWireGuard('''
[Interface]
PrivateKey = $privateKey
Address = 10.0.0.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = $publicKey
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0
''');

    expect(profileId, _FakeTransport.handle);
    expect(transport.opcodes, <int>[5]);
    expect(_containsSequence(transport.lastRequest, privateKey.codeUnits),
        isFalse);
  });

  test('logout cleanup uses only validated handle', () async {
    await provisioner.deleteProfile(_FakeTransport.handle);
    expect(transport.opcodes, <int>[6]);

    await expectLater(
      provisioner.deleteProfile('../profile'),
      throwsA(isA<ProfileProvisioningException>()),
    );
  });
}

final class _FakeTransport implements ProfileIpcTransport {
  static const String handle = 'wg-00112233445566778899aabbccddeeff';
  final List<int> opcodes = <int>[];
  Uint8List lastRequest = Uint8List(0);

  @override
  Future<Uint8List> exchange(Uint8List request) async {
    lastRequest = request;
    opcodes.add(request[6]);
    final int idLength = request[12];
    final List<int> requestId = request.sublist(13, 13 + idLength);
    final String code = request[6] == 5 ? 'PROFILE_STORED' : 'PROFILE_DELETED';
    final List<int> body = <int>[
      idLength,
      ...requestId,
      0,
      if (request[6] == 5) ...<int>[1, handle.length, ...handle.codeUnits] else
        0,
      0,
      code.length,
      ...code.codeUnits,
      0,
    ];
    final Uint8List response = Uint8List(12 + body.length)
      ..setRange(0, 4, const <int>[0x4b, 0x56, 0x50, 0x4e])
      ..setRange(12, 12 + body.length, body);
    ByteData.sublistView(response)
      ..setUint16(4, 2, Endian.little)
      ..setUint8(6, 0x81)
      ..setUint32(8, body.length, Endian.little);
    return response;
  }
}

bool _containsSequence(List<int> source, List<int> sequence) {
  for (var start = 0; start + sequence.length <= source.length; start += 1) {
    var matches = true;
    for (var index = 0; index < sequence.length; index += 1) {
      if (source[start + index] != sequence[index]) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}
