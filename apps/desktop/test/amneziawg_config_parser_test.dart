import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/amneziawg_config_parser.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/wireguard_config_parser.dart';

void main() {
  final String privateKey = base64Encode(List<int>.filled(32, 7));
  final String publicKey = base64Encode(List<int>.filled(32, 9));

  String profile({String extra = ''}) => '''
[Interface]
PrivateKey = $privateKey
Address = 10.8.0.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 64
Jmax = 128
S1 = 1
S2 = 2
S3 = 3
S4 = 4
H1 = 100
H2 = 200-210
H3 = 300
H4 = 400
$extra
[Peer]
PublicKey = $publicKey
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
''';

  test('parses only the bounded AmneziaWG 2.0 extension fields', () {
    final AmneziaWgProvisioningProfile parsed =
        const AmneziaWgConfigParser().parse(profile(extra: 'I1 = <b 0x01>'));
    expect(parsed.jc, 4);
    expect(parsed.jmin, 64);
    expect(parsed.jmax, 128);
    expect(parsed.h2, '200-210');
    expect(parsed.specialJunk, <String>['<b 0x01>']);
    expect(parsed.toString(), isNot(contains(privateKey)));
  });

  test('rejects missing, duplicate, out-of-range and injected fields', () {
    final AmneziaWgConfigParser parser = const AmneziaWgConfigParser();
    for (final String invalid in <String>[
      profile().replaceFirst('Jc = 4\n', ''),
      profile(extra: 'Jc = 5'),
      profile().replaceFirst('Jmin = 64', 'Jmin = 1025'),
      profile().replaceFirst('H1 = 100', 'H1 = 200-100'),
      profile(extra: 'PostUp = calc.exe'),
      profile(extra: 'I2 = gap'),
    ]) {
      expect(
        () => parser.parse(invalid),
        throwsA(isA<WireGuardConfigException>()),
      );
    }
  });
}
