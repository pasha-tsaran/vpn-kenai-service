import 'dart:convert';

import 'wireguard_config_parser.dart';

final class AmneziaWgProvisioningProfile {
  const AmneziaWgProvisioningProfile({
    required this.wireGuard,
    required this.jc,
    required this.jmin,
    required this.jmax,
    required this.s1,
    required this.s2,
    required this.s3,
    required this.s4,
    required this.h1,
    required this.h2,
    required this.h3,
    required this.h4,
    required this.specialJunk,
  });
  final WireGuardProvisioningProfile wireGuard;
  final int jc, jmin, jmax, s1, s2, s3, s4;
  final String h1, h2, h3, h4;
  final List<String> specialJunk;

  @override
  String toString() => 'AmneziaWgProvisioningProfile([REDACTED])';
}

final class AmneziaWgConfigParser {
  const AmneziaWgConfigParser({
    this.wireGuardParser = const WireGuardConfigParser(),
  });
  final WireGuardConfigParser wireGuardParser;
  static const Set<String> _awgFields = <String>{
    'Jc',
    'Jmin',
    'Jmax',
    'S1',
    'S2',
    'S3',
    'S4',
    'H1',
    'H2',
    'H3',
    'H4',
    'I1',
    'I2',
    'I3',
    'I4',
    'I5',
  };

  AmneziaWgProvisioningProfile parse(String source) {
    if (source.length > 64 * 1024 || source.contains('\x00')) {
      throw const WireGuardConfigException('INVALID_PROFILE');
    }
    final Map<String, String> values = <String, String>{};
    final List<String> wireGuardLines = <String>[];
    var inInterface = false;
    for (final String original in const LineSplitter().convert(source)) {
      final String line = original.trim();
      if (line == '[Interface]') inInterface = true;
      if (line == '[Peer]') inInterface = false;
      final int separator = line.indexOf('=');
      final String key =
          separator > 0 ? line.substring(0, separator).trim() : '';
      if (_awgFields.contains(key)) {
        if (!inInterface || values.containsKey(key)) {
          throw const WireGuardConfigException('INVALID_PROFILE');
        }
        final String value = line.substring(separator + 1).trim();
        if (value.isEmpty ||
            value.length > 4096 ||
            value.runes.any((int rune) => rune < 32 || rune == 127)) {
          throw const WireGuardConfigException('INVALID_PROFILE');
        }
        values[key] = value;
      } else {
        wireGuardLines.add(original);
      }
    }
    for (final String key in const <String>[
      'Jc',
      'Jmin',
      'Jmax',
      'S1',
      'S2',
      'S3',
      'S4',
      'H1',
      'H2',
      'H3',
      'H4'
    ]) {
      if (!values.containsKey(key))
        throw const WireGuardConfigException('INVALID_PROFILE');
    }
    final int jc = _integer(values['Jc']!, 0, 10);
    final int jmin = _integer(values['Jmin']!, 64, 1024);
    final int jmax = _integer(values['Jmax']!, 64, 1024);
    if (jmin > jmax) throw const WireGuardConfigException('INVALID_PROFILE');
    final List<String> special = <String>[];
    var missing = false;
    for (var index = 1; index <= 5; index += 1) {
      final String? value = values['I$index'];
      if (value == null) {
        missing = true;
      } else {
        if (missing) throw const WireGuardConfigException('INVALID_PROFILE');
        special.add(value);
      }
    }
    return AmneziaWgProvisioningProfile(
      wireGuard: wireGuardParser.parse(wireGuardLines.join('\n')),
      jc: jc,
      jmin: jmin,
      jmax: jmax,
      s1: _integer(values['S1']!, 0, 64),
      s2: _integer(values['S2']!, 0, 64),
      s3: _integer(values['S3']!, 0, 64),
      s4: _integer(values['S4']!, 0, 32),
      h1: _range(values['H1']!),
      h2: _range(values['H2']!),
      h3: _range(values['H3']!),
      h4: _range(values['H4']!),
      specialJunk: List<String>.unmodifiable(special),
    );
  }

  static int _integer(String value, int minimum, int maximum) {
    final int? parsed = int.tryParse(value);
    if (parsed == null || parsed < minimum || parsed > maximum) {
      throw const WireGuardConfigException('INVALID_PROFILE');
    }
    return parsed;
  }

  static String _range(String value) {
    final RegExpMatch? match = RegExp(r'^(\d+)(?:-(\d+))?$').firstMatch(value);
    if (match == null) throw const WireGuardConfigException('INVALID_PROFILE');
    final int start = int.parse(match.group(1)!);
    final int end = int.parse(match.group(2) ?? match.group(1)!);
    if (start > 0xffffffff || end > 0xffffffff || start > end) {
      throw const WireGuardConfigException('INVALID_PROFILE');
    }
    return value;
  }
}
