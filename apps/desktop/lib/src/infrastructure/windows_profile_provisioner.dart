import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:kenai_core/kenai_core.dart';

import 'wireguard_config_parser.dart';

const String _pipeName = r'\\.\pipe\KenaiVpnControl-v1';
const int _maximumFrameSize = 16 * 1024;

final class ProfileProvisioningException implements Exception {
  const ProfileProvisioningException(this.code);

  final String code;

  @override
  String toString() => 'ProfileProvisioningException($code)';
}

abstract interface class ProfileIpcTransport {
  Future<Uint8List> exchange(Uint8List request);
}

final class WindowsNamedPipeProfileTransport implements ProfileIpcTransport {
  const WindowsNamedPipeProfileTransport({
    this.timeout = const Duration(seconds: 10),
  });

  final Duration timeout;

  @override
  Future<Uint8List> exchange(Uint8List request) async {
    if (!Platform.isWindows) {
      throw const ProfileProvisioningException('SERVICE_UNAVAILABLE');
    }
    RandomAccessFile? pipe;
    try {
      pipe = await File(_pipeName).open(mode: FileMode.write).timeout(timeout);
      await pipe.writeFrom(request).timeout(timeout);
      await pipe.flush().timeout(timeout);
      final Uint8List header = await _readExactly(pipe, 12).timeout(timeout);
      final ByteData headerData = ByteData.sublistView(header);
      final int bodyLength = headerData.getUint32(8, Endian.little);
      if (bodyLength > _maximumFrameSize - 12) {
        throw const ProfileProvisioningException('INVALID_RESPONSE');
      }
      final Uint8List body =
          await _readExactly(pipe, bodyLength).timeout(timeout);
      return Uint8List.fromList(<int>[...header, ...body]);
    } on ProfileProvisioningException {
      rethrow;
    } on TimeoutException {
      throw const ProfileProvisioningException('SERVICE_TIMEOUT');
    } on FileSystemException {
      throw const ProfileProvisioningException('SERVICE_UNAVAILABLE');
    } finally {
      await pipe?.close();
    }
  }

  static Future<Uint8List> _readExactly(
    RandomAccessFile file,
    int length,
  ) async {
    final BytesBuilder result = BytesBuilder(copy: false);
    while (result.length < length) {
      final Uint8List chunk = await file.read(length - result.length);
      if (chunk.isEmpty) {
        throw const ProfileProvisioningException('INVALID_RESPONSE');
      }
      result.add(chunk);
    }
    return result.takeBytes();
  }
}

final class WindowsVpnProfileProvisioner implements VpnProfileProvisioner {
  WindowsVpnProfileProvisioner({
    ProfileIpcTransport transport = const WindowsNamedPipeProfileTransport(),
    WireGuardConfigParser parser = const WireGuardConfigParser(),
    Random? random,
  })  : _transport = transport,
        _parser = parser,
        _random = random ?? Random.secure();

  final ProfileIpcTransport _transport;
  final WireGuardConfigParser _parser;
  final Random _random;

  @override
  Future<String> provisionWireGuard(String configuration) async {
    final WireGuardProvisioningProfile profile = _parser.parse(configuration);
    final String requestId = _identifier('request');
    final Uint8List response = await _transport.exchange(
      _encodeImport(requestId, _identifier('provision'), profile),
    );
    final _ProfileResponse decoded = _decodeResponse(response, requestId);
    if (decoded.code != 'PROFILE_STORED' || decoded.profileId == null) {
      throw ProfileProvisioningException(decoded.code);
    }
    return decoded.profileId!;
  }

  @override
  Future<void> deleteProfile(String profileId) async {
    if (!_validIdentifier(profileId)) {
      throw const ProfileProvisioningException('INVALID_PROFILE_HANDLE');
    }
    final String requestId = _identifier('request');
    final Uint8List response = await _transport.exchange(
      _encodeDelete(requestId, _identifier('cleanup'), profileId),
    );
    final _ProfileResponse decoded = _decodeResponse(response, requestId);
    if (decoded.code != 'PROFILE_DELETED' &&
        decoded.code != 'PROFILE_NOT_FOUND') {
      throw ProfileProvisioningException(decoded.code);
    }
  }

  String _identifier(String prefix) {
    final StringBuffer value = StringBuffer('$prefix-');
    for (var index = 0; index < 16; index += 1) {
      value.write(_random.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return value.toString();
  }
}

Uint8List _encodeImport(
  String requestId,
  String operationId,
  WireGuardProvisioningProfile profile,
) {
  final BytesBuilder body = BytesBuilder(copy: false)
    ..add(_identifierBytes(requestId))
    ..add(_identifierBytes(operationId))
    ..add(profile.privateKey)
    ..add(_stringList(profile.addresses))
    ..add(_stringList(profile.dnsServers))
    ..add(profile.peerPublicKey);
  if (profile.presharedKey == null) {
    body.addByte(0);
  } else {
    body
      ..addByte(1)
      ..add(profile.presharedKey!);
  }
  body
    ..add(_boundedString(profile.endpointHost))
    ..add(_u16(profile.endpointPort))
    ..add(_stringList(profile.allowedIps));
  if (profile.persistentKeepalive == null) {
    body.addByte(0);
  } else {
    body
      ..addByte(1)
      ..add(_u16(profile.persistentKeepalive!));
  }
  return _frame(5, body.takeBytes());
}

Uint8List _encodeDelete(
  String requestId,
  String operationId,
  String profileId,
) =>
    _frame(
      6,
      Uint8List.fromList(<int>[
        ..._identifierBytes(requestId),
        ..._identifierBytes(operationId),
        ..._identifierBytes(profileId),
      ]),
    );

Uint8List _frame(int opcode, Uint8List body) {
  if (body.length + 12 > _maximumFrameSize) {
    throw const ProfileProvisioningException('PROFILE_TOO_LARGE');
  }
  final Uint8List frame = Uint8List(body.length + 12);
  frame.setRange(0, 4, const <int>[0x4b, 0x56, 0x50, 0x4e]);
  ByteData.sublistView(frame)
    ..setUint16(4, 1, Endian.little)
    ..setUint8(6, opcode)
    ..setUint8(7, 0)
    ..setUint32(8, body.length, Endian.little);
  frame.setRange(12, frame.length, body);
  return frame;
}

Uint8List _identifierBytes(String value) {
  if (!_validIdentifier(value)) {
    throw const ProfileProvisioningException('INVALID_IDENTIFIER');
  }
  return _boundedString(value);
}

bool _validIdentifier(String value) =>
    value.isNotEmpty &&
    value.length <= 64 &&
    RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value);

Uint8List _boundedString(String value) {
  final Uint8List encoded = Uint8List.fromList(value.codeUnits);
  if (encoded.isEmpty || encoded.length > 253 || encoded.contains(0)) {
    throw const ProfileProvisioningException('INVALID_PROFILE');
  }
  return Uint8List.fromList(<int>[encoded.length, ...encoded]);
}

Uint8List _stringList(List<String> values) => Uint8List.fromList(<int>[
      values.length,
      for (final String value in values) ..._boundedString(value),
    ]);

Uint8List _u16(int value) {
  final Uint8List bytes = Uint8List(2);
  ByteData.sublistView(bytes).setUint16(0, value, Endian.little);
  return bytes;
}

_ProfileResponse _decodeResponse(Uint8List frame, String expectedRequestId) {
  if (frame.length < 12 || frame.length > _maximumFrameSize) {
    throw const ProfileProvisioningException('INVALID_RESPONSE');
  }
  final ByteData data = ByteData.sublistView(frame);
  if (frame[0] != 0x4b ||
      frame[1] != 0x56 ||
      frame[2] != 0x50 ||
      frame[3] != 0x4e ||
      data.getUint16(4, Endian.little) != 1 ||
      frame[6] != 0x81 ||
      frame[7] != 0 ||
      data.getUint32(8, Endian.little) != frame.length - 12) {
    throw const ProfileProvisioningException('INVALID_RESPONSE');
  }
  final _Cursor cursor = _Cursor(frame, 12);
  final String requestId = cursor.string();
  cursor.byte(); // connection phase is irrelevant to provisioning.
  final int hasProfile = cursor.byte();
  final String? profileId = switch (hasProfile) {
    0 => null,
    1 => cursor.string(),
    _ => throw const ProfileProvisioningException('INVALID_RESPONSE'),
  };
  final int killSwitch = cursor.byte();
  if (killSwitch != 0 && killSwitch != 1) {
    throw const ProfileProvisioningException('INVALID_RESPONSE');
  }
  final String code = cursor.string();
  if (!cursor.finished ||
      requestId != expectedRequestId ||
      !_validIdentifier(code) ||
      (profileId != null && !_validIdentifier(profileId))) {
    throw const ProfileProvisioningException('INVALID_RESPONSE');
  }
  return _ProfileResponse(profileId: profileId, code: code);
}

final class _ProfileResponse {
  const _ProfileResponse({required this.profileId, required this.code});

  final String? profileId;
  final String code;
}

final class _Cursor {
  _Cursor(this.bytes, this.offset);

  final Uint8List bytes;
  int offset;

  bool get finished => offset == bytes.length;

  int byte() {
    if (offset >= bytes.length) {
      throw const ProfileProvisioningException('INVALID_RESPONSE');
    }
    return bytes[offset++];
  }

  String string() {
    final int length = byte();
    final int end = offset + length;
    if (end > bytes.length) {
      throw const ProfileProvisioningException('INVALID_RESPONSE');
    }
    final String value = String.fromCharCodes(bytes.sublist(offset, end));
    offset = end;
    return value;
  }
}
