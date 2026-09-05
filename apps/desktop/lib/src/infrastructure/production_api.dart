import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kenai_core/kenai_core.dart';

const int _maximumResponseBytes = 256 * 1024;

Uri? validatedProductionApiBaseUri(String value) {
  if (value.trim().isEmpty) return null;
  final Uri? uri = Uri.tryParse(value.trim());
  if (uri == null ||
      uri.scheme != 'https' ||
      uri.host.isEmpty ||
      uri.hasQuery ||
      uri.hasFragment ||
      uri.userInfo.isNotEmpty) {
    return null;
  }
  return uri.path.endsWith('/') ? uri : uri.replace(path: '${uri.path}/');
}

final class DartIoApiClient implements ApiClient {
  DartIoApiClient({
    required this.baseUri,
    this.connectionTimeout = const Duration(seconds: 10),
    this.requestTimeout = const Duration(seconds: 20),
  });

  final Uri baseUri;
  final Duration connectionTimeout;
  final Duration requestTimeout;

  @override
  Future<ApiResponse> send(ApiRequest request) async {
    final Uri uri = _resolve(request);
    final HttpClient client = HttpClient()
      ..connectionTimeout = connectionTimeout
      ..userAgent = 'KenaiVPN/0.1.0 (Windows)';
    try {
      final HttpClientRequest outgoing = await client
          .openUrl(_method(request.method), uri)
          .timeout(requestTimeout);
      outgoing.headers.contentType = ContentType.json;
      outgoing.headers.set(HttpHeaders.acceptHeader, ContentType.json.mimeType);
      for (final MapEntry<String, String> header in request.headers.entries) {
        outgoing.headers.set(header.key, header.value);
      }
      if (request.body.isNotEmpty) {
        outgoing.add(utf8.encode(jsonEncode(request.body)));
      }
      final HttpClientResponse incoming =
          await outgoing.close().timeout(requestTimeout);
      final BytesBuilder bytes = BytesBuilder(copy: false);
      await for (final List<int> chunk in incoming.timeout(requestTimeout)) {
        if (bytes.length + chunk.length > _maximumResponseBytes) {
          throw const ApiClientException(
            ApiTransportFailure.malformedResponse,
          );
        }
        bytes.add(chunk);
      }
      final Map<String, Object?> body = _decodeBody(
        bytes.takeBytes(),
        requireObject: incoming.statusCode >= 200 && incoming.statusCode < 300,
      );
      return ApiResponse(statusCode: incoming.statusCode, body: body);
    } on ApiClientException {
      rethrow;
    } on TimeoutException {
      throw const ApiClientException(ApiTransportFailure.timeout);
    } on SocketException {
      throw const ApiClientException(ApiTransportFailure.noNetwork);
    } on HandshakeException {
      throw const ApiClientException(ApiTransportFailure.tls);
    } on TlsException {
      throw const ApiClientException(ApiTransportFailure.tls);
    } on FormatException {
      throw const ApiClientException(ApiTransportFailure.malformedResponse);
    } on HttpException {
      throw const ApiClientException(ApiTransportFailure.malformedResponse);
    } finally {
      client.close(force: true);
    }
  }

  Uri _resolve(ApiRequest request) {
    final Uri? relative = Uri.tryParse(request.path);
    if (relative == null ||
        !request.path.startsWith('/') ||
        relative.hasScheme ||
        relative.hasAuthority ||
        !request.path.startsWith('/api/')) {
      throw const ApiClientException(ApiTransportFailure.unavailable);
    }
    return baseUri.resolveUri(relative.replace(queryParameters: request.query));
  }

  static String _method(ApiMethod method) => switch (method) {
        ApiMethod.get => 'GET',
        ApiMethod.post => 'POST',
        ApiMethod.put => 'PUT',
        ApiMethod.patch => 'PATCH',
        ApiMethod.delete => 'DELETE',
      };

  static Map<String, Object?> _decodeBody(
    List<int> bytes, {
    required bool requireObject,
  }) {
    if (bytes.isEmpty && !requireObject) return const <String, Object?>{};
    final Object? decoded = jsonDecode(utf8.decode(bytes));
    if (decoded is! Map<String, Object?>) {
      if (!requireObject) return const <String, Object?>{};
      throw const FormatException('Expected a JSON object');
    }
    return decoded;
  }
}

final class ProductionActivationApiClient implements ActivationApiClient {
  ProductionActivationApiClient({
    required ApiClient apiClient,
    DateTime Function()? now,
  })  : _apiClient = apiClient,
        _now = now ?? DateTime.now;

  final ApiClient _apiClient;
  final DateTime Function() _now;

  @override
  bool get isMock => false;

  @override
  Future<ActivationResult> activate(ActivationKey activationKey) async {
    final ApiResponse response;
    try {
      response = await _apiClient.send(
        ApiRequest(
          method: ApiMethod.post,
          path: '/api/v1/activate',
          body: <String, Object?>{'activation_key': activationKey.value},
        ),
      );
    } on ApiClientException catch (error) {
      final AccountApiFailure failure = switch (error.failure) {
        ApiTransportFailure.noNetwork ||
        ApiTransportFailure.timeout =>
          AccountApiFailure.noNetwork,
        _ => AccountApiFailure.server,
      };
      throw AccountApiException(failure);
    }

    if (response.statusCode == HttpStatus.unauthorized) {
      throw const AccountApiException(AccountApiFailure.invalidKey);
    }
    if (response.statusCode == HttpStatus.tooManyRequests) {
      throw const AccountApiException(AccountApiFailure.rateLimited);
    }
    if (response.statusCode != HttpStatus.ok) {
      throw const AccountApiException(AccountApiFailure.server);
    }

    try {
      final Map<String, Object?> account = _object(response.body, 'account');
      final Map<String, Object?> protocols =
          _object(response.body, 'protocols');
      final String wireGuard = _requiredString(
        protocols,
        'wireguard',
        maximumLength: 64 * 1024,
      );
      if (!wireGuard.contains('[Interface]') || !wireGuard.contains('[Peer]')) {
        throw const FormatException('Invalid WireGuard profile');
      }
      return ActivationResult(
        account: Account(
          id: _requiredString(account, 'id', maximumLength: 128),
          email: _optionalString(account, 'email', maximumLength: 254),
          telegramUsername: _optionalString(
            account,
            'telegram_username',
            maximumLength: 64,
          ),
          phoneNumber: _optionalString(
            account,
            'phone_number',
            maximumLength: 32,
          ),
        ),
        subscription: Subscription(
          status: SubscriptionStatus.active,
          planName: 'Активная подписка',
          expiresAt: null,
          deviceLimit: 1,
          lastVerifiedAt: _now().toUtc(),
        ),
        // The MVP intentionally retains only WireGuard. The current server
        // returns AWG/Xray too; those values are ignored and never persisted.
        vpnCredentials: <VpnProtocol, String>{
          VpnProtocol.wireGuard: wireGuard,
        },
      );
    } on FormatException {
      throw const AccountApiException(AccountApiFailure.server);
    } on TypeError {
      throw const AccountApiException(AccountApiFailure.server);
    }
  }

  static Map<String, Object?> _object(
    Map<String, Object?> source,
    String key,
  ) {
    final Object? value = source[key];
    if (value is! Map<String, Object?>) {
      throw FormatException('Invalid $key');
    }
    return value;
  }

  static String _requiredString(
    Map<String, Object?> source,
    String key, {
    required int maximumLength,
  }) {
    final String? value =
        _optionalString(source, key, maximumLength: maximumLength);
    if (value == null || value.isEmpty) throw FormatException('Invalid $key');
    return value;
  }

  static String? _optionalString(
    Map<String, Object?> source,
    String key, {
    required int maximumLength,
  }) {
    final Object? value = source[key];
    if (value == null) return null;
    if (value is! String ||
        value.length > maximumLength ||
        value.contains(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F]'))) {
      throw FormatException('Invalid $key');
    }
    return value;
  }
}
