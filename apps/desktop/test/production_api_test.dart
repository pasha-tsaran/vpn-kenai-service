import 'package:flutter_test/flutter_test.dart';
import 'package:kenai_core/kenai_core.dart';
import 'package:kenai_vpn_desktop/src/infrastructure/production_api.dart';

void main() {
  test('accepts only an HTTPS production API base URI', () {
    expect(
      validatedProductionApiBaseUri('https://api.kenai.example'),
      Uri.parse('https://api.kenai.example/'),
    );
    for (final String value in <String>[
      '',
      'http://api.kenai.example',
      'https://user:password@api.kenai.example',
      'https://api.kenai.example?debug=true',
      'not a uri',
    ]) {
      expect(validatedProductionApiBaseUri(value), isNull);
    }
  });

  test('activation uses the real contract and retains only WireGuard',
      () async {
    final _RecordingApiClient transport = _RecordingApiClient(
      response: const ApiResponse(
        statusCode: 200,
        body: <String, Object?>{
          'account': <String, Object?>{
            'id': 'account-1',
            'email': null,
            'telegram_username': 'kenai_user',
            'phone_number': null,
          },
          'protocols': <String, Object?>{
            'wireguard': '[Interface]\nPrivateKey=fake\n[Peer]\nPublicKey=fake',
            'amneziawg': 'ignored-awg-secret',
            'vless': 'ignored-vless-secret',
          },
        },
      ),
    );
    final ProductionActivationApiClient client = ProductionActivationApiClient(
      apiClient: transport,
      now: () => DateTime.utc(2026, 9, 5, 12),
    );

    final ActivationResult result =
        await client.activate(ActivationKey.parse(_activationKey()));

    expect(client.isMock, isFalse);
    expect(transport.request?.method, ApiMethod.post);
    expect(transport.request?.path, '/api/v1/activate');
    expect(transport.request?.body['activation_key'], _activationKey());
    expect(result.account.id, 'account-1');
    expect(result.subscription.status, SubscriptionStatus.active);
    expect(result.subscription.lastVerifiedAt, DateTime.utc(2026, 9, 5, 12));
    expect(result.vpnCredentials.keys, <VpnProtocol>[VpnProtocol.wireGuard]);
    expect(result.vpnCredentials.values.single, isNot(contains('ignored')));
  });

  test('activation maps safe HTTP and transport failures', () async {
    for (final ({int status, AccountApiFailure failure}) item
        in <({int status, AccountApiFailure failure})>[
      (status: 401, failure: AccountApiFailure.invalidKey),
      (status: 429, failure: AccountApiFailure.rateLimited),
      (status: 503, failure: AccountApiFailure.server),
    ]) {
      final ProductionActivationApiClient client =
          ProductionActivationApiClient(
        apiClient: _RecordingApiClient(
          response: ApiResponse(
            statusCode: item.status,
            body: const <String, Object?>{},
          ),
        ),
      );
      await expectLater(
        client.activate(ActivationKey.parse(_activationKey())),
        throwsA(
          isA<AccountApiException>().having(
            (AccountApiException error) => error.failure,
            'failure',
            item.failure,
          ),
        ),
      );
    }

    final ProductionActivationApiClient offline = ProductionActivationApiClient(
      apiClient: const _FailingApiClient(
        ApiTransportFailure.noNetwork,
      ),
    );
    await expectLater(
      offline.activate(ActivationKey.parse(_activationKey())),
      throwsA(
        isA<AccountApiException>().having(
          (AccountApiException error) => error.failure,
          'failure',
          AccountApiFailure.noNetwork,
        ),
      ),
    );
  });

  test('malformed success response does not expose returned secrets', () async {
    final ProductionActivationApiClient client = ProductionActivationApiClient(
      apiClient: _RecordingApiClient(
        response: const ApiResponse(
          statusCode: 200,
          body: <String, Object?>{
            'account': <String, Object?>{'id': 'account-1'},
            'protocols': <String, Object?>{
              'wireguard': 'private-secret-without-sections',
            },
          },
        ),
      ),
    );
    try {
      await client.activate(ActivationKey.parse(_activationKey()));
      fail('Expected a safe API error');
    } on AccountApiException catch (error) {
      expect(error.failure, AccountApiFailure.server);
      expect(error.toString(), isNot(contains('private-secret')));
    }
  });
}

final class _RecordingApiClient implements ApiClient {
  _RecordingApiClient({required this.response});

  final ApiResponse response;
  ApiRequest? request;

  @override
  Future<ApiResponse> send(ApiRequest request) async {
    this.request = request;
    return response;
  }
}

final class _FailingApiClient implements ApiClient {
  const _FailingApiClient(this.failure);

  final ApiTransportFailure failure;

  @override
  Future<ApiResponse> send(ApiRequest request) =>
      throw ApiClientException(failure);
}

String _activationKey() => <String>['1234', '5678', '9012'].join();
