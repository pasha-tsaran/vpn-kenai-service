import 'dart:convert';

import '../domain/models.dart';
import '../ports/ports.dart';

final class SecureAccountRepository implements AccountRepository {
  SecureAccountRepository({
    required ActivationApiClient apiClient,
    required SecureStorage secureStorage,
  })  : _apiClient = apiClient,
        _secureStorage = secureStorage;

  static const String _activationKey = 'account.activation_key';
  static const String _session = 'account.session';
  static const String _wireGuard = 'vpn.wireguard';
  static const String _amneziaWg = 'vpn.amneziawg';
  static const String _vless = 'vpn.vless';

  final ActivationApiClient _apiClient;
  final SecureStorage _secureStorage;

  @override
  bool get isMock => _apiClient.isMock;

  @override
  Future<AccountSession> activate(ActivationKey activationKey) async {
    final ActivationResult result = await _apiClient.activate(activationKey);
    final AccountSession session = AccountSession(
      account: result.account,
      subscription: result.subscription,
      activationKeyMask: activationKey.masked,
    );
    try {
      await _secureStorage.write(
        key: _activationKey,
        value: activationKey.value,
      );
      await _writeCredential(
        _wireGuard,
        result.vpnCredentials[VpnProtocol.wireGuard],
      );
      await _writeCredential(
        _amneziaWg,
        result.vpnCredentials[VpnProtocol.amneziaWg],
      );
      await _writeCredential(
        _vless,
        result.vpnCredentials[VpnProtocol.vlessReality],
      );
      await _secureStorage.write(key: _session, value: _encode(session));
      return session;
    } on Object {
      await _clearAccountData();
      rethrow;
    }
  }

  @override
  Future<AccountSession?> restoreSession() async {
    final String? encoded = await _secureStorage.read(_session);
    if (encoded == null) return null;
    try {
      return _decode(encoded);
    } on Object {
      await _clearAccountData();
      return null;
    }
  }

  @override
  Future<String?> revealActivationKey() => _secureStorage.read(_activationKey);

  @override
  Future<void> signOut() => _clearAccountData();

  Future<void> _clearAccountData() async {
    for (final String key in <String>[
      _activationKey,
      _session,
      _wireGuard,
      _amneziaWg,
      _vless,
    ]) {
      await _secureStorage.delete(key);
    }
  }

  Future<void> _writeCredential(String key, String? value) async {
    if (value == null || value.isEmpty) {
      await _secureStorage.delete(key);
      return;
    }
    await _secureStorage.write(key: key, value: value);
  }

  static String _encode(AccountSession session) => jsonEncode(
        <String, Object?>{
          'account': <String, Object?>{
            'id': session.account.id,
            'email': session.account.email,
            'telegram_username': session.account.telegramUsername,
            'phone_number': session.account.phoneNumber,
          },
          'subscription': <String, Object?>{
            'status': session.subscription.status.name,
            'plan_name': session.subscription.planName,
            'expires_at': session.subscription.expiresAt?.toIso8601String(),
            'device_limit': session.subscription.deviceLimit,
            'last_verified_at':
                session.subscription.lastVerifiedAt?.toIso8601String(),
          },
          'activation_key_mask': session.activationKeyMask,
        },
      );

  static AccountSession _decode(String encoded) {
    final Map<String, Object?> data =
        jsonDecode(encoded) as Map<String, Object?>;
    final Map<String, Object?> account =
        data['account']! as Map<String, Object?>;
    final Map<String, Object?> subscription =
        data['subscription']! as Map<String, Object?>;
    return AccountSession(
      account: Account(
        id: account['id']! as String,
        email: account['email'] as String?,
        telegramUsername: account['telegram_username'] as String?,
        phoneNumber: account['phone_number'] as String?,
      ),
      subscription: Subscription(
        status: SubscriptionStatus.values.byName(
          subscription['status']! as String,
        ),
        planName: subscription['plan_name']! as String,
        expiresAt: _date(subscription['expires_at']),
        deviceLimit: subscription['device_limit']! as int,
        lastVerifiedAt: _date(subscription['last_verified_at']),
      ),
      activationKeyMask: data['activation_key_mask']! as String,
    );
  }

  static DateTime? _date(Object? value) =>
      value is String ? DateTime.parse(value) : null;
}
