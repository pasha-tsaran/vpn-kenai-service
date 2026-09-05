import 'dart:convert';

import '../domain/models.dart';
import '../ports/ports.dart';

/// Stable non-secret storage key names shared with platform VPN adapters.
abstract final class SecureAccountStorageKeys {
  static const String activationKey = 'account.activation_key';
  static const String session = 'account.session';
  static const String wireGuard = 'vpn.wireguard';
  static const String amneziaWg = 'vpn.amneziawg';
  static const String vless = 'vpn.vless';
  static const String profileHandle = 'vpn.profile_handle';
  static const String amneziaWgProfileHandle = 'vpn.amneziawg_profile_handle';
}

final class SecureAccountRepository implements AccountRepository {
  SecureAccountRepository({
    required ActivationApiClient apiClient,
    required SecureStorage secureStorage,
    VpnProfileProvisioner? profileProvisioner,
  })  : _apiClient = apiClient,
        _secureStorage = secureStorage,
        _profileProvisioner = profileProvisioner;

  static const String _activationKey = SecureAccountStorageKeys.activationKey;
  static const String _session = SecureAccountStorageKeys.session;
  static const String _wireGuard = SecureAccountStorageKeys.wireGuard;
  static const String _amneziaWg = SecureAccountStorageKeys.amneziaWg;
  static const String _vless = SecureAccountStorageKeys.vless;
  static const String _profileHandle = SecureAccountStorageKeys.profileHandle;
  static const String _amneziaWgProfileHandle =
      SecureAccountStorageKeys.amneziaWgProfileHandle;

  final ActivationApiClient _apiClient;
  final SecureStorage _secureStorage;
  final VpnProfileProvisioner? _profileProvisioner;

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
    String? provisionedHandle;
    String? provisionedAmneziaWgHandle;
    try {
      await _secureStorage.write(
        key: _activationKey,
        value: activationKey.value,
      );
      final String? wireGuard = result.vpnCredentials[VpnProtocol.wireGuard];
      if (_profileProvisioner != null && wireGuard != null) {
        provisionedHandle =
            await _profileProvisioner.provisionWireGuard(wireGuard);
        await _secureStorage.write(
          key: _profileHandle,
          value: provisionedHandle,
        );
        await _secureStorage.delete(_wireGuard);
      } else {
        await _writeCredential(_wireGuard, wireGuard);
        await _secureStorage.delete(_profileHandle);
      }
      await _writeCredential(
        _amneziaWg,
        _profileProvisioner == null
            ? result.vpnCredentials[VpnProtocol.amneziaWg]
            : null,
      );
      final String? amneziaWg = result.vpnCredentials[VpnProtocol.amneziaWg];
      if (_profileProvisioner != null && amneziaWg != null) {
        provisionedAmneziaWgHandle =
            await _profileProvisioner.provisionAmneziaWg(amneziaWg);
        await _secureStorage.write(
            key: _amneziaWgProfileHandle, value: provisionedAmneziaWgHandle);
      } else {
        await _secureStorage.delete(_amneziaWgProfileHandle);
      }
      await _writeCredential(
        _vless,
        result.vpnCredentials[VpnProtocol.vlessReality],
      );
      await _secureStorage.write(key: _session, value: _encode(session));
      return session;
    } on Object {
      if (provisionedHandle != null) {
        try {
          await _profileProvisioner?.deleteProfile(provisionedHandle);
        } on Object {
          // Preserve the original activation/storage failure. The service uses
          // opaque encrypted files; a later activation replaces stale state.
        }
      }
      if (provisionedAmneziaWgHandle != null) {
        try {
          await _profileProvisioner?.deleteProfile(provisionedAmneziaWgHandle);
        } on Object {/* preserve original error */}
      }
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
  Future<void> signOut() async {
    final String? profileHandle = await _secureStorage.read(_profileHandle);
    if (profileHandle != null && _profileProvisioner != null) {
      await _profileProvisioner.deleteProfile(profileHandle);
    }
    final String? amneziaWgHandle =
        await _secureStorage.read(_amneziaWgProfileHandle);
    if (amneziaWgHandle != null && _profileProvisioner != null) {
      await _profileProvisioner.deleteProfile(amneziaWgHandle);
    }
    await _clearAccountData();
  }

  Future<void> _clearAccountData() async {
    for (final String key in <String>[
      _activationKey,
      _session,
      _wireGuard,
      _amneziaWg,
      _vless,
      _profileHandle,
      _amneziaWgProfileHandle,
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
