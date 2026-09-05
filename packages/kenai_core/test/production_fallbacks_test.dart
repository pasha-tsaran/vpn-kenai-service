import 'package:kenai_core/kenai_core.dart';
import 'package:test/test.dart';

void main() {
  test('MVP server repository exposes Armenia with implemented engines',
      () async {
    final ArmeniaMvpServerRepository repository = ArmeniaMvpServerRepository();

    final List<VpnServer> servers = await repository.getServers();

    expect(repository.isMock, isFalse);
    expect(servers, hasLength(1));
    expect(servers.single.countryCode, 'AM');
    expect(servers.single.isTest, isFalse);
    expect(servers.single.protocols, <VpnProtocol>{
      VpnProtocol.wireGuard,
      VpnProtocol.amneziaWg,
      VpnProtocol.vlessReality,
    });
    expect(await repository.getServers(query: 'Германия'), isEmpty);
  });

  test('unavailable release engine never reports a connection', () async {
    final UnavailableVpnEngine engine = UnavailableVpnEngine();
    final List<VpnConnectionState> states = <VpnConnectionState>[];
    final subscription = engine.states.listen(states.add);

    await engine.connect(
      const ConnectionRequest(
        operationId: 'connect-1',
        profile: VpnProfile(
          id: 'profile-armenia-1-wireGuard',
          deviceId: 'local-windows-device',
          serverId: 'armenia-1',
          protocol: VpnProtocol.wireGuard,
        ),
        killSwitch: false,
      ),
    );

    expect(engine.isMock, isFalse);
    expect(engine.supportedProtocols, isEmpty);
    expect(states.single.phase, VpnConnectionPhase.error);
    expect(states.single.errorCode, 'ENGINE_NOT_INSTALLED');
    expect((await engine.status()).phase, isNot(VpnConnectionPhase.connected));
    await subscription.cancel();
  });
}
