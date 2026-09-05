import 'dart:async';

import 'package:flutter/material.dart';
import 'package:kenai_core/kenai_core.dart';
import 'package:kenai_ui/kenai_ui.dart';

import '../../bootstrap.dart';

final class ServersScreen extends StatefulWidget {
  const ServersScreen({required this.dependencies, super.key});

  final AppDependencies dependencies;

  @override
  State<ServersScreen> createState() => _ServersScreenState();
}

final class _ServersScreenState extends State<ServersScreen> {
  late VpnConnectionState _connection;
  late VpnStatistics _statistics;
  late final StreamSubscription<VpnConnectionState> _subscription;
  Timer? _connectionTimer;
  List<VpnServer> _allServers = <VpnServer>[];
  List<VpnServer> _visibleServers = <VpnServer>[];
  bool _catalogLoading = true;
  bool _catalogFailed = false;
  int _catalogRequest = 0;
  VpnServer? _selected;
  VpnProtocol? _selectedProtocol;
  ProtocolPreference _protocolPreference = ProtocolPreference.automatic;
  String _query = '';
  String? _countryCode;
  ServerSort _sort = ServerSort.recommended;
  bool _favoritesOnly = false;
  bool _pinging = false;

  @override
  void initState() {
    super.initState();
    _connection = const VpnConnectionState.disconnected();
    _statistics = VpnStatistics(
      bytesReceived: 0,
      bytesSent: 0,
      measuredAt: DateTime.now(),
    );
    _subscription = widget.dependencies.vpnEngine.states.listen(
      _applyConnectionState,
    );
    unawaited(_loadInitialData());
  }

  @override
  void dispose() {
    _connectionTimer?.cancel();
    unawaited(_subscription.cancel());
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.all(KenaiSpacing.xl),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              children: <Widget>[
                Expanded(
                  child: Text(
                    'Серверы',
                    style: Theme.of(context).textTheme.headlineMedium,
                  ),
                ),
                if (widget.dependencies.serverRepository.isMock)
                  _MockBadge(hasTestServers: _allServers.any(_isTestServer)),
              ],
            ),
            const SizedBox(height: KenaiSpacing.md),
            Expanded(
              child: LayoutBuilder(
                builder: (BuildContext context, BoxConstraints constraints) {
                  if (constraints.maxWidth < 900) {
                    return ListView(
                      children: <Widget>[
                        SizedBox(height: 500, child: _buildCatalog()),
                        const SizedBox(height: KenaiSpacing.lg),
                        SizedBox(height: 530, child: _buildConnectionPanel()),
                      ],
                    );
                  }
                  return Row(
                    children: <Widget>[
                      Expanded(flex: 48, child: _buildCatalog()),
                      const SizedBox(width: KenaiSpacing.lg),
                      Expanded(flex: 52, child: _buildConnectionPanel()),
                    ],
                  );
                },
              ),
            ),
          ],
        ),
      );

  Widget _buildCatalog() => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Row(
            children: <Widget>[
              Expanded(
                child: TextField(
                  key: const Key('server-search'),
                  decoration: const InputDecoration(
                    hintText: 'Страна, город или сервер',
                    prefixIcon: Icon(Icons.search),
                  ),
                  onChanged: (String query) {
                    _query = query;
                    _reloadServers();
                  },
                ),
              ),
              const SizedBox(width: KenaiSpacing.sm),
              PopupMenuButton<ServerSort>(
                key: const Key('server-sort'),
                tooltip: 'Сортировка: ${_sortLabel(_sort)}',
                initialValue: _sort,
                onSelected: (ServerSort value) {
                  _sort = value;
                  _reloadServers();
                },
                itemBuilder: (BuildContext context) => ServerSort.values
                    .map(
                      (ServerSort value) => PopupMenuItem<ServerSort>(
                        value: value,
                        child: Text(_sortLabel(value)),
                      ),
                    )
                    .toList(growable: false),
                icon: const Icon(Icons.sort),
              ),
            ],
          ),
          const SizedBox(height: KenaiSpacing.sm),
          SizedBox(
            height: 40,
            child: ListView(
              scrollDirection: Axis.horizontal,
              children: <Widget>[
                FilterChip(
                  key: const Key('favorites-filter'),
                  selected: _favoritesOnly,
                  avatar: const Icon(Icons.star_outline, size: 18),
                  label: const Text('Избранное'),
                  onSelected: (bool selected) {
                    _favoritesOnly = selected;
                    _reloadServers();
                  },
                ),
                const SizedBox(width: KenaiSpacing.sm),
                ChoiceChip(
                  key: const Key('country-all'),
                  selected: _countryCode == null,
                  label: const Text('Все страны'),
                  onSelected: (_) => _selectCountry(null),
                ),
                for (final ({String code, String name}) country in _countries)
                  Padding(
                    padding: const EdgeInsets.only(left: KenaiSpacing.sm),
                    child: ChoiceChip(
                      key: Key('country-${country.code}'),
                      selected: _countryCode == country.code,
                      label: Text(country.name),
                      onSelected: (_) => _selectCountry(country.code),
                    ),
                  ),
              ],
            ),
          ),
          const SizedBox(height: KenaiSpacing.sm),
          Expanded(
            child: _buildServerList(),
          ),
        ],
      );

  Widget _buildServerList() {
    if (_catalogLoading) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_catalogFailed) {
      return const _CatalogMessage(
        icon: Icons.cloud_off_outlined,
        title: 'Не удалось загрузить серверы',
        message: 'Проверьте подключение и попробуйте ещё раз.',
      );
    }
    if (_visibleServers.isEmpty) {
      return const _CatalogMessage(
        icon: Icons.search_off,
        title: 'Ничего не найдено',
        message: 'Измените поиск или фильтры.',
      );
    }
    return Card(
      clipBehavior: Clip.antiAlias,
      child: ListView.separated(
        itemCount: _visibleServers.length,
        separatorBuilder: (_, __) => const Divider(height: 1),
        itemBuilder: (BuildContext context, int index) =>
            _buildServerTile(_visibleServers[index]),
      ),
    );
  }

  Widget _buildServerTile(VpnServer server) {
    final _AvailabilityCopy availability = _availability(server.status);
    final bool selectionLocked = _connection.phase.isBusy ||
        _connection.phase == VpnConnectionPhase.connected;
    return ListTile(
      key: Key('server-${server.id}'),
      selected: _selected?.id == server.id,
      enabled: !selectionLocked,
      contentPadding: const EdgeInsets.fromLTRB(16, 8, 8, 8),
      leading: CircleAvatar(child: Text(server.countryCode)),
      title: Row(
        children: <Widget>[
          Flexible(child: Text(server.name, overflow: TextOverflow.ellipsis)),
          if (server.isRecommended)
            const Padding(
              padding: EdgeInsets.only(left: KenaiSpacing.sm),
              child: _SmallBadge(label: 'Рекомендуемый'),
            ),
          if (server.isTest)
            const Padding(
              padding: EdgeInsets.only(left: KenaiSpacing.sm),
              child: _SmallBadge(label: 'Тестовый', warning: true),
            ),
        ],
      ),
      subtitle: Padding(
        padding: const EdgeInsets.only(top: KenaiSpacing.xs),
        child: Row(
          children: <Widget>[
            Flexible(child: Text('${server.countryName}, ${server.city}')),
            const SizedBox(width: KenaiSpacing.sm),
            Icon(Icons.circle, size: 8, color: availability.color),
            const SizedBox(width: KenaiSpacing.xs),
            Text(availability.label),
          ],
        ),
      ),
      trailing: Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Text(_latencyLabel(server.status.latency)),
          IconButton(
            key: Key('favorite-${server.id}'),
            tooltip: server.isFavorite
                ? 'Удалить из избранного'
                : 'Добавить в избранное',
            onPressed: () => _toggleFavorite(server),
            icon: Icon(
              server.isFavorite ? Icons.star : Icons.star_outline,
              color: server.isFavorite ? KenaiTheme.warning : null,
            ),
          ),
        ],
      ),
      onTap: selectionLocked ? null : () => _selectServer(server),
    );
  }

  Widget _buildConnectionPanel() {
    final VpnServer? server = _selected;
    if (server == null) {
      return const Card(
        child: _CatalogMessage(
          icon: Icons.dns_outlined,
          title: 'Выберите сервер',
          message: 'Сведения о подключении появятся здесь.',
        ),
      );
    }
    final _ConnectionCopy copy = _connectionCopy(_connection.phase);
    final bool connected = _connection.phase == VpnConnectionPhase.connected;
    final VpnProtocol protocol =
        _connection.protocol ?? _selectedProtocol ?? server.protocols.first;
    final bool engineSupportsProtocol =
        widget.dependencies.vpnEngine.supportedProtocols.contains(protocol);
    final bool canConnect = server.isAvailable &&
        !_connection.phase.isBusy &&
        engineSupportsProtocol;
    final _AvailabilityCopy availability = _availability(server.status);

    return Card(
      child: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(KenaiSpacing.xxl),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: <Widget>[
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: <Widget>[
                  CircleAvatar(
                    radius: 24,
                    child: Text(server.countryCode),
                  ),
                  const SizedBox(width: KenaiSpacing.md),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(
                          server.name,
                          style: Theme.of(context).textTheme.titleLarge,
                        ),
                        Text('${server.countryName}, ${server.city}'),
                        const SizedBox(height: KenaiSpacing.xs),
                        Wrap(
                          spacing: KenaiSpacing.sm,
                          runSpacing: KenaiSpacing.xs,
                          children: <Widget>[
                            if (server.isRecommended)
                              const _SmallBadge(label: 'Рекомендуемый'),
                            if (server.isTest)
                              const _SmallBadge(
                                label: 'Тестовый сервер',
                                warning: true,
                              ),
                            _StatusBadge(copy: availability),
                          ],
                        ),
                      ],
                    ),
                  ),
                  IconButton(
                    key: const Key('ping-button'),
                    tooltip: 'Проверить ping',
                    onPressed: _pinging ? null : _pingSelected,
                    icon: _pinging
                        ? const SizedBox.square(
                            dimension: 20,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Icon(Icons.network_ping),
                  ),
                ],
              ),
              const SizedBox(height: KenaiSpacing.lg),
              DropdownButtonFormField<VpnProtocol>(
                key: ValueKey<String>('protocol-${server.id}'),
                initialValue: protocol,
                decoration: const InputDecoration(
                  labelText: 'Протокол',
                  prefixIcon: Icon(Icons.security_outlined),
                ),
                items: server.protocols
                    .map(
                      (VpnProtocol value) => DropdownMenuItem<VpnProtocol>(
                        value: value,
                        child: Text(_protocolLabel(value)),
                      ),
                    )
                    .toList(growable: false),
                onChanged: connected || _connection.phase.isBusy
                    ? null
                    : (VpnProtocol? value) {
                        if (value != null) {
                          setState(() => _selectedProtocol = value);
                        }
                      },
              ),
              const SizedBox(height: KenaiSpacing.lg),
              Icon(
                connected ? Icons.lock : Icons.lock_open,
                size: 32,
                color: connected ? KenaiTheme.success : availability.color,
              ),
              const SizedBox(height: KenaiSpacing.sm),
              Text(
                copy.title,
                key: const Key('connection-phase'),
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: KenaiSpacing.xs),
              Text(
                copy.message,
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodyMedium,
              ),
              const SizedBox(height: KenaiSpacing.lg),
              Center(
                child: Semantics(
                  button: true,
                  label: connected ? 'Отключить VPN' : 'Подключить VPN',
                  child: SizedBox.square(
                    dimension: 132,
                    child: FilledButton(
                      key: const Key('connect-button'),
                      style: FilledButton.styleFrom(
                        shape: const CircleBorder(),
                      ),
                      onPressed: canConnect ? _toggleConnection : null,
                      child: _connection.phase.isBusy
                          ? const CircularProgressIndicator(color: Colors.white)
                          : Icon(
                              connected ? Icons.stop : Icons.power_settings_new,
                              size: 48,
                            ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: KenaiSpacing.sm),
              Text(
                connected ? 'Отключить' : 'Подключиться',
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: KenaiSpacing.lg),
              Wrap(
                alignment: WrapAlignment.center,
                spacing: KenaiSpacing.sm,
                runSpacing: KenaiSpacing.sm,
                children: <Widget>[
                  _Metric(
                    key: const Key('connection-time'),
                    icon: Icons.schedule,
                    label: 'Время',
                    value: _durationLabel(_connectedDuration),
                  ),
                  _Metric(
                    key: const Key('traffic-received'),
                    icon: Icons.south,
                    label: 'Получено',
                    value: _bytesLabel(_statistics.bytesReceived),
                  ),
                  _Metric(
                    key: const Key('traffic-sent'),
                    icon: Icons.north,
                    label: 'Передано',
                    value: _bytesLabel(_statistics.bytesSent),
                  ),
                  _Metric(
                    key: const Key('selected-ping'),
                    icon: Icons.network_ping,
                    label: 'Ping',
                    value: _latencyLabel(server.status.latency),
                  ),
                ],
              ),
              const SizedBox(height: KenaiSpacing.md),
              if (widget.dependencies.vpnEngine.isMock)
                Text(
                  'Mock VPN · системные настройки не изменяются',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                )
              else if (!engineSupportsProtocol)
                Text(
                  'VPN-движок недоступен в этой сборке.',
                  textAlign: TextAlign.center,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
            ],
          ),
        ),
      ),
    );
  }

  List<({String code, String name})> get _countries {
    final Map<String, String> countries = <String, String>{
      for (final VpnServer server in _allServers)
        server.countryCode: server.countryName,
    };
    final List<({String code, String name})> result = countries.entries
        .map((entry) => (code: entry.key, name: entry.value))
        .toList(growable: false);
    result.sort((left, right) => left.name.compareTo(right.name));
    return result;
  }

  Duration get _connectedDuration {
    final DateTime? connectedAt = _connection.connectedAt;
    if (connectedAt == null) return Duration.zero;
    final Duration elapsed = DateTime.now().difference(connectedAt);
    return elapsed.isNegative ? Duration.zero : elapsed;
  }

  Future<void> _loadInitialData() async {
    try {
      final List<VpnServer> servers =
          await widget.dependencies.serverRepository.getServers();
      final VpnServer? selected =
          await widget.dependencies.serverRepository.getSelectedServer();
      final AppSettings settings =
          await widget.dependencies.settingsRepository.load();
      final VpnConnectionState state =
          await widget.dependencies.vpnEngine.status();
      if (!mounted) return;
      setState(() {
        _allServers = servers;
        _visibleServers = servers;
        _catalogLoading = false;
        _catalogFailed = false;
        _selected = selected;
        _protocolPreference = settings.protocol;
        _selectedProtocol = selected == null
            ? null
            : _preferredProtocol(selected, settings.protocol);
      });
      _applyConnectionState(state);
    } on Object {
      if (!mounted) return;
      setState(() {
        _catalogLoading = false;
        _catalogFailed = true;
      });
      _showSafeMessage('Не удалось подготовить список серверов.');
    }
  }

  Future<void> _reloadServers() async {
    final int request = ++_catalogRequest;
    setState(() {
      _catalogLoading = true;
      _catalogFailed = false;
    });
    try {
      final List<VpnServer> servers =
          await widget.dependencies.serverRepository.getServers(
        query: _query,
        sort: _sort,
        countryCode: _countryCode,
        favoritesOnly: _favoritesOnly,
      );
      if (!mounted || request != _catalogRequest) return;
      setState(() {
        _visibleServers = servers;
        _catalogLoading = false;
      });
    } on Object {
      if (!mounted || request != _catalogRequest) return;
      setState(() {
        _catalogLoading = false;
        _catalogFailed = true;
      });
    }
  }

  void _selectCountry(String? countryCode) {
    _countryCode = countryCode;
    _reloadServers();
  }

  Future<void> _selectServer(VpnServer server) async {
    try {
      await widget.dependencies.serverRepository.selectServer(server.id);
      if (!mounted) return;
      setState(() {
        _selected = server;
        _selectedProtocol = _preferredProtocol(server, _protocolPreference);
      });
    } on Object {
      if (mounted) _showSafeMessage('Не удалось выбрать сервер.');
    }
  }

  Future<void> _toggleFavorite(VpnServer server) async {
    try {
      await widget.dependencies.serverRepository.toggleFavorite(server.id);
      final VpnServer? selected =
          await widget.dependencies.serverRepository.getSelectedServer();
      if (!mounted) return;
      setState(() => _selected = selected);
      await _reloadServers();
    } on Object {
      if (mounted) _showSafeMessage('Не удалось изменить избранное.');
    }
  }

  Future<void> _pingSelected() async {
    final VpnServer? server = _selected;
    if (server == null || _pinging) return;
    setState(() => _pinging = true);
    try {
      final Duration? latency =
          await widget.dependencies.serverRepository.ping(server.id);
      final VpnServer? selected =
          await widget.dependencies.serverRepository.getSelectedServer();
      if (!mounted) return;
      setState(() {
        _selected = selected;
        _pinging = false;
      });
      await _reloadServers();
      if (latency == null) {
        _showSafeMessage('Ping для этого сервера временно недоступен.');
      }
    } on Object {
      if (!mounted) return;
      setState(() => _pinging = false);
      _showSafeMessage('Не удалось проверить ping.');
    }
  }

  Future<void> _toggleConnection() async {
    final VpnServer? server = _selected;
    if (server == null) return;
    try {
      if (_connection.phase == VpnConnectionPhase.connected) {
        await widget.dependencies.vpnEngine.disconnect(
          operationId: 'disconnect-${DateTime.now().microsecondsSinceEpoch}',
        );
        return;
      }
      if (!server.isAvailable) {
        _showSafeMessage('Этот сервер сейчас недоступен.');
        return;
      }
      final VpnProtocol protocol = _selectedProtocol ?? server.protocols.first;
      await widget.dependencies.vpnEngine.connect(
        ConnectionRequest(
          operationId: 'connect-${DateTime.now().microsecondsSinceEpoch}',
          profile: VpnProfile(
            id: 'profile-${server.id}-${protocol.name}',
            deviceId: 'local-windows-device',
            serverId: server.id,
            protocol: protocol,
          ),
          // Enabled only after the dedicated leak-test gate.
          killSwitch: false,
        ),
      );
    } on Object {
      if (mounted) {
        _showSafeMessage('Операцию выполнить не удалось. Попробуйте ещё раз.');
      }
    }
  }

  void _applyConnectionState(VpnConnectionState state) {
    if (!mounted) return;
    setState(() => _connection = state);
    if (state.phase == VpnConnectionPhase.connected) {
      _startConnectionTimer();
      unawaited(_refreshStatistics());
    } else if (!state.phase.isBusy) {
      _stopConnectionTimer(resetStatistics: true);
    }
  }

  void _startConnectionTimer() {
    _connectionTimer ??= Timer.periodic(const Duration(seconds: 1), (_) {
      if (!mounted) return;
      setState(() {});
      unawaited(_refreshStatistics());
    });
  }

  void _stopConnectionTimer({required bool resetStatistics}) {
    _connectionTimer?.cancel();
    _connectionTimer = null;
    if (resetStatistics) {
      _statistics = VpnStatistics(
        bytesReceived: 0,
        bytesSent: 0,
        measuredAt: DateTime.now(),
      );
    }
  }

  Future<void> _refreshStatistics() async {
    if (_connection.phase != VpnConnectionPhase.connected) return;
    final VpnStatistics statistics =
        await widget.dependencies.vpnEngine.statistics();
    if (mounted && _connection.phase == VpnConnectionPhase.connected) {
      setState(() => _statistics = statistics);
    }
  }

  void _showSafeMessage(String message) {
    ScaffoldMessenger.of(context)
      ..hideCurrentSnackBar()
      ..showSnackBar(SnackBar(content: Text(message)));
  }
}

final class _MockBadge extends StatelessWidget {
  const _MockBadge({required this.hasTestServers});

  final bool hasTestServers;

  @override
  Widget build(BuildContext context) => Container(
        key: const Key('mock-api-badge'),
        padding: const EdgeInsets.symmetric(
          horizontal: KenaiSpacing.md,
          vertical: KenaiSpacing.sm,
        ),
        decoration: BoxDecoration(
          color: KenaiTheme.warning.withValues(alpha: 0.14),
          borderRadius: BorderRadius.circular(KenaiRadii.control),
        ),
        child: Text(
          hasTestServers ? 'Mock API · тестовые серверы' : 'Mock API',
        ),
      );
}

final class _SmallBadge extends StatelessWidget {
  const _SmallBadge({required this.label, this.warning = false});

  final String label;
  final bool warning;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
        decoration: BoxDecoration(
          color: (warning ? KenaiTheme.warning : KenaiTheme.accent).withValues(
            alpha: 0.14,
          ),
          borderRadius: BorderRadius.circular(99),
        ),
        child: Text(label, style: Theme.of(context).textTheme.labelSmall),
      );
}

final class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.copy});

  final _AvailabilityCopy copy;

  @override
  Widget build(BuildContext context) => Row(
        mainAxisSize: MainAxisSize.min,
        children: <Widget>[
          Icon(Icons.circle, size: 8, color: copy.color),
          const SizedBox(width: KenaiSpacing.xs),
          Text(copy.label),
        ],
      );
}

final class _Metric extends StatelessWidget {
  const _Metric({
    required this.icon,
    required this.label,
    required this.value,
    super.key,
  });

  final IconData icon;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Container(
        width: 126,
        padding: const EdgeInsets.all(KenaiSpacing.md),
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.surfaceContainerHighest,
          borderRadius: BorderRadius.circular(KenaiRadii.control),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: <Widget>[
            Icon(icon, size: 18),
            const SizedBox(height: KenaiSpacing.xs),
            Text(label, style: Theme.of(context).textTheme.labelSmall),
            Text(value, maxLines: 1, overflow: TextOverflow.ellipsis),
          ],
        ),
      );
}

final class _CatalogMessage extends StatelessWidget {
  const _CatalogMessage({
    required this.icon,
    required this.title,
    required this.message,
  });

  final IconData icon;
  final String title;
  final String message;

  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(KenaiSpacing.xl),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: <Widget>[
              Icon(icon, size: 40),
              const SizedBox(height: KenaiSpacing.sm),
              Text(title, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: KenaiSpacing.xs),
              Text(message, textAlign: TextAlign.center),
            ],
          ),
        ),
      );
}

final class _ConnectionCopy {
  const _ConnectionCopy(this.title, this.message);

  final String title;
  final String message;
}

final class _AvailabilityCopy {
  const _AvailabilityCopy(this.label, this.color);

  final String label;
  final Color color;
}

_ConnectionCopy _connectionCopy(VpnConnectionPhase phase) => switch (phase) {
      VpnConnectionPhase.disconnected => const _ConnectionCopy(
          'VPN не подключён',
          'Выберите протокол и подключитесь к защищённому соединению.',
        ),
      VpnConnectionPhase.validating => const _ConnectionCopy(
          'Проверяем профиль',
          'Это займёт несколько секунд.',
        ),
      VpnConnectionPhase.connecting => const _ConnectionCopy(
          'Подключаемся',
          'Настраиваем защищённое соединение.',
        ),
      VpnConnectionPhase.connected => const _ConnectionCopy(
          'VPN подключён',
          'Соединение защищено.',
        ),
      VpnConnectionPhase.reconnecting => const _ConnectionCopy(
          'Восстанавливаем соединение',
          'Сеть изменилась, выполняется переподключение.',
        ),
      VpnConnectionPhase.disconnecting => const _ConnectionCopy(
          'Отключаем VPN',
          'Завершаем соединение безопасно.',
        ),
      VpnConnectionPhase.blockedBySubscription => const _ConnectionCopy(
          'Подключение приостановлено',
          'Продлите подписку, чтобы снова подключаться.',
        ),
      VpnConnectionPhase.noNetwork => const _ConnectionCopy(
          'Нет подключения к интернету',
          'Проверьте сеть — VPN попробует подключиться снова.',
        ),
      VpnConnectionPhase.serverUnavailable => const _ConnectionCopy(
          'Сервер временно недоступен',
          'Выберите другой сервер или повторите попытку позже.',
        ),
      VpnConnectionPhase.error => const _ConnectionCopy(
          'Не удалось подключиться',
          'Попробуйте ещё раз. Если ошибка повторится, откройте диагностику.',
        ),
    };

_AvailabilityCopy _availability(ServerStatus status) {
  if (status.operational == ServerOperationalStatus.maintenance) {
    return const _AvailabilityCopy('Техобслуживание', KenaiTheme.warning);
  }
  if (status.operational == ServerOperationalStatus.offline ||
      status.internetReachability == InternetReachability.unreachable) {
    return const _AvailabilityCopy('Недоступен', KenaiTheme.danger);
  }
  if (status.operational == ServerOperationalStatus.degraded) {
    return const _AvailabilityCopy('Нестабильно', KenaiTheme.warning);
  }
  if (status.isAvailable) {
    return const _AvailabilityCopy('Доступен', KenaiTheme.success);
  }
  return const _AvailabilityCopy('Проверяется', KenaiTheme.warning);
}

String _sortLabel(ServerSort sort) => switch (sort) {
      ServerSort.recommended => 'Сначала рекомендуемые',
      ServerSort.latency => 'По ping',
      ServerSort.name => 'По названию',
      ServerSort.country => 'По стране',
    };

String _protocolLabel(VpnProtocol protocol) => switch (protocol) {
      VpnProtocol.wireGuard => 'WireGuard',
      VpnProtocol.amneziaWg => 'AmneziaWG 2.0',
      VpnProtocol.vlessReality => 'VLESS + REALITY',
    };

VpnProtocol _preferredProtocol(
  VpnServer server,
  ProtocolPreference preference,
) {
  final VpnProtocol? requested = switch (preference) {
    ProtocolPreference.wireGuard => VpnProtocol.wireGuard,
    ProtocolPreference.amneziaWg => VpnProtocol.amneziaWg,
    ProtocolPreference.vlessReality => VpnProtocol.vlessReality,
    ProtocolPreference.automatic => null,
  };
  if (requested != null && server.protocols.contains(requested)) {
    return requested;
  }
  return server.protocols.first;
}

String _latencyLabel(Duration? latency) =>
    latency == null ? '—' : '${latency.inMilliseconds} ms';

String _durationLabel(Duration duration) {
  String twoDigits(int value) => value.toString().padLeft(2, '0');
  final int hours = duration.inHours;
  final int minutes = duration.inMinutes.remainder(60);
  final int seconds = duration.inSeconds.remainder(60);
  return '${twoDigits(hours)}:${twoDigits(minutes)}:${twoDigits(seconds)}';
}

String _bytesLabel(int bytes) {
  if (bytes < 1024) return '$bytes Б';
  final double kibibytes = bytes / 1024;
  if (kibibytes < 1024) return '${kibibytes.toStringAsFixed(1)} КБ';
  final double mebibytes = kibibytes / 1024;
  if (mebibytes < 1024) return '${mebibytes.toStringAsFixed(1)} МБ';
  return '${(mebibytes / 1024).toStringAsFixed(1)} ГБ';
}

bool _isTestServer(VpnServer server) => server.isTest;
