import 'package:flutter/material.dart';
import 'package:kenai_ui/kenai_ui.dart';

import '../../bootstrap.dart';
import '../screens/account_screen.dart';
import '../screens/app_settings_screen.dart';
import '../screens/logs_screen.dart';
import '../screens/placeholder_screen.dart';
import '../screens/plans_screen.dart';
import '../screens/servers_screen.dart';
import '../screens/speed_test_screen.dart';
import '../screens/vpn_settings_screen.dart';
import 'destination.dart';

final class AppShell extends StatefulWidget {
  const AppShell({required this.dependencies, super.key});

  final AppDependencies dependencies;

  @override
  State<AppShell> createState() => _AppShellState();
}

final class _AppShellState extends State<AppShell> {
  AppDestination _destination = AppDestination.servers;

  List<AppDestination> get _destinations => widget.dependencies.minimalMvpMode
      ? const <AppDestination>[
          AppDestination.servers,
          AppDestination.account,
          AppDestination.vpnSettings,
          AppDestination.logs,
          AppDestination.settings,
        ]
      : AppDestination.values;

  @override
  Widget build(BuildContext context) => Scaffold(
        body: SafeArea(
          child: Row(
            children: <Widget>[
              NavigationRail(
                selectedIndex: _destinations.indexOf(_destination),
                labelType: NavigationRailLabelType.none,
                onDestinationSelected: (int index) {
                  setState(() => _destination = _destinations[index]);
                },
                leading: const Padding(
                  padding: EdgeInsets.symmetric(vertical: KenaiSpacing.md),
                  child: _KenaiMark(),
                ),
                destinations: _destinations
                    .map(
                      (AppDestination destination) => NavigationRailDestination(
                        icon: Tooltip(
                          message: destination.label,
                          child: Icon(destination.icon),
                        ),
                        selectedIcon: Icon(destination.selectedIcon),
                        label: Text(destination.label),
                      ),
                    )
                    .toList(growable: false),
              ),
              Expanded(child: _buildScreen()),
            ],
          ),
        ),
      );

  Widget _buildScreen() {
    if (_destination == AppDestination.servers) {
      return ServersScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.account) {
      return AccountScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.plans) {
      return PlansScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.vpnSettings) {
      return VpnSettingsScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.logs) {
      return LogsScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.speedTest) {
      return SpeedTestScreen(dependencies: widget.dependencies);
    }
    if (_destination == AppDestination.settings) {
      return AppSettingsScreen(dependencies: widget.dependencies);
    }
    return PlaceholderScreen(destination: _destination);
  }
}

final class _KenaiMark extends StatelessWidget {
  const _KenaiMark();

  @override
  Widget build(BuildContext context) => Semantics(
        label: 'Kenai VPN',
        child: Container(
          width: 42,
          height: 42,
          alignment: Alignment.center,
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primary,
            borderRadius: BorderRadius.circular(12),
          ),
          child: const Text(
            'K',
            style: TextStyle(
              color: Colors.white,
              fontSize: 22,
              fontWeight: FontWeight.w700,
            ),
          ),
        ),
      );
}
