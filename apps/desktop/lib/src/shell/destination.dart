import 'package:flutter/material.dart';

enum AppDestination {
  servers('Серверы', Icons.public_outlined, Icons.public),
  account('Аккаунт', Icons.person_outline, Icons.person),
  plans('Тарифы', Icons.credit_card_outlined, Icons.credit_card),
  vpnSettings('Настройки VPN', Icons.tune_outlined, Icons.tune),
  statistics('Статистика', Icons.monitor_heart_outlined, Icons.monitor_heart),
  logs('Логи', Icons.terminal_outlined, Icons.terminal),
  speedTest('Тест скорости', Icons.speed_outlined, Icons.speed),
  settings('Параметры', Icons.settings_outlined, Icons.settings);

  const AppDestination(this.label, this.icon, this.selectedIcon);

  final String label;
  final IconData icon;
  final IconData selectedIcon;
}
