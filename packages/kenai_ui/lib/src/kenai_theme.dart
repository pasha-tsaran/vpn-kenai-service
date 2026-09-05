import 'package:flutter/material.dart';

abstract final class KenaiSpacing {
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 20;
  static const double xl = 24;
  static const double xxl = 32;
}

abstract final class KenaiRadii {
  static const double control = 10;
  static const double card = 16;
  static const double panel = 24;
}

abstract final class KenaiTheme {
  static const Color accent = Color(0xFF6874F8);
  static const Color success = Color(0xFF43B97F);
  static const Color warning = Color(0xFFE2A94B);
  static const Color danger = Color(0xFFE45D68);

  static ThemeData light() => _build(
        brightness: Brightness.light,
        surface: const Color(0xFFF6F7FA),
        panel: Colors.white,
        foreground: const Color(0xFF1C2028),
      );

  static ThemeData dark() => _build(
        brightness: Brightness.dark,
        surface: const Color(0xFF17191E),
        panel: const Color(0xFF22252B),
        foreground: const Color(0xFFF3F4F7),
      );

  static ThemeData _build({
    required Brightness brightness,
    required Color surface,
    required Color panel,
    required Color foreground,
  }) {
    final ColorScheme scheme = ColorScheme.fromSeed(
      seedColor: accent,
      brightness: brightness,
      surface: surface,
    );
    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme.copyWith(
        primary: accent,
        surface: surface,
        onSurface: foreground,
      ),
      scaffoldBackgroundColor: surface,
      cardTheme: CardThemeData(
        color: panel,
        elevation: 0,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(KenaiRadii.card),
        ),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: panel,
        indicatorColor: accent.withValues(alpha: 0.16),
        minWidth: 72,
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: panel,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(KenaiRadii.control),
          borderSide: BorderSide.none,
        ),
      ),
    );
  }
}
