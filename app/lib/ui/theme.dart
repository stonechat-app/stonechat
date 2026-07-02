/// Zeon visual identity.
///
/// Not another bubble app: dark "console" surfaces, sharp 4px corners, an
/// ion-chartreuse accent, and a monospace voice for anything machine-made
/// (IDs, timestamps, relay status). Messages render as a left-aligned ledger
/// with colored rails instead of chat bubbles.
library;

import 'package:flutter/material.dart';

abstract final class Zn {
  // palette
  static const bg = Color(0xFF0B0F14);
  static const surface = Color(0xFF121820);
  static const raised = Color(0xFF1A222C);
  static const line = Color(0xFF232D38);
  static const ion = Color(0xFFC6F14E); // you
  static const cyan = Color(0xFF5AD7E6); // them
  static const text = Color(0xFFE8EEF4);
  static const muted = Color(0xFF8493A3);
  static const danger = Color(0xFFF2555A);
  static const ok = Color(0xFF6BE675);

  static const radius = 4.0;

  static const monoFamily = 'Menlo';
  static const monoFallback = ['Roboto Mono', 'monospace'];

  static TextStyle mono({
    double size = 12,
    Color color = muted,
    FontWeight weight = FontWeight.w400,
    double? letterSpacing,
  }) =>
      TextStyle(
        fontFamily: monoFamily,
        fontFamilyFallback: monoFallback,
        fontSize: size,
        color: color,
        fontWeight: weight,
        letterSpacing: letterSpacing,
      );

  /// Deterministic accent for a contact, derived from their ID.
  static Color idColor(String zeonId) {
    const palette = [
      cyan,
      Color(0xFFE6A85A),
      Color(0xFFB48AF2),
      Color(0xFF6BE675),
      Color(0xFFF28AB4),
      Color(0xFF7FA8F2),
    ];
    var h = 0;
    for (final c in zeonId.codeUnits) {
      h = (h * 31 + c) & 0x7FFFFFFF;
    }
    return palette[h % palette.length];
  }
}

ThemeData zeonTheme() {
  final base = ThemeData(
    brightness: Brightness.dark,
    useMaterial3: true,
    scaffoldBackgroundColor: Zn.bg,
    colorScheme: const ColorScheme.dark(
      primary: Zn.ion,
      onPrimary: Color(0xFF15200A),
      secondary: Zn.cyan,
      surface: Zn.surface,
      onSurface: Zn.text,
      error: Zn.danger,
    ),
  );

  return base.copyWith(
    appBarTheme: const AppBarTheme(
      backgroundColor: Zn.bg,
      foregroundColor: Zn.text,
      elevation: 0,
      centerTitle: false,
    ),
    dividerTheme: const DividerThemeData(color: Zn.line, thickness: 1),
    cardTheme: CardThemeData(
      color: Zn.surface,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        side: const BorderSide(color: Zn.line),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: Zn.surface,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        borderSide: const BorderSide(color: Zn.line),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        borderSide: const BorderSide(color: Zn.line),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        borderSide: const BorderSide(color: Zn.ion),
      ),
      hintStyle: const TextStyle(color: Zn.muted),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: Zn.ion,
        foregroundColor: const Color(0xFF15200A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Zn.radius),
        ),
        textStyle: const TextStyle(fontWeight: FontWeight.w700),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: Zn.text,
        side: const BorderSide(color: Zn.line),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(Zn.radius),
        ),
      ),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: Zn.raised,
      contentTextStyle: const TextStyle(color: Zn.text),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(Zn.radius),
        side: const BorderSide(color: Zn.line),
      ),
      behavior: SnackBarBehavior.floating,
    ),
  );
}
