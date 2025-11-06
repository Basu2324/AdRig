import 'package:flutter/material.dart';

/// ScanX Brand Colors & Theme
class ScanXColors {
  // Primary Colors
  static const Color primaryDark = Color(0xFF1F2937); // Deep blue-gray
  static const Color accentOrange = Color(0xFFFF6B35); // Bold orange
  static const Color accentCyan = Color(0xFF00D9FF); // Bright cyan

  // Background & Surface
  static const Color background = Color(0xFF0F1419);
  static const Color surface = Color(0xFF1A1F2E);
  static const Color surfaceLight = Color(0xFF2D3142);

  // Threat Severity Colors
  static const Color threatCritical = Color(0xFFFF1744); // Deep red
  static const Color threatHigh = Color(0xFFFF9100); // Orange
  static const Color threatMedium = Color(0xFFFFC400); // Amber
  static const Color threatLow = Color(0xFF4CAF50); // Green
  static const Color threatInfo = Color(0xFF00B8D4); // Cyan

  // Text Colors
  static const Color textPrimary = Color(0xFFFFFFFF); // White
  static const Color textSecondary = Color(0xFFB0BEC5); // Light gray
  static const Color textDisabled = Color(0xFF78909C); // Muted gray

  // UI Elements
  static const Color buttonPrimary = accentOrange;
  static const Color buttonHover = Color(0xFFE55100);
  static const Color divider = Color(0xFF37474F);
  static const Color border = Color(0xFF455A64);

  // Scan States
  static const Color scanRunning = accentCyan;
  static const Color scanComplete = Color(0xFF4CAF50);
  static const Color scanError = Color(0xFFFF1744);
}

/// ScanX Theme Data
class ScanXTheme {
  static ThemeData darkTheme() {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: ScanXColors.background,
      primaryColor: ScanXColors.accentOrange,
      colorScheme: ColorScheme.dark(
        primary: ScanXColors.accentOrange,
        secondary: ScanXColors.accentCyan,
        surface: ScanXColors.surface,
        background: ScanXColors.background,
        error: ScanXColors.threatCritical,
      ),
      appBarTheme: AppBarTheme(
        backgroundColor: ScanXColors.surface,
        elevation: 0,
        centerTitle: true,
        titleTextStyle: TextStyle(
          color: ScanXColors.textPrimary,
          fontSize: 20,
          fontWeight: FontWeight.bold,
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: ScanXColors.accentOrange,
          foregroundColor: Colors.white,
          padding: EdgeInsets.symmetric(horizontal: 24, vertical: 12),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
      textTheme: TextTheme(
        displayLarge: TextStyle(
          color: ScanXColors.textPrimary,
          fontSize: 32,
          fontWeight: FontWeight.bold,
        ),
        displayMedium: TextStyle(
          color: ScanXColors.textPrimary,
          fontSize: 24,
          fontWeight: FontWeight.bold,
        ),
        titleLarge: TextStyle(
          color: ScanXColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        bodyLarge: TextStyle(
          color: ScanXColors.textPrimary,
          fontSize: 16,
        ),
        bodyMedium: TextStyle(
          color: ScanXColors.textSecondary,
          fontSize: 14,
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: ScanXColors.surfaceLight,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: ScanXColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: ScanXColors.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: ScanXColors.accentOrange, width: 2),
        ),
      ),
    );
  }
}
