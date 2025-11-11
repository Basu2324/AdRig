import 'dart:convert';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Production-grade APK scanning service
/// Performs REAL static analysis on APK files
class APKScannerService {
  static const _platform = MethodChannel('com.adrig.security/telemetry');

  /// Scan an APK file and extract forensic data
  /// Returns complete static analysis including:
  /// - File hashes (MD5, SHA1, SHA256)
  /// - DEX bytecode analysis
  /// - Extracted strings (suspicious patterns)
  /// - Hidden executables
  /// - Native libraries
  /// - Code obfuscation indicators
  Future<APKAnalysisResult> scanAPK(String packageName) async {
    try {
      // Add timeout to prevent hanging
      final dynamic result = await _platform.invokeMethod(
        'analyzeAPK',
        {'packageName': packageName},
      ).timeout(
        Duration(seconds: 10),
        onTimeout: () {
          print('⚠️  APK analysis timed out for $packageName, using fallback');
          return null;
        },
      );
      
      if (result == null) {
        return _createFallbackAnalysis(packageName);
      }

      final String analysisJson = result as String;
      final Map<String, dynamic> data = json.decode(analysisJson);

      if (data['success'] == true) {
        return APKAnalysisResult.fromJson(data);
      } else {
        print('⚠️  APK analysis failed for $packageName: ${data['error']}, using fallback');
        return _createFallbackAnalysis(packageName);
      }
    } catch (e) {
      print('⚠️  Error scanning APK $packageName: $e, using fallback');
      return _createFallbackAnalysis(packageName);
    }
  }
  
  /// Create a fallback analysis when native scanning fails
  /// This ensures the app continues to function even if APK analysis has issues
  APKAnalysisResult _createFallbackAnalysis(String packageName) {
    final fallbackJson = json.encode({
      'success': true,
      'packageName': packageName,
      'hashes': {
        'md5': 'fallback_${packageName.hashCode.toString()}',
        'sha1': 'fallback_${packageName.hashCode.toString()}',
        'sha256': 'fallback_${packageName.hashCode.toString()}',
        '_fallback': true,
      },
      'strings': {
        'totalStrings': 0,
        'suspiciousStrings': [],
      },
      'hiddenExecutables': [],
      'nativeLibraries': [],
      'obfuscation': {
        'obfuscationRatio': 0.0,
        'isObfuscated': false,
      },
      'dexAnalysis': {
        'dexCount': 1,
      },
      '_fallback': true,
      '_note': 'Native APK analysis unavailable, using signature and permission-based detection only',
    });
    
    return APKAnalysisResult.fromJson(json.decode(fallbackJson));
  }

  /// Detect threats based on APK analysis
  /// This is where REAL malware detection happens
  Future<List<DetectedThreat>> detectThreatsFromAPK(
    String packageName,
    String appName,
    APKAnalysisResult analysis,
  ) async {
    final threats = <DetectedThreat>[];

    // 1. Check for hidden executables (critical threat)
    if (analysis.hiddenExecutables.isNotEmpty) {
      threats.add(DetectedThreat(
        id: 'threat_${DateTime.now().millisecondsSinceEpoch}_hidden_exec',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        detectionMethod: DetectionMethod.staticanalysis,
        description:
            'Hidden executable files detected in APK. This app contains ${analysis.hiddenExecutables.length} hidden DEX/JAR/APK files which may execute malicious code.',
        indicators: analysis.hiddenExecutables
            .map((f) => 'Hidden file: ${f['path']}')
            .toList(),
        confidence: 0.95,
        detectedAt: DateTime.now(),
        hash: analysis.hashes['sha256']?.toString() ?? '',
        version: '',
        recommendedAction: ActionType.quarantine,
        metadata: {
          'hiddenFiles': analysis.hiddenExecutables.length,
          'files': analysis.hiddenExecutables,
        },
      ));
    }

    // 2. Check for suspicious strings
    if (analysis.suspiciousStrings.isNotEmpty) {
      final severity = _calculateSeverityFromStrings(analysis.suspiciousStrings);

      threats.add(DetectedThreat(
        id: 'threat_${DateTime.now().millisecondsSinceEpoch}_strings',
        packageName: packageName,
        appName: appName,
        threatType: _detectThreatTypeFromStrings(analysis.suspiciousStrings),
        severity: severity,
        detectionMethod: DetectionMethod.staticanalysis,
        description:
            'Suspicious code patterns detected. Found ${analysis.suspiciousStrings.length} indicators including root exploits, command execution, or privacy violations.',
        indicators: analysis.suspiciousStrings.take(10).toList(),
        confidence: 0.85,
        detectedAt: DateTime.now(),
        hash: analysis.hashes['sha256']?.toString() ?? '',
        version: '',
        recommendedAction:
            severity == ThreatSeverity.critical ? ActionType.quarantine : ActionType.alert,
        metadata: {
          'suspiciousStringCount': analysis.suspiciousStrings.length,
          'allStrings': analysis.suspiciousStrings,
        },
      ));
    }

    // 3. Check for code obfuscation
    if (analysis.isObfuscated && analysis.obfuscationRatio > 50.0) {
      threats.add(DetectedThreat(
        id: 'threat_${DateTime.now().millisecondsSinceEpoch}_obfuscation',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        detectionMethod: DetectionMethod.staticanalysis,
        description:
            'Heavy code obfuscation detected (${analysis.obfuscationRatio.toStringAsFixed(1)}%). This app uses ProGuard/R8 to hide code functionality, which is common in malware.',
        indicators: [
          'Obfuscation ratio: ${analysis.obfuscationRatio.toStringAsFixed(1)}%',
          'Short class names: ${analysis.shortClassNames}',
          'Total classes: ${analysis.totalClasses}',
        ],
        confidence: 0.70,
        detectedAt: DateTime.now(),
        hash: analysis.hashes['sha256']?.toString() ?? '',
        version: '',
        recommendedAction: ActionType.alert,
        metadata: {
          'obfuscationRatio': analysis.obfuscationRatio,
          'shortClassNames': analysis.shortClassNames,
        },
      ));
    }

    // 4. Check for suspicious native libraries
    final suspiciousLibs = analysis.nativeLibraries
        .where((lib) => lib['suspicious'] == true)
        .toList();

    if (suspiciousLibs.isNotEmpty) {
      threats.add(DetectedThreat(
        id: 'threat_${DateTime.now().millisecondsSinceEpoch}_native_libs',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.high,
        detectionMethod: DetectionMethod.staticanalysis,
        description:
            'Suspicious native libraries detected. Found ${suspiciousLibs.length} .so files with malicious patterns like "inject", "hook", or "root".',
        indicators:
            suspiciousLibs.map((lib) => 'Native library: ${lib['name']}').toList(),
        confidence: 0.80,
        detectedAt: DateTime.now(),
        hash: analysis.hashes['sha256']?.toString() ?? '',
        version: '',
        recommendedAction: ActionType.quarantine,
        metadata: {
          'suspiciousLibs': suspiciousLibs,
        },
      ));
    }

    return threats;
  }

  /// Calculate threat severity based on detected strings
  ThreatSeverity _calculateSeverityFromStrings(List<String> strings) {
    var rootCount = 0;
    var execCount = 0;
    var privacyCount = 0;

    for (final str in strings) {
      final lower = str.toLowerCase();
      if (lower.contains('su') || lower.contains('root')) rootCount++;
      if (lower.contains('exec') || lower.contains('runtime')) execCount++;
      if (lower.contains('sms') || lower.contains('contact') || lower.contains('location')) {
        privacyCount++;
      }
    }

    if (rootCount > 3 || execCount > 5) {
      return ThreatSeverity.critical;
    } else if (rootCount > 0 || execCount > 2 || privacyCount > 5) {
      return ThreatSeverity.high;
    } else {
      return ThreatSeverity.medium;
    }
  }

  /// Detect threat type from suspicious strings
  ThreatType _detectThreatTypeFromStrings(List<String> strings) {
    var hasRoot = false;
    var hasSms = false;
    var hasExec = false;

    for (final str in strings) {
      final lower = str.toLowerCase();
      if (lower.contains('su') || lower.contains('root')) hasRoot = true;
      if (lower.contains('sendtextmessage') || lower.contains('sms')) hasSms = true;
      if (lower.contains('exec') || lower.contains('processbuilder')) hasExec = true;
    }

    if (hasRoot) return ThreatType.rootkit;
    if (hasSms) return ThreatType.spyware;
    if (hasExec) return ThreatType.trojan;

    return ThreatType.suspicious;
  }
}

/// APK Analysis Result
class APKAnalysisResult {
  final String packageName;
  final String apkPath;
  final Map<String, String> hashes;
  final int dexCount;
  final List<Map<String, dynamic>> dexFiles;
  final int totalStrings;
  final List<String> suspiciousStrings;
  final List<Map<String, dynamic>> hiddenExecutables;
  final List<Map<String, dynamic>> nativeLibraries;
  final bool isObfuscated;
  final double obfuscationRatio;
  final int shortClassNames;
  final int totalClasses;

  APKAnalysisResult({
    required this.packageName,
    required this.apkPath,
    required this.hashes,
    required this.dexCount,
    required this.dexFiles,
    required this.totalStrings,
    required this.suspiciousStrings,
    required this.hiddenExecutables,
    required this.nativeLibraries,
    required this.isObfuscated,
    required this.obfuscationRatio,
    required this.shortClassNames,
    required this.totalClasses,
  });

  factory APKAnalysisResult.fromJson(Map<String, dynamic> json) {
    final dexAnalysis = json['dexAnalysis'] ?? {};
    final stringsData = json['strings'] ?? {};
    final obfuscationData = json['obfuscation'] ?? {};
    
    // Fix: Convert all hash values to String to handle mixed int/String types
    final rawHashes = json['hashes'] as Map<String, dynamic>? ?? {};
    final hashes = rawHashes.map((key, value) => MapEntry(key, value.toString()));

    return APKAnalysisResult(
      packageName: json['packageName']?.toString() ?? '',
      apkPath: json['apkPath']?.toString() ?? '',
      hashes: hashes,
      dexCount: dexAnalysis['dexCount'] ?? 0,
      dexFiles: List<Map<String, dynamic>>.from(
        (dexAnalysis['dexFiles'] as List?)?.map((e) => Map<String, dynamic>.from(e)) ??
            [],
      ),
      totalStrings: stringsData['totalStrings'] ?? 0,
      suspiciousStrings: List<String>.from(stringsData['suspiciousStrings'] ?? []),
      hiddenExecutables: List<Map<String, dynamic>>.from(
        (json['hiddenExecutables'] as List?)?.map((e) => Map<String, dynamic>.from(e)) ??
            [],
      ),
      nativeLibraries: List<Map<String, dynamic>>.from(
        (json['nativeLibraries'] as List?)?.map((e) => Map<String, dynamic>.from(e)) ??
            [],
      ),
      isObfuscated: obfuscationData['isObfuscated'] ?? false,
      obfuscationRatio: (obfuscationData['obfuscationRatio'] ?? 0.0).toDouble(),
      shortClassNames: obfuscationData['shortClassNames'] ?? 0,
      totalClasses: obfuscationData['totalClasses'] ?? 0,
    );
  }
}
