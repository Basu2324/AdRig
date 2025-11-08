import 'package:adrig/core/models/threat_model.dart';
import 'dart:async';

/// Static analysis engine for APK manifest and code patterns
class StaticAnalysisEngine {
  /// Analyze app manifest for suspicious configurations
  List<DetectedThreat> analyzeManifest(
    String packageName,
    String appName,
    Map<String, dynamic> manifestData,
    List<String> requestedPermissions,
  ) {
    final threats = <DetectedThreat>[];

    // Check for debuggable flag
    if (manifestData['debuggable'] == true) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Debuggable manifest flag enabled - allows arbitrary code injection',
        ThreatType.trojan,
        ThreatSeverity.high,
        confidence: 0.85,
      ));
    }

    // Check for cleartext traffic
    if (manifestData['usesCleartextTraffic'] == true ||
        manifestData['cleartextTrafficAllowed'] == true) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Cleartext (HTTP) traffic enabled - data interception risk',
        ThreatType.spyware,
        ThreatSeverity.medium,
        confidence: 0.70,
      ));
    }

    // Check for suspicious export configurations
    final activities = manifestData['activities'] as List? ?? [];
    for (final activity in activities) {
      if (activity['exported'] == true && activity['intentFilters'] != null) {
        threats.add(_createThreat(
          packageName,
          appName,
          'Exported activity with intent-filter - IPC vulnerability',
          ThreatType.trojan,
          ThreatSeverity.high,
          confidence: 0.80,
        ));
      }
    }

    // Check for suspicious services/receivers
    final services = manifestData['services'] as List? ?? [];
    for (final service in services) {
      if (service['exported'] == true &&
          service['permission'] == null &&
          !_isSystemService(service['name'])) {
        threats.add(_createThreat(
          packageName,
          appName,
          'Unprotected exported service - direct IPC access possible',
          ThreatType.trojan,
          ThreatSeverity.high,
          confidence: 0.75,
        ));
      }
    }

    return threats;
  }

  /// Analyze app size and structure for anomalies
  List<DetectedThreat> analyzeCodeStructure(
    String packageName,
    String appName,
    Map<String, dynamic> appMetadata,
  ) {
    final threats = <DetectedThreat>[];

    final appSize = appMetadata['size'] as int? ?? 0;
    final methodCount = appMetadata['methodCount'] as int? ?? 0;
    final classCount = appMetadata['classCount'] as int? ?? 0;
    final hasNativeLibs = appMetadata['hasNativeLibs'] as bool? ?? false;

    // Anomaly: massive app size for simple app
    if (appSize > 100 * 1024 * 1024 && _looksLikeSimpleApp(packageName)) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Suspicious app size anomaly - potential obfuscated code/payload',
        ThreatType.dropper,
        ThreatSeverity.high,
        confidence: 0.70,
      ));
    }

    // Anomaly: excessive methods (code bloat or packing)
    if (methodCount > 100000) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Excessive method count - possible code packing/obfuscation',
        ThreatType.malware,
        ThreatSeverity.medium,
        confidence: 0.65,
      ));
    }

    // Anomaly: native libraries in unusual apps
    if (hasNativeLibs && _isKnownLikelyPureJavaApp(packageName)) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Unexpected native code in pure-Java application',
        ThreatType.trojan,
        ThreatSeverity.medium,
        confidence: 0.60,
      ));
    }

    return threats;
  }

  /// Analyze SDK version and version history for exploitation risks
  List<DetectedThreat> analyzeSdkVersions(
    String packageName,
    String appName,
    Map<String, dynamic> versionInfo,
  ) {
    final threats = <DetectedThreat>[];

    final targetSdkVersion = versionInfo['targetSdkVersion'] as int? ?? 0;
    final minSdkVersion = versionInfo['minSdkVersion'] as int? ?? 0;

    // Old target SDK = unpatched vulnerabilities
    if (targetSdkVersion < 30) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Old target SDK version - may contain unpatched Android vulnerabilities',
        ThreatType.malware,
        ThreatSeverity.medium,
        confidence: 0.65,
      ));
    }

    // Min SDK too low = potential compatibility abuse
    if (minSdkVersion < 21) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Very low minimum SDK - possible compatibility abuse for exploitation',
        ThreatType.malware,
        ThreatSeverity.low,
        confidence: 0.50,
      ));
    }

    return threats;
  }

  /// Analyze certificate and signing for spoofing
  List<DetectedThreat> analyzeCertificate(
    String packageName,
    String appName,
    String? certificate,
    String? knownGoodCertificate,
  ) {
    final threats = <DetectedThreat>[];

    if (certificate == null) {
      threats.add(_createThreat(
        packageName,
        appName,
        'App has no signing certificate - could be tampered',
        ThreatType.malware,
        ThreatSeverity.high,
        confidence: 0.90,
      ));
      return threats;
    }

    if (knownGoodCertificate != null && certificate != knownGoodCertificate) {
      threats.add(_createThreat(
        packageName,
        appName,
        'Certificate mismatch - possible app spoofing/repackaging',
        ThreatType.malware,
        ThreatSeverity.critical,
        confidence: 0.95,
      ));
    }

    return threats;
  }

  /// Analyze installer source for trust
  List<DetectedThreat> analyzeInstallerSource(
    String packageName,
    String appName,
    String installerPackage,
  ) {
    final threats = <DetectedThreat>[];

    const trustedInstallers = [
      'com.android.vending', // Google Play
      'com.android.packageinstaller',
      'com.samsung.android.packageinstaller',
      'com.sec.android.app.samsungapps', // Samsung Galaxy Store
    ];

    if (!trustedInstallers.contains(installerPackage) &&
        !_isSystemPackage(installerPackage)) {
      threats.add(_createThreat(
        packageName,
        appName,
        'App installed from untrusted source - possible sideloading attack',
        ThreatType.malware,
        ThreatSeverity.medium,
        confidence: 0.70,
      ));
    }

    return threats;
  }

  /// Analyze string resources for suspicious patterns
  List<DetectedThreat> analyzeStringResources(
    String packageName,
    String appName,
    List<String> strings,
  ) {
    final threats = <DetectedThreat>[];

    final suspiciousPatterns = {
      r'bot\.command',
      r'c2_server',
      r'command_control',
      r'exfiltrate',
      r'keylog',
      r'backdoor',
      r'kill_antivirus',
      r'disable_protection',
      r'ransomware_key',
    };

    for (final pattern in suspiciousPatterns) {
      final regex = RegExp(pattern, caseSensitive: false);
      if (strings.any((s) => regex.hasMatch(s))) {
        threats.add(_createThreat(
          packageName,
          appName,
          'Suspicious string pattern detected: $pattern',
          ThreatType.malware,
          ThreatSeverity.high,
          confidence: 0.85,
        ));
      }
    }

    return threats;
  }

  // Helper methods

  bool _isSystemService(String serviceName) {
    const systemServices = [
      'android.app.Service',
      'android.inputmethodservice.InputMethodService',
      'android.accessibilityservice.AccessibilityService',
      'android.webkit.WebViewClient',
    ];
    return systemServices.any((s) => serviceName.contains(s));
  }

  bool _looksLikeSimpleApp(String packageName) {
    // Simple apps like calculator, notes, etc shouldn't be huge
    final simpleKeywords = [
      'calc',
      'note',
      'todo',
      'weather',
      'clock',
      'timer',
      'stopwatch',
    ];
    return simpleKeywords.any((k) => packageName.toLowerCase().contains(k));
  }

  bool _isKnownLikelyPureJavaApp(String packageName) {
    // Most productivity apps don't need native code
    const pureJavaApps = [
      'com.google.android.apps',
      'com.microsoft',
      'com.android',
    ];
    return pureJavaApps.any((p) => packageName.startsWith(p));
  }

  bool _isSystemPackage(String packageName) {
    return packageName.startsWith('com.android') ||
        packageName.startsWith('android') ||
        packageName.contains('system');
  }

  DetectedThreat _createThreat(
    String packageName,
    String appName,
    String description,
    ThreatType threatType,
    ThreatSeverity severity, {
    double confidence = 0.70,
  }) {
    return DetectedThreat(
      id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
      packageName: packageName,
      appName: appName,
      threatType: threatType,
      severity: severity,
      detectionMethod: DetectionMethod.staticanalysis,
      description: description,
      indicators: [],
      confidence: confidence,
      detectedAt: DateTime.now(),
      recommendedAction: _getRecommendedAction(severity),
      metadata: {
        'analysis_type': 'static_analysis',
        'category': threatType.toString(),
      },
    );
  }

  ActionType _getRecommendedAction(ThreatSeverity severity) {
    return {
      ThreatSeverity.critical: ActionType.quarantine,
      ThreatSeverity.high: ActionType.quarantine,
      ThreatSeverity.medium: ActionType.alert,
      ThreatSeverity.low: ActionType.monitoronly,
      ThreatSeverity.info: ActionType.monitoronly,
    }[severity] ?? ActionType.alert;
  }
}
