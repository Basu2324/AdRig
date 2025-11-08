import 'dart:math';
import 'dart:typed_data';
import 'package:adrig/core/models/threat_model.dart';

/// Advanced static heuristics engine
/// Features: Entropy analysis, packing detection, native library inspection, permission correlation
class AdvancedStaticHeuristics {
  
  /// Analyze file entropy to detect packing/encryption
  static EntropyAnalysis analyzeEntropy(Uint8List data) {
    if (data.isEmpty) {
      return EntropyAnalysis(entropy: 0.0, isPacked: false, confidence: 0.0);
    }
    
    // Calculate Shannon entropy
    final frequencies = List<int>.filled(256, 0);
    for (final byte in data) {
      frequencies[byte]++;
    }
    
    double entropy = 0.0;
    final length = data.length;
    
    for (final freq in frequencies) {
      if (freq > 0) {
        final probability = freq / length;
        entropy -= probability * (log(probability) / log(2));
      }
    }
    
    // High entropy (>7.2) often indicates packing/encryption
    final isPacked = entropy > 7.2;
    final confidence = entropy > 7.5 ? 0.9 : 
                       entropy > 7.2 ? 0.7 : 
                       entropy > 6.8 ? 0.4 : 0.1;
    
    return EntropyAnalysis(
      entropy: entropy,
      isPacked: isPacked,
      confidence: confidence,
    );
  }
  
  /// Detect suspicious native library characteristics
  static List<NativeLibraryAlert> inspectNativeLibrary(String libPath, Uint8List data) {
    final alerts = <NativeLibraryAlert>[];
    
    // Check for hidden DEX files in .so
    if (_containsDexSignature(data)) {
      alerts.add(NativeLibraryAlert(
        libraryPath: libPath,
        alertType: 'hidden_dex',
        severity: ThreatSeverity.critical,
        description: 'Hidden DEX file found in native library',
        confidence: 0.95,
      ));
    }
    
    // Check for suspicious strings
    final strings = _extractStrings(data);
    
    if (strings.any((s) => s.contains('shell') || s.contains('exec'))) {
      alerts.add(NativeLibraryAlert(
        libraryPath: libPath,
        alertType: 'shell_execution',
        severity: ThreatSeverity.high,
        description: 'Shell execution strings detected',
        confidence: 0.7,
      ));
    }
    
    if (strings.any((s) => s.contains('root') || s.contains('/system/xbin'))) {
      alerts.add(NativeLibraryAlert(
        libraryPath: libPath,
        alertType: 'root_access',
        severity: ThreatSeverity.critical,
        description: 'Root access attempts detected',
        confidence: 0.85,
      ));
    }
    
    // Check entropy
    final entropyAnalysis = analyzeEntropy(data);
    if (entropyAnalysis.isPacked && entropyAnalysis.confidence > 0.7) {
      alerts.add(NativeLibraryAlert(
        libraryPath: libPath,
        alertType: 'packed_library',
        severity: ThreatSeverity.medium,
        description: 'Library appears to be packed/encrypted (entropy: ${entropyAnalysis.entropy.toStringAsFixed(2)})',
        confidence: entropyAnalysis.confidence,
      ));
    }
    
    // Check for anti-debugging
    if (strings.any((s) => s.contains('ptrace') || s.contains('JDWP'))) {
      alerts.add(NativeLibraryAlert(
        libraryPath: libPath,
        alertType: 'anti_debug',
        severity: ThreatSeverity.medium,
        description: 'Anti-debugging techniques detected',
        confidence: 0.75,
      ));
    }
    
    return alerts;
  }
  
  /// Analyze permission combinations for suspicious patterns
  static PermissionCorrelationResult analyzePermissions(
    List<String> requestedPermissions,
    String appCategory,
  ) {
    final suspiciousPatterns = <SuspiciousPermissionPattern>[];
    double riskScore = 0.0;
    
    // Pattern 1: Banking trojan permissions
    if (_hasPermissions(requestedPermissions, [
      'SYSTEM_ALERT_WINDOW',
      'BIND_ACCESSIBILITY_SERVICE',
      'READ_SMS',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Banking Trojan Overlay + SMS',
        permissions: ['SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE', 'READ_SMS'],
        severity: ThreatSeverity.critical,
        description: 'Combination typical of banking trojans (overlay attacks + SMS interception)',
        riskContribution: 40.0,
      ));
      riskScore += 40.0;
    }
    
    // Pattern 2: Spyware keylogging
    if (_hasPermissions(requestedPermissions, [
      'BIND_ACCESSIBILITY_SERVICE',
      'INTERNET',
    ]) && _hasAnyPermission(requestedPermissions, [
      'READ_CONTACTS',
      'READ_CALL_LOG',
      'READ_SMS',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Spyware Keylogging + Exfiltration',
        permissions: ['BIND_ACCESSIBILITY_SERVICE', 'INTERNET', 'READ_*'],
        severity: ThreatSeverity.critical,
        description: 'Accessibility abuse for keylogging with network access',
        riskContribution: 35.0,
      ));
      riskScore += 35.0;
    }
    
    // Pattern 3: Screen recording spyware
    if (_hasPermissions(requestedPermissions, [
      'RECORD_AUDIO',
      'CAMERA',
      'INTERNET',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Audio/Video Surveillance',
        permissions: ['RECORD_AUDIO', 'CAMERA', 'INTERNET'],
        severity: ThreatSeverity.high,
        description: 'Surveillance capabilities with network exfiltration',
        riskContribution: 30.0,
      ));
      riskScore += 30.0;
    }
    
    // Pattern 4: Location tracking
    if (_hasPermissions(requestedPermissions, [
      'ACCESS_FINE_LOCATION',
      'ACCESS_BACKGROUND_LOCATION',
      'INTERNET',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Background Location Tracking',
        permissions: ['ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'INTERNET'],
        severity: ThreatSeverity.medium,
        description: 'Continuous location monitoring with network access',
        riskContribution: 20.0,
      ));
      riskScore += 20.0;
    }
    
    // Pattern 5: SMS fraud
    if (_hasPermissions(requestedPermissions, [
      'SEND_SMS',
      'READ_SMS',
      'RECEIVE_SMS',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'SMS Fraud',
        permissions: ['SEND_SMS', 'READ_SMS', 'RECEIVE_SMS'],
        severity: ThreatSeverity.high,
        description: 'Full SMS control - typical premium SMS fraud',
        riskContribution: 35.0,
      ));
      riskScore += 35.0;
    }
    
    // Pattern 6: Admin privileges
    if (_hasPermissions(requestedPermissions, [
      'BIND_DEVICE_ADMIN',
    ])) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Device Admin Activation',
        permissions: ['BIND_DEVICE_ADMIN'],
        severity: ThreatSeverity.high,
        description: 'Device admin - makes uninstall difficult',
        riskContribution: 25.0,
      ));
      riskScore += 25.0;
    }
    
    // Pattern 7: Excessive data access (all sensors)
    final dataPermissions = requestedPermissions.where((p) =>
      p.startsWith('READ_') || 
      p.contains('CONTACTS') || 
      p.contains('CALENDAR') ||
      p.contains('CALL_LOG')
    ).length;
    
    if (dataPermissions >= 5) {
      suspiciousPatterns.add(SuspiciousPermissionPattern(
        patternName: 'Excessive Data Harvesting',
        permissions: ['Multiple READ_* permissions'],
        severity: ThreatSeverity.medium,
        description: '$dataPermissions data access permissions requested',
        riskContribution: 15.0,
      ));
      riskScore += 15.0;
    }
    
    // Normalize risk score (0-100)
    riskScore = min(100.0, riskScore);
    
    return PermissionCorrelationResult(
      suspiciousPatterns: suspiciousPatterns,
      riskScore: riskScore,
      hasCriticalPatterns: suspiciousPatterns.any((p) => p.severity == ThreatSeverity.critical),
    );
  }
  
  /// Detect code obfuscation through static analysis
  static ObfuscationDetection detectObfuscation(String dexCode) {
    int obfuscationScore = 0;
    final indicators = <String>[];
    
    // Check for short class/method names (ProGuard)
    final shortNamePattern = RegExp(r'class\s+[a-z]{1,2}\s|method\s+[a-z]{1,2}\(');
    final shortNames = shortNamePattern.allMatches(dexCode).length;
    if (shortNames > 10) {
      obfuscationScore += 30;
      indicators.add('Heavy name obfuscation detected ($shortNames short names)');
    }
    
    // Check for string encryption
    if (dexCode.contains('decrypt') || dexCode.contains('xor_decode')) {
      obfuscationScore += 25;
      indicators.add('String decryption routines found');
    }
    
    // Check for reflection usage
    final reflectionPattern = RegExp(r'(Class\.forName|Method\.invoke|getDeclaredMethod)');
    final reflectionCount = reflectionPattern.allMatches(dexCode).length;
    if (reflectionCount > 5) {
      obfuscationScore += 20;
      indicators.add('Excessive reflection usage ($reflectionCount calls)');
    }
    
    // Check for control flow obfuscation
    if (dexCode.contains('switch') && dexCode.contains('0x')) {
      final switchCount = 'switch'.allMatches(dexCode).length;
      if (switchCount > 10) {
        obfuscationScore += 25;
        indicators.add('Control flow flattening detected');
      }
    }
    
    // Check for dynamic code loading
    if (dexCode.contains('DexClassLoader') || dexCode.contains('PathClassLoader')) {
      obfuscationScore += 30;
      indicators.add('Dynamic code loading detected');
    }
    
    final severity = obfuscationScore > 70 ? ThreatSeverity.high :
                     obfuscationScore > 40 ? ThreatSeverity.medium :
                     ThreatSeverity.low;
    
    return ObfuscationDetection(
      obfuscationScore: min(100, obfuscationScore),
      severity: severity,
      indicators: indicators,
      isHighlyObfuscated: obfuscationScore > 70,
    );
  }
  
  // ============= HELPER METHODS =============
  
  static bool _containsDexSignature(Uint8List data) {
    // DEX magic: "dex\n035\0" or "dex\n036\0" or "dex\n037\0" or "dex\n038\0" or "dex\n039\0"
    if (data.length < 8) return false;
    
    return data[0] == 0x64 && // 'd'
           data[1] == 0x65 && // 'e'
           data[2] == 0x78 && // 'x'
           data[3] == 0x0A && // '\n'
           data[4] == 0x30 && // '0'
           data[5] == 0x33 && // '3'
           (data[6] >= 0x35 && data[6] <= 0x39); // '5'-'9'
  }
  
  static List<String> _extractStrings(Uint8List data, {int minLength = 4}) {
    final strings = <String>[];
    final currentString = <int>[];
    
    for (final byte in data) {
      if (byte >= 0x20 && byte <= 0x7E) {
        // Printable ASCII
        currentString.add(byte);
      } else {
        if (currentString.length >= minLength) {
          strings.add(String.fromCharCodes(currentString));
        }
        currentString.clear();
      }
    }
    
    if (currentString.length >= minLength) {
      strings.add(String.fromCharCodes(currentString));
    }
    
    return strings;
  }
  
  static bool _hasPermissions(List<String> permissions, List<String> required) {
    return required.every((r) => permissions.contains(r));
  }
  
  static bool _hasAnyPermission(List<String> permissions, List<String> candidates) {
    return candidates.any((c) => permissions.contains(c));
  }
}

/// Entropy analysis result
class EntropyAnalysis {
  final double entropy;
  final bool isPacked;
  final double confidence;
  
  EntropyAnalysis({
    required this.entropy,
    required this.isPacked,
    required this.confidence,
  });
}

/// Native library alert
class NativeLibraryAlert {
  final String libraryPath;
  final String alertType;
  final ThreatSeverity severity;
  final String description;
  final double confidence;
  
  NativeLibraryAlert({
    required this.libraryPath,
    required this.alertType,
    required this.severity,
    required this.description,
    required this.confidence,
  });
}

/// Permission correlation result
class PermissionCorrelationResult {
  final List<SuspiciousPermissionPattern> suspiciousPatterns;
  final double riskScore;
  final bool hasCriticalPatterns;
  
  PermissionCorrelationResult({
    required this.suspiciousPatterns,
    required this.riskScore,
    required this.hasCriticalPatterns,
  });
}

/// Suspicious permission pattern
class SuspiciousPermissionPattern {
  final String patternName;
  final List<String> permissions;
  final ThreatSeverity severity;
  final String description;
  final double riskContribution;
  
  SuspiciousPermissionPattern({
    required this.patternName,
    required this.permissions,
    required this.severity,
    required this.description,
    required this.riskContribution,
  });
}

/// Obfuscation detection result
class ObfuscationDetection {
  final int obfuscationScore;
  final ThreatSeverity severity;
  final List<String> indicators;
  final bool isHighlyObfuscated;
  
  ObfuscationDetection({
    required this.obfuscationScore,
    required this.severity,
    required this.indicators,
    required this.isHighlyObfuscated,
  });
}
