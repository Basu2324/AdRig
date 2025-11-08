import 'package:crypto/crypto.dart';
import 'dart:io';
import 'package:adrig/core/models/threat_model.dart';

/// Signature-based malware detection engine
class SignatureEngine {
  final Map<String, MalwareSignature> _signatureDatabase = {};
  final Map<String, ThreatIndicator> _iocDatabase = {};

  /// Initialize with sample signatures (in production: load from encrypted DB)
  void initializeSampleSignatures() {
    _signatureDatabase.addAll({
      'sig_001': MalwareSignature(
        id: 'sig_001',
        hash: '5d41402abc4b2a76b9719d911017c592', // Known malware hash
        hashType: 'md5',
        malwareName: 'Trojan.Generic',
        family: 'Trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        indicators: ['calls_system_methods', 'hidden_component'],
        metadata: {'source': 'public_malware_db'},
      ),
      'sig_002': MalwareSignature(
        id: 'sig_002',
        hash: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', // Empty file SHA1
        hashType: 'sha1',
        malwareName: 'Adware.Mobile',
        family: 'Adware',
        threatType: ThreatType.adware,
        severity: ThreatSeverity.high,
        indicators: ['excessive_ads', 'tracking_beacon'],
      ),
    });

    _iocDatabase.addAll({
      'ioc_001': ThreatIndicator(
        id: 'ioc_001',
        indicator: 'malicious.c2.com',
        indicatorType: 'domain',
        source: 'threat_intelligence_feed',
        severity: ThreatSeverity.critical,
        lastSeen: DateTime.now(),
        confidence: 95,
      ),
    });
  }

  /// Scan file hash against signature database
  Future<List<DetectedThreat>> scanFileHash(String filePath) async {
    final threats = <DetectedThreat>[];

    try {
      final file = File(filePath);
      if (!await file.exists()) {
        return threats;
      }

      // Calculate multiple hashes
      final fileBytes = await file.readAsBytes();
      final md5Hash = md5.convert(fileBytes).toString();
      final sha1Hash = sha1.convert(fileBytes).toString();
      final sha256Hash = sha256.convert(fileBytes).toString();

      // Check against signature database
      for (final sig in _signatureDatabase.values) {
        if (sig.hash == md5Hash ||
            sig.hash == sha1Hash ||
            sig.hash == sha256Hash) {
          threats.add(
            DetectedThreat(
              id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
              packageName: 'file.${filePath.split('/').last}',
              appName: filePath.split('/').last,
              threatType: sig.threatType,
              severity: sig.severity,
              detectionMethod: DetectionMethod.signature,
              description:
                  'Malware signature matched: ${sig.malwareName} (${sig.family})',
              indicators: sig.indicators ?? [],
              confidence: 0.99,
              detectedAt: DateTime.now(),
              hash: md5Hash,
              recommendedAction: ActionType.quarantine,
              metadata: {
                'signature_id': sig.id,
                'hash_type': sig.hashType,
                'family': sig.family,
              },
            ),
          );
        }
      }
    } catch (e) {
      print('Error scanning file: $e');
    }

    return threats;
  }

  /// Permission-pattern based detection (ransomware, spyware, trojans)
  List<DetectedThreat> detectPermissionPatterns(
    String packageName,
    String appName,
    List<String> requestedPermissions,
    List<String> grantedPermissions,
  ) {
    final threats = <DetectedThreat>[];

    // Ransomware pattern: write + delete + usb storage access
    if (_containsPermissions(requestedPermissions, [
      'android.permission.WRITE_EXTERNAL_STORAGE',
      'android.permission.READ_EXTERNAL_STORAGE',
      'android.permission.MANAGE_EXTERNAL_STORAGE',
    ])) {
      // Check for suspicious combination
      final suspicious = _analyzeRansomwarePattern(
        packageName,
        appName,
        requestedPermissions,
      );
      if (suspicious != null) threats.add(suspicious);
    }

    // Spyware pattern: location + contacts + call log + camera + microphone
    final spywareIndicators = [
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.ACCESS_COARSE_LOCATION',
      'android.permission.READ_CONTACTS',
      'android.permission.READ_CALL_LOG',
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
    ];
    if (_countMatchingPermissions(requestedPermissions, spywareIndicators) >=
        4) {
      threats.add(_createPermissionThreat(
        packageName,
        appName,
        ThreatType.spyware,
        'Excessive surveillance permissions requested',
        spywareIndicators,
      ));
    }

    // Credential stealer pattern: accessibility + clipboard
    if (_containsPermissions(requestedPermissions, [
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
    ])) {
      threats.add(_createPermissionThreat(
        packageName,
        appName,
        ThreatType.trojan,
        'Accessibility service + credential capture indicators',
        ['android.permission.BIND_ACCESSIBILITY_SERVICE'],
      ));
    }

    // Overlay trojan: system alert window + clipboard
    if (_containsPermissions(requestedPermissions, [
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.SYSTEM_OVERLAY_WINDOW',
    ])) {
      threats.add(_createPermissionThreat(
        packageName,
        appName,
        ThreatType.trojan,
        'Overlay window + system permission abuse',
        [
          'android.permission.SYSTEM_ALERT_WINDOW',
          'android.permission.SYSTEM_OVERLAY_WINDOW'
        ],
      ));
    }

    return threats;
  }

  /// IOC-based detection (domains, IPs, command servers)
  List<DetectedThreat> detectByIOC(
    String packageName,
    String appName,
    List<String> detectedNetworks,
  ) {
    final threats = <DetectedThreat>[];

    for (final network in detectedNetworks) {
      for (final ioc in _iocDatabase.values) {
        if (network.contains(ioc.indicator)) {
          threats.add(
            DetectedThreat(
              id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
              packageName: packageName,
              appName: appName,
              threatType: ThreatType.malware,
              severity: ioc.severity,
              detectionMethod: DetectionMethod.threatintel,
              description:
                  'Known malicious IOC detected: ${ioc.indicator} (${ioc.indicatorType})',
              indicators: [ioc.indicator],
              confidence: ioc.confidence / 100.0,
              detectedAt: DateTime.now(),
              recommendedAction: ActionType.autoblock,
              metadata: {
                'ioc_id': ioc.id,
                'ioc_type': ioc.indicatorType,
                'source': ioc.source,
              },
            ),
          );
        }
      }
    }

    return threats;
  }

  // Helper methods

  bool _containsPermissions(
    List<String> requested,
    List<String> target,
  ) {
    return target.every((p) => requested.contains(p));
  }

  int _countMatchingPermissions(
    List<String> requested,
    List<String> target,
  ) {
    return target.where((p) => requested.contains(p)).length;
  }

  DetectedThreat? _analyzeRansomwarePattern(
    String packageName,
    String appName,
    List<String> permissions,
  ) {
    // Ransomware typically has write access + deletion patterns
    if (_containsPermissions(permissions, [
      'android.permission.WRITE_EXTERNAL_STORAGE',
    ])) {
      return _createPermissionThreat(
        packageName,
        appName,
        ThreatType.ransomware,
        'Ransomware-like permission pattern: storage write access',
        ['android.permission.WRITE_EXTERNAL_STORAGE'],
      );
    }
    return null;
  }

  DetectedThreat _createPermissionThreat(
    String packageName,
    String appName,
    ThreatType threatType,
    String description,
    List<String> indicators,
  ) {
    final severityMap = {
      ThreatType.ransomware: ThreatSeverity.critical,
      ThreatType.spyware: ThreatSeverity.high,
      ThreatType.trojan: ThreatSeverity.high,
      ThreatType.adware: ThreatSeverity.medium,
    };

    return DetectedThreat(
      id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
      packageName: packageName,
      appName: appName,
      threatType: threatType,
      severity: severityMap[threatType] ?? ThreatSeverity.medium,
      detectionMethod: DetectionMethod.staticanalysis,
      description: description,
      indicators: indicators,
      confidence: 0.75,
      detectedAt: DateTime.now(),
      recommendedAction: ActionType.alert,
      metadata: {
        'detection_type': 'permission_pattern',
        'threat_type': threatType.toString(),
      },
    );
  }

  /// Add signature to database (for updates)
  void addSignature(MalwareSignature signature) {
    _signatureDatabase[signature.id] = signature;
  }

  /// Add threat indicator (for threat intel updates)
  void addThreatIndicator(ThreatIndicator indicator) {
    _iocDatabase[indicator.id] = indicator;
  }

  /// Get database statistics
  Map<String, int> getStats() => {
    'signatures': _signatureDatabase.length,
    'indicators': _iocDatabase.length,
  };
}
