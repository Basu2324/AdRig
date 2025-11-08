import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:adrig/core/models/threat_model.dart';
import 'package:crypto/crypto.dart';

/// Privacy-first data handling service
/// Manages consent, anonymization, and on-device processing
class PrivacyService {
  PrivacyConsent? _currentConsent;
  final Set<String> _allowedDataTypes = {};
  bool _isInitialized = false;

  /// Initialize privacy service
  Future<void> initialize() async {
    try {
      await _loadConsent();
      _isInitialized = true;
      print('✓ Privacy service initialized');
    } catch (e) {
      print('Error initializing privacy service: $e');
    }
  }

  /// Request user consent for data processing
  Future<PrivacyConsent> requestConsent({
    bool cloudScanningEnabled = false,
    bool threatIntelSharingEnabled = false,
    bool anonymousTelemetryEnabled = false,
    bool autoUpdateEnabled = true,
  }) async {
    final consent = PrivacyConsent(
      userId: _generateAnonymousUserId(),
      cloudScanningEnabled: cloudScanningEnabled,
      threatIntelSharingEnabled: threatIntelSharingEnabled,
      anonymousTelemetryEnabled: anonymousTelemetryEnabled,
      autoUpdateEnabled: autoUpdateEnabled,
      consentDate: DateTime.now(),
    );

    await _saveConsent(consent);
    _currentConsent = consent;

    return consent;
  }

  /// Update consent settings
  Future<bool> updateConsent(PrivacyConsent updatedConsent) async {
    try {
      final consent = PrivacyConsent(
        userId: updatedConsent.userId,
        cloudScanningEnabled: updatedConsent.cloudScanningEnabled,
        threatIntelSharingEnabled: updatedConsent.threatIntelSharingEnabled,
        anonymousTelemetryEnabled: updatedConsent.anonymousTelemetryEnabled,
        autoUpdateEnabled: updatedConsent.autoUpdateEnabled,
        consentDate: updatedConsent.consentDate,
        lastModified: DateTime.now(),
      );

      await _saveConsent(consent);
      _currentConsent = consent;

      print('✓ Consent updated');
      return true;
    } catch (e) {
      print('Error updating consent: $e');
      return false;
    }
  }

  /// Check if cloud scanning is allowed
  bool isCloudScanningAllowed() {
    return _currentConsent?.cloudScanningEnabled ?? false;
  }

  /// Check if threat intel sharing is allowed
  bool isThreatIntelSharingAllowed() {
    return _currentConsent?.threatIntelSharingEnabled ?? false;
  }

  /// Check if telemetry is allowed
  bool isTelemetryAllowed() {
    return _currentConsent?.anonymousTelemetryEnabled ?? false;
  }

  /// Check if auto-update is allowed
  bool isAutoUpdateAllowed() {
    return _currentConsent?.autoUpdateEnabled ?? true;
  }

  /// Anonymize app metadata before cloud transmission
  Map<String, dynamic> anonymizeAppMetadata(AppMetadata app) {
    return {
      'package_hash': _hashString(app.packageName),
      'app_name_hash': _hashString(app.appName),
      'version': app.version,
      'size': app.size,
      'is_system_app': app.isSystemApp,
      'installer_type': _categorizeInstaller(app.installerPackage),
      'permission_count': app.requestedPermissions.length,
      'granted_permission_count': app.grantedPermissions.length,
      // DO NOT include: actual package name, app name, certificate
    };
  }

  /// Anonymize threat data before sharing
  Map<String, dynamic> anonymizeThreatData(DetectedThreat threat) {
    return {
      'threat_id': _generateAnonymousId(),
      'threat_type': threat.threatType.toString(),
      'severity': threat.severity.toString(),
      'detection_method': threat.detectionMethod.toString(),
      'confidence': threat.confidence,
      'hash': threat.hash,
      'timestamp': threat.detectedAt.toIso8601String(),
      // DO NOT include: package name, app name, user data
    };
  }

  /// Anonymize network connection data
  Map<String, dynamic> anonymizeNetworkData(NetworkConnection conn) {
    return {
      'destination_ip_subnet': _anonymizeIp(conn.destinationIp),
      'destination_port': conn.destinationPort,
      'protocol': conn.protocol,
      'is_encrypted': conn.isEncrypted,
      'bytes_range': _anonymizeBytes(conn.bytesTransferred),
      // DO NOT include: exact IP, domain, package name
    };
  }

  /// Check if data can be processed on-device
  bool shouldProcessOnDevice(String dataType) {
    // Always process these on-device
    final onDeviceOnly = {
      'app_enumeration',
      'permission_analysis',
      'file_hashing',
      'manifest_parsing',
      'signature_matching',
    };

    return onDeviceOnly.contains(dataType) || !isCloudScanningAllowed();
  }

  /// Check if data can be sent to cloud
  bool canSendToCloud(String dataType) {
    if (!isCloudScanningAllowed()) return false;

    // Only these can be sent to cloud with consent
    final cloudAllowed = {
      'file_hash',
      'threat_signature',
      'anonymized_metadata',
      'anonymized_threat_report',
    };

    return cloudAllowed.contains(dataType);
  }

  /// Sanitize data before storage
  Map<String, dynamic> sanitizeForStorage(Map<String, dynamic> data) {
    final sanitized = Map<String, dynamic>.from(data);

    // Remove PII fields
    final piiFields = [
      'email',
      'phone',
      'device_id',
      'imei',
      'mac_address',
      'exact_location',
    ];

    for (final field in piiFields) {
      sanitized.remove(field);
    }

    return sanitized;
  }

  /// Generate anonymous user ID
  String _generateAnonymousUserId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random = timestamp.toString() + 'scanx';
    return _hashString(random).substring(0, 16);
  }

  /// Generate anonymous ID for data
  String _generateAnonymousId() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    return _hashString(timestamp.toString()).substring(0, 12);
  }

  /// Hash a string
  String _hashString(String input) {
    return sha256.convert(utf8.encode(input)).toString();
  }

  /// Anonymize IP address (keep subnet)
  String _anonymizeIp(String ip) {
    final parts = ip.split('.');
    if (parts.length == 4) {
      return '${parts[0]}.${parts[1]}.xxx.xxx';
    }
    return 'xxx.xxx.xxx.xxx';
  }

  /// Anonymize byte count (use ranges)
  String _anonymizeBytes(int bytes) {
    if (bytes < 1024) return '< 1KB';
    if (bytes < 1024 * 1024) return '< 1MB';
    if (bytes < 10 * 1024 * 1024) return '< 10MB';
    if (bytes < 100 * 1024 * 1024) return '< 100MB';
    return '> 100MB';
  }

  /// Categorize installer without revealing exact name
  String _categorizeInstaller(String installer) {
    if (installer.contains('vending') || installer.contains('play')) {
      return 'official_store';
    } else if (installer == 'android' || installer.contains('system')) {
      return 'system';
    } else if (installer == 'unknown_source' || installer.isEmpty) {
      return 'unknown';
    } else {
      return 'third_party';
    }
  }

  /// Save consent to storage
  Future<void> _saveConsent(PrivacyConsent consent) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final consentJson = {
        'userId': consent.userId,
        'cloudScanningEnabled': consent.cloudScanningEnabled,
        'threatIntelSharingEnabled': consent.threatIntelSharingEnabled,
        'anonymousTelemetryEnabled': consent.anonymousTelemetryEnabled,
        'autoUpdateEnabled': consent.autoUpdateEnabled,
        'consentDate': consent.consentDate.toIso8601String(),
        'lastModified': consent.lastModified?.toIso8601String(),
      };
      await prefs.setString('privacy_consent', jsonEncode(consentJson));
    } catch (e) {
      print('Error saving consent: $e');
    }
  }

  /// Load consent from storage
  Future<void> _loadConsent() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final consentStr = prefs.getString('privacy_consent');
      
      if (consentStr != null) {
        final consentJson = jsonDecode(consentStr) as Map<String, dynamic>;
        _currentConsent = PrivacyConsent(
          userId: consentJson['userId'] as String,
          cloudScanningEnabled: consentJson['cloudScanningEnabled'] as bool,
          threatIntelSharingEnabled: consentJson['threatIntelSharingEnabled'] as bool,
          anonymousTelemetryEnabled: consentJson['anonymousTelemetryEnabled'] as bool,
          autoUpdateEnabled: consentJson['autoUpdateEnabled'] as bool,
          consentDate: DateTime.parse(consentJson['consentDate'] as String),
          lastModified: consentJson['lastModified'] != null
              ? DateTime.parse(consentJson['lastModified'] as String)
              : null,
        );
      }
    } catch (e) {
      print('Error loading consent: $e');
    }
  }

  /// Get current consent
  PrivacyConsent? getCurrentConsent() => _currentConsent;

  /// Check if consent has been given
  bool hasConsent() => _currentConsent != null;

  /// Check if initialized
  bool isInitialized() => _isInitialized;

  /// Clear all consent and data
  Future<void> clearAllData() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove('privacy_consent');
      _currentConsent = null;
      print('✓ Privacy data cleared');
    } catch (e) {
      print('Error clearing data: $e');
    }
  }
}
