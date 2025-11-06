import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:scanx/core/models/threat_model.dart';

/// Collects device telemetry and installed app metadata
class DeviceDataCollector {
  /// Get list of all installed apps with metadata
  Future<List<AppMetadata>> getInstalledApps() async {
    // In production: use native Android method channel to enumerate packages
    // For now: return mock data for testing
    return _generateMockApps();
  }

  /// Calculate file hashes (MD5, SHA1, SHA256)
  Future<Map<String, String>> calculateFileHashes(String filePath) async {
    try {
      final file = File(filePath);
      if (!await file.exists()) {
        return {};
      }

      final bytes = await file.readAsBytes();
      return {
        'md5': md5.convert(bytes).toString(),
        'sha1': sha1.convert(bytes).toString(),
        'sha256': sha256.convert(bytes).toString(),
      };
    } catch (e) {
      print('Error calculating hashes: $e');
      return {};
    }
  }

  /// Get app manifest information
  Future<Map<String, dynamic>> getAppManifest(String packageName) async {
    // In production: parse AndroidManifest.xml from APK
    return _getMockManifest(packageName);
  }

  /// Get system information
  Map<String, String> getSystemInfo() {
    return {
      'os_version': Platform.operatingSystemVersion,
      'locale': Platform.localeName,
      'architecture': Platform.numberOfProcessors.toString(),
    };
  }

  /// Check if device is rooted
  Future<bool> isDeviceRooted() async {
    // In production: check for root indicators
    // - su binary existence
    // - Magisk/SuperSU installations
    // - SELinux context
    return false;
  }

  /// Get network interfaces info
  Future<List<String>> getNetworkInterfaces() async {
    try {
      final interfaces = await NetworkInterface.list();
      return interfaces
          .map((i) => '${i.name}:${i.addresses.first.address}')
          .toList();
    } catch (e) {
      return [];
    }
  }

  // Mock data generation for testing

  List<AppMetadata> _generateMockApps() {
    return [
      // Legitimate apps
      AppMetadata(
        packageName: 'com.android.chrome',
        appName: 'Google Chrome',
        version: '119.0.0.1',
        hash: 'abc123def456',
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch,
        isSystemApp: false,
        installerPackage: 'com.android.vending',
        size: 150 * 1024 * 1024,
        requestedPermissions: [
          'android.permission.INTERNET',
          'android.permission.ACCESS_NETWORK_STATE',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.CAMERA',
          'android.permission.RECORD_AUDIO',
        ],
        grantedPermissions: [
          'android.permission.INTERNET',
          'android.permission.ACCESS_NETWORK_STATE',
        ],
      ),
      AppMetadata(
        packageName: 'com.android.settings',
        appName: 'Settings',
        version: '14.0',
        hash: 'settings_hash',
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 365,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch,
        isSystemApp: true,
        installerPackage: 'android',
        size: 20 * 1024 * 1024,
        requestedPermissions: [
          'android.permission.CHANGE_NETWORK_STATE',
          'android.permission.WRITE_SETTINGS',
        ],
        grantedPermissions: [
          'android.permission.CHANGE_NETWORK_STATE',
        ],
      ),
      AppMetadata(
        packageName: 'com.whatsapp',
        appName: 'WhatsApp',
        version: '23.20.0',
        hash: 'whatsapp_hash',
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 30,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 2,
        isSystemApp: false,
        installerPackage: 'com.android.vending',
        size: 80 * 1024 * 1024,
        requestedPermissions: [
          'android.permission.INTERNET',
          'android.permission.RECORD_AUDIO',
          'android.permission.CAMERA',
          'android.permission.READ_CONTACTS',
          'android.permission.READ_CALL_LOG',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.WRITE_EXTERNAL_STORAGE',
        ],
        grantedPermissions: [
          'android.permission.INTERNET',
          'android.permission.RECORD_AUDIO',
          'android.permission.CAMERA',
          'android.permission.READ_CONTACTS',
        ],
      ),
      // Suspicious app (simulated)
      AppMetadata(
        packageName: 'com.fake.cleaner',
        appName: 'Fast Cleaner',
        version: '1.0.0',
        hash: '5d41402abc4b2a76b9719d911017c592', // Matches signature DB
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 3,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 3,
        isSystemApp: false,
        installerPackage: 'unknown_source',
        size: 250 * 1024 * 1024, // Suspiciously large
        requestedPermissions: [
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.READ_EXTERNAL_STORAGE',
          'android.permission.SYSTEM_ALERT_WINDOW',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
          'android.permission.READ_CONTACTS',
          'android.permission.READ_CALL_LOG',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.CAMERA',
          'android.permission.RECORD_AUDIO',
        ],
        grantedPermissions: [
          'android.permission.WRITE_EXTERNAL_STORAGE',
          'android.permission.SYSTEM_ALERT_WINDOW',
        ],
      ),
      // Another suspicious app
      AppMetadata(
        packageName: 'com.scam.update',
        appName: 'System Update',
        version: '1.0',
        hash: 'fake_update_hash',
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch - 86400000,
        isSystemApp: false,
        installerPackage: 'unknown',
        size: 180 * 1024 * 1024,
        requestedPermissions: [
          'android.permission.MANAGE_EXTERNAL_STORAGE',
          'android.permission.RECORD_AUDIO',
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.BIND_ACCESSIBILITY_SERVICE',
        ],
        grantedPermissions: [
          'android.permission.MANAGE_EXTERNAL_STORAGE',
        ],
      ),
      // Normal banking app
      AppMetadata(
        packageName: 'com.example.bank',
        appName: 'MyBank',
        version: '5.2.1',
        hash: 'bank_hash_verified',
        installTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 180,
        lastUpdateTime: DateTime.now().millisecondsSinceEpoch - 86400000 * 7,
        isSystemApp: false,
        installerPackage: 'com.android.vending',
        size: 45 * 1024 * 1024,
        requestedPermissions: [
          'android.permission.INTERNET',
          'android.permission.ACCESS_NETWORK_STATE',
          'android.permission.CAMERA',
        ],
        grantedPermissions: [
          'android.permission.INTERNET',
          'android.permission.CAMERA',
        ],
      ),
    ];
  }

  Map<String, dynamic> _getMockManifest(String packageName) {
    return {
      'packageName': packageName,
      'debuggable': false,
      'usesCleartextTraffic': false,
      'activities': [],
      'services': [],
    };
  }
}
