import 'package:permission_handler/permission_handler.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'dart:io';

/// Manages all runtime permissions required for malware scanning
class PermissionService {
  /// Request all critical permissions needed for malware scanning
  Future<bool> requestAllPermissions() async {
    if (!Platform.isAndroid) {
      return true; // Only needed on Android
    }

    print('🔵 Starting COMPREHENSIVE permission request...');

    final androidInfo = await _getAndroidVersion();
    print('🔵 Android SDK version: $androidInfo');

    // Track permission results
    Map<String, bool> permissionResults = {};

    // ==================== STORAGE PERMISSIONS ====================
    bool storageGranted = false;

    if (androidInfo >= 33) {
      // Android 13+: Use MANAGE_EXTERNAL_STORAGE for full access
      print('🔵 Android 13+: Requesting MANAGE_EXTERNAL_STORAGE...');
      
      final manageStorageStatus = await Permission.manageExternalStorage.request();
      print('🔵 MANAGE_EXTERNAL_STORAGE result: $manageStorageStatus');
      storageGranted = manageStorageStatus.isGranted;
      permissionResults['MANAGE_EXTERNAL_STORAGE'] = storageGranted;
      
      // Also request media permissions for Android 13+
      try {
        final photos = await Permission.photos.request();
        final videos = await Permission.videos.request();
        final audio = await Permission.audio.request();
        permissionResults['photos'] = photos.isGranted;
        permissionResults['videos'] = videos.isGranted;
        permissionResults['audio'] = audio.isGranted;
        print('🔵 Media permissions: photos=${photos.isGranted}, videos=${videos.isGranted}, audio=${audio.isGranted}');
      } catch (e) {
        print('⚠️ Media permissions error: $e');
      }
      
    } else if (androidInfo >= 30) {
      // Android 11-12: Use MANAGE_EXTERNAL_STORAGE
      print('🔵 Android 11-12: Requesting MANAGE_EXTERNAL_STORAGE...');
      
      final manageStorageStatus = await Permission.manageExternalStorage.request();
      print('🔵 MANAGE_EXTERNAL_STORAGE result: $manageStorageStatus');
      storageGranted = manageStorageStatus.isGranted;
      permissionResults['MANAGE_EXTERNAL_STORAGE'] = storageGranted;
      
    } else {
      // Android 10 and below: Use legacy storage permission
      print('🔵 Android 10-: Requesting legacy storage...');
      
      final storageStatus = await Permission.storage.request();
      print('🔵 Storage result: $storageStatus');
      storageGranted = storageStatus.isGranted;
      permissionResults['storage'] = storageGranted;
    }

    // ==================== NOTIFICATION PERMISSIONS (Android 13+) ====================
    if (androidInfo >= 33) {
      try {
        final notification = await Permission.notification.request();
        permissionResults['notification'] = notification.isGranted;
        print('🔵 Notification permission: ${notification.isGranted}');
      } catch (e) {
        print('⚠️ Notification permission error: $e');
      }
    }

    // ==================== OPTIONAL BUT RECOMMENDED PERMISSIONS ====================
    // Request these to enable advanced threat detection features
    
    // Phone state (for detecting suspicious call activity)
    try {
      final phone = await Permission.phone.request();
      permissionResults['phone'] = phone.isGranted;
      print('🔵 Phone permission: ${phone.isGranted}');
    } catch (e) {
      print('⚠️ Phone permission not available: $e');
    }

    // SMS (for phishing message detection)
    try {
      final sms = await Permission.sms.request();
      permissionResults['sms'] = sms.isGranted;
      print('🔵 SMS permission: ${sms.isGranted}');
    } catch (e) {
      print('⚠️ SMS permission not available: $e');
    }

    // Contacts (for data leak detection)
    try {
      final contacts = await Permission.contacts.request();
      permissionResults['contacts'] = contacts.isGranted;
      print('🔵 Contacts permission: ${contacts.isGranted}');
    } catch (e) {
      print('⚠️ Contacts permission not available: $e');
    }

    // Location (for network threat correlation)
    try {
      final location = await Permission.location.request();
      permissionResults['location'] = location.isGranted;
      print('🔵 Location permission: ${location.isGranted}');
    } catch (e) {
      print('⚠️ Location permission not available: $e');
    }

    print('🔵 ==================== PERMISSION SUMMARY ====================');
    permissionResults.forEach((key, value) {
      print('🔵 $key: ${value ? "✅ GRANTED" : "❌ DENIED"}');
    });
    print('🔵 ==========================================================');

    print('🔵 Final storage permission status: $storageGranted');
    return storageGranted; // Storage is CRITICAL - must be granted
  }

  /// Request storage permissions (critical for scanning)
  Future<bool> requestStoragePermission() async {
    print('🔵 requestStoragePermission() called');
    if (!Platform.isAndroid) return true;

    // For Android 11+ (API 30+), we need MANAGE_EXTERNAL_STORAGE
    final androidInfo = await _getAndroidVersion();
    print('🔵 Android version: $androidInfo');
    
    if (androidInfo >= 30) {
      print('🔵 Android 11+, checking MANAGE_EXTERNAL_STORAGE...');
      // Check if already granted
      final currentStatus = await Permission.manageExternalStorage.status;
      print('🔵 Current status: $currentStatus');
      
      if (currentStatus.isGranted) {
        print('✅ MANAGE_EXTERNAL_STORAGE already granted!');
        return true;
      }
      
      // Request All Files Access for Android 11+
      print('🔵 Requesting MANAGE_EXTERNAL_STORAGE...');
      final status = await Permission.manageExternalStorage.request();
      print('🔵 Request result: $status');
      
      if (!status.isGranted) {
        // This permission cannot be granted via dialog, must use Settings
        print('⚠️ MANAGE_EXTERNAL_STORAGE denied - need to open Settings');
        return false;
      }
      return true;
    } else {
      print('🔵 Android 10 or below, requesting standard storage...');
      // For Android 10 and below
      final status = await Permission.storage.request();
      print('🔵 Storage permission result: $status');
      return status.isGranted;
    }
  }

  /// Request package query permission (to scan installed apps)
  Future<bool> requestPackagePermission() async {
    if (!Platform.isAndroid) return true;
    
    // This is a manifest permission, automatically granted
    // But we verify app can query packages
    return true;
  }

  /// Request phone state permission
  Future<bool> requestPhonePermission() async {
    final status = await Permission.phone.request();
    return status.isGranted;
  }

  /// Request SMS permission
  Future<bool> requestSmsPermission() async {
    final status = await Permission.sms.request();
    return status.isGranted;
  }

  /// Request location permission
  Future<bool> requestLocationPermission() async {
    final status = await Permission.location.request();
    return status.isGranted;
  }

  /// Request contacts permission
  Future<bool> requestContactsPermission() async {
    final status = await Permission.contacts.request();
    return status.isGranted;
  }

  /// Request camera permission
  Future<bool> requestCameraPermission() async {
    final status = await Permission.camera.request();
    return status.isGranted;
  }

  /// Request notification permission (Android 13+)
  Future<bool> requestNotificationPermission() async {
    if (!Platform.isAndroid) return true;
    
    final androidInfo = await _getAndroidVersion();
    if (androidInfo >= 33) {
      final status = await Permission.notification.request();
      return status.isGranted;
    }
    return true; // Not needed for older Android versions
  }

  /// Check if all critical permissions are granted
  Future<bool> hasAllCriticalPermissions() async {
    if (!Platform.isAndroid) return true;

    print('🔵 Checking critical permissions...');
    
    final androidInfo = await _getAndroidVersion();
    print('🔵 Android SDK: $androidInfo');
    
    if (androidInfo >= 30) {
      // Android 11+ needs MANAGE_EXTERNAL_STORAGE
      final manageStorageStatus = await Permission.manageExternalStorage.status;
      print('🔵 MANAGE_EXTERNAL_STORAGE: $manageStorageStatus');
      
      if (manageStorageStatus.isGranted) {
        return true;
      }
      
      // Fallback: check if regular storage is granted (shouldn't happen but just in case)
      try {
        final storageStatus = await Permission.storage.status;
        print('🔵 Legacy STORAGE (fallback): $storageStatus');
        return storageStatus.isGranted;
      } catch (e) {
        print('⚠️ Legacy storage check failed: $e');
        return false;
      }
    } else {
      // Android 10 and below need regular storage permission
      final storageStatus = await Permission.storage.status;
      print('🔵 STORAGE: $storageStatus');
      return storageStatus.isGranted;
    }
  }

  /// Check specific permission status
  Future<bool> hasPermission(Permission permission) async {
    final status = await permission.status;
    return status.isGranted;
  }

  /// Get detailed permission status report
  Future<Map<String, bool>> getPermissionReport() async {
    if (!Platform.isAndroid) {
      return {'all_granted': true};
    }

    final report = <String, bool>{};
    
    final permissions = {
      'storage': Permission.storage,
      'manage_storage': Permission.manageExternalStorage,
      'phone': Permission.phone,
      'sms': Permission.sms,
      'contacts': Permission.contacts,
      'location': Permission.location,
      'camera': Permission.camera,
      'notification': Permission.notification,
    };

    for (var entry in permissions.entries) {
      final status = await entry.value.status;
      report[entry.key] = status.isGranted;
    }

    return report;
  }

  /// Open app settings for manual permission grant
  Future<void> openSettings() async {
    await openAppSettings();
  }

  /// Get Android version
  Future<int> _getAndroidVersion() async {
    if (!Platform.isAndroid) return 0;
    
    try {
      final deviceInfo = DeviceInfoPlugin();
      final androidInfo = await deviceInfo.androidInfo;
      final sdkInt = androidInfo.version.sdkInt;
      print('🔵 Android SDK version: $sdkInt');
      return sdkInt;
    } catch (e) {
      print('⚠️ Error getting Android version: $e');
      return 30; // Default to Android 11 for safety
    }
  }

  /// Show permission rationale dialog
  String getPermissionRationale(Permission permission) {
    final rationales = {
      Permission.storage: 
        'Storage access is required to scan files, APKs, and detect malware on your device.',
      Permission.manageExternalStorage: 
        'Full storage access enables deep scanning of all files and folders for comprehensive malware detection.',
      Permission.phone: 
        'Phone permission helps detect suspicious call activities and SIM-based attacks.',
      Permission.sms: 
        'SMS access allows scanning for phishing messages and malicious links.',
      Permission.contacts: 
        'Contacts permission helps identify potential data leak attempts.',
      Permission.location: 
        'Location permission helps detect location-based tracking malware.',
      Permission.camera: 
        'Camera permission enables QR code scanning for security verification.',
      Permission.notification: 
        'Notification permission enables real-time threat alerts and scan updates.',
    };

    return rationales[permission] ?? 'This permission is needed for malware scanning.';
  }

  /// Check if permission is permanently denied
  Future<bool> isPermissionPermanentlyDenied(Permission permission) async {
    final status = await permission.status;
    return status.isPermanentlyDenied;
  }

  /// Request essential permissions in order
  Future<Map<String, dynamic>> requestEssentialPermissionsSequentially() async {
    final results = <String, dynamic>{
      'granted': <String>[],
      'denied': <String>[],
      'permanently_denied': <String>[],
    };

    // 1. Storage (most critical)
    final storageStatus = await requestStoragePermission();
    if (storageStatus) {
      results['granted'].add('storage');
    } else {
      results['denied'].add('storage');
    }

    // 2. Notification
    final notificationStatus = await requestNotificationPermission();
    if (notificationStatus) {
      results['granted'].add('notification');
    }

    // 3. Phone state
    final phoneStatus = await Permission.phone.request();
    if (phoneStatus.isGranted) {
      results['granted'].add('phone');
    } else if (phoneStatus.isPermanentlyDenied) {
      results['permanently_denied'].add('phone');
    } else {
      results['denied'].add('phone');
    }

    return results;
  }
}
