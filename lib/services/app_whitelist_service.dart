import 'package:adrig/core/models/threat_model.dart';

/// Intelligent app whitelist service
/// Excludes safe apps from scanning to reduce false positives
class AppWhitelistService {
  
  // ONLY CORE Android system components (minimal whitelist)
  // We WILL scan: User apps, pre-installed apps, system apps, Play Store apps
  static final Set<String> _systemPackages = {
    // Core Android framework (cannot be malware)
    'android',
    'com.android.systemui',
    
    // Our own scanner app
    'com.autoguard.malware_scanner',
  };
  
  /// Publishers with strong security reputations
  static final Set<String> _trustedPublishers = {
    'Google LLC',
    'Google Inc.',
    'Samsung Electronics Co., Ltd.',
    'Microsoft Corporation',
    'Facebook',
    'Meta Platforms, Inc.',
    'WhatsApp Inc.',
    'Telegram Messenger LLP',
    'Spotify Ltd.',
    'Netflix, Inc.',
    'Amazon Mobile LLC',
    'Adobe',
  };
  
  /// Check if app should be whitelisted (excluded from scanning)
  static bool isWhitelisted(AppMetadata app) {
    // 1. ONLY whitelist our own scanner app
    if (app.packageName == 'com.autoguard.malware_scanner') {
      return true;
    }
    
    // 2. ONLY whitelist CORE Android system packages (very minimal list)
    if (_systemPackages.contains(app.packageName)) {
      return true;
    }
    
    // 3. User manually whitelisted apps
    if (_userWhitelist.contains(app.packageName)) {
      return true;
    }
    
    // DO NOT SKIP: System apps (they can contain malware!)
    // DO NOT SKIP: Play Store apps (malware exists on Play Store!)
    // DO NOT SKIP: Pre-installed apps (OEM bloatware can be malicious!)
    
    return false;
  }
  
  /// Check if app should be scanned despite system flags
  /// (for high-risk pre-installed apps)
  static bool forceScantSystemApp(AppMetadata app) {
    // High-risk system app patterns
    final riskyPatterns = [
      'cleaner',
      'booster',
      'antivirus',
      'security',
      'vpn',
      'browser', // Except Chrome
    ];
    
    final packageLower = app.packageName.toLowerCase();
    final appNameLower = app.appName.toLowerCase();
    
    // Whitelist Chrome
    if (packageLower.contains('chrome') || 
        packageLower.contains('com.google.android.apps.chrome')) {
      return false;
    }
    
    // Scan risky categories even if system app
    for (final pattern in riskyPatterns) {
      if (packageLower.contains(pattern) || appNameLower.contains(pattern)) {
        return true;
      }
    }
    
    return false;
  }
  
  /// Get whitelist statistics
  static Map<String, dynamic> getStatistics() {
    return {
      'totalSystemPackages': _systemPackages.length,
      'trustedPublishers': _trustedPublishers.length,
      'whitelistVersion': '1.0.0',
    };
  }
  
  /// Add custom package to whitelist (for user-approved apps)
  static final Set<String> _userWhitelist = {};
  
  static void addToUserWhitelist(String packageName) {
    _userWhitelist.add(packageName);
  }
  
  static void removeFromUserWhitelist(String packageName) {
    _userWhitelist.remove(packageName);
  }
  
  static bool isUserWhitelisted(String packageName) {
    return _userWhitelist.contains(packageName);
  }
  
  /// Get user whitelist
  static Set<String> getUserWhitelist() {
    return Set.from(_userWhitelist);
  }
  
  /// Add to whitelist (public method)
  static void addToWhitelist(String packageName) {
    _userWhitelist.add(packageName);
  }
  
  /// Remove from whitelist (public method)
  static void removeFromWhitelist(String packageName) {
    _userWhitelist.remove(packageName);
  }
  
  // Helper: Check if certificate is from trusted publisher
  static bool _isTrustedPublisher(String? certificate) {
    if (certificate == null || certificate.isEmpty) return false;
    
    // Certificate contains publisher name in CN (Common Name)
    final certLower = certificate.toLowerCase();
    
    for (final publisher in _trustedPublishers) {
      if (certLower.contains(publisher.toLowerCase())) {
        return true;
      }
    }
    
    return false;
  }
  
  /// Get whitelist reason for debugging
  static String? getWhitelistReason(AppMetadata app) {
    if (app.packageName == 'com.autoguard.malware_scanner') {
      return 'AdRig Scanner (self)';
    }
    
    if (_systemPackages.contains(app.packageName)) {
      return 'Core Android framework';
    }
    
    if (_userWhitelist.contains(app.packageName)) {
      return 'User approved';
    }
    
    return null;
  }
}
