import 'package:flutter_dotenv/flutter_dotenv.dart';

/// API Configuration - Loads real API keys from .env file
/// This provides access to real malware detection services
class APIConfig {
  /// VirusTotal API - Scans against 70+ antivirus engines
  static String get virusTotalKey => dotenv.env['VIRUSTOTAL_API_KEY'] ?? '';
  
  /// IPQualityScore API - Malware & fraud detection
  static String get ipQualityScoreKey => dotenv.env['IPQUALITYSCORE_API_KEY'] ?? '';
  
  /// AbuseIPDB API - IP reputation & malicious IP detection
  static String get abuseIPDBKey => dotenv.env['ABUSEIPDB_API_KEY'] ?? '';
  
  /// AlienVault OTX API - Threat intelligence
  static String get alienVaultKey => dotenv.env['ALIENVAULT_OTX_API_KEY'] ?? '';
  
  /// Check if APIs are configured
  static bool get isConfigured {
    return virusTotalKey.isNotEmpty;
  }
  
  /// Initialize and load environment variables
  static Future<void> initialize() async {
    try {
      await dotenv.load(fileName: ".env");
      print('✅ API keys loaded successfully');
      print('   - VirusTotal: ${virusTotalKey.isNotEmpty ? "✓" : "✗"}');
      print('   - IPQualityScore: ${ipQualityScoreKey.isNotEmpty ? "✓" : "✗"}');
      print('   - AbuseIPDB: ${abuseIPDBKey.isNotEmpty ? "✓" : "✗"}');
      print('   - AlienVault: ${alienVaultKey.isNotEmpty ? "✓" : "✗"}');
    } catch (e) {
      print('⚠️  Failed to load API keys: $e');
      print('   Please ensure .env file exists in project root');
    }
  }
}
