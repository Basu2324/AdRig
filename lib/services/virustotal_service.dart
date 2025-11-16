import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:adrig/config/api_config.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Real VirusTotal API Integration
/// Scans APK hashes against 70+ antivirus engines
class VirusTotalService {
  static const String _baseUrl = 'https://www.virustotal.com/vtapi/v2';
  
  final String _apiKey;
  final _cache = <String, VirusTotalResult>{};
  
  VirusTotalService({String? apiKey}) 
    : _apiKey = apiKey ?? APIConfig.virusTotalKey;
  
  /// Check if service is configured
  bool get isConfigured => _apiKey.isNotEmpty;
  
  /// Scan file hash (SHA256) against VirusTotal
  /// This is FAST - just a hash lookup, no file upload needed
  Future<VirusTotalResult?> scanHash(String sha256Hash) async {
    if (!isConfigured) {
      print('⚠️  VirusTotal API key not configured');
      return null;
    }
    
    // Check cache first
    if (_cache.containsKey(sha256Hash)) {
      print('✓ Using cached VirusTotal result for $sha256Hash');
      return _cache[sha256Hash];
    }
    
    try {
      final url = Uri.parse('$_baseUrl/file/report?apikey=$_apiKey&resource=$sha256Hash');
      final response = await http.get(url).timeout(Duration(seconds: 10));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        
        // V2 API response format
        if (data['response_code'] == 0) {
          print('ℹ️  File not found in VirusTotal database');
          return null;
        }
        
        final result = VirusTotalResult.fromJsonV2(data);
        
        // Cache result
        _cache[sha256Hash] = result;
        
        print('✓ VirusTotal: ${result.positives}/${result.total} engines detected malware');
        return result;
      } else if (response.statusCode == 404) {
        print('ℹ️  File not found in VirusTotal database');
        return null;
      } else {
        print('⚠️  VirusTotal API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ VirusTotal scan error: $e');
      return null;
    }
  }
  
  /// Convert VirusTotal result to threat if malware detected
  DetectedThreat? resultToThreat({
    required VirusTotalResult result,
    required String packageName,
    required String appName,
  }) {
    if (result.positives == 0) {
      return null; // Clean
    }
    
    // Calculate severity based on detection rate
    final detectionRate = result.positives / result.total;
    ThreatSeverity severity;
    if (detectionRate >= 0.5) {
      severity = ThreatSeverity.critical; // 50%+ engines detected it
    } else if (detectionRate >= 0.3) {
      severity = ThreatSeverity.high; // 30-50% detected
    } else if (detectionRate >= 0.1) {
      severity = ThreatSeverity.medium; // 10-30% detected
    } else {
      severity = ThreatSeverity.low; // <10% detected (possibly false positive)
    }
    
    return DetectedThreat(
      id: 'vt_${DateTime.now().millisecondsSinceEpoch}',
      packageName: packageName,
      appName: appName,
      threatType: _inferThreatType(result.malwareNames),
      severity: severity,
      detectionMethod: DetectionMethod.signature,
      description: 'Detected by ${result.positives} out of ${result.total} antivirus engines',
      indicators: [
        'Detection rate: ${(detectionRate * 100).toStringAsFixed(1)}%',
        'Detected as: ${result.malwareNames.take(3).join(", ")}',
        'Scanned by: ${result.engineNames.take(5).join(", ")}',
      ],
      confidence: detectionRate.clamp(0.0, 1.0),
      detectedAt: DateTime.now(),
      hash: result.sha256,
      version: '',
      recommendedAction: severity == ThreatSeverity.critical 
        ? ActionType.quarantine 
        : ActionType.alert,
      metadata: {
        'virusTotalPositives': result.positives,
        'virusTotalTotal': result.total,
        'detectionRate': detectionRate,
        'malwareNames': result.malwareNames,
      },
      isSystemApp: false,
    );
  }
  
  /// Infer threat type from malware names
  ThreatType _inferThreatType(List<String> names) {
    final joined = names.join(' ').toLowerCase();
    
    if (joined.contains('trojan')) return ThreatType.trojan;
    if (joined.contains('ransomware')) return ThreatType.ransomware;
    if (joined.contains('spy') || joined.contains('keylog')) return ThreatType.spyware;
    if (joined.contains('adware')) return ThreatType.adware;
    if (joined.contains('rootkit')) return ThreatType.rootkit;
    if (joined.contains('backdoor')) return ThreatType.backdoor;
    
    return ThreatType.malware; // Generic malware
  }
  
  /// Clear cache
  void clearCache() {
    _cache.clear();
  }
}

/// VirusTotal scan result
class VirusTotalResult {
  final String sha256;
  final int positives; // Number of engines that detected malware
  final int total; // Total engines scanned
  final List<String> malwareNames; // What engines called it
  final List<String> engineNames; // Which engines detected it
  final DateTime scanDate;
  
  VirusTotalResult({
    required this.sha256,
    required this.positives,
    required this.total,
    required this.malwareNames,
    required this.engineNames,
    required this.scanDate,
  });
  
  factory VirusTotalResult.fromJson(Map<String, dynamic> json) {
    final attributes = json['data']['attributes'];
    final stats = attributes['last_analysis_stats'];
    final results = attributes['last_analysis_results'] as Map<String, dynamic>;
    
    final malwareNames = <String>[];
    final engineNames = <String>[];
    
    results.forEach((engine, result) {
      if (result['category'] == 'malicious') {
        engineNames.add(engine);
        final name = result['result'];
        if (name != null && !malwareNames.contains(name)) {
          malwareNames.add(name);
        }
      }
    });
    
    return VirusTotalResult(
      sha256: attributes['sha256'],
      positives: stats['malicious'] ?? 0,
      total: (stats['malicious'] ?? 0) + 
             (stats['undetected'] ?? 0) + 
             (stats['suspicious'] ?? 0),
      malwareNames: malwareNames,
      engineNames: engineNames,
      scanDate: DateTime.fromMillisecondsSinceEpoch(
        attributes['last_analysis_date'] * 1000,
      ),
    );
  }
  
  /// V2 API format parser
  factory VirusTotalResult.fromJsonV2(Map<String, dynamic> json) {
    final scans = json['scans'] as Map<String, dynamic>? ?? {};
    
    final malwareNames = <String>[];
    final engineNames = <String>[];
    
    scans.forEach((engine, result) {
      if (result['detected'] == true) {
        engineNames.add(engine);
        final name = result['result'];
        if (name != null && !malwareNames.contains(name)) {
          malwareNames.add(name);
        }
      }
    });
    
    return VirusTotalResult(
      sha256: json['sha256'] ?? json['resource'] ?? '',
      positives: json['positives'] ?? 0,
      total: json['total'] ?? 0,
      malwareNames: malwareNames,
      engineNames: engineNames,
      scanDate: DateTime.parse(json['scan_date'] ?? DateTime.now().toIso8601String()),
    );
  }
  
  bool get isMalware => positives > 0;
  double get detectionRate => total > 0 ? positives / total : 0.0;
}
