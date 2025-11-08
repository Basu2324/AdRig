import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Cloud reputation service
/// Checks APK hashes against VirusTotal, Google SafeBrowsing, and other threat intel sources
class CloudReputationService {
  // API Keys (should be stored securely in production)
  static const String _vtApiKey = 'YOUR_VIRUSTOTAL_API_KEY';
  static const String _gsbApiKey = 'YOUR_GOOGLE_SAFEBROWSING_API_KEY';
  
  // Rate limiting
  static const int _vtRateLimit = 4; // VirusTotal free tier: 4 requests/min
  static const int _maxCacheAge = 7; // Cache results for 7 days
  
  DateTime? _lastVTRequest;
  int _vtRequestCount = 0;
  
  /// Check APK hash against VirusTotal
  Future<VirusTotalResult?> checkVirusTotal(String sha256Hash) async {
    try {
      // Check cache first
      final cached = await _getCachedResult('vt_$sha256Hash');
      if (cached != null) {
        print('✅ VirusTotal: Using cached result for $sha256Hash');
        return VirusTotalResult.fromJson(json.decode(cached));
      }
      
      // Rate limiting
      if (!_canMakeVTRequest()) {
        print('⏳ VirusTotal: Rate limit reached, skipping');
        return null;
      }
      
      print('🔍 VirusTotal: Checking hash $sha256Hash');
      
      // VirusTotal API v3
      final response = await http.get(
        Uri.parse('https://www.virustotal.com/api/v3/files/$sha256Hash'),
        headers: {
          'x-apikey': _vtApiKey,
        },
      ).timeout(Duration(seconds: 15));
      
      _updateVTRateLimit();
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        final result = VirusTotalResult.fromVTResponse(data);
        
        // Cache result
        await _cacheResult('vt_$sha256Hash', json.encode(result.toJson()));
        
        print('✅ VirusTotal: ${result.positives}/${result.total} detections');
        return result;
      } else if (response.statusCode == 404) {
        print('ℹ️  VirusTotal: Hash not found (new/unknown file)');
        return null;
      } else {
        print('❌ VirusTotal API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ VirusTotal error: $e');
      return null;
    }
  }
  
  /// Submit APK for VirusTotal scanning (if not already in database)
  Future<String?> submitToVirusTotal(String apkPath) async {
    try {
      if (!_canMakeVTRequest()) {
        print('⏳ VirusTotal: Rate limit reached, cannot submit');
        return null;
      }
      
      print('📤 VirusTotal: Submitting file for analysis');
      
      final request = http.MultipartRequest(
        'POST',
        Uri.parse('https://www.virustotal.com/api/v3/files'),
      );
      
      request.headers['x-apikey'] = _vtApiKey;
      request.files.add(await http.MultipartFile.fromPath('file', apkPath));
      
      final response = await request.send().timeout(Duration(minutes: 5));
      _updateVTRateLimit();
      
      if (response.statusCode == 200) {
        final responseData = await response.stream.bytesToString();
        final data = json.decode(responseData);
        final analysisId = data['data']['id'];
        
        print('✅ VirusTotal: File submitted, analysis ID: $analysisId');
        return analysisId;
      } else {
        print('❌ VirusTotal submission failed: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ VirusTotal submission error: $e');
      return null;
    }
  }
  
  /// Check URL/domain against Google SafeBrowsing
  Future<SafeBrowsingResult?> checkSafeBrowsing(List<String> urls) async {
    if (urls.isEmpty) return null;
    
    try {
      print('🔍 SafeBrowsing: Checking ${urls.length} URLs');
      
      final response = await http.post(
        Uri.parse('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$_gsbApiKey'),
        headers: {'Content-Type': 'application/json'},
        body: json.encode({
          'client': {
            'clientId': 'scanx-mobile-security',
            'clientVersion': '1.0.0',
          },
          'threatInfo': {
            'threatTypes': [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            'platformTypes': ['ANDROID'],
            'threatEntryTypes': ['URL'],
            'threatEntries': urls.map((url) => {'url': url}).toList(),
          },
        }),
      ).timeout(Duration(seconds: 10));
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        final matches = data['matches'] as List?;
        
        if (matches != null && matches.isNotEmpty) {
          print('⚠️  SafeBrowsing: Found ${matches.length} malicious URLs');
          return SafeBrowsingResult(
            isMalicious: true,
            matches: matches.map((m) => ThreatMatch.fromJson(m)).toList(),
          );
        } else {
          print('✅ SafeBrowsing: All URLs clean');
          return SafeBrowsingResult(isMalicious: false, matches: []);
        }
      } else {
        print('❌ SafeBrowsing API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ SafeBrowsing error: $e');
      return null;
    }
  }
  
  /// Check against abuse.ch URLhaus (malicious URL database)
  Future<URLhausResult?> checkURLhaus(String url) async {
    try {
      final response = await http.post(
        Uri.parse('https://urlhaus-api.abuse.ch/v1/url/'),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {'url': url},
      ).timeout(Duration(seconds: 10));
      
      if (response.statusCode == 200) {
        final data = json.decode(response.body);
        
        if (data['query_status'] == 'ok') {
          print('⚠️  URLhaus: Malicious URL detected');
          return URLhausResult(
            isMalicious: true,
            threat: data['threat'] ?? 'malware_download',
            tags: List<String>.from(data['tags'] ?? []),
          );
        } else {
          return URLhausResult(isMalicious: false, threat: null, tags: []);
        }
      }
    } catch (e) {
      print('❌ URLhaus error: $e');
    }
    
    return null;
  }
  
  /// Calculate reputation score from all sources
  Future<ReputationScore> calculateReputationScore(
    String sha256Hash,
    List<String> urls,
  ) async {
    var score = 100; // Start with clean score
    final threats = <String>[];
    
    // Check VirusTotal
    final vtResult = await checkVirusTotal(sha256Hash);
    if (vtResult != null) {
      if (vtResult.positives > 0) {
        final detectionRate = (vtResult.positives / vtResult.total) * 100;
        
        if (detectionRate > 50) {
          score -= 80; // Highly malicious
          threats.add('${vtResult.positives}/${vtResult.total} AV vendors flagged this as malware');
        } else if (detectionRate > 20) {
          score -= 50; // Suspicious
          threats.add('${vtResult.positives}/${vtResult.total} AV vendors flagged this as suspicious');
        } else {
          score -= 20; // Low confidence detection
          threats.add('${vtResult.positives}/${vtResult.total} AV vendors reported issues');
        }
      }
    }
    
    // Check SafeBrowsing
    final gsbResult = await checkSafeBrowsing(urls);
    if (gsbResult != null && gsbResult.isMalicious) {
      score -= 60;
      threats.add('${gsbResult.matches.length} malicious URLs detected by Google SafeBrowsing');
    }
    
    // Check URLhaus
    for (final url in urls.take(5)) {
      final urlhausResult = await checkURLhaus(url);
      if (urlhausResult != null && urlhausResult.isMalicious) {
        score -= 30;
        threats.add('URL flagged as ${urlhausResult.threat} by URLhaus');
        break;
      }
    }
    
    return ReputationScore(
      score: score.clamp(0, 100),
      isMalicious: score < 30,
      threats: threats,
      vtResult: vtResult,
      gsbResult: gsbResult,
    );
  }
  
  // ==================== Rate Limiting ====================
  
  bool _canMakeVTRequest() {
    final now = DateTime.now();
    
    if (_lastVTRequest == null || now.difference(_lastVTRequest!).inMinutes >= 1) {
      _lastVTRequest = now;
      _vtRequestCount = 0;
      return true;
    }
    
    return _vtRequestCount < _vtRateLimit;
  }
  
  void _updateVTRateLimit() {
    _vtRequestCount++;
  }
  
  // ==================== Caching ====================
  
  Future<void> _cacheResult(String key, String value) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(key, value);
      await prefs.setInt('${key}_timestamp', DateTime.now().millisecondsSinceEpoch);
    } catch (e) {
      print('Cache write error: $e');
    }
  }
  
  Future<String?> _getCachedResult(String key) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final timestamp = prefs.getInt('${key}_timestamp');
      
      if (timestamp != null) {
        final age = DateTime.now().millisecondsSinceEpoch - timestamp;
        final ageDays = age / (1000 * 60 * 60 * 24);
        
        if (ageDays < _maxCacheAge) {
          return prefs.getString(key);
        }
      }
    } catch (e) {
      print('Cache read error: $e');
    }
    
    return null;
  }
}

// ==================== Data Models ====================

class VirusTotalResult {
  final int positives;
  final int total;
  final List<String> detections;
  final String scanDate;

  VirusTotalResult({
    required this.positives,
    required this.total,
    required this.detections,
    required this.scanDate,
  });

  factory VirusTotalResult.fromVTResponse(Map<String, dynamic> data) {
    final attributes = data['data']['attributes'];
    final stats = attributes['last_analysis_stats'];
    
    final positives = stats['malicious'] ?? 0;
    final total = (stats['harmless'] ?? 0) +
                 (stats['malicious'] ?? 0) +
                 (stats['suspicious'] ?? 0) +
                 (stats['undetected'] ?? 0);
    
    final results = attributes['last_analysis_results'] as Map<String, dynamic>?;
    final detections = <String>[];
    
    if (results != null) {
      results.forEach((engine, result) {
        if (result['category'] == 'malicious' || result['category'] == 'suspicious') {
          detections.add('$engine: ${result['result']}');
        }
      });
    }
    
    return VirusTotalResult(
      positives: positives,
      total: total,
      detections: detections,
      scanDate: attributes['last_analysis_date']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
        'positives': positives,
        'total': total,
        'detections': detections,
        'scanDate': scanDate,
      };

  factory VirusTotalResult.fromJson(Map<String, dynamic> json) => VirusTotalResult(
        positives: json['positives'],
        total: json['total'],
        detections: List<String>.from(json['detections']),
        scanDate: json['scanDate'],
      );
}

class SafeBrowsingResult {
  final bool isMalicious;
  final List<ThreatMatch> matches;

  SafeBrowsingResult({required this.isMalicious, required this.matches});
}

class ThreatMatch {
  final String threatType;
  final String platformType;
  final String url;

  ThreatMatch({
    required this.threatType,
    required this.platformType,
    required this.url,
  });

  factory ThreatMatch.fromJson(Map<String, dynamic> json) => ThreatMatch(
        threatType: json['threatType'] ?? 'UNKNOWN',
        platformType: json['platformType'] ?? 'ANDROID',
        url: json['threat']['url'] ?? '',
      );
}

class URLhausResult {
  final bool isMalicious;
  final String? threat;
  final List<String> tags;

  URLhausResult({
    required this.isMalicious,
    required this.threat,
    required this.tags,
  });
}

class ReputationScore {
  final int score; // 0-100 (0 = malicious, 100 = clean)
  final bool isMalicious;
  final List<String> threats;
  final VirusTotalResult? vtResult;
  final SafeBrowsingResult? gsbResult;

  ReputationScore({
    required this.score,
    required this.isMalicious,
    required this.threats,
    this.vtResult,
    this.gsbResult,
  });
}
