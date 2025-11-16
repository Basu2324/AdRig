import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:adrig/config/api_config.dart';

/// AbuseIPDB API Integration - Real-time IP reputation & malicious IP detection
/// Detects IPs involved in hacking, DDoS, spam, botnets, malware distribution
class AbuseIPDBService {
  static const String _baseUrl = 'https://api.abuseipdb.com/api/v2';
  
  final String _apiKey;
  final _cache = <String, AbuseIPResult>{};
  
  AbuseIPDBService({String? apiKey}) 
    : _apiKey = apiKey ?? APIConfig.abuseIPDBKey;
  
  bool get isConfigured => _apiKey.isNotEmpty;
  
  /// Check IP address reputation (REAL-TIME)
  Future<AbuseIPResult?> checkIP(String ipAddress) async {
    if (!isConfigured) {
      print('⚠️  AbuseIPDB API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(ipAddress)) {
      return _cache[ipAddress];
    }
    
    try {
      final apiUrl = Uri.parse('$_baseUrl/check').replace(
        queryParameters: {
          'ipAddress': ipAddress,
          'maxAgeInDays': '90',
          'verbose': 'true',
        },
      );
      
      final response = await http.get(
        apiUrl,
        headers: {
          'Key': _apiKey,
          'Accept': 'application/json',
        },
      ).timeout(Duration(seconds: 5));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = AbuseIPResult.fromJson(data['data']);
        
        _cache[ipAddress] = result;
        
        print('✓ AbuseIPDB: ${result.isMalicious ? "MALICIOUS" : "Clean"} (confidence: ${result.abuseConfidenceScore}%, reports: ${result.totalReports})');
        return result;
      } else if (response.statusCode == 429) {
        print('⚠️  AbuseIPDB rate limit exceeded');
        return null;
      } else {
        print('⚠️  AbuseIPDB API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ AbuseIPDB check error: $e');
      return null;
    }
  }
  
  /// Report malicious IP (optional - for contributing back)
  Future<bool> reportIP({
    required String ipAddress,
    required List<int> categories,
    required String comment,
  }) async {
    if (!isConfigured) return false;
    
    try {
      final apiUrl = Uri.parse('$_baseUrl/report');
      
      final response = await http.post(
        apiUrl,
        headers: {
          'Key': _apiKey,
          'Accept': 'application/json',
        },
        body: {
          'ip': ipAddress,
          'categories': categories.join(','),
          'comment': comment,
        },
      ).timeout(Duration(seconds: 10));
      
      return response.statusCode == 200;
    } catch (e) {
      print('❌ AbuseIPDB report error: $e');
      return false;
    }
  }
  
  void clearCache() {
    _cache.clear();
  }
}

/// AbuseIPDB Result
class AbuseIPResult {
  final String ipAddress;
  final bool isMalicious;
  final int abuseConfidenceScore; // 0-100
  final int totalReports;
  final int numDistinctUsers;
  final DateTime? lastReportedAt;
  final List<String> categories;
  final String countryCode;
  final String isp;
  final String domain;
  
  AbuseIPResult({
    required this.ipAddress,
    required this.isMalicious,
    required this.abuseConfidenceScore,
    required this.totalReports,
    required this.numDistinctUsers,
    this.lastReportedAt,
    required this.categories,
    required this.countryCode,
    required this.isp,
    required this.domain,
  });
  
  factory AbuseIPResult.fromJson(Map<String, dynamic> json) {
    final abuseScore = json['abuseConfidenceScore'] ?? 0;
    final totalReports = json['totalReports'] ?? 0;
    
    // Parse abuse categories
    final reports = json['reports'] as List<dynamic>? ?? [];
    final categorySet = <String>{};
    
    for (final report in reports) {
      final cats = report['categories'] as List<dynamic>? ?? [];
      for (final cat in cats) {
        categorySet.add(_getCategoryName(cat));
      }
    }
    
    return AbuseIPResult(
      ipAddress: json['ipAddress'] ?? '',
      isMalicious: abuseScore >= 25 || totalReports >= 5, // Malicious if 25+ score OR 5+ reports
      abuseConfidenceScore: abuseScore,
      totalReports: totalReports,
      numDistinctUsers: json['numDistinctUsers'] ?? 0,
      lastReportedAt: json['lastReportedAt'] != null 
        ? DateTime.parse(json['lastReportedAt']) 
        : null,
      categories: categorySet.toList(),
      countryCode: json['countryCode'] ?? '',
      isp: json['isp'] ?? 'Unknown',
      domain: json['domain'] ?? '',
    );
  }
  
  static String _getCategoryName(int categoryId) {
    const categories = {
      3: 'Fraud',
      4: 'DDoS Attack',
      9: 'Hacking',
      10: 'Spam',
      14: 'Port Scan',
      15: 'Brute Force',
      18: 'Web Spam',
      19: 'Email Spam',
      20: 'Blog Spam',
      21: 'VPN/Proxy',
      22: 'Exploited Host',
      23: 'Web App Attack',
    };
    return categories[categoryId] ?? 'Malicious Activity';
  }
}
