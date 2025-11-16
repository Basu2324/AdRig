import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:adrig/config/api_config.dart';

/// IPQualityScore API Integration - Real-time URL/IP fraud & malware detection
/// Detects phishing, malware URLs, suspicious IPs, proxy/VPN usage
class IPQualityScoreService {
  static const String _baseUrl = 'https://ipqualityscore.com/api/json';
  
  final String _apiKey;
  final _cache = <String, IPQSResult>{};
  
  IPQualityScoreService({String? apiKey}) 
    : _apiKey = apiKey ?? APIConfig.ipQualityScoreKey;
  
  bool get isConfigured => _apiKey.isNotEmpty;
  
  /// Check URL for malware/phishing (REAL-TIME)
  Future<IPQSResult?> checkURL(String url) async {
    if (!isConfigured) {
      print('⚠️  IPQualityScore API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(url)) {
      return _cache[url];
    }
    
    try {
      final encodedUrl = Uri.encodeComponent(url);
      final apiUrl = Uri.parse('$_baseUrl/url/$_apiKey/$encodedUrl');
      
      final response = await http.get(apiUrl).timeout(Duration(seconds: 5));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = IPQSResult.fromUrlJson(data);
        
        _cache[url] = result;
        
        print('✓ IPQualityScore URL: ${result.isMalicious ? "MALICIOUS" : "Clean"} (risk: ${result.riskScore})');
        return result;
      } else {
        print('⚠️  IPQualityScore API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ IPQualityScore URL check error: $e');
      return null;
    }
  }
  
  /// Check IP address for fraud/malicious activity (REAL-TIME)
  Future<IPQSResult?> checkIP(String ipAddress) async {
    if (!isConfigured) {
      print('⚠️  IPQualityScore API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(ipAddress)) {
      return _cache[ipAddress];
    }
    
    try {
      final apiUrl = Uri.parse('$_baseUrl/ip/$_apiKey/$ipAddress');
      
      final response = await http.get(apiUrl).timeout(Duration(seconds: 5));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = IPQSResult.fromIpJson(data);
        
        _cache[ipAddress] = result;
        
        print('✓ IPQualityScore IP: ${result.isMalicious ? "MALICIOUS" : "Clean"} (fraud score: ${result.fraudScore})');
        return result;
      } else {
        print('⚠️  IPQualityScore API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ IPQualityScore IP check error: $e');
      return null;
    }
  }
  
  void clearCache() {
    _cache.clear();
  }
}

/// IPQualityScore API Result
class IPQSResult {
  final bool isMalicious;
  final int riskScore; // 0-100
  final int fraudScore; // 0-100
  final bool isPhishing;
  final bool isMalware;
  final bool isSuspicious;
  final bool isProxy;
  final bool isVpn;
  final bool isTor;
  final String category;
  final List<String> threatTypes;
  
  IPQSResult({
    required this.isMalicious,
    required this.riskScore,
    required this.fraudScore,
    required this.isPhishing,
    required this.isMalware,
    required this.isSuspicious,
    required this.isProxy,
    required this.isVpn,
    required this.isTor,
    required this.category,
    required this.threatTypes,
  });
  
  factory IPQSResult.fromUrlJson(Map<String, dynamic> json) {
    final riskScore = json['risk_score'] ?? 0;
    final isPhishing = json['phishing'] ?? false;
    final isMalware = json['malware'] ?? false;
    final isSuspicious = json['suspicious'] ?? false;
    
    final threats = <String>[];
    if (isPhishing) threats.add('Phishing');
    if (isMalware) threats.add('Malware');
    if (isSuspicious) threats.add('Suspicious');
    if (json['adult'] == true) threats.add('Adult Content');
    
    return IPQSResult(
      isMalicious: isPhishing || isMalware || riskScore >= 85,
      riskScore: riskScore,
      fraudScore: 0,
      isPhishing: isPhishing,
      isMalware: isMalware,
      isSuspicious: isSuspicious,
      isProxy: false,
      isVpn: false,
      isTor: false,
      category: json['category'] ?? 'Unknown',
      threatTypes: threats,
    );
  }
  
  factory IPQSResult.fromIpJson(Map<String, dynamic> json) {
    final fraudScore = json['fraud_score'] ?? 0;
    final isProxy = json['proxy'] ?? false;
    final isVpn = json['vpn'] ?? false;
    final isTor = json['tor'] ?? false;
    final isBot = json['bot_status'] ?? false;
    
    final threats = <String>[];
    if (isBot) threats.add('Bot/Scanner');
    if (isProxy) threats.add('Proxy');
    if (isVpn) threats.add('VPN');
    if (isTor) threats.add('Tor Exit Node');
    if (json['recent_abuse'] == true) threats.add('Recent Abuse');
    
    return IPQSResult(
      isMalicious: fraudScore >= 85 || (json['recent_abuse'] == true),
      riskScore: fraudScore,
      fraudScore: fraudScore,
      isPhishing: false,
      isMalware: false,
      isSuspicious: fraudScore >= 75,
      isProxy: isProxy,
      isVpn: isVpn,
      isTor: isTor,
      category: json['ISP'] ?? 'Unknown',
      threatTypes: threats,
    );
  }
}
