import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:adrig/config/api_config.dart';

/// AlienVault OTX API Integration - Real-time threat intelligence
/// Community-driven threat data: file hashes, IPs, domains, URLs
class AlienVaultOTXService {
  static const String _baseUrl = 'https://otx.alienvault.com/api/v1';
  
  final String _apiKey;
  final _cache = <String, OTXResult>{};
  
  AlienVaultOTXService({String? apiKey}) 
    : _apiKey = apiKey ?? APIConfig.alienVaultKey;
  
  bool get isConfigured => _apiKey.isNotEmpty;
  
  /// Check file hash against threat intel (REAL-TIME)
  Future<OTXResult?> checkFileHash(String hash) async {
    if (!isConfigured) {
      print('⚠️  AlienVault OTX API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(hash)) {
      return _cache[hash];
    }
    
    try {
      // AlienVault supports MD5, SHA1, SHA256
      final hashType = hash.length == 64 ? 'sha256' : hash.length == 40 ? 'sha1' : 'md5';
      final apiUrl = Uri.parse('$_baseUrl/indicators/file/$hash/general');
      
      final response = await http.get(
        apiUrl,
        headers: {
          'X-OTX-API-KEY': _apiKey,
          'Accept': 'application/json',
        },
      ).timeout(Duration(seconds: 15));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = OTXResult.fromFileJson(data, hash);
        
        _cache[hash] = result;
        
        print('✓ AlienVault OTX Hash: ${result.isMalicious ? "MALICIOUS" : "Clean"} (pulses: ${result.pulseCount})');
        return result;
      } else if (response.statusCode == 404) {
        // Not found - likely clean
        final result = OTXResult.clean(hash);
        _cache[hash] = result;
        return result;
      } else {
        print('⚠️  AlienVault OTX API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ AlienVault OTX hash check error: $e');
      return null;
    }
  }
  
  /// Check IP address against threat intel (REAL-TIME)
  Future<OTXResult?> checkIP(String ipAddress) async {
    if (!isConfigured) {
      print('⚠️  AlienVault OTX API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(ipAddress)) {
      return _cache[ipAddress];
    }
    
    try {
      final apiUrl = Uri.parse('$_baseUrl/indicators/IPv4/$ipAddress/general');
      
      final response = await http.get(
        apiUrl,
        headers: {
          'X-OTX-API-KEY': _apiKey,
          'Accept': 'application/json',
        },
      ).timeout(Duration(seconds: 15));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = OTXResult.fromIpJson(data, ipAddress);
        
        _cache[ipAddress] = result;
        
        print('✓ AlienVault OTX IP: ${result.isMalicious ? "MALICIOUS" : "Clean"} (pulses: ${result.pulseCount})');
        return result;
      } else if (response.statusCode == 404) {
        final result = OTXResult.clean(ipAddress);
        _cache[ipAddress] = result;
        return result;
      } else {
        print('⚠️  AlienVault OTX API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ AlienVault OTX IP check error: $e');
      return null;
    }
  }
  
  /// Check domain against threat intel (REAL-TIME)
  Future<OTXResult?> checkDomain(String domain) async {
    if (!isConfigured) {
      print('⚠️  AlienVault OTX API key not configured');
      return null;
    }
    
    // Check cache
    if (_cache.containsKey(domain)) {
      return _cache[domain];
    }
    
    try {
      final apiUrl = Uri.parse('$_baseUrl/indicators/domain/$domain/general');
      
      final response = await http.get(
        apiUrl,
        headers: {
          'X-OTX-API-KEY': _apiKey,
          'Accept': 'application/json',
        },
      ).timeout(Duration(seconds: 15));
      
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        final result = OTXResult.fromDomainJson(data, domain);
        
        _cache[domain] = result;
        
        print('✓ AlienVault OTX Domain: ${result.isMalicious ? "MALICIOUS" : "Clean"} (pulses: ${result.pulseCount})');
        return result;
      } else if (response.statusCode == 404) {
        final result = OTXResult.clean(domain);
        _cache[domain] = result;
        return result;
      } else {
        print('⚠️  AlienVault OTX API error: ${response.statusCode}');
        return null;
      }
    } catch (e) {
      print('❌ AlienVault OTX domain check error: $e');
      return null;
    }
  }
  
  void clearCache() {
    _cache.clear();
  }
}

/// AlienVault OTX Result
class OTXResult {
  final String indicator;
  final bool isMalicious;
  final int pulseCount; // Number of threat intelligence pulses mentioning this IoC
  final List<String> malwareFamilies;
  final List<String> threatTypes;
  final List<String> tags;
  final String? country;
  final String? asn;
  
  OTXResult({
    required this.indicator,
    required this.isMalicious,
    required this.pulseCount,
    required this.malwareFamilies,
    required this.threatTypes,
    required this.tags,
    this.country,
    this.asn,
  });
  
  factory OTXResult.fromFileJson(Map<String, dynamic> json, String hash) {
    final pulseInfo = json['pulse_info'] ?? {};
    final pulseCount = pulseInfo['count'] ?? 0;
    final pulses = pulseInfo['pulses'] as List<dynamic>? ?? [];
    
    final malwareFamilies = <String>{};
    final threatTypes = <String>{};
    final tags = <String>{};
    
    for (final pulse in pulses) {
      final families = pulse['malware_families'] as List<dynamic>? ?? [];
      malwareFamilies.addAll(families.map((f) => f['display_name'] as String? ?? f.toString()));
      
      final pulseTags = pulse['tags'] as List<dynamic>? ?? [];
      tags.addAll(pulseTags.map((t) => t.toString()));
      
      final adversary = pulse['adversary'] as String?;
      if (adversary != null && adversary.isNotEmpty) {
        threatTypes.add(adversary);
      }
    }
    
    return OTXResult(
      indicator: hash,
      isMalicious: pulseCount > 0,
      pulseCount: pulseCount,
      malwareFamilies: malwareFamilies.toList(),
      threatTypes: threatTypes.toList(),
      tags: tags.toList(),
    );
  }
  
  factory OTXResult.fromIpJson(Map<String, dynamic> json, String ip) {
    final pulseInfo = json['pulse_info'] ?? {};
    final pulseCount = pulseInfo['count'] ?? 0;
    final pulses = pulseInfo['pulses'] as List<dynamic>? ?? [];
    
    final threatTypes = <String>{};
    final tags = <String>{};
    
    for (final pulse in pulses) {
      final pulseTags = pulse['tags'] as List<dynamic>? ?? [];
      tags.addAll(pulseTags.map((t) => t.toString()));
    }
    
    return OTXResult(
      indicator: ip,
      isMalicious: pulseCount > 0,
      pulseCount: pulseCount,
      malwareFamilies: [],
      threatTypes: threatTypes.toList(),
      tags: tags.toList(),
      country: json['country_code'],
      asn: json['asn'],
    );
  }
  
  factory OTXResult.fromDomainJson(Map<String, dynamic> json, String domain) {
    final pulseInfo = json['pulse_info'] ?? {};
    final pulseCount = pulseInfo['count'] ?? 0;
    final pulses = pulseInfo['pulses'] as List<dynamic>? ?? [];
    
    final threatTypes = <String>{};
    final tags = <String>{};
    
    for (final pulse in pulses) {
      final pulseTags = pulse['tags'] as List<dynamic>? ?? [];
      tags.addAll(pulseTags.map((t) => t.toString()));
    }
    
    return OTXResult(
      indicator: domain,
      isMalicious: pulseCount > 0,
      pulseCount: pulseCount,
      malwareFamilies: [],
      threatTypes: threatTypes.toList(),
      tags: tags.toList(),
    );
  }
  
  factory OTXResult.clean(String indicator) {
    return OTXResult(
      indicator: indicator,
      isMalicious: false,
      pulseCount: 0,
      malwareFamilies: [],
      threatTypes: [],
      tags: [],
    );
  }
}
