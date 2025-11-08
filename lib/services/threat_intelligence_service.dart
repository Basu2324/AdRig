import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:adrig/core/models/threat_model.dart';

/// Threat intelligence correlation service
/// Integrates with threat feeds, reputation APIs, and IoC databases
class ThreatIntelligenceService {
  final Map<String, ThreatReputation> _reputationCache = {};
  final Map<String, ThreatIndicator> _iocDatabase = {};
  final List<String> _threatFeeds = [];
  
  DateTime? _lastUpdate;
  bool _isInitialized = false;

  /// Initialize threat intelligence feeds
  Future<void> initialize() async {
    try {
      // In production: connect to real threat intel APIs
      // - VirusTotal API
      // - AbuseIPDB
      // - URLhaus
      // - MalwareBazaar
      // - Custom threat feeds
      
      _threatFeeds.addAll([
        'virustotal',
        'abuseipdb',
        'urlhaus',
        'malwarebazaar',
      ]);

      // Load initial IoC database
      await _loadIoCDatabase();
      
      _isInitialized = true;
      _lastUpdate = DateTime.now();
      print('✓ Threat intelligence initialized with ${_iocDatabase.length} IoCs');
    } catch (e) {
      print('Error initializing threat intelligence: $e');
    }
  }

  /// Check app reputation using multiple sources
  Future<ThreatReputation> checkAppReputation(
    String packageName,
    String? hash,
  ) async {
    // Check cache first
    if (_reputationCache.containsKey(packageName)) {
      final cached = _reputationCache[packageName]!;
      if (DateTime.now().difference(cached.lastChecked).inHours < 24) {
        return cached;
      }
    }

    // Query reputation APIs (simulated)
    final reputation = await _queryReputationAPIs(packageName, hash);
    _reputationCache[packageName] = reputation;
    
    return reputation;
  }

  /// Correlate detected threats with threat intelligence
  Future<List<DetectedThreat>> correlateWithThreatIntel(
    List<DetectedThreat> threats,
    List<AppMetadata> apps,
  ) async {
    final correlatedThreats = <DetectedThreat>[];

    for (final threat in threats) {
      // Check if threat matches known IoCs
      final matchingIoCs = _findMatchingIoCs(threat);
      
      if (matchingIoCs.isNotEmpty) {
        // Enhance threat with IoC data
        correlatedThreats.add(DetectedThreat(
          id: '${threat.id}_correlated',
          packageName: threat.packageName,
          appName: threat.appName,
          threatType: threat.threatType,
          severity: _enhanceSeverity(threat.severity, matchingIoCs),
          detectionMethod: DetectionMethod.threatintel,
          description: '${threat.description} - Confirmed by threat intelligence',
          indicators: [...threat.indicators, ...matchingIoCs.map((i) => i.indicator)],
          confidence: (threat.confidence + 0.15).clamp(0.0, 0.99),
          detectedAt: DateTime.now(),
          hash: threat.hash,
          version: threat.version,
          recommendedAction: threat.recommendedAction,
          metadata: {
            ...threat.metadata,
            'threat_intel_sources': matchingIoCs.map((i) => i.source).toSet().toList(),
            'ioc_matches': matchingIoCs.length,
          },
        ));
      }
    }

    // Check apps not yet flagged
    for (final app in apps) {
      if (!threats.any((t) => t.packageName == app.packageName)) {
        final reputation = await checkAppReputation(app.packageName, app.hash);
        
        if (reputation.reputationScore < 0.3) {
          correlatedThreats.add(DetectedThreat(
            id: 'threat_ti_${DateTime.now().millisecondsSinceEpoch}',
            packageName: app.packageName,
            appName: app.appName,
            threatType: ThreatType.malware,
            severity: _reputationToSeverity(reputation.reputationScore),
            detectionMethod: DetectionMethod.threatintel,
            description: 'Low reputation score from threat intelligence: ${reputation.verdict}',
            indicators: ['Negative reports: ${reputation.negativeReports}'],
            confidence: 0.80,
            detectedAt: DateTime.now(),
            hash: app.hash,
            version: app.version,
            recommendedAction: ActionType.alert,
            metadata: {
              'reputation_score': reputation.reputationScore,
              'reputation_source': reputation.source,
              'negative_reports': reputation.negativeReports,
            },
          ));
        }
      }
    }

    return correlatedThreats;
  }

  /// Check domain against threat feeds
  Future<bool> isDomainMalicious(String domain) async {
    // Check IoC database
    for (final ioc in _iocDatabase.values) {
      if (ioc.indicatorType == 'domain' && ioc.indicator == domain) {
        return true;
      }
    }

    // In production: query real-time threat feeds
    // - URLhaus API
    // - PhishTank
    // - Google Safe Browsing
    
    return false;
  }

  /// Check IP against threat feeds
  Future<bool> isIpMalicious(String ip) async {
    // Check IoC database
    for (final ioc in _iocDatabase.values) {
      if (ioc.indicatorType == 'ip' && ioc.indicator == ip) {
        return true;
      }
    }

    // In production: query AbuseIPDB, etc.
    return false;
  }

  /// Check file hash against threat databases
  Future<bool> isHashMalicious(String hash) async {
    // Check IoC database
    for (final ioc in _iocDatabase.values) {
      if (ioc.indicatorType == 'hash' && ioc.indicator == hash) {
        return true;
      }
    }

    // In production: query VirusTotal, MalwareBazaar
    return false;
  }

  /// Update threat intelligence feeds
  Future<void> updateThreatFeeds() async {
    try {
      print('🔄 Updating threat intelligence feeds...');
      
      // In production: download latest IoCs from threat feeds
      await _loadIoCDatabase();
      
      _lastUpdate = DateTime.now();
      print('✓ Threat intelligence updated (${_iocDatabase.length} IoCs)');
    } catch (e) {
      print('Error updating threat feeds: $e');
    }
  }

  /// Load IoC database
  Future<void> _loadIoCDatabase() async {
    // Simulated IoC data (in production: load from API/database)
    _iocDatabase.addAll({
      'ioc_001': ThreatIndicator(
        id: 'ioc_001',
        indicator: 'malicious.c2server.com',
        indicatorType: 'domain',
        source: 'urlhaus',
        severity: ThreatSeverity.critical,
        lastSeen: DateTime.now(),
        confidence: 95,
        details: {'threat_type': 'c2_server'},
      ),
      'ioc_002': ThreatIndicator(
        id: 'ioc_002',
        indicator: '192.0.2.100',
        indicatorType: 'ip',
        source: 'abuseipdb',
        severity: ThreatSeverity.high,
        lastSeen: DateTime.now(),
        confidence: 90,
        details: {'threat_type': 'botnet'},
      ),
      'ioc_003': ThreatIndicator(
        id: 'ioc_003',
        indicator: '5d41402abc4b2a76b9719d911017c592',
        indicatorType: 'hash',
        source: 'virustotal',
        severity: ThreatSeverity.critical,
        lastSeen: DateTime.now(),
        confidence: 98,
        details: {'malware_family': 'trojan.generic'},
      ),
    });
  }

  /// Query reputation APIs (simulated)
  Future<ThreatReputation> _queryReputationAPIs(
    String packageName,
    String? hash,
  ) async {
    // In production: query real APIs
    // - VirusTotal
    // - Google Play Store ratings/reviews
    // - Community threat reports
    
    // Simulated reputation
    final isSuspicious = packageName.contains('fake') || 
                         packageName.contains('malware');
    
    return ThreatReputation(
      packageName: packageName,
      reputationScore: isSuspicious ? 0.25 : 0.85,
      source: 'threat_intelligence',
      positiveReports: isSuspicious ? 5 : 100,
      negativeReports: isSuspicious ? 45 : 2,
      lastChecked: DateTime.now(),
      verdict: isSuspicious ? 'Potentially Malicious' : 'Clean',
    );
  }

  /// Find matching IoCs for a threat
  List<ThreatIndicator> _findMatchingIoCs(DetectedThreat threat) {
    final matches = <ThreatIndicator>[];

    for (final ioc in _iocDatabase.values) {
      // Match by hash
      if (ioc.indicatorType == 'hash' && ioc.indicator == threat.hash) {
        matches.add(ioc);
      }
      
      // Match by indicators
      for (final indicator in threat.indicators) {
        if (indicator.contains(ioc.indicator)) {
          matches.add(ioc);
        }
      }
    }

    return matches;
  }

  /// Enhance severity based on IoC matches
  ThreatSeverity _enhanceSeverity(
    ThreatSeverity current,
    List<ThreatIndicator> iocs,
  ) {
    if (iocs.any((i) => i.severity == ThreatSeverity.critical)) {
      return ThreatSeverity.critical;
    }
    return current;
  }

  /// Convert reputation score to severity
  ThreatSeverity _reputationToSeverity(double score) {
    if (score < 0.2) return ThreatSeverity.critical;
    if (score < 0.4) return ThreatSeverity.high;
    if (score < 0.6) return ThreatSeverity.medium;
    return ThreatSeverity.low;
  }

  /// Get IoC count
  int getIoCCount() => _iocDatabase.length;

  /// Get last update time
  DateTime? getLastUpdate() => _lastUpdate;

  /// Check if initialized
  bool isInitialized() => _isInitialized;
}
