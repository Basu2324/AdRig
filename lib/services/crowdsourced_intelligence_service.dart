import 'dart:convert';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Crowdsourced Threat Intelligence Service
/// Collects, aggregates, and correlates threat data across user base
class CrowdsourcedIntelligenceService {
  final FirebaseFirestore _firestore = FirebaseFirestore.instance;
  
  // Collection references
  late final CollectionReference _globalThreatsRef;
  late final CollectionReference _communityReportsRef;
  late final CollectionReference _deviceTelemetryRef;
  late final CollectionReference _threatCorrelationsRef;
  
  /// Initialize crowdsourced intelligence system
  Future<void> initialize() async {
    print('🌐 Initializing Crowdsourced Intelligence Service...');
    
    _globalThreatsRef = _firestore.collection('global_threats');
    _communityReportsRef = _firestore.collection('community_reports');
    _deviceTelemetryRef = _firestore.collection('device_telemetry');
    _threatCorrelationsRef = _firestore.collection('threat_correlations');
    
    print('✅ Crowdsourced Intelligence initialized');
  }
  
  /// Submit threat detection to global database (privacy-preserving)
  Future<void> submitThreatReport({
    required String packageName,
    required String fileHash,
    required ThreatSeverity severity,
    required List<String> detectionEngines,
    required Map<String, dynamic> indicators,
    String? deviceId, // Anonymous device ID
  }) async {
    try {
      // Privacy-preserving submission (no PII)
      final report = {
        'package_name': packageName,
        'file_hash': fileHash,
        'severity': severity.name,
        'detection_engines': detectionEngines,
        'indicators': indicators,
        'device_id_hash': deviceId != null ? _hashDeviceId(deviceId) : null,
        'timestamp': FieldValue.serverTimestamp(),
        'version': 1,
      };
      
      // Add to community reports
      await _communityReportsRef.add(report);
      
      // Update global threat database
      await _updateGlobalThreatDatabase(packageName, fileHash, severity);
      
      print('✅ Threat report submitted: $packageName');
    } catch (e) {
      print('⚠️ Failed to submit threat report: $e');
    }
  }
  
  /// Query global threat reputation
  Future<GlobalThreatReputation> queryGlobalReputation(String fileHash) async {
    try {
      // Query all reports for this hash
      final snapshot = await _communityReportsRef
          .where('file_hash', isEqualTo: fileHash)
          .orderBy('timestamp', descending: true)
          .limit(100)
          .get();
      
      if (snapshot.docs.isEmpty) {
        return GlobalThreatReputation(
          fileHash: fileHash,
          isThreat: false,
          reportCount: 0,
          confidence: 0.0,
          firstSeen: null,
          lastSeen: null,
          severityBreakdown: {},
          detectionEngines: [],
        );
      }
      
      // Aggregate reports
      final reports = snapshot.docs.map((doc) => doc.data() as Map<String, dynamic>).toList();
      final reportCount = reports.length;
      
      final severityCounts = <String, int>{};
      final allEngines = <String>{};
      
      DateTime? firstSeen;
      DateTime? lastSeen;
      
      for (final report in reports) {
        final severity = report['severity'] as String;
        severityCounts[severity] = (severityCounts[severity] ?? 0) + 1;
        
        final engines = (report['detection_engines'] as List).cast<String>();
        allEngines.addAll(engines);
        
        final timestamp = (report['timestamp'] as Timestamp?)?.toDate();
        if (timestamp != null) {
          if (firstSeen == null || timestamp.isBefore(firstSeen)) {
            firstSeen = timestamp;
          }
          if (lastSeen == null || timestamp.isAfter(lastSeen)) {
            lastSeen = timestamp;
          }
        }
      }
      
      // Calculate confidence based on report count and agreement
      final dominantSeverity = severityCounts.entries.reduce((a, b) => a.value > b.value ? a : b).key;
      final agreement = severityCounts[dominantSeverity]! / reportCount;
      final confidence = _calculateConfidence(reportCount, agreement);
      
      final isThreat = reportCount >= 3 && (dominantSeverity == 'high' || dominantSeverity == 'critical');
      
      return GlobalThreatReputation(
        fileHash: fileHash,
        isThreat: isThreat,
        reportCount: reportCount,
        confidence: confidence,
        firstSeen: firstSeen,
        lastSeen: lastSeen,
        severityBreakdown: severityCounts,
        detectionEngines: allEngines.toList(),
      );
    } catch (e) {
      print('⚠️ Failed to query global reputation: $e');
      return GlobalThreatReputation(
        fileHash: fileHash,
        isThreat: false,
        reportCount: 0,
        confidence: 0.0,
        firstSeen: null,
        lastSeen: null,
        severityBreakdown: {},
        detectionEngines: [],
      );
    }
  }
  
  /// Correlate threat patterns across devices
  Future<List<ThreatCorrelation>> correlateThreatPatterns() async {
    try {
      // Query recent threat correlations
      final snapshot = await _threatCorrelationsRef
          .orderBy('detection_count', descending: true)
          .limit(50)
          .get();
      
      final correlations = <ThreatCorrelation>[];
      
      for (final doc in snapshot.docs) {
        final data = doc.data() as Map<String, dynamic>;
        correlations.add(ThreatCorrelation(
          pattern: data['pattern'] as String,
          detectionCount: data['detection_count'] as int,
          affectedDevices: data['affected_devices'] as int,
          commonIndicators: (data['common_indicators'] as List).cast<String>(),
          firstDetected: (data['first_detected'] as Timestamp).toDate(),
          lastDetected: (data['last_detected'] as Timestamp).toDate(),
        ));
      }
      
      return correlations;
    } catch (e) {
      print('⚠️ Failed to correlate threat patterns: $e');
      return [];
    }
  }
  
  /// Submit device telemetry (privacy-preserving, aggregated data only)
  Future<void> submitDeviceTelemetry({
    required String deviceIdHash,
    required int totalScans,
    required int threatsDetected,
    required Map<String, int> detectionEngineStats,
    required List<String> topThreats, // Package names only
  }) async {
    try {
      final telemetry = {
        'device_id_hash': deviceIdHash,
        'total_scans': totalScans,
        'threats_detected': threatsDetected,
        'detection_engine_stats': detectionEngineStats,
        'top_threats': topThreats,
        'timestamp': FieldValue.serverTimestamp(),
      };
      
      await _deviceTelemetryRef.doc(deviceIdHash).set(
        telemetry,
        SetOptions(merge: true),
      );
      
      print('✅ Device telemetry submitted');
    } catch (e) {
      print('⚠️ Failed to submit telemetry: $e');
    }
  }
  
  /// Get global threat statistics
  Future<GlobalThreatStats> getGlobalStats() async {
    try {
      final snapshot = await _globalThreatsRef
          .orderBy('detection_count', descending: true)
          .limit(100)
          .get();
      
      var totalThreats = 0;
      var totalDetections = 0;
      final topThreats = <String, int>{};
      
      for (final doc in snapshot.docs) {
        final data = doc.data() as Map<String, dynamic>;
        final count = data['detection_count'] as int;
        
        totalThreats++;
        totalDetections += count;
        
        final packageName = data['package_name'] as String;
        topThreats[packageName] = count;
      }
      
      // Get active devices count
      final devicesSnapshot = await _deviceTelemetryRef
          .where('timestamp', isGreaterThan: Timestamp.fromDate(
            DateTime.now().subtract(const Duration(days: 7)),
          ))
          .count()
          .get();
      
      final activeDevices = devicesSnapshot.count ?? 0;
      
      return GlobalThreatStats(
        totalThreatsTracked: totalThreats,
        totalDetections: totalDetections,
        activeDevices: activeDevices,
        topThreats: topThreats,
      );
    } catch (e) {
      print('⚠️ Failed to get global stats: $e');
      return GlobalThreatStats(
        totalThreatsTracked: 0,
        totalDetections: 0,
        activeDevices: 0,
        topThreats: {},
      );
    }
  }
  
  /// Get emerging threats (newly detected in past 24 hours)
  Future<List<EmergingThreat>> getEmergingThreats() async {
    try {
      final yesterday = DateTime.now().subtract(const Duration(hours: 24));
      
      final snapshot = await _globalThreatsRef
          .where('first_seen', isGreaterThan: Timestamp.fromDate(yesterday))
          .orderBy('first_seen', descending: true)
          .orderBy('detection_count', descending: true)
          .limit(20)
          .get();
      
      final threats = <EmergingThreat>[];
      
      for (final doc in snapshot.docs) {
        final data = doc.data() as Map<String, dynamic>;
        threats.add(EmergingThreat(
          packageName: data['package_name'] as String,
          fileHash: data['file_hash'] as String,
          detectionCount: data['detection_count'] as int,
          severity: ThreatSeverity.values.firstWhere(
            (s) => s.name == data['severity'],
            orElse: () => ThreatSeverity.medium,
          ),
          firstSeen: (data['first_seen'] as Timestamp).toDate(),
          primaryIndicators: (data['indicators'] as List?)?.cast<String>() ?? [],
        ));
      }
      
      return threats;
    } catch (e) {
      print('⚠️ Failed to get emerging threats: $e');
      return [];
    }
  }
  
  /// Check if package is whitelisted by community
  Future<bool> isCommunityWhitelisted(String packageName) async {
    try {
      final doc = await _globalThreatsRef.doc(packageName).get();
      
      if (!doc.exists) return false;
      
      final data = doc.data() as Map<String, dynamic>;
      return data['whitelisted'] == true;
    } catch (e) {
      return false;
    }
  }
  
  // ==================== HELPER METHODS ====================
  
  Future<void> _updateGlobalThreatDatabase(
    String packageName,
    String fileHash,
    ThreatSeverity severity,
  ) async {
    final docRef = _globalThreatsRef.doc(fileHash);
    
    await _firestore.runTransaction((transaction) async {
      final doc = await transaction.get(docRef);
      
      if (doc.exists) {
        // Update existing threat
        transaction.update(docRef, {
          'detection_count': FieldValue.increment(1),
          'last_seen': FieldValue.serverTimestamp(),
        });
      } else {
        // Create new threat entry
        transaction.set(docRef, {
          'package_name': packageName,
          'file_hash': fileHash,
          'severity': severity.name,
          'detection_count': 1,
          'first_seen': FieldValue.serverTimestamp(),
          'last_seen': FieldValue.serverTimestamp(),
        });
      }
    });
  }
  
  String _hashDeviceId(String deviceId) {
    // Simple hash for privacy (use crypto hash in production)
    return deviceId.hashCode.toRadixString(36);
  }
  
  double _calculateConfidence(int reportCount, double agreement) {
    // Confidence increases with report count and agreement
    final countFactor = (reportCount / 10.0).clamp(0.0, 1.0);
    final agreementFactor = agreement;
    
    return (countFactor * 0.4 + agreementFactor * 0.6).clamp(0.0, 1.0);
  }
}

// ==================== DATA CLASSES ====================

class GlobalThreatReputation {
  final String fileHash;
  final bool isThreat;
  final int reportCount;
  final double confidence;
  final DateTime? firstSeen;
  final DateTime? lastSeen;
  final Map<String, int> severityBreakdown;
  final List<String> detectionEngines;
  
  GlobalThreatReputation({
    required this.fileHash,
    required this.isThreat,
    required this.reportCount,
    required this.confidence,
    required this.firstSeen,
    required this.lastSeen,
    required this.severityBreakdown,
    required this.detectionEngines,
  });
}

class ThreatCorrelation {
  final String pattern;
  final int detectionCount;
  final int affectedDevices;
  final List<String> commonIndicators;
  final DateTime firstDetected;
  final DateTime lastDetected;
  
  ThreatCorrelation({
    required this.pattern,
    required this.detectionCount,
    required this.affectedDevices,
    required this.commonIndicators,
    required this.firstDetected,
    required this.lastDetected,
  });
}

class GlobalThreatStats {
  final int totalThreatsTracked;
  final int totalDetections;
  final int activeDevices;
  final Map<String, int> topThreats;
  
  GlobalThreatStats({
    required this.totalThreatsTracked,
    required this.totalDetections,
    required this.activeDevices,
    required this.topThreats,
  });
}

class EmergingThreat {
  final String packageName;
  final String fileHash;
  final int detectionCount;
  final ThreatSeverity severity;
  final DateTime firstSeen;
  final List<String> primaryIndicators;
  
  EmergingThreat({
    required this.packageName,
    required this.fileHash,
    required this.detectionCount,
    required this.severity,
    required this.firstSeen,
    required this.primaryIndicators,
  });
}
