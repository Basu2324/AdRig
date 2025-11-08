import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Service to persist and retrieve threat detection history
class ThreatHistoryService {
  static const String _historyKey = 'threat_history';
  static const String _categoriesKey = 'threat_categories';
  static const int _maxHistoryDays = 90;

  /// Save scan result to history
  Future<void> saveScanResult(ScanResult result) async {
    final prefs = await SharedPreferences.getInstance();
    
    // Get existing history
    final historyJson = prefs.getString(_historyKey);
    final List<Map<String, dynamic>> history = historyJson != null
        ? List<Map<String, dynamic>>.from(jsonDecode(historyJson))
        : [];
    
    // Add new scan result
    history.add({
      'scanId': result.scanId,
      'timestamp': result.startTime.millisecondsSinceEpoch,
      'totalApps': result.totalApps,
      'threatsFound': result.totalThreatsFound,
      'criticalCount': result.statistics.criticalThreats,
      'highCount': result.statistics.highThreats,
      'mediumCount': result.statistics.mediumThreats,
      'lowCount': result.statistics.lowThreats,
      'threats': result.threats.map((t) => {
        'id': t.id,
        'appName': t.appName,
        'description': t.description,
        'packageName': t.packageName,
        'severity': t.severity.toString(),
        'threatType': t.threatType.toString(),
        'detectionMethod': t.detectionMethod.toString(),
        'confidence': t.confidence,
        'detectedAt': t.detectedAt.millisecondsSinceEpoch,
      }).toList(),
    });
    
    // Clean up old entries (keep only last 90 days)
    final cutoffTime = DateTime.now().subtract(const Duration(days: _maxHistoryDays));
    history.removeWhere((scan) => 
      DateTime.fromMillisecondsSinceEpoch(scan['timestamp'] as int)
          .isBefore(cutoffTime)
    );
    
    // Save back to preferences
    await prefs.setString(_historyKey, jsonEncode(history));
    
    // Update category counts
    await _updateCategoryCounts(history);
  }

  /// Get threat counts by category for last 90 days
  Future<Map<String, int>> getLast90DaysThreats() async {
    final prefs = await SharedPreferences.getInstance();
    final categoriesJson = prefs.getString(_categoriesKey);
    
    if (categoriesJson != null) {
      return Map<String, int>.from(jsonDecode(categoriesJson));
    }
    
    // Return zeros if no data
    return {
      'Apps': 0,
      'Wi-Fi Networks': 0,
      'Internet': 0,
      'Devices': 0,
      'Files': 0,
      'AI Detected': 0,
    };
  }

  /// Update category counts from scan history
  Future<void> _updateCategoryCounts(List<Map<String, dynamic>> history) async {
    final prefs = await SharedPreferences.getInstance();
    
    final categoryCounts = <String, int>{
      'Apps': 0,
      'Wi-Fi Networks': 0,
      'Internet': 0,
      'Devices': 0,
      'Files': 0,
      'AI Detected': 0,
    };
    
    // Count threats by category
    for (final scan in history) {
      final threats = scan['threats'] as List<dynamic>;
      
      for (final threat in threats) {
        final threatType = threat['threatType'] as String;
        final detectionMethod = threat['detectionMethod'] as String;
        
        // Categorize threats - most threats are app-based
        if (threatType.contains('malware') || threatType.contains('trojan') || 
            threatType.contains('spyware') || threatType.contains('adware') ||
            threatType.contains('pua') || threatType.contains('ransomware') ||
            threatType.contains('backdoor') || threatType.contains('dropper')) {
          categoryCounts['Apps'] = (categoryCounts['Apps'] ?? 0) + 1;
        }
        
        // For now, most detections will be app-based since we're scanning APKs
        // Future: Add Wi-Fi, Network, Device, File scanning
        
        // Count AI detections separately
        if (detectionMethod.contains('machinelearning') || 
            detectionMethod.contains('behavioral') ||
            detectionMethod.contains('anomaly')) {
          categoryCounts['AI Detected'] = (categoryCounts['AI Detected'] ?? 0) + 1;
        }
      }
    }
    
    await prefs.setString(_categoriesKey, jsonEncode(categoryCounts));
  }

  /// Get all scan results from history
  Future<List<Map<String, dynamic>>> getAllScanResults() async {
    final prefs = await SharedPreferences.getInstance();
    final historyJson = prefs.getString(_historyKey);
    
    if (historyJson != null) {
      return List<Map<String, dynamic>>.from(jsonDecode(historyJson));
    }
    
    return [];
  }

  /// Get total threats found in last 90 days
  Future<int> getTotalThreatsLast90Days() async {
    final history = await getAllScanResults();
    int total = 0;
    
    for (final scan in history) {
      total += (scan['threatsFound'] as int?) ?? 0;
    }
    
    return total;
  }

  /// Clear all history
  Future<void> clearHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_historyKey);
    await prefs.remove(_categoriesKey);
  }
}
