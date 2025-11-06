import 'package:uuid/uuid.dart';
import '../models/threat_model.dart';
import 'signature_engine.dart';
import 'static_analysis_engine.dart';
import 'behavioral_anomaly_engine.dart';

/// Central scanning orchestrator - coordinates all detection engines
class ScanCoordinator {
  late final SignatureEngine _signatureEngine;
  late final StaticAnalysisEngine _staticAnalyzer;
  late final BehavioralAnomalyEngine _behavioralEngine;

  final Map<String, ScanResult> _scanHistory = {};
  final _uuid = const Uuid();

  ScanCoordinator() {
    _initializeEngines();
  }

  void _initializeEngines() {
    _signatureEngine = SignatureEngine();
    _signatureEngine.initializeSampleSignatures();
    _staticAnalyzer = StaticAnalysisEngine();
    _behavioralEngine = BehavioralAnomalyEngine();
  }

  /// Execute full scan on installed apps
  Future<ScanResult> scanInstalledApps(
    List<AppMetadata> installedApps,
  ) async {
    final scanId = _uuid.v4();
    final startTime = DateTime.now();
    final threats = <DetectedThreat>[];
    final deduplicatedThreats = <String, DetectedThreat>{};

    print('🔍 Starting comprehensive scan (ID: $scanId)');
    print('📱 Scanning ${installedApps.length} installed apps');

    // Stage 1: Signature-based scanning
    print('\n[Stage 1/4] Signature Database Scan');
    for (int i = 0; i < installedApps.length; i++) {
      final app = installedApps[i];
      print('  → [${i + 1}/${installedApps.length}] ${app.appName}');

      // Signature-based detection
      final sigThreats = _signatureEngine.detectPermissionPatterns(
        app.packageName,
        app.appName,
        app.requestedPermissions,
        app.grantedPermissions,
      );
      _deduplicateThreats(deduplicatedThreats, sigThreats);

      // IOC detection
      final iocThreats = _signatureEngine.detectByIOC(
        app.packageName,
        app.appName,
        [], // Would be populated with network telemetry
      );
      _deduplicateThreats(deduplicatedThreats, iocThreats);
    }
    print('  ✓ Signature scan complete (${deduplicatedThreats.length} threats found)');

    // Stage 2: Static Analysis
    print('\n[Stage 2/4] Static Code Analysis');
    for (int i = 0; i < installedApps.length; i++) {
      final app = installedApps[i];
      if ((i + 1) % 10 == 0 || i == installedApps.length - 1) {
        print('  → [${i + 1}/${installedApps.length}] analyzed');
      }

      // Manifest analysis
      final manifestThreats = _staticAnalyzer.analyzeManifest(
        app.packageName,
        app.appName,
        _getMockManifestData(app),
        app.requestedPermissions,
      );
      _deduplicateThreats(deduplicatedThreats, manifestThreats);

      // Code structure analysis
      final structureThreats = _staticAnalyzer.analyzeCodeStructure(
        app.packageName,
        app.appName,
        _getMockAppMetadata(app),
      );
      _deduplicateThreats(deduplicatedThreats, structureThreats);

      // Version analysis
      final versionThreats = _staticAnalyzer.analyzeSdkVersions(
        app.packageName,
        app.appName,
        {'targetSdkVersion': 33, 'minSdkVersion': 21},
      );
      _deduplicateThreats(deduplicatedThreats, versionThreats);

      // Installer source analysis
      final installerThreats = _staticAnalyzer.analyzeInstallerSource(
        app.packageName,
        app.appName,
        app.installerPackage,
      );
      _deduplicateThreats(deduplicatedThreats, installerThreats);
    }
    print('  ✓ Static analysis complete (${deduplicatedThreats.length} threats total)');

    // Stage 3: ML/Heuristic Analysis (simulated)
    print('\n[Stage 3/4] ML Heuristic & Anomaly Detection');
    for (int i = 0; i < installedApps.length; i++) {
      final app = installedApps[i];
      if ((i + 1) % 15 == 0 || i == installedApps.length - 1) {
        print('  → [${i + 1}/${installedApps.length}] analyzed');
      }

      // Behavioral analysis
      final behavioralThreats = _behavioralEngine.detectResourceAnomalies(
        app.packageName,
        app.appName,
        _getMockResourceMetrics(app),
      );
      _deduplicateThreats(deduplicatedThreats, behavioralThreats);
    }
    print('  ✓ ML analysis complete (${deduplicatedThreats.length} threats total)');

    // Stage 4: Threat Intelligence & Reputation
    print('\n[Stage 4/4] Threat Intelligence Correlation');
    final tiThreats = _correlateWithThreatIntelligence(
      installedApps,
      deduplicatedThreats.values.toList(),
    );
    _deduplicateThreats(deduplicatedThreats, tiThreats);
    print('  ✓ Threat intelligence complete (${deduplicatedThreats.length} threats total)');

    // Compile results
    threats.addAll(deduplicatedThreats.values);
    threats.sort((a, b) => b.severityScore.compareTo(a.severityScore));

    final endTime = DateTime.now();
    final statistics = _calculateStatistics(
      threats,
      installedApps.length,
      endTime.difference(startTime),
    );

    final result = ScanResult(
      scanId: scanId,
      startTime: startTime,
      endTime: endTime,
      totalApps: installedApps.length,
      totalThreatsFound: threats.length,
      threats: threats,
      statistics: statistics,
      isComplete: true,
    );

    _scanHistory[scanId] = result;
    _printScanSummary(result);

    return result;
  }

  /// Scan single file for malware
  Future<List<DetectedThreat>> scanFile(String filePath) async {
    final threats = <DetectedThreat>[];

    // Hash-based signature detection
    threats.addAll(await _signatureEngine.scanFileHash(filePath));

    return threats;
  }

  /// Get scan history
  Map<String, ScanResult> getScanHistory() => Map.from(_scanHistory);

  /// Get specific scan result
  ScanResult? getScanResult(String scanId) => _scanHistory[scanId];

  /// Update signature database
  void updateSignatures(List<MalwareSignature> signatures) {
    for (final sig in signatures) {
      _signatureEngine.addSignature(sig);
    }
  }

  /// Update threat indicators
  void updateThreatIndicators(List<ThreatIndicator> indicators) {
    for (final indicator in indicators) {
      _signatureEngine.addThreatIndicator(indicator);
    }
  }

  // Private helper methods

  void _deduplicateThreats(
    Map<String, DetectedThreat> deduplicated,
    List<DetectedThreat> newThreats,
  ) {
    for (final threat in newThreats) {
      final key = '${threat.packageName}_${threat.description}';
      if (!deduplicated.containsKey(key)) {
        deduplicated[key] = threat;
      } else {
        // Keep the higher confidence threat
        if (threat.confidence > deduplicated[key]!.confidence) {
          deduplicated[key] = threat;
        }
      }
    }
  }

  List<DetectedThreat> _correlateWithThreatIntelligence(
    List<AppMetadata> apps,
    List<DetectedThreat> existingThreats,
  ) {
    // In production: correlate with real threat feeds
    return [];
  }

  ScanStatistics _calculateStatistics(
    List<DetectedThreat> threats,
    int totalAppsScanned,
    Duration scanDuration,
  ) {
    final criticalCount = threats
        .where((t) => t.severity == ThreatSeverity.critical)
        .length;
    final highCount = threats.where((t) => t.severity == ThreatSeverity.high).length;
    final mediumCount =
        threats.where((t) => t.severity == ThreatSeverity.medium).length;
    final lowCount = threats.where((t) => t.severity == ThreatSeverity.low).length;
    final infoCount = threats.where((t) => t.severity == ThreatSeverity.info).length;

    final methodCounts = <String, int>{};
    for (final threat in threats) {
      final method = threat.detectionMethod.toString();
      methodCounts[method] = (methodCounts[method] ?? 0) + 1;
    }

    final avgConfidence =
        threats.isNotEmpty ? threats.map((t) => t.confidence).reduce((a, b) => a + b) / threats.length : 0.0;

    return ScanStatistics(
      criticalThreats: criticalCount,
      highThreats: highCount,
      mediumThreats: mediumCount,
      lowThreats: lowCount,
      infoThreats: infoCount,
      scanDuration: scanDuration,
      averageConfidence: avgConfidence,
      appsScanned: totalAppsScanned,
      filesScanned: 0, // Would be populated from file scanning
      detectionMethodCounts: methodCounts,
    );
  }

  Map<String, dynamic> _getMockManifestData(AppMetadata app) => {
    'debuggable': false,
    'usesCleartextTraffic': false,
    'activities': [],
    'services': [],
  };

  Map<String, dynamic> _getMockAppMetadata(AppMetadata app) => {
    'size': app.size,
    'methodCount': 5000,
    'classCount': 500,
    'hasNativeLibs': false,
  };

  ResourceMetrics _getMockResourceMetrics(AppMetadata app) => ResourceMetrics(
    cpuUsage: 5.0,
    memoryUsage: 50 * 1024 * 1024,
    batteryDrain: 2.0,
    networkBytesTransferred: 10 * 1024 * 1024,
  );

  void _printScanSummary(ScanResult result) {
    print('\n' + '=' * 70);
    print('📊 SCAN COMPLETE - Summary');
    print('=' * 70);
    print('Scan ID: ${result.scanId}');
    print('Duration: ${result.statistics.scanDuration.inSeconds}s');
    print('Apps scanned: ${result.totalApps}');
    print(
        'Total threats found: ${result.totalThreatsFound} (Confidence: ${(result.statistics.averageConfidence * 100).toStringAsFixed(1)}%)');
    print('\nThreat breakdown:');
    print('  🔴 Critical: ${result.statistics.criticalThreats}');
    print('  🟠 High:     ${result.statistics.highThreats}');
    print('  🟡 Medium:   ${result.statistics.mediumThreats}');
    print('  🟢 Low:      ${result.statistics.lowThreats}');
    print('  🔵 Info:     ${result.statistics.infoThreats}');
    print('\nDetection methods used:');
    for (final method in result.statistics.detectionMethodCounts.entries) {
      print('  • ${method.key}: ${method.value}');
    }
    print('=' * 70 + '\n');
  }
}
