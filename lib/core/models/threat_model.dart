enum ThreatSeverity { critical, high, medium, low, info }

enum ThreatType {
  malware,
  pua,
  adware,
  spyware,
  trojan,
  ransomware,
  dropper,
  backdoor,
  exploit,
  anomaly,
}

enum DetectionMethod {
  signature,
  behavioral,
  heuristic,
  machinelearning,
  threatintel,
  anomaly,
  yara,
  staticanalysis,
}

enum ActionType {
  quarantine,
  alert,
  autoblock,
  removalrequest,
  monitoronly,
}

/// Core threat detection result
class DetectedThreat {
  final String id;
  final String packageName;
  final String appName;
  final ThreatType threatType;
  final ThreatSeverity severity;
  final DetectionMethod detectionMethod;
  final String description;
  final List<String> indicators;
  final double confidence;
  final DateTime detectedAt;
  final String? hash;
  final String? version;
  final ActionType recommendedAction;
  final Map<String, dynamic> metadata;

  DetectedThreat({
    required this.id,
    required this.packageName,
    required this.appName,
    required this.threatType,
    required this.severity,
    required this.detectionMethod,
    required this.description,
    required this.indicators,
    required this.confidence,
    required this.detectedAt,
    this.hash,
    this.version,
    required this.recommendedAction,
    this.metadata = const {},
  });

  int get severityScore => {
    ThreatSeverity.critical: 5,
    ThreatSeverity.high: 4,
    ThreatSeverity.medium: 3,
    ThreatSeverity.low: 2,
    ThreatSeverity.info: 1,
  }[severity] ?? 0;
}

/// Scan result with aggregated findings
class ScanResult {
  final String scanId;
  final DateTime startTime;
  final DateTime? endTime;
  final int totalApps;
  final int totalThreatsFound;
  final List<DetectedThreat> threats;
  final ScanStatistics statistics;
  final bool isComplete;

  ScanResult({
    required this.scanId,
    required this.startTime,
    this.endTime,
    required this.totalApps,
    required this.totalThreatsFound,
    required this.threats,
    required this.statistics,
    required this.isComplete,
  });
}

/// Scan statistics
class ScanStatistics {
  final int criticalThreats;
  final int highThreats;
  final int mediumThreats;
  final int lowThreats;
  final int infoThreats;
  final Duration scanDuration;
  final double averageConfidence;
  final int appsScanned;
  final int filesScanned;
  final Map<String, int> detectionMethodCounts;

  ScanStatistics({
    required this.criticalThreats,
    required this.highThreats,
    required this.mediumThreats,
    required this.lowThreats,
    required this.infoThreats,
    required this.scanDuration,
    required this.averageConfidence,
    required this.appsScanned,
    required this.filesScanned,
    required this.detectionMethodCounts,
  });

  int get totalThreats =>
      criticalThreats + highThreats + mediumThreats + lowThreats + infoThreats;
}

/// App metadata for scanning
class AppMetadata {
  final String packageName;
  final String appName;
  final String version;
  final String? hash;
  final int installTime;
  final int lastUpdateTime;
  final bool isSystemApp;
  final String installerPackage;
  final int size;
  final List<String> requestedPermissions;
  final List<String> grantedPermissions;
  final String? certificate;

  AppMetadata({
    required this.packageName,
    required this.appName,
    required this.version,
    this.hash,
    required this.installTime,
    required this.lastUpdateTime,
    required this.isSystemApp,
    required this.installerPackage,
    required this.size,
    required this.requestedPermissions,
    required this.grantedPermissions,
    this.certificate,
  });
}

/// Behavioral anomaly detection result
class BehavioralAnomaly {
  final String id;
  final String description;
  final double anomalyScore;
  final List<String> triggeredRules;
  final Map<String, dynamic> context;

  BehavioralAnomaly({
    required this.id,
    required this.description,
    required this.anomalyScore,
    required this.triggeredRules,
    required this.context,
  });
}

/// Network behavior indicator
class NetworkIndicator {
  final String id;
  final String domain;
  final int port;
  final String protocol;
  final String appPackage;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final int requestCount;
  final bool isBlocked;
  final String? reputationScore;

  NetworkIndicator({
    required this.id,
    required this.domain,
    required this.port,
    required this.protocol,
    required this.appPackage,
    required this.firstSeen,
    required this.lastSeen,
    required this.requestCount,
    required this.isBlocked,
    this.reputationScore,
  });
}

/// Signature database entry
class MalwareSignature {
  final String id;
  final String hash;
  final String hashType;
  final String malwareName;
  final String? family;
  final ThreatType threatType;
  final ThreatSeverity severity;
  final DateTime? discoveredDate;
  final List<String>? indicators;
  final Map<String, dynamic>? metadata;

  MalwareSignature({
    required this.id,
    required this.hash,
    required this.hashType,
    required this.malwareName,
    this.family,
    required this.threatType,
    required this.severity,
    this.discoveredDate,
    this.indicators,
    this.metadata,
  });
}

/// YARA-style rule for pattern matching
class DetectionRule {
  final String id;
  final String name;
  final String pattern;
  final String ruleType;
  final ThreatType threatType;
  final ThreatSeverity severity;
  final bool enabled;
  final DateTime lastUpdated;
  final String? description;

  DetectionRule({
    required this.id,
    required this.name,
    required this.pattern,
    required this.ruleType,
    required this.threatType,
    required this.severity,
    required this.enabled,
    required this.lastUpdated,
    this.description,
  });
}

/// Threat Intelligence Indicator
class ThreatIndicator {
  final String id;
  final String indicator;
  final String indicatorType;
  final String source;
  final ThreatSeverity severity;
  final DateTime lastSeen;
  final int confidence;
  final Map<String, dynamic>? details;

  ThreatIndicator({
    required this.id,
    required this.indicator,
    required this.indicatorType,
    required this.source,
    required this.severity,
    required this.lastSeen,
    required this.confidence,
    this.details,
  });
}
