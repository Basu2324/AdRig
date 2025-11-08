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
  suspicious,
  rootkit,
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
  final bool isSystemApp;

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
    this.isSystemApp = false,
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

/// Signature database entry with multi-hash support
class MalwareSignature {
  final String id;
  final String hash;  // Legacy field (primary hash)
  final String hashType;  // Legacy field
  final String? sha256;  // SHA-256 hash
  final String? md5;     // MD5 hash
  final String? sha1;    // SHA-1 hash
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
    this.sha256,
    this.md5,
    this.sha1,
    required this.malwareName,
    this.family,
    required this.threatType,
    required this.severity,
    this.discoveredDate,
    this.indicators,
    this.metadata,
  });
  
  /// Get the primary hash value (prefers SHA256 > SHA1 > MD5 > legacy hash)
  String get primaryHash {
    if (sha256 != null && sha256!.isNotEmpty) return sha256!;
    if (sha1 != null && sha1!.isNotEmpty) return sha1!;
    if (md5 != null && md5!.isNotEmpty) return md5!;
    return hash;
  }
  
  /// Check if any hash matches the given value
  bool matchesHash(String hashValue) {
    return sha256 == hashValue || 
           md5 == hashValue || 
           sha1 == hashValue || 
           hash == hashValue;
  }
  
  Map<String, dynamic> toJson() => {
    'id': id,
    'hash': hash,
    'hashType': hashType,
    'sha256': sha256,
    'md5': md5,
    'sha1': sha1,
    'malwareName': malwareName,
    'family': family,
    'threatType': threatType.toString(),
    'severity': severity.toString(),
    'discoveredDate': discoveredDate?.toIso8601String(),
    'indicators': indicators,
    'metadata': metadata,
  };
  
  factory MalwareSignature.fromJson(Map<String, dynamic> json) => MalwareSignature(
    id: json['id']?.toString() ?? '',
    hash: json['hash']?.toString() ?? json['sha256']?.toString() ?? '',
    hashType: json['hashType']?.toString() ?? 'sha256',
    sha256: json['sha256']?.toString(),
    md5: json['md5']?.toString(),
    sha1: json['sha1']?.toString(),
    malwareName: json['malwareName']?.toString() ?? 'Unknown',
    family: json['family']?.toString(),
    threatType: ThreatType.values.firstWhere(
      (t) => t.toString() == json['threatType']?.toString(),
      orElse: () => ThreatType.suspicious,
    ),
    severity: ThreatSeverity.values.firstWhere(
      (s) => s.toString() == json['severity']?.toString(),
      orElse: () => ThreatSeverity.medium,
    ),
    discoveredDate: json['discoveredDate'] != null
        ? DateTime.tryParse(json['discoveredDate'].toString())
        : null,
    indicators: json['indicators'] != null 
        ? (json['indicators'] as List).map((e) => e.toString()).toList()
        : null,
    metadata: json['metadata'] as Map<String, dynamic>?,
  );
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

/// Network connection record
class NetworkConnection {
  final String id;
  final String packageName;
  final String destinationIp;
  final String? destinationDomain;
  final int destinationPort;
  final String protocol;
  final DateTime timestamp;
  final int bytesTransferred;
  final bool isEncrypted;
  final String? connectionType;

  NetworkConnection({
    required this.id,
    required this.packageName,
    required this.destinationIp,
    this.destinationDomain,
    required this.destinationPort,
    required this.protocol,
    required this.timestamp,
    required this.bytesTransferred,
    required this.isEncrypted,
    this.connectionType,
  });
}

/// Process behavior record
class ProcessBehavior {
  final String id;
  final String packageName;
  final int pid;
  final String processName;
  final List<String> systemCalls;
  final List<String> fileAccesses;
  final List<String> networkConnections;
  final DateTime timestamp;
  final Map<String, dynamic> metadata;

  ProcessBehavior({
    required this.id,
    required this.packageName,
    required this.pid,
    required this.processName,
    required this.systemCalls,
    required this.fileAccesses,
    required this.networkConnections,
    required this.timestamp,
    this.metadata = const {},
  });
}

/// Resource usage metrics
class ResourceMetrics {
  final String packageName;
  final double cpuUsage;
  final int memoryUsage;
  final double batteryDrain;
  final int networkBytesTransferred;
  final DateTime timestamp;

  ResourceMetrics({
    required this.packageName,
    required this.cpuUsage,
    required this.memoryUsage,
    required this.batteryDrain,
    required this.networkBytesTransferred,
    required this.timestamp,
  });
}

/// Permission usage tracking
class PermissionUsage {
  final String packageName;
  final String permission;
  final int accessCount;
  final DateTime lastAccessed;
  final bool isUserNotified;
  final String? accessContext;

  PermissionUsage({
    required this.packageName,
    required this.permission,
    required this.accessCount,
    required this.lastAccessed,
    required this.isUserNotified,
    this.accessContext,
  });
}

/// Beacon pattern analysis result
class BeaconPattern {
  final bool isAnomalous;
  final String description;
  final List<String> indicators;
  final double frequency;
  final String? c2Server;

  BeaconPattern({
    required this.isAnomalous,
    required this.description,
    required this.indicators,
    required this.frequency,
    this.c2Server,
  });
}

/// Behavior profile for anomaly detection
class BehaviorProfile {
  final String packageName;
  final Map<String, double> normalCpuUsage;
  final Map<String, double> normalMemoryUsage;
  final Map<String, int> normalNetworkActivity;
  final List<String> normalPermissions;
  final DateTime profileCreated;
  final DateTime lastUpdated;

  BehaviorProfile({
    required this.packageName,
    required this.normalCpuUsage,
    required this.normalMemoryUsage,
    required this.normalNetworkActivity,
    required this.normalPermissions,
    required this.profileCreated,
    required this.lastUpdated,
  });
}

/// ML Model metadata
class MLModelMetadata {
  final String id;
  final String name;
  final String version;
  final String modelPath;
  final String modelType;
  final DateTime lastUpdated;
  final int modelSize;
  final double accuracy;
  final Map<String, dynamic> configuration;

  MLModelMetadata({
    required this.id,
    required this.name,
    required this.version,
    required this.modelPath,
    required this.modelType,
    required this.lastUpdated,
    required this.modelSize,
    required this.accuracy,
    this.configuration = const {},
  });
}

/// Update package metadata
class UpdatePackage {
  final String id;
  final String type;
  final String version;
  final int size;
  final String checksum;
  final DateTime releaseDate;
  final String downloadUrl;
  final bool isDelta;
  final String? baseVersion;
  final Map<String, dynamic> metadata;

  UpdatePackage({
    required this.id,
    required this.type,
    required this.version,
    required this.size,
    required this.checksum,
    required this.releaseDate,
    required this.downloadUrl,
    required this.isDelta,
    this.baseVersion,
    this.metadata = const {},
  });
}

/// Quarantine entry
class QuarantineEntry {
  final String id;
  final String packageName;
  final String appName;
  final String reason;
  final DateTime quarantinedAt;
  final String filePath;
  final String originalHash;
  final List<DetectedThreat> threats;
  final bool canRestore;

  QuarantineEntry({
    required this.id,
    required this.packageName,
    required this.appName,
    required this.reason,
    required this.quarantinedAt,
    required this.filePath,
    required this.originalHash,
    required this.threats,
    required this.canRestore,
  });
}

/// Privacy consent record
class PrivacyConsent {
  final String userId;
  final bool cloudScanningEnabled;
  final bool threatIntelSharingEnabled;
  final bool anonymousTelemetryEnabled;
  final bool autoUpdateEnabled;
  final DateTime consentDate;
  final DateTime? lastModified;

  PrivacyConsent({
    required this.userId,
    required this.cloudScanningEnabled,
    required this.threatIntelSharingEnabled,
    required this.anonymousTelemetryEnabled,
    required this.autoUpdateEnabled,
    required this.consentDate,
    this.lastModified,
  });
}

/// Threat reputation score
class ThreatReputation {
  final String packageName;
  final double reputationScore;
  final String source;
  final int positiveReports;
  final int negativeReports;
  final DateTime lastChecked;
  final String? verdict;

  ThreatReputation({
    required this.packageName,
    required this.reputationScore,
    required this.source,
    required this.positiveReports,
    required this.negativeReports,
    required this.lastChecked,
    this.verdict,
  });
}

// ============================================================================
// PHASE 2: Device & App Telemetry Models
// ============================================================================

/// Comprehensive app telemetry data
class AppTelemetry {
  final String packageName;
  final String appName;
  final String version;
  final String? installer;
  final String? signingCertFingerprint;
  final AppManifestData manifest;
  final APKHash hashes;
  final List<String> declaredPermissions;
  final List<String> runtimeGrantedPermissions;
  final DateTime installedDate;
  final DateTime lastUpdated;
  final int appSize;
  final String apkPath;
  final bool isSystemApp;

  AppTelemetry({
    required this.packageName,
    required this.appName,
    required this.version,
    this.installer,
    this.signingCertFingerprint,
    required this.manifest,
    required this.hashes,
    required this.declaredPermissions,
    required this.runtimeGrantedPermissions,
    required this.installedDate,
    required this.lastUpdated,
    required this.appSize,
    required this.apkPath,
    this.isSystemApp = false,
  });
}

/// APK file hashes (MD5, SHA1, SHA256)
class APKHash {
  final String md5;
  final String sha1;
  final String sha256;

  APKHash({
    required this.md5,
    required this.sha1,
    required this.sha256,
  });
}

/// App manifest parsed data
class AppManifestData {
  final String packageName;
  final String minSdkVersion;
  final String targetSdkVersion;
  final List<String> activities;
  final List<String> services;
  final List<String> receivers;
  final List<String> providers;
  final List<String> usesPermissions;
  final Map<String, String> metadata;

  AppManifestData({
    required this.packageName,
    required this.minSdkVersion,
    required this.targetSdkVersion,
    required this.activities,
    required this.services,
    required this.receivers,
    required this.providers,
    required this.usesPermissions,
    required this.metadata,
  });
}

/// File system entry telemetry
class FileSystemEntry {
  final String path;
  final String filename;
  final int size;
  final String mimeType;
  final APKHash? hash;
  final DateTime created;
  final DateTime modified;
  final String mountPoint;
  final bool isExecutable;
  final bool isSuspicious;

  FileSystemEntry({
    required this.path,
    required this.filename,
    required this.size,
    required this.mimeType,
    this.hash,
    required this.created,
    required this.modified,
    required this.mountPoint,
    required this.isExecutable,
    required this.isSuspicious,
  });
}

/// Running process information
class ProcessInfo {
  final int pid;
  final String processName;
  final String packageName;
  final List<NativeLibrary> loadedLibraries;
  final List<NetworkSocket> openSockets;
  final List<IPCEndpoint> ipcEndpoints;
  final int memoryUsage;
  final double cpuUsage;
  final DateTime startTime;

  ProcessInfo({
    required this.pid,
    required this.processName,
    required this.packageName,
    required this.loadedLibraries,
    required this.openSockets,
    required this.ipcEndpoints,
    required this.memoryUsage,
    required this.cpuUsage,
    required this.startTime,
  });
}

/// Native library (.so) information
class NativeLibrary {
  final String name;
  final String path;
  final String hash;
  final bool isSuspicious;

  NativeLibrary({
    required this.name,
    required this.path,
    required this.hash,
    required this.isSuspicious,
  });
}

/// Network socket information
class NetworkSocket {
  final String protocol;
  final String localAddress;
  final int localPort;
  final String? remoteAddress;
  final int? remotePort;
  final String state;

  NetworkSocket({
    required this.protocol,
    required this.localAddress,
    required this.localPort,
    this.remoteAddress,
    this.remotePort,
    required this.state,
  });
}

/// IPC endpoint information
class IPCEndpoint {
  final String type;
  final String name;
  final String packageName;
  final bool isExported;

  IPCEndpoint({
    required this.type,
    required this.name,
    required this.packageName,
    required this.isExported,
  });
}

/// Permission usage analysis
class PermissionAnalysis {
  final String packageName;
  final String permission;
  final int accessCount;
  final DateTime lastAccess;
  final bool isSuspicious;
  final String suspicionReason;

  PermissionAnalysis({
    required this.packageName,
    required this.permission,
    required this.accessCount,
    required this.lastAccess,
    required this.isSuspicious,
    required this.suspicionReason,
  });
}

/// Root/jailbreak detection indicators
class RootIndicator {
  final String type;
  final String path;
  final String description;
  final ThreatSeverity severity;
  final DateTime detected;

  RootIndicator({
    required this.type,
    required this.path,
    required this.description,
    required this.severity,
    required this.detected,
  });
}

/// Play Protect verdict
class PlayProtectVerdict {
  final String packageName;
  final String verdict;
  final String? category;
  final DateTime checkedAt;
  final Map<String, dynamic> integrityData;

  PlayProtectVerdict({
    required this.packageName,
    required this.verdict,
    this.category,
    required this.checkedAt,
    required this.integrityData,
  });
}
