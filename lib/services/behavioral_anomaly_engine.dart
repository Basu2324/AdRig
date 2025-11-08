import 'package:adrig/core/models/threat_model.dart';
import 'package:flutter/services.dart';
import 'dart:convert';

/// Real-time behavioral anomaly detection using native monitors
class BehavioralAnomalyEngine {
  static const platform = MethodChannel('com.autoguard.malware_scanner/security');
  
  final Map<String, BehaviorProfile> _knownBehaviors = {};
  final Map<String, List<BehavioralAnomaly>> _detectedAnomalies = {};

  BehavioralAnomalyEngine() {
    _initializeKnownBehaviors();
  }

  /// Analyze app using native network and process monitors
  Future<List<DetectedThreat>> analyzeRuntimeBehavior(
    String packageName,
    String appName,
  ) async {
    final threats = <DetectedThreat>[];
    
    try {
      // Get network threats from NetworkMonitor.kt
      final networkThreats = await _getNetworkThreats(packageName);
      threats.addAll(_parseNetworkThreats(networkThreats, appName));
      
      // Get process anomalies from ProcessMonitor.kt
      final processAnomalies = await _getProcessAnomalies(packageName);
      threats.addAll(_parseProcessAnomalies(processAnomalies, appName));
      
    } catch (e) {
      print('[BehavioralEngine] Error analyzing runtime: $e');
    }
    
    return threats;
  }
  
  /// Get network threats from native monitor
  Future<List<dynamic>> _getNetworkThreats(String packageName) async {
    try {
      final result = await platform.invokeMethod('getNetworkThreats', {
        'packageName': packageName,
      });
      return result != null ? List<dynamic>.from(result) : [];
    } catch (e) {
      print('[BehavioralEngine] Failed to get network threats: $e');
      return [];
    }
  }
  
  /// Get process anomalies from native monitor
  Future<List<dynamic>> _getProcessAnomalies(String packageName) async {
    try {
      final result = await platform.invokeMethod('getProcessAnomalies', {
        'packageName': packageName,
      });
      return result != null ? List<dynamic>.from(result) : [];
    } catch (e) {
      print('[BehavioralEngine] Failed to get process anomalies: $e');
      return [];
    }
  }
  
  /// Parse network threats from native data
  List<DetectedThreat> _parseNetworkThreats(List<dynamic> networkData, String appName) {
    final threats = <DetectedThreat>[];
    
    for (var threat in networkData) {
      final type = threat['type']?.toString() ?? '';
      final severity = _mapSeverity(threat['severity']?.toString() ?? 'MEDIUM');
      
      threats.add(DetectedThreat(
        id: 'net_${DateTime.now().millisecondsSinceEpoch}_${threats.length}',
        packageName: threat['packageName']?.toString() ?? '',
        appName: appName,
        threatType: _mapNetworkThreatType(type),
        severity: severity,
        detectionMethod: DetectionMethod.behavioral,
        description: threat['description']?.toString() ?? 'Network anomaly detected',
        indicators: [threat['destination']?.toString() ?? ''],
        confidence: 0.85,
        detectedAt: DateTime.now(),
        recommendedAction: severity == ThreatSeverity.critical 
          ? ActionType.autoblock 
          : ActionType.quarantine,
        metadata: {
          'threat_type': type,
          'destination': threat['destination']?.toString() ?? '',
          'detection_source': 'NetworkMonitor',
        },
      ));
    }
    
    return threats;
  }
  
  /// Parse process anomalies from native data
  List<DetectedThreat> _parseProcessAnomalies(List<dynamic> anomalyData, String appName) {
    final threats = <DetectedThreat>[];
    
    for (var anomaly in anomalyData) {
      final type = anomaly['type']?.toString() ?? '';
      final severity = _mapSeverity(anomaly['severity']?.toString() ?? 'MEDIUM');
      
      threats.add(DetectedThreat(
        id: 'proc_${DateTime.now().millisecondsSinceEpoch}_${threats.length}',
        packageName: anomaly['packageName']?.toString() ?? '',
        appName: appName,
        threatType: _mapProcessThreatType(type),
        severity: severity,
        detectionMethod: DetectionMethod.behavioral,
        description: anomaly['description']?.toString() ?? 'Process anomaly detected',
        indicators: [type],
        confidence: 0.80,
        detectedAt: DateTime.now(),
        recommendedAction: severity == ThreatSeverity.critical 
          ? ActionType.autoblock 
          : ActionType.monitor,
        metadata: {
          'anomaly_type': type,
          'pid': anomaly['pid']?.toString() ?? '0',
          'detection_source': 'ProcessMonitor',
        },
      ));
    }
    
    return threats;
  }
  
  /// Map network threat type string to ThreatType enum
  ThreatType _mapNetworkThreatType(String type) {
    switch (type) {
      case 'C2_COMMUNICATION':
        return ThreatType.trojan;
      case 'DATA_EXFILTRATION':
        return ThreatType.spyware;
      case 'MALICIOUS_IP':
        return ThreatType.trojan;
      case 'TOR_USAGE':
        return ThreatType.pua;
      case 'CRYPTO_MINING':
        return ThreatType.cryptominer;
      default:
        return ThreatType.pua;
    }
  }
  
  /// Map process threat type string to ThreatType enum
  ThreatType _mapProcessThreatType(String type) {
    switch (type) {
      case 'ROOT_DETECTION':
        return ThreatType.rootkit;
      case 'PRIVILEGE_ESCALATION':
        return ThreatType.trojan;
      case 'CODE_INJECTION':
        return ThreatType.trojan;
      case 'CHILD_PROCESS_SPAWN':
        return ThreatType.dropper;
      case 'DEBUGGER_EVASION':
        return ThreatType.trojan;
      default:
        return ThreatType.pua;
    }
  }
  
  /// Map severity string to ThreatSeverity enum
  ThreatSeverity _mapSeverity(String severity) {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return ThreatSeverity.critical;
      case 'HIGH':
        return ThreatSeverity.high;
      case 'MEDIUM':
        return ThreatSeverity.medium;
      case 'LOW':
        return ThreatSeverity.low;
      default:
        return ThreatSeverity.info;
    }
  }

  /// Detect network beaconing (C2 communication)
  List<DetectedThreat> detectNetworkBeaconing(
    String packageName,
    String appName,
    List<NetworkConnection> connections,
  ) {
    final threats = <DetectedThreat>[];

    // Analyze for C2 patterns
    final beaconPattern = _analyzeBeaconPatterns(connections);
    if (beaconPattern.isAnomalous) {
      threats.add(
        DetectedThreat(
          id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
          packageName: packageName,
          appName: appName,
          threatType: ThreatType.trojan,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.behavioral,
          description: beaconPattern.description,
          indicators: beaconPattern.indicators,
          confidence: 0.85,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.autoblock,
          metadata: {
            'pattern': 'network_beaconing',
            'connection_count': connections.length,
            'beacon_frequency': beaconPattern.frequency,
          },
        ),
      );
    }

    return threats;
  }

  /// Detect suspicious process behavior
  List<DetectedThreat> detectProcessAnomalies(
    String packageName,
    String appName,
    List<ProcessBehavior> behaviors,
  ) {
    final threats = <DetectedThreat>[];

    // Check for privilege escalation attempts
    final privEsc = _detectPrivilegeEscalation(behaviors);
    if (privEsc != null) {
      threats.add(privEsc);
    }

    // Check for injection attacks
    final injection = _detectCodeInjection(behaviors);
    if (injection != null) {
      threats.add(injection);
    }

    // Check for process spawning (malware dropper pattern)
    final spawning = _detectProcessSpawning(packageName, appName, behaviors);
    if (spawning.isNotEmpty) {
      threats.addAll(spawning);
    }

    return threats;
  }

  /// Detect resource consumption anomalies
  List<DetectedThreat> detectResourceAnomalies(
    String packageName,
    String appName,
    ResourceMetrics metrics,
  ) {
    final threats = <DetectedThreat>[];

    // Excessive CPU (cryptomining, computation)
    if (metrics.cpuUsage > 80) {
      threats.add(_createResourceThreat(
        packageName,
        appName,
        'Excessive CPU consumption - possible cryptomining or intensive computation',
        ThreatType.pua,
        ThreatSeverity.medium,
      ));
    }

    // Memory leak or excessive memory
    if (metrics.memoryUsage > 500 * 1024 * 1024) {
      // > 500MB
      threats.add(_createResourceThreat(
        packageName,
        appName,
        'Excessive memory usage - possible memory leak or data exfiltration buffer',
        ThreatType.malware,
        ThreatSeverity.medium,
      ));
    }

    // Excessive battery drain
    if (metrics.batteryDrain > 30) {
      threats.add(_createResourceThreat(
        packageName,
        appName,
        'Abnormal battery drain - suspicious background activity',
        ThreatType.adware,
        ThreatSeverity.low,
      ));
    }

    // Excessive network I/O
    if (metrics.networkBytesTransferred > 1024 * 1024 * 1024) {
      // > 1GB
      threats.add(_createResourceThreat(
        packageName,
        appName,
        'Excessive network data transfer - possible data exfiltration',
        ThreatType.spyware,
        ThreatSeverity.high,
      ));
    }

    return threats;
  }

  /// Detect permission usage anomalies (using declared permissions)
  List<DetectedThreat> detectPermissionUsageAnomalies(
    String packageName,
    String appName,
    List<PermissionUsage> usages,
  ) {
    final threats = <DetectedThreat>[];

    // Camera/mic use without user notification
    for (final usage in usages) {
      if ((usage.permission == 'android.permission.CAMERA' ||
              usage.permission == 'android.permission.RECORD_AUDIO') &&
          usage.accessCount > 100 &&
          !usage.isUserNotified) {
        threats.add(
          DetectedThreat(
            id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
            packageName: packageName,
            appName: appName,
            threatType: ThreatType.spyware,
            severity: ThreatSeverity.critical,
            detectionMethod: DetectionMethod.behavioral,
            description:
                'Frequent ${usage.permission} access without user notification',
            indicators: [usage.permission],
            confidence: 0.90,
            detectedAt: DateTime.now(),
            recommendedAction: ActionType.autoblock,
          ),
        );
      }

      // Location access at unusual times/frequency
      if (usage.permission == 'android.permission.ACCESS_FINE_LOCATION' &&
          usage.accessCount > 50 &&
          _isUnusualAccessPattern(usage)) {
        threats.add(
          DetectedThreat(
            id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
            packageName: packageName,
            appName: appName,
            threatType: ThreatType.spyware,
            severity: ThreatSeverity.high,
            detectionMethod: DetectionMethod.behavioral,
            description: 'Unusual location access pattern detected',
            indicators: ['android.permission.ACCESS_FINE_LOCATION'],
            confidence: 0.80,
            detectedAt: DateTime.now(),
            recommendedAction: ActionType.alert,
          ),
        );
      }
    }

    return threats;
  }

  /// Detect file system access anomalies
  List<DetectedThreat> detectFileSystemAnomalies(
    String packageName,
    String appName,
    List<FileAccess> accesses,
  ) {
    final threats = <DetectedThreat>[];

    const sensitiveDirectories = [
      '/data/data/',
      '/data/user/',
      '/storage/emulated/0/Android/data/',
    ];

    for (final access in accesses) {
      // Access to sensitive system directories
      if (sensitiveDirectories
          .any((dir) => access.path.startsWith(dir)) &&
          access.path != '/data/data/$packageName/') {
        threats.add(
          DetectedThreat(
            id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
            packageName: packageName,
            appName: appName,
            threatType: ThreatType.malware,
            severity: ThreatSeverity.high,
            detectionMethod: DetectionMethod.behavioral,
            description:
                'Unauthorized access to sensitive directory: ${access.path}',
            indicators: [access.path],
            confidence: 0.85,
            detectedAt: DateTime.now(),
            recommendedAction: ActionType.quarantine,
          ),
        );
      }

      // Excessive file operations (ransomware)
      if (access.operationType == 'write' && access.operationCount > 10000) {
        threats.add(
          DetectedThreat(
            id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
            packageName: packageName,
            appName: appName,
            threatType: ThreatType.ransomware,
            severity: ThreatSeverity.critical,
            detectionMethod: DetectionMethod.behavioral,
            description:
                'Massive file write operations - ransomware-like behavior',
            indicators: [access.path],
            confidence: 0.80,
            detectedAt: DateTime.now(),
            recommendedAction: ActionType.quarantine,
          ),
        );
      }
    }

    return threats;
  }

  // Private helper methods

  void _initializeKnownBehaviors() {
    // Normal browser behavior
    _knownBehaviors['browser'] = BehaviorProfile(
      name: 'Browser',
      expectedNetworkConnections: ['http', 'https'],
      expectedFileAccess: ['/storage/emulated/0/Download/'],
      expectedPermissions: [
        'android.permission.INTERNET',
        'android.permission.ACCESS_NETWORK_STATE',
      ],
    );

    // Normal camera app behavior
    _knownBehaviors['camera'] = BehaviorProfile(
      name: 'Camera',
      expectedNetworkConnections: [],
      expectedFileAccess: ['/storage/emulated/0/DCIM/', '/storage/emulated/0/Pictures/'],
      expectedPermissions: [
        'android.permission.CAMERA',
        'android.permission.WRITE_EXTERNAL_STORAGE',
      ],
    );
  }

  BeaconPattern _analyzeBeaconPatterns(List<NetworkConnection> connections) {
    if (connections.isEmpty) {
      return BeaconPattern(
        isAnomalous: false,
        description: 'No suspicious beaconing detected',
        indicators: [],
        frequency: 0,
      );
    }

    // Group connections by destination
    final destinationFreq = <String, int>{};
    for (final conn in connections) {
      destinationFreq[conn.destination] =
          (destinationFreq[conn.destination] ?? 0) + 1;
    }

    // Check for regular intervals to same destination (C2 beaconing)
    for (final dest in destinationFreq.keys) {
      if (destinationFreq[dest]! > 10) {
        // Repeated connections to same server
        return BeaconPattern(
          isAnomalous: true,
          description:
              'Suspicious beaconing pattern to $dest (${destinationFreq[dest]} connections)',
          indicators: [dest],
          frequency: destinationFreq[dest]!,
        );
      }
    }

    return BeaconPattern(
      isAnomalous: false,
      description: 'Normal network patterns',
      indicators: [],
      frequency: 0,
    );
  }

  DetectedThreat? _detectPrivilegeEscalation(
    List<ProcessBehavior> behaviors,
  ) {
    for (final behavior in behaviors) {
      if (behavior.action.contains('escalate_privilege') ||
          behavior.action.contains('su') ||
          behavior.action.contains('sudo')) {
        return DetectedThreat(
          id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'unknown',
          appName: 'unknown',
          threatType: ThreatType.trojan,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.behavioral,
          description: 'Privilege escalation attempt detected: ${behavior.action}',
          indicators: [behavior.action],
          confidence: 0.95,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.quarantine,
        );
      }
    }
    return null;
  }

  DetectedThreat? _detectCodeInjection(
    List<ProcessBehavior> behaviors,
  ) {
    for (final behavior in behaviors) {
      if (behavior.action.contains('ptrace') ||
          behavior.action.contains('inject') ||
          behavior.action.contains('dlopen')) {
        return DetectedThreat(
          id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'unknown',
          appName: 'unknown',
          threatType: ThreatType.trojan,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.behavioral,
          description: 'Code injection attempt detected: ${behavior.action}',
          indicators: [behavior.action],
          confidence: 0.90,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.quarantine,
        );
      }
    }
    return null;
  }

  List<DetectedThreat> _detectProcessSpawning(
    String packageName,
    String appName,
    List<ProcessBehavior> behaviors,
  ) {
    final threats = <DetectedThreat>[];
    int spawnCount = 0;

    for (final behavior in behaviors) {
      if (behavior.action.contains('spawn') ||
          behavior.action.contains('fork') ||
          behavior.action.contains('exec')) {
        spawnCount++;
      }
    }

    if (spawnCount > 5) {
      threats.add(DetectedThreat(
        id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.dropper,
        severity: ThreatSeverity.high,
        detectionMethod: DetectionMethod.behavioral,
        description: 'Multiple process spawning detected ($spawnCount processes)',
        indicators: ['process_spawning'],
        confidence: 0.80,
        detectedAt: DateTime.now(),
        recommendedAction: ActionType.quarantine,
      ));
    }

    return threats;
  }

  bool _isUnusualAccessPattern(PermissionUsage usage) {
    // Check if access pattern is outside normal hours or too frequent
    final now = DateTime.now();
    return usage.lastAccessTime != null &&
        now.difference(usage.lastAccessTime!).inMinutes < 5 &&
        (now.hour < 6 || now.hour > 23);
  }

  DetectedThreat _createResourceThreat(
    String packageName,
    String appName,
    String description,
    ThreatType threatType,
    ThreatSeverity severity,
  ) {
    return DetectedThreat(
      id: 'threat_${DateTime.now().millisecondsSinceEpoch}',
      packageName: packageName,
      appName: appName,
      threatType: threatType,
      severity: severity,
      detectionMethod: DetectionMethod.behavioral,
      description: description,
      indicators: [],
      confidence: 0.70,
      detectedAt: DateTime.now(),
      recommendedAction: ActionType.alert,
      metadata: {'detection_type': 'resource_anomaly'},
    );
  }
}

// Supporting data classes for behavioral analysis

class NetworkConnection {
  final String source;
  final String destination;
  final int port;
  final String protocol;
  final DateTime timestamp;

  NetworkConnection({
    required this.source,
    required this.destination,
    required this.port,
    required this.protocol,
    required this.timestamp,
  });
}

class ProcessBehavior {
  final String pid;
  final String process;
  final String action;
  final DateTime timestamp;

  ProcessBehavior({
    required this.pid,
    required this.process,
    required this.action,
    required this.timestamp,
  });
}

class PermissionUsage {
  final String permission;
  final int accessCount;
  final bool isUserNotified;
  final DateTime? lastAccessTime;

  PermissionUsage({
    required this.permission,
    required this.accessCount,
    required this.isUserNotified,
    this.lastAccessTime,
  });
}

class FileAccess {
  final String path;
  final String operationType; // read, write, delete
  final int operationCount;
  final DateTime timestamp;

  FileAccess({
    required this.path,
    required this.operationType,
    required this.operationCount,
    required this.timestamp,
  });
}

class BehaviorProfile {
  final String name;
  final List<String> expectedNetworkConnections;
  final List<String> expectedFileAccess;
  final List<String> expectedPermissions;

  BehaviorProfile({
    required this.name,
    required this.expectedNetworkConnections,
    required this.expectedFileAccess,
    required this.expectedPermissions,
  });
}

class BeaconPattern {
  final bool isAnomalous;
  final String description;
  final List<String> indicators;
  final int frequency;

  BeaconPattern({
    required this.isAnomalous,
    required this.description,
    required this.indicators,
    required this.frequency,
  });
}
