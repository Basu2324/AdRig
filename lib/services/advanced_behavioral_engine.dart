import 'dart:collection';
import 'dart:convert';
import 'dart:math' as math;
import 'package:adrig/core/models/threat_model.dart';

/// Advanced Behavioral Detection Engine
/// Real-time monitoring of API calls, permissions, network activity, file operations
/// Pattern matching against known malware behavior signatures
/// Anomaly detection for zero-day threats
class AdvancedBehavioralEngine {
  // Behavioral signature database
  final Map<String, BehavioralSignature> _signatureDB = {};
  
  // Runtime behavior monitoring
  final List<BehaviorEvent> _eventLog = [];
  final Queue<APICallEvent> _apiCallSequence = Queue();
  
  // Behavior analysis state
  final Map<String, BehaviorState> _behaviorStates = {};
  
  // Detection thresholds
  static const int MAX_API_SEQUENCE_LENGTH = 1000;
  static const int BEHAVIOR_WINDOW_SECONDS = 300; // 5 minutes
  static const double ANOMALY_THRESHOLD = 0.75;
  static const double MALICIOUS_BEHAVIOR_THRESHOLD = 0.70;

  /// Initialize behavioral engine with signatures
  Future<void> initialize() async {
    print('🧠 Initializing Advanced Behavioral Detection Engine...');
    
    await _loadBehavioralSignatures();
    _initializeMonitoring();
    
    print('✅ Behavioral Engine initialized');
    print('📊 Loaded ${_signatureDB.length} behavioral signatures');
  }

  /// Load behavioral signatures from database
  Future<void> _loadBehavioralSignatures() async {
    // ========== BANKING TROJAN BEHAVIORS ==========
    
    _signatureDB['banking_overlay_attack'] = BehavioralSignature(
      id: 'banking_overlay_attack',
      name: 'Banking App Overlay Attack',
      category: 'credential_theft',
      severity: ThreatSeverity.critical,
      description: 'Detects overlay attacks targeting banking applications',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'WindowManager.addView',
            'PackageManager.getInstalledApplications',
            'UsageStatsManager.queryUsageStats',
            'EditText.getText',
          ],
          confidence: 0.95,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['SYSTEM_ALERT_WINDOW', 'PACKAGE_USAGE_STATS'],
          confidence: 0.90,
        ),
        BehaviorIndicator(
          type: IndicatorType.targetApp,
          pattern: ['com.chase.mobile', 'com.bankofamerica', 'com.paypal', 'com.venmo'],
          confidence: 0.85,
        ),
      ],
      minConfidence: 0.85,
    );

    _signatureDB['sms_interception'] = BehavioralSignature(
      id: 'sms_interception',
      name: 'SMS Interception & Exfiltration',
      category: 'data_exfiltration',
      severity: ThreatSeverity.high,
      description: 'Intercepts SMS messages and sends to remote server',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'BroadcastReceiver.onReceive',
            'SmsMessage.getMessageBody',
            'HttpURLConnection.connect',
            'OutputStream.write',
          ],
          confidence: 0.92,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['RECEIVE_SMS', 'READ_SMS', 'INTERNET'],
          confidence: 0.88,
        ),
      ],
      minConfidence: 0.80,
    );

    // ========== SPYWARE BEHAVIORS ==========
    
    _signatureDB['call_recording'] = BehavioralSignature(
      id: 'call_recording',
      name: 'Phone Call Recording',
      category: 'surveillance',
      severity: ThreatSeverity.high,
      description: 'Records phone calls without user consent',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'TelephonyManager.listen',
            'MediaRecorder.start',
            'File.createNewFile',
            'FileOutputStream.write',
          ],
          confidence: 0.90,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['READ_PHONE_STATE', 'RECORD_AUDIO', 'WRITE_EXTERNAL_STORAGE'],
          confidence: 0.85,
        ),
      ],
      minConfidence: 0.80,
    );

    _signatureDB['location_stalking'] = BehavioralSignature(
      id: 'location_stalking',
      name: 'Continuous Location Tracking',
      category: 'stalkerware',
      severity: ThreatSeverity.high,
      description: 'Continuously tracks user location and sends to remote server',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'LocationManager.requestLocationUpdates',
            'Location.getLatitude',
            'Location.getLongitude',
            'HttpClient.post',
          ],
          confidence: 0.88,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['ACCESS_FINE_LOCATION', 'INTERNET'],
          confidence: 0.82,
        ),
        BehaviorIndicator(
          type: IndicatorType.frequency,
          pattern: ['location_updates_per_minute > 10'],
          confidence: 0.75,
        ),
      ],
      minConfidence: 0.75,
    );

    _signatureDB['contact_exfiltration'] = BehavioralSignature(
      id: 'contact_exfiltration',
      name: 'Contact List Exfiltration',
      category: 'data_exfiltration',
      severity: ThreatSeverity.medium,
      description: 'Exports contact list and sends to remote server',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'ContentResolver.query',
            'ContactsContract.CommonDataKinds',
            'JSONObject.put',
            'HttpURLConnection.setRequestMethod',
          ],
          confidence: 0.85,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['READ_CONTACTS', 'INTERNET'],
          confidence: 0.80,
        ),
      ],
      minConfidence: 0.75,
    );

    // ========== ACCESSIBILITY ABUSE ==========
    
    _signatureDB['accessibility_keylogging'] = BehavioralSignature(
      id: 'accessibility_keylogging',
      name: 'Accessibility Service Keylogging',
      category: 'credential_theft',
      severity: ThreatSeverity.critical,
      description: 'Uses accessibility service to capture keystrokes',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'AccessibilityService.onAccessibilityEvent',
            'AccessibilityNodeInfo.getText',
            'TYPE_VIEW_TEXT_CHANGED',
          ],
          confidence: 0.93,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['BIND_ACCESSIBILITY_SERVICE'],
          confidence: 0.90,
        ),
      ],
      minConfidence: 0.85,
    );

    _signatureDB['accessibility_auto_click'] = BehavioralSignature(
      id: 'accessibility_auto_click',
      name: 'Accessibility Auto-Click Fraud',
      category: 'fraud',
      severity: ThreatSeverity.high,
      description: 'Automatically clicks ads or UI elements without user interaction',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'AccessibilityService.performGlobalAction',
            'AccessibilityNodeInfo.performAction',
            'ACTION_CLICK',
          ],
          confidence: 0.87,
        ),
        BehaviorIndicator(
          type: IndicatorType.frequency,
          pattern: ['auto_clicks_per_minute > 20'],
          confidence: 0.82,
        ),
      ],
      minConfidence: 0.75,
    );

    // ========== RANSOMWARE BEHAVIORS ==========
    
    _signatureDB['device_admin_lock'] = BehavioralSignature(
      id: 'device_admin_lock',
      name: 'Device Admin Lockscreen Ransomware',
      category: 'ransomware',
      severity: ThreatSeverity.critical,
      description: 'Uses device admin to lock device and demand ransom',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'DevicePolicyManager.isAdminActive',
            'DevicePolicyManager.lockNow',
            'DevicePolicyManager.resetPassword',
          ],
          confidence: 0.95,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['BIND_DEVICE_ADMIN'],
          confidence: 0.92,
        ),
      ],
      minConfidence: 0.90,
    );

    _signatureDB['file_encryption_ransomware'] = BehavioralSignature(
      id: 'file_encryption_ransomware',
      name: 'File Encryption Ransomware',
      category: 'ransomware',
      severity: ThreatSeverity.critical,
      description: 'Encrypts user files and demands ransom',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'File.listFiles',
            'Cipher.getInstance',
            'Cipher.doFinal',
            'File.delete',
            'File.renameTo',
          ],
          confidence: 0.90,
        ),
        BehaviorIndicator(
          type: IndicatorType.fileOperation,
          pattern: ['mass_file_encryption'],
          confidence: 0.88,
        ),
      ],
      minConfidence: 0.85,
    );

    // ========== PERSISTENCE BEHAVIORS ==========
    
    _signatureDB['boot_persistence'] = BehavioralSignature(
      id: 'boot_persistence',
      name: 'Boot Persistence Mechanism',
      category: 'persistence',
      severity: ThreatSeverity.medium,
      description: 'Ensures malware runs on device boot',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.component,
          pattern: ['BOOT_COMPLETED receiver'],
          confidence: 0.75,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['RECEIVE_BOOT_COMPLETED'],
          confidence: 0.70,
        ),
      ],
      minConfidence: 0.65,
    );

    // ========== PREMIUM SMS FRAUD ==========
    
    _signatureDB['premium_sms_fraud'] = BehavioralSignature(
      id: 'premium_sms_fraud',
      name: 'Premium SMS Fraud',
      category: 'fraud',
      severity: ThreatSeverity.high,
      description: 'Sends premium rate SMS messages without user consent',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'SmsManager.sendTextMessage',
            'BroadcastReceiver.abortBroadcast',
          ],
          confidence: 0.88,
        ),
        BehaviorIndicator(
          type: IndicatorType.permission,
          pattern: ['SEND_SMS', 'RECEIVE_SMS'],
          confidence: 0.85,
        ),
        BehaviorIndicator(
          type: IndicatorType.networkIndicator,
          pattern: ['premium_rate_numbers'],
          confidence: 0.90,
        ),
      ],
      minConfidence: 0.80,
    );

    // ========== C2 COMMUNICATION ==========
    
    _signatureDB['c2_beacon'] = BehavioralSignature(
      id: 'c2_beacon',
      name: 'Command & Control Beaconing',
      category: 'command_control',
      severity: ThreatSeverity.critical,
      description: 'Regular beaconing to C2 server for commands',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.networkPattern,
          pattern: ['periodic_network_connections'],
          confidence: 0.85,
        ),
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'AlarmManager.setRepeating',
            'HttpURLConnection.connect',
            'Runtime.exec',
          ],
          confidence: 0.82,
        ),
      ],
      minConfidence: 0.75,
    );

    // ========== ROOT EXPLOITS ==========
    
    _signatureDB['root_exploit'] = BehavioralSignature(
      id: 'root_exploit',
      name: 'Root Privilege Escalation',
      category: 'privilege_escalation',
      severity: ThreatSeverity.critical,
      description: 'Attempts to gain root access on device',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'Runtime.exec',
            'ProcessBuilder.command',
          ],
          confidence: 0.80,
        ),
        BehaviorIndicator(
          type: IndicatorType.stringPattern,
          pattern: ['su', '/system/xbin/su', 'chmod 777', 'mount -o remount'],
          confidence: 0.85,
        ),
      ],
      minConfidence: 0.75,
    );

    // ========== DYNAMIC CODE LOADING ==========
    
    _signatureDB['dynamic_payload_loading'] = BehavioralSignature(
      id: 'dynamic_payload_loading',
      name: 'Dynamic Payload Loading',
      category: 'evasion',
      severity: ThreatSeverity.high,
      description: 'Loads additional malicious code at runtime',
      indicators: [
        BehaviorIndicator(
          type: IndicatorType.apiSequence,
          pattern: [
            'HttpURLConnection.getInputStream',
            'FileOutputStream.write',
            'DexClassLoader.<init>',
            'Class.forName',
            'Method.invoke',
          ],
          confidence: 0.90,
        ),
      ],
      minConfidence: 0.80,
    );
  }

  /// Initialize runtime monitoring
  void _initializeMonitoring() {
    // Reset monitoring state
    _eventLog.clear();
    _apiCallSequence.clear();
    _behaviorStates.clear();
  }

  /// Analyze application behavior in real-time
  Future<BehavioralAnalysisResult> analyzeBehavior(ApplicationBehaviorData behaviorData) async {
    print('🔍 Analyzing application behavior...');

    final detectedThreats = <DetectedBehavior>[];
    double overallRiskScore = 0.0;

    // Analyze API call sequences
    final apiSequenceThreats = await _analyzeAPISequences(behaviorData.apiCalls);
    detectedThreats.addAll(apiSequenceThreats);

    // Analyze permission usage
    final permissionThreats = _analyzePermissionPatterns(behaviorData.permissions);
    detectedThreats.addAll(permissionThreats);

    // Analyze network behavior
    final networkThreats = _analyzeNetworkBehavior(behaviorData.networkActivity);
    detectedThreats.addAll(networkThreats);

    // Analyze file operations
    final fileThreats = _analyzeFileOperations(behaviorData.fileOperations);
    detectedThreats.addAll(fileThreats);

    // Analyze component behavior
    final componentThreats = _analyzeComponents(behaviorData.components);
    detectedThreats.addAll(componentThreats);

    // Calculate overall risk score
    if (detectedThreats.isNotEmpty) {
      overallRiskScore = detectedThreats
          .map((t) => t.confidence * _getSeverityWeight(t.severity))
          .reduce((a, b) => a + b) / detectedThreats.length;
    }

    // Determine if malicious
    final isMalicious = overallRiskScore >= MALICIOUS_BEHAVIOR_THRESHOLD;

    print('📊 Behavioral analysis complete');
    print('   • Detected ${detectedThreats.length} suspicious behaviors');
    print('   • Overall risk score: ${(overallRiskScore * 100).toStringAsFixed(1)}%');
    print('   • Verdict: ${isMalicious ? "MALICIOUS" : "CLEAN"}');

    return BehavioralAnalysisResult(
      isMalicious: isMalicious,
      riskScore: overallRiskScore,
      detectedBehaviors: detectedThreats,
      behaviorCategories: _categorizeBehaviors(detectedThreats),
      mitreAttackTechniques: _mapToMitre(detectedThreats),
    );
  }

  /// Analyze API call sequences for malicious patterns
  Future<List<DetectedBehavior>> _analyzeAPISequences(List<String> apiCalls) async {
    final detected = <DetectedBehavior>[];

    for (final signature in _signatureDB.values) {
      final apiIndicators = signature.indicators
          .where((i) => i.type == IndicatorType.apiSequence)
          .toList();

      for (final indicator in apiIndicators) {
        final pattern = indicator.pattern;
        if (_matchAPISequence(apiCalls, pattern)) {
          detected.add(DetectedBehavior(
            signatureId: signature.id,
            behaviorName: signature.name,
            category: signature.category,
            severity: signature.severity,
            confidence: indicator.confidence,
            evidence: 'API sequence match: ${pattern.join(" -> ")}',
            timestamp: DateTime.now(),
          ));
        }
      }
    }

    return detected;
  }

  /// Match API call sequence pattern
  bool _matchAPISequence(List<String> apiCalls, List<String> pattern) {
    if (pattern.isEmpty) return false;
    
    for (int i = 0; i <= apiCalls.length - pattern.length; i++) {
      bool matched = true;
      for (int j = 0; j < pattern.length; j++) {
        if (!apiCalls[i + j].contains(pattern[j])) {
          matched = false;
          break;
        }
      }
      if (matched) return true;
    }
    
    return false;
  }

  /// Analyze permission patterns
  List<DetectedBehavior> _analyzePermissionPatterns(List<String> permissions) {
    final detected = <DetectedBehavior>[];

    for (final signature in _signatureDB.values) {
      final permIndicators = signature.indicators
          .where((i) => i.type == IndicatorType.permission)
          .toList();

      for (final indicator in permIndicators) {
        final requiredPerms = indicator.pattern;
        final hasAllPerms = requiredPerms.every((p) => 
          permissions.any((up) => up.contains(p))
        );

        if (hasAllPerms) {
          detected.add(DetectedBehavior(
            signatureId: signature.id,
            behaviorName: signature.name,
            category: signature.category,
            severity: signature.severity,
            confidence: indicator.confidence,
            evidence: 'Permission combination: ${requiredPerms.join(", ")}',
            timestamp: DateTime.now(),
          ));
        }
      }
    }

    return detected;
  }

  /// Analyze network behavior
  List<DetectedBehavior> _analyzeNetworkBehavior(NetworkActivity networkActivity) {
    final detected = <DetectedBehavior>[];

    // Check for suspicious domains
    for (final domain in networkActivity.domains) {
      if (_isSuspiciousDomain(domain)) {
        detected.add(DetectedBehavior(
          signatureId: 'suspicious_domain',
          behaviorName: 'Suspicious Domain Connection',
          category: 'command_control',
          severity: ThreatSeverity.high,
          confidence: 0.85,
          evidence: 'Connected to suspicious domain: $domain',
          timestamp: DateTime.now(),
        ));
      }
    }

    // Check for periodic beaconing
    if (_detectPeriodicBeaconing(networkActivity.connections)) {
      detected.add(DetectedBehavior(
        signatureId: 'c2_beacon',
        behaviorName: 'C2 Beaconing Detected',
        category: 'command_control',
        severity: ThreatSeverity.critical,
        confidence: 0.88,
        evidence: 'Periodic network connections detected',
        timestamp: DateTime.now(),
      ));
    }

    return detected;
  }

  /// Analyze file operations
  List<DetectedBehavior> _analyzeFileOperations(List<FileOperation> fileOps) {
    final detected = <DetectedBehavior>[];

    // Check for mass file encryption
    final encryptionOps = fileOps.where((op) => 
      op.operation == 'encrypt' || op.operation == 'modify'
    ).length;

    if (encryptionOps > 50) {
      detected.add(DetectedBehavior(
        signatureId: 'file_encryption_ransomware',
        behaviorName: 'Mass File Encryption',
        category: 'ransomware',
        severity: ThreatSeverity.critical,
        confidence: 0.92,
        evidence: 'Encrypted $encryptionOps files',
        timestamp: DateTime.now(),
      ));
    }

    return detected;
  }

  /// Analyze component behavior
  List<DetectedBehavior> _analyzeComponents(Map<String, dynamic> components) {
    final detected = <DetectedBehavior>[];

    final receivers = components['receivers'] as List? ?? [];
    
    // Check for BOOT_COMPLETED receiver
    if (receivers.any((r) => r.toString().contains('BOOT_COMPLETED'))) {
      detected.add(DetectedBehavior(
        signatureId: 'boot_persistence',
        behaviorName: 'Boot Persistence',
        category: 'persistence',
        severity: ThreatSeverity.medium,
        confidence: 0.75,
        evidence: 'BOOT_COMPLETED receiver registered',
        timestamp: DateTime.now(),
      ));
    }

    return detected;
  }

  /// Check if domain is suspicious
  bool _isSuspiciousDomain(String domain) {
    final suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq'];
    return suspiciousTLDs.any((tld) => domain.endsWith(tld)) ||
           domain.contains('onion') ||
           domain.split('.').length <= 2; // Short domains
  }

  /// Detect periodic network beaconing
  bool _detectPeriodicBeaconing(List<NetworkConnection> connections) {
    if (connections.length < 5) return false;

    // Check for regular time intervals
    final intervals = <int>[];
    for (int i = 1; i < connections.length; i++) {
      final interval = connections[i].timestamp.difference(connections[i-1].timestamp).inSeconds;
      intervals.add(interval);
    }

    // Calculate variance
    if (intervals.isEmpty) return false;
    final mean = intervals.reduce((a, b) => a + b) / intervals.length;
    final variance = intervals.map((i) => math.pow(i - mean, 2)).reduce((a, b) => a + b) / intervals.length;
    final stdDev = math.sqrt(variance);

    // Low variance indicates periodic beaconing
    return stdDev < mean * 0.2 && mean > 10; // Regular intervals > 10 sec
  }

  /// Categorize detected behaviors
  Map<String, int> _categorizeBehaviors(List<DetectedBehavior> behaviors) {
    final categories = <String, int>{};
    
    for (final behavior in behaviors) {
      categories[behavior.category] = (categories[behavior.category] ?? 0) + 1;
    }
    
    return categories;
  }

  /// Map behaviors to MITRE ATT&CK techniques
  List<String> _mapToMitre(List<DetectedBehavior> behaviors) {
    final techniques = <String>{};
    
    final categoryToMitre = {
      'credential_theft': 'T1417',
      'data_exfiltration': 'T1532',
      'surveillance': 'T1429',
      'persistence': 'T1402',
      'command_control': 'T1437',
      'privilege_escalation': 'T1401',
      'evasion': 'T1406',
      'ransomware': 'T1471',
      'fraud': 'T1448',
    };

    for (final behavior in behaviors) {
      final techniqueId = categoryToMitre[behavior.category];
      if (techniqueId != null) {
        techniques.add(techniqueId);
      }
    }

    return techniques.toList();
  }

  /// Get severity weight for scoring
  double _getSeverityWeight(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return 1.0;
      case ThreatSeverity.high:
        return 0.8;
      case ThreatSeverity.medium:
        return 0.5;
      case ThreatSeverity.low:
        return 0.3;
      default:
        return 0.5;
    }
  }

  /// Get signature count
  int get signatureCount => _signatureDB.length;

  /// Clear event logs
  void clearLogs() {
    _eventLog.clear();
    _apiCallSequence.clear();
  }
}

// ==================== DATA MODELS ====================

class BehavioralSignature {
  final String id;
  final String name;
  final String category;
  final ThreatSeverity severity;
  final String description;
  final List<BehaviorIndicator> indicators;
  final double minConfidence;

  BehavioralSignature({
    required this.id,
    required this.name,
    required this.category,
    required this.severity,
    required this.description,
    required this.indicators,
    required this.minConfidence,
  });
}

class BehaviorIndicator {
  final IndicatorType type;
  final List<String> pattern;
  final double confidence;

  BehaviorIndicator({
    required this.type,
    required this.pattern,
    required this.confidence,
  });
}

enum IndicatorType {
  apiSequence,
  permission,
  targetApp,
  frequency,
  fileOperation,
  networkPattern,
  networkIndicator,
  stringPattern,
  component,
}

class ApplicationBehaviorData {
  final List<String> apiCalls;
  final List<String> permissions;
  final NetworkActivity networkActivity;
  final List<FileOperation> fileOperations;
  final Map<String, dynamic> components;

  ApplicationBehaviorData({
    required this.apiCalls,
    required this.permissions,
    required this.networkActivity,
    required this.fileOperations,
    required this.components,
  });
}

class NetworkActivity {
  final List<String> domains;
  final List<String> ipAddresses;
  final List<NetworkConnection> connections;

  NetworkActivity({
    required this.domains,
    required this.ipAddresses,
    required this.connections,
  });
}

class NetworkConnection {
  final String destination;
  final int port;
  final DateTime timestamp;

  NetworkConnection({
    required this.destination,
    required this.port,
    required this.timestamp,
  });
}

class FileOperation {
  final String path;
  final String operation;
  final DateTime timestamp;

  FileOperation({
    required this.path,
    required this.operation,
    required this.timestamp,
  });
}

class BehavioralAnalysisResult {
  final bool isMalicious;
  final double riskScore;
  final List<DetectedBehavior> detectedBehaviors;
  final Map<String, int> behaviorCategories;
  final List<String> mitreAttackTechniques;

  BehavioralAnalysisResult({
    required this.isMalicious,
    required this.riskScore,
    required this.detectedBehaviors,
    required this.behaviorCategories,
    required this.mitreAttackTechniques,
  });
}

class DetectedBehavior {
  final String signatureId;
  final String behaviorName;
  final String category;
  final ThreatSeverity severity;
  final double confidence;
  final String evidence;
  final DateTime timestamp;

  DetectedBehavior({
    required this.signatureId,
    required this.behaviorName,
    required this.category,
    required this.severity,
    required this.confidence,
    required this.evidence,
    required this.timestamp,
  });
}

class BehaviorEvent {
  final String eventType;
  final Map<String, dynamic> data;
  final DateTime timestamp;

  BehaviorEvent({
    required this.eventType,
    required this.data,
    required this.timestamp,
  });
}

class APICallEvent {
  final String apiName;
  final List<dynamic> parameters;
  final DateTime timestamp;

  APICallEvent({
    required this.apiName,
    required this.parameters,
    required this.timestamp,
  });
}

class BehaviorState {
  final String packageName;
  final Map<String, int> eventCounts;
  final DateTime lastUpdate;

  BehaviorState({
    required this.packageName,
    required this.eventCounts,
    required this.timestamp,
  });
}
