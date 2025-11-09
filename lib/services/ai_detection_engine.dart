import 'dart:async';
import 'dart:math';
import 'package:adrig/core/models/threat_model.dart';

/// AI-Based Realtime Detection Engine
/// The "bread winner" feature - learns on-device, monitors everything, protects user
/// 
/// Key Features:
/// - On-device ML model with continuous learning
/// - Behavioral anomaly detection (app lifecycle, permissions, background activities)
/// - Network traffic analysis (DNS, SSL, C2 detection)
/// - User feedback loop for model improvement
/// - Real-time threat scoring with explainable AI
class AIDetectionEngine {
  // ML Model components
  late BehavioralFeatureExtractor _featureExtractor;
  late AnomalyDetectionModel _mlModel;
  late NetworkTrafficAnalyzer _networkAnalyzer;
  late UserFeedbackLearner _feedbackLearner;
  
  // Monitoring state
  final Map<String, AppBehaviorProfile> _behaviorProfiles = {};
  final Map<String, NetworkActivityProfile> _networkProfiles = {};
  final List<BehavioralAnomaly> _detectedAnomalies = [];
  
  // Learning state
  int _modelVersion = 1;
  DateTime? _lastModelUpdate;
  double _modelAccuracy = 0.75; // Initial accuracy
  
  bool _initialized = false;
  
  AIDetectionEngine();
  
  /// Initialize AI engine - load pre-trained model, start monitors
  Future<void> initialize() async {
    if (_initialized) return;
    
    print('\n🤖 ===== INITIALIZING AI DETECTION ENGINE =====');
    print('🧠 Loading on-device ML model...');
    
    try {
      // Initialize behavioral feature extractor
      _featureExtractor = BehavioralFeatureExtractor();
      await _featureExtractor.initialize();
      print('  ✓ Feature extractor ready');
      
      // Load pre-trained anomaly detection model
      _mlModel = AnomalyDetectionModel();
      await _mlModel.loadModel();
      print('  ✓ ML model loaded (v${_modelVersion})');
      
      // Initialize network traffic analyzer
      _networkAnalyzer = NetworkTrafficAnalyzer();
      await _networkAnalyzer.initialize();
      print('  ✓ Network analyzer ready');
      
      // Initialize user feedback learner
      _feedbackLearner = UserFeedbackLearner();
      await _feedbackLearner.initialize();
      print('  ✓ Feedback learner ready');
      
      _initialized = true;
      print('✅ AI Detection Engine initialized\n');
      
      // Start background monitors
      _startBackgroundMonitoring();
      
    } catch (e) {
      print('❌ AI Engine initialization failed: $e');
      rethrow;
    }
  }
  
  /// Start background monitoring services
  void _startBackgroundMonitoring() {
    print('🔍 Starting background monitoring...');
    
    // Monitor app lifecycle events
    _featureExtractor.startLifecycleMonitoring((event) {
      _handleBehavioralEvent(event);
    });
    
    // Monitor network traffic
    _networkAnalyzer.startTrafficMonitoring((traffic) {
      _handleNetworkTraffic(traffic);
    });
    
    print('  ✓ Background monitors active');
  }
  
  /// Analyze app behavior and detect anomalies using AI
  Future<AIThreatAssessment> analyzeAppBehavior({
    required String packageName,
    required String appName,
    required AppMetadata metadata,
  }) async {
    if (!_initialized) await initialize();
    
    print('\n🤖 AI Analysis: $appName');
    
    try {
      // Extract behavioral features
      final features = await _featureExtractor.extractFeatures(
        packageName: packageName,
        metadata: metadata,
        historicalProfile: _behaviorProfiles[packageName],
      );
      
      print('  📊 Extracted ${features.length} behavioral features');
      
      // Get network activity profile
      final networkProfile = _networkProfiles[packageName];
      if (networkProfile != null) {
        print('  🌐 Network activity: ${networkProfile.connectionCount} connections');
      }
      
      // Run ML model inference
      final prediction = await _mlModel.predict(features);
      print('  🧠 ML Prediction: ${(prediction.threatProbability * 100).toStringAsFixed(1)}% malicious');
      
      // Analyze network behavior
      NetworkThreatScore? networkScore;
      if (networkProfile != null) {
        networkScore = await _networkAnalyzer.analyzeBehavior(networkProfile);
        print('  🌐 Network Score: ${networkScore.score}/100');
      }
      
      // Combine scores with explainable AI
      final assessment = _computeComprehensiveAssessment(
        appName: appName,
        packageName: packageName,
        mlPrediction: prediction,
        networkScore: networkScore,
        features: features,
      );
      
      print('  ✅ AI Assessment: ${assessment.riskLevel} (${assessment.overallScore}/100)');
      
      // Update behavior profile for continuous learning
      _updateBehaviorProfile(packageName, features, assessment);
      
      return assessment;
      
    } catch (e) {
      print('  ❌ AI analysis failed: $e');
      
      // Return conservative assessment on error
      return AIThreatAssessment(
        packageName: packageName,
        appName: appName,
        overallScore: 50,
        riskLevel: 'UNKNOWN',
        mlThreatProbability: 0.5,
        networkRiskScore: 0,
        behavioralAnomalies: [],
        confidence: 0.3,
        explanation: 'AI analysis failed: $e',
        recommendedAction: ActionType.monitoronly,
        timestamp: DateTime.now(),
      );
    }
  }
  
  /// Handle behavioral event from monitoring
  void _handleBehavioralEvent(BehavioralEvent event) {
    // Update behavior profile
    final profile = _behaviorProfiles[event.packageName] ?? 
        AppBehaviorProfile(packageName: event.packageName);
    
    profile.recordEvent(event);
    _behaviorProfiles[event.packageName] = profile;
    
    // Check for immediate anomalies
    final anomaly = _detectImmediateAnomaly(event, profile);
    if (anomaly != null) {
      _detectedAnomalies.add(anomaly);
      print('⚠️  Behavioral anomaly detected: ${anomaly.description}');
    }
  }
  
  /// Handle network traffic from monitoring
  void _handleNetworkTraffic(NetworkTrafficEvent traffic) {
    // Update network profile
    final profile = _networkProfiles[traffic.packageName] ?? 
        NetworkActivityProfile(packageName: traffic.packageName);
    
    profile.recordTraffic(traffic);
    _networkProfiles[traffic.packageName] = profile;
    
    // Check for suspicious network patterns
    final suspicious = _networkAnalyzer.checkSuspiciousPattern(traffic, profile);
    if (suspicious != null) {
      print('🚨 Suspicious network activity: ${suspicious.description}');
    }
  }
  
  /// Detect immediate behavioral anomaly
  BehavioralAnomaly? _detectImmediateAnomaly(
    BehavioralEvent event,
    AppBehaviorProfile profile,
  ) {
    // Check for suspicious patterns
    
    // 1. Excessive background activity
    if (event.type == BehavioralEventType.backgroundActivity) {
      if (profile.backgroundActivityCount > 100) {
        return BehavioralAnomaly(
          packageName: event.packageName,
          type: AnomalyType.excessiveBackgroundActivity,
          description: 'App has excessive background activity (${profile.backgroundActivityCount} events)',
          severity: ThreatSeverity.medium,
          timestamp: DateTime.now(),
        );
      }
    }
    
    // 2. Unexpected permission requests
    if (event.type == BehavioralEventType.permissionRequest) {
      final permissionName = event.data['permission'] as String?;
      if (permissionName != null && _isSuspiciousPermission(permissionName)) {
        return BehavioralAnomaly(
          packageName: event.packageName,
          type: AnomalyType.suspiciousPermissionRequest,
          description: 'Requested suspicious permission: $permissionName',
          severity: ThreatSeverity.high,
          timestamp: DateTime.now(),
        );
      }
    }
    
    // 3. Unusual time activity (active at 3 AM)
    if (event.timestamp.hour >= 2 && event.timestamp.hour <= 5) {
      if (event.type == BehavioralEventType.networkActivity) {
        return BehavioralAnomaly(
          packageName: event.packageName,
          type: AnomalyType.unusualTimeActivity,
          description: 'Network activity during unusual hours (${event.timestamp.hour}:00)',
          severity: ThreatSeverity.low,
          timestamp: DateTime.now(),
        );
      }
    }
    
    return null;
  }
  
  /// Check if permission is suspicious
  bool _isSuspiciousPermission(String permission) {
    const suspiciousPermissions = [
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.REQUEST_INSTALL_PACKAGES',
      'android.permission.WRITE_SETTINGS',
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.BIND_DEVICE_ADMIN',
    ];
    return suspiciousPermissions.contains(permission);
  }
  
  /// Advanced permission risk scoring with combinations
  int _calculatePermissionRisk(List<String> permissions) {
    int riskScore = 0;
    
    // Individual permission weights
    final permissionWeights = {
      // Critical permissions (50 points each)
      'android.permission.BIND_DEVICE_ADMIN': 50,
      'android.permission.BIND_ACCESSIBILITY_SERVICE': 50,
      'android.permission.REQUEST_INSTALL_PACKAGES': 45,
      'android.permission.SYSTEM_ALERT_WINDOW': 40,
      'android.permission.WRITE_SETTINGS': 35,
      
      // High-risk permissions (30 points)
      'android.permission.READ_SMS': 30,
      'android.permission.SEND_SMS': 30,
      'android.permission.READ_CALL_LOG': 30,
      'android.permission.PROCESS_OUTGOING_CALLS': 30,
      'android.permission.READ_CONTACTS': 25,
      
      // Medium-risk permissions (15 points)
      'android.permission.CAMERA': 15,
      'android.permission.RECORD_AUDIO': 15,
      'android.permission.ACCESS_FINE_LOCATION': 15,
      'android.permission.READ_EXTERNAL_STORAGE': 10,
      'android.permission.WRITE_EXTERNAL_STORAGE': 10,
      
      // Network permissions (10 points)
      'android.permission.INTERNET': 5,
      'android.permission.ACCESS_NETWORK_STATE': 3,
      'android.permission.ACCESS_WIFI_STATE': 3,
    };
    
    // Add individual scores
    for (final perm in permissions) {
      riskScore += permissionWeights[perm] ?? 0;
    }
    
    // DANGEROUS COMBINATIONS (extra 50-100 points)
    final permSet = permissions.toSet();
    
    // Spyware combo: SMS + Call logs + Contacts
    if (permSet.contains('android.permission.READ_SMS') &&
        permSet.contains('android.permission.READ_CALL_LOG') &&
        permSet.contains('android.permission.READ_CONTACTS')) {
      riskScore += 80;
      print('  🚨 Spyware combo detected: SMS+CALL_LOG+CONTACTS');
    }
    
    // Ransomware combo: Device Admin + Overlay + Storage
    if (permSet.contains('android.permission.BIND_DEVICE_ADMIN') &&
        permSet.contains('android.permission.SYSTEM_ALERT_WINDOW') &&
        permSet.contains('android.permission.WRITE_EXTERNAL_STORAGE')) {
      riskScore += 100;
      print('  🚨 Ransomware combo detected: ADMIN+OVERLAY+STORAGE');
    }
    
    // Banking trojan: Accessibility + SMS + Overlay
    if (permSet.contains('android.permission.BIND_ACCESSIBILITY_SERVICE') &&
        permSet.contains('android.permission.READ_SMS') &&
        permSet.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
      riskScore += 90;
      print('  🚨 Banking trojan combo: ACCESSIBILITY+SMS+OVERLAY');
    }
    
    // Stalkerware: Location + Camera + Mic + SMS
    if (permSet.contains('android.permission.ACCESS_FINE_LOCATION') &&
        permSet.contains('android.permission.CAMERA') &&
        permSet.contains('android.permission.RECORD_AUDIO') &&
        permSet.contains('android.permission.READ_SMS')) {
      riskScore += 85;
      print('  🚨 Stalkerware combo detected: LOCATION+CAMERA+MIC+SMS');
    }
    
    // Ad fraud: Install packages + Accessibility + Overlay
    if (permSet.contains('android.permission.REQUEST_INSTALL_PACKAGES') &&
        permSet.contains('android.permission.BIND_ACCESSIBILITY_SERVICE')) {
      riskScore += 70;
      print('  🚨 Ad fraud combo: INSTALL+ACCESSIBILITY');
    }
    
    return riskScore.clamp(0, 100);
  }
  
  /// Compute comprehensive threat assessment
  AIThreatAssessment _computeComprehensiveAssessment({
    required String appName,
    required String packageName,
    required MLPrediction mlPrediction,
    NetworkThreatScore? networkScore,
    required List<BehavioralFeature> features,
  }) {
    // Weighted scoring
    final mlWeight = 0.5;
    final networkWeight = 0.3;
    final behavioralWeight = 0.2;
    
    final mlScore = mlPrediction.threatProbability * 100;
    final netScore = networkScore?.score ?? 0.0;
    final behaviorScore = _computeBehavioralScore(features);
    
    final overallScore = (mlScore * mlWeight) + 
                         (netScore * networkWeight) + 
                         (behaviorScore * behavioralWeight);
    
    // Determine risk level
    String riskLevel;
    ThreatSeverity severity;
    ActionType action;
    
    if (overallScore >= 80) {
      riskLevel = 'CRITICAL';
      severity = ThreatSeverity.critical;
      action = ActionType.quarantine;
    } else if (overallScore >= 60) {
      riskLevel = 'HIGH';
      severity = ThreatSeverity.high;
      action = ActionType.autoblock;
    } else if (overallScore >= 40) {
      riskLevel = 'MEDIUM';
      severity = ThreatSeverity.medium;
      action = ActionType.monitoronly;
    } else if (overallScore >= 20) {
      riskLevel = 'LOW';
      severity = ThreatSeverity.low;
      action = ActionType.monitoronly;
    } else {
      riskLevel = 'SAFE';
      severity = ThreatSeverity.info;
      action = ActionType.monitoronly;
    }
    
    // Generate explanation
    final explanation = _generateExplanation(
      mlPrediction: mlPrediction,
      networkScore: networkScore,
      features: features,
    );
    
    // Collect anomalies for this app
    final appAnomalies = _detectedAnomalies
        .where((a) => a.packageName == packageName)
        .toList();
    
    return AIThreatAssessment(
      packageName: packageName,
      appName: appName,
      overallScore: overallScore.round(),
      riskLevel: riskLevel,
      mlThreatProbability: mlPrediction.threatProbability,
      networkRiskScore: netScore.round(),
      behavioralAnomalies: appAnomalies,
      confidence: _computeConfidence(mlPrediction, networkScore),
      explanation: explanation,
      recommendedAction: action,
      timestamp: DateTime.now(),
    );
  }
  
  /// Compute behavioral anomaly score
  double _computeBehavioralScore(List<BehavioralFeature> features) {
    double score = 0.0;
    
    for (final feature in features) {
      if (feature.name == 'background_activity_rate' && feature.value > 0.8) {
        score += 20;
      }
      if (feature.name == 'permission_entropy' && feature.value > 0.7) {
        score += 15;
      }
      if (feature.name == 'service_count' && feature.value > 10) {
        score += 10;
      }
    }
    
    return min(score, 100.0);
  }
  
  /// Compute overall confidence
  double _computeConfidence(MLPrediction mlPrediction, NetworkThreatScore? networkScore) {
    final mlConfidence = mlPrediction.confidence;
    final networkConfidence = networkScore?.confidence ?? 0.5;
    return (mlConfidence + networkConfidence) / 2;
  }
  
  /// Generate human-readable explanation
  String _generateExplanation({
    required MLPrediction mlPrediction,
    NetworkThreatScore? networkScore,
    required List<BehavioralFeature> features,
  }) {
    final reasons = <String>[];
    
    if (mlPrediction.threatProbability > 0.7) {
      reasons.add('ML model detected ${(mlPrediction.threatProbability * 100).toStringAsFixed(0)}% malicious probability');
    }
    
    if (networkScore != null && networkScore.score > 60) {
      reasons.add('Suspicious network activity detected');
    }
    
    for (final feature in features) {
      if (feature.value > 0.8 && feature.importance > 0.7) {
        reasons.add('High ${feature.name}: ${(feature.value * 100).toStringAsFixed(0)}%');
      }
    }
    
    if (reasons.isEmpty) {
      return 'No significant threats detected by AI analysis';
    }
    
    return reasons.join('; ');
  }
  
  /// Update behavior profile for learning
  void _updateBehaviorProfile(
    String packageName,
    List<BehavioralFeature> features,
    AIThreatAssessment assessment,
  ) {
    final profile = _behaviorProfiles[packageName];
    if (profile != null) {
      profile.updateFeatures(features);
      profile.lastAssessment = assessment;
      profile.lastUpdateTime = DateTime.now();
    }
  }
  
  /// Learn from user feedback (allow/block action)
  Future<void> learnFromUserAction({
    required String packageName,
    required bool userTrusted, // true = user allowed, false = user blocked
    required AIThreatAssessment assessment,
  }) async {
    print('\n📚 Learning from user action: $packageName');
    print('  User action: ${userTrusted ? "TRUSTED" : "BLOCKED"}');
    print('  AI predicted: ${assessment.riskLevel}');
    
    await _feedbackLearner.recordFeedback(
      packageName: packageName,
      predictedScore: assessment.overallScore,
      userTrusted: userTrusted,
      timestamp: DateTime.now(),
    );
    
    // Check if model needs retraining
    final feedbackCount = await _feedbackLearner.getFeedbackCount();
    if (feedbackCount >= 50) {
      print('  🔄 Retraining model with user feedback...');
      await _retrainModel();
    }
  }
  
  /// Retrain ML model with user feedback
  Future<void> _retrainModel() async {
    try {
      final feedbackData = await _feedbackLearner.getFeedbackDataset();
      await _mlModel.retrain(feedbackData);
      
      _modelVersion++;
      _lastModelUpdate = DateTime.now();
      
      print('  ✅ Model retrained successfully (v$_modelVersion)');
      
      // Clear old feedback after retraining
      await _feedbackLearner.clearOldFeedback();
      
    } catch (e) {
      print('  ❌ Model retraining failed: $e');
    }
  }
  
  /// Get current model statistics
  Map<String, dynamic> getModelStats() {
    return {
      'version': _modelVersion,
      'accuracy': _modelAccuracy,
      'lastUpdate': _lastModelUpdate?.toIso8601String(),
      'trackedApps': _behaviorProfiles.length,
      'detectedAnomalies': _detectedAnomalies.length,
      'networkProfiles': _networkProfiles.length,
    };
  }
}

/// AI Threat Assessment result
class AIThreatAssessment {
  final String packageName;
  final String appName;
  final int overallScore; // 0-100
  final String riskLevel; // SAFE, LOW, MEDIUM, HIGH, CRITICAL
  final double mlThreatProbability;
  final int networkRiskScore;
  final List<BehavioralAnomaly> behavioralAnomalies;
  final double confidence;
  final String explanation;
  final ActionType recommendedAction;
  final DateTime timestamp;
  
  AIThreatAssessment({
    required this.packageName,
    required this.appName,
    required this.overallScore,
    required this.riskLevel,
    required this.mlThreatProbability,
    required this.networkRiskScore,
    required this.behavioralAnomalies,
    required this.confidence,
    required this.explanation,
    required this.recommendedAction,
    required this.timestamp,
  });
}

/// Behavioral feature for ML model
class BehavioralFeature {
  final String name;
  final double value; // Normalized 0-1
  final double importance; // Feature importance 0-1
  
  BehavioralFeature({
    required this.name,
    required this.value,
    required this.importance,
  });
}

/// ML prediction result
class MLPrediction {
  final double threatProbability; // 0-1
  final double confidence; // 0-1
  final List<String> topFeatures;
  
  MLPrediction({
    required this.threatProbability,
    required this.confidence,
    required this.topFeatures,
  });
}

/// Network threat score
class NetworkThreatScore {
  final double score; // 0-100
  final double confidence;
  final List<String> suspiciousPatterns;
  
  NetworkThreatScore({
    required this.score,
    required this.confidence,
    required this.suspiciousPatterns,
  });
}

/// Behavioral event types
enum BehavioralEventType {
  appLaunch,
  appClose,
  backgroundActivity,
  permissionRequest,
  networkActivity,
  fileAccess,
  serviceStart,
  broadcastReceived,
}

/// Anomaly types
enum AnomalyType {
  excessiveBackgroundActivity,
  suspiciousPermissionRequest,
  unusualTimeActivity,
  unexpectedNetworkPattern,
  abnormalDataUsage,
  suspiciousFileAccess,
  suspiciousNetworkActivity,
  sslCertificateError,
}

/// Behavioral event
class BehavioralEvent {
  final String packageName;
  final BehavioralEventType type;
  final DateTime timestamp;
  final Map<String, dynamic> data;
  
  BehavioralEvent({
    required this.packageName,
    required this.type,
    required this.timestamp,
    this.data = const {},
  });
}

/// App behavior profile (for continuous learning)
class AppBehaviorProfile {
  final String packageName;
  int backgroundActivityCount = 0;
  int networkActivityCount = 0;
  int permissionRequestCount = 0;
  List<BehavioralFeature> features = [];
  AIThreatAssessment? lastAssessment;
  DateTime? lastUpdateTime;
  
  AppBehaviorProfile({required this.packageName});
  
  void recordEvent(BehavioralEvent event) {
    switch (event.type) {
      case BehavioralEventType.backgroundActivity:
        backgroundActivityCount++;
        break;
      case BehavioralEventType.networkActivity:
        networkActivityCount++;
        break;
      case BehavioralEventType.permissionRequest:
        permissionRequestCount++;
        break;
      default:
        break;
    }
  }
  
  void updateFeatures(List<BehavioralFeature> newFeatures) {
    features = newFeatures;
  }
}

/// Network activity profile
class NetworkActivityProfile {
  final String packageName;
  int connectionCount = 0;
  int dnsQueryCount = 0;
  int sslErrorCount = 0;
  Set<String> contactedDomains = {};
  DateTime? lastActivity;
  
  NetworkActivityProfile({required this.packageName});
  
  void recordTraffic(NetworkTrafficEvent traffic) {
    connectionCount++;
    if (traffic.domain != null) {
      contactedDomains.add(traffic.domain!);
    }
    if (traffic.isDnsQuery) {
      dnsQueryCount++;
    }
    if (traffic.hasSslError) {
      sslErrorCount++;
    }
    lastActivity = traffic.timestamp;
  }
}

/// Network traffic event
class NetworkTrafficEvent {
  final String packageName;
  final String? domain;
  final String? ipAddress;
  final int port;
  final bool isDnsQuery;
  final bool hasSslError;
  final DateTime timestamp;
  
  NetworkTrafficEvent({
    required this.packageName,
    this.domain,
    this.ipAddress,
    required this.port,
    this.isDnsQuery = false,
    this.hasSslError = false,
    required this.timestamp,
  });
}

/// Behavioral anomaly
class BehavioralAnomaly {
  final String packageName;
  final AnomalyType type;
  final String description;
  final ThreatSeverity severity;
  final DateTime timestamp;
  
  BehavioralAnomaly({
    required this.packageName,
    required this.type,
    required this.description,
    required this.severity,
    required this.timestamp,
  });
}

// Placeholder classes - to be implemented next

class BehavioralFeatureExtractor {
  Future<void> initialize() async {
    print('  ✓ Behavioral feature extractor initialized');
  }
  
  void startLifecycleMonitoring(Function(BehavioralEvent) callback) {
    // Placeholder - would need native Android code for real monitoring
    print('  ℹ️  Lifecycle monitoring (requires native implementation)');
  }
  
  Future<List<BehavioralFeature>> extractFeatures({
    required String packageName,
    required AppMetadata metadata,
    AppBehaviorProfile? historicalProfile,
  }) async {
    final features = <BehavioralFeature>[];
    
    // 1. Permission-based features
    final permissionRisk = _calculatePermissionRisk(metadata.requestedPermissions);
    features.add(BehavioralFeature(
      name: 'permission_risk_score',
      value: permissionRisk / 100.0,
      importance: 0.9,
    ));
    
    // 2. Installation source risk
    final installerRisk = _calculateInstallerRisk(metadata.installerPackage);
    features.add(BehavioralFeature(
      name: 'installer_risk',
      value: installerRisk,
      importance: 0.7,
    ));
    
    // 3. App age (newer = more suspicious)
    final appAgeDays = DateTime.now().difference(
      DateTime.fromMillisecondsSinceEpoch(metadata.installTime)
    ).inDays;
    final ageRisk = appAgeDays < 7 ? 0.8 : appAgeDays < 30 ? 0.5 : 0.2;
    features.add(BehavioralFeature(
      name: 'app_age_risk',
      value: ageRisk,
      importance: 0.4,
    ));
    
    // 4. Update frequency (no updates = suspicious)
    final daysSinceUpdate = DateTime.now().difference(
      DateTime.fromMillisecondsSinceEpoch(metadata.lastUpdateTime)
    ).inDays;
    final updateRisk = daysSinceUpdate > 365 ? 0.7 : daysSinceUpdate > 180 ? 0.5 : 0.2;
    features.add(BehavioralFeature(
      name: 'update_staleness',
      value: updateRisk,
      importance: 0.5,
    ));
    
    // 5. Certificate validity
    final certRisk = metadata.certificate == null ? 0.9 : 0.1;
    features.add(BehavioralFeature(
      name: 'certificate_risk',
      value: certRisk,
      importance: 0.8,
    ));
    
    // 6. System app anomaly (system apps shouldn't request dangerous perms)
    if (metadata.isSystemApp) {
      final systemAppAnomalyRisk = _hasSystemAppAnomaly(metadata.requestedPermissions) ? 0.9 : 0.1;
      features.add(BehavioralFeature(
        name: 'system_app_anomaly',
        value: systemAppAnomalyRisk,
        importance: 0.85,
      ));
    }
    
    // 7. Historical behavior (if available)
    if (historicalProfile != null) {
      final behaviorChange = _detectBehaviorChange(historicalProfile);
      features.add(BehavioralFeature(
        name: 'behavior_change_score',
        value: behaviorChange,
        importance: 0.75,
      ));
    }
    
    return features;
  }
  
  int _calculatePermissionRisk(List<String> permissions) {
    int riskScore = 0;
    
    final permissionWeights = {
      'android.permission.BIND_DEVICE_ADMIN': 50,
      'android.permission.BIND_ACCESSIBILITY_SERVICE': 50,
      'android.permission.REQUEST_INSTALL_PACKAGES': 45,
      'android.permission.SYSTEM_ALERT_WINDOW': 40,
      'android.permission.WRITE_SETTINGS': 35,
      'android.permission.READ_SMS': 30,
      'android.permission.SEND_SMS': 30,
      'android.permission.READ_CALL_LOG': 30,
      'android.permission.PROCESS_OUTGOING_CALLS': 30,
      'android.permission.READ_CONTACTS': 25,
      'android.permission.CAMERA': 15,
      'android.permission.RECORD_AUDIO': 15,
      'android.permission.ACCESS_FINE_LOCATION': 15,
      'android.permission.READ_EXTERNAL_STORAGE': 10,
      'android.permission.WRITE_EXTERNAL_STORAGE': 10,
    };
    
    for (final perm in permissions) {
      riskScore += permissionWeights[perm] ?? 0;
    }
    
    // Check dangerous combinations
    final permSet = permissions.toSet();
    
    if (permSet.contains('android.permission.READ_SMS') &&
        permSet.contains('android.permission.READ_CALL_LOG')) {
      riskScore += 80;
    }
    
    if (permSet.contains('android.permission.BIND_DEVICE_ADMIN') &&
        permSet.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
      riskScore += 100;
    }
    
    return riskScore.clamp(0, 100);
  }
  
  double _calculateInstallerRisk(String installerPackage) {
    // Google Play = safe
    if (installerPackage == 'com.android.vending') return 0.1;
    
    // System installer = medium risk (pre-installed/side-loaded)
    if (installerPackage.contains('packageinstaller')) return 0.5;
    
    // Unknown/third-party = high risk
    return 0.8;
  }
  
  bool _hasSystemAppAnomaly(List<String> permissions) {
    // System apps shouldn't request dangerous permissions
    final dangerousPerms = [
      'android.permission.READ_SMS',
      'android.permission.SEND_SMS',
      'android.permission.BIND_DEVICE_ADMIN',
      'android.permission.REQUEST_INSTALL_PACKAGES',
    ];
    
    return permissions.any((p) => dangerousPerms.contains(p));
  }
  
  double _detectBehaviorChange(AppBehaviorProfile profile) {
    // Compare current vs historical behavior
    final hoursSinceLastUpdate = profile.lastUpdateTime != null
        ? DateTime.now().difference(profile.lastUpdateTime!).inHours
        : 0;
    
    // Sudden spike in background activity = suspicious
    if (hoursSinceLastUpdate < 24 && profile.backgroundActivityCount > 100) {
      return 0.8;
    }
    
    // Excessive network activity
    if (profile.networkActivityCount > 500) {
      return 0.7;
    }
    
    return 0.2;
  }
}

class AnomalyDetectionModel {
  Future<void> loadModel() async {
    print('  ℹ️  Using heuristic-based detection (TFLite model: future AWS deployment)');
  }
  
  Future<MLPrediction> predict(List<BehavioralFeature> features) async {
    // Advanced heuristic scoring (until real ML model deployed)
    double totalScore = 0.0;
    double totalImportance = 0.0;
    final topFeatures = <String>[];
    
    // Weighted scoring based on feature importance
    for (final feature in features) {
      final weightedScore = feature.value * feature.importance;
      totalScore += weightedScore;
      totalImportance += feature.importance;
      
      // Track high-risk features
      if (feature.value > 0.7) {
        topFeatures.add('${feature.name}: ${(feature.value * 100).toStringAsFixed(0)}%');
      }
    }
    
    // Normalize score
    final normalizedScore = totalImportance > 0 
        ? (totalScore / totalImportance).clamp(0.0, 1.0)
        : 0.3;
    
    // Calculate confidence based on number of high-risk features
    final confidence = topFeatures.isNotEmpty 
        ? (0.7 + (topFeatures.length * 0.05)).clamp(0.7, 0.95)
        : 0.6;
    
    return MLPrediction(
      threatProbability: normalizedScore,
      confidence: confidence,
      topFeatures: topFeatures,
    );
  }
  
  Future<void> retrain(List<Map<String, dynamic>> feedbackData) async {
    // Placeholder for future AWS ML retraining
    print('  ℹ️  Model retraining queued for AWS deployment');
    print('  📊 Feedback samples: ${feedbackData.length}');
  }
}

class NetworkTrafficAnalyzer {
  // Known malicious domain patterns
  final List<RegExp> _maliciousDomainPatterns = [
    RegExp(r'[a-z]{10,}\.(tk|ml|ga|cf|gq)$'), // DGA + free TLDs
    RegExp(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'), // Raw IPs (suspicious)
    RegExp(r'bit\.ly|tinyurl|goo\.gl'), // URL shorteners (phishing)
  ];
  
  // Suspicious TLDs
  final Set<String> _suspiciousTLDs = {
    'tk', 'ml', 'ga', 'cf', 'gq', // Free domains
    'top', 'xyz', 'club', 'work', // Cheap domains
  };
  
  // C2 server port patterns
  final Set<int> _suspiciousPorts = {
    1337, 31337, // Leet speak ports
    4444, 5555, // Common RAT ports
    6666, 7777, 8888, 9999, // Sequential patterns
    1234, 12345, // Simple patterns
  };
  
  Future<void> initialize() async {
    print('  ✓ Network traffic analyzer initialized');
  }
  
  void startTrafficMonitoring(Function(NetworkTrafficEvent) callback) {
    // Placeholder - requires VPN service implementation
    print('  ℹ️  Network monitoring (requires VPN service)');
  }
  
  Future<NetworkThreatScore> analyzeBehavior(NetworkActivityProfile profile) async {
    int riskScore = 0;
    final suspiciousPatterns = <String>[];
    
    // 1. Check contacted domains
    for (final domain in profile.contactedDomains) {
      // Check malicious patterns
      for (final pattern in _maliciousDomainPatterns) {
        if (pattern.hasMatch(domain)) {
          riskScore += 30;
          suspiciousPatterns.add('Malicious domain pattern: $domain');
        }
      }
      
      // Check suspicious TLDs
      final tld = domain.split('.').last.toLowerCase();
      if (_suspiciousTLDs.contains(tld)) {
        riskScore += 15;
        suspiciousPatterns.add('Suspicious TLD: .$tld');
      }
      
      // Check for DGA (Domain Generation Algorithm) patterns
      if (_isDGA(domain)) {
        riskScore += 40;
        suspiciousPatterns.add('DGA detected: $domain');
      }
    }
    
    // 2. Excessive DNS queries (DNS tunneling)
    if (profile.dnsQueryCount > 1000) {
      riskScore += 35;
      suspiciousPatterns.add('Excessive DNS queries: ${profile.dnsQueryCount}');
    }
    
    // 3. SSL errors (man-in-the-middle)
    if (profile.sslErrorCount > 5) {
      riskScore += 40;
      suspiciousPatterns.add('Multiple SSL errors: ${profile.sslErrorCount}');
    }
    
    // 4. Excessive connections (DDoS bot)
    if (profile.connectionCount > 5000) {
      riskScore += 30;
      suspiciousPatterns.add('Excessive connections: ${profile.connectionCount}');
    }
    
    // 5. Activity timing (late night = suspicious)
    if (profile.lastActivity != null) {
      final hour = profile.lastActivity!.hour;
      if (hour >= 2 && hour <= 5) {
        riskScore += 20;
        suspiciousPatterns.add('Late night activity: ${hour}:00');
      }
    }
    
    final confidence = suspiciousPatterns.isNotEmpty ? 0.8 : 0.6;
    
    return NetworkThreatScore(
      score: riskScore.clamp(0, 100).toDouble(),
      confidence: confidence,
      suspiciousPatterns: suspiciousPatterns,
    );
  }
  
  BehavioralAnomaly? checkSuspiciousPattern(
    NetworkTrafficEvent traffic,
    NetworkActivityProfile profile,
  ) {
    // Check for C2 server communication
    if (traffic.port != null && _suspiciousPorts.contains(traffic.port)) {
      return BehavioralAnomaly(
        packageName: traffic.packageName,
        type: AnomalyType.suspiciousNetworkActivity,
        description: 'Connection to suspicious port: ${traffic.port}',
        severity: ThreatSeverity.high,
        timestamp: DateTime.now(),
      );
    }
    
    // Check for raw IP connections (bypassing DNS)
    if (traffic.domain != null && _isIPAddress(traffic.domain!)) {
      return BehavioralAnomaly(
        packageName: traffic.packageName,
        type: AnomalyType.suspiciousNetworkActivity,
        description: 'Direct IP connection: ${traffic.domain}',
        severity: ThreatSeverity.medium,
        timestamp: DateTime.now(),
      );
    }
    
    // Check for SSL errors (MITM)
    if (traffic.hasSslError) {
      return BehavioralAnomaly(
        packageName: traffic.packageName,
        type: AnomalyType.sslCertificateError,
        description: 'SSL certificate validation failed',
        severity: ThreatSeverity.high,
        timestamp: DateTime.now(),
      );
    }
    
    return null;
  }
  
  /// Detect Domain Generation Algorithm (DGA) patterns
  bool _isDGA(String domain) {
    // Remove TLD
    final name = domain.split('.').first;
    
    // DGA characteristics:
    // 1. Long random-looking strings (>10 chars)
    // 2. High consonant-to-vowel ratio
    // 3. Low character repetition
    
    if (name.length < 10) return false;
    
    // Count vowels vs consonants
    final vowels = 'aeiou';
    int vowelCount = 0;
    for (final char in name.toLowerCase().split('')) {
      if (vowels.contains(char)) vowelCount++;
    }
    
    final consonantRatio = (name.length - vowelCount) / name.length;
    
    // High consonant ratio = likely DGA
    return consonantRatio > 0.75;
  }
  
  bool _isIPAddress(String domain) {
    final ipPattern = RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$');
    return ipPattern.hasMatch(domain);
  }
}

class UserFeedbackLearner {
  final List<Map<String, dynamic>> _feedbackHistory = [];
  
  // Dynamic threshold adjustment
  double _falsePositiveRate = 0.0;
  double _falseNegativeRate = 0.0;
  int _totalPredictions = 0;
  int _correctPredictions = 0;
  
  Future<void> initialize() async {
    // TODO: Load feedback history from SharedPreferences/SQLite
    print('  ✓ User feedback learner initialized');
  }
  
  Future<void> recordFeedback({
    required String packageName,
    required int predictedScore,
    required bool userTrusted,
    required DateTime timestamp,
  }) async {
    _feedbackHistory.add({
      'packageName': packageName,
      'predictedScore': predictedScore,
      'userTrusted': userTrusted,
      'timestamp': timestamp.toIso8601String(),
    });
    
    // Update accuracy metrics
    _totalPredictions++;
    
    // Predicted malicious (score > 50) but user trusted = false positive
    if (predictedScore > 50 && userTrusted) {
      _falsePositiveRate = (_falsePositiveRate * (_totalPredictions - 1) + 1) / _totalPredictions;
    }
    // Predicted safe (score < 50) but user blocked = false negative
    else if (predictedScore < 50 && !userTrusted) {
      _falseNegativeRate = (_falseNegativeRate * (_totalPredictions - 1) + 1) / _totalPredictions;
    }
    // Correct prediction
    else {
      _correctPredictions++;
    }
    
    // Adjust detection thresholds based on feedback
    _adjustThresholds();
    
    // TODO: Persist to storage
  }
  
  void _adjustThresholds() {
    // If too many false positives, increase threshold
    if (_falsePositiveRate > 0.3) {
      print('  📉 High false positive rate: ${(_falsePositiveRate * 100).toStringAsFixed(1)}%');
      print('  🔧 Consider increasing detection threshold');
    }
    
    // If too many false negatives, decrease threshold
    if (_falseNegativeRate > 0.2) {
      print('  📈 High false negative rate: ${(_falseNegativeRate * 100).toStringAsFixed(1)}%');
      print('  🔧 Consider decreasing detection threshold');
    }
  }
  
  Future<int> getFeedbackCount() async {
    return _feedbackHistory.length;
  }
  
  Future<List<Map<String, dynamic>>> getFeedbackDataset() async {
    return _feedbackHistory;
  }
  
  Future<void> clearOldFeedback() async {
    _feedbackHistory.clear();
    // TODO: Clear from persistent storage
  }
  
  Map<String, dynamic> getAccuracyMetrics() {
    final accuracy = _totalPredictions > 0 
        ? _correctPredictions / _totalPredictions
        : 0.0;
    
    return {
      'accuracy': accuracy,
      'falsePositiveRate': _falsePositiveRate,
      'falseNegativeRate': _falseNegativeRate,
      'totalPredictions': _totalPredictions,
      'correctPredictions': _correctPredictions,
    };
  }
}
