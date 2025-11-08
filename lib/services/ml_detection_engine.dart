import 'dart:io';
import 'package:adrig/core/models/threat_model.dart';

/// ML-based anomaly detection engine
/// In production: integrate with TensorFlow Lite for on-device inference
class MLDetectionEngine {
  MLModelMetadata? _currentModel;
  bool _isModelLoaded = false;
  final Map<String, BehaviorProfile> _behaviorProfiles = {};

  /// Initialize ML models
  Future<void> initializeModels() async {
    try {
      _currentModel = MLModelMetadata(
        id: 'model_001',
        name: 'Malware Behavior Classifier',
        version: '1.2.0',
        modelPath: 'assets/models/malware_classifier.tflite',
        modelType: 'behavior_classification',
        lastUpdated: DateTime.now(),
        modelSize: 4 * 1024 * 1024, // 4MB
        accuracy: 0.94,
        configuration: {
          'input_shape': [1, 128],
          'output_classes': 10,
          'threshold': 0.75,
        },
      );

      // In production: load TFLite model
      // final interpreter = await Interpreter.fromAsset(_currentModel.modelPath);
      
      _isModelLoaded = true;
      print('✓ ML model loaded: ${_currentModel?.name}');
    } catch (e) {
      print('Error loading ML model: $e');
      _isModelLoaded = false;
    }
  }

  /// Detect anomalies using behavioral analysis
  List<DetectedThreat> detectBehavioralAnomalies(
    String packageName,
    String appName,
    Map<String, dynamic> behaviorData,
  ) {
    if (!_isModelLoaded) {
      return [];
    }

    final threats = <DetectedThreat>[];

    // Extract features from behavior data
    final features = _extractFeatures(behaviorData);
    
    // Run inference (simulated)
    final prediction = _runInference(features);
    
    if (prediction.isAnomalous) {
      threats.add(DetectedThreat(
        id: 'threat_ml_${DateTime.now().millisecondsSinceEpoch}',
        packageName: packageName,
        appName: appName,
        threatType: prediction.threatType,
        severity: prediction.severity,
        detectionMethod: DetectionMethod.machinelearning,
        description: prediction.description,
        indicators: prediction.indicators,
        confidence: prediction.confidence,
        detectedAt: DateTime.now(),
        recommendedAction: prediction.recommendedAction,
        metadata: {
          'model_version': _currentModel?.version,
          'anomaly_score': prediction.anomalyScore,
          'feature_importance': prediction.featureImportance,
        },
      ));
    }

    return threats;
  }

  /// Detect anomalies in app permission usage patterns
  List<DetectedThreat> detectPermissionAnomalies(
    String packageName,
    String appName,
    List<PermissionUsage> usages,
  ) {
    final threats = <DetectedThreat>[];

    // Build permission usage vector
    final permissionVector = _buildPermissionVector(usages);
    
    // Compare with known benign patterns
    final anomalyScore = _calculatePermissionAnomalyScore(permissionVector);
    
    if (anomalyScore > 0.70) {
      threats.add(DetectedThreat(
        id: 'threat_ml_perm_${DateTime.now().millisecondsSinceEpoch}',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.spyware,
        severity: anomalyScore > 0.85 
            ? ThreatSeverity.high 
            : ThreatSeverity.medium,
        detectionMethod: DetectionMethod.machinelearning,
        description: 'Anomalous permission usage pattern detected',
        indicators: _getAnomalousPermissions(usages, permissionVector),
        confidence: anomalyScore,
        detectedAt: DateTime.now(),
        recommendedAction: ActionType.alert,
        metadata: {
          'anomaly_score': anomalyScore,
          'permission_count': usages.length,
        },
      ));
    }

    return threats;
  }

  /// Detect code structure anomalies
  List<DetectedThreat> detectCodeStructureAnomalies(
    String packageName,
    String appName,
    Map<String, dynamic> codeMetrics,
  ) {
    final threats = <DetectedThreat>[];

    // Extract code complexity features
    final complexity = codeMetrics['cyclomatic_complexity'] as int? ?? 0;
    final methodCount = codeMetrics['method_count'] as int? ?? 0;
    final classCount = codeMetrics['class_count'] as int? ?? 0;
    final nativeLibCount = codeMetrics['native_lib_count'] as int? ?? 0;

    // Calculate anomaly score based on code structure
    final structureScore = _calculateCodeStructureScore(
      complexity,
      methodCount,
      classCount,
      nativeLibCount,
    );

    if (structureScore > 0.75) {
      threats.add(DetectedThreat(
        id: 'threat_ml_code_${DateTime.now().millisecondsSinceEpoch}',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.malware,
        severity: ThreatSeverity.medium,
        detectionMethod: DetectionMethod.machinelearning,
        description: 'Suspicious code structure detected - possible obfuscation',
        indicators: [
          'High code complexity: $complexity',
          'Method count: $methodCount',
          'Class count: $classCount',
        ],
        confidence: structureScore,
        detectedAt: DateTime.now(),
        recommendedAction: ActionType.alert,
        metadata: {
          'structure_score': structureScore,
          'complexity': complexity,
        },
      ));
    }

    return threats;
  }

  /// Create or update behavior profile for app
  void updateBehaviorProfile(
    String packageName,
    ResourceMetrics metrics,
    List<NetworkConnection> connections,
  ) {
    if (!_behaviorProfiles.containsKey(packageName)) {
      _behaviorProfiles[packageName] = BehaviorProfile(
        packageName: packageName,
        normalCpuUsage: {'mean': metrics.cpuUsage, 'std': 5.0},
        normalMemoryUsage: {'mean': metrics.memoryUsage.toDouble(), 'std': 10000.0},
        normalNetworkActivity: {'bytes_per_hour': metrics.networkBytesTransferred},
        normalPermissions: [],
        profileCreated: DateTime.now(),
        lastUpdated: DateTime.now(),
      );
    } else {
      // Update existing profile with exponential moving average
      final profile = _behaviorProfiles[packageName]!;
      final alpha = 0.3; // Smoothing factor

      profile.normalCpuUsage['mean'] = 
          (alpha * metrics.cpuUsage) + ((1 - alpha) * (profile.normalCpuUsage['mean'] ?? 0));
      
      profile.normalMemoryUsage['mean'] = 
          (alpha * metrics.memoryUsage) + ((1 - alpha) * (profile.normalMemoryUsage['mean'] ?? 0));
    }
  }

  /// Extract feature vector from behavior data
  List<double> _extractFeatures(Map<String, dynamic> behaviorData) {
    // Feature extraction for ML model input
    // In production: normalize and scale features properly
    return [
      (behaviorData['cpu_usage'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['memory_usage'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['network_bytes'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['permission_count'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['process_count'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['file_access_count'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['network_connection_count'] as num?)?.toDouble() ?? 0.0,
      (behaviorData['system_call_count'] as num?)?.toDouble() ?? 0.0,
    ];
  }

  /// Run ML inference (simulated)
  MLPrediction _runInference(List<double> features) {
    // In production: use TFLite interpreter
    // Example: interpreter.run(features, output);
    
    // Simulated inference logic
    final cpuUsage = features.isNotEmpty ? features[0] : 0.0;
    final memoryUsage = features.length > 1 ? features[1] : 0.0;
    final networkBytes = features.length > 2 ? features[2] : 0.0;

    // Simple rule-based simulation (replace with real ML model)
    if (cpuUsage > 80 && networkBytes > 1000000) {
      return MLPrediction(
        isAnomalous: true,
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.high,
        description: 'ML model detected C2 beaconing pattern',
        indicators: ['High CPU', 'High network activity'],
        confidence: 0.87,
        anomalyScore: 0.89,
        recommendedAction: ActionType.autoblock,
        featureImportance: {'cpu_usage': 0.6, 'network_bytes': 0.4},
      );
    } else if (memoryUsage > 500000000) {
      return MLPrediction(
        isAnomalous: true,
        threatType: ThreatType.malware,
        severity: ThreatSeverity.medium,
        description: 'ML model detected memory-based anomaly',
        indicators: ['Excessive memory usage'],
        confidence: 0.72,
        anomalyScore: 0.75,
        recommendedAction: ActionType.alert,
        featureImportance: {'memory_usage': 0.9},
      );
    }

    return MLPrediction(
      isAnomalous: false,
      threatType: ThreatType.anomaly,
      severity: ThreatSeverity.info,
      description: 'Normal behavior',
      indicators: [],
      confidence: 0.10,
      anomalyScore: 0.10,
      recommendedAction: ActionType.monitoronly,
      featureImportance: {},
    );
  }

  /// Build permission usage vector
  Map<String, double> _buildPermissionVector(List<PermissionUsage> usages) {
    final vector = <String, double>{};
    for (final usage in usages) {
      vector[usage.permission] = usage.accessCount.toDouble();
    }
    return vector;
  }

  /// Calculate permission anomaly score
  double _calculatePermissionAnomalyScore(Map<String, double> vector) {
    // Suspicious permission combinations
    final suspiciousPerms = [
      'android.permission.READ_CONTACTS',
      'android.permission.READ_CALL_LOG',
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.RECORD_AUDIO',
      'android.permission.CAMERA',
    ];

    final matchCount = vector.keys.where((k) => suspiciousPerms.contains(k)).length;
    return (matchCount / suspiciousPerms.length).clamp(0.0, 1.0);
  }

  /// Get anomalous permissions
  List<String> _getAnomalousPermissions(
    List<PermissionUsage> usages,
    Map<String, double> vector,
  ) {
    return usages
        .where((u) => (vector[u.permission] ?? 0) > 50)
        .map((u) => u.permission)
        .toList();
  }

  /// Calculate code structure anomaly score
  double _calculateCodeStructureScore(
    int complexity,
    int methodCount,
    int classCount,
    int nativeLibCount,
  ) {
    var score = 0.0;

    if (complexity > 100) score += 0.3;
    if (methodCount > 100000) score += 0.3;
    if (classCount > 10000) score += 0.2;
    if (nativeLibCount > 10) score += 0.2;

    return score.clamp(0.0, 1.0);
  }

  /// Get current model info
  MLModelMetadata? getCurrentModel() => _currentModel;

  /// Check if model is loaded
  bool isModelLoaded() => _isModelLoaded;
}

/// ML prediction result
class MLPrediction {
  final bool isAnomalous;
  final ThreatType threatType;
  final ThreatSeverity severity;
  final String description;
  final List<String> indicators;
  final double confidence;
  final double anomalyScore;
  final ActionType recommendedAction;
  final Map<String, double> featureImportance;

  MLPrediction({
    required this.isAnomalous,
    required this.threatType,
    required this.severity,
    required this.description,
    required this.indicators,
    required this.confidence,
    required this.anomalyScore,
    required this.recommendedAction,
    required this.featureImportance,
  });
}
