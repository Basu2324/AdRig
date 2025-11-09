import 'dart:math' as math;
import 'package:adrig/core/models/threat_model.dart';

/// Advanced ML Detection Engine with Feature-Based Classification
/// Uses ensemble models and graph-based anomaly detection
class AdvancedMLEngine {
  // Model weights (would be loaded from trained models in production)
  final Map<String, double> _featureWeights = {};
  
  // Training data statistics (for normalization)
  final Map<String, FeatureStats> _featureStats = {};
  
  // Graph database for behavioral patterns
  final Map<String, AppBehaviorGraph> _behaviorGraphs = {};
  
  /// Initialize ML engine with pre-trained weights
  Future<void> initialize() async {
    print('🧠 Initializing Advanced ML Engine...');
    
    // Load feature weights (simulated - in production: load from .tflite model)
    _loadFeatureWeights();
    
    // Load normalization statistics
    _loadFeatureStatistics();
    
    print('✅ ML Engine initialized with 50+ features');
  }
  
  /// Extract comprehensive feature vector (50+ features)
  Future<List<double>> extractFeatures({
    required String packageName,
    required List<String> permissions,
    required Map<String, dynamic> staticAnalysis,
    required Map<String, dynamic> behavioralData,
    required List<String> networkDomains,
  }) async {
    final features = <double>[];
    
    // ==================== PERMISSION FEATURES (15) ====================
    features.add(_hasPermission(permissions, 'INTERNET') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'ACCESS_FINE_LOCATION') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'READ_CONTACTS') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'READ_SMS') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'SEND_SMS') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'CAMERA') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'RECORD_AUDIO') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'WRITE_EXTERNAL_STORAGE') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'BIND_ACCESSIBILITY_SERVICE') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'SYSTEM_ALERT_WINDOW') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'REQUEST_INSTALL_PACKAGES') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'BIND_DEVICE_ADMIN') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'READ_CALL_LOG') ? 1.0 : 0.0);
    features.add(_hasPermission(permissions, 'PROCESS_OUTGOING_CALLS') ? 1.0 : 0.0);
    features.add(permissions.length.toDouble()); // Total permission count
    
    // ==================== CODE STRUCTURE FEATURES (10) ====================
    features.add((staticAnalysis['method_count'] as int? ?? 0).toDouble());
    features.add((staticAnalysis['class_count'] as int? ?? 0).toDouble());
    features.add((staticAnalysis['string_count'] as int? ?? 0).toDouble());
    features.add((staticAnalysis['native_lib_count'] as int? ?? 0).toDouble());
    features.add((staticAnalysis['dex_count'] as int? ?? 1).toDouble());
    features.add((staticAnalysis['app_size_mb'] as double? ?? 0.0));
    features.add((staticAnalysis['obfuscation_ratio'] as double? ?? 0.0));
    features.add((staticAnalysis['entropy'] as double? ?? 0.0));
    features.add((staticAnalysis['hidden_files_count'] as int? ?? 0).toDouble());
    features.add((staticAnalysis['suspicious_strings'] as int? ?? 0).toDouble());
    
    // ==================== API CALL FEATURES (10) ====================
    final apiCalls = staticAnalysis['api_calls'] as List<String>? ?? [];
    features.add(_containsAPI(apiCalls, 'Runtime.exec') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'ProcessBuilder') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'DexClassLoader') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'Class.forName') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'Method.invoke') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'Cipher') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'HttpURLConnection') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'Socket') ? 1.0 : 0.0);
    features.add(_containsAPI(apiCalls, 'SmsManager') ? 1.0 : 0.0);
    features.add(apiCalls.length.toDouble());
    
    // ==================== BEHAVIORAL FEATURES (8) ====================
    features.add((behavioralData['cpu_usage'] as double? ?? 0.0));
    features.add((behavioralData['memory_mb'] as double? ?? 0.0));
    features.add((behavioralData['network_kb'] as double? ?? 0.0));
    features.add((behavioralData['process_count'] as int? ?? 0).toDouble());
    features.add((behavioralData['background_starts'] as int? ?? 0).toDouble());
    features.add((behavioralData['permission_requests'] as int? ?? 0).toDouble());
    features.add((behavioralData['file_modifications'] as int? ?? 0).toDouble());
    features.add((behavioralData['network_connections'] as int? ?? 0).toDouble());
    
    // ==================== NETWORK FEATURES (7) ====================
    features.add(networkDomains.length.toDouble());
    features.add(_hasSuspiciousTLD(networkDomains) ? 1.0 : 0.0);
    features.add(_hasDGADomain(networkDomains) ? 1.0 : 0.0);
    features.add(_hasIPAddress(networkDomains) ? 1.0 : 0.0);
    features.add(_hasOnionDomain(networkDomains) ? 1.0 : 0.0);
    features.add(_calculateDomainEntropy(networkDomains));
    features.add(_countUniqueDomains(networkDomains).toDouble());
    
    return features;
  }
  
  /// Run ensemble prediction (Random Forest + Gradient Boosting + Neural Network)
  Future<MLClassificationResult> classifyMalware(List<double> features) async {
    // Normalize features
    final normalizedFeatures = _normalizeFeatures(features);
    
    // Ensemble predictions
    final rfScore = await _randomForestPredict(normalizedFeatures);
    final gbScore = await _gradientBoostingPredict(normalizedFeatures);
    final nnScore = await _neuralNetworkPredict(normalizedFeatures);
    
    // Weighted ensemble (RF: 40%, GB: 35%, NN: 25%)
    final ensembleScore = (rfScore * 0.40) + (gbScore * 0.35) + (nnScore * 0.25);
    
    // Calculate confidence
    final modelAgreement = _calculateModelAgreement([rfScore, gbScore, nnScore]);
    final confidence = math.min(1.0, ensembleScore.abs() * modelAgreement);
    
    // Determine threat level
    final isMalware = ensembleScore >= 0.5;
    final threatProbability = ensembleScore;
    
    ThreatSeverity severity;
    if (threatProbability >= 0.90) {
      severity = ThreatSeverity.critical;
    } else if (threatProbability >= 0.75) {
      severity = ThreatSeverity.high;
    } else if (threatProbability >= 0.50) {
      severity = ThreatSeverity.medium;
    } else {
      severity = ThreatSeverity.low;
    }
    
    // Get top contributing features
    final topFeatures = _getTopFeatures(features, normalizedFeatures);
    
    return MLClassificationResult(
      isMalware: isMalware,
      threatProbability: threatProbability,
      confidence: confidence,
      severity: severity,
      modelScores: {
        'random_forest': rfScore,
        'gradient_boosting': gbScore,
        'neural_network': nnScore,
        'ensemble': ensembleScore,
      },
      topFeatures: topFeatures,
    );
  }
  
  /// Graph-based anomaly detection
  Future<GraphAnomalyScore> detectGraphAnomalies(String packageName) async {
    // Build or retrieve behavior graph
    final graph = _behaviorGraphs.putIfAbsent(
      packageName,
      () => AppBehaviorGraph(packageName: packageName),
    );
    
    // Analyze graph properties
    final nodeCount = graph.nodes.length;
    final edgeCount = graph.edges.length;
    final avgDegree = edgeCount / math.max(1, nodeCount);
    
    // Detect suspicious patterns
    final anomalies = <String>[];
    double anomalyScore = 0.0;
    
    // Pattern 1: Excessive fan-out (one app connecting to many domains)
    if (avgDegree > 50) {
      anomalies.add('Excessive network fan-out (${avgDegree.toInt()} connections)');
      anomalyScore += 0.3;
    }
    
    // Pattern 2: Isolated subgraphs (hidden C2 communication)
    final subgraphs = _findSubgraphs(graph);
    if (subgraphs.length > 5) {
      anomalies.add('Multiple isolated communication channels (${subgraphs.length})');
      anomalyScore += 0.2;
    }
    
    // Pattern 3: Unusual graph density
    final density = (2.0 * edgeCount) / math.max(1, nodeCount * (nodeCount - 1));
    if (density > 0.8 || density < 0.1) {
      anomalies.add('Abnormal graph density: ${(density * 100).toInt()}%');
      anomalyScore += 0.2;
    }
    
    // Pattern 4: High centrality nodes (critical infrastructure abuse)
    final highCentralityNodes = _findHighCentralityNodes(graph);
    if (highCentralityNodes.isNotEmpty) {
      anomalies.add('Critical infrastructure connections: ${highCentralityNodes.join(", ")}');
      anomalyScore += 0.3;
    }
    
    return GraphAnomalyScore(
      packageName: packageName,
      anomalyScore: math.min(1.0, anomalyScore),
      detectedPatterns: anomalies,
      graphMetrics: {
        'nodes': nodeCount,
        'edges': edgeCount,
        'avg_degree': avgDegree,
        'density': density,
        'subgraphs': subgraphs.length,
      },
    );
  }
  
  // ==================== HELPER METHODS ====================
  
  bool _hasPermission(List<String> permissions, String permission) {
    return permissions.any((p) => p.contains(permission));
  }
  
  bool _containsAPI(List<String> apis, String api) {
    return apis.any((a) => a.contains(api));
  }
  
  bool _hasSuspiciousTLD(List<String> domains) {
    final suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc'];
    return domains.any((d) => suspiciousTLDs.any((tld) => d.endsWith(tld)));
  }
  
  bool _hasDGADomain(List<String> domains) {
    // Simple DGA detection: high entropy, random-looking domains
    return domains.any((d) {
      final entropy = _calculateStringEntropy(d);
      return entropy > 3.5 && d.length > 15;
    });
  }
  
  bool _hasIPAddress(List<String> domains) {
    return domains.any((d) => RegExp(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$').hasMatch(d));
  }
  
  bool _hasOnionDomain(List<String> domains) {
    return domains.any((d) => d.endsWith('.onion'));
  }
  
  double _calculateDomainEntropy(List<String> domains) {
    if (domains.isEmpty) return 0.0;
    final avgEntropy = domains.map(_calculateStringEntropy).reduce((a, b) => a + b) / domains.length;
    return avgEntropy / 5.0; // Normalize to 0-1
  }
  
  double _calculateStringEntropy(String str) {
    if (str.isEmpty) return 0.0;
    
    final freq = <String, int>{};
    for (final char in str.split('')) {
      freq[char] = (freq[char] ?? 0) + 1;
    }
    
    double entropy = 0.0;
    for (final count in freq.values) {
      final p = count / str.length;
      entropy -= p * math.log(p) / math.ln2;
    }
    
    return entropy;
  }
  
  int _countUniqueDomains(List<String> domains) {
    return domains.toSet().length;
  }
  
  List<double> _normalizeFeatures(List<double> features) {
    // Min-max normalization to 0-1 range
    return features.asMap().entries.map((entry) {
      final idx = entry.key;
      final value = entry.value;
      
      if (!_featureStats.containsKey('feature_$idx')) {
        return value; // No stats available
      }
      
      final stats = _featureStats['feature_$idx']!;
      final range = stats.max - stats.min;
      
      if (range == 0) return 0.0;
      return (value - stats.min) / range;
    }).toList();
  }
  
  Future<double> _randomForestPredict(List<double> features) async {
    // Simulated Random Forest (in production: use real TFLite model)
    // Decision tree ensemble averaging
    double score = 0.0;
    
    // Tree 1: Permission-based
    if (features[8] > 0.5) score += 0.3; // Accessibility service
    if (features[9] > 0.5) score += 0.2; // System alert window
    if (features[11] > 0.5) score += 0.2; // Device admin
    
    // Tree 2: API-based
    if (features[25] > 0.5) score += 0.2; // Runtime.exec
    if (features[28] > 0.5) score += 0.15; // Reflection
    
    // Tree 3: Behavioral
    if (features[35] > 0.7) score += 0.15; // High CPU
    
    return math.min(1.0, score);
  }
  
  Future<double> _gradientBoostingPredict(List<double> features) async {
    // Simulated Gradient Boosting
    double score = 0.5; // Base score
    
    // Boosting iterations
    if (features[14] > 10) score += 0.1; // Many permissions
    if (features[21] > 0.8) score += 0.15; // High obfuscation
    if (features[46] > 0.5) score += 0.1; // Suspicious TLD
    if (features[47] > 0.5) score += 0.15; // DGA domain
    
    return math.min(1.0, score);
  }
  
  Future<double> _neuralNetworkPredict(List<double> features) async {
    // Simulated Neural Network (3 layers)
    // In production: load real trained weights
    
    // Input layer -> Hidden layer 1 (32 neurons)
    final hidden1 = _applyDenseLayer(features, 32);
    
    // Hidden layer 1 -> Hidden layer 2 (16 neurons)
    final hidden2 = _applyDenseLayer(hidden1, 16);
    
    // Hidden layer 2 -> Output (1 neuron with sigmoid)
    final output = _applyDenseLayer(hidden2, 1);
    
    return _sigmoid(output[0]);
  }
  
  List<double> _applyDenseLayer(List<double> input, int neurons) {
    // Simplified dense layer (would use real weights in production)
    final output = <double>[];
    for (var i = 0; i < neurons; i++) {
      double sum = input.fold<double>(0.0, (a, b) => a + b) / input.length;
      output.add(_relu(sum));
    }
    return output;
  }
  
  double _relu(double x) => math.max(0.0, x);
  
  double _sigmoid(double x) => 1.0 / (1.0 + math.exp(-x));
  
  double _calculateModelAgreement(List<double> scores) {
    final mean = scores.reduce((a, b) => a + b) / scores.length;
    final variance = scores.map((s) => math.pow(s - mean, 2)).reduce((a, b) => a + b) / scores.length;
    final stdDev = math.sqrt(variance);
    
    // Low std dev = high agreement
    return 1.0 - math.min(1.0, stdDev);
  }
  
  List<String> _getTopFeatures(List<double> raw, List<double> normalized) {
    final featureNames = _getFeatureNames();
    final scored = <Map<String, dynamic>>[];
    
    for (var i = 0; i < normalized.length; i++) {
      if (normalized[i] > 0.5) {
        scored.add({
          'name': featureNames[i],
          'value': raw[i],
          'weight': _featureWeights['feature_$i'] ?? 0.5,
        });
      }
    }
    
    scored.sort((a, b) => (b['weight'] as double).compareTo(a['weight'] as double));
    
    return scored.take(5).map((f) => f['name'] as String).toList();
  }
  
  List<String> _getFeatureNames() {
    return [
      'INTERNET', 'LOCATION', 'CONTACTS', 'READ_SMS', 'SEND_SMS',
      'CAMERA', 'RECORD_AUDIO', 'WRITE_STORAGE', 'ACCESSIBILITY', 'ALERT_WINDOW',
      'INSTALL_PACKAGES', 'DEVICE_ADMIN', 'CALL_LOG', 'OUTGOING_CALLS', 'Permission Count',
      'Method Count', 'Class Count', 'String Count', 'Native Libs', 'DEX Count',
      'App Size', 'Obfuscation', 'Entropy', 'Hidden Files', 'Suspicious Strings',
      'Runtime.exec', 'ProcessBuilder', 'DexClassLoader', 'Class.forName', 'Method.invoke',
      'Cipher', 'HttpURLConnection', 'Socket', 'SmsManager', 'API Count',
      'CPU Usage', 'Memory', 'Network', 'Processes', 'Background Starts',
      'Permission Requests', 'File Mods', 'Net Connections', 'Domain Count',
      'Suspicious TLD', 'DGA Domain', 'IP Address', 'Onion Domain', 'Domain Entropy', 'Unique Domains',
    ];
  }
  
  void _loadFeatureWeights() {
    // Simulated feature importance from trained model
    for (var i = 0; i < 50; i++) {
      _featureWeights['feature_$i'] = 0.5 + (i % 10) / 20.0;
    }
  }
  
  void _loadFeatureStatistics() {
    // Simulated statistics from training data
    for (var i = 0; i < 50; i++) {
      _featureStats['feature_$i'] = FeatureStats(
        min: 0.0,
        max: i < 15 ? 1.0 : (i < 35 ? 10000.0 : 100.0),
        mean: i < 15 ? 0.3 : (i < 35 ? 5000.0 : 10.0),
        stdDev: 0.2,
      );
    }
  }
  
  List<List<GraphNode>> _findSubgraphs(AppBehaviorGraph graph) {
    // Simple subgraph detection (would use proper graph algorithms)
    return []; // Placeholder
  }
  
  List<String> _findHighCentralityNodes(AppBehaviorGraph graph) {
    // Detect nodes with high betweenness centrality
    return []; // Placeholder
  }
}

// ==================== DATA CLASSES ====================

class MLClassificationResult {
  final bool isMalware;
  final double threatProbability;
  final double confidence;
  final ThreatSeverity severity;
  final Map<String, double> modelScores;
  final List<String> topFeatures;
  
  MLClassificationResult({
    required this.isMalware,
    required this.threatProbability,
    required this.confidence,
    required this.severity,
    required this.modelScores,
    required this.topFeatures,
  });
}

class GraphAnomalyScore {
  final String packageName;
  final double anomalyScore;
  final List<String> detectedPatterns;
  final Map<String, dynamic> graphMetrics;
  
  GraphAnomalyScore({
    required this.packageName,
    required this.anomalyScore,
    required this.detectedPatterns,
    required this.graphMetrics,
  });
}

class FeatureStats {
  final double min;
  final double max;
  final double mean;
  final double stdDev;
  
  FeatureStats({
    required this.min,
    required this.max,
    required this.mean,
    required this.stdDev,
  });
}

class AppBehaviorGraph {
  final String packageName;
  final List<GraphNode> nodes = [];
  final List<GraphEdge> edges = [];
  
  AppBehaviorGraph({required this.packageName});
}

class GraphNode {
  final String id;
  final String type; // 'app', 'domain', 'ip', 'service'
  final Map<String, dynamic> attributes;
  
  GraphNode({
    required this.id,
    required this.type,
    this.attributes = const {},
  });
}

class GraphEdge {
  final String from;
  final String to;
  final String relationship; // 'connects_to', 'requests', 'exfiltrates_to'
  final double weight;
  
  GraphEdge({
    required this.from,
    required this.to,
    required this.relationship,
    this.weight = 1.0,
  });
}
