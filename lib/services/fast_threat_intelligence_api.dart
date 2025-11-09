import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

/// Fast API client for remote threat intelligence lookups
/// Optimized for <20ms p95 latency with Redis/Cassandra/Neo4j backends
class FastThreatIntelligenceAPI {
  final String baseUrl;
  final http.Client _httpClient;
  final Duration timeout;
  
  // Circuit breaker configuration
  int _failureCount = 0;
  DateTime? _circuitOpenTime;
  final int _failureThreshold = 5;
  final Duration _circuitResetDuration = Duration(seconds: 30);
  
  // Performance tracking
  final List<int> _latencies = [];
  int _totalRequests = 0;
  int _successfulRequests = 0;
  
  FastThreatIntelligenceAPI({
    required this.baseUrl,
    http.Client? httpClient,
    this.timeout = const Duration(milliseconds: 50), // Aggressive timeout for <20ms p95
  }) : _httpClient = httpClient ?? http.Client();
  
  /// On-device hash check: GET /v1/hashes/{sha256}
  /// Redis lookup with Scylla/Cassandra fallback
  /// Target: <20ms p95 latency
  Future<HashLookupResult?> lookupHash(String sha256) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .get(
            Uri.parse('$baseUrl/v1/hashes/$sha256'),
            headers: {
              'Accept': 'application/json',
              'X-Client-Version': '1.0',
            },
          )
          .timeout(timeout);
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body);
        return HashLookupResult.fromJson(data);
      } else if (response.statusCode == 404) {
        _recordSuccess();
        return null; // Hash not found (clean)
      } else {
        _recordFailure();
        throw ApiException('Hash lookup failed: ${response.statusCode}');
      }
    } on TimeoutException {
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      _recordFailure();
      throw ApiTimeoutException('Hash lookup timeout after ${timeout.inMilliseconds}ms');
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Batch IOC lookup: POST /v1/ioc/lookup
  /// Supports 50-500 items per request
  /// Returns reputation + TTL + latest_source
  Future<List<IOCLookupResult>> batchLookupIOCs(List<String> iocs) async {
    if (iocs.isEmpty) return [];
    if (iocs.length > 500) {
      throw ArgumentError('Batch size must be ≤500 items (got ${iocs.length})');
    }
    
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .post(
            Uri.parse('$baseUrl/v1/ioc/lookup'),
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
            body: jsonEncode({
              'iocs': iocs,
              'include_metadata': true,
            }),
          )
          .timeout(Duration(milliseconds: 100)); // Slightly higher timeout for batch
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final results = (data['results'] as List)
            .map((item) => IOCLookupResult.fromJson(item))
            .toList();
        return results;
      } else {
        _recordFailure();
        throw ApiException('IOC batch lookup failed: ${response.statusCode}');
      }
    } on TimeoutException {
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      _recordFailure();
      throw ApiTimeoutException('IOC batch lookup timeout');
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Get YARA rule by ID: GET /v1/yara/{rule_id}
  Future<YaraRule?> getYaraRule(String ruleId) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .get(
            Uri.parse('$baseUrl/v1/yara/$ruleId'),
            headers: {'Accept': 'application/json'},
          )
          .timeout(timeout);
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body);
        return YaraRule.fromJson(data);
      } else if (response.statusCode == 404) {
        _recordSuccess();
        return null;
      } else {
        _recordFailure();
        throw ApiException('YARA rule fetch failed: ${response.statusCode}');
      }
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Server-side YARA matching: POST /v1/yara/match
  /// For heavy rules that can't run on-device
  Future<YaraMatchResult> runYaraMatch(String fileHash, List<String> ruleIds) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .post(
            Uri.parse('$baseUrl/v1/yara/match'),
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
            body: jsonEncode({
              'file_hash': fileHash,
              'rule_ids': ruleIds,
            }),
          )
          .timeout(Duration(seconds: 2)); // Higher timeout for server-side scanning
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body);
        return YaraMatchResult.fromJson(data);
      } else {
        _recordFailure();
        throw ApiException('YARA match failed: ${response.statusCode}');
      }
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Graph traversal query: GET /v1/graph/neighbors
  /// For Neo4j/Neptune graph analysis in triage UI
  /// Example: ?node=domain:bad.example&depth=2
  Future<GraphQueryResult> getGraphNeighbors({
    required String node,
    int depth = 2,
    int limit = 100,
  }) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final queryParams = {
        'node': node,
        'depth': depth.toString(),
        'limit': limit.toString(),
      };
      
      final uri = Uri.parse('$baseUrl/v1/graph/neighbors')
          .replace(queryParameters: queryParams);
      
      final response = await _httpClient
          .get(
            uri,
            headers: {'Accept': 'application/json'},
          )
          .timeout(Duration(milliseconds: 200)); // Graph queries can be slower
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body);
        return GraphQueryResult.fromJson(data);
      } else {
        _recordFailure();
        throw ApiException('Graph query failed: ${response.statusCode}');
      }
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Fuzzy string search via ElasticSearch: POST /v1/search/strings
  Future<List<StringSearchResult>> fuzzySearchStrings(
    String query, {
    int limit = 50,
    double minScore = 0.7,
  }) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .post(
            Uri.parse('$baseUrl/v1/search/strings'),
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
            body: jsonEncode({
              'query': query,
              'limit': limit,
              'min_score': minScore,
              'fuzzy': true,
            }),
          )
          .timeout(Duration(milliseconds: 150));
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final results = (data['results'] as List)
            .map((item) => StringSearchResult.fromJson(item))
            .toList();
        return results;
      } else {
        _recordFailure();
        throw ApiException('String search failed: ${response.statusCode}');
      }
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  /// Code snippet search: POST /v1/search/code
  Future<List<CodeSearchResult>> searchCodeSnippets(
    String snippet, {
    int limit = 50,
  }) async {
    if (_isCircuitOpen()) {
      throw CircuitBreakerOpenException('Circuit breaker is open');
    }
    
    final stopwatch = Stopwatch()..start();
    
    try {
      final response = await _httpClient
          .post(
            Uri.parse('$baseUrl/v1/search/code'),
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
            body: jsonEncode({
              'snippet': snippet,
              'limit': limit,
            }),
          )
          .timeout(Duration(milliseconds: 150));
      
      stopwatch.stop();
      _recordLatency(stopwatch.elapsedMilliseconds);
      
      if (response.statusCode == 200) {
        _recordSuccess();
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final results = (data['results'] as List)
            .map((item) => CodeSearchResult.fromJson(item))
            .toList();
        return results;
      } else {
        _recordFailure();
        throw ApiException('Code search failed: ${response.statusCode}');
      }
    } catch (e) {
      stopwatch.stop();
      _recordFailure();
      rethrow;
    }
  }
  
  // Circuit breaker helpers
  bool _isCircuitOpen() {
    if (_circuitOpenTime == null) return false;
    
    if (DateTime.now().difference(_circuitOpenTime!) > _circuitResetDuration) {
      _circuitOpenTime = null;
      _failureCount = 0;
      return false;
    }
    
    return true;
  }
  
  void _recordSuccess() {
    _totalRequests++;
    _successfulRequests++;
    _failureCount = 0; // Reset on success
  }
  
  void _recordFailure() {
    _totalRequests++;
    _failureCount++;
    
    if (_failureCount >= _failureThreshold) {
      _circuitOpenTime = DateTime.now();
    }
  }
  
  void _recordLatency(int milliseconds) {
    _latencies.add(milliseconds);
    
    // Keep only last 1000 measurements
    if (_latencies.length > 1000) {
      _latencies.removeAt(0);
    }
  }
  
  /// Get performance statistics
  APIPerformanceStats getStats() {
    if (_latencies.isEmpty) {
      return APIPerformanceStats(
        totalRequests: _totalRequests,
        successfulRequests: _successfulRequests,
        failureRate: 0.0,
        p50Latency: 0,
        p95Latency: 0,
        p99Latency: 0,
        avgLatency: 0,
      );
    }
    
    final sorted = List<int>.from(_latencies)..sort();
    final p50Index = (sorted.length * 0.5).floor();
    final p95Index = (sorted.length * 0.95).floor();
    final p99Index = (sorted.length * 0.99).floor();
    
    final sum = sorted.reduce((a, b) => a + b);
    
    return APIPerformanceStats(
      totalRequests: _totalRequests,
      successfulRequests: _successfulRequests,
      failureRate: _totalRequests > 0 
          ? 1.0 - (_successfulRequests / _totalRequests) 
          : 0.0,
      p50Latency: sorted[p50Index],
      p95Latency: sorted[p95Index],
      p99Latency: sorted[p99Index],
      avgLatency: sum ~/ sorted.length,
    );
  }
  
  void dispose() {
    _httpClient.close();
  }
}

/// Hash lookup result from Redis/Cassandra
class HashLookupResult {
  final String hash;
  final String verdict; // 'malicious', 'suspicious', 'clean'
  final double confidence;
  final String? malwareFamily;
  final List<String> tags;
  final DateTime firstSeen;
  final DateTime lastSeen;
  final int ttl; // Cache TTL in seconds
  final String source; // 'virustotal', 'malwarebazaar', 'hybrid-analysis'
  
  HashLookupResult({
    required this.hash,
    required this.verdict,
    required this.confidence,
    this.malwareFamily,
    required this.tags,
    required this.firstSeen,
    required this.lastSeen,
    required this.ttl,
    required this.source,
  });
  
  factory HashLookupResult.fromJson(Map<String, dynamic> json) {
    return HashLookupResult(
      hash: json['hash'] as String,
      verdict: json['verdict'] as String,
      confidence: (json['confidence'] as num).toDouble(),
      malwareFamily: json['malware_family'] as String?,
      tags: (json['tags'] as List).cast<String>(),
      firstSeen: DateTime.parse(json['first_seen'] as String),
      lastSeen: DateTime.parse(json['last_seen'] as String),
      ttl: json['ttl'] as int,
      source: json['source'] as String,
    );
  }
  
  Map<String, dynamic> toJson() {
    return {
      'hash': hash,
      'verdict': verdict,
      'confidence': confidence,
      'malware_family': malwareFamily,
      'tags': tags,
      'first_seen': firstSeen.toIso8601String(),
      'last_seen': lastSeen.toIso8601String(),
      'ttl': ttl,
      'source': source,
    };
  }
}

/// IOC lookup result with reputation and metadata
class IOCLookupResult {
  final String ioc;
  final String type; // 'domain', 'ip', 'url', 'hash'
  final int reputation; // 0-100 (0=malicious, 100=clean)
  final int ttl; // Cache TTL
  final String latestSource;
  final DateTime lastUpdated;
  final Map<String, dynamic> metadata;
  
  IOCLookupResult({
    required this.ioc,
    required this.type,
    required this.reputation,
    required this.ttl,
    required this.latestSource,
    required this.lastUpdated,
    required this.metadata,
  });
  
  factory IOCLookupResult.fromJson(Map<String, dynamic> json) {
    return IOCLookupResult(
      ioc: json['ioc'] as String,
      type: json['type'] as String,
      reputation: json['reputation'] as int,
      ttl: json['ttl'] as int,
      latestSource: json['latest_source'] as String,
      lastUpdated: DateTime.parse(json['last_updated'] as String),
      metadata: json['metadata'] as Map<String, dynamic>,
    );
  }
}

/// YARA rule definition
class YaraRule {
  final String id;
  final String name;
  final String content;
  final String category;
  final List<String> tags;
  final DateTime createdAt;
  
  YaraRule({
    required this.id,
    required this.name,
    required this.content,
    required this.category,
    required this.tags,
    required this.createdAt,
  });
  
  factory YaraRule.fromJson(Map<String, dynamic> json) {
    return YaraRule(
      id: json['id'] as String,
      name: json['name'] as String,
      content: json['content'] as String,
      category: json['category'] as String,
      tags: (json['tags'] as List).cast<String>(),
      createdAt: DateTime.parse(json['created_at'] as String),
    );
  }
}

/// YARA match result from server-side scanning
class YaraMatchResult {
  final String fileHash;
  final List<String> matchedRules;
  final Map<String, List<String>> matchDetails; // rule_id -> matched strings
  final DateTime scannedAt;
  
  YaraMatchResult({
    required this.fileHash,
    required this.matchedRules,
    required this.matchDetails,
    required this.scannedAt,
  });
  
  factory YaraMatchResult.fromJson(Map<String, dynamic> json) {
    return YaraMatchResult(
      fileHash: json['file_hash'] as String,
      matchedRules: (json['matched_rules'] as List).cast<String>(),
      matchDetails: (json['match_details'] as Map<String, dynamic>).map(
        (k, v) => MapEntry(k, (v as List).cast<String>()),
      ),
      scannedAt: DateTime.parse(json['scanned_at'] as String),
    );
  }
}

/// Graph query result from Neo4j/Neptune
class GraphQueryResult {
  final String rootNode;
  final int depth;
  final List<GraphNode> nodes;
  final List<GraphEdge> edges;
  
  GraphQueryResult({
    required this.rootNode,
    required this.depth,
    required this.nodes,
    required this.edges,
  });
  
  factory GraphQueryResult.fromJson(Map<String, dynamic> json) {
    return GraphQueryResult(
      rootNode: json['root_node'] as String,
      depth: json['depth'] as int,
      nodes: (json['nodes'] as List)
          .map((n) => GraphNode.fromJson(n))
          .toList(),
      edges: (json['edges'] as List)
          .map((e) => GraphEdge.fromJson(e))
          .toList(),
    );
  }
}

class GraphNode {
  final String id;
  final String type; // 'domain', 'ip', 'hash', 'malware_family', 'apt_group'
  final Map<String, dynamic> properties;
  
  GraphNode({
    required this.id,
    required this.type,
    required this.properties,
  });
  
  factory GraphNode.fromJson(Map<String, dynamic> json) {
    return GraphNode(
      id: json['id'] as String,
      type: json['type'] as String,
      properties: json['properties'] as Map<String, dynamic>,
    );
  }
}

class GraphEdge {
  final String source;
  final String target;
  final String relationship; // 'communicates_with', 'belongs_to', 'similar_to'
  final Map<String, dynamic> properties;
  
  GraphEdge({
    required this.source,
    required this.target,
    required this.relationship,
    required this.properties,
  });
  
  factory GraphEdge.fromJson(Map<String, dynamic> json) {
    return GraphEdge(
      source: json['source'] as String,
      target: json['target'] as String,
      relationship: json['relationship'] as String,
      properties: json['properties'] as Map<String, dynamic>,
    );
  }
}

/// String search result from ElasticSearch
class StringSearchResult {
  final String value;
  final double score;
  final String category;
  final List<String> relatedHashes;
  
  StringSearchResult({
    required this.value,
    required this.score,
    required this.category,
    required this.relatedHashes,
  });
  
  factory StringSearchResult.fromJson(Map<String, dynamic> json) {
    return StringSearchResult(
      value: json['value'] as String,
      score: (json['score'] as num).toDouble(),
      category: json['category'] as String,
      relatedHashes: (json['related_hashes'] as List).cast<String>(),
    );
  }
}

/// Code search result
class CodeSearchResult {
  final String snippet;
  final double similarity;
  final List<String> matchedHashes;
  final String malwareFamily;
  
  CodeSearchResult({
    required this.snippet,
    required this.similarity,
    required this.matchedHashes,
    required this.malwareFamily,
  });
  
  factory CodeSearchResult.fromJson(Map<String, dynamic> json) {
    return CodeSearchResult(
      snippet: json['snippet'] as String,
      similarity: (json['similarity'] as num).toDouble(),
      matchedHashes: (json['matched_hashes'] as List).cast<String>(),
      malwareFamily: json['malware_family'] as String,
    );
  }
}

/// API performance statistics
class APIPerformanceStats {
  final int totalRequests;
  final int successfulRequests;
  final double failureRate;
  final int p50Latency; // ms
  final int p95Latency; // ms
  final int p99Latency; // ms
  final int avgLatency; // ms
  
  APIPerformanceStats({
    required this.totalRequests,
    required this.successfulRequests,
    required this.failureRate,
    required this.p50Latency,
    required this.p95Latency,
    required this.p99Latency,
    required this.avgLatency,
  });
  
  @override
  String toString() {
    return 'APIStats(total: $totalRequests, success: $successfulRequests, '
           'failure_rate: ${(failureRate * 100).toStringAsFixed(2)}%, '
           'p50: ${p50Latency}ms, p95: ${p95Latency}ms, p99: ${p99Latency}ms, '
           'avg: ${avgLatency}ms)';
  }
}

/// Custom exceptions
class ApiException implements Exception {
  final String message;
  ApiException(this.message);
  
  @override
  String toString() => 'ApiException: $message';
}

class ApiTimeoutException implements Exception {
  final String message;
  ApiTimeoutException(this.message);
  
  @override
  String toString() => 'ApiTimeoutException: $message';
}

class CircuitBreakerOpenException implements Exception {
  final String message;
  CircuitBreakerOpenException(this.message);
  
  @override
  String toString() => 'CircuitBreakerOpenException: $message';
}
