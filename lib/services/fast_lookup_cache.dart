import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

/// Multi-layer caching system optimized for <20ms lookups
/// L1: In-memory LRU cache (instant access)
/// L2: Redis cache (network call, ~5-10ms)
/// L3: Persistent local cache (disk, ~10-20ms)
class FastLookupCache {
  // L1 Cache: In-memory LRU (hottest 10% of data)
  final _L1Cache<String, CachedHashResult> _hashCache;
  final _L1Cache<String, CachedIOCResult> _iocCache;
  
  // Cache statistics
  int _l1Hits = 0;
  int _l1Misses = 0;
  int _l2Hits = 0;
  int _l2Misses = 0;
  int _l3Hits = 0;
  int _l3Misses = 0;
  
  // Configuration
  final int _l1HashCapacity;
  final int _l1IOCCapacity;
  final Duration _defaultTTL;
  
  // Redis simulation (in production, use redis_client package)
  final Map<String, _CacheEntry> _l2Cache = {};
  
  // L3: Persistent local cache
  SharedPreferences? _prefs;
  
  FastLookupCache({
    int l1HashCapacity = 10000, // Top 10% hottest hashes
    int l1IOCCapacity = 50000, // Top 10% hottest IOCs
    Duration defaultTTL = const Duration(hours: 24),
  })  : _l1HashCapacity = l1HashCapacity,
        _l1IOCCapacity = l1IOCCapacity,
        _defaultTTL = defaultTTL,
        _hashCache = _L1Cache<String, CachedHashResult>(capacity: l1HashCapacity),
        _iocCache = _L1Cache<String, CachedIOCResult>(capacity: l1IOCCapacity);
  
  /// Initialize persistent cache
  Future<void> initialize() async {
    _prefs = await SharedPreferences.getInstance();
    await _warmupCache();
  }
  
  /// Warmup L1 cache with most frequently accessed items
  Future<void> _warmupCache() async {
    if (_prefs == null) return;
    
    // Load top accessed hashes from persistent storage
    final topHashesJson = _prefs!.getString('cache_warmup_hashes');
    if (topHashesJson != null) {
      final topHashes = jsonDecode(topHashesJson) as List;
      for (var item in topHashes) {
        final hash = item['hash'] as String;
        final cached = await _getFromL3Hash(hash);
        if (cached != null && !cached.isExpired) {
          _hashCache.put(hash, cached);
        }
      }
    }
    
    // Load top accessed IOCs
    final topIOCsJson = _prefs!.getString('cache_warmup_iocs');
    if (topIOCsJson != null) {
      final topIOCs = jsonDecode(topIOCsJson) as List;
      for (var item in topIOCs) {
        final ioc = item['ioc'] as String;
        final cached = await _getFromL3IOC(ioc);
        if (cached != null && !cached.isExpired) {
          _iocCache.put(ioc, cached);
        }
      }
    }
  }
  
  /// Get hash result with multi-layer lookup
  /// Returns (result, cacheLevel) where level is 'L1', 'L2', 'L3', or null
  Future<(CachedHashResult?, String?)> getHash(String hash) async {
    // L1: In-memory LRU (instant)
    final l1Result = _hashCache.get(hash);
    if (l1Result != null && !l1Result.isExpired) {
      _l1Hits++;
      return (l1Result, 'L1');
    }
    _l1Misses++;
    
    // L2: Redis cache (~5-10ms)
    final l2Result = _getFromL2Hash(hash);
    if (l2Result != null && !l2Result.isExpired) {
      _l2Hits++;
      // Promote to L1
      _hashCache.put(hash, l2Result);
      return (l2Result, 'L2');
    }
    _l2Misses++;
    
    // L3: Persistent local cache (~10-20ms)
    final l3Result = await _getFromL3Hash(hash);
    if (l3Result != null && !l3Result.isExpired) {
      _l3Hits++;
      // Promote to L1 and L2
      _hashCache.put(hash, l3Result);
      _putToL2Hash(hash, l3Result);
      return (l3Result, 'L3');
    }
    _l3Misses++;
    
    return (null, null);
  }
  
  /// Put hash result into all cache layers
  Future<void> putHash(String hash, CachedHashResult result) async {
    // Update all layers
    _hashCache.put(hash, result);
    _putToL2Hash(hash, result);
    await _putToL3Hash(hash, result);
  }
  
  /// Batch get IOCs with multi-layer lookup
  Future<Map<String, CachedIOCResult>> batchGetIOCs(List<String> iocs) async {
    final results = <String, CachedIOCResult>{};
    final misses = <String>[];
    
    // Try L1 first for all IOCs
    for (var ioc in iocs) {
      final l1Result = _iocCache.get(ioc);
      if (l1Result != null && !l1Result.isExpired) {
        results[ioc] = l1Result;
        _l1Hits++;
      } else {
        misses.add(ioc);
        _l1Misses++;
      }
    }
    
    if (misses.isEmpty) return results;
    
    // Try L2 for misses
    final l2Misses = <String>[];
    for (var ioc in misses) {
      final l2Result = _getFromL2IOC(ioc);
      if (l2Result != null && !l2Result.isExpired) {
        results[ioc] = l2Result;
        _iocCache.put(ioc, l2Result); // Promote to L1
        _l2Hits++;
      } else {
        l2Misses.add(ioc);
        _l2Misses++;
      }
    }
    
    if (l2Misses.isEmpty) return results;
    
    // Try L3 for remaining misses
    for (var ioc in l2Misses) {
      final l3Result = await _getFromL3IOC(ioc);
      if (l3Result != null && !l3Result.isExpired) {
        results[ioc] = l3Result;
        _iocCache.put(ioc, l3Result); // Promote to L1
        _putToL2IOC(ioc, l3Result); // Promote to L2
        _l3Hits++;
      } else {
        _l3Misses++;
      }
    }
    
    return results;
  }
  
  /// Batch put IOCs into all cache layers
  Future<void> batchPutIOCs(Map<String, CachedIOCResult> iocs) async {
    for (var entry in iocs.entries) {
      _iocCache.put(entry.key, entry.value);
      _putToL2IOC(entry.key, entry.value);
    }
    
    // Batch write to L3
    await _batchPutToL3IOCs(iocs);
  }
  
  /// Invalidate cache entry
  Future<void> invalidateHash(String hash) async {
    _hashCache.remove(hash);
    _l2Cache.remove('hash:$hash');
    await _prefs?.remove('hash:$hash');
  }
  
  Future<void> invalidateIOC(String ioc) async {
    _iocCache.remove(ioc);
    _l2Cache.remove('ioc:$ioc');
    await _prefs?.remove('ioc:$ioc');
  }
  
  /// Invalidate expired entries (background cleanup)
  Future<void> cleanupExpired() async {
    // L1 cleanup (automatic via LRU eviction)
    
    // L2 cleanup
    final now = DateTime.now();
    _l2Cache.removeWhere((key, entry) => entry.expiresAt.isBefore(now));
    
    // L3 cleanup (scan for expired entries)
    if (_prefs != null) {
      final keys = _prefs!.getKeys();
      for (var key in keys) {
        if (key.startsWith('hash:') || key.startsWith('ioc:')) {
          final json = _prefs!.getString(key);
          if (json != null) {
            final data = jsonDecode(json);
            final expiresAt = DateTime.parse(data['expires_at'] as String);
            if (expiresAt.isBefore(now)) {
              await _prefs!.remove(key);
            }
          }
        }
      }
    }
  }
  
  /// Update cache warmup list based on access patterns
  Future<void> updateWarmupList() async {
    if (_prefs == null) return;
    
    // Get top accessed hashes from L1 (most frequently used)
    final topHashes = _hashCache.getAccessCounts()
        .entries
        .where((e) => e.value > 5) // Accessed more than 5 times
        .take(100) // Top 100
        .map((e) => {'hash': e.key, 'count': e.value})
        .toList();
    
    await _prefs!.setString('cache_warmup_hashes', jsonEncode(topHashes));
    
    // Get top accessed IOCs
    final topIOCs = _iocCache.getAccessCounts()
        .entries
        .where((e) => e.value > 5)
        .take(100)
        .map((e) => {'ioc': e.key, 'count': e.value})
        .toList();
    
    await _prefs!.setString('cache_warmup_iocs', jsonEncode(topIOCs));
  }
  
  /// Get cache statistics
  CacheStatistics getStatistics() {
    final totalL1 = _l1Hits + _l1Misses;
    final totalL2 = _l2Hits + _l2Misses;
    final totalL3 = _l3Hits + _l3Misses;
    
    return CacheStatistics(
      l1Hits: _l1Hits,
      l1Misses: _l1Misses,
      l1HitRate: totalL1 > 0 ? _l1Hits / totalL1 : 0.0,
      l1Size: _hashCache.size + _iocCache.size,
      l2Hits: _l2Hits,
      l2Misses: _l2Misses,
      l2HitRate: totalL2 > 0 ? _l2Hits / totalL2 : 0.0,
      l2Size: _l2Cache.length,
      l3Hits: _l3Hits,
      l3Misses: _l3Misses,
      l3HitRate: totalL3 > 0 ? _l3Hits / totalL3 : 0.0,
    );
  }
  
  // L2 Cache operations (Redis simulation)
  CachedHashResult? _getFromL2Hash(String hash) {
    final entry = _l2Cache['hash:$hash'];
    if (entry == null) return null;
    
    if (entry.expiresAt.isBefore(DateTime.now())) {
      _l2Cache.remove('hash:$hash');
      return null;
    }
    
    return CachedHashResult.fromJson(entry.data);
  }
  
  void _putToL2Hash(String hash, CachedHashResult result) {
    _l2Cache['hash:$hash'] = _CacheEntry(
      data: result.toJson(),
      expiresAt: result.expiresAt,
    );
  }
  
  CachedIOCResult? _getFromL2IOC(String ioc) {
    final entry = _l2Cache['ioc:$ioc'];
    if (entry == null) return null;
    
    if (entry.expiresAt.isBefore(DateTime.now())) {
      _l2Cache.remove('ioc:$ioc');
      return null;
    }
    
    return CachedIOCResult.fromJson(entry.data);
  }
  
  void _putToL2IOC(String ioc, CachedIOCResult result) {
    _l2Cache['ioc:$ioc'] = _CacheEntry(
      data: result.toJson(),
      expiresAt: result.expiresAt,
    );
  }
  
  // L3 Cache operations (persistent local storage)
  Future<CachedHashResult?> _getFromL3Hash(String hash) async {
    if (_prefs == null) return null;
    
    final json = _prefs!.getString('hash:$hash');
    if (json == null) return null;
    
    final data = jsonDecode(json);
    final result = CachedHashResult.fromJson(data);
    
    if (result.isExpired) {
      await _prefs!.remove('hash:$hash');
      return null;
    }
    
    return result;
  }
  
  Future<void> _putToL3Hash(String hash, CachedHashResult result) async {
    if (_prefs == null) return;
    await _prefs!.setString('hash:$hash', jsonEncode(result.toJson()));
  }
  
  Future<CachedIOCResult?> _getFromL3IOC(String ioc) async {
    if (_prefs == null) return null;
    
    final json = _prefs!.getString('ioc:$ioc');
    if (json == null) return null;
    
    final data = jsonDecode(json);
    final result = CachedIOCResult.fromJson(data);
    
    if (result.isExpired) {
      await _prefs!.remove('ioc:$ioc');
      return null;
    }
    
    return result;
  }
  
  Future<void> _batchPutToL3IOCs(Map<String, CachedIOCResult> iocs) async {
    if (_prefs == null) return;
    
    for (var entry in iocs.entries) {
      await _prefs!.setString('ioc:${entry.key}', jsonEncode(entry.value.toJson()));
    }
  }
}

/// LRU cache implementation with access tracking
class _L1Cache<K, V> {
  final int capacity;
  final LinkedHashMap<K, V> _cache = LinkedHashMap();
  final Map<K, int> _accessCounts = {};
  
  _L1Cache({required this.capacity});
  
  V? get(K key) {
    final value = _cache.remove(key);
    if (value != null) {
      _cache[key] = value; // Move to end (most recent)
      _accessCounts[key] = (_accessCounts[key] ?? 0) + 1;
    }
    return value;
  }
  
  void put(K key, V value) {
    _cache.remove(key);
    _cache[key] = value;
    _accessCounts[key] = (_accessCounts[key] ?? 0) + 1;
    
    if (_cache.length > capacity) {
      final oldest = _cache.keys.first;
      _cache.remove(oldest);
      // Keep access counts for warmup analysis
    }
  }
  
  void remove(K key) {
    _cache.remove(key);
  }
  
  int get size => _cache.length;
  
  Map<K, int> getAccessCounts() => Map.from(_accessCounts);
  
  void clear() {
    _cache.clear();
    _accessCounts.clear();
  }
}

/// Cached hash lookup result
class CachedHashResult {
  final String hash;
  final String verdict;
  final double confidence;
  final String? malwareFamily;
  final List<String> tags;
  final String source;
  final DateTime cachedAt;
  final DateTime expiresAt;
  
  CachedHashResult({
    required this.hash,
    required this.verdict,
    required this.confidence,
    this.malwareFamily,
    required this.tags,
    required this.source,
    required this.cachedAt,
    required this.expiresAt,
  });
  
  bool get isExpired => DateTime.now().isAfter(expiresAt);
  
  factory CachedHashResult.fromJson(Map<String, dynamic> json) {
    return CachedHashResult(
      hash: json['hash'] as String,
      verdict: json['verdict'] as String,
      confidence: (json['confidence'] as num).toDouble(),
      malwareFamily: json['malware_family'] as String?,
      tags: (json['tags'] as List).cast<String>(),
      source: json['source'] as String,
      cachedAt: DateTime.parse(json['cached_at'] as String),
      expiresAt: DateTime.parse(json['expires_at'] as String),
    );
  }
  
  Map<String, dynamic> toJson() {
    return {
      'hash': hash,
      'verdict': verdict,
      'confidence': confidence,
      'malware_family': malwareFamily,
      'tags': tags,
      'source': source,
      'cached_at': cachedAt.toIso8601String(),
      'expires_at': expiresAt.toIso8601String(),
    };
  }
}

/// Cached IOC result
class CachedIOCResult {
  final String ioc;
  final String type;
  final int reputation;
  final String latestSource;
  final DateTime cachedAt;
  final DateTime expiresAt;
  
  CachedIOCResult({
    required this.ioc,
    required this.type,
    required this.reputation,
    required this.latestSource,
    required this.cachedAt,
    required this.expiresAt,
  });
  
  bool get isExpired => DateTime.now().isAfter(expiresAt);
  
  factory CachedIOCResult.fromJson(Map<String, dynamic> json) {
    return CachedIOCResult(
      ioc: json['ioc'] as String,
      type: json['type'] as String,
      reputation: json['reputation'] as int,
      latestSource: json['latest_source'] as String,
      cachedAt: DateTime.parse(json['cached_at'] as String),
      expiresAt: DateTime.parse(json['expires_at'] as String),
    );
  }
  
  Map<String, dynamic> toJson() {
    return {
      'ioc': ioc,
      'type': type,
      'reputation': reputation,
      'latest_source': latestSource,
      'cached_at': cachedAt.toIso8601String(),
      'expires_at': expiresAt.toIso8601String(),
    };
  }
}

/// Internal cache entry
class _CacheEntry {
  final Map<String, dynamic> data;
  final DateTime expiresAt;
  
  _CacheEntry({
    required this.data,
    required this.expiresAt,
  });
}

/// Cache performance statistics
class CacheStatistics {
  final int l1Hits;
  final int l1Misses;
  final double l1HitRate;
  final int l1Size;
  
  final int l2Hits;
  final int l2Misses;
  final double l2HitRate;
  final int l2Size;
  
  final int l3Hits;
  final int l3Misses;
  final double l3HitRate;
  
  CacheStatistics({
    required this.l1Hits,
    required this.l1Misses,
    required this.l1HitRate,
    required this.l1Size,
    required this.l2Hits,
    required this.l2Misses,
    required this.l2HitRate,
    required this.l2Size,
    required this.l3Hits,
    required this.l3Misses,
    required this.l3HitRate,
  });
  
  double get overallHitRate {
    final totalHits = l1Hits + l2Hits + l3Hits;
    final totalRequests = totalHits + l3Misses;
    return totalRequests > 0 ? totalHits / totalRequests : 0.0;
  }
  
  @override
  String toString() {
    return '''
Cache Statistics:
  L1 (In-Memory): ${(l1HitRate * 100).toStringAsFixed(2)}% hit rate (${l1Hits}/${l1Hits + l1Misses}), size: $l1Size
  L2 (Redis): ${(l2HitRate * 100).toStringAsFixed(2)}% hit rate (${l2Hits}/${l2Hits + l2Misses}), size: $l2Size
  L3 (Disk): ${(l3HitRate * 100).toStringAsFixed(2)}% hit rate (${l3Hits}/${l3Hits + l3Misses})
  Overall: ${(overallHitRate * 100).toStringAsFixed(2)}% hit rate
''';
  }
}
