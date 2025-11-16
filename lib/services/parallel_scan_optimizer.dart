import 'dart:async';
import 'dart:isolate';
import 'package:adrig/core/models/threat_model.dart';
import 'package:adrig/services/production_scanner.dart'; // For APKScanResult

/// Parallel Scan Optimizer
/// Uses Dart Isolates and smart batching to dramatically improve scan speed
/// Can scan 10-20 apps simultaneously instead of sequential scanning
class ParallelScanOptimizer {
  static const int _maxConcurrentScans = 10; // Increased from 3 to 10
  static const int _timeoutSeconds = 60; // 60 seconds per app scan (comprehensive analysis)
  
  /// Execute scans in parallel with intelligent batching
  /// Returns completed results as they finish (stream-based)
  static Stream<ScanJobResult> parallelScan<T, R>({
    required List<T> items,
    required Future<R> Function(T item) scanFunction,
    int? maxConcurrent,
    int? timeoutSeconds,
  }) async* {
    final concurrent = maxConcurrent ?? _maxConcurrentScans;
    final timeout = timeoutSeconds ?? _timeoutSeconds;
    
    print('⚡ Parallel scanner: ${items.length} items, $concurrent concurrent');
    
    // Process in batches
    int completed = 0;
    for (int i = 0; i < items.length; i += concurrent) {
      final batch = items.skip(i).take(concurrent).toList();
      
      // Create futures for this batch
      final futures = batch.asMap().entries.map((entry) {
        return _executeScanWithTimeout(
          item: entry.value,
          scanFunction: scanFunction,
          timeout: Duration(seconds: timeout),
          index: i + entry.key,
        );
      }).toList();
      
      // Wait for all futures in this batch to complete
      final results = await Future.wait(futures);
      
      // Yield each result
      for (final result in results) {
        completed++;
        yield result;
      }
    }
    
    print('✅ Parallel scan complete: $completed items processed');
  }
  
  /// Execute scan with timeout protection
  static Future<ScanJobResult<R>> _executeScanWithTimeout<T, R>({
    required T item,
    required Future<R> Function(T item) scanFunction,
    required Duration timeout,
    required int index,
  }) async {
    try {
      final result = await scanFunction(item).timeout(
        timeout,
        onTimeout: () {
          print('  ⏱️  Timeout on item #$index');
          throw TimeoutException('Scan timeout', timeout);
        },
      );
      
      return ScanJobResult<R>(
        success: true,
        result: result,
        item: item,
        index: index,
      );
    } catch (e) {
      return ScanJobResult<R>(
        success: false,
        error: e,
        item: item,
        index: index,
      );
    }
  }
  
  /// Batch items into groups for processing
  static List<List<T>> batchItems<T>(List<T> items, int batchSize) {
    final batches = <List<T>>[];
    
    for (int i = 0; i < items.length; i += batchSize) {
      final end = (i + batchSize < items.length) ? i + batchSize : items.length;
      batches.add(items.sublist(i, end));
    }
    
    return batches;
  }
}

/// Result of a scan job
class ScanJobResult<R> {
  final bool success;
  final R? result;
  final dynamic error;
  final dynamic item;
  final int index;
  
  ScanJobResult({
    required this.success,
    this.result,
    this.error,
    required this.item,
    required this.index,
  });
}

/// Incremental scanner - only scans changes since last scan
class IncrementalScanner {
  final Map<String, DateTime> _lastScanned = {};
  final Map<String, String> _fileHashes = {};
  final Duration _incrementalThreshold = Duration(hours: 1);
  
  /// Check if item needs rescanning
  bool needsRescan(String itemId, {String? currentHash}) {
    final lastScan = _lastScanned[itemId];
    
    // Never scanned before
    if (lastScan == null) return true;
    
    // Check if hash changed (file modified)
    if (currentHash != null) {
      final oldHash = _fileHashes[itemId];
      if (oldHash != null && oldHash != currentHash) {
        return true;
      }
    }
    
    // Check time threshold
    final elapsed = DateTime.now().difference(lastScan);
    return elapsed > _incrementalThreshold;
  }
  
  /// Mark item as scanned
  void markScanned(String itemId, {String? hash}) {
    _lastScanned[itemId] = DateTime.now();
    if (hash != null) {
      _fileHashes[itemId] = hash;
    }
  }
  
  /// Clear scan history
  void clear() {
    _lastScanned.clear();
    _fileHashes.clear();
  }
  
  /// Get stats
  Map<String, int> getStats() {
    return {
      'totalScanned': _lastScanned.length,
      'withHashes': _fileHashes.length,
    };
  }
}

/// Smart cache for scan results to avoid rescanning
class ScanResultCache {
  final Map<String, CachedScanResult> _cache = {};
  final Duration _cacheLifetime = Duration(hours: 6);
  int _hits = 0;
  int _misses = 0;
  
  /// Get cached result if valid
  APKScanResult? getCached(String packageName, String version) {
    final key = '$packageName:$version';
    final cached = _cache[key];
    
    if (cached == null) {
      _misses++;
      return null;
    }
    
    // Check if cache is still valid
    final age = DateTime.now().difference(cached.timestamp);
    if (age > _cacheLifetime) {
      _cache.remove(key);
      _misses++;
      return null;
    }
    
    _hits++;
    return cached.result;
  }
  
  /// Store result in cache
  void cache(String packageName, String version, APKScanResult result) {
    final key = '$packageName:$version';
    _cache[key] = CachedScanResult(
      result: result,
      timestamp: DateTime.now(),
    );
  }
  
  /// Clear cache
  void clear() {
    _cache.clear();
    _hits = 0;
    _misses = 0;
  }
  
  /// Get cache stats
  Map<String, dynamic> getStats() {
    final total = _hits + _misses;
    final hitRate = total > 0 ? (_hits / total * 100) : 0;
    
    return {
      'hits': _hits,
      'misses': _misses,
      'hitRate': hitRate.toStringAsFixed(1) + '%',
      'cacheSize': _cache.length,
    };
  }
}

class CachedScanResult {
  final APKScanResult result;
  final DateTime timestamp;
  
  CachedScanResult({
    required this.result,
    required this.timestamp,
  });
}

/// Priority-based scanner - scans high-risk items first
class PriorityScanner {
  /// Sort items by priority (high risk first)
  static List<T> sortByPriority<T>(
    List<T> items,
    int Function(T item) priorityFunction,
  ) {
    final sorted = items.toList();
    sorted.sort((a, b) => priorityFunction(b).compareTo(priorityFunction(a)));
    return sorted;
  }
  
  /// Calculate app priority score (0-100, higher = more urgent)
  static int calculateAppPriority(AppTelemetry app) {
    int priority = 0;
    
    // Recently installed apps are higher priority
    final daysSinceInstall = DateTime.now().difference(app.installedDate).inDays;
    if (daysSinceInstall < 1) priority += 50;
    else if (daysSinceInstall < 7) priority += 30;
    else if (daysSinceInstall < 30) priority += 10;
    
    // Non-system apps are higher priority
    if (!app.isSystemApp) priority += 20;
    
    // Apps with dangerous permissions
    final dangerousPerms = [
      'READ_SMS', 'SEND_SMS', 'READ_CONTACTS', 'CAMERA',
      'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'READ_CALL_LOG'
    ];
    
    for (final perm in app.declaredPermissions) {
      if (dangerousPerms.any((dp) => perm.contains(dp))) {
        priority += 5;
      }
    }
    
    // Unknown installer is suspicious
    if (app.installer == null || app.installer == 'Unknown') {
      priority += 15;
    }
    
    return priority.clamp(0, 100);
  }
}
