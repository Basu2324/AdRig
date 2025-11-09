import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:path_provider/path_provider.dart';
import 'dart:io';

/// Bloom filter manager for fast known-clean hash preflight checks
/// Reduces remote API calls by 80-90% for known-clean files
/// Target false positive rate: <1%
class BloomFilterManager {
  // Bloom filter parameters
  final int _expectedElements;
  final double _falsePositiveRate;
  late int _bitArraySize;
  late int _numHashFunctions;
  
  // Bit array storage
  late Uint8List _bitArray;
  
  // Statistics
  int _elementsAdded = 0;
  int _lookupCount = 0;
  int _positiveCount = 0;
  
  // Delta management
  DateTime? _lastUpdate;
  final List<String> _pendingAdditions = [];
  
  BloomFilterManager({
    int expectedElements = 1000000, // 1M known-clean hashes
    double falsePositiveRate = 0.01, // 1% FPR
  })  : _expectedElements = expectedElements,
        _falsePositiveRate = falsePositiveRate {
    _calculateOptimalParameters();
    _initializeBitArray();
  }
  
  /// Calculate optimal bit array size and hash function count
  /// Formula: m = -n*ln(p) / (ln(2)^2)
  /// Formula: k = (m/n) * ln(2)
  void _calculateOptimalParameters() {
    final n = _expectedElements;
    final p = _falsePositiveRate;
    
    // Bit array size
    _bitArraySize = ((-n * log(p)) / (log(2) * log(2))).ceil();
    
    // Number of hash functions
    _numHashFunctions = ((_bitArraySize / n) * log(2)).ceil();
    
    // Ensure minimum values
    _bitArraySize = max(_bitArraySize, 1024);
    _numHashFunctions = max(_numHashFunctions, 3);
    
    print('Bloom filter initialized: ${_bitArraySize} bits, ${_numHashFunctions} hash functions');
  }
  
  void _initializeBitArray() {
    final byteSize = (_bitArraySize / 8).ceil();
    _bitArray = Uint8List(byteSize);
  }
  
  /// Add a hash to the bloom filter (mark as known-clean)
  void addHash(String hash) {
    final normalizedHash = hash.toLowerCase();
    final indices = _getHashIndices(normalizedHash);
    
    for (var index in indices) {
      _setBit(index);
    }
    
    _elementsAdded++;
    _pendingAdditions.add(normalizedHash);
  }
  
  /// Batch add hashes
  void addHashes(List<String> hashes) {
    for (var hash in hashes) {
      addHash(hash);
    }
  }
  
  /// Check if hash might be in the set (known-clean)
  /// Returns true if POSSIBLY in set (might be false positive)
  /// Returns false if DEFINITELY NOT in set (100% accurate)
  bool mightContain(String hash) {
    _lookupCount++;
    
    final normalizedHash = hash.toLowerCase();
    final indices = _getHashIndices(normalizedHash);
    
    for (var index in indices) {
      if (!_getBit(index)) {
        return false; // Definitely not in set
      }
    }
    
    _positiveCount++;
    return true; // Possibly in set
  }
  
  /// Batch check hashes
  /// Returns map of hash -> mightContain result
  Map<String, bool> batchMightContain(List<String> hashes) {
    final results = <String, bool>{};
    for (var hash in hashes) {
      results[hash] = mightContain(hash);
    }
    return results;
  }
  
  /// Calculate hash indices using double hashing technique
  /// h(i) = (h1(x) + i*h2(x)) mod m
  List<int> _getHashIndices(String value) {
    // Primary hash using SHA256
    final h1 = _hashToInt(sha256.convert(utf8.encode(value)).bytes);
    
    // Secondary hash using MD5
    final h2 = _hashToInt(md5.convert(utf8.encode(value)).bytes);
    
    final indices = <int>[];
    for (var i = 0; i < _numHashFunctions; i++) {
      final index = ((h1 + i * h2) % _bitArraySize).abs();
      indices.add(index);
    }
    
    return indices;
  }
  
  int _hashToInt(List<int> bytes) {
    // Take first 8 bytes and convert to int
    var result = 0;
    for (var i = 0; i < min(8, bytes.length); i++) {
      result = (result << 8) | bytes[i];
    }
    return result;
  }
  
  void _setBit(int index) {
    final byteIndex = index ~/ 8;
    final bitIndex = index % 8;
    _bitArray[byteIndex] |= (1 << bitIndex);
  }
  
  bool _getBit(int index) {
    final byteIndex = index ~/ 8;
    final bitIndex = index % 8;
    return (_bitArray[byteIndex] & (1 << bitIndex)) != 0;
  }
  
  /// Save bloom filter to disk (compact binary format)
  Future<void> saveToDisk() async {
    final dir = await getApplicationDocumentsDirectory();
    final file = File('${dir.path}/bloom_filter.bin');
    
    final metadata = {
      'version': 1,
      'expected_elements': _expectedElements,
      'false_positive_rate': _falsePositiveRate,
      'bit_array_size': _bitArraySize,
      'num_hash_functions': _numHashFunctions,
      'elements_added': _elementsAdded,
      'last_update': _lastUpdate?.toIso8601String(),
    };
    
    // Create compact binary format:
    // [metadata_length:4][metadata:json][bit_array]
    final metadataJson = jsonEncode(metadata);
    final metadataBytes = utf8.encode(metadataJson);
    
    final output = BytesBuilder();
    // Write metadata length (4 bytes)
    output.add(_int32ToBytes(metadataBytes.length));
    // Write metadata
    output.add(metadataBytes);
    // Write bit array
    output.add(_bitArray);
    
    await file.writeAsBytes(output.toBytes());
    
    print('Bloom filter saved: ${file.path} (${output.length} bytes)');
  }
  
  /// Load bloom filter from disk
  Future<bool> loadFromDisk() async {
    try {
      final dir = await getApplicationDocumentsDirectory();
      final file = File('${dir.path}/bloom_filter.bin');
      
      if (!await file.exists()) {
        print('Bloom filter file not found');
        return false;
      }
      
      final bytes = await file.readAsBytes();
      
      // Read metadata length
      final metadataLength = _bytesToInt32(bytes.sublist(0, 4));
      
      // Read metadata
      final metadataBytes = bytes.sublist(4, 4 + metadataLength);
      final metadataJson = utf8.decode(metadataBytes);
      final metadata = jsonDecode(metadataJson) as Map<String, dynamic>;
      
      // Validate compatibility
      if (metadata['expected_elements'] != _expectedElements ||
          metadata['false_positive_rate'] != _falsePositiveRate) {
        print('Bloom filter parameters mismatch, reinitializing');
        return false;
      }
      
      // Load bit array
      _bitArraySize = metadata['bit_array_size'] as int;
      _numHashFunctions = metadata['num_hash_functions'] as int;
      _elementsAdded = metadata['elements_added'] as int;
      _lastUpdate = metadata['last_update'] != null
          ? DateTime.parse(metadata['last_update'] as String)
          : null;
      
      _bitArray = Uint8List.fromList(bytes.sublist(4 + metadataLength));
      
      print('Bloom filter loaded: $_elementsAdded elements, last update: $_lastUpdate');
      return true;
    } catch (e) {
      print('Error loading bloom filter: $e');
      return false;
    }
  }
  
  /// Apply delta update (incremental additions)
  /// Delta format: JSON array of hashes to add
  Future<void> applyDelta(String deltaJson) async {
    final delta = jsonDecode(deltaJson) as Map<String, dynamic>;
    final additions = (delta['additions'] as List).cast<String>();
    
    addHashes(additions);
    _lastUpdate = DateTime.now();
    
    print('Applied delta: ${additions.length} additions');
  }
  
  /// Generate delta of pending additions
  /// Returns compact JSON for network transmission
  String generateDelta() {
    final delta = {
      'version': 1,
      'timestamp': DateTime.now().toIso8601String(),
      'additions': _pendingAdditions,
    };
    
    _pendingAdditions.clear();
    return jsonEncode(delta);
  }
  
  /// Download and apply daily delta from server
  /// URL format: https://api.example.com/v1/bloom/delta/{date}
  Future<bool> downloadAndApplyDelta(String baseUrl, {DateTime? date}) async {
    date ??= DateTime.now();
    final dateStr = '${date.year}${date.month.toString().padLeft(2, '0')}${date.day.toString().padLeft(2, '0')}';
    
    try {
      final response = await http.get(Uri.parse('$baseUrl/v1/bloom/delta/$dateStr'));
      
      if (response.statusCode == 200) {
        await applyDelta(response.body);
        await saveToDisk();
        return true;
      } else if (response.statusCode == 404) {
        print('No delta available for $dateStr');
        return false;
      } else {
        print('Delta download failed: ${response.statusCode}');
        return false;
      }
    } catch (e) {
      print('Error downloading delta: $e');
      return false;
    }
  }
  
  /// Clear all data
  void clear() {
    _initializeBitArray();
    _elementsAdded = 0;
    _lookupCount = 0;
    _positiveCount = 0;
    _pendingAdditions.clear();
    _lastUpdate = null;
  }
  
  /// Get current statistics
  BloomFilterStats getStats() {
    final actualFPR = _lookupCount > 0 ? _positiveCount / _lookupCount : 0.0;
    final fillRatio = _bitArraySize > 0 ? _countSetBits() / _bitArraySize : 0.0;
    
    // Estimated FPR based on fill ratio: (1 - e^(-kn/m))^k
    final estimatedFPR = _bitArraySize > 0
        ? pow(1 - exp(-_numHashFunctions * _elementsAdded / _bitArraySize), _numHashFunctions)
        : 0.0;
    
    return BloomFilterStats(
      expectedElements: _expectedElements,
      elementsAdded: _elementsAdded,
      targetFPR: _falsePositiveRate,
      actualFPR: actualFPR,
      estimatedFPR: estimatedFPR.toDouble(),
      bitArraySize: _bitArraySize,
      bitArraySizeBytes: _bitArray.length,
      numHashFunctions: _numHashFunctions,
      fillRatio: fillRatio,
      lookupCount: _lookupCount,
      positiveCount: _positiveCount,
      lastUpdate: _lastUpdate,
    );
  }
  
  int _countSetBits() {
    var count = 0;
    for (var byte in _bitArray) {
      count += _popcount(byte);
    }
    return count;
  }
  
  int _popcount(int n) {
    var count = 0;
    while (n > 0) {
      count += n & 1;
      n >>= 1;
    }
    return count;
  }
  
  Uint8List _int32ToBytes(int value) {
    return Uint8List(4)
      ..[0] = (value >> 24) & 0xFF
      ..[1] = (value >> 16) & 0xFF
      ..[2] = (value >> 8) & 0xFF
      ..[3] = value & 0xFF;
  }
  
  int _bytesToInt32(List<int> bytes) {
    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
  }
}

/// Bloom filter statistics
class BloomFilterStats {
  final int expectedElements;
  final int elementsAdded;
  final double targetFPR;
  final double actualFPR;
  final double estimatedFPR;
  final int bitArraySize;
  final int bitArraySizeBytes;
  final int numHashFunctions;
  final double fillRatio;
  final int lookupCount;
  final int positiveCount;
  final DateTime? lastUpdate;
  
  BloomFilterStats({
    required this.expectedElements,
    required this.elementsAdded,
    required this.targetFPR,
    required this.actualFPR,
    required this.estimatedFPR,
    required this.bitArraySize,
    required this.bitArraySizeBytes,
    required this.numHashFunctions,
    required this.fillRatio,
    required this.lookupCount,
    required this.positiveCount,
    this.lastUpdate,
  });
  
  @override
  String toString() {
    return '''
Bloom Filter Statistics:
  Capacity: $elementsAdded / $expectedElements elements (${(elementsAdded / expectedElements * 100).toStringAsFixed(1)}%)
  False Positive Rate:
    Target: ${(targetFPR * 100).toStringAsFixed(2)}%
    Estimated: ${(estimatedFPR * 100).toStringAsFixed(2)}%
    Actual: ${(actualFPR * 100).toStringAsFixed(2)}%
  Storage:
    Bit array: $bitArraySize bits (${(bitArraySizeBytes / 1024).toStringAsFixed(2)} KB)
    Fill ratio: ${(fillRatio * 100).toStringAsFixed(2)}%
    Hash functions: $numHashFunctions
  Performance:
    Lookups: $lookupCount
    Positives: $positiveCount
    Last update: ${lastUpdate ?? 'Never'}
''';
  }
}

// Need to import http for delta downloads
import 'package:http/http.dart' as http;
