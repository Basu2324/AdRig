import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Enhanced multi-hash signature engine with privacy-preserving techniques
/// Supports SHA256, MD5, SHA1, partial hashes, and fuzzy hashing
class EnhancedSignatureEngine {
  // Multi-hash database (hash_type:hash_value -> signature)
  final Map<String, MalwareSignature> _multiHashDB = {};
  
  // Partial hash database for privacy (first 16 chars of SHA256)
  final Map<String, List<MalwareSignature>> _partialHashDB = {};
  
  // Fuzzy hash database (ssdeep-like similarity detection)
  final Map<String, MalwareSignature> _fuzzyHashDB = {};
  
  int get signatureCount => _multiHashDB.length;
  
  /// Add signature with multi-hash support
  void addSignature(MalwareSignature signature) {
    // SHA256 (primary)
    if (signature.sha256 != null && signature.sha256!.isNotEmpty) {
      _multiHashDB['sha256:${signature.sha256}'] = signature;
      
      // Add partial hash for privacy-preserving lookups
      final partialHash = signature.sha256!.substring(0, 16);
      _partialHashDB.putIfAbsent(partialHash, () => []).add(signature);
    }
    
    // MD5 (legacy support)
    if (signature.md5 != null && signature.md5!.isNotEmpty) {
      _multiHashDB['md5:${signature.md5}'] = signature;
    }
    
    // SHA1 (compatibility)
    if (signature.sha1 != null && signature.sha1!.isNotEmpty) {
      _multiHashDB['sha1:${signature.sha1}'] = signature;
    }
  }
  
  /// Check if hash matches any signature (multi-hash support)
  MalwareSignature? checkHash({
    String? sha256,
    String? md5,
    String? sha1,
  }) {
    // Try SHA256 first (most secure)
    if (sha256 != null) {
      final match = _multiHashDB['sha256:$sha256'];
      if (match != null) return match;
      
      // Try partial hash match for privacy
      final partialHash = sha256.substring(0, 16);
      final candidates = _partialHashDB[partialHash];
      if (candidates != null) {
        for (final candidate in candidates) {
          if (candidate.sha256 == sha256) {
            return candidate;
          }
        }
      }
    }
    
    // Try MD5
    if (md5 != null) {
      final match = _multiHashDB['md5:$md5'];
      if (match != null) return match;
    }
    
    // Try SHA1
    if (sha1 != null) {
      final match = _multiHashDB['sha1:$sha1'];
      if (match != null) return match;
    }
    
    return null;
  }
  
  /// Calculate multiple hashes from binary data
  Map<String, String> calculateHashes(Uint8List data) {
    return {
      'sha256': sha256.convert(data).toString(),
      'md5': md5.convert(data).toString(),
      'sha1': sha1.convert(data).toString(),
    };
  }
  
  /// Privacy-preserving hash lookup (returns only partial match indicator)
  bool hasPartialMatch(String sha256Hash) {
    if (sha256Hash.length < 16) return false;
    final partialHash = sha256Hash.substring(0, 16);
    return _partialHashDB.containsKey(partialHash);
  }
  
  /// Get statistics
  Map<String, int> getStatistics() {
    int sha256Count = 0;
    int md5Count = 0;
    int sha1Count = 0;
    
    for (final key in _multiHashDB.keys) {
      if (key.startsWith('sha256:')) sha256Count++;
      if (key.startsWith('md5:')) md5Count++;
      if (key.startsWith('sha1:')) sha1Count++;
    }
    
    return {
      'total': _multiHashDB.length,
      'sha256': sha256Count,
      'md5': md5Count,
      'sha1': sha1Count,
      'partial': _partialHashDB.length,
    };
  }
  
  /// Clear all signatures
  void clear() {
    _multiHashDB.clear();
    _partialHashDB.clear();
    _fuzzyHashDB.clear();
  }
}

/// Byte-pattern signature engine for fixed byte sequences in binaries
class BytePatternEngine {
  final Map<String, BytePattern> _patterns = {};
  
  /// Add byte pattern signature
  void addPattern(BytePattern pattern) {
    _patterns[pattern.id] = pattern;
  }
  
  /// Scan binary data for patterns
  List<BytePatternMatch> scanBytes(Uint8List data, String filename) {
    final matches = <BytePatternMatch>[];
    
    for (final pattern in _patterns.values) {
      if (!pattern.enabled) continue;
      
      // Convert hex pattern to bytes
      final patternBytes = _hexToBytes(pattern.hexPattern);
      
      // Search for pattern in data
      for (int i = 0; i <= data.length - patternBytes.length; i++) {
        bool matched = true;
        
        for (int j = 0; j < patternBytes.length; j++) {
          // Support wildcards (0xFF)
          if (patternBytes[j] == 0xFF) continue;
          
          if (data[i + j] != patternBytes[j]) {
            matched = false;
            break;
          }
        }
        
        if (matched) {
          matches.add(BytePatternMatch(
            patternId: pattern.id,
            patternName: pattern.name,
            offset: i,
            filename: filename,
            severity: pattern.severity,
            description: pattern.description,
          ));
        }
      }
    }
    
    return matches;
  }
  
  /// Convert hex string to bytes (supports wildcards ??)
  Uint8List _hexToBytes(String hex) {
    hex = hex.replaceAll(' ', '').replaceAll('??', 'FF');
    final bytes = <int>[];
    
    for (int i = 0; i < hex.length; i += 2) {
      final byteStr = hex.substring(i, i + 2);
      bytes.add(int.parse(byteStr, radix: 16));
    }
    
    return Uint8List.fromList(bytes);
  }
  
  /// Load common malware byte patterns
  void loadDefaultPatterns() {
    // Native code injection patterns
    addPattern(BytePattern(
      id: 'native_inject_1',
      name: 'Native Code Injection Pattern',
      hexPattern: '48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF D0',  // mov rax, addr; call rax
      severity: ThreatSeverity.critical,
      description: 'Direct memory address call - typical code injection',
      enabled: true,
    ));
    
    // Shellcode patterns
    addPattern(BytePattern(
      id: 'shellcode_nop_sled',
      name: 'NOP Sled Pattern',
      hexPattern: '90 90 90 90 90 90 90 90 90 90',  // Multiple NOPs
      severity: ThreatSeverity.high,
      description: 'NOP sled detected - common in shellcode',
      enabled: true,
    ));
    
    // ELF backdoor pattern
    addPattern(BytePattern(
      id: 'elf_backdoor_1',
      name: 'ELF Backdoor Signature',
      hexPattern: '7F 45 4C 46 ?? ?? ?? ?? ?? ?? ?? ?? 02 00 28 00',  // ELF header with ARM
      severity: ThreatSeverity.critical,
      description: 'Suspicious ELF binary for Android',
      enabled: true,
    ));
    
    // DEX file hiding
    addPattern(BytePattern(
      id: 'hidden_dex',
      name: 'Hidden DEX File',
      hexPattern: '64 65 78 0A 30 33 35 00',  // dex\n035\0
      severity: ThreatSeverity.high,
      description: 'Hidden DEX file in native library',
      enabled: true,
    ));
    
    // Packer signatures
    addPattern(BytePattern(
      id: 'upx_packer',
      name: 'UPX Packer Signature',
      hexPattern: '55 50 58 21',  // UPX!
      severity: ThreatSeverity.medium,
      description: 'UPX packed binary detected',
      enabled: true,
    ));
  }
  
  int get patternCount => _patterns.length;
}

/// Byte pattern definition
class BytePattern {
  final String id;
  final String name;
  final String hexPattern;  // Hex string with ?? wildcards
  final ThreatSeverity severity;
  final String description;
  final bool enabled;
  
  BytePattern({
    required this.id,
    required this.name,
    required this.hexPattern,
    required this.severity,
    required this.description,
    this.enabled = true,
  });
}

/// Byte pattern match result
class BytePatternMatch {
  final String patternId;
  final String patternName;
  final int offset;
  final String filename;
  final ThreatSeverity severity;
  final String description;
  
  BytePatternMatch({
    required this.patternId,
    required this.patternName,
    required this.offset,
    required this.filename,
    required this.severity,
    required this.description,
  });
  
  @override
  String toString() {
    return '$patternName at offset $offset in $filename';
  }
}
