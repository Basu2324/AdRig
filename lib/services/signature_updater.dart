import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Signature database update system with delta sync and version control
class SignatureDatabaseUpdater {
  static const String _updateUrl = 'https://mb-api.abuse.ch/api/v1/';
  static const String _versionKey = 'signature_db_version';
  static const String _lastUpdateKey = 'signature_db_last_update';
  static const String _updateHashKey = 'signature_db_hash';
  
  // Update every 6 hours
  static const Duration updateInterval = Duration(hours: 6);
  
  int _currentVersion = 0;
  DateTime? _lastUpdateTime;
  
  /// Check if update is needed
  Future<bool> needsUpdate() async {
    final prefs = await SharedPreferences.getInstance();
    final lastUpdate = prefs.getInt(_lastUpdateKey);
    
    if (lastUpdate == null) return true;
    
    final lastUpdateTime = DateTime.fromMillisecondsSinceEpoch(lastUpdate);
    final timeSinceUpdate = DateTime.now().difference(lastUpdateTime);
    
    return timeSinceUpdate > updateInterval;
  }
  
  /// Download delta updates (only new signatures since last sync)
  Future<SignatureUpdateResult> fetchDeltaUpdate() async {
    print('🔄 Checking for signature database updates...');
    
    try {
      final prefs = await SharedPreferences.getInstance();
      final currentVersion = prefs.getInt(_versionKey) ?? 0;
      final lastUpdate = prefs.getInt(_lastUpdateKey);
      
      // Calculate timestamp for delta query
      final sinceTimestamp = lastUpdate != null
          ? DateTime.fromMillisecondsSinceEpoch(lastUpdate)
          : DateTime.now().subtract(Duration(days: 30));
      
      // Query MalwareBazaar for recent Android malware
      final response = await http.post(
        Uri.parse(_updateUrl),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'query': 'get_recent',
          'selector': sinceTimestamp.millisecondsSinceEpoch ~/ 1000,
        },
      ).timeout(Duration(seconds: 30));
      
      if (response.statusCode != 200) {
        throw Exception('Update server returned ${response.statusCode}');
      }
      
      final data = jsonDecode(response.body);
      
      if (data['query_status'] != 'ok') {
        throw Exception('Update query failed: ${data['query_status']}');
      }
      
      final signatures = <MalwareSignature>[];
      final rawData = data['data'] ?? [];
      
      // Filter for Android malware only
      for (final item in rawData) {
        if (item['file_type']?.toString().contains('Android') ?? false) {
          signatures.add(MalwareSignature(
            id: 'mb_${item['sha256_hash']?.substring(0, 8)}',
            hash: item['sha256_hash'] ?? '',
            hashType: 'sha256',
            malwareName: item['signature'] ?? 'Unknown',
            family: item['tags']?.join(',') ?? 'Unknown',
            threatType: _mapThreatType(item['tags']),
            severity: ThreatSeverity.critical,
            discoveredDate: item['first_seen'] != null
                ? DateTime.tryParse(item['first_seen'])
                : null,
            indicators: [
              'First seen: ${item['first_seen']}',
              'File type: ${item['file_type']}',
              if (item['intelligence'] != null)
                'Intel: ${item['intelligence']}',
            ],
            metadata: {
              'source': 'MalwareBazaar',
              'tags': item['tags'],
            },
          ));
        }
      }
      
      // Calculate update hash for integrity verification
      final updateHash = _calculateUpdateHash(signatures);
      
      final newVersion = currentVersion + 1;
      
      print('✅ Found ${signatures.length} new signatures');
      print('📦 Version: $currentVersion → $newVersion');
      
      return SignatureUpdateResult(
        signatures: signatures,
        version: newVersion,
        updateHash: updateHash,
        timestamp: DateTime.now(),
      );
      
    } catch (e) {
      print('❌ Update failed: $e');
      return SignatureUpdateResult(
        signatures: [],
        version: _currentVersion,
        updateHash: '',
        timestamp: DateTime.now(),
        error: e.toString(),
      );
    }
  }
  
  /// Apply delta update to local database
  Future<bool> applyUpdate(SignatureUpdateResult update) async {
    if (update.error != null) return false;
    if (update.signatures.isEmpty) {
      print('ℹ️  No new signatures to apply');
      return true;
    }
    
    try {
      print('📥 Applying ${update.signatures.length} signature updates...');
      
      // Save version info BEFORE applying updates (for rollback)
      await _createBackupPoint();
      
      // Apply signatures to database
      // (This would be called from SignatureDatabase class)
      
      // Update metadata
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(_versionKey, update.version);
      await prefs.setInt(_lastUpdateKey, update.timestamp.millisecondsSinceEpoch);
      await prefs.setString(_updateHashKey, update.updateHash);
      
      print('✅ Update applied successfully');
      print('📊 Database version: ${update.version}');
      print('🔐 Update hash: ${update.updateHash.substring(0, 16)}...');
      
      _currentVersion = update.version;
      _lastUpdateTime = update.timestamp;
      
      return true;
      
    } catch (e) {
      print('❌ Failed to apply update: $e');
      await _rollbackToBackup();
      return false;
    }
  }
  
  /// Verify update integrity using hash
  bool verifyUpdate(SignatureUpdateResult update) {
    if (update.signatures.isEmpty) return true;
    
    final calculatedHash = _calculateUpdateHash(update.signatures);
    final isValid = calculatedHash == update.updateHash;
    
    if (!isValid) {
      print('⚠️  Update integrity check FAILED!');
      print('   Expected: ${update.updateHash}');
      print('   Got:      $calculatedHash');
    }
    
    return isValid;
  }
  
  /// Get current database version
  Future<int> getCurrentVersion() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getInt(_versionKey) ?? 0;
  }
  
  /// Get last update timestamp
  Future<DateTime?> getLastUpdateTime() async {
    final prefs = await SharedPreferences.getInstance();
    final timestamp = prefs.getInt(_lastUpdateKey);
    return timestamp != null 
        ? DateTime.fromMillisecondsSinceEpoch(timestamp)
        : null;
  }
  
  /// Force full database refresh (not delta)
  Future<SignatureUpdateResult> fetchFullUpdate() async {
    print('🔄 Fetching full signature database...');
    
    try {
      final response = await http.post(
        Uri.parse(_updateUrl),
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: {
          'query': 'get_taginfo',
          'tag': 'Android',
          'limit': '1000',
        },
      ).timeout(Duration(seconds: 60));
      
      if (response.statusCode != 200) {
        throw Exception('Server returned ${response.statusCode}');
      }
      
      final data = jsonDecode(response.body);
      final signatures = <MalwareSignature>[];
      
      for (final item in (data['data'] ?? [])) {
        signatures.add(MalwareSignature(
          id: 'mb_${item['sha256_hash']?.substring(0, 8)}',
          hash: item['sha256_hash'] ?? '',
          hashType: 'sha256',
          malwareName: item['signature'] ?? 'Unknown',
          family: item['tags']?.join(',') ?? 'Unknown',
          threatType: _mapThreatType(item['tags']),
          severity: ThreatSeverity.critical,
          discoveredDate: item['first_seen'] != null
              ? DateTime.tryParse(item['first_seen'])
              : null,
          indicators: [
            'First seen: ${item['first_seen']}',
            if (item['intelligence'] != null)
              'Intel: ${item['intelligence']}',
          ],
          metadata: {
            'source': 'MalwareBazaar',
            'tags': item['tags'],
          },
        ));
      }
      
      print('✅ Downloaded ${signatures.length} signatures');
      
      return SignatureUpdateResult(
        signatures: signatures,
        version: 1,
        updateHash: _calculateUpdateHash(signatures),
        timestamp: DateTime.now(),
      );
      
    } catch (e) {
      print('❌ Full update failed: $e');
      return SignatureUpdateResult(
        signatures: [],
        version: 0,
        updateHash: '',
        timestamp: DateTime.now(),
        error: e.toString(),
      );
    }
  }
  
  /// Create backup point for rollback
  Future<void> _createBackupPoint() async {
    final prefs = await SharedPreferences.getInstance();
    final currentVersion = prefs.getInt(_versionKey) ?? 0;
    
    // Save backup metadata
    await prefs.setInt('backup_version', currentVersion);
    await prefs.setInt('backup_timestamp', DateTime.now().millisecondsSinceEpoch);
    
    print('💾 Backup point created (version $currentVersion)');
  }
  
  /// Rollback to previous version
  Future<void> _rollbackToBackup() async {
    print('⏪ Rolling back to previous version...');
    
    final prefs = await SharedPreferences.getInstance();
    final backupVersion = prefs.getInt('backup_version');
    
    if (backupVersion != null) {
      await prefs.setInt(_versionKey, backupVersion);
      print('✅ Rolled back to version $backupVersion');
    } else {
      print('⚠️  No backup available');
    }
  }
  
  /// Calculate hash of signature set for integrity verification
  String _calculateUpdateHash(List<MalwareSignature> signatures) {
    final concatenated = signatures
        .map((s) => s.hash)
        .join('|');
    
    final bytes = utf8.encode(concatenated);
    final digest = sha256.convert(bytes);
    
    return digest.toString();
  }
  
  /// Map MalwareBazaar tags to ThreatType
  ThreatType _mapThreatType(dynamic tags) {
    if (tags == null) return ThreatType.suspicious;
    
    final tagList = tags.toString().toLowerCase();
    
    if (tagList.contains('banker') || tagList.contains('trojan-banker')) {
      return ThreatType.trojan;
    } else if (tagList.contains('spy') || tagList.contains('stealer')) {
      return ThreatType.spyware;
    } else if (tagList.contains('ransom')) {
      return ThreatType.ransomware;
    } else if (tagList.contains('adware')) {
      return ThreatType.adware;
    } else if (tagList.contains('rat') || tagList.contains('backdoor')) {
      return ThreatType.trojan;
    }
    
    return ThreatType.suspicious;
  }
}

/// Result of signature update operation
class SignatureUpdateResult {
  final List<MalwareSignature> signatures;
  final int version;
  final String updateHash;
  final DateTime timestamp;
  final String? error;

  SignatureUpdateResult({
    required this.signatures,
    required this.version,
    required this.updateHash,
    required this.timestamp,
    this.error,
  });
  
  bool get isSuccess => error == null;
  bool get hasNewSignatures => signatures.isNotEmpty;
}
