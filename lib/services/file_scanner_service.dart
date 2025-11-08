import 'dart:io';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:path/path.dart' as path;
import 'package:adrig/core/models/threat_model.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/services.dart';

/// File system scanner service
/// Scans internal storage and SD cards for suspicious files
/// Collects: path, filename, size, MIME type, hashes, timestamps
class FileScannerService {
  static const platform = MethodChannel('com.adrig.security/telemetry');
  
  /// Scan all accessible file system locations
  Future<List<FileSystemEntry>> scanFileSystem() async {
    final entries = <FileSystemEntry>[];
    
    try {
      // Scan internal storage
      entries.addAll(await _scanInternalStorage());
      
      // Scan external storage (SD cards)
      entries.addAll(await _scanExternalStorage());
      
      // Scan app-specific directories
      entries.addAll(await _scanAppDirectories());
      
    } catch (e) {
      print('Error scanning file system: $e');
    }
    
    return entries;
  }
  
  /// Scan specific directory
  Future<List<FileSystemEntry>> scanDirectory(String dirPath) async {
    final entries = <FileSystemEntry>[];
    
    try {
      // Call native Android file scanning via platform channel
      final List<dynamic> result = await platform.invokeMethod(
        'scanFiles',
        {'path': dirPath},
      );
      
      for (final fileData in result) {
        try {
          final data = Map<String, dynamic>.from(fileData as Map);
          
          entries.add(FileSystemEntry(
            path: data['path'] as String,
            name: data['name'] as String,
            size: (data['size'] as int?) ?? 0,
            mimeType: _guessMimeType(data['name'] as String),
            hash: FileHash(
              md5: data['md5'] as String? ?? '',
              sha1: data['sha1'] as String? ?? '',
              sha256: data['sha256'] as String? ?? '',
            ),
            permissions: data['permissions'] as String? ?? '',
            created: DateTime.fromMillisecondsSinceEpoch(data['created'] as int),
            modified: DateTime.fromMillisecondsSinceEpoch(data['modified'] as int),
            accessed: DateTime.fromMillisecondsSinceEpoch(data['accessed'] as int),
            isHidden: (data['name'] as String).startsWith('.'),
            owner: data['owner'] as String? ?? 'system',
          ));
        } catch (e) {
          print('Error parsing file data: $e');
          continue;
        }
      }
    } catch (e) {
      print('Error calling native scanFiles: $e');
      // Fall back to Dart file scanning if platform channel fails
      return _scanDirectoryFallback(dirPath);
    }
    
    return entries;
  }
  
  /// Fallback to Dart-based file scanning
  Future<List<FileSystemEntry>> _scanDirectoryFallback(String dirPath) async {
    final entries = <FileSystemEntry>[];
    
    try {
      final dir = Directory(dirPath);
      if (!await dir.exists()) {
        return entries;
      }
      
      await for (final entity in dir.list(recursive: true, followLinks: false)) {
        if (entity is File) {
          final entry = await _analyzeFile(entity);
          if (entry != null) {
            entries.add(entry);
          }
        }
      }
    } catch (e) {
      print('Error scanning directory $dirPath: $e');
    }
    
    return entries;
  }
  
  /// Scan internal storage
  Future<List<FileSystemEntry>> _scanInternalStorage() async {
    final entries = <FileSystemEntry>[];
    
    try {
      // Common suspicious paths on Android
      final suspiciousPaths = [
        '/data/local/tmp',
        '/data/data',
        '/system/bin',
        '/system/xbin',
      ];
      
      for (final dirPath in suspiciousPaths) {
        final dir = Directory(dirPath);
        if (await dir.exists()) {
          entries.addAll(await scanDirectory(dirPath));
        }
      }
    } catch (e) {
      print('Error scanning internal storage: $e');
    }
    
    return entries;
  }
  
  /// Scan external storage (SD cards)
  Future<List<FileSystemEntry>> _scanExternalStorage() async {
    final entries = <FileSystemEntry>[];
    
    try {
      // Get external storage directory
      final extDir = await getExternalStorageDirectory();
      if (extDir != null) {
        entries.addAll(await scanDirectory(extDir.path));
      }
      
      // Scan common SD card mount points
      final sdCardPaths = [
        '/storage/sdcard1',
        '/storage/extSdCard',
        '/mnt/extsd',
        '/mnt/sdcard/external_sd',
      ];
      
      for (final mountPoint in sdCardPaths) {
        final dir = Directory(mountPoint);
        if (await dir.exists()) {
          entries.addAll(await scanDirectory(mountPoint));
        }
      }
    } catch (e) {
      print('Error scanning external storage: $e');
    }
    
    return entries;
  }
  
  /// Scan app-specific directories
  Future<List<FileSystemEntry>> _scanAppDirectories() async {
    final entries = <FileSystemEntry>[];
    
    try {
      // Scan app documents directory
      final docsDir = await getApplicationDocumentsDirectory();
      entries.addAll(await scanDirectory(docsDir.path));
      
      // Scan app cache directory
      final cacheDir = await getTemporaryDirectory();
      entries.addAll(await scanDirectory(cacheDir.path));
      
      // Scan downloads directory
      if (Platform.isAndroid) {
        final downloadDir = Directory('/storage/emulated/0/Download');
        if (await downloadDir.exists()) {
          entries.addAll(await scanDirectory(downloadDir.path));
        }
      }
    } catch (e) {
      print('Error scanning app directories: $e');
    }
    
    return entries;
  }
  
  /// Analyze individual file
  Future<FileSystemEntry?> _analyzeFile(File file) async {
    try {
      final filePath = file.path;
      final filename = path.basename(filePath);
      final stat = await file.stat();
      
      // Skip if file is too large (>100MB) to avoid performance issues
      if (stat.size > 100 * 1024 * 1024) {
        return null;
      }
      
      // Determine mount point
      final mountPoint = _getMountPoint(filePath);
      
      // Check if file is executable
      final isExecutable = _isExecutableFile(filename);
      
      // Check if file is suspicious
      final isSuspicious = _isSuspiciousFile(filename, filePath);
      
      // Calculate hashes for suspicious or executable files
      APKHash? hashes;
      if (isSuspicious || isExecutable) {
        hashes = await _calculateFileHashes(file);
      }
      
      return FileSystemEntry(
        path: filePath,
        filename: filename,
        size: stat.size,
        mimeType: _getMimeType(filename),
        hash: hashes,
        created: stat.changed,
        modified: stat.modified,
        mountPoint: mountPoint,
        isExecutable: isExecutable,
        isSuspicious: isSuspicious,
      );
    } catch (e) {
      print('Error analyzing file ${file.path}: $e');
      return null;
    }
  }
  
  /// Calculate file hashes (MD5, SHA1, SHA256)
  Future<APKHash> _calculateFileHashes(File file) async {
    try {
      final bytes = await file.readAsBytes();
      
      return APKHash(
        md5: md5.convert(bytes).toString(),
        sha1: sha1.convert(bytes).toString(),
        sha256: sha256.convert(bytes).toString(),
      );
    } catch (e) {
      print('Error calculating hashes: $e');
      return APKHash(md5: '', sha1: '', sha256: '');
    }
  }
  
  /// Determine mount point from file path
  String _getMountPoint(String filePath) {
    if (filePath.startsWith('/storage/sdcard1')) return 'sdcard1';
    if (filePath.startsWith('/storage/extSdCard')) return 'extSdCard';
    if (filePath.startsWith('/mnt/extsd')) return 'extsd';
    if (filePath.startsWith('/storage/emulated/0')) return 'internal';
    if (filePath.startsWith('/data')) return 'internal';
    return 'unknown';
  }
  
  /// Check if file is executable
  bool _isExecutableFile(String filename) {
    final executableExtensions = [
      '.apk', '.dex', '.so', '.elf', '.sh',
      '.bin', '.exe', '.jar', '.zip',
    ];
    
    return executableExtensions.any((ext) => 
      filename.toLowerCase().endsWith(ext));
  }
  
  /// Check if file is suspicious
  bool _isSuspiciousFile(String filename, String filePath) {
    // Suspicious file names
    final suspiciousNames = [
      'su', 'busybox', 'magisk', 'supersu',
      'payload', 'exploit', 'rootkit', 'backdoor',
      'keylog', 'stealer', 'miner', 'cryptominer',
    ];
    
    final lowerFilename = filename.toLowerCase();
    if (suspiciousNames.any((name) => lowerFilename.contains(name))) {
      return true;
    }
    
    // Suspicious paths
    final suspiciousPaths = [
      '/data/local/tmp',
      '/system/xbin',
      '/sbin',
      '/.hidden',
    ];
    
    if (suspiciousPaths.any((path) => filePath.startsWith(path))) {
      return true;
    }
    
    // Hidden files in suspicious locations
    if (filename.startsWith('.') && filePath.contains('/data/')) {
      return true;
    }
    
    // Executable files in download directory
    if (_isExecutableFile(filename) && filePath.contains('/Download')) {
      return true;
    }
    
    return false;
  }
  
  /// Get MIME type from filename
  String _guessMimeType(String filename) {
    final extension = path.extension(filename).toLowerCase();
    
    final mimeTypes = {
      '.apk': 'application/vnd.android.package-archive',
      '.dex': 'application/octet-stream',
      '.so': 'application/x-sharedlib',
      '.elf': 'application/x-executable',
      '.sh': 'application/x-sh',
      '.bin': 'application/octet-stream',
      '.zip': 'application/zip',
      '.jar': 'application/java-archive',
      '.txt': 'text/plain',
      '.pdf': 'application/pdf',
      '.jpg': 'image/jpeg',
      '.png': 'image/png',
      '.mp4': 'video/mp4',
      '.mp3': 'audio/mpeg',
    };
    
    return mimeTypes[extension] ?? 'application/octet-stream';
  }
  
  /// Get MIME type from filename (legacy compatibility)
  String _getMimeType(String filename) => _guessMimeType(filename);
  
  /// Get mount points information
  Future<List<String>> getMountPoints() async {
    final mountPoints = <String>[];
    
    try {
      // Internal storage
      mountPoints.add('/storage/emulated/0');
      
      // Check for external SD cards
      final sdCardPaths = [
        '/storage/sdcard1',
        '/storage/extSdCard',
        '/mnt/extsd',
        '/mnt/sdcard/external_sd',
      ];
      
      for (final path in sdCardPaths) {
        final dir = Directory(path);
        if (await dir.exists()) {
          mountPoints.add(path);
        }
      }
    } catch (e) {
      print('Error getting mount points: $e');
    }
    
    return mountPoints;
  }
  
  /// Scan for specific file patterns
  Future<List<FileSystemEntry>> scanForPattern(String pattern) async {
    final entries = <FileSystemEntry>[];
    
    try {
      final allEntries = await scanFileSystem();
      entries.addAll(allEntries.where((entry) => 
        entry.filename.contains(pattern) || entry.path.contains(pattern)));
    } catch (e) {
      print('Error scanning for pattern $pattern: $e');
    }
    
    return entries;
  }
}
