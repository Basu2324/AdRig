import 'dart:io';
import 'package:adrig/core/models/threat_model.dart';
import 'package:flutter/services.dart';

/// Root/jailbreak detection service
/// Detects: su binary, unsafe binaries, system file modifications,
/// Magisk, Xposed, and other root indicators
class RootDetectionService {
  static const platform = MethodChannel('com.adrig.security/telemetry');
  
  /// Perform comprehensive root/jailbreak detection
  Future<List<RootIndicator>> detectRootJailbreak() async {
    final indicators = <RootIndicator>[];
    
    try {
      if (Platform.isAndroid) {
        // Call native Android root detection via platform channel
        final Map<dynamic, dynamic> result = await platform.invokeMethod('checkRootAccess');
        final data = Map<String, dynamic>.from(result);
        
        // Parse su binary detection
        if (data['suBinaryFound'] == true) {
          indicators.add(RootIndicator(
            type: 'SU_BINARY',
            path: data['suPath'] as String? ?? '/system/xbin/su',
            severity: ThreatSeverity.critical,
            description: 'SuperUser (su) binary detected',
            detected: DateTime.now(),
          ));
        }
        
        // Parse root apps detection
        final rootApps = List<String>.from(data['rootApps'] as List? ?? []);
        for (final app in rootApps) {
          indicators.add(RootIndicator(
            type: 'ROOT_APP',
            path: app,
            severity: ThreatSeverity.high,
            description: 'Root management app detected: $app',
            detected: DateTime.now(),
          ));
        }
        
        // Parse test-keys detection
        if (data['testKeys'] == true) {
          indicators.add(RootIndicator(
            type: 'BUILD_TAGS',
            path: 'Build.TAGS',
            severity: ThreatSeverity.medium,
            description: 'Device built with test-keys (custom ROM)',
            detected: DateTime.now(),
          ));
        }
        
        // Add additional checks that may not be in native code
        indicators.addAll(await _detectAdditionalRootIndicators());
        
      } else if (Platform.isIOS) {
        indicators.addAll(await _detectIOSJailbreak());
      }
    } catch (e) {
      print('Error detecting root/jailbreak: $e');
      rethrow;
    }
    
    return indicators;
  }

  /// Additional root indicators not covered by native check
  Future<List<RootIndicator>> _detectAdditionalRootIndicators() async {
    final indicators = <RootIndicator>[];
    
    // Check for Magisk
    indicators.addAll(await _checkMagisk());
    
    // Check for Xposed
    indicators.addAll(await _checkXposed());
    
    return indicators;
  }

  /// iOS jailbreak detection
  Future<List<RootIndicator>> _detectIOSJailbreak() async {
    final indicators = <RootIndicator>[];
    
    // Check for Cydia
    indicators.addAll(await _checkCydia());
    
    // Check for suspicious file system paths
    indicators.addAll(await _checkIOSPaths());
    
    // Check for URL schemes
    indicators.addAll(await _checkIOSURLSchemes());
    
    return indicators;
  }
  
  
  /// Check for Magisk
  Future<List<RootIndicator>> _checkMagisk() async {
    final indicators = <RootIndicator>[];
    
    final magiskPaths = [
      '/sbin/.magisk',
      '/sbin/magisk',
      '/data/adb/magisk',
      '/data/adb/magisk.db',
      '/cache/magisk.log',
    ];
    
    for (final path in magiskPaths) {
      try {
        final entity = FileSystemEntity.typeSync(path);
        if (entity != FileSystemEntityType.notFound) {
          indicators.add(RootIndicator(
            type: 'MAGISK',
            path: path,
            severity: ThreatSeverity.critical,
            description: 'Magisk root framework detected at $path',
            detected: DateTime.now(),
          ));
        }
      } catch (e) {
        // Expected on non-rooted devices
      }
    }
    
    return indicators;
  }
  
  /// Check for Xposed Framework
  Future<List<RootIndicator>> _checkXposed() async {
    final indicators = <RootIndicator>[];
    
    final xposedPaths = [
      '/system/framework/XposedBridge.jar',
      '/system/bin/app_process32_xposed',
      '/system/bin/app_process64_xposed',
    ];
    
    for (final path in xposedPaths) {
      try {
        final file = File(path);
        if (await file.exists()) {
          indicators.add(RootIndicator(
            type: 'XPOSED',
            path: path,
            severity: ThreatSeverity.high,
            description: 'Xposed Framework detected at $path',
            detected: DateTime.now(),
          ));
        }
      } catch (e) {
        // Expected on non-rooted devices
      }
    }
    
    return indicators;
  }
  
  /// Check for Cydia (iOS)
  Future<List<RootIndicator>> _checkCydia() async {
    final indicators = <RootIndicator>[];
    
    if (!Platform.isIOS) return indicators;
    
    final cydiaPath = '/Applications/Cydia.app';
    try {
      final dir = Directory(cydiaPath);
      if (await dir.exists()) {
        indicators.add(RootIndicator(
          type: 'CYDIA',
          path: cydiaPath,
          severity: ThreatSeverity.critical,
          description: 'Cydia jailbreak app detected',
          detected: DateTime.now(),
        ));
      }
    } catch (e) {
      // Expected on non-jailbroken devices
    }
    
    return indicators;
  }
  
  /// Check iOS jailbreak paths
  Future<List<RootIndicator>> _checkIOSPaths() async {
    final indicators = <RootIndicator>[];
    
    if (!Platform.isIOS) return indicators;
    
    final jailbreakPaths = [
      '/Applications/Cydia.app',
      '/Library/MobileSubstrate/MobileSubstrate.dylib',
      '/bin/bash',
      '/usr/sbin/sshd',
      '/etc/apt',
      '/private/var/lib/apt/',
      '/private/var/lib/cydia',
      '/private/var/stash',
    ];
    
    for (final path in jailbreakPaths) {
      try {
        final entity = FileSystemEntity.typeSync(path);
        if (entity != FileSystemEntityType.notFound) {
          indicators.add(RootIndicator(
            type: 'JAILBREAK_FILE',
            path: path,
            severity: ThreatSeverity.critical,
            description: 'Jailbreak file/directory detected at $path',
            detected: DateTime.now(),
          ));
        }
      } catch (e) {
        // Expected on non-jailbroken devices
      }
    }
    
    return indicators;
  }
  
  /// Check iOS URL schemes
  Future<List<RootIndicator>> _checkIOSURLSchemes() async {
    final indicators = <RootIndicator>[];
    
    if (!Platform.isIOS) return indicators;
    
    // In production, use UIApplication.canOpenURL() via platform channels
    // to check for cydia:// URL scheme
    
    return indicators;
  }
  
  /// Quick root check (fast method)
  Future<bool> isDeviceRooted() async {
    final indicators = await detectRootJailbreak();
    return indicators.any((i) => 
      i.severity == ThreatSeverity.critical || 
      i.severity == ThreatSeverity.high);
  }
}
