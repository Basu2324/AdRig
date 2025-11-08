import 'dart:io';
import 'package:crypto/crypto.dart';
import 'dart:convert';
import 'package:adrig/core/models/threat_model.dart';
import 'package:flutter/services.dart';

/// Process analyzer service
/// Monitors running processes, loaded native libraries (.so files),
/// open ports/sockets, and IPC endpoints
class ProcessAnalyzerService {
  static const platform = MethodChannel('com.adrig.security/telemetry');
  
  /// Analyze all running processes
  Future<List<ProcessInfo>> analyzeRunningProcesses() async {
    final processes = <ProcessInfo>[];
    
    try {
      if (Platform.isAndroid) {
        processes.addAll(await _analyzeAndroidProcesses());
      } else if (Platform.isIOS) {
        processes.addAll(await _analyzeIOSProcesses());
      }
    } catch (e) {
      print('Error analyzing running processes: $e');
    }
    
    return processes;
  }
  
  /// Analyze specific process
  Future<ProcessInfo?> analyzeProcess(int pid) async {
    try {
      if (Platform.isAndroid) {
        return await _getAndroidProcessInfo(pid);
      } else if (Platform.isIOS) {
        return await _getIOSProcessInfo(pid);
      }
    } catch (e) {
      print('Error analyzing process $pid: $e');
    }
    
    return null;
  }
  
  /// Android process analysis
  Future<List<ProcessInfo>> _analyzeAndroidProcesses() async {
    final processes = <ProcessInfo>[];
    
    try {
      // Call native Android code to get running processes from /proc
      final List<dynamic> result = await platform.invokeMethod('getRunningProcesses');
      
      for (final processData in result) {
        try {
          final data = Map<String, dynamic>.from(processData as Map);
          
          processes.add(ProcessInfo(
            pid: data['pid'] as int,
            processName: data['name'] as String,
            packageName: data['packageName'] as String? ?? 'unknown',
            uid: data['uid'] as int? ?? 0,
            cpuUsage: (data['cpuUsage'] as double?)?.toDouble() ?? 0.0,
            memoryUsage: (data['memoryUsage'] as int?)?.toInt() ?? 0,
            loadedLibraries: [], // Would require additional native method
            openPorts: [], // Would require additional native method
            networkConnections: [], // Would require additional native method
            ipcEndpoints: [], // Would require additional native method
            startTime: data['startTime'] != null 
              ? DateTime.fromMillisecondsSinceEpoch(data['startTime'] as int)
              : DateTime.now(),
            parentPid: data['ppid'] as int? ?? 0,
            threadCount: data['threadCount'] as int? ?? 1,
          ));
        } catch (e) {
          print('Error parsing process data: $e');
          continue;
        }
      }
    } catch (e) {
      print('Error calling native getRunningProcesses: $e');
      rethrow;
    }
    
    return processes;
  }

  /// iOS process analysis
  Future<List<ProcessInfo>> _analyzeIOSProcesses() async {
    final processes = <ProcessInfo>[];
    
    try {
      // iOS severely restricts process monitoring
      // Can only monitor own process
      
      final currentPid = pid;
      final processInfo = await _getIOSProcessInfo(currentPid);
      if (processInfo != null) {
        processes.add(processInfo);
      }
    } catch (e) {
      print('Error analyzing iOS processes: $e');
    }
    
    return processes;
  }
  
  /// Get Android process information
  Future<ProcessInfo?> _getAndroidProcessInfo(int processId) async {
    try {
      // In production, read from /proc/$pid/
      // - /proc/$pid/cmdline for process name
      // - /proc/$pid/maps for loaded libraries
      // - /proc/$pid/net/tcp for open sockets
      // - /proc/$pid/status for memory and CPU info
      
      final processName = await _getProcessName(processId);
      final packageName = await _getProcessPackage(processId);
      final libraries = await _getLoadedLibraries(processId);
      final sockets = await _getOpenSockets(processId);
      final ipcEndpoints = await _getIPCEndpoints(processId);
      final memoryUsage = await _getMemoryUsage(processId);
      final cpuUsage = await _getCPUUsage(processId);
      
      return ProcessInfo(
        pid: processId,
        processName: processName,
        packageName: packageName,
        loadedLibraries: libraries,
        openSockets: sockets,
        ipcEndpoints: ipcEndpoints,
        memoryUsage: memoryUsage,
        cpuUsage: cpuUsage,
        startTime: DateTime.now().subtract(Duration(hours: 1)),
      );
    } catch (e) {
      print('Error getting Android process info for PID $processId: $e');
      return null;
    }
  }
  
  /// Get iOS process information
  Future<ProcessInfo?> _getIOSProcessInfo(int processId) async {
    try {
      // iOS has limited access to process information
      
      return ProcessInfo(
        pid: processId,
        processName: 'AdRig Security',
        packageName: 'com.adrig.security',
        loadedLibraries: [],
        openSockets: [],
        ipcEndpoints: [],
        memoryUsage: 50 * 1024 * 1024,
        cpuUsage: 5.0,
        startTime: DateTime.now().subtract(Duration(minutes: 5)),
      );
    } catch (e) {
      print('Error getting iOS process info: $e');
      return null;
    }
  }
  
  /// Get process name from PID
  Future<String> _getProcessName(int pid) async {
    try {
      // Read from /proc/$pid/cmdline
      final cmdlineFile = File('/proc/$pid/cmdline');
      if (await cmdlineFile.exists()) {
        final content = await cmdlineFile.readAsString();
        return content.split('\u0000').first;
      }
    } catch (e) {
      print('Error getting process name for PID $pid: $e');
    }
    
    // Mock data
    final mockNames = {
      1000: 'system_server',
      2000: 'com.android.systemui',
      3000: 'com.google.android.gms',
      4000: 'com.android.chrome',
      5000: 'com.suspicious.app',
    };
    
    return mockNames[pid] ?? 'process_$pid';
  }
  
  /// Get package name from process
  Future<String> _getProcessPackage(int pid) async {
    // In production, use ActivityManager or parse /proc/$pid/
    
    final mockPackages = {
      1000: 'android',
      2000: 'com.android.systemui',
      3000: 'com.google.android.gms',
      4000: 'com.android.chrome',
      5000: 'com.suspicious.app',
    };
    
    return mockPackages[pid] ?? 'unknown';
  }
  
  /// Get loaded native libraries
  Future<List<NativeLibrary>> _getLoadedLibraries(int pid) async {
    final libraries = <NativeLibrary>[];
    
    try {
      // In production, parse /proc/$pid/maps for .so files
      
      // Mock libraries
      final mockLibs = [
        'libc.so',
        'libart.so',
        'libandroid.so',
      ];
      
      if (pid == 5000) {
        // Add suspicious library for mock suspicious app
        mockLibs.add('libmalicious.so');
      }
      
      for (final libName in mockLibs) {
        libraries.add(NativeLibrary(
          name: libName,
          path: '/system/lib/$libName',
          hash: _calculateLibHash(libName),
          isSuspicious: _isSuspiciousLibrary(libName),
        ));
      }
    } catch (e) {
      print('Error getting loaded libraries for PID $pid: $e');
    }
    
    return libraries;
  }
  
  /// Get open sockets/ports
  Future<List<NetworkSocket>> _getOpenSockets(int pid) async {
    final sockets = <NetworkSocket>[];
    
    try {
      // In production, parse /proc/net/tcp and /proc/net/tcp6
      // Filter by inode matching /proc/$pid/fd/*
      
      // Mock sockets
      if (pid == 4000) {
        // Chrome with normal HTTPS connection
        sockets.add(NetworkSocket(
          protocol: 'TCP',
          localAddress: '192.168.1.100',
          localPort: 54321,
          remoteAddress: '142.250.185.78',
          remotePort: 443,
          state: 'ESTABLISHED',
        ));
      }
      
      if (pid == 5000) {
        // Suspicious app with unusual port
        sockets.add(NetworkSocket(
          protocol: 'TCP',
          localAddress: '192.168.1.100',
          localPort: 12345,
          remoteAddress: '185.220.101.1',
          remotePort: 9050,
          state: 'ESTABLISHED',
        ));
      }
    } catch (e) {
      print('Error getting open sockets for PID $pid: $e');
    }
    
    return sockets;
  }
  
  /// Get IPC endpoints (Binder, Intent, etc.)
  Future<List<IPCEndpoint>> _getIPCEndpoints(int pid) async {
    final endpoints = <IPCEndpoint>[];
    
    try {
      // In production, use platform channels to call:
      // PackageManager to get exported components
      // Or parse binder transactions
      
      final packageName = await _getProcessPackage(pid);
      
      // Mock IPC endpoints
      endpoints.add(IPCEndpoint(
        type: 'Service',
        name: '$packageName.BackgroundService',
        packageName: packageName,
        isExported: false,
      ));
      
      if (pid == 5000) {
        // Suspicious exported service
        endpoints.add(IPCEndpoint(
          type: 'Service',
          name: '$packageName.CommandService',
          packageName: packageName,
          isExported: true,
        ));
      }
    } catch (e) {
      print('Error getting IPC endpoints for PID $pid: $e');
    }
    
    return endpoints;
  }
  
  /// Get memory usage in bytes
  Future<int> _getMemoryUsage(int pid) async {
    try {
      // In production, parse /proc/$pid/status
      // Look for VmRSS (resident memory)
      
      final mockMemory = {
        1000: 100 * 1024 * 1024,
        2000: 50 * 1024 * 1024,
        3000: 200 * 1024 * 1024,
        4000: 150 * 1024 * 1024,
        5000: 80 * 1024 * 1024,
      };
      
      return mockMemory[pid] ?? 50 * 1024 * 1024;
    } catch (e) {
      print('Error getting memory usage for PID $pid: $e');
      return 0;
    }
  }
  
  /// Get CPU usage percentage
  Future<double> _getCPUUsage(int pid) async {
    try {
      // In production, parse /proc/$pid/stat
      // Calculate CPU usage from utime and stime
      
      final mockCPU = {
        1000: 15.5,
        2000: 2.3,
        3000: 5.1,
        4000: 8.7,
        5000: 25.8, // Suspicious high CPU
      };
      
      return mockCPU[pid] ?? 1.0;
    } catch (e) {
      print('Error getting CPU usage for PID $pid: $e');
      return 0.0;
    }
  }
  
  /// Calculate library hash
  String _calculateLibHash(String libName) {
    // In production, read actual library file and calculate SHA256
    return sha256.convert(utf8.encode(libName)).toString();
  }
  
  /// Check if library is suspicious
  bool _isSuspiciousLibrary(String libName) {
    final suspiciousLibs = [
      'libmalicious',
      'libhook',
      'libinject',
      'libexploit',
      'libroot',
      'libsu',
      'libfrida',
      'libxposed',
    ];
    
    return suspiciousLibs.any((name) => 
      libName.toLowerCase().contains(name));
  }
  
  /// Find processes by package name
  Future<List<ProcessInfo>> findProcessesByPackage(String packageName) async {
    final allProcesses = await analyzeRunningProcesses();
    return allProcesses.where((p) => p.packageName == packageName).toList();
  }
  
  /// Find processes with suspicious libraries
  Future<List<ProcessInfo>> findProcessesWithSuspiciousLibraries() async {
    final allProcesses = await analyzeRunningProcesses();
    return allProcesses.where((p) => 
      p.loadedLibraries.any((lib) => lib.isSuspicious)).toList();
  }
  
  /// Find processes with unusual network activity
  Future<List<ProcessInfo>> findProcessesWithUnusualNetwork() async {
    final allProcesses = await analyzeRunningProcesses();
    return allProcesses.where((p) => 
      p.openSockets.any((socket) => 
        socket.remotePort == 9050 || // Tor
        socket.remotePort == 4444 || // Common backdoor
        socket.remotePort == 31337   // Elite hacker port
      )).toList();
  }
}
