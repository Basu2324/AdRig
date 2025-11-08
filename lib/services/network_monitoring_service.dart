import 'dart:async';
import 'dart:io';
import 'package:adrig/core/models/threat_model.dart';

/// Network monitoring and telemetry service
/// Monitors real-time network connections for malicious activity
class NetworkMonitoringService {
  final Map<String, List<NetworkConnection>> _connectionHistory = {};
  final Map<String, NetworkStats> _networkStats = {};
  final Set<String> _blockedDomains = {};
  final Set<String> _blockedIps = {};
  
  bool _isMonitoring = false;
  StreamController<NetworkConnection>? _connectionStream;

  /// Start network monitoring
  Future<void> startMonitoring() async {
    if (_isMonitoring) return;

    try {
      _isMonitoring = true;
      _connectionStream = StreamController<NetworkConnection>.broadcast();
      
      // In production: use platform-specific APIs
      // Android: VpnService API, NetworkStatsManager
      // iOS: Network Extension framework
      
      print('🌐 Network monitoring started');
      
      // Simulate monitoring loop
      _monitoringLoop();
    } catch (e) {
      print('Error starting network monitoring: $e');
    }
  }

  /// Stop network monitoring
  Future<void> stopMonitoring() async {
    _isMonitoring = false;
    await _connectionStream?.close();
    _connectionStream = null;
    print('🛑 Network monitoring stopped');
  }

  /// Get network connections for a package
  List<NetworkConnection> getConnectionsForPackage(String packageName) {
    return _connectionHistory[packageName] ?? [];
  }

  /// Analyze network connections for threats
  List<DetectedThreat> analyzeConnections(
    String packageName,
    String appName,
  ) {
    final threats = <DetectedThreat>[];
    final connections = getConnectionsForPackage(packageName);

    if (connections.isEmpty) return threats;

    // Detect C2 beaconing patterns
    final beaconThreat = _detectBeaconing(packageName, appName, connections);
    if (beaconThreat != null) threats.add(beaconThreat);

    // Detect data exfiltration
    final exfiltrationThreat = _detectDataExfiltration(
      packageName,
      appName,
      connections,
    );
    if (exfiltrationThreat != null) threats.add(exfiltrationThreat);

    // Detect connections to known malicious domains/IPs
    final maliciousConnectionThreats = _detectMaliciousConnections(
      packageName,
      appName,
      connections,
    );
    threats.addAll(maliciousConnectionThreats);

    // Detect suspicious port usage
    final portThreats = _detectSuspiciousPorts(
      packageName,
      appName,
      connections,
    );
    threats.addAll(portThreats);

    return threats;
  }

  /// Detect C2 beaconing patterns
  DetectedThreat? _detectBeaconing(
    String packageName,
    String appName,
    List<NetworkConnection> connections,
  ) {
    if (connections.length < 5) return null;

    // Group connections by destination
    final destGroups = <String, List<NetworkConnection>>{};
    for (final conn in connections) {
      final key = '${conn.destinationIp}:${conn.destinationPort}';
      destGroups.putIfAbsent(key, () => []).add(conn);
    }

    // Check for beaconing (regular repeated connections)
    for (final entry in destGroups.entries) {
      if (entry.value.length < 5) continue;

      // Calculate time intervals
      final timestamps = entry.value.map((c) => c.timestamp).toList()
        ..sort();
      
      final intervals = <Duration>[];
      for (int i = 1; i < timestamps.length; i++) {
        intervals.add(timestamps[i].difference(timestamps[i - 1]));
      }

      // Check if intervals are regular (beaconing pattern)
      if (_isRegularInterval(intervals)) {
        final avgInterval = intervals.fold<Duration>(
          Duration.zero,
          (sum, d) => sum + d,
        ) ~/ intervals.length;

        return DetectedThreat(
          id: 'threat_beacon_${DateTime.now().millisecondsSinceEpoch}',
          packageName: packageName,
          appName: appName,
          threatType: ThreatType.trojan,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.behavioral,
          description: 'C2 beaconing detected - regular communication to ${entry.key}',
          indicators: [
            'Beacon frequency: every ${avgInterval.inSeconds}s',
            'Connection count: ${entry.value.length}',
            'Destination: ${entry.key}',
          ],
          confidence: 0.90,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.autoblock,
          metadata: {
            'beacon_destination': entry.key,
            'beacon_interval': avgInterval.inSeconds,
            'beacon_count': entry.value.length,
          },
        );
      }
    }

    return null;
  }

  /// Detect data exfiltration
  DetectedThreat? _detectDataExfiltration(
    String packageName,
    String appName,
    List<NetworkConnection> connections,
  ) {
    final totalBytes = connections.fold<int>(
      0,
      (sum, conn) => sum + conn.bytesTransferred,
    );

    // Threshold: > 100MB in session
    if (totalBytes > 100 * 1024 * 1024) {
      return DetectedThreat(
        id: 'threat_exfil_${DateTime.now().millisecondsSinceEpoch}',
        packageName: packageName,
        appName: appName,
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        detectionMethod: DetectionMethod.behavioral,
        description: 'Possible data exfiltration - excessive data transfer',
        indicators: [
          'Total bytes transferred: ${(totalBytes / 1024 / 1024).toStringAsFixed(2)} MB',
          'Connection count: ${connections.length}',
        ],
        confidence: 0.78,
        detectedAt: DateTime.now(),
        recommendedAction: ActionType.alert,
        metadata: {
          'bytes_transferred': totalBytes,
          'connection_count': connections.length,
        },
      );
    }

    return null;
  }

  /// Detect connections to malicious domains/IPs
  List<DetectedThreat> _detectMaliciousConnections(
    String packageName,
    String appName,
    List<NetworkConnection> connections,
  ) {
    final threats = <DetectedThreat>[];

    for (final conn in connections) {
      // Check against blocked lists
      if (_blockedDomains.contains(conn.destinationDomain) ||
          _blockedIps.contains(conn.destinationIp)) {
        threats.add(DetectedThreat(
          id: 'threat_malconn_${DateTime.now().millisecondsSinceEpoch}',
          packageName: packageName,
          appName: appName,
          threatType: ThreatType.trojan,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.threatintel,
          description: 'Connection to known malicious server',
          indicators: [
            'Domain: ${conn.destinationDomain}',
            'IP: ${conn.destinationIp}',
            'Port: ${conn.destinationPort}',
          ],
          confidence: 0.95,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.autoblock,
          metadata: {
            'destination': conn.destinationDomain ?? conn.destinationIp,
            'port': conn.destinationPort,
          },
        ));
      }
    }

    return threats;
  }

  /// Detect suspicious port usage
  List<DetectedThreat> _detectSuspiciousPorts(
    String packageName,
    String appName,
    List<NetworkConnection> connections,
  ) {
    final threats = <DetectedThreat>[];
    
    // Suspicious ports (common malware ports)
    final suspiciousPorts = {4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337};

    for (final conn in connections) {
      if (suspiciousPorts.contains(conn.destinationPort)) {
        threats.add(DetectedThreat(
          id: 'threat_port_${DateTime.now().millisecondsSinceEpoch}',
          packageName: packageName,
          appName: appName,
          threatType: ThreatType.backdoor,
          severity: ThreatSeverity.high,
          detectionMethod: DetectionMethod.behavioral,
          description: 'Connection to suspicious port ${conn.destinationPort}',
          indicators: [
            'Port: ${conn.destinationPort}',
            'Destination: ${conn.destinationIp}',
          ],
          confidence: 0.70,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {
            'port': conn.destinationPort,
            'destination': conn.destinationIp,
          },
        ));
      }
    }

    return threats;
  }

  /// Check if intervals are regular (beaconing)
  bool _isRegularInterval(List<Duration> intervals) {
    if (intervals.length < 3) return false;

    final avgSeconds = intervals.fold<int>(
      0,
      (sum, d) => sum + d.inSeconds,
    ) / intervals.length;

    // Check variance - intervals should be similar
    final variance = intervals.fold<double>(
      0.0,
      (sum, d) => sum + ((d.inSeconds - avgSeconds) * (d.inSeconds - avgSeconds)),
    ) / intervals.length;

    // Low variance = regular beaconing
    return variance < (avgSeconds * 0.2); // 20% tolerance
  }

  /// Block domain
  void blockDomain(String domain) {
    _blockedDomains.add(domain);
    print('🚫 Blocked domain: $domain');
  }

  /// Block IP
  void blockIp(String ip) {
    _blockedIps.add(ip);
    print('🚫 Blocked IP: $ip');
  }

  /// Get network stats for package
  NetworkStats? getNetworkStats(String packageName) {
    return _networkStats[packageName];
  }

  /// Monitoring loop (simulated)
  void _monitoringLoop() {
    // In production: integrate with VpnService/Network Extension
    // - Capture packets in real-time
    // - Parse connection data
    // - Emit connection events
    
    Timer.periodic(Duration(seconds: 5), (timer) {
      if (!_isMonitoring) {
        timer.cancel();
        return;
      }

      // Simulated connection event
      final conn = NetworkConnection(
        id: 'conn_${DateTime.now().millisecondsSinceEpoch}',
        packageName: 'com.example.app',
        destinationIp: '192.0.2.1',
        destinationDomain: 'example.com',
        destinationPort: 443,
        protocol: 'https',
        timestamp: DateTime.now(),
        bytesTransferred: 1024,
        isEncrypted: true,
        connectionType: 'outbound',
      );

      _recordConnection(conn);
    });
  }

  /// Record a network connection
  void _recordConnection(NetworkConnection conn) {
    _connectionHistory.putIfAbsent(conn.packageName, () => []).add(conn);
    _connectionStream?.add(conn);

    // Update stats
    final stats = _networkStats.putIfAbsent(
      conn.packageName,
      () => NetworkStats(
        packageName: conn.packageName,
        totalConnections: 0,
        totalBytesTransferred: 0,
        uniqueDestinations: <String>{},
        firstSeen: DateTime.now(),
        lastSeen: DateTime.now(),
      ),
    );

    stats.totalConnections++;
    stats.totalBytesTransferred += conn.bytesTransferred;
    stats.uniqueDestinations.add(conn.destinationDomain ?? conn.destinationIp);
    stats.lastSeen = DateTime.now();
  }

  /// Get connection stream
  Stream<NetworkConnection>? getConnectionStream() => _connectionStream?.stream;

  /// Is monitoring active
  bool isMonitoring() => _isMonitoring;

  /// Clear history for package
  void clearHistory(String packageName) {
    _connectionHistory.remove(packageName);
    _networkStats.remove(packageName);
  }
}

/// Network statistics for a package
class NetworkStats {
  final String packageName;
  int totalConnections;
  int totalBytesTransferred;
  Set<String> uniqueDestinations;
  DateTime firstSeen;
  DateTime lastSeen;

  NetworkStats({
    required this.packageName,
    required this.totalConnections,
    required this.totalBytesTransferred,
    required this.uniqueDestinations,
    required this.firstSeen,
    required this.lastSeen,
  });
}
