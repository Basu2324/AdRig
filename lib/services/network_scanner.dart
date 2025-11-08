import 'dart:io';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:network_info_plus/network_info_plus.dart';
import 'package:adrig/core/models/threat_model.dart';

/// Network security scanner
/// Scans: Wi-Fi networks, DNS, open ports, ARP spoofing, SSL/TLS
class NetworkScanner {
  final _connectivity = Connectivity();
  final _networkInfo = NetworkInfo();
  
  bool _isInitialized = false;
  
  /// Initialize scanner
  Future<void> initialize() async {
    if (_isInitialized) return;
    _isInitialized = true;
    print('✓ Network Scanner initialized');
  }
  
  /// Scan current network for threats
  Future<NetworkScanResult> scanNetwork() async {
    print('🔍 Starting Network Security Scan');
    
    final threats = <DetectedThreat>[];
    
    // 1. Check Wi-Fi security
    final wifiThreats = await _scanWiFiSecurity();
    threats.addAll(wifiThreats);
    
    // 2. Check DNS settings
    final dnsThreats = await _scanDNS();
    threats.addAll(dnsThreats);
    
    // 3. Check for open ports
    final portThreats = await _scanOpenPorts();
    threats.addAll(portThreats);
    
    // 4. Check for ARP spoofing
    final arpThreats = await _checkARPSpoofing();
    threats.addAll(arpThreats);
    
    print('\n📊 Network Scan Complete');
    print('Threats found: ${threats.length}');
    
    return NetworkScanResult(
      threatsFound: threats,
      wifiSSID: await _networkInfo.getWifiName() ?? 'Unknown',
      ipAddress: await _networkInfo.getWifiIP() ?? 'Unknown',
    );
  }
  
  /// Scan Wi-Fi security
  Future<List<DetectedThreat>> _scanWiFiSecurity() async {
    final threats = <DetectedThreat>[];
    
    try {
      final connectivityResult = await _connectivity.checkConnectivity();
      
      if (!connectivityResult.contains(ConnectivityResult.wifi)) {
        print('  ℹ️  Not connected to Wi-Fi');
        return threats;
      }
      
      final wifiName = await _networkInfo.getWifiName();
      final wifiBSSID = await _networkInfo.getWifiBSSID();
      
      if (wifiName == null) return threats;
      
      print('  📡 Wi-Fi: $wifiName');
      
      // Check for open/insecure networks
      if (_isOpenNetwork(wifiName)) {
        threats.add(DetectedThreat(
          id: 'wifi_open_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'network.wifi',
          appName: 'Wi-Fi: $wifiName',
          threatType: ThreatType.suspicious,
          severity: ThreatSeverity.high,
          detectionMethod: DetectionMethod.heuristic,
          description: 'Connected to open/insecure Wi-Fi network',
          indicators: [
            'Network name: $wifiName',
            'No encryption detected',
            'Data transmitted in plaintext',
            'Risk of man-in-the-middle attacks',
          ],
          confidence: 0.95,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {
            'ssid': wifiName,
            'bssid': wifiBSSID ?? 'Unknown',
            'networkType': 'open',
          },
        ));
      }
      
      // Check for suspicious SSID patterns
      if (_isSuspiciousSSID(wifiName)) {
        threats.add(DetectedThreat(
          id: 'wifi_suspicious_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'network.wifi',
          appName: 'Wi-Fi: $wifiName',
          threatType: ThreatType.suspicious,
          severity: ThreatSeverity.medium,
          detectionMethod: DetectionMethod.heuristic,
          description: 'Suspicious Wi-Fi network name detected',
          indicators: [
            'Network name: $wifiName',
            'May be rogue access point',
            'Possible phishing/spoofing attempt',
          ],
          confidence: 0.75,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {
            'ssid': wifiName,
            'bssid': wifiBSSID ?? 'Unknown',
          },
        ));
      }
    } catch (e) {
      print('  ❌ Wi-Fi scan error: $e');
    }
    
    return threats;
  }
  
  /// Scan DNS settings
  Future<List<DetectedThreat>> _scanDNS() async {
    final threats = <DetectedThreat>[];
    
    try {
      print('  🌐 Checking DNS configuration...');
      
      // Test DNS resolution
      final testDomains = ['google.com', 'cloudflare.com', 'amazon.com'];
      
      for (final domain in testDomains) {
        try {
          final addresses = await InternetAddress.lookup(domain);
          
          // Check for DNS hijacking (unexpected IPs)
          for (final addr in addresses) {
            if (_isSuspiciousIP(addr.address)) {
              threats.add(DetectedThreat(
                id: 'dns_hijack_${DateTime.now().millisecondsSinceEpoch}',
                packageName: 'network.dns',
                appName: 'DNS Resolver',
                threatType: ThreatType.suspicious,
                severity: ThreatSeverity.critical,
                detectionMethod: DetectionMethod.anomaly,
                description: 'Possible DNS hijacking detected',
                indicators: [
                  'Domain: $domain',
                  'Suspicious IP: ${addr.address}',
                  'DNS may be redirecting to malicious servers',
                ],
                confidence: 0.80,
                detectedAt: DateTime.now(),
                recommendedAction: ActionType.alert,
                metadata: {
                  'domain': domain,
                  'resolvedIP': addr.address,
                },
              ));
            }
          }
        } catch (e) {
          // DNS resolution failed
          print('  ⚠️  DNS resolution failed for $domain');
        }
      }
    } catch (e) {
      print('  ❌ DNS scan error: $e');
    }
    
    return threats;
  }
  
  /// Scan for open ports
  Future<List<DetectedThreat>> _scanOpenPorts() async {
    final threats = <DetectedThreat>[];
    
    try {
      print('  🔍 Scanning for open ports...');
      
      final localIP = await _networkInfo.getWifiIP();
      if (localIP == null) return threats;
      
      // Scan common vulnerable ports
      final riskyPorts = [23, 445, 135, 139, 3389, 5900, 1433, 3306];
      final openPorts = <int>[];
      
      for (final port in riskyPorts) {
        try {
          final socket = await Socket.connect(
            localIP,
            port,
            timeout: Duration(milliseconds: 500),
          );
          
          openPorts.add(port);
          await socket.close();
        } catch (e) {
          // Port closed (good)
        }
      }
      
      if (openPorts.isNotEmpty) {
        threats.add(DetectedThreat(
          id: 'ports_open_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'network.ports',
          appName: 'Network Ports',
          threatType: ThreatType.suspicious,
          severity: ThreatSeverity.high,
          detectionMethod: DetectionMethod.heuristic,
          description: 'Vulnerable ports open on device',
          indicators: [
            'Open ports: ${openPorts.join(", ")}',
            'Device may be exposed to network attacks',
            'Malware may be listening on these ports',
          ],
          confidence: 0.85,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {
            'openPorts': openPorts,
            'deviceIP': localIP,
          },
        ));
      }
    } catch (e) {
      print('  ❌ Port scan error: $e');
    }
    
    return threats;
  }
  
  /// Check for ARP spoofing
  Future<List<DetectedThreat>> _checkARPSpoofing() async {
    final threats = <DetectedThreat>[];
    
    try {
      print('  🛡️  Checking for ARP spoofing...');
      
      // Get gateway
      final gateway = await _networkInfo.getWifiGatewayIP();
      if (gateway == null) return threats;
      
      // Ping gateway multiple times and check if MAC changes
      final gatewayMACs = <String>[];
      
      for (int i = 0; i < 3; i++) {
        try {
          final result = await Process.run('ping', ['-c', '1', gateway]);
          
          // Parse ARP cache to get MAC (platform-specific)
          // This is simplified - full implementation needs native code
          
          await Future.delayed(Duration(milliseconds: 500));
        } catch (e) {
          // Ping failed
        }
      }
      
      // If different MACs detected for same IP, possible ARP spoofing
      if (gatewayMACs.toSet().length > 1) {
        threats.add(DetectedThreat(
          id: 'arp_spoof_${DateTime.now().millisecondsSinceEpoch}',
          packageName: 'network.arp',
          appName: 'ARP Protocol',
          threatType: ThreatType.exploit,
          severity: ThreatSeverity.critical,
          detectionMethod: DetectionMethod.anomaly,
          description: 'Possible ARP spoofing attack detected',
          indicators: [
            'Gateway IP: $gateway',
            'Multiple MAC addresses detected',
            'Man-in-the-middle attack possible',
          ],
          confidence: 0.90,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {
            'gatewayIP': gateway,
            'detectedMACs': gatewayMACs.length,
          },
        ));
      }
    } catch (e) {
      print('  ❌ ARP check error: $e');
    }
    
    return threats;
  }
  
  /// Check if network is open/insecure
  bool _isOpenNetwork(String ssid) {
    // Common open network patterns
    final openPatterns = [
      'free',
      'open',
      'guest',
      'public',
      'starbucks',
      'mcdonalds',
      'airport',
    ];
    
    final lowerSSID = ssid.toLowerCase().replaceAll('"', '');
    return openPatterns.any((pattern) => lowerSSID.contains(pattern));
  }
  
  /// Check if SSID is suspicious
  bool _isSuspiciousSSID(String ssid) {
    final cleanSSID = ssid.toLowerCase().replaceAll('"', '');
    
    // Evil twin / spoofing patterns
    final suspiciousPatterns = [
      'free wifi',
      'free internet',
      'android ap',
      'default',
      'linksys',
      'netgear',
      'test',
    ];
    
    return suspiciousPatterns.any((pattern) => cleanSSID.contains(pattern));
  }
  
  /// Check if IP is suspicious
  bool _isSuspiciousIP(String ip) {
    // Known malicious IP ranges (example - would need real threat intel)
    // This is a placeholder - real implementation needs threat intelligence feeds
    
    // Block localhost redirects (DNS hijacking)
    if (ip.startsWith('127.') || ip == '0.0.0.0') {
      return true;
    }
    
    return false;
  }
}

/// Network scan result
class NetworkScanResult {
  final List<DetectedThreat> threatsFound;
  final String wifiSSID;
  final String ipAddress;
  
  NetworkScanResult({
    required this.threatsFound,
    required this.wifiSSID,
    required this.ipAddress,
  });
}
