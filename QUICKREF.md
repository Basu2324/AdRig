# MalwareScanner - Quick Reference Guide

## What It Does

**Real-time multi-layer malware detection** for Android apps using:
1. **Signature-based** detection (hash + permission patterns)
2. **Static analysis** (manifest, code structure, certificates)
3. **Behavioral monitoring** (network, processes, resources)
4. **Threat intelligence** (known IOCs, reputation)

## Files Structure

```
malware_scanner/
├── lib/
│   ├── core/
│   │   └── models/
│   │       └── threat_model.dart          # Data models (Threat, ScanResult, etc)
│   ├── services/
│   │   ├── device_data_collector.dart     # Enumerate apps, collect telemetry
│   │   ├── signature_engine.dart          # Hash + permission-based detection
│   │   ├── static_analysis_engine.dart    # Manifest, code, certificate analysis
│   │   ├── behavioral_anomaly_engine.dart # Runtime behavior monitoring
│   │   └── scan_coordinator.dart          # Orchestrates all engines
│   └── main.dart                          # UI app
├── ARCHITECTURE.md                        # Full technical documentation
└── README.md                              # This file
```

## Quick Start

### 1. Run Full Device Scan
```dart
import 'services/scan_coordinator.dart';
import 'services/device_data_collector.dart';

final coordinator = ScanCoordinator();
final collector = DeviceDataCollector();

// Get installed apps
final apps = await collector.getInstalledApps();

// Scan everything
final result = await coordinator.scanInstalledApps(apps);

// View results
print('Found ${result.totalThreatsFound} threats');
result.threats.forEach((threat) {
  print('${threat.appName}: ${threat.description}');
});
```

### 2. Scan Single File
```dart
final threats = await coordinator.scanFile('/path/to/app.apk');
```

### 3. Update Detection Rules
```dart
// Add new malware signature
final newSig = MalwareSignature(
  id: 'sig_new_1',
  hash: 'abc123...',
  hashType: 'md5',
  malwareName: 'NewTrojan.X',
  threatType: ThreatType.trojan,
  severity: ThreatSeverity.critical,
);
coordinator.updateSignatures([newSig]);

// Add IOC
final ioc = ThreatIndicator(
  id: 'ioc_1',
  indicator: 'evil.c2.com',
  indicatorType: 'domain',
  source: 'threat_feed',
  severity: ThreatSeverity.critical,
  lastSeen: DateTime.now(),
  confidence: 95,
);
coordinator.updateThreatIndicators([ioc]);
```

## Detection Methods

### Signature Engine
```
✓ Hash-based: MD5/SHA1/SHA256 against malware database
✓ Ransomware: storage write + delete access patterns
✓ Spyware: location + contacts + camera + microphone
✓ Trojans: accessibility service + clipboard access
✓ IOC matching: known malicious domains/IPs
```

### Static Analysis
```
✓ Manifest flags: debuggable, cleartext traffic
✓ Code anomalies: huge size, excessive methods, unexpected native libs
✓ SDK risks: old target SDK versions = unpatched vulnerabilities
✓ Certificates: spoofing detection, verification
✓ Installer source: trust verification (Play Store, Galaxy Store, etc)
✓ String patterns: hardcoded C2 servers, malware commands
```

### Behavioral Detection
```
✓ Network beaconing: repeated connections to same server
✓ Process anomalies: code injection (ptrace), privilege escalation
✓ Resource abuse: >80% CPU, >500MB memory, >1GB data transfer
✓ Permission misuse: camera/mic use without notification
✓ File operations: ransomware-like write patterns
```

### Threat Intelligence
```
✓ IOC database queries: malicious domains/IPs
✓ Reputation scoring: aggregate threat data
✓ Community detection: crowd-sourced threats
✓ Threat feeds: automated updates
```

## Key Classes

### ScanCoordinator
**Main orchestrator** - runs all 4 detection stages

```dart
ScanCoordinator coordinator = ScanCoordinator();
ScanResult result = await coordinator.scanInstalledApps(apps);
```

### DeviceDataCollector
**Collects app info**

```dart
DeviceDataCollector collector = DeviceDataCollector();
List<AppMetadata> apps = await collector.getInstalledApps();
Map<String, String> hashes = await collector.calculateFileHashes(path);
```

### SignatureEngine
**Hash + permission detection**

```dart
SignatureEngine engine = SignatureEngine();
engine.initializeSampleSignatures();
List<DetectedThreat> threats = engine.detectPermissionPatterns(...);
```

### StaticAnalysisEngine
**Code & manifest analysis**

```dart
StaticAnalysisEngine analyzer = StaticAnalysisEngine();
List<DetectedThreat> threats = analyzer.analyzeManifest(...);
```

### BehavioralAnomalyEngine
**Runtime behavior monitoring**

```dart
BehavioralAnomalyEngine behavioral = BehavioralAnomalyEngine();
List<DetectedThreat> threats = behavioral.detectNetworkBeaconing(...);
```

## Data Models

### DetectedThreat
```dart
class DetectedThreat {
  String id;
  String packageName;        // com.example.app
  String appName;            // "MyApp"
  ThreatType threatType;     // trojan, ransomware, spyware, etc
  ThreatSeverity severity;   // critical, high, medium, low, info
  DetectionMethod method;    // signature, behavioral, static, etc
  String description;        // What was detected
  List<String> indicators;   // Evidence (permissions, domains, etc)
  double confidence;         // 0.0 - 1.0 (99% = 0.99)
  ActionType action;         // quarantine, alert, block, etc
}
```

### ScanResult
```dart
class ScanResult {
  String scanId;             // Unique scan ID
  DateTime startTime;        // When scan started
  DateTime endTime;          // When scan finished
  int totalApps;             // Apps scanned
  int totalThreatsFound;     // Number of threats
  List<DetectedThreat> threats;  // List of threats
  ScanStatistics statistics; // Summary stats
  bool isComplete;           // Scan finished?
}
```

### ScanStatistics
```dart
class ScanStatistics {
  int criticalThreats;       // Count by severity
  int highThreats;
  int mediumThreats;
  int lowThreats;
  int infoThreats;
  Duration scanDuration;     // How long it took
  double averageConfidence;  // Avg confidence of detections
  int appsScanned;
  int filesScanned;
  Map<String, int> detectionMethodCounts;  // Which methods caught what
}
```

## Severity Levels

| Level | Score | Action | Examples |
|---|---|---|---|
| Critical | 5 | QUARANTINE | Banking trojan, ransomware |
| High | 4 | QUARANTINE/ALERT | Spyware, backdoor |
| Medium | 3 | ALERT | Risky permissions, old SDK |
| Low | 2 | MONITOR | Adware, suspicious activity |
| Info | 1 | LOG | Permission requested, pattern match |

## Confidence Ranges

| Confidence | Detection Type | Reliability |
|---|---|---|
| 0.99 | Hash match (signature) | Nearly certain |
| 0.85-0.95 | Multiple layers + behavioral | Very high |
| 0.70-0.85 | Static + behavioral | High |
| 0.60-0.70 | Single method | Medium |
| 0.50-0.60 | Anomaly scoring | Lower confidence |
| <0.50 | Single indicator | Requires human review |

## Performance

| Task | Time | Notes |
|---|---|---|
| Enumerate apps | <100ms | Native call |
| Scan 100 apps | 10-20s | All 4 stages |
| Hash single file | 50-500ms | Depends on size |
| Permission analysis | <1s per app | Fast pattern matching |
| Manifest analysis | <2s per app | XML parsing |
| Behavioral check | <1s per app | Profile comparison |

## Privacy Features

- ✅ **On-device first** - App enumeration, hashing, analysis all local
- ✅ **No app code uploaded** - Only hashes, not binaries
- ✅ **No interaction logs** - Doesn't track user behavior
- ✅ **Encrypted cloud** - Optional updates only
- ✅ **User consent** - Opt-in for threat feeds
- ✅ **Auto-delete** - Data purged after 30 days
- ✅ **Pseudonymized** - No device identifiers in reports

## Common Threats Detected

### Ransomware
- Detects: Write + delete + storage access patterns
- Confidence: 80-95%
- Action: QUARANTINE

### Spyware
- Detects: Camera/mic/location/contacts abuse
- Confidence: 75-90%
- Action: QUARANTINE/ALERT

### Banking Trojans
- Detects: Signature match + accessibility abuse
- Confidence: 95-99%
- Action: QUARANTINE

### Adware
- Detects: Aggressive ads + system permissions + tracking beacons
- Confidence: 70-85%
- Action: ALERT

### Droppers
- Detects: Process spawning (>5), code injection
- Confidence: 80-90%
- Action: QUARANTINE

## Deployment

### Build APK
```bash
flutter build apk --release
```

### Install
```bash
adb install -r build/app/outputs/flutter-app.apk
```

### Run Tests
```bash
flutter test
flutter analyze lib/
```

## Troubleshooting

### App not found
- Ensure you've called `getInstalledApps()` first
- Check package name matches exactly

### False positives
- Increase confidence threshold
- Use multiple detection layers (don't rely on single method)
- Fine-tune permission patterns

### Performance slow
- Reduce number of apps scanned
- Run behavioral monitoring in background
- Cache results

### OOM errors
- Reduce scan batch size
- Clear threat cache between scans
- Monitor memory usage

## Contributing

To add new detection methods:

1. Create new engine class inheriting base pattern
2. Implement detection logic
3. Return List<DetectedThreat>
4. Integrate into ScanCoordinator
5. Add unit tests
6. Update documentation

---

**Happy scanning!** 🛡️
