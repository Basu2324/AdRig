import 'dart:async';
import 'package:adrig/core/models/threat_model.dart';

/// Behavioral Sequence Detection Engine
/// Detects multi-step attack patterns by correlating events over time
/// Examples: download→write→execute→exfiltrate, install→hide→spy→send
class BehavioralSequenceEngine {
  // Active sequence tracking
  final Map<String, List<BehavioralEvent>> _eventHistory = {};
  final Map<String, DateTime> _lastEventTime = {};
  
  // Sequence rules database
  final List<SequenceRule> _rules = [];
  
  // Detection configuration
  static const Duration _sequenceWindow = Duration(minutes: 30);
  static const int _maxHistoryPerApp = 100;
  
  /// Initialize with built-in attack sequence rules
  void initialize() {
    initializeRules();
  }
  
  /// Get number of loaded sequence rules
  int getRuleCount() {
    return _rules.length;
  }
  
  /// Initialize with built-in attack sequence rules
  void initializeRules() {
    _rules.addAll([
      // ============= MALWARE INSTALLATION SEQUENCES =============
      
      SequenceRule(
        id: 'seq_dropper_001',
        name: 'Dropper Installation Chain',
        description: 'Downloads payload → Writes to disk → Executes binary',
        pattern: [
          EventPattern(type: EventType.networkDownload, requiredAttributes: {'file_type': 'binary'}),
          EventPattern(type: EventType.fileWrite, requiredAttributes: {'location': 'external_storage'}),
          EventPattern(type: EventType.processExecution, requiredAttributes: {'source': 'downloaded'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 5),
        confidence: 0.95,
      ),
      
      SequenceRule(
        id: 'seq_dropper_002',
        name: 'Multi-Stage Dropper',
        description: 'Downloads APK → Requests install permission → Installs silently',
        pattern: [
          EventPattern(type: EventType.networkDownload, requiredAttributes: {'extension': '.apk'}),
          EventPattern(type: EventType.permissionRequest, requiredAttributes: {'permission': 'INSTALL_PACKAGES'}),
          EventPattern(type: EventType.packageInstall),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 10),
        confidence: 0.90,
      ),
      
      // ============= DATA EXFILTRATION SEQUENCES =============
      
      SequenceRule(
        id: 'seq_exfil_001',
        name: 'Contact Exfiltration',
        description: 'Reads contacts → Encrypts data → Sends to C2',
        pattern: [
          EventPattern(type: EventType.dataAccess, requiredAttributes: {'data_type': 'contacts'}),
          EventPattern(type: EventType.cryptoOperation, requiredAttributes: {'operation': 'encrypt'}),
          EventPattern(type: EventType.networkUpload, requiredAttributes: {'protocol': 'https'}),
        ],
        severity: ThreatSeverity.high,
        maxTimeWindow: Duration(minutes: 15),
        confidence: 0.88,
      ),
      
      SequenceRule(
        id: 'seq_exfil_002',
        name: 'SMS Theft Chain',
        description: 'Reads SMS → Encodes → Exfiltrates',
        pattern: [
          EventPattern(type: EventType.dataAccess, requiredAttributes: {'data_type': 'sms'}),
          EventPattern(type: EventType.cryptoOperation),
          EventPattern(type: EventType.networkUpload),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 5),
        confidence: 0.92,
      ),
      
      // ============= SPYWARE SEQUENCES =============
      
      SequenceRule(
        id: 'seq_spy_001',
        name: 'Location Tracking Chain',
        description: 'Gets location → Sends to server → Repeats periodically',
        pattern: [
          EventPattern(type: EventType.locationAccess),
          EventPattern(type: EventType.networkUpload, requiredAttributes: {'contains': 'coordinates'}),
          EventPattern(type: EventType.locationAccess), // Repeated access
        ],
        severity: ThreatSeverity.high,
        maxTimeWindow: Duration(minutes: 30),
        confidence: 0.85,
      ),
      
      SequenceRule(
        id: 'seq_spy_002',
        name: 'Keylogger Sequence',
        description: 'Accessibility capture → Buffer keystrokes → Send to C2',
        pattern: [
          EventPattern(type: EventType.accessibilityEvent, requiredAttributes: {'event': 'TYPE_VIEW_TEXT_CHANGED'}),
          EventPattern(type: EventType.fileWrite, requiredAttributes: {'purpose': 'buffer'}),
          EventPattern(type: EventType.networkUpload),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 10),
        confidence: 0.93,
      ),
      
      // ============= RANSOMWARE SEQUENCES =============
      
      SequenceRule(
        id: 'seq_ransom_001',
        name: 'File Encryption Attack',
        description: 'Scans files → Encrypts multiple → Displays ransom note',
        pattern: [
          EventPattern(type: EventType.fileEnumeration),
          EventPattern(type: EventType.cryptoOperation, requiredAttributes: {'operation': 'encrypt'}),
          EventPattern(type: EventType.uiDisplay, requiredAttributes: {'contains': 'payment'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 20),
        confidence: 0.97,
      ),
      
      SequenceRule(
        id: 'seq_ransom_002',
        name: 'Screen Lock Ransomware',
        description: 'Gains device admin → Locks screen → Demands payment',
        pattern: [
          EventPattern(type: EventType.permissionRequest, requiredAttributes: {'permission': 'DEVICE_ADMIN'}),
          EventPattern(type: EventType.screenLock),
          EventPattern(type: EventType.uiDisplay, requiredAttributes: {'contains': 'bitcoin'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 15),
        confidence: 0.95,
      ),
      
      // ============= BANKING TROJAN SEQUENCES =============
      
      SequenceRule(
        id: 'seq_banking_001',
        name: 'Overlay Attack Chain',
        description: 'Detects banking app → Creates overlay → Captures credentials',
        pattern: [
          EventPattern(type: EventType.appLaunch, requiredAttributes: {'app_category': 'banking'}),
          EventPattern(type: EventType.overlayCreate, requiredAttributes: {'type': 'SYSTEM_ALERT_WINDOW'}),
          EventPattern(type: EventType.dataCapture, requiredAttributes: {'data_type': 'credentials'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 5),
        confidence: 0.96,
      ),
      
      SequenceRule(
        id: 'seq_banking_002',
        name: 'SMS Interception for 2FA',
        description: 'Intercepts SMS → Parses OTP → Forwards to attacker',
        pattern: [
          EventPattern(type: EventType.smsReceived),
          EventPattern(type: EventType.dataAccess, requiredAttributes: {'data_type': 'sms', 'action': 'parse'}),
          EventPattern(type: EventType.networkUpload, requiredAttributes: {'contains': 'otp'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(seconds: 30),
        confidence: 0.94,
      ),
      
      // ============= PRIVILEGE ESCALATION SEQUENCES =============
      
      SequenceRule(
        id: 'seq_escalation_001',
        name: 'Root Exploit Chain',
        description: 'Exploits vulnerability → Gains root → Installs backdoor',
        pattern: [
          EventPattern(type: EventType.processExecution, requiredAttributes: {'binary': 'exploit'}),
          EventPattern(type: EventType.privilegeEscalation, requiredAttributes: {'target': 'root'}),
          EventPattern(type: EventType.fileWrite, requiredAttributes: {'location': '/system'}),
        ],
        severity: ThreatSeverity.critical,
        maxTimeWindow: Duration(minutes: 10),
        confidence: 0.98,
      ),
      
      // ============= CRYPTOMINING SEQUENCES =============
      
      SequenceRule(
        id: 'seq_crypto_001',
        name: 'Cryptominer Deployment',
        description: 'Downloads miner → Executes in background → High CPU usage',
        pattern: [
          EventPattern(type: EventType.networkDownload, requiredAttributes: {'file_type': 'binary'}),
          EventPattern(type: EventType.processExecution, requiredAttributes: {'cpu_usage': 'high'}),
          EventPattern(type: EventType.networkConnection, requiredAttributes: {'port': '3333'}), // Mining pool
        ],
        severity: ThreatSeverity.high,
        maxTimeWindow: Duration(minutes: 15),
        confidence: 0.87,
      ),
    ]);
    
    print('✅ Initialized ${_rules.length} behavioral sequence rules');
  }
  
  /// Record a behavioral event
  void recordEvent(String packageName, BehavioralEvent event) {
    // Initialize history if needed
    _eventHistory.putIfAbsent(packageName, () => []);
    
    // Add event to history
    _eventHistory[packageName]!.add(event);
    _lastEventTime[packageName] = event.timestamp;
    
    // Limit history size
    if (_eventHistory[packageName]!.length > _maxHistoryPerApp) {
      _eventHistory[packageName]!.removeAt(0);
    }
    
    // Clean old events outside time window
    _cleanOldEvents(packageName);
  }
  
  /// Detect active attack sequences
  List<SequenceDetection> detectSequences(String packageName) {
    final detections = <SequenceDetection>[];
    
    if (!_eventHistory.containsKey(packageName)) {
      return detections;
    }
    
    final events = _eventHistory[packageName]!;
    
    // Test each rule
    for (final rule in _rules) {
      final match = _matchSequence(events, rule);
      if (match != null) {
        detections.add(match);
      }
    }
    
    return detections;
  }
  
  /// Match events against a sequence rule
  SequenceDetection? _matchSequence(List<BehavioralEvent> events, SequenceRule rule) {
    if (events.length < rule.pattern.length) return null;
    
    // Try to find matching sequence
    for (var i = 0; i <= events.length - rule.pattern.length; i++) {
      final matchedEvents = <BehavioralEvent>[];
      var patternIndex = 0;
      
      for (var j = i; j < events.length && patternIndex < rule.pattern.length; j++) {
        final event = events[j];
        final expectedPattern = rule.pattern[patternIndex];
        
        // Check if event matches pattern
        if (_eventMatchesPattern(event, expectedPattern)) {
          matchedEvents.add(event);
          patternIndex++;
          
          // Check time window
          if (matchedEvents.length > 1) {
            final timeSpan = matchedEvents.last.timestamp.difference(matchedEvents.first.timestamp);
            if (timeSpan > rule.maxTimeWindow) {
              break; // Exceeded time window
            }
          }
        }
      }
      
      // Full sequence matched?
      if (patternIndex == rule.pattern.length) {
        return SequenceDetection(
          rule: rule,
          matchedEvents: matchedEvents,
          startTime: matchedEvents.first.timestamp,
          endTime: matchedEvents.last.timestamp,
          confidence: rule.confidence,
        );
      }
    }
    
    return null;
  }
  
  /// Check if event matches pattern
  bool _eventMatchesPattern(BehavioralEvent event, EventPattern pattern) {
    // Type must match
    if (event.type != pattern.type) return false;
    
    // Check required attributes
    for (final entry in pattern.requiredAttributes.entries) {
      final key = entry.key;
      final expectedValue = entry.value;
      
      if (key == 'contains') {
        // Special case: check if any attribute contains the value
        final found = event.attributes.values.any((v) => 
          v.toString().toLowerCase().contains(expectedValue.toString().toLowerCase())
        );
        if (!found) return false;
      } else {
        // Exact match
        if (!event.attributes.containsKey(key)) return false;
        if (event.attributes[key].toString().toLowerCase() != 
            expectedValue.toString().toLowerCase()) {
          return false;
        }
      }
    }
    
    return true;
  }
  
  /// Clean events outside time window
  void _cleanOldEvents(String packageName) {
    if (!_eventHistory.containsKey(packageName)) return;
    
    final now = DateTime.now();
    _eventHistory[packageName]!.removeWhere((event) =>
      now.difference(event.timestamp) > _sequenceWindow
    );
  }
  
  /// Get statistics
  Map<String, dynamic> getStatistics() {
    return {
      'total_rules': _rules.length,
      'tracked_apps': _eventHistory.length,
      'total_events': _eventHistory.values.fold<int>(0, (sum, events) => sum + events.length),
      'active_sequences': _eventHistory.values
          .map((events) => _rules.where((rule) => _matchSequence(events, rule) != null).length)
          .fold<int>(0, (sum, count) => sum + count),
    };
  }
  
  /// Clear history for an app
  void clearHistory(String packageName) {
    _eventHistory.remove(packageName);
    _lastEventTime.remove(packageName);
  }
}

/// Behavioral event types
enum EventType {
  networkDownload,
  networkUpload,
  networkConnection,
  fileWrite,
  fileRead,
  fileDelete,
  fileEnumeration,
  processExecution,
  permissionRequest,
  packageInstall,
  dataAccess,
  cryptoOperation,
  locationAccess,
  accessibilityEvent,
  uiDisplay,
  screenLock,
  appLaunch,
  overlayCreate,
  dataCapture,
  smsReceived,
  privilegeEscalation,
}

/// Behavioral event
class BehavioralEvent {
  final EventType type;
  final Map<String, dynamic> attributes;
  final DateTime timestamp;
  
  BehavioralEvent({
    required this.type,
    required this.attributes,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();
}

/// Event pattern for matching
class EventPattern {
  final EventType type;
  final Map<String, String> requiredAttributes;
  
  EventPattern({
    required this.type,
    this.requiredAttributes = const {},
  });
}

/// Sequence detection rule
class SequenceRule {
  final String id;
  final String name;
  final String description;
  final List<EventPattern> pattern;
  final ThreatSeverity severity;
  final Duration maxTimeWindow;
  final double confidence;
  
  SequenceRule({
    required this.id,
    required this.name,
    required this.description,
    required this.pattern,
    required this.severity,
    required this.maxTimeWindow,
    required this.confidence,
  });
}

/// Detected sequence
class SequenceDetection {
  final SequenceRule rule;
  final List<BehavioralEvent> matchedEvents;
  final DateTime startTime;
  final DateTime endTime;
  final double confidence;
  
  SequenceDetection({
    required this.rule,
    required this.matchedEvents,
    required this.startTime,
    required this.endTime,
    required this.confidence,
  });
  
  Duration get duration => endTime.difference(startTime);
  
  String get summary => '${rule.name}: ${matchedEvents.length} events over ${duration.inSeconds}s';
  
  String get ruleName => rule.name;
  String get description => rule.description;
}
