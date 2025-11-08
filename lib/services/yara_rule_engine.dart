import 'package:adrig/core/models/threat_model.dart';
import 'expanded_yara_rules.dart';

/// YARA-style rule engine for pattern-based detection
/// Now includes 100+ rules covering all major threat categories
class YaraRuleEngine {
  final Map<String, DetectionRule> _rules = {};
  final Map<String, RegExp> _compiledPatterns = {};

  /// Initialize with built-in detection rules (35 baseline + 67 expanded = 102 total)
  void initializeRules() {
    // Load expanded YARA rules first (67 new rules)
    _loadExpandedRules();
    
    // ============= BANKING TROJANS (Baseline 7 rules) =============
    
    _addRule(DetectionRule(
      id: 'rule_banking_001',
      name: 'Anubis Banking Trojan',
      pattern: r'(anubis|anubisbot|anb_config|twitter_api_key.*4XbFmLCKvPOz)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Anubis banking trojan - targets 250+ financial apps',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_002',
      name: 'Cerberus Banking Trojan',
      pattern: r'(cerberus|ceberus_bot|get_overlay_config|steal_sms_data|keylog_enable)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Cerberus banking trojan - overlay attacks & keylogging',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_003',
      name: 'Hydra Banking Trojan',
      pattern: r'(hydra_bot|brunhilda|overlay_injector|vnc_remote|accessibility_capture)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Hydra/Brunhilda banking trojan - VNC control & overlays',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_004',
      name: 'FluBot Banking Trojan',
      pattern: r'(flubot|cabassous|smishing_module|contact_harvest|banking_overlay)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects FluBot - SMS spreading banking trojan',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_005',
      name: 'Medusa Banking Trojan',
      pattern: r'(medusa_rat|screen_stream|vnc_session|banking_inject|teamviewer_hook)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Medusa banking trojan - RAT with screen streaming',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_006',
      name: 'Oscorp Banking Trojan',
      pattern: r'(oscorp|fake_bank_login|accessibility_hijack|sms_intercept)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Oscorp banking trojan - accessibility abuse',
    ));

    _addRule(DetectionRule(
      id: 'rule_banking_007',
      name: 'SharkBot Banking Trojan',
      pattern: r'(sharkbot|geofencing|atp_module|autofill_steal|direct_reply_intercept)',
      ruleType: 'banking_trojan',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects SharkBot - ATS (Automatic Transfer System) banking trojan',
    ));

    // ============= SPYWARE & STALKERWARE =============
    
    _addRule(DetectionRule(
      id: 'rule_spyware_001',
      name: 'Joker Spyware',
      pattern: r'(joker|bread_sms|subscription_fraud|silently_subscribe|premium_service)',
      ruleType: 'spyware',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Joker spyware - billing fraud and SMS subscription abuse',
    ));

    _addRule(DetectionRule(
      id: 'rule_spyware_002',
      name: 'AbstractEmu Spyware',
      pattern: r'(abstractemu|rooting_module|code_virtualization|password_stealer)',
      ruleType: 'spyware',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects AbstractEmu - rooting malware with code virtualization',
    ));

    _addRule(DetectionRule(
      id: 'rule_spyware_003',
      name: 'General Stalkerware Patterns',
      pattern: r'(spy_mode|stealth_mode|hide_icon|call_recording|gps_tracking|ambient_listening)',
      ruleType: 'spyware',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects stalkerware features - hidden tracking and monitoring',
    ));

    _addRule(DetectionRule(
      id: 'rule_spyware_004',
      name: 'TeaBot Spyware',
      pattern: r'(teabot|toddler|overlay_attack|accessibility_logger|screen_record)',
      ruleType: 'spyware',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects TeaBot - screen recording banking spyware',
    ));

    // ============= CRYPTO MINERS =============
    
    _addRule(DetectionRule(
      id: 'rule_miner_001',
      name: 'XMRig Crypto Miner',
      pattern: r'(xmrig|monero|cryptonight|randomx|mining_pool|donate\.v2\.xmrig)',
      ruleType: 'crypto_miner',
      threatType: ThreatType.pua,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects XMRig Monero cryptocurrency miner',
    ));

    _addRule(DetectionRule(
      id: 'rule_miner_002',
      name: 'CoinMiner Patterns',
      pattern: r'(stratum\+tcp://|pool\.minexmr|nanopool|ethermine|mining\.pool)',
      ruleType: 'crypto_miner',
      threatType: ThreatType.pua,
      severity: ThreatSeverity.medium,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects cryptocurrency mining pool connections',
    ));

    // ============= RATS (Remote Access Trojans) =============
    
    _addRule(DetectionRule(
      id: 'rule_rat_001',
      name: 'AhMyth RAT',
      pattern: r'(ahmyth|socket\.io|remote_camera|file_explorer|call_logs)',
      ruleType: 'rat',
      threatType: ThreatType.backdoor,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects AhMyth Android RAT - remote access trojan',
    ));

    _addRule(DetectionRule(
      id: 'rule_rat_002',
      name: 'DroidJack RAT',
      pattern: r'(droidjack|sandrorat|remote_shell|screen_capture|audio_record)',
      ruleType: 'rat',
      threatType: ThreatType.backdoor,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects DroidJack/SandroRAT - remote administration tool',
    ));

    _addRule(DetectionRule(
      id: 'rule_rat_003',
      name: 'SpyNote RAT',
      pattern: r'(spynote|cybergate|remote_admin|keylogger|live_screen)',
      ruleType: 'rat',
      threatType: ThreatType.backdoor,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects SpyNote RAT - keylogging and remote control',
    ));

    // ============= DROPPERS & LOADERS =============
    
    _addRule(DetectionRule(
      id: 'rule_dropper_001',
      name: 'Dynamic Code Loading',
      pattern: r'(DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadDex|loadClass)',
      ruleType: 'dropper',
      threatType: ThreatType.dropper,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects dynamic DEX loading - dropper/loader behavior',
    ));

    _addRule(DetectionRule(
      id: 'rule_dropper_002',
      name: 'Native Library Loading',
      pattern: r'(System\.loadLibrary|dlopen|dlsym|JNI_OnLoad)',
      ruleType: 'dropper',
      threatType: ThreatType.dropper,
      severity: ThreatSeverity.medium,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects suspicious native library loading',
    ));

    _addRule(DetectionRule(
      id: 'rule_dropper_003',
      name: 'Hidden APK/DEX in Assets',
      pattern: r'(assets/.*\.apk|assets/.*\.dex|assets/.*\.jar|classes.*\.dex)',
      ruleType: 'dropper',
      threatType: ThreatType.dropper,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects hidden executables in assets folder',
    ));

    // ============= GENERAL MALICIOUS PATTERNS =============
    
    _addRule(DetectionRule(
      id: 'rule_general_001',
      name: 'Shell Command Execution',
      pattern: r'(Runtime\.getRuntime\(\)\.exec|ProcessBuilder|/system/bin/su|/system/xbin/su)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.backdoor,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects shell command execution and root access attempts',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_002',
      name: 'Reflection API Abuse',
      pattern: r'(Class\.forName|Method\.invoke|Field\.get|setAccessible\(true\)|getDeclaredMethod)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.medium,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects Java reflection abuse for security bypass',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_003',
      name: 'Obfuscation Techniques',
      pattern: r'(base64_decode|Base64\.decode|decrypt|deobfuscate|unpack|xor_cipher)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.malware,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects code obfuscation and encryption techniques',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_004',
      name: 'C2 Communication',
      pattern: r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\.onion|\.tk|\.xyz|\.top|\.pw)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects C2 server communication patterns',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_005',
      name: 'SMS/Call Interception',
      pattern: r'(SmsManager\.sendTextMessage|android\.provider\.Telephony|abortBroadcast|onReceive.*SMS)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects SMS/call interception and manipulation',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_006',
      name: 'Accessibility Service Abuse',
      pattern: r'(AccessibilityService|TYPE_VIEW_CLICKED|performGlobalAction|findAccessibilityNodeInfo)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.trojan,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects accessibility service abuse for overlay attacks',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_007',
      name: 'Root Detection Bypass',
      pattern: r'(Magisk|Xposed|RootCloak|su_binary|busybox|SuperSU|hide_root)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.exploit,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects root detection bypass and hiding tools',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_008',
      name: 'Device Admin Abuse',
      pattern: r'(DeviceAdminReceiver|lockNow|wipeData|resetPassword|setPasswordQuality)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.ransomware,
      severity: ThreatSeverity.critical,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects device admin API abuse - ransomware indicator',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_009',
      name: 'Keylogging Patterns',
      pattern: r'(InputMethodService|KeyEvent|onKeyDown|logKeystrokes|captureInput)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects keylogging via InputMethodService',
    ));

    _addRule(DetectionRule(
      id: 'rule_general_010',
      name: 'Screen Recording/Capture',
      pattern: r'(MediaProjection|VirtualDisplay|createScreenCaptureIntent|getDisplayMetrics)',
      ruleType: 'malicious_behavior',
      threatType: ThreatType.spyware,
      severity: ThreatSeverity.high,
      enabled: true,
      lastUpdated: DateTime.now(),
      description: 'Detects screen recording and capture capabilities',
    ));
  }

  /// Add a new rule to the engine
  void _addRule(DetectionRule rule) {
    _rules[rule.id] = rule;
    try {
      _compiledPatterns[rule.id] = RegExp(rule.pattern, caseSensitive: false);
    } catch (e) {
      print('Error compiling rule ${rule.id}: $e');
    }
  }

  /// Scan code/strings against YARA rules
  List<DetectedThreat> scanWithRules(
    String packageName,
    String appName,
    List<String> codeStrings,
    Map<String, dynamic> metadata,
  ) {
    final threats = <DetectedThreat>[];
    final matchedRules = <String, List<String>>{};

    // Test each string against all enabled rules
    for (final rule in _rules.values.where((r) => r.enabled)) {
      final pattern = _compiledPatterns[rule.id];
      if (pattern == null) continue;

      final matches = <String>[];
      for (final codeString in codeStrings) {
        if (pattern.hasMatch(codeString)) {
          matches.add(codeString.length > 100
              ? '${codeString.substring(0, 100)}...'
              : codeString);
        }
      }

      if (matches.isNotEmpty) {
        matchedRules[rule.name] = matches;

        threats.add(DetectedThreat(
          id: 'threat_${DateTime.now().millisecondsSinceEpoch}_${rule.id}',
          packageName: packageName,
          appName: appName,
          threatType: rule.threatType,
          severity: rule.severity,
          detectionMethod: DetectionMethod.yara,
          description: '${rule.description} - Rule: ${rule.name}',
          indicators: matches,
          confidence: _calculateRuleConfidence(rule, matches.length),
          detectedAt: DateTime.now(),
          recommendedAction: _getActionForRule(rule),
          metadata: {
            'rule_id': rule.id,
            'rule_name': rule.name,
            'match_count': matches.length,
            'matched_strings': matches,
          },
        ));
      }
    }

    return threats;
  }

  /// Scan file content with byte pattern matching
  List<DetectedThreat> scanFileBytes(
    String packageName,
    String appName,
    List<int> fileBytes,
  ) {
    final threats = <DetectedThreat>[];

    // Convert bytes to searchable string (hex representation)
    final hexString = fileBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    // Look for known malicious byte patterns
    final patterns = {
      'elf_header_anomaly': RegExp(r'7f454c46.*[^\x00-\x7f]{100,}'),
      'packed_dex': RegExp(r'6465780a30333[5-9]'),
      'embedded_apk': RegExp(r'504b0304'),
    };

    for (final entry in patterns.entries) {
      if (entry.value.hasMatch(hexString)) {
        threats.add(DetectedThreat(
          id: 'threat_${DateTime.now().millisecondsSinceEpoch}_byte',
          packageName: packageName,
          appName: appName,
          threatType: ThreatType.malware,
          severity: ThreatSeverity.high,
          detectionMethod: DetectionMethod.yara,
          description: 'Suspicious byte pattern detected: ${entry.key}',
          indicators: [entry.key],
          confidence: 0.75,
          detectedAt: DateTime.now(),
          recommendedAction: ActionType.alert,
          metadata: {'pattern_type': entry.key},
        ));
      }
    }

    return threats;
  }

  /// Calculate confidence based on rule match quality
  double _calculateRuleConfidence(DetectionRule rule, int matchCount) {
    // Base confidence from rule severity
    final baseConfidence = {
      ThreatSeverity.critical: 0.85,
      ThreatSeverity.high: 0.75,
      ThreatSeverity.medium: 0.65,
      ThreatSeverity.low: 0.55,
      ThreatSeverity.info: 0.45,
    }[rule.severity] ?? 0.50;

    // Adjust for match count (more matches = higher confidence)
    final matchBonus = (matchCount - 1) * 0.05;
    return (baseConfidence + matchBonus).clamp(0.0, 0.95);
  }

  /// Determine recommended action based on rule
  ActionType _getActionForRule(DetectionRule rule) {
    if (rule.severity == ThreatSeverity.critical) {
      return ActionType.quarantine;
    } else if (rule.severity == ThreatSeverity.high) {
      return ActionType.alert;
    } else {
      return ActionType.monitoronly;
    }
  }
  
  /// Load expanded YARA rules (67 new rules)
  void _loadExpandedRules() {
    final expandedRules = ExpandedYaraRules.getAllExpandedRules();
    print('📚 Loading ${expandedRules.length} expanded YARA rules...');
    
    for (final rule in expandedRules) {
      _addRule(rule);
    }
    
    print('✅ Expanded rules loaded successfully');
  }

  /// Add custom rule at runtime
  void addCustomRule(DetectionRule rule) {
    _addRule(rule);
  }

  /// Update existing rule
  void updateRule(String ruleId, DetectionRule updatedRule) {
    if (_rules.containsKey(ruleId)) {
      _rules[ruleId] = updatedRule;
      try {
        _compiledPatterns[ruleId] = RegExp(
          updatedRule.pattern,
          caseSensitive: false,
        );
      } catch (e) {
        print('Error updating rule $ruleId: $e');
      }
    }
  }

  /// Disable a rule
  void disableRule(String ruleId) {
    if (_rules.containsKey(ruleId)) {
      final rule = _rules[ruleId]!;
      _rules[ruleId] = DetectionRule(
        id: rule.id,
        name: rule.name,
        pattern: rule.pattern,
        ruleType: rule.ruleType,
        threatType: rule.threatType,
        severity: rule.severity,
        enabled: false,
        lastUpdated: DateTime.now(),
        description: rule.description,
      );
    }
  }

  /// Get all rules
  List<DetectionRule> getAllRules() => _rules.values.toList();

  /// Get enabled rules count
  int getEnabledRulesCount() => _rules.values.where((r) => r.enabled).length;
}
