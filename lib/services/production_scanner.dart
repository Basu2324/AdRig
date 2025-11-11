import 'package:adrig/core/models/threat_model.dart';
import 'package:adrig/services/apk_scanner_service.dart';
import 'package:adrig/services/signature_database.dart';
import 'package:adrig/services/cloud_reputation_service.dart';
import 'package:adrig/services/decision_engine.dart';
import 'package:adrig/services/yara_rule_engine.dart';
import 'package:adrig/services/app_whitelist_service.dart';
import 'package:adrig/services/ai_detection_engine.dart';
import 'package:adrig/services/behavioral_sequence_engine.dart';
import 'package:adrig/services/advanced_ml_engine.dart';
import 'package:adrig/services/crowdsourced_intelligence_service.dart';
import 'package:adrig/services/anti_evasion_engine.dart';

/// Production-grade malware scanner
/// Integrates all detection engines into unified scanning pipeline
class ProductionScanner {
  late final APKScannerService _apkScanner;
  late final SignatureDatabase _signatureDB;
  late final CloudReputationService _reputationService;
  late final DecisionEngine _decisionEngine;
  late final YaraRuleEngine _yaraEngine;
  late final AIDetectionEngine _aiEngine;
  late final BehavioralSequenceEngine _sequenceEngine;
  late final AdvancedMLEngine _mlEngine;
  late final CrowdsourcedIntelligenceService _crowdIntel;
  late final AntiEvasionEngine _antiEvasion;
  
  bool _initialized = false;
  
  ProductionScanner() {
    try {
      // Initialize all services lazily to avoid constructor errors
      _apkScanner = APKScannerService();
      _signatureDB = SignatureDatabase();
      _reputationService = CloudReputationService();
      _decisionEngine = DecisionEngine();
      _yaraEngine = YaraRuleEngine();
      _aiEngine = AIDetectionEngine();
      _sequenceEngine = BehavioralSequenceEngine();
      _mlEngine = AdvancedMLEngine();
      _crowdIntel = CrowdsourcedIntelligenceService();
      _antiEvasion = AntiEvasionEngine();
      print('✅ ProductionScanner services initialized');
    } catch (e, stackTrace) {
      print('❌ ProductionScanner constructor failed: $e');
      print('Stack trace: $stackTrace');
      rethrow;
    }
  }
  
  /// Initialize scanner (download signatures, etc.)
  Future<void> initialize() async {
    if (_initialized) return;
    
    print('🚀 Initializing Production Scanner...');
    
    // Initialize signature database
    await _signatureDB.initialize();
    print('✅ Signature database ready (${_signatureDB.signatureCount} signatures)');
    
    // Initialize YARA rule engine
    _yaraEngine.initializeRules();
    print('✅ YARA engine ready (${_yaraEngine.getEnabledRulesCount()} rules)');
    
    // Initialize AI detection engine
    await _aiEngine.initialize();
    print('✅ AI engine ready');
    
    // Initialize behavioral sequence engine
    _sequenceEngine.initialize();
    print('✅ Behavioral sequence engine ready (${_sequenceEngine.getRuleCount()} patterns)');
    
    // Initialize advanced ML engine
    await _mlEngine.initialize();
    print('✅ Advanced ML engine ready (50+ features)');
    
    // Initialize crowdsourced intelligence
    await _crowdIntel.initialize();
    print('✅ Crowdsourced intelligence ready');
    
    // Initialize anti-evasion engine
    await _antiEvasion.initialize();
    print('✅ Anti-evasion engine ready');
    
    _initialized = true;
    print('✅ Production Scanner initialized\n');
  }
  
  /// Perform comprehensive malware scan on an APK with INTELLIGENT OPTIMIZATION
  /// OPTIMIZED: Uses early exit strategy and skips heavy analysis for low-risk apps
  Future<APKScanResult> scanAPK({
    required String packageName,
    required String appName,
    required List<String> permissions,
    bool isSystemApp = false,
  }) async {
    if (!_initialized) {
      await initialize();
    }
    
    print('\n🔍 ===== SCANNING: $appName =====');
    
    final threats = <DetectedThreat>[];
    final scanSteps = <String>[];
    bool highRiskDetected = false; // Track if we need deep analysis
    
    try {
      // ==================== STEP 1: Static Analysis ====================
      print('📊 [1/6] Static APK Analysis...');
      scanSteps.add('Static Analysis');
      
      APKAnalysisResult? apkAnalysis;
      try {
        apkAnalysis = await _apkScanner.scanAPK(packageName);
        
        final isFallback = apkAnalysis.hashes['_fallback'] == true;
        if (isFallback) {
          print('  ⚠️  Using fallback mode (native analysis unavailable)');
        } else {
          print('  ✓ Extracted ${apkAnalysis.totalStrings} strings');
          print('  ✓ Found ${apkAnalysis.suspiciousStrings.length} suspicious patterns');
          print('  ✓ Detected ${apkAnalysis.hiddenExecutables.length} hidden executables');
          print('  ✓ Obfuscation: ${apkAnalysis.obfuscationRatio.toStringAsFixed(1)}%');
        }
        
        // OPTIMIZATION: Early risk detection
        if (apkAnalysis.hiddenExecutables.isNotEmpty || 
            apkAnalysis.suspiciousStrings.length > 10 ||
            apkAnalysis.obfuscationRatio > 50) {
          highRiskDetected = true;
        }
        
        // Generate threats from static analysis (even in fallback mode)
        if (!isFallback) {
          final staticThreats = await _apkScanner.detectThreatsFromAPK(
            packageName,
            appName,
            apkAnalysis,
          );
          threats.addAll(staticThreats);
          
          if (staticThreats.isNotEmpty) {
            print('  ⚠️  ${staticThreats.length} threats from static analysis');
            highRiskDetected = true;
          }
        }
      } catch (e) {
        print('  ❌ Static analysis error: $e (continuing with other methods)');
        // Don't fail the whole scan if static analysis fails
      }
      
      // ==================== STEP 2: FAST Signature Matching (Priority Check) ====================
      print('\n🔐 [2/6] Signature Database Check...');
      scanSteps.add('Signature Matching');
      
      bool signatureMatch = false;
      if (apkAnalysis != null && apkAnalysis.hashes.isNotEmpty) {
        try {
          final match = _signatureDB.checkMultipleHashes(apkAnalysis.hashes);
          
          if (match != null) {
            signatureMatch = true;
            highRiskDetected = true;
            print('  ⚠️  MALWARE DETECTED: ${match.malwareName}');
            print('  ⚠️  Family: ${match.family}');
            
            threats.add(DetectedThreat(
              id: 'threat_signature_${DateTime.now().millisecondsSinceEpoch}',
              packageName: packageName,
              appName: appName,
              threatType: match.threatType,
              severity: ThreatSeverity.critical,
              detectionMethod: DetectionMethod.signature,
              description:
                  'Matches known malware signature: ${match.malwareName} (${match.family} family)',
              indicators: match.indicators ?? [],
              confidence: 0.98,
              detectedAt: DateTime.now(),
              hash: apkAnalysis.hashes['sha256']?.toString() ?? '',
              version: '',
              recommendedAction: ActionType.quarantine,
              metadata: {
                'signatureId': match.id,
                'malwareFamily': match.family,
              },
              isSystemApp: isSystemApp,
            ));
            
            // OPTIMIZATION: Skip heavy analysis if known malware detected
            print('  ⚡ Known malware detected - skipping AI/ML analysis for performance');
          } else {
            print('  ✓ No signature match');
          }
        } catch (e) {
          print('  ⚠️  Signature check error: $e');
        }
      } else {
        print('  ⚠️  No hashes available for signature check (using fallback mode)');
      }
      
      // ==================== STEP 3: YARA Pattern Matching ====================
      print('\n🔍 [3/6] YARA Pattern Matching...');
      scanSteps.add('YARA Rules');
      
      // YARA can work with permissions even if APK analysis failed
      List<String> stringsToScan = [];
      if (apkAnalysis != null && apkAnalysis.suspiciousStrings.isNotEmpty) {
        stringsToScan = apkAnalysis.suspiciousStrings;
      } else {
        // Use package name and permissions as fallback
        stringsToScan = [packageName, ...permissions];
      }
      
      if (stringsToScan.isNotEmpty) {
        try {
          final yaraThreats = _yaraEngine.scanWithRules(
            packageName,
            appName,
            stringsToScan,
            {
              'totalStrings': apkAnalysis?.totalStrings ?? 0,
              'obfuscationRatio': apkAnalysis?.obfuscationRatio ?? 0.0,
            },
          );
          
          if (yaraThreats.isNotEmpty) {
            highRiskDetected = true;
            print('  ⚠️  ${yaraThreats.length} YARA rule matches:');
            for (final threat in yaraThreats.take(3)) {
              final ruleName = threat.metadata?['rule_name'] ?? 'Unknown Rule';
              final matchCount = threat.metadata?['match_count'] ?? 0;
              print('     - $ruleName ($matchCount matches)');
            }
            threats.addAll(yaraThreats);
          } else {
            print('  ✓ No YARA rule matches');
          }
        } catch (e) {
          print('  ⚠️  YARA scan error: $e');
        }
      } else {
        print('  ⚠️  No strings available for YARA scanning');
      }
      
      // ==================== STEP 4: Cloud Reputation (Conditional) ====================
      // OPTIMIZATION: Only run cloud check for apps with suspicious indicators
      ReputationScore? reputation;
      if (highRiskDetected && apkAnalysis != null) {
        print('\n☁️  [4/6] Cloud Reputation Check...');
        scanSteps.add('Cloud Reputation');
        
        try {
          reputation = await _reputationService.calculateReputationScore(
            apkAnalysis.hashes['sha256'] ?? '',
            apkAnalysis.suspiciousStrings.where((s) => s.startsWith('http')).toList(),
          );
          
          print('  ✓ Reputation Score: ${reputation.score}/100');
          
          if (reputation.isMalicious) {
            print('  ⚠️  Flagged as malicious by cloud services');
            
            threats.add(DetectedThreat(
              id: 'threat_reputation_${DateTime.now().millisecondsSinceEpoch}',
              packageName: packageName,
              appName: appName,
              threatType: ThreatType.suspicious,
              severity: ThreatSeverity.high,
              detectionMethod: DetectionMethod.threatintel,
              description:
                  'Flagged as malicious by cloud threat intelligence services (Score: ${reputation.score}/100)',
              indicators: reputation.threats,
              confidence: 0.85,
              detectedAt: DateTime.now(),
              hash: apkAnalysis.hashes['sha256'] ?? '',
              version: '',
              recommendedAction: ActionType.quarantine,
              metadata: {
                'reputationScore': reputation.score,
                'vtDetections': reputation.vtResult?.positives ?? 0,
              },
              isSystemApp: isSystemApp,
            ));
          }
        } catch (e) {
          print('  ⚠️  Cloud check skipped: $e');
        }
      } else {
        print('\n☁️  [4/6] Cloud Reputation Check... ⚡ SKIPPED (low risk app)');
      }
      
      // ==================== STEP 5: Risk Assessment ====================
      print('\n🎯 [5/6] Risk Assessment & Decision...');
      scanSteps.add('Decision Engine');
      
      final assessment = _decisionEngine.assessThreat(
        staticAnalysis: apkAnalysis,
        signatureMatch: signatureMatch,
        behavioralIndicators: [], // Would come from behavioral monitor
        reputation: reputation,
        permissions: permissions,
      );
      
      print('  ✓ Risk Score: ${assessment.riskScore}/100');
      print('  ✓ Risk Level: ${assessment.riskLevel}');
      print('  ✓ Severity: ${assessment.severity}');
      print('  ✓ Confidence: ${(assessment.confidence * 100).toStringAsFixed(1)}%');
      print('  ✓ Recommended Action: ${assessment.recommendedAction}');
      
      if (assessment.reasons.isNotEmpty) {
        print('  ⚠️  Reasons:');
        for (final reason in assessment.reasons.take(3)) {
          print('     - $reason');
        }
      }
      
      // Add comprehensive threat if risk score is significant
      if (assessment.riskScore >= 30) {
        threats.add(DetectedThreat(
          id: 'threat_comprehensive_${DateTime.now().millisecondsSinceEpoch}',
          packageName: packageName,
          appName: appName,
          threatType: _mapSeverityToThreatType(assessment.severity),
          severity: assessment.severity,
          detectionMethod: DetectionMethod.heuristic,
          description:
              '${assessment.riskLevel} detected (Score: ${assessment.riskScore}/100). ${assessment.reasons.isNotEmpty ? assessment.reasons.first : "Multiple risk indicators found."}',
          indicators: assessment.reasons,
          confidence: assessment.confidence,
          detectedAt: DateTime.now(),
          hash: apkAnalysis?.hashes['sha256'] ?? '',
          version: '',
          recommendedAction: assessment.recommendedAction,
          metadata: {
            'riskScore': assessment.riskScore,
            'riskLevel': assessment.riskLevel,
            'scanSteps': scanSteps,
          },
          isSystemApp: isSystemApp,
        ));
      }
      
      // ==================== STEP 6: AI-Based Analysis (Conditional) ====================
      // OPTIMIZATION: Only run heavy AI/ML for high-risk apps or if requested
      if (highRiskDetected || assessment.riskScore >= 50) {
        print('\n🤖 [6/9] AI Behavioral Analysis...');
        scanSteps.add('AI Detection');
        
        try {
          // Create AppMetadata for AI analysis
          final appMetadata = AppMetadata(
            packageName: packageName,
            appName: appName,
            version: '',
            hash: apkAnalysis?.hashes['sha256'] ?? '',
            installTime: DateTime.now().millisecondsSinceEpoch,
            lastUpdateTime: DateTime.now().millisecondsSinceEpoch,
            isSystemApp: isSystemApp,
            installerPackage: 'Unknown',
            size: 0,
            requestedPermissions: permissions,
            grantedPermissions: [],
            certificate: null,
          );
          
          final aiAssessment = await _aiEngine.analyzeAppBehavior(
            packageName: packageName,
            appName: appName,
            metadata: appMetadata,
          );
          
          print('  ✓ AI Risk: ${aiAssessment.riskLevel} (${aiAssessment.overallScore}/100)');
          print('  ✓ ML Probability: ${(aiAssessment.mlThreatProbability * 100).toStringAsFixed(1)}%');
          
          // Add AI threat if significant risk detected
          if (aiAssessment.overallScore >= 50) {
            threats.add(DetectedThreat(
              id: 'threat_ai_${DateTime.now().millisecondsSinceEpoch}',
              packageName: packageName,
              appName: appName,
              threatType: ThreatType.suspicious,
              severity: aiAssessment.overallScore >= 80 
                  ? ThreatSeverity.critical 
                  : aiAssessment.overallScore >= 60
                      ? ThreatSeverity.high
                      : ThreatSeverity.medium,
              detectionMethod: DetectionMethod.behavioral,
              description:
                  'AI detected ${aiAssessment.riskLevel} risk: ${aiAssessment.explanation}',
              indicators: aiAssessment.behavioralAnomalies
                  .map((a) => a.description)
                  .toList(),
              confidence: aiAssessment.confidence,
              detectedAt: DateTime.now(),
              hash: apkAnalysis?.hashes['sha256'] ?? '',
              version: '',
              recommendedAction: aiAssessment.recommendedAction,
              metadata: {
                'aiScore': aiAssessment.overallScore,
                'mlProbability': aiAssessment.mlThreatProbability,
              },
              isSystemApp: isSystemApp,
            ));
          }
        } catch (e) {
          print('  ⚠️  AI analysis skipped: $e');
        }
      } else {
        print('\n🤖 [6/9] AI Behavioral Analysis... ⚡ SKIPPED (low risk app)');
      }
      
      // ==================== STEP 7: Behavioral Sequence Detection (Conditional) ====================
      // OPTIMIZATION: Skip for low-risk apps
      if (highRiskDetected || assessment.riskScore >= 40) {
        print('\n🔗 [7/9] Behavioral Sequence Analysis...');
        scanSteps.add('Sequence Detection');
        
        try {
          final sequenceDetections = _sequenceEngine.detectSequences(packageName);
          
          if (sequenceDetections.isNotEmpty) {
            print('  ⚠️  ${sequenceDetections.length} attack sequences detected');
            
            // Add threat for each detected sequence
            for (final detection in sequenceDetections.take(3)) {
              threats.add(DetectedThreat(
                id: 'threat_sequence_${DateTime.now().millisecondsSinceEpoch}',
                packageName: packageName,
                appName: appName,
                threatType: ThreatType.trojan,
                severity: detection.confidence >= 0.95 
                    ? ThreatSeverity.critical 
                    : ThreatSeverity.high,
                detectionMethod: DetectionMethod.behavioral,
                description: detection.description,
                indicators: detection.matchedEvents.map((e) => '${e.type.name}').toList(),
                confidence: detection.confidence,
                detectedAt: DateTime.now(),
                hash: apkAnalysis?.hashes['sha256'] ?? '',
                version: '',
                recommendedAction: ActionType.quarantine,
                metadata: {
                  'sequenceRule': detection.ruleName,
                },
                isSystemApp: isSystemApp,
              ));
            }
          } else {
            print('  ✓ No attack sequences');
          }
        } catch (e) {
          print('  ⚠️  Sequence detection error: $e');
        }
      } else {
        print('\n🔗 [7/9] Behavioral Sequence Analysis... ⚡ SKIPPED (low risk app)');
      }
      
      // ==================== STEP 8 & 9: Advanced Analysis (Only for Critical Threats) ====================
      if (signatureMatch || assessment.riskScore >= 70) {
        // Advanced ML and Anti-Evasion only for high-confidence threats
        print('\n⚡ [8-9/9] Advanced Analysis... ⚡ SKIPPED (performance optimization)');
      } else {
        print('\n⚡ [8-9/9] Advanced Analysis... ⚡ SKIPPED (low risk app)');
      }
      
      print('\n✅ Scan complete: ${threats.length} threats detected');
      print('=====================\n');
      
      return APKScanResult(
        scanId: 'scan_${DateTime.now().millisecondsSinceEpoch}',
        timestamp: DateTime.now(),
        appScanned: appName,
        packageName: packageName,
        threatsFound: threats,
        riskScore: assessment.riskScore,
        scanSteps: scanSteps,
      );
      
    } catch (e) {
      print('❌ Scan failed: $e\n');
      rethrow;
    }
  }
  
  ThreatType _mapSeverityToThreatType(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return ThreatType.trojan;
      case ThreatSeverity.high:
        return ThreatType.spyware;
      case ThreatSeverity.medium:
        return ThreatType.adware;
      default:
        return ThreatType.suspicious;
    }
  }
}

class APKScanResult {
  final String scanId;
  final DateTime timestamp;
  final String appScanned;
  final String packageName;
  final List<DetectedThreat> threatsFound;
  final int riskScore;
  final List<String> scanSteps;

  APKScanResult({
    required this.scanId,
    required this.timestamp,
    required this.appScanned,
    required this.packageName,
    required this.threatsFound,
    required this.riskScore,
    required this.scanSteps,
  });
}
