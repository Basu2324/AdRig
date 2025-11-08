import 'package:adrig/core/models/threat_model.dart';
import 'package:adrig/services/apk_scanner_service.dart';
import 'package:adrig/services/signature_database.dart';
import 'package:adrig/services/cloud_reputation_service.dart';
import 'package:adrig/services/decision_engine.dart';
import 'package:adrig/services/yara_rule_engine.dart';
import 'package:adrig/services/app_whitelist_service.dart';
import 'package:adrig/services/ai_detection_engine.dart';

/// Production-grade malware scanner
/// Integrates all detection engines into unified scanning pipeline
class ProductionScanner {
  final APKScannerService _apkScanner = APKScannerService();
  final SignatureDatabase _signatureDB = SignatureDatabase();
  final CloudReputationService _reputationService = CloudReputationService();
  final DecisionEngine _decisionEngine = DecisionEngine();
  final YaraRuleEngine _yaraEngine = YaraRuleEngine();
  final AIDetectionEngine _aiEngine = AIDetectionEngine();
  
  bool _initialized = false;
  
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
    
    _initialized = true;
    print('✅ Production Scanner initialized\n');
  }
  
  /// Perform comprehensive malware scan on an APK
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
    
    try {
      // ==================== STEP 1: Static Analysis ====================
      print('📊 [1/4] Static APK Analysis...');
      scanSteps.add('Static Analysis');
      
      APKAnalysisResult? apkAnalysis;
      try {
        apkAnalysis = await _apkScanner.scanAPK(packageName);
        print('  ✓ Extracted ${apkAnalysis.totalStrings} strings');
        print('  ✓ Found ${apkAnalysis.suspiciousStrings.length} suspicious patterns');
        print('  ✓ Detected ${apkAnalysis.hiddenExecutables.length} hidden executables');
        print('  ✓ Obfuscation: ${apkAnalysis.obfuscationRatio.toStringAsFixed(1)}%');
        
        // Generate threats from static analysis
        final staticThreats = await _apkScanner.detectThreatsFromAPK(
          packageName,
          appName,
          apkAnalysis,
        );
        threats.addAll(staticThreats);
        
        if (staticThreats.isNotEmpty) {
          print('  ⚠️  ${staticThreats.length} threats from static analysis');
        }
      } catch (e) {
        print('  ❌ Static analysis failed: $e');
      }
      
      // ==================== STEP 2: YARA Pattern Matching ====================
      print('\n🔍 [2/5] YARA Pattern Matching...');
      scanSteps.add('YARA Rules');
      
      if (apkAnalysis != null && apkAnalysis.suspiciousStrings.isNotEmpty) {
        try {
          final yaraThreats = _yaraEngine.scanWithRules(
            packageName,
            appName,
            apkAnalysis.suspiciousStrings,
            {
              'totalStrings': apkAnalysis.totalStrings,
              'obfuscationRatio': apkAnalysis.obfuscationRatio,
            },
          );
          
          if (yaraThreats.isNotEmpty) {
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
      }
      
      // ==================== STEP 3: Signature Matching ====================
      print('\n🔐 [3/5] Signature Database Check...');
      scanSteps.add('Signature Matching');
      
      bool signatureMatch = false;
      if (apkAnalysis != null) {
        final match = _signatureDB.checkMultipleHashes(apkAnalysis.hashes);
        
        if (match != null) {
          signatureMatch = true;
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
            hash: apkAnalysis.hashes['sha256'] ?? '',
            version: '',
            recommendedAction: ActionType.quarantine,
            metadata: {
              'signatureId': match.id,
              'malwareFamily': match.family,
            },
            isSystemApp: isSystemApp,
          ));
        } else {
          print('  ✓ No signature match');
        }
      }
      
      // ==================== STEP 4: Cloud Reputation ====================
      print('\n☁️  [4/5] Cloud Reputation Check...');
      scanSteps.add('Cloud Reputation');
      
      ReputationScore? reputation;
      if (apkAnalysis != null) {
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
      }
      
      // ==================== STEP 5: Risk Assessment ====================
      print('\n🎯 [5/5] Risk Assessment & Decision...');
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
      
      // ==================== STEP 6: AI-Based Analysis ====================
      print('\n🤖 [6/6] AI Behavioral Analysis...');
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
        print('  ✓ Network Risk: ${aiAssessment.networkRiskScore}/100');
        print('  ✓ Anomalies: ${aiAssessment.behavioralAnomalies.length}');
        
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
              'networkScore': aiAssessment.networkRiskScore,
              'anomalyCount': aiAssessment.behavioralAnomalies.length,
            },
            isSystemApp: isSystemApp,
          ));
        }
      } catch (e) {
        print('  ⚠️  AI analysis skipped: $e');
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
