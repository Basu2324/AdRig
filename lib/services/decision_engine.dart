import 'package:adrig/core/models/threat_model.dart';
import 'package:adrig/services/cloud_reputation_service.dart';
import 'package:adrig/services/apk_scanner_service.dart';

/// Production decision engine
/// Combines signals from all detection engines to calculate final risk score
/// and determine appropriate action
class DecisionEngine {
  /// Calculate comprehensive threat score
  /// Combines:
  /// - Static analysis score (APK bytecode, strings, obfuscation)
  /// - Signature match score (known malware hashes)
  /// - Behavioral score (runtime activity)
  /// - Reputation score (VirusTotal, SafeBrowsing)
  /// - Permission score (dangerous permissions)
  ThreatAssessment assessThreat({
    required APKAnalysisResult? staticAnalysis,
    required bool signatureMatch,
    required List<String> behavioralIndicators,
    required ReputationScore? reputation,
    required List<String> permissions,
  }) {
    var riskScore = 0;
    final reasons = <String>[];
    var severity = ThreatSeverity.low;
    var recommendedAction = ActionType.alert;
    
    // ==================== Static Analysis Score (0-30 points) ====================
    if (staticAnalysis != null) {
      // Hidden executables (critical)
      if (staticAnalysis.hiddenExecutables.isNotEmpty) {
        riskScore += 25;
        reasons.add('Contains ${staticAnalysis.hiddenExecutables.length} hidden executables');
        severity = ThreatSeverity.critical;
      }
      
      // Suspicious strings
      final suspiciousCount = staticAnalysis.suspiciousStrings.length;
      if (suspiciousCount > 10) {
        riskScore += 15;
        reasons.add('$suspiciousCount suspicious code patterns detected');
      } else if (suspiciousCount > 5) {
        riskScore += 10;
        reasons.add('$suspiciousCount suspicious patterns found');
      } else if (suspiciousCount > 0) {
        riskScore += 5;
        reasons.add('Some suspicious code patterns detected');
      }
      
      // Code obfuscation
      if (staticAnalysis.isObfuscated && staticAnalysis.obfuscationRatio > 70) {
        riskScore += 10;
        reasons.add('Heavy code obfuscation (${staticAnalysis.obfuscationRatio.toStringAsFixed(1)}%)');
      } else if (staticAnalysis.isObfuscated && staticAnalysis.obfuscationRatio > 40) {
        riskScore += 5;
        reasons.add('Code obfuscation detected');
      }
      
      // Suspicious native libraries
      final suspiciousLibs = staticAnalysis.nativeLibraries
          .where((lib) => lib['suspicious'] == true)
          .length;
      if (suspiciousLibs > 0) {
        riskScore += 8;
        reasons.add('$suspiciousLibs suspicious native libraries');
      }
    }
    
    // ==================== Signature Match (0-40 points) ====================
    if (signatureMatch) {
      riskScore += 40;
      reasons.add('Matches known malware signature');
      severity = ThreatSeverity.critical;
      recommendedAction = ActionType.quarantine;
    }
    
    // ==================== Behavioral Indicators (0-20 points) ====================
    if (behavioralIndicators.isNotEmpty) {
      final criticalBehaviors = behavioralIndicators.where((b) =>
          b.contains('SUSPICIOUS_PROCESS') ||
          b.contains('FILE_MODIFICATION') ||
          b.contains('SUSPICIOUS_NETWORK')).length;
      
      if (criticalBehaviors > 3) {
        riskScore += 20;
        reasons.add('Multiple critical behavioral anomalies detected');
        severity = ThreatSeverity.high;
      } else if (criticalBehaviors > 0) {
        riskScore += 10;
        reasons.add('Suspicious runtime behavior detected');
      }
      
      if (behavioralIndicators.length > 5) {
        riskScore += 5;
        reasons.add('${behavioralIndicators.length} behavioral indicators');
      }
    }
    
    // ==================== Cloud Reputation (0-30 points) ====================
    if (reputation != null) {
      if (reputation.score < 20) {
        riskScore += 30;
        reasons.add('Flagged by ${reputation.threats.length} threat intelligence sources');
        severity = ThreatSeverity.critical;
        recommendedAction = ActionType.quarantine;
      } else if (reputation.score < 50) {
        riskScore += 20;
        reasons.add('Suspicious reputation from cloud analysis');
        severity = ThreatSeverity.high;
      } else if (reputation.score < 70) {
        riskScore += 10;
        reasons.add('Low reputation score');
      }
      
      // VirusTotal detections
      if (reputation.vtResult != null && reputation.vtResult!.positives > 0) {
        final detectionRate = (reputation.vtResult!.positives / reputation.vtResult!.total) * 100;
        
        if (detectionRate > 50) {
          reasons.add('${reputation.vtResult!.positives}/${reputation.vtResult!.total} AV engines detected malware');
        } else if (detectionRate > 20) {
          reasons.add('${reputation.vtResult!.positives}/${reputation.vtResult!.total} AV engines flagged as suspicious');
        }
      }
    }
    
    // ==================== Permission Score (0-10 points) ====================
    final dangerousPermissions = _analyzeDangerousPermissions(permissions);
    if (dangerousPermissions.score > 0) {
      riskScore += dangerousPermissions.score.clamp(0, 10);
      if (dangerousPermissions.patterns.isNotEmpty) {
        reasons.add('Dangerous permission pattern: ${dangerousPermissions.patterns.first}');
      }
    }
    
    // ==================== Calculate Final Assessment ====================
    
    // Clamp risk score to 0-100
    riskScore = riskScore.clamp(0, 100);
    
    // Determine severity if not already set
    if (severity == ThreatSeverity.low) {
      if (riskScore >= 80) {
        severity = ThreatSeverity.critical;
      } else if (riskScore >= 60) {
        severity = ThreatSeverity.high;
      } else if (riskScore >= 40) {
        severity = ThreatSeverity.medium;
      } else if (riskScore >= 20) {
        severity = ThreatSeverity.low;
      }
    }
    
    // Determine recommended action if not already set
    if (recommendedAction == ActionType.alert) {
      if (riskScore >= 75) {
        recommendedAction = ActionType.quarantine;
      } else if (riskScore >= 50) {
        recommendedAction = ActionType.autoblock;
      } else if (riskScore >= 30) {
        recommendedAction = ActionType.alert;
      }
    }
    
    return ThreatAssessment(
      riskScore: riskScore,
      severity: severity,
      recommendedAction: recommendedAction,
      reasons: reasons,
      confidence: _calculateConfidence(
        staticAnalysis,
        signatureMatch,
        reputation,
      ),
    );
  }
  
  /// Analyze permissions for dangerous patterns
  PermissionAnalysis _analyzeDangerousPermissions(List<String> permissions) {
    var score = 0;
    final patterns = <String>[];
    
    // Spyware pattern: location + contacts + call log + camera + mic
    final spywarePerms = [
      'android.permission.ACCESS_FINE_LOCATION',
      'android.permission.READ_CONTACTS',
      'android.permission.READ_CALL_LOG',
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
    ];
    
    final spywareCount = permissions.where((p) => spywarePerms.contains(p)).length;
    if (spywareCount >= 4) {
      score += 8;
      patterns.add('Spyware (surveillance permissions)');
    }
    
    // Banking trojan pattern: accessibility + SMS + device admin
    if (permissions.contains('android.permission.BIND_ACCESSIBILITY_SERVICE') ||
        permissions.contains('android.permission.BIND_DEVICE_ADMIN')) {
      score += 5;
      patterns.add('Accessibility abuse (credential theft risk)');
    }
    
    // SMS fraud pattern
    if (permissions.contains('android.permission.SEND_SMS') ||
        permissions.contains('android.permission.READ_SMS')) {
      score += 3;
      patterns.add('SMS access (potential premium SMS fraud)');
    }
    
    // Overlay attack
    if (permissions.contains('android.permission.SYSTEM_ALERT_WINDOW')) {
      score += 2;
      patterns.add('Screen overlay (phishing risk)');
    }
    
    return PermissionAnalysis(score: score, patterns: patterns);
  }
  
  /// Calculate confidence score (0.0-1.0)
  double _calculateConfidence(
    APKAnalysisResult? staticAnalysis,
    bool signatureMatch,
    ReputationScore? reputation,
  ) {
    var confidence = 0.5; // Base confidence
    
    // Signature match = very high confidence
    if (signatureMatch) {
      confidence = 0.95;
    }
    
    // Multiple detection methods increase confidence
    var detectionMethods = 0;
    if (staticAnalysis != null && staticAnalysis.suspiciousStrings.isNotEmpty) {
      detectionMethods++;
    }
    if (reputation != null && reputation.isMalicious) {
      detectionMethods++;
      confidence += 0.15;
    }
    if (staticAnalysis != null && staticAnalysis.hiddenExecutables.isNotEmpty) {
      detectionMethods++;
      confidence += 0.2;
    }
    
    // More detection methods = higher confidence
    confidence += (detectionMethods * 0.05);
    
    return confidence.clamp(0.0, 1.0);
  }
}

// ==================== Data Models ====================

class ThreatAssessment {
  final int riskScore; // 0-100
  final ThreatSeverity severity;
  final ActionType recommendedAction;
  final List<String> reasons;
  final double confidence; // 0.0-1.0

  ThreatAssessment({
    required this.riskScore,
    required this.severity,
    required this.recommendedAction,
    required this.reasons,
    required this.confidence,
  });
  
  /// Get human-readable risk level
  String get riskLevel {
    if (riskScore >= 80) return 'Critical Risk';
    if (riskScore >= 60) return 'High Risk';
    if (riskScore >= 40) return 'Medium Risk';
    if (riskScore >= 20) return 'Low Risk';
    return 'Minimal Risk';
  }
  
  /// Get color for UI display
  String get riskColor {
    if (riskScore >= 80) return '#FF0000'; // Red
    if (riskScore >= 60) return '#FF6600'; // Orange
    if (riskScore >= 40) return '#FFAA00'; // Yellow
    if (riskScore >= 20) return '#00AA00'; // Green
    return '#00FF00'; // Bright green
  }
}

class PermissionAnalysis {
  final int score;
  final List<String> patterns;

  PermissionAnalysis({required this.score, required this.patterns});
}
