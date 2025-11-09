import 'package:flutter/material.dart';
import '../core/models/threat_model.dart';

class ScanLogScreen extends StatelessWidget {
  final ScanResult result;

  const ScanLogScreen({Key? key, required this.result}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        elevation: 0,
        title: Text(
          'Scan Log',
          style: TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.w300,
          ),
        ),
        leading: IconButton(
          icon: Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(20),
        children: [
          _buildInfoCard(
            'Scan Summary',
            [
              _buildInfoRow('Scan ID', result.scanId.substring(0, 8)),
              _buildInfoRow('Apps Scanned', '${result.statistics.appsScanned}'),
              _buildInfoRow('Scan Duration', '${result.statistics.scanDuration.inSeconds}s'),
              _buildInfoRow('Total Threats', '${result.threats.length}'),
            ],
          ),
          
          SizedBox(height: 16),
          
          _buildInfoCard(
            'Threat Breakdown',
            [
              _buildThreatRow('Critical', result.statistics.criticalThreats, Color(0xFFD32F2F)),
              _buildThreatRow('High', result.statistics.highThreats, Color(0xFFFF6D00)),
              _buildThreatRow('Medium', result.statistics.mediumThreats, Color(0xFFFFD600)),
              _buildThreatRow('Low', result.statistics.lowThreats, Color(0xFF00C853)),
            ],
          ),
          
          if (result.threats.isNotEmpty) ...[
            SizedBox(height: 16),
            _buildInfoCard(
              'Detection Details',
              result.threats.map((threat) => _buildThreatDetail(threat)).toList(),
            ),
          ],
          
          SizedBox(height: 16),
          
          _buildInfoCard(
            'Engine Statistics',
            [
              _buildEngineRow('Static Analysis', Icons.analytics, true),
              _buildEngineRow('YARA Patterns', Icons.bug_report, _hasYaraDetections()),
              _buildEngineRow('Signature DB', Icons.fingerprint, _hasSignatureDetections()),
              _buildEngineRow('Cloud Reputation', Icons.cloud_queue, false),
              _buildEngineRow('Risk Assessment', Icons.security, true),
            ],
          ),
        ],
      ),
    );
  }
  
  bool _hasYaraDetections() {
    return result.threats.any((t) => t.detectionMethod == DetectionMethod.yara);
  }
  
  bool _hasSignatureDetections() {
    return result.threats.any((t) => t.detectionMethod == DetectionMethod.signature);
  }
  
  Widget _buildInfoCard(String title, List<Widget> children) {
    return Container(
      padding: EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF1A1F3A),
            Color(0xFF151933),
          ],
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Color(0xFF6C63FF).withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.bold,
              color: Color(0xFF6C63FF),
              letterSpacing: 0.5,
            ),
          ),
          SizedBox(height: 16),
          ...children,
        ],
      ),
    );
  }
  
  Widget _buildInfoRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              fontSize: 14,
              color: Colors.white54,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              fontSize: 14,
              color: Colors.white,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildThreatRow(String label, int count, Color color) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Row(
            children: [
              Container(
                width: 12,
                height: 12,
                decoration: BoxDecoration(
                  color: color,
                  shape: BoxShape.circle,
                ),
              ),
              SizedBox(width: 10),
              Text(
                label,
                style: TextStyle(
                  fontSize: 14,
                  color: Colors.white70,
                ),
              ),
            ],
          ),
          Container(
            padding: EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            decoration: BoxDecoration(
              color: color.withOpacity(0.2),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: color, width: 1),
            ),
            child: Text(
              '$count',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildThreatDetail(DetectedThreat threat) {
    final isYara = threat.detectionMethod == DetectionMethod.yara;
    final ruleName = isYara && threat.metadata.containsKey('rule_name') 
      ? threat.metadata['rule_name'] 
      : null;
    
    return Container(
      margin: EdgeInsets.only(bottom: 16),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF0A0E27),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: _getSeverityColor(threat.severity).withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  threat.appName,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
              ),
              Container(
                padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: _getSeverityColor(threat.severity).withOpacity(0.2),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  threat.severity.toString().split('.').last.toUpperCase(),
                  style: TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                    color: _getSeverityColor(threat.severity),
                  ),
                ),
              ),
            ],
          ),
          
          SizedBox(height: 8),
          
          if (ruleName != null) ...[
            Container(
              padding: EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [Color(0xFFFF6B6B), Color(0xFFFF8E53)],
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.verified_user, size: 14, color: Colors.white),
                  SizedBox(width: 6),
                  Text(
                    'YARA: $ruleName',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(height: 8),
          ],
          
          Text(
            threat.description,
            style: TextStyle(
              fontSize: 13,
              color: Colors.white60,
              height: 1.4,
            ),
          ),
          
          SizedBox(height: 8),
          
          Row(
            children: [
              Icon(Icons.assessment, size: 12, color: Color(0xFF00D9FF)),
              SizedBox(width: 6),
              Text(
                'Confidence: ${(threat.confidence * 100).toInt()}%',
                style: TextStyle(
                  fontSize: 12,
                  color: Color(0xFF00D9FF),
                ),
              ),
              SizedBox(width: 16),
              Icon(Icons.radar, size: 12, color: Color(0xFF6C63FF)),
              SizedBox(width: 6),
              Text(
                _getMethodLabel(threat.detectionMethod),
                style: TextStyle(
                  fontSize: 12,
                  color: Color(0xFF6C63FF),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
  
  Widget _buildEngineRow(String label, IconData icon, bool active) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        children: [
          Container(
            padding: EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: active 
                ? Color(0xFF00D9FF).withOpacity(0.15) 
                : Colors.white.withOpacity(0.05),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              icon,
              size: 16,
              color: active ? Color(0xFF00D9FF) : Colors.white24,
            ),
          ),
          SizedBox(width: 12),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                fontSize: 14,
                color: active ? Colors.white : Colors.white38,
                fontWeight: active ? FontWeight.w600 : FontWeight.normal,
              ),
            ),
          ),
          if (active)
            Icon(Icons.check_circle, size: 16, color: Color(0xFF00D9FF)),
        ],
      ),
    );
  }
  
  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Color(0xFFD32F2F);
      case ThreatSeverity.high:
        return Color(0xFFFF6D00);
      case ThreatSeverity.medium:
        return Color(0xFFFFD600);
      case ThreatSeverity.low:
        return Color(0xFF00C853);
      case ThreatSeverity.info:
        return Color(0xFF2196F3);
    }
  }
  
  String _getMethodLabel(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return 'Signature';
      case DetectionMethod.yara:
        return 'YARA';
      case DetectionMethod.ml:
        return 'ML';
      case DetectionMethod.machinelearning:
        return 'ML';
      case DetectionMethod.staticanalysis:
        return 'Static';
      case DetectionMethod.anomaly:
        return 'Anomaly';
      case DetectionMethod.behavioral:
        return 'Behavioral';
      case DetectionMethod.heuristic:
        return 'Heuristic';
      case DetectionMethod.threatintel:
        return 'Threat Intel';
    }
  }
}
