import 'package:flutter/material.dart';
import '../core/models/threat_model.dart';
import 'threat_detail_screen.dart';

class ScanResultsScreen extends StatelessWidget {
  final ScanResult result;

  const ScanResultsScreen({Key? key, required this.result}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final criticalThreats = result.threats.where((t) => t.severity == ThreatSeverity.critical).toList();
    final highThreats = result.threats.where((t) => t.severity == ThreatSeverity.high).toList();
    final mediumThreats = result.threats.where((t) => t.severity == ThreatSeverity.medium).toList();
    final lowThreats = result.threats.where((t) => t.severity == ThreatSeverity.low).toList();

    return Scaffold(
      appBar: AppBar(
        title: Text('Scan Results', style: TextStyle(fontWeight: FontWeight.w300)),
        actions: [
          IconButton(
            icon: Icon(Icons.share),
            onPressed: () {
              // TODO: Share scan report
            },
          ),
        ],
      ),
      body: result.threats.isEmpty ? _buildCleanState() : _buildThreatsView(
        context,
        criticalThreats,
        highThreats,
        mediumThreats,
        lowThreats,
      ),
    );
  }

  Widget _buildCleanState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.verified_user,
            size: 100,
            color: Color(0xFF00D9FF),
          ),
          SizedBox(height: 24),
          Text(
            'Device is Clean',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.w300,
              color: Colors.white,
            ),
          ),
          SizedBox(height: 12),
          Text(
            'No threats detected',
            style: TextStyle(
              fontSize: 14,
              color: Colors.white38,
            ),
          ),
          SizedBox(height: 8),
          Text(
            '${result.totalApps} apps scanned in ${result.statistics.scanDuration.inSeconds}s',
            style: TextStyle(
              fontSize: 12,
              color: Colors.white24,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatsView(
    BuildContext context,
    List<DetectedThreat> critical,
    List<DetectedThreat> high,
    List<DetectedThreat> medium,
    List<DetectedThreat> low,
  ) {
    return CustomScrollView(
      slivers: [
        // Header Summary
        SliverToBoxAdapter(
          child: Container(
            margin: EdgeInsets.all(16),
            padding: EdgeInsets.all(24),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFFFF4757), Color(0xFFFF6348)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              children: [
                Icon(Icons.warning_rounded, size: 60, color: Colors.white),
                SizedBox(height: 16),
                Text(
                  '${result.threats.length} Threats Detected',
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  '${result.totalApps} apps scanned • ${result.statistics.scanDuration.inSeconds}s',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.white70,
                  ),
                ),
                SizedBox(height: 20),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: [
                    _buildThreatCount('Critical', critical.length, Color(0xFFFF4757)),
                    _buildThreatCount('High', high.length, Color(0xFFFF6348)),
                    _buildThreatCount('Medium', medium.length, Color(0xFFFFA502)),
                    _buildThreatCount('Low', low.length, Color(0xFFFFD32D)),
                  ],
                ),
              ],
            ),
          ),
        ),

        // Critical Threats
        if (critical.isNotEmpty) ...[
          _buildSectionHeader('Critical Threats', critical.length, Color(0xFFFF4757)),
          SliverList(
            delegate: SliverChildBuilderDelegate(
              (context, index) => _buildThreatCard(context, critical[index]),
              childCount: critical.length,
            ),
          ),
        ],

        // High Threats
        if (high.isNotEmpty) ...[
          _buildSectionHeader('High Severity', high.length, Color(0xFFFF6348)),
          SliverList(
            delegate: SliverChildBuilderDelegate(
              (context, index) => _buildThreatCard(context, high[index]),
              childCount: high.length,
            ),
          ),
        ],

        // Medium Threats
        if (medium.isNotEmpty) ...[
          _buildSectionHeader('Medium Severity', medium.length, Color(0xFFFFA502)),
          SliverList(
            delegate: SliverChildBuilderDelegate(
              (context, index) => _buildThreatCard(context, medium[index]),
              childCount: medium.length,
            ),
          ),
        ],

        // Low Threats
        if (low.isNotEmpty) ...[
          _buildSectionHeader('Low Severity', low.length, Color(0xFFFFD32D)),
          SliverList(
            delegate: SliverChildBuilderDelegate(
              (context, index) => _buildThreatCard(context, low[index]),
              childCount: low.length,
            ),
          ),
        ],

        SliverToBoxAdapter(child: SizedBox(height: 80)),
      ],
    );
  }

  Widget _buildThreatCount(String label, int count, Color color) {
    return Column(
      children: [
        Text(
          '$count',
          style: TextStyle(
            fontSize: 20,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
        SizedBox(height: 4),
        Container(
          padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            color: Colors.white24,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Text(
            label,
            style: TextStyle(
              fontSize: 10,
              color: Colors.white,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildSectionHeader(String title, int count, Color color) {
    return SliverToBoxAdapter(
      child: Container(
        margin: EdgeInsets.fromLTRB(16, 24, 16, 12),
        child: Row(
          children: [
            Container(
              width: 4,
              height: 20,
              decoration: BoxDecoration(
                color: color,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            SizedBox(width: 12),
            Text(
              title,
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            SizedBox(width: 8),
            Container(
              padding: EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: color.withOpacity(0.2),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                '$count',
                style: TextStyle(
                  fontSize: 12,
                  color: color,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildThreatCard(BuildContext context, DetectedThreat threat) {
    final severityColor = _getSeverityColor(threat.severity);
    
    return Container(
      margin: EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: severityColor.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => ThreatDetailScreen(threat: threat),
              ),
            );
          },
          child: Padding(
            padding: EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // App name + badge
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        threat.appName,
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                    ),
                    _buildSeverityBadge(threat.severity, severityColor),
                  ],
                ),
                
                SizedBox(height: 8),
                
                // YARA Detection Badge (if applicable)
                if (threat.detectionMethod == DetectionMethod.yara && 
                    threat.metadata.containsKey('rule_name')) ...[
                  Container(
                    margin: EdgeInsets.only(bottom: 8),
                    padding: EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Color(0xFFFF6B6B),
                          Color(0xFFFF8E53),
                        ],
                      ),
                      borderRadius: BorderRadius.circular(8),
                      boxShadow: [
                        BoxShadow(
                          color: Color(0xFFFF6B6B).withOpacity(0.3),
                          blurRadius: 8,
                          offset: Offset(0, 2),
                        ),
                      ],
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.verified_user, size: 16, color: Colors.white),
                        SizedBox(width: 6),
                        Flexible(
                          child: Text(
                            'YARA: ${threat.metadata['rule_name']}',
                            style: TextStyle(
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                              letterSpacing: 0.5,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
                
                // Threat description
                Text(
                  threat.description,
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.white70,
                    height: 1.4,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                
                SizedBox(height: 12),
                
                // Detection metadata
                Row(
                  children: [
                    _buildInfoChip(
                      _getDetectionMethodIcon(threat.detectionMethod),
                      _getDetectionMethodLabel(threat.detectionMethod),
                      Color(0xFF6C63FF),
                    ),
                    SizedBox(width: 8),
                    _buildInfoChip(
                      Icons.assessment,
                      '${(threat.confidence * 100).toInt()}%',
                      Color(0xFF00D9FF),
                    ),
                    SizedBox(width: 8),
                    _buildInfoChip(
                      Icons.flash_on,
                      threat.recommendedAction.toString().split('.').last.toUpperCase(),
                      severityColor,
                    ),
                  ],
                ),
                
                // Indicators preview
                if (threat.indicators.isNotEmpty) ...[
                  SizedBox(height: 12),
                  Container(
                    padding: EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: Colors.black26,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Row(
                      children: [
                        Icon(Icons.info_outline, size: 14, color: Colors.white38),
                        SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            '${threat.indicators.length} indicators detected',
                            style: TextStyle(
                              fontSize: 11,
                              color: Colors.white38,
                            ),
                          ),
                        ),
                        Icon(Icons.chevron_right, size: 16, color: Colors.white38),
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSeverityBadge(ThreatSeverity severity, Color color) {
    return Container(
      padding: EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.2),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color, width: 1),
      ),
      child: Text(
        severity.toString().split('.').last.toUpperCase(),
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.bold,
          color: color,
          letterSpacing: 0.5,
        ),
      ),
    );
  }

  Widget _buildInfoChip(IconData icon, String label, Color color) {
    return Container(
      padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 12, color: color),
          SizedBox(width: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 10,
              color: color,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ),
    );
  }

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Color(0xFFFF4757);
      case ThreatSeverity.high:
        return Color(0xFFFF6348);
      case ThreatSeverity.medium:
        return Color(0xFFFFA502);
      case ThreatSeverity.low:
        return Color(0xFFFFD32D);
      default:
        return Color(0xFF6C63FF);
    }
  }

  IconData _getDetectionMethodIcon(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return Icons.fingerprint;
      case DetectionMethod.heuristic:
        return Icons.psychology;
      case DetectionMethod.behavioral:
        return Icons.timeline;
      case DetectionMethod.threatintel:
        return Icons.cloud;
      case DetectionMethod.machinelearning:
        return Icons.auto_awesome;
      case DetectionMethod.yara:
        return Icons.rule;
      case DetectionMethod.anomaly:
        return Icons.warning;
      case DetectionMethod.staticanalysis:
        return Icons.code;
      default:
        return Icons.security;
    }
  }

  String _getDetectionMethodLabel(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return 'Signature';
      case DetectionMethod.heuristic:
        return 'Heuristic';
      case DetectionMethod.behavioral:
        return 'Behavioral';
      case DetectionMethod.threatintel:
        return 'Cloud Intel';
      case DetectionMethod.machinelearning:
        return 'ML';
      case DetectionMethod.yara:
        return 'YARA';
      case DetectionMethod.anomaly:
        return 'Anomaly';
      case DetectionMethod.staticanalysis:
        return 'Static';
      default:
        return 'Unknown';
    }
  }
}
