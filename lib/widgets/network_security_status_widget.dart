import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/scan_coordinator.dart';
import '../services/network_security_service.dart';

/// Network Security Status Widget
/// Shows real-time network protection status on home screen
/// Displays: Active monitoring, threats blocked, connections analyzed
class NetworkSecurityStatusWidget extends StatefulWidget {
  const NetworkSecurityStatusWidget({Key? key}) : super(key: key);

  @override
  State<NetworkSecurityStatusWidget> createState() => _NetworkSecurityStatusWidgetState();
}

class _NetworkSecurityStatusWidgetState extends State<NetworkSecurityStatusWidget> {
  Map<String, dynamic> _stats = {};
  List<NetworkThreat> _recentThreats = [];

  @override
  void initState() {
    super.initState();
    _loadNetworkStatus();
    
    // Refresh every 10 seconds
    Future.delayed(Duration(seconds: 1), () {
      if (mounted) {
        _startAutoRefresh();
      }
    });
  }

  void _startAutoRefresh() {
    Future.delayed(Duration(seconds: 10), () {
      if (mounted) {
        _loadNetworkStatus();
        _startAutoRefresh();
      }
    });
  }

  Future<void> _loadNetworkStatus() async {
    try {
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final stats = coordinator.getNetworkSecurityStats();
      final threats = coordinator.getNetworkThreats();
      
      if (mounted) {
        setState(() {
          _stats = stats;
          _recentThreats = threats.take(3).toList();
        });
      }
    } catch (e) {
      print('Error loading network status: $e');
    }
  }

  @override
  Widget build(BuildContext context) {
    final isMonitoring = _stats['isMonitoring'] as bool? ?? false;
    final threatsBlocked = _stats['threatsBlocked'] as int? ?? 0;
    final connectionsAnalyzed = _stats['totalConnectionsAnalyzed'] as int? ?? 0;
    
    return Container(
      margin: EdgeInsets.symmetric(horizontal: 24, vertical: 8),
      padding: EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF1A1F3A),
            Color(0xFF0D1025),
          ],
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: isMonitoring ? Color(0xFF00D9FF).withOpacity(0.5) : Color(0xFFFF6B6B).withOpacity(0.3),
          width: 2,
        ),
        boxShadow: [
          BoxShadow(
            color: isMonitoring ? Color(0xFF00D9FF).withOpacity(0.2) : Colors.transparent,
            blurRadius: 20,
            offset: Offset(0, 4),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Container(
                padding: EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: isMonitoring ? Color(0xFF00D9FF).withOpacity(0.15) : Color(0xFFFF6B6B).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  Icons.security,
                  color: isMonitoring ? Color(0xFF00D9FF) : Color(0xFFFF6B6B),
                  size: 28,
                ),
              ),
              SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Network Security',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                    SizedBox(height: 4),
                    Row(
                      children: [
                        Container(
                          width: 8,
                          height: 8,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: isMonitoring ? Color(0xFF00FF88) : Color(0xFFFF6B6B),
                            boxShadow: [
                              BoxShadow(
                                color: isMonitoring ? Color(0xFF00FF88).withOpacity(0.5) : Color(0xFFFF6B6B).withOpacity(0.5),
                                blurRadius: 8,
                              ),
                            ],
                          ),
                        ),
                        SizedBox(width: 8),
                        Text(
                          isMonitoring ? 'Active Protection' : 'Inactive',
                          style: TextStyle(
                            fontSize: 13,
                            color: isMonitoring ? Color(0xFF00FF88) : Color(0xFFFF6B6B),
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
          
          SizedBox(height: 20),
          
          // Stats
          Row(
            children: [
              Expanded(
                child: _buildStat(
                  label: 'Threats Blocked',
                  value: threatsBlocked.toString(),
                  icon: Icons.block,
                  color: Color(0xFFFF6B6B),
                ),
              ),
              SizedBox(width: 12),
              Expanded(
                child: _buildStat(
                  label: 'Connections',
                  value: connectionsAnalyzed.toString(),
                  icon: Icons.network_check,
                  color: Color(0xFF00D9FF),
                ),
              ),
            ],
          ),
          
          // Recent threats
          if (_recentThreats.isNotEmpty) ...[
            SizedBox(height: 16),
            Divider(color: Colors.white12, height: 1),
            SizedBox(height: 12),
            Text(
              'Recent Threats',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.bold,
                color: Colors.white70,
              ),
            ),
            SizedBox(height: 8),
            ..._recentThreats.map((threat) => _buildThreatItem(threat)).toList(),
          ],
        ],
      ),
    );
  }
  
  Widget _buildStat({
    required String label,
    required String value,
    required IconData icon,
    required Color color,
  }) {
    return Container(
      padding: EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: color.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 20),
          SizedBox(height: 6),
          Text(
            value,
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          SizedBox(height: 2),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              color: Colors.white54,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }
  
  Widget _buildThreatItem(NetworkThreat threat) {
    Color severityColor;
    switch (threat.severity) {
      case ThreatSeverity.critical:
        severityColor = Color(0xFFFF4757);
        break;
      case ThreatSeverity.high:
        severityColor = Color(0xFFFF6B6B);
        break;
      case ThreatSeverity.medium:
        severityColor = Color(0xFFFFA502);
        break;
      default:
        severityColor = Color(0xFFFFD93D);
    }
    
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      padding: EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: severityColor.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: severityColor.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Row(
        children: [
          Icon(
            threat.blocked ? Icons.block : Icons.warning,
            color: severityColor,
            size: 16,
          ),
          SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  threat.type,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Text(
                  threat.description,
                  style: TextStyle(
                    fontSize: 10,
                    color: Colors.white60,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          if (threat.blocked)
            Container(
              padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: Color(0xFF00FF88).withOpacity(0.2),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                'BLOCKED',
                style: TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.bold,
                  color: Color(0xFF00FF88),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
