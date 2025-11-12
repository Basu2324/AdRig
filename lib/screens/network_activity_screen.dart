import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/network_monitoring_service.dart';
import '../services/realtime_network_security_service.dart';
import '../core/models/threat_model.dart';
import 'package:intl/intl.dart';

/// Network Activity Screen - View network monitoring logs and detected network threats
/// NOW SHOWS ALWAYS-ON REAL-TIME NETWORK SECURITY STATUS
class NetworkActivityScreen extends StatefulWidget {
  const NetworkActivityScreen({Key? key}) : super(key: key);

  @override
  State<NetworkActivityScreen> createState() => _NetworkActivityScreenState();
}

class _NetworkActivityScreenState extends State<NetworkActivityScreen> {
  final NetworkMonitoringService _networkService = NetworkMonitoringService();
  final RealTimeNetworkSecurityService _realtimeService = RealTimeNetworkSecurityService();
  List<DetectedThreat> _networkThreats = [];
  List<NetworkThreat> _realtimeThreats = [];
  bool _isMonitoring = false;
  bool _isLoading = true;
  
  @override
  void initState() {
    super.initState();
    _loadNetworkData();
  }

  Future<void> _loadNetworkData() async {
    setState(() => _isLoading = true);
    
    try {
      // Get real-time network security threats
      final threats = _realtimeService.getDetectedThreats();
      final stats = _realtimeService.getStatistics();
      
      if (mounted) {
        setState(() {
          _realtimeThreats = threats;
          _isMonitoring = _realtimeService.isRunning;
          _isLoading = false;
        });
        
        print('📊 Network Activity: Loaded ${threats.length} real-time threats');
        print('   Status: ${_realtimeService.isRunning ? "ACTIVE" : "STOPPED"}');
      }
    } catch (e) {
      print('Error loading network data: $e');
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _toggleMonitoring() async {
    try {
      if (_isMonitoring) {
        await _networkService.stopMonitoring();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('🛑 Network monitoring stopped'),
              backgroundColor: Color(0xFFFF9800),
            ),
          );
        }
      } else {
        await _networkService.startMonitoring();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('🌐 Network monitoring started'),
              backgroundColor: Color(0xFF2ECC71),
            ),
          );
        }
      }
      
      if (mounted) {
        setState(() => _isMonitoring = !_isMonitoring);
      }
    } catch (e) {
      print('Error toggling monitoring: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Error: $e'),
            backgroundColor: Color(0xFFFF4757),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final stats = _realtimeService.getStatistics();
    
    return Scaffold(
      backgroundColor: Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: Color(0xFF0A0E27),
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'Network Security',
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          IconButton(
            icon: Icon(Icons.refresh, color: Colors.white70),
            onPressed: _loadNetworkData,
          ),
        ],
      ),
      body: Column(
        children: [
          // Always-On Status Card
          Container(
            margin: EdgeInsets.all(16),
            padding: EdgeInsets.all(20),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: _realtimeService.isRunning
                    ? [Color(0xFF2ECC71), Color(0xFF27AE60)]
                    : [Color(0xFFFF4757), Color(0xFFE84118)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(16),
              boxShadow: [
                BoxShadow(
                  color: (_realtimeService.isRunning ? Color(0xFF2ECC71) : Color(0xFFFF4757)).withOpacity(0.3),
                  blurRadius: 20,
                  offset: Offset(0, 10),
                ),
              ],
            ),
            child: Column(
              children: [
                Row(
                  children: [
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(
                        Icons.security,
                        color: Colors.white,
                        size: 32,
                      ),
                    ),
                    SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Container(
                                width: 10,
                                height: 10,
                                decoration: BoxDecoration(
                                  color: Colors.white,
                                  shape: BoxShape.circle,
                                ),
                              ),
                              SizedBox(width: 8),
                              Text(
                                'REAL-TIME PROTECTION',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                  fontWeight: FontWeight.bold,
                                  letterSpacing: 1.2,
                                ),
                              ),
                            ],
                          ),
                          SizedBox(height: 4),
                          Text(
                            _realtimeService.isRunning ? 'Always Active' : 'Stopped',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 4),
                          Text(
                            'Monitoring URLs, domains, IPs & traffic',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.9),
                              fontSize: 13,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          
          // Statistics Cards
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: [
                Expanded(
                  child: _buildStatCard(
                    'Threats\nBlocked',
                    '${stats['threatsDetected']}',
                    Icons.block,
                    Color(0xFFFF4757),
                  ),
                ),
                SizedBox(width: 12),
                Expanded(
                  child: _buildStatCard(
                    'Blocked\nDomains',
                    '${stats['blockedDomains']}',
                    Icons.domain_disabled,
                    Color(0xFFFF9800),
                  ),
                ),
                SizedBox(width: 12),
                Expanded(
                  child: _buildStatCard(
                    'Protected',
                    '24/7',
                    Icons.verified_user,
                    Color(0xFF2ECC71),
                  ),
                ),
              ],
            ),
          ),
          
          SizedBox(height: 16),
          
          // Detected Threats Section
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Detected Threats',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  '${_realtimeThreats.length} found',
                  style: TextStyle(
                    color: Color(0xFF6C63FF),
                    fontSize: 14,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
          
          SizedBox(height: 12),
          
          // Threat List
          Expanded(
            child: _isLoading
                ? Center(
                    child: CircularProgressIndicator(
                      color: Color(0xFF6C63FF),
                    ),
                  )
                : _realtimeThreats.isEmpty
                    ? _buildEmptyState()
                    : RefreshIndicator(
                        onRefresh: _loadNetworkData,
                        backgroundColor: Color(0xFF1A1F3A),
                        color: Color(0xFF6C63FF),
                        child: ListView.builder(
                          padding: EdgeInsets.symmetric(horizontal: 16),
                          itemCount: _realtimeThreats.length,
                          itemBuilder: (context, index) {
                            final threat = _realtimeThreats[index];
                            return _buildRealtimeThreatCard(threat);
                          },
                        ),
                      ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(String label, String value, IconData icon, Color color) {
    return Container(
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(
        children: [
          Icon(icon, color: color, size: 24),
          SizedBox(height: 8),
          Text(
            value,
            style: TextStyle(
              color: Colors.white,
              fontSize: 20,
              fontWeight: FontWeight.bold,
            ),
          ),
          SizedBox(height: 4),
          Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              color: Colors.white60,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRealtimeThreatCard(NetworkThreat threat) {
    Color severityColor;
    IconData severityIcon;
    
    switch (threat.severity) {
      case 'critical':
        severityColor = Color(0xFFFF4757);
        severityIcon = Icons.dangerous;
        break;
      case 'high':
        severityColor = Color(0xFFFF6348);
        severityIcon = Icons.warning;
        break;
      case 'medium':
        severityColor = Color(0xFFFF9800);
        severityIcon = Icons.error_outline;
        break;
      default:
        severityColor = Color(0xFFFFCA28);
        severityIcon = Icons.info_outline;
    }
    
    return Card(
      color: Color(0xFF151933),
      margin: EdgeInsets.only(bottom: 8),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: severityColor.withOpacity(0.3)),
      ),
      child: ListTile(
        leading: Container(
          padding: EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: severityColor.withOpacity(0.2),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(severityIcon, color: severityColor, size: 24),
        ),
        title: Text(
          threat.type,
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.w600,
          ),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(height: 4),
            Text(
              threat.target,
              style: TextStyle(color: Color(0xFF6C63FF), fontSize: 12),
            ),
            SizedBox(height: 4),
            Text(
              DateFormat('MMM dd, yyyy HH:mm').format(threat.timestamp),
              style: TextStyle(color: Colors.white54, fontSize: 11),
            ),
          ],
        ),
        trailing: Container(
          padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            color: severityColor.withOpacity(0.2),
            borderRadius: BorderRadius.circular(6),
          ),
          child: Text(
            threat.severity.toUpperCase(),
            style: TextStyle(
              color: severityColor,
              fontSize: 10,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.shield_outlined,
            size: 80,
            color: Colors.white24,
          ),
          SizedBox(height: 16),
          Text(
            _isMonitoring
                ? 'No network threats detected'
                : 'Start monitoring to see network activity',
            style: TextStyle(
              color: Colors.white54,
              fontSize: 16,
            ),
          ),
          SizedBox(height: 8),
          Text(
            _isMonitoring
                ? 'Your network connections are secure'
                : 'Real-time network threat detection',
            style: TextStyle(
              color: Colors.white38,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatCard(DetectedThreat threat) {
    Color severityColor;
    IconData severityIcon;
    
    switch (threat.severity) {
      case ThreatSeverity.critical:
        severityColor = Color(0xFFFF4757);
        severityIcon = Icons.dangerous;
        break;
      case ThreatSeverity.high:
        severityColor = Color(0xFFFF6B6B);
        severityIcon = Icons.warning;
        break;
      case ThreatSeverity.medium:
        severityColor = Color(0xFFFF9800);
        severityIcon = Icons.info;
        break;
      case ThreatSeverity.low:
        severityColor = Color(0xFFFFA726);
        severityIcon = Icons.info_outline;
        break;
      case ThreatSeverity.info:
        severityColor = Color(0xFF2196F3);
        severityIcon = Icons.info_outline;
        break;
    }
    
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: severityColor.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () => _showThreatDetails(threat),
          child: Padding(
            padding: EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  padding: EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: severityColor.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    severityIcon,
                    color: severityColor,
                    size: 24,
                  ),
                ),
                SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        threat.appName,
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      SizedBox(height: 4),
                      Text(
                        threat.description,
                        style: TextStyle(
                          color: Colors.white54,
                          fontSize: 13,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                Icon(
                  Icons.chevron_right,
                  color: Colors.white38,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _showThreatDetails(DetectedThreat threat) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) => Container(
        height: MediaQuery.of(context).size.height * 0.6,
        decoration: BoxDecoration(
          color: Color(0xFF1A1F3A),
          borderRadius: BorderRadius.only(
            topLeft: Radius.circular(24),
            topRight: Radius.circular(24),
          ),
        ),
        child: Column(
          children: [
            Container(
              margin: EdgeInsets.symmetric(vertical: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            Padding(
              padding: EdgeInsets.all(20),
              child: Row(
                children: [
                  Icon(
                    Icons.network_check,
                    color: Color(0xFF6C63FF),
                    size: 28,
                  ),
                  SizedBox(width: 12),
                  Text(
                    'Network Threat Details',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
            Divider(color: Colors.white12, height: 1),
            Expanded(
              child: ListView(
                padding: EdgeInsets.all(20),
                children: [
                  _buildDetailRow('Threat', threat.appName),
                  _buildDetailRow('Severity', threat.severity.toString().split('.').last.toUpperCase()),
                  _buildDetailRow('Type', threat.threatType.toString().split('.').last),
                  _buildDetailRow('Description', threat.description),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(
              color: Colors.white54,
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
          SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(
              color: Colors.white,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }
}
