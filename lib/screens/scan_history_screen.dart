import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/threat_history_service.dart';
import '../core/models/threat_model.dart';
import 'package:intl/intl.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';

/// Scan History Screen - View all past scans with results
class ScanHistoryScreen extends StatefulWidget {
  const ScanHistoryScreen({Key? key}) : super(key: key);

  @override
  State<ScanHistoryScreen> createState() => _ScanHistoryScreenState();
}

class _ScanHistoryScreenState extends State<ScanHistoryScreen> {
  List<Map<String, dynamic>> _scanHistory = [];
  bool _isLoading = true;
  String _filterType = 'all'; // all, threats, clean

  @override
  void initState() {
    super.initState();
    _loadScanHistory();
  }

  Future<void> _loadScanHistory() async {
    setState(() => _isLoading = true);
    
    try {
      final prefs = await SharedPreferences.getInstance();
      final historyJson = prefs.getString('threat_history');
      
      if (historyJson != null) {
        final List<dynamic> history = jsonDecode(historyJson);
        if (mounted) {
          setState(() {
            _scanHistory = history.cast<Map<String, dynamic>>();
            _isLoading = false;
          });
        }
      } else {
        if (mounted) {
          setState(() {
            _scanHistory = [];
            _isLoading = false;
          });
        }
      }
    } catch (e) {
      print('Error loading scan history: $e');
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  List<Map<String, dynamic>> get _filteredHistory {
    switch (_filterType) {
      case 'threats':
        return _scanHistory.where((s) => (s['threatsFound'] as int) > 0).toList();
      case 'clean':
        return _scanHistory.where((s) => (s['threatsFound'] as int) == 0).toList();
      default:
        return _scanHistory;
    }
  }

  @override
  Widget build(BuildContext context) {
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
          'Scan History',
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          PopupMenuButton<String>(
            icon: Icon(Icons.filter_list, color: Colors.white),
            onSelected: (value) {
              setState(() => _filterType = value);
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                value: 'all',
                child: Text('All Scans'),
              ),
              PopupMenuItem(
                value: 'threats',
                child: Text('With Threats'),
              ),
              PopupMenuItem(
                value: 'clean',
                child: Text('Clean Scans'),
              ),
            ],
          ),
        ],
      ),
      body: _isLoading
          ? Center(
              child: CircularProgressIndicator(
                color: Color(0xFF6C63FF),
              ),
            )
          : _filteredHistory.isEmpty
              ? _buildEmptyState()
              : RefreshIndicator(
                  onRefresh: _loadScanHistory,
                  backgroundColor: Color(0xFF1A1F3A),
                  color: Color(0xFF6C63FF),
                  child: ListView.builder(
                    padding: EdgeInsets.all(16),
                    itemCount: _filteredHistory.length,
                    itemBuilder: (context, index) {
                      final scan = _filteredHistory[index];
                      return _buildScanCard(scan);
                    },
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
            Icons.history,
            size: 80,
            color: Colors.white24,
          ),
          SizedBox(height: 16),
          Text(
            _filterType == 'threats'
                ? 'No threats found in history'
                : _filterType == 'clean'
                    ? 'No clean scans in history'
                    : 'No scan history yet',
            style: TextStyle(
              color: Colors.white54,
              fontSize: 16,
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Run a scan to see results here',
            style: TextStyle(
              color: Colors.white38,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanCard(Map<String, dynamic> scan) {
    final dateFormat = DateFormat('MMM dd, yyyy • HH:mm');
    final timestamp = DateTime.fromMillisecondsSinceEpoch(scan['timestamp'] as int);
    final appsScanned = scan['totalApps'] as int;
    final threatsFound = scan['threatsFound'] as int;
    final hasThreats = threatsFound > 0;
    
    return Container(
      margin: EdgeInsets.only(bottom: 16),
      decoration: BoxDecoration(
        color: Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: hasThreats ? Color(0xFFFF4757).withOpacity(0.3) : Colors.transparent,
          width: 1,
        ),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: () => _showScanDetails(scan),
          child: Padding(
            padding: EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: hasThreats
                            ? Color(0xFFFF4757).withOpacity(0.2)
                            : Color(0xFF2ECC71).withOpacity(0.2),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(
                        hasThreats ? Icons.warning_amber : Icons.check_circle,
                        color: hasThreats ? Color(0xFFFF4757) : Color(0xFF2ECC71),
                        size: 24,
                      ),
                    ),
                    SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            dateFormat.format(timestamp),
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          SizedBox(height: 4),
                          Text(
                            'Scan ID: ${(scan['scanId'] as String).substring(0, 8)}...',
                            style: TextStyle(
                              color: Colors.white38,
                              fontSize: 12,
                            ),
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
                SizedBox(height: 16),
                Row(
                  children: [
                    _buildStatItem(
                      Icons.apps,
                      '$appsScanned Apps',
                      Colors.blue.shade400,
                    ),
                    SizedBox(width: 16),
                    _buildStatItem(
                      hasThreats ? Icons.warning : Icons.shield_outlined,
                      hasThreats
                          ? '$threatsFound Threats'
                          : 'Clean',
                      hasThreats ? Color(0xFFFF4757) : Color(0xFF2ECC71),
                    ),
                    SizedBox(width: 16),
                    _buildStatItem(
                      Icons.timer_outlined,
                      '~${(appsScanned * 0.5).round()}s',
                      Colors.purple.shade400,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStatItem(IconData icon, String label, Color color) {
    return Row(
      children: [
        Icon(icon, size: 16, color: color),
        SizedBox(width: 4),
        Text(
          label,
          style: TextStyle(
            color: Colors.white70,
            fontSize: 12,
          ),
        ),
      ],
    );
  }

  String _formatDuration(int seconds) {
    if (seconds > 3600) {
      final hours = seconds ~/ 3600;
      final mins = (seconds % 3600) ~/ 60;
      return '${hours}h ${mins}m';
    } else if (seconds > 60) {
      final mins = seconds ~/ 60;
      final secs = seconds % 60;
      return '${mins}m ${secs}s';
    } else {
      return '${seconds}s';
    }
  }

  void _showScanDetails(Map<String, dynamic> scan) {
    final timestamp = DateTime.fromMillisecondsSinceEpoch(scan['timestamp'] as int);
    final appsScanned = scan['totalApps'] as int;
    final threatsFound = scan['threatsFound'] as int;
    final scanId = scan['scanId'] as String;
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (context) => Container(
        height: MediaQuery.of(context).size.height * 0.7,
        decoration: BoxDecoration(
          color: Color(0xFF1A1F3A),
          borderRadius: BorderRadius.only(
            topLeft: Radius.circular(24),
            topRight: Radius.circular(24),
          ),
        ),
        child: Column(
          children: [
            // Handle bar
            Container(
              margin: EdgeInsets.symmetric(vertical: 12),
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Colors.white24,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            // Header
            Padding(
              padding: EdgeInsets.all(20),
              child: Row(
                children: [
                  Icon(
                    Icons.assessment,
                    color: Color(0xFF6C63FF),
                    size: 28,
                  ),
                  SizedBox(width: 12),
                  Text(
                    'Scan Details',
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
            // Content
            Expanded(
              child: ListView(
                padding: EdgeInsets.all(20),
                children: [
                  _buildDetailRow('Scan ID', scanId),
                  _buildDetailRow('Apps Scanned', '$appsScanned'),
                  _buildDetailRow('Threats Found', '$threatsFound'),
                  _buildDetailRow('Duration', '~${(appsScanned * 0.5).round()}s'),
                  _buildDetailRow(
                    'Scanned',
                    DateFormat('MMM dd, yyyy HH:mm:ss').format(timestamp),
                  ),
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
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              color: Colors.white54,
              fontSize: 14,
            ),
          ),
          Text(
            value,
            style: TextStyle(
              color: Colors.white,
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }
}
