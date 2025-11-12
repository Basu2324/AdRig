import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/quarantine_service.dart';
import '../services/scan_coordinator.dart';
import '../core/models/threat_model.dart';
import 'package:intl/intl.dart';

/// Quarantine Management Screen - View and manage quarantined apps
class QuarantineManagementScreen extends StatefulWidget {
  const QuarantineManagementScreen({Key? key}) : super(key: key);

  @override
  State<QuarantineManagementScreen> createState() => _QuarantineManagementScreenState();
}

class _QuarantineManagementScreenState extends State<QuarantineManagementScreen> {
  List<QuarantineEntry> _quarantinedApps = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadQuarantinedApps();
  }

  Future<void> _loadQuarantinedApps() async {
    setState(() => _isLoading = true);
    
    try {
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final quarantineService = coordinator.getQuarantineService();
      
      final apps = await quarantineService.getQuarantinedApps();
      
      if (mounted) {
        setState(() {
          _quarantinedApps = apps;
          _isLoading = false;
        });
      }
    } catch (e) {
      print('Error loading quarantined apps: $e');
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _restoreApp(QuarantineEntry entry) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
        title: Text(
          'Restore App?',
          style: TextStyle(color: Colors.white),
        ),
        content: Text(
          'Are you sure you want to restore "${entry.appName}"?\n\nThis app was quarantined because:\n${entry.reason}',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('Cancel', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFF6C63FF),
            ),
            child: Text('Restore'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
        final quarantineService = coordinator.getQuarantineService();
        
        final success = await quarantineService.restoreApp(entry.packageName);
        
        if (mounted) {
          if (success) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('✅ ${entry.appName} restored successfully'),
                backgroundColor: Color(0xFF2ECC71),
              ),
            );
            _loadQuarantinedApps();
          } else {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('❌ Failed to restore app'),
                backgroundColor: Color(0xFFFF4757),
              ),
            );
          }
        }
      } catch (e) {
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
  }

  Future<void> _deleteApp(QuarantineEntry entry) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
        title: Text(
          'Delete Permanently?',
          style: TextStyle(color: Colors.white),
        ),
        content: Text(
          'Are you sure you want to permanently delete "${entry.appName}"?\n\nThis action cannot be undone.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('Cancel', style: TextStyle(color: Colors.white54)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('Delete'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      // TODO: Implement permanent deletion
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('🗑️ Permanent deletion not yet implemented'),
            backgroundColor: Color(0xFFFF9800),
          ),
        );
      }
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
          'Quarantine',
          style: TextStyle(
            color: Colors.white,
            fontWeight: FontWeight.bold,
          ),
        ),
      ),
      body: _isLoading
          ? Center(
              child: CircularProgressIndicator(
                color: Color(0xFF6C63FF),
              ),
            )
          : _quarantinedApps.isEmpty
              ? _buildEmptyState()
              : Column(
                  children: [
                    // Stats Header
                    Container(
                      margin: EdgeInsets.all(16),
                      padding: EdgeInsets.all(20),
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: [Color(0xFFFF4757), Color(0xFFE84118)],
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                        ),
                        borderRadius: BorderRadius.circular(16),
                        boxShadow: [
                          BoxShadow(
                            color: Color(0xFFFF4757).withOpacity(0.3),
                            blurRadius: 20,
                            offset: Offset(0, 10),
                          ),
                        ],
                      ),
                      child: Row(
                        children: [
                          Container(
                            padding: EdgeInsets.all(12),
                            decoration: BoxDecoration(
                              color: Colors.white.withOpacity(0.2),
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Icon(
                              Icons.lock_outline,
                              color: Colors.white,
                              size: 28,
                            ),
                          ),
                          SizedBox(width: 16),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  '${_quarantinedApps.length} Apps Quarantined',
                                  style: TextStyle(
                                    color: Colors.white,
                                    fontSize: 18,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                                SizedBox(height: 4),
                                Text(
                                  'Isolated from your system',
                                  style: TextStyle(
                                    color: Colors.white.withOpacity(0.9),
                                    fontSize: 14,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                    
                    // App List
                    Expanded(
                      child: RefreshIndicator(
                        onRefresh: _loadQuarantinedApps,
                        backgroundColor: Color(0xFF1A1F3A),
                        color: Color(0xFF6C63FF),
                        child: ListView.builder(
                          padding: EdgeInsets.symmetric(horizontal: 16),
                          itemCount: _quarantinedApps.length,
                          itemBuilder: (context, index) {
                            final entry = _quarantinedApps[index];
                            return _buildQuarantineCard(entry);
                          },
                        ),
                      ),
                    ),
                  ],
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
            'No quarantined apps',
            style: TextStyle(
              color: Colors.white54,
              fontSize: 16,
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Malicious apps will be isolated here',
            style: TextStyle(
              color: Colors.white38,
              fontSize: 14,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQuarantineCard(QuarantineEntry entry) {
    final dateFormat = DateFormat('MMM dd, yyyy • HH:mm');
    
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Color(0xFF1A1F3A),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Color(0xFFFF4757).withOpacity(0.3),
          width: 1,
        ),
      ),
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
                    color: Color(0xFFFF4757).withOpacity(0.2),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    Icons.dangerous,
                    color: Color(0xFFFF4757),
                    size: 24,
                  ),
                ),
                SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        entry.appName,
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      SizedBox(height: 4),
                      Text(
                        entry.packageName,
                        style: TextStyle(
                          color: Colors.white38,
                          fontSize: 12,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            SizedBox(height: 12),
            Container(
              padding: EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Color(0xFF0A0E27),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Reason:',
                    style: TextStyle(
                      color: Colors.white54,
                      fontSize: 12,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    entry.reason,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 13,
                    ),
                  ),
                ],
              ),
            ),
            SizedBox(height: 12),
            Row(
              children: [
                Icon(Icons.access_time, size: 14, color: Colors.white38),
                SizedBox(width: 4),
                Text(
                  'Quarantined: ${dateFormat.format(entry.quarantinedAt)}',
                  style: TextStyle(
                    color: Colors.white38,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
            SizedBox(height: 12),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: entry.canRestore ? () => _restoreApp(entry) : null,
                    icon: Icon(Icons.restore, size: 18),
                    label: Text('Restore'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Color(0xFF2ECC71),
                      side: BorderSide(color: Color(0xFF2ECC71)),
                      padding: EdgeInsets.symmetric(vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
                SizedBox(width: 12),
                Expanded(
                  child: OutlinedButton.icon(
                    onPressed: () => _deleteApp(entry),
                    icon: Icon(Icons.delete_outline, size: 18),
                    label: Text('Delete'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Color(0xFFFF4757),
                      side: BorderSide(color: Color(0xFFFF4757)),
                      padding: EdgeInsets.symmetric(vertical: 10),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
