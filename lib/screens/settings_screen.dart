import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'dart:io';
import 'package:path_provider/path_provider.dart';
import '../services/signature_database.dart';
import 'threat_list_screen.dart';
import 'scan_history_screen.dart';
import 'network_activity_screen.dart';
import 'quarantine_management_screen.dart';
import 'whitelist_management_screen.dart';
import 'data_collection_screen.dart';
import 'privacy_policy_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({Key? key}) : super(key: key);

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  bool _realTimeProtection = true;
  bool _autoScan = false;
  bool _notifications = true;
  bool _cloudSync = true;
  bool _biometricLock = false;
  
  String _scanFrequency = 'Daily';
  String _threatLevel = 'Medium';
  
  @override
  void initState() {
    super.initState();
    _loadSettings();
  }
  
  /// Load settings from SharedPreferences
  Future<void> _loadSettings() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      setState(() {
        _realTimeProtection = prefs.getBool('realTimeProtection') ?? true;
        _autoScan = prefs.getBool('autoScan') ?? false;
        _notifications = prefs.getBool('notifications') ?? true;
        _cloudSync = prefs.getBool('cloudSync') ?? true;
        _biometricLock = prefs.getBool('biometricLock') ?? false;
        _scanFrequency = prefs.getString('scanFrequency') ?? 'Daily';
        _threatLevel = prefs.getString('threatLevel') ?? 'Medium';
      });
    } catch (e) {
      print('Error loading settings: $e');
    }
  }
  
  /// Save settings to SharedPreferences
  Future<void> _saveSettings() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('realTimeProtection', _realTimeProtection);
      await prefs.setBool('autoScan', _autoScan);
      await prefs.setBool('notifications', _notifications);
      await prefs.setBool('cloudSync', _cloudSync);
      await prefs.setBool('biometricLock', _biometricLock);
      await prefs.setString('scanFrequency', _scanFrequency);
      await prefs.setString('threatLevel', _threatLevel);
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('✅ Settings saved'),
          backgroundColor: Colors.green,
          duration: Duration(seconds: 1),
        ),
      );
    } catch (e) {
      print('Error saving settings: $e');
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
          'Settings',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(16),
        children: [
          // General Settings
          _buildSectionHeader('General'),
          _buildSwitchTile(
            title: 'Real-Time Protection',
            subtitle: 'Monitor apps and files continuously',
            value: _realTimeProtection,
            onChanged: (value) {
              setState(() => _realTimeProtection = value);
              _saveSettings();
            },
          ),
          _buildSwitchTile(
            title: 'Auto Scan',
            subtitle: 'Automatically scan new apps on install',
            value: _autoScan,
            onChanged: (value) {
              setState(() => _autoScan = value);
              _saveSettings();
            },
          ),
          _buildSwitchTile(
            title: 'Notifications',
            subtitle: 'Get alerts about threats and updates',
            value: _notifications,
            onChanged: (value) {
              setState(() => _notifications = value);
              _saveSettings();
            },
          ),
          
          _buildDropdownTile(
            title: 'Scan Frequency',
            subtitle: 'How often to run automatic scans',
            value: _scanFrequency,
            items: ['Daily', 'Weekly', 'Monthly'],
            onChanged: (value) {
              setState(() => _scanFrequency = value!);
              _saveSettings();
            },
          ),
          
          SizedBox(height: 24),
          
          // Security Settings
          _buildSectionHeader('Security'),
          _buildSwitchTile(
            title: 'Biometric Lock',
            subtitle: 'Require fingerprint to open app',
            value: _biometricLock,
            onChanged: (value) {
              setState(() => _biometricLock = value);
              _saveSettings();
            },
          ),
          
          _buildDropdownTile(
            title: 'Threat Detection Level',
            subtitle: 'Sensitivity of malware detection',
            value: _threatLevel,
            items: ['Low', 'Medium', 'High', 'Paranoid'],
            onChanged: (value) {
              setState(() => _threatLevel = value!);
              _saveSettings();
            },
          ),
          
          _buildNavigationTile(
            title: 'Whitelist Management',
            subtitle: 'Manage trusted apps',
            icon: Icons.verified_user_outlined,
            onTap: () {
              // TODO: Navigate to whitelist screen
            },
          ),
          
          _buildNavigationTile(
            title: 'Quarantine Settings',
            subtitle: 'Manage quarantined apps',
            icon: Icons.folder_special_outlined,
            onTap: () {
              // TODO: Navigate to quarantine screen
            },
          ),
          
          SizedBox(height: 24),
          
          // Privacy Settings
          _buildSectionHeader('Privacy'),
          _buildSwitchTile(
            title: 'Cloud Sync',
            subtitle: 'Sync threat data across devices',
            value: _cloudSync,
            onChanged: (value) {
              setState(() => _cloudSync = value);
              _saveSettings();
            },
          ),
          
          _buildNavigationTile(
            title: 'Data Collection',
            subtitle: 'Manage what data is shared',
            icon: Icons.analytics_outlined,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => DataCollectionScreen(),
                ),
              );
            },
          ),
          
          _buildNavigationTile(
            title: 'Privacy Policy',
            subtitle: 'View our privacy policy',
            icon: Icons.policy_outlined,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => PrivacyPolicyScreen(),
                ),
              );
            },
          ),
          
          SizedBox(height: 24),
          
          // Activity Log
          _buildSectionHeader('Activity Log'),
          _buildNavigationTile(
            title: 'Scan History',
            subtitle: 'View past scans and results',
            icon: Icons.history,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => ScanHistoryScreen(),
                ),
              );
            },
          ),
          
          _buildNavigationTile(
            title: 'Threat Log',
            subtitle: 'View all detected threats',
            icon: Icons.warning_amber_outlined,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => ThreatListScreen(category: 'high'),
                ),
              );
            },
          ),
          
          _buildNavigationTile(
            title: 'Network Activity',
            subtitle: 'View network monitoring logs',
            icon: Icons.network_check,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => NetworkActivityScreen(),
                ),
              );
            },
          ),
          
          SizedBox(height: 24),
          
          // Advanced Settings
          _buildSectionHeader('Advanced'),
          _buildNavigationTile(
            title: 'Quarantine',
            subtitle: 'Manage quarantined apps',
            icon: Icons.lock_outline,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => QuarantineManagementScreen(),
                ),
              );
            },
          ),
          
          _buildNavigationTile(
            title: 'Whitelist',
            subtitle: 'Manage trusted apps',
            icon: Icons.verified_user,
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (context) => WhitelistManagementScreen(),
                ),
              );
            },
          ),
          
          _buildNavigationTile(
            title: 'Update Database',
            subtitle: 'Update malware signatures',
            icon: Icons.update,
            onTap: () {
              _showUpdateDialog();
            },
          ),
          
          _buildNavigationTile(
            title: 'Clear Cache',
            subtitle: 'Free up storage space',
            icon: Icons.cleaning_services_outlined,
            onTap: () {
              _showClearCacheDialog();
            },
          ),
          
          _buildNavigationTile(
            title: 'Export Settings',
            subtitle: 'Backup your configuration',
            icon: Icons.download,
            onTap: () {
              _exportSettings();
            },
          ),
          
          SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: EdgeInsets.only(left: 4, bottom: 12, top: 8),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.bold,
          color: Color(0xFF6C63FF),
          letterSpacing: 1.2,
        ),
      ),
    );
  }

  Widget _buildSwitchTile({
    required String title,
    required String subtitle,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: SwitchListTile(
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontSize: 15),
        ),
        subtitle: Text(
          subtitle,
          style: TextStyle(color: Colors.white60, fontSize: 12),
        ),
        value: value,
        onChanged: onChanged,
        activeColor: Color(0xFF6C63FF),
        contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 4),
      ),
    );
  }

  Widget _buildDropdownTile({
    required String title,
    required String subtitle,
    required String value,
    required List<String> items,
    required ValueChanged<String?> onChanged,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(color: Colors.white, fontSize: 15),
          ),
          SizedBox(height: 4),
          Text(
            subtitle,
            style: TextStyle(color: Colors.white60, fontSize: 12),
          ),
          SizedBox(height: 12),
          DropdownButton<String>(
            value: value,
            isExpanded: true,
            dropdownColor: Color(0xFF1A1F3A),
            style: TextStyle(color: Colors.white),
            underline: Container(
              height: 1,
              color: Colors.white30,
            ),
            items: items.map((item) {
              return DropdownMenuItem(
                value: item,
                child: Text(item),
              );
            }).toList(),
            onChanged: onChanged,
          ),
        ],
      ),
    );
  }

  Widget _buildNavigationTile({
    required String title,
    required String subtitle,
    required IconData icon,
    required VoidCallback onTap,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: ListTile(
        leading: Icon(icon, color: Color(0xFF6C63FF)),
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontSize: 15),
        ),
        subtitle: Text(
          subtitle,
          style: TextStyle(color: Colors.white60, fontSize: 12),
        ),
        trailing: Icon(Icons.chevron_right, color: Colors.white30),
        onTap: onTap,
      ),
    );
  }

  void _showUpdateDialog() {
    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Colors.white,
        title: Text('Update Database', style: TextStyle(color: Colors.black87)),
        content: Text(
          'Download the latest malware signatures?\n\nSize: ~15 MB',
          style: TextStyle(color: Colors.black87),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text('CANCEL', style: TextStyle(color: Colors.grey.shade700)),
          ),
          ElevatedButton(
            onPressed: () async {
              // Close confirmation dialog first
              Navigator.pop(dialogContext);
              
              // Show loading dialog with its own context
              showDialog(
                context: context,
                barrierDismissible: false,
                builder: (loadingContext) => WillPopScope(
                  onWillPop: () async => false,
                  child: Center(
                    child: Container(
                      padding: EdgeInsets.all(32),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          CircularProgressIndicator(color: Colors.blue.shade700),
                          SizedBox(height: 16),
                          Text(
                            'Updating database...',
                            style: TextStyle(color: Colors.black87),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              );
              
              try {
                // Update the signature database
                final signatureDB = SignatureDatabase();
                await signatureDB.initialize();
                final success = await signatureDB.manualUpdate();
                
                // Close loading dialog using Navigator.of(context).pop()
                if (mounted) {
                  Navigator.of(context).pop();
                  
                  if (success) {
                    final stats = await signatureDB.getDatabaseStats();
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('✅ Database updated!\n${stats['totalSignatures']} signatures loaded'),
                        backgroundColor: Colors.green,
                        duration: Duration(seconds: 3),
                      ),
                    );
                  } else {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('ℹ️ Database is already up to date'),
                        backgroundColor: Colors.blue,
                        duration: Duration(seconds: 2),
                      ),
                    );
                  }
                }
              } catch (e) {
                // Close loading dialog
                if (mounted) {
                  Navigator.of(context).pop();
                  
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('❌ Update failed: $e'),
                      backgroundColor: Colors.red,
                      duration: Duration(seconds: 3),
                    ),
                  );
                }
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.blue.shade700,
              foregroundColor: Colors.white,
            ),
            child: Text('UPDATE'),
          ),
        ],
      ),
    );
  }

  void _showClearCacheDialog() {
    showDialog(
      context: context,
      builder: (dialogContext) => AlertDialog(
        backgroundColor: Colors.white,
        title: Text('Clear Cache', style: TextStyle(color: Colors.black87)),
        content: Text(
          'This will clear temporary files and logs.\n\nEstimated space: 45 MB',
          style: TextStyle(color: Colors.black87),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialogContext),
            child: Text('CANCEL', style: TextStyle(color: Colors.grey.shade700)),
          ),
          ElevatedButton(
            onPressed: () async {
              // Close confirmation dialog first
              Navigator.pop(dialogContext);
              
              // Show loading dialog with its own context
              showDialog(
                context: context,
                barrierDismissible: false,
                builder: (loadingContext) => WillPopScope(
                  onWillPop: () async => false,
                  child: Center(
                    child: Container(
                      padding: EdgeInsets.all(32),
                      decoration: BoxDecoration(
                        color: Colors.white,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          CircularProgressIndicator(color: Colors.blue.shade700),
                          SizedBox(height: 16),
                          Text(
                            'Clearing cache...',
                            style: TextStyle(color: Colors.black87),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              );
              
              try {
                // Clear cache (simulate delay for processing)
                await Future.delayed(Duration(seconds: 1));
                
                // Clear SharedPreferences cache (except settings)
                final prefs = await SharedPreferences.getInstance();
                final keysToKeep = [
                  'realTimeProtection',
                  'autoScan',
                  'notifications',
                  'cloudSync',
                  'biometricLock',
                  'scanFrequency',
                  'threatLevel',
                  'isLoggedIn',
                  'userId',
                  'userName',
                  'userEmail',
                ];
                
                final allKeys = prefs.getKeys();
                int clearedCount = 0;
                for (final key in allKeys) {
                  if (!keysToKeep.contains(key)) {
                    await prefs.remove(key);
                    clearedCount++;
                  }
                }
                
                // Close loading dialog using Navigator.of(context).pop()
                if (mounted) {
                  Navigator.of(context).pop();
                  
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('✅ Cache cleared successfully\n$clearedCount items removed'),
                      backgroundColor: Colors.green,
                      duration: Duration(seconds: 2),
                    ),
                  );
                }
              } catch (e) {
                // Close loading dialog
                if (mounted) {
                  Navigator.of(context).pop();
                  
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('❌ Failed to clear cache: $e'),
                      backgroundColor: Colors.red,
                      duration: Duration(seconds: 3),
                    ),
                  );
                }
              }
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.blue.shade700,
              foregroundColor: Colors.white,
            ),
            child: Text('CLEAR'),
          ),
        ],
      ),
    );
  }

  /// Export settings to JSON file
  Future<void> _exportSettings() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      
      // Collect all settings
      final settingsData = {
        'exported_at': DateTime.now().toIso8601String(),
        'app': 'AdRig Malware Scanner',
        'version': '1.0.0',
        'settings': {
          'general': {
            'realTimeProtection': prefs.getBool('realTimeProtection') ?? true,
            'autoScan': prefs.getBool('autoScan') ?? false,
            'notifications': prefs.getBool('notifications') ?? true,
            'cloudSync': prefs.getBool('cloudSync') ?? true,
            'biometricLock': prefs.getBool('biometricLock') ?? false,
            'scanFrequency': prefs.getString('scanFrequency') ?? 'Daily',
            'threatLevel': prefs.getString('threatLevel') ?? 'Medium',
          },
          'privacy': {
            'data_crashReports': prefs.getBool('data_crashReports') ?? true,
            'data_usageStats': prefs.getBool('data_usageStats') ?? true,
            'data_threatIntel': prefs.getBool('data_threatIntel') ?? true,
            'data_performanceData': prefs.getBool('data_performanceData') ?? false,
            'data_diagnostics': prefs.getBool('data_diagnostics') ?? false,
          },
        },
      };
      
      // Convert to JSON
      final jsonString = JsonEncoder.withIndent('  ').convert(settingsData);
      
      // Get documents directory
      final directory = await getApplicationDocumentsDirectory();
      final filePath = '${directory.path}/adrig_settings_backup.json';
      final file = File(filePath);
      
      // Write to file
      await file.writeAsString(jsonString);
      
      if (mounted) {
        showDialog(
          context: context,
          builder: (context) => AlertDialog(
            backgroundColor: Color(0xFF151933),
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
            title: Row(
              children: [
                Icon(Icons.check_circle, color: Colors.green, size: 28),
                SizedBox(width: 12),
                Text(
                  'Export Successful',
                  style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
                ),
              ],
            ),
            content: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Settings exported to:',
                  style: TextStyle(color: Colors.white70, fontSize: 14),
                ),
                SizedBox(height: 8),
                Container(
                  padding: EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Color(0xFF0A0E27),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    filePath,
                    style: TextStyle(
                      color: Color(0xFF6C63FF),
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(context),
                child: Text('OK', style: TextStyle(color: Color(0xFF6C63FF))),
              ),
            ],
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Export failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }
}
