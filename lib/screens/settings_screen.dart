import 'package:flutter/material.dart';

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
            onChanged: (value) => setState(() => _realTimeProtection = value),
          ),
          _buildSwitchTile(
            title: 'Auto Scan',
            subtitle: 'Automatically scan new apps on install',
            value: _autoScan,
            onChanged: (value) => setState(() => _autoScan = value),
          ),
          _buildSwitchTile(
            title: 'Notifications',
            subtitle: 'Get alerts about threats and updates',
            value: _notifications,
            onChanged: (value) => setState(() => _notifications = value),
          ),
          
          _buildDropdownTile(
            title: 'Scan Frequency',
            subtitle: 'How often to run automatic scans',
            value: _scanFrequency,
            items: ['Daily', 'Weekly', 'Monthly'],
            onChanged: (value) => setState(() => _scanFrequency = value!),
          ),
          
          SizedBox(height: 24),
          
          // Security Settings
          _buildSectionHeader('Security'),
          _buildSwitchTile(
            title: 'Biometric Lock',
            subtitle: 'Require fingerprint to open app',
            value: _biometricLock,
            onChanged: (value) => setState(() => _biometricLock = value),
          ),
          
          _buildDropdownTile(
            title: 'Threat Detection Level',
            subtitle: 'Sensitivity of malware detection',
            value: _threatLevel,
            items: ['Low', 'Medium', 'High', 'Paranoid'],
            onChanged: (value) => setState(() => _threatLevel = value!),
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
            onChanged: (value) => setState(() => _cloudSync = value),
          ),
          
          _buildNavigationTile(
            title: 'Data Collection',
            subtitle: 'Manage what data is shared',
            icon: Icons.analytics_outlined,
            onTap: () {
              // TODO: Navigate to data collection screen
            },
          ),
          
          _buildNavigationTile(
            title: 'Privacy Policy',
            subtitle: 'View our privacy policy',
            icon: Icons.policy_outlined,
            onTap: () {
              // TODO: Show privacy policy
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
              // TODO: Navigate to scan history
            },
          ),
          
          _buildNavigationTile(
            title: 'Threat Log',
            subtitle: 'View all detected threats',
            icon: Icons.warning_amber_outlined,
            onTap: () {
              // TODO: Navigate to threat log
            },
          ),
          
          _buildNavigationTile(
            title: 'Network Activity',
            subtitle: 'View network monitoring logs',
            icon: Icons.network_check,
            onTap: () {
              // TODO: Navigate to network log
            },
          ),
          
          SizedBox(height: 24),
          
          // Advanced Settings
          _buildSectionHeader('Advanced'),
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
              // TODO: Export settings
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
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text('Update Database', style: TextStyle(color: Colors.white)),
        content: Text(
          'Download the latest malware signatures?\n\nSize: ~15 MB',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Start update
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Database updated successfully'),
                  backgroundColor: Color(0xFF00C853),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFF6C63FF),
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
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text('Clear Cache', style: TextStyle(color: Colors.white)),
        content: Text(
          'This will clear temporary files and logs.\n\nEstimated space: 45 MB',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Clear cache
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Cache cleared successfully'),
                  backgroundColor: Color(0xFF00C853),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFF6C63FF),
            ),
            child: Text('CLEAR'),
          ),
        ],
      ),
    );
  }
}
