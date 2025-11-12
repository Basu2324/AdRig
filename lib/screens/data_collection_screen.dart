import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Data Collection Settings Screen - Control what data is shared
class DataCollectionScreen extends StatefulWidget {
  const DataCollectionScreen({Key? key}) : super(key: key);

  @override
  State<DataCollectionScreen> createState() => _DataCollectionScreenState();
}

class _DataCollectionScreenState extends State<DataCollectionScreen> {
  bool _crashReports = true;
  bool _usageStats = true;
  bool _threatIntel = true;
  bool _performanceData = false;
  bool _diagnostics = false;

  @override
  void initState() {
    super.initState();
    _loadSettings();
  }

  Future<void> _loadSettings() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _crashReports = prefs.getBool('data_crashReports') ?? true;
      _usageStats = prefs.getBool('data_usageStats') ?? true;
      _threatIntel = prefs.getBool('data_threatIntel') ?? true;
      _performanceData = prefs.getBool('data_performanceData') ?? false;
      _diagnostics = prefs.getBool('data_diagnostics') ?? false;
    });
  }

  Future<void> _saveSettings() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('data_crashReports', _crashReports);
    await prefs.setBool('data_usageStats', _usageStats);
    await prefs.setBool('data_threatIntel', _threatIntel);
    await prefs.setBool('data_performanceData', _performanceData);
    await prefs.setBool('data_diagnostics', _diagnostics);

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('✅ Data collection settings saved'),
        backgroundColor: Colors.green,
      ),
    );
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
          'Data Collection',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(16),
        children: [
          // Info Card
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Color(0xFF151933),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Color(0xFF6C63FF).withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.privacy_tip, color: Color(0xFF6C63FF), size: 24),
                    SizedBox(width: 12),
                    Text(
                      'Your Privacy Matters',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                SizedBox(height: 12),
                Text(
                  'We collect minimal data to improve AdRig and provide better protection. All data is anonymized and encrypted.',
                  style: TextStyle(color: Colors.white70, fontSize: 13),
                ),
              ],
            ),
          ),

          SizedBox(height: 24),

          // Essential Data Collection
          Text(
            'ESSENTIAL',
            style: TextStyle(
              color: Color(0xFF6C63FF),
              fontSize: 14,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
            ),
          ),
          SizedBox(height: 12),

          _buildSwitchTile(
            title: 'Crash Reports',
            subtitle: 'Help us fix bugs and crashes',
            icon: Icons.bug_report_outlined,
            value: _crashReports,
            onChanged: (value) {
              setState(() => _crashReports = value);
              _saveSettings();
            },
          ),

          _buildSwitchTile(
            title: 'Threat Intelligence',
            subtitle: 'Share detected threats (anonymous)',
            icon: Icons.security_outlined,
            value: _threatIntel,
            onChanged: (value) {
              setState(() => _threatIntel = value);
              _saveSettings();
            },
          ),

          SizedBox(height: 24),

          // Optional Data Collection
          Text(
            'OPTIONAL',
            style: TextStyle(
              color: Color(0xFF6C63FF),
              fontSize: 14,
              fontWeight: FontWeight.bold,
              letterSpacing: 1.2,
            ),
          ),
          SizedBox(height: 12),

          _buildSwitchTile(
            title: 'Usage Statistics',
            subtitle: 'App usage patterns and features used',
            icon: Icons.analytics_outlined,
            value: _usageStats,
            onChanged: (value) {
              setState(() => _usageStats = value);
              _saveSettings();
            },
          ),

          _buildSwitchTile(
            title: 'Performance Data',
            subtitle: 'Scan speed, memory usage, battery impact',
            icon: Icons.speed_outlined,
            value: _performanceData,
            onChanged: (value) {
              setState(() => _performanceData = value);
              _saveSettings();
            },
          ),

          _buildSwitchTile(
            title: 'Diagnostics',
            subtitle: 'Detailed system information for debugging',
            icon: Icons.medical_services_outlined,
            value: _diagnostics,
            onChanged: (value) {
              setState(() => _diagnostics = value);
              _saveSettings();
            },
          ),

          SizedBox(height: 24),

          // What We DON'T Collect
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Color(0xFF151933),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.green.withOpacity(0.3)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Icon(Icons.lock_outline, color: Colors.green, size: 24),
                    SizedBox(width: 12),
                    Text(
                      'We NEVER Collect',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                SizedBox(height: 12),
                _buildDontCollectItem('Personal messages or contacts'),
                _buildDontCollectItem('Photos or media files'),
                _buildDontCollectItem('Passwords or credentials'),
                _buildDontCollectItem('Location data'),
                _buildDontCollectItem('Browsing history'),
                _buildDontCollectItem('Financial information'),
              ],
            ),
          ),

          SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildSwitchTile({
    required String title,
    required String subtitle,
    required IconData icon,
    required bool value,
    required ValueChanged<bool> onChanged,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10),
      ),
      child: SwitchListTile(
        secondary: Icon(icon, color: Color(0xFF6C63FF)),
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.w500),
        ),
        subtitle: Text(
          subtitle,
          style: TextStyle(color: Colors.white60, fontSize: 12),
        ),
        value: value,
        onChanged: onChanged,
        activeColor: Color(0xFF6C63FF),
      ),
    );
  }

  Widget _buildDontCollectItem(String text) {
    return Padding(
      padding: EdgeInsets.only(bottom: 8),
      child: Row(
        children: [
          Icon(Icons.block, color: Colors.green, size: 16),
          SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: TextStyle(color: Colors.white70, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}
