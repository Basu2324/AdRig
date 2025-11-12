import 'package:flutter/material.dart';
import '../services/app_whitelist_service.dart';
import '../services/app_telemetry_collector.dart';
import '../core/models/threat_model.dart';

/// Whitelist Management Screen - Manage apps excluded from scanning
/// REAL IMPLEMENTATION: Shows installed apps and allows user to select which to whitelist
class WhitelistManagementScreen extends StatefulWidget {
  const WhitelistManagementScreen({Key? key}) : super(key: key);

  @override
  State<WhitelistManagementScreen> createState() => _WhitelistManagementScreenState();
}

class _WhitelistManagementScreenState extends State<WhitelistManagementScreen> {
  List<String> _whitelistedApps = [];
  List<AppTelemetry> _installedApps = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadData();
  }

  Future<void> _loadData() async {
    setState(() => _isLoading = true);
    
    try {
      // Get installed apps
      final telemetry = AppTelemetryCollector();
      final apps = await telemetry.collectAllAppsTelemetry();
      
      // Get user whitelist
      final userWhitelist = AppWhitelistService.getUserWhitelist();
      
      if (mounted) {
        setState(() {
          _installedApps = apps;
          _whitelistedApps = userWhitelist.toList();
          _isLoading = false;
        });
      }
    } catch (e) {
      print('Error loading data: $e');
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _showAddDialog() async {
    // Filter out already whitelisted apps
    final availableApps = _installedApps
        .where((app) => !_whitelistedApps.contains(app.packageName))
        .toList();
    
    // Sort alphabetically
    availableApps.sort((a, b) => a.appName.compareTo(b.appName));
    
    if (availableApps.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('✅ All apps are already whitelisted!'),
          backgroundColor: Colors.orange,
        ),
      );
      return;
    }
    
    final selectedApp = await showDialog<AppTelemetry>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(
          'Select App to Whitelist',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        content: Container(
          width: double.maxFinite,
          height: 400,
          child: ListView.builder(
            itemCount: availableApps.length,
            itemBuilder: (context, index) {
              final app = availableApps[index];
              return Card(
                color: Color(0xFF1A1F3A),
                margin: EdgeInsets.symmetric(vertical: 4),
                child: ListTile(
                  leading: Container(
                    padding: EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: app.isSystemApp ? Colors.blue.withOpacity(0.2) : Colors.green.withOpacity(0.2),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Icon(
                      Icons.android,
                      color: app.isSystemApp ? Colors.blue : Colors.green,
                      size: 24,
                    ),
                  ),
                  title: Text(
                    app.appName,
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.w500),
                  ),
                  subtitle: Text(
                    app.packageName,
                    style: TextStyle(color: Colors.white60, fontSize: 11),
                  ),
                  trailing: Icon(Icons.add_circle, color: Color(0xFF6C63FF)),
                  onTap: () => Navigator.pop(context, app),
                ),
              );
            },
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('Cancel', style: TextStyle(color: Colors.white70)),
          ),
        ],
      ),
    );
    
    if (selectedApp != null) {
      _addToWhitelist(selectedApp.packageName, selectedApp.appName);
    }
  }

  Future<void> _addToWhitelist(String packageName, String appName) async {
    try {
      AppWhitelistService.addToWhitelist(packageName);
      
      if (mounted) {
        setState(() {
          _whitelistedApps.add(packageName);
        });
        
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('✅ Added "$appName" to whitelist'),
            backgroundColor: Colors.green,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('⚠️ Failed to add: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _removeFromWhitelist(String packageName) async {
    final appName = _installedApps
        .firstWhere((app) => app.packageName == packageName, orElse: () => AppTelemetry(
              packageName: packageName,
              appName: packageName,
              version: '',
              installer: null,
              signingCertFingerprint: '',
              manifest: AppManifestData(
                packageName: packageName,
                minSdkVersion: '0',
                targetSdkVersion: '0',
                activities: [],
                services: [],
                receivers: [],
                providers: [],
                usesPermissions: [],
                metadata: {},
              ),
              hashes: APKHash(md5: '', sha1: '', sha256: ''),
              declaredPermissions: [],
              runtimeGrantedPermissions: [],
              installedDate: DateTime.now(),
              lastUpdated: DateTime.now(),
              appSize: 0,
              apkPath: '',
              isSystemApp: false,
            ))
        .appName;
    
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(
          'Remove from Whitelist?',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        content: Text(
          'Remove "$appName" from whitelist?\n\nThis app will be scanned again.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('Cancel', style: TextStyle(color: Colors.white70)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('Remove'),
          ),
        ],
      ),
    );

    if (confirm == true) {
      try {
        AppWhitelistService.removeFromWhitelist(packageName);
        
        if (mounted) {
          setState(() {
            _whitelistedApps.remove(packageName);
          });
          
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('🗑️ Removed "$appName" from whitelist'),
              backgroundColor: Color(0xFFFF9800),
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('⚠️ Error: $e'),
              backgroundColor: Colors.red,
            ),
          );
        }
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
          'Whitelist Management',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
        actions: [
          IconButton(
            icon: Icon(Icons.refresh, color: Colors.white70),
            onPressed: _loadData,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showAddDialog,
        backgroundColor: Color(0xFF6C63FF),
        icon: Icon(Icons.add, color: Colors.white),
        label: Text('Add App', style: TextStyle(color: Colors.white)),
      ),
      body: _isLoading
          ? Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Color(0xFF6C63FF)),
                  SizedBox(height: 16),
                  Text(
                    'Loading installed apps...',
                    style: TextStyle(color: Colors.white70),
                  ),
                ],
              ),
            )
          : _whitelistedApps.isEmpty
              ? _buildEmptyState()
              : _buildWhitelistedApps(),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              padding: EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: Color(0xFF151933),
                borderRadius: BorderRadius.circular(100),
              ),
              child: Icon(
                Icons.verified_user,
                size: 80,
                color: Color(0xFF6C63FF),
              ),
            ),
            SizedBox(height: 24),
            Text(
              'No Whitelisted Apps',
              style: TextStyle(
                color: Colors.white,
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            SizedBox(height: 12),
            Text(
              'Whitelisted apps are excluded from scanning.\n\nTap the + button to add trusted apps.',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: Colors.white60,
                fontSize: 14,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildWhitelistedApps() {
    return Column(
      children: [
        // Info Banner
        Container(
          margin: EdgeInsets.all(16),
          padding: EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: Color(0xFF151933),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Color(0xFF6C63FF).withOpacity(0.3)),
          ),
          child: Row(
            children: [
              Icon(Icons.info_outline, color: Color(0xFF6C63FF), size: 20),
              SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Whitelisted apps are automatically excluded from scanning',
                  style: TextStyle(color: Colors.white70, fontSize: 13),
                ),
              ),
            ],
          ),
        ),
        
        // Stats
        Container(
          margin: EdgeInsets.symmetric(horizontal: 16),
          padding: EdgeInsets.all(16),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              colors: [Color(0xFF6C63FF), Color(0xFF4834DF)],
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
            ),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(Icons.shield_outlined, color: Colors.white, size: 24),
              SizedBox(width: 12),
              Text(
                '${_whitelistedApps.length} Trusted App${_whitelistedApps.length != 1 ? 's' : ''}',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ),
        ),
        
        SizedBox(height: 16),
        
        // Whitelisted Apps List
        Expanded(
          child: ListView.builder(
            padding: EdgeInsets.symmetric(horizontal: 16),
            itemCount: _whitelistedApps.length,
            itemBuilder: (context, index) {
              final packageName = _whitelistedApps[index];
              final app = _installedApps.firstWhere(
                (a) => a.packageName == packageName,
                orElse: () => AppTelemetry(
                  packageName: packageName,
                  appName: packageName,
                  version: '',
                  installer: null,
                  signingCertFingerprint: '',
                  manifest: AppManifestData(
                    packageName: packageName,
                    minSdkVersion: '0',
                    targetSdkVersion: '0',
                    activities: [],
                    services: [],
                    receivers: [],
                    providers: [],
                    usesPermissions: [],
                    metadata: {},
                  ),
                  hashes: APKHash(md5: '', sha1: '', sha256: ''),
                  declaredPermissions: [],
                  runtimeGrantedPermissions: [],
                  installedDate: DateTime.now(),
                  lastUpdated: DateTime.now(),
                  appSize: 0,
                  apkPath: '',
                  isSystemApp: false,
                ),
              );
              
              return Card(
                color: Color(0xFF151933),
                margin: EdgeInsets.only(bottom: 8),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                  side: BorderSide(color: Colors.white10),
                ),
                child: ListTile(
                  leading: Container(
                    padding: EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Colors.green.withOpacity(0.2),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      Icons.check_circle,
                      color: Colors.green,
                      size: 24,
                    ),
                  ),
                  title: Text(
                    app.appName,
                    style: TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  subtitle: Text(
                    packageName,
                    style: TextStyle(color: Colors.white60, fontSize: 12),
                  ),
                  trailing: IconButton(
                    icon: Icon(Icons.delete_outline, color: Color(0xFFFF4757)),
                    onPressed: () => _removeFromWhitelist(packageName),
                  ),
                  onLongPress: () => _removeFromWhitelist(packageName),
                ),
              );
            },
          ),
        ),
      ],
    );
  }
}
