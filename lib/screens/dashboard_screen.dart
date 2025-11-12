import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'package:provider/provider.dart';
import '../services/scan_coordinator.dart';
import '../services/app_telemetry_collector.dart';
import '../services/auth_service.dart';
import '../services/permission_service.dart';
import '../services/realtime_network_security_service.dart';
import '../widgets/adrig_logo.dart';
import 'scan_results_screen.dart';
import 'settings_screen.dart';
import 'profile_screen.dart';
import 'help_support_screen.dart';
import 'about_screen.dart';
import 'threat_list_screen.dart';
import 'dart:math' as math;

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({Key? key}) : super(key: key);

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> with TickerProviderStateMixin {
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();
  bool _isScanning = false;
  bool _cancelScan = false;
  int _scannedApps = 0;
  int _totalApps = 0;
  String _currentApp = '';
  String _userName = 'Loading...';
  String _userEmail = '';
  String _subscriptionType = 'Free';
  bool _dataLoaded = false; // Track if data is already loaded
  bool _isProcessing = false; // Prevent double-tap
  DateTime? _lastTapTime; // Track last button tap
  
  late AnimationController _pulseController;
  late AnimationController _rotateController;

  // Real threat data - will be loaded from scan history (cached)
  Map<String, int> _last90DaysThreats = {
    'Apps': 0,
    'Wi-Fi Networks': 0,
    'Internet': 0,
    'Devices': 0,
    'Files': 0,
    'AI Detected': 0,
  };

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      duration: Duration(milliseconds: 2000),
      vsync: this,
    )..repeat(reverse: true);
    
    _rotateController = AnimationController(
      duration: Duration(milliseconds: 3000),
      vsync: this,
    );
    
    // Start real-time network security monitoring
    _initializeNetworkSecurity();
    
    // Load data only once, not on every rebuild
    if (!_dataLoaded) {
      _dataLoaded = true;
      // Load real threat data from history
      _loadThreatHistory();
      _loadUserInfo();
    }
  }
  
  /// Initialize always-on network security
  Future<void> _initializeNetworkSecurity() async {
    try {
      final networkSecurity = RealTimeNetworkSecurityService();
      await networkSecurity.initialize();
      print('✅ Real-Time Network Security activated from Dashboard');
    } catch (e) {
      print('⚠️ Failed to start network security: $e');
    }
  }
  
  Future<void> _loadThreatHistory() async {
    print('📊 Dashboard: Loading threat history...');
    try {
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final historyService = coordinator.getHistoryService();
      final threatCounts = await historyService.getLast90DaysThreats();
      
      print('   Threat counts: $threatCounts');
      
      if (mounted) {
        setState(() {
          _last90DaysThreats = threatCounts;
        });
        print('✅ Dashboard updated with new counts');
      }
    } catch (e) {
      print('Error loading threat history: $e');
    }
  }
  
  Future<void> _loadUserInfo() async {
    try {
      final authService = AuthService();
      final name = await authService.getUserName();
      final email = await authService.getUserEmail();
      final subType = await authService.getSubscriptionType();
      
      if (mounted) {
        setState(() {
          _userName = name ?? 'User';
          _userEmail = email ?? '';
          _subscriptionType = subType == SubscriptionType.free ? 'Free Account' : 
                             subType == SubscriptionType.premium ? 'Premium Account' : 'Pro Account';
        });
      }
    } catch (e) {
      print('Error loading user info: $e');
    }
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _rotateController.dispose();
    super.dispose();
  }

  /// Safely stop rotation animation
  void _stopRotation() {
    try {
      if (!mounted) return;
      if (_rotateController.isAnimating) {
        _rotateController.stop();
        _rotateController.reset();
      }
    } catch (e) {
      print('⚠️ Error stopping rotation animation: $e');
    }
  }

  Future<void> _performScan() async {
    print('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    print('� Dashboard: _performScan() called');
    print('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    
    // Check permissions first!
    final permissionService = Provider.of<PermissionService>(context, listen: false);
    final hasPermissions = await permissionService.hasAllCriticalPermissions();
    
    if (!hasPermissions) {
      // Request permissions directly
      print('🔵 Requesting permissions...');
      final granted = await permissionService.requestAllPermissions();
      
      if (!granted) {
        // Permissions denied - offer to open settings
        if (mounted) {
          final shouldOpenSettings = await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              backgroundColor: const Color(0xFF151933),
              title: const Text('Permissions Required', style: TextStyle(color: Colors.white)),
              content: const Text(
                'AdRig needs storage access to scan your device.\n\nFor Android 11+, please grant "All files access" in Settings:\n1. Tap "Open Settings"\n2. Find "AdRig Security"\n3. Select "Files and media"\n4. Choose "Allow management of all files"\n\nAfter granting, tap "Scan Now" again.',
                style: TextStyle(color: Colors.white70),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: const Text('Cancel'),
                ),
                ElevatedButton(
                  onPressed: () => Navigator.of(context).pop(true),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF6C63FF),
                  ),
                  child: const Text('Open Settings'),
                ),
              ],
            ),
          );
          
          if (shouldOpenSettings == true) {
            await permissionService.openSettings();
            // Show message to user
            if (mounted) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('✅ After granting permissions, return here and tap "Scan Now" again'),
                  backgroundColor: Colors.blue,
                  duration: Duration(seconds: 4),
                ),
              );
            }
          }
        }
        _isProcessing = false;
        return;
      } else {
        // Permissions granted! Show success message
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('✅ Permissions granted! Starting scan...'),
              backgroundColor: Colors.green,
              duration: Duration(seconds: 2),
            ),
          );
        }
        // Continue with scan below
      }
    }
    
    // Show immediate feedback
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('🔍 Starting scan...'),
          backgroundColor: Colors.blue,
          duration: Duration(seconds: 2),
        ),
      );
    }
    
    if (!mounted) return;
    
    setState(() {
      _isScanning = true;
      _cancelScan = false;
      _scannedApps = 0;
      _totalApps = 0;
      _currentApp = '';
    });
    
    _rotateController.repeat();

    try {
      print('Step 1: Getting providers...');
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final telemetryCollector = Provider.of<AppTelemetryCollector>(context, listen: false);
      print('✅ Step 1 complete: Providers obtained');
      
      print('Step 2: Calling collectAllAppsTelemetry()...');
      
      // TEST: Try direct platform call first
      try {
        print('🧪 TEST: Direct platform channel call...');
        const platform = MethodChannel('com.adrig.security/telemetry');
        final List<dynamic> directResult = await platform
            .invokeMethod('getInstalledApps')
            .timeout(Duration(seconds: 10));
        print('🧪 DIRECT CALL SUCCESS: Got ${directResult.length} apps');
        
        if (directResult.isEmpty) {
          print('⚠️  DIRECT CALL returned EMPTY LIST');
        } else {
          print('✅ Sample app: ${directResult.first}');
        }
      } catch (e) {
        print('❌ DIRECT CALL FAILED: $e');
      }
      
      // Check if scan was cancelled
      if (_cancelScan) {
        print('⚠️ Scan cancelled by user');
        if (mounted) {
          setState(() => _isScanning = false);
          _stopRotation();
        }
        return;
      }
      
      print('Step 3: Calling via telemetryCollector...');
      final apps = await telemetryCollector.collectAllAppsTelemetry()
          .timeout(Duration(seconds: 15));
      print('✅ Step 3 complete: Got ${apps.length} apps from telemetry');
      
      if (apps.isEmpty) {
        print('⚠️  NO APPS FOUND - Showing error to user');
        if (mounted) {
          setState(() => _isScanning = false);
          _stopRotation();
          
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('❌ No apps found!\n\nThis could mean:\n- Permission issue\n- Native code error\n\nCheck adb logcat for details.'),
              backgroundColor: Color(0xFFFF6B6B),
              duration: Duration(seconds: 8),
            ),
          );
        }
        return;
      }
      
      // Check if scan was cancelled
      if (_cancelScan) {
        print('⚠️ Scan cancelled by user');
        if (mounted) {
          setState(() => _isScanning = false);
          _stopRotation();
        }
        return;
      }
      
      print('Step 4: Starting scan of ${apps.length} apps...');

      final result = await coordinator.scanInstalledApps(
        apps,
        onProgress: (scanned, total, appName) {
          // Check for cancellation during scan
          if (_cancelScan || !mounted) {
            print('⚠️ Scan cancelled at $scanned/$total apps');
            return;
          }
          
          if (mounted) {
            try {
              setState(() {
                _scannedApps = scanned;
                _totalApps = total;
                _currentApp = appName;
              });
            } catch (e) {
              print('⚠️ Error updating progress: $e');
            }
          }
        },
      );

      // Check if scan was cancelled
      if (_cancelScan || !mounted) {
        print('⚠️ Scan cancelled - not showing results');
        _isProcessing = false;
        if (mounted) {
          setState(() => _isScanning = false);
          _stopRotation();
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('🛑 Scan cancelled'),
              backgroundColor: Color(0xFFFF9800),
              duration: Duration(seconds: 2),
            ),
          );
        }
        return;
      }

      print('✅ Scan complete!');

      if (mounted) {
        setState(() => _isScanning = false);
        _stopRotation();
        
        await _loadThreatHistory();
        
        if (mounted) {
          Navigator.push(
            context,
            MaterialPageRoute(
              builder: (_) => ScanResultsScreen(result: result),
            ),
          );
        }
      }
    } on TimeoutException catch (e) {
      print('❌ TIMEOUT: $e');
      if (mounted) {
        setState(() => _isScanning = false);
        _stopRotation();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('⏱️ Scan timed out!\n\nThe app is taking too long to respond. Check adb logcat.'),
            backgroundColor: Color(0xFFFF9800),
            duration: Duration(seconds: 8),
          ),
        );
      }
      _isProcessing = false;
    } catch (e, stackTrace) {
      print('❌ Dashboard: Scan failed with error: $e');
      print('Stack trace: $stackTrace');
      
      if (mounted) {
        setState(() => _isScanning = false);
        _stopRotation();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('❌ Scan failed: $e\n\nCheck logs for details.'),
            backgroundColor: Color(0xFFD32F2F),
            duration: Duration(seconds: 8),
          ),
        );
      }
      _isProcessing = false;
    } finally {
      _isProcessing = false;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: _scaffoldKey,
      backgroundColor: Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: Color(0xFF0A0E27),
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.menu, color: Colors.white),
          onPressed: () => _scaffoldKey.currentState?.openDrawer(),
        ),
        title: Row(
          children: [
            // AdRig Logo in header
            AdRigLogo(size: 35, showText: false),
            SizedBox(width: 12),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  'AdRig',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Text(
                  'Advanced Detection & Response',
                  style: TextStyle(
                    fontSize: 10,
                    color: Colors.white60,
                  ),
                ),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: Icon(Icons.notifications_outlined, color: Colors.white70),
            onPressed: () {
              _showNotificationsDialog();
            },
          ),
        ],
      ),
      drawer: _buildSidePanel(),
      body: _isScanning ? _buildScanningView() : _buildDashboardView(),
    );
  }

  Widget _buildSidePanel() {
    return Drawer(
      backgroundColor: Color(0xFF151933),
      child: ListView(
        padding: EdgeInsets.zero,
        children: [
          Container(
            height: 200,
            padding: EdgeInsets.fromLTRB(16, 40, 16, 16),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFF000428), Color(0xFF004e92)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.center,
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                // AdRig Logo
                AdRigLogo(size: 70, showText: false),
                SizedBox(height: 8),
                Text(
                  'AI THREAT INTELLIGENCE',
                  style: TextStyle(
                    color: Color(0xFF00D9FF),
                    fontSize: 9,
                    letterSpacing: 1.5,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 12),
                // User name with proper overflow handling
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8.0),
                  child: Text(
                    _userName,
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 15,
                      fontWeight: FontWeight.bold,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    textAlign: TextAlign.center,
                  ),
                ),
                SizedBox(height: 4),
                // Subscription type with overflow handling
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8.0),
                  child: Text(
                    _subscriptionType,
                    style: TextStyle(
                      color: Colors.white70,
                      fontSize: 11,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    textAlign: TextAlign.center,
                  ),
                ),
              ],
            ),
          ),
          
          // Settings Section
          _buildDrawerItem(
            icon: Icons.settings_outlined,
            title: 'Settings',
            onTap: () {
              Navigator.pop(context);
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => SettingsScreen()),
              );
            },
          ),
          
          // User Profile Section
          _buildDrawerItem(
            icon: Icons.person_outline,
            title: 'User Profile',
            onTap: () {
              Navigator.pop(context);
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => ProfileScreen()),
              );
            },
          ),
          
          // Help & Support
          _buildDrawerItem(
            icon: Icons.help_outline,
            title: 'Help & Support',
            onTap: () {
              Navigator.pop(context);
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => HelpSupportScreen()),
              );
            },
          ),
          
          // About
          _buildDrawerItem(
            icon: Icons.info_outline,
            title: 'About',
            onTap: () {
              Navigator.pop(context);
              Navigator.push(
                context,
                MaterialPageRoute(builder: (_) => AboutScreen()),
              );
            },
          ),
          
          Divider(color: Colors.white12, height: 1),
          
          // Send Feedback
          _buildDrawerItem(
            icon: Icons.feedback_outlined,
            title: 'Send Feedback',
            onTap: () {
              Navigator.pop(context);
              _showFeedbackDialog();
            },
          ),
          
          SizedBox(height: 20),
          
          // App Version
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Version 1.0.0',
              style: TextStyle(
                color: Colors.white30,
                fontSize: 12,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDrawerItem({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
  }) {
    return ListTile(
      leading: Icon(icon, color: Colors.white70),
      title: Text(
        title,
        style: TextStyle(color: Colors.white, fontSize: 15),
      ),
      onTap: onTap,
      hoverColor: Colors.white10,
    );
  }

  Widget _buildDashboardView() {
    final totalThreats = _last90DaysThreats.values.fold(0, (sum, count) => sum + count);
    
    return SingleChildScrollView(
      child: Padding(
        padding: EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Scan Button
            Center(
              child: AnimatedBuilder(
                animation: _pulseController,
                builder: (context, child) {
                  return Container(
                    width: 240,
                    height: 240,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: Color(0xFF6C63FF).withOpacity(0.5),
                          blurRadius: 40,
                          spreadRadius: 10,
                        ),
                      ],
                      gradient: RadialGradient(
                        colors: [
                          Color(0xFF6C63FF).withOpacity(0.4),
                          Color(0xFF00D9FF).withOpacity(0.2),
                          Colors.transparent,
                        ],
                        stops: [
                          0.3 + (_pulseController.value * 0.2),
                          0.6 + (_pulseController.value * 0.2),
                          1.0,
                        ],
                      ),
                    ),
                    child: Center(
                      child: Container(
                        width: 200,
                        height: 200,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: LinearGradient(
                            begin: Alignment.topLeft,
                            end: Alignment.bottomRight,
                            colors: [
                              Color(0xFF7C6DFF),
                              Color(0xFF6C63FF),
                              Color(0xFF5B52E8),
                            ],
                          ),
                          boxShadow: [
                            BoxShadow(
                              color: Color(0xFF6C63FF).withOpacity(0.6),
                              blurRadius: 30,
                              offset: Offset(0, 10),
                            ),
                          ],
                        ),
                        child: Material(
                          color: Colors.transparent,
                          child: InkWell(
                            onTap: () {
                              // Prevent double-tap
                              final now = DateTime.now();
                              if (_lastTapTime != null && 
                                  now.difference(_lastTapTime!) < Duration(seconds: 2)) {
                                print('⚠️ Ignoring double-tap');
                                return;
                              }
                              _lastTapTime = now;
                              
                              // Prevent multiple simultaneous scans
                              if (_isProcessing || _isScanning) {
                                print('⚠️ Scan already in progress');
                                return;
                              }
                              
                              _performScan();
                            },
                            borderRadius: BorderRadius.circular(100),
                            splashColor: Colors.white.withOpacity(0.3),
                            child: Container(
                              decoration: BoxDecoration(
                                shape: BoxShape.circle,
                                border: Border.all(
                                  color: Colors.white.withOpacity(0.3),
                                  width: 2,
                                ),
                              ),
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Container(
                                    padding: EdgeInsets.all(12),
                                    decoration: BoxDecoration(
                                      shape: BoxShape.circle,
                                      color: Colors.white.withOpacity(0.2),
                                    ),
                                    child: Icon(
                                      Icons.play_arrow_rounded,
                                      size: 50,
                                      color: Colors.white,
                                    ),
                                  ),
                                  SizedBox(height: 12),
                                  Text(
                                    'SCAN NOW',
                                    style: TextStyle(
                                      fontSize: 18,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.white,
                                      letterSpacing: 2,
                                    ),
                                  ),
                                  SizedBox(height: 4),
                                  Text(
                                    'AI-Powered Protection',
                                    style: TextStyle(
                                      fontSize: 10,
                                      color: Colors.white70,
                                      letterSpacing: 1,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  );
                },
              ),
            ),
            
            SizedBox(height: 40),
            
            // 90 Days Threat Report Header
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  'Last 90 Days',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Container(
                  padding: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: totalThreats > 0 ? Color(0xFFFF4757) : Color(0xFF00C853),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(
                    '$totalThreats Threats',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ),
              ],
            ),
            
            SizedBox(height: 16),
            
            // Threat Categories
            ..._last90DaysThreats.entries.map((entry) {
              return _buildThreatCategoryCard(
                category: entry.key,
                count: entry.value,
                icon: _getCategoryIcon(entry.key),
              );
            }).toList(),
            
            SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildThreatCategoryCard({
    required String category,
    required int count,
    required IconData icon,
  }) {
    return InkWell(
      onTap: () async {
        print('📱 Dashboard: User tapped category: $category');
        
        // Navigate and wait for result
        await Navigator.push(
          context,
          MaterialPageRoute(
            builder: (context) => ThreatListScreen(category: category),
          ),
        );
        
        print('⬅️ Dashboard: Returned from threat list, reloading counts...');
        
        // Reload threat counts when returning
        _loadThreatHistory();
      },
      borderRadius: BorderRadius.circular(12),
      child: Container(
        margin: EdgeInsets.only(bottom: 12),
        padding: EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Color(0xFF151933),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: count > 0 ? Color(0xFFFF4757).withOpacity(0.3) : Colors.white10,
            width: 1,
          ),
        ),
        child: Row(
          children: [
            Container(
              width: 48,
              height: 48,
              decoration: BoxDecoration(
                color: count > 0 
                    ? Color(0xFFFF4757).withOpacity(0.2) 
                    : Color(0xFF00C853).withOpacity(0.2),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Icon(
                icon,
                color: count > 0 ? Color(0xFFFF4757) : Color(0xFF00C853),
                size: 24,
              ),
            ),
            SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    category,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    count == 0 ? 'No threats detected' : '$count threat${count > 1 ? 's' : ''} blocked',
                    style: TextStyle(
                      fontSize: 12,
                      color: Colors.white60,
                    ),
                  ),
                ],
              ),
            ),
            Container(
              padding: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: count > 0 ? Color(0xFFFF4757) : Color(0xFF00C853).withOpacity(0.2),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                count.toString(),
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  IconData _getCategoryIcon(String category) {
    switch (category) {
      case 'Apps':
        return Icons.apps;
      case 'Wi-Fi Networks':
        return Icons.wifi;
      case 'Internet':
        return Icons.language;
      case 'Devices':
        return Icons.devices;
      case 'Files':
        return Icons.folder;
      case 'AI Detected':
        return Icons.psychology;
      default:
        return Icons.security;
    }
  }

  Widget _buildScanningView() {
    final progress = _totalApps > 0 ? _scannedApps / _totalApps : 0.0;
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          AnimatedBuilder(
            animation: _rotateController,
            builder: (context, child) {
              return Transform.rotate(
                angle: _rotateController.value * 2 * math.pi,
                child: Container(
                  width: 120,
                  height: 120,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: SweepGradient(
                      colors: [
                        Color(0xFF6C63FF),
                        Color(0xFF00D9FF),
                        Color(0xFF6C63FF),
                      ],
                      stops: [0.0, 0.5, 1.0],
                    ),
                  ),
                  child: Padding(
                    padding: EdgeInsets.all(4),
                    child: Container(
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: Color(0xFF0A0E27),
                      ),
                      child: Center(
                        child: Icon(
                          Icons.shield,
                          size: 50,
                          color: Color(0xFF6C63FF),
                        ),
                      ),
                    ),
                  ),
                ),
              );
            },
          ),
          
          SizedBox(height: 40),
          
          Text(
            'Scanning...',
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          
          SizedBox(height: 20),
          
          Container(
            width: 300,
            height: 8,
            decoration: BoxDecoration(
              color: Colors.white10,
              borderRadius: BorderRadius.circular(4),
            ),
            child: FractionallySizedBox(
              alignment: Alignment.centerLeft,
              widthFactor: progress,
              child: Container(
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Color(0xFF6C63FF), Color(0xFF00D9FF)],
                  ),
                  borderRadius: BorderRadius.circular(4),
                ),
              ),
            ),
          ),
          
          SizedBox(height: 16),
          
          Text(
            '$_scannedApps / $_totalApps apps',
            style: TextStyle(
              fontSize: 16,
              color: Colors.white70,
            ),
          ),
          
          SizedBox(height: 8),
          
          Text(
            _currentApp,
            style: TextStyle(
              fontSize: 14,
              color: Colors.white60,
            ),
            textAlign: TextAlign.center,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          
          SizedBox(height: 40),
          
          // Cancel/Stop Button
          ElevatedButton.icon(
            onPressed: _isScanning ? () {
              print('🛑 STOP BUTTON PRESSED - Cancelling scan...');
              
              // Request cancellation from coordinator FIRST
              try {
                final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
                coordinator.requestCancellation();
                print('✅ Cancellation requested from coordinator');
              } catch (e) {
                print('⚠️ Error requesting cancellation: $e');
              }
              
              // Then update UI state
              if (mounted) {
                setState(() {
                  _cancelScan = true;
                  _isScanning = false;
                });
                
                // Stop animation
                _stopRotation();
                
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('🛑 Scan stopped'),
                    backgroundColor: Color(0xFFFF9800),
                    duration: Duration(seconds: 1),
                  ),
                );
              }
            } : null,
            icon: Icon(Icons.stop_circle_outlined, color: Colors.white),
            label: Text(
              'Stop Scan',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
              padding: EdgeInsets.symmetric(horizontal: 32, vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ],
      ),
    );
  }

  void _showFeedbackDialog() {
    final TextEditingController feedbackController = TextEditingController();
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text(
          'Send Feedback',
          style: TextStyle(color: Colors.white),
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Help us improve AdRig by sharing your thoughts',
              style: TextStyle(color: Colors.white70, fontSize: 14),
            ),
            SizedBox(height: 16),
            TextField(
              controller: feedbackController,
              maxLines: 4,
              style: TextStyle(color: Colors.white),
              decoration: InputDecoration(
                hintText: 'Your feedback...',
                hintStyle: TextStyle(color: Colors.white30),
                border: OutlineInputBorder(
                  borderSide: BorderSide(color: Colors.white30),
                ),
                enabledBorder: OutlineInputBorder(
                  borderSide: BorderSide(color: Colors.white30),
                ),
                focusedBorder: OutlineInputBorder(
                  borderSide: BorderSide(color: Color(0xFF6C63FF)),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              // TODO: Send feedback to server
              Navigator.pop(context);
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Thank you for your feedback!'),
                  backgroundColor: Color(0xFF00C853),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFF6C63FF),
            ),
            child: Text('SEND'),
          ),
        ],
      ),
    );
  }

  void _showNotificationsDialog() async {
    // Get recent scan results and threat counts
    final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
    final historyService = coordinator.getHistoryService();
    final totalThreats = await historyService.getTotalThreatsLast90Days();
    final scanHistory = await historyService.getAllScanResults();
    
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Row(
          children: [
            Icon(Icons.notifications, color: Color(0xFF6C63FF)),
            SizedBox(width: 12),
            Text('Notifications', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Container(
          width: double.maxFinite,
          constraints: BoxConstraints(maxHeight: 400),
          child: ListView(
            shrinkWrap: true,
            children: [
              if (totalThreats > 0)
                _buildNotificationItem(
                  icon: Icons.warning_amber_rounded,
                  color: Colors.red,
                  title: '$totalThreats Threats Detected',
                  subtitle: 'Review and take action immediately',
                  time: 'Last 90 days',
                ),
              if (scanHistory.isNotEmpty)
                _buildNotificationItem(
                  icon: Icons.check_circle,
                  color: Colors.green,
                  title: 'Scan Completed',
                  subtitle: '${scanHistory.first['totalApps']} apps scanned',
                  time: _formatTime(DateTime.fromMillisecondsSinceEpoch(
                    scanHistory.first['timestamp'] as int
                  )),
                ),
              _buildNotificationItem(
                icon: Icons.security,
                color: Color(0xFF6C63FF),
                title: 'Real-time Protection Active',
                subtitle: 'Your device is being monitored',
                time: 'Always on',
              ),
              _buildNotificationItem(
                icon: Icons.update,
                color: Colors.blue,
                title: 'Database Updated',
                subtitle: '30+ malware signatures loaded',
                time: '1 hour ago',
              ),
              if (totalThreats == 0 && scanHistory.isEmpty)
                Padding(
                  padding: EdgeInsets.all(32),
                  child: Column(
                    children: [
                      Icon(Icons.notifications_none, size: 64, color: Colors.white30),
                      SizedBox(height: 16),
                      Text(
                        'No notifications yet',
                        style: TextStyle(color: Colors.white60, fontSize: 16),
                      ),
                      SizedBox(height: 8),
                      Text(
                        'Start a scan to see activity',
                        style: TextStyle(color: Colors.white30, fontSize: 12),
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CLOSE', style: TextStyle(color: Color(0xFF6C63FF))),
          ),
        ],
      ),
    );
  }

  Widget _buildNotificationItem({
    required IconData icon,
    required Color color,
    required String title,
    required String subtitle,
    required String time,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      padding: EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Color(0xFF0A0E27),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(icon, color: color, size: 20),
          ),
          SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  subtitle,
                  style: TextStyle(color: Colors.white60, fontSize: 12),
                ),
                SizedBox(height: 4),
                Text(
                  time,
                  style: TextStyle(color: Colors.white30, fontSize: 10),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _formatTime(DateTime dateTime) {
    final now = DateTime.now();
    final difference = now.difference(dateTime);
    
    if (difference.inMinutes < 1) return 'Just now';
    if (difference.inMinutes < 60) return '${difference.inMinutes}m ago';
    if (difference.inHours < 24) return '${difference.inHours}h ago';
    if (difference.inDays < 7) return '${difference.inDays}d ago';
    return '${(difference.inDays / 7).floor()}w ago';
  }
}
