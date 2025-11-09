import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/scan_coordinator.dart';
import '../services/app_telemetry_collector.dart';
import '../services/auth_service.dart';
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
  int _scannedApps = 0;
  int _totalApps = 0;
  String _currentApp = '';
  String _userName = 'Loading...';
  String _userEmail = '';
  String _subscriptionType = 'Free';
  
  late AnimationController _pulseController;
  late AnimationController _rotateController;

  // Real threat data - will be loaded from scan history
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
    
    // Load real threat data from history
    _loadThreatHistory();
    _loadUserInfo();
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

  Future<void> _startScan() async {
    setState(() {
      _isScanning = true;
      _scannedApps = 0;
      _totalApps = 0;
      _currentApp = '';
    });
    
    _rotateController.repeat();

    try {
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final telemetryCollector = Provider.of<AppTelemetryCollector>(context, listen: false);
      
      final apps = await telemetryCollector.collectAllAppsTelemetry();
      
      // Don't set _totalApps here - we'll get the actual scanned count from result
      // because whitelist filtering happens inside scanInstalledApps

      final result = await coordinator.scanInstalledApps(
        apps,
        onProgress: (scanned, total, appName) {
          if (mounted) {
            setState(() {
              _scannedApps = scanned;
              _totalApps = total;
              _currentApp = appName;
            });
          }
        },
      );

      if (mounted) {
        setState(() => _isScanning = false);
        _rotateController.stop();
        
        // Reload threat history to show updated counts
        await _loadThreatHistory();
        
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (_) => ScanResultsScreen(result: result),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isScanning = false);
        _rotateController.stop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Scan failed: $e'),
            backgroundColor: Color(0xFFD32F2F),
          ),
        );
      }
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
              // TODO: Navigate to notifications
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
                AdRigLogo(size: 80, showText: false),
                SizedBox(height: 8),
                Text(
                  'AI THREAT INTELLIGENCE',
                  style: TextStyle(
                    color: Color(0xFF00D9FF),
                    fontSize: 10,
                    letterSpacing: 2,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 12),
                Text(
                  _userName,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  _subscriptionType,
                  style: TextStyle(
                    color: Colors.white70,
                    fontSize: 11,
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
                            onTap: _startScan,
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
}
