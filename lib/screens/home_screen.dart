import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/scan_coordinator.dart';
import '../services/app_telemetry_collector.dart';
import 'scan_results_screen.dart';
import 'dart:math' as math;

class HomeScreen extends StatefulWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with TickerProviderStateMixin {
  bool _isScanning = false;
  bool _isInitializing = true;
  int _scannedApps = 0;
  int _totalApps = 0;
  String _currentApp = '';
  
  late AnimationController _pulseController;
  late AnimationController _rotateController;

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
    
    WidgetsBinding.instance.addPostFrameCallback((_) async {
      await Future.delayed(Duration(milliseconds: 500));
      setState(() => _isInitializing = false);
    });
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
      setState(() => _totalApps = apps.length);

      final result = await coordinator.scanInstalledApps(
        apps,
        onProgress: (scanned, total, appName) {
          if (mounted) {
            setState(() {
              _scannedApps = scanned;
              _currentApp = appName;
            });
          }
        },
      );

      if (mounted) {
        setState(() => _isScanning = false);
        _rotateController.stop();
        
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
    if (_isInitializing) {
      return Scaffold(
        backgroundColor: Color(0xFF0A0E27),
        body: Center(
          child: CircularProgressIndicator(
            valueColor: AlwaysStoppedAnimation(Color(0xFF6C63FF)),
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Color(0xFF0A0E27),
      body: SafeArea(
        child: _isScanning ? _buildScanningView() : _buildHomeView(),
      ),
    );
  }

  Widget _buildHomeView() {
    return SingleChildScrollView(
      child: Column(
        children: [
          SizedBox(height: 20),
          
          // App Header
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Row(
              children: [
                // Custom AdRig Logo
                Container(
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    boxShadow: [
                      BoxShadow(
                        color: Color(0xFF6C63FF).withOpacity(0.3),
                        blurRadius: 15,
                        offset: Offset(0, 4),
                      ),
                    ],
                  ),
                  child: CustomPaint(
                    size: Size(56, 56),
                    painter: AdRigLogoPainter(),
                  ),
                ),
                SizedBox(width: 16),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ShaderMask(
                      shaderCallback: (bounds) => LinearGradient(
                        colors: [Color(0xFF6C63FF), Color(0xFF00D9FF)],
                      ).createShader(bounds),
                      child: Text(
                        'AdRig',
                        style: TextStyle(
                          fontSize: 32,
                          fontWeight: FontWeight.w900,
                          color: Colors.white,
                          letterSpacing: 2,
                        ),
                      ),
                    ),
                    Text(
                      'Advanced Detection & Response',
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.white54,
                        letterSpacing: 0.8,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
          
          SizedBox(height: 40),
          
          // Main Scan Button
          GestureDetector(
            onTap: _startScan,
            child: AnimatedBuilder(
              animation: _pulseController,
              builder: (context, child) {
                return Container(
                  width: 260,
                  height: 260,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: RadialGradient(
                      colors: [
                        Color(0xFF6C63FF).withOpacity(0.4 * _pulseController.value),
                        Colors.transparent,
                      ],
                    ),
                  ),
                  child: Center(
                    child: Container(
                      width: 220,
                      height: 220,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: LinearGradient(
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                          colors: [
                            Color(0xFF6C63FF),
                            Color(0xFF00D9FF),
                          ],
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Color(0xFF6C63FF).withOpacity(0.5),
                            blurRadius: 30,
                            offset: Offset(0, 10),
                          ),
                        ],
                      ),
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.play_arrow_rounded,
                            size: 80,
                            color: Colors.white,
                          ),
                          SizedBox(height: 8),
                          Text(
                            'SCAN NOW',
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                              letterSpacing: 2,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ),
          
          SizedBox(height: 50),
          
          // Feature Cards
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              children: [
                _buildFeatureCard(
                  icon: Icons.bug_report,
                  title: 'YARA Pattern Detection',
                  description: '35 malware signatures including banking trojans, spyware & RATs',
                  color: Color(0xFFFF6B6B),
                ),
                SizedBox(height: 16),
                _buildFeatureCard(
                  icon: Icons.cloud_queue,
                  title: 'Cloud Reputation Check',
                  description: 'Real-time threat intelligence from VirusTotal & SafeBrowsing',
                  color: Color(0xFF00D9FF),
                ),
                SizedBox(height: 16),
                _buildFeatureCard(
                  icon: Icons.security,
                  title: 'Behavioral Analysis',
                  description: 'Monitor app permissions, network activity & file operations',
                  color: Color(0xFF6C63FF),
                ),
              ],
            ),
          ),
          
          SizedBox(height: 40),
        ],
      ),
    );
  }
  
  Widget _buildFeatureCard({
    required IconData icon,
    required String title,
    required String description,
    required Color color,
  }) {
    return Container(
      padding: EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFF1A1F3A),
            Color(0xFF151933),
          ],
        ),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: color.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: color.withOpacity(0.15),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Icon(icon, color: color, size: 28),
          ),
          SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                SizedBox(height: 6),
                Text(
                  description,
                  style: TextStyle(
                    fontSize: 13,
                    color: Colors.white54,
                    height: 1.4,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanningView() {
    final progress = _totalApps > 0 ? _scannedApps / _totalApps : 0.0;
    
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        // Animated Scanner - ONLY progress ring rotates
        Stack(
          alignment: Alignment.center,
          children: [
            // Static background
            Container(
              width: 240,
              height: 240,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: RadialGradient(
                  colors: [
                    Color(0xFF6C63FF).withOpacity(0.3),
                    Colors.transparent,
                  ],
                ),
              ),
            ),
            
            // Rotating progress ring ONLY
            AnimatedBuilder(
              animation: _rotateController,
              builder: (context, child) {
                return Transform.rotate(
                  angle: _rotateController.value * 2 * math.pi,
                  child: SizedBox(
                    width: 200,
                    height: 200,
                    child: CircularProgressIndicator(
                      value: progress,
                      strokeWidth: 8,
                      valueColor: AlwaysStoppedAnimation(Color(0xFF00D9FF)),
                      backgroundColor: Color(0xFF6C63FF).withOpacity(0.2),
                    ),
                  ),
                );
              },
            ),
            
            // Static center content (NOT rotating)
            Container(
              width: 160,
              height: 160,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    Color(0xFF151933),
                    Color(0xFF0A0E27),
                  ],
                ),
                border: Border.all(
                  color: Color(0xFF6C63FF).withOpacity(0.5),
                  width: 2,
                ),
              ),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(
                    Icons.security,
                    size: 60,
                    color: Color(0xFF6C63FF),
                  ),
                  SizedBox(height: 8),
                  Text(
                    '${(progress * 100).toInt()}%',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
        
        SizedBox(height: 40),
        
        Text(
          'Scanning your device...',
          style: TextStyle(
            fontSize: 22,
            fontWeight: FontWeight.bold,
            color: Colors.white,
          ),
        ),
        
        SizedBox(height: 12),
        
        Text(
          '$_scannedApps / $_totalApps apps analyzed',
          style: TextStyle(
            fontSize: 16,
            color: Colors.white54,
          ),
        ),
        
        // Current app being scanned
        if (_currentApp.isNotEmpty) ...[
          SizedBox(height: 8),
          Container(
            padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            margin: EdgeInsets.symmetric(horizontal: 40),
            decoration: BoxDecoration(
              color: Color(0xFF6C63FF).withOpacity(0.2),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: Color(0xFF6C63FF).withOpacity(0.5),
                width: 1,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                SizedBox(
                  width: 12,
                  height: 12,
                  child: CircularProgressIndicator(
                    strokeWidth: 2,
                    valueColor: AlwaysStoppedAnimation(Color(0xFF00D9FF)),
                  ),
                ),
                SizedBox(width: 10),
                Flexible(
                  child: Text(
                    _currentApp,
                    style: TextStyle(
                      fontSize: 13,
                      color: Color(0xFF00D9FF),
                      fontWeight: FontWeight.w500,
                    ),
                    overflow: TextOverflow.ellipsis,
                    maxLines: 1,
                  ),
                ),
              ],
            ),
          ),
        ],
        
        SizedBox(height: 50),
        
        // Active Engines
        Container(
          padding: EdgeInsets.symmetric(horizontal: 28, vertical: 20),
          margin: EdgeInsets.symmetric(horizontal: 24),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: [
                Color(0xFF1A1F3A),
                Color(0xFF151933),
              ],
            ),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: Color(0xFF6C63FF).withOpacity(0.3),
              width: 1,
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'ACTIVE ENGINES',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color: Colors.white38,
                  letterSpacing: 1.5,
                ),
              ),
              SizedBox(height: 16),
              _buildScanStep('Static APK Analysis', progress > 0.0, Icons.analytics),
              _buildScanStep('YARA Pattern Matching', progress > 0.2, Icons.bug_report),
              _buildScanStep('Signature Database', progress > 0.4, Icons.fingerprint),
              _buildScanStep('Cloud Reputation', progress > 0.6, Icons.cloud_queue),
              _buildScanStep('Risk Assessment', progress > 0.8, Icons.security),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildScanStep(String label, bool active, IconData icon) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 8),
      child: Row(
        children: [
          Container(
            padding: EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: active 
                ? Color(0xFF00D9FF).withOpacity(0.15) 
                : Colors.white.withOpacity(0.05),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              icon,
              size: 18,
              color: active ? Color(0xFF00D9FF) : Colors.white24,
            ),
          ),
          SizedBox(width: 14),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                fontSize: 14,
                color: active ? Colors.white : Colors.white24,
                fontWeight: active ? FontWeight.w600 : FontWeight.normal,
              ),
            ),
          ),
          if (active)
            Icon(Icons.check_circle, size: 18, color: Color(0xFF00D9FF)),
        ],
      ),
    );
  }
}

/// Custom AdRig Logo Painter - Modern shield with "AR" monogram
class AdRigLogoPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    // Gradient shield background
    final shieldPaint = Paint()
      ..style = PaintingStyle.fill
      ..shader = LinearGradient(
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
        colors: [Color(0xFF6C63FF), Color(0xFF00D9FF)],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));

    // Draw shield shape
    final path = Path();
    final centerX = size.width / 2;
    
    // Modern shield outline
    path.moveTo(centerX, size.height * 0.05);
    path.quadraticBezierTo(size.width * 0.85, size.height * 0.2, size.width * 0.95, size.height * 0.45);
    path.quadraticBezierTo(size.width * 0.88, size.height * 0.78, centerX, size.height * 0.95);
    path.quadraticBezierTo(size.width * 0.12, size.height * 0.78, size.width * 0.05, size.height * 0.45);
    path.quadraticBezierTo(size.width * 0.15, size.height * 0.2, centerX, size.height * 0.05);
    path.close();
    
    canvas.drawPath(path, shieldPaint);
    
    // Add inner glow/border effect
    final borderPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2
      ..color = Colors.white.withOpacity(0.3);
    canvas.drawPath(path, borderPaint);
    
    // Draw bold "AdRig" text or just "AR" for compact logo
    final textPainter = TextPainter(
      text: TextSpan(
        text: 'AR',
        style: TextStyle(
          color: Colors.white,
          fontSize: size.width * 0.4,
          fontWeight: FontWeight.w900,
          letterSpacing: -2,
          shadows: [
            Shadow(
              color: Colors.black.withOpacity(0.3),
              offset: Offset(0, 2),
              blurRadius: 4,
            ),
          ],
        ),
      ),
      textDirection: TextDirection.ltr,
    );
    
    textPainter.layout();
    textPainter.paint(
      canvas,
      Offset(
        centerX - textPainter.width / 2,
        size.height * 0.35 - textPainter.height / 2,
      ),
    );
    
    // Add small shield lock accent at bottom
    final lockPaint = Paint()
      ..color = Colors.white.withOpacity(0.4)
      ..style = PaintingStyle.fill;
    
    final lockBodyRect = Rect.fromCenter(
      center: Offset(centerX, size.height * 0.72),
      width: size.width * 0.18,
      height: size.height * 0.12,
    );
    
    canvas.drawRRect(
      RRect.fromRectAndRadius(lockBodyRect, Radius.circular(3)),
      lockPaint,
    );
    
    // Lock shackle (semi-circle on top)
    final shacklePaint = Paint()
      ..color = Colors.white.withOpacity(0.4)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2.5;
    
    final shacklePath = Path();
    shacklePath.addArc(
      Rect.fromCenter(
        center: Offset(centerX, size.height * 0.67),
        width: size.width * 0.13,
        height: size.height * 0.1,
      ),
      3.14,
      3.14,
    );
    canvas.drawPath(shacklePath, shacklePaint);
    
    // Small dot in lock
    final dotPaint = Paint()
      ..color = Colors.white.withOpacity(0.6)
      ..style = PaintingStyle.fill;
    canvas.drawCircle(
      Offset(centerX, size.height * 0.72),
      2,
      dotPaint,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
