import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/scan_coordinator.dart';
import '../services/app_telemetry_collector.dart';
import '../core/models/threat_model.dart';
import 'scan_results_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({Key? key}) : super(key: key);

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with SingleTickerProviderStateMixin {
  bool _isInitializing = true;
  bool _isScanning = false;
  int _scannedApps = 0;
  int _totalApps = 0;
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: Duration(milliseconds: 1500),
    )..repeat(reverse: true);
    _initializeAsync();
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _initializeAsync() async {
    final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
    await coordinator.initializeAsync();
    
    if (mounted) {
      setState(() => _isInitializing = false);
    }
  }

  Future<void> _startScan() async {
    setState(() {
      _isScanning = true;
      _scannedApps = 0;
      _totalApps = 0;
    });

    try {
      final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
      final telemetryCollector = Provider.of<AppTelemetryCollector>(context, listen: false);
      
      final apps = await telemetryCollector.collectAllAppsTelemetry();
      setState(() => _totalApps = apps.length);

      final result = await coordinator.scanInstalledApps(apps);

      if (mounted) {
        setState(() => _isScanning = false);
        
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
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Scan failed: $e')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isInitializing) {
      return Scaffold(
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              CircularProgressIndicator(
                valueColor: AlwaysStoppedAnimation(Color(0xFF6C63FF)),
              ),
              SizedBox(height: 24),
              Text(
                'Initializing Scanner...',
                style: TextStyle(color: Colors.white70, fontSize: 16),
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      body: SafeArea(
        child: _isScanning ? _buildScanningView() : _buildIdleView(),
      ),
    );
  }

  Widget _buildIdleView() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Minimal branding
          Text(
            'ScanX',
            style: TextStyle(
              fontSize: 48,
              fontWeight: FontWeight.w300,
              color: Colors.white,
              letterSpacing: 4,
            ),
          ),
          SizedBox(height: 8),
          Text(
            'Production Malware Scanner',
            style: TextStyle(
              fontSize: 14,
              color: Colors.white38,
              letterSpacing: 1.5,
            ),
          ),
          
          SizedBox(height: 120),
          
          // Main scan button
          GestureDetector(
            onTap: _startScan,
            child: Container(
              width: 200,
              height: 200,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: LinearGradient(
                  colors: [Color(0xFF6C63FF), Color(0xFF00D9FF)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                boxShadow: [
                  BoxShadow(
                    color: Color(0xFF6C63FF).withOpacity(0.5),
                    blurRadius: 40,
                    spreadRadius: 5,
                  ),
                ],
              ),
              child: Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.shield_outlined, size: 80, color: Colors.white),
                    SizedBox(height: 12),
                    Text(
                      'SCAN',
                      style: TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                        letterSpacing: 3,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          
          SizedBox(height: 80),
          
          // Detection engines - minimal
          Text(
            'Detection Engines',
            style: TextStyle(
              fontSize: 12,
              color: Colors.white24,
              letterSpacing: 2,
            ),
          ),
          SizedBox(height: 16),
          Wrap(
            spacing: 12,
            children: [
              _buildEngineChip('APK Analysis'),
              _buildEngineChip('Signature DB'),
              _buildEngineChip('Cloud Intel'),
              _buildEngineChip('Behavioral'),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildEngineChip(String label) {
    return Container(
      padding: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: Color(0xFF6C63FF).withOpacity(0.3)),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 10,
          color: Color(0xFF6C63FF),
          fontWeight: FontWeight.w500,
        ),
      ),
    );
  }

  Widget _buildScanningView() {
    final progress = _totalApps > 0 ? _scannedApps / _totalApps : 0.0;
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Animated scanner
          AnimatedBuilder(
            animation: _pulseController,
            builder: (context, child) {
              return Container(
                width: 250,
                height: 250,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: RadialGradient(
                    colors: [
                      Color(0xFF6C63FF).withOpacity(0.3 * _pulseController.value),
                      Colors.transparent,
                    ],
                  ),
                ),
                child: Center(
                  child: Container(
                    width: 180,
                    height: 180,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: Color(0xFF151933),
                      border: Border.all(
                        color: Color(0xFF6C63FF),
                        width: 3,
                      ),
                    ),
                    child: Stack(
                      alignment: Alignment.center,
                      children: [
                        SizedBox(
                          width: 160,
                          height: 160,
                          child: CircularProgressIndicator(
                            value: progress,
                            strokeWidth: 4,
                            valueColor: AlwaysStoppedAnimation(Color(0xFF00D9FF)),
                            backgroundColor: Color(0xFF6C63FF).withOpacity(0.2),
                          ),
                        ),
                        Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.security,
                              size: 50,
                              color: Color(0xFF6C63FF),
                            ),
                            SizedBox(height: 12),
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
                      ],
                    ),
                  ),
                ),
              );
            },
          ),
          
          SizedBox(height: 40),
          
          Text(
            'Scanning Device',
            style: TextStyle(
              fontSize: 20,
              color: Colors.white,
              fontWeight: FontWeight.w300,
            ),
          ),
          SizedBox(height: 12),
          Text(
            '$_scannedApps / $_totalApps apps',
            style: TextStyle(
              fontSize: 14,
              color: Colors.white38,
            ),
          ),
          
          SizedBox(height: 40),
          
          // Active engines
          Container(
            padding: EdgeInsets.symmetric(horizontal: 24, vertical: 16),
            decoration: BoxDecoration(
              color: Color(0xFF151933),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Column(
              children: [
                _buildScanStep('APK Analysis', true),
                _buildScanStep('YARA Pattern Matching', progress > 0.2),
                _buildScanStep('Signature Database', progress > 0.4),
                _buildScanStep('Cloud Reputation', progress > 0.6),
                _buildScanStep('Risk Assessment', progress > 0.8),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanStep(String label, bool active) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: active ? Color(0xFF00D9FF) : Colors.white10,
            ),
          ),
          SizedBox(width: 12),
          Text(
            label,
            style: TextStyle(
              fontSize: 12,
              color: active ? Colors.white : Colors.white24,
            ),
          ),
        ],
      ),
    );
  }
}
