import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'core/theme/scanx_colors.dart';
import 'services/scan_coordinator.dart';
import 'services/device_data_collector.dart';
import 'core/models/threat_model.dart';

void main() {
  runApp(const ScanXApp());
}

class ScanXApp extends StatelessWidget {
  const ScanXApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider(create: (_) => DeviceDataCollector()),
        Provider(create: (_) => ScanCoordinator()),
      ],
      child: MaterialApp(
        title: 'ScanX - Mobile Security',
        theme: ScanXTheme.darkTheme(),
        debugShowCheckedModeBanner: false,
        home: const ScanXHome(),
      ),
    );
  }
}

class ScanXHome extends StatefulWidget {
  const ScanXHome({Key? key}) : super(key: key);

  @override
  State<ScanXHome> createState() => _ScanXHomeState();
}

class _ScanXHomeState extends State<ScanXHome> {
  bool isScanning = false;
  ScanResult? lastScanResult;
  double scanProgress = 0;
  String currentStage = 'Initializing...';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: ScanXColors.background,
      appBar: AppBar(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              'ScanX',
              style: TextStyle(
                color: ScanXColors.accentOrange,
                fontSize: 24,
                fontWeight: FontWeight.bold,
              ),
            ),
            SizedBox(width: 8),
            Icon(Icons.security, color: ScanXColors.accentCyan, size: 24),
          ],
        ),
        backgroundColor: ScanXColors.surface,
        elevation: 0,
      ),
      body: isScanning
          ? _buildScanningScreen()
          : lastScanResult == null
              ? _buildInitialScreen()
              : _buildResultsScreen(),
      floatingActionButton: !isScanning
          ? FloatingActionButton(
              backgroundColor: ScanXColors.accentOrange,
              onPressed: _startScan,
              child: Icon(Icons.security_rounded, color: Colors.white),
            )
          : null,
    );
  }

  Widget _buildInitialScreen() {
    return SingleChildScrollView(
      child: Column(
        children: [
          SizedBox(height: 40),
          Container(
            width: 140,
            height: 140,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: ScanXColors.accentOrange, width: 2),
              gradient: LinearGradient(
                colors: [
                  ScanXColors.surface.withOpacity(0.5),
                  ScanXColors.surfaceLight,
                ],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
            ),
            child: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.shield, size: 60, color: ScanXColors.accentOrange),
                  SizedBox(height: 8),
                  Text(
                    'ScanX',
                    style: TextStyle(
                      color: ScanXColors.accentCyan,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ],
              ),
            ),
          ),
          SizedBox(height: 40),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              children: [
                Text(
                  'Mobile Security Scanner',
                  style: Theme.of(context).textTheme.displayMedium?.copyWith(
                        color: ScanXColors.textPrimary,
                      ),
                  textAlign: TextAlign.center,
                ),
                SizedBox(height: 16),
                Text(
                  'Comprehensive threat detection using multi-layer analysis. Scan your device for malware, spyware, and security vulnerabilities.',
                  style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                        color: ScanXColors.textSecondary,
                        height: 1.6,
                      ),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
          SizedBox(height: 40),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              children: [
                _buildFeature('🔍', 'Signature Detection', 'Hash-based malware database'),
                SizedBox(height: 16),
                _buildFeature('⚙️', 'Static Analysis', 'APK manifest & code inspection'),
                SizedBox(height: 16),
                _buildFeature('🔄', 'Behavioral Monitoring', 'Real-time threat detection'),
                SizedBox(height: 16),
                _buildFeature('🎯', 'Multi-Layer Engine', '4-stage threat detection pipeline'),
              ],
            ),
          ),
          SizedBox(height: 60),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: ElevatedButton(
              onPressed: _startScan,
              style: ElevatedButton.styleFrom(
                backgroundColor: ScanXColors.accentOrange,
                padding: EdgeInsets.symmetric(horizontal: 48, vertical: 16),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.security_rounded, size: 20),
                  SizedBox(width: 12),
                  Text(
                    'Start Security Scan',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            ),
          ),
          SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildFeature(String icon, String title, String description) {
    return Container(
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: ScanXColors.surfaceLight,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: ScanXColors.border, width: 1),
      ),
      child: Row(
        children: [
          Text(icon, style: TextStyle(fontSize: 32)),
          SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    color: ScanXColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  description,
                  style: TextStyle(
                    color: ScanXColors.textSecondary,
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanningScreen() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: ScanXColors.accentCyan, width: 3),
            ),
            child: Center(
              child: Icon(
                Icons.security_rounded,
                size: 60,
                color: ScanXColors.accentCyan,
              ),
            ),
          ),
          SizedBox(height: 40),
          Text(
            'Scanning Your Device',
            style: TextStyle(
              color: ScanXColors.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.bold,
            ),
          ),
          SizedBox(height: 24),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 40),
            child: Column(
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(10),
                  child: LinearProgressIndicator(
                    value: scanProgress,
                    minHeight: 8,
                    backgroundColor: ScanXColors.surfaceLight,
                    valueColor: AlwaysStoppedAnimation(ScanXColors.accentOrange),
                  ),
                ),
                SizedBox(height: 16),
                Text(
                  '\${(scanProgress * 100).toStringAsFixed(0)}%',
                  style: TextStyle(
                    color: ScanXColors.accentCyan,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),
          SizedBox(height: 32),
          Container(
            padding: EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            decoration: BoxDecoration(
              color: ScanXColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: ScanXColors.border),
            ),
            child: Text(
              currentStage,
              style: TextStyle(
                color: ScanXColors.textSecondary,
                fontSize: 14,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildResultsScreen() {
    if (lastScanResult == null) return SizedBox();

    final result = lastScanResult!;
    final threatCounts = {
      'Critical': result.threats.where((t) => t.severity == ThreatSeverity.critical).length,
      'High': result.threats.where((t) => t.severity == ThreatSeverity.high).length,
      'Medium': result.threats.where((t) => t.severity == ThreatSeverity.medium).length,
      'Low': result.threats.where((t) => t.severity == ThreatSeverity.low).length,
    };

    return SingleChildScrollView(
      child: Column(
        children: [
          SizedBox(height: 24),
          Container(
            margin: EdgeInsets.symmetric(horizontal: 24),
            padding: EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: ScanXColors.surface,
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: ScanXColors.accentCyan, width: 2),
            ),
            child: Column(
              children: [
                Icon(
                  result.threats.isEmpty ? Icons.check_circle : Icons.warning_rounded,
                  size: 64,
                  color: result.threats.isEmpty ? Color(0xFF4CAF50) : ScanXColors.threatHigh,
                ),
                SizedBox(height: 16),
                Text(
                  result.threats.isEmpty ? 'Device Secure' : 'Threats Detected',
                  style: TextStyle(
                    color: ScanXColors.textPrimary,
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  '\${result.threats.length} threat(s) found',
                  style: TextStyle(
                    color: ScanXColors.textSecondary,
                    fontSize: 16,
                  ),
                ),
              ],
            ),
          ),
          SizedBox(height: 24),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Threat Summary',
                  style: TextStyle(
                    color: ScanXColors.textPrimary,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 16),
                _buildThreatCount('🔴 Critical', threatCounts['Critical']!, ScanXColors.threatCritical),
                SizedBox(height: 12),
                _buildThreatCount('🟠 High', threatCounts['High']!, ScanXColors.threatHigh),
                SizedBox(height: 12),
                _buildThreatCount('🟡 Medium', threatCounts['Medium']!, ScanXColors.threatMedium),
                SizedBox(height: 12),
                _buildThreatCount('🟢 Low', threatCounts['Low']!, ScanXColors.threatLow),
              ],
            ),
          ),
          SizedBox(height: 24),
          Padding(
            padding: EdgeInsets.symmetric(horizontal: 24),
            child: ElevatedButton(
              onPressed: () {
                setState(() {
                  lastScanResult = null;
                  scanProgress = 0;
                });
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: ScanXColors.accentOrange,
                padding: EdgeInsets.symmetric(horizontal: 48, vertical: 14),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              child: Text(
                'Scan Again',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
              ),
            ),
          ),
          SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildThreatCount(String label, int count, Color color) {
    return Container(
      padding: EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: ScanXColors.surfaceLight,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.3), width: 1),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(color: ScanXColors.textPrimary, fontSize: 14),
          ),
          Container(
            padding: EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            decoration: BoxDecoration(
              color: color.withOpacity(0.2),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              count.toString(),
              style: TextStyle(
                color: color,
                fontWeight: FontWeight.bold,
                fontSize: 14,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _startScan() async {
    setState(() => isScanning = true);

    try {
      final coordinator = context.read<ScanCoordinator>();
      final result = final apps = await context.read<DeviceDataCollector>().getInstalledApps();
      final result = await coordinator.scanInstalledApps(apps);

      setState(() {
        lastScanResult = result;
        isScanning = false;
        scanProgress = 0;
      });
    } catch (e) {
      setState(() => isScanning = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Scan error: \$e')),
      );
    }
  }
}
