import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'services/scan_coordinator.dart';
import 'services/device_data_collector.dart';
import 'core/models/threat_model.dart';

void main() {
  runApp(const MalwareScannerApp());
}

class MalwareScannerApp extends StatelessWidget {
  const MalwareScannerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider<ScanCoordinator>(create: (_) => ScanCoordinator()),
        Provider<DeviceDataCollector>(create: (_) => DeviceDataCollector()),
      ],
      child: MaterialApp(
        title: 'MalwareScanner',
        theme: ThemeData(
          useMaterial3: true,
          colorScheme: ColorScheme.fromSeed(
            seedColor: Colors.red,
            brightness: Brightness.dark,
          ),
        ),
        home: const ScannerHomePage(),
      ),
    );
  }
}

class ScannerHomePage extends StatefulWidget {
  const ScannerHomePage({Key? key}) : super(key: key);

  @override
  State<ScannerHomePage> createState() => _ScannerHomePageState();
}

class _ScannerHomePageState extends State<ScannerHomePage> {
  ScanResult? _lastScanResult;
  bool _isScanning = false;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('🛡️ MalwareScanner'),
        elevation: 0,
      ),
      body: _isScanning
          ? _buildScanningProgress()
          : _lastScanResult != null
              ? _buildScanResults(_lastScanResult!)
              : _buildInitialScreen(),
      floatingActionButton: !_isScanning
          ? FloatingActionButton.extended(
              onPressed: _startScan,
              backgroundColor: Colors.red,
              icon: const Icon(Icons.security_rounded),
              label: const Text('Start Scan'),
            )
          : null,
    );
  }

  Widget _buildInitialScreen() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.red, width: 2),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  '🔒 Production-Grade Malware Detection',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Real-time on-device + cloud-assisted scanning for installed apps, files, network telemetry, and processes.',
                  style: TextStyle(fontSize: 14, color: Colors.white70),
                ),
                const SizedBox(height: 24),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildScanningProgress() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(
            width: 80,
            height: 80,
            child: CircularProgressIndicator(
              strokeWidth: 4,
              valueColor: AlwaysStoppedAnimation<Color>(Colors.red),
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'Scanning installed apps...',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 12),
          const Text(
            'Stage 1: Signature Analysis\nStage 2: Static Code Analysis\nStage 3: Behavioral Detection\nStage 4: Threat Intelligence',
            style: TextStyle(fontSize: 12, color: Colors.white70),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildScanResults(ScanResult result) {
    final stats = result.statistics;
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.1),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.red, width: 2),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Scan Summary',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                const SizedBox(height: 12),
                Text('Apps: ${stats.appsScanned} | Threats: ${result.totalThreatsFound} | Time: ${stats.scanDuration.inSeconds}s'),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _startScan() async {
    setState(() => _isScanning = true);
    try {
      final collector = context.read<DeviceDataCollector>();
      final coordinator = context.read<ScanCoordinator>();
      final apps = await collector.getInstalledApps();
      final result = await coordinator.scanInstalledApps(apps);
      setState(() {
        _lastScanResult = result;
        _isScanning = false;
      });
    } catch (e) {
      setState(() => _isScanning = false);
    }
  }
}
