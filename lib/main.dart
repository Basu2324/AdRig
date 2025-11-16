import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'core/theme/scanx_colors.dart';
import 'services/scan_coordinator.dart';
import 'services/app_telemetry_collector.dart';
import 'services/auth_service.dart';
import 'services/permission_service.dart';
import 'core/models/threat_model.dart';
import 'screens/dashboard_screen.dart';
import 'screens/login_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Load environment variables (API keys)
  try {
    await dotenv.load(fileName: ".env");
    print('✅ Environment variables loaded');
  } catch (e) {
    print('⚠️ .env file not found - API features disabled');
    print('ℹ️ Create .env file with API keys for full functionality');
  }
  
  // Initialize Firebase (optional - app works without it)
  try {
    await Firebase.initializeApp();
    print('✅ Firebase initialized');
  } catch (e) {
    print('⚠️ Firebase not configured - using local storage mode');
    print('ℹ️ To enable cloud sync, follow FIREBASE_SETUP.md');
  }
  
  runApp(const AdRigApp());
}

class AdRigApp extends StatelessWidget {
  const AdRigApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        Provider(create: (_) => PermissionService()),
        Provider(create: (_) => AppTelemetryCollector()),
        Provider(create: (_) {
          try {
            return ScanCoordinator();
          } catch (e) {
            print('⚠️ ScanCoordinator initialization error: $e');
            print('Stack trace: ${StackTrace.current}');
            rethrow;
          }
        }),
        Provider(create: (_) {
          try {
            return AuthService();
          } catch (e) {
            print('⚠️ AuthService initialization error: $e');
            return AuthService();
          }
        }),
      ],
      child: MaterialApp(
        title: 'Malware Scanner - Secure Your Device',
        theme: ThemeData(
          brightness: Brightness.dark,
          scaffoldBackgroundColor: Color(0xFF0A0E27),
          primaryColor: Color(0xFF6C63FF),
          colorScheme: ColorScheme.dark(
            primary: Color(0xFF6C63FF),
            secondary: Color(0xFF00D9FF),
            surface: Color(0xFF151933),
            error: Color(0xFFFF4757),
          ),
          appBarTheme: AppBarTheme(
            backgroundColor: Color(0xFF0A0E27),
            elevation: 0,
          ),
        ),
        debugShowCheckedModeBanner: false,
        home: const AuthGate(),
      ),
    );
  }
}

/// Auth gate - checks permissions and login status
class AuthGate extends StatelessWidget {
  const AuthGate({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final authService = Provider.of<AuthService>(context, listen: false);
    
    return FutureBuilder<bool>(
      future: authService.isLoggedIn(),
      builder: (context, snapshot) {
        if (snapshot.connectionState == ConnectionState.waiting) {
          return Scaffold(
            backgroundColor: const Color(0xFF0A0E27),
            body: Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: const [
                  CircularProgressIndicator(color: Color(0xFF6C63FF)),
                  SizedBox(height: 24),
                  Text(
                    'Initializing AdRig Security...',
                    style: TextStyle(color: Colors.white70),
                  ),
                ],
              ),
            ),
          );
        }
        
        final isLoggedIn = snapshot.data ?? false;
        
        // Show Login or Dashboard - permissions will be requested when needed
        if (isLoggedIn) {
          return const DashboardScreen();
        } else {
          return const LoginScreen();
        }
      },
    );
  }
}

class AdRigHome extends StatefulWidget {
  const AdRigHome({Key? key}) : super(key: key);

  @override
  State<AdRigHome> createState() => _AdRigHomeState();
}

class _AdRigHomeState extends State<AdRigHome> {
  bool isScanning = false;
  bool isInitializing = true;
  ScanResult? lastScanResult;
  double scanProgress = 0;
  String currentStage = 'Initializing...';

  @override
  void initState() {
    super.initState();
    _initializeAsync();
  }

  Future<void> _initializeAsync() async {
    final coordinator = Provider.of<ScanCoordinator>(context, listen: false);
    await coordinator.initializeAsync();
    
    if (mounted) {
      setState(() {
        isInitializing = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (isInitializing) {
      return Scaffold(
        backgroundColor: ScanXColors.background,
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              CircularProgressIndicator(color: ScanXColors.accentOrange),
              SizedBox(height: 24),
              Text(
                'Initializing AdRig Security...',
                style: TextStyle(color: ScanXColors.textPrimary),
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: ScanXColors.background,
      appBar: AppBar(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              'AdRig',
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
                    'AdRig',
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
                SizedBox(height: 12),
                _buildFeature('📋', 'YARA Rules', '10 pattern matching rules'),
                SizedBox(height: 12),
                _buildFeature('⚙️', 'Static Analysis', 'APK manifest & code inspection'),
                SizedBox(height: 12),
                _buildFeature('🔄', 'Behavioral Monitoring', 'Real-time threat detection'),
                SizedBox(height: 12),
                _buildFeature('🤖', 'ML Detection', 'TensorFlow Lite anomaly detection'),
                SizedBox(height: 12),
                _buildFeature('🌐', 'Network Analysis', 'C2 beaconing & data exfiltration'),
                SizedBox(height: 12),
                _buildFeature('⚡', 'Process Monitoring', 'Runtime behavior analysis'),
                SizedBox(height: 12),
                _buildFeature('🛡️', 'Threat Intelligence', 'IoC correlation & reputation'),
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
                  '${(scanProgress * 100).toStringAsFixed(0)}%',
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
                  '${result.threats.length} threat(s) found',
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
          SizedBox(height: 32),
          
          // THREAT DETAILS SECTION
          if (result.threats.isNotEmpty) ...[
            Padding(
              padding: EdgeInsets.symmetric(horizontal: 24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Threat Details',
                    style: TextStyle(
                      color: ScanXColors.textPrimary,
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  SizedBox(height: 16),
                  ...result.threats.map((threat) => _buildThreatDetailCard(threat)),
                ],
              ),
            ),
            SizedBox(height: 24),
          ],
          
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
  
  Widget _buildThreatDetailCard(DetectedThreat threat) {
    Color severityColor;
    String severityLabel;
    
    switch (threat.severity) {
      case ThreatSeverity.critical:
        severityColor = ScanXColors.threatCritical;
        severityLabel = 'CRITICAL';
        break;
      case ThreatSeverity.high:
        severityColor = ScanXColors.threatHigh;
        severityLabel = 'HIGH';
        break;
      case ThreatSeverity.medium:
        severityColor = ScanXColors.threatMedium;
        severityLabel = 'MEDIUM';
        break;
      case ThreatSeverity.low:
        severityColor = ScanXColors.threatLow;
        severityLabel = 'LOW';
        break;
      default:
        severityColor = ScanXColors.textSecondary;
        severityLabel = 'INFO';
    }
    
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: ScanXColors.surfaceLight,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: severityColor.withOpacity(0.3), width: 2),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: severityColor.withOpacity(0.2),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  severityLabel,
                  style: TextStyle(
                    color: severityColor,
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
              SizedBox(width: 8),
              Expanded(
                child: Text(
                  threat.appName,
                  style: TextStyle(
                    color: ScanXColors.textPrimary,
                    fontSize: 15,
                    fontWeight: FontWeight.bold,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          SizedBox(height: 12),
          
          // Threat Description
          Text(
            threat.description,
            style: TextStyle(
              color: ScanXColors.textSecondary,
              fontSize: 13,
              height: 1.4,
            ),
          ),
          SizedBox(height: 12),
          
          // Detection Details
          Container(
            padding: EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: ScanXColors.surface,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildDetailRow('📦 Package', threat.packageName),
                SizedBox(height: 6),
                _buildDetailRow('🔍 Detection Method', _getDetectionMethodLabel(threat.detectionMethod)),
                SizedBox(height: 6),
                _buildDetailRow('📊 Confidence', '${(threat.confidence * 100).toStringAsFixed(1)}%'),
                SizedBox(height: 6),
                _buildDetailRow('🕐 Detected At', _formatTimestamp(threat.detectedAt)),
                if (threat.indicators.isNotEmpty) ...[
                  SizedBox(height: 8),
                  Divider(color: ScanXColors.border, height: 1),
                  SizedBox(height: 8),
                  Text(
                    'Indicators:',
                    style: TextStyle(
                      color: ScanXColors.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  SizedBox(height: 6),
                  ...threat.indicators.take(3).map((indicator) => Padding(
                    padding: EdgeInsets.only(bottom: 4),
                    child: Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('• ', style: TextStyle(color: severityColor)),
                        Expanded(
                          child: Text(
                            indicator,
                            style: TextStyle(
                              color: ScanXColors.textSecondary,
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ],
                    ),
                  )),
                  if (threat.indicators.length > 3)
                    Text(
                      '  ... and ${threat.indicators.length - 3} more',
                      style: TextStyle(
                        color: ScanXColors.textSecondary,
                        fontSize: 11,
                        fontStyle: FontStyle.italic,
                      ),
                    ),
                ],
              ],
            ),
          ),
          
          // Recommended Action
          SizedBox(height: 12),
          Container(
            padding: EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: severityColor.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: severityColor.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                Icon(Icons.lightbulb_outline, color: severityColor, size: 18),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    _getActionLabel(threat.recommendedAction),
                    style: TextStyle(
                      color: ScanXColors.textPrimary,
                      fontSize: 12,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
  
  Widget _buildDetailRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label + ': ',
          style: TextStyle(
            color: ScanXColors.textSecondary,
            fontSize: 12,
          ),
        ),
        Expanded(
          child: Text(
            value,
            style: TextStyle(
              color: ScanXColors.textPrimary,
              fontSize: 12,
              fontWeight: FontWeight.w500,
            ),
          ),
        ),
      ],
    );
  }
  
  String _getDetectionMethodLabel(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return 'Signature Database';
      case DetectionMethod.yara:
        return 'YARA Pattern';
      case DetectionMethod.staticanalysis:
        return 'Static Analysis';
      case DetectionMethod.behavioral:
        return 'Behavioral Analysis';
      case DetectionMethod.machinelearning:
        return 'ML Model';
      case DetectionMethod.threatintel:
        return 'Threat Intelligence';
      case DetectionMethod.heuristic:
        return 'Heuristic Analysis';
      case DetectionMethod.anomaly:
        return 'Anomaly Detection';
      default:
        return 'Unknown';
    }
  }
  
  String _formatTimestamp(DateTime timestamp) {
    final now = DateTime.now();
    final diff = now.difference(timestamp);
    
    if (diff.inSeconds < 60) {
      return '${diff.inSeconds}s ago';
    } else if (diff.inMinutes < 60) {
      return '${diff.inMinutes}m ago';
    } else if (diff.inHours < 24) {
      return '${diff.inHours}h ago';
    } else {
      return '${diff.inDays}d ago';
    }
  }

  String _getActionLabel(ActionType action) {
    switch (action) {
      case ActionType.quarantine:
        return '⚠️ Quarantine this app immediately';
      case ActionType.alert:
        return 'ℹ️ Monitor this app for suspicious activity';
      case ActionType.autoblock:
        return '🚫 Block and remove this app';
      default:
        return 'Review this threat';
    }
  }

  Future<void> _startScan() async {
    setState(() {
      isScanning = true;
      scanProgress = 0;
      currentStage = 'Initializing scan...';
    });

    try {
      final coordinator = context.read<ScanCoordinator>();
      final collector = context.read<AppTelemetryCollector>();
      
      // Stage 1: Get installed apps
      setState(() {
        currentStage = 'Enumerating installed apps...';
        scanProgress = 0.1;
      });
      await Future.delayed(Duration(milliseconds: 500));
      
      final telemetryApps = await collector.collectAllAppsTelemetry();
      
      // Convert AppTelemetry to AppMetadata for ScanCoordinator
      final apps = telemetryApps.map((app) => AppMetadata(
        packageName: app.packageName,
        appName: app.appName,
        version: app.version,
        hash: app.hashes.sha256,
        installTime: app.installedDate.millisecondsSinceEpoch,
        lastUpdateTime: app.lastUpdated.millisecondsSinceEpoch,
        isSystemApp: false,
        installerPackage: app.installer ?? 'unknown',
        size: app.appSize,
        requestedPermissions: app.declaredPermissions,
        grantedPermissions: app.runtimeGrantedPermissions,
      )).toList();
      
      // Stage 2: Signature scanning
      setState(() {
        currentStage = 'Stage 1/6: Signature Analysis';
        scanProgress = 0.2;
      });
      await Future.delayed(Duration(milliseconds: 800));
      
      // Stage 3: YARA rules
      setState(() {
        currentStage = 'Stage 2/6: YARA Pattern Matching';
        scanProgress = 0.35;
      });
      await Future.delayed(Duration(milliseconds: 800));
      
      // Stage 4: Static analysis
      setState(() {
        currentStage = 'Stage 3/6: Static Code Analysis';
        scanProgress = 0.5;
      });
      await Future.delayed(Duration(milliseconds: 1000));
      
      // Stage 5: Behavioral & ML
      setState(() {
        currentStage = 'Stage 4/6: Behavioral & ML Analysis';
        scanProgress = 0.65;
      });
      await Future.delayed(Duration(milliseconds: 1000));
      
      // Stage 6: Network & Process
      setState(() {
        currentStage = 'Stage 5/6: Network & Process Analysis';
        scanProgress = 0.8;
      });
      await Future.delayed(Duration(milliseconds: 800));
      
      // Stage 7: Threat Intelligence
      setState(() {
        currentStage = 'Stage 6/6: Threat Intelligence Correlation';
        scanProgress = 0.9;
      });
      
      // Run actual scan
      final result = await coordinator.scanInstalledApps(telemetryApps);
      
      // Complete
      setState(() {
        currentStage = 'Scan complete!';
        scanProgress = 1.0;
      });
      await Future.delayed(Duration(milliseconds: 500));

      setState(() {
        lastScanResult = result;
        isScanning = false;
        scanProgress = 0;
      });
    } catch (e) {
      print('Scan error: $e');
      setState(() {
        isScanning = false;
        currentStage = 'Scan failed';
      });
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Scan error: $e'),
            backgroundColor: ScanXColors.threatHigh,
          ),
        );
      }
    }
  }
}
