import 'package:flutter/material.dart';
import '../core/models/threat_model.dart';
import '../services/quarantine_service.dart';
import 'threat_detail_screen.dart';
import 'scan_log_screen.dart';
import 'dart:math' as math;
import 'package:url_launcher/url_launcher.dart';

class ScanResultsScreen extends StatefulWidget {
  final ScanResult result;

  const ScanResultsScreen({Key? key, required this.result}) : super(key: key);

  @override
  State<ScanResultsScreen> createState() => _ScanResultsScreenState();
}

class _ScanResultsScreenState extends State<ScanResultsScreen> with TickerProviderStateMixin {
  late AnimationController _scoreController;
  late Animation<double> _scoreAnimation;
  final QuarantineService _quarantineService = QuarantineService();
  bool _isProcessing = false;
  
  @override
  void initState() {
    super.initState();
    _quarantineService.initialize();
    _scoreController = AnimationController(
      duration: Duration(milliseconds: 2000),
      vsync: this,
    );
    
    final securityScore = _calculateSecurityScore();
    _scoreAnimation = Tween<double>(begin: 0, end: securityScore).animate(
      CurvedAnimation(parent: _scoreController, curve: Curves.easeOutCubic),
    );
    
    _scoreController.forward();
  }
  
  @override
  void dispose() {
    _scoreController.dispose();
    super.dispose();
  }
  
  double _calculateSecurityScore() {
    if (widget.result.threats.isEmpty) return 100.0;
    
    double penalty = 0;
    for (var threat in widget.result.threats) {
      // Use risk score weighted by severity
      double basePenalty = 0;
      switch (threat.severity) {
        case ThreatSeverity.critical:
          basePenalty = 40; // Much higher penalty for critical
          break;
        case ThreatSeverity.high:
          basePenalty = 25;
          break;
        case ThreatSeverity.medium:
          basePenalty = 12;
          break;
        case ThreatSeverity.low:
          basePenalty = 3;
          break;
        case ThreatSeverity.info:
          basePenalty = 1;
          break;
      }
      
      // Adjust penalty based on confidence
      penalty += basePenalty * threat.confidence;
    }
    
    return math.max(0, 100 - penalty);
  }
  
  Color _getScoreColor(double score) {
    if (score >= 80) return Color(0xFF00C853); // Green
    if (score >= 60) return Color(0xFFFFD600); // Yellow
    if (score >= 40) return Color(0xFFFF6D00); // Orange
    return Color(0xFFD32F2F); // Red
  }
  
  String _getScoreLabel(double score) {
    if (score >= 80) return 'SECURE';
    if (score >= 60) return 'GOOD';
    if (score >= 40) return 'AT RISK';
    return 'CRITICAL';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color(0xFF0A0E27),
      body: SafeArea(
        child: CustomScrollView(
          slivers: [
            _buildAppBar(context),
            _buildSecurityScoreCard(),
            _buildQuickActions(),
            _buildThreatList(),
          ],
        ),
      ),
    );
  }
  
  Widget _buildAppBar(BuildContext context) {
    return SliverAppBar(
      backgroundColor: Colors.transparent,
      elevation: 0,
      pinned: true,
      leading: IconButton(
        icon: Icon(Icons.arrow_back, color: Colors.white),
        onPressed: () => Navigator.pop(context),
      ),
      title: Text(
        'Scan Results',
        style: TextStyle(
          color: Colors.white,
          fontSize: 24,
          fontWeight: FontWeight.w300,
          letterSpacing: 1,
        ),
      ),
      actions: [
        IconButton(
          icon: Icon(Icons.share_outlined, color: Colors.white70),
          onPressed: () {
            // TODO: Share report
          },
        ),
      ],
    );
  }
  
  Widget _buildSecurityScoreCard() {
    final securityScore = _calculateSecurityScore();
    final scoreColor = _getScoreColor(securityScore);
    final scoreLabel = _getScoreLabel(securityScore);
    
    return SliverToBoxAdapter(
      child: Container(
        margin: EdgeInsets.symmetric(horizontal: 20, vertical: 16),
        padding: EdgeInsets.all(32),
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              Color(0xFF1A1F3A),
              Color(0xFF151933),
            ],
          ),
          borderRadius: BorderRadius.circular(24),
          boxShadow: [
            BoxShadow(
              color: scoreColor.withOpacity(0.2),
              blurRadius: 20,
              offset: Offset(0, 10),
            ),
          ],
        ),
        child: Column(
          children: [
            // Circular Security Score
            AnimatedBuilder(
              animation: _scoreAnimation,
              builder: (context, child) {
                return Stack(
                  alignment: Alignment.center,
                  children: [
                    SizedBox(
                      width: 180,
                      height: 180,
                      child: CustomPaint(
                        painter: SecurityScorePainter(
                          score: _scoreAnimation.value,
                          color: scoreColor,
                        ),
                      ),
                    ),
                    Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Text(
                          '${_scoreAnimation.value.toInt()}',
                          style: TextStyle(
                            fontSize: 56,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                            height: 1,
                          ),
                        ),
                        SizedBox(height: 4),
                        Text(
                          'Security Score',
                          style: TextStyle(
                            fontSize: 14,
                            color: Colors.white54,
                            letterSpacing: 1,
                          ),
                        ),
                      ],
                    ),
                  ],
                );
              },
            ),
            
            SizedBox(height: 24),
            
            // Status Badge
            Container(
              padding: EdgeInsets.symmetric(horizontal: 24, vertical: 10),
              decoration: BoxDecoration(
                color: scoreColor.withOpacity(0.15),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: scoreColor, width: 1.5),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    securityScore >= 80 ? Icons.verified_user : Icons.warning_amber_rounded,
                    color: scoreColor,
                    size: 20,
                  ),
                  SizedBox(width: 8),
                  Text(
                    scoreLabel,
                    style: TextStyle(
                      color: scoreColor,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      letterSpacing: 1.5,
                    ),
                  ),
                ],
              ),
            ),
            
            SizedBox(height: 20),
            
            // Scan Summary
            Text(
              widget.result.threats.isEmpty 
                ? 'No threats detected. Your device is secure.' 
                : '${widget.result.threats.length} threat(s) detected on your device',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 15,
                color: Colors.white70,
                height: 1.5,
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  Widget _buildQuickActions() {
    return SliverToBoxAdapter(
      child: Container(
        margin: EdgeInsets.symmetric(horizontal: 20, vertical: 8),
        child: Column(
          children: [
            // View Scan Log button (always visible)
            _buildActionButton(
              icon: Icons.assignment_outlined,
              label: 'View Scan Log',
              color: Color(0xFF00D9FF),
              onTap: () {
                Navigator.push(
                  context,
                  MaterialPageRoute(
                    builder: (context) => ScanLogScreen(result: widget.result),
                  ),
                );
              },
            ),
            
            if (widget.result.threats.isNotEmpty) ...[
              SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.delete_outline,
                      label: 'Remove All',
                      color: Color(0xFFFF6B6B),
                      onTap: () => _handleRemoveAll(context),
                    ),
                  ),
                  SizedBox(width: 12),
                  Expanded(
                    child: _buildActionButton(
                      icon: Icons.shield_outlined,
                      label: 'Quarantine',
                      color: Color(0xFFFFA502),
                      onTap: () => _handleQuarantineAll(context),
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
  
  Widget _buildActionButton({
    required IconData icon,
    required String label,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Material(
      color: color.withOpacity(0.15),
      borderRadius: BorderRadius.circular(16),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(16),
        child: Container(
          padding: EdgeInsets.symmetric(vertical: 16),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(icon, color: color, size: 22),
              SizedBox(width: 8),
              Text(
                label,
                style: TextStyle(
                  color: color,
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
  
  Widget _buildThreatList() {
    if (widget.result.threats.isEmpty) {
      return SliverToBoxAdapter(
        child: Container(
          margin: EdgeInsets.all(40),
          child: Column(
            children: [
              Icon(
                Icons.check_circle_outline,
                size: 80,
                color: Color(0xFF00C853),
              ),
              SizedBox(height: 16),
              Text(
                'All Clear!',
                style: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              SizedBox(height: 8),
              Text(
                'No threats found on your device',
                style: TextStyle(
                  fontSize: 15,
                  color: Colors.white54,
                ),
              ),
            ],
          ),
        ),
      );
    }
    
    // Group threats by severity
    final critical = widget.result.threats.where((t) => t.severity == ThreatSeverity.critical).toList();
    final high = widget.result.threats.where((t) => t.severity == ThreatSeverity.high).toList();
    final medium = widget.result.threats.where((t) => t.severity == ThreatSeverity.medium).toList();
    final low = widget.result.threats.where((t) => t.severity == ThreatSeverity.low).toList();
    
    return SliverPadding(
      padding: EdgeInsets.symmetric(horizontal: 20),
      sliver: SliverList(
        delegate: SliverChildBuilderDelegate(
          (context, index) {
            List<DetectedThreat> currentList;
            String sectionTitle;
            Color sectionColor;
            
            if (index < critical.length) {
              currentList = critical;
              sectionTitle = index == 0 ? 'CRITICAL THREATS' : '';
              sectionColor = Color(0xFFD32F2F);
            } else if (index < critical.length + high.length) {
              currentList = high;
              sectionTitle = index == critical.length ? 'HIGH SEVERITY' : '';
              sectionColor = Color(0xFFFF6D00);
            } else if (index < critical.length + high.length + medium.length) {
              currentList = medium;
              sectionTitle = index == critical.length + high.length ? 'MEDIUM SEVERITY' : '';
              sectionColor = Color(0xFFFFD600);
            } else {
              currentList = low;
              sectionTitle = index == critical.length + high.length + medium.length ? 'LOW SEVERITY' : '';
              sectionColor = Color(0xFF00C853);
            }
            
            final threatIndex = index - 
              (index < critical.length ? 0 : 
               index < critical.length + high.length ? critical.length :
               index < critical.length + high.length + medium.length ? critical.length + high.length :
               critical.length + high.length + medium.length);
            
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (sectionTitle.isNotEmpty) ...[
                  SizedBox(height: index == 0 ? 8 : 24),
                  Padding(
                    padding: EdgeInsets.only(left: 4, bottom: 12),
                    child: Text(
                      sectionTitle,
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.bold,
                        color: sectionColor,
                        letterSpacing: 1.5,
                      ),
                    ),
                  ),
                ],
                _buildModernThreatCard(currentList[threatIndex], sectionColor),
              ],
            );
          },
          childCount: widget.result.threats.length,
        ),
      ),
    );
  }
  
  Widget _buildModernThreatCard(DetectedThreat threat, Color severityColor) {
    final isYara = threat.detectionMethod == DetectionMethod.yara;
    final ruleName = isYara && threat.metadata.containsKey('rule_name') 
      ? threat.metadata['rule_name'] 
      : null;
    
    return Container(
      margin: EdgeInsets.only(bottom: 12),
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
          color: severityColor.withOpacity(0.3),
          width: 1.5,
        ),
        boxShadow: [
          BoxShadow(
            color: severityColor.withOpacity(0.1),
            blurRadius: 12,
            offset: Offset(0, 4),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(20),
          onTap: () {
            Navigator.push(
              context,
              MaterialPageRoute(
                builder: (_) => ThreatDetailScreen(threat: threat),
              ),
            );
          },
          child: Padding(
            padding: EdgeInsets.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Header Row
                Row(
                  children: [
                    // Threat Icon
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: severityColor.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(
                        _getThreatIcon(threat),
                        color: severityColor,
                        size: 24,
                      ),
                    ),
                    
                    SizedBox(width: 16),
                    
                    // App Name & Severity
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            threat.appName,
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                          SizedBox(height: 4),
                          Row(
                            children: [
                              Container(
                                padding: EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                                decoration: BoxDecoration(
                                  color: severityColor.withOpacity(0.2),
                                  borderRadius: BorderRadius.circular(6),
                                ),
                                child: Text(
                                  threat.severity.toString().split('.').last.toUpperCase(),
                                  style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.bold,
                                    color: severityColor,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                              ),
                              SizedBox(width: 8),
                              Text(
                                '${(threat.confidence * 100).toInt()}% confidence',
                                style: TextStyle(
                                  fontSize: 12,
                                  color: Colors.white38,
                                ),
                              ),
                            ],
                          ),
                        ],
                      ),
                    ),
                    
                    Icon(Icons.chevron_right, color: Colors.white24, size: 24),
                  ],
                ),
                
                SizedBox(height: 16),
                
                // YARA Detection Badge (if applicable)
                if (ruleName != null) ...[
                  Container(
                    padding: EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Color(0xFFFF6B6B),
                          Color(0xFFFF8E53),
                        ],
                      ),
                      borderRadius: BorderRadius.circular(12),
                      boxShadow: [
                        BoxShadow(
                          color: Color(0xFFFF6B6B).withOpacity(0.3),
                          blurRadius: 12,
                          offset: Offset(0, 4),
                        ),
                      ],
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.verified_user, size: 18, color: Colors.white),
                        SizedBox(width: 8),
                        Flexible(
                          child: Text(
                            'YARA: $ruleName',
                            style: TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                              color: Colors.white,
                              letterSpacing: 0.5,
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                      ],
                    ),
                  ),
                  SizedBox(height: 12),
                ],
                
                // Threat Description
                Text(
                  threat.description,
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.white70,
                    height: 1.5,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                
                SizedBox(height: 16),
                
                // Bottom Metadata Row
                Row(
                  children: [
                    _buildMetadataChip(
                      icon: Icons.fingerprint,
                      label: threat.packageName,
                      color: Color(0xFF6C63FF),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
  
  Widget _buildMetadataChip({
    required IconData icon,
    required String label,
    required Color color,
  }) {
    return Flexible(
      child: Container(
        padding: EdgeInsets.symmetric(horizontal: 10, vertical: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: color),
            SizedBox(width: 6),
            Flexible(
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 12,
                  color: color,
                  fontWeight: FontWeight.w500,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }
  
  IconData _getThreatIcon(DetectedThreat threat) {
    if (threat.detectionMethod == DetectionMethod.yara) {
      return Icons.bug_report;
    }
    switch (threat.severity) {
      case ThreatSeverity.critical:
        return Icons.dangerous;
      case ThreatSeverity.high:
        return Icons.warning_amber_rounded;
      case ThreatSeverity.medium:
        return Icons.info_outline;
      case ThreatSeverity.low:
        return Icons.help_outline;
      case ThreatSeverity.info:
        return Icons.info;
    }
  }
  
  Future<void> _handleRemoveAll(BuildContext context) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        title: Text('Open App Settings?', style: TextStyle(color: Colors.white)),
        content: Text(
          'This will open Android settings where you can manually uninstall the ${widget.result.threats.length} apps identified as threats.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('OPEN SETTINGS'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    setState(() => _isProcessing = true);

    try {
      // Open first threat app settings
      if (widget.result.threats.isNotEmpty) {
        final firstThreat = widget.result.threats.first;
        final uri = Uri.parse('package:${firstThreat.packageName}');
        if (await canLaunchUrl(uri)) {
          await launchUrl(uri);
          
          if (mounted) {
            ScaffoldMessenger.of(context).showSnackBar(
              SnackBar(
                content: Text('Opening app settings. You can uninstall ${widget.result.threats.length} threat(s) from there.'),
                backgroundColor: Color(0xFF00C853),
                behavior: SnackBarBehavior.floating,
                duration: Duration(seconds: 5),
              ),
            );
          }
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to open settings: $e'),
            backgroundColor: Color(0xFFD32F2F),
          ),
        );
      }
    } finally{
      if (mounted) {
        setState(() => _isProcessing = false);
      }
    }
  }

  Future<void> _handleQuarantineAll(BuildContext context) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        title: Text('Quarantine All Threats?', style: TextStyle(color: Colors.white)),
        content: Text(
          'This will disable and block network access for ${widget.result.threats.length} apps. They can be restored later.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context, false),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () => Navigator.pop(context, true),
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFFA502),
            ),
            child: Text('QUARANTINE ALL'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    setState(() => _isProcessing = true);

    int successCount = 0;
    int failCount = 0;

    for (var threat in widget.result.threats) {
      try {
        final appMetadata = AppMetadata(
          packageName: threat.packageName,
          appName: threat.appName,
          version: threat.version ?? 'unknown',
          hash: threat.hash,
          installTime: threat.detectedAt.millisecondsSinceEpoch,
          lastUpdateTime: threat.detectedAt.millisecondsSinceEpoch,
          isSystemApp: false,
          installerPackage: 'unknown',
          size: 0,
          requestedPermissions: [],
          grantedPermissions: [],
        );

        final success = await _quarantineService.quarantineApp(
          appMetadata,
          [threat],
        );

        if (success) {
          successCount++;
        } else {
          failCount++;
        }
      } catch (e) {
        failCount++;
      }
    }

    setState(() => _isProcessing = false);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Quarantined $successCount apps. $failCount failed.'),
          backgroundColor: successCount > 0 ? Color(0xFF00C853) : Color(0xFFFF4757),
          behavior: SnackBarBehavior.floating,
        ),
      );
      
      if (successCount > 0) {
        Navigator.pop(context, true);
      }
    }
  }
}

// Custom Painter for Security Score Circle
class SecurityScorePainter extends CustomPainter {
  final double score;
  final Color color;
  
  SecurityScorePainter({required this.score, required this.color});
  
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2;
    
    // Background circle
    final backgroundPaint = Paint()
      ..color = Colors.white.withOpacity(0.1)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 12;
    
    canvas.drawCircle(center, radius - 6, backgroundPaint);
    
    // Progress arc
    final progressPaint = Paint()
      ..shader = LinearGradient(
        colors: [color, color.withOpacity(0.6)],
        begin: Alignment.topLeft,
        end: Alignment.bottomRight,
      ).createShader(Rect.fromCircle(center: center, radius: radius))
      ..style = PaintingStyle.stroke
      ..strokeWidth = 12
      ..strokeCap = StrokeCap.round;
    
    final sweepAngle = (score / 100) * 2 * math.pi;
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius - 6),
      -math.pi / 2,
      sweepAngle,
      false,
      progressPaint,
    );
  }
  
  @override
  bool shouldRepaint(SecurityScorePainter oldDelegate) {
    return oldDelegate.score != score || oldDelegate.color != color;
  }
}
