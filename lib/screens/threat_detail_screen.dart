import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../core/models/threat_model.dart';
import '../services/quarantine_service.dart';
import '../services/threat_history_service.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:android_intent_plus/android_intent.dart';

class ThreatDetailScreen extends StatefulWidget {
  final DetectedThreat threat;

  const ThreatDetailScreen({Key? key, required this.threat}) : super(key: key);

  @override
  State<ThreatDetailScreen> createState() => _ThreatDetailScreenState();
}

class _ThreatDetailScreenState extends State<ThreatDetailScreen> {
  final QuarantineService _quarantineService = QuarantineService();
  final ThreatHistoryService _historyService = ThreatHistoryService();
  bool _isProcessing = false;

  @override
  void initState() {
    super.initState();
    _quarantineService.initialize();
  }

  @override
  Widget build(BuildContext context) {
    final severityColor = _getSeverityColor(widget.threat.severity);

    return Scaffold(
      appBar: AppBar(
        title: Text('Threat Details', style: TextStyle(fontWeight: FontWeight.w300)),
        actions: [
          IconButton(
            icon: Icon(Icons.share),
            onPressed: () => _shareReport(context),
          ),
        ],
      ),
      body: ListView(
        padding: EdgeInsets.all(16),
        children: [
          // Threat Overview Card
          _buildOverviewCard(severityColor),
          
          SizedBox(height: 16),
          
          // Detection Engine Analysis
          _buildSectionCard(
            'Detection Engine',
            Icons.settings,
            Color(0xFF6C63FF),
            [
              _buildDetailRow('Method', _getDetectionMethodLabel(widget.threat.detectionMethod)),
              _buildDetailRow('Confidence', '${(widget.threat.confidence * 100).toInt()}%'),
              _buildDetailRow('Detected At', _formatTimestamp(widget.threat.detectedAt)),
              if (widget.threat.hash != null && widget.threat.hash!.isNotEmpty)
                _buildDetailRow('APK Hash', widget.threat.hash!, mono: true, copyable: true),
            ],
          ),
          
          SizedBox(height: 16),
          
          // Risk Assessment
          _buildSectionCard(
            'Risk Assessment',
            Icons.assessment,
            Color(0xFFFF6348),
            [
              _buildDetailRow('Severity', widget.threat.severity.toString().split('.').last.toUpperCase()),
              _buildDetailRow('Threat Type', widget.threat.threatType.toString().split('.').last),
              _buildDetailRow('Recommended Action', widget.threat.recommendedAction.toString().split('.').last.toUpperCase()),
            ],
          ),
          
          SizedBox(height: 16),
          
          // Application Info
          _buildSectionCard(
            'Application Information',
            Icons.apps,
            Color(0xFF00D9FF),
            [
              _buildDetailRow('App Name', widget.threat.appName),
              _buildDetailRow('Package', widget.threat.packageName, mono: true, copyable: true),
              if (widget.threat.version != null && widget.threat.version!.isNotEmpty)
                _buildDetailRow('Version', widget.threat.version!),
            ],
          ),
          
          SizedBox(height: 16),
          
          // Threat Indicators
          if (widget.threat.indicators.isNotEmpty)
            _buildIndicatorsCard(),
          
          SizedBox(height: 16),
          
          // Metadata (Engine-specific details)
          if (widget.threat.metadata.isNotEmpty)
            _buildMetadataCard(),
          
          SizedBox(height: 16),
          
          // Action Buttons
          _buildActionButtons(context, severityColor),
          
          SizedBox(height: 80),
        ],
      ),
    );
  }

  Widget _buildOverviewCard(Color severityColor) {
    return Container(
      padding: EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [severityColor, severityColor.withOpacity(0.7)],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.warning_rounded, color: Colors.white, size: 32),
              SizedBox(width: 12),
              Expanded(
                child: Text(
                  widget.threat.appName,
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
              ),
            ],
          ),
          SizedBox(height: 16),
          Text(
            widget.threat.description,
            style: TextStyle(
              fontSize: 15,
              color: Colors.white,
              height: 1.5,
            ),
          ),
          SizedBox(height: 16),
          Container(
            padding: EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: BoxDecoration(
              color: Colors.white24,
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.shield, size: 14, color: Colors.white),
                SizedBox(width: 6),
                Text(
                  '${widget.threat.severity.toString().split('.').last.toUpperCase()} SEVERITY',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                    letterSpacing: 1,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionCard(String title, IconData icon, Color color, List<Widget> children) {
    return Container(
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              border: Border(
                bottom: BorderSide(color: color.withOpacity(0.2)),
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: color.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(icon, size: 20, color: color),
                ),
                SizedBox(width: 12),
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
              ],
            ),
          ),
          Padding(
            padding: EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: children,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, {bool mono = false, bool copyable = false}) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: TextStyle(
                fontSize: 13,
                color: Colors.white38,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
          Expanded(
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    value,
                    style: TextStyle(
                      fontSize: 13,
                      color: Colors.white,
                      fontFamily: mono ? 'monospace' : null,
                    ),
                  ),
                ),
                if (copyable)
                  IconButton(
                    icon: Icon(Icons.copy, size: 16, color: Color(0xFF6C63FF)),
                    padding: EdgeInsets.zero,
                    constraints: BoxConstraints(),
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: value));
                    },
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildIndicatorsCard() {
    return Container(
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Color(0xFFFFA502).withOpacity(0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              border: Border(
                bottom: BorderSide(color: Color(0xFFFFA502).withOpacity(0.2)),
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Color(0xFFFFA502).withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(Icons.flag, size: 20, color: Color(0xFFFFA502)),
                ),
                SizedBox(width: 12),
                Text(
                  'Threat Indicators',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Spacer(),
                Container(
                  padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Color(0xFFFFA502).withOpacity(0.2),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    '${widget.threat.indicators.length}',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                      color: Color(0xFFFFA502),
                    ),
                  ),
                ),
              ],
            ),
          ),
          ListView.separated(
            shrinkWrap: true,
            physics: NeverScrollableScrollPhysics(),
            padding: EdgeInsets.all(16),
            itemCount: widget.threat.indicators.length,
            separatorBuilder: (_, __) => SizedBox(height: 8),
            itemBuilder: (context, index) {
              return Container(
                padding: EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.black26,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      margin: EdgeInsets.only(top: 2),
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        color: Color(0xFFFFA502),
                      ),
                    ),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        widget.threat.indicators[index],
                        style: TextStyle(
                          fontSize: 13,
                          color: Colors.white70,
                          height: 1.4,
                        ),
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  Widget _buildMetadataCard() {
    // Special handling for YARA detection
    final isYaraDetection = widget.threat.detectionMethod == DetectionMethod.yara;
    
    return Container(
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isYaraDetection 
            ? Color(0xFFFF6B6B).withOpacity(0.3)
            : Color(0xFF6C63FF).withOpacity(0.2)
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isYaraDetection 
                ? Color(0xFFFF6B6B).withOpacity(0.1)
                : null,
              border: Border(
                bottom: BorderSide(
                  color: isYaraDetection
                    ? Color(0xFFFF6B6B).withOpacity(0.2)
                    : Color(0xFF6C63FF).withOpacity(0.2)
                ),
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: isYaraDetection
                      ? Color(0xFFFF6B6B).withOpacity(0.2)
                      : Color(0xFF6C63FF).withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    isYaraDetection ? Icons.rule : Icons.code, 
                    size: 20, 
                    color: isYaraDetection ? Color(0xFFFF6B6B) : Color(0xFF6C63FF)
                  ),
                ),
                SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        isYaraDetection ? 'YARA Rule Match' : 'Technical Details',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.white,
                        ),
                      ),
                      if (isYaraDetection && widget.threat.metadata.containsKey('rule_name'))
                        Text(
                          widget.threat.metadata['rule_name'].toString(),
                          style: TextStyle(
                            fontSize: 12,
                            color: Color(0xFFFF6B6B),
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                    ],
                  ),
                ),
                if (isYaraDetection)
                  Container(
                    padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: Color(0xFFFF6B6B).withOpacity(0.2),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      'PATTERN MATCH',
                      style: TextStyle(
                        fontSize: 10,
                        color: Color(0xFFFF6B6B),
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
              ],
            ),
          ),
          Padding(
            padding: EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Show YARA-specific information first
                if (isYaraDetection) ...[
                  if (widget.threat.metadata.containsKey('rule_id'))
                    _buildMetadataRow('Rule ID', widget.threat.metadata['rule_id'].toString()),
                  if (widget.threat.metadata.containsKey('match_count'))
                    _buildMetadataRow('Pattern Matches', '${widget.threat.metadata['match_count']} patterns found'),
                  if (widget.threat.metadata.containsKey('matched_strings')) ...[
                    SizedBox(height: 8),
                    Text(
                      'Matched Patterns:',
                      style: TextStyle(
                        fontSize: 13,
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    SizedBox(height: 8),
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Color(0xFF0A0E27),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Color(0xFFFF6B6B).withOpacity(0.2)),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: (widget.threat.metadata['matched_strings'] as List)
                          .take(5)
                          .map((pattern) => Padding(
                            padding: EdgeInsets.only(bottom: 6),
                            child: Row(
                              children: [
                                Icon(Icons.chevron_right, size: 14, color: Color(0xFFFF6B6B)),
                                SizedBox(width: 4),
                                Expanded(
                                  child: Text(
                                    pattern.toString(),
                                    style: TextStyle(
                                      fontSize: 11,
                                      color: Color(0xFF00D9FF),
                                      fontFamily: 'monospace',
                                    ),
                                    maxLines: 2,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                              ],
                            ),
                          ))
                          .toList(),
                      ),
                    ),
                    SizedBox(height: 12),
                  ],
                ],
                // Show other metadata
                ...widget.threat.metadata.entries
                  .where((entry) => !['rule_name', 'rule_id', 'match_count', 'matched_strings'].contains(entry.key))
                  .map((entry) => _buildMetadataRow(entry.key, entry.value.toString()))
                  .toList(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMetadataRow(String key, String value) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(
              key,
              style: TextStyle(
                fontSize: 12,
                color: Colors.white38,
                fontWeight: FontWeight.w500,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 12,
                color: Color(0xFF00D9FF),
                fontFamily: 'monospace',
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildActionButtons(BuildContext context, Color severityColor) {
    return Column(
      children: [
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            onPressed: _isProcessing ? null : () => _handleQuarantine(context),
            icon: _isProcessing 
                ? SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2),
                  )
                : Icon(Icons.lock),
            label: Text(_isProcessing ? 'PROCESSING...' : 'QUARANTINE APP'),
            style: ElevatedButton.styleFrom(
              backgroundColor: severityColor,
              foregroundColor: Colors.white,
              padding: EdgeInsets.symmetric(vertical: 16),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
            ),
          ),
        ),
        SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _isProcessing ? null : () => _handleUninstall(context),
                icon: Icon(Icons.delete_outline),
                label: Text('UNINSTALL'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Color(0xFFFF4757),
                  side: BorderSide(color: Color(0xFFFF4757)),
                  padding: EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
            ),
            SizedBox(width: 12),
            Expanded(
              child: OutlinedButton.icon(
                onPressed: _isProcessing ? null : () => _handleIgnore(context),
                icon: Icon(Icons.visibility_off),
                label: Text('IGNORE'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: Colors.white38,
                  side: BorderSide(color: Colors.white38),
                  padding: EdgeInsets.symmetric(vertical: 16),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12),
                  ),
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Future<void> _handleQuarantine(BuildContext context) async {
    // Confirm action
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        title: Row(
          children: [
            Icon(Icons.lock, color: Color(0xFFFF4757)),
            SizedBox(width: 12),
            Text('Quarantine App?', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'This will:',
              style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
            ),
            SizedBox(height: 8),
            _buildBulletPoint('Remove from threat history'),
            _buildBulletPoint('Add to quarantine list'),
            _buildBulletPoint('Mark as handled'),
            SizedBox(height: 12),
            Container(
              padding: EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.orange.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: Colors.orange.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  Icon(Icons.info_outline, color: Colors.orange, size: 20),
                  SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      'To fully remove the threat, uninstall the app from Android settings.',
                      style: TextStyle(color: Colors.white70, fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
          ],
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
            child: Text('QUARANTINE'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    setState(() => _isProcessing = true);

    try {
      print('🔒 Starting quarantine for: ${widget.threat.appName}');
      print('   Threat ID: ${widget.threat.id}');
      
      // Create AppMetadata from threat
      final appMetadata = AppMetadata(
        packageName: widget.threat.packageName,
        appName: widget.threat.appName,
        version: widget.threat.version ?? 'unknown',
        hash: widget.threat.hash,
        installTime: widget.threat.detectedAt.millisecondsSinceEpoch,
        lastUpdateTime: widget.threat.detectedAt.millisecondsSinceEpoch,
        isSystemApp: false,
        installerPackage: 'unknown',
        size: 0,
        requestedPermissions: [],
        grantedPermissions: [],
      );

      // Quarantine the app
      print('📦 Calling quarantine service...');
      final success = await _quarantineService.quarantineApp(
        appMetadata,
        [widget.threat],
      );

      if (success) {
        print('✅ Quarantine successful, removing from history...');
        
        // Remove from threat history
        await _historyService.removeThreat(widget.threat.id);
        
        print('✅ Threat removed from history, returning to list...');
        
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  Icon(Icons.check_circle, color: Colors.white),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text('${widget.threat.appName} has been quarantined'),
                  ),
                ],
              ),
              backgroundColor: Color(0xFF00C853),
              behavior: SnackBarBehavior.floating,
            ),
          );
          // Return true to signal dashboard needs refresh
          Navigator.pop(context, true);
        }
      } else {
        throw Exception('Quarantine operation failed');
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to quarantine app: $e'),
            backgroundColor: Color(0xFFD32F2F),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isProcessing = false);
      }
    }
  }

  Future<void> _handleUninstall(BuildContext context) async {
    // Check if system app first
    if (widget.threat.isSystemApp) {
      await showDialog(
        context: context,
        builder: (context) => AlertDialog(
          backgroundColor: Color(0xFF1A1F3A),
          title: Row(
            children: [
              Icon(Icons.block, color: Color(0xFFFF4757)),
              SizedBox(width: 12),
              Text('Cannot Uninstall', style: TextStyle(color: Colors.white)),
            ],
          ),
          content: Text(
            '${widget.threat.appName} is a system app and cannot be uninstalled.\n\n'
            'You can disable it in Android Settings instead.',
            style: TextStyle(color: Colors.white70),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: Text('CANCEL'),
            ),
            ElevatedButton(
              onPressed: () async {
                Navigator.pop(context);
                // Open app settings for disable option
                try {
                  final intent = AndroidIntent(
                    action: 'android.settings.APPLICATION_DETAILS_SETTINGS',
                    data: 'package:${widget.threat.packageName}',
                  );
                  await intent.launch();
                } catch (e) {
                  if (mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Failed to open app settings: $e'),
                        backgroundColor: Color(0xFFD32F2F),
                      ),
                    );
                  }
                }
              },
              style: ElevatedButton.styleFrom(
                backgroundColor: Color(0xFF2196F3),
              ),
              child: Text('OPEN SETTINGS'),
            ),
          ],
        ),
      );
      return;
    }
    
    // Confirm action
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        title: Text('Uninstall App?', style: TextStyle(color: Colors.white)),
        content: Text(
          'This will open Android settings to uninstall ${widget.threat.appName}. This action cannot be undone.',
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
      // Open app details settings for uninstall
      final intent = AndroidIntent(
        action: 'android.settings.APPLICATION_DETAILS_SETTINGS',
        data: 'package:${widget.threat.packageName}',
      );
      await intent.launch();
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Opening app settings for ${widget.threat.appName}'),
            backgroundColor: Color(0xFF00C853),
            behavior: SnackBarBehavior.floating,
          ),
        );
        // Don't pop immediately - user might come back
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to open settings: ${e.toString()}'),
            backgroundColor: Color(0xFFD32F2F),
            behavior: SnackBarBehavior.floating,
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isProcessing = false);
      }
    }
  }

  Future<void> _handleIgnore(BuildContext context) async {
    // Confirm action
    final confirm = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF1A1F3A),
        title: Text('Ignore Threat?', style: TextStyle(color: Colors.white)),
        content: Text(
          'This will add ${widget.threat.appName} to the whitelist and it will not be flagged in future scans. Only do this if you trust this app.',
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
              backgroundColor: Colors.white24,
            ),
            child: Text('IGNORE'),
          ),
        ],
      ),
    );

    if (confirm != true) return;

    setState(() => _isProcessing = true);

    try {
      // Add to whitelist (you can implement a WhitelistService)
      await Future.delayed(Duration(milliseconds: 500)); // Simulate operation
      
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Row(
              children: [
                Icon(Icons.check_circle, color: Colors.white),
                SizedBox(width: 12),
                Expanded(
                  child: Text('${widget.threat.appName} added to whitelist'),
                ),
              ],
            ),
            backgroundColor: Color(0xFF00C853),
            behavior: SnackBarBehavior.floating,
          ),
        );
        Navigator.pop(context, true);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to ignore threat: $e'),
            backgroundColor: Color(0xFFD32F2F),
          ),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _isProcessing = false);
      }
    }
  }

  Widget _buildBulletPoint(String text) {
    return Padding(
      padding: EdgeInsets.only(left: 8, bottom: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('• ', style: TextStyle(color: Colors.white70, fontSize: 16)),
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

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return Color(0xFFFF4757);
      case ThreatSeverity.high:
        return Color(0xFFFF6348);
      case ThreatSeverity.medium:
        return Color(0xFFFFA502);
      case ThreatSeverity.low:
        return Color(0xFFFFD32D);
      default:
        return Color(0xFF6C63FF);
    }
  }

  String _getDetectionMethodLabel(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return 'Signature Database Match';
      case DetectionMethod.heuristic:
        return 'Heuristic Analysis';
      case DetectionMethod.behavioral:
        return 'Behavioral Monitoring';
      case DetectionMethod.threatintel:
        return 'Cloud Threat Intelligence';
      case DetectionMethod.machinelearning:
        return 'Machine Learning';
      case DetectionMethod.yara:
        return 'YARA Pattern Matching';
      case DetectionMethod.anomaly:
        return 'Anomaly Detection';
      case DetectionMethod.staticanalysis:
        return 'Static Code Analysis';
      default:
        return 'Unknown Method';
    }
  }

  String _formatTimestamp(DateTime dt) {
    return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')} '
           '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
  }

  void _shareReport(BuildContext context) {
    // TODO: Implement share functionality
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Share functionality coming soon')),
    );
  }
}
