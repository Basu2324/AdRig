import 'package:flutter/material.dart';
import 'package:adrig/services/threat_history_service.dart';
import 'package:adrig/core/models/threat_model.dart';
import 'package:adrig/screens/threat_detail_screen.dart';

/// Screen to display all threats filtered by category
class ThreatListScreen extends StatefulWidget {
  final String category;

  const ThreatListScreen({
    Key? key,
    required this.category,
  }) : super(key: key);

  @override
  State<ThreatListScreen> createState() => _ThreatListScreenState();
}

class _ThreatListScreenState extends State<ThreatListScreen> {
  final ThreatHistoryService _historyService = ThreatHistoryService();
  List<DetectedThreat> _threats = [];
  bool _isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadThreats();
  }

  Future<void> _loadThreats() async {
    print('📋 ThreatListScreen: Loading threats for category: ${widget.category}');
    setState(() => _isLoading = true);

    try {
      // Get all scan results
      final scanResults = await _historyService.getAllScanResults();
      print('   Found ${scanResults.length} scan result(s)');
      
      final List<DetectedThreat> allThreats = [];

      // Extract threats from all scans
      for (final scan in scanResults) {
        final threats = scan['threats'] as List<dynamic>;
        print('   Scan has ${threats.length} threat(s)');

        for (final threatData in threats) {
          // Convert back to DetectedThreat
          final threat = DetectedThreat(
            id: threatData['id'] as String,
            appName: threatData['appName'] as String,
            packageName: threatData['packageName'] as String,
            description: threatData['description'] as String,
            severity: _parseSeverity(threatData['severity'] as String),
            threatType: _parseThreatType(threatData['threatType'] as String),
            detectionMethod: _parseDetectionMethod(threatData['detectionMethod'] as String),
            confidence: (threatData['confidence'] as num).toDouble(),
            detectedAt: DateTime.fromMillisecondsSinceEpoch(threatData['detectedAt'] as int),
            recommendedAction: ActionType.quarantine,
            indicators: [],
            metadata: {},
          );

          allThreats.add(threat);
        }
      }

      print('   Total threats before filtering: ${allThreats.length}');

      // Filter by category
      final filteredThreats = _filterThreatsByCategory(allThreats, widget.category);

      print('   Filtered threats for ${widget.category}: ${filteredThreats.length}');

      setState(() {
        _threats = filteredThreats;
        _isLoading = false;
      });
    } catch (e) {
      debugPrint('Error loading threats: $e');
      setState(() => _isLoading = false);
    }
  }

  List<DetectedThreat> _filterThreatsByCategory(List<DetectedThreat> threats, String category) {
    switch (category) {
      case 'Apps':
        // Return all app-based malware threats
        return threats.where((t) {
          final type = t.threatType.toString().toLowerCase();
          return type.contains('malware') || 
                 type.contains('trojan') || 
                 type.contains('spyware') || 
                 type.contains('adware') ||
                 type.contains('pua') || 
                 type.contains('ransomware') ||
                 type.contains('backdoor') || 
                 type.contains('dropper');
        }).toList();

      case 'AI Detected':
        // Return threats detected by AI/ML
        return threats.where((t) {
          final method = t.detectionMethod.toString().toLowerCase();
          return method.contains('machinelearning') || 
                 method.contains('behavioral') ||
                 method.contains('anomaly');
        }).toList();

      case 'Wi-Fi Networks':
      case 'Internet':
      case 'Devices':
      case 'Files':
        // For future: these categories will have their own detection logic
        return [];

      default:
        return threats;
    }
  }

  ThreatSeverity _parseSeverity(String severity) {
    switch (severity.split('.').last) {
      case 'critical':
        return ThreatSeverity.critical;
      case 'high':
        return ThreatSeverity.high;
      case 'medium':
        return ThreatSeverity.medium;
      case 'low':
        return ThreatSeverity.low;
      default:
        return ThreatSeverity.low;
    }
  }

  ThreatType _parseThreatType(String type) {
    switch (type.split('.').last) {
      case 'malware':
        return ThreatType.malware;
      case 'trojan':
        return ThreatType.trojan;
      case 'spyware':
        return ThreatType.spyware;
      case 'adware':
        return ThreatType.adware;
      case 'ransomware':
        return ThreatType.ransomware;
      case 'pua':
        return ThreatType.pua;
      case 'backdoor':
        return ThreatType.backdoor;
      case 'rootkit':
        return ThreatType.rootkit;
      case 'dropper':
        return ThreatType.dropper;
      case 'exploit':
        return ThreatType.exploit;
      case 'suspicious':
        return ThreatType.suspicious;
      case 'anomaly':
        return ThreatType.anomaly;
      default:
        return ThreatType.suspicious;
    }
  }

  DetectionMethod _parseDetectionMethod(String method) {
    switch (method.split('.').last) {
      case 'signature':
        return DetectionMethod.signature;
      case 'heuristic':
        return DetectionMethod.heuristic;
      case 'behavioral':
        return DetectionMethod.behavioral;
      case 'machinelearning':
        return DetectionMethod.machinelearning;
      case 'threatintel':
        return DetectionMethod.threatintel;
      case 'yara':
        return DetectionMethod.yara;
      case 'anomaly':
        return DetectionMethod.anomaly;
      case 'staticanalysis':
        return DetectionMethod.staticanalysis;
      default:
        return DetectionMethod.heuristic;
    }
  }

  Color _getSeverityColor(ThreatSeverity severity) {
    switch (severity) {
      case ThreatSeverity.critical:
        return const Color(0xFFFF0000);
      case ThreatSeverity.high:
        return const Color(0xFFFF4757);
      case ThreatSeverity.medium:
        return const Color(0xFFFF9500);
      case ThreatSeverity.low:
        return const Color(0xFFFFD700);
      case ThreatSeverity.info:
        return const Color(0xFF00D9FF);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: const Color(0xFF0A0E27),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          widget.category,
          style: const TextStyle(
            color: Colors.white,
            fontSize: 20,
            fontWeight: FontWeight.bold,
          ),
        ),
        actions: [
          if (_threats.isNotEmpty)
            IconButton(
              icon: Icon(Icons.delete_sweep, color: Colors.red),
              tooltip: 'Clear All Threats',
              onPressed: _showClearAllConfirmation,
            ),
        ],
      ),
      body: _isLoading
          ? const Center(
              child: CircularProgressIndicator(
                color: Color(0xFF00D9FF),
              ),
            )
          : _threats.isEmpty
              ? _buildEmptyState()
              : _buildThreatsList(),
      floatingActionButton: _threats.isNotEmpty
          ? FloatingActionButton.extended(
              backgroundColor: Color(0xFFFF4757),
              onPressed: _showClearAllConfirmation,
              icon: Icon(Icons.delete_forever),
              label: Text('Clear All (${_threats.length})'),
            )
          : null,
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 100,
            height: 100,
            decoration: BoxDecoration(
              color: const Color(0xFF00C853).withOpacity(0.2),
              shape: BoxShape.circle,
            ),
            child: const Icon(
              Icons.check_circle,
              color: Color(0xFF00C853),
              size: 50,
            ),
          ),
          const SizedBox(height: 24),
          const Text(
            'No threats detected',
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            'Your ${widget.category.toLowerCase()} ${widget.category == 'Apps' ? 'are' : 'is'} safe',
            style: const TextStyle(
              fontSize: 14,
              color: Colors.white60,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildThreatsList() {
    // Sort by severity (critical first) then by date (newest first)
    _threats.sort((a, b) {
      final severityCompare = b.severity.index.compareTo(a.severity.index);
      if (severityCompare != 0) return severityCompare;
      return b.detectedAt.compareTo(a.detectedAt);
    });

    return Column(
      children: [
        // Header with count
        Container(
          margin: const EdgeInsets.all(16),
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0xFFFF4757).withOpacity(0.1),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: const Color(0xFFFF4757).withOpacity(0.3),
              width: 1,
            ),
          ),
          child: Row(
            children: [
              const Icon(
                Icons.warning_rounded,
                color: Color(0xFFFF4757),
                size: 24,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${_threats.length} threat${_threats.length > 1 ? 's' : ''} detected',
                      style: const TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Last 90 days',
                      style: TextStyle(
                        fontSize: 12,
                        color: Colors.white60,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),

        // Threats list
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            itemCount: _threats.length,
            itemBuilder: (context, index) {
              final threat = _threats[index];
              return _buildThreatCard(threat);
            },
          ),
        ),
      ],
    );
  }

  Widget _buildThreatCard(DetectedThreat threat) {
    final severityColor = _getSeverityColor(threat.severity);
    final severityLabel = threat.severity.toString().split('.').last.toUpperCase();

    return InkWell(
      onTap: () async {
        print('👆 User tapped threat: ${threat.appName}');
        
        // Navigate and wait for result
        final result = await Navigator.push(
          context,
          MaterialPageRoute(
            builder: (context) => ThreatDetailScreen(threat: threat),
          ),
        );
        
        print('⬅️ Returned from threat detail, result: $result');
        
        // If threat was quarantined, reload the list
        if (result == true) {
          print('🔄 Reloading threat list...');
          _loadThreats();
        }
      },
      child: Container(
        margin: const EdgeInsets.only(bottom: 12),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF151933),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: severityColor.withOpacity(0.3),
            width: 1,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                // Severity badge
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: severityColor.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: severityColor.withOpacity(0.5),
                      width: 1,
                    ),
                  ),
                  child: Text(
                    severityLabel,
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                      color: severityColor,
                      letterSpacing: 0.5,
                    ),
                  ),
                ),
                const Spacer(),
                // Confidence indicator
                Row(
                  children: [
                    Icon(
                      Icons.bar_chart,
                      color: Colors.white.withOpacity(0.5),
                      size: 14,
                    ),
                    const SizedBox(width: 4),
                    Text(
                      '${(threat.confidence * 100).toInt()}%',
                      style: const TextStyle(
                        fontSize: 12,
                        color: Colors.white60,
                      ),
                    ),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 12),
            // App name
            Text(
              threat.appName,
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 6),
            // Package name
            Text(
              threat.packageName,
              style: const TextStyle(
                fontSize: 12,
                color: Colors.white60,
                fontFamily: 'monospace',
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 8),
            // Description
            Text(
              threat.description,
              style: const TextStyle(
                fontSize: 13,
                color: Colors.white70,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 12),
            // Footer row
            Row(
              children: [
                Icon(
                  _getDetectionMethodIcon(threat.detectionMethod),
                  color: Colors.white.withOpacity(0.5),
                  size: 14,
                ),
                const SizedBox(width: 4),
                Text(
                  _getDetectionMethodLabel(threat.detectionMethod),
                  style: const TextStyle(
                    fontSize: 11,
                    color: Colors.white60,
                  ),
                ),
                const Spacer(),
                Text(
                  _formatDate(threat.detectedAt),
                  style: const TextStyle(
                    fontSize: 11,
                    color: Colors.white60,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  IconData _getDetectionMethodIcon(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return Icons.fingerprint;
      case DetectionMethod.heuristic:
        return Icons.radar;
      case DetectionMethod.behavioral:
        return Icons.psychology;
      case DetectionMethod.ml:
        return Icons.smart_toy;
      case DetectionMethod.machinelearning:
        return Icons.smart_toy;
      case DetectionMethod.threatintel:
        return Icons.cloud;
      case DetectionMethod.yara:
        return Icons.search;
      case DetectionMethod.anomaly:
        return Icons.warning_amber;
      case DetectionMethod.staticanalysis:
        return Icons.find_in_page;
    }
  }

  String _getDetectionMethodLabel(DetectionMethod method) {
    switch (method) {
      case DetectionMethod.signature:
        return 'Signature';
      case DetectionMethod.heuristic:
        return 'Heuristic';
      case DetectionMethod.behavioral:
        return 'Behavioral';
      case DetectionMethod.ml:
        return 'AI Detection';
      case DetectionMethod.machinelearning:
        return 'AI Detection';
      case DetectionMethod.threatintel:
        return 'Threat Intel';
      case DetectionMethod.yara:
        return 'YARA';
      case DetectionMethod.anomaly:
        return 'Anomaly';
      case DetectionMethod.staticanalysis:
        return 'Static Analysis';
    }
  }

  String _formatDate(DateTime date) {
    final now = DateTime.now();
    final diff = now.difference(date);

    if (diff.inDays == 0) {
      if (diff.inHours == 0) {
        return '${diff.inMinutes}m ago';
      }
      return '${diff.inHours}h ago';
    } else if (diff.inDays < 7) {
      return '${diff.inDays}d ago';
    } else if (diff.inDays < 30) {
      return '${(diff.inDays / 7).floor()}w ago';
    } else {
      return '${date.day}/${date.month}/${date.year}';
    }
  }

  void _showClearAllConfirmation() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Row(
          children: [
            Icon(Icons.warning_amber_rounded, color: Colors.orange),
            SizedBox(width: 12),
            Text('Clear All Threats?', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Text(
          'This will permanently delete all ${_threats.length} threat records in this category.\n\nThis action cannot be undone.',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL', style: TextStyle(color: Colors.white70)),
          ),
          ElevatedButton(
            onPressed: () async {
              Navigator.pop(context); // Close dialog
              await _clearAllThreats();
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('DELETE ALL'),
          ),
        ],
      ),
    );
  }

  Future<void> _clearAllThreats() async {
    // Show loading
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (context) => Center(
        child: Container(
          padding: EdgeInsets.all(32),
          decoration: BoxDecoration(
            color: Color(0xFF151933),
            borderRadius: BorderRadius.circular(16),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              CircularProgressIndicator(color: Color(0xFF6C63FF)),
              SizedBox(height: 16),
              Text(
                'Clearing ${_threats.length} threats...',
                style: TextStyle(color: Colors.white),
              ),
            ],
          ),
        ),
      ),
    );

    try {
      // Delete all scan results (which contain threats)
      await _historyService.clearAllScanResults();
      
      Navigator.pop(context); // Close loading
      Navigator.pop(context); // Go back to dashboard
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('✅ All threats cleared successfully'),
          backgroundColor: Colors.green,
          duration: Duration(seconds: 2),
        ),
      );
    } catch (e) {
      Navigator.pop(context); // Close loading
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('❌ Failed to clear threats: $e'),
          backgroundColor: Colors.red,
          duration: Duration(seconds: 3),
        ),
      );
    }
  }
}
