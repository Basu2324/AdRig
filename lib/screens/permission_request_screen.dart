import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import '../services/permission_service.dart';
import 'dashboard_screen.dart';

/// Permission request screen - shown on first launch
class PermissionRequestScreen extends StatefulWidget {
  const PermissionRequestScreen({Key? key}) : super(key: key);

  @override
  State<PermissionRequestScreen> createState() => _PermissionRequestScreenState();
}

class _PermissionRequestScreenState extends State<PermissionRequestScreen> {
  final PermissionService _permissionService = PermissionService();
  bool _isRequesting = false;
  Map<String, bool>? _permissionStatus;
  String? _errorMessage;

  @override
  void initState() {
    super.initState();
    _checkExistingPermissions();
  }

  Future<void> _checkExistingPermissions() async {
    final status = await _permissionService.getPermissionReport();
    setState(() {
      _permissionStatus = status;
    });
  }

  Future<void> _requestAllPermissions() async {
    setState(() {
      _isRequesting = true;
      _errorMessage = null;
    });

    try {
      // Request standard permissions first
      final granted = await _permissionService.requestAllPermissions();
      
      // Check if we need to request MANAGE_EXTERNAL_STORAGE separately
      final needsStorageSettings = !(_permissionStatus?['manage_storage'] ?? false);
      
      if (granted && !needsStorageSettings) {
        // All permissions granted, navigate to dashboard
        if (mounted) {
          Navigator.of(context).pushReplacement(
            MaterialPageRoute(builder: (_) => const DashboardScreen()),
          );
        }
      } else if (needsStorageSettings) {
        // Show dialog for storage permission
        if (mounted) {
          final shouldOpenSettings = await showDialog<bool>(
            context: context,
            builder: (context) => AlertDialog(
              backgroundColor: const Color(0xFF151933),
              title: const Text(
                'Storage Access Required',
                style: TextStyle(color: Colors.white),
              ),
              content: const Text(
                'For complete malware scanning, AdRig needs "All files access" permission.\n\nThis will open Settings where you can:\n1. Find "AdRig Security"\n2. Tap "Files and media"\n3. Select "Allow management of all files"',
                style: TextStyle(color: Colors.white70),
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: const Text('Later'),
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
            await _openSettings();
          } else {
            // User declined, but update status
            final status = await _permissionService.getPermissionReport();
            setState(() {
              _permissionStatus = status;
              _errorMessage = 'Storage permission needed for full scanning capability.';
              _isRequesting = false;
            });
          }
        }
      } else {
        // Some permissions denied
        final status = await _permissionService.getPermissionReport();
        setState(() {
          _permissionStatus = status;
          _errorMessage = 'Some permissions were denied. Grant them for full protection.';
        });
      }
    } catch (e) {
      print('❌ Permission request error: $e');
      setState(() {
        _errorMessage = 'Error: ${e.toString()}';
      });
    } finally {
      if (mounted) {
        setState(() {
          _isRequesting = false;
        });
      }
    }
  }

  Future<void> _openSettings() async {
    await _permissionService.openSettings();
    // Recheck permissions when user returns
    await Future.delayed(const Duration(milliseconds: 500));
    await _checkExistingPermissions();
  }

  Future<void> _requestStoragePermissionIndividually() async {
    print('📂 _requestStoragePermissionIndividually() START');
    setState(() {
      _isRequesting = true;
      _errorMessage = null;
    });

    try {
      print('📂 Calling _permissionService.requestStoragePermission()...');
      // First try to request storage permission
      final granted = await _permissionService.requestStoragePermission();
      
      print('📂 requestStoragePermission returned: $granted');
      
      if (granted) {
        // Storage granted, update UI
        print('✅ Storage granted! Updating UI...');
        await _checkExistingPermissions();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('✅ Storage permission granted!'),
              backgroundColor: Colors.green,
              duration: Duration(seconds: 2),
            ),
          );
        }
      } else {
        // Need to open settings for MANAGE_EXTERNAL_STORAGE
        print('⚠️ Storage NOT granted, showing settings dialog...');
        if (mounted) {
          final shouldOpenSettings = await showDialog<bool>(
            context: context,
            barrierDismissible: false,
            builder: (context) => AlertDialog(
              backgroundColor: const Color(0xFF151933),
              title: Row(
                children: const [
                  Icon(Icons.folder_special, color: Color(0xFF6C63FF), size: 28),
                  SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      'Full Storage Access',
                      style: TextStyle(color: Colors.white, fontSize: 20),
                    ),
                  ),
                ],
              ),
              content: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: const [
                  Text(
                    'To scan all files and apps for malware, AdRig needs "All files access" permission.',
                    style: TextStyle(color: Colors.white70, fontSize: 15, height: 1.5),
                  ),
                  SizedBox(height: 16),
                  Text(
                    'Steps to grant permission:',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  SizedBox(height: 8),
                  Text(
                    '1. Tap "Open Settings" below',
                    style: TextStyle(color: Color(0xFF00D9FF), fontSize: 14),
                  ),
                  SizedBox(height: 4),
                  Text(
                    '2. Find "AdRig Security" in the list',
                    style: TextStyle(color: Color(0xFF00D9FF), fontSize: 14),
                  ),
                  SizedBox(height: 4),
                  Text(
                    '3. Tap "Files and media"',
                    style: TextStyle(color: Color(0xFF00D9FF), fontSize: 14),
                  ),
                  SizedBox(height: 4),
                  Text(
                    '4. Select "Allow management of all files"',
                    style: TextStyle(color: Color(0xFF00D9FF), fontSize: 14),
                  ),
                  SizedBox(height: 4),
                  Text(
                    '5. Return to this app',
                    style: TextStyle(color: Color(0xFF00D9FF), fontSize: 14),
                  ),
                ],
              ),
              actions: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(false),
                  child: const Text(
                    'Later',
                    style: TextStyle(color: Colors.white54),
                  ),
                ),
                ElevatedButton.icon(
                  onPressed: () => Navigator.of(context).pop(true),
                  icon: const Icon(Icons.settings, color: Colors.white),
                  label: const Text('Open Settings'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF6C63FF),
                    padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                  ),
                ),
              ],
            ),
          );
          
          if (shouldOpenSettings == true) {
            await _openSettings();
          }
        }
      }
    } catch (e) {
      print('❌ Storage permission error: $e');
      if (mounted) {
        setState(() {
          _errorMessage = 'Error requesting storage: ${e.toString()}';
        });
      }
    } finally {
      if (mounted) {
        setState(() {
          _isRequesting = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0A0E27),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 20),
              
              // App Icon
              Center(
                child: Container(
                  width: 100,
                  height: 100,
                  decoration: BoxDecoration(
                    color: const Color(0xFF6C63FF).withOpacity(0.2),
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(
                    Icons.security,
                    size: 50,
                    color: Color(0xFF6C63FF),
                  ),
                ),
              ),
              
              const SizedBox(height: 32),
              
              // Title
              const Text(
                'Permissions Required',
                style: TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              
              const SizedBox(height: 12),
              
              // Description
              const Text(
                'AdRig needs the following permissions to scan your device for malware and protect you from threats.',
                style: TextStyle(
                  fontSize: 16,
                  color: Colors.white70,
                  height: 1.5,
                ),
              ),
              
              const SizedBox(height: 32),
              
              // Permission List
              _buildPermissionItem(
                Icons.folder_open,
                'Storage Access',
                'Scan files and APKs for malware',
                (_permissionStatus?['storage'] ?? false) && (_permissionStatus?['manage_storage'] ?? false),
                true,
              ),
              
              _buildPermissionItem(
                Icons.apps,
                'App Information',
                'Analyze installed apps for threats',
                true, // Manifest permission
                true,
              ),
              
              _buildPermissionItem(
                Icons.notifications,
                'Notifications',
                'Alert you about detected threats',
                _permissionStatus?['notification'] ?? false,
                true,
              ),
              
              _buildPermissionItem(
                Icons.phone,
                'Phone State',
                'Detect suspicious call activities',
                _permissionStatus?['phone'] ?? false,
                false,
              ),
              
              _buildPermissionItem(
                Icons.message,
                'SMS Access',
                'Scan for phishing messages',
                _permissionStatus?['sms'] ?? false,
                false,
              ),
              
              _buildPermissionItem(
                Icons.location_on,
                'Location',
                'Detect location-based threats',
                _permissionStatus?['location'] ?? false,
                false,
              ),
              
              _buildPermissionItem(
                Icons.camera,
                'Camera',
                'Scan QR codes for security',
                _permissionStatus?['camera'] ?? false,
                false,
              ),
              
              _buildPermissionItem(
                Icons.contacts,
                'Contacts',
                'Identify data leak attempts',
                _permissionStatus?['contacts'] ?? false,
                false,
              ),
              
              const SizedBox(height: 24),
              
              // Error message
              if (_errorMessage != null)
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.orange.withOpacity(0.2),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.orange),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.warning, color: Colors.orange),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          _errorMessage!,
                          style: const TextStyle(color: Colors.orange),
                        ),
                      ),
                    ],
                  ),
                ),
              
              const SizedBox(height: 24),
              
              // Grant Permissions Button
              SizedBox(
                width: double.infinity,
                height: 56,
                child: ElevatedButton(
                  onPressed: _isRequesting ? null : _requestAllPermissions,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFF6C63FF),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: _isRequesting
                      ? const SizedBox(
                          width: 24,
                          height: 24,
                          child: CircularProgressIndicator(
                            color: Colors.white,
                            strokeWidth: 2,
                          ),
                        )
                      : const Text(
                          'Grant Permissions',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                ),
              ),
              
              const SizedBox(height: 16),
              
              // Open Settings Button
              SizedBox(
                width: double.infinity,
                height: 56,
                child: OutlinedButton(
                  onPressed: _openSettings,
                  style: OutlinedButton.styleFrom(
                    side: const BorderSide(color: Color(0xFF6C63FF)),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  child: const Text(
                    'Open Settings',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.bold,
                      color: Color(0xFF6C63FF),
                    ),
                  ),
                ),
              ),
              
              const SizedBox(height: 16),
              
              // Skip Button - Small text button
              Center(
                child: TextButton(
                  onPressed: () {
                    Navigator.of(context).pushReplacement(
                      MaterialPageRoute(builder: (_) => const DashboardScreen()),
                    );
                  },
                  child: const Text(
                    'I\'ll grant permissions later',
                    style: TextStyle(
                      color: Colors.white54,
                      decoration: TextDecoration.underline,
                    ),
                  ),
                ),
              ),
              
              const SizedBox(height: 24),
              
              // Privacy Note
              Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.05),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Row(
                  children: const [
                    Icon(Icons.privacy_tip, color: Colors.white54, size: 20),
                    SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        'Your privacy is protected. All scanning is done locally on your device.',
                        style: TextStyle(
                          fontSize: 12,
                          color: Colors.white54,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPermissionItem(
    IconData icon,
    String title,
    String description,
    bool isGranted,
    bool isRequired,
  ) {
    // Determine which permission this is based on title
    final isStoragePermission = title == 'Storage Access';
    
    // Debug logging
    if (isStoragePermission) {
      print('🔍 Storage Permission Card: isGranted=$isGranted (storage: ${_permissionStatus?['storage']}, manage: ${_permissionStatus?['manage_storage']})');
    }
    
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: isGranted ? null : () async {
          print('🔵 TAPPED: $title (isGranted=$isGranted)');
          
          // Handle individual permission request
          if (isStoragePermission) {
            print('📂 Calling _requestStoragePermissionIndividually()');
            await _requestStoragePermissionIndividually();
          } else {
            print('📋 Calling _requestAllPermissions()');
            await _requestAllPermissions();
          }
        },
        borderRadius: BorderRadius.circular(12),
        splashColor: const Color(0xFF6C63FF).withOpacity(0.3),
        highlightColor: const Color(0xFF6C63FF).withOpacity(0.1),
        child: Container(
          margin: const EdgeInsets.only(bottom: 16),
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0xFF151933),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(
              color: isGranted 
                  ? Colors.green.withOpacity(0.5)
                  : (isRequired ? Colors.orange.withOpacity(0.5) : Colors.white.withOpacity(0.1)),
              width: isGranted ? 2 : 1,
            ),
            // Add subtle shadow for clickable items
            boxShadow: !isGranted ? [
              BoxShadow(
                color: const Color(0xFF6C63FF).withOpacity(0.1),
                blurRadius: 8,
                offset: const Offset(0, 2),
              ),
            ] : null,
          ),
          child: Row(
            children: [
              Container(
                width: 48,
                height: 48,
                decoration: BoxDecoration(
                  color: const Color(0xFF6C63FF).withOpacity(0.2),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(icon, color: const Color(0xFF6C63FF)),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(
                          title,
                          style: const TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                        if (isRequired)
                          Container(
                            margin: const EdgeInsets.only(left: 8),
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: Colors.orange.withOpacity(0.2),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: const Text(
                              'REQUIRED',
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.bold,
                                color: Colors.orange,
                              ),
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Text(
                      description,
                      style: const TextStyle(
                        fontSize: 13,
                        color: Colors.white60,
                      ),
                    ),
                    // Add "TAP TO ENABLE" for storage if not granted
                    if (isStoragePermission && !isGranted)
                      Padding(
                        padding: const EdgeInsets.only(top: 6),
                        child: Row(
                          children: const [
                            Icon(Icons.touch_app, size: 14, color: Color(0xFF00D9FF)),
                            SizedBox(width: 4),
                            Text(
                              'TAP TO ENABLE',
                              style: TextStyle(
                                fontSize: 11,
                                fontWeight: FontWeight.bold,
                                color: Color(0xFF00D9FF),
                                letterSpacing: 0.5,
                              ),
                            ),
                          ],
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              Icon(
                isGranted ? Icons.check_circle : Icons.circle_outlined,
                color: isGranted ? Colors.green : Colors.white30,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
