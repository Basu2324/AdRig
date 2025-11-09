import 'package:flutter/material.dart';
import 'package:flutter/gestures.dart';
import 'package:url_launcher/url_launcher.dart';

/// Privacy Policy Consent Dialog
class PrivacyConsentDialog extends StatefulWidget {
  const PrivacyConsentDialog({Key? key}) : super(key: key);

  @override
  State<PrivacyConsentDialog> createState() => _PrivacyConsentDialogState();
}

class _PrivacyConsentDialogState extends State<PrivacyConsentDialog> {
  bool _acceptedPrivacy = false;
  bool _acceptedTerms = false;

  @override
  Widget build(BuildContext context) {
    return Dialog(
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(20),
      ),
      child: Container(
        constraints: BoxConstraints(maxWidth: 500, maxHeight: 600),
        padding: EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Row(
              children: [
                Icon(
                  Icons.privacy_tip,
                  color: Colors.blue,
                  size: 32,
                ),
                SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Privacy & Terms',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
            SizedBox(height: 24),

            // Content
            Expanded(
              child: SingleChildScrollView(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Welcome to AdRig!',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    SizedBox(height: 12),
                    Text(
                      'Before you continue, please review and accept our Privacy Policy and Terms of Service.',
                      style: TextStyle(
                        fontSize: 14,
                        color: Colors.grey.shade700,
                      ),
                    ),
                    SizedBox(height: 24),

                    // Privacy highlights
                    _buildInfoSection(
                      icon: Icons.security,
                      title: 'Your Privacy Matters',
                      description:
                          'We collect only necessary data to protect your device. Your scan results are stored locally and encrypted.',
                    ),
                    SizedBox(height: 16),

                    _buildInfoSection(
                      icon: Icons.storage,
                      title: 'Data We Collect',
                      description:
                          'Device info, app permissions, scan results, and usage statistics to improve threat detection.',
                    ),
                    SizedBox(height: 16),

                    _buildInfoSection(
                      icon: Icons.share_outlined,
                      title: 'Data Sharing',
                      description:
                          'We never sell your data. Anonymous threat data may be shared with security partners to improve detection.',
                    ),
                    SizedBox(height: 16),

                    _buildInfoSection(
                      icon: Icons.delete_outline,
                      title: 'Your Rights',
                      description:
                          'You can delete your account and all associated data at any time from the Profile screen.',
                    ),
                  ],
                ),
              ),
            ),
            SizedBox(height: 24),

            // Checkboxes
            CheckboxListTile(
              value: _acceptedPrivacy,
              onChanged: (value) {
                setState(() => _acceptedPrivacy = value ?? false);
              },
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: RichText(
                text: TextSpan(
                  style: TextStyle(
                    fontSize: 13,
                    color: Colors.black87,
                  ),
                  children: [
                    TextSpan(text: 'I have read and accept the '),
                    TextSpan(
                      text: 'Privacy Policy',
                      style: TextStyle(
                        color: Colors.blue,
                        decoration: TextDecoration.underline,
                      ),
                      recognizer: TapGestureRecognizer()
                        ..onTap = () => _openUrl('privacy'),
                    ),
                  ],
                ),
              ),
            ),

            CheckboxListTile(
              value: _acceptedTerms,
              onChanged: (value) {
                setState(() => _acceptedTerms = value ?? false);
              },
              contentPadding: EdgeInsets.zero,
              controlAffinity: ListTileControlAffinity.leading,
              title: RichText(
                text: TextSpan(
                  style: TextStyle(
                    fontSize: 13,
                    color: Colors.black87,
                  ),
                  children: [
                    TextSpan(text: 'I agree to the '),
                    TextSpan(
                      text: 'Terms of Service',
                      style: TextStyle(
                        color: Colors.blue,
                        decoration: TextDecoration.underline,
                      ),
                      recognizer: TapGestureRecognizer()
                        ..onTap = () => _openUrl('terms'),
                    ),
                  ],
                ),
              ),
            ),
            SizedBox(height: 24),

            // Buttons
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () {
                      Navigator.of(context).pop(false);
                    },
                    style: OutlinedButton.styleFrom(
                      padding: EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: Text('Decline'),
                  ),
                ),
                SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: ElevatedButton(
                    onPressed: (_acceptedPrivacy && _acceptedTerms)
                        ? () {
                            Navigator.of(context).pop(true);
                          }
                        : null,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blue.shade700,
                      foregroundColor: Colors.white,
                      padding: EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: Text(
                      'Accept & Continue',
                      style: TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoSection({
    required IconData icon,
    required String title,
    required String description,
  }) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          padding: EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Colors.blue.shade50,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(icon, color: Colors.blue, size: 20),
        ),
        SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                title,
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                ),
              ),
              SizedBox(height: 4),
              Text(
                description,
                style: TextStyle(
                  fontSize: 12,
                  color: Colors.grey.shade600,
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  void _openUrl(String type) {
    // TODO: Replace with actual URLs
    final url = type == 'privacy'
        ? 'https://adrig.app/privacy'
        : 'https://adrig.app/terms';
    
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text('Opening $type policy...'),
        duration: Duration(seconds: 1),
      ),
    );
    // launchUrl(Uri.parse(url));
  }
}
