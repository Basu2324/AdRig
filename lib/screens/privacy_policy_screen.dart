import 'package:flutter/material.dart';

/// Privacy Policy Screen - Display app privacy policy
class PrivacyPolicyScreen extends StatelessWidget {
  const PrivacyPolicyScreen({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Color(0xFF0A0E27),
      appBar: AppBar(
        backgroundColor: Color(0xFF0A0E27),
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.arrow_back, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: Text(
          'Privacy Policy',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(20),
        children: [
          // Header
          Container(
            padding: EdgeInsets.all(20),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [Color(0xFF6C63FF), Color(0xFF4834DF)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(16),
            ),
            child: Column(
              children: [
                Icon(Icons.policy, size: 60, color: Colors.white),
                SizedBox(height: 16),
                Text(
                  'AdRig Privacy Policy',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  'Last Updated: November 2025',
                  style: TextStyle(color: Colors.white70, fontSize: 14),
                ),
              ],
            ),
          ),

          SizedBox(height: 24),

          _buildSection(
            title: '1. Information We Collect',
            content: '''We collect minimal data necessary to provide malware protection:

• App Information: Package names, versions, signatures of installed apps (for malware detection)
• Scan Results: Detected threats and risk scores (anonymous)
• Crash Reports: Error logs to fix bugs (if enabled)
• Usage Statistics: Feature usage patterns (if enabled)

We do NOT collect personal information, messages, photos, contacts, or location data.''',
          ),

          _buildSection(
            title: '2. How We Use Your Data',
            content: '''Your data is used exclusively to:

• Detect and protect against malware
• Improve detection accuracy
• Fix bugs and crashes
• Enhance app performance
• Update malware signatures

We never sell or share your data with third parties for advertising.''',
          ),

          _buildSection(
            title: '3. Data Storage & Security',
            content: '''• All data is encrypted in transit and at rest
• Scan history stored locally on your device
• Cloud data (if enabled) is anonymized
• You can delete all data anytime from Settings
• Data retention: 90 days for scan history''',
          ),

          _buildSection(
            title: '4. Third-Party Services',
            content: '''We may use:

• Firebase: Crash reporting and analytics (Google)
• Cloud Reputation: Malware hash checking (anonymous)

These services have their own privacy policies.''',
          ),

          _buildSection(
            title: '5. Your Privacy Rights',
            content: '''You have the right to:

• Access your data
• Delete your data
• Opt-out of data collection
• Export your settings
• Request data corrections''',
          ),

          _buildSection(
            title: '6. Children\'s Privacy',
            content: '''AdRig does not knowingly collect data from children under 13. If you are a parent and believe your child provided us with information, please contact us.''',
          ),

          _buildSection(
            title: '7. Changes to This Policy',
            content: '''We may update this policy occasionally. We will notify you of significant changes through the app.''',
          ),

          _buildSection(
            title: '8. Contact Us',
            content: '''For privacy concerns or questions:

Email: privacy@adrig.app
Website: www.adrig.app/privacy

You can also manage data collection in Settings > Privacy & Security > Data Collection.''',
          ),

          SizedBox(height: 24),

          // Footer
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Color(0xFF151933),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.green.withOpacity(0.3)),
            ),
            child: Row(
              children: [
                Icon(Icons.verified_user, color: Colors.green, size: 24),
                SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Your privacy is our top priority. AdRig is designed with privacy-first principles.',
                    style: TextStyle(color: Colors.white70, fontSize: 13),
                  ),
                ),
              ],
            ),
          ),

          SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildSection({required String title, required String content}) {
    return Container(
      margin: EdgeInsets.only(bottom: 16),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              color: Color(0xFF6C63FF),
              fontSize: 16,
              fontWeight: FontWeight.bold,
            ),
          ),
          SizedBox(height: 12),
          Text(
            content,
            style: TextStyle(
              color: Colors.white70,
              fontSize: 14,
              height: 1.5,
            ),
          ),
        ],
      ),
    );
  }
}
