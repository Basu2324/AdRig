import 'package:flutter/material.dart';

class AboutScreen extends StatelessWidget {
  const AboutScreen({Key? key}) : super(key: key);

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
          'About',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(16),
        children: [
          // App Logo and Info
          Center(
            child: Column(
              children: [
                Container(
                  width: 100,
                  height: 100,
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      colors: [Color(0xFF2196F3), Color(0xFF0D47A1)],
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Center(
                    child: Text(
                      'AR',
                      style: TextStyle(
                        color: Colors.white,
                        fontSize: 40,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                ),
                SizedBox(height: 16),
                Text(
                  'AdRig',
                  style: TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                Text(
                  'Advanced Detection & Response',
                  style: TextStyle(
                    fontSize: 14,
                    color: Colors.white60,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  'Version 1.0.0 (Build 100)',
                  style: TextStyle(
                    fontSize: 12,
                    color: Colors.white.withOpacity(0.4),
                  ),
                ),
              ],
            ),
          ),
          
          SizedBox(height: 32),
          
          // About Description
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Color(0xFF151933),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: Colors.white10, width: 1),
            ),
            child: Text(
              'AdRig is a next-generation mobile security platform that combines advanced malware detection with AI-powered behavioral analysis. Protect your device from threats with real-time monitoring, cloud intelligence, and continuous learning.',
              style: TextStyle(
                color: Colors.white70,
                fontSize: 14,
                height: 1.6,
              ),
              textAlign: TextAlign.center,
            ),
          ),
          
          SizedBox(height: 24),
          
          // Legal Documents
          _buildSectionHeader('Legal'),
          _buildNavigationTile(
            icon: Icons.description_outlined,
            title: 'Terms of Service',
            onTap: () {
              _showDocument(context, 'Terms of Service', _termsOfService);
            },
          ),
          _buildNavigationTile(
            icon: Icons.shield_outlined,
            title: 'Privacy Policy',
            onTap: () {
              _showDocument(context, 'Privacy Policy', _privacyPolicy);
            },
          ),
          _buildNavigationTile(
            icon: Icons.gavel,
            title: 'End User License Agreement',
            onTap: () {
              _showDocument(context, 'EULA', _eula);
            },
          ),
          _buildNavigationTile(
            icon: Icons.security,
            title: 'Global Privacy Statement',
            onTap: () {
              _showDocument(context, 'Global Privacy Statement', _globalPrivacy);
            },
          ),
          
          SizedBox(height: 24),
          
          // Open Source
          _buildSectionHeader('Open Source'),
          _buildNavigationTile(
            icon: Icons.code,
            title: 'Open Source Licenses',
            onTap: () {
              Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => LicensePage(
                    applicationName: 'AdRig',
                    applicationVersion: '1.0.0',
                    applicationLegalese: '© 2025 AdRig Technologies. All rights reserved.',
                  ),
                ),
              );
            },
          ),
          _buildNavigationTile(
            icon: Icons.info_outline,
            title: 'Acknowledgements',
            onTap: () {
              _showAcknowledgements(context);
            },
          ),
          
          SizedBox(height: 24),
          
          // Feedback
          _buildSectionHeader('Feedback'),
          _buildNavigationTile(
            icon: Icons.star_outline,
            title: 'Rate the App',
            onTap: () {
              _showRatingDialog(context);
            },
          ),
          _buildNavigationTile(
            icon: Icons.share_outlined,
            title: 'Share with Friends',
            onTap: () {
              // TODO: Share app
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Share functionality coming soon'),
                  backgroundColor: Color(0xFF6C63FF),
                ),
              );
            },
          ),
          
          SizedBox(height: 32),
          
          // Copyright
          Center(
            child: Column(
              children: [
                Text(
                  '© 2025 AdRig Technologies',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.4),
                    fontSize: 12,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  'All rights reserved',
                  style: TextStyle(
                    color: Colors.white30,
                    fontSize: 11,
                  ),
                ),
                SizedBox(height: 16),
                Text(
                  'Made with ❤️ for your security',
                  style: TextStyle(
                    color: Colors.white30,
                    fontSize: 11,
                    fontStyle: FontStyle.italic,
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

  Widget _buildSectionHeader(String title) {
    return Padding(
      padding: EdgeInsets.only(left: 4, bottom: 12, top: 8),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.bold,
          color: Color(0xFF6C63FF),
          letterSpacing: 1.2,
        ),
      ),
    );
  }

  Widget _buildNavigationTile({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: ListTile(
        leading: Icon(icon, color: Color(0xFF6C63FF)),
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontSize: 15),
        ),
        trailing: Icon(Icons.chevron_right, color: Colors.white30),
        onTap: onTap,
      ),
    );
  }

  void _showDocument(BuildContext context, String title, String content) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text(title, style: TextStyle(color: Colors.white)),
        content: SingleChildScrollView(
          child: Text(
            content,
            style: TextStyle(color: Colors.white70, fontSize: 13, height: 1.5),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CLOSE'),
          ),
        ],
      ),
    );
  }

  void _showAcknowledgements(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text('Acknowledgements', style: TextStyle(color: Colors.white)),
        content: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'AdRig uses the following technologies:',
                style: TextStyle(color: Colors.white70, fontSize: 14),
              ),
              SizedBox(height: 16),
              _buildAckItem('Flutter', 'UI Framework'),
              _buildAckItem('TensorFlow Lite', 'AI/ML Engine'),
              _buildAckItem('YARA', 'Pattern Matching'),
              _buildAckItem('VirusTotal API', 'Cloud Reputation'),
              _buildAckItem('Provider', 'State Management'),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CLOSE'),
          ),
        ],
      ),
    );
  }

  Widget _buildAckItem(String name, String description) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.check_circle, color: Color(0xFF00C853), size: 16),
          SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 13,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  description,
                  style: TextStyle(
                    color: Colors.white60,
                    fontSize: 11,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showRatingDialog(BuildContext context) {
    int rating = 0;
    
    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          backgroundColor: Color(0xFF151933),
          title: Text('Rate AdRig', style: TextStyle(color: Colors.white)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'How would you rate your experience?',
                style: TextStyle(color: Colors.white70),
              ),
              SizedBox(height: 20),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: List.generate(5, (index) {
                  return IconButton(
                    icon: Icon(
                      index < rating ? Icons.star : Icons.star_border,
                      color: Color(0xFFFFD700),
                      size: 32,
                    ),
                    onPressed: () {
                      setState(() => rating = index + 1);
                    },
                  );
                }),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: Text('CANCEL'),
            ),
            ElevatedButton(
              onPressed: rating > 0 ? () {
                Navigator.pop(context);
                // TODO: Submit rating
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Thank you for your $rating-star rating!'),
                    backgroundColor: Color(0xFF00C853),
                  ),
                );
              } : null,
              style: ElevatedButton.styleFrom(
                backgroundColor: Color(0xFF6C63FF),
              ),
              child: Text('SUBMIT'),
            ),
          ],
        ),
      ),
    );
  }

  // Mock legal documents
  static const String _termsOfService = '''
TERMS OF SERVICE

Last updated: November 8, 2025

1. ACCEPTANCE OF TERMS
By downloading, installing, or using AdRig, you agree to be bound by these Terms of Service.

2. LICENSE GRANT
We grant you a limited, non-exclusive, non-transferable license to use AdRig on your personal devices.

3. USER RESPONSIBILITIES
You agree to use AdRig only for lawful purposes and in accordance with these Terms.

4. DISCLAIMER OF WARRANTIES
AdRig is provided "as is" without warranties of any kind, either express or implied.

5. LIMITATION OF LIABILITY
In no event shall AdRig Technologies be liable for any damages arising from the use of this software.

For complete terms, visit www.adrig.com/terms
''';

  static const String _privacyPolicy = '''
PRIVACY POLICY

Last updated: November 8, 2025

1. INFORMATION WE COLLECT
AdRig collects information about detected threats, app behavior, and usage statistics to improve security.

2. HOW WE USE YOUR INFORMATION
- To detect and prevent malware
- To improve our AI detection algorithms
- To provide customer support

3. DATA SECURITY
We implement industry-standard security measures to protect your data.

4. DATA SHARING
We do not sell your personal information. Threat data may be anonymously shared with security research partners.

5. YOUR RIGHTS
You have the right to access, correct, or delete your personal data.

For complete privacy policy, visit www.adrig.com/privacy
''';

  static const String _eula = '''
END USER LICENSE AGREEMENT (EULA)

This End User License Agreement is a legal agreement between you and AdRig Technologies.

1. SOFTWARE LICENSE
This EULA grants you the right to install and use AdRig on devices you own or control.

2. RESTRICTIONS
You may not reverse engineer, decompile, or disassemble the software.

3. UPDATES
AdRig may automatically download and install updates.

4. TERMINATION
This license is effective until terminated by either party.

5. GOVERNING LAW
This EULA shall be governed by the laws of the jurisdiction in which AdRig Technologies operates.
''';

  static const String _globalPrivacy = '''
GLOBAL PRIVACY STATEMENT

AdRig Technologies is committed to protecting your privacy worldwide.

INTERNATIONAL DATA TRANSFERS
Your data may be transferred to and processed in countries other than your own.

GDPR COMPLIANCE (EU Users)
We comply with the General Data Protection Regulation for EU residents.

CCPA COMPLIANCE (California Users)
California residents have specific privacy rights under the CCPA.

DATA RETENTION
We retain your data only as long as necessary to provide our services.

CONTACT US
For privacy concerns, contact privacy@adrig.com
''';
}
