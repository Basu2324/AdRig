import 'package:flutter/material.dart';

class HelpSupportScreen extends StatelessWidget {
  const HelpSupportScreen({Key? key}) : super(key: key);

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
          'Help & Support',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: ListView(
        padding: EdgeInsets.all(16),
        children: [
          // Contact Information
          _buildSectionHeader('Contact Us'),
          _buildContactCard(
            icon: Icons.email_outlined,
            title: 'Email Support',
            subtitle: 'support@adrig.com',
            color: Color(0xFF6C63FF),
            onTap: () {
              // TODO: Open email client
            },
          ),
          _buildContactCard(
            icon: Icons.phone_outlined,
            title: 'Phone Support',
            subtitle: '+1 (800) 123-4567',
            color: Color(0xFF00C853),
            onTap: () {
              // TODO: Make phone call
            },
          ),
          _buildContactCard(
            icon: Icons.chat_bubble_outline,
            title: 'Live Chat',
            subtitle: 'Chat with our support team',
            color: Color(0xFF00D9FF),
            onTap: () {
              _showChatDialog(context);
            },
          ),
          
          SizedBox(height: 24),
          
          // FAQ
          _buildSectionHeader('Frequently Asked Questions'),
          _buildFAQItem(
            question: 'How do I scan for malware?',
            answer: 'Tap the "SCAN NOW" button on the home screen. AdRig will automatically scan all installed apps using multiple detection engines including YARA patterns, cloud reputation, and AI behavioral analysis.',
          ),
          _buildFAQItem(
            question: 'What does AI detection do?',
            answer: 'Our AI engine monitors app behavior in real-time, analyzing permissions, network activity, and file operations. It learns from your actions and continuously improves threat detection accuracy.',
          ),
          _buildFAQItem(
            question: 'How do I quarantine an app?',
            answer: 'When a threat is detected, tap on it to view details, then select "Quarantine". The app will be isolated and prevented from running until you take further action.',
          ),
          _buildFAQItem(
            question: 'Can I whitelist trusted apps?',
            answer: 'Yes! AdRig automatically whitelists system apps and trusted publishers. You can manage your custom whitelist in Settings > Security > Whitelist Management.',
          ),
          _buildFAQItem(
            question: 'How often should I scan?',
            answer: 'We recommend enabling Auto Scan in Settings to automatically scan new apps. For full scans, weekly is sufficient for most users, but daily scans provide maximum protection.',
          ),
          
          SizedBox(height: 24),
          
          // Resources
          _buildSectionHeader('Resources'),
          _buildResourceTile(
            icon: Icons.menu_book,
            title: 'User Guide',
            subtitle: 'Complete documentation',
            onTap: () {
              // TODO: Open user guide
            },
          ),
          _buildResourceTile(
            icon: Icons.video_library,
            title: 'Video Tutorials',
            subtitle: 'Learn how to use AdRig',
            onTap: () {
              // TODO: Open video tutorials
            },
          ),
          _buildResourceTile(
            icon: Icons.bug_report,
            title: 'Report a Bug',
            subtitle: 'Help us improve AdRig',
            onTap: () {
              // TODO: Open bug report form
            },
          ),
          _buildResourceTile(
            icon: Icons.new_releases_outlined,
            title: 'What\'s New',
            subtitle: 'Latest features and updates',
            onTap: () {
              // TODO: Show changelog
            },
          ),
          
          SizedBox(height: 24),
          
          // Community
          _buildSectionHeader('Community'),
          _buildSocialButton(
            icon: Icons.public,
            title: 'Visit Website',
            color: Color(0xFF6C63FF),
            onTap: () {
              // TODO: Open website
            },
          ),
          _buildSocialButton(
            icon: Icons.facebook,
            title: 'Facebook',
            color: Color(0xFF1877F2),
            onTap: () {
              // TODO: Open Facebook
            },
          ),
          _buildSocialButton(
            icon: Icons.alternate_email,
            title: 'Twitter',
            color: Color(0xFF1DA1F2),
            onTap: () {
              // TODO: Open Twitter
            },
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

  Widget _buildContactCard({
    required IconData icon,
    required String title,
    required String subtitle,
    required Color color,
    required VoidCallback onTap,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: ListTile(
        leading: Container(
          padding: EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: color.withOpacity(0.2),
            borderRadius: BorderRadius.circular(10),
          ),
          child: Icon(icon, color: color, size: 24),
        ),
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.bold),
        ),
        subtitle: Text(
          subtitle,
          style: TextStyle(color: Colors.white60, fontSize: 12),
        ),
        trailing: Icon(Icons.chevron_right, color: Colors.white30),
        onTap: onTap,
      ),
    );
  }

  Widget _buildFAQItem({required String question, required String answer}) {
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: Theme(
        data: ThemeData(dividerColor: Colors.transparent),
        child: ExpansionTile(
          title: Text(
            question,
            style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w500),
          ),
          iconColor: Color(0xFF6C63FF),
          collapsedIconColor: Colors.white30,
          children: [
            Padding(
              padding: EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Text(
                answer,
                style: TextStyle(color: Colors.white70, fontSize: 13, height: 1.5),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResourceTile({
    required IconData icon,
    required String title,
    required String subtitle,
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
        subtitle: Text(
          subtitle,
          style: TextStyle(color: Colors.white60, fontSize: 12),
        ),
        trailing: Icon(Icons.open_in_new, color: Colors.white30, size: 20),
        onTap: onTap,
      ),
    );
  }

  Widget _buildSocialButton({
    required IconData icon,
    required String title,
    required Color color,
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
        leading: Icon(icon, color: color),
        title: Text(
          title,
          style: TextStyle(color: Colors.white, fontSize: 15),
        ),
        trailing: Icon(Icons.open_in_new, color: Colors.white30, size: 20),
        onTap: onTap,
      ),
    );
  }

  void _showChatDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Row(
          children: [
            Icon(Icons.chat_bubble, color: Color(0xFF00D9FF)),
            SizedBox(width: 12),
            Text('Live Chat', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Connect with our support team',
              style: TextStyle(color: Colors.white70),
            ),
            SizedBox(height: 16),
            Text(
              'Average response time: 2 minutes',
              style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Start chat
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Connecting to support...'),
                  backgroundColor: Color(0xFF00D9FF),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFF00D9FF),
            ),
            child: Text('START CHAT'),
          ),
        ],
      ),
    );
  }
}
