import 'package:flutter/material.dart';

class ProfileScreen extends StatelessWidget {
  const ProfileScreen({Key? key}) : super(key: key);

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
          'User Profile',
          style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold),
        ),
      ),
      body: SingleChildScrollView(
        child: Column(
          children: [
            // Profile Header
            Container(
              width: double.infinity,
              padding: EdgeInsets.all(24),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [Color(0xFF2196F3), Color(0xFF0D47A1)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
              ),
              child: Column(
                children: [
                  CircleAvatar(
                    radius: 50,
                    backgroundColor: Colors.white24,
                    child: Icon(Icons.person, size: 60, color: Colors.white),
                  ),
                  SizedBox(height: 16),
                  Text(
                    'John Doe',
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.bold,
                      color: Colors.white,
                    ),
                  ),
                  SizedBox(height: 4),
                  Text(
                    'john.doe@email.com',
                    style: TextStyle(
                      fontSize: 14,
                      color: Colors.white70,
                    ),
                  ),
                  SizedBox(height: 16),
                  ElevatedButton.icon(
                    onPressed: () {
                      // TODO: Edit profile
                    },
                    icon: Icon(Icons.edit, size: 18),
                    label: Text('EDIT PROFILE'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.white24,
                      foregroundColor: Colors.white,
                      padding: EdgeInsets.symmetric(horizontal: 24, vertical: 12),
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
                  // Account Status
                  _buildSectionHeader('Account Status'),
                  _buildInfoCard(
                    icon: Icons.verified,
                    title: 'Premium Account',
                    subtitle: 'Active until Dec 31, 2025',
                    color: Color(0xFF00C853),
                  ),
                  
                  SizedBox(height: 24),
                  
                  // Subscription
                  _buildSectionHeader('Subscription'),
                  _buildInfoCard(
                    icon: Icons.workspace_premium,
                    title: 'AdRig Premium',
                    subtitle: '\$9.99/month',
                    color: Color(0xFF6C63FF),
                    trailing: TextButton(
                      onPressed: () {
                        // TODO: Manage subscription
                      },
                      child: Text('MANAGE'),
                    ),
                  ),
                  
                  _buildNavigationTile(
                    icon: Icons.payment,
                    title: 'Payment Methods',
                    subtitle: 'Visa ending in 4242',
                    onTap: () {
                      // TODO: Navigate to payment methods
                    },
                  ),
                  
                  _buildNavigationTile(
                    icon: Icons.receipt_long,
                    title: 'Billing History',
                    subtitle: 'View invoices and receipts',
                    onTap: () {
                      // TODO: Navigate to billing history
                    },
                  ),
                  
                  SizedBox(height: 24),
                  
                  // Devices
                  _buildSectionHeader('Protected Devices'),
                  _buildDeviceCard(
                    deviceName: 'Samsung Galaxy S23',
                    deviceType: 'Android 14',
                    lastScan: 'Today at 10:14 AM',
                    isActive: true,
                  ),
                  _buildDeviceCard(
                    deviceName: 'Google Pixel 7',
                    deviceType: 'Android 13',
                    lastScan: '2 days ago',
                    isActive: false,
                  ),
                  
                  _buildNavigationTile(
                    icon: Icons.add_circle_outline,
                    title: 'Add Device',
                    subtitle: '2 of 5 devices used',
                    onTap: () {
                      // TODO: Add device
                    },
                  ),
                  
                  SizedBox(height: 24),
                  
                  // Account Statistics
                  _buildSectionHeader('Your Statistics'),
                  Row(
                    children: [
                      Expanded(
                        child: _buildStatCard(
                          value: '127',
                          label: 'Threats Blocked',
                          icon: Icons.shield_outlined,
                        ),
                      ),
                      SizedBox(width: 12),
                      Expanded(
                        child: _buildStatCard(
                          value: '89',
                          label: 'Apps Scanned',
                          icon: Icons.apps,
                        ),
                      ),
                    ],
                  ),
                  SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: _buildStatCard(
                          value: '45',
                          label: 'Days Protected',
                          icon: Icons.calendar_today,
                        ),
                      ),
                      SizedBox(width: 12),
                      Expanded(
                        child: _buildStatCard(
                          value: '3.2GB',
                          label: 'Data Saved',
                          icon: Icons.data_usage,
                        ),
                      ),
                    ],
                  ),
                  
                  SizedBox(height: 32),
                  
                  // Danger Zone
                  _buildSectionHeader('Danger Zone', color: Color(0xFFFF4757)),
                  _buildDangerButton(
                    icon: Icons.logout,
                    title: 'Sign Out',
                    onTap: () {
                      _showSignOutDialog(context);
                    },
                  ),
                  _buildDangerButton(
                    icon: Icons.delete_forever,
                    title: 'Delete Account',
                    onTap: () {
                      _showDeleteAccountDialog(context);
                    },
                  ),
                  
                  SizedBox(height: 40),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title, {Color? color}) {
    return Padding(
      padding: EdgeInsets.only(left: 4, bottom: 12, top: 8),
      child: Text(
        title,
        style: TextStyle(
          fontSize: 14,
          fontWeight: FontWeight.bold,
          color: color ?? Color(0xFF6C63FF),
          letterSpacing: 1.2,
        ),
      ),
    );
  }

  Widget _buildInfoCard({
    required IconData icon,
    required String title,
    required String subtitle,
    required Color color,
    Widget? trailing,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: Row(
        children: [
          Container(
            padding: EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: color.withOpacity(0.2),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: color, size: 24),
          ),
          SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                SizedBox(height: 4),
                Text(
                  subtitle,
                  style: TextStyle(
                    fontSize: 12,
                    color: Colors.white60,
                  ),
                ),
              ],
            ),
          ),
          if (trailing != null) trailing,
        ],
      ),
    );
  }

  Widget _buildNavigationTile({
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
        trailing: Icon(Icons.chevron_right, color: Colors.white30),
        onTap: onTap,
      ),
    );
  }

  Widget _buildDeviceCard({
    required String deviceName,
    required String deviceType,
    required String lastScan,
    required bool isActive,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 12),
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isActive ? Color(0xFF00C853).withOpacity(0.3) : Colors.white10,
          width: 1,
        ),
      ),
      child: Row(
        children: [
          Container(
            padding: EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isActive 
                  ? Color(0xFF00C853).withOpacity(0.2)
                  : Colors.white10,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(
              Icons.smartphone,
              color: isActive ? Color(0xFF00C853) : Colors.white30,
              size: 24,
            ),
          ),
          SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      deviceName,
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.bold,
                        color: Colors.white,
                      ),
                    ),
                    if (isActive) ...[
                      SizedBox(width: 8),
                      Container(
                        padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Color(0xFF00C853),
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Text(
                          'ACTIVE',
                          style: TextStyle(
                            fontSize: 9,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
                SizedBox(height: 4),
                Text(
                  deviceType,
                  style: TextStyle(
                    fontSize: 12,
                    color: Colors.white60,
                  ),
                ),
                SizedBox(height: 2),
                Text(
                  'Last scan: $lastScan',
                  style: TextStyle(
                    fontSize: 11,
                    color: Colors.white.withOpacity(0.4),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard({
    required String value,
    required String label,
    required IconData icon,
  }) {
    return Container(
      padding: EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white10, width: 1),
      ),
      child: Column(
        children: [
          Icon(icon, color: Color(0xFF6C63FF), size: 28),
          SizedBox(height: 8),
          Text(
            value,
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.bold,
              color: Colors.white,
            ),
          ),
          SizedBox(height: 4),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              color: Colors.white60,
            ),
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildDangerButton({
    required IconData icon,
    required String title,
    required VoidCallback onTap,
  }) {
    return Container(
      margin: EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        color: Color(0xFF151933),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Color(0xFFFF4757).withOpacity(0.3), width: 1),
      ),
      child: ListTile(
        leading: Icon(icon, color: Color(0xFFFF4757)),
        title: Text(
          title,
          style: TextStyle(color: Color(0xFFFF4757), fontSize: 15),
        ),
        trailing: Icon(Icons.chevron_right, color: Color(0xFFFF4757).withOpacity(0.5)),
        onTap: onTap,
      ),
    );
  }

  void _showSignOutDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Text('Sign Out', style: TextStyle(color: Colors.white)),
        content: Text(
          'Are you sure you want to sign out?',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              Navigator.pop(context);
              // TODO: Sign out
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('SIGN OUT'),
          ),
        ],
      ),
    );
  }

  void _showDeleteAccountDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Color(0xFF151933),
        title: Row(
          children: [
            Icon(Icons.warning, color: Color(0xFFFF4757)),
            SizedBox(width: 8),
            Text('Delete Account', style: TextStyle(color: Colors.white)),
          ],
        ),
        content: Text(
          'This action cannot be undone. All your data will be permanently deleted.\n\nAre you absolutely sure?',
          style: TextStyle(color: Colors.white70),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('CANCEL'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // TODO: Delete account
              ScaffoldMessenger.of(context).showSnackBar(
                SnackBar(
                  content: Text('Account deletion request submitted'),
                  backgroundColor: Color(0xFFFF4757),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Color(0xFFFF4757),
            ),
            child: Text('DELETE ACCOUNT'),
          ),
        ],
      ),
    );
  }
}
