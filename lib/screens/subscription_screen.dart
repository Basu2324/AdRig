import 'package:flutter/material.dart';
import '../services/auth_service.dart';

class SubscriptionScreen extends StatefulWidget {
  const SubscriptionScreen({super.key});

  @override
  State<SubscriptionScreen> createState() => _SubscriptionScreenState();
}

class _SubscriptionScreenState extends State<SubscriptionScreen> {
  final authService = AuthService();
  SubscriptionType currentType = SubscriptionType.free;
  DateTime? expiryDate;
  bool isLoading = true;

  @override
  void initState() {
    super.initState();
    _loadSubscriptionInfo();
  }

  Future<void> _loadSubscriptionInfo() async {
    final type = await authService.getSubscriptionType();
    final expiry = await authService.getSubscriptionExpiry();

    setState(() {
      currentType = type;
      expiryDate = expiry;
      isLoading = false;
    });
  }

  Future<void> _upgradeToPremium() async {
    final success = await authService.upgradeSubscription(
      SubscriptionType.premium,
      const Duration(days: 30),
    );

    if (success && mounted) {
      await _loadSubscriptionInfo();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Upgraded to Premium!'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }

  Future<void> _upgradeToPro() async {
    final success = await authService.upgradeSubscription(
      SubscriptionType.pro,
      const Duration(days: 30),
    );

    if (success && mounted) {
      await _loadSubscriptionInfo();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('✅ Upgraded to Pro!'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Subscription Plans'),
        backgroundColor: Colors.blue.shade700,
      ),
      body: isLoading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Current Plan Banner
                  Card(
                    color: Colors.blue.shade50,
                    child: Padding(
                      padding: const EdgeInsets.all(16),
                      child: Column(
                        children: [
                          Row(
                            children: [
                              Icon(
                                Icons.verified_user,
                                color: Colors.blue.shade700,
                                size: 32,
                              ),
                              const SizedBox(width: 12),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'Current Plan',
                                      style: TextStyle(
                                        fontSize: 14,
                                        color: Colors.grey.shade700,
                                      ),
                                    ),
                                    Text(
                                      currentType.name.toUpperCase(),
                                      style: TextStyle(
                                        fontSize: 24,
                                        fontWeight: FontWeight.bold,
                                        color: Colors.blue.shade700,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ],
                          ),
                          if (expiryDate != null) ...[
                            const SizedBox(height: 8),
                            Text(
                              'Expires: ${_formatDate(expiryDate!)}',
                              style: TextStyle(
                                fontSize: 12,
                                color: Colors.grey.shade600,
                              ),
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 24),

                  // Norton-style subscription cards
                  _buildPlanCard(
                    title: 'FREE',
                    price: '\$0/month',
                    color: Colors.grey,
                    features: [
                      'Basic malware scanning',
                      'App permission analysis',
                      'Manual scans only',
                      'View threat details',
                      'Basic quarantine',
                    ],
                    isCurrentPlan: currentType == SubscriptionType.free,
                    onUpgrade: null,
                  ),
                  const SizedBox(height: 16),

                  _buildPlanCard(
                    title: 'PREMIUM',
                    price: '\$9.99/month',
                    color: Colors.blue,
                    badge: 'POPULAR',
                    features: [
                      '✅ Everything in FREE',
                      '✅ Real-time protection',
                      '✅ Cloud-based scanning',
                      '✅ Behavioral analysis',
                      '✅ Auto-quarantine threats',
                      '✅ Wi-Fi security scanning',
                    ],
                    isCurrentPlan: currentType == SubscriptionType.premium,
                    onUpgrade:
                        currentType == SubscriptionType.free ? _upgradeToPremium : null,
                  ),
                  const SizedBox(height: 16),

                  _buildPlanCard(
                    title: 'PRO',
                    price: '\$19.99/month',
                    color: Colors.purple,
                    badge: 'BEST VALUE',
                    features: [
                      '✅ Everything in PREMIUM',
                      '✅ Advanced threat reports',
                      '✅ Priority support 24/7',
                      '✅ Multi-device protection (up to 5)',
                      '✅ VPN included',
                      '✅ Dark web monitoring',
                      '✅ Password manager',
                    ],
                    isCurrentPlan: currentType == SubscriptionType.pro,
                    onUpgrade: currentType != SubscriptionType.pro ? _upgradeToPro : null,
                  ),
                  const SizedBox(height: 24),

                  // Norton-style trust badges
                  Padding(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(Icons.verified_user, color: Colors.green, size: 20),
                        const SizedBox(width: 8),
                        Text(
                          'Trusted by millions worldwide',
                          style: TextStyle(
                            fontSize: 12,
                            color: Colors.grey.shade600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
    );
  }

  Widget _buildPlanCard({
    required String title,
    required String price,
    required Color color,
    required List<String> features,
    required bool isCurrentPlan,
    String? badge,
    VoidCallback? onUpgrade,
  }) {
    return Card(
      elevation: isCurrentPlan ? 8 : 2,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: isCurrentPlan
            ? BorderSide(color: color, width: 2)
            : BorderSide.none,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Header
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: const BorderRadius.only(
                topLeft: Radius.circular(16),
                topRight: Radius.circular(16),
              ),
            ),
            child: Column(
              children: [
                if (badge != null) ...[
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 12,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.orange,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Text(
                      badge,
                      style: const TextStyle(
                        color: Colors.white,
                        fontSize: 10,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                ],
                Text(
                  title,
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                    color: color,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  price,
                  style: const TextStyle(
                    fontSize: 32,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ),
          ),

          // Features
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                ...features.map((feature) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: Row(
                        children: [
                          Icon(
                            Icons.check_circle,
                            size: 16,
                            color: feature.startsWith('✅')
                                ? Colors.green
                                : Colors.grey,
                          ),
                          const SizedBox(width: 8),
                          Expanded(
                            child: Text(
                              feature.replaceAll('✅ ', ''),
                              style: const TextStyle(fontSize: 14),
                            ),
                          ),
                        ],
                      ),
                    )),
                const SizedBox(height: 16),

                // Action Button
                if (isCurrentPlan)
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    decoration: BoxDecoration(
                      color: Colors.grey.shade200,
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: const Text(
                      'CURRENT PLAN',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        color: Colors.grey,
                      ),
                    ),
                  )
                else if (onUpgrade != null)
                  ElevatedButton(
                    onPressed: onUpgrade,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: color,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(vertical: 12),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                    ),
                    child: const Text(
                      'UPGRADE NOW',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
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

  String _formatDate(DateTime date) {
    return '${date.day}/${date.month}/${date.year}';
  }
}
