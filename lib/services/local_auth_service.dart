import 'package:shared_preferences/shared_preferences.dart';
import 'package:crypto/crypto.dart';
import 'dart:convert';

/// Local-only authentication service (no Firebase required)
/// This is a fallback when Firebase is not configured
class LocalAuthService {
  static const String _usersKey = 'local_users';
  static const String _currentUserKey = 'current_user_email';
  static const String _subscriptionTypeKey = 'subscription_type';
  static const String _subscriptionExpiryKey = 'subscription_expiry';
  static const String _privacyConsentKey = 'privacy_consent_accepted';
  static const String _rememberMeKey = 'remember_me';
  static const String _savedEmailKey = 'saved_email';
  static const String _savedPasswordKey = 'saved_password';

  /// Check if user is logged in
  Future<bool> isLoggedIn() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_currentUserKey) != null;
  }

  /// Sign up with email and password
  Future<LocalAuthResult> signUp({
    required String email,
    required String password,
    required String name,
  }) async {
    try {
      if (email.isEmpty || password.isEmpty || name.isEmpty) {
        return LocalAuthResult(
          success: false,
          message: 'All fields are required',
        );
      }

      if (!email.contains('@')) {
        return LocalAuthResult(
          success: false,
          message: 'Invalid email format',
        );
      }

      if (password.length < 6) {
        return LocalAuthResult(
          success: false,
          message: 'Password must be at least 6 characters',
        );
      }

      final prefs = await SharedPreferences.getInstance();
      final usersJson = prefs.getString(_usersKey) ?? '{}';
      final users = Map<String, dynamic>.from(jsonDecode(usersJson));

      // Check if user already exists
      if (users.containsKey(email)) {
        return LocalAuthResult(
          success: false,
          message: 'Email is already registered',
        );
      }

      // Hash password
      final hashedPassword = _hashPassword(password);

      // Create user
      users[email] = {
        'name': name,
        'email': email,
        'password': hashedPassword,
        'createdAt': DateTime.now().toIso8601String(),
        'subscriptionType': 'free',
      };

      // Save users
      await prefs.setString(_usersKey, jsonEncode(users));
      await prefs.setString(_currentUserKey, email);
      await prefs.setString(_subscriptionTypeKey, 'free');

      print('✅ User created locally: $email');

      return LocalAuthResult(
        success: true,
        message: 'Account created successfully!',
        email: email,
      );
    } catch (e) {
      return LocalAuthResult(
        success: false,
        message: 'An error occurred: ${e.toString()}',
      );
    }
  }

  /// Sign in with email and password
  Future<LocalAuthResult> signIn(String email, String password) async {
    try {
      if (email.isEmpty || password.isEmpty) {
        return LocalAuthResult(
          success: false,
          message: 'Email and password are required',
        );
      }

      final prefs = await SharedPreferences.getInstance();
      final usersJson = prefs.getString(_usersKey) ?? '{}';
      final users = Map<String, dynamic>.from(jsonDecode(usersJson));

      if (!users.containsKey(email)) {
        return LocalAuthResult(
          success: false,
          message: 'No account found with this email',
        );
      }

      final user = users[email];
      final hashedPassword = _hashPassword(password);

      if (user['password'] != hashedPassword) {
        return LocalAuthResult(
          success: false,
          message: 'Incorrect password',
        );
      }

      await prefs.setString(_currentUserKey, email);

      print('✅ User signed in locally: $email');

      return LocalAuthResult(
        success: true,
        message: 'Signed in successfully!',
        email: email,
      );
    } catch (e) {
      return LocalAuthResult(
        success: false,
        message: 'An error occurred: ${e.toString()}',
      );
    }
  }

  /// Sign out user
  Future<void> signOut() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_currentUserKey);
    print('✅ User signed out locally');
  }

  /// Get current user email
  Future<String?> getUserEmail() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_currentUserKey);
  }

  /// Get current user name
  Future<String?> getUserName() async {
    final email = await getUserEmail();
    if (email == null) return null;

    final prefs = await SharedPreferences.getInstance();
    final usersJson = prefs.getString(_usersKey) ?? '{}';
    final users = Map<String, dynamic>.from(jsonDecode(usersJson));

    return users[email]?['name'] as String?;
  }

  /// Get subscription type
  Future<String> getSubscriptionType() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_subscriptionTypeKey) ?? 'free';
  }

  /// Check if subscription is active
  Future<bool> isSubscriptionActive() async {
    final prefs = await SharedPreferences.getInstance();
    final expiryTimestamp = prefs.getInt(_subscriptionExpiryKey);

    if (expiryTimestamp == null) {
      return true; // Free tier never expires
    }

    final expiryDate = DateTime.fromMillisecondsSinceEpoch(expiryTimestamp);
    return DateTime.now().isBefore(expiryDate);
  }

  /// Upgrade subscription
  Future<bool> upgradeSubscription(String type, Duration duration) async {
    final prefs = await SharedPreferences.getInstance();
    final expiryDate = DateTime.now().add(duration);

    await prefs.setString(_subscriptionTypeKey, type);
    await prefs.setInt(_subscriptionExpiryKey, expiryDate.millisecondsSinceEpoch);

    print('✅ Subscription upgraded to $type (local)');
    return true;
  }

  /// Get subscription expiry date
  Future<DateTime?> getSubscriptionExpiry() async {
    final prefs = await SharedPreferences.getInstance();
    final expiryTimestamp = prefs.getInt(_subscriptionExpiryKey);

    if (expiryTimestamp == null) return null;

    return DateTime.fromMillisecondsSinceEpoch(expiryTimestamp);
  }
  
  /// Check if privacy consent has been accepted
  Future<bool> hasAcceptedPrivacyConsent() async {
    final prefs = await SharedPreferences.getInstance();
    final email = prefs.getString(_currentUserKey);
    if (email == null) return false;
    return prefs.getBool('${_privacyConsentKey}_$email') ?? false;
  }
  
  /// Save privacy consent acceptance
  Future<void> savePrivacyConsent(bool accepted) async {
    final prefs = await SharedPreferences.getInstance();
    final email = prefs.getString(_currentUserKey);
    if (email != null) {
      await prefs.setBool('${_privacyConsentKey}_$email', accepted);
    }
  }
  
  /// Check if Remember Me is enabled
  Future<bool> isRememberMeEnabled() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getBool(_rememberMeKey) ?? false;
  }
  
  /// Set Remember Me preference
  Future<void> setRememberMe(bool remember) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_rememberMeKey, remember);
  }
  
  /// Save credentials for Remember Me
  Future<void> saveCredentials(String email, String password) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_savedEmailKey, email);
    await prefs.setString(_savedPasswordKey, password);
  }
  
  /// Get saved credentials
  Future<Map<String, String?>> getSavedCredentials() async {
    final prefs = await SharedPreferences.getInstance();
    return {
      'email': prefs.getString(_savedEmailKey),
      'password': prefs.getString(_savedPasswordKey),
    };
  }
  
  /// Clear saved credentials
  Future<void> clearSavedCredentials() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_savedEmailKey);
    await prefs.remove(_savedPasswordKey);
  }

  /// Hash password using SHA-256
  String _hashPassword(String password) {
    final bytes = utf8.encode(password);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }
}

/// Local auth result wrapper
class LocalAuthResult {
  final bool success;
  final String message;
  final String? email;

  LocalAuthResult({
    required this.success,
    required this.message,
    this.email,
  });
}
