import 'package:firebase_auth/firebase_auth.dart';
import 'package:cloud_firestore/cloud_firestore.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'dart:convert';
import 'local_auth_service.dart';

/// Firebase-based authentication and user management service
/// Falls back to local auth if Firebase is not configured
class AuthService {
  FirebaseAuth? _auth;
  FirebaseFirestore? _firestore;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();
  final LocalAuthService _localAuth = LocalAuthService();
  
  static const String _subscriptionTypeKey = 'subscription_type';
  static const String _subscriptionExpiryKey = 'subscription_expiry';

  AuthService() {
    try {
      _auth = FirebaseAuth.instance;
      _firestore = FirebaseFirestore.instance;
    } catch (e) {
      print('⚠️ Firebase not available, using local auth mode');
      _auth = null;
      _firestore = null;
    }
  }

  /// Check if Firebase is available
  bool get isFirebaseAvailable => _auth != null && _firestore != null;

  /// Get current Firebase user
  User? get currentUser => _auth?.currentUser;

  /// Stream of auth state changes
  Stream<User?> get authStateChanges => _auth?.authStateChanges() ?? Stream.value(null);

  /// Check if user is logged in
  Future<bool> isLoggedIn() async {
    if (isFirebaseAvailable) {
      return _auth!.currentUser != null;
    } else {
      return await _localAuth.isLoggedIn();
    }
  }

  /// Sign up with email and password
  Future<AuthResult> signUp({
    required String email,
    required String password,
    required String name,
  }) async {
    // Use local auth if Firebase not available
    if (!isFirebaseAvailable) {
      final result = await _localAuth.signUp(
        email: email,
        password: password,
        name: name,
      );
      return AuthResult(
        success: result.success,
        message: result.message,
        user: null,
      );
    }

    try {
      // Validate inputs
      if (email.isEmpty || password.isEmpty || name.isEmpty) {
        return AuthResult(
          success: false,
          message: 'All fields are required',
        );
      }

      if (!email.contains('@')) {
        return AuthResult(
          success: false,
          message: 'Invalid email format',
        );
      }

      if (password.length < 6) {
        return AuthResult(
          success: false,
          message: 'Password must be at least 6 characters',
        );
      }

      // Create user with Firebase Auth
      final userCredential = await _auth!.createUserWithEmailAndPassword(
        email: email,
        password: password,
      );

      // Update display name
      await userCredential.user?.updateDisplayName(name);

      // Create user document in Firestore
      await _firestore!.collection('users').doc(userCredential.user!.uid).set({
        'email': email,
        'name': name,
        'createdAt': FieldValue.serverTimestamp(),
        'subscriptionType': 'free',
        'subscriptionExpiry': null,
        'deviceInfo': {},
        'scanCount': 0,
        'threatCount': 0,
      });

      print('✅ User created: $email');

      return AuthResult(
        success: true,
        message: 'Account created successfully!',
        user: userCredential.user,
      );
    } on FirebaseAuthException catch (e) {
      String message;
      switch (e.code) {
        case 'weak-password':
          message = 'Password is too weak';
          break;
        case 'email-already-in-use':
          message = 'Email is already registered';
          break;
        case 'invalid-email':
          message = 'Invalid email format';
          break;
        case 'operation-not-allowed':
          message = 'Email/password accounts are disabled';
          break;
        default:
          message = e.message ?? 'Failed to create account';
      }
      return AuthResult(success: false, message: message);
    } catch (e) {
      return AuthResult(
        success: false,
        message: 'An error occurred: ${e.toString()}',
      );
    }
  }

  /// Sign in with email and password
  Future<AuthResult> signIn(String email, String password) async {
    // Use local auth if Firebase not available
    if (!isFirebaseAvailable) {
      final result = await _localAuth.signIn(email, password);
      return AuthResult(
        success: result.success,
        message: result.message,
        user: null,
      );
    }

    try {
      if (email.isEmpty || password.isEmpty) {
        return AuthResult(
          success: false,
          message: 'Email and password are required',
        );
      }

      final userCredential = await _auth!.signInWithEmailAndPassword(
        email: email,
        password: password,
      );

      print('✅ User signed in: $email');

      return AuthResult(
        success: true,
        message: 'Signed in successfully!',
        user: userCredential.user,
      );
    } on FirebaseAuthException catch (e) {
      String message;
      switch (e.code) {
        case 'user-not-found':
          message = 'No account found with this email';
          break;
        case 'wrong-password':
          message = 'Incorrect password';
          break;
        case 'invalid-email':
          message = 'Invalid email format';
          break;
        case 'user-disabled':
          message = 'This account has been disabled';
          break;
        case 'invalid-credential':
          message = 'Invalid email or password';
          break;
        default:
          message = e.message ?? 'Failed to sign in';
      }
      return AuthResult(success: false, message: message);
    } catch (e) {
      return AuthResult(
        success: false,
        message: 'An error occurred: ${e.toString()}',
      );
    }
  }

  /// Sign out user
  Future<void> signOut() async {
    if (isFirebaseAvailable) {
      await _auth!.signOut();
    } else {
      await _localAuth.signOut();
    }
    print('✅ User signed out');
  }

  /// Get current user email
  Future<String?> getUserEmail() async {
    if (isFirebaseAvailable) {
      return _auth!.currentUser?.email;
    } else {
      return await _localAuth.getUserEmail();
    }
  }

  /// Get current user name
  Future<String?> getUserName() async {
    if (!isFirebaseAvailable) {
      return await _localAuth.getUserName();
    }

    final user = _auth!.currentUser;
    if (user == null) return null;

    // Try display name first
    if (user.displayName != null && user.displayName!.isNotEmpty) {
      return user.displayName;
    }

    // Fallback to Firestore
    try {
      final doc = await _firestore!.collection('users').doc(user.uid).get();
      return doc.data()?['name'] as String?;
    } catch (e) {
      return user.email?.split('@')[0];
    }
  }

  /// Get subscription type
  Future<SubscriptionType> getSubscriptionType() async {
    if (!isFirebaseAvailable) {
      final typeStr = await _localAuth.getSubscriptionType();
      switch (typeStr) {
        case 'premium':
          return SubscriptionType.premium;
        case 'pro':
          return SubscriptionType.pro;
        default:
          return SubscriptionType.free;
      }
    }

    final user = _auth!.currentUser;
    if (user == null) return SubscriptionType.free;

    try {
      final doc = await _firestore!.collection('users').doc(user.uid).get();
      final typeStr = doc.data()?['subscriptionType'] as String? ?? 'free';

      switch (typeStr) {
        case 'premium':
          return SubscriptionType.premium;
        case 'pro':
          return SubscriptionType.pro;
        default:
          return SubscriptionType.free;
      }
    } catch (e) {
      return SubscriptionType.free;
    }
  }

  /// Check if subscription is active
  Future<bool> isSubscriptionActive() async {
    if (!isFirebaseAvailable) {
      return await _localAuth.isSubscriptionActive();
    }

    final user = _auth!.currentUser;
    if (user == null) return false;

    try {
      final doc = await _firestore!.collection('users').doc(user.uid).get();
      final expiryTimestamp = doc.data()?['subscriptionExpiry'] as Timestamp?;

      if (expiryTimestamp == null) {
        // Free tier never expires
        return true;
      }

      final expiryDate = expiryTimestamp.toDate();
      return DateTime.now().isBefore(expiryDate);
    } catch (e) {
      return true; // Default to active for free tier
    }
  }

  /// Upgrade subscription
  Future<bool> upgradeSubscription(SubscriptionType type, Duration duration) async {
    if (!isFirebaseAvailable) {
      return await _localAuth.upgradeSubscription(type.name, duration);
    }

    final user = _auth!.currentUser;
    if (user == null) return false;

    try {
      final expiryDate = DateTime.now().add(duration);

      await _firestore!.collection('users').doc(user.uid).update({
        'subscriptionType': type.name,
        'subscriptionExpiry': Timestamp.fromDate(expiryDate),
        'updatedAt': FieldValue.serverTimestamp(),
      });

      print('✅ Subscription upgraded to ${type.name}');
      return true;
    } catch (e) {
      print('❌ Failed to upgrade subscription: $e');
      return false;
    }
  }

  /// Get subscription expiry date
  Future<DateTime?> getSubscriptionExpiry() async {
    if (!isFirebaseAvailable) {
      return await _localAuth.getSubscriptionExpiry();
    }

    final user = _auth!.currentUser;
    if (user == null) return null;

    try {
      final doc = await _firestore!.collection('users').doc(user.uid).get();
      final expiryTimestamp = doc.data()?['subscriptionExpiry'] as Timestamp?;

      return expiryTimestamp?.toDate();
    } catch (e) {
      return null;
    }
  }

  /// Check if feature is available for current subscription
  Future<bool> hasFeatureAccess(AppFeature feature) async {
    final subscriptionType = await getSubscriptionType();
    final isActive = await isSubscriptionActive();

    if (!isActive) {
      return false; // Expired subscription
    }

    switch (feature) {
      case AppFeature.basicScan:
        return true; // Available for all tiers

      case AppFeature.realtimeProtection:
      case AppFeature.cloudScanning:
      case AppFeature.behavioralAnalysis:
        return subscriptionType == SubscriptionType.premium ||
            subscriptionType == SubscriptionType.pro;

      case AppFeature.advancedReports:
      case AppFeature.prioritySupport:
      case AppFeature.multiDevice:
        return subscriptionType == SubscriptionType.pro;

      default:
        return false;
    }
  }

  /// Reset password
  Future<AuthResult> resetPassword(String email) async {
    try {
      if (email.isEmpty) {
        return AuthResult(
          success: false,
          message: 'Email is required',
        );
      }

      await _auth!.sendPasswordResetEmail(email: email);

      return AuthResult(
        success: true,
        message: 'Password reset email sent!',
      );
    } on FirebaseAuthException catch (e) {
      String message;
      switch (e.code) {
        case 'user-not-found':
          message = 'No account found with this email';
          break;
        case 'invalid-email':
          message = 'Invalid email format';
          break;
        default:
          message = e.message ?? 'Failed to send reset email';
      }
      return AuthResult(success: false, message: message);
    } catch (e) {
      return AuthResult(
        success: false,
        message: 'An error occurred: ${e.toString()}',
      );
    }
  }

  /// Update scan statistics in Firestore
  Future<void> updateScanStats({
    required int threatCount,
    required int scanCount,
  }) async {
    final user = _auth!.currentUser;
    if (user == null) return;

    try {
      await _firestore!.collection('users').doc(user.uid).update({
        'scanCount': FieldValue.increment(scanCount),
        'threatCount': FieldValue.increment(threatCount),
        'lastScanAt': FieldValue.serverTimestamp(),
      });
    } catch (e) {
      print('❌ Failed to update scan stats: $e');
    }
  }
  
  /// Check if privacy consent has been accepted
  Future<bool> hasAcceptedPrivacyConsent() async {
    if (!isFirebaseAvailable) {
      return await _localAuth.hasAcceptedPrivacyConsent();
    }
    
    // For Firebase, check Firestore
    final user = _auth!.currentUser;
    if (user == null) return false;
    
    try {
      final prefs = await SharedPreferences.getInstance();
      return prefs.getBool('privacy_consent_${user.uid}') ?? false;
    } catch (e) {
      return false;
    }
  }
  
  /// Save privacy consent acceptance
  Future<void> savePrivacyConsent(bool accepted) async {
    if (!isFirebaseAvailable) {
      return await _localAuth.savePrivacyConsent(accepted);
    }
    
    final user = _auth!.currentUser;
    if (user == null) return;
    
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setBool('privacy_consent_${user.uid}', accepted);
    } catch (e) {
      print('Failed to save privacy consent: $e');
    }
  }
  
  /// Check if Remember Me is enabled
  Future<bool> isRememberMeEnabled() async {
    return await _localAuth.isRememberMeEnabled();
  }
  
  /// Set Remember Me preference
  Future<void> setRememberMe(bool remember) async {
    return await _localAuth.setRememberMe(remember);
  }
}

/// Authentication result wrapper
class AuthResult {
  final bool success;
  final String message;
  final User? user;

  AuthResult({
    required this.success,
    required this.message,
    this.user,
  });
}

/// Subscription tiers (like Norton)
enum SubscriptionType {
  free, // Basic scanning only
  premium, // + Real-time protection, cloud scanning
  pro, // + Advanced reports, priority support, multi-device
}

/// App features that can be gated by subscription
enum AppFeature {
  basicScan,
  realtimeProtection,
  cloudScanning,
  behavioralAnalysis,
  advancedReports,
  prioritySupport,
  multiDevice,
}

