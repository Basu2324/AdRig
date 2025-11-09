# Firebase Setup Instructions

## 🔥 Setting Up Firebase Backend

Your app now uses **Firebase Authentication** and **Cloud Firestore** for secure user management and data storage.

### Prerequisites

1. **Google Account** - You'll need a Google account
2. **Firebase Console Access** - Go to https://console.firebase.google.com

### Step-by-Step Setup

#### 1. Create Firebase Project

1. Go to [Firebase Console](https://console.firebase.google.com)
2. Click **"Add project"**
3. Enter project name: `malware-scanner` (or your choice)
4. Enable Google Analytics (optional)
5. Click **"Create project"**

#### 2. Add Android App to Firebase

1. In Firebase Console, click **Android icon** (⚙️)
2. Enter package name: `com.autoguard.malware_scanner`
   - Must match exactly from `android/app/build.gradle.kts`
3. Enter app nickname: `Malware Scanner` (optional)
4. Leave SHA-1 empty for now (optional)
5. Click **"Register app"**

#### 3. Download google-services.json

1. Click **"Download google-services.json"**
2. Move the downloaded file to:
   ```
   /Users/basu/Projects/malware_scanner/android/app/google-services.json
   ```

#### 4. Enable Authentication

1. In Firebase Console, go to **Build → Authentication**
2. Click **"Get started"**
3. Click **"Sign-in method"** tab
4. Enable **Email/Password** provider:
   - Click on "Email/Password"
   - Toggle "Enable"
   - Click "Save"

#### 5. Enable Cloud Firestore

1. In Firebase Console, go to **Build → Firestore Database**
2. Click **"Create database"**
3. Select **"Start in production mode"** (we'll adjust rules later)
4. Choose a location (e.g., `us-central`)
5. Click **"Enable"**

#### 6. Set Firestore Security Rules

1. In Firestore, go to **"Rules"** tab
2. Replace with these rules:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Users can only read/write their own data
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Scan history - users can only access their own
    match /scan_history/{userId}/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

3. Click **"Publish"**

### Automated Setup (Alternative)

If you have Firebase CLI installed:

```bash
# Install Firebase CLI
npm install -g firebase-tools

# Login to Firebase
firebase login

# Initialize Firebase in your project
cd /Users/basu/Projects/malware_scanner
firebase init

# Select:
# - Firestore
# - Authentication
# Choose existing project or create new one
```

### Testing Without Firebase (Development Mode)

If you want to test without setting up Firebase immediately, the app will gracefully handle the missing configuration:

1. The auth service will catch Firebase errors
2. You'll see: `⚠️ Firebase initialization failed`
3. App won't crash, but signup/login won't work

### After Setup

Once `google-services.json` is in place:

```bash
cd /Users/basu/Projects/malware_scanner
flutter clean
flutter pub get
flutter build apk --debug
```

### Verify Setup

1. Launch app
2. Click "Create Account"
3. Fill in details:
   - Name: Test User
   - Email: test@example.com
   - Password: test123
4. Accept terms
5. Click "Create Account"
6. Should see: "Account created successfully!"

### Firebase Console - Monitor Users

1. Go to Firebase Console
2. **Build → Authentication → Users** tab
3. You'll see all registered users
4. **Build → Firestore Database → Data** tab
5. You'll see user documents under `users` collection

### Data Structure in Firestore

```
users/
  {userId}/
    - email: string
    - name: string
    - createdAt: timestamp
    - subscriptionType: "free" | "premium" | "pro"
    - subscriptionExpiry: timestamp | null
    - scanCount: number
    - threatCount: number
    - lastScanAt: timestamp
```

### Security Features

✅ **Password hashing** - Handled by Firebase Auth  
✅ **Secure tokens** - Stored in flutter_secure_storage  
✅ **Data isolation** - Firestore rules prevent cross-user access  
✅ **Email verification** - Can be enabled in Auth settings  
✅ **Password reset** - Built-in with Firebase Auth  

### Troubleshooting

**Error: "Default FirebaseApp is not initialized"**
- Make sure `google-services.json` is in `android/app/`
- Run `flutter clean && flutter pub get`

**Error: "PERMISSION_DENIED"**
- Check Firestore security rules
- Make sure user is signed in

**Error: "EMAIL_ALREADY_IN_USE"**
- That email is already registered
- Use sign in instead or reset password

### Production Checklist

Before releasing to production:

- [ ] Enable email verification in Firebase Console
- [ ] Set up password recovery email templates
- [ ] Configure proper Firestore security rules
- [ ] Add rate limiting for sign-ups
- [ ] Set up Firebase Analytics
- [ ] Configure app check for abuse prevention
- [ ] Add proper error logging (Firebase Crashlytics)

---

**Need help?** Check Firebase documentation: https://firebase.google.com/docs
