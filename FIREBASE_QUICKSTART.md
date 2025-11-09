# 🔥 Firebase Setup - Quick Reference

## ⚡ 5-Minute Setup

### 1. Firebase Console
```
https://console.firebase.google.com
→ Add project → "malware-scanner" → Create
```

### 2. Add Android App
```
Click Android icon
Package name: com.autoguard.malware_scanner
Download google-services.json
Move to: /Users/basu/Projects/malware_scanner/android/app/
```

### 3. Enable Services
```
Build → Authentication → Get started → Email/Password → Enable
Build → Firestore Database → Create → Production mode → Enable
```

### 4. Set Firestore Rules
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

### 5. Rebuild App
```bash
cd /Users/basu/Projects/malware_scanner

# Edit android/app/build.gradle.kts
# Uncomment: id("com.google.gms.google-services")

flutter clean && flutter pub get && flutter build apk
```

## ✅ Test Credentials
```
Email: test@example.com
Password: test123456
Name: Test User
```

## 📱 APK Location
```
build/app/outputs/flutter-apk/app-debug.apk
```

## 🆘 Quick Fixes

**App crashes:** Add google-services.json  
**Build fails:** Uncomment google-services plugin  
**Auth fails:** Enable Email/Password in Firebase Console  
**Data fails:** Set Firestore rules  

---

**Full guide:** See `FIREBASE_AUTH_READY.md`
