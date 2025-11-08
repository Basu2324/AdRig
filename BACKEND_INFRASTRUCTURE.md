# Backend Infrastructure Requirements

## Complete Production Malware Scanner Backend

This document outlines all infrastructure components needed for a **production-grade** malware scanning platform.

---

## 1. Real-Time Signature Database System

### What You Need:

#### A. Malware Hash Database (Primary)
**MalwareBazaar API** ✅ *Already Integrated*
- **Endpoint**: `https://mb-api.abuse.ch/api/v1/`
- **What it provides**: 1000+ Android malware hashes per query
- **Update frequency**: Daily
- **Cost**: FREE
- **Implementation**: Already in `SignatureDatabase.dart`

**Additional Sources to Add:**
1. **VirusShare** - `https://virusshare.com/`
   - Massive malware repository (40M+ samples)
   - Daily hash feed available
   - Requires registration
   - Cost: FREE

2. **Koodous** - `https://koodous.com/apks`
   - Android-specific malware database
   - REST API for hash lookups
   - Community-driven APK analysis
   - Cost: FREE with rate limits

3. **Hybrid Analysis** - `https://www.hybrid-analysis.com/`
   - Hash database + behavioral reports
   - API for automated queries
   - Cost: FREE tier (limited), Paid for high volume

#### B. Database Infrastructure

**Option 1: SQLite (Local) - Current**
```dart
// Already implemented in SignatureDatabase.dart
// Pros: Fast, offline-capable, no server needed
// Cons: Limited to device storage, no centralized updates
```

**Option 2: Firebase Firestore (Recommended for Production)**
```dart
// Cloud-synced signature database
// Pros: Real-time sync, centralized management, automatic backups
// Cons: Requires internet, Firebase costs

dependencies:
  cloud_firestore: ^4.13.0
  firebase_core: ^2.24.0

// Schema:
collection: malware_signatures
  document: {sha256}
    - malwareName: String
    - family: String
    - threatType: String
    - firstSeen: Timestamp
    - indicators: Array<String>
    - severity: String
```

**Option 3: PostgreSQL + REST API (Enterprise)**
```
// Self-hosted database with REST API layer
// Pros: Full control, unlimited storage, high performance
// Cons: Requires server infrastructure, maintenance overhead

Stack:
- PostgreSQL database
- FastAPI/Node.js REST API
- Redis caching layer
- Nginx load balancer
```

#### C. Update Mechanism

**What to Build:**
```dart
class SignatureDatabaseSync {
  // Delta updates instead of full download
  Future<void> syncIncrementalUpdates() async {
    final lastSync = await getLastSyncTimestamp();
    
    // Download only new signatures since last sync
    final newSignatures = await fetchSignaturesSince(lastSync);
    
    // Merge with local database
    await mergeSignatures(newSignatures);
    
    // Update timestamp
    await setLastSyncTimestamp(DateTime.now());
  }
  
  // Scheduled background sync
  void scheduleAutoSync() {
    // Using WorkManager for Android
    Workmanager().registerPeriodicTask(
      "signature-sync",
      "syncSignatures",
      frequency: Duration(hours: 6), // Sync every 6 hours
    );
  }
}
```

**Required Packages:**
```yaml
dependencies:
  workmanager: ^0.5.1  # Background tasks
  sqflite: ^2.3.0      # Local database
  shared_preferences: ^2.2.2  # Metadata storage
```

---

## 2. AI/ML Detection Engine

### What You Need:

#### A. ML Model Architecture

**Recommendation: TensorFlow Lite (On-Device)**

**Training Pipeline (Python):**
```python
import tensorflow as tf
from tensorflow import keras
import pandas as pd
import numpy as np

# Dataset: APK features extracted from 100k+ samples
# Features: permissions array, API calls, strings, code structure
# Labels: malicious (1) or benign (0)

# Model architecture
model = keras.Sequential([
    keras.layers.Dense(256, activation='relu', input_shape=(input_dim,)),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(128, activation='relu'),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(64, activation='relu'),
    keras.layers.Dense(1, activation='sigmoid')  # Binary classification
])

model.compile(
    optimizer='adam',
    loss='binary_crossentropy',
    metrics=['accuracy', 'precision', 'recall']
)

# Train model
model.fit(X_train, y_train, epochs=50, batch_size=32, validation_split=0.2)

# Convert to TensorFlow Lite
converter = tf.lite.TFLiteConverter.from_keras_model(model)
tflite_model = converter.convert()

# Save model
with open('malware_detector.tflite', 'wb') as f:
    f.write(tflite_model)
```

**Flutter Integration:**
```dart
import 'package:tflite_flutter/tflite_flutter.dart';

class MLDetectionEngine {
  Interpreter? _interpreter;
  
  Future<void> loadModel() async {
    _interpreter = await Interpreter.fromAsset('assets/models/malware_detector.tflite');
  }
  
  Future<double> predictMalwareProbability(Map<String, dynamic> features) async {
    // Convert APK features to input tensor
    final input = _prepareInputTensor(features);
    
    // Run inference
    final output = List.filled(1, 0.0).reshape([1, 1]);
    _interpreter!.run(input, output);
    
    return output[0][0]; // Probability score (0.0 - 1.0)
  }
  
  List<double> _prepareInputTensor(Map<String, dynamic> features) {
    return [
      features['permission_count'] / 100.0,
      features['dangerous_permission_count'] / 50.0,
      features['api_call_count'] / 1000.0,
      features['suspicious_string_count'] / 100.0,
      features['obfuscation_ratio'],
      features['hidden_executable_count'] / 10.0,
      // ... 100+ features total
    ];
  }
}
```

**Required Packages:**
```yaml
dependencies:
  tflite_flutter: ^0.10.4
  tflite_flutter_helper: ^0.3.1
```

#### B. Training Dataset

**Where to Get Android Malware Samples:**

1. **AndroZoo** - `https://androzoo.uni.lu/`
   - 15M+ Android apps (malware + benign)
   - Academic research dataset
   - Requires university affiliation or research proposal

2. **AMD (Android Malware Dataset)** - `http://amd.arguslab.org/`
   - 24k malware samples
   - Categorized by family
   - FREE download

3. **Drebin Dataset** - `https://www.sec.cs.tu-bs.de/~danarp/drebin/`
   - 5,560 malware samples
   - 179 malware families
   - Feature vectors pre-extracted

4. **Google Play Store (Benign Samples)**
   - Download top 10k apps for benign training data
   - Use APK Downloader tools
   - Ensure compliance with Terms of Service

**Feature Extraction Code:**
```python
def extract_apk_features(apk_path):
    # Use androguard for APK analysis
    from androguard.core.bytecodes.apk import APK
    
    apk = APK(apk_path)
    
    features = {
        # Permissions
        'permissions': apk.get_permissions(),
        'permission_count': len(apk.get_permissions()),
        'dangerous_permissions': [p for p in apk.get_permissions() if is_dangerous(p)],
        
        # API calls (requires DEX analysis)
        'api_calls': extract_api_calls(apk),
        
        # Code structure
        'method_count': get_method_count(apk),
        'class_count': get_class_count(apk),
        'package_count': get_package_count(apk),
        
        # Strings analysis
        'suspicious_strings': find_suspicious_strings(apk),
        'url_count': count_urls(apk),
        'ip_addresses': find_ip_addresses(apk),
        
        # Metadata
        'min_sdk_version': apk.get_min_sdk_version(),
        'target_sdk_version': apk.get_target_sdk_version(),
        'has_native_code': has_native_libraries(apk),
        
        # Behavioral indicators
        'obfuscation_score': calculate_obfuscation(apk),
        'hidden_executables': find_hidden_executables(apk),
    }
    
    return features
```

#### C. Cloud ML Inference (Optional)

**For complex analysis, use cloud-based models:**

**Google Cloud AI Platform:**
```dart
class CloudMLService {
  Future<double> analyzeAPKInCloud(String apkPath) async {
    // Upload APK to Cloud Storage
    final gsUrl = await uploadToGCS(apkPath);
    
    // Call AI Platform prediction endpoint
    final response = await http.post(
      Uri.parse('https://ml.googleapis.com/v1/projects/YOUR_PROJECT/models/malware_detector:predict'),
      headers: {'Authorization': 'Bearer $accessToken'},
      body: jsonEncode({'instances': [{'apk_url': gsUrl}]}),
    );
    
    final prediction = jsonDecode(response.body)['predictions'][0];
    return prediction['malware_score'];
  }
}
```

**Cost**: $0.05 per 1000 predictions (Cloud AI Platform)

---

## 3. Cloud Threat Intelligence

### What You Need:

#### A. VirusTotal Integration (Already Implemented ✅)

**Current Implementation:**
```dart
// lib/services/cloud_reputation_service.dart
// Already has VirusTotal API v3 integration
```

**Optimization Needed:**
- **Rate Limiting**: Free tier = 4 requests/min
- **Caching**: Cache results for 7 days (already implemented)
- **Batch Queries**: Group multiple hash lookups

**Cost:**
- Free: 4 req/min, 500 req/day
- Premium: $500/month for unlimited API access

#### B. Google SafeBrowsing (Already Implemented ✅)

**Current Implementation:**
```dart
// lib/services/cloud_reputation_service.dart
// Already has SafeBrowsing API v4 integration
```

**API Key Setup:**
```
1. Go to https://console.cloud.google.com/
2. Enable Safe Browsing API
3. Create credentials → API Key
4. Add to .env: SAFE_BROWSING_API_KEY=your_key
```

**Cost:** FREE (50k requests/day)

#### C. Additional Threat Intel Sources

**1. URLhaus (Already Implemented ✅)**
```dart
// Already in cloud_reputation_service.dart
// Detects malware distribution URLs
```

**2. AlienVault OTX (Open Threat Exchange)**
```dart
class AlienVaultService {
  Future<ThreatIntel> checkHash(String hash) async {
    final response = await http.get(
      Uri.parse('https://otx.alienvault.com/api/v1/indicators/file/$hash/general'),
      headers: {'X-OTX-API-KEY': apiKey},
    );
    
    final data = jsonDecode(response.body);
    return ThreatIntel(
      isMalicious: data['pulse_info']['count'] > 0,
      malwareFamily: data['malware']['families'] ?? [],
      threatLevel: data['pulse_info']['count'],
    );
  }
}
```

**Setup**: Free API key at https://otx.alienvault.com/

**3. AbuseIPDB (Network Threat Intel)**
```dart
class AbuseIPDBService {
  Future<bool> isIPMalicious(String ipAddress) async {
    final response = await http.get(
      Uri.parse('https://api.abuseipdb.com/api/v2/check?ipAddress=$ipAddress'),
      headers: {'Key': apiKey},
    );
    
    final data = jsonDecode(response.body)['data'];
    return data['abuseConfidenceScore'] > 50;
  }
}
```

**Cost:** FREE (1000 checks/day)

---

## 4. Behavioral Monitoring System

### What You Need:

#### A. Runtime Monitoring (Partially Implemented)

**Current Status:**
- ✅ Process monitoring (`BehavioralMonitor.kt`)
- ✅ Network connection parsing
- ❌ File I/O monitoring (needs implementation)
- ❌ System call tracing (needs root or ADB)

**What to Add:**

**1. File I/O Monitoring (Requires Root):**
```kotlin
class FileIOMonitor(context: Context) {
    fun monitorFileAccess() {
        // Monitor sensitive paths
        val sensitivePaths = listOf(
            "/data/data/com.android.providers.contacts/",
            "/data/data/com.android.providers.telephony/",
            "/sdcard/DCIM/",
            "/sdcard/Download/",
        )
        
        // Using inotify (Linux kernel feature)
        for (path in sensitivePaths) {
            val observer = FileObserver(path, FileObserver.ALL_EVENTS)
            observer.startWatching()
        }
    }
}
```

**2. System Call Tracing (Advanced - Requires Kernel Module):**
```kotlin
// Use strace or ftrace for system call monitoring
// Requires root access or ADB debugging

class SystemCallMonitor {
    fun traceSyscalls(pid: Int): List<Syscall> {
        val process = Runtime.getRuntime().exec("su -c strace -p $pid -e trace=open,read,write,sendto,recvfrom")
        // Parse strace output
        return parseSyscalls(process.inputStream)
    }
}
```

**3. Memory Analysis:**
```kotlin
class MemoryAnalyzer {
    fun scanProcessMemory(packageName: String) {
        // Requires root
        val pid = getPidForPackage(packageName)
        val memoryMap = File("/proc/$pid/maps").readText()
        
        // Look for suspicious patterns in memory
        val suspiciousPatterns = listOf(
            "libfrida-agent.so",  // Frida detection
            "libsubstrate.so",    // Substrate detection
            ".dex",               // Dynamically loaded DEX
        )
        
        for (pattern in suspiciousPatterns) {
            if (memoryMap.contains(pattern)) {
                reportSuspiciousActivity("Detected $pattern in memory")
            }
        }
    }
}
```

#### B. Permission Monitoring

**What to Build:**
```dart
class PermissionMonitor {
  // Monitor permission changes in real-time
  void startMonitoring() {
    // Listen for permission grant/revoke events
    const platform = MethodChannel('permission_monitor');
    platform.setMethodCallHandler((call) async {
      if (call.method == 'onPermissionChanged') {
        final packageName = call.arguments['package'];
        final permission = call.arguments['permission'];
        final granted = call.arguments['granted'];
        
        _analyzePermissionChange(packageName, permission, granted);
      }
    });
  }
  
  void _analyzePermissionChange(String pkg, String perm, bool granted) {
    if (granted && _isDangerousPermission(perm)) {
      // Check if newly granted permission is suspicious
      _checkForPermissionAbuse(pkg, perm);
    }
  }
}
```

---

## 5. Backend API Server (Optional but Recommended)

### Why You Need It:

- Centralized signature database management
- Cloud-based ML inference for heavy models
- User telemetry and threat intelligence sharing
- Remote configuration and feature flags

### Recommended Stack:

**Option 1: Firebase (Fastest Setup)**
```
Services Needed:
- Cloud Firestore: Signature database
- Cloud Functions: API endpoints
- Cloud Storage: APK sample uploads
- Authentication: User management
- Analytics: Usage tracking

Cost: FREE tier (limited), ~$25/month for production
```

**Option 2: AWS (Enterprise)**
```
Services Needed:
- RDS PostgreSQL: Signature database
- Lambda: Serverless API
- S3: APK storage
- API Gateway: REST API
- Cognito: Authentication
- CloudWatch: Monitoring

Cost: ~$50-200/month depending on traffic
```

**Option 3: Self-Hosted (Full Control)**
```
Stack:
- FastAPI (Python) or Express (Node.js)
- PostgreSQL database
- Redis caching
- Nginx reverse proxy
- Docker containerization
- Kubernetes orchestration (optional)

Cost: VPS ~$10-40/month (DigitalOcean, Linode)
```

### API Endpoints to Build:

```python
# FastAPI example
from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel

app = FastAPI()

@app.post("/api/v1/scan/hash")
async def check_hash(hash: str):
    """Check if hash exists in malware database"""
    result = await db.query_hash(hash)
    return {"is_malware": result.is_malicious, "family": result.family}

@app.post("/api/v1/scan/apk")
async def upload_apk(file: UploadFile):
    """Upload APK for cloud analysis"""
    # Save APK
    apk_path = await save_upload(file)
    
    # Extract features
    features = extract_features(apk_path)
    
    # Run ML model
    prediction = ml_model.predict(features)
    
    # Update database
    await db.add_sample(file.filename, prediction)
    
    return {"malware_score": prediction, "threats": []}

@app.get("/api/v1/signatures/updates")
async def get_signature_updates(since: datetime):
    """Get signature database delta updates"""
    new_signatures = await db.get_signatures_since(since)
    return {"count": len(new_signatures), "signatures": new_signatures}

@app.post("/api/v1/telemetry/report")
async def report_threat(threat: ThreatReport):
    """Receive threat telemetry from clients"""
    await db.insert_telemetry(threat)
    return {"status": "received"}
```

---

## 6. Development Priorities

### Phase 1: Core Detection (DONE ✅)
- [x] APK Analysis Engine
- [x] Signature Database
- [x] Cloud Reputation Service
- [x] Decision Engine
- [x] Quarantine System

### Phase 2: AI/ML Integration (NEXT)
- [ ] Train TensorFlow Lite model on malware dataset
- [ ] Integrate on-device ML inference
- [ ] Build feature extraction pipeline
- [ ] Deploy model updates via Firebase

### Phase 3: Real-Time Intelligence (NEXT)
- [ ] Implement delta signature updates
- [ ] Add AlienVault OTX integration
- [ ] Build backend API server
- [ ] Add telemetry reporting

### Phase 4: Advanced Monitoring (FUTURE)
- [ ] File I/O monitoring
- [ ] System call tracing
- [ ] Memory analysis
- [ ] Dynamic code injection detection

---

## 7. Estimated Costs

### FREE Tier (Good for Development):
- MalwareBazaar: FREE
- VirusTotal: FREE (4 req/min)
- SafeBrowsing: FREE (50k/day)
- URLhaus: FREE
- Firebase: FREE (limited)
- **Total: $0/month**

### Production Tier:
- VirusTotal Premium: $500/month
- Firebase Blaze Plan: $25-100/month
- VPS for backend: $20/month
- ML training (Cloud GPU): $50/month
- **Total: ~$600/month**

### Enterprise Tier:
- VirusTotal Enterprise: $10,000/year
- AWS infrastructure: $500/month
- Dedicated GPU servers: $200/month
- Malware sample licenses: $1,000/year
- **Total: ~$2,000/month**

---

## 8. Immediate Action Items

**To Complete Production Scanner:**

1. **Get API Keys (30 minutes)**
   - VirusTotal: https://www.virustotal.com/gui/join-us
   - SafeBrowsing: https://console.cloud.google.com/
   - Add to project `.env` file

2. **Train ML Model (2-3 days)**
   - Download AMD malware dataset
   - Extract APK features using Python script
   - Train TensorFlow model
   - Convert to TFLite
   - Integrate into app

3. **Setup Firebase (1 hour)**
   - Create Firebase project
   - Enable Firestore for signature sync
   - Deploy Cloud Functions for API
   - Configure authentication

4. **Implement Delta Updates (4 hours)**
   - Build incremental sync system
   - Add background sync with WorkManager
   - Test update mechanism

5. **Build Backend API (1 week)**
   - Setup FastAPI server
   - PostgreSQL database
   - Deploy to VPS or cloud
   - Connect mobile app to API

**Total Time Estimate: 2-3 weeks for complete production system**

---

## Questions?

What component do you want to prioritize?
1. ML model training and integration?
2. Backend API server setup?
3. Advanced behavioral monitoring?
4. Something else?

Let me know and I'll provide detailed implementation code for your choice.
