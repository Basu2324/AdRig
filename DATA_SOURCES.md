# Data Source Documentation

## NO DUMMY DATA IN THIS APP

All threat counts and statistics come from **REAL scan results** stored in SharedPreferences.

### Where "328 threats" comes from:

1. **User runs a scan** (Dashboard → "SCAN NOW" button)
2. **Real apps are analyzed** by:
   - Permission analyzer
   - Signature validator
   - YARA rule engine
   - AI detection engine
   - Behavioral analysis
3. **Results are saved** to SharedPreferences (`threat_history` key)
4. **Dashboard displays** the saved counts

### Data Flow:

```
Scan Button → ScanCoordinator → Threat Analysis → ThreatHistoryService.addScanResult()
                                                    ↓
                                            SharedPreferences
                                                    ↓
                                        Dashboard reads counts
```

### Data Storage:

- **Service**: `ThreatHistoryService`
- **Storage**: SharedPreferences (local device storage)
- **Key**: `threat_history`
- **Retention**: Last 90 days
- **Format**: JSON array of scan results

### Statistics Sources:

| Statistic | Source |
|-----------|--------|
| Total Threats | `ThreatHistoryService.getTotalThreatsLast90Days()` |
| Apps Scanned | Sum of `totalApps` from all scan results |
| Days Protected | Days since first scan |
| Threat Categories | Count by category (Apps, Wi-Fi, Internet) |

### Authentication Data:

| Field | Storage |
|-------|---------|
| User Email | SharedPreferences (`user_email`) |
| Subscription Type | SharedPreferences (`subscription_type`) |
| Subscription Expiry | SharedPreferences (`subscription_expiry`) |
| Login Status | SharedPreferences (`is_logged_in`) |

### Mock Data (For Development Only):

**Only exists in**: `process_analyzer_service.dart`
- Mock process names (for system process simulation)
- Mock library names (for loaded library analysis)
- **NOT used for threat counts or dashboard statistics**

## How to Clear All Data:

1. **Clear scan history**:
   ```dart
   final prefs = await SharedPreferences.getInstance();
   await prefs.remove('threat_history');
   ```

2. **Sign out** (clears auth data):
   ```dart
   final authService = AuthService();
   await authService.signOut();
   ```

3. **Run fresh scan** to see current device threats

## Subscription Tiers:

### FREE (Default)
- Basic malware scanning
- Manual scans only
- View threat details
- Basic quarantine

### PREMIUM (\$9.99/month)
- ✅ Everything in FREE
- ✅ Real-time protection
- ✅ Cloud-based scanning
- ✅ Behavioral analysis
- ✅ Auto-quarantine threats

### PRO (\$19.99/month)
- ✅ Everything in PREMIUM
- ✅ Advanced threat reports
- ✅ Priority support 24/7
- ✅ Multi-device protection
- ✅ VPN included
- ✅ Dark web monitoring

## Norton-Style Features:

1. **Authentication**: Login/Sign Out required
2. **Subscription-based**: Free tier with premium upgrades
3. **Feature Gates**: Premium features locked behind subscription
4. **Real-time Protection**: Background scanning (Premium+)
5. **Cloud Intelligence**: Server-based threat analysis (Premium+)
6. **Multi-device**: Protect up to 5 devices (Pro only)

---

**IMPORTANT**: If you see "328 threats" or any number, it's from a previous scan you ran. It's NOT fake data. Run a new scan to see current threats.
