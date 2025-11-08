import 'package:workmanager/workmanager.dart';
import 'signature_updater.dart';
import 'signature_database.dart';

/// Background task scheduler for automatic signature updates
class SignatureUpdateScheduler {
  static const String updateTaskName = 'signature_database_update';
  static const String updateTaskTag = 'signature_update';
  
  /// Initialize WorkManager and schedule periodic updates
  Future<void> initialize() async {
    await Workmanager().initialize(
      callbackDispatcher,
      isInDebugMode: false,
    );
    
    print('📅 Scheduling automatic signature updates...');
    
    // Schedule periodic update every 6 hours
    await Workmanager().registerPeriodicTask(
      updateTaskName,
      updateTaskName,
      frequency: Duration(hours: 6),
      constraints: Constraints(
        networkType: NetworkType.connected, // Require internet
        requiresBatteryNotLow: true,        // Don't drain battery
        requiresCharging: false,
      ),
      backoffPolicy: BackoffPolicy.exponential,
      backoffPolicyDelay: Duration(minutes: 15),
      tag: updateTaskTag,
    );
    
    print('✅ Auto-update scheduled (every 6 hours)');
  }
  
  /// Trigger immediate update (bypasses schedule)
  Future<void> triggerImmediateUpdate() async {
    print('🚀 Triggering immediate signature update...');
    
    await Workmanager().registerOneOffTask(
      '${updateTaskName}_immediate',
      updateTaskName,
      constraints: Constraints(
        networkType: NetworkType.connected,
      ),
      tag: updateTaskTag,
    );
  }
  
  /// Cancel all scheduled updates
  Future<void> cancelScheduledUpdates() async {
    await Workmanager().cancelByTag(updateTaskTag);
    print('🛑 Scheduled updates cancelled');
  }
  
  /// Get next scheduled update time (approximate)
  DateTime getNextUpdateTime() {
    // WorkManager doesn't expose exact next run time
    // Return estimated time based on 6-hour interval
    return DateTime.now().add(Duration(hours: 6));
  }
}

/// Background callback function (runs in separate isolate)
@pragma('vm:entry-point')
void callbackDispatcher() {
  Workmanager().executeTask((task, inputData) async {
    print('\n🔄 Background signature update started');
    print('📋 Task: $task');
    print('⏰ Time: ${DateTime.now()}');
    
    try {
      // Initialize services
      final updater = SignatureDatabaseUpdater();
      final database = SignatureDatabase();
      
      // Check if update is needed
      final needsUpdate = await updater.needsUpdate();
      
      if (!needsUpdate) {
        print('ℹ️  Database is up to date, skipping');
        return Future.value(true);
      }
      
      // Fetch delta updates
      final updateResult = await updater.fetchDeltaUpdate();
      
      if (!updateResult.isSuccess) {
        print('❌ Update failed: ${updateResult.error}');
        return Future.value(false);
      }
      
      if (!updateResult.hasNewSignatures) {
        print('ℹ️  No new signatures available');
        return Future.value(true);
      }
      
      // Verify update integrity
      if (!updater.verifyUpdate(updateResult)) {
        print('❌ Update integrity check failed!');
        return Future.value(false);
      }
      
      // Apply updates to database
      for (final signature in updateResult.signatures) {
        database.addSignature(signature);
      }
      
      // Commit metadata
      final success = await updater.applyUpdate(updateResult);
      
      if (success) {
        print('✅ Background update completed successfully');
        print('📊 Added ${updateResult.signatures.length} new signatures');
        print('🔢 Database version: ${updateResult.version}');
        
        // Show notification to user (optional)
        _showUpdateNotification(updateResult.signatures.length);
        
        return Future.value(true);
      } else {
        print('❌ Failed to apply update');
        return Future.value(false);
      }
      
    } catch (e, stackTrace) {
      print('❌ Background update error: $e');
      print('📍 Stack trace: $stackTrace');
      return Future.value(false);
    }
  });
}

/// Show notification when updates are downloaded
void _showUpdateNotification(int count) {
  // TODO: Implement using flutter_local_notifications
  print('🔔 Notification: $count new malware signatures downloaded');
}
