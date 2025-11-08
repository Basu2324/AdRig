import 'package:adrig/core/models/threat_model.dart';

/// Expanded YARA-style rules for comprehensive malware detection
/// Covers: Rootkits, Ransomware, Exploits, Packers, Obfuscation, APT families
class ExpandedYaraRules {
  
  /// Get all expanded rules (65+ new rules)
  static List<DetectionRule> getAllExpandedRules() {
    return [
      ...getRootkitRules(),
      ...getRansomwareRules(),
      ...getExploitRules(),
      ...getPackerObfuscationRules(),
      ...getAptMalwareRules(),
      ...getCapabilityDetectionRules(),
      ...getCryptoMinerRules(),
      ...getMobileRatRules(),
    ];
  }
  
  /// ============= ROOTKIT DETECTION (10 rules) =============
  static List<DetectionRule> getRootkitRules() {
    return [
      DetectionRule(
        id: 'rule_rootkit_001',
        name: 'SU Binary Privilege Escalation',
        pattern: r'(/system/xbin/su|/system/bin/su|/sbin/su|su\s+\-c|chmod\s+6755)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects attempts to deploy or execute SU binary for root access',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_002',
        name: 'Kernel Module Injection',
        pattern: r'(insmod|modprobe|lkm_inject|kernel_hook|kallsyms_lookup)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects kernel module loading for rootkit installation',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_003',
        name: 'SELinux Bypass',
        pattern: r'(setenforce\s+0|selinux_disabled|permissive_mode|supolicy|sepolicy_inject)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects SELinux disabling or policy manipulation',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_004',
        name: 'Magisk Root Detection',
        pattern: r'(magisk|magiskhide|resetprop|magisk_bb|libmagisk)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Magisk root framework (legitimate but security risk)',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_005',
        name: 'SuperSU Root Framework',
        pattern: r'(supersu|daemonsu|/system/app/supersu|eu\.chainfire)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects SuperSU root management tool',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_006',
        name: 'Process Hiding',
        pattern: r'(hide_process|proc_hide|ps_filter|task_struct_hide|proc_root_link)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects process hiding techniques',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_007',
        name: 'File Hiding',
        pattern: r'(vfs_readdir_hook|getdents_hook|file_hide|hidden_directory)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects VFS hooking for file hiding',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_008',
        name: 'System Call Hooking',
        pattern: r'(syscall_hook|sys_call_table|hijack_syscall|inline_hook)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects system call table manipulation',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_009',
        name: 'Zygote Injection',
        pattern: r'(zygote.*inject|zygote_hook|app_process_hook|zygote_preload)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Zygote process injection for persistent access',
      ),
      
      DetectionRule(
        id: 'rule_rootkit_010',
        name: 'Xposed Framework',
        pattern: r'(xposed|xposedbridge|de\.robv\.android\.xposed|hookmeth)',
        ruleType: 'rootkit',
        threatType: ThreatType.rootkit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Xposed framework (can be legitimate or malicious)',
      ),
    ];
  }
  
  /// ============= RANSOMWARE DETECTION (8 rules) =============
  static List<DetectionRule> getRansomwareRules() {
    return [
      DetectionRule(
        id: 'rule_ransomware_001',
        name: 'File Encryption Activity',
        pattern: r'(AES_encrypt|RSA_encrypt|encrypt_files|\.encrypted|\.locked|\.crypt)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects file encryption behavior',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_002',
        name: 'Ransom Note Display',
        pattern: r'(YOUR FILES.*ENCRYPTED|PAY RANSOM|BITCOIN|DECRYPT|ransom.*note)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects ransom note display',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_003',
        name: 'Android/Simplocker',
        pattern: r'(simplocker|simplock|files.*locked|unlock_files_pay)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Simplocker Android ransomware',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_004',
        name: 'Android/Koler Locker',
        pattern: r'(koler|police.*virus|fbi.*warning|device.*locked)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Koler screen locker ransomware',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_005',
        name: 'Crypto Wallet Targeting',
        pattern: r'(wallet\.dat|bitcoin.*wallet|ethereum.*keystore|crypto.*keys)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects cryptocurrency wallet targeting',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_006',
        name: 'DoubleLocker Ransomware',
        pattern: r'(doublelocker|change_pin|lock_screen|encrypt_sdcard)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects DoubleLocker - PIN changing ransomware',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_007',
        name: 'Massive File Iteration',
        pattern: r'(listFiles.*recursive|scan_all_files|iterate_storage)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects suspicious mass file enumeration',
      ),
      
      DetectionRule(
        id: 'rule_ransomware_008',
        name: 'WannaCry-style Behavior',
        pattern: r'(kill_switch|worm_spread|smb_exploit|eternal_blue)',
        ruleType: 'ransomware',
        threatType: ThreatType.ransomware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects WannaCry-style worm behavior',
      ),
    ];
  }
  
  /// ============= EXPLOIT DETECTION (10 rules) =============
  static List<DetectionRule> getExploitRules() {
    return [
      DetectionRule(
        id: 'rule_exploit_001',
        name: 'Stagefright Exploit',
        pattern: r'(stagefright|libstagefright|mediaserver_exploit|cve-2015-1538)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Stagefright media processing exploit',
      ),
      
      DetectionRule(
        id: 'rule_exploit_002',
        name: 'DirtyCow Exploit',
        pattern: r'(dirtycow|dirty_cow|ptrace_pokedata|/proc/self/mem|cve-2016-5195)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects DirtyCow privilege escalation exploit',
      ),
      
      DetectionRule(
        id: 'rule_exploit_003',
        name: 'Towelroot Exploit',
        pattern: r'(towelroot|futex_requeue|CVE-2014-3153|pwn_kernel)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Towelroot kernel exploit',
      ),
      
      DetectionRule(
        id: 'rule_exploit_004',
        name: 'EvilParcel Exploit',
        pattern: r'(evilparcel|parcel.*exploit|bundle_hijack|serializ.*attack)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Android Parcel serialization exploits',
      ),
      
      DetectionRule(
        id: 'rule_exploit_005',
        name: 'Installer Hijacking',
        pattern: r'(install_hijack|package_replace|overlay_install|install_intercept)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects package installer hijacking',
      ),
      
      DetectionRule(
        id: 'rule_exploit_006',
        name: 'WebView RCE',
        pattern: r'(addJavascriptInterface|webview.*exploit|javascript_bridge_rce)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects WebView JavaScript bridge exploitation',
      ),
      
      DetectionRule(
        id: 'rule_exploit_007',
        name: 'Memory Corruption',
        pattern: r'(heap_spray|use_after_free|buffer_overflow|rop_gadget)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects memory corruption techniques',
      ),
      
      DetectionRule(
        id: 'rule_exploit_008',
        name: 'JIT Spray Attack',
        pattern: r'(jit_spray|shellcode_generation|eval.*loop|nop.*sled)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects JIT spray code generation attacks',
      ),
      
      DetectionRule(
        id: 'rule_exploit_009',
        name: 'Native Library Exploit',
        pattern: r'(libc_exploit|ld_preload|rtld_exploit|linker_hijack)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects native library exploitation',
      ),
      
      DetectionRule(
        id: 'rule_exploit_010',
        name: 'Binder Exploit',
        pattern: r'(binder_exploit|servicemanager_hook|transaction_exploit)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Android Binder IPC exploitation',
      ),
    ];
  }
  
  /// ============= PACKER & OBFUSCATION (12 rules) =============
  static List<DetectionRule> getPackerObfuscationRules() {
    return [
      DetectionRule(
        id: 'rule_packer_001',
        name: 'DexGuard Protection',
        pattern: r'(dexguard|string_decrypt|class_encrypt|control_flow_obf)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects DexGuard obfuscation (commercial, but suspicious)',
      ),
      
      DetectionRule(
        id: 'rule_packer_002',
        name: 'ProGuard Heavy Obfuscation',
        pattern: r'(com\.a\.a\.a\.a|SourceFile:""|class\s+[a-z]{1,2}\s)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.low,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects heavy ProGuard obfuscation',
      ),
      
      DetectionRule(
        id: 'rule_packer_003',
        name: 'String Encryption',
        pattern: r'(decrypt_string|xor_decode|base64.*decrypt|rc4_string)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects runtime string decryption',
      ),
      
      DetectionRule(
        id: 'rule_packer_004',
        name: 'Reflection Heavy Usage',
        pattern: r'(Class\.forName|Method\.invoke|Field\.get|getDeclaredMethod)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.low,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects excessive reflection usage',
      ),
      
      DetectionRule(
        id: 'rule_packer_005',
        name: 'Dynamic Code Loading',
        pattern: r'(DexClassLoader|PathClassLoader|loadClass|defineClass)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects dynamic DEX loading',
      ),
      
      DetectionRule(
        id: 'rule_packer_006',
        name: 'Native Library Packing',
        pattern: r'(unpack_so|decrypt_library|extract_elf|uncompress_native)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects packed native libraries',
      ),
      
      DetectionRule(
        id: 'rule_packer_007',
        name: 'Anti-Debug Detection',
        pattern: r'(isDebuggerConnected|JDWP|android:debuggable|ptrace.*self)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects anti-debugging techniques',
      ),
      
      DetectionRule(
        id: 'rule_packer_008',
        name: 'Anti-Emulator Detection',
        pattern: r'(detect_emulator|goldfish|ranchu|generic.*android)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects emulator detection code',
      ),
      
      DetectionRule(
        id: 'rule_packer_009',
        name: 'Root Detection Evasion',
        pattern: r'(hide_from_root|root_cloak|bypass_root_check)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects root detection bypass attempts',
      ),
      
      DetectionRule(
        id: 'rule_packer_010',
        name: 'Control Flow Flattening',
        pattern: r'(switch.*0x[0-9a-f]{8}|dispatch_table|opaque_predicate)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects control flow obfuscation',
      ),
      
      DetectionRule(
        id: 'rule_packer_011',
        name: 'Multi-layer DEX',
        pattern: r'(assets/.*\.dex|hidden_dex|secondary_dex|load_payload)',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects hidden DEX files in assets',
      ),
      
      DetectionRule(
        id: 'rule_packer_012',
        name: 'High Entropy Code',
        pattern: r'(compress|cipher|encode|encrypt).*{50,}',
        ruleType: 'obfuscation',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.low,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects high entropy encoded data',
      ),
    ];
  }
  
  /// ============= APT & ADVANCED MALWARE (10 rules) =============
  static List<DetectionRule> getAptMalwareRules() {
    return [
      DetectionRule(
        id: 'rule_apt_001',
        name: 'Pegasus Spyware',
        pattern: r'(pegasus|nso_group|trident_exploit|jailbreak_ios)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Pegasus nation-state spyware',
      ),
      
      DetectionRule(
        id: 'rule_apt_002',
        name: 'Chrysaor APT',
        pattern: r'(chrysaor|chrysaor_payload|pegasus_android)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Chrysaor Android APT spyware',
      ),
      
      DetectionRule(
        id: 'rule_apt_003',
        name: 'FinSpy Mobile',
        pattern: r'(finspy|finfisher|gamma_group|trojan_finspy)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects FinSpy surveillance malware',
      ),
      
      DetectionRule(
        id: 'rule_apt_004',
        name: 'Exodus Spyware',
        pattern: r'(exodus|esurv|italian_spyware|root_expl)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Exodus Italian spyware',
      ),
      
      DetectionRule(
        id: 'rule_apt_005',
        name: 'Skygofree Implant',
        pattern: r'(skygofree|reverse_shell|location_track|audio_record)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Skygofree surveillance implant',
      ),
      
      DetectionRule(
        id: 'rule_apt_006',
        name: 'Triada Modular Backdoor',
        pattern: r'(triada|backdoor_module|zygote_inject|system_partition_write)',
        ruleType: 'apt',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Triada modular backdoor',
      ),
      
      DetectionRule(
        id: 'rule_apt_007',
        name: 'Mandrake APT',
        pattern: r'(mandrake|bitdefender|advanced_obf|stage.*payload)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Mandrake advanced spyware',
      ),
      
      DetectionRule(
        id: 'rule_apt_008',
        name: 'APT-C-23 (Two-tailed Scorpion)',
        pattern: r'(twotailed.*scorpion|desert.*scorpion|apt.*c.*23)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects APT-C-23 Middle East campaign',
      ),
      
      DetectionRule(
        id: 'rule_apt_009',
        name: 'Gustuff Banking APT',
        pattern: r'(gustuff|push_send|sms_forward|autopilot_transfer)',
        ruleType: 'apt',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Gustuff automated banking fraud',
      ),
      
      DetectionRule(
        id: 'rule_apt_010',
        name: 'RedDrop Campaign',
        pattern: r'(reddrop|fake_vpn|data_ex filtrate|c2_communication)',
        ruleType: 'apt',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects RedDrop espionage campaign',
      ),
    ];
  }
  
  /// ============= CAPABILITY-BASED DETECTION (8 rules) =============
  static List<DetectionRule> getCapabilityDetectionRules() {
    return [
      DetectionRule(
        id: 'rule_cap_001',
        name: 'Screen Recording Capability',
        pattern: r'(MediaProjection|createVirtualDisplay|screenshot_capture)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects screen recording capability',
      ),
      
      DetectionRule(
        id: 'rule_cap_002',
        name: 'Keylogging Capability',
        pattern: r'(AccessibilityEvent|TYPE_VIEW_TEXT_CHANGED|keylog|input_capture)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects keylogging via accessibility',
      ),
      
      DetectionRule(
        id: 'rule_cap_003',
        name: 'Call Interception',
        pattern: r'(PhoneStateListener|outgoing_call|call_log|record_call)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects call monitoring/recording',
      ),
      
      DetectionRule(
        id: 'rule_cap_004',
        name: 'SMS Interception',
        pattern: r'(SMS_RECEIVED|READ_SMS|getMessageBody|sms_steal)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects SMS interception',
      ),
      
      DetectionRule(
        id: 'rule_cap_005',
        name: 'Location Tracking',
        pattern: r'(requestLocationUpdates|getLastKnownLocation|gps_track)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects location tracking capability',
      ),
      
      DetectionRule(
        id: 'rule_cap_006',
        name: 'Camera Hijacking',
        pattern: r'(Camera\.open|takePicture|camera_spy|silent_photo)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects silent camera activation',
      ),
      
      DetectionRule(
        id: 'rule_cap_007',
        name: 'Microphone Recording',
        pattern: r'(MediaRecorder|AudioRecord|ambient_listen|voice_capture)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects ambient audio recording',
      ),
      
      DetectionRule(
        id: 'rule_cap_008',
        name: 'Contact Harvesting',
        pattern: r'(ContactsContract|getContacts|contact_steal|phonebook_dump)',
        ruleType: 'capability',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects contact list exfiltration',
      ),
    ];
  }
  
  /// ============= CRYPTOMINER DETECTION (4 rules) =============
  static List<DetectionRule> getCryptoMinerRules() {
    return [
      DetectionRule(
        id: 'rule_miner_001',
        name: 'Coinhive Miner',
        pattern: r'(coinhive|coin.*hive|cryptonight|monero.*mine)',
        ruleType: 'cryptominer',
        threatType: ThreatType.malware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Coinhive cryptocurrency miner',
      ),
      
      DetectionRule(
        id: 'rule_miner_002',
        name: 'XMRig Miner',
        pattern: r'(xmrig|xmr.*pool|mining.*config|hashrate)',
        ruleType: 'cryptominer',
        threatType: ThreatType.malware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects XMRig Monero miner',
      ),
      
      DetectionRule(
        id: 'rule_miner_003',
        name: 'Mining Pool Connection',
        pattern: r'(stratum\+tcp|pool\.supportxmr|minergate|nanopool)',
        ruleType: 'cryptominer',
        threatType: ThreatType.malware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects mining pool connections',
      ),
      
      DetectionRule(
        id: 'rule_miner_004',
        name: 'CPU Intensive Mining',
        pattern: r'(cpu_intensive|pow_calculate|hash_loop|difficulty)',
        ruleType: 'cryptominer',
        threatType: ThreatType.malware,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects CPU-intensive mining operations',
      ),
    ];
  }
  
  /// ============= MOBILE RAT DETECTION (5 rules) =============
  static List<DetectionRule> getMobileRatRules() {
    return [
      DetectionRule(
        id: 'rule_rat_001',
        name: 'AhMyth RAT',
        pattern: r'(ahmyth|ahm_bot|remote_shell|file_manager)',
        ruleType: 'rat',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects AhMyth Remote Access Trojan',
      ),
      
      DetectionRule(
        id: 'rule_rat_002',
        name: 'OmniRAT',
        pattern: r'(omnirat|command_shell|file_transfer|screen_control)',
        ruleType: 'rat',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects OmniRAT remote access tool',
      ),
      
      DetectionRule(
        id: 'rule_rat_003',
        name: 'DroidJack RAT',
        pattern: r'(droidjack|sandr at|remote_admin|device_control)',
        ruleType: 'rat',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects DroidJack/SandRAT remote admin tool',
      ),
      
      DetectionRule(
        id: 'rule_rat_004',
        name: 'SpyNote RAT',
        pattern: r'(spynote|craxs.*rat|remote_bind|socket_backdoor)',
        ruleType: 'rat',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects SpyNote/CraxsRAT remote access trojan',
      ),
      
      DetectionRule(
        id: 'rule_rat_005',
        name: 'Generic RAT Indicators',
        pattern: r'(reverse_tcp|bind_shell|meterpreter|rat_config)',
        ruleType: 'rat',
        threatType: ThreatType.backdoor,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects generic RAT communication patterns',
      ),
    ];
  }
}
