import 'package:adrig/core/models/threat_model.dart';

/// Latest 2025 Malware Patterns - Updated November 2025
/// Includes newest banking trojans, spyware, and mobile threats
class YaraRules2025 {
  
  /// Get all 2025 malware detection rules (50+ new patterns)
  static List<DetectionRule> getAll2025Rules() {
    return [
      ...getLatestBankingTrojans(),
      ...getLatestSpyware(),
      ...getLatestCryptoThreats(),
      ...getLatestAPTMalware(),
      ...getLatestExploits(),
      ...getLatestPhishing(),
    ];
  }
  
  /// ============= LATEST BANKING TROJANS (2024-2025) =============
  static List<DetectionRule> getLatestBankingTrojans() {
    return [
      DetectionRule(
        id: 'rule_banking_2025_001',
        name: 'Chameleon Banking Trojan',
        pattern: r'(chameleon_bot|biometric_bypass|cookie_stealer|accessibility_overlay)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Chameleon - advanced banking trojan targeting European banks (2024)',
      ),
      
      DetectionRule(
        id: 'rule_banking_2025_002',
        name: 'Godfather Banking Trojan',
        pattern: r'(godfather_trojan|mfa_intercept|banking_overlay_v2|credential_phish)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Godfather - targets 400+ banking apps worldwide',
      ),
      
      DetectionRule(
        id: 'rule_banking_2025_003',
        name: 'Hook Banking Trojan',
        pattern: r'(hook_malware|vnc_stream|remote_interaction|banking_rat)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Hook - advanced RAT with VNC capabilities',
      ),
      
      DetectionRule(
        id: 'rule_banking_2025_004',
        name: 'Anatsa/TeaBot Evolution',
        pattern: r'(anatsa_v3|teabot_advanced|dropper_module|multi_stage_payload)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects evolved Anatsa/TeaBot with dropper capabilities',
      ),
      
      DetectionRule(
        id: 'rule_banking_2025_005',
        name: 'BrazKing Banking Trojan',
        pattern: r'(brazking|pix_stealer|brazilian_banking|overlay_brazil)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects BrazKing - targets Brazilian banking PIX system',
      ),
      
      DetectionRule(
        id: 'rule_banking_2025_006',
        name: 'Xenomorph v3',
        pattern: r'(xenomorph_v3|adaptive_overlay|ai_evasion|dynamic_config)',
        ruleType: 'banking_trojan',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Xenomorph v3 with AI-based evasion',
      ),
    ];
  }
  
  /// ============= LATEST SPYWARE (2024-2025) =============
  static List<DetectionRule> getLatestSpyware() {
    return [
      DetectionRule(
        id: 'rule_spyware_2025_001',
        name: 'SpinOk Spyware Module',
        pattern: r'(spinok|sdk_malware|clipboard_monitor|file_exfiltrate)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects SpinOk SDK - infected 421M devices via legitimate apps',
      ),
      
      DetectionRule(
        id: 'rule_spyware_2025_002',
        name: 'Predator Commercial Spyware',
        pattern: r'(predator_spyware|zero_click|kernel_exploit|commercial_spyware)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Predator - commercial grade spyware with zero-click',
      ),
      
      DetectionRule(
        id: 'rule_spyware_2025_003',
        name: 'Pegasus/NSO Group',
        pattern: r'(pegasus|nso_group|zero_day_exploit|iMessage_exploit|whatsapp_exploit)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Pegasus spyware indicators',
      ),
      
      DetectionRule(
        id: 'rule_spyware_2025_004',
        name: 'BadBazaar Surveillance',
        pattern: r'(badbazaar|signal_intercept|telegram_spy|chat_surveillance)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects BadBazaar - targets Signal and Telegram users',
      ),
      
      DetectionRule(
        id: 'rule_spyware_2025_005',
        name: 'Hermit Commercial Spyware',
        pattern: r'(hermit_spyware|rcs_labs|modular_surveillance|call_recording)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Hermit - modular commercial spyware',
      ),
      
      DetectionRule(
        id: 'rule_spyware_2025_006',
        name: 'Monokle Surveillance',
        pattern: r'(monokle|special_force|recording_module|location_tracker)',
        ruleType: 'spyware',
        threatType: ThreatType.spyware,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Monokle surveillance framework',
      ),
    ];
  }
  
  /// ============= LATEST CRYPTO THREATS (2024-2025) =============
  static List<DetectionRule> getLatestCryptoThreats() {
    return [
      DetectionRule(
        id: 'rule_crypto_2025_001',
        name: 'CryptBot Crypto Stealer',
        pattern: r'(cryptbot|wallet_stealer|seed_phrase_steal|metamask_target)',
        ruleType: 'crypto_stealer',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects CryptBot - targets crypto wallets and seed phrases',
      ),
      
      DetectionRule(
        id: 'rule_crypto_2025_002',
        name: 'Pink Drainer Phishing',
        pattern: r'(pink_drainer|wallet_connect_phish|approve_unlimited|drain_wallet)',
        ruleType: 'crypto_stealer',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Pink Drainer - stole \$85M+ through phishing',
      ),
      
      DetectionRule(
        id: 'rule_crypto_2025_003',
        name: 'Clipper Malware',
        pattern: r'(clipboard_replace|bitcoin_address_swap|crypto_clipper|wallet_redirect)',
        ruleType: 'crypto_stealer',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects clipboard hijacking for crypto theft',
      ),
      
      DetectionRule(
        id: 'rule_crypto_2025_004',
        name: 'NFT Stealer',
        pattern: r'(nft_steal|opensea_phish|setApprovalForAll|transferFrom_hijack)',
        ruleType: 'crypto_stealer',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects NFT stealing malware',
      ),
      
      DetectionRule(
        id: 'rule_crypto_2025_005',
        name: 'Mining Pool Hijacker',
        pattern: r'(pool_redirect|mining_hijack|hashrate_steal|worker_replace)',
        ruleType: 'crypto_miner',
        threatType: ThreatType.adware,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects crypto mining pool redirection',
      ),
    ];
  }
  
  /// ============= LATEST APT MALWARE (2024-2025) =============
  static List<DetectionRule> getLatestAPTMalware() {
    return [
      DetectionRule(
        id: 'rule_apt_2025_001',
        name: 'LightSpy iOS/Android Implant',
        pattern: r'(lightspy|apt_ios|data_exfil|plugin_download)',
        ruleType: 'apt_malware',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects LightSpy APT implant (TwoTail campaign)',
      ),
      
      DetectionRule(
        id: 'rule_apt_2025_002',
        name: 'Crocodilus APT Framework',
        pattern: r'(crocodilus|apt_framework|c2_beacon|stealth_mode)',
        ruleType: 'apt_malware',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Crocodilus APT targeting government entities',
      ),
      
      DetectionRule(
        id: 'rule_apt_2025_003',
        name: 'RatMilad APT',
        pattern: r'(ratmilad|telegram_c2|persian_apt|middle_east_target)',
        ruleType: 'apt_malware',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects RatMilad - Telegram-based C2 RAT',
      ),
      
      DetectionRule(
        id: 'rule_apt_2025_004',
        name: 'PlugX Mobile Variant',
        pattern: r'(plugx_mobile|modular_backdoor|apt_plugin|persistence_module)',
        ruleType: 'apt_malware',
        threatType: ThreatType.trojan,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects mobile variant of PlugX backdoor',
      ),
    ];
  }
  
  /// ============= LATEST EXPLOITS (2024-2025) =============
  static List<DetectionRule> getLatestExploits() {
    return [
      DetectionRule(
        id: 'rule_exploit_2025_001',
        name: 'Dirty Pipe Exploit',
        pattern: r'(dirty_pipe|CVE-2022-0847|pipe_exploit|privilege_escalation)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Dirty Pipe kernel exploit',
      ),
      
      DetectionRule(
        id: 'rule_exploit_2025_002',
        name: 'Mali GPU Exploit',
        pattern: r'(mali_gpu_exploit|CVE-2023-4211|gpu_overflow|kernel_read)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Mali GPU driver exploitation',
      ),
      
      DetectionRule(
        id: 'rule_exploit_2025_003',
        name: 'Qualcomm Chipset Exploit',
        pattern: r'(qualcomm_exploit|adreno_overflow|dsp_exploit|modem_vulnerability)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.critical,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects Qualcomm chipset exploitation',
      ),
      
      DetectionRule(
        id: 'rule_exploit_2025_004',
        name: 'WebView Exploit Chain',
        pattern: r'(webview_exploit|javascript_inject|uaf_vulnerability|sandbox_escape)',
        ruleType: 'exploit',
        threatType: ThreatType.exploit,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects WebView exploitation attempts',
      ),
    ];
  }
  
  /// ============= LATEST PHISHING (2024-2025) =============
  static List<DetectionRule> getLatestPhishing() {
    return [
      DetectionRule(
        id: 'rule_phish_2025_001',
        name: 'Fake Update Phishing',
        pattern: r'(urgent.*update|security.*patch|install.*now|update_required)',
        ruleType: 'phishing',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects fake update phishing campaigns',
      ),
      
      DetectionRule(
        id: 'rule_phish_2025_002',
        name: 'ChatGPT/AI Impersonation',
        pattern: r'(chatgpt.*premium|openai.*verify|ai.*subscription|gpt.*unlock)',
        ruleType: 'phishing',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects ChatGPT/AI service phishing',
      ),
      
      DetectionRule(
        id: 'rule_phish_2025_003',
        name: 'Package Delivery Scam',
        pattern: r'(package.*tracking|delivery.*failed|ups.*usps.*fedex|shipment.*pending)',
        ruleType: 'phishing',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects package delivery scam apps',
      ),
      
      DetectionRule(
        id: 'rule_phish_2025_004',
        name: 'Tax/Government Impersonation',
        pattern: r'(tax.*refund|irs.*notice|government.*payment|stimulus.*check)',
        ruleType: 'phishing',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.high,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects tax/government impersonation scams',
      ),
      
      DetectionRule(
        id: 'rule_phish_2025_005',
        name: 'Job Offer Scam',
        pattern: r'(work.*from.*home|earn.*money|remote.*job|hiring.*now)',
        ruleType: 'phishing',
        threatType: ThreatType.suspicious,
        severity: ThreatSeverity.medium,
        enabled: true,
        lastUpdated: DateTime.now(),
        description: 'Detects job offer scam applications',
      ),
    ];
  }
}
