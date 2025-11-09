import 'dart:io';
import 'dart:convert';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'fast_threat_intelligence_api.dart';
import 'fast_lookup_cache.dart';
import 'bloom_filter_manager.dart';

/// Heavy enterprise-grade threat intelligence database with SQLite
/// Contains 10,000+ malware signatures, APT groups, IoCs, MITRE ATT&CK, CVEs
/// Optimized for fast lookups with comprehensive indexing
class HeavyThreatIntelligenceDB {
  static Database? _database;
  static const String _dbName = 'adrig_threat_intel.db';
  static const int _dbVersion = 1;

  // Fast lookup components
  FastThreatIntelligenceAPI? _api;
  FastLookupCache? _cache;
  BloomFilterManager? _bloomFilter;
  
  // Performance tracking
  int _apiCalls = 0;
  int _cacheHits = 0;
  int _bloomFilterHits = 0;

  // Table definitions
  static const String TABLE_MALWARE_HASHES = 'malware_hashes';
  static const String TABLE_YARA_RULES = 'yara_rules';
  static const String TABLE_BEHAVIORAL_SIGNATURES = 'behavioral_signatures';
  static const String TABLE_MALWARE_FAMILIES = 'malware_families';
  static const String TABLE_APT_GROUPS = 'apt_groups';
  static const String TABLE_IOCS = 'indicators_of_compromise';
  static const String TABLE_MITRE_ATTACK = 'mitre_attack';
  static const String TABLE_CVE_DATABASE = 'cve_database';
  static const String TABLE_AI_MODELS = 'ai_models';
  static const String TABLE_STRING_PATTERNS = 'string_patterns';
  static const String TABLE_NETWORK_INDICATORS = 'network_indicators';
  static const String TABLE_API_SEQUENCES = 'api_sequences';
  static const String TABLE_PERMISSION_PATTERNS = 'permission_patterns';
  static const String TABLE_METADATA = 'metadata';

  /// Get database instance (singleton pattern)
  Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDatabase();
    return _database!;
  }

  /// Initialize SQLite database with comprehensive schema
  Future<Database> _initDatabase() async {
    final Directory documentsDirectory = await getApplicationDocumentsDirectory();
    final String path = join(documentsDirectory.path, _dbName);

    print('🏗️ Initializing Heavy Threat Intelligence Database...');
    print('📂 Path: $path');

    return await openDatabase(
      path,
      version: _dbVersion,
      onCreate: _onCreate,
      onUpgrade: _onUpgrade,
    );
  }

  /// Create database schema
  Future<void> _onCreate(Database db, int version) async {
    print('🔨 Creating database schema v$version...');

    // ==================== METADATA TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_METADATA (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        value TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      )
    ''');

    // ==================== MALWARE HASHES TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_MALWARE_HASHES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        md5 TEXT,
        sha1 TEXT,
        sha256 TEXT NOT NULL UNIQUE,
        sha512 TEXT,
        malware_name TEXT NOT NULL,
        malware_family TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        source TEXT,
        confidence REAL DEFAULT 1.0,
        tags TEXT,
        capabilities TEXT,
        target_platforms TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    // Create comprehensive indexes for fast hash lookups
    await db.execute('CREATE INDEX idx_md5 ON $TABLE_MALWARE_HASHES(md5)');
    await db.execute('CREATE INDEX idx_sha1 ON $TABLE_MALWARE_HASHES(sha1)');
    await db.execute('CREATE INDEX idx_sha256 ON $TABLE_MALWARE_HASHES(sha256)');
    await db.execute('CREATE INDEX idx_family ON $TABLE_MALWARE_HASHES(malware_family)');
    await db.execute('CREATE INDEX idx_threat_type ON $TABLE_MALWARE_HASHES(threat_type)');

    // ==================== YARA RULES TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_YARA_RULES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_name TEXT UNIQUE NOT NULL,
        rule_content TEXT NOT NULL,
        category TEXT NOT NULL,
        malware_family TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        author TEXT,
        reference TEXT,
        tags TEXT,
        enabled INTEGER DEFAULT 1,
        confidence REAL DEFAULT 0.9,
        false_positive_rate REAL DEFAULT 0.05,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_yara_category ON $TABLE_YARA_RULES(category)');
    await db.execute('CREATE INDEX idx_yara_enabled ON $TABLE_YARA_RULES(enabled)');

    // ==================== BEHAVIORAL SIGNATURES TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_BEHAVIORAL_SIGNATURES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        signature_name TEXT UNIQUE NOT NULL,
        behavior_type TEXT NOT NULL,
        pattern_data TEXT NOT NULL,
        malware_family TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        required_permissions TEXT,
        api_calls TEXT,
        network_patterns TEXT,
        file_operations TEXT,
        process_operations TEXT,
        confidence REAL DEFAULT 0.85,
        false_positive_rate REAL DEFAULT 0.1,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_behavior_type ON $TABLE_BEHAVIORAL_SIGNATURES(behavior_type)');

    // ==================== MALWARE FAMILIES TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_MALWARE_FAMILIES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        family_name TEXT UNIQUE NOT NULL,
        family_type TEXT NOT NULL,
        aliases TEXT,
        description TEXT,
        capabilities TEXT,
        evasion_techniques TEXT,
        propagation_methods TEXT,
        target_platforms TEXT,
        target_regions TEXT,
        first_discovered INTEGER NOT NULL,
        last_activity INTEGER NOT NULL,
        active INTEGER DEFAULT 1,
        sample_count INTEGER DEFAULT 0,
        severity TEXT NOT NULL,
        references TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    // ==================== APT GROUPS TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_APT_GROUPS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_name TEXT UNIQUE NOT NULL,
        aliases TEXT,
        country_origin TEXT,
        motivation TEXT,
        description TEXT,
        targets TEXT,
        capabilities TEXT,
        tools_used TEXT,
        malware_families TEXT,
        attack_vectors TEXT,
        ttps TEXT,
        first_seen INTEGER NOT NULL,
        last_activity INTEGER NOT NULL,
        active INTEGER DEFAULT 1,
        sophistication_level TEXT,
        references TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    // ==================== INDICATORS OF COMPROMISE ====================
    await db.execute('''
      CREATE TABLE $TABLE_IOCS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        ioc_value TEXT NOT NULL,
        malware_family TEXT,
        apt_group TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        active INTEGER DEFAULT 1,
        confidence REAL DEFAULT 0.9,
        tags TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_ioc_type ON $TABLE_IOCS(ioc_type)');
    await db.execute('CREATE INDEX idx_ioc_value ON $TABLE_IOCS(ioc_value)');
    await db.execute('CREATE INDEX idx_ioc_active ON $TABLE_IOCS(active)');

    // ==================== MITRE ATT&CK TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_MITRE_ATTACK (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        technique_id TEXT NOT NULL,
        technique_name TEXT NOT NULL,
        tactic TEXT NOT NULL,
        sub_technique_id TEXT,
        sub_technique_name TEXT,
        description TEXT,
        detection_methods TEXT,
        platforms TEXT,
        data_sources TEXT,
        permissions_required TEXT,
        impact_type TEXT,
        references TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_mitre_technique_id ON $TABLE_MITRE_ATTACK(technique_id)');
    await db.execute('CREATE INDEX idx_mitre_tactic ON $TABLE_MITRE_ATTACK(tactic)');

    // ==================== CVE DATABASE ====================
    await db.execute('''
      CREATE TABLE $TABLE_CVE_DATABASE (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_score REAL,
        cvss_vector TEXT,
        affected_products TEXT,
        affected_versions TEXT,
        exploit_available INTEGER DEFAULT 0,
        patch_available INTEGER DEFAULT 0,
        malware_exploiting TEXT,
        published_date INTEGER NOT NULL,
        last_modified INTEGER NOT NULL,
        references TEXT,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_cve_id ON $TABLE_CVE_DATABASE(cve_id)');
    await db.execute('CREATE INDEX idx_cve_severity ON $TABLE_CVE_DATABASE(severity)');

    // ==================== AI MODELS TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_AI_MODELS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT UNIQUE NOT NULL,
        model_type TEXT NOT NULL,
        model_version TEXT NOT NULL,
        model_path TEXT,
        description TEXT,
        input_features TEXT NOT NULL,
        output_classes TEXT NOT NULL,
        accuracy REAL,
        precision_score REAL,
        recall REAL,
        f1_score REAL,
        false_positive_rate REAL,
        training_date INTEGER,
        training_samples INTEGER,
        enabled INTEGER DEFAULT 1,
        priority INTEGER DEFAULT 5,
        inference_time_ms INTEGER,
        model_size_mb REAL,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_model_enabled ON $TABLE_AI_MODELS(enabled)');
    await db.execute('CREATE INDEX idx_model_priority ON $TABLE_AI_MODELS(priority)');

    // ==================== STRING PATTERNS TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_STRING_PATTERNS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_name TEXT UNIQUE NOT NULL,
        string_pattern TEXT NOT NULL,
        pattern_type TEXT NOT NULL,
        malware_family TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        regex INTEGER DEFAULT 0,
        case_sensitive INTEGER DEFAULT 1,
        confidence REAL DEFAULT 0.7,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    ''');

    // ==================== NETWORK INDICATORS TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_NETWORK_INDICATORS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indicator_name TEXT UNIQUE NOT NULL,
        indicator_type TEXT NOT NULL,
        domain TEXT,
        ip_address TEXT,
        port INTEGER,
        url_pattern TEXT,
        protocol TEXT,
        malware_family TEXT,
        apt_group TEXT,
        severity TEXT NOT NULL,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL,
        active INTEGER DEFAULT 1,
        confidence REAL DEFAULT 0.9,
        created_at INTEGER NOT NULL
      )
    ''');

    await db.execute('CREATE INDEX idx_network_domain ON $TABLE_NETWORK_INDICATORS(domain)');
    await db.execute('CREATE INDEX idx_network_ip ON $TABLE_NETWORK_INDICATORS(ip_address)');

    // ==================== API SEQUENCES TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_API_SEQUENCES (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sequence_name TEXT UNIQUE NOT NULL,
        api_calls TEXT NOT NULL,
        call_order TEXT NOT NULL,
        malware_family TEXT,
        behavior_category TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        min_occurrences INTEGER DEFAULT 1,
        time_window_ms INTEGER,
        confidence REAL DEFAULT 0.85,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    ''');

    // ==================== PERMISSION PATTERNS TABLE ====================
    await db.execute('''
      CREATE TABLE $TABLE_PERMISSION_PATTERNS (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern_name TEXT UNIQUE NOT NULL,
        permissions TEXT NOT NULL,
        permission_combination TEXT NOT NULL,
        malware_family TEXT,
        behavior_type TEXT,
        severity TEXT NOT NULL,
        description TEXT,
        risk_score REAL DEFAULT 0.5,
        confidence REAL DEFAULT 0.7,
        enabled INTEGER DEFAULT 1,
        created_at INTEGER NOT NULL
      )
    ''');

    print('✅ Database schema created successfully');

    // Initialize metadata
    await _initializeMetadata(db);
    
    // Populate with comprehensive threat intelligence
    await _populateHeavyIntelligence(db);
  }

  /// Handle database upgrades
  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    print('⬆️ Upgrading database from v$oldVersion to v$newVersion');
    // Migration logic for future versions
  }

  /// Initialize metadata
  Future<void> _initializeMetadata(Database db) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    
    await db.insert(TABLE_METADATA, {
      'key': 'db_version',
      'value': _dbVersion.toString(),
      'updated_at': now,
    });

    await db.insert(TABLE_METADATA, {
      'key': 'last_update',
      'value': now.toString(),
      'updated_at': now,
    });

    await db.insert(TABLE_METADATA, {
      'key': 'total_signatures',
      'value': '0',
      'updated_at': now,
    });
  }

  /// Populate database with 10,000+ threat intelligence signatures
  Future<void> _populateHeavyIntelligence(Database db) async {
    print('📊 Populating Heavy Threat Intelligence Database...');
    print('⏳ This may take a few moments...');
    
    final now = DateTime.now().millisecondsSinceEpoch;
    int totalRecords = 0;

    // Populate all tables in parallel for speed
    await Future.wait([
      _populateMalwareHashes(db, now).then((count) => totalRecords += count),
      _populateYaraRules(db, now).then((count) => totalRecords += count),
      _populateBehavioralSignatures(db, now).then((count) => totalRecords += count),
      _populateMalwareFamilies(db, now).then((count) => totalRecords += count),
      _populateAPTGroups(db, now).then((count) => totalRecords += count),
      _populateIOCs(db, now).then((count) => totalRecords += count),
      _populateMitreAttack(db, now).then((count) => totalRecords += count),
      _populateCVEDatabase(db, now).then((count) => totalRecords += count),
      _populateAIModels(db, now).then((count) => totalRecords += count),
      _populateStringPatterns(db, now).then((count) => totalRecords += count),
      _populateNetworkIndicators(db, now).then((count) => totalRecords += count),
      _populateAPISequences(db, now).then((count) => totalRecords += count),
      _populatePermissionPatterns(db, now).then((count) => totalRecords += count),
    ]);

    // Update metadata
    await db.update(
      TABLE_METADATA,
      {'value': totalRecords.toString(), 'updated_at': now},
      where: 'key = ?',
      whereArgs: ['total_signatures'],
    );

    print('✅ Database populated with $totalRecords intelligence records');
  }

  /// Populate 5,000+ malware hashes (real-world Android malware)
  Future<int> _populateMalwareHashes(Database db, int now) async {
    print('  📱 Loading malware hash signatures...');
    
    // Load from JSON file (contains 5,000+ real Android malware hashes)
    final String jsonData = await _loadAsset('assets/data/malware_hashes.json');
    final List<dynamic> hashes = json.decode(jsonData);
    
    int count = 0;
    final batch = db.batch();
    
    for (final hash in hashes) {
      batch.insert(TABLE_MALWARE_HASHES, {
        'md5': hash['md5'],
        'sha1': hash['sha1'],
        'sha256': hash['sha256'],
        'sha512': hash['sha512'],
        'malware_name': hash['name'],
        'malware_family': hash['family'],
        'threat_type': hash['type'],
        'severity': hash['severity'],
        'description': hash['description'],
        'first_seen': _parseDate(hash['first_seen']),
        'last_seen': _parseDate(hash['last_seen']),
        'source': hash['source'],
        'confidence': hash['confidence'] ?? 1.0,
        'tags': json.encode(hash['tags'] ?? []),
        'capabilities': json.encode(hash['capabilities'] ?? []),
        'target_platforms': json.encode(hash['platforms'] ?? ['Android']),
        'created_at': now,
      });
      count++;
      
      // Commit in batches of 500 for performance
      if (count % 500 == 0) {
        await batch.commit(noResult: true);
      }
    }
    
    await batch.commit(noResult: true);
    print('    ✓ Loaded $count malware hashes');
    return count;
  }

  /// Populate 200+ YARA rules
  Future<int> _populateYaraRules(Database db, int now) async {
    print('  🔍 Loading YARA detection rules...');
    
    final String jsonData = await _loadAsset('assets/data/yara_rules.json');
    final List<dynamic> rules = json.decode(jsonData);
    
    int count = 0;
    for (final rule in rules) {
      await db.insert(TABLE_YARA_RULES, {
        'rule_name': rule['name'],
        'rule_content': rule['content'],
        'category': rule['category'],
        'malware_family': rule['family'],
        'severity': rule['severity'],
        'description': rule['description'],
        'author': rule['author'],
        'reference': rule['reference'],
        'tags': json.encode(rule['tags'] ?? []),
        'enabled': 1,
        'confidence': rule['confidence'] ?? 0.9,
        'false_positive_rate': rule['fpr'] ?? 0.05,
        'created_at': now,
        'updated_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count YARA rules');
    return count;
  }

  /// Populate 500+ behavioral signatures
  Future<int> _populateBehavioralSignatures(Database db, int now) async {
    print('  🧠 Loading behavioral signatures...');
    
    final String jsonData = await _loadAsset('assets/data/behavioral_signatures.json');
    final List<dynamic> signatures = json.decode(jsonData);
    
    int count = 0;
    for (final sig in signatures) {
      await db.insert(TABLE_BEHAVIORAL_SIGNATURES, {
        'signature_name': sig['name'],
        'behavior_type': sig['type'],
        'pattern_data': json.encode(sig['pattern']),
        'malware_family': sig['family'],
        'severity': sig['severity'],
        'description': sig['description'],
        'required_permissions': json.encode(sig['permissions'] ?? []),
        'api_calls': json.encode(sig['apis'] ?? []),
        'network_patterns': json.encode(sig['network'] ?? []),
        'file_operations': json.encode(sig['files'] ?? []),
        'process_operations': json.encode(sig['processes'] ?? []),
        'confidence': sig['confidence'] ?? 0.85,
        'false_positive_rate': sig['fpr'] ?? 0.1,
        'enabled': 1,
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count behavioral signatures');
    return count;
  }

  /// Populate 200+ malware families
  Future<int> _populateMalwareFamilies(Database db, int now) async {
    print('  🦠 Loading malware families database...');
    
    final String jsonData = await _loadAsset('assets/data/malware_families.json');
    final List<dynamic> families = json.decode(jsonData);
    
    int count = 0;
    for (final family in families) {
      await db.insert(TABLE_MALWARE_FAMILIES, {
        'family_name': family['name'],
        'family_type': family['type'],
        'aliases': json.encode(family['aliases'] ?? []),
        'description': family['description'],
        'capabilities': json.encode(family['capabilities'] ?? []),
        'evasion_techniques': json.encode(family['evasion'] ?? []),
        'propagation_methods': json.encode(family['propagation'] ?? []),
        'target_platforms': json.encode(family['platforms'] ?? []),
        'target_regions': json.encode(family['regions'] ?? []),
        'first_discovered': _parseDate(family['first_discovered']),
        'last_activity': _parseDate(family['last_activity']),
        'active': family['active'] ?? 1,
        'sample_count': family['sample_count'] ?? 0,
        'severity': family['severity'],
        'references': json.encode(family['references'] ?? []),
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count malware families');
    return count;
  }

  /// Populate 100+ APT groups
  Future<int> _populateAPTGroups(Database db, int now) async {
    print('  🎯 Loading APT groups intelligence...');
    
    final String jsonData = await _loadAsset('assets/data/apt_groups.json');
    final List<dynamic> groups = json.decode(jsonData);
    
    int count = 0;
    for (final group in groups) {
      await db.insert(TABLE_APT_GROUPS, {
        'group_name': group['name'],
        'aliases': json.encode(group['aliases'] ?? []),
        'country_origin': group['origin'],
        'motivation': group['motivation'],
        'description': group['description'],
        'targets': json.encode(group['targets'] ?? []),
        'capabilities': json.encode(group['capabilities'] ?? []),
        'tools_used': json.encode(group['tools'] ?? []),
        'malware_families': json.encode(group['families'] ?? []),
        'attack_vectors': json.encode(group['vectors'] ?? []),
        'ttps': json.encode(group['ttps'] ?? []),
        'first_seen': _parseDate(group['first_seen']),
        'last_activity': _parseDate(group['last_activity']),
        'active': group['active'] ?? 1,
        'sophistication_level': group['sophistication'],
        'references': json.encode(group['references'] ?? []),
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count APT groups');
    return count;
  }

  /// Populate 2,000+ indicators of compromise
  Future<int> _populateIOCs(Database db, int now) async {
    print('  🚨 Loading indicators of compromise...');
    
    final String jsonData = await _loadAsset('assets/data/iocs.json');
    final List<dynamic> iocs = json.decode(jsonData);
    
    int count = 0;
    final batch = db.batch();
    
    for (final ioc in iocs) {
      batch.insert(TABLE_IOCS, {
        'ioc_type': ioc['type'],
        'ioc_value': ioc['value'],
        'malware_family': ioc['family'],
        'apt_group': ioc['apt_group'],
        'severity': ioc['severity'],
        'description': ioc['description'],
        'first_seen': _parseDate(ioc['first_seen']),
        'last_seen': _parseDate(ioc['last_seen']),
        'active': ioc['active'] ?? 1,
        'confidence': ioc['confidence'] ?? 0.9,
        'tags': json.encode(ioc['tags'] ?? []),
        'created_at': now,
      });
      count++;
      
      if (count % 500 == 0) {
        await batch.commit(noResult: true);
      }
    }
    
    await batch.commit(noResult: true);
    print('    ✓ Loaded $count IoCs');
    return count;
  }

  /// Populate 150+ MITRE ATT&CK techniques (Android-specific)
  Future<int> _populateMitreAttack(Database db, int now) async {
    print('  ⚔️ Loading MITRE ATT&CK techniques...');
    
    final String jsonData = await _loadAsset('assets/data/mitre_attack.json');
    final List<dynamic> techniques = json.decode(jsonData);
    
    int count = 0;
    for (final tech in techniques) {
      await db.insert(TABLE_MITRE_ATTACK, {
        'technique_id': tech['id'],
        'technique_name': tech['name'],
        'tactic': tech['tactic'],
        'sub_technique_id': tech['sub_id'],
        'sub_technique_name': tech['sub_name'],
        'description': tech['description'],
        'detection_methods': json.encode(tech['detection'] ?? []),
        'platforms': json.encode(tech['platforms'] ?? []),
        'data_sources': json.encode(tech['data_sources'] ?? []),
        'permissions_required': json.encode(tech['permissions'] ?? []),
        'impact_type': tech['impact'],
        'references': json.encode(tech['references'] ?? []),
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count MITRE ATT&CK techniques');
    return count;
  }

  /// Populate 500+ CVE database (Android-related vulnerabilities)
  Future<int> _populateCVEDatabase(Database db, int now) async {
    print('  🔓 Loading CVE vulnerability database...');
    
    final String jsonData = await _loadAsset('assets/data/cves.json');
    final List<dynamic> cves = json.decode(jsonData);
    
    int count = 0;
    for (final cve in cves) {
      await db.insert(TABLE_CVE_DATABASE, {
        'cve_id': cve['id'],
        'description': cve['description'],
        'severity': cve['severity'],
        'cvss_score': cve['cvss_score'],
        'cvss_vector': cve['cvss_vector'],
        'affected_products': json.encode(cve['products'] ?? []),
        'affected_versions': json.encode(cve['versions'] ?? []),
        'exploit_available': cve['exploit_available'] ?? 0,
        'patch_available': cve['patch_available'] ?? 0,
        'malware_exploiting': json.encode(cve['exploited_by'] ?? []),
        'published_date': _parseDate(cve['published']),
        'last_modified': _parseDate(cve['modified']),
        'references': json.encode(cve['references'] ?? []),
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count CVEs');
    return count;
  }

  /// Populate 10+ AI/ML models metadata
  Future<int> _populateAIModels(Database db, int now) async {
    print('  🤖 Loading AI models metadata...');
    
    final String jsonData = await _loadAsset('assets/data/ai_models.json');
    final List<dynamic> models = json.decode(jsonData);
    
    int count = 0;
    for (final model in models) {
      await db.insert(TABLE_AI_MODELS, {
        'model_name': model['name'],
        'model_type': model['type'],
        'model_version': model['version'],
        'model_path': model['path'],
        'description': model['description'],
        'input_features': json.encode(model['features'] ?? []),
        'output_classes': json.encode(model['classes'] ?? []),
        'accuracy': model['accuracy'],
        'precision_score': model['precision'],
        'recall': model['recall'],
        'f1_score': model['f1'],
        'false_positive_rate': model['fpr'],
        'training_date': _parseDate(model['training_date']),
        'training_samples': model['training_samples'],
        'enabled': model['enabled'] ?? 1,
        'priority': model['priority'] ?? 5,
        'inference_time_ms': model['inference_ms'],
        'model_size_mb': model['size_mb'],
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count AI models');
    return count;
  }

  /// Populate 1,000+ string patterns
  Future<int> _populateStringPatterns(Database db, int now) async {
    print('  📝 Loading string detection patterns...');
    
    final String jsonData = await _loadAsset('assets/data/string_patterns.json');
    final List<dynamic> patterns = json.decode(jsonData);
    
    int count = 0;
    for (final pattern in patterns) {
      await db.insert(TABLE_STRING_PATTERNS, {
        'pattern_name': pattern['name'],
        'string_pattern': pattern['pattern'],
        'pattern_type': pattern['type'],
        'malware_family': pattern['family'],
        'severity': pattern['severity'],
        'description': pattern['description'],
        'regex': pattern['regex'] ?? 0,
        'case_sensitive': pattern['case_sensitive'] ?? 1,
        'confidence': pattern['confidence'] ?? 0.7,
        'enabled': 1,
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count string patterns');
    return count;
  }

  /// Populate 500+ network indicators (C2, malicious domains/IPs)
  Future<int> _populateNetworkIndicators(Database db, int now) async {
    print('  🌐 Loading network threat indicators...');
    
    final String jsonData = await _loadAsset('assets/data/network_indicators.json');
    final List<dynamic> indicators = json.decode(jsonData);
    
    int count = 0;
    for (final indicator in indicators) {
      await db.insert(TABLE_NETWORK_INDICATORS, {
        'indicator_name': indicator['name'],
        'indicator_type': indicator['type'],
        'domain': indicator['domain'],
        'ip_address': indicator['ip'],
        'port': indicator['port'],
        'url_pattern': indicator['url_pattern'],
        'protocol': indicator['protocol'],
        'malware_family': indicator['family'],
        'apt_group': indicator['apt_group'],
        'severity': indicator['severity'],
        'first_seen': _parseDate(indicator['first_seen']),
        'last_seen': _parseDate(indicator['last_seen']),
        'active': indicator['active'] ?? 1,
        'confidence': indicator['confidence'] ?? 0.9,
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count network indicators');
    return count;
  }

  /// Populate 300+ API call sequences
  Future<int> _populateAPISequences(Database db, int now) async {
    print('  📞 Loading API call sequences...');
    
    final String jsonData = await _loadAsset('assets/data/api_sequences.json');
    final List<dynamic> sequences = json.decode(jsonData);
    
    int count = 0;
    for (final seq in sequences) {
      await db.insert(TABLE_API_SEQUENCES, {
        'sequence_name': seq['name'],
        'api_calls': json.encode(seq['calls'] ?? []),
        'call_order': seq['order'],
        'malware_family': seq['family'],
        'behavior_category': seq['category'],
        'severity': seq['severity'],
        'description': seq['description'],
        'min_occurrences': seq['min_occurrences'] ?? 1,
        'time_window_ms': seq['time_window'],
        'confidence': seq['confidence'] ?? 0.85,
        'enabled': 1,
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count API sequences');
    return count;
  }

  /// Populate 200+ permission patterns
  Future<int> _populatePermissionPatterns(Database db, int now) async {
    print('  🔐 Loading permission patterns...');
    
    final String jsonData = await _loadAsset('assets/data/permission_patterns.json');
    final List<dynamic> patterns = json.decode(jsonData);
    
    int count = 0;
    for (final pattern in patterns) {
      await db.insert(TABLE_PERMISSION_PATTERNS, {
        'pattern_name': pattern['name'],
        'permissions': json.encode(pattern['permissions'] ?? []),
        'permission_combination': pattern['combination'],
        'malware_family': pattern['family'],
        'behavior_type': pattern['behavior'],
        'severity': pattern['severity'],
        'description': pattern['description'],
        'risk_score': pattern['risk_score'] ?? 0.5,
        'confidence': pattern['confidence'] ?? 0.7,
        'enabled': 1,
        'created_at': now,
      });
      count++;
    }
    
    print('    ✓ Loaded $count permission patterns');
    return count;
  }

  // ==================== HELPER METHODS ====================

  /// Load JSON asset (fallback to empty data if missing)
  Future<String> _loadAsset(String path) async {
    try {
      return await File(path).readAsString();
    } catch (e) {
      print('⚠️ Could not load $path, using fallback data');
      return '[]'; // Return empty array as fallback
    }
  }

  /// Parse date string to milliseconds since epoch
  int _parseDate(dynamic date) {
    if (date == null) return DateTime.now().millisecondsSinceEpoch;
    if (date is int) return date;
    if (date is String) {
      try {
        return DateTime.parse(date).millisecondsSinceEpoch;
      } catch (e) {
        return DateTime.now().millisecondsSinceEpoch;
      }
    }
    return DateTime.now().millisecondsSinceEpoch;
  }

  // ==================== QUERY METHODS ====================

  /// Search malware hash (supports MD5, SHA1, SHA256, SHA512)
  Future<Map<String, dynamic>?> searchHash({
    String? md5,
    String? sha1,
    String? sha256,
    String? sha512,
  }) async {
    final db = await database;
    
    if (sha256 != null) {
      final results = await db.query(
        TABLE_MALWARE_HASHES,
        where: 'sha256 = ?',
        whereArgs: [sha256.toLowerCase()],
        limit: 1,
      );
      if (results.isNotEmpty) return results.first;
    }
    
    if (sha1 != null) {
      final results = await db.query(
        TABLE_MALWARE_HASHES,
        where: 'sha1 = ?',
        whereArgs: [sha1.toLowerCase()],
        limit: 1,
      );
      if (results.isNotEmpty) return results.first;
    }
    
    if (md5 != null) {
      final results = await db.query(
        TABLE_MALWARE_HASHES,
        where: 'md5 = ?',
        whereArgs: [md5.toLowerCase()],
        limit: 1,
      );
      if (results.isNotEmpty) return results.first;
    }
    
    if (sha512 != null) {
      final results = await db.query(
        TABLE_MALWARE_HASHES,
        where: 'sha512 = ?',
        whereArgs: [sha512.toLowerCase()],
        limit: 1,
      );
      if (results.isNotEmpty) return results.first;
    }
    
    return null;
  }

  /// Get all enabled YARA rules
  Future<List<Map<String, dynamic>>> getEnabledYaraRules() async {
    final db = await database;
    return await db.query(
      TABLE_YARA_RULES,
      where: 'enabled = ?',
      whereArgs: [1],
      orderBy: 'confidence DESC',
    );
  }

  /// Get behavioral signatures by type
  Future<List<Map<String, dynamic>>> getBehavioralSignatures({String? type}) async {
    final db = await database;
    if (type != null) {
      return await db.query(
        TABLE_BEHAVIORAL_SIGNATURES,
        where: 'behavior_type = ? AND enabled = ?',
        whereArgs: [type, 1],
      );
    }
    return await db.query(
      TABLE_BEHAVIORAL_SIGNATURES,
      where: 'enabled = ?',
      whereArgs: [1],
    );
  }

  /// Get database statistics
  Future<Map<String, int>> getStatistics() async {
    final db = await database;
    
    final stats = <String, int>{};
    
    stats['malware_hashes'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_MALWARE_HASHES')
    ) ?? 0;
    
    stats['yara_rules'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_YARA_RULES')
    ) ?? 0;
    
    stats['behavioral_signatures'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_BEHAVIORAL_SIGNATURES')
    ) ?? 0;
    
    stats['malware_families'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_MALWARE_FAMILIES')
    ) ?? 0;
    
    stats['apt_groups'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_APT_GROUPS')
    ) ?? 0;
    
    stats['iocs'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_IOCS')
    ) ?? 0;
    
    stats['mitre_techniques'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_MITRE_ATTACK')
    ) ?? 0;
    
    stats['cves'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_CVE_DATABASE')
    ) ?? 0;
    
    stats['ai_models'] = Sqflite.firstIntValue(
      await db.rawQuery('SELECT COUNT(*) FROM $TABLE_AI_MODELS')
    ) ?? 0;
    
    return stats;
  }
  
  // ==================== FAST LOOKUP METHODS ====================
  
  /// Initialize fast lookup system (API + Cache + Bloom Filter)
  Future<void> initializeFastLookup({
    String? apiBaseUrl,
    bool enableBloomFilter = true,
  }) async {
    print('🚀 Initializing fast lookup system...');
    
    // Initialize API client for remote lookups
    if (apiBaseUrl != null) {
      _api = FastThreatIntelligenceAPI(
        baseUrl: apiBaseUrl,
        timeout: Duration(milliseconds: 50), // <20ms target
      );
      print('  ✓ API client initialized: $apiBaseUrl');
    }
    
    // Initialize multi-layer cache
    _cache = FastLookupCache(
      l1HashCapacity: 10000, // Top 10% hottest hashes
      l1IOCCapacity: 50000, // Top 10% hottest IOCs
      defaultTTL: Duration(hours: 24),
    );
    await _cache!.initialize();
    print('  ✓ Multi-layer cache initialized (L1+L2+L3)');
    
    // Initialize bloom filter for known-clean preflight checks
    if (enableBloomFilter) {
      _bloomFilter = BloomFilterManager(
        expectedElements: 1000000, // 1M known-clean hashes
        falsePositiveRate: 0.01, // 1% FPR
      );
      
      // Try to load existing bloom filter
      final loaded = await _bloomFilter!.loadFromDisk();
      if (!loaded) {
        print('  ⚠️ Bloom filter not found, starting fresh');
      } else {
        print('  ✓ Bloom filter loaded from disk');
      }
    }
    
    print('✅ Fast lookup system ready');
  }
  
  /// Fast hash lookup with multi-layer fallback
  /// Lookup chain: Bloom Filter → Cache (L1→L2→L3) → API → Local DB
  /// Target: <20ms p95 latency
  Future<FastHashLookupResult> fastHashLookup(String sha256) async {
    final stopwatch = Stopwatch()..start();
    String source = 'unknown';
    
    try {
      // Step 1: Bloom filter preflight check (instant, on-device)
      if (_bloomFilter != null && _bloomFilter!.mightContain(sha256)) {
        _bloomFilterHits++;
        stopwatch.stop();
        return FastHashLookupResult(
          hash: sha256,
          verdict: 'clean',
          confidence: 0.99, // High confidence for bloom filter hits
          source: 'bloom_filter',
          latencyMs: stopwatch.elapsedMilliseconds,
          cached: false,
        );
      }
      
      // Step 2: Check multi-layer cache
      if (_cache != null) {
        final (cachedResult, cacheLevel) = await _cache!.getHash(sha256);
        if (cachedResult != null) {
          _cacheHits++;
          stopwatch.stop();
          return FastHashLookupResult(
            hash: sha256,
            verdict: cachedResult.verdict,
            confidence: cachedResult.confidence,
            malwareFamily: cachedResult.malwareFamily,
            tags: cachedResult.tags,
            source: 'cache_$cacheLevel',
            latencyMs: stopwatch.elapsedMilliseconds,
            cached: true,
          );
        }
      }
      
      // Step 3: Try remote API (Redis → Cassandra)
      if (_api != null) {
        try {
          _apiCalls++;
          final apiResult = await _api!.lookupHash(sha256);
          
          if (apiResult != null) {
            source = 'api_${apiResult.source}';
            
            // Cache the result for future lookups
            if (_cache != null) {
              await _cache!.putHash(
                sha256,
                CachedHashResult(
                  hash: sha256,
                  verdict: apiResult.verdict,
                  confidence: apiResult.confidence,
                  malwareFamily: apiResult.malwareFamily,
                  tags: apiResult.tags,
                  source: apiResult.source,
                  cachedAt: DateTime.now(),
                  expiresAt: DateTime.now().add(Duration(seconds: apiResult.ttl)),
                ),
              );
            }
            
            // If clean, add to bloom filter
            if (apiResult.verdict == 'clean' && _bloomFilter != null) {
              _bloomFilter!.addHash(sha256);
            }
            
            stopwatch.stop();
            return FastHashLookupResult(
              hash: sha256,
              verdict: apiResult.verdict,
              confidence: apiResult.confidence,
              malwareFamily: apiResult.malwareFamily,
              tags: apiResult.tags,
              source: source,
              latencyMs: stopwatch.elapsedMilliseconds,
              cached: false,
            );
          }
        } on ApiTimeoutException catch (e) {
          print('⚠️ API timeout: ${e.message}, falling back to local DB');
        } on CircuitBreakerOpenException catch (e) {
          print('⚠️ Circuit breaker open, falling back to local DB');
        } catch (e) {
          print('⚠️ API error: $e, falling back to local DB');
        }
      }
      
      // Step 4: Fallback to local SQLite database
      final localResult = await searchHash(sha256: sha256);
      stopwatch.stop();
      
      if (localResult != null) {
        source = 'local_db';
        return FastHashLookupResult(
          hash: sha256,
          verdict: 'malicious',
          confidence: localResult['confidence'] as double? ?? 1.0,
          malwareFamily: localResult['malware_family'] as String?,
          tags: _parseTags(localResult['tags'] as String?),
          source: source,
          latencyMs: stopwatch.elapsedMilliseconds,
          cached: false,
        );
      }
      
      // Not found anywhere - assume clean
      source = 'not_found';
      return FastHashLookupResult(
        hash: sha256,
        verdict: 'clean',
        confidence: 0.5, // Low confidence for unknown
        source: source,
        latencyMs: stopwatch.elapsedMilliseconds,
        cached: false,
      );
    } finally {
      stopwatch.stop();
    }
  }
  
  /// Batch IOC lookup with caching
  /// Supports 50-500 IOCs per request
  Future<Map<String, FastIOCLookupResult>> batchIOCLookup(List<String> iocs) async {
    if (iocs.isEmpty) return {};
    if (iocs.length > 500) {
      throw ArgumentError('Batch size must be ≤500 items (got ${iocs.length})');
    }
    
    final stopwatch = Stopwatch()..start();
    final results = <String, FastIOCLookupResult>{};
    final cacheMisses = <String>[];
    
    // Step 1: Check cache for all IOCs
    if (_cache != null) {
      final cachedResults = await _cache!.batchGetIOCs(iocs);
      for (var entry in cachedResults.entries) {
        results[entry.key] = FastIOCLookupResult(
          ioc: entry.key,
          type: entry.value.type,
          reputation: entry.value.reputation,
          latestSource: entry.value.latestSource,
          latencyMs: stopwatch.elapsedMilliseconds,
          cached: true,
        );
      }
      
      // Track misses
      for (var ioc in iocs) {
        if (!results.containsKey(ioc)) {
          cacheMisses.add(ioc);
        }
      }
    } else {
      cacheMisses.addAll(iocs);
    }
    
    if (cacheMisses.isEmpty) {
      stopwatch.stop();
      return results;
    }
    
    // Step 2: Fetch misses from API
    if (_api != null) {
      try {
        _apiCalls++;
        final apiResults = await _api!.batchLookupIOCs(cacheMisses);
        
        final toCache = <String, CachedIOCResult>{};
        for (var apiResult in apiResults) {
          results[apiResult.ioc] = FastIOCLookupResult(
            ioc: apiResult.ioc,
            type: apiResult.type,
            reputation: apiResult.reputation,
            latestSource: apiResult.latestSource,
            latencyMs: stopwatch.elapsedMilliseconds,
            cached: false,
          );
          
          // Prepare for batch caching
          toCache[apiResult.ioc] = CachedIOCResult(
            ioc: apiResult.ioc,
            type: apiResult.type,
            reputation: apiResult.reputation,
            latestSource: apiResult.latestSource,
            cachedAt: DateTime.now(),
            expiresAt: DateTime.now().add(Duration(seconds: apiResult.ttl)),
          );
        }
        
        // Batch cache the results
        if (_cache != null && toCache.isNotEmpty) {
          await _cache!.batchPutIOCs(toCache);
        }
      } catch (e) {
        print('⚠️ Batch IOC lookup error: $e');
      }
    }
    
    stopwatch.stop();
    return results;
  }
  
  /// Fuzzy string search via ElasticSearch
  Future<List<StringSearchResult>> fuzzyStringSearch(
    String query, {
    int limit = 50,
    double minScore = 0.7,
  }) async {
    if (_api == null) {
      throw StateError('API client not initialized. Call initializeFastLookup() first.');
    }
    
    try {
      return await _api!.fuzzySearchStrings(query, limit: limit, minScore: minScore);
    } catch (e) {
      print('⚠️ Fuzzy search error: $e');
      return [];
    }
  }
  
  /// Server-side YARA matching for heavy rules
  Future<YaraMatchResult?> serverSideYaraMatch(String fileHash, List<String> ruleIds) async {
    if (_api == null) {
      throw StateError('API client not initialized. Call initializeFastLookup() first.');
    }
    
    try {
      return await _api!.runYaraMatch(fileHash, ruleIds);
    } catch (e) {
      print('⚠️ Server-side YARA match error: $e');
      return null;
    }
  }
  
  /// Graph traversal for threat correlation
  Future<GraphQueryResult?> getGraphNeighbors({
    required String node,
    int depth = 2,
    int limit = 100,
  }) async {
    if (_api == null) {
      throw StateError('API client not initialized. Call initializeFastLookup() first.');
    }
    
    try {
      return await _api!.getGraphNeighbors(
        node: node,
        depth: depth,
        limit: limit,
      );
    } catch (e) {
      print('⚠️ Graph query error: $e');
      return null;
    }
  }
  
  /// Update bloom filter from server (daily delta)
  Future<void> updateBloomFilter(String apiBaseUrl) async {
    if (_bloomFilter == null) {
      print('⚠️ Bloom filter not initialized');
      return;
    }
    
    print('📥 Downloading bloom filter delta...');
    final success = await _bloomFilter!.downloadAndApplyDelta(apiBaseUrl);
    
    if (success) {
      print('✅ Bloom filter updated successfully');
    } else {
      print('⚠️ Bloom filter update failed');
    }
  }
  
  /// Get performance statistics
  FastLookupStatistics getFastLookupStats() {
    return FastLookupStatistics(
      apiCalls: _apiCalls,
      cacheHits: _cacheHits,
      bloomFilterHits: _bloomFilterHits,
      apiStats: _api?.getStats(),
      cacheStats: _cache?.getStatistics(),
      bloomFilterStats: _bloomFilter?.getStats(),
    );
  }
  
  List<String> _parseTags(String? tagsJson) {
    if (tagsJson == null || tagsJson.isEmpty) return [];
    try {
      final decoded = json.decode(tagsJson);
      if (decoded is List) return decoded.cast<String>();
      return [];
    } catch (e) {
      return [];
    }
  }

  /// Close database
  Future<void> close() async {
    final db = await database;
    await db.close();
    _database = null;
    _api?.dispose();
  }
}

// ==================== RESULT CLASSES ====================

/// Fast hash lookup result
class FastHashLookupResult {
  final String hash;
  final String verdict; // 'malicious', 'suspicious', 'clean'
  final double confidence;
  final String? malwareFamily;
  final List<String> tags;
  final String source; // 'bloom_filter', 'cache_L1', 'cache_L2', 'cache_L3', 'api_*', 'local_db', 'not_found'
  final int latencyMs;
  final bool cached;
  
  FastHashLookupResult({
    required this.hash,
    required this.verdict,
    required this.confidence,
    this.malwareFamily,
    List<String>? tags,
    required this.source,
    required this.latencyMs,
    required this.cached,
  }) : tags = tags ?? [];
  
  bool get isMalicious => verdict == 'malicious';
  bool get isSuspicious => verdict == 'suspicious';
  bool get isClean => verdict == 'clean';
  
  @override
  String toString() {
    return 'FastHashLookup($hash: $verdict, confidence: $confidence, source: $source, ${latencyMs}ms)';
  }
}

/// Fast IOC lookup result
class FastIOCLookupResult {
  final String ioc;
  final String type;
  final int reputation; // 0-100 (0=malicious, 100=clean)
  final String latestSource;
  final int latencyMs;
  final bool cached;
  
  FastIOCLookupResult({
    required this.ioc,
    required this.type,
    required this.reputation,
    required this.latestSource,
    required this.latencyMs,
    required this.cached,
  });
  
  bool get isMalicious => reputation < 30;
  bool get isSuspicious => reputation >= 30 && reputation < 70;
  bool get isClean => reputation >= 70;
  
  @override
  String toString() {
    return 'FastIOCLookup($ioc: reputation=$reputation, source: $latestSource, ${latencyMs}ms)';
  }
}

/// Fast lookup performance statistics
class FastLookupStatistics {
  final int apiCalls;
  final int cacheHits;
  final int bloomFilterHits;
  final APIPerformanceStats? apiStats;
  final CacheStatistics? cacheStats;
  final BloomFilterStats? bloomFilterStats;
  
  FastLookupStatistics({
    required this.apiCalls,
    required this.cacheHits,
    required this.bloomFilterHits,
    this.apiStats,
    this.cacheStats,
    this.bloomFilterStats,
  });
  
  @override
  String toString() {
    final buffer = StringBuffer();
    buffer.writeln('=== Fast Lookup Performance ===');
    buffer.writeln('API Calls: $apiCalls');
    buffer.writeln('Cache Hits: $cacheHits');
    buffer.writeln('Bloom Filter Hits: $bloomFilterHits');
    
    if (apiStats != null) {
      buffer.writeln('\n$apiStats');
    }
    
    if (cacheStats != null) {
      buffer.writeln('\n$cacheStats');
    }
    
    if (bloomFilterStats != null) {
      buffer.writeln('\n$bloomFilterStats');
    }
    
    return buffer.toString();
  }
}
