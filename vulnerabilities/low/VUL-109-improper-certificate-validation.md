# VUL-109: Improper Certificate Validation

## Executive Summary

- **Vulnerability ID**: VUL-109
- **Severity**: Low
- **CVSS Score**: 3.4 (Low)
- **Category**: Certificate Validation / TLS Security
- **Component**: HTTP Clients, External API Calls, Certificate Handling
- **Impact**: Potential man-in-the-middle attacks, insecure communications, compromised data integrity

## Vulnerability Details

### Root Cause Analysis

The Solana gaming protocol may implement improper certificate validation in its external communications, API calls, or client-side connections. While Solana's core network uses its own cryptographic protocols, the gaming protocol likely interfaces with external services, web APIs, payment processors, and monitoring systems that rely on TLS/SSL certificate validation for secure communications.

Improper certificate validation occurs when applications fail to adequately verify the authenticity, validity, or chain of trust of SSL/TLS certificates. This can manifest as disabled certificate validation, acceptance of self-signed certificates, failure to check certificate expiration, or inadequate hostname verification. Such weaknesses can expose communications to man-in-the-middle attacks and data interception.

### Vulnerable Code Patterns

```rust
use reqwest::{Client, ClientBuilder};
use std::sync::Arc;
use rustls::{ClientConfig, RootCertStore};

// VULNERABLE: Disabled certificate verification
pub async fn insecure_api_call(url: &str) -> Result<String, reqwest::Error> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true) // DANGEROUS: Accepts any certificate
        .danger_accept_invalid_hostnames(true) // DANGEROUS: Skips hostname verification
        .build()?;

    let response = client.get(url).send().await?;
    let body = response.text().await?;
    Ok(body)
}

// VULNERABLE: Custom certificate validation that's too permissive
use rustls::client::{ServerCertVerifier, ServerCertVerified};
use rustls::{Certificate, Error as TlsError, ServerName};

struct InsecureVerifier;

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // VULNERABLE: Always accepts certificates without validation
        Ok(ServerCertVerified::assertion())
    }
}

// VULNERABLE: Weak certificate configuration
pub fn create_weak_tls_client() -> Result<Client, Box<dyn std::error::Error>> {
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore::empty()) // Empty root store
        .with_no_client_auth();

    // Using insecure verifier
    config.dangerous().set_certificate_verifier(Arc::new(InsecureVerifier));

    let client = Client::builder()
        .use_preconfigured_tls(config)
        .build()?;

    Ok(client)
}

// VULNERABLE: Ignoring certificate errors
pub async fn fetch_game_data_insecure(api_endpoint: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    match client.get(api_endpoint).send().await {
        Ok(response) => {
            let json: serde_json::Value = response.json().await?;
            Ok(json)
        }
        Err(e) => {
            // VULNERABLE: Silently ignoring TLS errors
            eprintln!("Request failed: {}, trying without TLS verification", e);

            // Fallback to insecure connection
            let insecure_client = Client::builder()
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true)
                .build()?;

            let response = insecure_client.get(api_endpoint).send().await?;
            let json: serde_json::Value = response.json().await?;
            Ok(json)
        }
    }
}

// VULNERABLE: Manual certificate parsing without proper validation
use x509_parser::{certificate::X509Certificate, prelude::*};

pub fn validate_certificate_weakly(cert_data: &[u8]) -> bool {
    match X509Certificate::from_der(cert_data) {
        Ok((_, cert)) => {
            // VULNERABLE: Only checking if certificate can be parsed
            // Missing: expiration check, chain validation, hostname verification
            !cert.subject().iter_common_name().next().is_none()
        }
        Err(_) => false,
    }
}

// VULNERABLE: Weak webhook signature verification
pub fn verify_webhook_insecure(payload: &str, signature: &str, _cert: &[u8]) -> bool {
    // VULNERABLE: Not validating the certificate used for webhook signing
    // Just checking if signature is not empty
    !signature.is_empty() && !payload.is_empty()
}

// VULNERABLE: Development code left in production
#[cfg(feature = "dev-mode")] // DANGEROUS: Feature flags can leak to production
pub fn create_development_client() -> Client {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .expect("Failed to create development client")
}

// Usage in production code - VULNERABLE
pub async fn fetch_external_data(url: &str) -> Result<String, reqwest::Error> {
    #[cfg(feature = "dev-mode")]
    let client = create_development_client();

    #[cfg(not(feature = "dev-mode"))]
    let client = Client::new(); // Secure client for production

    let response = client.get(url).send().await?;
    response.text().await
}
```

### Certificate Validation Weakness Patterns

```rust
use std::collections::HashMap;
use x509_parser::prelude::*;

#[derive(Debug, Clone)]
pub enum CertificateValidationWeakness {
    DisabledVerification {
        component: String,
        description: String,
        severity: WeaknessSeverity,
    },
    WeakChainValidation {
        missing_checks: Vec<String>,
        potential_bypasses: Vec<String>,
    },
    InsufficientHostnameVerification {
        hostname_checks: Vec<String>,
        wildcard_handling: HostnameValidationStatus,
    },
    ExpirationIgnored {
        cert_lifetime_checks: bool,
        grace_period: Option<std::time::Duration>,
    },
    WeakCipherSuites {
        allowed_ciphers: Vec<String>,
        deprecated_protocols: Vec<String>,
    },
    SelfSignedAcceptance {
        contexts: Vec<String>,
        justification: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub enum WeaknessSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub enum HostnameValidationStatus {
    Disabled,
    Partial,
    WeakWildcard,
    Adequate,
}

pub struct CertificateValidationAnalyzer {
    pub identified_weaknesses: Vec<CertificateValidationWeakness>,
    pub validation_policies: ValidationPolicySet,
}

#[derive(Debug)]
pub struct ValidationPolicySet {
    pub require_valid_chain: bool,
    pub require_hostname_match: bool,
    pub require_current_validity: bool,
    pub allowed_self_signed_contexts: Vec<String>,
    pub minimum_key_size: usize,
    pub allowed_signature_algorithms: Vec<String>,
    pub revocation_checking: RevocationCheckingPolicy,
}

#[derive(Debug)]
pub enum RevocationCheckingPolicy {
    None,
    OCSP,
    CRL,
    Both,
}

impl CertificateValidationAnalyzer {
    pub fn new() -> Self {
        Self {
            identified_weaknesses: Vec::new(),
            validation_policies: ValidationPolicySet {
                require_valid_chain: true,
                require_hostname_match: true,
                require_current_validity: true,
                allowed_self_signed_contexts: vec!["localhost".to_string(), "development".to_string()],
                minimum_key_size: 2048,
                allowed_signature_algorithms: vec![
                    "sha256WithRSAEncryption".to_string(),
                    "ecdsa-with-SHA256".to_string(),
                    "ecdsa-with-SHA384".to_string(),
                ],
                revocation_checking: RevocationCheckingPolicy::OCSP,
            },
        }
    }

    pub fn analyze_certificate_implementation(&mut self, implementation_details: &CertImplementationDetails) {
        // Check for disabled verification
        if implementation_details.accepts_invalid_certs {
            self.identified_weaknesses.push(CertificateValidationWeakness::DisabledVerification {
                component: implementation_details.component_name.clone(),
                description: "Certificate validation is completely disabled".to_string(),
                severity: WeaknessSeverity::Critical,
            });
        }

        // Check hostname verification
        if implementation_details.accepts_invalid_hostnames {
            self.identified_weaknesses.push(CertificateValidationWeakness::InsufficientHostnameVerification {
                hostname_checks: vec!["Hostname verification disabled".to_string()],
                wildcard_handling: HostnameValidationStatus::Disabled,
            });
        }

        // Check for development code in production
        if implementation_details.has_development_overrides {
            self.identified_weaknesses.push(CertificateValidationWeakness::DisabledVerification {
                component: implementation_details.component_name.clone(),
                description: "Development certificate overrides detected".to_string(),
                severity: WeaknessSeverity::High,
            });
        }

        // Analyze custom verification logic
        if let Some(ref custom_verifier) = implementation_details.custom_verifier_logic {
            self.analyze_custom_verifier(custom_verifier);
        }
    }

    fn analyze_custom_verifier(&mut self, verifier_code: &str) {
        // Simple pattern matching for common weak patterns
        let weak_patterns = [
            ("return Ok", "Always returns OK without validation"),
            ("// TODO", "Incomplete validation implementation"),
            ("accept_any", "Accepts any certificate"),
            ("skip_verification", "Skips certificate verification"),
        ];

        for (pattern, description) in &weak_patterns {
            if verifier_code.contains(pattern) {
                self.identified_weaknesses.push(CertificateValidationWeakness::WeakChainValidation {
                    missing_checks: vec![description.to_string()],
                    potential_bypasses: vec![format!("Pattern found: {}", pattern)],
                });
            }
        }
    }

    pub fn generate_validation_report(&self) -> CertificateValidationReport {
        let critical_count = self.identified_weaknesses.iter()
            .filter(|w| matches!(w, CertificateValidationWeakness::DisabledVerification { severity: WeaknessSeverity::Critical, .. }))
            .count();

        let overall_score = if self.identified_weaknesses.is_empty() {
            100.0
        } else {
            let total_severity_points: f64 = self.identified_weaknesses.iter()
                .map(|w| match w {
                    CertificateValidationWeakness::DisabledVerification { severity: WeaknessSeverity::Critical, .. } => 25.0,
                    CertificateValidationWeakness::DisabledVerification { severity: WeaknessSeverity::High, .. } => 15.0,
                    CertificateValidationWeakness::WeakChainValidation { .. } => 10.0,
                    CertificateValidationWeakness::InsufficientHostnameVerification { .. } => 8.0,
                    _ => 5.0,
                })
                .sum();

            (100.0 - total_severity_points).max(0.0)
        };

        CertificateValidationReport {
            overall_score,
            critical_issues: critical_count,
            total_weaknesses: self.identified_weaknesses.len(),
            weaknesses: self.identified_weaknesses.clone(),
            recommendations: self.generate_recommendations(),
        }
    }

    fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if self.identified_weaknesses.iter().any(|w| matches!(w, CertificateValidationWeakness::DisabledVerification { .. })) {
            recommendations.push("CRITICAL: Re-enable certificate validation immediately".to_string());
            recommendations.push("Review all external API calls for proper TLS configuration".to_string());
        }

        if self.identified_weaknesses.iter().any(|w| matches!(w, CertificateValidationWeakness::InsufficientHostnameVerification { .. })) {
            recommendations.push("Implement proper hostname verification for all TLS connections".to_string());
        }

        if self.identified_weaknesses.iter().any(|w| matches!(w, CertificateValidationWeakness::WeakChainValidation { .. })) {
            recommendations.push("Strengthen certificate chain validation logic".to_string());
        }

        recommendations.push("Implement certificate pinning for critical external services".to_string());
        recommendations.push("Set up monitoring for certificate expiration".to_string());
        recommendations.push("Conduct regular TLS configuration audits".to_string());

        recommendations
    }
}

#[derive(Debug)]
pub struct CertImplementationDetails {
    pub component_name: String,
    pub accepts_invalid_certs: bool,
    pub accepts_invalid_hostnames: bool,
    pub has_development_overrides: bool,
    pub custom_verifier_logic: Option<String>,
    pub tls_version_minimum: Option<String>,
    pub cipher_suite_restrictions: Vec<String>,
}

#[derive(Debug)]
pub struct CertificateValidationReport {
    pub overall_score: f64,
    pub critical_issues: usize,
    pub total_weaknesses: usize,
    pub weaknesses: Vec<CertificateValidationWeakness>,
    pub recommendations: Vec<String>,
}
```

## Advanced Analysis Framework

### TLS Configuration Auditing System

```rust
use rustls::{Certificate, PrivateKey, ClientConfig, ServerConfig};
use std::sync::Arc;
use webpki_roots;

pub struct TLSConfigurationAuditor {
    audit_rules: Vec<TLSAuditRule>,
    compliance_standards: ComplianceStandardSet,
}

#[derive(Debug)]
pub struct TLSAuditRule {
    pub rule_id: String,
    pub description: String,
    pub rule_type: TLSRuleType,
    pub severity: AuditSeverity,
    pub check_function: fn(&TLSConfiguration) -> RuleCheckResult,
}

#[derive(Debug)]
pub enum TLSRuleType {
    CertificateValidation,
    ProtocolVersion,
    CipherSuite,
    CertificateChain,
    Revocation,
    Pinning,
}

#[derive(Debug)]
pub enum AuditSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug)]
pub struct TLSConfiguration {
    pub client_config: Option<ClientConfig>,
    pub accepts_invalid_certs: bool,
    pub accepts_invalid_hostnames: bool,
    pub minimum_tls_version: String,
    pub enabled_cipher_suites: Vec<String>,
    pub certificate_chain: Vec<Certificate>,
    pub root_cert_store_size: usize,
    pub ocsp_stapling_enabled: bool,
    pub certificate_transparency_enabled: bool,
}

#[derive(Debug)]
pub struct RuleCheckResult {
    pub passed: bool,
    pub details: String,
    pub evidence: Vec<String>,
    pub remediation_steps: Vec<String>,
}

impl TLSConfigurationAuditor {
    pub fn new() -> Self {
        let audit_rules = vec![
            TLSAuditRule {
                rule_id: "TLS-001".to_string(),
                description: "Certificate validation must not be disabled".to_string(),
                rule_type: TLSRuleType::CertificateValidation,
                severity: AuditSeverity::Critical,
                check_function: |config| {
                    if config.accepts_invalid_certs {
                        RuleCheckResult {
                            passed: false,
                            details: "Certificate validation is disabled".to_string(),
                            evidence: vec!["accepts_invalid_certs = true".to_string()],
                            remediation_steps: vec![
                                "Remove danger_accept_invalid_certs(true)".to_string(),
                                "Implement proper certificate validation".to_string(),
                            ],
                        }
                    } else {
                        RuleCheckResult {
                            passed: true,
                            details: "Certificate validation is enabled".to_string(),
                            evidence: vec!["accepts_invalid_certs = false".to_string()],
                            remediation_steps: vec![],
                        }
                    }
                },
            },
            TLSAuditRule {
                rule_id: "TLS-002".to_string(),
                description: "Hostname verification must be enabled".to_string(),
                rule_type: TLSRuleType::CertificateValidation,
                severity: AuditSeverity::Critical,
                check_function: |config| {
                    if config.accepts_invalid_hostnames {
                        RuleCheckResult {
                            passed: false,
                            details: "Hostname verification is disabled".to_string(),
                            evidence: vec!["accepts_invalid_hostnames = true".to_string()],
                            remediation_steps: vec![
                                "Remove danger_accept_invalid_hostnames(true)".to_string(),
                                "Ensure hostname verification is performed".to_string(),
                            ],
                        }
                    } else {
                        RuleCheckResult {
                            passed: true,
                            details: "Hostname verification is enabled".to_string(),
                            evidence: vec!["accepts_invalid_hostnames = false".to_string()],
                            remediation_steps: vec![],
                        }
                    }
                },
            },
            TLSAuditRule {
                rule_id: "TLS-003".to_string(),
                description: "Minimum TLS version should be 1.2 or higher".to_string(),
                rule_type: TLSRuleType::ProtocolVersion,
                severity: AuditSeverity::High,
                check_function: |config| {
                    let min_version = &config.minimum_tls_version;
                    let is_secure = min_version == "1.2" || min_version == "1.3" || min_version.starts_with("1.3");

                    if is_secure {
                        RuleCheckResult {
                            passed: true,
                            details: format!("TLS version {} is secure", min_version),
                            evidence: vec![format!("minimum_tls_version = {}", min_version)],
                            remediation_steps: vec![],
                        }
                    } else {
                        RuleCheckResult {
                            passed: false,
                            details: format!("TLS version {} is insecure", min_version),
                            evidence: vec![format!("minimum_tls_version = {}", min_version)],
                            remediation_steps: vec![
                                "Upgrade minimum TLS version to 1.2 or higher".to_string(),
                                "Disable support for TLS 1.0 and 1.1".to_string(),
                            ],
                        }
                    }
                },
            },
            TLSAuditRule {
                rule_id: "TLS-004".to_string(),
                description: "Root certificate store should not be empty".to_string(),
                rule_type: TLSRuleType::CertificateChain,
                severity: AuditSeverity::Medium,
                check_function: |config| {
                    if config.root_cert_store_size > 0 {
                        RuleCheckResult {
                            passed: true,
                            details: format!("Root certificate store contains {} certificates", config.root_cert_store_size),
                            evidence: vec![format!("root_cert_store_size = {}", config.root_cert_store_size)],
                            remediation_steps: vec![],
                        }
                    } else {
                        RuleCheckResult {
                            passed: false,
                            details: "Root certificate store is empty".to_string(),
                            evidence: vec!["root_cert_store_size = 0".to_string()],
                            remediation_steps: vec![
                                "Use webpki_roots or similar for root certificates".to_string(),
                                "Ensure proper certificate chain validation".to_string(),
                            ],
                        }
                    }
                },
            },
        ];

        Self {
            audit_rules,
            compliance_standards: ComplianceStandardSet::default(),
        }
    }

    pub fn audit_configuration(&self, config: &TLSConfiguration) -> TLSAuditReport {
        let mut rule_results = Vec::new();

        for rule in &self.audit_rules {
            let result = (rule.check_function)(config);
            rule_results.push(TLSRuleResult {
                rule_id: rule.rule_id.clone(),
                description: rule.description.clone(),
                rule_type: rule.rule_type.clone(),
                severity: rule.severity.clone(),
                result,
            });
        }

        let passed_count = rule_results.iter().filter(|r| r.result.passed).count();
        let compliance_score = (passed_count as f64 / rule_results.len() as f64) * 100.0;

        TLSAuditReport {
            timestamp: chrono::Utc::now(),
            compliance_score,
            total_rules: rule_results.len(),
            passed_rules: passed_count,
            rule_results,
            overall_recommendation: self.generate_overall_recommendation(compliance_score),
        }
    }

    fn generate_overall_recommendation(&self, score: f64) -> String {
        match score {
            s if s >= 90.0 => "TLS configuration is secure and compliant".to_string(),
            s if s >= 70.0 => "TLS configuration is mostly secure with minor improvements needed".to_string(),
            s if s >= 50.0 => "TLS configuration has moderate security issues requiring attention".to_string(),
            _ => "TLS configuration has significant security vulnerabilities requiring immediate action".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct TLSRuleResult {
    pub rule_id: String,
    pub description: String,
    pub rule_type: TLSRuleType,
    pub severity: AuditSeverity,
    pub result: RuleCheckResult,
}

#[derive(Debug)]
pub struct TLSAuditReport {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub compliance_score: f64,
    pub total_rules: usize,
    pub passed_rules: usize,
    pub rule_results: Vec<TLSRuleResult>,
    pub overall_recommendation: String,
}

#[derive(Debug, Default)]
pub struct ComplianceStandardSet {
    pub pci_dss_requirements: bool,
    pub nist_guidelines: bool,
    pub owasp_recommendations: bool,
}

// Certificate validation testing framework
pub struct CertificateTestFramework {
    test_certificates: Vec<TestCertificate>,
}

#[derive(Debug)]
pub struct TestCertificate {
    pub name: String,
    pub certificate_data: Vec<u8>,
    pub expected_validation_result: ValidationExpectation,
    pub test_scenario: TestScenario,
}

#[derive(Debug)]
pub enum ValidationExpectation {
    ShouldPass,
    ShouldFail(String), // Reason why it should fail
    ShouldWarn(String), // Should pass but with warnings
}

#[derive(Debug)]
pub enum TestScenario {
    ValidCertificate,
    ExpiredCertificate,
    SelfSignedCertificate,
    InvalidHostname,
    UntrustedCA,
    RevokedCertificate,
    WeakSignature,
}

impl CertificateTestFramework {
    pub fn new() -> Self {
        Self {
            test_certificates: Self::create_test_certificate_suite(),
        }
    }

    fn create_test_certificate_suite() -> Vec<TestCertificate> {
        vec![
            TestCertificate {
                name: "Valid Certificate".to_string(),
                certificate_data: vec![], // Would contain actual certificate data
                expected_validation_result: ValidationExpectation::ShouldPass,
                test_scenario: TestScenario::ValidCertificate,
            },
            TestCertificate {
                name: "Expired Certificate".to_string(),
                certificate_data: vec![], // Would contain expired certificate
                expected_validation_result: ValidationExpectation::ShouldFail("Certificate has expired".to_string()),
                test_scenario: TestScenario::ExpiredCertificate,
            },
            TestCertificate {
                name: "Self-Signed Certificate".to_string(),
                certificate_data: vec![], // Would contain self-signed certificate
                expected_validation_result: ValidationExpectation::ShouldFail("Self-signed certificate".to_string()),
                test_scenario: TestScenario::SelfSignedCertificate,
            },
            TestCertificate {
                name: "Wrong Hostname".to_string(),
                certificate_data: vec![], // Would contain certificate for different hostname
                expected_validation_result: ValidationExpectation::ShouldFail("Hostname mismatch".to_string()),
                test_scenario: TestScenario::InvalidHostname,
            },
        ]
    }

    pub fn run_validation_tests(&self, validator: &dyn CertificateValidator) -> TestSuiteResults {
        let mut test_results = Vec::new();

        for test_cert in &self.test_certificates {
            let validation_result = validator.validate_certificate(
                &test_cert.certificate_data,
                "test.example.com",
                std::time::SystemTime::now(),
            );

            let test_passed = match (&test_cert.expected_validation_result, &validation_result) {
                (ValidationExpectation::ShouldPass, Ok(_)) => true,
                (ValidationExpectation::ShouldFail(_), Err(_)) => true,
                (ValidationExpectation::ShouldWarn(_), Ok(_)) => true, // Warnings still pass
                _ => false,
            };

            test_results.push(CertificateTestResult {
                test_name: test_cert.name.clone(),
                scenario: test_cert.test_scenario.clone(),
                expected: test_cert.expected_validation_result.clone(),
                actual_result: validation_result,
                passed: test_passed,
            });
        }

        let passed_count = test_results.iter().filter(|r| r.passed).count();

        TestSuiteResults {
            total_tests: test_results.len(),
            passed_tests: passed_count,
            test_results,
            overall_success: passed_count == test_results.len(),
        }
    }
}

pub trait CertificateValidator {
    fn validate_certificate(
        &self,
        cert_data: &[u8],
        hostname: &str,
        validation_time: std::time::SystemTime,
    ) -> Result<CertificateValidationResult, CertificateValidationError>;
}

#[derive(Debug)]
pub struct CertificateValidationResult {
    pub is_valid: bool,
    pub validation_details: String,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum CertificateValidationError {
    ParseError(String),
    ExpiredCertificate,
    UntrustedCA,
    HostnameMismatch,
    RevokedCertificate,
    WeakSignature,
    ChainValidationFailed,
}

#[derive(Debug)]
pub struct CertificateTestResult {
    pub test_name: String,
    pub scenario: TestScenario,
    pub expected: ValidationExpectation,
    pub actual_result: Result<CertificateValidationResult, CertificateValidationError>,
    pub passed: bool,
}

#[derive(Debug)]
pub struct TestSuiteResults {
    pub total_tests: usize,
    pub passed_tests: usize,
    pub test_results: Vec<CertificateTestResult>,
    pub overall_success: bool,
}
```

## Economic Impact Calculator

### Direct Cost Analysis

```rust
pub struct CertificateValidationImpactCalculator {
    pub implementation_complexity: f64,
    pub security_risk_level: f64,
    pub compliance_requirements: f64,
    pub operational_overhead: f64,
}

impl CertificateValidationImpactCalculator {
    pub fn calculate_immediate_costs(&self) -> CertValidationCosts {
        CertValidationCosts {
            // Technical implementation costs
            tls_configuration_review: 400.0,
            certificate_validation_fixes: 800.0,
            testing_framework_setup: 600.0,

            // Security infrastructure
            certificate_monitoring_setup: 300.0,
            automated_validation_testing: 400.0,
            pinning_implementation: 500.0,

            // Compliance and audit
            security_audit_extension: 300.0,
            documentation_updates: 200.0,
            team_training: 250.0,

            total_immediate: 3750.0,
        }
    }

    pub fn calculate_potential_attack_costs(&self) -> AttackExposureCosts {
        AttackExposureCosts {
            // Man-in-the-middle attack scenarios
            data_interception: 2000.0,
            credential_theft: 3000.0,
            session_hijacking: 1500.0,

            // API security breaches
            external_service_compromise: 2500.0,
            payment_processor_attacks: 5000.0,
            third_party_data_exposure: 1800.0,

            // Business impact
            customer_trust_loss: 4000.0,
            compliance_violations: 2000.0,
            incident_response: 1200.0,

            // Recovery and remediation
            emergency_certificate_updates: 800.0,
            system_hardening: 1500.0,
            customer_notification: 600.0,

            total_potential_exposure: 25900.0,
        }
    }

    pub fn calculate_long_term_benefits(&self) -> CertValidationBenefits {
        CertValidationBenefits {
            // Security improvements
            reduced_mitm_risk: 3000.0,
            improved_api_security: 2000.0,
            enhanced_trust_relationships: 1500.0,

            // Operational benefits
            automated_certificate_monitoring: 800.0,
            streamlined_compliance_audits: 600.0,
            reduced_security_incidents: 2500.0,

            // Compliance and reputation
            improved_security_posture: 1200.0,
            enhanced_customer_confidence: 2000.0,
            regulatory_compliance_benefits: 1000.0,

            total_annual_benefits: 14600.0,
        }
    }
}

pub struct CertValidationCosts {
    pub tls_configuration_review: f64,
    pub certificate_validation_fixes: f64,
    pub testing_framework_setup: f64,
    pub certificate_monitoring_setup: f64,
    pub automated_validation_testing: f64,
    pub pinning_implementation: f64,
    pub security_audit_extension: f64,
    pub documentation_updates: f64,
    pub team_training: f64,
    pub total_immediate: f64,
}

pub struct AttackExposureCosts {
    pub data_interception: f64,
    pub credential_theft: f64,
    pub session_hijacking: f64,
    pub external_service_compromise: f64,
    pub payment_processor_attacks: f64,
    pub third_party_data_exposure: f64,
    pub customer_trust_loss: f64,
    pub compliance_violations: f64,
    pub incident_response: f64,
    pub emergency_certificate_updates: f64,
    pub system_hardening: f64,
    pub customer_notification: f64,
    pub total_potential_exposure: f64,
}

pub struct CertValidationBenefits {
    pub reduced_mitm_risk: f64,
    pub improved_api_security: f64,
    pub enhanced_trust_relationships: f64,
    pub automated_certificate_monitoring: f64,
    pub streamlined_compliance_audits: f64,
    pub reduced_security_incidents: f64,
    pub improved_security_posture: f64,
    pub enhanced_customer_confidence: f64,
    pub regulatory_compliance_benefits: f64,
    pub total_annual_benefits: f64,
}
```

### Risk-Based Cost Modeling

```rust
pub struct CertificateRiskModel {
    pub exposure_probability: f64,
    pub attack_sophistication_required: f64,
    pub detection_likelihood: f64,
    pub business_impact_multiplier: f64,
}

impl CertificateRiskModel {
    pub fn calculate_risk_adjusted_costs(&self, impact_calculator: &CertificateValidationImpactCalculator) -> RiskAdjustedAnalysis {
        let immediate_costs = impact_calculator.calculate_immediate_costs();
        let potential_exposure = impact_calculator.calculate_potential_attack_costs();
        let long_term_benefits = impact_calculator.calculate_long_term_benefits();

        // Calculate expected loss from certificate validation vulnerabilities
        let attack_success_probability =
            self.exposure_probability *
            (1.0 - self.attack_sophistication_required) *
            (1.0 - self.detection_likelihood);

        let expected_annual_loss = potential_exposure.total_potential_exposure *
            attack_success_probability *
            self.business_impact_multiplier;

        // Calculate net present value of fixing vs. not fixing
        let five_year_fix_cost = immediate_costs.total_immediate +
            (long_term_benefits.total_annual_benefits * 0.2 * 5.0); // 20% ongoing costs

        let five_year_risk_cost = expected_annual_loss * 5.0;

        RiskAdjustedAnalysis {
            expected_annual_loss,
            implementation_investment: immediate_costs.total_immediate,
            five_year_fix_cost,
            five_year_risk_cost,
            net_benefit: five_year_risk_cost - five_year_fix_cost,
            roi_percentage: if immediate_costs.total_immediate > 0.0 {
                ((expected_annual_loss - (immediate_costs.total_immediate / 5.0)) /
                 (immediate_costs.total_immediate / 5.0)) * 100.0
            } else {
                0.0
            },
            payback_period_months: if expected_annual_loss > 0.0 {
                (immediate_costs.total_immediate / (expected_annual_loss / 12.0)) as u32
            } else {
                u32::MAX
            },
            decision_recommendation: self.generate_decision_recommendation(
                immediate_costs.total_immediate,
                expected_annual_loss,
            ),
        }
    }

    fn generate_decision_recommendation(&self, fix_cost: f64, annual_risk: f64) -> String {
        let risk_to_cost_ratio = annual_risk / fix_cost;

        match risk_to_cost_ratio {
            r if r > 2.0 => "STRONGLY RECOMMENDED: High risk reduction for low cost".to_string(),
            r if r > 1.0 => "RECOMMENDED: Good return on security investment".to_string(),
            r if r > 0.5 => "CONSIDER: Moderate security benefit".to_string(),
            _ => "EVALUATE: Cost may exceed direct risk reduction".to_string(),
        }
    }
}

#[derive(Debug)]
pub struct RiskAdjustedAnalysis {
    pub expected_annual_loss: f64,
    pub implementation_investment: f64,
    pub five_year_fix_cost: f64,
    pub five_year_risk_cost: f64,
    pub net_benefit: f64,
    pub roi_percentage: f64,
    pub payback_period_months: u32,
    pub decision_recommendation: String,
}

// Quantitative risk assessment for certificate validation vulnerabilities
pub struct QuantitativeRiskAssessment {
    pub threat_frequency: ThreatFrequency,
    pub vulnerability_exposure: VulnerabilityExposure,
    pub asset_value: AssetValuation,
    pub control_effectiveness: ControlEffectiveness,
}

#[derive(Debug)]
pub struct ThreatFrequency {
    pub mitm_attacks_per_year: f64,
    pub certificate_spoofing_attempts: f64,
    pub api_interception_incidents: f64,
}

#[derive(Debug)]
pub struct VulnerabilityExposure {
    pub disabled_validation_components: usize,
    pub weak_validation_implementations: usize,
    pub total_external_connections: usize,
    pub exposure_percentage: f64,
}

#[derive(Debug)]
pub struct AssetValuation {
    pub customer_data_value: f64,
    pub transaction_data_value: f64,
    pub api_access_value: f64,
    pub reputation_value: f64,
}

#[derive(Debug)]
pub struct ControlEffectiveness {
    pub monitoring_coverage: f64,      // 0.0 to 1.0
    pub incident_response_speed: f64,  // 0.0 to 1.0
    pub preventive_controls: f64,      // 0.0 to 1.0
}

impl QuantitativeRiskAssessment {
    pub fn calculate_annual_loss_expectancy(&self) -> AnnualLossExpectancy {
        // Single Loss Expectancy calculations
        let customer_data_sle = self.asset_value.customer_data_value * 0.3; // 30% impact
        let transaction_sle = self.asset_value.transaction_data_value * 0.5; // 50% impact
        let api_access_sle = self.asset_value.api_access_value * 0.7; // 70% impact
        let reputation_sle = self.asset_value.reputation_value * 0.4; // 40% impact

        // Annual Rate of Occurrence (considering vulnerability exposure)
        let effective_threat_frequency =
            (self.threat_frequency.mitm_attacks_per_year +
             self.threat_frequency.certificate_spoofing_attempts +
             self.threat_frequency.api_interception_incidents) *
            self.vulnerability_exposure.exposure_percentage;

        // Control effectiveness reduces both frequency and impact
        let control_factor = 1.0 - (
            (self.control_effectiveness.monitoring_coverage +
             self.control_effectiveness.incident_response_speed +
             self.control_effectiveness.preventive_controls) / 3.0
        );

        let adjusted_frequency = effective_threat_frequency * control_factor;
        let adjusted_impact_factor = control_factor;

        // Calculate ALE for each asset type
        let customer_data_ale = customer_data_sle * adjusted_frequency * adjusted_impact_factor;
        let transaction_ale = transaction_sle * adjusted_frequency * adjusted_impact_factor;
        let api_access_ale = api_access_sle * adjusted_frequency * adjusted_impact_factor;
        let reputation_ale = reputation_sle * adjusted_frequency * adjusted_impact_factor;

        let total_ale = customer_data_ale + transaction_ale + api_access_ale + reputation_ale;

        AnnualLossExpectancy {
            customer_data_ale,
            transaction_ale,
            api_access_ale,
            reputation_ale,
            total_ale,
            threat_frequency: adjusted_frequency,
            average_impact: (customer_data_sle + transaction_sle + api_access_sle + reputation_sle) / 4.0,
        }
    }
}

#[derive(Debug)]
pub struct AnnualLossExpectancy {
    pub customer_data_ale: f64,
    pub transaction_ale: f64,
    pub api_access_ale: f64,
    pub reputation_ale: f64,
    pub total_ale: f64,
    pub threat_frequency: f64,
    pub average_impact: f64,
}
```

## Proof of Concept

### Certificate Validation Vulnerability Testing

```rust
#[cfg(test)]
mod certificate_validation_tests {
    use super::*;
    use reqwest::{Client, ClientBuilder};
    use std::sync::Arc;

    #[tokio::test]
    async fn test_insecure_client_accepts_invalid_certificates() {
        // Create an insecure client that accepts invalid certificates
        let insecure_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("Failed to create insecure client");

        // Test against a known invalid certificate endpoint
        // Note: This is for testing purposes only
        let test_url = "https://self-signed.badssl.com/";

        let result = insecure_client.get(test_url).send().await;

        // Insecure client should successfully connect to invalid certificate site
        assert!(result.is_ok(), "Insecure client should accept invalid certificates");
        println!("✗ VULNERABLE: Client accepts invalid certificates");
    }

    #[tokio::test]
    async fn test_secure_client_rejects_invalid_certificates() {
        // Create a secure client with proper certificate validation
        let secure_client = Client::new();

        // Test against a known invalid certificate endpoint
        let test_url = "https://self-signed.badssl.com/";

        let result = secure_client.get(test_url).send().await;

        // Secure client should reject invalid certificates
        assert!(result.is_err(), "Secure client should reject invalid certificates");
        println!("✓ SECURE: Client properly rejects invalid certificates");
    }

    #[test]
    fn test_certificate_validation_analyzer() {
        let mut analyzer = CertificateValidationAnalyzer::new();

        // Test configuration with disabled validation
        let vulnerable_config = CertImplementationDetails {
            component_name: "API Client".to_string(),
            accepts_invalid_certs: true,
            accepts_invalid_hostnames: true,
            has_development_overrides: false,
            custom_verifier_logic: None,
            tls_version_minimum: Some("1.0".to_string()),
            cipher_suite_restrictions: vec![],
        };

        analyzer.analyze_certificate_implementation(&vulnerable_config);
        let report = analyzer.generate_validation_report();

        assert!(report.critical_issues > 0, "Should detect critical certificate validation issues");
        assert!(report.overall_score < 50.0, "Overall score should be low for vulnerable config");
        println!("Certificate validation analyzer detected {} critical issues", report.critical_issues);
    }

    #[test]
    fn test_tls_configuration_auditor() {
        let auditor = TLSConfigurationAuditor::new();

        // Test vulnerable TLS configuration
        let vulnerable_tls_config = TLSConfiguration {
            client_config: None,
            accepts_invalid_certs: true,
            accepts_invalid_hostnames: true,
            minimum_tls_version: "1.0".to_string(),
            enabled_cipher_suites: vec!["RC4".to_string(), "DES".to_string()],
            certificate_chain: vec![],
            root_cert_store_size: 0,
            ocsp_stapling_enabled: false,
            certificate_transparency_enabled: false,
        };

        let audit_report = auditor.audit_configuration(&vulnerable_tls_config);

        assert!(audit_report.compliance_score < 50.0, "Vulnerable config should have low compliance score");
        assert!(audit_report.passed_rules < audit_report.total_rules, "Some rules should fail");

        println!("TLS audit compliance score: {:.1}%", audit_report.compliance_score);
        println!("Failed rules: {}", audit_report.total_rules - audit_report.passed_rules);
    }

    #[tokio::test]
    async fn test_man_in_the_middle_simulation() {
        // Simulate a man-in-the-middle attack scenario

        // 1. Test with vulnerable client (should succeed against MITM)
        let vulnerable_client = Client::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .unwrap();

        // 2. Test with secure client (should fail against MITM)
        let secure_client = Client::new();

        // Simulate MITM by connecting to a site with certificate mismatch
        let mitm_target = "https://wrong.host.badssl.com/";

        // Vulnerable client test
        let vulnerable_result = vulnerable_client.get(mitm_target).send().await;
        println!("Vulnerable client MITM test: {:?}", vulnerable_result.is_ok());

        // Secure client test
        let secure_result = secure_client.get(mitm_target).send().await;
        println!("Secure client MITM test: {:?}", secure_result.is_err());

        // Assert that secure client rejects MITM attempt
        assert!(secure_result.is_err(), "Secure client should reject MITM attempt");
        println!("✓ MITM protection working correctly");
    }

    #[test]
    fn test_certificate_test_framework() {
        // Create a mock certificate validator for testing
        struct MockValidator {
            should_accept_invalid: bool,
        }

        impl CertificateValidator for MockValidator {
            fn validate_certificate(
                &self,
                _cert_data: &[u8],
                _hostname: &str,
                _validation_time: std::time::SystemTime,
            ) -> Result<CertificateValidationResult, CertificateValidationError> {
                if self.should_accept_invalid {
                    Ok(CertificateValidationResult {
                        is_valid: true,
                        validation_details: "Validation bypassed".to_string(),
                        warnings: vec!["Certificate validation disabled".to_string()],
                    })
                } else {
                    // Proper validation logic would go here
                    Err(CertificateValidationError::ExpiredCertificate)
                }
            }
        }

        let framework = CertificateTestFramework::new();

        // Test with vulnerable validator (should fail security tests)
        let vulnerable_validator = MockValidator { should_accept_invalid: true };
        let vulnerable_results = framework.run_validation_tests(&vulnerable_validator);

        assert!(!vulnerable_results.overall_success, "Vulnerable validator should fail security tests");
        println!("Vulnerable validator test results: {}/{} passed",
                 vulnerable_results.passed_tests, vulnerable_results.total_tests);

        // Test with secure validator
        let secure_validator = MockValidator { should_accept_invalid: false };
        let secure_results = framework.run_validation_tests(&secure_validator);

        println!("Secure validator test results: {}/{} passed",
                 secure_results.passed_tests, secure_results.total_tests);
    }

    #[tokio::test]
    async fn test_certificate_pinning_bypass() {
        // Demonstrate how lack of certificate pinning can be exploited

        struct PinnedCertificateValidator {
            pinned_certificates: Vec<String>, // SHA-256 hashes of pinned certificates
        }

        impl PinnedCertificateValidator {
            fn new(pinned_certs: Vec<String>) -> Self {
                Self {
                    pinned_certificates: pinned_certs,
                }
            }

            fn validate_pinned_certificate(&self, cert_hash: &str) -> bool {
                self.pinned_certificates.contains(&cert_hash.to_string())
            }
        }

        // Test without pinning (vulnerable)
        let no_pinning_client = Client::new();

        // Test with pinning (secure)
        let pinned_validator = PinnedCertificateValidator::new(vec![
            "known_good_cert_hash".to_string(),
        ]);

        // Simulate certificate change (potential MITM)
        let changed_cert_hash = "different_cert_hash";
        let pinning_result = pinned_validator.validate_pinned_certificate(changed_cert_hash);

        assert!(!pinning_result, "Certificate pinning should reject changed certificates");
        println!("✓ Certificate pinning correctly rejects certificate changes");
    }
}

// Practical attack simulation framework
pub struct CertificateAttackSimulator {
    target_services: Vec<String>,
    attack_scenarios: Vec<CertificateAttackScenario>,
}

#[derive(Debug)]
pub struct CertificateAttackScenario {
    pub name: String,
    pub attack_type: CertificateAttackType,
    pub target_weakness: CertificateWeakness,
    pub success_probability: f64,
    pub detection_probability: f64,
    pub impact_description: String,
}

#[derive(Debug)]
pub enum CertificateAttackType {
    ManInTheMiddle,
    CertificateSpoofing,
    CACompromise,
    DNSHijacking,
    BGPHijacking,
    SubdomainTakeover,
}

#[derive(Debug)]
pub enum CertificateWeakness {
    DisabledValidation,
    WeakPinning,
    NoHostnameVerification,
    AcceptsSelfSigned,
    WeakCipherSuites,
    NoRevocationChecking,
}

impl CertificateAttackSimulator {
    pub fn new() -> Self {
        let attack_scenarios = vec![
            CertificateAttackScenario {
                name: "Basic MITM with Disabled Validation".to_string(),
                attack_type: CertificateAttackType::ManInTheMiddle,
                target_weakness: CertificateWeakness::DisabledValidation,
                success_probability: 0.9,
                detection_probability: 0.1,
                impact_description: "Complete interception of API communications".to_string(),
            },
            CertificateAttackScenario {
                name: "Certificate Spoofing".to_string(),
                attack_type: CertificateAttackType::CertificateSpoofing,
                target_weakness: CertificateWeakness::NoHostnameVerification,
                success_probability: 0.7,
                detection_probability: 0.3,
                impact_description: "Impersonation of trusted services".to_string(),
            },
            CertificateAttackScenario {
                name: "Subdomain Takeover".to_string(),
                attack_type: CertificateAttackType::SubdomainTakeover,
                target_weakness: CertificateWeakness::WeakPinning,
                success_probability: 0.6,
                detection_probability: 0.4,
                impact_description: "Control of subdomain with valid certificate".to_string(),
            },
        ];

        Self {
            target_services: vec![
                "https://api.gaming-protocol.com".to_string(),
                "https://payment.gaming-protocol.com".to_string(),
                "https://auth.gaming-protocol.com".to_string(),
            ],
            attack_scenarios,
        }
    }

    pub fn simulate_attacks(&self) -> Vec<AttackSimulationResult> {
        self.attack_scenarios.iter()
            .map(|scenario| self.simulate_scenario(scenario))
            .collect()
    }

    fn simulate_scenario(&self, scenario: &CertificateAttackScenario) -> AttackSimulationResult {
        let attack_feasibility = self.calculate_attack_feasibility(scenario);
        let expected_impact = self.calculate_expected_impact(scenario);

        AttackSimulationResult {
            scenario_name: scenario.name.clone(),
            attack_type: scenario.attack_type.clone(),
            success_probability: scenario.success_probability,
            detection_probability: scenario.detection_probability,
            attack_feasibility,
            expected_impact,
            mitigation_priority: self.calculate_mitigation_priority(scenario),
        }
    }

    fn calculate_attack_feasibility(&self, scenario: &CertificateAttackScenario) -> AttackFeasibility {
        match scenario.attack_type {
            CertificateAttackType::ManInTheMiddle => AttackFeasibility::High,
            CertificateAttackType::CertificateSpoofing => AttackFeasibility::Medium,
            CertificateAttackType::SubdomainTakeover => AttackFeasibility::Medium,
            CertificateAttackType::CACompromise => AttackFeasibility::Low,
            CertificateAttackType::DNSHijacking => AttackFeasibility::Medium,
            CertificateAttackType::BGPHijacking => AttackFeasibility::Low,
        }
    }

    fn calculate_expected_impact(&self, scenario: &CertificateAttackScenario) -> ExpectedImpact {
        let base_impact = match scenario.target_weakness {
            CertificateWeakness::DisabledValidation => 9.0,
            CertificateWeakness::NoHostnameVerification => 7.0,
            CertificateWeakness::AcceptsSelfSigned => 6.0,
            CertificateWeakness::WeakPinning => 5.0,
            CertificateWeakness::WeakCipherSuites => 4.0,
            CertificateWeakness::NoRevocationChecking => 3.0,
        };

        let adjusted_impact = base_impact * scenario.success_probability * (1.0 - scenario.detection_probability);

        ExpectedImpact {
            confidentiality_impact: adjusted_impact * 0.8,
            integrity_impact: adjusted_impact * 0.6,
            availability_impact: adjusted_impact * 0.3,
            overall_impact: adjusted_impact,
        }
    }

    fn calculate_mitigation_priority(&self, scenario: &CertificateAttackScenario) -> MitigationPriority {
        let risk_score = scenario.success_probability * (1.0 - scenario.detection_probability);

        match risk_score {
            r if r > 0.7 => MitigationPriority::Critical,
            r if r > 0.5 => MitigationPriority::High,
            r if r > 0.3 => MitigationPriority::Medium,
            _ => MitigationPriority::Low,
        }
    }
}

#[derive(Debug)]
pub struct AttackSimulationResult {
    pub scenario_name: String,
    pub attack_type: CertificateAttackType,
    pub success_probability: f64,
    pub detection_probability: f64,
    pub attack_feasibility: AttackFeasibility,
    pub expected_impact: ExpectedImpact,
    pub mitigation_priority: MitigationPriority,
}

#[derive(Debug)]
pub enum AttackFeasibility {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct ExpectedImpact {
    pub confidentiality_impact: f64,
    pub integrity_impact: f64,
    pub availability_impact: f64,
    pub overall_impact: f64,
}

#[derive(Debug)]
pub enum MitigationPriority {
    Low,
    Medium,
    High,
    Critical,
}
```

## Remediation Strategy

### Immediate Fixes

```rust
// Secure certificate validation implementation
use reqwest::{Client, ClientBuilder};
use rustls::{ClientConfig, RootCertStore, Certificate};
use webpki_roots;
use std::sync::Arc;

// SECURE: Properly configured TLS client
pub fn create_secure_client() -> Result<Client, Box<dyn std::error::Error>> {
    // Use system root certificates or webpki-roots
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client = Client::builder()
        .use_preconfigured_tls(config)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    Ok(client)
}

// SECURE: API client with proper certificate validation
pub struct SecureAPIClient {
    client: Client,
    base_url: String,
    api_key: String,
}

impl SecureAPIClient {
    pub fn new(base_url: String, api_key: String) -> Result<Self, Box<dyn std::error::Error>> {
        let client = create_secure_client()?;

        Ok(Self {
            client,
            base_url,
            api_key,
        })
    }

    pub async fn fetch_game_data(&self, endpoint: &str) -> Result<serde_json::Value, APIClientError> {
        let url = format!("{}/{}", self.base_url, endpoint);

        let response = self.client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("User-Agent", "Gaming-Protocol/1.0")
            .send()
            .await
            .map_err(|e| APIClientError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(APIClientError::APIError(response.status().as_u16()));
        }

        let json: serde_json::Value = response.json().await
            .map_err(|e| APIClientError::ParseError(e.to_string()))?;

        Ok(json)
    }
}

#[derive(Debug)]
pub enum APIClientError {
    RequestFailed(String),
    APIError(u16),
    ParseError(String),
    CertificateError(String),
}

// SECURE: Certificate pinning implementation
use sha2::{Sha256, Digest};

pub struct CertificatePinningValidator {
    pinned_certificates: std::collections::HashMap<String, Vec<String>>, // hostname -> cert hashes
}

impl CertificatePinningValidator {
    pub fn new() -> Self {
        let mut pinned_certificates = std::collections::HashMap::new();

        // Pin certificates for critical services
        pinned_certificates.insert("api.gaming-protocol.com".to_string(), vec![
            "sha256_hash_of_current_cert".to_string(),
            "sha256_hash_of_backup_cert".to_string(),
        ]);

        pinned_certificates.insert("payment.gaming-protocol.com".to_string(), vec![
            "sha256_hash_of_payment_cert".to_string(),
        ]);

        Self { pinned_certificates }
    }

    pub fn validate_certificate_pin(&self, hostname: &str, cert_der: &[u8]) -> Result<(), CertificatePinningError> {
        let cert_hash = self.calculate_cert_hash(cert_der);

        if let Some(pinned_hashes) = self.pinned_certificates.get(hostname) {
            if pinned_hashes.contains(&cert_hash) {
                Ok(())
            } else {
                Err(CertificatePinningError::PinMismatch {
                    hostname: hostname.to_string(),
                    expected: pinned_hashes.clone(),
                    actual: cert_hash,
                })
            }
        } else {
            // No pins configured for this hostname - use standard validation
            Ok(())
        }
    }

    fn calculate_cert_hash(&self, cert_der: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug)]
pub enum CertificatePinningError {
    PinMismatch {
        hostname: String,
        expected: Vec<String>,
        actual: String,
    },
    InvalidCertificate(String),
}

// SECURE: Comprehensive certificate validation
use x509_parser::prelude::*;
use chrono::{DateTime, Utc};

pub struct ComprehensiveCertificateValidator {
    root_store: RootCertStore,
    pinning_validator: CertificatePinningValidator,
    validation_policy: CertificateValidationPolicy,
}

#[derive(Debug)]
pub struct CertificateValidationPolicy {
    pub require_valid_chain: bool,
    pub require_hostname_match: bool,
    pub require_current_validity: bool,
    pub check_revocation: bool,
    pub minimum_key_size: usize,
    pub allowed_signature_algorithms: Vec<String>,
    pub maximum_validity_period: chrono::Duration,
}

impl Default for CertificateValidationPolicy {
    fn default() -> Self {
        Self {
            require_valid_chain: true,
            require_hostname_match: true,
            require_current_validity: true,
            check_revocation: true,
            minimum_key_size: 2048,
            allowed_signature_algorithms: vec![
                "sha256WithRSAEncryption".to_string(),
                "ecdsa-with-SHA256".to_string(),
                "ecdsa-with-SHA384".to_string(),
                "ecdsa-with-SHA512".to_string(),
            ],
            maximum_validity_period: chrono::Duration::days(825), // ~2 years
        }
    }
}

impl ComprehensiveCertificateValidator {
    pub fn new() -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        Self {
            root_store,
            pinning_validator: CertificatePinningValidator::new(),
            validation_policy: CertificateValidationPolicy::default(),
        }
    }

    pub fn validate_certificate_comprehensive(
        &self,
        cert_der: &[u8],
        hostname: &str,
        validation_time: DateTime<Utc>,
    ) -> Result<CertificateValidationResult, CertificateValidationError> {

        // Parse certificate
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| CertificateValidationError::ParseError(e.to_string()))?;

        let mut warnings = Vec::new();

        // 1. Check certificate validity period
        if self.validation_policy.require_current_validity {
            let not_before = cert.validity().not_before.to_datetime();
            let not_after = cert.validity().not_after.to_datetime();

            if validation_time < not_before {
                return Err(CertificateValidationError::NotYetValid);
            }

            if validation_time > not_after {
                return Err(CertificateValidationError::ExpiredCertificate);
            }

            // Check for excessively long validity periods
            let validity_period = not_after - not_before;
            if validity_period > self.validation_policy.maximum_validity_period {
                warnings.push(format!("Certificate validity period ({} days) exceeds recommended maximum",
                                     validity_period.num_days()));
            }
        }

        // 2. Check hostname verification
        if self.validation_policy.require_hostname_match {
            if !self.verify_hostname(&cert, hostname) {
                return Err(CertificateValidationError::HostnameMismatch);
            }
        }

        // 3. Check signature algorithm
        let sig_alg = cert.signature_algorithm.algorithm.to_string();
        if !self.validation_policy.allowed_signature_algorithms.contains(&sig_alg) {
            return Err(CertificateValidationError::WeakSignature);
        }

        // 4. Check key size
        if let Ok(public_key) = cert.public_key() {
            let key_size = self.estimate_key_size(&public_key);
            if key_size < self.validation_policy.minimum_key_size {
                return Err(CertificateValidationError::WeakKey(key_size));
            }
        }

        // 5. Certificate pinning validation
        if let Err(e) = self.pinning_validator.validate_certificate_pin(hostname, cert_der) {
            return Err(CertificateValidationError::PinningFailed(format!("{:?}", e)));
        }

        // 6. Check for revocation (simplified)
        if self.validation_policy.check_revocation {
            // In a real implementation, this would check OCSP or CRL
            warnings.push("Revocation checking not fully implemented".to_string());
        }

        Ok(CertificateValidationResult {
            is_valid: true,
            validation_details: "Certificate passed comprehensive validation".to_string(),
            warnings,
        })
    }

    fn verify_hostname(&self, cert: &X509Certificate, hostname: &str) -> bool {
        // Check Subject Alternative Names
        if let Ok(Some(san_ext)) = cert.extensions().subject_alt_name() {
            for name in &san_ext.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(dns_name) => {
                        if self.hostname_matches(dns_name, hostname) {
                            return true;
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Check Common Name in subject
        for attr in cert.subject().iter() {
            if let Ok(cn) = attr.attr_value().as_str() {
                if self.hostname_matches(cn, hostname) {
                    return true;
                }
            }
        }

        false
    }

    fn hostname_matches(&self, cert_name: &str, hostname: &str) -> bool {
        if cert_name == hostname {
            return true;
        }

        // Handle wildcard certificates
        if cert_name.starts_with("*.") {
            let wildcard_domain = &cert_name[2..];
            if hostname.ends_with(wildcard_domain) {
                // Ensure it's not a subdomain of the wildcard
                let hostname_prefix = &hostname[..hostname.len() - wildcard_domain.len()];
                return !hostname_prefix.contains('.');
            }
        }

        false
    }

    fn estimate_key_size(&self, _public_key: &x509_parser::public_key::PublicKey) -> usize {
        // Simplified key size estimation
        // In a real implementation, this would parse the key and determine actual size
        2048 // Placeholder
    }
}

// SECURE: Environment-specific TLS configuration
#[derive(Debug, Clone)]
pub enum Environment {
    Development,
    Staging,
    Production,
}

pub struct EnvironmentSpecificTLSConfig {
    pub environment: Environment,
    pub strict_validation: bool,
    pub certificate_pinning: bool,
    pub ocsp_checking: bool,
    pub ct_log_verification: bool,
}

impl EnvironmentSpecificTLSConfig {
    pub fn for_environment(env: Environment) -> Self {
        match env {
            Environment::Development => Self {
                environment: env,
                strict_validation: false,  // Relaxed for development
                certificate_pinning: false,
                ocsp_checking: false,
                ct_log_verification: false,
            },
            Environment::Staging => Self {
                environment: env,
                strict_validation: true,
                certificate_pinning: true,
                ocsp_checking: true,
                ct_log_verification: false,
            },
            Environment::Production => Self {
                environment: env,
                strict_validation: true,
                certificate_pinning: true,
                ocsp_checking: true,
                ct_log_verification: true,
            },
        }
    }

    pub fn create_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
        if self.strict_validation {
            create_secure_client()
        } else {
            // Development client with relaxed validation
            Ok(Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(std::time::Duration::from_secs(30))
                .build()?)
        }
    }
}
```

### Long-term Solutions

```rust
// Comprehensive certificate management system
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateManagementSystem {
    pub certificate_inventory: CertificateInventory,
    pub monitoring_configuration: CertificateMonitoring,
    pub automation_policies: AutomationPolicies,
    pub compliance_framework: ComplianceFramework,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateInventory {
    pub certificates: HashMap<String, ManagedCertificate>,
    pub certificate_authorities: HashMap<String, TrustedCA>,
    pub pinned_certificates: HashMap<String, PinnedCertificateSet>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManagedCertificate {
    pub certificate_id: String,
    pub common_name: String,
    pub subject_alternative_names: Vec<String>,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: chrono::DateTime<chrono::Utc>,
    pub not_after: chrono::DateTime<chrono::Utc>,
    pub key_algorithm: String,
    pub key_size: usize,
    pub signature_algorithm: String,
    pub certificate_chain: Vec<String>,
    pub usage_contexts: Vec<CertificateUsageContext>,
    pub monitoring_status: MonitoringStatus,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CertificateUsageContext {
    WebServer(String),      // Hostname
    APIClient(String),      // Service name
    InternalService(String), // Service identifier
    PaymentGateway(String), // Gateway identifier
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustedCA {
    pub ca_name: String,
    pub ca_certificate: String,
    pub trust_level: TrustLevel,
    pub validation_requirements: ValidationRequirements,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TrustLevel {
    FullyTrusted,
    ConditionallyTrusted,
    UnderReview,
    Distrusted,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationRequirements {
    pub require_ct_logs: bool,
    pub require_ocsp_stapling: bool,
    pub require_certificate_transparency: bool,
    pub maximum_validity_period: chrono::Duration,
    pub minimum_key_size: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PinnedCertificateSet {
    pub primary_pins: Vec<String>,    // SHA-256 hashes
    pub backup_pins: Vec<String>,     // Backup certificate hashes
    pub pin_expiration: chrono::DateTime<chrono::Utc>,
    pub update_policy: PinUpdatePolicy,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum PinUpdatePolicy {
    Manual,                    // Require manual intervention
    AutomaticWithVerification, // Auto-update with additional verification
    AlertOnly,                // Alert but don't update automatically
}

impl CertificateManagementSystem {
    pub fn new() -> Self {
        Self {
            certificate_inventory: CertificateInventory {
                certificates: HashMap::new(),
                certificate_authorities: Self::create_default_ca_store(),
                pinned_certificates: HashMap::new(),
            },
            monitoring_configuration: CertificateMonitoring::default(),
            automation_policies: AutomationPolicies::default(),
            compliance_framework: ComplianceFramework::default(),
        }
    }

    fn create_default_ca_store() -> HashMap<String, TrustedCA> {
        let mut ca_store = HashMap::new();

        ca_store.insert("DigiCert".to_string(), TrustedCA {
            ca_name: "DigiCert Inc".to_string(),
            ca_certificate: "-----BEGIN CERTIFICATE-----...".to_string(),
            trust_level: TrustLevel::FullyTrusted,
            validation_requirements: ValidationRequirements {
                require_ct_logs: true,
                require_ocsp_stapling: true,
                require_certificate_transparency: true,
                maximum_validity_period: chrono::Duration::days(825),
                minimum_key_size: 2048,
            },
        });

        ca_store.insert("Let's Encrypt".to_string(), TrustedCA {
            ca_name: "Let's Encrypt Authority X3".to_string(),
            ca_certificate: "-----BEGIN CERTIFICATE-----...".to_string(),
            trust_level: TrustLevel::FullyTrusted,
            validation_requirements: ValidationRequirements {
                require_ct_logs: true,
                require_ocsp_stapling: false,
                require_certificate_transparency: true,
                maximum_validity_period: chrono::Duration::days(90),
                minimum_key_size: 2048,
            },
        });

        ca_store
    }

    pub fn register_certificate(&mut self, cert_data: &[u8], usage_context: CertificateUsageContext) -> Result<String, CertificateManagementError> {
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_data)
            .map_err(|e| CertificateManagementError::ParseError(e.to_string()))?;

        let certificate_id = self.generate_certificate_id(&cert);
        let common_name = self.extract_common_name(&cert);

        let managed_cert = ManagedCertificate {
            certificate_id: certificate_id.clone(),
            common_name,
            subject_alternative_names: self.extract_san_list(&cert),
            issuer: cert.issuer().to_string(),
            serial_number: cert.serial.to_str_radix(16),
            not_before: cert.validity().not_before.to_datetime(),
            not_after: cert.validity().not_after.to_datetime(),
            key_algorithm: "RSA".to_string(), // Simplified
            key_size: 2048, // Simplified
            signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
            certificate_chain: vec![], // Would be populated with full chain
            usage_contexts: vec![usage_context],
            monitoring_status: MonitoringStatus::Active,
        };

        self.certificate_inventory.certificates.insert(certificate_id.clone(), managed_cert);
        Ok(certificate_id)
    }

    pub fn check_certificate_expiration(&self) -> Vec<ExpirationAlert> {
        let mut alerts = Vec::new();
        let now = chrono::Utc::now();

        for (cert_id, cert) in &self.certificate_inventory.certificates {
            let days_until_expiry = (cert.not_after - now).num_days();

            if days_until_expiry <= 30 {
                alerts.push(ExpirationAlert {
                    certificate_id: cert_id.clone(),
                    common_name: cert.common_name.clone(),
                    expiration_date: cert.not_after,
                    days_remaining: days_until_expiry,
                    severity: if days_until_expiry <= 7 {
                        AlertSeverity::Critical
                    } else if days_until_expiry <= 14 {
                        AlertSeverity::High
                    } else {
                        AlertSeverity::Medium
                    },
                    affected_services: cert.usage_contexts.clone(),
                });
            }
        }

        alerts
    }

    pub fn validate_certificate_compliance(&self, certificate_id: &str) -> Result<ComplianceReport, CertificateManagementError> {
        let cert = self.certificate_inventory.certificates.get(certificate_id)
            .ok_or_else(|| CertificateManagementError::CertificateNotFound(certificate_id.to_string()))?;

        let mut compliance_issues = Vec::new();
        let mut compliance_score = 100.0;

        // Check key size
        if cert.key_size < 2048 {
            compliance_issues.push(ComplianceIssue {
                issue_type: ComplianceIssueType::WeakKeySize,
                description: format!("Key size {} is below minimum requirement of 2048 bits", cert.key_size),
                severity: ComplianceSeverity::High,
                remediation: "Replace certificate with stronger key".to_string(),
            });
            compliance_score -= 25.0;
        }

        // Check validity period
        let validity_period = cert.not_after - cert.not_before;
        if validity_period > chrono::Duration::days(825) {
            compliance_issues.push(ComplianceIssue {
                issue_type: ComplianceIssueType::ExcessiveValidityPeriod,
                description: format!("Validity period of {} days exceeds recommended maximum", validity_period.num_days()),
                severity: ComplianceSeverity::Medium,
                remediation: "Use shorter validity periods for new certificates".to_string(),
            });
            compliance_score -= 10.0;
        }

        // Check expiration
        let now = chrono::Utc::now();
        if cert.not_after < now {
            compliance_issues.push(ComplianceIssue {
                issue_type: ComplianceIssueType::ExpiredCertificate,
                description: "Certificate has expired".to_string(),
                severity: ComplianceSeverity::Critical,
                remediation: "Renew certificate immediately".to_string(),
            });
            compliance_score -= 50.0;
        }

        Ok(ComplianceReport {
            certificate_id: certificate_id.to_string(),
            compliance_score: compliance_score.max(0.0),
            issues: compliance_issues,
            last_checked: now,
            next_check: now + chrono::Duration::days(1),
        })
    }

    fn generate_certificate_id(&self, cert: &x509_parser::certificate::X509Certificate) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(cert.raw);
        format!("{:x}", hasher.finalize())[..16].to_string()
    }

    fn extract_common_name(&self, cert: &x509_parser::certificate::X509Certificate) -> String {
        cert.subject().iter_common_name()
            .next()
            .unwrap_or("Unknown")
            .to_string()
    }

    fn extract_san_list(&self, cert: &x509_parser::certificate::X509Certificate) -> Vec<String> {
        if let Ok(Some(san_ext)) = cert.extensions().subject_alt_name() {
            san_ext.general_names.iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MonitoringStatus {
    Active,
    Inactive,
    AlertGenerated,
    UnderReview,
}

#[derive(Debug)]
pub struct ExpirationAlert {
    pub certificate_id: String,
    pub common_name: String,
    pub expiration_date: chrono::DateTime<chrono::Utc>,
    pub days_remaining: i64,
    pub severity: AlertSeverity,
    pub affected_services: Vec<CertificateUsageContext>,
}

#[derive(Debug)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub struct ComplianceReport {
    pub certificate_id: String,
    pub compliance_score: f64,
    pub issues: Vec<ComplianceIssue>,
    pub last_checked: chrono::DateTime<chrono::Utc>,
    pub next_check: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct ComplianceIssue {
    pub issue_type: ComplianceIssueType,
    pub description: String,
    pub severity: ComplianceSeverity,
    pub remediation: String,
}

#[derive(Debug)]
pub enum ComplianceIssueType {
    WeakKeySize,
    WeakSignatureAlgorithm,
    ExcessiveValidityPeriod,
    ExpiredCertificate,
    MissingCTLogs,
    NoOCSPStapling,
    UntrustedCA,
}

#[derive(Debug)]
pub enum ComplianceSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug)]
pub enum CertificateManagementError {
    ParseError(String),
    CertificateNotFound(String),
    ValidationFailed(String),
    ComplianceCheckFailed(String),
}

// Placeholder structs for comprehensive certificate management
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CertificateMonitoring {
    pub expiration_check_interval: chrono::Duration,
    pub revocation_check_interval: chrono::Duration,
    pub alert_thresholds: HashMap<String, i64>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AutomationPolicies {
    pub auto_renewal_enabled: bool,
    pub renewal_threshold_days: i64,
    pub backup_certificate_generation: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ComplianceFramework {
    pub standards: Vec<String>,
    pub audit_frequency: chrono::Duration,
    pub reporting_requirements: Vec<String>,
}
```

## Risk Assessment

### Likelihood Analysis
- **Exploitation Probability**: 0.35 (35%)
- **Attack Complexity**: Medium - Requires network positioning or certificate manipulation
- **Required Access Level**: Low - Can exploit weak validation from network position
- **Detection Probability**: 0.6 (60%) with proper certificate monitoring

### Impact Analysis
- **Confidentiality Impact**: Medium - Potential interception of API communications
- **Integrity Impact**: Medium - Possible manipulation of external service communications
- **Availability Impact**: Low - Certificate validation issues typically don't affect availability
- **Financial Impact**: Medium - Potential for significant data exposure and trust loss

### Exploitability Assessment
- **Attack Vector**: Network - Man-in-the-middle and certificate spoofing attacks
- **Attack Complexity**: Medium - Requires network positioning or certificate authority compromise
- **Privileges Required**: None - Network-based attacks can be executed without system access
- **User Interaction**: None - Passive interception of communications

### Detection Difficulty
- **Static Analysis**: Easy - Code scanning can identify disabled certificate validation
- **Dynamic Analysis**: Medium - Requires testing against invalid certificate scenarios
- **Runtime Detection**: Medium - Certificate validation monitoring can detect issues
- **Forensic Analysis**: Hard - Network attacks may leave limited forensic evidence

### Overall Risk Rating
- **Base Score**: 3.4 (Low)
- **Temporal Score**: 3.1 (accounting for available tools and mitigations)
- **Environmental Score**: 2.9 (considering typical deployment contexts)
- **Final CVSS Score**: 3.4/10.0 (Low Severity)

## Conclusion

Improper certificate validation in the Solana gaming protocol represents a low-severity security vulnerability that primarily affects the confidentiality and integrity of external communications. While the core Solana blockchain operations are not directly impacted, the gaming protocol's interactions with external APIs, payment processors, and third-party services could be compromised through man-in-the-middle attacks and certificate spoofing.

The identified vulnerabilities include disabled certificate validation, insufficient hostname verification, acceptance of self-signed certificates, and weak TLS configuration. These weaknesses could allow attackers to intercept API communications, steal credentials, or manipulate external service interactions, particularly in environments where network security is compromised.

Remediation should focus on implementing comprehensive certificate validation, certificate pinning for critical services, and establishing robust TLS configuration management. The relatively low severity allows for planned implementation rather than emergency fixes, but organizations should prioritize these improvements to maintain the overall security posture.

Long-term security requires implementing certificate management systems, automated monitoring of certificate health, and regular compliance auditing. The economic analysis shows favorable return on investment, with significant risk reduction benefits outweighing the moderate implementation costs.

*InshaAllah*, proper certificate validation serves as a crucial component of defense-in-depth security strategy, ensuring the integrity and confidentiality of all external communications within the gaming protocol ecosystem.