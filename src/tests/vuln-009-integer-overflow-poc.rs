//! VUL-009: Integer Overflow Arithmetic Vulnerabilities - Proof of Concept
//!
//! VULNERABILITY: Integer Overflow in Arithmetic Operations
//! SEVERITY: Critical (CVSS 9.0)
//! DESCRIPTION: Unchecked arithmetic operations can cause overflow, underflow, and wrapping
//!
//! AFFECTED CODE:
//! - programs/wager-program/src/instructions/distribute_winnings.rs:39
//!   let earnings = kills_and_spawns as u64 * game_session.session_bet / 10;
//! - programs/wager-program/src/instructions/distribute_winnings.rs:171
//!   let total_pot = game_session.session_bet * players_per_team as u64 * 2;
//! - programs/wager-program/src/instructions/distribute_winnings.rs:174
//!   let winning_amount = game_session.session_bet * 2;
//!
//! ATTACK VECTOR:
//! 1. Create sessions with maximum bet amounts near u64::MAX
//! 2. Multiplication operations overflow and wrap to small values
//! 3. Players receive 0 or minimal payouts despite huge stakes
//! 4. Chain multiplications compound overflow risk

use anchor_lang::prelude::*;
use std::u64;

/// Mock game session structure for testing overflow scenarios
#[derive(Debug, Clone)]
pub struct MockGameSession {
    pub session_id: String,
    pub session_bet: u64,
    pub players_per_team: usize,
    pub team_a_kills: Vec<u16>,
    pub team_a_spawns: Vec<u16>,
    pub team_b_kills: Vec<u16>,
    pub team_b_spawns: Vec<u16>,
}

impl MockGameSession {
    pub fn new(session_bet: u64, players_per_team: usize) -> Self {
        Self {
            session_id: "test_session".to_string(),
            session_bet,
            players_per_team,
            team_a_kills: vec![0; players_per_team],
            team_a_spawns: vec![0; players_per_team],
            team_b_kills: vec![0; players_per_team],
            team_b_spawns: vec![0; players_per_team],
        }
    }

    /// Vulnerable calculation: kills_and_spawns as u64 * session_bet / 10
    pub fn calculate_vulnerable_earnings(&self, team: u8, player_index: usize) -> u64 {
        let (kills, spawns) = if team == 0 {
            (self.team_a_kills[player_index], self.team_a_spawns[player_index])
        } else {
            (self.team_b_kills[player_index], self.team_b_spawns[player_index])
        };

        let kills_and_spawns = (kills + spawns) as u64;

        // ❌ VULNERABLE: No overflow checking
        let earnings = kills_and_spawns * self.session_bet / 10;
        earnings
    }

    /// Vulnerable calculation: session_bet * players_per_team * 2
    pub fn calculate_vulnerable_total_pot(&self) -> u64 {
        // ❌ VULNERABLE: Chain multiplication without overflow checking
        let total_pot = self.session_bet * self.players_per_team as u64 * 2;
        total_pot
    }

    /// Vulnerable calculation: session_bet * 2
    pub fn calculate_vulnerable_winning_amount(&self) -> u64 {
        // ❌ VULNERABLE: Simple multiplication without overflow checking
        let winning_amount = self.session_bet * 2;
        winning_amount
    }

    /// Safe calculation with overflow checking
    pub fn calculate_safe_earnings(&self, team: u8, player_index: usize) -> Result<u64> {
        let (kills, spawns) = if team == 0 {
            (self.team_a_kills[player_index], self.team_a_spawns[player_index])
        } else {
            (self.team_b_kills[player_index], self.team_b_spawns[player_index])
        };

        let kills_and_spawns = (kills as u64)
            .checked_add(spawns as u64)
            .ok_or_else(|| error!(MockError::ArithmeticOverflow))?;

        let earnings = kills_and_spawns
            .checked_mul(self.session_bet)
            .ok_or_else(|| error!(MockError::ArithmeticOverflow))?
            .checked_div(10)
            .ok_or_else(|| error!(MockError::DivisionByZero))?;

        Ok(earnings)
    }

    /// Safe total pot calculation
    pub fn calculate_safe_total_pot(&self) -> Result<u64> {
        let players_bet = self.session_bet
            .checked_mul(self.players_per_team as u64)
            .ok_or_else(|| error!(MockError::ArithmeticOverflow))?;

        let total_pot = players_bet
            .checked_mul(2)
            .ok_or_else(|| error!(MockError::ArithmeticOverflow))?;

        Ok(total_pot)
    }
}

/// Integer overflow attack simulator
pub struct IntegerOverflowAttacker {
    pub test_cases: Vec<OverflowTestCase>,
}

impl IntegerOverflowAttacker {
    pub fn new() -> Self {
        Self {
            test_cases: vec![
                // Critical overflow scenarios
                OverflowTestCase {
                    name: "Maximum Bet Overflow".to_string(),
                    session_bet: u64::MAX / 2 + 1,
                    players_per_team: 5,
                    player_kills: 100,
                    player_spawns: 50,
                    expected_overflow: true,
                },
                OverflowTestCase {
                    name: "Chain Multiplication Overflow".to_string(),
                    session_bet: u64::MAX / 8, // Will overflow when * 5 * 2
                    players_per_team: 5,
                    player_kills: 1,
                    player_spawns: 1,
                    expected_overflow: true,
                },
                OverflowTestCase {
                    name: "Earnings Multiplication Overflow".to_string(),
                    session_bet: u64::MAX / 100, // Will overflow when * large kills_and_spawns
                    players_per_team: 1,
                    player_kills: u16::MAX,
                    player_spawns: u16::MAX,
                    expected_overflow: true,
                },
                OverflowTestCase {
                    name: "Near-Maximum Safe Values".to_string(),
                    session_bet: 1_000_000_000_000, // 1 trillion
                    players_per_team: 5,
                    player_kills: 1000,
                    player_spawns: 1000,
                    expected_overflow: false,
                },
            ],
        }
    }

    /// Execute overflow attack simulation
    pub fn execute_overflow_attacks(&self) -> OverflowAttackReport {
        let mut report = OverflowAttackReport::new();

        msg!("🚨 EXECUTING INTEGER OVERFLOW ATTACKS");
        msg!("Testing {} overflow scenarios", self.test_cases.len());

        for test_case in &self.test_cases {
            msg!("\n--- Testing: {} ---", test_case.name);

            let session = MockGameSession::new(test_case.session_bet, test_case.players_per_team);
            let mut session_with_stats = session.clone();

            // Set player stats for testing
            session_with_stats.team_a_kills[0] = test_case.player_kills;
            session_with_stats.team_a_spawns[0] = test_case.player_spawns;

            // Test vulnerable calculations
            let earnings_result = self.test_earnings_overflow(&session_with_stats);
            let pot_result = self.test_pot_overflow(&session_with_stats);
            let winning_result = self.test_winning_amount_overflow(&session_with_stats);

            let test_result = OverflowTestResult {
                test_case: test_case.clone(),
                earnings_overflow: earnings_result.overflow_detected,
                pot_overflow: pot_result.overflow_detected,
                winning_overflow: winning_result.overflow_detected,
                earnings_wrapped_value: earnings_result.wrapped_value,
                pot_wrapped_value: pot_result.wrapped_value,
                winning_wrapped_value: winning_result.wrapped_value,
                financial_impact: self.calculate_financial_impact(
                    test_case.session_bet,
                    earnings_result.wrapped_value,
                    pot_result.wrapped_value,
                ),
            };

            report.test_results.push(test_result);

            if earnings_result.overflow_detected || pot_result.overflow_detected || winning_result.overflow_detected {
                report.overflow_cases_found += 1;
                report.total_financial_impact += test_result.financial_impact;
            }
        }

        report.calculate_summary();
        msg!("Attack simulation complete: {} overflow cases found", report.overflow_cases_found);
        report
    }

    /// Test earnings calculation overflow
    fn test_earnings_overflow(&self, session: &MockGameSession) -> OverflowResult {
        let vulnerable_earnings = session.calculate_vulnerable_earnings(0, 0);
        let safe_earnings = session.calculate_safe_earnings(0, 0);

        let kills_and_spawns = (session.team_a_kills[0] + session.team_a_spawns[0]) as u64;
        let expected_earnings = kills_and_spawns
            .saturating_mul(session.session_bet)
            .saturating_div(10);

        let overflow_detected = safe_earnings.is_err() || vulnerable_earnings != expected_earnings;

        msg!("Earnings calculation:");
        msg!("  Session bet: {}", session.session_bet);
        msg!("  Kills + Spawns: {}", kills_and_spawns);
        msg!("  Vulnerable result: {}", vulnerable_earnings);
        msg!("  Expected (safe): {}", expected_earnings);
        msg!("  Overflow detected: {}", overflow_detected);

        OverflowResult {
            overflow_detected,
            wrapped_value: vulnerable_earnings,
            expected_value: expected_earnings,
        }
    }

    /// Test total pot calculation overflow
    fn test_pot_overflow(&self, session: &MockGameSession) -> OverflowResult {
        let vulnerable_pot = session.calculate_vulnerable_total_pot();
        let safe_pot = session.calculate_safe_total_pot();

        let expected_pot = (session.session_bet as u128)
            .saturating_mul(session.players_per_team as u128)
            .saturating_mul(2);
        let expected_pot_u64 = if expected_pot > u64::MAX as u128 {
            u64::MAX
        } else {
            expected_pot as u64
        };

        let overflow_detected = safe_pot.is_err() || vulnerable_pot != expected_pot_u64;

        msg!("Total pot calculation:");
        msg!("  Session bet: {}", session.session_bet);
        msg!("  Players per team: {}", session.players_per_team);
        msg!("  Vulnerable result: {}", vulnerable_pot);
        msg!("  Expected (safe): {}", expected_pot_u64);
        msg!("  Overflow detected: {}", overflow_detected);

        OverflowResult {
            overflow_detected,
            wrapped_value: vulnerable_pot,
            expected_value: expected_pot_u64,
        }
    }

    /// Test winning amount calculation overflow
    fn test_winning_amount_overflow(&self, session: &MockGameSession) -> OverflowResult {
        let vulnerable_winning = session.calculate_vulnerable_winning_amount();
        let expected_winning = session.session_bet.saturating_mul(2);

        let overflow_detected = vulnerable_winning != expected_winning;

        msg!("Winning amount calculation:");
        msg!("  Session bet: {}", session.session_bet);
        msg!("  Vulnerable result: {}", vulnerable_winning);
        msg!("  Expected (safe): {}", expected_winning);
        msg!("  Overflow detected: {}", overflow_detected);

        OverflowResult {
            overflow_detected,
            wrapped_value: vulnerable_winning,
            expected_value: expected_winning,
        }
    }

    /// Calculate financial impact of overflow
    fn calculate_financial_impact(&self, original_bet: u64, wrapped_earnings: u64, wrapped_pot: u64) -> u64 {
        // Calculate how much money is lost due to overflow
        let expected_earnings = original_bet.saturating_mul(2); // Simplified expected earnings
        let expected_pot = original_bet.saturating_mul(10); // Simplified expected pot

        let earnings_loss = expected_earnings.saturating_sub(wrapped_earnings);
        let pot_loss = expected_pot.saturating_sub(wrapped_pot);

        earnings_loss.saturating_add(pot_loss)
    }
}

/// Test case for overflow scenarios
#[derive(Debug, Clone)]
pub struct OverflowTestCase {
    pub name: String,
    pub session_bet: u64,
    pub players_per_team: usize,
    pub player_kills: u16,
    pub player_spawns: u16,
    pub expected_overflow: bool,
}

/// Result of overflow testing
#[derive(Debug)]
pub struct OverflowResult {
    pub overflow_detected: bool,
    pub wrapped_value: u64,
    pub expected_value: u64,
}

/// Individual test result
#[derive(Debug)]
pub struct OverflowTestResult {
    pub test_case: OverflowTestCase,
    pub earnings_overflow: bool,
    pub pot_overflow: bool,
    pub winning_overflow: bool,
    pub earnings_wrapped_value: u64,
    pub pot_wrapped_value: u64,
    pub winning_wrapped_value: u64,
    pub financial_impact: u64,
}

/// Comprehensive attack report
#[derive(Debug)]
pub struct OverflowAttackReport {
    pub test_results: Vec<OverflowTestResult>,
    pub overflow_cases_found: u32,
    pub total_financial_impact: u64,
    pub most_dangerous_case: Option<String>,
    pub recommendations: Vec<String>,
}

impl OverflowAttackReport {
    pub fn new() -> Self {
        Self {
            test_results: Vec::new(),
            overflow_cases_found: 0,
            total_financial_impact: 0,
            most_dangerous_case: None,
            recommendations: Vec::new(),
        }
    }

    pub fn calculate_summary(&mut self) {
        // Find most dangerous case
        let mut max_impact = 0u64;
        let mut most_dangerous = None;

        for result in &self.test_results {
            if result.financial_impact > max_impact {
                max_impact = result.financial_impact;
                most_dangerous = Some(result.test_case.name.clone());
            }
        }

        self.most_dangerous_case = most_dangerous;

        // Generate recommendations
        self.recommendations = vec![
            "Replace all arithmetic operators with checked variants".to_string(),
            "Implement input validation for maximum bet amounts".to_string(),
            "Use saturating arithmetic for non-critical calculations".to_string(),
            "Add comprehensive overflow testing".to_string(),
            "Consider using larger integer types (u128) for intermediate calculations".to_string(),
        ];
    }

    pub fn print_report(&self) {
        msg!("📊 INTEGER OVERFLOW ATTACK REPORT");
        msg!("================================");
        msg!("Total test cases: {}", self.test_results.len());
        msg!("Overflow cases found: {}", self.overflow_cases_found);
        msg!("Total financial impact: {} tokens", self.total_financial_impact);

        if let Some(ref dangerous_case) = self.most_dangerous_case {
            msg!("Most dangerous case: {}", dangerous_case);
        }

        msg!("\nRecommendations:");
        for (i, rec) in self.recommendations.iter().enumerate() {
            msg!("  {}. {}", i + 1, rec);
        }
    }
}

/// Mock error types for testing
#[error_code]
pub enum MockError {
    #[msg("Arithmetic overflow detected")]
    ArithmeticOverflow,
    #[msg("Division by zero")]
    DivisionByZero,
}

/// Safe arithmetic operations library
pub struct SafeMath;

impl SafeMath {
    /// Safe multiplication with overflow checking
    pub fn safe_mul(a: u64, b: u64) -> Result<u64> {
        a.checked_mul(b).ok_or_else(|| error!(MockError::ArithmeticOverflow))
    }

    /// Safe addition with overflow checking
    pub fn safe_add(a: u64, b: u64) -> Result<u64> {
        a.checked_add(b).ok_or_else(|| error!(MockError::ArithmeticOverflow))
    }

    /// Safe division with zero checking
    pub fn safe_div(a: u64, b: u64) -> Result<u64> {
        if b == 0 {
            return Err(error!(MockError::DivisionByZero));
        }
        Ok(a / b)
    }

    /// Safe percentage calculation
    pub fn safe_percentage(amount: u64, percentage: u64) -> Result<u64> {
        require!(percentage <= 100, MockError::ArithmeticOverflow);

        let result = Self::safe_mul(amount, percentage)?;
        Self::safe_div(result, 100)
    }

    /// Safe earnings calculation matching vulnerable code
    pub fn safe_earnings_calculation(kills_and_spawns: u16, session_bet: u64) -> Result<u64> {
        let kills_and_spawns_u64 = kills_and_spawns as u64;
        let multiplied = Self::safe_mul(kills_and_spawns_u64, session_bet)?;
        Self::safe_div(multiplied, 10)
    }
}

/// Comprehensive test suite
#[cfg(test)]
mod integer_overflow_tests {
    use super::*;

    #[tokio::test]
    async fn test_maximum_bet_overflow() {
        let session_bet = u64::MAX / 2 + 1; // This will overflow when multiplied by 2
        let session = MockGameSession::new(session_bet, 5);

        // Test winning amount calculation (session_bet * 2)
        let winning_amount = session.calculate_vulnerable_winning_amount();

        // Should overflow and wrap to a small value
        assert!(winning_amount < session_bet);
        assert_eq!(winning_amount, 0); // Wraps to 0

        println!("✅ Maximum bet overflow confirmed:");
        println!("   Session bet: {}", session_bet);
        println!("   Winning amount (after overflow): {}", winning_amount);
        println!("   Expected (without overflow): ~{}", u64::MAX);
    }

    #[tokio::test]
    async fn test_earnings_calculation_overflow() {
        let session_bet = u64::MAX / 100; // Large session bet
        let mut session = MockGameSession::new(session_bet, 1);

        // Set maximum kills and spawns
        session.team_a_kills[0] = u16::MAX;
        session.team_a_spawns[0] = u16::MAX;

        let earnings = session.calculate_vulnerable_earnings(0, 0);
        let kills_and_spawns = (u16::MAX + u16::MAX) as u64;

        // Calculate what the result should be without overflow
        let expected_without_overflow = (kills_and_spawns as u128) * (session_bet as u128) / 10;

        // Should overflow
        assert!(expected_without_overflow > u64::MAX as u128);
        assert!(earnings < session_bet); // Wrapped to small value

        println!("✅ Earnings calculation overflow confirmed:");
        println!("   Session bet: {}", session_bet);
        println!("   Kills + Spawns: {}", kills_and_spawns);
        println!("   Earnings (after overflow): {}", earnings);
        println!("   Expected (without overflow): {}", expected_without_overflow);
    }

    #[tokio::test]
    async fn test_chain_multiplication_overflow() {
        let session_bet = u64::MAX / 8; // Will overflow when * 5 * 2
        let session = MockGameSession::new(session_bet, 5);

        let total_pot = session.calculate_vulnerable_total_pot();

        // Calculate expected value without overflow
        let expected = (session_bet as u128) * 5u128 * 2u128;

        // Should overflow
        assert!(expected > u64::MAX as u128);
        assert!(total_pot < session_bet); // Wrapped to smaller value

        println!("✅ Chain multiplication overflow confirmed:");
        println!("   Session bet: {}", session_bet);
        println!("   Total pot (after overflow): {}", total_pot);
        println!("   Expected (without overflow): {}", expected);
    }

    #[tokio::test]
    async fn test_safe_math_operations() {
        // Test safe multiplication
        let result = SafeMath::safe_mul(u64::MAX / 2, 3);
        assert!(result.is_err()); // Should detect overflow

        let safe_result = SafeMath::safe_mul(1000, 2000);
        assert_eq!(safe_result.unwrap(), 2_000_000);

        // Test safe division by zero
        let div_result = SafeMath::safe_div(100, 0);
        assert!(div_result.is_err()); // Should detect division by zero

        println!("✅ Safe math operations working correctly");
    }

    #[tokio::test]
    async fn test_comprehensive_overflow_attack() {
        let attacker = IntegerOverflowAttacker::new();
        let report = attacker.execute_overflow_attacks();

        // Should find overflow cases
        assert!(report.overflow_cases_found > 0);
        assert!(report.total_financial_impact > 0);
        assert!(report.most_dangerous_case.is_some());

        report.print_report();

        println!("✅ Comprehensive overflow attack simulation completed");
        println!("   Overflow cases found: {}", report.overflow_cases_found);
        println!("   Total financial impact: {} tokens", report.total_financial_impact);
    }

    #[tokio::test]
    async fn test_real_world_scenario() {
        // Simulate real gaming scenario with high-value tournament
        let tournament_bet = 1_000_000_000_000; // 1 trillion tokens per player
        let mut session = MockGameSession::new(tournament_bet, 5);

        // Set realistic but high player stats
        session.team_a_kills[0] = 1000; // 1000 kills
        session.team_a_spawns[0] = 500;  // 500 spawns

        let earnings = session.calculate_vulnerable_earnings(0, 0);
        let total_pot = session.calculate_vulnerable_total_pot();
        let winning_amount = session.calculate_vulnerable_winning_amount();

        // Check for potential issues
        let kills_and_spawns = 1500u64;
        let expected_earnings = kills_and_spawns * tournament_bet / 10;
        let expected_pot = tournament_bet * 5 * 2;
        let expected_winning = tournament_bet * 2;

        println!("🎮 Real-world high-value tournament scenario:");
        println!("   Tournament bet per player: {} tokens", tournament_bet);
        println!("   Player performance: {} kills + spawns", kills_and_spawns);
        println!("   Calculated earnings: {} tokens", earnings);
        println!("   Expected earnings: {} tokens", expected_earnings);
        println!("   Total pot: {} tokens", total_pot);
        println!("   Expected pot: {} tokens", expected_pot);
        println!("   Winning amount: {} tokens", winning_amount);
        println!("   Expected winning: {} tokens", expected_winning);

        // In a real scenario, these calculations might overflow
        if earnings != expected_earnings {
            println!("⚠️  Earnings calculation overflow detected!");
        }
        if total_pot != expected_pot {
            println!("⚠️  Total pot calculation overflow detected!");
        }
        if winning_amount != expected_winning {
            println!("⚠️  Winning amount calculation overflow detected!");
        }
    }

    #[tokio::test]
    async fn test_boundary_conditions() {
        // Test various boundary conditions for overflow
        let boundary_tests = vec![
            ("u64::MAX", u64::MAX),
            ("u64::MAX / 2", u64::MAX / 2),
            ("u64::MAX / 10", u64::MAX / 10),
            ("u32::MAX as u64", u32::MAX as u64),
            ("Large but safe", 1_000_000_000_000),
        ];

        for (name, bet) in boundary_tests {
            let session = MockGameSession::new(bet, 5);
            let winning_amount = session.calculate_vulnerable_winning_amount();

            println!("Boundary test - {}: bet={}, winning={}", name, bet, winning_amount);

            // Check for overflow (wrapped value would be much smaller)
            if bet > u64::MAX / 2 {
                assert!(winning_amount < bet, "Overflow should have occurred for {}", name);
            }
        }

        println!("✅ Boundary condition testing completed");
    }
}

/// Economic impact analysis for overflow vulnerabilities
pub struct EconomicImpactAnalyzer;

impl EconomicImpactAnalyzer {
    /// Calculate potential economic damage from overflow vulnerabilities
    pub fn calculate_overflow_damage(
        daily_high_value_sessions: u32,
        average_session_value: u64,
        overflow_probability: f64,
    ) -> EconomicOverflowReport {
        let daily_sessions_affected = (daily_high_value_sessions as f64 * overflow_probability) as u32;
        let daily_value_lost = daily_sessions_affected as u64 * average_session_value;
        let annual_value_lost = daily_value_lost * 365;

        // Calculate worst-case scenario (maximum possible overflow)
        let max_overflow_loss = if average_session_value > u64::MAX / 10 {
            average_session_value // Nearly entire bet lost due to overflow
        } else {
            average_session_value / 2 // Partial loss
        };

        EconomicOverflowReport {
            daily_sessions_affected,
            daily_value_lost,
            annual_value_lost,
            max_single_session_loss: max_overflow_loss,
            platform_risk_level: if overflow_probability > 0.1 {
                "Critical".to_string()
            } else {
                "High".to_string()
            },
        }
    }
}

#[derive(Debug)]
pub struct EconomicOverflowReport {
    pub daily_sessions_affected: u32,
    pub daily_value_lost: u64,
    pub annual_value_lost: u64,
    pub max_single_session_loss: u64,
    pub platform_risk_level: String,
}

#[cfg(test)]
mod economic_impact_tests {
    use super::*;

    #[test]
    fn test_economic_overflow_damage() {
        let damage_report = EconomicImpactAnalyzer::calculate_overflow_damage(
            50,     // 50 high-value sessions per day
            10_000_000_000_000, // 10 trillion tokens average per session
            0.05,   // 5% overflow probability
        );

        println!("💰 Economic Overflow Damage Analysis:");
        println!("   Daily sessions affected: {}", damage_report.daily_sessions_affected);
        println!("   Daily value lost: {} tokens", damage_report.daily_value_lost);
        println!("   Annual value lost: {} tokens", damage_report.annual_value_lost);
        println!("   Max single session loss: {} tokens", damage_report.max_single_session_loss);
        println!("   Platform risk level: {}", damage_report.platform_risk_level);

        // With 5% overflow rate on high-value sessions, should see significant losses
        assert!(damage_report.annual_value_lost > 1_000_000_000_000); // > 1 trillion annually
        assert_eq!(damage_report.platform_risk_level, "Critical");
    }
}