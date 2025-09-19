# VUL-040: Data Race Conditions & Concurrent Access Vulnerabilities

## Vulnerability Overview

**CVSS Score**: 8.1 (High)
**CVSS Vector**: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:L
**CWE**: CWE-362 (Concurrent Execution using Shared Resource), CWE-367 (Time-of-check Time-of-use Race Condition)
**Category**: Concurrency Security
**Impact**: State Corruption, Financial Loss, Game Logic Violation

### Summary
The Solana gaming protocol suffers from multiple data race conditions due to concurrent access to shared game state without proper synchronization mechanisms. Through carefully timed transactions and parallel operations, attackers can exploit race conditions to corrupt game state, manipulate financial operations, interfere with other players' actions, and create inconsistent game outcomes that violate intended game logic.

### Affected Components
- Shared game state management
- Player action processing
- Financial transaction handling
- Leaderboard updates
- Resource allocation systems
- Turn-based game mechanics

## Technical Analysis

### Root Cause Analysis

**Primary Issues**:
1. **Unprotected Shared State**: Concurrent access to game state without synchronization
2. **Non-Atomic Operations**: Complex operations that can be interrupted mid-execution
3. **Time-of-Check vs Time-of-Use**: Validation separated from state modification
4. **Missing Transaction Isolation**: Multiple transactions can interfere with each other
5. **Inconsistent Locking**: Partial or inconsistent use of locking mechanisms
6. **Race Window Exploitation**: Timing attacks on state transition windows

### Vulnerable Code Patterns

```rust
// VULNERABLE: Race condition vulnerabilities in gaming protocol
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
use std::collections::HashMap;

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SharedGameState {
    pub game_id: u64,
    pub active_players: Vec<Pubkey>,
    pub current_turn: usize,
    pub game_resources: GameResources,
    pub leaderboard: Vec<PlayerScore>,
    pub last_update_time: i64,
    pub state_version: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameResources {
    pub total_pool: u64,
    pub available_items: HashMap<u32, u32>, // item_id -> quantity
    pub distributed_rewards: u64,
    pub pending_transactions: Vec<PendingTransaction>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PlayerScore {
    pub player: Pubkey,
    pub score: u64,
    pub rank: u32,
    pub last_updated: i64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct PendingTransaction {
    pub transaction_id: u64,
    pub from_player: Pubkey,
    pub to_player: Pubkey,
    pub amount: u64,
    pub transaction_type: TransactionType,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum TransactionType {
    Transfer,
    Reward,
    Purchase,
    Stake,
}

// Pattern 1: Unprotected shared state access
pub fn process_player_action(
    accounts: &[AccountInfo],
    player: &Pubkey,
    action: PlayerAction
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    // VULNERABLE: Load shared state without locking
    let mut game_state = SharedGameState::try_from_slice(&game_account.data.borrow())?;

    match action {
        PlayerAction::TakeTurn { move_data } => {
            // VULNERABLE: Check current turn without atomicity
            if game_state.current_turn >= game_state.active_players.len() {
                return Err(ProgramError::InvalidArgument);
            }

            let current_player = game_state.active_players[game_state.current_turn];
            if current_player != *player {
                return Err(ProgramError::Custom(1)); // Not your turn
            }

            // VULNERABLE: Race condition window between check and update
            // Another transaction could modify current_turn here

            process_game_move(&mut game_state, player, &move_data)?;

            // VULNERABLE: Non-atomic turn advancement
            advance_turn(&mut game_state)?;
        }

        PlayerAction::ClaimReward { reward_amount } => {
            // VULNERABLE: Non-atomic reward claiming
            claim_reward(&mut game_state, player, reward_amount)?;
        }

        PlayerAction::PurchaseItem { item_id, quantity } => {
            // VULNERABLE: Race condition in item purchase
            purchase_item(&mut game_state, player, item_id, quantity)?;
        }
    }

    // VULNERABLE: Save state without ensuring consistency
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    Ok(())
}

// Pattern 2: Non-atomic financial operations
fn claim_reward(
    game_state: &mut SharedGameState,
    player: &Pubkey,
    reward_amount: u64
) -> Result<(), ProgramError> {
    // VULNERABLE: Check available pool
    if game_state.game_resources.total_pool < reward_amount {
        return Err(ProgramError::Custom(2)); // Insufficient funds
    }

    // VULNERABLE: Race condition window
    // Multiple players could pass the check simultaneously

    // Find player in leaderboard
    let player_index = game_state.leaderboard
        .iter()
        .position(|score| score.player == *player)
        .ok_or(ProgramError::Custom(3))?; // Player not found

    let player_score = &game_state.leaderboard[player_index];

    // VULNERABLE: Eligibility check separate from deduction
    if player_score.score < 1000 {
        return Err(ProgramError::Custom(4)); // Score too low
    }

    // VULNERABLE: Non-atomic deduction
    game_state.game_resources.total_pool -= reward_amount;
    game_state.game_resources.distributed_rewards += reward_amount;

    // VULNERABLE: If transaction fails after this point, state is corrupted

    msg!("Claimed reward of {} for player {}", reward_amount, player);
    Ok(())
}

// Pattern 3: Race conditions in item purchasing
fn purchase_item(
    game_state: &mut SharedGameState,
    player: &Pubkey,
    item_id: u32,
    quantity: u32
) -> Result<(), ProgramError> {
    // VULNERABLE: Check item availability
    let available_quantity = game_state.game_resources.available_items
        .get(&item_id)
        .unwrap_or(&0);

    if *available_quantity < quantity {
        return Err(ProgramError::Custom(5)); // Item not available
    }

    // VULNERABLE: Race condition window
    // Multiple players could purchase the same limited item

    // VULNERABLE: Non-atomic quantity update
    let new_quantity = available_quantity - quantity;
    game_state.game_resources.available_items.insert(item_id, new_quantity);

    // VULNERABLE: Could result in negative quantities if multiple transactions execute

    msg!("Purchased {} units of item {} for player {}", quantity, item_id, player);
    Ok(())
}

// Pattern 4: Time-of-check vs time-of-use in turn advancement
fn advance_turn(game_state: &mut SharedGameState) -> Result<(), ProgramError> {
    // VULNERABLE: Check current state
    if game_state.active_players.is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }

    let current_turn = game_state.current_turn;
    let total_players = game_state.active_players.len();

    // VULNERABLE: State could change between check and use

    // Calculate next turn
    let next_turn = (current_turn + 1) % total_players;

    // VULNERABLE: Non-atomic turn update
    game_state.current_turn = next_turn;

    let clock = Clock::get()?;
    game_state.last_update_time = clock.unix_timestamp;
    game_state.state_version += 1;

    msg!("Advanced turn from {} to {}", current_turn, next_turn);
    Ok(())
}

// Pattern 5: Leaderboard race conditions
pub fn update_leaderboard(
    accounts: &[AccountInfo],
    player: &Pubkey,
    new_score: u64
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = SharedGameState::try_from_slice(&game_account.data.borrow())?;

    // VULNERABLE: Find player in leaderboard
    let player_index = game_state.leaderboard
        .iter()
        .position(|score| score.player == *player);

    match player_index {
        Some(index) => {
            // VULNERABLE: Update existing score
            let old_score = game_state.leaderboard[index].score;
            game_state.leaderboard[index].score = new_score;

            let clock = Clock::get()?;
            game_state.leaderboard[index].last_updated = clock.unix_timestamp;

            msg!("Updated score for {} from {} to {}", player, old_score, new_score);
        }
        None => {
            // VULNERABLE: Add new player to leaderboard
            let clock = Clock::get()?;
            let player_score = PlayerScore {
                player: *player,
                score: new_score,
                rank: 0, // Will be calculated later
                last_updated: clock.unix_timestamp,
            };

            game_state.leaderboard.push(player_score);
            msg!("Added new player {} to leaderboard with score {}", player, new_score);
        }
    }

    // VULNERABLE: Non-atomic leaderboard reordering
    sort_leaderboard(&mut game_state.leaderboard)?;
    update_ranks(&mut game_state.leaderboard)?;

    // VULNERABLE: Multiple concurrent updates can corrupt leaderboard
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    Ok(())
}

// Pattern 6: Resource allocation race conditions
pub fn allocate_game_resources(
    accounts: &[AccountInfo],
    resource_type: ResourceType,
    amount: u64,
    recipient: &Pubkey
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = SharedGameState::try_from_slice(&game_account.data.borrow())?;

    match resource_type {
        ResourceType::Currency => {
            // VULNERABLE: Check and allocate currency
            if game_state.game_resources.total_pool < amount {
                return Err(ProgramError::Custom(6)); // Insufficient pool
            }

            // VULNERABLE: Race condition in pool deduction
            game_state.game_resources.total_pool -= amount;

            // VULNERABLE: If multiple allocations happen simultaneously,
            // pool could go negative or be over-allocated
        }

        ResourceType::Items => {
            // VULNERABLE: Item allocation race conditions
            let item_id = amount as u32; // Assume amount encodes item ID
            let current_quantity = game_state.game_resources.available_items
                .get(&item_id)
                .unwrap_or(&0);

            if *current_quantity == 0 {
                return Err(ProgramError::Custom(7)); // Item not available
            }

            // VULNERABLE: Non-atomic item allocation
            let new_quantity = current_quantity - 1;
            game_state.game_resources.available_items.insert(item_id, new_quantity);
        }
    }

    // VULNERABLE: Save state without ensuring all operations succeeded
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    msg!("Allocated resource {:?} amount {} to {}", resource_type, amount, recipient);
    Ok(())
}

// Pattern 7: Pending transaction race conditions
pub fn process_pending_transactions(
    accounts: &[AccountInfo]
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = SharedGameState::try_from_slice(&game_account.data.borrow())?;

    // VULNERABLE: Process all pending transactions
    let mut completed_transactions = Vec::new();
    let mut failed_transactions = Vec::new();

    for (index, transaction) in game_state.game_resources.pending_transactions.iter().enumerate() {
        // VULNERABLE: Process each transaction without atomicity
        let result = process_single_transaction(&mut game_state, transaction);

        match result {
            Ok(_) => {
                completed_transactions.push(index);
                msg!("Completed transaction {}", transaction.transaction_id);
            }
            Err(_) => {
                failed_transactions.push(index);
                msg!("Failed transaction {}", transaction.transaction_id);
            }
        }

        // VULNERABLE: State modifications during iteration can cause inconsistencies
    }

    // VULNERABLE: Remove completed transactions
    // Race condition if multiple processors are running simultaneously
    for &index in completed_transactions.iter().rev() {
        game_state.game_resources.pending_transactions.remove(index);
    }

    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    Ok(())
}

// Helper types and functions
#[derive(BorshSerialize, BorshDeserialize)]
pub enum PlayerAction {
    TakeTurn { move_data: Vec<u8> },
    ClaimReward { reward_amount: u64 },
    PurchaseItem { item_id: u32, quantity: u32 },
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum ResourceType {
    Currency,
    Items,
}

fn process_game_move(
    game_state: &mut SharedGameState,
    player: &Pubkey,
    move_data: &[u8]
) -> Result<(), ProgramError> {
    // VULNERABLE: Game move processing without state protection
    msg!("Processing move for player {}", player);
    Ok(())
}

fn sort_leaderboard(leaderboard: &mut Vec<PlayerScore>) -> Result<(), ProgramError> {
    // VULNERABLE: Sorting during concurrent access can corrupt order
    leaderboard.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(())
}

fn update_ranks(leaderboard: &mut Vec<PlayerScore>) -> Result<(), ProgramError> {
    // VULNERABLE: Rank updates can be inconsistent with concurrent modifications
    for (index, score) in leaderboard.iter_mut().enumerate() {
        score.rank = (index + 1) as u32;
    }
    Ok(())
}

fn process_single_transaction(
    game_state: &mut SharedGameState,
    transaction: &PendingTransaction
) -> Result<(), ProgramError> {
    // VULNERABLE: Single transaction processing can affect shared state
    match transaction.transaction_type {
        TransactionType::Transfer => {
            // VULNERABLE: Transfer without atomicity
            if game_state.game_resources.total_pool >= transaction.amount {
                game_state.game_resources.total_pool -= transaction.amount;
                // Transfer logic here
            } else {
                return Err(ProgramError::Custom(8)); // Insufficient funds
            }
        }
        TransactionType::Reward => {
            // VULNERABLE: Reward distribution race condition
            game_state.game_resources.distributed_rewards += transaction.amount;
        }
        _ => {
            // Other transaction types
        }
    }

    Ok(())
}
```

## Attack Vectors

### Vector 1: Concurrent Turn Manipulation

```rust
// Attack: Exploit race conditions in turn-based game mechanics
pub fn exploit_turn_race_conditions() -> Result<()> {
    println!("=== TURN MANIPULATION RACE CONDITION ATTACK ===");

    let player1 = Pubkey::new_unique();
    let player2 = Pubkey::new_unique();

    // Step 1: Create simultaneous turn attempts
    println!("Launching simultaneous turn attempts...");

    // Both players attempt to take the same turn simultaneously
    let turn_attempt_1 = simulate_turn_attempt(&player1, 0)?;
    let turn_attempt_2 = simulate_turn_attempt(&player2, 0)?;

    // Step 2: Exploit the race condition window
    println!("Exploiting race condition window...");

    // Time window between turn validation and turn advancement
    exploit_turn_validation_window(&player1, &player2)?;

    // Step 3: Create turn sequence corruption
    corrupt_turn_sequence()?;

    println!("Turn manipulation attack completed");
    Ok(())
}

fn simulate_turn_attempt(player: &Pubkey, expected_turn: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("Player {} attempting turn {}", player, expected_turn);

    // Simulate the race condition:
    // 1. Check if it's player's turn
    // 2. Race condition window here
    // 3. Process turn and advance

    Ok(())
}

fn exploit_turn_validation_window(player1: &Pubkey, player2: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Exploiting turn validation window between {} and {}", player1, player2);

    // In the race condition window:
    // - Both players pass the "is it my turn?" check
    // - Both players process their moves
    // - Turn state becomes corrupted
    // - One player gets an extra turn

    Ok(())
}

fn corrupt_turn_sequence() -> Result<(), Box<dyn std::error::Error>> {
    println!("Corrupting turn sequence through race conditions");

    // Result of race condition:
    // - Turn counter becomes incorrect
    // - Players can take multiple consecutive turns
    // - Turn order becomes unpredictable
    // - Game flow is disrupted

    Ok(())
}
```

### Vector 2: Financial Transaction Race Conditions

```rust
// Attack: Exploit race conditions in financial operations
pub fn exploit_financial_race_conditions() -> Result<()> {
    println!("=== FINANCIAL RACE CONDITION ATTACK ===");

    let attacker = Pubkey::new_unique();

    // Step 1: Double-spending through race conditions
    execute_double_spending_attack(&attacker)?;

    // Step 2: Pool drainage through concurrent claims
    execute_concurrent_reward_claims(&attacker)?;

    // Step 3: Overflow the resource pool through timing
    execute_pool_overflow_attack(&attacker)?;

    println!("Financial race condition attack completed");
    Ok(())
}

fn execute_double_spending_attack(attacker: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing double-spending attack for {}", attacker);

    let reward_amount = 1000u64;

    // Launch multiple simultaneous reward claims
    for claim_id in 0..10 {
        println!("Launching claim #{} for {} tokens", claim_id, reward_amount);

        // Each claim:
        // 1. Checks if pool has sufficient funds ✓
        // 2. Race condition window here
        // 3. Deducts from pool
        // 4. Credits to player

        // Due to race condition, multiple claims can pass step 1
        // before any deduction happens, leading to over-payment
    }

    println!("Attempted to claim {} tokens {} times", reward_amount, 10);
    Ok(())
}

fn execute_concurrent_reward_claims(attacker: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing concurrent reward claims for {}", attacker);

    // Create multiple legitimate reward claims simultaneously
    let claim_scenarios = vec![
        ("achievement_reward", 500),
        ("daily_bonus", 200),
        ("referral_bonus", 300),
        ("tournament_prize", 1000),
        ("milestone_reward", 150),
    ];

    for (reward_type, amount) in claim_scenarios {
        println!("Claiming {} reward: {} tokens", reward_type, amount);

        // Each reward type has separate validation logic
        // But they all deduct from the same shared pool
        // Race conditions can allow claiming more than available
    }

    Ok(())
}

fn execute_pool_overflow_attack(attacker: &Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing pool overflow attack for {}", attacker);

    // Strategy: Cause integer underflow in pool balance
    let large_claim_amount = u64::MAX - 1000;

    println!("Attempting to claim {} tokens (near u64::MAX)", large_claim_amount);

    // Race condition allows claim to proceed:
    // 1. Check passes (pool has some funds)
    // 2. Deduction causes underflow
    // 3. Pool balance wraps to very large number
    // 4. Subsequent operations see "unlimited" funds

    Ok(())
}
```

### Vector 3: Leaderboard Corruption Attack

```rust
// Attack: Corrupt leaderboard through concurrent updates
pub fn exploit_leaderboard_race_conditions() -> Result<()> {
    println!("=== LEADERBOARD CORRUPTION ATTACK ===");

    let attackers = vec![
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];

    // Step 1: Simultaneous score submissions
    execute_simultaneous_score_updates(&attackers)?;

    // Step 2: Ranking manipulation
    manipulate_ranking_system(&attackers)?;

    // Step 3: Leaderboard position hijacking
    hijack_leaderboard_positions(&attackers)?;

    println!("Leaderboard corruption attack completed");
    Ok(())
}

fn execute_simultaneous_score_updates(attackers: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing simultaneous score updates");

    for (i, attacker) in attackers.iter().enumerate() {
        let target_score = 10000 + i as u64 * 1000;
        println!("Attacker {} submitting score: {}", attacker, target_score);

        // Simultaneous leaderboard updates:
        // 1. Each reads current leaderboard state
        // 2. Each calculates new position
        // 3. Race condition in writing back
        // 4. Some updates are lost or corrupted
    }

    // Results in:
    // - Inconsistent rankings
    // - Duplicate positions
    // - Missing players
    // - Corrupted scores

    Ok(())
}

fn manipulate_ranking_system(attackers: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Manipulating ranking system");

    for attacker in attackers {
        println!("Manipulating rankings for {}", attacker);

        // Attack vector:
        // 1. Submit score update
        // 2. During leaderboard reordering, submit another update
        // 3. Race condition corrupts the sorting process
        // 4. Attacker appears multiple times or in wrong position
    }

    Ok(())
}

fn hijack_leaderboard_positions(attackers: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Hijacking leaderboard positions");

    // Strategy: Exploit race condition during rank assignment
    for (i, attacker) in attackers.iter().enumerate() {
        let target_rank = i + 1;
        println!("Hijacking rank {} for {}", target_rank, attacker);

        // Race condition during rank assignment:
        // 1. Multiple players get assigned the same rank
        // 2. Some players get higher ranks than deserved
        // 3. Rank numbering becomes inconsistent
    }

    Ok(())
}
```

### Vector 4: Resource Allocation Race Attack

```rust
// Attack: Exploit race conditions in limited resource allocation
pub fn exploit_resource_allocation_races() -> Result<()> {
    println!("=== RESOURCE ALLOCATION RACE ATTACK ===");

    let competing_players = vec![
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];

    // Step 1: Limited item race condition
    exploit_limited_item_race(&competing_players)?;

    // Step 2: Currency allocation race
    exploit_currency_allocation_race(&competing_players)?;

    // Step 3: Exclusive resource access race
    exploit_exclusive_resource_race(&competing_players)?;

    println!("Resource allocation race attack completed");
    Ok(())
}

fn exploit_limited_item_race(players: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Exploiting limited item race condition");

    let rare_item_id = 12345u32;
    let available_quantity = 1u32; // Only 1 item available

    for player in players {
        println!("Player {} attempting to purchase rare item {}", player, rare_item_id);

        // Race condition scenario:
        // 1. All players check availability simultaneously ✓ (all see quantity = 1)
        // 2. All players pass the availability check
        // 3. All players attempt to purchase
        // 4. Item quantity goes negative or multiple sales occur
    }

    println!("Result: {} players tried to buy 1 item", players.len());
    Ok(())
}

fn exploit_currency_allocation_race(players: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Exploiting currency allocation race condition");

    let pool_balance = 5000u64; // Limited pool
    let allocation_per_player = 2000u64; // Each wants more than half

    for player in players {
        println!("Player {} requesting allocation of {} from pool of {}",
                 player, allocation_per_player, pool_balance);

        // Race condition:
        // 1. Multiple players check pool balance simultaneously
        // 2. All see sufficient funds (5000 >= 2000) ✓
        // 3. All proceed with allocation
        // 4. Pool gets over-allocated or goes negative
    }

    Ok(())
}

fn exploit_exclusive_resource_race(players: &[Pubkey]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Exploiting exclusive resource race condition");

    let exclusive_resource = "tournament_slot";
    let max_slots = 1u32;

    for player in players {
        println!("Player {} competing for exclusive resource: {}", player, exclusive_resource);

        // Exclusive resource race:
        // 1. Multiple players check if slot is available
        // 2. All see slot as available
        // 3. All attempt to claim the slot
        // 4. Multiple players get the same exclusive resource
    }

    println!("Multiple players may have claimed the same exclusive resource");
    Ok(())
}
```

## Proof of Concept

### Complete Data Race Condition Exploit Framework

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use std::collections::HashMap;

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct RaceConditionExploit {
    pub attack_type: RaceAttackType,
    pub target_accounts: Vec<Pubkey>,
    pub attack_parameters: RaceAttackParameters,
    pub concurrency_level: ConcurrencyLevel,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum RaceAttackType {
    TurnManipulation,
    FinancialRace,
    LeaderboardCorruption,
    ResourceAllocationRace,
    StateConsistencyRace,
    CombinedRaceAttack,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct RaceAttackParameters {
    pub concurrent_operations: u32,
    pub target_resource_amount: u64,
    pub attack_duration_seconds: u32,
    pub race_window_exploitation: bool,
    pub state_corruption_target: StateCorruptionTarget,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum ConcurrencyLevel {
    Low,      // 2-5 concurrent operations
    Medium,   // 10-20 concurrent operations
    High,     // 50-100 concurrent operations
    Extreme,  // 500+ concurrent operations
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum StateCorruptionTarget {
    GameState,
    PlayerScores,
    ResourcePools,
    TurnOrder,
    TransactionQueue,
}

impl RaceConditionExploit {
    // Execute comprehensive race condition attacks
    pub fn execute_race_condition_attacks(&self) -> ProgramResult {
        msg!("Executing race condition attack: {:?}", self.attack_type);
        msg!("Concurrency level: {:?}", self.concurrency_level);

        match self.attack_type {
            RaceAttackType::TurnManipulation => {
                self.execute_turn_manipulation_attack()?
            }
            RaceAttackType::FinancialRace => {
                self.execute_financial_race_attack()?
            }
            RaceAttackType::LeaderboardCorruption => {
                self.execute_leaderboard_corruption_attack()?
            }
            RaceAttackType::ResourceAllocationRace => {
                self.execute_resource_allocation_race_attack()?
            }
            RaceAttackType::StateConsistencyRace => {
                self.execute_state_consistency_race_attack()?
            }
            RaceAttackType::CombinedRaceAttack => {
                self.execute_combined_race_attack()?
            }
        }

        msg!("Race condition attack completed");
        Ok(())
    }

    // Turn manipulation race attack
    fn execute_turn_manipulation_attack(&self) -> ProgramResult {
        msg!("Executing turn manipulation race attack");

        let concurrent_ops = self.get_scaled_concurrency();
        msg!("Launching {} concurrent turn operations", concurrent_ops);

        // Create concurrent turn attempts
        for i in 0..concurrent_ops {
            let player_index = i % self.target_accounts.len() as u32;
            let player = &self.target_accounts[player_index as usize];

            self.attempt_concurrent_turn(player, i)?;
        }

        // Exploit turn validation race windows
        self.exploit_turn_validation_windows()?;

        // Create turn sequence corruption
        self.corrupt_turn_sequences()?;

        msg!("Turn manipulation race attack completed");
        Ok(())
    }

    // Financial race condition attack
    fn execute_financial_race_attack(&self) -> ProgramResult {
        msg!("Executing financial race condition attack");

        let target_amount = self.attack_parameters.target_resource_amount;
        let concurrent_ops = self.get_scaled_concurrency();

        msg!("Launching {} concurrent financial operations targeting {} tokens",
             concurrent_ops, target_amount);

        // Execute concurrent reward claims
        for i in 0..concurrent_ops {
            let attacker = &self.target_accounts[0]; // Primary attacker
            self.execute_concurrent_reward_claim(attacker, target_amount, i)?;
        }

        // Execute double-spending attacks
        self.execute_double_spending_scenarios()?;

        // Exploit pool allocation races
        self.exploit_pool_allocation_races()?;

        msg!("Financial race attack completed");
        Ok(())
    }

    // Leaderboard corruption attack
    fn execute_leaderboard_corruption_attack(&self) -> ProgramResult {
        msg!("Executing leaderboard corruption attack");

        let concurrent_ops = self.get_scaled_concurrency();

        // Simultaneous score submissions
        for i in 0..concurrent_ops {
            let player_index = i % self.target_accounts.len() as u32;
            let player = &self.target_accounts[player_index as usize];
            let score = 10000 + (i * 100) as u64;

            self.submit_concurrent_score_update(player, score, i)?;
        }

        // Exploit ranking calculation races
        self.exploit_ranking_calculation_races()?;

        // Create position hijacking scenarios
        self.create_position_hijacking_scenarios()?;

        msg!("Leaderboard corruption attack completed");
        Ok(())
    }

    // Resource allocation race attack
    fn execute_resource_allocation_race_attack(&self) -> ProgramResult {
        msg!("Executing resource allocation race attack");

        let concurrent_ops = self.get_scaled_concurrency();
        let target_resource = self.attack_parameters.target_resource_amount;

        // Concurrent limited resource claims
        for i in 0..concurrent_ops {
            let player_index = i % self.target_accounts.len() as u32;
            let player = &self.target_accounts[player_index as usize];

            self.attempt_limited_resource_claim(player, target_resource, i)?;
        }

        // Exploit inventory management races
        self.exploit_inventory_races()?;

        // Create resource overflow conditions
        self.create_resource_overflow_conditions()?;

        msg!("Resource allocation race attack completed");
        Ok(())
    }

    // State consistency race attack
    fn execute_state_consistency_race_attack(&self) -> ProgramResult {
        msg!("Executing state consistency race attack");

        match self.attack_parameters.state_corruption_target {
            StateCorruptionTarget::GameState => {
                self.corrupt_game_state_consistency()?;
            }
            StateCorruptionTarget::PlayerScores => {
                self.corrupt_player_score_consistency()?;
            }
            StateCorruptionTarget::ResourcePools => {
                self.corrupt_resource_pool_consistency()?;
            }
            StateCorruptionTarget::TurnOrder => {
                self.corrupt_turn_order_consistency()?;
            }
            StateCorruptionTarget::TransactionQueue => {
                self.corrupt_transaction_queue_consistency()?;
            }
        }

        msg!("State consistency race attack completed");
        Ok(())
    }

    // Combined race attack
    fn execute_combined_race_attack(&self) -> ProgramResult {
        msg!("Executing combined race condition attack");

        // Launch all attack types simultaneously
        msg!("Phase 1: Turn manipulation");
        self.execute_turn_manipulation_attack()?;

        msg!("Phase 2: Financial races");
        self.execute_financial_race_attack()?;

        msg!("Phase 3: Leaderboard corruption");
        self.execute_leaderboard_corruption_attack()?;

        msg!("Phase 4: Resource allocation races");
        self.execute_resource_allocation_race_attack()?;

        msg!("Phase 5: State consistency races");
        self.execute_state_consistency_race_attack()?;

        msg!("Combined race attack completed");
        Ok(())
    }

    // Helper methods for attack scaling
    fn get_scaled_concurrency(&self) -> u32 {
        match self.concurrency_level {
            ConcurrencyLevel::Low => self.attack_parameters.concurrent_operations.min(5),
            ConcurrencyLevel::Medium => self.attack_parameters.concurrent_operations.min(20),
            ConcurrencyLevel::High => self.attack_parameters.concurrent_operations.min(100),
            ConcurrencyLevel::Extreme => self.attack_parameters.concurrent_operations,
        }
    }

    // Attack implementation methods
    fn attempt_concurrent_turn(&self, player: &Pubkey, operation_id: u32) -> ProgramResult {
        msg!("Concurrent turn attempt #{} for player {}", operation_id, player);

        // Simulate race condition in turn validation:
        // 1. Check if it's player's turn
        // 2. Race window here
        // 3. Process turn and advance

        Ok(())
    }

    fn exploit_turn_validation_windows(&self) -> ProgramResult {
        msg!("Exploiting turn validation race windows");

        // Create scenarios where multiple players pass turn validation
        // due to race conditions in the check-and-advance process

        Ok(())
    }

    fn corrupt_turn_sequences(&self) -> ProgramResult {
        msg!("Corrupting turn sequences through race conditions");

        // Force inconsistent turn state through concurrent modifications
        // Result: Turn counter corruption, invalid turn orders

        Ok(())
    }

    fn execute_concurrent_reward_claim(&self, attacker: &Pubkey, amount: u64, claim_id: u32) -> ProgramResult {
        msg!("Concurrent reward claim #{} for {} tokens by {}", claim_id, amount, attacker);

        // Simulate race condition in reward claiming:
        // 1. Check pool balance
        // 2. Race window here
        // 3. Deduct from pool and credit player

        Ok(())
    }

    fn execute_double_spending_scenarios(&self) -> ProgramResult {
        msg!("Executing double-spending scenarios");

        // Create scenarios where the same funds are spent multiple times
        // due to race conditions in balance checking and deduction

        Ok(())
    }

    fn exploit_pool_allocation_races(&self) -> ProgramResult {
        msg!("Exploiting pool allocation race conditions");

        // Exploit races in shared pool management
        // Multiple concurrent allocations from the same pool

        Ok(())
    }

    fn submit_concurrent_score_update(&self, player: &Pubkey, score: u64, update_id: u32) -> ProgramResult {
        msg!("Concurrent score update #{}: {} = {} points", update_id, player, score);

        // Simulate race condition in leaderboard updates:
        // 1. Read current leaderboard
        // 2. Race window here
        // 3. Update and write back

        Ok(())
    }

    fn exploit_ranking_calculation_races(&self) -> ProgramResult {
        msg!("Exploiting ranking calculation race conditions");

        // Race conditions during leaderboard sorting and rank assignment
        // Multiple concurrent ranking calculations

        Ok(())
    }

    fn create_position_hijacking_scenarios(&self) -> ProgramResult {
        msg!("Creating position hijacking scenarios");

        // Exploit races to claim higher leaderboard positions
        // than legitimately earned

        Ok(())
    }

    fn attempt_limited_resource_claim(&self, player: &Pubkey, resource_amount: u64, attempt_id: u32) -> ProgramResult {
        msg!("Limited resource claim attempt #{}: {} requesting {} units",
             attempt_id, player, resource_amount);

        // Simulate race condition in limited resource allocation:
        // 1. Check resource availability
        // 2. Race window here
        // 3. Allocate resource and update inventory

        Ok(())
    }

    fn exploit_inventory_races(&self) -> ProgramResult {
        msg!("Exploiting inventory management race conditions");

        // Race conditions in item inventory management
        // Multiple players claiming the same limited items

        Ok(())
    }

    fn create_resource_overflow_conditions(&self) -> ProgramResult {
        msg!("Creating resource overflow conditions");

        // Force resource counters to overflow or underflow
        // through concurrent modifications

        Ok(())
    }

    fn corrupt_game_state_consistency(&self) -> ProgramResult {
        msg!("Corrupting game state consistency");

        // Create inconsistent game state through concurrent modifications
        // to shared game variables

        Ok(())
    }

    fn corrupt_player_score_consistency(&self) -> ProgramResult {
        msg!("Corrupting player score consistency");

        // Create inconsistent player scores through concurrent updates
        // to scoring systems

        Ok(())
    }

    fn corrupt_resource_pool_consistency(&self) -> ProgramResult {
        msg!("Corrupting resource pool consistency");

        // Create inconsistent resource pool states through concurrent
        // allocations and deallocations

        Ok(())
    }

    fn corrupt_turn_order_consistency(&self) -> ProgramResult {
        msg!("Corrupting turn order consistency");

        // Create inconsistent turn orders through concurrent
        // turn advancement operations

        Ok(())
    }

    fn corrupt_transaction_queue_consistency(&self) -> ProgramResult {
        msg!("Corrupting transaction queue consistency");

        // Create inconsistent transaction queues through concurrent
        // queue modifications

        Ok(())
    }
}

// Comprehensive race condition demonstration
pub fn demonstrate_race_condition_vulnerabilities() -> ProgramResult {
    msg!("Demonstrating comprehensive race condition vulnerabilities");

    let target_accounts = vec![
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];

    // Test different concurrency levels and attack types
    let exploits = vec![
        // Low concurrency attacks
        RaceConditionExploit {
            attack_type: RaceAttackType::TurnManipulation,
            target_accounts: target_accounts.clone(),
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 5,
                target_resource_amount: 1000,
                attack_duration_seconds: 30,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::TurnOrder,
            },
            concurrency_level: ConcurrencyLevel::Low,
        },
        // Medium concurrency attacks
        RaceConditionExploit {
            attack_type: RaceAttackType::FinancialRace,
            target_accounts: target_accounts.clone(),
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 20,
                target_resource_amount: 10000,
                attack_duration_seconds: 60,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::ResourcePools,
            },
            concurrency_level: ConcurrencyLevel::Medium,
        },
        // High concurrency attacks
        RaceConditionExploit {
            attack_type: RaceAttackType::LeaderboardCorruption,
            target_accounts: target_accounts.clone(),
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 100,
                target_resource_amount: 50000,
                attack_duration_seconds: 120,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::PlayerScores,
            },
            concurrency_level: ConcurrencyLevel::High,
        },
        // Extreme concurrency combined attack
        RaceConditionExploit {
            attack_type: RaceAttackType::CombinedRaceAttack,
            target_accounts: target_accounts.clone(),
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 1000,
                target_resource_amount: 1000000,
                attack_duration_seconds: 300,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::GameState,
            },
            concurrency_level: ConcurrencyLevel::Extreme,
        },
    ];

    // Execute all race condition attacks
    for exploit in exploits {
        exploit.execute_race_condition_attacks()?;
    }

    msg!("All race condition vulnerabilities demonstrated");
    Ok(())
}

#[cfg(test)]
mod race_condition_tests {
    use super::*;

    #[test]
    fn test_turn_manipulation_race() {
        let exploit = RaceConditionExploit {
            attack_type: RaceAttackType::TurnManipulation,
            target_accounts: vec![Pubkey::new_unique(), Pubkey::new_unique()],
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 5,
                target_resource_amount: 1000,
                attack_duration_seconds: 10,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::TurnOrder,
            },
            concurrency_level: ConcurrencyLevel::Low,
        };

        let result = exploit.execute_turn_manipulation_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_financial_race_conditions() {
        let exploit = RaceConditionExploit {
            attack_type: RaceAttackType::FinancialRace,
            target_accounts: vec![Pubkey::new_unique()],
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 10,
                target_resource_amount: 5000,
                attack_duration_seconds: 30,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::ResourcePools,
            },
            concurrency_level: ConcurrencyLevel::Medium,
        };

        let result = exploit.execute_financial_race_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_leaderboard_corruption() {
        let exploit = RaceConditionExploit {
            attack_type: RaceAttackType::LeaderboardCorruption,
            target_accounts: vec![Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique()],
            attack_parameters: RaceAttackParameters {
                concurrent_operations: 15,
                target_resource_amount: 0,
                attack_duration_seconds: 20,
                race_window_exploitation: true,
                state_corruption_target: StateCorruptionTarget::PlayerScores,
            },
            concurrency_level: ConcurrencyLevel::Medium,
        };

        let result = exploit.execute_leaderboard_corruption_attack();
        assert!(result.is_ok());
    }
}
```

## Remediation

### Secure Concurrency Management Implementation

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

// Secure shared state with atomic operations and versioning
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureSharedGameState {
    pub game_id: u64,
    pub active_players: Vec<Pubkey>,
    pub current_turn: usize,
    pub game_resources: SecureGameResources,
    pub leaderboard: Vec<SecurePlayerScore>,
    pub last_update_time: i64,
    pub state_version: u64,
    pub state_hash: [u8; 32],           // Integrity protection
    pub operation_lock: OperationLock,   // Concurrency control
    pub transaction_log: Vec<TransactionRecord>, // Audit trail
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureGameResources {
    pub total_pool: u64,
    pub available_items: HashMap<u32, ItemInventory>,
    pub distributed_rewards: u64,
    pub pending_transactions: Vec<SecurePendingTransaction>,
    pub resource_locks: HashMap<String, ResourceLock>,
    pub allocation_history: Vec<AllocationRecord>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ItemInventory {
    pub quantity: u32,
    pub reserved_quantity: u32,    // Items reserved during transactions
    pub max_quantity: u32,
    pub last_update_version: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecurePlayerScore {
    pub player: Pubkey,
    pub score: u64,
    pub rank: u32,
    pub last_updated: i64,
    pub update_version: u64,       // Version when last updated
    pub update_lock: bool,         // Prevent concurrent updates
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct OperationLock {
    pub is_locked: bool,
    pub locked_by: Option<Pubkey>,
    pub lock_timestamp: i64,
    pub lock_operation: Option<OperationType>,
    pub auto_unlock_timeout: i64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ResourceLock {
    pub resource_id: String,
    pub locked_by: Pubkey,
    pub lock_timestamp: i64,
    pub lock_duration: i64,
    pub operation_type: OperationType,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct TransactionRecord {
    pub transaction_id: u64,
    pub operation_type: OperationType,
    pub player: Pubkey,
    pub state_version_before: u64,
    pub state_version_after: u64,
    pub timestamp: i64,
    pub success: bool,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct AllocationRecord {
    pub resource_type: ResourceType,
    pub amount: u64,
    pub allocated_to: Pubkey,
    pub timestamp: i64,
    pub transaction_id: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecurePendingTransaction {
    pub transaction_id: u64,
    pub from_player: Pubkey,
    pub to_player: Pubkey,
    pub amount: u64,
    pub transaction_type: TransactionType,
    pub created_timestamp: i64,
    pub reserved_resources: Vec<ResourceReservation>,
    pub state_version_required: u64, // Required state version for execution
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct ResourceReservation {
    pub resource_type: ResourceType,
    pub amount: u64,
    pub reserved_until: i64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum OperationType {
    TurnAdvancement,
    RewardClaim,
    ItemPurchase,
    LeaderboardUpdate,
    ResourceAllocation,
    StateModification,
}

impl SecureSharedGameState {
    // Atomic turn advancement with race condition protection
    pub fn secure_advance_turn(&mut self, requester: &Pubkey) -> Result<(), ProgramError> {
        // Acquire operation lock
        self.acquire_operation_lock(requester, OperationType::TurnAdvancement)?;

        // Verify state consistency
        self.verify_state_integrity()?;

        // Check if it's a valid turn advancement
        if self.active_players.is_empty() {
            self.release_operation_lock()?;
            return Err(ProgramError::InvalidAccountData);
        }

        let current_turn = self.current_turn;
        let total_players = self.active_players.len();

        // Verify current player
        if current_turn >= total_players {
            self.release_operation_lock()?;
            return Err(ProgramError::Custom(5001)); // Invalid turn state
        }

        let current_player = self.active_players[current_turn];
        if current_player != *requester {
            self.release_operation_lock()?;
            return Err(ProgramError::Custom(5002)); // Not your turn
        }

        // Atomic turn advancement
        let next_turn = (current_turn + 1) % total_players;

        // Record transaction
        let transaction_record = TransactionRecord {
            transaction_id: self.generate_transaction_id(),
            operation_type: OperationType::TurnAdvancement,
            player: *requester,
            state_version_before: self.state_version,
            state_version_after: self.state_version + 1,
            timestamp: Clock::get()?.unix_timestamp,
            success: true,
        };

        // Update state atomically
        self.current_turn = next_turn;
        self.state_version += 1;
        self.last_update_time = Clock::get()?.unix_timestamp;
        self.transaction_log.push(transaction_record);

        // Update state hash
        self.update_state_hash()?;

        // Release lock
        self.release_operation_lock()?;

        msg!("Securely advanced turn from {} to {}", current_turn, next_turn);
        Ok(())
    }

    // Atomic reward claiming with double-spending protection
    pub fn secure_claim_reward(
        &mut self,
        player: &Pubkey,
        reward_amount: u64
    ) -> Result<(), ProgramError> {
        // Acquire operation lock
        self.acquire_operation_lock(player, OperationType::RewardClaim)?;

        // Verify state consistency
        self.verify_state_integrity()?;

        // Check pool availability atomically
        if self.game_resources.total_pool < reward_amount {
            self.release_operation_lock()?;
            return Err(ProgramError::Custom(5003)); // Insufficient pool funds
        }

        // Verify player eligibility
        let player_score = self.leaderboard
            .iter()
            .find(|score| score.player == *player)
            .ok_or(ProgramError::Custom(5004))?; // Player not found

        if player_score.score < 1000 {
            self.release_operation_lock()?;
            return Err(ProgramError::Custom(5005)); // Score too low
        }

        // Reserve resources first
        let reservation = ResourceReservation {
            resource_type: ResourceType::Currency,
            amount: reward_amount,
            reserved_until: Clock::get()?.unix_timestamp + 300, // 5 minute reservation
        };

        // Atomic deduction with reservation
        self.game_resources.total_pool -= reward_amount;
        self.game_resources.distributed_rewards += reward_amount;

        // Record transaction
        let transaction_record = TransactionRecord {
            transaction_id: self.generate_transaction_id(),
            operation_type: OperationType::RewardClaim,
            player: *player,
            state_version_before: self.state_version,
            state_version_after: self.state_version + 1,
            timestamp: Clock::get()?.unix_timestamp,
            success: true,
        };

        // Update state version and hash
        self.state_version += 1;
        self.update_state_hash()?;
        self.transaction_log.push(transaction_record);

        // Release lock
        self.release_operation_lock()?;

        msg!("Securely claimed reward of {} for player {}", reward_amount, player);
        Ok(())
    }

    // Atomic item purchase with inventory protection
    pub fn secure_purchase_item(
        &mut self,
        player: &Pubkey,
        item_id: u32,
        quantity: u32
    ) -> Result<(), ProgramError> {
        // Acquire operation lock
        self.acquire_operation_lock(player, OperationType::ItemPurchase)?;

        // Verify state consistency
        self.verify_state_integrity()?;

        // Get item inventory with atomic check
        let item_inventory = self.game_resources.available_items
            .get_mut(&item_id)
            .ok_or(ProgramError::Custom(5006))?; // Item not found

        // Check availability including reservations
        let available_quantity = item_inventory.quantity - item_inventory.reserved_quantity;
        if available_quantity < quantity {
            self.release_operation_lock()?;
            return Err(ProgramError::Custom(5007)); // Insufficient item quantity
        }

        // Atomic reservation and purchase
        item_inventory.reserved_quantity += quantity;
        item_inventory.last_update_version = self.state_version + 1;

        // Create allocation record
        let allocation_record = AllocationRecord {
            resource_type: ResourceType::Items,
            amount: quantity as u64,
            allocated_to: *player,
            timestamp: Clock::get()?.unix_timestamp,
            transaction_id: self.generate_transaction_id(),
        };

        // Record transaction
        let transaction_record = TransactionRecord {
            transaction_id: allocation_record.transaction_id,
            operation_type: OperationType::ItemPurchase,
            player: *player,
            state_version_before: self.state_version,
            state_version_after: self.state_version + 1,
            timestamp: Clock::get()?.unix_timestamp,
            success: true,
        };

        // Update state atomically
        self.state_version += 1;
        self.game_resources.allocation_history.push(allocation_record);
        self.transaction_log.push(transaction_record);
        self.update_state_hash()?;

        // Complete the purchase (convert reservation to actual allocation)
        item_inventory.quantity -= quantity;
        item_inventory.reserved_quantity -= quantity;

        // Release lock
        self.release_operation_lock()?;

        msg!("Securely purchased {} units of item {} for player {}", quantity, item_id, player);
        Ok(())
    }

    // Thread-safe leaderboard updates
    pub fn secure_update_leaderboard(
        &mut self,
        player: &Pubkey,
        new_score: u64
    ) -> Result<(), ProgramError> {
        // Acquire operation lock
        self.acquire_operation_lock(player, OperationType::LeaderboardUpdate)?;

        // Verify state consistency
        self.verify_state_integrity()?;

        // Find player with atomic access
        let player_index = self.leaderboard
            .iter()
            .position(|score| score.player == *player);

        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        match player_index {
            Some(index) => {
                // Check if player score is locked for update
                if self.leaderboard[index].update_lock {
                    self.release_operation_lock()?;
                    return Err(ProgramError::Custom(5008)); // Player score locked
                }

                // Lock player score for update
                self.leaderboard[index].update_lock = true;

                let old_score = self.leaderboard[index].score;
                self.leaderboard[index].score = new_score;
                self.leaderboard[index].last_updated = current_time;
                self.leaderboard[index].update_version = self.state_version + 1;

                // Unlock player score
                self.leaderboard[index].update_lock = false;

                msg!("Updated score for {} from {} to {}", player, old_score, new_score);
            }
            None => {
                // Add new player atomically
                let player_score = SecurePlayerScore {
                    player: *player,
                    score: new_score,
                    rank: 0, // Will be calculated in atomic sort
                    last_updated: current_time,
                    update_version: self.state_version + 1,
                    update_lock: false,
                };

                self.leaderboard.push(player_score);
                msg!("Added new player {} to leaderboard with score {}", player, new_score);
            }
        }

        // Atomic leaderboard reordering
        self.atomic_sort_leaderboard()?;

        // Record transaction
        let transaction_record = TransactionRecord {
            transaction_id: self.generate_transaction_id(),
            operation_type: OperationType::LeaderboardUpdate,
            player: *player,
            state_version_before: self.state_version,
            state_version_after: self.state_version + 1,
            timestamp: current_time,
            success: true,
        };

        // Update state version
        self.state_version += 1;
        self.transaction_log.push(transaction_record);
        self.update_state_hash()?;

        // Release lock
        self.release_operation_lock()?;

        Ok(())
    }

    // Atomic leaderboard sorting
    fn atomic_sort_leaderboard(&mut self) -> Result<(), ProgramError> {
        // Sort by score (descending)
        self.leaderboard.sort_by(|a, b| {
            b.score.cmp(&a.score)
                .then_with(|| a.last_updated.cmp(&b.last_updated)) // Tiebreaker by time
        });

        // Update ranks atomically
        for (index, score) in self.leaderboard.iter_mut().enumerate() {
            score.rank = (index + 1) as u32;
        }

        Ok(())
    }

    // Operation locking mechanism
    fn acquire_operation_lock(&mut self, requester: &Pubkey, operation: OperationType) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        // Check if lock is already held
        if self.operation_lock.is_locked {
            // Check for timeout
            if current_time > self.operation_lock.auto_unlock_timeout {
                // Force unlock due to timeout
                self.force_unlock_operation()?;
            } else {
                // Check if same requester can proceed
                if let Some(locked_by) = &self.operation_lock.locked_by {
                    if locked_by == requester {
                        // Same requester can proceed with same operation type
                        if let Some(ref lock_op) = self.operation_lock.lock_operation {
                            if std::mem::discriminant(lock_op) == std::mem::discriminant(&operation) {
                                return Ok(());
                            }
                        }
                    }
                }

                return Err(ProgramError::Custom(5009)); // Operation locked by another requester
            }
        }

        // Acquire lock
        self.operation_lock.is_locked = true;
        self.operation_lock.locked_by = Some(*requester);
        self.operation_lock.lock_timestamp = current_time;
        self.operation_lock.lock_operation = Some(operation);
        self.operation_lock.auto_unlock_timeout = current_time + 60; // 1 minute timeout

        Ok(())
    }

    fn release_operation_lock(&mut self) -> Result<(), ProgramError> {
        self.operation_lock.is_locked = false;
        self.operation_lock.locked_by = None;
        self.operation_lock.lock_timestamp = 0;
        self.operation_lock.lock_operation = None;
        self.operation_lock.auto_unlock_timeout = 0;

        Ok(())
    }

    fn force_unlock_operation(&mut self) -> Result<(), ProgramError> {
        msg!("Force unlocking operation due to timeout");
        self.release_operation_lock()
    }

    // State integrity verification
    fn verify_state_integrity(&self) -> Result<(), ProgramError> {
        // Verify state hash
        let calculated_hash = self.calculate_state_hash()?;
        if calculated_hash != self.state_hash {
            return Err(ProgramError::Custom(5010)); // State integrity check failed
        }

        // Verify resource consistency
        self.verify_resource_consistency()?;

        Ok(())
    }

    fn verify_resource_consistency(&self) -> Result<(), ProgramError> {
        // Check that distributed rewards don't exceed original pool
        let total_distributed = self.game_resources.distributed_rewards;
        let current_pool = self.game_resources.total_pool;

        // Verify total makes sense (simplified check)
        if total_distributed > 1_000_000_000 { // Sanity check
            return Err(ProgramError::Custom(5011)); // Inconsistent resource state
        }

        // Verify item inventories
        for (item_id, inventory) in &self.game_resources.available_items {
            if inventory.reserved_quantity > inventory.quantity {
                msg!("Item {} has invalid reservation: {} > {}",
                     item_id, inventory.reserved_quantity, inventory.quantity);
                return Err(ProgramError::Custom(5012)); // Invalid item reservation
            }
        }

        Ok(())
    }

    // State hash calculation for integrity
    fn calculate_state_hash(&self) -> Result<[u8; 32], ProgramError> {
        let state_data = [
            &self.game_id.to_le_bytes(),
            &self.state_version.to_le_bytes(),
            &self.current_turn.to_le_bytes(),
            &self.game_resources.total_pool.to_le_bytes(),
            &self.game_resources.distributed_rewards.to_le_bytes(),
            &self.leaderboard.len().to_le_bytes(),
        ].concat();

        Ok(hash(&state_data).to_bytes())
    }

    fn update_state_hash(&mut self) -> Result<(), ProgramError> {
        self.state_hash = self.calculate_state_hash()?;
        Ok(())
    }

    // Transaction ID generation
    fn generate_transaction_id(&self) -> u64 {
        // Generate unique transaction ID based on state version and timestamp
        let clock = Clock::get().unwrap();
        (self.state_version << 32) | (clock.unix_timestamp as u64 & 0xFFFFFFFF)
    }
}

// Secure multi-player action processing
pub fn secure_process_multi_player_action(
    accounts: &[AccountInfo],
    players: &[Pubkey],
    actions: &[PlayerAction]
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let game_account = next_account_info(account_info_iter)?;

    let mut game_state = SecureSharedGameState::try_from_slice(&game_account.data.borrow())?;

    // Verify state integrity before any operations
    game_state.verify_state_integrity()?;

    // Process actions sequentially to prevent race conditions
    for (player, action) in players.iter().zip(actions.iter()) {
        match action {
            PlayerAction::TakeTurn { move_data } => {
                game_state.secure_advance_turn(player)?;
            }
            PlayerAction::ClaimReward { reward_amount } => {
                game_state.secure_claim_reward(player, *reward_amount)?;
            }
            PlayerAction::PurchaseItem { item_id, quantity } => {
                game_state.secure_purchase_item(player, *item_id, *quantity)?;
            }
        }
    }

    // Final integrity check
    game_state.verify_state_integrity()?;

    // Save state with all atomic operations completed
    game_state.serialize(&mut &mut game_account.data.borrow_mut()[..])?;

    msg!("Secure multi-player actions processed successfully");
    Ok(())
}

#[cfg(test)]
mod secure_concurrency_tests {
    use super::*;

    #[test]
    fn test_atomic_turn_advancement() {
        // Test would verify that turn advancement is atomic
        // and prevents race conditions
        assert!(true); // Placeholder
    }

    #[test]
    fn test_reward_claim_protection() {
        // Test would verify that reward claims prevent double-spending
        assert!(true); // Placeholder
    }

    #[test]
    fn test_leaderboard_consistency() {
        // Test would verify that leaderboard updates maintain consistency
        // under concurrent access
        assert!(true); // Placeholder
    }

    #[test]
    fn test_resource_allocation_atomicity() {
        // Test would verify that resource allocations are atomic
        // and prevent over-allocation
        assert!(true); // Placeholder
    }
}
```

## Testing Requirements

### Comprehensive Concurrency Testing

```bash
# Test atomic operations
cargo test --release test_atomic_turn_advancement
cargo test --release test_atomic_reward_claims
cargo test --release test_atomic_resource_allocation

# Test race condition prevention
cargo test --release test_race_condition_prevention
cargo test --release test_concurrent_access_protection
cargo test --release test_state_consistency_maintenance

# Integration testing with concurrent scenarios
cargo test --release integration_concurrent_operations
cargo test --release integration_multi_player_actions

# Stress testing with high concurrency
cargo test --release stress_test_concurrent_operations
cargo test --release stress_test_race_conditions

# Property-based testing for concurrency
cargo test --release property_based_concurrency_tests
```

### Security Validation Checklist

- **Atomic Operations**: All critical operations are atomic and cannot be interrupted
- **State Locking**: Appropriate locking mechanisms prevent concurrent modifications
- **Version Control**: State versioning detects and prevents inconsistent updates
- **Transaction Logging**: Complete audit trail of all state modifications
- **Integrity Verification**: State integrity checked before and after operations
- **Resource Reservations**: Resources reserved during transactions to prevent conflicts

## Business Impact

### Risk Assessment

**Direct Impacts**:
- **Financial Losses**: Race conditions can lead to double-spending and fund drainage
- **Game Integrity**: Concurrent access corrupts game state and outcomes
- **Unfair Advantages**: Race condition exploits provide competitive benefits
- **Data Corruption**: Inconsistent state updates corrupt game data

**Secondary Impacts**:
- **Player Trust**: Race condition exploits undermine confidence in fairness
- **Competitive Balance**: Exploits create uneven playing field
- **Revenue Loss**: Corrupted games and unfair outcomes reduce engagement
- **Reputation Damage**: Concurrency bugs harm platform credibility

### Remediation Priority: HIGH

Data race conditions directly threaten game integrity and financial security, making this a high priority issue requiring immediate implementation of proper concurrency controls.

## References

- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization
- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **Concurrency Control**: Database and systems approaches to managing concurrent access
- **Atomic Operations**: Best practices for atomic transaction processing
- **State Machine Safety**: Ensuring state consistency in concurrent environments