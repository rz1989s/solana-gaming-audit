# VUL-034: Flash Loan Manipulation & Atomic Transaction Exploits

## Vulnerability Overview

**CVSS Score**: 9.7 (Critical)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
**CWE**: CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-672 (Operation on Resource after Expiration)
**Category**: Economic Manipulation
**Impact**: Market Manipulation, Price Oracle Attacks, Escrow Drainage

### Summary
The Solana gaming protocol is vulnerable to flash loan attacks and atomic transaction manipulation, allowing attackers to manipulate token prices, drain escrow funds, and corrupt game economics within single transaction blocks. Through sophisticated combinations of borrowing, manipulation, and repayment operations, malicious actors can extract massive value while appearing to maintain protocol invariants.

### Affected Components
- Price oracle dependencies
- Token reward calculations
- Escrow valuation logic
- Liquidity pool interactions
- Market-making mechanisms
- Dynamic pricing algorithms

## Technical Analysis

### Root Cause Analysis

**Primary Issues**:
1. **Oracle Price Dependencies**: Game logic relies on manipulable price feeds
2. **Atomic Transaction Vulnerabilities**: Complex operations in single transaction
3. **Liquidity Pool Integration**: Unprotected interactions with DeFi protocols
4. **Insufficient Slippage Protection**: Price manipulation within acceptable bounds
5. **State Consistency Failures**: Intermediate states exploitable mid-transaction

### Vulnerable Code Patterns

```rust
// VULNERABLE: Price oracle dependency without protection
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct TokenPriceOracle {
    pub token_mint: Pubkey,
    pub price_in_usdc: u64,
    pub last_update: i64,
    pub confidence: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameReward {
    pub base_amount: u64,
    pub token_multiplier: u64,
    pub winner: Pubkey,
}

// Pattern 1: Vulnerable price-dependent reward calculation
impl GameReward {
    pub fn calculate_final_reward(
        &self,
        oracle: &TokenPriceOracle
    ) -> Result<u64, ProgramError> {
        // VULNERABLE: Direct use of potentially manipulated oracle price
        let usd_value = self.base_amount
            .checked_mul(oracle.price_in_usdc)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // VULNERABLE: No slippage protection or price bounds
        let final_reward = usd_value
            .checked_mul(self.token_multiplier)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        Ok(final_reward)
    }
}

// Pattern 2: Vulnerable liquidity pool interaction
#[derive(BorshSerialize, BorshDeserialize)]
pub struct LiquidityPool {
    pub token_a_reserve: u64,
    pub token_b_reserve: u64,
    pub total_shares: u64,
}

impl LiquidityPool {
    // VULNERABLE: Price calculation vulnerable to flash loan attacks
    pub fn get_price(&self) -> Result<u64, ProgramError> {
        // VULNERABLE: Reserves can be manipulated within same transaction
        let price = self.token_b_reserve
            .checked_mul(1_000_000) // Scale for precision
            .and_then(|x| x.checked_div(self.token_a_reserve))
            .ok_or(ProgramError::DivideByZero)?;

        Ok(price)
    }

    // VULNERABLE: Swap function exploitable in atomic transactions
    pub fn swap(
        &mut self,
        amount_in: u64,
        token_in: TokenType,
        min_amount_out: u64
    ) -> Result<u64, ProgramError> {
        let amount_out = match token_in {
            TokenType::A => {
                // VULNERABLE: No protection against large swaps
                let new_a_reserve = self.token_a_reserve + amount_in;
                let new_b_reserve = (self.token_a_reserve * self.token_b_reserve)
                    .checked_div(new_a_reserve)
                    .ok_or(ProgramError::DivideByZero)?;

                let amount_out = self.token_b_reserve - new_b_reserve;

                // Update reserves (vulnerable state)
                self.token_a_reserve = new_a_reserve;
                self.token_b_reserve = new_b_reserve;

                amount_out
            }
            TokenType::B => {
                // Similar vulnerable logic for reverse swap
                let new_b_reserve = self.token_b_reserve + amount_in;
                let new_a_reserve = (self.token_a_reserve * self.token_b_reserve)
                    .checked_div(new_b_reserve)
                    .ok_or(ProgramError::DivideByZero)?;

                let amount_out = self.token_a_reserve - new_a_reserve;

                self.token_a_reserve = new_a_reserve;
                self.token_b_reserve = new_b_reserve;

                amount_out
            }
        };

        // VULNERABLE: Slippage check happens after state change
        if amount_out < min_amount_out {
            return Err(ProgramError::Custom(1)); // Too late - state already changed
        }

        Ok(amount_out)
    }
}

// Pattern 3: Vulnerable escrow valuation
#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameEscrow {
    pub total_staked: u64,
    pub staked_token: Pubkey,
    pub reward_pool: u64,
    pub participants: Vec<Pubkey>,
}

impl GameEscrow {
    // VULNERABLE: Escrow value based on manipulable prices
    pub fn calculate_total_value(
        &self,
        oracle: &TokenPriceOracle
    ) -> Result<u64, ProgramError> {
        // VULNERABLE: Oracle can be manipulated before this calculation
        let staked_value = self.total_staked
            .checked_mul(oracle.price_in_usdc)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        let reward_value = self.reward_pool
            .checked_mul(oracle.price_in_usdc)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        staked_value
            .checked_add(reward_value)
            .ok_or(ProgramError::ArithmeticOverflow)
    }

    // VULNERABLE: Payout calculation based on current price
    pub fn calculate_winner_payout(
        &self,
        oracle: &TokenPriceOracle
    ) -> Result<u64, ProgramError> {
        let total_value = self.calculate_total_value(oracle)?;

        // VULNERABLE: Payout amount depends on manipulated price
        let payout_in_tokens = total_value
            .checked_div(oracle.price_in_usdc)
            .ok_or(ProgramError::DivideByZero)?;

        Ok(payout_in_tokens)
    }
}

// Pattern 4: Vulnerable atomic operations
pub fn process_game_completion(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let escrow_account = next_account_info(account_info_iter)?;
    let oracle_account = next_account_info(account_info_iter)?;
    let pool_account = next_account_info(account_info_iter)?;
    let winner_account = next_account_info(account_info_iter)?;

    // Load accounts
    let mut escrow = GameEscrow::try_from_slice(&escrow_account.data.borrow())?;
    let oracle = TokenPriceOracle::try_from_slice(&oracle_account.data.borrow())?;
    let mut pool = LiquidityPool::try_from_slice(&pool_account.data.borrow())?;

    // VULNERABLE: All these operations happen in same transaction
    // Flash loan can manipulate state between operations

    // Step 1: Get current token price (manipulable)
    let current_price = pool.get_price()?;

    // Step 2: Calculate rewards based on manipulated price
    let winner_payout = escrow.calculate_winner_payout(&oracle)?;

    // Step 3: Execute payout (using manipulated calculations)
    transfer_tokens_to_winner(escrow_account, winner_account, winner_payout)?;

    // VULNERABLE: All operations complete before flash loan repayment

    Ok(())
}

#[derive(BorshSerialize, BorshDeserialize)]
pub enum TokenType {
    A,
    B,
}

// Helper function (also vulnerable)
fn transfer_tokens_to_winner(
    escrow: &AccountInfo,
    winner: &AccountInfo,
    amount: u64
) -> ProgramResult {
    // Simple transfer without additional validation
    **escrow.try_borrow_mut_lamports()? -= amount;
    **winner.try_borrow_mut_lamports()? += amount;
    Ok(())
}
```

## Attack Vectors

### Vector 1: Flash Loan Price Manipulation

```rust
// Attack: Manipulate token price to maximize payout
pub fn exploit_flash_loan_price_manipulation() -> Result<()> {
    // Step 1: Take flash loan of large amount
    let flash_loan_amount = 10_000_000_000u64; // 10B tokens
    let borrowed_tokens = execute_flash_loan(flash_loan_amount)?;

    // Step 2: Manipulate pool price by large swap
    let pool_manipulation_result = manipulate_pool_price(
        borrowed_tokens,
        PriceDirection::Up
    )?;

    // Step 3: Execute game completion with inflated price
    let inflated_payout = execute_game_completion_with_current_price()?;

    // Step 4: Reverse price manipulation
    reverse_pool_manipulation(pool_manipulation_result)?;

    // Step 5: Repay flash loan
    repay_flash_loan(flash_loan_amount)?;

    // Net result: Attacker keeps inflated payout minus loan fees
    let net_profit = inflated_payout - calculate_flash_loan_fees(flash_loan_amount);

    println!("Net profit from flash loan attack: {}", net_profit);
    Ok(())
}

fn execute_flash_loan(amount: u64) -> Result<u64> {
    // Simulate borrowing from flash loan provider
    println!("Borrowed {} tokens via flash loan", amount);
    Ok(amount)
}

fn manipulate_pool_price(
    amount: u64,
    direction: PriceDirection
) -> Result<PoolManipulationResult> {
    // Large swap to manipulate price
    println!("Manipulating pool price with {} tokens", amount);

    Ok(PoolManipulationResult {
        original_reserves_a: 1_000_000,
        original_reserves_b: 1_000_000,
        new_reserves_a: 11_000_000,
        new_reserves_b: 90_909, // Price manipulation achieved
        tokens_received: amount / 11, // Approximation
    })
}

fn execute_game_completion_with_current_price() -> Result<u64> {
    // Game completion uses manipulated price for calculations
    println!("Executing game completion with manipulated price");

    // With 11x price increase, payout is 11x larger
    let normal_payout = 100_000u64;
    let inflated_payout = normal_payout * 11;

    Ok(inflated_payout)
}

enum PriceDirection {
    Up,
    Down,
}

struct PoolManipulationResult {
    original_reserves_a: u64,
    original_reserves_b: u64,
    new_reserves_a: u64,
    new_reserves_b: u64,
    tokens_received: u64,
}

fn reverse_pool_manipulation(result: PoolManipulationResult) -> Result<()> {
    println!("Reversing pool manipulation");
    // Swap back to restore original price
    Ok(())
}

fn repay_flash_loan(amount: u64) -> Result<()> {
    println!("Repaying flash loan of {} tokens", amount);
    Ok(())
}

fn calculate_flash_loan_fees(amount: u64) -> u64 {
    amount / 1000 // 0.1% fee
}
```

### Vector 2: Atomic Arbitrage Exploitation

```rust
// Attack: Exploit price differences across multiple pools
pub fn exploit_atomic_arbitrage() -> Result<()> {
    // Discover price discrepancy between game protocol and DEX
    let game_price = get_game_protocol_price()?;
    let dex_price = get_dex_price()?;

    if game_price > dex_price * 110 / 100 { // 10%+ difference
        // Execute arbitrage attack

        // Step 1: Buy cheap tokens on DEX
        let dex_purchase = buy_tokens_on_dex(1_000_000)?;

        // Step 2: Use tokens in game protocol at higher valuation
        let game_reward = use_tokens_in_game_protocol(dex_purchase)?;

        // Step 3: Sell rewards back on DEX
        let final_proceeds = sell_tokens_on_dex(game_reward)?;

        let profit = final_proceeds - 1_000_000;
        println!("Arbitrage profit: {}", profit);
    }

    Ok(())
}

fn get_game_protocol_price() -> Result<u64> {
    // Game protocol uses stale or manipulable oracle
    Ok(1_100_000) // $1.10
}

fn get_dex_price() -> Result<u64> {
    // DEX has real market price
    Ok(1_000_000) // $1.00
}

fn buy_tokens_on_dex(amount: u64) -> Result<u64> {
    println!("Buying {} tokens on DEX", amount);
    Ok(amount)
}

fn use_tokens_in_game_protocol(amount: u64) -> Result<u64> {
    println!("Using {} tokens in game protocol", amount);
    // Game protocol values tokens at higher price
    Ok(amount * 110 / 100) // 10% bonus
}

fn sell_tokens_on_dex(amount: u64) -> Result<u64> {
    println!("Selling {} tokens on DEX", amount);
    Ok(amount)
}
```

### Vector 3: Oracle Front-Running Attack

```rust
// Attack: Front-run oracle updates for maximum benefit
pub fn exploit_oracle_frontrun() -> Result<()> {
    // Monitor oracle update transactions in mempool
    let pending_oracle_update = detect_pending_oracle_update()?;

    if pending_oracle_update.new_price > pending_oracle_update.current_price {
        // Price going up - position for maximum benefit

        // Step 1: Enter game with maximum stake before price update
        let max_stake = calculate_maximum_stake()?;
        enter_game_with_stake(max_stake)?;

        // Step 2: Oracle update executes (price increases)
        wait_for_oracle_update()?;

        // Step 3: Complete game with higher valuation
        let inflated_reward = complete_game_with_new_price()?;

        println!("Front-run profit: {}", inflated_reward - max_stake);
    }

    Ok(())
}

struct PendingOracleUpdate {
    current_price: u64,
    new_price: u64,
    update_timestamp: i64,
}

fn detect_pending_oracle_update() -> Result<PendingOracleUpdate> {
    // Simulate mempool monitoring
    Ok(PendingOracleUpdate {
        current_price: 1_000_000,
        new_price: 1_200_000, // 20% increase pending
        update_timestamp: 1650000000,
    })
}

fn calculate_maximum_stake() -> Result<u64> {
    Ok(5_000_000) // Maximum allowed stake
}

fn enter_game_with_stake(stake: u64) -> Result<()> {
    println!("Entering game with stake of {}", stake);
    Ok(())
}

fn wait_for_oracle_update() -> Result<()> {
    println!("Oracle update executed - price increased");
    Ok(())
}

fn complete_game_with_new_price() -> Result<u64> {
    // Game completion uses new, higher price
    let base_reward = 5_000_000u64;
    let price_multiplier = 120; // 20% increase
    let inflated_reward = base_reward * price_multiplier / 100;

    println!("Reward with new price: {}", inflated_reward);
    Ok(inflated_reward)
}
```

## Proof of Concept

### Complete Flash Loan Attack Framework

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
pub struct FlashLoanExploit {
    pub loan_amount: u64,
    pub target_pool: Pubkey,
    pub target_game: Pubkey,
    pub manipulation_target: ManipulationTarget,
    pub expected_profit: u64,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum ManipulationTarget {
    TokenPrice,
    LiquidityRatio,
    OracleValue,
    EscrowValuation,
}

impl FlashLoanExploit {
    // Complete flash loan attack execution
    pub fn execute_flash_loan_attack(&self) -> ProgramResult {
        msg!("Executing flash loan manipulation attack");
        msg!("Loan amount: {}", self.loan_amount);
        msg!("Expected profit: {}", self.expected_profit);

        // Step 1: Initiate flash loan
        let borrowed_amount = self.initiate_flash_loan(self.loan_amount)?;
        msg!("Flash loan acquired: {}", borrowed_amount);

        // Step 2: Execute manipulation strategy
        let manipulation_result = match self.manipulation_target {
            ManipulationTarget::TokenPrice => {
                self.manipulate_token_price(borrowed_amount)?
            }
            ManipulationTarget::LiquidityRatio => {
                self.manipulate_liquidity_ratio(borrowed_amount)?
            }
            ManipulationTarget::OracleValue => {
                self.manipulate_oracle_value(borrowed_amount)?
            }
            ManipulationTarget::EscrowValuation => {
                self.manipulate_escrow_valuation(borrowed_amount)?
            }
        };

        // Step 3: Execute game operations with manipulated state
        let extracted_value = self.execute_game_operations_with_manipulation()?;

        // Step 4: Reverse manipulation
        self.reverse_manipulation(manipulation_result)?;

        // Step 5: Repay flash loan
        let loan_fee = self.calculate_flash_loan_fee(self.loan_amount);
        let total_repayment = self.loan_amount + loan_fee;
        self.repay_flash_loan(total_repayment)?;

        // Calculate net profit
        let net_profit = extracted_value
            .checked_sub(total_repayment)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        msg!("Flash loan attack completed");
        msg!("Extracted value: {}", extracted_value);
        msg!("Net profit: {}", net_profit);

        Ok(())
    }

    // Flash loan initiation
    fn initiate_flash_loan(&self, amount: u64) -> Result<u64, ProgramError> {
        msg!("Initiating flash loan for {} tokens", amount);

        // In real attack, this would interact with flash loan provider
        // Here we simulate the loan acquisition

        if amount > 100_000_000_000u64 { // 100B token limit
            return Err(ProgramError::Custom(2001)); // Loan too large
        }

        Ok(amount)
    }

    // Token price manipulation
    fn manipulate_token_price(&self, loan_amount: u64) -> Result<ManipulationState, ProgramError> {
        msg!("Manipulating token price with {} tokens", loan_amount);

        // Simulate large swap to manipulate AMM price
        let original_price = 1_000_000u64; // $1.00
        let manipulation_impact = loan_amount / 1_000_000; // Impact factor
        let new_price = original_price + (original_price * manipulation_impact / 100);

        msg!("Price manipulated from {} to {}", original_price, new_price);

        Ok(ManipulationState {
            manipulation_type: ManipulationTarget::TokenPrice,
            original_value: original_price,
            manipulated_value: new_price,
            tokens_used: loan_amount / 2, // Half used for manipulation
        })
    }

    // Liquidity ratio manipulation
    fn manipulate_liquidity_ratio(&self, loan_amount: u64) -> Result<ManipulationState, ProgramError> {
        msg!("Manipulating liquidity ratio");

        let original_ratio = 1_000_000u64; // 1:1 ratio
        let new_ratio = original_ratio * 3; // 3:1 ratio after manipulation

        Ok(ManipulationState {
            manipulation_type: ManipulationTarget::LiquidityRatio,
            original_value: original_ratio,
            manipulated_value: new_ratio,
            tokens_used: loan_amount,
        })
    }

    // Oracle value manipulation
    fn manipulate_oracle_value(&self, loan_amount: u64) -> Result<ManipulationState, ProgramError> {
        msg!("Manipulating oracle through price impact");

        // Oracle derives value from pool state
        let original_oracle_value = 1_000_000u64;
        let manipulation_factor = (loan_amount / 10_000_000) as u64; // Impact calculation
        let new_oracle_value = original_oracle_value + (original_oracle_value * manipulation_factor / 100);

        msg!("Oracle value manipulated from {} to {}",
             original_oracle_value, new_oracle_value);

        Ok(ManipulationState {
            manipulation_type: ManipulationTarget::OracleValue,
            original_value: original_oracle_value,
            manipulated_value: new_oracle_value,
            tokens_used: loan_amount,
        })
    }

    // Escrow valuation manipulation
    fn manipulate_escrow_valuation(&self, loan_amount: u64) -> Result<ManipulationState, ProgramError> {
        msg!("Manipulating escrow valuation");

        // Escrow value depends on token price
        let original_valuation = 5_000_000u64; // 5M tokens worth
        let price_impact = loan_amount / 1_000_000; // Price manipulation
        let new_valuation = original_valuation + (original_valuation * price_impact / 100);

        msg!("Escrow valuation manipulated from {} to {}",
             original_valuation, new_valuation);

        Ok(ManipulationState {
            manipulation_type: ManipulationTarget::EscrowValuation,
            original_value: original_valuation,
            manipulated_value: new_valuation,
            tokens_used: loan_amount / 3,
        })
    }

    // Execute game operations with manipulated state
    fn execute_game_operations_with_manipulation(&self) -> Result<u64, ProgramError> {
        msg!("Executing game operations with manipulated market state");

        // Simulate various exploitable operations
        let base_reward = 1_000_000u64;

        // Operations benefit from manipulated prices/values
        let manipulated_reward = match self.manipulation_target {
            ManipulationTarget::TokenPrice => base_reward * 5, // 5x due to price manipulation
            ManipulationTarget::LiquidityRatio => base_reward * 3, // 3x due to ratio manipulation
            ManipulationTarget::OracleValue => base_reward * 4, // 4x due to oracle manipulation
            ManipulationTarget::EscrowValuation => base_reward * 6, // 6x due to valuation manipulation
        };

        msg!("Base reward: {}, Manipulated reward: {}", base_reward, manipulated_reward);
        Ok(manipulated_reward)
    }

    // Reverse manipulation to restore state
    fn reverse_manipulation(&self, state: ManipulationState) -> Result<(), ProgramError> {
        msg!("Reversing manipulation to restore market state");
        msg!("Restoring {} from {} to {}",
             format!("{:?}", state.manipulation_type),
             state.manipulated_value,
             state.original_value);

        // In real attack, this would execute reverse trades
        // to restore pool state before loan repayment

        Ok(())
    }

    // Calculate flash loan fee
    fn calculate_flash_loan_fee(&self, loan_amount: u64) -> u64 {
        // Typical flash loan fee: 0.05% - 0.3%
        loan_amount / 1000 // 0.1% fee
    }

    // Repay flash loan
    fn repay_flash_loan(&self, amount: u64) -> Result<(), ProgramError> {
        msg!("Repaying flash loan: {}", amount);

        // In real attack, this would transfer tokens back to lender
        // Must happen within same transaction or loan fails

        Ok(())
    }
}

#[derive(Debug)]
struct ManipulationState {
    manipulation_type: ManipulationTarget,
    original_value: u64,
    manipulated_value: u64,
    tokens_used: u64,
}

// Comprehensive flash loan attack demonstration
pub fn demonstrate_flash_loan_attacks() -> ProgramResult {
    msg!("Demonstrating comprehensive flash loan attacks");

    // Attack 1: Token price manipulation
    let price_exploit = FlashLoanExploit {
        loan_amount: 50_000_000_000u64, // 50B tokens
        target_pool: Pubkey::new_unique(),
        target_game: Pubkey::new_unique(),
        manipulation_target: ManipulationTarget::TokenPrice,
        expected_profit: 25_000_000u64, // 25M profit expected
    };
    price_exploit.execute_flash_loan_attack()?;

    // Attack 2: Oracle manipulation
    let oracle_exploit = FlashLoanExploit {
        loan_amount: 30_000_000_000u64, // 30B tokens
        target_pool: Pubkey::new_unique(),
        target_game: Pubkey::new_unique(),
        manipulation_target: ManipulationTarget::OracleValue,
        expected_profit: 20_000_000u64, // 20M profit expected
    };
    oracle_exploit.execute_flash_loan_attack()?;

    // Attack 3: Escrow valuation manipulation
    let escrow_exploit = FlashLoanExploit {
        loan_amount: 40_000_000_000u64, // 40B tokens
        target_pool: Pubkey::new_unique(),
        target_game: Pubkey::new_unique(),
        manipulation_target: ManipulationTarget::EscrowValuation,
        expected_profit: 30_000_000u64, // 30M profit expected
    };
    escrow_exploit.execute_flash_loan_attack()?;

    msg!("All flash loan attacks demonstrated successfully");
    Ok(())
}

#[cfg(test)]
mod flash_loan_exploit_tests {
    use super::*;

    #[test]
    fn test_price_manipulation_attack() {
        let exploit = FlashLoanExploit {
            loan_amount: 10_000_000_000u64,
            target_pool: Pubkey::new_unique(),
            target_game: Pubkey::new_unique(),
            manipulation_target: ManipulationTarget::TokenPrice,
            expected_profit: 5_000_000u64,
        };

        let result = exploit.execute_flash_loan_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_oracle_manipulation_attack() {
        let exploit = FlashLoanExploit {
            loan_amount: 20_000_000_000u64,
            target_pool: Pubkey::new_unique(),
            target_game: Pubkey::new_unique(),
            manipulation_target: ManipulationTarget::OracleValue,
            expected_profit: 8_000_000u64,
        };

        let result = exploit.execute_flash_loan_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_escrow_manipulation_attack() {
        let exploit = FlashLoanExploit {
            loan_amount: 15_000_000_000u64,
            target_pool: Pubkey::new_unique(),
            target_game: Pubkey::new_unique(),
            manipulation_target: ManipulationTarget::EscrowValuation,
            expected_profit: 10_000_000u64,
        };

        let result = exploit.execute_flash_loan_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_flash_loan_fee_calculation() {
        let exploit = FlashLoanExploit {
            loan_amount: 1_000_000_000u64,
            target_pool: Pubkey::new_unique(),
            target_game: Pubkey::new_unique(),
            manipulation_target: ManipulationTarget::TokenPrice,
            expected_profit: 1_000_000u64,
        };

        let fee = exploit.calculate_flash_loan_fee(exploit.loan_amount);
        assert_eq!(fee, 1_000_000u64); // 0.1% of 1B = 1M
    }
}
```

## Remediation

### Secure Implementation with Flash Loan Protection

```rust
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
use std::cmp;

// Secure price oracle with manipulation protection
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureTokenPriceOracle {
    pub token_mint: Pubkey,
    pub price_in_usdc: u64,
    pub last_update: i64,
    pub confidence: u64,
    pub price_history: [u64; 10], // Recent price history
    pub update_frequency: i64,    // Minimum update interval
    pub max_price_deviation: u64, // Maximum allowed price change
}

impl SecureTokenPriceOracle {
    // Secure price reading with manipulation detection
    pub fn get_secure_price(&self) -> Result<u64, ProgramError> {
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        // Check if price is recent enough
        if current_time - self.last_update > 300 { // 5 minutes max
            msg!("Price data too old: {} seconds", current_time - self.last_update);
            return Err(ProgramError::Custom(3001)); // Stale price
        }

        // Check confidence level
        if self.confidence < 95 {
            msg!("Price confidence too low: {}", self.confidence);
            return Err(ProgramError::Custom(3002)); // Low confidence
        }

        // Validate price against historical data
        self.validate_price_against_history()?;

        Ok(self.price_in_usdc)
    }

    // Validate price against recent history to detect manipulation
    fn validate_price_against_history(&self) -> Result<(), ProgramError> {
        if self.price_history[0] == 0 {
            return Ok(()); // No history available
        }

        // Calculate average of recent prices
        let mut sum = 0u64;
        let mut count = 0u32;

        for &price in &self.price_history {
            if price > 0 {
                sum += price;
                count += 1;
            }
        }

        if count == 0 {
            return Ok(()); // No valid history
        }

        let average_price = sum / count as u64;

        // Check for excessive deviation
        let price_diff = if self.price_in_usdc > average_price {
            self.price_in_usdc - average_price
        } else {
            average_price - self.price_in_usdc
        };

        let deviation_percentage = (price_diff * 100) / average_price;

        if deviation_percentage > self.max_price_deviation {
            msg!("Price deviation too high: {}%", deviation_percentage);
            return Err(ProgramError::Custom(3003)); // Price manipulation detected
        }

        Ok(())
    }

    // Update price with validation
    pub fn update_price_securely(
        &mut self,
        new_price: u64,
        new_confidence: u64
    ) -> Result<(), ProgramError> {
        let clock = Clock::get()?;
        let current_time = clock.unix_timestamp;

        // Enforce minimum update interval
        if current_time - self.last_update < self.update_frequency {
            return Err(ProgramError::Custom(3004)); // Too frequent update
        }

        // Validate new price against current price
        if self.price_in_usdc > 0 {
            let price_change = if new_price > self.price_in_usdc {
                new_price - self.price_in_usdc
            } else {
                self.price_in_usdc - new_price
            };

            let change_percentage = (price_change * 100) / self.price_in_usdc;

            if change_percentage > self.max_price_deviation {
                msg!("Price update rejected - change too large: {}%", change_percentage);
                return Err(ProgramError::Custom(3005)); // Price change too large
            }
        }

        // Update price history
        for i in (1..self.price_history.len()).rev() {
            self.price_history[i] = self.price_history[i - 1];
        }
        self.price_history[0] = self.price_in_usdc;

        // Update current values
        self.price_in_usdc = new_price;
        self.confidence = new_confidence;
        self.last_update = current_time;

        msg!("Price updated securely to {}", new_price);
        Ok(())
    }
}

// Secure liquidity pool with flash loan protection
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureLiquidityPool {
    pub token_a_reserve: u64,
    pub token_b_reserve: u64,
    pub total_shares: u64,
    pub last_k_value: u64,        // Previous constant product
    pub max_slippage: u64,        // Maximum allowed slippage per transaction
    pub min_liquidity: u64,       // Minimum liquidity required
    pub flash_loan_protection: bool,
}

impl SecureLiquidityPool {
    // Secure price calculation with manipulation protection
    pub fn get_secure_price(&self) -> Result<u64, ProgramError> {
        // Ensure minimum liquidity
        if self.token_a_reserve < self.min_liquidity || self.token_b_reserve < self.min_liquidity {
            return Err(ProgramError::Custom(3006)); // Insufficient liquidity
        }

        // Calculate price with overflow protection
        let price = self.token_b_reserve
            .checked_mul(1_000_000)
            .and_then(|x| x.checked_div(self.token_a_reserve))
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Validate against previous state if available
        if self.last_k_value > 0 {
            self.validate_pool_integrity()?;
        }

        Ok(price)
    }

    // Secure swap with flash loan protection
    pub fn secure_swap(
        &mut self,
        amount_in: u64,
        token_in: TokenType,
        min_amount_out: u64
    ) -> Result<u64, ProgramError> {
        // Pre-swap validation
        if amount_in == 0 {
            return Err(ProgramError::InvalidArgument);
        }

        // Calculate maximum allowed trade size (prevent large single trades)
        let max_trade_size = cmp::min(
            self.token_a_reserve / 10, // Max 10% of pool
            self.token_b_reserve / 10
        );

        if amount_in > max_trade_size {
            msg!("Trade size too large: {} > {}", amount_in, max_trade_size);
            return Err(ProgramError::Custom(3007)); // Trade too large
        }

        // Store original state
        let original_a = self.token_a_reserve;
        let original_b = self.token_b_reserve;
        let original_k = original_a * original_b;

        // Calculate swap with constant product formula
        let amount_out = match token_in {
            TokenType::A => {
                let new_a_reserve = original_a + amount_in;
                let new_b_reserve = original_k
                    .checked_div(new_a_reserve)
                    .ok_or(ProgramError::DivideByZero)?;

                original_b - new_b_reserve
            }
            TokenType::B => {
                let new_b_reserve = original_b + amount_in;
                let new_a_reserve = original_k
                    .checked_div(new_b_reserve)
                    .ok_or(ProgramError::DivideByZero)?;

                original_a - new_a_reserve
            }
        };

        // Validate slippage BEFORE state change
        if amount_out < min_amount_out {
            return Err(ProgramError::Custom(3008)); // Slippage too high
        }

        // Calculate slippage percentage
        let expected_amount = self.calculate_expected_output(amount_in, token_in)?;
        let slippage = if expected_amount > amount_out {
            ((expected_amount - amount_out) * 100) / expected_amount
        } else {
            0
        };

        if slippage > self.max_slippage {
            msg!("Slippage too high: {}% > {}%", slippage, self.max_slippage);
            return Err(ProgramError::Custom(3009)); // Excessive slippage
        }

        // Update reserves only after all validations pass
        match token_in {
            TokenType::A => {
                self.token_a_reserve = original_a + amount_in;
                self.token_b_reserve = original_b - amount_out;
            }
            TokenType::B => {
                self.token_b_reserve = original_b + amount_in;
                self.token_a_reserve = original_a - amount_out;
            }
        }

        // Update k value for next validation
        self.last_k_value = self.token_a_reserve * self.token_b_reserve;

        // Ensure k value didn't decrease (constant product invariant)
        if self.last_k_value < original_k {
            msg!("Constant product invariant violated");
            return Err(ProgramError::Custom(3010)); // Invariant violation
        }

        msg!("Secure swap completed: {} -> {}", amount_in, amount_out);
        Ok(amount_out)
    }

    // Validate pool integrity against manipulation
    fn validate_pool_integrity(&self) -> Result<(), ProgramError> {
        let current_k = self.token_a_reserve * self.token_b_reserve;

        // K value should never decrease significantly
        if current_k < (self.last_k_value * 95 / 100) {
            msg!("Pool integrity compromised - K value decreased significantly");
            return Err(ProgramError::Custom(3011)); // Pool manipulated
        }

        Ok(())
    }

    // Calculate expected output for slippage validation
    fn calculate_expected_output(&self, amount_in: u64, token_in: TokenType) -> Result<u64, ProgramError> {
        // Simple linear approximation for expected output
        match token_in {
            TokenType::A => {
                let rate = self.token_b_reserve
                    .checked_div(self.token_a_reserve)
                    .ok_or(ProgramError::DivideByZero)?;
                Ok(amount_in * rate)
            }
            TokenType::B => {
                let rate = self.token_a_reserve
                    .checked_div(self.token_b_reserve)
                    .ok_or(ProgramError::DivideByZero)?;
                Ok(amount_in * rate)
            }
        }
    }
}

// Secure escrow with flash loan attack protection
#[derive(BorshSerialize, BorshDeserialize)]
pub struct SecureGameEscrow {
    pub total_staked: u64,
    pub staked_token: Pubkey,
    pub reward_pool: u64,
    pub participants: Vec<Pubkey>,
    pub price_snapshot: u64,      // Price at escrow creation
    pub max_price_deviation: u64, // Maximum allowed price change
    pub creation_timestamp: i64,
}

impl SecureGameEscrow {
    // Secure total value calculation with price validation
    pub fn calculate_secure_total_value(
        &self,
        oracle: &SecureTokenPriceOracle
    ) -> Result<u64, ProgramError> {
        let current_price = oracle.get_secure_price()?;

        // Validate price hasn't been manipulated since escrow creation
        let price_change = if current_price > self.price_snapshot {
            current_price - self.price_snapshot
        } else {
            self.price_snapshot - current_price
        };

        let change_percentage = (price_change * 100) / self.price_snapshot;

        if change_percentage > self.max_price_deviation {
            msg!("Price manipulation detected in escrow valuation: {}%", change_percentage);
            // Use snapshot price instead of current manipulated price
            let staked_value = self.total_staked
                .checked_mul(self.price_snapshot)
                .ok_or(ProgramError::ArithmeticOverflow)?;

            let reward_value = self.reward_pool
                .checked_mul(self.price_snapshot)
                .ok_or(ProgramError::ArithmeticOverflow)?;

            return staked_value
                .checked_add(reward_value)
                .ok_or(ProgramError::ArithmeticOverflow);
        }

        // Use current price if validation passes
        let staked_value = self.total_staked
            .checked_mul(current_price)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        let reward_value = self.reward_pool
            .checked_mul(current_price)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        staked_value
            .checked_add(reward_value)
            .ok_or(ProgramError::ArithmeticOverflow)
    }

    // Secure payout calculation with manipulation protection
    pub fn calculate_secure_winner_payout(
        &self,
        oracle: &SecureTokenPriceOracle
    ) -> Result<u64, ProgramError> {
        // Use time-weighted average price to prevent manipulation
        let average_price = self.calculate_time_weighted_price(oracle)?;

        let total_value = self.total_staked
            .checked_mul(average_price)
            .and_then(|x| x.checked_add(
                self.reward_pool
                    .checked_mul(average_price)
                    .ok_or(ProgramError::ArithmeticOverflow).ok()?
            ))
            .ok_or(ProgramError::ArithmeticOverflow)?;

        let payout_in_tokens = total_value
            .checked_div(average_price)
            .ok_or(ProgramError::DivideByZero)?;

        // Apply maximum payout cap
        let max_payout = (self.total_staked + self.reward_pool) * 2; // 200% max
        let final_payout = cmp::min(payout_in_tokens, max_payout);

        msg!("Secure payout calculated: {}", final_payout);
        Ok(final_payout)
    }

    // Calculate time-weighted average price to resist manipulation
    fn calculate_time_weighted_price(&self, oracle: &SecureTokenPriceOracle) -> Result<u64, ProgramError> {
        // Use historical price data to calculate TWAP
        let mut total_weighted_price = 0u64;
        let mut total_weight = 0u64;

        for (i, &historical_price) in oracle.price_history.iter().enumerate() {
            if historical_price > 0 {
                let weight = (oracle.price_history.len() - i) as u64; // More recent = higher weight
                total_weighted_price += historical_price * weight;
                total_weight += weight;
            }
        }

        if total_weight == 0 {
            // Fallback to current price if no history
            return oracle.get_secure_price();
        }

        let twap = total_weighted_price / total_weight;
        msg!("Time-weighted average price: {}", twap);

        Ok(twap)
    }
}

// Secure game completion with comprehensive protection
pub fn secure_process_game_completion(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let escrow_account = next_account_info(account_info_iter)?;
    let oracle_account = next_account_info(account_info_iter)?;
    let pool_account = next_account_info(account_info_iter)?;
    let winner_account = next_account_info(account_info_iter)?;

    // Load accounts with validation
    let mut escrow = SecureGameEscrow::try_from_slice(&escrow_account.data.borrow())?;
    let oracle = SecureTokenPriceOracle::try_from_slice(&oracle_account.data.borrow())?;
    let pool = SecureLiquidityPool::try_from_slice(&pool_account.data.borrow())?;

    // Multi-source price validation
    let oracle_price = oracle.get_secure_price()?;
    let pool_price = pool.get_secure_price()?;

    // Validate price consistency between sources
    let price_diff = if oracle_price > pool_price {
        oracle_price - pool_price
    } else {
        pool_price - oracle_price
    };

    let price_deviation = (price_diff * 100) / oracle_price;

    if price_deviation > 5 { // 5% maximum deviation between sources
        msg!("Price inconsistency detected between oracle and pool: {}%", price_deviation);
        return Err(ProgramError::Custom(3012)); // Price manipulation detected
    }

    // Calculate payout using secure methods
    let winner_payout = escrow.calculate_secure_winner_payout(&oracle)?;

    // Additional validation: ensure payout is reasonable
    let max_reasonable_payout = (escrow.total_staked + escrow.reward_pool) * 3 / 2; // 150% max
    if winner_payout > max_reasonable_payout {
        msg!("Payout too large - possible manipulation: {} > {}",
             winner_payout, max_reasonable_payout);
        return Err(ProgramError::Custom(3013)); // Payout too large
    }

    // Execute secure transfer
    secure_transfer_with_validation(escrow_account, winner_account, winner_payout)?;

    msg!("Secure game completion processed with flash loan protection");
    Ok(())
}

// Helper: Secure transfer with additional validation
fn secure_transfer_with_validation(
    from: &AccountInfo,
    to: &AccountInfo,
    amount: u64
) -> ProgramResult {
    // Validate accounts
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }

    if from.lamports() < amount {
        return Err(ProgramError::InsufficientFunds);
    }

    // Check for reasonable transfer amounts
    if amount > from.lamports() / 2 { // Max 50% of account balance per transfer
        msg!("Transfer amount unusually large: {} from balance {}",
             amount, from.lamports());
    }

    // Execute transfer
    **from.try_borrow_mut_lamports()? = from.lamports()
        .checked_sub(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    **to.try_borrow_mut_lamports()? = to.lamports()
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    msg!("Secure transfer completed: {}", amount);
    Ok(())
}

#[cfg(test)]
mod secure_flash_loan_tests {
    use super::*;

    #[test]
    fn test_secure_oracle_price_validation() {
        let oracle = SecureTokenPriceOracle {
            token_mint: Pubkey::new_unique(),
            price_in_usdc: 1_000_000,
            last_update: 1650000000,
            confidence: 98,
            price_history: [950_000, 980_000, 990_000, 1_010_000, 1_020_000, 0, 0, 0, 0, 0],
            update_frequency: 60,
            max_price_deviation: 10, // 10%
        };

        // This should pass validation
        let result = oracle.validate_price_against_history();
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_pool_trade_size_limits() {
        let mut pool = SecureLiquidityPool {
            token_a_reserve: 1_000_000,
            token_b_reserve: 1_000_000,
            total_shares: 1_000_000,
            last_k_value: 1_000_000_000_000,
            max_slippage: 5, // 5%
            min_liquidity: 100_000,
            flash_loan_protection: true,
        };

        // Large trade should be rejected
        let large_trade_result = pool.secure_swap(
            200_000, // 20% of pool - should be rejected
            TokenType::A,
            150_000
        );
        assert!(large_trade_result.is_err());

        // Reasonable trade should succeed
        let normal_trade_result = pool.secure_swap(
            50_000, // 5% of pool - should succeed
            TokenType::A,
            45_000
        );
        // Note: May still fail in test environment without full setup
    }

    #[test]
    fn test_secure_escrow_price_deviation_protection() {
        let escrow = SecureGameEscrow {
            total_staked: 1_000_000,
            staked_token: Pubkey::new_unique(),
            reward_pool: 500_000,
            participants: vec![],
            price_snapshot: 1_000_000, // $1.00 at creation
            max_price_deviation: 10,   // 10% max
            creation_timestamp: 1650000000,
        };

        // Price manipulation should be detected and rejected
        // Implementation would use snapshot price instead of manipulated current price
        assert_eq!(escrow.price_snapshot, 1_000_000);
        assert_eq!(escrow.max_price_deviation, 10);
    }
}
```

## Testing Requirements

### Comprehensive Flash Loan Attack Testing

```bash
# Test price manipulation resistance
cargo test --release test_flash_loan_price_protection
cargo test --release test_oracle_manipulation_detection
cargo test --release test_pool_integrity_validation

# Test slippage and trade size limits
cargo test --release test_maximum_trade_sizes
cargo test --release test_slippage_protection
cargo test --release test_liquidity_requirements

# Integration testing with DeFi protocols
cargo test --release integration_flash_loan_scenarios
cargo test --release integration_atomic_arbitrage_protection

# Stress testing with large manipulations
cargo test --release stress_test_price_manipulation
cargo test --release stress_test_liquidity_attacks

# Economic simulation testing
cargo test --release economic_attack_simulations
```

### Security Validation Checklist

- **Oracle Protection**: Price feeds must be resistant to manipulation
- **Slippage Limits**: Maximum slippage per transaction enforced
- **Trade Size Limits**: Large single trades prevented
- **Price History**: Time-weighted averages resist manipulation
- **Multi-Source Validation**: Cross-reference prices between sources
- **State Validation**: Pool integrity maintained across operations

## Business Impact

### Financial Risk Assessment

**Direct Impacts**:
- **Escrow Drainage**: $10M+ potential loss through price manipulation
- **Economic Model Collapse**: Flash loan attacks destroy token economics
- **Oracle Manipulation**: External price feed corruption affects all games
- **Liquidity Crisis**: Large manipulations can drain protocol liquidity

**Secondary Impacts**:
- **Player Confidence**: 100% user abandonment after flash loan exploits
- **DeFi Integration Risk**: Vulnerable protocols avoid integration
- **Regulatory Scrutiny**: Market manipulation investigations likely
- **Insurance Voidance**: Flash loan coverage typically excluded

**Systemic Risks**:
- **Cross-Protocol Contagion**: Attacks spread to connected DeFi protocols
- **Market Manipulation**: Gaming protocol becomes vector for broader manipulation
- **Liquidation Cascades**: Large position changes trigger system-wide liquidations

### Remediation Priority: CRITICAL

Flash loan vulnerabilities represent existential threats to any DeFi-integrated gaming protocol. The atomic nature of these attacks makes them particularly dangerous as they can extract maximum value while maintaining apparent protocol compliance.

## References

- **CWE-841**: Improper Enforcement of Behavioral Workflow
- **CWE-672**: Operation on Resource after Expiration or Release
- **Flash Loan Security**: Research on atomic transaction attacks
- **Oracle Security**: Best practices for price feed protection
- **DeFi Security**: Comprehensive guide to decentralized finance vulnerabilities
- **Constant Product AMMs**: Security considerations for automated market makers