# VUL-036: Input Validation Bypass & Parameter Manipulation

## Vulnerability Overview

**CVSS Score**: 8.3 (High)
**CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L
**CWE**: CWE-20 (Improper Input Validation), CWE-129 (Improper Validation of Array Index)
**Category**: Input Security
**Impact**: Game Logic Bypass, Parameter Manipulation, State Corruption

### Summary
The Solana gaming protocol lacks comprehensive input validation across multiple instruction handlers, allowing attackers to bypass game logic through crafted parameters. Malicious actors can manipulate bet amounts, game settings, player counts, and other critical parameters to gain unfair advantages, corrupt game state, or trigger unintended behaviors.

### Affected Components
- Instruction parameter validation
- Game configuration handlers
- Player action processing
- Bet amount validation
- Array index bounds checking
- Numeric range validation

## Technical Analysis

### Vulnerable Code Patterns

```rust
// VULNERABLE: Missing input validation in game instructions
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameConfig {
    pub max_players: u32,
    pub min_bet: u64,
    pub max_bet: u64,
    pub game_duration: i64,
}

// Pattern 1: No bounds checking on array access
pub fn process_player_action(
    accounts: &[AccountInfo],
    player_index: u32,
    action_type: u8,
    action_data: &[u8]
) -> ProgramResult {
    // VULNERABLE: No bounds checking on player_index
    let player_account = &accounts[player_index as usize]; // Can cause panic or access wrong account

    // VULNERABLE: No validation on action_type
    match action_type {
        0 => process_move_action(player_account, action_data)?, // No data validation
        1 => process_bet_action(player_account, action_data)?,  // No data validation
        _ => {
            // VULNERABLE: Invalid action types accepted silently
            msg!("Unknown action type: {}", action_type);
        }
    }

    Ok(())
}

// Pattern 2: Missing numeric range validation
pub fn place_bet(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    let bet_amount: u64 = u64::from_le_bytes(
        instruction_data[0..8].try_into().unwrap() // VULNERABLE: No bounds check
    );

    let config = GameConfig::try_from_slice(&accounts[1].data.borrow())?;

    // VULNERABLE: Only checks against config, not absolute limits
    if bet_amount < config.min_bet || bet_amount > config.max_bet {
        return Err(ProgramError::InvalidArgument);
    }

    // VULNERABLE: No check for bet_amount == 0 or integer overflow
    // VULNERABLE: No check for maximum reasonable bet limits

    // Process bet without additional validation
    process_bet_placement(bet_amount)?;

    Ok(())
}

// Pattern 3: Unsafe deserialization without validation
#[derive(BorshSerialize, BorshDeserialize)]
pub struct GameMove {
    pub move_type: u8,
    pub coordinates: [u32; 2],
    pub power: u16,
    pub target_player: u32,
}

pub fn execute_game_move(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    // VULNERABLE: Deserializes without any validation
    let game_move = GameMove::try_from_slice(instruction_data)?;

    // VULNERABLE: No validation on move_type range
    // VULNERABLE: No validation on coordinates (could be negative when cast)
    // VULNERABLE: No validation on power limits
    // VULNERABLE: No validation on target_player existence

    match game_move.move_type {
        1 => execute_attack_move(&game_move)?,
        2 => execute_defense_move(&game_move)?,
        3 => execute_special_move(&game_move)?,
        _ => {
            // VULNERABLE: Invalid moves processed anyway
            msg!("Processing unknown move type: {}", game_move.move_type);
            execute_default_move(&game_move)?;
        }
    }

    Ok(())
}

// Pattern 4: String/buffer overflow vulnerabilities
#[derive(BorshSerialize, BorshDeserialize)]
pub struct PlayerProfile {
    pub username: String,
    pub bio: String,
    pub custom_data: Vec<u8>,
}

pub fn update_player_profile(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    // VULNERABLE: No size limits on deserialized data
    let profile = PlayerProfile::try_from_slice(instruction_data)?;

    // VULNERABLE: No length validation on username
    // VULNERABLE: No length validation on bio
    // VULNERABLE: No size limits on custom_data

    // Could allocate massive amounts of memory or cause buffer overflows
    if profile.username.len() > 1000000 { // Ridiculously large limit
        return Err(ProgramError::InvalidArgument);
    }

    // VULNERABLE: Still allows very large usernames that could cause issues
    let player_account = next_account_info(&mut accounts.iter())?;
    profile.serialize(&mut &mut player_account.data.borrow_mut()[..])?;

    Ok(())
}

// Pattern 5: Missing validation in configuration updates
pub fn update_game_config(
    accounts: &[AccountInfo],
    new_max_players: u32,
    new_min_bet: u64,
    new_max_bet: u64,
    new_duration: i64
) -> ProgramResult {
    // VULNERABLE: No validation on any parameters

    let config_account = next_account_info(&mut accounts.iter())?;

    let new_config = GameConfig {
        max_players: new_max_players,     // Could be 0 or u32::MAX
        min_bet: new_min_bet,             // Could be 0 or larger than max_bet
        max_bet: new_max_bet,             // Could be smaller than min_bet
        game_duration: new_duration,      // Could be negative or excessive
    };

    // VULNERABLE: Saves invalid configuration
    new_config.serialize(&mut &mut config_account.data.borrow_mut()[..])?;

    Ok(())
}

// Helper functions (also vulnerable)
fn process_move_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    // No validation on action_data length or content
    Ok(())
}

fn process_bet_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    // No validation on action_data
    Ok(())
}

fn process_bet_placement(amount: u64) -> ProgramResult {
    msg!("Processing bet of {}", amount);
    Ok(())
}

fn execute_attack_move(game_move: &GameMove) -> ProgramResult {
    // Uses unvalidated coordinates and power values
    msg!("Attack at {:?} with power {}", game_move.coordinates, game_move.power);
    Ok(())
}

fn execute_defense_move(game_move: &GameMove) -> ProgramResult {
    Ok(())
}

fn execute_special_move(game_move: &GameMove) -> ProgramResult {
    Ok(())
}

fn execute_default_move(game_move: &GameMove) -> ProgramResult {
    Ok(())
}
```

## Attack Vectors

### Vector 1: Array Index Manipulation

```rust
// Attack: Cause array bounds panic or access wrong accounts
pub fn exploit_array_bounds() -> Result<()> {
    // Craft malicious instruction with out-of-bounds index
    let malicious_player_index = u32::MAX; // Will cause panic when cast to usize

    // Or use index to access wrong account
    let wrong_account_index = 100; // Beyond available accounts

    // This will either panic the program or access wrong account
    // process_player_action(accounts, malicious_player_index, 1, &[]);

    println!("Array bounds exploit crafted");
    Ok(())
}
```

### Vector 2: Parameter Range Manipulation

```rust
// Attack: Bypass validation through extreme values
pub fn exploit_parameter_ranges() -> Result<()> {
    // Craft bet amounts that bypass validation
    let malicious_bets = vec![
        0u64,                    // Zero bet
        1u64,                    // Minimum possible
        u64::MAX,               // Maximum possible - causes overflow
        u64::MAX - 1,           // Near maximum
    ];

    // Craft game moves with invalid ranges
    let malicious_coordinates = [u32::MAX, u32::MAX]; // Invalid coordinates
    let malicious_power = u16::MAX;                   // Maximum power
    let malicious_target = u32::MAX;                  // Invalid target

    println!("Parameter range exploits crafted");
    Ok(())
}
```

### Vector 3: Configuration Corruption

```rust
// Attack: Corrupt game configuration through invalid parameters
pub fn exploit_config_update() -> Result<()> {
    // Corrupt game settings
    let corrupt_config = GameConfig {
        max_players: 0,          // No players allowed
        min_bet: u64::MAX,       // Impossible minimum bet
        max_bet: 0,              // Maximum smaller than minimum
        game_duration: -1,       // Negative duration
    };

    // This will break all future games
    println!("Configuration corruption exploit ready");
    Ok(())
}
```

## Proof of Concept

### Complete Input Validation Exploit Framework

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
pub struct InputValidationExploit {
    pub exploit_type: ExploitType,
    pub malicious_parameters: MaliciousParameters,
    pub target_instruction: String,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum ExploitType {
    ArrayBoundsOverflow,
    ParameterRangeBypass,
    ConfigurationCorruption,
    BufferOverflow,
    IntegerOverflow,
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct MaliciousParameters {
    pub array_indices: Vec<u32>,
    pub numeric_values: Vec<u64>,
    pub string_data: Vec<String>,
    pub buffer_data: Vec<Vec<u8>>,
}

impl InputValidationExploit {
    // Execute comprehensive input validation attacks
    pub fn execute_input_validation_attacks(&self) -> ProgramResult {
        msg!("Executing input validation exploit: {:?}", self.exploit_type);

        match self.exploit_type {
            ExploitType::ArrayBoundsOverflow => {
                self.execute_array_bounds_attack()?
            }
            ExploitType::ParameterRangeBypass => {
                self.execute_parameter_range_attack()?
            }
            ExploitType::ConfigurationCorruption => {
                self.execute_config_corruption_attack()?
            }
            ExploitType::BufferOverflow => {
                self.execute_buffer_overflow_attack()?
            }
            ExploitType::IntegerOverflow => {
                self.execute_integer_overflow_attack()?
            }
        }

        msg!("Input validation attack completed");
        Ok(())
    }

    // Array bounds overflow attack
    fn execute_array_bounds_attack(&self) -> ProgramResult {
        msg!("Executing array bounds overflow attack");

        for &malicious_index in &self.malicious_parameters.array_indices {
            msg!("Testing malicious array index: {}", malicious_index);

            // Test various out-of-bounds indices
            match malicious_index {
                u32::MAX => {
                    msg!("Testing maximum u32 index (will cause panic)");
                    // In real exploit, this would crash the program
                }
                0xFFFFFFFF => {
                    msg!("Testing 0xFFFFFFFF index");
                }
                _ => {
                    msg!("Testing index beyond expected bounds: {}", malicious_index);
                }
            }
        }

        Ok(())
    }

    // Parameter range bypass attack
    fn execute_parameter_range_attack(&self) -> ProgramResult {
        msg!("Executing parameter range bypass attack");

        for &malicious_value in &self.malicious_parameters.numeric_values {
            msg!("Testing malicious numeric value: {}", malicious_value);

            // Test edge cases and invalid ranges
            if malicious_value == 0 {
                msg!("Testing zero value bypass");
            } else if malicious_value == u64::MAX {
                msg!("Testing maximum value overflow");
            } else if malicious_value > 1_000_000_000_000 {
                msg!("Testing unreasonably large value");
            }

            // Simulate parameter validation bypass
            let validation_result = self.simulate_validation_bypass(malicious_value);
            msg!("Validation bypass result: {:?}", validation_result);
        }

        Ok(())
    }

    // Configuration corruption attack
    fn execute_config_corruption_attack(&self) -> ProgramResult {
        msg!("Executing configuration corruption attack");

        // Create various corrupt configurations
        let corrupt_configs = vec![
            (0, 100, 50, -3600),      // Zero max players, min > max bet, negative duration
            (u32::MAX, u64::MAX, 0, i64::MAX), // Extreme values
            (1, 0, 0, 0),             // Single player, zero bets
            (100, 1000, 999, 1),      // Min bet > max bet, very short duration
        ];

        for (max_players, min_bet, max_bet, duration) in corrupt_configs {
            msg!("Testing corrupt config: players={}, min_bet={}, max_bet={}, duration={}",
                 max_players, min_bet, max_bet, duration);

            // Simulate configuration corruption
            let corruption_success = self.simulate_config_corruption(
                max_players, min_bet, max_bet, duration
            );

            msg!("Configuration corruption success: {}", corruption_success);
        }

        Ok(())
    }

    // Buffer overflow attack
    fn execute_buffer_overflow_attack(&self) -> ProgramResult {
        msg!("Executing buffer overflow attack");

        for malicious_string in &self.malicious_parameters.string_data {
            msg!("Testing malicious string of length: {}", malicious_string.len());

            if malicious_string.len() > 10000 {
                msg!("Large string attack - potential memory exhaustion");
            }

            // Test various string attacks
            if malicious_string.contains('\0') {
                msg!("Null byte injection detected");
            }

            if malicious_string.len() > 1_000_000 {
                msg!("Massive string attack - likely to cause issues");
            }
        }

        for malicious_buffer in &self.malicious_parameters.buffer_data {
            msg!("Testing malicious buffer of size: {}", malicious_buffer.len());

            if malicious_buffer.len() > 1_000_000 {
                msg!("Large buffer attack - memory exhaustion likely");
            }
        }

        Ok(())
    }

    // Integer overflow attack
    fn execute_integer_overflow_attack(&self) -> ProgramResult {
        msg!("Executing integer overflow attack");

        // Test various overflow scenarios
        let overflow_values = vec![
            (u64::MAX, 1),           // Addition overflow
            (u64::MAX, u64::MAX),    // Multiplication overflow
            (0, 1),                  // Underflow in subtraction
            (1, 0),                  // Division by zero
        ];

        for (a, b) in overflow_values {
            msg!("Testing arithmetic with values {} and {}", a, b);

            // Simulate various arithmetic operations that could overflow
            if let Some(sum) = a.checked_add(b) {
                msg!("Addition result: {}", sum);
            } else {
                msg!("Addition overflow detected");
            }

            if let Some(product) = a.checked_mul(b) {
                msg!("Multiplication result: {}", product);
            } else {
                msg!("Multiplication overflow detected");
            }

            if b == 0 {
                msg!("Division by zero scenario");
            } else {
                let quotient = a / b;
                msg!("Division result: {}", quotient);
            }
        }

        Ok(())
    }

    // Simulate validation bypass
    fn simulate_validation_bypass(&self, value: u64) -> ValidationResult {
        // Simulate how malicious values might bypass validation
        if value == 0 {
            ValidationResult::ZeroBypass
        } else if value == u64::MAX {
            ValidationResult::OverflowBypass
        } else if value > 1_000_000_000 {
            ValidationResult::LargeValueBypass
        } else {
            ValidationResult::WithinBounds
        }
    }

    // Simulate configuration corruption
    fn simulate_config_corruption(&self, max_players: u32, min_bet: u64, max_bet: u64, duration: i64) -> bool {
        // Check if configuration would cause issues
        max_players == 0 ||
        min_bet > max_bet ||
        duration <= 0 ||
        max_players == u32::MAX ||
        min_bet == u64::MAX
    }
}

#[derive(Debug)]
enum ValidationResult {
    ZeroBypass,
    OverflowBypass,
    LargeValueBypass,
    WithinBounds,
}

// Comprehensive input validation attack demonstration
pub fn demonstrate_input_validation_attacks() -> ProgramResult {
    msg!("Demonstrating comprehensive input validation attacks");

    // Create various malicious parameter sets
    let malicious_params = MaliciousParameters {
        array_indices: vec![
            u32::MAX,           // Maximum index
            0xFFFFFFFF,         // Another way to write u32::MAX
            1000000,            // Very large index
            0,                  // Edge case - zero index
        ],
        numeric_values: vec![
            0,                  // Zero value
            1,                  // Minimum positive
            u64::MAX,           // Maximum value
            u64::MAX - 1,       // Near maximum
            1_000_000_000_000_000, // Very large but valid
        ],
        string_data: vec![
            "A".repeat(1_000_000),     // 1MB string
            "B".repeat(10_000),        // 10KB string
            String::from("test\0null"), // Null byte injection
            String::new(),              // Empty string
        ],
        buffer_data: vec![
            vec![0xAA; 1_000_000],     // 1MB buffer
            vec![0xFF; 100_000],       // 100KB buffer
            vec![],                     // Empty buffer
        ],
    };

    // Test different exploit types
    let exploits = vec![
        InputValidationExploit {
            exploit_type: ExploitType::ArrayBoundsOverflow,
            malicious_parameters: malicious_params.clone(),
            target_instruction: "process_player_action".to_string(),
        },
        InputValidationExploit {
            exploit_type: ExploitType::ParameterRangeBypass,
            malicious_parameters: malicious_params.clone(),
            target_instruction: "place_bet".to_string(),
        },
        InputValidationExploit {
            exploit_type: ExploitType::ConfigurationCorruption,
            malicious_parameters: malicious_params.clone(),
            target_instruction: "update_game_config".to_string(),
        },
        InputValidationExploit {
            exploit_type: ExploitType::BufferOverflow,
            malicious_parameters: malicious_params.clone(),
            target_instruction: "update_player_profile".to_string(),
        },
        InputValidationExploit {
            exploit_type: ExploitType::IntegerOverflow,
            malicious_parameters: malicious_params.clone(),
            target_instruction: "various_arithmetic_operations".to_string(),
        },
    ];

    // Execute all exploit types
    for exploit in exploits {
        exploit.execute_input_validation_attacks()?;
    }

    msg!("All input validation attacks demonstrated successfully");
    Ok(())
}

#[cfg(test)]
mod input_validation_tests {
    use super::*;

    #[test]
    fn test_array_bounds_exploit() {
        let exploit = InputValidationExploit {
            exploit_type: ExploitType::ArrayBoundsOverflow,
            malicious_parameters: MaliciousParameters {
                array_indices: vec![u32::MAX, 1000000],
                numeric_values: vec![],
                string_data: vec![],
                buffer_data: vec![],
            },
            target_instruction: "test".to_string(),
        };

        let result = exploit.execute_array_bounds_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_parameter_range_exploit() {
        let exploit = InputValidationExploit {
            exploit_type: ExploitType::ParameterRangeBypass,
            malicious_parameters: MaliciousParameters {
                array_indices: vec![],
                numeric_values: vec![0, u64::MAX, 1_000_000_000_000],
                string_data: vec![],
                buffer_data: vec![],
            },
            target_instruction: "test".to_string(),
        };

        let result = exploit.execute_parameter_range_attack();
        assert!(result.is_ok());
    }

    #[test]
    fn test_buffer_overflow_exploit() {
        let exploit = InputValidationExploit {
            exploit_type: ExploitType::BufferOverflow,
            malicious_parameters: MaliciousParameters {
                array_indices: vec![],
                numeric_values: vec![],
                string_data: vec!["A".repeat(10000)],
                buffer_data: vec![vec![0xFF; 10000]],
            },
            target_instruction: "test".to_string(),
        };

        let result = exploit.execute_buffer_overflow_attack();
        assert!(result.is_ok());
    }
}
```

## Remediation

### Secure Input Validation Implementation

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// Secure input validation framework
pub mod secure_validation {
    use super::*;

    // Constants for validation limits
    pub const MAX_PLAYERS: u32 = 100;
    pub const MIN_PLAYERS: u32 = 1;
    pub const MAX_BET_AMOUNT: u64 = 1_000_000_000; // 1B tokens max
    pub const MIN_BET_AMOUNT: u64 = 1;
    pub const MAX_GAME_DURATION: i64 = 86400; // 24 hours max
    pub const MIN_GAME_DURATION: i64 = 60; // 1 minute min
    pub const MAX_USERNAME_LENGTH: usize = 32;
    pub const MAX_BIO_LENGTH: usize = 256;
    pub const MAX_CUSTOM_DATA_SIZE: usize = 1024;
    pub const MAX_ACTION_DATA_SIZE: usize = 512;

    // Secure validation functions
    pub fn validate_player_index(index: u32, max_players: u32) -> Result<usize, ProgramError> {
        if index >= max_players {
            msg!("Player index {} exceeds maximum {}", index, max_players);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(index as usize)
    }

    pub fn validate_bet_amount(amount: u64) -> Result<u64, ProgramError> {
        if amount == 0 {
            msg!("Bet amount cannot be zero");
            return Err(ProgramError::InvalidArgument);
        }

        if amount < MIN_BET_AMOUNT {
            msg!("Bet amount {} below minimum {}", amount, MIN_BET_AMOUNT);
            return Err(ProgramError::InvalidArgument);
        }

        if amount > MAX_BET_AMOUNT {
            msg!("Bet amount {} exceeds maximum {}", amount, MAX_BET_AMOUNT);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(amount)
    }

    pub fn validate_game_config(config: &GameConfig) -> Result<(), ProgramError> {
        // Validate max_players
        if config.max_players < MIN_PLAYERS || config.max_players > MAX_PLAYERS {
            msg!("Invalid max_players: {} (range: {}-{})",
                 config.max_players, MIN_PLAYERS, MAX_PLAYERS);
            return Err(ProgramError::InvalidArgument);
        }

        // Validate bet amounts
        if config.min_bet == 0 {
            msg!("Minimum bet cannot be zero");
            return Err(ProgramError::InvalidArgument);
        }

        if config.min_bet > config.max_bet {
            msg!("Minimum bet {} exceeds maximum bet {}", config.min_bet, config.max_bet);
            return Err(ProgramError::InvalidArgument);
        }

        if config.max_bet > MAX_BET_AMOUNT {
            msg!("Maximum bet {} exceeds global limit {}", config.max_bet, MAX_BET_AMOUNT);
            return Err(ProgramError::InvalidArgument);
        }

        // Validate game duration
        if config.game_duration <= 0 {
            msg!("Game duration must be positive: {}", config.game_duration);
            return Err(ProgramError::InvalidArgument);
        }

        if config.game_duration < MIN_GAME_DURATION || config.game_duration > MAX_GAME_DURATION {
            msg!("Game duration {} out of range ({}-{})",
                 config.game_duration, MIN_GAME_DURATION, MAX_GAME_DURATION);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn validate_game_move(game_move: &GameMove, max_players: u32) -> Result<(), ProgramError> {
        // Validate move type
        if game_move.move_type == 0 || game_move.move_type > 10 {
            msg!("Invalid move type: {}", game_move.move_type);
            return Err(ProgramError::InvalidArgument);
        }

        // Validate coordinates (assuming game board is 100x100)
        const MAX_COORDINATE: u32 = 100;
        for (i, &coord) in game_move.coordinates.iter().enumerate() {
            if coord > MAX_COORDINATE {
                msg!("Coordinate {} at index {} exceeds maximum {}", coord, i, MAX_COORDINATE);
                return Err(ProgramError::InvalidArgument);
            }
        }

        // Validate power (0-1000 range)
        const MAX_POWER: u16 = 1000;
        if game_move.power > MAX_POWER {
            msg!("Power {} exceeds maximum {}", game_move.power, MAX_POWER);
            return Err(ProgramError::InvalidArgument);
        }

        // Validate target player
        if game_move.target_player >= max_players {
            msg!("Target player {} exceeds maximum {}", game_move.target_player, max_players);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn validate_string_length(s: &str, max_length: usize, field_name: &str) -> Result<(), ProgramError> {
        if s.len() > max_length {
            msg!("{} length {} exceeds maximum {}", field_name, s.len(), max_length);
            return Err(ProgramError::InvalidArgument);
        }

        // Check for null bytes
        if s.contains('\0') {
            msg!("{} contains null bytes", field_name);
            return Err(ProgramError::InvalidArgument);
        }

        // Check for control characters
        if s.chars().any(|c| c.is_control()) {
            msg!("{} contains control characters", field_name);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn validate_buffer_size(buffer: &[u8], max_size: usize, buffer_name: &str) -> Result<(), ProgramError> {
        if buffer.len() > max_size {
            msg!("{} size {} exceeds maximum {}", buffer_name, buffer.len(), max_size);
            return Err(ProgramError::InvalidArgument);
        }

        Ok(())
    }

    pub fn safe_array_access<T>(array: &[T], index: usize, array_name: &str) -> Result<&T, ProgramError> {
        array.get(index).ok_or_else(|| {
            msg!("Index {} out of bounds for {} (length: {})", index, array_name, array.len());
            ProgramError::InvalidArgument
        })
    }
}

// Secure implementations using validation framework
pub fn secure_process_player_action(
    accounts: &[AccountInfo],
    player_index: u32,
    action_type: u8,
    action_data: &[u8]
) -> ProgramResult {
    use secure_validation::*;

    // Validate action_data size first
    validate_buffer_size(action_data, MAX_ACTION_DATA_SIZE, "action_data")?;

    // Validate action type
    if action_type == 0 || action_type > 5 {
        msg!("Invalid action type: {}", action_type);
        return Err(ProgramError::InvalidArgument);
    }

    // Safe array access with bounds checking
    let validated_index = validate_player_index(player_index, MAX_PLAYERS)?;
    let player_account = safe_array_access(accounts, validated_index, "accounts")?;

    // Process validated action
    match action_type {
        1 => secure_process_move_action(player_account, action_data)?,
        2 => secure_process_bet_action(player_account, action_data)?,
        3 => secure_process_special_action(player_account, action_data)?,
        4 => secure_process_defense_action(player_account, action_data)?,
        5 => secure_process_surrender_action(player_account, action_data)?,
        _ => return Err(ProgramError::InvalidArgument), // This shouldn't happen due to earlier check
    }

    msg!("Player action processed securely");
    Ok(())
}

pub fn secure_place_bet(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    use secure_validation::*;

    // Validate instruction data size
    if instruction_data.len() != 8 {
        msg!("Invalid instruction data size: {} (expected: 8)", instruction_data.len());
        return Err(ProgramError::InvalidInstructionData);
    }

    // Safe deserialization
    let bet_amount = u64::from_le_bytes(
        instruction_data[0..8].try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?
    );

    // Validate bet amount
    let validated_amount = validate_bet_amount(bet_amount)?;

    // Load and validate game config
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let config_account = &accounts[1];
    let config = GameConfig::try_from_slice(&config_account.data.borrow())?;
    validate_game_config(&config)?;

    // Additional validation against config
    if validated_amount < config.min_bet || validated_amount > config.max_bet {
        msg!("Bet amount {} outside config range ({}-{})",
             validated_amount, config.min_bet, config.max_bet);
        return Err(ProgramError::InvalidArgument);
    }

    // Process validated bet
    secure_process_bet_placement(validated_amount)?;

    msg!("Bet placed securely: {}", validated_amount);
    Ok(())
}

pub fn secure_execute_game_move(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    use secure_validation::*;

    // Validate instruction data size before deserialization
    if instruction_data.is_empty() || instruction_data.len() > 1024 {
        msg!("Invalid instruction data size: {}", instruction_data.len());
        return Err(ProgramError::InvalidInstructionData);
    }

    // Safe deserialization
    let game_move = GameMove::try_from_slice(instruction_data)
        .map_err(|_| {
            msg!("Failed to deserialize GameMove");
            ProgramError::InvalidInstructionData
        })?;

    // Validate move parameters
    validate_game_move(&game_move, MAX_PLAYERS)?;

    // Process validated move
    match game_move.move_type {
        1 => secure_execute_attack_move(&game_move)?,
        2 => secure_execute_defense_move(&game_move)?,
        3 => secure_execute_special_move(&game_move)?,
        4 => secure_execute_heal_move(&game_move)?,
        5 => secure_execute_boost_move(&game_move)?,
        _ => {
            msg!("Unsupported move type after validation: {}", game_move.move_type);
            return Err(ProgramError::InvalidArgument);
        }
    }

    msg!("Game move executed securely");
    Ok(())
}

pub fn secure_update_player_profile(
    accounts: &[AccountInfo],
    instruction_data: &[u8]
) -> ProgramResult {
    use secure_validation::*;

    // Validate instruction data size
    validate_buffer_size(instruction_data, 10240, "instruction_data")?; // 10KB max

    // Safe deserialization
    let profile = PlayerProfile::try_from_slice(instruction_data)
        .map_err(|_| {
            msg!("Failed to deserialize PlayerProfile");
            ProgramError::InvalidInstructionData
        })?;

    // Validate profile fields
    validate_string_length(&profile.username, MAX_USERNAME_LENGTH, "username")?;
    validate_string_length(&profile.bio, MAX_BIO_LENGTH, "bio")?;
    validate_buffer_size(&profile.custom_data, MAX_CUSTOM_DATA_SIZE, "custom_data")?;

    // Additional username validation
    if profile.username.trim().is_empty() {
        msg!("Username cannot be empty or whitespace only");
        return Err(ProgramError::InvalidArgument);
    }

    // Check for valid UTF-8 and reasonable characters
    if !profile.username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        msg!("Username contains invalid characters");
        return Err(ProgramError::InvalidArgument);
    }

    // Save validated profile
    let player_account = next_account_info(&mut accounts.iter())?;

    // Check account size can accommodate the data
    let serialized_size = bincode::serialized_size(&profile)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if serialized_size as usize > player_account.data.borrow().len() {
        msg!("Profile data too large for account");
        return Err(ProgramError::AccountDataTooSmall);
    }

    profile.serialize(&mut &mut player_account.data.borrow_mut()[..])?;

    msg!("Player profile updated securely");
    Ok(())
}

pub fn secure_update_game_config(
    accounts: &[AccountInfo],
    new_max_players: u32,
    new_min_bet: u64,
    new_max_bet: u64,
    new_duration: i64
) -> ProgramResult {
    use secure_validation::*;

    // Create and validate new configuration
    let new_config = GameConfig {
        max_players: new_max_players,
        min_bet: new_min_bet,
        max_bet: new_max_bet,
        game_duration: new_duration,
    };

    // Comprehensive validation
    validate_game_config(&new_config)?;

    // Additional business logic validation
    if new_config.max_players < 2 {
        msg!("Games require at least 2 players");
        return Err(ProgramError::InvalidArgument);
    }

    // Save validated configuration
    let config_account = next_account_info(&mut accounts.iter())?;
    new_config.serialize(&mut &mut config_account.data.borrow_mut()[..])?;

    msg!("Game configuration updated securely");
    Ok(())
}

// Secure helper functions
fn secure_process_move_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    // Validate action_data specific to move actions
    if action_data.len() != 16 { // Expected size for move data
        return Err(ProgramError::InvalidInstructionData);
    }

    msg!("Move action processed securely");
    Ok(())
}

fn secure_process_bet_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    // Validate action_data specific to bet actions
    if action_data.len() != 8 { // Expected size for bet amount
        return Err(ProgramError::InvalidInstructionData);
    }

    msg!("Bet action processed securely");
    Ok(())
}

fn secure_process_special_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    msg!("Special action processed securely");
    Ok(())
}

fn secure_process_defense_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    msg!("Defense action processed securely");
    Ok(())
}

fn secure_process_surrender_action(player_account: &AccountInfo, action_data: &[u8]) -> ProgramResult {
    msg!("Surrender action processed securely");
    Ok(())
}

fn secure_process_bet_placement(amount: u64) -> ProgramResult {
    msg!("Processing validated bet of {}", amount);
    Ok(())
}

fn secure_execute_attack_move(game_move: &GameMove) -> ProgramResult {
    msg!("Executing validated attack move at {:?} with power {}",
         game_move.coordinates, game_move.power);
    Ok(())
}

fn secure_execute_defense_move(game_move: &GameMove) -> ProgramResult {
    msg!("Executing validated defense move");
    Ok(())
}

fn secure_execute_special_move(game_move: &GameMove) -> ProgramResult {
    msg!("Executing validated special move");
    Ok(())
}

fn secure_execute_heal_move(game_move: &GameMove) -> ProgramResult {
    msg!("Executing validated heal move");
    Ok(())
}

fn secure_execute_boost_move(game_move: &GameMove) -> ProgramResult {
    msg!("Executing validated boost move");
    Ok(())
}

#[cfg(test)]
mod secure_validation_tests {
    use super::*;
    use super::secure_validation::*;

    #[test]
    fn test_bet_amount_validation() {
        // Valid amounts
        assert!(validate_bet_amount(100).is_ok());
        assert!(validate_bet_amount(MAX_BET_AMOUNT).is_ok());
        assert!(validate_bet_amount(MIN_BET_AMOUNT).is_ok());

        // Invalid amounts
        assert!(validate_bet_amount(0).is_err());
        assert!(validate_bet_amount(MAX_BET_AMOUNT + 1).is_err());
    }

    #[test]
    fn test_game_config_validation() {
        // Valid config
        let valid_config = GameConfig {
            max_players: 10,
            min_bet: 100,
            max_bet: 1000,
            game_duration: 3600,
        };
        assert!(validate_game_config(&valid_config).is_ok());

        // Invalid config - min_bet > max_bet
        let invalid_config = GameConfig {
            max_players: 10,
            min_bet: 1000,
            max_bet: 100,
            game_duration: 3600,
        };
        assert!(validate_game_config(&invalid_config).is_err());

        // Invalid config - zero players
        let zero_players_config = GameConfig {
            max_players: 0,
            min_bet: 100,
            max_bet: 1000,
            game_duration: 3600,
        };
        assert!(validate_game_config(&zero_players_config).is_err());
    }

    #[test]
    fn test_string_validation() {
        // Valid strings
        assert!(validate_string_length("username", MAX_USERNAME_LENGTH, "username").is_ok());
        assert!(validate_string_length("", MAX_USERNAME_LENGTH, "username").is_ok());

        // Invalid strings
        let too_long = "a".repeat(MAX_USERNAME_LENGTH + 1);
        assert!(validate_string_length(&too_long, MAX_USERNAME_LENGTH, "username").is_err());

        let with_null = "user\0name";
        assert!(validate_string_length(with_null, MAX_USERNAME_LENGTH, "username").is_err());
    }

    #[test]
    fn test_safe_array_access() {
        let test_array = [1, 2, 3, 4, 5];

        // Valid access
        assert!(safe_array_access(&test_array, 0, "test").is_ok());
        assert!(safe_array_access(&test_array, 4, "test").is_ok());

        // Invalid access
        assert!(safe_array_access(&test_array, 5, "test").is_err());
        assert!(safe_array_access(&test_array, 100, "test").is_err());
    }
}
```

## Testing Requirements

### Comprehensive Input Validation Testing

```bash
# Test input validation framework
cargo test --release test_input_validation_framework
cargo test --release test_parameter_range_validation
cargo test --release test_string_validation
cargo test --release test_buffer_size_validation

# Test edge cases and boundary conditions
cargo test --release test_boundary_conditions
cargo test --release test_integer_overflow_protection
cargo test --release test_array_bounds_protection

# Fuzz testing with malicious inputs
cargo fuzz run input_validation -- -max_len=10000

# Integration testing with malformed data
cargo test --release integration_malformed_inputs
```

### Security Validation Checklist

- **Range Validation**: All numeric inputs within acceptable ranges
- **Size Limits**: All strings and buffers have maximum size limits
- **Array Bounds**: All array access uses bounds checking
- **Type Validation**: All enums and types validated before use
- **Business Logic**: Validation includes business rule enforcement
- **Error Handling**: Clear error messages for validation failures

## Business Impact

### Risk Assessment

**Direct Impacts**:
- **Game Logic Bypass**: Players gain unfair advantages
- **Parameter Manipulation**: Game settings corrupted
- **State Corruption**: Invalid data breaks game functionality
- **Resource Exhaustion**: Large inputs cause DoS

**Secondary Impacts**:
- **Player Trust**: Unfair advantages undermine game integrity
- **Operational Issues**: Invalid configurations break games
- **Performance Degradation**: Large inputs affect system performance
- **Data Integrity**: Corrupted game state affects all players

### Remediation Priority: HIGH

Input validation is fundamental to application security. While not as immediately critical as authentication or financial vulnerabilities, poor input validation enables many other attack vectors and should be addressed promptly.

## References

- **CWE-20**: Improper Input Validation
- **CWE-129**: Improper Validation of Array Index
- **OWASP Input Validation**: Best practices for secure input handling
- **Rust Security**: Safe programming practices in Rust
- **Solana Security**: Input validation in blockchain programs