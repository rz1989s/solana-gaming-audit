# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **security audit project** for a Solana-based competitive FPS gaming protocol with Win-2-Earn mechanics. Players stake tokens before matches, and winners take all escrowed funds. The audit focuses on fund security, game logic integrity, and anti-abuse systems.

**Critical Context**: This is NOT a traditional development project - it's a security bounty submission for PrimeSkill Studio with a deadline of September 26, 2025.

## Key Commands

### Prerequisites Setup
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/stable/install)"

# Install Anchor framework
npm install -g @coral-xyz/anchor-cli
```

### Source Code Management
```bash
# Source code must be manually downloaded from Google Drive
# See: resources/source-code-download.md for instructions
# URL: https://drive.google.com/file/d/1YR2s9KgHiQMD--LmBWK_HGAo22gU1A9K/view

# After download, extract to:
# resources/source-code/

# Analyze project structure
find resources/source-code/ -name "*.rs" | head -20
ls -la resources/source-code/
```

### Testing and Analysis Commands
```bash
# Build Rust project (once source code is available)
cd resources/source-code/
cargo build

# Run tests
cargo test

# Static analysis
cargo clippy
cargo audit

# Start local Solana validator for testing
solana-test-validator

# Check program with anchor (if applicable)
anchor build
anchor test
```

### Audit-Specific Commands
```bash
# Generate audit report
# Custom scripts will be in src/tools/

# Run security test suite
# Tests will be in src/tests/

# Performance analysis
solana-bench-tps
```

## Repository Architecture

### Directory Structure
```
solana-gaming-audit/
├── README.md                    # Project overview and setup
├── bounty-analysis.md          # Strategic audit analysis
├── project-status.md           # Current progress tracking
├── resources/                  # External materials
│   ├── source-code/           # Downloaded Solana contracts (manual)
│   ├── references.md          # Security and development resources
│   ├── flow-diagram.md        # Protocol architecture analysis
│   └── source-code-download.md # Download instructions
├── src/                       # Audit implementation workspace
│   ├── audit-report/          # Generated documentation
│   ├── tests/                 # Security test suites
│   ├── improvements/          # Enhanced contract implementations
│   └── tools/                 # Audit automation scripts
└── docs/                      # Final deliverables
```

### Core Components (Based on Protocol Analysis)

**Critical Security Areas**:
1. **Escrow System** - Fund locking/release mechanism (HIGHEST PRIORITY)
2. **Winner Determination** - Game result validation and payout logic
3. **Anti-Abuse Mechanics** - Fraud prevention and fair play enforcement
4. **Access Control** - Solana account ownership and PDA security

## Working with This Codebase

### Security Audit Workflow
1. **Static Analysis**: Review smart contract code for vulnerability patterns
2. **Dynamic Testing**: Develop attack simulations and edge case tests
3. **Documentation**: Create professional audit reports with severity ratings
4. **Improvements**: Implement security fixes and optimizations

### Key Security Patterns to Check
- **Re-entrancy Protection**: Cross-program invocation safety
- **Access Control**: Proper signer verification and account ownership
- **Integer Overflow/Underflow**: Safe arithmetic in stake calculations
- **PDA Security**: Correct Program Derived Address usage
- **Race Conditions**: Concurrent operation safety
- **Economic Attacks**: Flash loan and manipulation resistance

### Solana-Specific Considerations
- **Account Validation**: Verify account ownership before operations
- **Compute Budget**: Optimize for gas efficiency and prevent DoS
- **Cross-Program Invocation**: Safe inter-program communication
- **Account Size Limits**: Manage data storage constraints
- **Clock/Slot Usage**: Proper timing and randomness handling

## Development Environment

### Required Tools
- **Rust**: Smart contract language
- **Solana CLI**: Blockchain interaction
- **Anchor Framework**: Development framework (if used)
- **VS Code**: Recommended IDE with Rust extension

### Testing Environment
```bash
# Local development
solana config set --url localhost
solana-test-validator

# Devnet testing
solana config set --url devnet

# Check current configuration
solana config get
```

## Important Context

### Project Goals
- **Primary**: Win 750 USDC bounty (1st: 500 USDC, 2nd: 250 USDC)
- **Secondary**: Establish long-term partnership with PrimeSkill Studio
- **Deliverables**: Comprehensive audit report, security tests, improved implementations

### Critical Success Factors
- **Fund Security**: Escrow mechanism must be bulletproof
- **Professional Quality**: Industry-standard audit documentation
- **Practical Solutions**: Working fixes, not just problem identification
- **Competitive Edge**: Superior depth compared to other submissions

### Risk Areas by Priority
1. **Escrow Vulnerabilities** (Critical)
2. **Game Logic Integrity** (High)
3. **Anti-Abuse Effectiveness** (High)
4. **Performance Optimization** (Medium)
5. **User Experience** (Low)

## Contact and Resources

- **Bounty URL**: https://earn.superteam.fun/listing/smart-contract-improvement-and-audit-for-gaming-protocol
- **Sponsor Contact**: https://t.me/dimiprimeskilltg
- **Flow Diagram**: See resources/flow-diagram.md
- **Security References**: See resources/references.md

## Notes for Claude Code

- **Source Code Status**: Must be manually downloaded (see resources/source-code-download.md)
- **Time Sensitive**: Bounty deadline September 26, 2025
- **Security Focus**: This is primarily security analysis, not feature development
- **Documentation Standard**: Professional audit report format required
- **Competition**: Multiple submissions already exist - quality differentiation crucial

When working on this project, prioritize security analysis over feature development. Always consider the financial implications of vulnerabilities in an escrow-based gaming system.