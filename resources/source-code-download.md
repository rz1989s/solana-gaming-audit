# Source Code Download Instructions

## Google Drive Link
**URL**: https://drive.google.com/file/d/1YR2s9KgHiQMD--LmBWK_HGAo22gU1A9K/view?usp=sharing

## Manual Download Steps

1. **Access the Link**: Click the Google Drive URL above
2. **Download File**: Click the download button (should be a .rar file)
3. **Extract Contents**: Use your preferred extraction tool:
   ```bash
   # If you have unrar installed
   unrar x <filename>.rar

   # Or use built-in macOS Archive Utility
   # Double-click the .rar file
   ```
4. **Move to Project**: Copy extracted files to:
   ```
   solana-gaming-audit/resources/source-code/
   ```

## Alternative Download Methods

### Using wget/curl (if public)
```bash
# This may not work for Google Drive links that require authentication
wget --no-check-certificate 'https://drive.google.com/uc?export=download&id=1YR2s9KgHiQMD--LmBWK_HGAo22gU1A9K' -O source-code.rar
```

### Using gdown (Python tool)
```bash
# Install gdown
pip install gdown

# Download using file ID
gdown 1YR2s9KgHiQMD--LmBWK_HGAo22gU1A9K

# Extract
unrar x <downloaded-file>.rar
```

## Expected Contents

Based on the bounty description, the source code should contain:
- **Rust smart contracts** for the gaming protocol
- **Solana programs** handling:
  - Player matching
  - Escrow of funds
  - Payouts
  - Anti-abuse mechanics

## File Structure Analysis

Once downloaded, analyze the structure:
```bash
# List all files
find source-code/ -type f -name "*.rs" | head -20

# Check for key files
ls -la source-code/
```

## Key Files to Look For

- **lib.rs** or **main.rs** - Main entry points
- **Cargo.toml** - Rust dependencies and metadata
- **programs/** - Solana program directories
- **tests/** - Test files
- **instruction.rs** - Program instructions
- **state.rs** - Account state definitions
- **error.rs** - Custom error types

## Security Note

**Verify file integrity** before proceeding:
- Check file size and format
- Scan for any suspicious content
- Validate it's legitimate Rust/Solana code

## Next Steps After Download

1. **Copy files** to `resources/source-code/`
2. **Initial analysis** of project structure
3. **Dependency review** via Cargo.toml
4. **Code organization** understanding
5. **Begin security audit** process

---

**Status**: Manual download required
**Priority**: High - needed for audit progression
**Updated**: September 18, 2025

*Note: The source code is essential for the audit. Please download manually and extract to the resources/source-code/ directory.*