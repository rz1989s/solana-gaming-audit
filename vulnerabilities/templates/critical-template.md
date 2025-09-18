# VUL-XXX: [Vulnerability Title]

## 🚨 Critical Vulnerability Summary

**Vulnerability ID**: VUL-XXX
**CVSS Score**: X.X/10.0 (Critical)
**CVSS Vector**: CVSS:3.1/AV:X/AC:X/PR:X/UI:X/S:X/C:X/I:X/A:X
**Discovery Date**: YYYY-MM-DD
**Status**: [New/Confirmed/Fix-Developed/Fixed/Closed]
**Reporter**: RECTOR

## 📍 Location & Scope

**Affected Files**:
- `path/to/file.rs:line-number`

**Affected Functions**:
- `function_name()`

**Contract Component**:
- [ ] Escrow System
- [ ] Access Control
- [ ] Game Logic
- [ ] Token Management
- [ ] PDA Security

## 🔍 Technical Analysis

### Root Cause
[Detailed explanation of what causes the vulnerability]

### Attack Vector
[How an attacker could exploit this vulnerability]

### Code Analysis
```rust
// Vulnerable code snippet
[Show the problematic code with line numbers]
```

**Issue**: [Explain what's wrong with the code]

## 💥 Impact Assessment

### Financial Impact
- **Potential Loss**: $XXX,XXX+ (or percentage of protocol funds)
- **Attack Cost**: $XXX (cost for attacker to execute)
- **ROI for Attacker**: XXX% (profit/cost ratio)

### Protocol Impact
- [ ] Complete fund drainage possible
- [ ] Protocol shutdown capability
- [ ] Arbitrary code execution
- [ ] Access control bypass

### User Impact
- [ ] Loss of user funds
- [ ] Game manipulation
- [ ] Unfair gameplay
- [ ] Data exposure

### Business Impact
- [ ] Reputation damage
- [ ] Regulatory concerns
- [ ] Competitive disadvantage
- [ ] Legal liability

## 🔬 Proof of Concept

### Attack Scenario
1. [Step-by-step attack description]
2. [Include specific actions/transactions]
3. [Show expected vs actual outcomes]

### Test Code
```rust
#[cfg(test)]
mod vulnerability_tests {
    use super::*;

    #[test]
    fn test_vul_xxx_exploit() {
        // Proof of concept test code
        // This should demonstrate the vulnerability
    }
}
```

### Expected vs Actual Behavior
- **Expected**: [What should happen]
- **Actual**: [What actually happens]
- **Difference**: [Impact of the difference]

## ⚡ Exploitability Analysis

**Likelihood**: [High/Medium/Low]
**Complexity**: [Low/Medium/High]
**Prerequisites**:
- [List required conditions]
- [Required access levels]
- [Environmental factors]

**Attack Vectors**:
- [ ] Direct transaction
- [ ] Flash loan attack
- [ ] Sandwich attack
- [ ] MEV exploitation
- [ ] Cross-program invocation

## 🔧 Remediation

### Recommended Fix
[Detailed description of the fix]

### Code Patch
```rust
// Fixed code
[Show the corrected code implementation]
```

### Implementation Steps
1. [Step 1 of implementation]
2. [Step 2 of implementation]
3. [Step 3 of implementation]

### Additional Security Measures
- [Supplementary security improvements]
- [Defense-in-depth recommendations]
- [Monitoring suggestions]

## ✅ Testing & Verification

### Test Cases Required
- [ ] Positive test: Fix prevents exploit
- [ ] Negative test: Original attack path blocked
- [ ] Edge case: [Specific edge case]
- [ ] Integration: Function still works normally

### Verification Script
```bash
# Commands to verify the fix
cargo test test_vul_xxx_fixed
cargo test test_normal_functionality
```

### Acceptance Criteria
- [ ] Vulnerability no longer exploitable
- [ ] Normal functionality preserved
- [ ] No new vulnerabilities introduced
- [ ] Performance impact minimal

## 🔗 References

### Internal References
- Related vulnerabilities: [VUL-XXX, VUL-XXY]
- Affected test cases: [test_name.rs]
- Documentation: [docs/security.md]

### External References
- [Solana Security Best Practices](URL)
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [Similar CVE References](URL)

### Code References
- Function definition: `file.rs:line`
- Related functions: `file.rs:line`
- Test files: `tests/test_file.rs`

## 📝 Notes

### Developer Notes
[Any implementation notes for developers]

### Audit Trail
- **Discovery Method**: [How was this found?]
- **Initial Assessment**: [First impression]
- **Follow-up Analysis**: [Deeper investigation results]

### Risk Assessment Timeline
- **Immediate Risk**: [Impact if not fixed in 24h]
- **Short-term Risk**: [Impact if not fixed in 1 week]
- **Long-term Risk**: [Impact if never fixed]

---

**Classification**: Critical
**Priority**: P0 - Fix Immediately
**Estimated Fix Time**: [Hours/Days]
**Review Required**: Security Team + Protocol Maintainers

*This vulnerability requires immediate attention due to its critical nature and potential for significant financial loss.*