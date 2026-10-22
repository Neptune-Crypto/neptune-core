/-!
# Proof-system parameters used by Neptune Cash

Neptune verifies every consensus proof with `Stark::default()`
(`neptune-consensus/src/proof_abstractions/verifier.rs`,
`.../tasm/program.rs`, `.../tasm/builtins.rs`). In triton-vm 9.0.0
(`triton-vm/src/stark.rs`):

```rust
impl Default for Stark {
    fn default() -> Self {
        let log_2_of_fri_expansion_factor = 2;
        let security_level = 160;
        Self::new(security_level, log_2_of_fri_expansion_factor)
    }
}
// in Stark::new:
let num_collinearity_checks = security_level / log2_of_fri_expansion_factor;
let num_collinearity_checks = std::cmp::max(num_collinearity_checks, 1);
```
-/

namespace SecurityArguments

/-- The Oxfoi prime `p = 2^64 - 2^32 + 1`. -/
def p : Nat := 18446744069414584321

theorem p_eq : p = 2 ^ 64 - 2 ^ 32 + 1 := by decide

/-- Degree of the extension field `F_{p^3}` used for verifier challenges. -/
abbrev extensionDegree : Nat := 3

/-- `Stark::default().security_level`: conjectured bits of security. -/
abbrev securityLevel : Nat := 160

/-- `log2_of_fri_expansion_factor` in `Stark::default()`. -/
abbrev log2Expansion : Nat := 2

/-- Model of the collinearity-check count computed by `Stark::new`. -/
def numCollinearityChecks (securityLevel log2Expansion : Nat) : Nat :=
  max (securityLevel / log2Expansion) 1

/-- The count Neptune actually uses. -/
theorem neptune_num_checks : numCollinearityChecks securityLevel log2Expansion = 80 := by decide

end SecurityArguments
