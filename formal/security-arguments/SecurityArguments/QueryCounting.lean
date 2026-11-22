import SecurityArguments.Params

/-!
# SA-1: Query counting for FRI

FRI's query phase performs `q` independent collinearity checks. Against a
committed function that is far from every low-degree polynomial, each check
passes with probability at most `ε`, so all `q` pass with probability at most
`ε^q`. With rate `ρ = 1 / 2^k` (expansion factor `2^k`):

* **Conjectured regime** (proximity gaps up to list-decoding capacity, the
  assumption behind Triton VM's stated security level): `ε = ρ`, so the query
  phase contributes `q · k` bits.
* **Provable regime** (unique-decoding / Johnson-bound analyses): `ε ≈ √ρ`, so
  it contributes about `q · k / 2` bits.

Probabilities are expressed as fractions `num / den`, and `num/den ≤ 2^-b` is
written `num · 2^b ≤ den`, so everything is natural-number arithmetic.

Scope: this counts the **query phase only**. Commit-phase (folding challenge)
errors, the DEEP / out-of-domain sampling error and Fiat–Shamir grinding are
separate terms, not covered here.
-/

namespace SecurityArguments

/-- Bits contributed by `q` queries when each query has error `2^-bitsPerQuery`. -/
def queryBits (q bitsPerQuery : Nat) : Nat := q * bitsPerQuery

/-- **SA-1a.** `Stark::new` never loses more than `k - 1` bits to rounding:
the conjectured query-phase security is at least `λ - (k - 1)`. -/
theorem query_bits_floor_loss (lam k : Nat) (hk : 0 < k) :
    lam - (k - 1) ≤ queryBits (numCollinearityChecks lam k) k := by
  unfold queryBits numCollinearityChecks
  have h := Nat.div_add_mod lam k
  have hm := Nat.mod_lt lam hk
  have h1 : k * (lam / k) ≤ max (lam / k) 1 * k := by
    rw [Nat.mul_comm k]; exact Nat.mul_le_mul_right k (Nat.le_max_left _ _)
  generalize k * (lam / k) = A at h h1
  generalize max (lam / k) 1 * k = Bv at h1 ⊢
  omega

/-- **SA-1b.** For Neptune's parameters the conjectured query-phase error is
exactly `(1/4)^80 = 2^-160`, matching `security_level`. -/
theorem neptune_conjectured_query_error :
    (1 : Nat) * 2 ^ securityLevel = 4 ^ numCollinearityChecks securityLevel log2Expansion := by
  decide

/-- **SA-1c.** In the provable regime the same 80 queries give per-query
error `√(1/4) = 1/2`, i.e. a query-phase error of `2^-80`. -/
theorem neptune_provable_query_bits :
    queryBits (numCollinearityChecks securityLevel log2Expansion) log2Expansion / 2 = 80 := by
  decide

/-- **SA-1d.** Verifier challenges live in `F_{p^3}`, which has more than
`2^191` elements; a single challenge that must hit one of `d` bad values does
so with probability below `d / 2^191`. -/
theorem extension_field_size : 2 ^ 191 < p ^ extensionDegree := by decide

end SecurityArguments
