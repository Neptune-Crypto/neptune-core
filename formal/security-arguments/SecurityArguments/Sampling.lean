import SecurityArguments.Params
import SecurityArguments.Counting

/-!
# SA-3: Exact uniformity of Bloom-filter index sampling

twenty-first 3.0.0, `Tip5::sample_indices` (`twenty-first/src/tip5/mod.rs`):

```rust
assert!(upper_bound.is_power_of_two());
...
if element != const { BFieldElement::new(BFieldElement::MAX) } {
    indices.push(element.value() as u32 % upper_bound);
}
```

`BFieldElement::MAX = p - 1`. Each squeezed field element is therefore either
rejected (if it equals `p - 1`) or mapped to `(value mod 2^32) mod 2^20`. The
mutator set calls this with `upper_bound = WINDOW_SIZE = 2^20`.

**Result.** Because `2^20` divides `p - 1 = 2^64 - 2^32`, every index
`r < 2^20` has exactly `2^44 - 2^12` accepted preimages. If the squeezed
elements are uniform (random-oracle model of Tip5), the sampled indices are
*exactly* uniform: no modulo bias at all. Without the rejection step, index 0
would have one extra preimage.
-/

namespace SecurityArguments

/-- **Residue counting.** If `m > 0` and `r < m`, then among `x < q · m`
exactly `q` satisfy `x mod m = r`. -/
theorem count_residue (m r : Nat) (_hm : 0 < m) (hr : r < m) :
    ∀ q, countBelow (q * m) (fun x => x % m == r) = q := by
  have base : ∀ n, n ≤ m → countBelow n (fun x => x % m == r) = if r < n then 1 else 0 := by
    intro n
    induction n with
    | zero => intro _; simp [countBelow]
    | succ n ih =>
        intro hn
        simp only [countBelow, ih (by omega), Nat.mod_eq_of_lt (show n < m by omega)]
        by_cases h1 : r < n
        · have : (n == r) = false := by simp; omega
          simp [h1, this]; omega
        · by_cases h2 : n = r
          · subst h2; simp
          · have : (n == r) = false := by simp; omega
            simp [h1, this]; omega
  intro q
  induction q with
  | zero => simp [countBelow]
  | succ q ih =>
      rw [Nat.succ_mul, countBelow_add, ih]
      have hshift : countBelow m (fun x => (q * m + x) % m == r) = countBelow m (fun x => x % m == r) :=
        countBelow_congr m _ _ (fun x _ => by rw [Nat.mul_comm, Nat.mul_add_mod])
      rw [hshift, base m (Nat.le_refl m)]
      simp [hr]

/-- Number of accepted field elements, `p - 1` (all except `BFieldElement::MAX`). -/
@[irreducible] def numAccepted : Nat := p - 1

/-- `2^20` divides `p - 1`: `p - 1 = (2^44 - 2^12) · 2^20`. -/
theorem accepted_split : numAccepted = (2 ^ 44 - 2 ^ 12) * 2 ^ 20 := by
  simp only [numAccepted, p]

/-- `value as u32 % 2^20` equals `value mod 2^20`. -/
theorem truncate_then_mod (v : Nat) : v % 2 ^ 32 % 2 ^ 20 = v % 2 ^ 20 := by
  show v % 4294967296 % 1048576 = v % 1048576
  omega

/-- **SA-3a (exact uniformity).** Every Bloom-filter index `r < 2^20` is the
image of exactly `2^44 - 2^12` accepted field elements. -/
theorem sample_index_exactly_uniform (r : Nat) (hr : r < 2 ^ 20) :
    countBelow numAccepted (fun v => v % 2 ^ 32 % 2 ^ 20 == r) = 2 ^ 44 - 2 ^ 12 := by
  rw [countBelow_congr numAccepted _ (fun v => v % 2 ^ 20 == r)
        (fun v _ => by rw [truncate_then_mod])]
  rw [accepted_split]
  exact count_residue (2 ^ 20) r (by decide) hr (2 ^ 44 - 2 ^ 12)

/-- `p = numAccepted + 1`: the rejected element is the single extra one. -/
theorem p_eq_accepted_succ : p = (2 ^ 44 - 2 ^ 12) * 2 ^ 20 + 1 := by simp only [p]

/-- Without rejection, residue `0` gets one extra preimage (general form). -/
theorem count_residue_zero_plus_one (m q : Nat) (hm : 0 < m) :
    countBelow (q * m + 1) (fun v => v % m == 0) = q + 1 := by
  rw [countBelow_add, count_residue m 0 hm hm q]
  simp [countBelow, Nat.mul_mod_left]

/-- **SA-3b (why the rejection matters).** Over all `p` field elements
(`p = (2^44 - 2^12) · 2^20 + 1`), without rejecting `p - 1`, index `0` would
receive `2^44 - 2^12 + 1` preimages instead of `2^44 - 2^12`. -/
theorem without_rejection_zero_is_biased :
    countBelow ((2 ^ 44 - 2 ^ 12) * 2 ^ 20 + 1) (fun v => v % 2 ^ 20 == 0) = (2 ^ 44 - 2 ^ 12) + 1 :=
  count_residue_zero_plus_one (2 ^ 20) (2 ^ 44 - 2 ^ 12) (by decide)

end SecurityArguments
