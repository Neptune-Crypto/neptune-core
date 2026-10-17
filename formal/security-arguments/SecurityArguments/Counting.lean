/-!
# Counting primitives

Core Lean has no `Finset`, so cardinalities are defined by explicit recursion:
`countBelow N P` is the number of `x < N` with `P x`, and `sumBelow N f` is
`∑_{x<N} f x`. Every probability in this library is a ratio of such counts
(uniform sampling), and every bound is proved about these definitions.
-/

namespace SecurityArguments

/-- Number of `x < N` with `P x`. -/
def countBelow : Nat → (Nat → Bool) → Nat
  | 0, _ => 0
  | n + 1, P => countBelow n P + (P n).toNat

/-- `∑_{x<N} f x`. -/
def sumBelow : Nat → (Nat → Nat) → Nat
  | 0, _ => 0
  | n + 1, f => sumBelow n f + f n

theorem countBelow_add (a b : Nat) (P : Nat → Bool) :
    countBelow (a + b) P = countBelow a P + countBelow b (fun x => P (a + x)) := by
  induction b with
  | zero => rfl
  | succ b ih =>
      rw [← Nat.add_assoc]; simp only [countBelow]; rw [ih]; omega

theorem countBelow_congr (N : Nat) (P Q : Nat → Bool) (h : ∀ x, x < N → P x = Q x) :
    countBelow N P = countBelow N Q := by
  induction N with
  | zero => rfl
  | succ n ih =>
      simp only [countBelow]
      rw [ih (fun x hx => h x (by omega)), h n (by omega)]

theorem countBelow_le (N : Nat) (P : Nat → Bool) : countBelow N P ≤ N := by
  induction N with
  | zero => exact Nat.le_refl 0
  | succ n ih => simp only [countBelow]; cases P n <;> simp <;> omega

theorem countBelow_mono (N : Nat) (P Q : Nat → Bool) (h : ∀ x, P x = true → Q x = true) :
    countBelow N P ≤ countBelow N Q := by
  induction N with
  | zero => exact Nat.le_refl 0
  | succ n ih =>
      simp only [countBelow]
      cases hp : P n
      · simp; omega
      · simp [h n hp]; omega

/-- Union bound for counts. -/
theorem countBelow_or (N : Nat) (P Q : Nat → Bool) :
    countBelow N (fun x => P x || Q x) ≤ countBelow N P + countBelow N Q := by
  induction N with
  | zero => exact Nat.le_refl 0
  | succ n ih =>
      simp only [countBelow]
      cases P n <;> cases Q n <;> simp <;> omega

/-- The number of `x < N` in an interval `[L, L + K)` is at most `K`. -/
theorem countBelow_interval (N L K : Nat) :
    countBelow N (fun x => decide (L ≤ x ∧ x < L + K)) = min N (L + K) - min N L := by
  induction N with
  | zero => simp [countBelow]
  | succ n ih =>
      simp only [countBelow, ih]
      by_cases h : L ≤ n ∧ n < L + K
      · simp [h]; omega
      · simp [h]; omega

theorem countBelow_interval_le (N L K : Nat) :
    countBelow N (fun x => decide (L ≤ x ∧ x < L + K)) ≤ K := by
  rw [countBelow_interval]; omega

theorem sumBelow_ite (N c : Nat) (P : Nat → Bool) :
    sumBelow N (fun x => if P x then c else 0) = countBelow N P * c := by
  induction N with
  | zero => simp [sumBelow, countBelow]
  | succ n ih =>
      simp only [sumBelow, countBelow, ih, Nat.add_mul]
      cases P n <;> simp

theorem sumBelow_zero (N : Nat) : sumBelow N (fun _ => 0) = 0 := by
  induction N with
  | zero => rfl
  | succ n ih => simp [sumBelow, ih]

theorem countBelow_false (N : Nat) : countBelow N (fun _ => false) = 0 := by
  induction N with
  | zero => rfl
  | succ n ih => simp [countBelow, ih]

/-- A single point is counted once if it is below `N`. -/
theorem countBelow_single (a N : Nat) :
    countBelow N (fun x => decide (x = a)) = (decide (a < N)).toNat := by
  induction N with
  | zero => simp [countBelow]
  | succ n ih =>
      simp only [countBelow, ih]
      by_cases h1 : a < n
      · have h2 : n ≠ a := by omega
        have h3 : a < n + 1 := by omega
        simp [h1, h2, h3]
      · by_cases h2 : n = a
        · subst h2; simp
        · have h3 : ¬ a < n + 1 := by omega
          simp [h1, h2, h3]

/-- Counts add up for disjoint predicates. -/
theorem countBelow_or_disjoint (N : Nat) (P Q : Nat → Bool)
    (hd : ∀ x, ¬ (P x = true ∧ Q x = true)) :
    countBelow N (fun x => P x || Q x) = countBelow N P + countBelow N Q := by
  induction N with
  | zero => rfl
  | succ n ih =>
      simp only [countBelow, ih]
      have := hd n
      cases hp : P n <;> cases hq : Q n <;> simp_all <;> omega

end SecurityArguments
