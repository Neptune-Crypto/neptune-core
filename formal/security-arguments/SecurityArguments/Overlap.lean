import SecurityArguments.Counting

/-!
# SA-4: Privacy overlap and false-positive bound for the mutator set

A Bloom filter has false positives: a UTXO that was never spent could find
all 45 of its bits already set by other removals, and then appear spent (it
could no longer be spent). This is a liveness failure, never an inflation or
theft failure, but it must be negligible.

The argument has three layers, all proved here:

1. **Structure (SA-4a, SA-4b).** By the window lemma (MS-W in
   `formal/mutator-set`), an output at AOCL index `j` only sets bits inside
   the window of its own batch, `[⌊j/8⌋·2^12, ⌊j/8⌋·2^12 + 2^20)`. Two windows
   overlap only if their batches differ by at most 255, so at most
   `511 · 8 = 4088` distinct outputs can set bits in any given window.
2. **Union bound (SA-4c).** Each removal sets at most 45 bits, so at most
   `45 · 4088 = 183,960` of the window's `2^20` bits are ever set.
3. **Tuple counting (SA-4d, SA-4e).** A fresh output's 45 indices are uniform
   in its window (SA-3, random-oracle model of Tip5). The number of 45-tuples
   lying entirely inside the set bits is `s^45` out of `(2^20)^45`, and with
   `s ≤ 183,960` this fraction is below `2^-112`.

The bound holds for *every* history of spends; no assumption on load or on
honest behaviour of other users is needed.
-/

namespace SecurityArguments

/-- `WINDOW_SIZE`, `CHUNK_SIZE`, `BATCH_SIZE`, `NUM_TRIALS`
(`neptune-mutator-set/src/shared.rs`), as in `formal/mutator-set`. -/
abbrev W : Nat := 1048576
abbrev C : Nat := 4096
abbrev B : Nat := 8
abbrev NumTrials : Nat := 45

/-! ### Layer 1: which outputs can touch a window -/

/-- **SA-4a (window overlap).** If a bit lies in the windows of batches `b`
and `b'`, then the batches differ by at most 255. -/
theorem window_overlap (b b' a : Nat)
    (h1 : b' * C ≤ a ∧ a < b' * C + W) (h2 : b * C ≤ a ∧ a < b * C + W) :
    b ≤ b' + 255 ∧ b' ≤ b + 255 := by
  simp only [C, W] at *; omega

/-- The outputs whose batch is within 255 of `b` occupy an interval of
4088 AOCL positions starting at `(b - 255) · 8` (saturating). -/
theorem near_batch_interval (b j : Nat) (h : b ≤ j / B + 255 ∧ j / B ≤ b + 255) :
    (b - 255) * B ≤ j ∧ j < (b - 255) * B + 4088 := by
  simp only [B] at *; omega

/-- A duplicate-free list of naturals inside `[L, L + K)` has at most `K`
elements (pigeonhole, proved with the counting primitives). -/
theorem nodup_interval_length_le (L K : Nat) :
    ∀ (l : List Nat), l.Nodup → (∀ x ∈ l, L ≤ x ∧ x < L + K) → l.length ≤ K := by
  have hcount : ∀ (l : List Nat), l.Nodup → ∀ N, (∀ x ∈ l, x < N) →
      countBelow N (fun x => decide (x ∈ l)) = l.length := by
    intro l
    induction l with
    | nil =>
      intro _ N _
      rw [countBelow_congr N _ (fun _ => false) (fun x _ => by simp), countBelow_false]; rfl
    | cons a t ih =>
      intro hnd N hlt
      have ha : a ∉ t := (List.nodup_cons.mp hnd).1
      have ht : t.Nodup := (List.nodup_cons.mp hnd).2
      have ihN := ih ht N (fun x hx => hlt x (List.mem_cons_of_mem a hx))
      have haN : a < N := hlt a List.mem_cons_self
      rw [countBelow_congr N _ (fun x => decide (x = a) || decide (x ∈ t)) (fun x _ => by simp [List.mem_cons])]
      rw [countBelow_or_disjoint N _ _ (fun x h => by simp at h; exact ha (h.1 ▸ h.2))]
      rw [countBelow_single, ihN]; simp [haN]; omega
  intro l hnd hin
  have h1 := hcount l hnd (L + K) (fun x hx => (hin x hx).2)
  have h2 : countBelow (L + K) (fun x => decide (x ∈ l)) ≤
      countBelow (L + K) (fun x => decide (L ≤ x ∧ x < L + K)) :=
    countBelow_mono _ _ _ (fun x hx => by simp at hx ⊢; exact hin x hx)
  have h3 := countBelow_interval_le (L + K) L K
  omega

/-- **SA-4b (at most 4088 contributors).** Given distinct AOCL positions,
each of whose batch is within 255 of `b`, there are at most 4088 of them. -/
theorem contributors_le (b : Nat) (pos : List Nat) (hnd : pos.Nodup)
    (hnear : ∀ j ∈ pos, b ≤ j / B + 255 ∧ j / B ≤ b + 255) : pos.length ≤ 4088 :=
  nodup_interval_length_le ((b - 255) * B) 4088 pos hnd
    (fun j hj => near_batch_interval b j (hnear j hj))

/-! ### Layer 2: union bound on set bits -/

/-- Bits set by a list of removal records (each a list of absolute indices). -/
def setBits (records : List (List Nat)) (x : Nat) : Bool :=
  records.any (fun r => decide (x ∈ r))

theorem count_mem_le (N : Nat) : ∀ (r : List Nat), countBelow N (fun x => decide (x ∈ r)) ≤ r.length
  | [] => by
      rw [countBelow_congr N _ (fun _ => false) (fun x _ => by simp), countBelow_false]; simp
  | a :: t => by
      rw [countBelow_congr N _ (fun x => decide (x = a) || decide (x ∈ t)) (fun x _ => by simp [List.mem_cons])]
      have hor := countBelow_or N (fun x => decide (x = a)) (fun x => decide (x ∈ t))
      have hone := countBelow_single a N
      have hb : (decide (a < N)).toNat ≤ 1 := by cases decide (a < N) <;> simp
      have ht := count_mem_le N t
      simp only [List.length_cons]; omega

/-- **SA-4c (union bound).** `k` removal records of 45 indices each set at
most `45 · k` bits below any bound `N`. -/
theorem setBits_le (N : Nat) : ∀ (records : List (List Nat)),
    (∀ r ∈ records, r.length = NumTrials) →
    countBelow N (setBits records) ≤ NumTrials * records.length
  | [], _ => by
      rw [countBelow_congr N _ (fun _ => false) (fun x _ => by simp [setBits]), countBelow_false]
      simp
  | r :: rs, h => by
      have hr := h r (List.mem_cons_self)
      have ih := setBits_le N rs (fun x hx => h x (List.mem_cons_of_mem r hx))
      have hor := countBelow_or N (fun x => decide (x ∈ r)) (setBits rs)
      have heq : countBelow N (setBits (r :: rs)) = countBelow N (fun x => decide (x ∈ r) || setBits rs x) := by
        apply countBelow_congr; intro x _; simp [setBits]
      have hm := count_mem_le N r
      rw [heq]; simp only [List.length_cons]; rw [Nat.mul_succ]; omega

/-! ### Layer 3: counting index tuples -/

/-- Number of `n`-tuples over `[0, Wd)` satisfying `P`, defined by summing
over the first coordinate. -/
def tcount (Wd : Nat) : Nat → (List Nat → Bool) → Nat
  | 0, P => (P []).toNat
  | n + 1, P => sumBelow Wd (fun x => tcount Wd n (fun t => P (x :: t)))

theorem sumBelow_congr (N : Nat) (f g : Nat → Nat) (h : ∀ x, x < N → f x = g x) :
    sumBelow N f = sumBelow N g := by
  induction N with
  | zero => rfl
  | succ n ih => simp only [sumBelow]; rw [ih (fun x hx => h x (by omega)), h n (by omega)]

theorem tcount_and (Wd n : Nat) (b : Bool) (Q : List Nat → Bool) :
    tcount Wd n (fun t => b && Q t) = if b then tcount Wd n Q else 0 := by
  cases b
  · induction n generalizing Q with
    | zero => simp [tcount]
    | succ n ih =>
        simp only [tcount, Bool.false_and]
        have : ∀ _x : Nat, tcount Wd n (fun _ => false) = 0 := by
          intro _; have := ih (fun _ => true); simpa using this
        rw [sumBelow_congr Wd _ (fun _ => 0) (fun x _ => this x), sumBelow_zero]
        simp
  · simp

/-- **SA-4d (tuple counting).** Exactly `s^n` of the `Wd^n` tuples have all
coordinates in `S`, where `s` is the number of `x < Wd` in `S`. -/
theorem tcount_all (Wd : Nat) (S : Nat → Bool) :
    ∀ n, tcount Wd n (fun t => t.all S) = (countBelow Wd S) ^ n := by
  intro n
  induction n with
  | zero => simp [tcount]
  | succ n ih =>
      simp only [tcount, List.all_cons]
      rw [sumBelow_congr Wd _ (fun x => if S x then countBelow Wd S ^ n else 0)
            (fun x _ => by rw [tcount_and, ih])]
      rw [sumBelow_ite, Nat.pow_succ, Nat.mul_comm]

/-- The total number of tuples is `Wd^n`. -/
theorem tcount_total (Wd n : Nat) : tcount Wd n (fun t => t.all (fun _ => true)) = Wd ^ n := by
  rw [tcount_all]
  congr 1
  induction Wd with
  | zero => rfl
  | succ k ih => simp [countBelow, ih]

/-- **SA-4e (numeric bound).** `(45 · 4088 / 2^20)^45 < 2^-112`. -/
theorem fp_numeric : (NumTrials * 4088) ^ NumTrials * 2 ^ 112 ≤ W ^ NumTrials := by decide

/-- **SA-4 (false-positive bound).** If at most `45 · 4088` bits of the
target window are set (SA-4b, SA-4c), then among all `(2^20)^45` equally
likely index tuples of a fresh output, the fraction lying entirely on set
bits is below `2^-112`. -/
theorem false_positive_bound (S : Nat → Bool) (hS : countBelow W S ≤ NumTrials * 4088) :
    tcount W NumTrials (fun t => t.all S) * 2 ^ 112 ≤ tcount W NumTrials (fun t => t.all (fun _ => true)) := by
  rw [tcount_all, tcount_total]
  have hpow : countBelow W S ^ NumTrials ≤ (NumTrials * 4088) ^ NumTrials := Nat.pow_le_pow_left hS _
  have := fp_numeric
  calc countBelow W S ^ NumTrials * 2 ^ 112
      ≤ (NumTrials * 4088) ^ NumTrials * 2 ^ 112 := Nat.mul_le_mul_right _ hpow
    _ ≤ W ^ NumTrials := this

/-- **SA-4 (end to end).** Let `pos` be the distinct AOCL positions of the
removal records applied so far whose bits can reach the window of batch `b`
(by SA-4a, their batches are within 255 of `b`), and `records` their index
sets, each of 45 indices. Then a fresh output in batch `b` is a false
positive with probability below `2^-112`. Bits are counted relative to the
window start `b · 2^12`. -/
theorem false_positive_end_to_end (b : Nat) (pos : List Nat) (records : List (List Nat))
    (hnd : pos.Nodup) (hlen : records.length = pos.length)
    (hnear : ∀ j ∈ pos, b ≤ j / B + 255 ∧ j / B ≤ b + 255)
    (h45 : ∀ r ∈ records, r.length = NumTrials) :
    tcount W NumTrials (fun t => t.all (fun x => setBits records (b * C + x))) * 2 ^ 112
      ≤ (W ^ NumTrials) := by
  have hcontrib := contributors_le b pos hnd hnear
  have hbits : countBelow W (fun x => setBits records (b * C + x)) ≤ NumTrials * 4088 := by
    have h1 := setBits_le (b * C + W) records h45
    have h2 := countBelow_add (b * C) W (setBits records)
    have h3 : NumTrials * records.length ≤ NumTrials * 4088 := Nat.mul_le_mul_left _ (by omega)
    omega
  have := false_positive_bound _ hbits
  rwa [tcount_total] at this

end SecurityArguments
