import MutatorSet

/-!
Writes `vectors/aocl_range.csv`: inputs and expected outputs of the Lean model
of `AbsoluteIndexSet::aocl_range`. The Rust test
`neptune-mutator-set/tests/lean_aocl_range_vectors.rs` checks that the Rust
implementation returns the same values, which ties the Lean model to the code.

Columns: `minimum,max_offset,lo,hi` where `lo,hi` are `none,none` when the
model (and Rust) must reject the index set.
-/

open MutatorSet

/-- 64-bit xorshift; deterministic so the file is reproducible. -/
def xorshift (x : UInt64) : UInt64 :=
  let x := x ^^^ (x <<< 13)
  let x := x ^^^ (x >>> 7)
  x ^^^ (x <<< 17)

def row (minimum maxOffset : Nat) : String :=
  match aoclRange minimum maxOffset with
  | some (lo, hi) => s!"{minimum},{maxOffset},{lo},{hi}"
  | none => s!"{minimum},{maxOffset},none,none"

def edgeCases : List (Nat × Nat) := Id.run do
  let mut out := []
  -- small minimums exercise the saturating subtraction; offsets at the window edges
  for m in [0, 1, 4095, 4096, 4097, 8191, 8192, 1048575, 1048576, 1048577, 2097152] do
    for d in [0, 1, 4095, 4096, 524288, 1048574, 1048575, 1048576, 1048577, 4000000] do
      out := out ++ [(m, d)]
  return out

def randomCases (n : Nat) : List (Nat × Nat) := Id.run do
  let mut s : UInt64 := 0x9E3779B97F4A7C15
  let mut out := []
  for _ in [0:n] do
    s := xorshift s
    let aocl := s.toNat % 4000000000           -- AOCL index up to 4·10⁹
    s := xorshift s
    let m := s.toNat % W                      -- smallest relative index
    s := xorshift s
    let spread := s.toNat % (W - m)           -- keeps m + spread < W
    out := out ++ [(computedMinimum m aocl, spread)]
  return out

def main : IO Unit := do
  let rows := (edgeCases ++ randomCases 2000).map fun (m, d) => row m d
  IO.FS.createDirAll "vectors"
  IO.FS.writeFile "vectors/aocl_range.csv" (String.intercalate "\n" ("minimum,max_offset,lo,hi" :: rows) ++ "\n")
  IO.println s!"wrote {rows.length} vectors to vectors/aocl_range.csv"
