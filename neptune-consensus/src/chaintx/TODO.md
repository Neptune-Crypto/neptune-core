# Transaction Chaining — Implementation Plan and Progress Tracker

Follow the design in [1].

## Motivation

Two payoffs, one mechanism (chaining + cut-through of predecessor-successor
txs):

- **Throughput for self-perpetuating UTXOs / DeFi.** Today a block admits at
  most one interaction with a given smart-contract UTXO, capping e.g. a DEX at
  one trade per block. Chaining lets many interactions accumulate and collapse
  into a single block-borne transaction.
- **Spending unconfirmed funds.** Ordinary users (and wallets doing
  change-splitting or consolidation) can build on outputs that aren't yet in a
  block, instead of waiting a full confirmation between dependent payments.
- **Cheaper initiation.** `Forge` inlines `RemovalRecordsIntegrity`
  *non-recursively*, avoiding the expensive recursive `Raise` per transaction.

## Governing invariants

- **Block *format* unchanged.** Every block still contains exactly one
  `SingleProof`-backed `Transaction` (`block/block_body.rs:78`). A `LinkTx` is
  never held by a block; it enters a block only after `Fix` which sends a
  `LinkTx` to a `SingleProof Transaction`.
- **`SingleProof` gains a `Fix` branch => this IS a consensus change.** `Fix`
  sits alongside `Collection`, `Merger`, and `Update` in `SingleProofWitness`.
  It recursively verifies the `LinkProof` and asserts `thruputs == []`. This
  changes the `SingleProof` program hash and cascades:
  new `ConsensusRuleSet` variant + per-network activation heights.
- **The `Link` programs are consensus-critical.** `RemovalRecordsIntegrity`
  (RRI) is proven *once*, inlined non-recursively inside `Forge`, and carried
  upward by recursion (`Chain` -> `Fix` -> `SingleProof`) — never re-proven.
  Because `Fix` trusts that inlined RRI by recursion, a soundness bug in
  `Forge`'s RRI *is* a double-spend path. => `Forge` (and the recursion in
  `Chain`/`Update`/`Cast`) get the full soundness audit, same bar as the
  existing `SingleProof` branches.
- **Type scripts see a legacy transaction.** The type-script-facing salted input
  UTXOs contain *both* confirmed UTXOs *and* thruputs, and the kernel MAST
  exposes fee/coinbase/timestamp at legacy leaf positions — so `NativeCurrency`
  / `TimeLock` run unchanged, unaware of chaining. Induced obligation: `Forge`
  *must* bind that combined `salted_input_utxos` digest to
  `confirmed_inputs || thruputs` (and validate only the confirmed ones via MSA
  membership; thruputs are copied and validated transitively in `Chain`). The
  type script trusts this digest blindly, so *a gap here is an inflation path.*

## Documentation
- [x] Revise `transaction.md` (`docs/src/consensus/transaction.md`) to
      accurately reflect current transaction initiation pipeline and
      entity-relation graph. (Fixed stale witness field names, `merge_bit`
      semantics, and duplicate/skipped section labels. Added ASCII diagram of
      transformations.)
- [ ] Extend `transaction.md` with an accurate description of the dual
      (introduced in this development streak) pipeline and graph.
- [ ] Glossary: `thruput` = an `AdditionRecord` that is simultaneously (a) an
      unconfirmed input to this tx and (b) an output of a predecessor in the
      chain of transactions.
- [ ] Security argument for cut-through: no value creation, no double-spend
      across a chain; and the argument that RRI proven once in Forge and carried
      by recursion through `Chain`/`Fix` is as sound as a recursive `Raise`.
      Ensure the test suite has a test catching every claim here.
  - **A thruput's value is only realized at cut-through.** `Forge` counts a
    thruput in the salted inputs list but does *not* match it against a real
    predecessor output — that happens in `Chain`. So an over-valued (or
    otherwise fabricated) thruput is *not* rejected at `Forge` time; it is
    instead inert. Cut-through matches on the UTXO's canonical commitment, so a
    thruput corresponding to no predecessor output can never be cancelled, the
    `LinkTx` can never reach `thruputs == []`, and therefore can never `Fix`
    into a block-borne `Transaction`. Un-Fixable ⇒ harmless. (Distinct from the
    Forge-time check that every salted input UTXO is backed by *some*
    `RemovalRecord` or thruput `AdditionRecord`: that check rejects inputs
    backed by nothing; this argument covers inputs that have no predecessor.)

## Data Structures
- [ ] `LinkKernel { kernel: TransactionKernel, thruputs: Vec<AdditionRecord> }`
      (compose — reuse kernel MAST/hashing, no field drift)
- [ ] MAST encoding: thruputs as one extra leaf beside the existing kernel
      leaves
- [ ] `LinkTx { kernel: LinkKernel, proof: LinkProof }`
- [ ] `LinkWitness` — primitive-witness analog consumed by `Forge`
- [ ] `LinkProofWitness` enum: `Forge | Chain | Update | Cast`
      (mirror `SingleProofWitness`; note `Fix` is NOT here)
- [ ] `SingleProofWitness::Fix(FixWitness)` — new variant on the *existing*
      enum; recursively verifies a LinkProof, asserts `thruputs == []`

## Tasm
Four produce a `LinkProof`; `Fix` produces a `SingleProof`.
- [ ] **Forge** `LinkWitness -> LinkTx`: inline `RemovalRecordsIntegrity`
      (non-recursive) + recursively verify `collect_lock_scripts`,
      `collect_type_scripts`, and the lock/type-script proofs. Largest new
      program; RRI lives here.
- [ ] **Chain** `LinkTx * LinkTx -> LinkTx`: recursively verify both input
      LinkProofs, merge, cut-through where
      `successor.thruputs ⊆ predecessor.outputs` (mirror
      `single_proof/merge_branch`).
- [ ] **Update** `LinkTx -> LinkTx`: re-target a new mutator-set hash without
      re-forging (mirror `single_proof/update_branch`).
- [ ] **Cast** `Transaction -> LinkTx`: recursively verify the input
      `SingleProof`, produce `LinkProof(thruputs = [])` so a regular
      `Transaction` can join a chain.
- [ ] **Fix** = new `SingleProof` branch: recursively verify the `LinkProof`,
      assert `thruputs == []`, produce a standard `SingleProof`. Changes the
      `SingleProof` program hash (see §Consensus change).
- [ ] claim generators for each (parallel to `validity/tasm/claims/`)

## Consensus change (because SingleProof gains `Fix`)
- [ ] New `ConsensusRuleSet` variant + per-network activation `BlockHeight`s
      (`consensus_rule_set.rs::infer_from`)
- [ ] Pin the new `SingleProof` program hash + the four `Link` program hashes
- [ ] soundness audit: `SingleProof` `Fix` branch, and `Forge`'s inlined RRI
      + the recursion in `Chain`/`Update`/`Cast`
- [ ] Regenerate/store proof artifacts for the new program versions

## Integration
### Transaction-Initiation
- [ ] Builder path: witness -> `Forge` -> `LinkTx` (parallel to existing
      initiator)
- [ ] API surface in `neptune-core/src/api`
- [ ] `Cast` entry point for pulling an existing Transaction into a chain

### Mempool
The mempool holds both legacy `Transaction`s and `LinkTx`s. A `LinkTx` with
non-empty `thruputs` is *unresolved* — not yet block-eligible.
Chaining is opportunistic and bounded: the authoritative `LinkTx`->`Transaction`
map happens at time of block-template construction. The mempool `Chain`s
(with cut-through) on arrival first-come-first-served and rate-limited (via fee)
so that a crafted flood cannot force unbounded proving. Value-safety never
depends on the mempool — an unresolvable `LinkTx` is inert (un-`Fix`able). In
the worst case, space is wasted, until transactions are evicted.

- [ ] Store both `Transaction` and `LinkTx`. Index residents by: confirmed
      inputs (existing double-spend index), thruputs (new), and outputs (new) —
      the last two are what let an arrival find its `Chain` partners.
- [ ] On arrival, look up predecessors (`resident.outputs` ⊇ `arrival.thruputs`)
      and successors (`resident.thruputs` ⊆ `arrival.outputs`), and perform
      cut-through on matching pairs if the fee is large enough.
- [ ] Separate fee-gobbler for `LinkTx`s.
- [ ] Conflict rules: two residents on the same confirmed input (already a
      conflict now), OR two successors with overlapping thruputs (new). In case
      of conflict, replicate existing policy and exit-queue construction.
- [ ] On new block: evict residents whose confirmed inputs were spent or whose
      predecessor was dropped or confirmed away, `Update` residents to the new
      mutator-set hash.
- [ ] Integrate resident `LinkTx`s into priority queue.
- [ ] Eviction: bound mempool size and evict lowest fee-rate in case of excess
      (already now) + TTL for `LinkTx`s whose thruputs never resolve (new).
- [ ] Block template: select a fee-maximizing, all-thruputs-cut-through chain,
      `Chain` it to a single `LinkTx`, `Fix` into the block's `SingleProof`
      `Transaction`, then merge with legacy txs as today.
- [ ] Cast-on-demand: when a `LinkTx` can chain onto a resident legacy
      `Transaction`, `Cast` the latter in if the fee is beneficial.

## Peer
- [ ] Gossip/relay of `LinkTx` regardless of non-empty thruputs; but validate
      before relay
- [ ] Punish peers for relaying invalid `LinkTx`s

## Mirror Tests
The soundness tests that sit on the legacy `ProofCollection`/`SingleProof`
programs test meaningful soundness properties. Some of those properties should be
tested on the new dual pipeline as well.
- `NativeCurrency` and `TimeLock` are recursively verified by `Forge` *unchanged*,
  so their own existing tests still apply — no re-test; only their whole-tx
  consequences below are re-stated against a `LinkKernel`.
- `CollectLockScripts` / `CollectTypeScripts` do NOT survive as separate
  programs; `Forge` absorbs them. Their *net behavior* must be tested on `Forge`
  (below).

### onto `Forge`
- [ ] bad mutator-set accumulator rejected
      (← `removal_records_fail_on_bad_ms_acc`) — confirmed inputs only
- [ ] bad input MAST auth path rejected
      (← `removal_records_fail_on_bad_mast_path_inputs`) — confirmed inputs only
- [ ] bad absolute index set rejected (← `removal_record_fail_on_bad_absolute_indices`)
      — confirmed inputs only
- [ ] all lock scripts have valid witnesses (net behavior of `CollectLockScripts`)
- [ ] all unique type scripts have valid witnesses (net behavior of `CollectTypeScripts`)
- [ ] negative: a single missing lock-script or type-script witness fails `Forge`
- [ ] unbalanced `LinkTx` invalid (← `unbalanced_transaction_without_coinbase_is_invalid`)
  - [ ] unbalanced and `thruputs == []`
  - [ ] unbalanced only after counting `thruputs`
- [ ] fee-too-big inflation rejected (← `prop_inflation_violation_when_fee_too_big`)
- [ ] fee bounds enforced
      (← `positive_fee_cannot_exceed_max_nau` / `negative_fee_cannot_exceed_min_nau`)

### onto `Update`
- [ ] new timestamp older than old rejected (← `new_timestamp_older_than_old_prop`)
- [ ] bad new AOCL rejected (← `bad_new_aocl_prop`)
- [ ] bad old AOCL rejected (← `bad_old_aocl_prop`)
- [ ] tampered absolute-index-set value rejected (← `bad_absolute_index_set_value_prop`)
- [ ] tampered absolute-index-set length rejected (← `bad_absolute_index_set_length_too_short_prop`)

### onto `Chain`
- Not applicable: coinbase-specific merge tests (`too_big_time_diff`,
  `authenticate_coinbase_fields_*`) — a `LinkTx` is never a coinbase transaction

### onto `Fix`
- [ ] invalid `LinkProofWitness` discriminant crashes (← `invalid_discriminant_crashes_execution`)
- [ ] invalid `SingleProofWitness` discriminant crashes (now that `Fix` is a variant)


## New Tests
- [ ] Property: `Chain` associativity:
      `Chain(Chain(A, B), C) = Chain(A, Chain(B, C))`
- [ ] Property: `Fix` distributivity: `Fix(Chain(A, B)) = Merge(Fix(A), Fix(B))`
      when `thruputs == []`
- [ ] `Chain`: new timestamp unequal to max rejected
- [ ] Thruput-input integrity: a thruput must equal an output of a predecessor
      in the chain (validated against that output, not mutator-set membership)
- [ ] Negative: `LinkKernel` carrying a coinbase rejected
- [ ] `Update` then `Fix` == `Fix` on the updated mutator set
- [ ] `Cast` round-trip: `Cast(tx)` then `Fix` == `tx`
- [ ] Negative: `Fix` with non-empty thruputs rejected
- [ ] Negative: `Chain` with mismatched thruputs rejected
- [ ] Negative: `Chain` with double-spends rejected
- [ ] End-to-end: `Fix`'d tx passes existing `SingleProof` verification & enters
      into a block
- [ ] Phantom thruputs are rejected. Salted inputs list contains a UTXO not
      backed by any thruput AdditionRecord → Forge fails. This is the direct
      inflation path.
- [ ] Phantom confirmed UTXOs are rejected. Salted inputs list contains a UTXO
      not backed by any removal record → Forge fails.
- [ ] Bad commitments are rejected. The salted input UTXOs list contains an
      element whose canonical commitment disagrees with its backing
      `AdditionRecord` or `RemovalRecord` → Forge fails.
- [ ] Cardinality. `|salted_input_utxos| ≠ |confirmed_inputs| + |thruputs|` →
      Forge fails
- [ ] Two representations of thruputs must agree. A: the `thruputs` leaf in
      `LinkKernel`. B: the thruputs partition in the input UTXOs list.
      Disagreement → Forge fails
- [ ] Partition misclassification. A confirmed input placed in the thruput
      partition (or vice-versa) → Forge fails.
- [ ] Faithful union. A valid `Forge` with both confirmed inputs and thruputs
      produces a digest that the unchanged NativeCurrency accepts, and the
      balance sums over both sets.
- [ ] Chain rejects a bad MAST auth path for an operand's `inputs` / `outputs` /
      `thruputs` / `fee`.
- [ ] cut-through value conservation (positive): a cut-through cancels a
      (thruput, output) pair only when their canonical commitments are equal,
      and removes it from both sides together — so no value is created or
      destroyed.
- [ ] Cut-through value conservation (negative): one-sided removal, or a cancel
      on unequal commitments, is rejected.

## Benchmarks
- [ ] `Forge` (inlined RRI) vs `Prove`+`Raise` (recursive RRI) — the cost claim
- [ ] N chained interactions in one block vs N separate txs (throughput claim)

## Audit
- [ ] Scoped security audit

[1]: https://talk.neptune.cash/t/transaction-chaining-in-neptune-cash/349
