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
- **The `SingleProof` digest is a *parameter* of the `LinkProof` claim, never a
  constant inside it.** See §Breaking the `Fix`/`Cast` cycle.

## Breaking the `Fix`/`Cast` cycle

`Fix` recursively verifies a `LinkProof`, and `Cast` recursively verifies a
`SingleProof`. Both edges need the other program's digest at *program-
construction* time, so hardcoding both is impossible: no fixed point exists.

Resolution (Thorkil): promote the `SingleProof` digest `D` from a compile-time
constant inside `LinkProof` to a **public input of the `LinkProof` claim**.
`LinkProof` becomes a family `Link[D]` indexed by a digest it never chooses for
itself. This is the same move `SingleProof` already makes for its *self*-
recursion, where `Update`/`Merger` thread `tasm::own_program_digest()` into the
operand claims rather than hardcoding (`single_proof.rs:711`, `:812`, `:877`).

Claim shape (today `Forge`'s claim input is just `lkmh`; `forge.rs:512`, `:885`):

    Claim { program: LinkProof, input: [lkmh; 5] || [D; 5], output: [] }

`LinkProof`'s `main` reads both digests (`read_io 5` twice) before dispatching on
the witness discriminant. Per-branch obligations:

- `Forge`: ignores `D`; unconstrained (the prover picks it).
- `Chain(A,B)`: operand claims `{ program: own_program_digest(), input:
  [lkmh_A, D] }` and likewise for `B`, with `D` **copied verbatim** from own
  public input.
- `Update`: same verbatim pass-through onto the operand claim.
- `Cast`: verifies `{ program: D, input: [txkmh] }` — the only *use* of `D`.
- `Fix` (a `SingleProof` branch, not a `LinkProof` one): verifies
  `{ program: <hardcoded LinkProof digest>, input: [lkmh, own_program_digest()] }`
  and asserts `thruputs == []`.

Rust side: `LinkProofWitness::standard_input()` returns
`lkmh.reversed() || D.reversed()`, so `D` must be reachable from the witness —
an explicit field on each branch witness (`ChainWitness`, `UpdateWitness`,
`CastWitness`, and `ForgeWitness` too since it is in the claim), populated by
the builder from `ConsensusRuleSet::infer_from(..)`'s pinned `SingleProof`
digest. **Not built yet**: the claim input is `[lkmh]` alone until `Cast` gives
`D` a consumer (see §Data Structures).

**Why this breaks the cycle.** `LinkProof::hash()` becomes computable from
`LinkProof`'s code alone; `SingleProof::hash()` then depends on it one-
directionally. The Rust edge `chaintx -> transaction::validity::single_proof`
disappears (`Cast` reads `D` from stdin), so the module graph enforces
acyclicity structurally.

**Why it stays sound.** Invariant, by induction over the derivation tree of a
valid `LinkProof` for claim `(LinkProof, [lkmh, D])`: *every `SingleProof`
recursively verified anywhere in that derivation was verified against program
digest `D`.* `Forge`: vacuous. `Cast`: verifies exactly one, against its own
`D`. `Chain`/`Update`: operands carry the same `D`, so the IH applies to both
subtrees. `Fix` instantiates `D := own_program_digest()`, already pinned by the
outer verifier to the consensus `SingleProof` digest ⇒ anything block-borne was
`Cast` only from genuine `SingleProof`s.

**The residual prover freedom is inert.** A `Forge`/`Cast` prover may name any
`D`, but `Chain` refuses to mix `D`s and `Fix` accepts only its own, so a
wrong-`D` chain is never block-borne — same shape of argument as the
phantom-thruput case above.

**The audit-critical line.** `D` must be *copied* from public input into every
child claim in `Chain`/`Update` — never divined, never re-derived from witness
data. A gap here means "attacker names the program that gets recursively
verified", i.e. universal forgery. Covered by §Negative tests for `D`.

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
- [ ] Write §Breaking the `Fix`/`Cast` cycle into `transaction.md` too — the
      claim shape `[lkmh, D]` is consensus-visible, so it belongs in the spec,
      not only in this tracker.
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
- [x] `LinkKernel { kernel: TransactionKernel, thruputs: Vec<AdditionRecord> }`
      (compose — reuse kernel MAST/hashing, no field drift)
- [x] MAST encoding: thruputs as one extra leaf beside the existing kernel
      leafs
- [x] `LinkTx { kernel: LinkKernel, proof: LinkProof }`
- [x] `LinkPrimitiveWitness` — primitive-witness analog consumed by `Forge`
  - [x] an arbitrary strategy obtained by lifting its `PrimitiveWitness` analog
  - [x] `validate` -- analogous to `PrimitiveWitness::validate`
- [ ] `LinkProofWitness` enum: `Forge | Chain | Update | Cast`
      (mirror `SingleProofWitness`; note `Fix` is NOT here)
  - [x] `Forge(Box<ForgeWitness>)` — the variant holds what the branch consumes,
        mirroring `SingleProofWitness::Collection(ProofCollection)`.
        `LinkPrimitiveWitness` is the `PrimitiveWitness` analog and, like it, is
        deliberately not a variant.
  - [x] `Chain(Box<ChainWitness>)` — holds the two operand kernels, the chained
        kernel, the cut-through set, and the two operand link proofs. It needs
        no memory projection.
  - [ ] `Update` (2), `Cast` (3) — land with their witnesses
  - [x] `SecretWitness` impl — dispatches to the branch witness.
  - [ ] `standard_input()` gains `|| D.reversed()`, `D` = the `SingleProof`
        program digest (§Breaking the `Fix`/`Cast` cycle). Deferred until `Cast`
        lands: today no branch reads `D`, and sourcing it means plumbing
        `ConsensusRuleSet` into every branch witness for a value nothing
        consumes. Claim input is `[lkmh]` until then.
- [ ] `SingleProofWitness::Fix(FixWitness)` — new variant on the *existing*
      enum; recursively verifies a LinkProof, asserts `thruputs == []`

## Tasm
Four produce a `LinkProof`; `Fix` produces a `SingleProof`.

`LinkProof` is the program; the four are *branches* of it, dispatched on the
[`LinkProofWitness`] discriminant exactly as `SingleProof` dispatches on
`SingleProofWitness`. Each branch is a `BasicSnippet` with the stack contract
`[lkmh] *link_proof_witness disc -> [scratch] *link_proof_witness -1`, and the
dispatcher asserts the `-1` afterwards.

**The digest slot belongs to the dispatcher.** A branch receives `lkmh` there
and may leave anything behind; the dispatcher pops it unread. Should a
post-dispatch check ever need `lkmh`, stash it in a `kmalloc` in `LinkProof`,
once, for every branch -- do not make branches hand it back. Handing it back
puts the burden on each of them, and a branch that returns the wrong digest of
the same transaction (inner root vs. `lkmh`: both well-formed, both plausible)
would bind that check to the wrong tree without crashing.
- [x] **LinkProof** dispatcher (`link_proof.rs`): reads `lkmh` off stdin, reads
      the discriminant at address 0, range-checks it
      (`INVALID_WITNESS_DISCRIMINANT_ERROR` -- *not* redundant with
      `NO_BRANCH_TAKEN_ERROR`, since a witness claiming `-1` would otherwise
      impersonate a taken branch), dispatches, asserts a branch ran.
  - [x] `LinkProofWitnessMemory` -- the memory-image mirror of
        `LinkProofWitness`, the way `ForgeWitnessMemory` mirrors `ForgeWitness`.
        The witness enum holds the rich branch witness (it has to build the ND
        streams); only the projection is written to memory. Branches find their
        payload at `*witness + 2`, past the discriminant and field-size words.
  - [x] `test_program_snapshot!` — pins the `LinkProof` program hash (replaces
        the `Forge`-as-a-program pin; `Forge` no longer has a hash of its own)
  - [x] Import order is consensus-critical: `Forge` must be imported *first*,
        because four of its `kmalloc`s have to land at
        `RemovalRecordsIntegrity`'s addresses (`forge_confirmed_loop_matches_rri`
        compares the emitted instructions, `push`ed addresses included). Every
        branch added later imports after it. (`Chain` does; re-check the guard
        test again when `Update`/`Cast` land.)
  - [x] `main` reads the own program digest off the initial stack and hands it
        to every branch below `lkmh`. `Chain` needs it to name `LinkProof` in
        its operand claims; `Forge` ignores it. Mirrors `SingleProof`'s `main`.
- [x] **Forge** `LinkPrimitiveWitness -> LinkTx`: inline
      `RemovalRecordsIntegrity` (non-recursive) + collect the lock/type-script
      hashes inline and recursively verify the lock/type-script proofs.
  - [x] input integrity:
    - [x] msa / inputs / thruputs / no-coinbase / no-merge-bit authenticated
      against the `LinkKernel` MAST hash.
    - [x] inlined RRI over the confirmed inputs.
    - [x] thruput commitments.
    - [x] cardinality.
    - [x] Rust shadow + tasm agree on every confirmed/thruput split.
  - [x] output integrity:
    - [x] `KernelToOutputs` absorbed.
    - [x] `outputs` authenticated against the `LinkKernel` MAST hash
    - [x] each addition record checked to be the canonical commitment of the
          matching `output_utxos` entry.
  - [x] collect lock-script and type-script hashes inline over `input_utxos` and
        `input_utxos || output_utxos`, respectively. (Type-script collection
        absorbs `CollectTypeScripts`: seed `NativeCurrency`, dedup with
        `Contains` across every coin of every input then output UTXO.)
  - [x] recursively verify the lock-script and type-script proofs. Needs the
        *inner* `TransactionKernel` MAST root (type scripts see the legacy
        kernel, height 3) derived from the `LinkKernel` leafs (height 4).
        (Inner root divined, authenticated against `lkmh`, then kept at the
        bottom of the stack -- reusing the now-dead `lkmh` slot -- so both
        script-claim templates read it without static memory.)
- [x] **Chain** `LinkTx * LinkTx -> LinkTx`: recursively verify both input
      LinkProofs, merge, cut-through where
      `successor.thruputs ⊆ predecessor.outputs` (mirror
      `single_proof/merge_branch`).
  - [x] both operand claims: program = `own_program_digest()`, input =
        `[lkmh_operand]`.
  - [ ] append `D`, **copied verbatim** from own public input, to both operand
        claims (audit-critical; §Breaking the `Fix`/`Cast` cycle). Blocked on
        `D` entering the claim at all, which is deferred until `Cast`.
  - [x] cut-through as one witness-supplied multiset removed from the
        concatenated outputs *and* the concatenated thruputs, so a record can
        only leave the output side by leaving the input side with it. Matching
        is on the addition record, i.e. on the canonical commitment.
  - [x] inputs and announcements are the concatenations; fee is the sum (both
        operands bounded, hence non-negative); timestamp is the max; one mutator
        set hash across all three kernels.
  - [x] the chained kernel carries no coinbase and no merge bit. The operands'
        are *not* re-checked: every branch asserts both on the kernel it
        produces, so an operand that verifies has them by induction. Any branch
        added later owes the same assertion.
  - [ ] a positive test in which cut-through is *partial* -- the prover leaves a
        matching (output, thruput) pair standing. Permitted by design; currently
        only maximal cut-through is exercised.
- [ ] **Update** `LinkTx -> LinkTx`: re-target a new mutator-set hash without
      re-forging (mirror `single_proof/update_branch`). Same verbatim `D`
      pass-through onto the operand claim. `Update` re-targets the *mutator set*,
      never `D`.
- [ ] **Cast** `Transaction -> LinkTx`: recursively verify the input
      `SingleProof`, produce `LinkProof(thruputs = [])` so a regular
      `Transaction` can join a chain. The inner claim is
      `{ program: D, input: [txkmh] }` — `D` read from public input, *not*
      hardcoded: this is what breaks the cycle.
- [ ] **Fix** = new `SingleProof` branch: recursively verify the `LinkProof`
      against `{ program: <hardcoded LinkProof digest>, input:
      [lkmh, own_program_digest()] }`, assert `thruputs == []`, produce a
      standard `SingleProof`. The `own_program_digest()` in that claim is the
      sole tie between the two programs. Changes the `SingleProof` program hash
      (see §Consensus change).
- [ ] claim generators for each (parallel to `validity/tasm/claims/`); the
      `LinkProof` claim generator takes `(lkmh, D)` — mirror
      `GenerateSingleProofClaim`, whose second parameter is already a
      runtime-supplied program digest
      (`validity/tasm/claims/generate_single_proof_claim.rs:12`).

## Consensus change (because SingleProof gains `Fix`)
- [ ] New `ConsensusRuleSet` variant + per-network activation `BlockHeight`s
      (`consensus_rule_set.rs::infer_from`)
- [ ] Pin the new `SingleProof` program hash + the `LinkProof` program hash
- [ ] soundness audit: `SingleProof` `Fix` branch, and `Forge`'s inlined RRI
      + the recursion in `Chain`/`Update`/`Cast`, including the verbatim `D`
      pass-through
- [ ] Regenerate/store proof artifacts for the new program versions
- [ ] Upgrade coupling at the activation height: a new `SingleProof` hash changes
      `D`, invalidating every in-flight `LinkTx` — `Forge`'d ones need
      re-forging, not just `Update`ing. Mempool must drop `LinkTx`s whose `D` is
      not the active rule set's `SingleProof` digest at the activation height.

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
      before relay. 
- [ ] Punish peers for relaying invalid `LinkTx`s
- [ ] Reject on arrival any `LinkTx` whose claim carries a `D` other than the
      active rule set's `SingleProof` and punish the peer

## Reference-validator tests (`LinkPrimitiveWitness::validate`)
`LinkPrimitiveWitness::validate` is the proof-free, tier-1 predicate (analog of
`PrimitiveWitness::validate`): it *runs* the lock/type-script sub-VMs directly
rather than recursively verifying their proofs, so it is the cheap workhorse for
negative tests. The tasm `Forge` (§Mirror Tests → onto `Forge`) re-establishes
the same soundness properties by recursion later; these front-run them at a
fraction of the cost, they do not replace them. Idiom: start from a valid
witness (lift a `PrimitiveWitness`), then either poke one field, or poke the
`pw` and lift it — the latter lets `from_primitive_witness` rebuild the type
scripts so the kernel MAST stays consistent and the intended late-stage check
fires instead of an early `InvalidTypeScript`.

Positive:
- [x] round-trip `bfield_codec` (`bfield_codec_round_trip`)
- [x] lift preserves validity for any `PrimitiveWitness` at any thruput count
      (`lift_preserves_validity`)
- [x] all-thruputs (0 confirmed) validates — proves thruput value counts toward
      the input balance (`all_thruputs_is_valid`)

Negative — one per reachable branch (bracketed items pre-cover a §onto `Forge`
or §New Tests entry at this tier):
- [x] cardinality: extra input UTXO / short thruput-randomness vector
      (`extra_input_utxo_fails_cardinality`,
      `short_thruput_randomness_fails_cardinality`) [→ Cardinality]
- [x] bad lock-script witness → `InvalidLockScript`
      (`bad_lock_script_witness_fails`)
- [x] bad mutator-set accumulator → `InvalidMembershipProof`
      (`bad_mutator_set_accumulator_fails`) [→ bad ms acc]
- [x] unbalanced output / fee-too-big → `InvalidTypeScript`
      (`unbalanced_output_fails_type_script`, `fee_too_big_fails_type_script`)
      [→ unbalanced; fee-too-big inflation]
- [x] missing / too-many type-script witnesses
      (`missing_type_script_witness_fails`,
      `too_many_type_script_witnesses_fails`) [→ type scripts present]
- [x] swapped confirmed removal records → `RemovalRecordsMismatch`
      (`swapped_removal_records_fail`)
- [x] tampered thruput addition record / randomness → `ThruputCommitmentMismatch`
      (`tampered_thruput_addition_record_fails`,
      `tampered_thruput_randomness_fails`) [→ two representations of thruputs agree]
- [x] mutator-set-hash mismatch → `MutatorSetMismatch`
      (`mutator_set_hash_mismatch_is_rejected`)
- [x] merge bit set → `MergeBitSet` (`merge_bit_is_rejected`)
- [x] coinbase in kernel → `CoinbaseSet` (`coinbase_kernel_is_rejected`)
      [→ New Tests: `LinkKernel` carrying a coinbase rejected]

Gap pinned (same gap as `PrimitiveWitness::validate`; enforced later by `Forge`):
- [x] missing/extra lock script is *not* caught by `validate` — lock-script
      coverage is `Forge`/`CollectLockScripts`'s job
      (`missing_or_extra_lock_script_is_not_caught`)

Deferred to `Forge` (sharper there than at the proof-free tier):
- [x] bad input MAST auth path / bad absolute index set (confirmed inputs) — bad
      index set: `bad_absolute_index_set_is_rejected`
      (`COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR`); bad kernel-MAST binding:
      `unauthenticated_removal_record_is_rejected` / `unauthenticated_thruput_is_rejected`
      (`ROOT_MISMATCH`).
- [x] phantom thruput / phantom confirmed UTXO backed by no record —
      `phantom_input_utxo_is_rejected` (`CARDINALITY_MISMATCH_ERROR`)

## Mirror Tests
Two tiers: the proof-free `LinkPrimitiveWitness::validate` (above) and the tasm programs
(below). The `validate`-tier tests already cover several §onto `Forge` items;
when `Forge` exists, mirror those rather than reinventing them.

The soundness tests that sit on the legacy `ProofCollection`/`SingleProof`
programs test meaningful soundness properties. Some of those properties should be
tested on the new dual pipeline as well.
- `NativeCurrency` and `TimeLock` are recursively verified by `Forge` *unchanged*,
  so their own existing tests still apply — no re-test; only their whole-tx
  consequences below are re-stated against a `LinkKernel`.
- `CollectLockScripts` / `CollectTypeScripts` do NOT appear as separate programs
  in the dual pipeline; `Forge` absorbs them (they remain, unchanged and
  consensus-pinned, in the legacy pipeline). Their *net behavior* must be tested
  on `Forge` (below).
- Reuse strategy: build the base `LinkPrimitiveWitness` via
  `LinkPrimitiveWitness::from_primitive_witness(pw, k)` off the same legacy
  `PrimitiveWitness::arbitrary_*` strategy the mirrored test uses, then poke one
  field (legacy negative-test idiom) — no per-test strategy duplication.

### onto `Forge`
- [x] bad mutator-set accumulator rejected
      (← `removal_records_fail_on_bad_ms_acc`) — `bad_mutator_set_accumulator_is_rejected`
- [x] bad input MAST auth path rejected
      (← `removal_records_fail_on_bad_mast_path_inputs`) — covered by
      `unauthenticated_removal_record_is_rejected` (the kernel MAST path is
      derived from `mast_leafs`, so poking the confirmed record is the way to
      break the `Inputs`-leaf binding)
- [x] bad absolute index set rejected (← `removal_record_fail_on_bad_absolute_indices`)
      — `bad_absolute_index_set_is_rejected`
- [x] all lock scripts have valid witnesses (net behavior of `CollectLockScripts`)
      — every input UTXO needs a proof (count guard,
      `missing_lock_script_proof_is_rejected`) and each is `StarkVerify`d;
      the positive path is `forge_accepts_valid_witnesses`
- [x] all unique type scripts have valid witnesses (net behavior of `CollectTypeScripts`)
      (`forge_accepts_timelocked_witness` forges a tx whose unique list is
      `[NativeCurrency, TimeLock]`, recursively verifying both.)
- [x] negative: a single missing lock-script or type-script witness fails `Forge`
      (both tasm guards done: `missing_type_script_proof_is_rejected` /
      `missing_lock_script_proof_is_rejected` trip
      `WRONG_NUMBER_OF_{TYPE,LOCK}_SCRIPT_PROOFS_ERROR`; `validate` rejects a
      dropped lock- or type-script proof too -- see `validate_matches_forge`.)

Not on `Forge` -- these are `NativeCurrency` properties, recursively *verified*
(not re-implemented) by `Forge`, so `NativeCurrency`'s own tests still apply and
no valid `Forge` witness can violate them (`produce` cannot prove an unbalanced /
over-fee'd type script): unbalanced `LinkTx`; fee-too-big inflation; fee bounds.
Likewise partition misclassification (confirmed ↔ thruput) is not an error -- the
partition *is* the kernel, every input carries a lock-script proof, and an
unmatched thruput is un-`Fix`able (see §Motivation).

### onto `Update`
- [ ] new timestamp older than old rejected (← `new_timestamp_older_than_old_prop`)
- [ ] bad new AOCL rejected (← `bad_new_aocl_prop`)
- [ ] bad old AOCL rejected (← `bad_old_aocl_prop`)
- [ ] tampered absolute-index-set value rejected (← `bad_absolute_index_set_value_prop`)
- [ ] tampered absolute-index-set length rejected (← `bad_absolute_index_set_length_too_short_prop`)

### onto `Chain`
- Not applicable: coinbase-specific merge tests (`too_big_time_diff`,
  `authenticate_coinbase_fields_*`) — a `LinkTx` is never a coinbase transaction
- [x] chained inputs are the operands' inputs
- [x] chained announcements are the operands' announcements
- [x] chained fee is the sum of the operand fees (too big *and* too small)
- [ ] fee-sum overflow rejected. **Not testable through the tasm today, and the
      margin is thinner than it looks.** `Chain` bounds both operand fees to
      `[0, MAX_NAU]` before adding, and `MAX_NAU` is 98.74% of `2**127`, so two
      bounded fees clear `u128::MAX` by 1.26% — the overflow assert after
      `overflowing_add_u128` cannot fire, and no witness can drive it. *Three*
      bounded fees would overflow. Pinned by
      `two_bounded_fees_cannot_overflow` rather than left to the argument in a
      comment. Revisit if: the conversion factor or the 42M coin cap grows; a
      branch sums more than two amounts in one `u128` addition; or a negative
      operand fee (huge as a `u128`) ever becomes reachable — the last is what
      makes `Update`/`Cast` owe the same bounds check `Chain` does.
- [x] chained timestamp is the later of the operand timestamps
- [x] all three kernels agree on the mutator-set hash
- [x] coinbase / merge bit on the chained kernel rejected
- [x] bad MAST auth path rejected
- [x] chained kernel must be the one named in the claim
- [x] one-sided cut-through rejected, in both directions (← §cut-through value
      conservation, negative)
- [x] cut-through on unequal commitments rejected — the phantom-thruput
      argument, as a test: a thruput no predecessor output resolves can never
      be cancelled
- [ ] chained *outputs* are the operands' outputs when nothing cuts through
      (the `cut_through == []` case is only covered positively)
- [ ] double spend across operands: both operands spending the same input.
      `Chain` does not reject this today — nor does `merge_branch`; index-set
      uniqueness is enforced downstream. Confirm that is still true once a
      `LinkTx` can reach a block via `Fix`, and test it wherever it lands.

### onto `Fix`
- [ ] invalid `LinkProofWitness` discriminant crashes (← `invalid_discriminant_crashes_execution`)
- [ ] invalid `SingleProofWitness` discriminant crashes (now that `Fix` is a variant)

## Negative tests for `D` (the `SingleProof` digest in the `LinkProof` claim)

These guard §Breaking the `Fix`/`Cast` cycle. The invariant they defend — `D` is
copied verbatim into every child claim, and only `Fix` may name it — is the
difference between recursion and universal forgery, so *every* branch that
touches `D` gets a negative.

Claim / plumbing:
- [ ] Claim shape pinned: `LinkProofWitness::standard_input()` ==
      `lkmh.reversed() || D.reversed()`, length `2 * Digest::LEN`. Order and
      length must never drift (analog of the `Forge` program-hash pin).
- [ ] Proof/claim binding: a valid `LinkProof` for `[lkmh, D₁]` does **not**
      verify against `[lkmh, D₂]`, `D₁ ≠ D₂`. (Cheap; catches a `D` that is read
      but never actually made part of the claim.)
- [ ] `LinkProof` program hash does not change when the `SingleProof` program
      changes — i.e. `LinkProof::hash()` is stable across `ConsensusRuleSet`
      variants. This *is* the cycle-break, as a test.

`Chain`:
- [ ] mismatched operands: `Chain(A with D₁, B with D₂)`, `D₁ ≠ D₂` → rejected.
- [ ] substituted operand `D`: own claim says `D`, but an operand claim is built
      with `D' ≠ D` (left operand, and separately right operand) → rejected. Two
      tests; the pass-through is per-operand and a copy-paste slip hits one side.
- [ ] divined `D`: operand claims built from a witness-supplied digest instead of
      public input → rejected. (Whitebox: poke the nondeterminism so the
      would-be-divined value differs from stdin.)
- [ ] mixed provenance: `Chain(Forge'd with D₁, Cast'd with D₂)` → rejected —
      the case that would otherwise launder a junk-`D` `Cast` into a real chain.

`Update`:
- [ ] operand claim with `D' ≠ D` → rejected.
- [ ] `Update` cannot re-target `D`: output claim `D_new ≠ D_old` → rejected.

`Cast`:
- [ ] inner `SingleProof` claim built with a program digest ≠ `D` from public
      input → rejected.
- [ ] `Cast` with `D` = the `LinkProof` program's own digest (self-substitution:
      a `LinkProof` passed off as a `SingleProof`) → the `Cast` itself succeeds
      but the result is un-`Fix`able. Assert the `Fix` rejection, and assert that
      this is the *only* thing standing between it and a block.
- [ ] `Cast` of a `Transaction` whose `SingleProof` is invalid → rejected (the
      recursion actually runs; guards against `D` being read and then unused).

`Fix`:
- [ ] `D ≠ own_program_digest()` in the `LinkProof` claim → rejected. Including
      the two realistic wrong values: the *previous* rule set's `SingleProof`
      digest, and the `LinkProof` digest itself.
- [ ] `LinkProof` claim built with a program digest ≠ the hardcoded `LinkProof`
      digest → rejected.
- [ ] a `Forge`'d `LinkTx` carrying an arbitrary junk `D` → rejected (the inert-
      by-construction argument, as a test).
- [ ] `Fix` with non-empty thruputs → rejected (also listed under §New Tests).

Positive counterparts (so the negatives cannot pass vacuously):
- [ ] end-to-end `Forge → Chain → Fix` with `D` = the real `SingleProof` digest
      throughout accepts, and the resulting `SingleProof` verifies.
- [ ] `Cast → Chain → Fix` round-trip with the real `D` accepts.


## New Tests
- [ ] Property: `Chain` associativity:
      `Chain(Chain(A, B), C) = Chain(A, Chain(B, C))`
- [ ] Property: `Fix` distributivity: `Fix(Chain(A, B)) = Merge(Fix(A), Fix(B))`
      when `thruputs == []`
- [x] `Chain`: new timestamp unequal to max rejected
- [ ] Thruput-input integrity: a thruput must equal an output of a predecessor
      in the chain (validated against that output, not mutator-set membership)
- [ ] Negative: `LinkKernel` carrying a coinbase rejected
- [ ] `Update` then `Fix` == `Fix` on the updated mutator set
- [ ] `Cast` round-trip: `Cast(tx)` then `Fix` == `tx`
- [ ] Negative: `Fix` with non-empty thruputs rejected
- [x] Negative: `Chain` with mismatched thruputs rejected (a cut-through whose
      commitment matches no output)
- [ ] Negative: `Chain` with double-spends rejected. Not enforced by the branch
      today (`merge_branch` does not either -- index-set uniqueness is a
      downstream check); revisit once `Fix` can carry a `LinkTx` into a block
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
- [x] Chain rejects a bad MAST auth path for an operand's `inputs` / `outputs` /
      `thruputs` / `fee`. (One path tampered; every field goes through the same
      snippet.)
- [x] cut-through value conservation (positive): a cut-through cancels a
      (thruput, output) pair only when their canonical commitments are equal,
      and removes it from both sides together — so no value is created or
      destroyed. (Maximal cut-through only; see §Tasm > `Chain` for the partial
      case.)
- [x] Cut-through value conservation (negative): one-sided removal, or a cancel
      on unequal commitments, is rejected.

## Benchmarks
- [ ] `Forge` (inlined RRI) vs `Prove`+`Raise` (recursive RRI) — the cost claim
- [ ] N chained interactions in one block vs N separate txs (throughput claim)

## Audit
- [ ] Scoped security audit

[1]: https://talk.neptune.cash/t/transaction-chaining-in-neptune-cash/349
