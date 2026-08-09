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
- **Cut-through is maximal.** A `LinkKernel`'s outputs and its thruputs are
  disjoint: every (output, thruput) pair on a matching addition record is
  cancelled, always, and on both sides together. So a `LinkTx` never carries a
  thruput one of its own outputs already resolves, and `Chain` is a *function*
  of its two operands rather than a relation — which is what associativity
  (§New Tests) and the mempool's reckoning of which thruputs are still
  outstanding (§Mempool) both stand on. Induced obligation: every branch that
  cuts through must assert that disjointness outright. The two cut-through
  equations do not imply it — they are satisfied by any sub-multiset of the
  intersection, a short `cut_through` included. `Chain` asserts it; see §Tasm >
  `Chain`.
- **A `LinkTx` may hold zero confirmed inputs, so `Update` does not require
  otherwise.** An all-thruputs link -- one funded entirely by its predecessors
  -- is a normal shape in this pipeline, and it still has to follow the mutator
  set: `Chain` requires all three of its kernels to agree on the mutator set
  hash, so a link that cannot be updated is stranded the moment any chain
  partner moves. This is a deliberate divergence from `update_branch`, which
  rejects an empty input set outright (`INPUT_SET_IS_EMPTY_ERROR`). The legacy
  restriction's rationale is recorded nowhere -- not in the code, not in the
  (squashed) history -- so the divergence rests on the reasoning above rather
  than on a demonstrated equivalence. Induced obligation: the audit has to
  either confirm that reasoning or recover what the legacy check was defending,
  in which case whatever it defends has to be re-established for the chain
  pipeline some other way.
- **No negative fees anywhere in a chain — so upgraders must gobble fees with
  standard transactions.** `Chain` adds the operand fees as `u128`s and asserts
  the addition does not carry, which forbids a negative operand fee outright.
  `merge_branch` does the opposite: it *pops* the carry (`merge_branch.rs:520`)
  precisely so that a negative fee on its LHS wraps and adds correctly, and
  therefore still needs an explicit bound on its RHS. Consequence: an upgrader
  that pays itself by merging in a negative-fee transaction has to do it on the
  legacy `Transaction`/`Merge` path; there is no negative-fee `LinkTx` to
  `Chain` in.
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
`CastWitness`, and `ForgeWitness` too since it is in the claim). **Built**, for
`Forge` and `Chain`: `link_proof_public_input(lkmh, D)` in `link_proof.rs` is
the one place the shape is spelled out, and `link_proof_claim_shape_is_pinned`
holds it there. Still to come: populating `D` from
`ConsensusRuleSet::infer_from(..)`'s pinned `SingleProof` digest, which waits on
a builder path (§Integration); tests name a `D` with
`chaintx::mock_single_proof_digest`.

Tasm side: the dispatcher reads `D` (`read_io 5` twice) and stashes it in a
`kmalloc` allocated *first*, ahead of every branch import, so `D`'s address is at
the top of the static region where no later import can push it around. Branches
read it from there rather than off the stack: `Chain`'s frame already reaches
`own_program_digest` with `dup 11`, and five more words would bury it past
`dup 15`.

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
- [x] `LinkProofWitness` enum: `Forge | Chain | Update | Cast`
      (mirror `SingleProofWitness`; note `Fix` is NOT here)
  - [x] `Forge(Box<ForgeWitness>)` — the variant holds what the branch consumes,
        mirroring `SingleProofWitness::Collection(ProofCollection)`.
        `LinkPrimitiveWitness` is the `PrimitiveWitness` analog and, like it, is
        deliberately not a variant.
  - [x] `Chain(Box<ChainWitness>)` — holds the two operand kernels, the chained
        kernel, the cut-through set, and the two operand link proofs. It needs
        no memory projection.
  - [x] `Update(Box<UpdateWitness>)` — holds both kernels, both mutator set
        accumulators (pre-reduced, as `AuthenticateMsaAgainstTxk` eats them),
        the AOCL successor proof, and the old link proof. Its own memory
        projection, like `Chain`'s.
  - [x] `Cast(Box<CastWitness>)` (3) — holds the legacy transaction's kernel and
        its `SingleProof`. Its own memory projection, like `Chain`'s, though the
        branch reads only the proof out of it: the kernel is bound through its
        MAST hash, which is divined rather than recomputed, so the copy in memory
        is for the prover's sake (the hash, and the two authentication paths).
  - [x] `SecretWitness` impl — dispatches to the branch witness.
  - [x] `standard_input()` gains `|| D.reversed()`, `D` = the `SingleProof`
        program digest (§Breaking the `Fix`/`Cast` cycle). Landed ahead of
        `Cast`: the claim shape is consensus-visible and every later branch has
        to agree on it, so it is cheaper to establish -- and to test -- on two
        branches than on four. `Forge` carries `D` without reading it; `Chain`
        passes it through.
- [x] `SingleProofWitness::Fix(FixWitness)` — new variant on the *existing*
      enum (discriminant 3); recursively verifies a `LinkProof`. It holds the
      transaction kernel and the link proof, and nothing else: `thruputs == []`
      is not a field and not an assertion but the shape of the derived `lkmh`.
  - [x] `SingleProofWitness` loses its `SecretWitness` impl in the process.
        `program`/`claim`/`nondeterminism`/`produce` take a `ConsensusRuleSet`,
        because from delta onwards a witness cannot say by itself which of the
        two `SingleProof` programs it is being proven under, and the branches
        that recurse have to name the right digest.

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
  - [x] append `D`, **copied verbatim** from own public input, to both operand
        claims (audit-critical; §Breaking the `Fix`/`Cast` cycle). Read from the
        dispatcher's static slot, never from the witness -- which does carry a
        `single_proof_digest`, unread, precisely so that
        `witness_supplied_single_proof_digest_is_ignored` can prove it inert.
        Claims are built by `GenerateLinkProofClaim`, the two-digest analog of
        `GenerateSingleProofClaim`, living in `chaintx/` so the Rust edge to
        `single_proof` stays gone.
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
  - [x] **cut-through is maximal**: the chained kernel's outputs and its
        thruputs are disjoint, asserted outright. The two cut-through equations
        do not imply it -- they hold for *any* sub-multiset of the intersection,
        so on their own a prover could name a short `cut_through` and leave a
        matching (output, thruput) pair standing. Disjointness pins it to the
        whole intersection: the equations force cut-through multiplicity
        `c <= min(a, b)` for a record the operands hold `a` times as an output
        and `b` times as a thruput, and disjointness of the survivors then
        forces `c = min(a, b)`. A quadratic scan (`Contains` under `All`), since
        disjointness does not reduce to a multiset equation; an `AdditionRecord`
        is its own commitment, so it compares unhashed.
        (`non_maximal_cut_through_is_rejected`)
- [x] **Update** `LinkTx -> LinkTx`: re-target a new mutator-set hash without
      re-forging (mirror `single_proof/update_branch`). Same verbatim `D`
      pass-through onto the operand claim. `Update` re-targets the *mutator set*,
      never `D` -- and cannot: there is only one `D` in the program, the one the
      dispatcher read, and it goes into the operand claim verbatim.
  - [x] both mutator set accumulators authenticated against their own kernels'
        MAST hashes (shared `AuthenticateMsaAgainstTxk`, at `LinkKernel`'s
        height), and the new AOCL a successor of the old one.
  - [x] the inputs' absolute index sets are unchanged. The removal records
        themselves may be rewritten -- that is what re-targeting *is* -- but
        what a double spend collides on may not move.
  - [x] outputs, thruputs, announcements and fee carried over byte-for-byte:
        the *old* kernel's field bytes authenticated against *both* roots, which
        is one hash instead of two and rules out equal-hash-different-bytes by
        construction.
  - [x] thruputs unchanged is not a simplification: an `AdditionRecord` is a
        canonical commitment, which no mutator-set state enters into, so a
        thruput means the same thing before and after. Resolving one is `Chain`'s
        job.
  - [x] timestamp does not go backwards; new kernel carries no coinbase and no
        merge bit. The old kernel's two constant leafs are not re-checked --
        induction, as in `Chain`.
  - Deliberately *no* non-empty-input-set requirement, unlike `update_branch`;
        see §Governing invariants.
- [x] **Cast** `Transaction -> LinkTx`: recursively verify the input
      `SingleProof`, produce `LinkProof(thruputs = [])` so a regular
      `Transaction` can join a chain. The inner claim is
      `{ program: D, input: [txkmh] }` — `D` read from public input, *not*
      hardcoded: this is what breaks the cycle. The only branch that lets `D`
      name a *program*; everywhere else it is passed along untouched.
  - [x] the cast kernel is the transaction's kernel with no thruputs, in one
        hash: a `LinkKernel`'s nine leafs pad to sixteen and its first eight are
        exactly the legacy kernel's (already a power of two), so `txkmh` is the
        left child of `lkmh` and, thruputs being empty, the right child is the
        constant `no_thruputs_subtree_root()`. `txkmh` is divined and
        `hash_pair(txkmh, that constant)` must be `lkmh`. Empty thruputs are not
        a second check; they are baked into the constant.
        (`link_kernel.rs::mast_hash_pairs_the_kernel_root_with_the_thruputs_subtree`
        is what pins the structure the branch stands on.)
  - [x] no coinbase and no merge bit on the cast kernel, as constant leafs --
        which is to say a coinbase or an already-merged transaction cannot be
        cast. Deliberate: `Chain` relies on both by induction.
  - [x] nothing inspects the transaction's *contents*, the `SingleProof` being
        what says it is valid, and `Cast` adding nothing to it. In particular the
        mutator set is untouched: the cast link transaction names whichever one
        the transaction named, and requiring agreement is `Chain`'s job.
- [x] **Fix** = new `SingleProof` branch
      (`transaction/validity/tasm/single_proof/fix_branch.rs`): recursively
      verify the `LinkProof` against
      `{ program: <hardcoded LinkProof digest>, input:
      [lkmh, own_program_digest()] }` and produce a standard `SingleProof`. `D`
      is already the claim's second input, so `Fix` only has to *name*
      `own_program_digest()` there -- no claim-shape change left to make. The
      `own_program_digest()` in that claim is the sole tie between the two
      programs. Changes the `SingleProof` program hash (see §Consensus change).
  - [x] `thruputs == []` is not a separate assertion. `lkmh` is *derived*, not
        divined: `hash_pair(txkmh, no_thruputs_subtree_root())`, where `txkmh` is
        the public input -- i.e. the very transaction the outer claim is about.
        One hash binds the kernel and empties the thruputs at once, `Cast`'s
        binding read in the other direction. A link transaction that still
        carries thruputs has a different `lkmh` and so answers a different
        claim. (`link_transaction_with_thruputs_is_rejected`)
  - [x] no coinbase and no merge bit are *not* re-checked: they hold on the link
        kernel by induction over the `LinkProof` branches, and those two leafs
        sit at the same MAST positions in a `LinkKernel` as in the
        `TransactionKernel` it wraps.
  - [x] the branch asserts nothing of its own, so it declares no error IDs:
        every way of getting it wrong is a claim no link proof answers, and the
        negatives all land inside `stark_verify`.
- [x] claim generators for each; the `LinkProof` claim generator takes
      `(lkmh, D)` — `chaintx/generate_link_proof_claim.rs`, mirroring
      `GenerateSingleProofClaim`, whose second parameter is already a
      runtime-supplied program digest
      (`validity/tasm/claims/generate_single_proof_claim.rs:12`). It takes its
      three digests in stack order `[lkmh] [program_digest] [D]`, not claim
      order: `Chain` has to `dup` the program digest off its frame before `D`
      goes on, or it lands past `dup 15`.

## Consensus change (because SingleProof gains `Fix`)
- [x] New `ConsensusRuleSet` variant + per-network activation `BlockHeight`s
      (`consensus_rule_set.rs::infer_from`): `HardforkDelta`, at
      `BLOCK_HEIGHT_HARDFORK_DELTA_{MAIN_NET,TESTNET}`. **The heights are
      placeholders** (60_000 / 6_000) and want a real schedule before release.
  - [ ] Give delta its own `TritonProofVersion` when `triton-vm` bumps.
  - [x] `SingleProof` becomes a family indexed by the rule set, with
        `ConsensusRuleSet::has_fix_branch` as the one axis: two programs, two
        `OnceLock`s. Everything that produces or names a single proof takes a
        rule set, so the pre-delta program keeps running until the activation
        height, as it must.
  - [ ] `infer_from`'s catch-all (RegTest, TestnetMock, Testnet(n>0)) still
        answers gamma, so `Fix` is unreachable end-to-end there. Flip it to
        delta together with §Integration -- not before, since nothing yet
        builds a `LinkTx` on those networks and flipping invalidates every
        cached proof they use.
  - [ ] `ConsensusRuleSet::default()` is still gamma, deliberately: it is the
        rule set in force, and a caller that forgets to thread the real one
        should fall back to what today's peers accept. Move it with the
        activation.
- [x] Pin the new `SingleProof` program hash + the `LinkProof` program hash.
      Both `SingleProof` programs are pinned -- `tests::gamma_program` is the
      guard that adding `Fix` left the pre-delta program untouched, down to the
      static-memory addresses (which is why `FixBranch` is imported last).
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
- [x] the AOCL-membership half of the same loop: a confirmed input UTXO that is
      not the one its removal record spends —
      `confirmed_input_utxo_unbound_to_its_removal_record_is_rejected`. RRI has
      no counterpart to mirror; `forge_confirmed_loop_matches_rri` means this
      test covers both copies of the loop.
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
- [x] new timestamp older than old rejected (← `new_timestamp_older_than_old_prop`)
- [x] bad new AOCL rejected (← `bad_new_aocl_prop`)
- [x] bad old AOCL rejected (← `bad_old_aocl_prop`)
      (both in `mutator_set_accumulator_must_be_the_one_the_kernel_names`)
- [x] tampered absolute-index-set value rejected (← `bad_absolute_index_set_value_prop`)
- [x] tampered absolute-index-set length rejected (← `bad_absolute_index_set_length_too_short_prop`)
      (both in `tampered_absolute_index_set_is_rejected`)
- [x] changing a carried-over field -- outputs, thruputs, announcements, fee --
      rejected (`changing_a_carried_over_field_is_rejected`)
- [x] coinbase or merge bit on the new kernel rejected
- [x] the new kernel must be the one named in the claim
- Not applicable: merge-bit-unchanged (`update_branch` divines the bit and
  carries it across; a `LinkTx` never has it set, so the constant leaf is
  stronger)

### onto `Chain`
- Not applicable: coinbase-specific merge tests (`too_big_time_diff`,
  `authenticate_coinbase_fields_*`) — a `LinkTx` is never a coinbase transaction
- [x] chained inputs are the operands' inputs
- [x] chained announcements are the operands' announcements
- [x] chained fee is the sum of the operand fees (too big *and* too small)
- [x] a fee sum outside `[0, MAX_NAU]` is rejected
      (`fee_sum_outside_the_valid_range_is_rejected`).
- [x] a negative operand fee is rejected *even when the sum is a valid amount*
      (`negative_operand_fee_is_rejected_even_when_the_sum_is_valid`) — the case
      the range check cannot reach, caught by the assert that the `u128`
      addition did not carry. This is the test behind the no-negative-fees
      invariant; see §Governing invariants.
- [x] chained timestamp is the later of the operand timestamps
- [x] all three kernels agree on the mutator-set hash
- [x] coinbase / merge bit on the chained kernel rejected
- [x] bad MAST auth path rejected
- [x] chained kernel must be the one named in the claim
- [x] depth 2: a `Chain`-produced link proof is a valid operand
      (`chain_accepts_a_chain_produced_operand`) -- the only test that proves a
      `Chain`
- [x] an operand's link proof must attest to *that* operand: swapping the two
      proofs is rejected (`operand_proof_must_attest_to_its_own_operand`).
- [x] one-sided cut-through rejected, in both directions (← §cut-through value
      conservation, negative)
- [x] cut-through on unequal commitments rejected — the phantom-thruput
      argument, as a test: a thruput no predecessor output resolves can never
      be cancelled
- [x] a thruput cannot be cut through twice
      (`a_thruput_cannot_be_cut_through_twice`) — a thruput is not a removal
      record, so the host-machine check in `Block::is_valid` cannot check
      thruputs for double-spends. Setup: both `Chain` operands claim the same
      unconfirmed output. *Only one* claimed output between them is canceled; 
      the other survives as an obligation. `Fix` will not succeed because
      `thruputs` is not empty. Cancelling both fails the *outputs* equation.
- [x] chained *outputs* are the union of the operands' outputs when nothing cuts
      through (`chained_outputs_must_be_the_operands_outputs`).

### onto `Fix`
- [x] invalid `LinkProofWitness` discriminant crashes (← `invalid_discriminant_crashes_execution`)
- [x] invalid `SingleProofWitness` discriminant crashes (now that `Fix` is a
      variant) -- `single_proof.rs::invalid_discriminant_crashes_execution` now
      runs over both programs, and the pre-delta one gets `Fix`'s discriminant
      among its illegal values: a `Fix` witness handed to it names a branch that
      is not there, and must be rejected rather than ignored.

## Negative tests for `D` (the `SingleProof` digest in the `LinkProof` claim)

These guard §Breaking the `Fix`/`Cast` cycle. The invariant they defend — `D` is
copied verbatim into every child claim, and only `Fix` may name it — is the
difference between recursion and universal forgery, so *every* branch that
touches `D` gets a negative.

Claim / plumbing:
- [x] Claim shape pinned: `LinkProofWitness::standard_input()` ==
      `lkmh.reversed() || D.reversed()`, length `2 * Digest::LEN`. Order and
      length must never drift (analog of the `Forge` program-hash pin).
      (`link_proof_claim_shape_is_pinned`)
- [x] Proof/claim binding: a valid `LinkProof` for `[lkmh, D₁]` does **not**
      verify against `[lkmh, D₂]`, `D₁ ≠ D₂`.
      **Status: resolved.** Deliberately not written as a test, and not
      outstanding — the reasoning below settles it, and two existing tests cover
      the part that is actually ours. Do not re-open it.

      The check cannot fail, and not because of anything in this codebase. A
      STARK proof is made interactive-then-flattened: the prover derives the
      verifier's challenges by hashing a running transcript, and that transcript
      is seeded with the statement itself — program, input, output. So the
      challenges a proof answers are a function of the exact statement it was
      made for. Feed the same proof a different statement, the verifier derives
      different challenges, and the prover's pre-computed answers no longer fit.
      Nothing compares `D`; the mismatch falls out of the hashing. Writing the
      test would assert that Triton VM binds proofs to statements — the
      dependency's property, and its own suite's job. If it ever stopped
      holding, every proof in the system would be forgeable and this test would
      be the least of it.

      The entry was not pointless, though: the risk it aimed at is real, and it
      is ours. That risk exists because `D` is a *parameter* rather than a
      constant. Were it baked into the program there would be nothing to worry
      about, but the program reads it at runtime, so there is a live failure
      mode — **`D` gets read and then never actually used.** Read off the input,
      and then the claim built without it, or with something else. `D` would be
      decorative: anyone could name any digest, nothing would depend on it, and
      the whole indexing scheme would be theatre. That is universal forgery.

      Note the asymmetry. Fiat-Shamir guarantees a proof is bound to whatever
      statement you check it against, but says nothing about whether you built
      the *right* statement. That second part is entirely ours, and it is
      covered by two tests, because there are two places the bug could live:
      - `link_proof_claim_shape_is_pinned` — the Rust side, which is what the
        *prover* uses. Pins the claim's input to exactly `lkmh || D`, in that
        order, that length. Dropping `D` from the claim builder fails it.
      - `operand_forged_under_another_single_proof_digest_is_rejected` — the
        tasm side, which is what the *verifier* runs. Operands proven under one
        digest while the claim names another must be rejected. A branch that
        read `D` and then did not use it when constructing operand claims would
        pass this when it should fail.

      Both are needed: the prover's helper and the verifier's program are
      separate pieces of code, and either could be the one that forgets `D`.

`Chain`:
- [x] substituted operand `D`: the operands are proven under `D'` while the claim
      names `D` → rejected, inside `stark_verify`
      (`operand_forged_under_another_single_proof_digest_is_rejected`). Covers
      the mismatched-operands case too: what a wrong `D` on one operand does is
      exactly this. One test, not two: `verify_operand` is a single closure
      applied to both operands, reading `D` from the same static address either
      time, so the copy-paste slip has nowhere to live.
- [x] divined `D`: poke `single_proof_digest` in the witness's memory image,
      leave the public input alone → must still verify
      (`witness_supplied_single_proof_digest_is_ignored`). The negative stated as
      a positive: a branch that divined would fail it.
- [x] mixed provenance: `Chain(Forge'd with D₁, Cast'd with D₂)` → rejected.
      Two halves, and the first one dissolves the item's premise. `Chain` never
      *compares* two digests, because there is only one: `D` is read from the
      public input into a single static slot, and `generate_link_proof_claim`
      appends that one value to both operand claims (`chain.rs:945`). Operands
      supply no digest of their own, so mixed provenance is unrepresentable
      rather than rejected, and there is no laundering hazard to defend against
      — both operands are forced into the same `Link[D]` family by
      construction. How the junk operand was produced (`Forge` or `Cast`) is
      likewise irrelevant: `Chain` only ever checks the claim.
      What *is* worth pinning is that both claims are actually checked, and that
      needed a test: every other operand negative corrupts both operands at once
      (`operand_forged_under_another_single_proof_digest_is_rejected` forges each
      under `D'`; `operand_proof_must_attest_to_its_own_operand` swaps them), so
      the left verification alone trips all of them and deleting the right
      `verify_operand` call would have gone unnoticed by the whole suite.
      `each_operand_is_verified_against_the_claims_d` corrupts exactly one
      operand, in each direction, so the surviving verification is the only thing
      that can fire. Costs cache hits, not forges.

`Update`:
- [x] operand claim with `D' ≠ D` → rejected
      (`old_proof_forged_under_another_single_proof_digest_is_rejected`).
- [x] divined `D`: poke `single_proof_digest` in the witness's memory image,
      leave the public input alone → must still verify
      (`witness_supplied_single_proof_digest_is_ignored`). Narrower than
      `Chain`'s namesake: the dispatcher-slot-to-claim route is
      `GenerateLinkProofClaim`, shared and pinned there, so what this adds is
      that `Update` does not read the witness's copy on top of it.
-     `Update` cannot re-target `D`: output claim `D_new ≠ D_old` → rejected.
      Not written as its own test: there is no second `D` for the branch to
      name. It reads one digest, from the dispatcher's slot, and copies it into
      the operand claim; the *output* claim is not built by the branch at all --
      it is the public input. So re-targeting can only *look* like the two tests
      above: an operand proven under one digest and claimed under another
      (rejected), or a witness-supplied second digest (ignored).

`Cast`:
- [x] inner `SingleProof` claim built with a program digest ≠ `D` from public
      input → rejected
      (`transaction_proven_under_another_program_digest_is_rejected`), plus its
      mirror image `witness_supplied_single_proof_digest_is_ignored`: `D` poked
      in the witness's memory image, public input untouched → must still verify.
- [x] `Cast` under a bogus `SingleProof` program: the `Cast` succeeds, and the
      result is un-`Fix`able —
      `cast_under_a_bogus_single_proof_program_is_un_fixable`, in
      `fix_branch.rs` since that is where the payoff is asserted.
      `Cast` cannot check `D`, so a prover may name any program at all,
      including `read_io 5 halt` -- one that approves every transaction put to
      it and is claim-compatible by construction. Its proof verifies, the `Cast`
      is accepted (a plain `unwrap`, so that half cannot pass vacuously), and a
      `LinkTx` now exists attesting to nothing whatsoever. `Fix` then refuses
      it, *inside* `stark_verify`, which is what says the link proof is itself
      real and the digest is the sole disqualification. Together with
      `fix_accepts_a_resolved_link_transaction` -- the same construction under
      the true `D` -- that discharges "the only thing standing between it and a
      block".
      Note for anyone re-reading this item's original wording: the test does not
      literally name the `LinkProof` digest as `D`. That special case is
      *weaker*, not sharper -- `single_proof_claim` carries `txkmh` alone while
      `LinkProof` reads `lkmh || D`, so no proof of `LinkProof` answers a `Cast`
      inner claim and the substitution fails on input length, an accident of two
      unrelated claim shapes rather than a defence. A bogus program built to fit
      the claim is the real attack, and the only one worth pinning.
- [x] `Cast` of a `Transaction` whose `SingleProof` does not answer the claim →
      rejected: the recursion actually runs, which guards against `D` being read
      and then unused. Folded into
      `transaction_proven_under_another_program_digest_is_rejected`, which
      asserts the failure happens *inside* `stark_verify`; a *mock* proof is
      deliberately not used, since the verifier reads its garbage as lengths and
      exhausts the machine instead of rejecting. The positive counterpart,
      `cast_accepts_a_single_proof_backed_transaction`, runs the recursion
      against a real `SingleProof` and is the only test that does.

`Fix`:
- [x] a `Forge`'d `LinkTx` carrying an arbitrary junk `D` → rejected: the
      inert-by-construction argument, as a test
      (`link_proof_forged_under_another_single_proof_digest_is_rejected`). This
      is also the `D ≠ own_program_digest()` case: the branch reads one digest,
      its own, so a wrong `D` can only appear on the *proof*, never in the claim
      it builds. Naming the previous rule set's `SingleProof` digest, or the
      `LinkProof` digest, is the same test with a different junk value.
- [x] `Fix` with non-empty thruputs → rejected (also listed under §New Tests):
      `link_transaction_with_thruputs_is_rejected`.
- [x] the link proof must attest to the transaction the claim is about
      (`link_proof_must_attest_to_the_claimed_transaction`) -- the same single
      hash as the thruputs case, approached from the other side.

Positive counterparts (so the negatives cannot pass vacuously):
- [x] `Forge → Fix` with `D` = the real `SingleProof` digest accepts
      (`fix_accepts_a_resolved_link_transaction`) -- the one test that runs
      `Fix`'s recursion against a real `LinkProof`, and hence the one saying
      both digits of the claim it builds are the ones `LinkProof` establishes.
- [ ] end-to-end `Forge → Chain → Fix` with `D` = the real `SingleProof` digest
      throughout accepts, and the resulting `SingleProof` verifies. The
      `Forge → Fix` leg now runs all the way to a *proven* single proof, checked
      against the claim `single_proof_claim` hands a block
      (`forge_then_fix_yields_a_verifying_single_proof`) -- so what is missing is
      only the `Chain` in the middle.
- [ ] `Cast → Chain → Fix` round-trip with the real `D` accepts. The
      `Cast → Fix` leg is done and is the one test where the cycle closes end to
      end: a real `SingleProof` recursively verified by `Cast`, under the very
      digest a real `SingleProof` then instantiates in `Fix`
      (`cast_then_fix_yields_a_verifying_single_proof`; the transaction is proven
      under delta, not gamma as `cast.rs`'s own fixture is, because `D` is
      actually cashed out here). Missing, again, only the `Chain` in the middle.


## New Tests
- [x] Property: `Chain` associativity:
      `Chain(Chain(A, B), C) = Chain(A, Chain(B, C))` (`chain_is_associative`),
      up to the order of the multisets, and on the cut-through sets too.
- [ ] Property: `Fix` distributivity: `Fix(Chain(A, B)) = Merge(Fix(A), Fix(B))`
      when `thruputs == []`
- [x] `Chain`: new timestamp unequal to max rejected
- [ ] Thruput-input integrity: a thruput must equal an output of a predecessor
      in the chain (validated against that output, not mutator-set membership).
      The negatives are all there -- `cut_through_on_unequal_commitments_is_rejected`
      bounds the cut-through set below the outputs, `non_maximal_cut_through_is_rejected`
      above, `a_thruput_cannot_be_cut_through_twice` fixes the multiplicity, and
      `link_transaction_with_thruputs_is_rejected` closes the far end. The
      positive is `thruputs_resolve_in_two_stages`: a successor funded entirely
      by unconfirmed money, one thruput from each of two predecessors, chained
      in one at a time. The intermediate carries a thruput of its own, which is
      the honest carry-forward -- and the shape that makes the property mean
      anything, since both other positives chain to zero thruputs
      (`chain_accepts_a_predecessor_successor_pair` asserts as much;
      `chain_accepts_a_chain_produced_operand` uses `from_primitive_witness(pw, 0)`).
      It is also the two-stage resolution the mempool will actually produce,
      parents arriving separately. The fixture had to grow a range rather than a
      count -- `predecessor_resolving(&pw, range)`, which
      `chainable_link_primitive_witnesses` now delegates to -- because a
      successor's thruputs need not all come from one predecessor.
- [x] Negative: `LinkKernel` carrying a coinbase rejected. All four branches
      that mint or rewrite a kernel now have it:
      `coinbase_or_merge_bit_on_the_forged_kernel_is_rejected` (new),
      `..._on_the_chained_kernel_...`, `..._on_the_new_kernel_...` (`Update`),
      `..._on_the_cast_kernel_...`; each pokes both leafs and expects
      `ROOT_MISMATCH`, the two being constants the branches authenticate rather
      than values they read. `Fix` needs none: it derives the link kernel from
      the transaction kernel and verifies a `LinkProof`, and no branch that can
      produce one admits a coinbase, so it holds by induction.
      `coinbase_kernel_is_rejected` / `merge_bit_is_rejected` are the proof-free
      tier's counterparts.
- [ ] `Update` then `Fix` == `Fix` on the updated mutator set
- [x] `Cast` round-trip: `Cast(tx)` then `Fix` == `tx`
      (`cast_then_fix_yields_a_verifying_single_proof`). Equality is asserted on
      the *claim*: `Cast` adds nothing and `Fix` takes nothing away, so the
      composition is the identity on what a block checks -- which is what makes
      casting safe to do opportunistically, a transaction that joins a chain and
      finds no partner being no worse off than one that never joined.
- [x] Negative: `Fix` with non-empty thruputs rejected
      (`link_transaction_with_thruputs_is_rejected`)
- [x] Negative: `Chain` with mismatched thruputs rejected (a cut-through whose
      commitment matches no output)
- [ ] End-to-end: `Fix`'d tx passes existing `SingleProof` verification & enters
      into a block. First half done: both pipeline tests above prove the fixed
      transaction and verify the proof with `triton_vm::verify` against
      `single_proof_claim`, which is the claim the verifier out in the world
      builds. Entering a block waits on §Integration.
- [x] Phantom thruputs / phantom confirmed UTXOs are rejected. One assert covers
      both partitions rather than two: an unbacked UTXO in *either* half changes
      `|input_utxos|` and nothing else, so it dies on the cardinality equality
      (`phantom_input_utxo_is_rejected`, `CARDINALITY_MISMATCH_ERROR`) before
      either per-partition loop runs. The count-preserving flavors -- a UTXO
      swapped for another rather than appended -- are the "bad commitments"
      entry below; between them the inflation path is closed from both sides.
- [x] Bad commitments are rejected, on all three lists. Thruput side:
      `tampered_thruput_is_rejected` (`UTXO_COMMITMENT_MISMATCH_ERROR`). Output
      side: `output_utxos_unbound_to_addition_records_is_rejected` (same id).
      Confirmed-input side: `confirmed_input_utxo_unbound_to_its_removal_record_is_rejected`
      (new) -- the recomputed commitment stops being the AOCL leaf, so the
      inlined RRI membership check rejects; and
      `bad_absolute_index_set_is_rejected` for the index-set half of the same
      binding.
- [x] Cardinality. `phantom_input_utxo_is_rejected` /
      `phantom_output_utxo_is_rejected` trip the input- and output-side guards.
      Only the "one too many" direction is poked; both guards are equality
      asserts, so "too few" reaches the identical instruction. The
      parallel-vector lengths (`membership_proofs`, `thruput_sender_randomnesses`,
      ...) are checked at the proof-free tier instead --
      `short_thruput_randomness_fails_cardinality`.
- [x] Two representations of thruputs must agree.
      `unauthenticated_thruput_is_rejected` pins the kernel's `thruputs` leaf to
      the witness vector (`ROOT_MISMATCH`); `tampered_thruput_is_rejected` pins
      that vector to the input-UTXO tail partition. Count disagreement is the
      cardinality entry above. There is no third representation to disagree --
      `ForgeWitness` holds one `thruputs` field.
- [x] Faithful union. `forge_accepts_valid_witnesses` runs every split of
      `0..=3` inputs into confirmed and thruputs -- so the genuinely mixed
      shapes (1+1, 2+1, 1+2) and both extremes -- through `produce`, which
      proves the *unchanged* type scripts over the union `confirmed || thruputs`,
      and `Forge` then recursively verifies them.
      `forge_accepts_timelocked_witness` repeats it for a two-type-script
      witness. Caveat worth keeping: the balance claim rests on NativeCurrency
      proving at all, not on an assertion of the sum. `all_thruputs_is_valid` is
      the sharpest statement of it -- a witness with zero confirmed inputs
      balances only if thruput value counts toward the input side.
- [x] Chain rejects a bad MAST auth path for an operand's `inputs` / `outputs` /
      `thruputs` / `fee`. (One path tampered; every field goes through the same
      snippet.)
- [x] cut-through value conservation (positive): a cut-through cancels a
      (thruput, output) pair only when their canonical commitments are equal,
      and removes it from both sides together — so no value is created or
      destroyed.
- [x] Cut-through is maximal: a short `cut_through`, leaving a cancellable
      (output, thruput) pair standing, is rejected
      (`non_maximal_cut_through_is_rejected`).
- [x] Cut-through value conservation (negative): one-sided removal, or a cancel
      on unequal commitments, is rejected.

## Benchmarks
- [ ] `Forge` (inlined RRI) vs `Prove`+`Raise` (recursive RRI) — the cost claim
- [ ] N chained interactions in one block vs N separate txs (throughput claim)

## Audit
- [ ] Scoped security audit

[1]: https://talk.neptune.cash/t/transaction-chaining-in-neptune-cash/349
