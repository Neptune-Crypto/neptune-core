# Transaction Chaining — Implementation Plan and Progress Tracker

Follow the design in [1].

## Motivation

Two mechanisms — chaining with cut-through of predecessor-successor txs, and
promotion of thruputs the mutator set has since confirmed — paying off in four
places:

- **Throughput for self-perpetuating UTXOs / DeFi.** Today a block admits at
  most one interaction with a given smart-contract UTXO, capping e.g. a DEX at
  one trade per block. Chaining lets many interactions accumulate and collapse
  into a single block-borne transaction. And because a contract UTXO publishes
  its spending data in an announcement (§Integration), the chain need not be
  fully assembled before a block: one link confirming mid-chain does not break
  the rest — any node can promote the successors' thruputs and carry on.
- **Spending unconfirmed funds.** Ordinary users (and wallets doing
  change-splitting or consolidation) can build on outputs that aren't yet in a
  block, instead of waiting a full confirmation between dependent payments.
- **Surviving a partial confirmation.** Without promotion, a successor whose
  predecessor is mined *alone* is stranded permanently: its thruput can only be
  retired by cut-through against an operand carrying that output, and the
  predecessor is now confirmed and can never be chained again. The only recovery
  would be a re-forge from scratch. `Advance` moving confirmed thruputs into the
  confirmed inputs turns that into a routine advance. This is what makes
  chaining safe to use by default, rather than only when a whole chain lands
  together.
- **Cheaper initiation.** `Forge` inlines `RemovalRecordsIntegrity`,
  `KernelToOutputs`, `CollectLockScripts`, and `CollectTypeScripts`
  *non-recursively*, and the route to a `SingleProof` comes out roughly a third
  cheaper than the single-proof one (§Benchmarks). The saving is not in the inlining
  itself — proving them separately is a rounding error against either route's
  total. It is that the chained route recursively verifies three fewer proofs.
  Recursive verification is the dominant cost in all of these programs.

### Why `Weld`

`Weld` is a shortcut across the seam between the two pipelines. Given a
`SingleProof`-backed transaction A and a link transaction B whose thruputs A's
outputs resolve, it computes in one program what `Fix(Chain(Cast(A), B))`
computes in three. This is the join the chain pipeline performs whenever a
`LinkTx` finds its predecessor already in the single-proof pipeline -- what
§Mempool calls cast-on-demand -- so it is worth having as an operation rather
than as a routine. It pays off twice.

- **Cheaper joining**, by the same arithmetic as *Cheaper initiation* above. The
  decomposition costs three proofs and four recursive verifications: `Cast`
  verifies A, `Chain` verifies both operands, `Fix` verifies the result. `Weld`
  costs one proof and two, verifying A's `SingleProof` and B's `LinkProof`
  directly. Recursive verification being the dominant cost, that is half the
  work, in one STARK rather than three.
- **Joining *after* the merge.** This one is not an optimization; the
  decomposition cannot express it. `Cast` refuses a transaction carrying the
  merge bit, and the merge bit is exactly what makes a kernel a
  `BlockTransactionKernel` -- eligible to *be* a block's transaction. So the
  three-step route has to run before the block transaction is assembled: a chain
  that resolves afterwards can only be included by redoing the merge. `Weld`
  carries A's merge bit through, so a resolved chain welds into a block
  transaction that is already merged and already block-eligible. That is what
  lets a composer keep admitting chained fee-payers while it holds a candidate,
  instead of freezing the set at merge time.

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
  `Chain`/`Advance`/`Cast`) get the full soundness audit, same bar as the
  existing `SingleProof` branches. Promotion makes `Advance` a *second* RRI
  site: its promotion loop derives an absolute index set from divined preimages
  and an AOCL membership proof exactly as `Forge`'s confirmed loop does, so a
  soundness bug there is equally a double-spend path and carries the same audit
  bar.
- **Type scripts see a singleproof transaction.** The type-script-facing salted input
  UTXOs contain *both* confirmed UTXOs *and* thruputs, and the kernel MAST
  exposes fee/coinbase/timestamp at transaction-kernel leaf positions — so `NativeCurrency`
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
- **A `LinkTx` may hold zero confirmed inputs, so `Advance` does not require
  otherwise.** An all-thruputs link -- one funded entirely by its predecessors
  -- is a normal shape in this pipeline, and it still has to follow the mutator
  set: `Chain` requires all three of its kernels to agree on the mutator set
  hash, so a link that cannot be advanced is stranded the moment any chain
  partner moves. This is a deliberate divergence from `update_branch`, which
  rejects an empty input set outright (`INPUT_SET_IS_EMPTY_ERROR`). The single-proof pipeline's
  restriction's rationale is recorded nowhere -- not in the code, not in the
  (squashed) history -- so the divergence rests on the reasoning above rather
  than on a demonstrated equivalence. Induced obligation: the audit has to
  either confirm that reasoning or recover what the single-proof check was defending,
  in which case whatever it defends has to be re-established for the chain
  pipeline some other way.
- **Promotion is permitted, not mandatory.** `Advance` *may* move a thruput
  confirmed since the old mutator set into the confirmed inputs; it is never
  obliged to, and `P = []` is the ordinary case. Unlike cut-through, maximality
  here is not enforceable: it would take a proof that a thruput's commitment is
  *absent* from the new AOCL, and MMR non-membership is not cheap. Nothing is
  lost by the asymmetry — an unpromoted thruput just keeps the `LinkTx`
  un-`Fix`able, which is inert, and the same promotion can be done by a later
  advance. Induced obligation: no branch, and no mempool bookkeeping, may assume
  a resident `LinkTx`'s thruputs are all still unconfirmed.
- **Two thruputs may not be promoted at one AOCL leaf.** They would put two
  removal records with the same absolute index set in one kernel — one confirmed
  UTXO spent twice, while `Forge` counted it twice on the type-script-facing
  input side. `Advance` forbids it directly (§Tasm > `Advance`), which keeps a
  `LinkProof` from ever attesting to such a kernel; the block rule named next
  would reject it at block time regardless, so the supply is never at risk.
  The neighbouring case, a promoted index set colliding with one already in
  `old.kernel.inputs`, is *not* visible to `Advance` — a removal record does not
  reveal which AOCL leaf it spends — and is left to block rule 2.c
  (`block/mod.rs:866`,
  `BlockValidationError::RemovalRecordsUniqueness`), which sorts and dedups the
  block transaction's index sets unconditionally and therefore covers a `Fix`ed
  `LinkTx`. That is the same reliance `Merge` already has.
- **No negative fees anywhere in a chain — so upgraders must gobble fees with
  standard transactions.** `Chain` adds the operand fees as `u128`s and asserts
  the addition does not carry, which forbids a negative operand fee outright.
  `merge_branch` does the opposite: it *pops* the carry (`merge_branch.rs:520`)
  precisely so that a negative fee on its LHS wraps and adds correctly, and
  therefore still needs an explicit bound on its RHS. Consequence: an upgrader
  that pays itself by merging in a negative-fee transaction has to do it on the
  single-proof `Transaction`/`Merge` path; there is no negative-fee `LinkTx` to
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
- `Advance`: same verbatim pass-through onto the operand claim.
- `Cast`: verifies `{ program: D, input: [txkmh] }` — the only *use* of `D`.
- `Fix` (a `SingleProof` branch, not a `LinkProof` one): verifies
  `{ program: <hardcoded LinkProof digest>, input: [lkmh, own_program_digest()] }`
  and asserts `thruputs == []`.

Rust side: `LinkProofWitness::standard_input()` returns
`lkmh.reversed() || D.reversed()`, so `D` must be reachable from the witness —
an explicit field on each branch witness (`ChainWitness`, `AdvanceWitness`,
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
`D`. `Chain`/`Advance`: operands carry the same `D`, so the IH applies to both
subtrees. `Fix` instantiates `D := own_program_digest()`, already pinned by the
outer verifier to the consensus `SingleProof` digest ⇒ anything block-borne was
`Cast` only from genuine `SingleProof`s.

**The residual prover freedom is inert.** A `Forge`/`Cast` prover may name any
`D`, but `Chain` refuses to mix `D`s and `Fix` accepts only its own, so a
wrong-`D` chain is never block-borne — same shape of argument as the
phantom-thruput case above.

**The audit-critical line.** `D` must be *copied* from public input into every
child claim in `Chain`/`Advance` — never divined, never re-derived from witness
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
- [ ] Glossary: the **promotion equations** = the coupled pair `Advance`
      enforces over the witness-supplied promotion set `P`, both compared as
      multisets:

          multiset(old.thruputs) == multiset(new.thruputs) ⊎ records(P)
          indexsets(new.inputs)  == indexsets(old.inputs) ⊎ indexsets(P)

      Name them in `transaction.md` and write them out there verbatim. The
      term already earns its keep in the code -- `assert_promotion_equations`
      is the tasm subroutine that checks exactly this pair -- so the spec
      should use the same words. Say why they are one thing and not two: an
      addition record leaves the thruput list if and only if a removal record
      carrying its index set joins the input list. Say what `P = []` means:
      thruputs and index sets both unchanged, which is the update that
      promotes nothing.
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
    Promotion opens no second escape: it matches on the same canonical
    commitment and additionally demands an AOCL membership proof for it, so a
    thruput answering to no real UTXO can no more be promoted than cut through.

## Data Structures
- [x] `LinkKernel { kernel: TransactionKernel, thruputs: Vec<AdditionRecord> }`
      (compose — reuse kernel MAST/hashing, no field drift)
- [x] MAST encoding: thruputs as one extra leaf beside the existing kernel
      leafs
- [x] `LinkTx { kernel: LinkKernel, proof: LinkProof }`
- [x] `LinkPrimitiveWitness` — primitive-witness analog consumed by `Forge`
- [x] an arbitrary strategy obtained by lifting its `PrimitiveWitness` analog
- [x] `validate` -- analogous to `PrimitiveWitness::validate`
- [x] `LinkProofWitness` enum: `Forge | Chain | Advance | Cast`
    (mirror `SingleProofWitness`; note `Fix` is NOT here)
- [x] `Forge(Box<ForgeWitness>)` — the variant holds what the branch consumes,
      mirroring `SingleProofWitness::Collection(ProofCollection)`.
      `LinkPrimitiveWitness` is the `PrimitiveWitness` analog and, like it, is
      deliberately not a variant.
- [x] `Chain(Box<ChainWitness>)` — holds the two operand kernels, the chained
      kernel, the cut-through set, and the two operand link proofs. It needs
      no memory projection.
- [x] `Advance(Box<AdvanceWitness>)` — holds both kernels, both mutator set
      accumulators (pre-reduced, as `AuthenticateMsaAgainstTxk` eats them),
      the AOCL successor proof, and the old link proof. Its own memory
      projection, like `Chain`'s.
- [x] `AdvanceWitness::advance` gains a promotions argument, and mirrors every
      assertion the branch makes so that a bad witness
      fails in milliseconds instead of after a proof. Ascent is asserted
      rather than imposed by sorting: order carries no information -- an entry
      names neither the thruput nor the input it moves -- so sorting would be a
      safe repair, but the constructor refuses a mis-ordered set rather than
      silently rewriting what it was handed. Callers therefore do see the
      branch's ordering requirement.
- [x] `Cast(Box<CastWitness>)` (3) — holds the singleproof transaction's kernel and
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
- [ ] `SingleProofWitness::Weld(WeldWitness)` — second new variant on the same
      enum (discriminant 4). Holds A's kernel and `SingleProof`, B's
      `LinkKernel` and `LinkProof`, and the welded kernel. Its own memory
      image, like `ChainWitness`; the cut-through set is *not* a field, see
      §Tasm.
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
        *inner* `TransactionKernel` MAST root (type scripts see the transaction
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
- [x] **Advance** `LinkTx -> LinkTx`: re-target a new mutator-set hash without
      re-forging (mirror `single_proof/update_branch`). Named `Advance` rather
      than `Update` deliberately: `UpdateWitness` would otherwise name two
      different types in this repo, and once promotion lands the branch does
      strictly more than the legacy mirror it is named after. Same verbatim `D`
      pass-through onto the operand claim. `Advance` re-targets the *mutator
      set*, never `D` -- and cannot: there is only one `D` in the program, the
      one the dispatcher read, and it goes into the operand claim verbatim.
  - [x] percolate the rename into the code, which still says `Update`:
        `update.rs` -> `advance.rs`, `Update`/`UpdateWitness` ->
        `Advance`/`AdvanceWitness`, `DISCRIMINANT_FOR_UPDATE`,
        `update_branch_source` -> `advance_branch_source`, the
        `neptune_consensus_chaintx_link_proof_update_branch` entrypoint,
        `LinkProofWitness::Update`, and the `updatable` /
        `deterministic_updatable` fixtures. Discriminant *values* stay put, and
        the entrypoint label is an assembly label rather than part of the
        program encoding, so the rename does not move `LinkProof`'s hash --
        `test_program_snapshot!` should still pass untouched. Do it *last*,
        after promotion and after everything else on this branch: a rename
        touches every line it appears on, so landing it early rebases badly
        against every diff that follows.
  - [x] both mutator set accumulators authenticated against their own kernels'
        MAST hashes (shared `AuthenticateMsaAgainstTxk`, at `LinkKernel`'s
        height), and the new AOCL a successor of the old one.
  - [x] the inputs' absolute index sets are unchanged. The removal records
        themselves may be rewritten -- that is what re-targeting *is* -- but
        what a double spend collides on may not move. (Superseded by promotion,
        below: the index sets may now *grow*, by exactly the promoted set.)
  - [x] outputs, announcements and fee carried over byte-for-byte: the *old*
        kernel's field bytes authenticated against *both* roots, which is one
        hash instead of two and rules out equal-hash-different-bytes by
        construction. Thruputs were in this list until promotion; they are now
        governed by the multiset equation below instead.
  - [x] **promotion**: a thruput confirmed since the old mutator set may move
        into the confirmed inputs. This replaces the two assertions above --
        index sets unchanged, thruputs byte-for-byte -- with one coupled pair
        over a witness-supplied promotion set `P`:

            multiset(old.thruputs) == multiset(new.thruputs) ⊎ records(P)
            indexsets(new.inputs)  == indexsets(old.inputs) ⊎ indexsets(P)

        so an addition record leaves the thruput list if and only if a removal
        record carrying its index set joins the input list -- the same
        leaves-one-side-iff-it-leaves-the-other shape as `Chain`'s cut-through.
        `P = []` collapses the pair back to exactly the two old assertions, so
        today's behaviour is the empty case rather than a special one, and
        `INPUT_INDEX_SETS_ARE_NOT_UNCHANGED_ERROR` gives way to two new ids. The
        machinery is already in the module: `HashRemovalRecordIndexSets::<1>`
        and `::<2>`, `ChainMap::<1>` and `::<2>`, used exactly as `chain.rs`
        uses them for the cut-through equations.
  - [x] the promotion set `P` is a `Vec<Promotion>` on `UpdateWitness`, hence in
        the memory image -- `UpdateWitness` *is* its memory image. One entry is
        `(item, sender_randomness, receiver_preimage, aocl_leaf_index)`, the
        tuple `Forge`'s confirmed loop divines, plus the AOCL authentication
        path, which reaches the branch on the digest stream and sits in memory
        unread. Nothing in an entry names *which* thruput or *which* input it
        moves: the two equations above do the matching. Memory-resident rather
        than divined so the loop count is the list length rather than a
        length difference, and so the loop re-reads its operands instead of
        stashing them.
  - [x] per promoted entry, read out of `P`:

            commit(item, sr, hash(rp))                  == the retired thruput
            aocl_verify(new_aocl, idx, that commitment)
            compute_absolute_indices(item, sr, rp, idx) == the joined index set

        The first is the inflation-critical one: without it a promoted input
        could spend a *different* UTXO than the one whose lock script `Forge`
        proved. The second is what "confirmed in the meantime" means, and it is
        against the *new* AOCL -- the one the new kernel names.
  - [x] promoted `aocl_leaf_index`es are pairwise distinct, encoded as strictly
        ascending: one u64 comparison per iteration against a `previous + 1`
        carried in the loop's stack invariant, rather than a set or a sort. The
        `+ 1` cannot wrap, since the AOCL membership check above already bounds
        each index below `num_leafs`. Rationale and the neighbouring case that
        is *not* checked here: §Governing invariants.
  - [x] no static memory at all, unlike `Forge`'s loop: the whole state is an
        eight-word stack invariant,

            _ *new_aocl *records *indexes [previous + 1] num i *promotions[i]_si

        and everything else the body touches is a field of the entry the cursor
        is on. The deepest reach is `dup 14`, one word inside the sixteen
        addressable. This is what makes the loop `kmalloc`-free: `Forge` stashes
        its four divined values because it has nowhere else to put them, and a
        memory-resident `P` has the entry to read back instead.
  - [x] nondeterminism: only the AOCL authentication paths, in promotion order,
        appended to the digest stream after the field authentications and
        before `StarkVerify`'s -- the promotion loop sits between them. 
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
        exactly the transaction kernel's (already a power of two), so `txkmh` is the
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
- [ ] **Weld** `Transaction * LinkTx -> Transaction` = second new `SingleProof`
      branch (`transaction/validity/tasm/single_proof/weld_branch.rs`): the
      direct route to what `Fix(Chain(Cast(A), B))` computes in three proofs and
      four recursive verifications. `Weld` does it in one proof and two, against
      `{ program: own_program_digest(), input: [txkmh_A] }` and
      `{ program: <hardcoded LinkProof digest>,
      input: [lkmh_B, own_program_digest()] }`. One digest, read once, named in
      both claims -- `Fix`'s trick applied twice. Lands *with* `Fix`, in the same
      program and the same rule set: added afterwards it would cost a second
      hardfork and a second `D` migration (§Consensus change).
  - [ ] **not** `Fix ∘ Chain ∘ Cast`. The contract diverges in both directions,
        and says so:
        - *more permissive*: `Cast` refuses a merge-bit-bearing transaction,
          so the decomposition never accepts one. `Weld` does, and ignores the
          bit, using the `Transaction`'s merge-bit instead.
        - *more restrictive*: `Chain` cancels a thruput against its own
          operand's output as readily as against the other's (`chain.rs:222`).
          `Weld` cuts B's thruputs against A's outputs only.
  - [ ] cut-through, with no witness-supplied cut multiset and no maximality
        check -- both fall out of the restriction above and of the output type:
```
            A.outputs     ≡ leftover ⊎ B.thruputs
            weld.outputs  ≡ leftover ⊎ B.outputs
```
        A `TransactionKernel` has no thruputs field, so an unresolved thruput is
        not representable; it is *unprovable*. A thruput of B absent from A's
        outputs fails the first equation, and that is the whole of "the thruputs
        must be empty after cut-through", in one multiset split. The machinery is
        `Chain`'s -- `ChainMap` and the multiset-equality snippets -- minus the
        cut set and minus the maximality check.
  - [ ] no coinbase on A. Neither operand's proof gives it: the `LinkProof`
        induction covers B, and a `SingleProof`-backed transaction is entitled to
        a coinbase. On the decomposition path `Cast` is what refuses one
        (`cast.rs:391`), and `Weld` deletes `Cast` from the path. Without the
        assertion a coinbase-bearing A welds into a kernel declaring no coinbase
        while its outputs still carry the subsidy, and nothing re-runs a type
        script over the welded kernel to catch it.
  - [ ] the merge bit is *carried*, not asserted: `weld.merge_bit ==
        A.merge_bit`. B's is false by induction over the `LinkProof` branches, so
        "A's" and "either operand's" coincide; "A's" is the one to state. The bit
        is what makes a kernel a `BlockTransactionKernel`
        (`block_transaction.rs:37`), i.e. eligible to *be* a block's
        transaction, so carrying it is what lets a resolved chain weld into an
        already-merged block transaction without re-merging -- one weld where the
        decomposition needs a cast, a chain, a fix and a second merge.
    - [ ] consequence: `Merge` stops being the only producer of a set merge bit,
          and `have_merge_relationship` (`transaction_kernel.rs:176`) infers from
          it, assuming a merge output has no fewer outputs than either input.
          Cut-through can leave `Weld`'s with fewer than A's. Its one caller is
          the mempool's merge-input cache (`mempool.rs:1051`), so this degrades
          bookkeeping rather than consensus -- but it wants a look before
          release.
  - [ ] fee: the sum, in `[0, MAX_NAU]` with no carry. `Chain`'s argument
        verbatim (`chain.rs:1297`), and it bounds *both* operands at once -- raw
        `u128` addition makes a negative amount enormous, so a negative A or B
        either carries or lands out of range. No separate assertion on A's fee.
  - [ ] timestamp is the later of the two; A, B and the weld share one
        mutator-set hash; inputs and announcements are the concatenations.
        `Chain`'s rules, unchanged.
  - [ ] discriminant 4. The pre-delta program counts 3 *and* 4 as out of range
        (`single_proof.rs::invalid_discriminant_crashes_execution`).
- [x] claim generators for each; the `LinkProof` claim generator takes
      `(lkmh, D)` — `chaintx/generate_link_proof_claim.rs`, mirroring
      `GenerateSingleProofClaim`, whose second parameter is already a
      runtime-supplied program digest
      (`validity/tasm/claims/generate_single_proof_claim.rs:12`). It takes its
      three digests in stack order `[lkmh] [program_digest] [D]`, not claim
      order: `Chain` has to `dup` the program digest off its frame before `D`
      goes on, or it lands past `dup 15`.

## Consensus change (because SingleProof gains `Fix` and `Weld`)
- [x] New `ConsensusRuleSet` variant + per-network activation `BlockHeight`s
      (`consensus_rule_set.rs::infer_from`): `HardforkDelta`, at
      `BLOCK_HEIGHT_HARDFORK_DELTA_{MAIN_NET,TESTNET}`. **The heights are
      placeholders** (60_000 / 6_000) and want a real schedule before release.
  - [x] Give delta its own `TritonProofVersion` when `triton-vm` bumps.
  - [x] `SingleProof` becomes a family indexed by the rule set, with
        `ConsensusRuleSet::has_chain_branches` as the one axis: two programs, two
        `OnceLock`s. Everything that produces or names a single proof takes a
        rule set, so the pre-delta program keeps running until the activation
        height, as it must.
  - [x] `infer_from`'s catch-all (RegTest, TestnetMock, Testnet(n>0)) still
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
      guard that adding `Fix` and `Weld` left the pre-delta program untouched,
      down to the static-memory addresses (which is why `FixBranch` and
      `WeldBranch` are imported last).
- [ ] soundness audit: `SingleProof` `Fix` branch, and `Forge`'s inlined RRI
      + the recursion in `Chain`/`Advance`/`Cast`, including the verbatim `D`
      pass-through
- [ ] Regenerate/store proof artifacts for the new program versions
- [x] Arrival-side `D` binding at a rule-set change: `link_tx_claim` pins `D` to
      the active rule set's `SingleProof` digest, so a link carrying a stale one
      is inadmissible (§Peer). Vacuous at delta's own activation -- no `LinkTx`
      can be in the mempool under gamma, `has_chain_branches()` being false there.

## Integration
### Transaction-Initiation
- [x] Builder path: witness -> `Forge` -> `LinkTx` (parallel to existing
      initiator)
- [x] API surface in `neptune-core/src/api`
- [x] `Cast` entry point for pulling an existing Transaction into a chain
- [ ] Announcement payload for self-perpetuating UTXOs:
      `{ utxo, sender_randomness, receiver_preimage }` — `UtxoTriple`
      (`transaction/utxo_triple.rs:18`) with the preimage in place of the
      digest, so it yields a `UtxoTriple` for free (`receiver_digest =
      receiver_preimage.hash()`) and reuses its `addition_record()` rather than
      restating the commitment. Written by the transaction that *creates* the
      contract UTXO, for whoever later promotes a thruput spending it.
      Deliberately not `TransparentInput`
      (`transaction/transparent_input.rs:37`), which additionally carries
      `aocl_leaf_index`: the creating transaction cannot know it, an output's
      AOCL position being fixed only by the block that confirms it and by what
      lands ahead of it there. `TransparentInput` can carry it because it is
      written by the *spender*, who already holds a membership proof. The
      promoter recovers the index instead, by matching the announced commitment
      against the confirming block's addition records.
      Publishing the preimage grants no spending authority: it lets a third
      party *complete* an authorization the forger already gave -- the
      lock-script proof was made at `Forge` time -- and the commitment equation
      pins that authorization to one thruput.

### Mempool
The mempool holds both single-proof `Transaction`s and `LinkTx`s. A `LinkTx` with
non-empty `thruputs` is *unresolved* — not yet block-eligible.
Chaining is opportunistic and bounded: the authoritative `LinkTx`->`Transaction`
map happens at time of block-template construction. The mempool `Chain`s
(with cut-through) on arrival first-come-first-served and rate-limited (via fee)
so that a crafted flood cannot force unbounded proving. Value-safety never
depends on the mempool — an unresolvable `LinkTx` is inert (un-`Fix`able). In
the worst case, space is wasted, until transactions are evicted.

- [x] Store both `Transaction` and `LinkTx`.
- [ ] Index mempool-members (of either type) by: confirmed inputs (existing
      double-spend index), thruputs (new + if applicable), and outputs (new) —
      the last two are what let an arrival find its `Chain` partners.
- [ ] On arrival, look up predecessors (`member.outputs` ⊇ `arrival.thruputs`)
      and successors (`member.thruputs` ⊆ `arrival.outputs`), and perform
      cut-through on matching pairs if the fee is large enough.
- [ ] Conflict rules: two mempool members on the same confirmed input (already a
      conflict now), OR two successors with overlapping thruputs (new). In case
      of conflict, replicate existing policy and exit-queue construction.
- [x] On new block: evict members whose confirmed inputs were spent, and
      `Advance` locally-initiated proof-backed members to the new
      mutator-set hash.
- [ ] Evict members whose predecessor was dropped: nothing re-checks
      `contains_outputs` after a block, so an orphaned successor lingers
      until the (unbuilt) TTL.
- [ ] A member whose predecessor was *confirmed* is no longer evicted --
      its thruputs are promoted instead. `mempool.rs:1704` currently does
      the opposite, on the pre-promotion premise that a mined thruput can
      never be cut through. Blocked on the preimage source: §582
      (announcement) or §626 (wallet).
- [ ] Promotion on advance, best-effort, chosen by preimage availability:
      (a) published in an announcement (self-perpetuating UTXOs) -- any node
      promotes; (b) held by the wallet -- only the owner promotes; (c) neither
      -- plain re-target, and the member stays unresolved until it chains or
      its TTL expires. Candidates and their `aocl_leaf_index`es both fall out of
      matching members' thruputs against the new block's addition records,
      which is a scan the mempool needs anyway to notice a thruput was
      confirmed.
- [x] Integrate mempool-member `LinkTx`s into priority queue.
- [x] Eviction: bound mempool size and evict lowest fee-rate in case of excess (already now)
- [ ] TTL for `LinkTx`s whose thruputs never resolve (new).
- [ ] Cast-on-demand: when a `LinkTx` can chain onto a mempool-member single-proof
      `Transaction`, `Cast` the latter in if the fee is beneficial.

## Peer
- [x] Gossip/relay of `LinkTx` regardless of non-empty thruputs; but validate
      before relay. 
- [x] Punish peers for relaying invalid `LinkTx`s
- [x] Reject on arrival any `LinkTx` whose claim carries a `D` other than the
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
- [x] `bfield_codec_round_trip`: a `LinkPrimitiveWitness` survives encode/decode.
- [x] `lift_preserves_validity`: lifting any `PrimitiveWitness` at any thruput
      count yields a witness that validates.
- [x] `all_thruputs_is_valid`: a witness with zero confirmed inputs validates.

Negative:
- [x] `extra_input_utxo_fails_cardinality`: an input UTXO backed by no record
      gives `CardinalityMismatch`.
- [x] `extra_output_utxo_fails_cardinality`: an output UTXO backed by no addition
      record gives `OutputCardinalityMismatch`.
- [x] `short_thruput_randomness_fails_cardinality`: a thruput-randomness vector
      shorter than the thruput list fails the cardinality check.
- [x] `bad_lock_script_witness_fails`: a lock-script witness that does not
      satisfy its script gives `InvalidLockScript`.
- [x] `bad_mutator_set_accumulator_fails`: a mutator-set accumulator the inputs
      are not members of gives `InvalidMembershipProof`.
- [x] `unbalanced_output_fails_type_script`: outputs exceeding inputs gives
      `InvalidTypeScript`.
- [x] `fee_too_big_fails_type_script`: a fee exceeding the input sum gives
      `InvalidTypeScript`.
- [x] `missing_type_script_witness_fails` / `too_many_type_script_witnesses_fails`:
      a type-script witness list that does not match the unique type scripts is
      rejected.
- [x] `swapped_removal_records_fail`: confirmed removal records in the wrong
      order give `RemovalRecordsMismatch`.
- [x] `tampered_thruput_addition_record_fails` /
      `tampered_thruput_randomness_fails`: a thruput whose addition record or
      randomness no longer commits its UTXO gives `ThruputCommitmentMismatch`.
- [x] `tampered_output_randomness_fails`: an output UTXO whose sender randomness
      no longer commits it to the kernel's addition record gives
      `OutputCommitmentMismatch`.
- [x] `mutator_set_hash_mismatch_is_rejected`: a kernel naming a mutator set
      other than the witness's gives `MutatorSetMismatch`.
- [x] `merge_bit_is_rejected`: a kernel with the merge bit set gives
      `MergeBitSet`.
- [x] `coinbase_kernel_is_rejected`: a kernel carrying a coinbase gives
      `CoinbaseSet`.

Gap pinned (same gap as `PrimitiveWitness::validate`; enforced later by `Forge`):
- [x] `missing_or_extra_lock_script_is_not_caught`: `validate` accepts a witness
      whose lock scripts do not match its input UTXOs.

Deferred to `Forge` (sharper there than at the proof-free tier):
- [x] `bad_absolute_index_set_is_rejected`: a confirmed input whose claimed
      absolute index set differs from the computed one trips
      `COMPUTED_AND_CLAIMED_INDICES_DISAGREE_ERROR`.
- [x] `unauthenticated_removal_record_is_rejected` /
      `unauthenticated_thruput_is_rejected`: a removal record or thruput absent
      from the kernel MAST trips `ROOT_MISMATCH`.
- [x] `phantom_input_utxo_is_rejected`: an input UTXO backed by neither a removal
      record nor a thruput trips `CARDINALITY_MISMATCH_ERROR`.

## Mirror Tests
Two tiers: the proof-free `LinkPrimitiveWitness::validate` (above) and the tasm programs
(below). The `validate`-tier tests already cover several §onto `Forge` items;
when `Forge` exists, mirror those rather than reinventing them.

The soundness tests that sit on the single-proof pipeline's `ProofCollection`/`SingleProof`
programs test meaningful soundness properties. Some of those properties should be
tested on the new dual pipeline as well.
- `NativeCurrency` and `TimeLock` are recursively verified by `Forge` *unchanged*,
  so their own existing tests still apply — no re-test; only their whole-tx
  consequences below are re-stated against a `LinkKernel`.
- `CollectLockScripts` / `CollectTypeScripts` do NOT appear as separate programs
  in the dual pipeline; `Forge` absorbs them (they remain, unchanged and
  consensus-pinned, in the single-proof pipeline). Their *net behavior* must be tested
  on `Forge` (below).
- Reuse strategy: build the base `LinkPrimitiveWitness` via
  `LinkPrimitiveWitness::from_primitive_witness(pw, k)` off the same single-proof
  `PrimitiveWitness::arbitrary_*` strategy the mirrored test uses, then poke one
  field (single-proof negative-test idiom) — no per-test strategy duplication.

### onto `Forge`
- [x] `bad_mutator_set_accumulator_is_rejected`: a mutator-set accumulator other
      than the one the kernel names is rejected.
- [x] `unauthenticated_removal_record_is_rejected`: a confirmed removal record
      absent from the kernel's `Inputs` leaf is rejected.
- [x] `bad_absolute_index_set_is_rejected`: a confirmed input whose claimed
      absolute index set differs from the computed one is rejected.
- [x] `confirmed_input_utxo_unbound_to_its_removal_record_is_rejected`: a
      confirmed input UTXO that is not the one its removal record spends is
      rejected.
- [x] `forge_confirmed_loop_matches_rri`: `Forge`'s confirmed-input loop is
      instruction-for-instruction the one in `RemovalRecordsIntegrity`.
- [x] `missing_lock_script_proof_is_rejected`: fewer lock-script proofs than
      input UTXOs trips `WRONG_NUMBER_OF_LOCK_SCRIPT_PROOFS_ERROR`.
- [x] `missing_type_script_proof_is_rejected`: fewer type-script proofs than
      unique type scripts trips `WRONG_NUMBER_OF_TYPE_SCRIPT_PROOFS_ERROR`.
- [x] `validate_matches_forge`: `validate` rejects a dropped lock- or
      type-script proof too.
- [x] `forge_accepts_valid_witnesses`: `Forge` accepts every split of `0..=3`
      inputs into confirmed inputs and thruputs.
- [x] `forge_accepts_timelocked_witness`: `Forge` accepts a witness whose unique
      type scripts are `[NativeCurrency, TimeLock]`, verifying both.

Not on `Forge` -- these are `NativeCurrency` properties, recursively *verified*
(not re-implemented) by `Forge`, so `NativeCurrency`'s own tests still apply and
no valid `Forge` witness can violate them (`produce` cannot prove an unbalanced /
over-fee'd type script): unbalanced `LinkTx`; fee-too-big inflation; fee bounds.
Likewise partition misclassification (confirmed ↔ thruput) is not an error -- the
partition *is* the kernel, every input carries a lock-script proof, and an
unmatched thruput is un-`Fix`able (see §Motivation).

### onto `Advance`
- [x] `new_timestamp_older_than_old_is_rejected`: a new kernel timestamp earlier
      than the old kernel's is rejected.
- [x] `mutator_set_accumulator_must_be_the_one_the_kernel_names`: a new or old
      mutator-set accumulator other than the one its kernel names is rejected.
- [x] `tampered_absolute_index_set_is_rejected`: an absolute index set whose
      value or length changed across the advance is rejected.
- [x] `changing_a_carried_over_field_is_rejected`: changing outputs, thruputs,
      announcements or fee across the advance is rejected. Still true once
      promotion lands, but for thruputs the rejecting assertion changes from
      byte-equality to the promotion multiset equation.
- [x] `coinbase_or_merge_bit_on_the_new_kernel_is_rejected`: a coinbase or merge
      bit on the new kernel is rejected.
- [x] `new_kernel_must_be_the_one_in_the_claim`: a new kernel other than the one
      the claim names is rejected.
- [x] `advance_accepts_a_forged_link_transaction` /
      `advance_accepts_an_all_thruputs_link_transaction`: `Advance` re-targets a
      forged link transaction, with or without confirmed inputs.
- [x] `advance_promotes_none`: `P = []` is the pre-promotion behaviour,
      unchanged -- the existing positives re-run. (Every test but the one below
      promotes nothing, so this is what they all assert.)
- [x] `advance_promotes_a_confirmed_thruput`: a thruput whose addition record
      landed in the new AOCL moves into the confirmed inputs.
      (`update_promotes_a_confirmed_thruput`, one and two promotions, on the
      `promotable` fixture: promotion is the thruput reclassification
      `LinkPrimitiveWitness::from_primitive_witness` performs, run backwards.)
- [x] `advance_promotes_every_thruput`: promotion alone empties the thruput list
      and the result `Fix`es -- the stranded-successor rescue, end to end.
      (`update_promotes_every_thruput`, on the all-thruputs shape: no confirmed
      inputs before, no thruputs after. The `Fix` half is *not* asserted -- `Fix`
      does not exist yet -- so revisit this line when it does.)
- [x] `promoted_thruput_absent_from_the_old_thruputs_is_rejected`. (The old
      kernel gives up one thruput while both promotions stay, so the first
      equation is one addition record short on the left.)
- [x] `promoted_input_index_set_other_than_the_computed_one_is_rejected`. (The
      index set is recomputed from the promotion's own operands, so the poked
      removal record fails the second equation.)
- [x] `promoted_thruput_not_in_the_new_aocl_is_rejected`: a thruput still
      unconfirmed cannot be promoted. (Poked sender randomness moves the
      commitment off the accumulator; the MMR snippet's root mismatch is a bare
      `error_id 10`, named locally in the test module.)
- [x] `promotion_bound_to_the_wrong_aocl_leaf_is_rejected`: a membership proof
      for a leaf that is not the thruput's commitment. (Corrupted in place, so
      the digest stream keeps the length the loop expects and the failure is a
      root mismatch rather than a desynchronised stream.)
- [x] `promoted_input_spending_a_different_utxo_is_rejected`: the commitment
      equation, i.e. the inflation-critical one. (Runs on a *decoy*: a promotion
      built from an input that stays confirmed, so it names a real leaf of the
      new AOCL and carries a valid membership proof, and still retires no
      thruput. `promotable` now returns the decoys alongside the promotions.)
- [x] `one_sided_promotion_is_rejected`: a thruput retired without the matching
      input joining, and the reverse. (One direction per equation.)
- [x] `duplicate_promoted_aocl_leaf_index_is_rejected`. (One promotion cloned
      over the other. The equations carry the duplicate on both sides happily,
      being between multisets, so the ordering check is what refuses it.)
- [x] `unordered_promotions_are_rejected`: a valid promotion pair, swapped --
      what gives the strictly-ascending encoding teeth. (Both entries valid and
      the multisets identical either way round, so only the ordering check can
      reject it.)
- [x] Decided: no `promotion_loop_matches_rri` guard, because there is nothing
      to drift. `Forge` needs its guard since it *reimplements* RRI's loop
      inline; the promotion loop instead `call`s the very snippets RRI is built
      from -- `Commit`, `MmrVerifyFromSecretInLeafIndexOnStack`,
      `ComputeAbsoluteIndices` -- so the shared core cannot diverge without the
      snippets themselves changing under both. What is left is the loop's own
      scaffolding (the two list appends, the ordering check), which RRI has no
      counterpart for and a sub-block comparison would have to skip anyway.
- [x] the promotion fixture. Resolved without touching `LinkPrimitiveWitness`:
      its thruputs *are* reclassified confirmed inputs, so the primitive witness
      still holds the `(item, sr, rp)`, the AOCL leaf index and the very removal
      record the reclassification dropped. `promotable` reads them off it and
      carries the membership proofs across the AOCL's growth. The promoted
      records are then already in the *old* AOCL, which `Update` neither checks
      nor can check -- membership in the new one is the whole test.
- Not applicable: merge-bit-unchanged (`update_branch` divines the bit and
  carries it across; a `LinkTx` never has it set, so the constant leaf is
  stronger)

### onto `Chain`
- Not applicable: coinbase-specific merge tests (`too_big_time_diff`,
  `authenticate_coinbase_fields_*`) — a `LinkTx` is never a coinbase transaction
- [x] `chained_inputs_must_be_the_operands_inputs`: a chained input list that is
      not the concatenation of the operands' is rejected.
- [x] `chained_announcements_must_be_the_operands_announcements`: a chained
      announcement list that is not the concatenation of the operands' is
      rejected.
- [x] `chained_fee_must_be_the_sum_of_the_operand_fees`: a chained fee above or
      below the sum of the operand fees is rejected.
- [x] `fee_sum_outside_the_valid_range_is_rejected`: a fee sum outside
      `[0, MAX_NAU]` is rejected.
- [x] `negative_operand_fee_is_rejected_even_when_the_sum_is_valid`: a negative
      operand fee is rejected even where the sum lands in range.
- [x] `chained_timestamp_must_be_the_later_of_the_operand_timestamps`: a chained
      timestamp other than the later of the two is rejected.
- [x] `mismatched_mutator_set_hash_is_rejected`: operands or chained kernel
      disagreeing on the mutator-set hash is rejected.
- [x] `coinbase_or_merge_bit_on_the_chained_kernel_is_rejected`: a coinbase or
      merge bit on the chained kernel is rejected.
- [x] `bad_authentication_path_is_rejected`: an operand field absent from its
      kernel MAST is rejected.
- [x] `chained_kernel_must_be_the_one_in_the_claim`: a chained kernel other than
      the one the claim names is rejected.
- [x] `chain_accepts_a_chain_produced_operand`: a `Chain`-produced link proof is
      itself a valid operand.
- [x] `operand_proof_must_attest_to_its_own_operand`: swapping the two operands'
      link proofs is rejected.
- [x] `one_sided_cut_through_is_rejected`: a record removed from the outputs but
      not the thruputs, or the reverse, is rejected.
- [x] `cut_through_on_unequal_commitments_is_rejected`: cancelling a (thruput,
      output) pair whose commitments differ is rejected.
- [x] `a_thruput_cannot_be_cut_through_twice`: with both operands claiming the
      same unconfirmed output, cancelling both copies is rejected.
- [x] `chained_outputs_must_be_union_of_outputs_of_operands`: a chained output
      list that is not the concatenation of the operands' is rejected.
- [x] `chain_accepts_a_predecessor_successor_pair`: a successor chained onto the
      predecessor resolving all its thruputs leaves none outstanding.
- [x] `thruputs_resolve_in_two_stages`: a successor with one thruput from each of
      two predecessors is chained onto them in turn, and only the second empties
      the thruput list.
- [x] `chain_is_associative`: `Chain(Chain(A, B), C)` and `Chain(A, Chain(B, C))`
      agree as multisets, on the chained kernel and the cut-through set.
- [x] `cut_through_removes_matching_pairs_from_both_sides`: each cut-through pair
      drops one output and one thruput.
- [x] `non_maximal_cut_through_is_rejected`: a cut-through leaving a cancellable
      (output, thruput) pair standing is rejected.

### onto `Fix`
- [x] `link_proof.rs::invalid_discriminant_crashes_execution`: an out-of-range
      `LinkProofWitness` discriminant crashes the run.
- [x] `single_proof.rs::invalid_discriminant_crashes_execution`: an out-of-range
      `SingleProofWitness` discriminant crashes both programs, `Fix`'s counting
      as out of range for the pre-delta one.

### onto `Weld`

The union of `Cast`'s, `Chain`'s and `Fix`'s negatives, minus what the contract
deliberately changes. Mechanical except for the first three.

- [ ] `coinbase_on_the_transaction_is_rejected`: a coinbase-bearing A is
      refused. No analog anywhere else -- `Cast` used to own this check, and
      `Weld` deletes `Cast` from the path.
- [ ] `unresolved_thruput_is_rejected`: a thruput of B absent from A's outputs.
      `Fix`'s `link_transaction_with_thruputs_is_rejected` is enforced by
      arithmetic; here it is a multiset equation, so it earns its own test and
      its own error ID.
- [ ] `weld_equals_the_decomposition`: for A with the merge bit clear and no
      self-cancelling pair available, `Weld(A, B)` and `Fix(Chain(Cast(A), B))`
      agree field by field as multisets. *Not* by MAST hash: `Chain` shuffles
      its concatenations by a seed (`chain.rs:214`), so the two kernels are
      equal only up to order. Copy `chain_is_associative`'s comparison.
- [ ] `merge_bit_is_carried_from_the_transaction`: set and clear, B's false in
      both cases -- the welded kernel's bit is A's either way.
- [ ] `self_cut_through_is_rejected`: a thruput of B matching an output of B
      rather than of A. Accepted by the decomposition, refused here.
- [ ] `negative_operand_fee_is_rejected_even_when_the_sum_is_valid` /
      `fee_sum_outside_the_valid_range_is_rejected`: `Chain`'s two, on A and B.
- [ ] `welded_timestamp_must_be_the_later_of_the_two`.
- [ ] `mismatched_mutator_set_hash_is_rejected`: A, B or the weld naming a
      mutator set the others do not.
- [ ] `welded_inputs_must_be_the_operands_inputs` /
      `..._announcements_...` / `..._outputs_...`: a field that is not the
      concatenation, respectively not the two equations' `leftover ⊎ B.outputs`.
- [ ] `bad_authentication_path_is_rejected`: an A or B field absent from its
      kernel's MAST.
- [ ] `welded_kernel_must_be_the_one_in_the_claim`.
- [ ] `each_operand_proof_must_attest_to_its_own_operand`: A's `SingleProof`
      verified against B's kernel, and B's `LinkProof` against A's -- the
      operands being differently typed, this is two tamperings rather than
      `Chain`'s one swap.
- [ ] `weld_accepts_a_chain_produced_link_transaction`: B from `Chain` rather
      than `Forge`, so the positive is not vacuous on single-link Bs.

## Negative tests for `D` (the `SingleProof` digest in the `LinkProof` claim)

These guard §Breaking the `Fix`/`Cast` cycle. The invariant they defend — `D` is
copied verbatim into every child claim, and only `Fix` may name it — is the
difference between recursion and universal forgery, so *every* branch that
touches `D` gets a negative.

Claim / plumbing:
- [x] `link_proof_claim_shape_is_pinned`: `LinkProofWitness::standard_input()` is
      exactly `lkmh.reversed() || D.reversed()`, length `2 * Digest::LEN`.
- [x] Proof/claim binding — a valid `LinkProof` for `[lkmh, D₁]` not verifying
      against `[lkmh, D₂]` — is Triton VM's Fiat-Shamir, not ours; deliberately
      not a test, and not to be re-opened. What is ours is building the right
      claim, covered by `link_proof_claim_shape_is_pinned` (prover side) and
      `operand_forged_under_another_single_proof_digest_is_rejected` (verifier
      side).

`Chain`:
- [x] `operand_forged_under_another_single_proof_digest_is_rejected`: operands
      proven under `D'` while the claim names `D` are rejected inside
      `stark_verify`.
- [x] `each_operand_is_verified_against_the_claims_d`: corrupting exactly one
      operand, in each direction, is rejected — so both operand verifications
      run.
- [x] `witness_supplied_single_proof_digest_is_ignored`: a `single_proof_digest`
      poked into the witness's memory image, public input untouched, still
      verifies.
- [x] Mixed provenance — `Chain(Forge'd with D₁, Cast'd with D₂)` — is
      unrepresentable rather than rejected: `D` is read once into a static slot
      and appended to both operand claims, and operands carry no digest of their
      own.

`Advance`:
- [x] `old_proof_forged_under_another_single_proof_digest_is_rejected`: an
      operand claim naming `D' ≠ D` is rejected.
- [x] `witness_supplied_single_proof_digest_is_ignored`: a `single_proof_digest`
      poked into the witness's memory image, public input untouched, still
      verifies.
- [x] Re-targeting `D` is unrepresentable: the branch reads one digest and never
      builds the output claim, which is the public input.

`Cast`:
- [x] `transaction_proven_under_another_program_digest_is_rejected`: a
      transaction whose single proof was made under a digest other than the
      claim's `D` is rejected inside `stark_verify`.
- [x] `witness_supplied_single_proof_digest_is_ignored`: a `single_proof_digest`
      poked into the witness's memory image, public input untouched, still
      verifies.
- [x] `cast_accepts_a_single_proof_backed_transaction`: `Cast` accepts a
      transaction backed by a real `SingleProof`.
- [x] `cast_under_a_bogus_single_proof_program_is_un_fixable`: a transaction
      "proven" under `read_io 5 halt` casts successfully and is then rejected by
      `Fix` inside `stark_verify`.
- [x] `link_kernel_must_be_the_transaction_kernel_without_thruputs`: a claimed
      link kernel that is not the transaction's kernel with empty thruputs is
      rejected.
- [x] `coinbase_or_merge_bit_on_the_cast_kernel_is_rejected`: a coinbase or merge
      bit on the cast kernel is rejected.

`Fix`:
- [x] `link_proof_forged_under_another_single_proof_digest_is_rejected`: a link
      transaction forged under a `D` other than `own_program_digest()` is
      rejected.
- [x] `link_transaction_with_thruputs_is_rejected`: a link transaction still
      carrying thruputs is rejected.
- [x] `link_proof_must_attest_to_the_claimed_transaction`: a link proof about a
      transaction other than the claimed one is rejected.

`Weld` (it touches `D` twice, once per operand claim):
- [ ] `transaction_proven_under_another_program_digest_is_rejected`: A proven
      under `D' != own_program_digest()`.
- [ ] `link_proof_forged_under_another_single_proof_digest_is_rejected`: B
      forged under `D' != own_program_digest()`.
- [ ] `witness_supplied_single_proof_digest_is_ignored`: a `single_proof_digest`
      poked into the witness's memory image, public input untouched, still
      verifies.
- [ ] Naming two different digests is unrepresentable rather than rejected: the
      branch reads `own_program_digest()` once and names it in both claims, so A
      and B cannot be verified under different `D`s.

Positive counterparts (so the negatives cannot pass vacuously):
- [x] `fix_accepts_a_resolved_link_transaction`: `Fix` accepts a `Forge`'d link
      transaction with no thruputs, under the real `SingleProof` digest.
- [x] `forge_then_fix_yields_a_verifying_single_proof`: `Forge → Fix` produces a
      `SingleProof` that verifies against the claim `single_proof_claim` builds.
- [x] `cast_then_fix_yields_a_verifying_single_proof`: `Cast → Fix` produces a
      verifying `SingleProof` answering the claim the cast transaction started
      from.
- [ ] `Forge → Chain → Fix` with the real `D` throughout accepts and the
      resulting `SingleProof` verifies.
- [ ] `Cast → Chain → Fix` with the real `D` throughout accepts and the
      resulting `SingleProof` verifies.
- [ ] `Forge → Weld` with the real `D` throughout accepts and the resulting
      `SingleProof` verifies against the claim `single_proof_claim` builds.
- [ ] `Forge → Chain → Weld`: the same, with B carrying thruputs from more than
      one predecessor.


## New Tests
- [x] `chain_is_associative`: `Chain(Chain(A, B), C)` and `Chain(A, Chain(B, C))`
      agree as multisets, on the chained kernel and the cut-through set.
- [ ] `Fix` distributivity: `Fix(Chain(A, B)) = Merge(Fix(A), Fix(B))` when
      `thruputs == []`.
- [x] `chained_timestamp_must_be_the_later_of_the_operand_timestamps`: a chained
      timestamp other than the later of the two is rejected.
- [x] `thruputs_resolve_in_two_stages`: a successor with one thruput from each of
      two predecessors is chained onto them in turn, and only the second empties
      the thruput list.
- [x] `coinbase_or_merge_bit_on_the_forged_kernel_is_rejected` /
      `..._on_the_chained_kernel_...` / `..._on_the_new_kernel_...` /
      `..._on_the_cast_kernel_...`: a coinbase or merge bit on any minted or
      rewritten `LinkKernel` trips `ROOT_MISMATCH`.
- [ ] `Advance` then `Fix` equals `Fix` on the advanced mutator set.
- [x] `cast_then_fix_yields_a_verifying_single_proof`: `Cast(tx)` then `Fix`
      answers the claim `tx` itself answered.
- [x] `link_transaction_with_thruputs_is_rejected`: a link transaction still
      carrying thruputs is rejected by `Fix`.
- [x] `cut_through_on_unequal_commitments_is_rejected`: cancelling a (thruput,
      output) pair whose commitments differ is rejected.
- [ ] A `Fix`'d transaction enters a block. Its single proof already verifies
      against `single_proof_claim`
      (`forge_then_fix_yields_a_verifying_single_proof`,
      `cast_then_fix_yields_a_verifying_single_proof`); the block half waits on
      §Integration.
- [x] `phantom_input_utxo_is_rejected` / `phantom_output_utxo_is_rejected`: an
      input or output UTXO backed by no record trips
      `CARDINALITY_MISMATCH_ERROR`.
- [x] `tampered_thruput_is_rejected` /
      `output_utxos_unbound_to_addition_records_is_rejected`: a thruput or output
      UTXO that is not the one its addition record commits trips
      `UTXO_COMMITMENT_MISMATCH_ERROR`.
- [x] `confirmed_input_utxo_unbound_to_its_removal_record_is_rejected`: a
      confirmed input UTXO whose commitment is not the AOCL leaf its removal
      record spends is rejected.
- [x] `unauthenticated_thruput_is_rejected`: a witness thruput vector that is not
      the kernel's `thruputs` leaf trips `ROOT_MISMATCH`.
- [x] `forge_accepts_valid_witnesses`: `Forge` accepts every split of `0..=3`
      inputs into confirmed inputs and thruputs, type scripts proven over the
      union.
- [x] `bad_authentication_path_is_rejected`: an operand's `inputs`, `outputs`,
      `thruputs` or `fee` absent from its kernel MAST is rejected by `Chain`.
- [x] `cut_through_removes_matching_pairs_from_both_sides`: each cut-through pair
      drops one output and one thruput.
- [x] `non_maximal_cut_through_is_rejected`: a cut-through leaving a cancellable
      (output, thruput) pair standing is rejected.
- [x] `one_sided_cut_through_is_rejected`: a record removed from the outputs but
      not the thruputs, or the reverse, is rejected.

## Benchmarks

`neptune-consensus/benches/chaintx.rs`, run with `cargo bench -p
neptune-consensus --bench chaintx`.

- [x] `cost::forge_versus_raise`: `Forge → Fix` against `Collect`+`Raise`.
      Confirmed ~30% speedup.
- [x] `throughput::chained_{2,4}` / `throughput::separate_{2,4}`: `N`
      interactions with one self-perpetuating UTXO on the chaining pipeline
      versus `N` with `N` independent UTXOs. While not a like-for-like
      comparison, this is the closest counterpart the single-proof pipeline admits.
      Confirmed ~36% speedup at `N = 2`.

## Audit
- [x] Scoped security audit

## Misc

- [ ] Delete plan / progress tracker (this document)

[1]: https://talk.neptune.cash/t/transaction-chaining-in-neptune-cash/349
