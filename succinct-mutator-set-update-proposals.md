# Succinct validation: the mutator-set update cost

Discussion notes, 2026-09-21. Branch `thv/succinctness`.

## Where we stand

`PredecessorIsValid` enforces rule 2.e in the previous block: it unpacks the
transaction's chunks, verifies them against the inactive SWBF (SWBFI) with
divined authentication structures, inserts the removal indices, recomputes
the peaks and compares with the body. The whole program, skipping the STARK
verification, measured on synthetic previous blocks (ignored test
`profile_skipping_program_by_inputs`, no proofs needed):

| Inputs | Block words | Processor | RAM rows | Hash rows | U32 rows |
|-------:|------------:|----------:|---------:|----------:|---------:|
| 2      | 16.5k       | 1.08M     | 308k     | 143k      | 163k     |
| 20     | 152k        | 10.3M     | 2.94M    | 666k      | 984k     |
| per input | 7.5k     | 513k      | 146k     | 29k       | 46k      |
| everything but the update | | ~50k | ~16k | | |

Assumptions: 410-entry chunks (the arbitrary fixture), 45 indices per input
landing in ~42 distinct chunks within a 256-chunk window.

Chunk density is the pessimistic assumption. A chunk is covered by the
windows of the 2048 items added in the 256 batches before it, each of which
contributes 45/256 entries when spent, so entries per chunk = 360 × s with
s the fraction of those items spent. Measured packed inputs per input:
7.5k words at 410 entries, of which 6.4k packed chunk words (155 per
chunk) and 1.1k authentication data. Scaling with density:

| Entries per chunk | Spend fraction s | Packed words per input | Inputs per 1M-word block |
|------------------:|-----------------:|-----------------------:|-------------------------:|
| 100               | 0.28             | 2.7k                   | ~370                     |
| 200               | 0.56             | 4.3k                   | ~230                     |
| 360               | 1.0              | 6.8k                   | ~150                     |
| 410 (fixture)     | above 1          | 7.5k                   | ~130                     |

The proof cost scales the same way for its per-entry parts (hashing,
insertion, unpacking, about 70% of the per-input cost); the structure and
root parts are per chunk and stay.

Where the cycles go at 20 inputs (344k chunk entries):

| Part                                            | Cycles | Per entry |
|-------------------------------------------------|-------:|----------:|
| Chunk unpacking (12-bit fields from packed words) | 5.2M | 15        |
| Structure-length check                           | 1.1M   | 3         |
| Root from authentication structure (tasm-lib), two passes | 1.1M | 3 |
| Insertion into each chunk                        | 1.1M   | 3         |
| Hashing each chunk twice                         | 1.2M   | 3.6       |
| Everything else                                  | 0.6M   |           |

Conclusions from the measurements:

- The processor table binds, at about three times the RAM table. Within
  this design it cannot be brought down to the RAM table: the unpacker is
  half the cycles, and even without it the rest is ~250k cycles per input
  against ~105k RAM rows.
- The unpacker's range checks are near-optimal for the processor/U32
  trade-off. Bit operations move the blowup to the U32 table (~33 rows per
  field); combining words in one 64-bit recomposition is unsound (sum can
  exceed the modulus); pairing range checks loses uniqueness. Tuning the
  stack traffic gains ~15%.
- At 2^21 padded height the program holds about 4 inputs as is, 8 with the
  unpacker gone, ~28 at the floor of any design that re-hashes the touched
  chunks. The target of 200 to 1000 inputs needs structural change.
- Block size caps inputs independently: at fixture density the 1M-word
  limit allows ~130 inputs, at realistic density 200 to 350, and hashing a
  block of that size at one RAM row per word takes 2^20 to 2^21 on its own.

## Facts about what the proofs bind

- `RemovalRecordsIntegrity` proves absolute indices and AOCL membership. It
  never touches chunk dictionaries.
- The merge branch checks that the merged inputs' absolute indices are a
  permutation of the operands' (`merge_branch.rs`, `assert_input_integrity`
  shadow). Chunk data and packing are whatever the witness supplies.
- Packing is enforced only by host rule 2.a; chunk membership only by host
  rule 2.b. The chunk dictionaries are witness data for the host's own
  update and nothing else.
- Archival nodes store every chunk and never needed the block's copies.

## Options

Per-input figures assume the unpacker gone (250k cycles, 105k RAM rows),
except where stated, at fixture density. "Inputs per proof" is the
processor-bound capacity of one 2^21 proof. Options that keep the update in
one proof are capped there; c) and d) split the update over a tree of
proofs, so the block's input count is bounded by block size and proving
capacity instead, and the proofs run in parallel.

| Option | Per input, cycles / RAM rows | Inputs per proof at 2^21 | Inputs per block | Proofs for 1000 inputs | Fork |
|--------|-----------------------------:|-------------------------:|-----------------:|-----------------------:|------|
| Now | 510k / 146k | 4 | 4 | not reachable | soft |
| a) Unpacked inputs in blocks | 250k / 105k | 8 | 8 | not reachable | hard, rules only, inputs field ×3.8 |
| b) Packed chunks as SWBFI leaves | ~510k / ~125k | 4 | 4 | not reachable | hard, mutator set redesign |
| c) Task merge with MS update proof (c1 sequential, c2 parallel and distributed) | 250k / 105k | 8 per leaf or merge step | block size | ~125 leaves + ~124 merges, redone every block | hard, new merge program |
| d) Aggregation tree in the appendix | 250k / 105k | 8 per leaf | block size | ~125 leaves + ~124 aggregations, by the composer | soft |
| e1) Drop chunk data in block entirely | 250k / 105k | 8 | 8 alone; block size with c or d | as c or d | hard, rules only, blocks shrink |
| e2) Keep chunk data in block, don't validate | 250k / 105k | 8 | 8 | as e1 | hard, rules only, no benefit over e1 |
| e'_1) Composer proves knowledge of the archival mutator set, or of historical blocks | not yet assessed | | | | |
| e'_2) Guesser reveals one sampled chunk hash with its path | +a few hundred hash rows per block | unchanged | unchanged | none | hard, header rules |
| e'') Composer reveals knowledge of the archival mutator set | not yet assessed | | | | |
| f) Merkle-tree chunks in the SWBF | 21k tallest table (u32) per input, measured | ~100 | 100 alone; block size with d | ~10 leaves + ~9 aggregations with d, plus the window slide in `PredecessorIsValid` | hard, mutator set redesign |
| g) Micro-optimisations | 420k / 146k | 5 | 5 | not reachable | none |
| h) Increase block size | 510k / 146k | 4 | more than now | not reachable | hard, rules only |
| i) Nullifier set in a sparse Merkle tree | 361 / 1.26k, binding U32 2.24k (prototype) | ~930 | block size | 1 at 2^22 | hard, mutator set redesign, transaction programs untouched |

Combinations: d) + e1) is the soft-claim path to the target with existing
transaction programs; d) + e1) + f) cuts the per-block proof count about
three times; a) or e1) alone only double the single-proof cap.

### a) Drop chunk packing

Halves the processor cost and removes a quarter of the RAM rows. The
inputs field grows 3.8 times (measured: 572k words unpacked against 151k
packed at 20 inputs; the unpacked form also carries a membership proof per
chunk instead of a shared structure per tree). Since no program enforces
packing, it is a block-rules change only, but old nodes reject unpacked
inputs, so a hard fork.

### b) Packed chunks in the mutator set

Does not halve. Hashes shrink from 412 to 154 words each (~45k RAM rows,
~40k cycles per input), but the insertion needs the unpacked form so the
unpacker stays, and the new chunk must be repacked before hashing. Net: RAM
rows down ~15%, cycles flat or worse, for the most invasive fork. Dropped.

### c) Task merge with MS update proof

A transaction claim outputs the mutator set after its own removals relative
to its input mutator set. Leaf proofs apply their own removals; each merge
applies its right operand's removals on top of its left operand's output,
with chunks divined and verified against that output's root. No packed data
inside the tree. Cost ~250k cycles / ~105k RAM rows per input, distributed
over issuers and upgraders.

Two shapes: c1) sequential, where each merge applies its removals on top of
its left operand's output as described; c2) parallel and distributed, where
the removal work is proven by many parties at once and combined at the
merges. The costs below are for the shape as measured; c2) has not been
costed separately.

Problems:

- The top of a balanced tree applies half the block's inputs in one proof,
  so merges must combine children's leaf diffs, which is new machinery in a
  new merge program (hard fork of `SingleProof`, or a parallel claim type).
- The output is relative to the input mutator set, which changes with every
  block. Every pending transaction's update must redo its removal work each
  block, and a merged transaction of more than ~8 inputs cannot be updated
  in one proof. The pending merge tree is rebuilt bottom-up every block.
  Same total work as d), spread over the network, exposed to latency, and
  nothing can be prepared ahead of time.

### d) Aggregation tree in the block appendix

A transition claim `T`: from mutator set state `S_in`, applying a committed
set of removal indices yields `S_out`. Public input: hash of `S_in`, hash of
`S_out`, commitment to the indices. Witness: the touched chunks and one
authentication structure per SWBFI tree, divined and verified against
`S_in`'s peaks, as the peaks snippet does now. Additions (AOCL appends,
window slides) stay in `PredecessorIsValid`; they cost a few hundred rows
per record.

Composition: removals commute. The composer splits the block's inputs into
segments, computes every intermediate state natively, proves each segment
`T(S_i → S_{i+1})` in parallel, and aggregates pairwise with a claim `A`
that verifies two children whose middle states match and outputs the outer
pair. A chain-of-transitions tree: no diff merging, no chunk contents above
the leaves. Every claim outputs the peaks of the MMR over its own inputs'
index set digests, so a leaf is the same claim wherever its inputs land in
the block, which d2) needs since an upgrader proves it before the composer
orders anything. An aggregation takes the digests of all the index sets
beneath it as witness, five words per input, recomputes each child's peaks
from its share and requires them to match, then outputs the peaks over all
of them: one hash pair per input beneath it, against two STARK
verifications. Any tree shape and any leaf sizes combine; the only demand
on the composer is that the block's inputs follow the tree's leaf order,
which the final merge decides. `PredecessorIsValid`, hashing the previous
block anyway, recomputes the peaks from the inputs in one linear pass and
requires them of the root claim. Only the root claim goes in the appendix.

Programs. The leaf is a current-block program, `CorrectSwbfUpdate`: input
the hash of the mutator set it starts from, output the number of leaves
and of index sets it covers, the hash of the mutator set after those
removals, and the peaks. `SwbfUpdateAggregation` has the same input and
output layout and verifies two children, each a leaf or an aggregation: the
left child's input is its own, the right child's input is the left's output
state, and the children's peaks are those of the witnessed digests. The
root's proof is consumed by the block proof like every appendix claim's.
`PredecessorIsValid` drops the recomputation and keeps the cheap
remainder: find the root claim in the predecessor's appendix, check its
start hash against the recursion's own output, its count against the
block's inputs and its peaks against those it computes, divine the SWBFI
peaks after the removals and check them with the window against the output
hash, apply the additions, compare with the predecessor's body. `solo_validate` does the same binding
on the host machine for the tip, after verifying the block proof, with the
parent's accumulator fetched from a peer and checked against the hash the
recursion outputs. So the tip's update is verified at zero confirmations,
which e1) alone does not give.

Measured after the binding replaced the recomputation in
`PredecessorIsValid` (`predecessor-is-valid-cost-profile.md`): the whole
update there is ~1.6k processor rows and ~190 RAM rows per input, of which
the commitment is ~300 and the window and additions the rest, against
~505k processor rows before. The chunk work lives in the leaf alone.

Two shapes of the tree. d1) chains segments: each leaf starts from the
state the previous one ends in, the composer computes those states
natively and proves all leaves in parallel, and an aggregation only checks
that its children's middle states match. d2) starts every leaf from the
same state, the mutator set after the parent, and an aggregation unites:
from that state it must reach the state after both children's removals.
What d2) buys is delegation: a leaf can come from anyone, so an upgrader
can ship a synced transaction with its leaf and raise its chance of
inclusion, and the composer needs no native intermediate states. The leaf
program is the same in both.

Measured d2) union, `SwbfUpdateUnion` (ignored test `profile_union`,
without the two proof verifications): it takes both children's inputs
with their chunks and their union as one packed list, all relative to the
shared state, checks the index sets are the children's in order, and
applies the removals from the shared state three times, once per child to
reproduce its output hash and once for the union. 4 + 4 inputs: 7.96M
processor and 2.17M RAM rows, padded height 2^23; 8 + 8: 15.78M and
4.31M, 2^24; so 977k processor and 267k RAM rows per input beneath the
node, twice the leaf's. That is the shape of the problem, not of this
implementation: any union node must produce the peaks after all the
removals beneath it, so its cost is at least the touched chunks beneath
it, and the root of a d2) tree covers every input of the block. A union
that merges the children's chunk versions by paths instead of re-running
the removals lowers the constant, to about the leaf's cost per input for
the chunks one child touched, but not the order: d2)'s root is capped per
proof like a single leaf, at 8 to 16 inputs, where d1)'s root is two
STARK verifications whatever the block holds. So d2) does not reach the
target on its own; delegation would have to come from d1) with leaves
proved at known positions, or from a union split by chunk range.

Minimum work. Left alone, a composer includes as few inputs as fees force,
since every input costs proving. So the claim carries its leaf count, 1
for a leaf and the sum of its children's for an aggregation, so the tree
need not be balanced, and the block program accepts the root claim only if
the count is at least e.g. 8 or its proof's padded height is at least 2^22
or 2^23. The two branches cost about the same, an 8-leaf tree being 7
aggregations of ~2^20 even with empty leaves, so neither is a shortcut,
and once either is paid for, filling it
is free: about 32 inputs in the single proof, about 64 in the tree. Below
that there is no cost reason to leave transactions out; above it the next
level or power of two is a real step, and fees decide.

Cost per block at 2^21 per proof, ~300k RAM rows per verified child:

| Inputs | Leaf proofs, 8 inputs each | Aggregation proofs | Added to `PredecessorIsValid` |
|-------:|---------------------------:|-------------------:|-------------------------------|
| 200    | 25                         | 24                 | claim binding, ~1.6k processor and ~190 RAM rows per input |
| 1000   | 125                        | 124                | claim binding, ~1.6k processor and ~190 RAM rows per input |

Leaves are processor-bound at ~250k cycles per input (16 inputs at 2^22).
Aggregation nodes are ~600k RAM rows and fit in 2^20. Under f) the leaf
count drops about three times.

Transactions and the update branch are untouched: the tree is the
composer's, built once per block from the previous block's state, and leaf
proving can start the moment that state is known. Soft fork.

Open question: composer load. 250 proofs per block interval for 1000 inputs
needs a proving farm; 50 for 200 inputs is within reach of one strong
machine.

### e) Drop chunk data in block

e1) drops it entirely, e2) keeps it but does not validate it.

The composer merges with empty chunk dictionaries, which the merge program
accepts today. Post-activation rules for archival validation:

- 2.a and 2.b are dropped as block rules. Inputs carry no chunk
  dictionaries, so there is nothing to unpack and no record to validate
  against the predecessor's mutator set. Both live on inside the leaf as
  checks on its chunk witness, with the same error IDs: the witness must
  be a well-formed packed list holding no chunk the indices do not call
  for (2.a), and every index below the window start must have its chunk,
  authenticated against the peaks (2.b); without the latter a prover could
  leave a removal out.
- 2.d (unspent) and 2.e (mutator set after the block) are computed from
  the node's own SWBF store and compared with the body.
- Everything else unchanged.

Archival nodes still validate their tip natively and cheaply. Alone, e1)
leaves succinct nodes with the transition of block N proven only in block
N+1, so the tip is trusted at zero confirmations and verified at one; with
d) the claim in block N's own appendix verifies it at the tip. Both node
types judge the same thing, the transition: no gap.

Effects: blocks lose the packed inputs' chunk and authentication data,
2.7k to 7.5k words per input depending on density (a 1000-input block
transaction is then ~200k words); no program reads packed words; mempool
transactions keep
their dictionaries for the node's own use, updated natively as today. Rules
only, but old nodes reject records lacking required chunks, so a hard fork.
Required for the 1000-input target regardless of proof design because of
the block-size cap.

e2) keeps the data in blocks and stops checking it: same proof cost, same
fork, larger blocks. Dominated by e1).

### e'_1) Composer proves knowledge of the archival mutator set, or of historical blocks

### e'_2) Guesser proves knowledge of the archival mutator set

The guesser reveals the hash of one chunk of the inactive SWBF with its
authentication path to the SWBFI MMR root, at the index
`f(prev_block_hash)`, unknowable before the previous block lands.

The reveal lives in the free words of the PoW field, keeping the 10-permutation
guessing loop. Light nodes verify it on the host machine in `solo_validate`. One
chunk hash against the SWBFI peaks along the path. `PredecessorIsValid` repeats
it for the predecessor in recursion at a few hundred hash rows.

Picking the index using  `f(prev_block_hash, guesser_receiver_data)` can be made
safe too: grinding the receiver data toward a held subtree gains nothing, since
the siblings change with every block and only the whole tree keeps them current.
However, the guesser may not be allowed to pick which *Merkle tree* they reveal
from. That could be defined to either always be the largest, or the first
(largest) one touched by this block. The two-parameter form also keeps the
composer from bundling the reveal with the proposal, since the guesser is
unknown then: every guesser holds the archival set or fetches from someone who
does.

What it guarantees is that the archival mutator set is readily available
on the network, not that each guesser holds it, in the one-parameter model every
guesser reveals the same chunk per block, so one can fetch it from an archival
node. A competitor who can slow that response slows the guesser down, which is
the incentive for serious miners to keep their own.

Space: since hardfork beta, validation checks nothing in the PoW field
but the threshold, the version word and the six lustration words, and the
efficient guessing loop varies only the nine words after the lustration
status, the nonce. So all of `path_b` and all of `path_a` but seven words
are free: 56 whole digests, room for the chunk hash and a path of 55 digests.
Should the largest tree ever outgrow that, the guesser reveals the last
50-something leafs along the authentication path, along with the first elements
sibling.

### e'') Composer reveals knowledge of the archival mutator set

e'_1) and e'') are variants from the office mapping of who must hold the
archival data once blocks stop carrying chunk data: the composer proves it,
or proves the historical blocks instead; or the composer reveals it
outright. Not yet assessed for proof cost or fork type.

### f) Merkle-tree chunks in the SWBF

A chunk as a Merkle tree over the counts of its 4096 indices instead of a
sorted list, so that an insertion is a 12-level path update and the
inactive SWBF, an MMR over chunk roots, is one Merkle forest down to the
counts. A leaf holds an index's count, since an index can be set more
than once and reversion must unset; the counter vector is a canonical
form of the multiset the sorted list encodes today. A deep hard fork of
the mutator set. Measured 2026-10-05 and 2026-10-06 in test-only code;
the production programs are untouched.

**The leaf.** The leaf program with today's claim, the forest walked
directly: a table of the forest's trees from the leaf count, then one
pass over the records' indices, each index in the inactive part walked
twice from its count's leaf through its chunk's root up to the peak of
the divined tree, with the existing two-root walk against the peak in
place. The witness is the index sets and one path of 26 digests per
index; no chunks, no chunk list. The count each index found is what the
unspent rule reads, and rule 2.a has no chunk left to be exactly right.
Measured on the list form's fixture at 8 and 16 inputs, outputs checked
against the host (`profile_both_forms` in
`swbf_update/counter_tree_leaf.rs`):

| Per input | List form, 410 per chunk | List form, empty chunks | Counter form |
|---|---:|---:|---:|
| Processor rows | 66,774 (60,180 flat) | 54,381 (47,787 flat) | 15,972 |
| U32 rows | 14,687 | 12,466 | 20,601 |
| Hash rows | 29,176 | 8,820 | 14,893 |
| RAM rows | 48,559 | 12,820 | 14,373 |
| Tallest table | 66,774 (60,180 flat) | 54,381 (47,787 flat) | 20,601 |
| Inputs per 2^21 leaf | 31 | 38 | 101 |

The tallest table sets what a leaf buys: 21k rows per input against 67k,
a factor 3.2, or 2.9 against the list form with the flattened witness
of 2026-10-07 ("flat" in the table), which the counter form shares. The counter form is u32-bound, 15.5k of its rows per input
being the `merkle_step_mem` steps of the walks, 52 per index at this
forest height of 26; that is the floor of this design. The list form at
density zero (`witness_with_empty_chunks`, the fixture with every chunk
emptied) shows that chunk contents are only a fifth of its cost; the rest
is index bookkeeping, per-chunk MMR walks and the dictionary audit, which
the counter form does without. Two intermediate forms were dropped on the
way: path updates with the list form's bookkeeping kept, 40,850 processor
rows per input; and one merged pass with the per-chunk MMR walks kept,
31,475.

**The window slide.** Every 8 additions `PredecessorIsValid` must build
the slid chunk's root, where today it hashes a list for about 250 hash
rows. Measured as a sparse root over the slid chunk's sorted indices,
zero subtrees by table (`profile_slide_root` in
`swbf_update/counter_tree_root.rs`):

| Indices in the slid chunk | Occupied nodes | Processor rows | Hash rows |
|---:|---:|---:|---:|
| 100 | 537 | 55.6k | 3.7k |
| 250 | 1,061 | 104.3k | 6.5k |
| 410 | 1,448 | 146.7k | 8.9k |
| 1000 | 2,355 | 254.7k | 14.7k |

About 100 processor rows per occupied node, one of them the hash; a
tighter loop could reach 15k to 35k per slide, which is still 2k to 4k
per output against 334 today, in the one sequential proof. The cost
disappears if the active window is 256 chunk trees too, so that a slide
pops a root and pushes the empty tree's; a wider and unmeasured change.

**Activation.** The peaks before the fork are history. Either chunks
keep their form by index, lists below the fork's batch index and counter
trees above, with the threshold in the PoW field's lustration words like
the lustration counter's, which keeps old items in the list form forever
and both forms in the leaf; or the fork converts the whole inactive SWBF
at once, an archival recomputation light nodes take from the activating
block. No transaction program hashes a chunk. Not built.

**Standing.** Leaf gain measured at a factor 3.2; the slide and the
activation are open. Parked 2026-10-07, work continues without f).

### g) Micro-optimisations of the current program

Stack traffic in the unpacker (107 → ~90 cycles per group of three words)
and pointer walks instead of bounds-checked list reads in the
structure-length check (about half). 15 to 20% of the cycles, no change to
RAM rows, no change to the ceiling.

### h) Increase block size

Raises the number of inputs the 1M-word cap admits, at fixture density
~130. It changes nothing per input, so the single-proof cap of 4 inputs
stays, and hashing the block in `PredecessorIsValid` grows with the size:
at one RAM row per word, a block of the current cap already costs 2^20 to
2^21 on its own. Rules only, but old nodes reject larger blocks, so a hard
fork.

### i) Nullifier set in a sparse Merkle tree

Replace the SWBF by a set of nullifiers, committed to by a sparse Merkle
tree (SMT) in place of the SWBFI's MMR. The nullifier is `H(absolute index
set)`: the index set is already a deterministic function of item, sender
randomness, receiver preimage and AOCL index, and the kernel already
commits to it, so a UTXO has exactly one nullifier. A removal is a
non-membership path for the nullifier followed by the insertion along the
same path.

Transaction programs see the SWBF only as opaque digests:
`RemovalRecordsIntegrity` and `update_branch` take `swbfi_bagged` and
`swbfa_hash` as witness and hash them into `hash_pair(hash_pair(aocl,
swbfi), hash_pair(swbfa, default))`, never looking inside. With the SMT
root in the `swbfi` slot and a constant (or the frozen window's hash) in
the `swbfa` slot, the removal-records program, the merge and update
branches and the kernel format stay as they are. The change is confined to
the mutator set's consensus state and the block rules, like f), but deeper
in effect.

Proving cost, measured on a prototype (ignored test
`profile_smt_insertions` in `neptune-consensus/tests/smt_profile.rs`). The
tree has depth 124: `merkle_step` needs a u32 node index, so the walk
runs in four segments of 31 levels, keyed by 31 bits from each u32 half
of the nullifier's first two elements, which leaves no honest key
collision at any realistic chain size. Per input: derive the key, walk
from the empty leaf to the current root, walk from the nullifier to the
new root, both over the same siblings, divined into RAM and read with
`merkle_step_mem`. Against the current leaf `CorrectSwbfUpdate` (e1,
structure-length check dropped, ignored test `profile_leaf`), both as
slopes between the two measured input counts:

| AET rows per input | SWBF leaf (8 → 16 inputs) | SMT (8 → 64 inputs) | Ratio |
|--------------------|--------------------------:|--------------------:|------:|
| Processor          | 181k                      | 361                 | 500×  |
| Op stack           | 180k                      | 95                  |       |
| RAM                | 93k                       | 1.26k               | 74×   |
| Hash               | 24k                       | 1.49k               | 16×   |
| U32                | 22k                       | 2.24k               | 10×   |
| Binding table      | processor, 181k           | U32, 2.24k          | 81×   |
| Inputs per 2^21    | ~11                       | ~930                |       |
| 1000 inputs        | ~90 leaves + aggregations | one proof at 2^22   |       |

The SMT's U32 rows come from `merkle_step` checking the node index: rows
grow with the index's bit length, the two walks share their entries, and
so do the top levels of every segment across inputs. Shorter segments or
an indexed Merkle tree (sorted linked list, depth ~32, ~3 short paths per
insertion) would bring the U32 table down to the hash table. Not in the
prototype: hashing the 49-word index set into the nullifier (~5
permutations, ~30 hash rows) and, for pre-fork items, the frozen-SWBF
check (one chunk and its path, ~1/42 of the SWBF leaf's per-input cost,
estimated).

Block space. Words are 8 bytes. Per input:

| Removal record in the block                     | Words     | Bytes      | 1000 inputs  |
|-------------------------------------------------|----------:|-----------:|-------------:|
| SWBF today, packed chunks (100 to 410 entries per chunk) | 2.7k to 7.5k | 22 to 60 KB | 22 to 60 MB  |
| SWBF with e1), index set only                   | 52        | 416 B      | 0.42 MB      |
| i) with `H(index set)`, kernel unchanged        | 52        | 416 B      | 0.42 MB      |
| i) with a Zcash-style nullifier                 | ~6        | ~48 B      | 0.05 MB      |

The 52 words are the index set's 49 (a u128 minimum and 45 u32
distances) plus the encoding of an empty chunk dictionary. The block
space saving is e1)'s, not i)'s: i) only adds to it once the removal
record becomes the nullifier itself.

So the whole update fits in `PredecessorIsValid`, or one appendix claim,
and d)'s tree is no longer needed. e1) still is: the siblings come to
620 words per input, 620k for 1000 inputs, so they are the composer's
witness, not block data, and the composer must hold the whole nullifier
set, as e1) already asks of the archival chunks. e'_2) carries over,
revealing a sampled SMT leaf and its path.

What else goes: the window slide (f)'s open cost; additions become AOCL
appends only), the separate check for duplicate removals within a block
(the second insertion fails non-membership), reversion bookkeeping (a
reorg resets leaves to empty) and the wallets' target chunks, whose
membership proofs shrink to the AOCL part.

Activation. The SWBF is frozen at the activating block and the SMT starts
empty. An item whose AOCL index is at or above the threshold inserts its
nullifier and nothing else. An item below it also proves it was not spent
before the fork: one of its 45 indices is unset in the frozen SWBF, shown
with one chunk (or the frozen window) and its path, about 1/42 of today's
per-input chunk work, and since the SWBF no longer changes the witness
never goes stale. The threshold is written into the lustration words, as
in f).

Limits. A hard fork of the mutator set, archival nodes and wallets; the
SWBF code stays for pre-fork items. `H(index set)` keeps today's privacy
exactly, including the index set's partial linkage to the item's batch
window. A Zcash-style `H(secret, AOCL index)` nullifier would make the
anonymity set the whole AOCL, but changes `RemovalRecordsIntegrity`, the
kernel's removal record and the merge branch's permutation check, so
every transaction program. The SMT does not care what the nullifier is,
so that can follow as a second step.

## Ranking

1. d) with e1): reaches the target with the existing transaction programs;
   soft fork for the claim, rules-only hard fork for the chunk data.
2. i): the redesign to plan instead of f), and arguably the long-term
   design over d): 81 times cheaper per input on the binding table
   (prototype), one proof per block, transaction programs untouched, at
   the price of a mutator set hard fork.
3. f): the redesign to plan if the composer load of d) is too high and i)
   is ruled out.
4. a) standalone: cheapest win if nothing else moves, but does not reach the
   target.
5. c): same total work as d), worse update behaviour, needs a new merge
   program. Ranked below d).
6. b), e2), g), h): do not change the conclusion.

## Proposed next step

The leaf program `T` exists as `CorrectSwbfUpdate`, built from
`SwbfiPeaksAfterRemovals`, the part of the snippet that holds 2.a, 2.b/2.d
and the SWBFI half of 2.e, with the claim's public input in place of the
witness pointers. Measured on the arbitrary fixture (ignored test
`profile_leaf`), with the unpacker still in:

| Inputs | Processor | RAM rows | Hash rows | U32 rows | Padded height |
|-------:|----------:|---------:|----------:|---------:|--------------:|
| 8      | 3.98M     | 1.09M    | 200k      | 301k     | 2^22          |
| 16     | 7.89M     | 2.15M    | 391k      | 534k     | 2^23          |
| per input | 488k   | 133k     | 24k       | 29k      |               |

So a leaf holds 8 inputs at 2^22 as is, and would hold 16 there with the
unpacker gone.

Measured with the unpacker gone (e1 on the leaf: the witness holds the
packed list's structure with the chunks unpacked, and the block's inputs
carry index sets only; ignored test `profile_leaf`):

| Inputs | Processor | RAM rows | Padded height |
|-------:|----------:|---------:|--------------:|
| 8      | 1.83M     | 0.78M    | 2^21          |
| 16     | 3.63M     | 1.55M    | 2^22          |
| per input | 225k   | 96k      |               |

Against 489k and 134k per input with the unpacker: the processor cost
halves, and a leaf of 8 inputs drops a padded height. The union node
follows, at 450k processor and 192k RAM rows per input beneath it, still
twice the leaf.

With the structure-length check dropped as well (the exactness of a
tree's authentication structure was a canonical-form rule of the
archival unpack; once the block carries no structures there is nothing
to mirror, and a spare node is witness data nobody reads): 1.48M
processor and 0.76M RAM rows at 8 inputs, 2.93M and 1.50M at 16, so
181k processor and 93k RAM rows per input. What remains per input is
the two root passes over the authentication structure, the insertions
and the two chunk hashes, in roughly equal parts, and the witness audit.

With the loops around the bulk instructions unrolled (`HashWords`, forty
words per iteration) and the new chunk never written (`HashChunkWith`
`Insertions` absorbs the runs between insertions straight from the old
chunk's memory and stages only the words around each insertion): 1.22M
processor, 1.14M op-stack and 0.50M RAM rows at 8 inputs, 2.41M, 2.25M
and 0.98M at 16, so 149k processor, 139k op-stack and 61k RAM rows per
input. The two root passes are now 27% of the processor rows and 45% of
the op-stack rows; the insertion lists, the chunk witness and the old
chunk hashes' padding follow.

With the insertion lists read by pointer instead of bounds-checked list
reads, the old chunk hashes padding their own tail, and the staging
block addressed by pointer: 1.13M processor, 1.08M op-stack and 0.50M RAM
rows at 8 inputs, 2.24M, 2.14M and 0.99M at 16, so 138k processor, 132k
op-stack and 62k RAM rows per input. The two root passes are 29% of the
processor rows and 47% of the op-stack rows, and the largest item left
without f).

With the two root passes replaced by one walk
(`RootsFromAuthenticationStruct`: tasm-lib's root-from-authentication-
structure argument carried over to two digests per node, a node's factor
being `γ·index + xfe(old) + δ·xfe(new) − β` with a fourth challenge δ, a
structure node contributing `(1 + δ)·xfe`): 1.06M processor, 0.99M
op-stack and 0.48M RAM rows at 8 inputs, 2.10M, 1.95M and 0.95M at 16,
so 130k processor, 121k op-stack and 59k RAM rows per input. The walk is
32k processor and 51k op-stack rows per input, from 40k and 63k for the
two passes; what it shares is the divining, the index bookkeeping and the
structure, while the field arithmetic per digest stays. Without f) the
leaf is now within a few percent of this design's floor: the sponge work
over chunk contents and two field multiplications per digest in the
tree.

Micro-optimizations after that (each its own commit): the staged tail of
the chunk hash and its padding by two writes, pointer walks over the leaf
lists, one allocation per chunk for the insertion slots and their taken
flags, and locating a record's indices from its minimum once instead of
rebuilding each as a u128. 0.90M processor, 0.89M op-stack and 0.48M RAM
rows at 8 inputs, 1.79M, 1.76M and 0.95M at 16, so 110k processor, 109k
op-stack and 59k RAM rows per input, processor and op-stack padding to the
same height. Not taken, as it restructures rather than trims: folding the
insertion slots into rule 2.a's per-index resolution, about 7k processor
rows per input.

The two-root walk replaced (`RootsFromPaths`). The fingerprint argument
divines each structure node once and folds every node into two running
products; that costs about 160 processor and 270 op-stack rows per
distinct node. `merkle_step_mem` reads the sibling from RAM, so one path
in memory serves two walks: with the old leaf to the root the tree has,
with the new leaf to the root it gets. Each chunk's path is against the
tree after the chunks before it have changed, so the walks chain: a
chunk's old walk must land on the root the previous chunk's new walk
produced, and the last new walk is the new peak. Two instructions per
level (`merkle_step_mem`, `recurse_or_return`) for a u32 node index,
tasm-lib's u64 step while the index has a high limb. One tree, both
snippets on identical leaves:

| Height, leaves, layout | structure: processor / op-stack / RAM / hash | paths |
|---|---|---|
| 8, 37, scattered | 26.4k / 41.5k / 12.5k / 2.5k | 5.8k / 4.9k / 3.9k / 3.7k |
| 8, 38, clustered | 28.5k / 44.8k / 13.5k / 2.6k | 6.0k / 5.0k / 4.0k / 3.8k |
| 20, 41, scattered | 136.8k / 219.1k / 65.0k / 9.9k | 8.4k / 5.4k / 9.3k / 10.0k |
| 20, 39, clustered | 33.7k / 53.2k / 16.0k / 3.0k | 8.0k / 5.1k / 8.8k / 9.5k |
| 20, 67, clustered | 43.1k / 67.9k / 20.6k / 3.7k | 13.7k / 8.8k / 15.2k / 16.3k |
| 31, 39, clustered | 36.8k / 58.2k / 17.5k / 3.2k | 9.7k / 5.1k / 13.1k / 14.7k |
| 40, 38, clustered | 37.9k / 60.0k / 18.0k / 3.3k | 13.0k / 5.7k / 16.2k / 18.4k |
| 60, 39, clustered | 41.3k / 65.5k / 19.6k / 3.5k | 16.5k / 5.9k / 24.4k / 28.3k |
| 60, 71, clustered | 54.7k / 86.6k / 26.1k / 4.5k | 30.0k / 10.7k / 44.5k / 51.3k |
| 60, 41, scattered | 508.3k / 816.7k / 241.7k / 34.6k | 17.3k / 6.2k / 25.7k / 29.7k |

(Ignored test `benchmark_against_the_authentication_structure` in
`roots_from_paths.rs`; the structure snippet is kept as a test-only module
for it. Clustered: within 256 consecutive leaves, as one input's chunks
lie.) The walk wins at every height and layout, by 3 to 5 times on
processor rows for clustered inputs up to height 31 and by 8 to 10 times
on op-stack rows. Above height 31 the node index has a high limb;
tasm-lib's u64 `merkle_step_mem` step costs about 17 rows per level and
made the walk lose to the structure at height 60 (48.6k against 41.3k for
39 clustered leaves). The walk therefore takes a node index with a high
limb in two u32 rounds: the low limb's lower 31 bits, with bit 31 set so
the u32 halves to one after exactly 31 steps, then the index shifted down
31 as a u32, which covers tree heights up to 62 (the inactive SWBF cannot
exceed 2^61 leaves). Every level then costs two instructions, and the
rows above are with that walk.

An input's chunks sit in a span of 256 leaves and share every level above
the eighth, so the structure's realistic cost is the height 8 row plus a
shared trunk, which is what the profile fixture (a 2^8-leaf inactive SWBF)
shows; the walk gains nothing from sharing and costs the same at any
spread. The witness's tree entries now hold the paths of the tree's chunks
back to back instead of the authentication structure; the host converts
between the two forms (`sequential_paths`, `auth_struct_from_paths`) so
the archival update still takes packed records.

Leaf after the swap: 0.70M processor, 0.52M op-stack, 0.41M RAM and 0.24M
hash rows at 8 inputs, 1.39M, 1.03M, 0.82M and 0.47M at 16, so 86k
processor, 63k op-stack, 51k RAM and 29k hash rows per input, from 110k,
109k, 59k and 24k. The roots step is 7.7k processor rows per input, from
32k. Processor is the sole bottleneck again.

Micro-optimizations after the swap, one change each, processor rows per
input: the walk takes the expected old root and checks every chunk's old
walk against the running root (86.2k to 85.1k); the peak mutation walks
each chunk straight from its two hashes, one per-leaf snippet
`UpdateTreeLeaf` instead of two indexed leaf lists (81.3k); the unspent
check proves an unset index by a divined gap in the sorted chunk instead of
scanning it, resting on the mutator set keeping its chunks sorted and the
insertion hash keeping them so (78.9k); the run loop counts by pointer
reads and the positions list nothing read went (75.8k); the chunk
insertions carve every per-chunk list and its taken flags from one page
with pointers written directly (74.5k); the staging copy goes five, two,
one words and both hashes absorb a hundred and sixty words per loop check
(71.0k); the node index comes from one per-tree offset added limb by limb,
the resolution's carry and the chunk witness's appends are inline (69.0k).
Leaf: 0.56M processor, 0.42M op-stack, 0.40M RAM and 0.24M hash rows at 8
inputs, 1.12M, 0.83M, 0.79M and 0.47M at 16, so 69k processor, 51k
op-stack, 49k RAM and 29k hash rows per input.

The last rows, to get the leaf under 2^16 processor rows per input: the
leaf update takes a pointer to the running root and the node index with
its high limb raised, so the walk's dispatch is one comparison and the
caller handles single-leaf trees (67.6k); the insertion hash writes its two
length words at once, both hashes copy eight, four, two and one words as
the count's bits say, and rule 2.a marks used chunks and scans the flags
once instead of counting (65.4k); the insertion count rides on the stack
and the chunk index order compare is inline (64.9k). Leaf: 0.53M
processor, 0.40M op-stack, 0.39M RAM and 0.24M hash rows at 8 inputs,
1.05M, 0.79M, 0.78M and 0.47M at 16, so 64.9k processor, 48.7k op-stack,
48.3k RAM and 29.2k hash rows per input, 610 rows under 2^16. Per input:
the new chunk hashes with insertions 24.5k, the old chunk hashes 7.8k,
rule 2.a's resolution and chunk witness 9.9k, the chunk insertions 7.8k,
the walks 3.9k, the witness audit 4.0k, the rest 7.0k. This is the e1
floor against which f is to be compared; f replaces the 32k of chunk
hashing and the gap proof.

A hybrid could walk each chunk only to its join with the next chunk's
branch and merge partial nodes through a stack, touching each distinct
node once like the structure argument does but at two rows per node. It
would cut the roots' hash rows about fivefold and the roots' processor
rows by two to three thousand per input; the per-chunk bookkeeping stays.
Not taken while processor rows dominate and hash rows do not.

The d1 aggregation `SwbfUpdateAggregation` exists. Measured without the
two proof verifications (ignored test `profile_aggregation`, two leaves of 8
inputs): 8.4k processor rows and 1.4k RAM rows, of which the three peak
computations are 86%, about 225 processor rows per appended digest, so
about 450 per input beneath the node. At the root of a 1000-input block
that is ~450k processor rows next to two STARK verifications, so an
aggregation's padded height is the verifications'. The d2 union was built
and measured (see d) above), found not to reach the target, and removed
again; `PredecessorIsValid` accepts only an aggregation as the root, so
that the root attests the work beneath it, as the next section describes.

### Work floor on the tree

A block's SWBF update must cost its composer a minimum of proving work,
so that leaving transactions out saves nothing and the marginal cost of
the first inputs is zero. The epoch table carries the floor,
`min_swbf_padded_rows`, zero for none. The target is 2^23 rows, four
leaves at 2^21 (about 15 seconds each on a fast desktop) and three
aggregations, which also means that the first 128 or so inputs of a block
come free.

The aggregation reads the padded height of each child's proof, which is
the first item of the proof stream and which verification binds: a proof
declaring 2^h verifies only if it was built at 2^h, so declaring more
costs more. A leaf child contributes 2^h, an aggregation child the sum in
its own output, and the aggregation outputs the sum as the claim's first
word, a field element: a leaf adds at most 2^31, so wrapping the field
takes over 2^33 verified leaf proofs. `PredecessorIsValid` splits the
root's first word into u64 limbs and holds it to the epoch's floor. A leaf
alone cannot attest its height and writes zero there, which is why the
root must be an aggregation.

Triton VM 9 has no interface for padding a trace to a chosen height, and
the proving cost tracks the padded height whether the rows hold work or
padding: every stage from the low-degree extension to FRI runs over the
full padded trace. So a leaf short of its height idles up to it, four
processor rows per iteration of a loop at the end of the program, with the
count in witness memory, capped at 2^27 in the program and chosen by the
composer from one trace of the leaf. A composer with a modified prover
could over-pad instead, at the same cost.

The empty leaf ends where it starts, so without more it would chain with
itself and one idled proof could stand in for four. Every claim therefore
carries its position: the index of its first leaf in its input, the index
of its last in its output, a leaf's own on both ends, an aggregation's
left child's first and right child's last. The aggregation requires the
right child's first index to be the left child's last plus one, for leaf
and aggregation children alike, and `PredecessorIsValid` requires the
root's first index to be 1. Every leaf position in a block is then a
distinct claim, hence a distinct proof.

Reuse of a tree's proofs across competing blocks on the same parent needs
no counter-measure: the block proof consumes every appendix claim's proof,
so a block proposal exposes the claims and nothing a competitor could
re-prove the block program with. Binding the leaves to the composer's
coinbase output was built and reverted on that ground.

The tree can be built to any height: adjacent nodes aggregate pairwise and
an odd node waits for the next level (`SwbfUpdateAggregation::tree`), or
a running root takes a new leaf as its right child, which lets a composer
append transactions as they arrive at one leaf and one aggregation proof
each. Appending across merges needs the block's inputs to keep the leaf
order, which the merge's shuffle does not; that is open.

### Costs of the tree as built

Measured on 2026-10-05, at the arbitrary fixture, in processor rows unless
said otherwise.

The leaf (ignored test `profile_leaf`, 8 and 16 inputs): 545.6k and
1,079.8k rows, so 66.8k per input, of which the chunk hashing and root
walks are 48.9k, rule 2.a's resolution and chunk witness 11.8k, the
witness audit 4.0k, the active window 1.4k and the index-set commitment
0.5k. The index and the idle check cost about 20 rows, once. A leaf of
2^21 holds 31 inputs, one of 2^22 holds 62. RAM rows are 48.6k and hash
rows 29.2k per input, both below the processor.

With the witness flattened on 2026-10-07 (the chunks, the tree heights and
the trees' paths as three lists beside the inputs' index sets, instead of
the packed list's chunk dictionaries; `WitnessLists` reads them in place
of the dictionary parser, and the audit of the nested dictionaries goes
with it): 60.2k per input at the fixture's density of about 410 per chunk,
47.8k with every chunk emptied. The RAM table stays at 48.1k per input,
the two reads of every chunk's contents, so the next optimisation of the
list form meets it at about 48k.

`PredecessorIsValid`, without the verification of the previous block's
proof (ignored test `profile_skipping_program_by_transaction_shape`, which
regenerates `predecessor-is-valid-cost-profile.md`): 11.4k rows per input
while blocks carry the packed chunks, of which hashing the inputs into the
kernel's MAST is 4.5k and 7.5k RAM rows, the witness audit 3.9k, and the
rules 3.0k. With the chunk data stripped from the block's inputs, as e1
has it, 3.1k per input: the 2.e completion from the root's hash 1.3k, the
lustration scan 0.9k, the index-set peaks 0.5k, rule 2.c 0.3k. The
chunkless chains are the profile's own, built by stripping the chunk
dictionaries from a finished block and supplying them to the witness
separately, as the archival mutator set will. Totals: a 2-input block
costs 49.9k rows with chunks and 32.5k without, bound either way by the
hash table's 84k of program attestation, so 2^17; a 20-input block 255.7k
and 87.9k; a block of the maximum size, a million words, 641k processor
and 1,008k RAM rows, so 2^20. The verification of the previous block's
proof comes on top of each. Under e1 a 1000-input block costs
`PredecessorIsValid` about 3M rows, a 2^22 proof, next to 32 leaf proofs
of 2^21.

Next: the host side of e1, which is where the 11.4k drops to 3.1k; the
assessment of e'_1 and e'_2, the composer or guesser holding the archival
mutator set; and the f prototype, a chunk hash over a Merkle tree, for the
leaf numbers it gives.
