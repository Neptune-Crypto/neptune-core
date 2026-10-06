# SOFuN — Standing Orders for Future Neptune

Status: the lock script, the announcement, the order book and the fill are
implemented (§9, phases 1 to 2b); the proposer side is not.
Last updated: 2026-10-06.

---

## 1. Motivation

### 1.1 The composer's forced position

Consensus requires that, in any transaction bearing a coinbase, **at least half
of the total output** be time-locked for
`MINING_REWARD_TIME_LOCK_PERIOD = 3 years` (`block/mod.rs:97`; the check is
`assert_half_output_amount_timelocked`, `native_currency.rs:180-209`, with the
reference implementation at `:925-931`). Guesser rewards are split the same way
— exactly half, time-locked three years from the block header timestamp
(`block_kernel.rs:54-73`). A miner therefore cannot be paid entirely in liquid
NPT. Every block hands them a three-year position whether they want one or not.

Note the rule is stated over *total output*, not over the coinbase. The
distinction is easy to misread, and it is the rule any validator of a fill has
to check.

Composers have real, immediate, denominated-in-fiat costs: electricity,
hardware, hosting, salaries. Half their revenue arriving three years late is a
working-capital problem. Today their only remedies are to sell the position
off-chain (counterparty risk, no price discovery, not available at small scale)
or to hold it and eat the cash-flow gap.

### 1.2 The symmetric want

Meanwhile there are NPT holders on the other side of that trade: people who are
already holding for the long term and are indifferent between liquid NPT now
and more NPT in three years. For them the composer's problem is an opportunity —
they are being offered a discount to do something they were going to do anyway.

The two wants are exactly complementary. What is missing is a market.

### 1.3 Why this does not undo the time-lock's purpose

The obvious objection is that letting composers sell their locked coins defeats
the reason the lock exists. It does not.

The time-lock exists to ensure that whoever is securing the chain today has a
stake in what the coin is worth in three years. SOFuN does not dissolve that
stake. The coins stay locked for the full period; not one NPT is released
early. What changes is *who holds it*. The three-year position is transferred,
intact, to a counterparty who bid for it voluntarily.

Arguably, the alignment improves. Under the status quo, the position sits with
whoever happened to mine, regardless of their time preference, and its holder is
the party most motivated to find a way out. Under SOFuN it migrates to whoever
values three-year exposure most, at a price the market sets. That price is
itself a public, on-chain signal of the network's collective discount rate.

The composer does give up their own long-horizon exposure. What they keep is the
obligation to have found a buyer for it, which is not nothing: a composer who
can only unload the position at a steep discount is being told something.

### 1.4 Why on-chain

The order book could live off-chain. Putting it on-chain buys:

- **Atomicity.** Fill and payment are the same transaction. Neither side can
  renege; there is no escrow and no counterparty risk.
- **Availability to the party who needs it.** The composer is already building a
  transaction. The order book being in the block history means they need no
  additional infrastructure, no account anywhere, and no trust in a venue.
- **Price discovery in public.** The implied discount rate is visible to
  everyone, including to people deciding whether to mine.
- **One consensus change.** A hard fork lets a coinbase transaction spend
  inputs, and nothing else in consensus changes. See §5.

The cost is block space and privacy (§8).

### 1.5 The larger goal: this should generalize

SOFuN is the motivating instance, not the intended endpoint. The mechanism it
needs is a **standing swap order**: a UTXO that can be reclaimed at any time,
and that anyone else may take provided the same transaction creates a specified
output. *I offer this UTXO; whoever pays me that UTXO may have it.*
The book lives on-chain, the trade is atomic, and there is no escrow and no
counterparty risk. Nothing about that description mentions time locks, mining,
or native currency.

**Standing swap order** is the name, and the code should use it rather than
SOFuN's wherever the thing named is general: the announcement flag is
`STANDING_SWAP_ORDER_FLAG` and the generic body struct is `StandingSwapOrderV1`
(§4.3). SOFuN's name appears only on what belongs to SOFuN alone: the `Sofun`
configuration, its per-order `SofunParams`, and `SofunBody`, which is the
generic body's second reading — the same 28 elements, with the demanded-amount
window carrying each SOFuN order's own parameters instead. "Standing" says the
offer rests until its owner withdraws it, "swap" says both sides move at once,
and "order" is what a book is made of.

The intent is therefore that SOFuN be a *configuration* of that primitive rather
than a thing of its own, and that wherever the two diverge the divergence is
**additive**: SOFuN should be a layer over a general core. The notes below flag
where the two come apart.

**Partial fills stay out, but not because the lock script could not express
them.** Filling half an order means spending the order UTXO, paying half the
reward, and returning the other half of the offer to the book — as a new UTXO
under the same lock script. So the script must assert that an output exists
whose lock script hash is its own, and it can. Triton initializes the op stack
with the running program's digest, reversed, in its bottom five positions
(`triton-isa-9.0.0/src/op_stack.rs:58-62`), so a program reads its own hash with
five `dup 15` and no divination at all; the VM's own tests do exactly that and
label the result `own_digest`. Self-reference is available, and a continuation
output can be constrained directly.

What stands in the way is cost and bookkeeping rather than expressiveness. A
partially fillable order's *remaining* size is not in its announcement, because
the announcement is written once, at creation; every consumer would have to
derive the remaining size by replaying each fill against the chain, and the book
would hold partial rows whose terms change under them. The lock script grows a
continuity check that every filler re-proves. None of that is impossible, and a
later version may decide the ledger is worth it.

Against that, the cost of doing without is small and lands on the right party:
granularity is chosen at order creation, by the proposer, who pays one
announcement and one UTXO per piece. The mismatch it cannot express is a taker
who wants a size no proposer offered — which for SOFuN cannot arise, since every
order is exactly one block's slot (§4.1), and for the general case is a reason
to revisit the primitive rather than to complicate this one.

**One divergence is already known, and it is the largest.** SOFuN's demanded
UTXO carries variable state: the release date `D` is not known when the order is
written. That is what forces the discovery problem of §2 and the grid that
answers it. Typical tokens have no variable state: the demanded UTXO is fully
determined when the order is created, its addition record is a single constant,
and order is filled once the desired output is included — there is no
transmission from accepter to proposer.

The clean way to say it: path (b) asserts that **at least one member of an
admissible set of addition records** appears among the transaction's outputs. A
general swap order has a **one-element** set, computed by the proposer when the
order is written. SOFuN needs a **larger**
one, and the grid of §2 is a rule for constructing it — the one-element case is
that grid at `K = 1`, with its constants folded away.

Two things follow, and both are what we want. The wider-scope primitive uses the
*smaller* admissible set, so broadening scope never demands a more capable lock
script: the simplest form of path (b) (Fill) already serves every ordinary swap.
And SOFuN sits as a construction rule layered over that core, rather than being
the thing the core has to be carved out of — so the general primitive can be
specified, implemented and audited without reference to time locks at all.

## 2. The Discovery Problem

The proposer needs to be made aware of the particular timestamp that lives on
the reward UTXO. We solve this by constraining the timestamp to a grid of a
small number of points — a small enough number that enumeration is feasible,
and spaced far enough apart to span a reasonable amount of time. The remainder
of this section motivates this solution and can be safely skipped by the reader
interested in saving time.

The reward is a UTXO carrying `TimeLock::until(D)`. What appears on-chain is not
that UTXO but its addition record — an opaque commitment
`AR(D) = commit(Hash(utxo(D)), sender_randomness*, receiver_digest*)`. The proposer
must be able to identify `AR(D)` in a block, or they cannot locate, prove
membership of, or ever spend their own reward. `D` is a millisecond timestamp,
so guessing is not a recovery path.

Therefore:

> **The set of addition records the reward might take must be small enough for
> the proposer to enumerate, or `D` must be communicated to the proposer.**

That is an exhaustive fork, and it defines the whole design space:

| | How the proposer finds the reward | Cost |
|---|---|---|
| **A. `D` fixed at order creation** | One candidate. Nothing to find. | The proposer must name a date safe for an unknown fill time, so **shelf life and waiting time become the same knob**. |
| **B. `D` on a proposer-defined grid** | `K` candidates, precomputed. | Quantization: the proposer waits up to one grid step longer than necessary. `K` digests of wallet bookkeeping. |
| **C. `D` unconstrained, communicated by announcement** | Read from the announcement. | The announcement must be **enforced by the lock script**, since the accepter has no incentive to publish it. Costs a third kernel-field authentication, block space on every fill, and work for the accepter. |

A fourth option — derive `D` from the filling transaction's timestamp, so the
proposer reads it off the block — **does not work**. The proposer sees the *merged*
kernel, whose timestamp is `max(left, right)` and may exceed the composer's own
by up to `BoundTimeDiff::MAX_TIMESTAMP_DIFF = 12 hours`
(`.../merge_branch/bound_time_diff.rs:17`). At millisecond granularity that is
43.2 million candidates. Dead.

### 2.1 A is a special case of B

Set `K = 1` and option B *is* option A. So there is no fork to resolve here,
only a parameter to choose. The design below is B, and a proposer who wants A picks
`K = 1`.

### 2.2 Why not C

C buys exactly one thing over B: zero quantization. The proposer's wait is
`3 years + composer's margin` instead of `3 years + up to one grid step`. On a
three-year horizon, with a grid step the proposer chooses, that difference is
noise.

Against it, C costs an extra `authenticate_txk_field` plus a linear scan in the
lock script, permanent block space on every fill, extra work for every accepter,
and a rule that must be enforced in-script or else a lazy accepter silently
destroys the proposer's `Y`. B needs none of that: no announcement, no accepter
cooperation, no additional field authenticated.

B dominates. **We choose B and reject C**; nothing below relies on C.

## 3. Design decisions

| Decision | Choice | Why |
|---|---|---|
| Release date `D` | Chosen by the accepter from a **grid** `D ∈ {D₀ + k·G : 0 ≤ k < K}` named by the proposer | Makes the reward enumerable by the proposer (§2) while letting `D` track the actual fill time. Shelf life `K·G` and waiting time `≈3 years + G` are then **independent knobs**, which is what a single fixed date cannot give. |
| Payout announcement | **None** | Not needed once the reward is enumerable. Saves a field authentication, block space, and any reliance on accepter cooperation. |
| Partial fills | **Not supported**, deliberately | One order = one UTXO = one fill; a proposer wanting granularity places several orders and chooses the granularity themselves. Moot for SOFuN, where one order is exactly one block's slot (§4.1). Deferred rather than rejected for the general case — see §1.5. |
| Reward amount `Y` | **Fixed**: half the block subsidy | Every block mints exactly that much time-locked coin, so one order fits one block exactly. Orders then differ only in price `X`, which makes them fungible and the composer's choice among them trivial (§4.1, §4.7). |
| Who may fill | **Anyone** | The lock script does not and should not care. Only a coinbase transaction has a mandatory time-lock for the reward to discharge (§4.6), so composers select themselves; no restriction needs enforcing. |


## 4. Mechanism

### 4.1 The order UTXO

The proposer places `X` NPT into a UTXO whose lock script admits two spending
paths:

- **(a) Cancel.** The proposer's ordinary hash lock. Spendable at any time by the
  proposer, with no further conditions.
- **(b) Fill.** Spendable by *anyone*, provided the same transaction pays the
  reward.

The reward is a UTXO of the shape

```
utxo(D) = Utxo {
    lock_script_hash: <proposer's chosen lock script hash>,
    coins: [ NativeCurrency(Y), TimeLock::until(D) ],
}
AR(D)   = commit( Hash(utxo(D)), sender_randomness*, receiver_digest* )
```

where `commit` is the mutator set operation, *i.e.*,
`hash_pair(hash_pair(item, sender_randomness), receiver_digest)`.

The proposer fixes `Y`, the reward lock script hash, `sender_randomness*`,
`receiver_digest*`, and the grid `(D₀, G, K)`, of which only `D₀` is theirs to
choose — `G` and `K` are protocol constants (§4.3). From those they compute
`AR(D₀ + k·G)` for every `0 ≤ k < K` and hard-code the `K` records into the lock
script; §4.2 says why the script holds the records rather than the ingredients.
The accepter picks a `k` by paying the corresponding record. `k` is never
transmitted — it is not transaction data, not nondeterministic input, and does
not appear on-chain; the composer's choice is visible only as which of the `K`
records the block pays. Write `D_max = D₀ + (K−1)·G` for the last grid point.

**`Y` is not a free parameter either.** Every block mints a fixed amount of
time-locked coin: half the subsidy. It is half however the composer splits the
subsidy with a guesser, because the guesser's share is itself half time-locked
(`block_kernel.rs:54-73`). An order for exactly that amount is filled by one
composer out of one block and consumes the whole of what that block has to
redirect. An order for less makes the composer take several to fill the same
slot, and an order for more cannot be filled at all. So a proposer always asks
for `Y = Block::block_subsidy(h) / 2` (`block/mod.rs:427`), and a composer only
ever fills an order whose `Y` is half of their own block's subsidy.

The subsidy halves every three years (`BLOCKS_PER_GENERATION = 160815` at 588
second blocks, `block_height.rs:45-47`), which is six times an order's shelf
life, so `Y` is stable for the life of any order. The exception is an order
placed shortly before a halving: after it, no composer's block mints enough for
the reward to fit, so the order simply stops being filled and the proposer
cancels it.

There is deliberately **no lower bound beyond `D₀`**. A smaller `D` is strictly
better for the proposer and never cheaper for the accepter — flat in cost down
to `t + 3 years`, and a loss below it (§4.6) — so nothing needs to enforce one.

### 4.2 The lock script

A lock script sees exactly one public input: the transaction kernel MAST hash,
five words, read by `read_io 5`.
Everything else must be divined and authenticated against that root.

Sketch:

```text
read_io 5                             // [txkmh]
divine 5; hash                        // candidate cancel preimage, hashed
push <post-image>                     // 5 words, hard-coded
opened := (the two digests agree)     // 5×eq + 4×mul -> 1 or 0
skiz_over: if not opened:
    // fill
    divine outputs list               // Vec<AdditionRecord>
    authenticate_txk_field(Outputs, txkmh)
    divine i
    assert i < |outputs|
    matches := Σ_{ar ∈ admissible} [outputs[i] == ar]   // admissible hard-coded
    assert matches ≠ 0
halt
```

**The admissible set is hard-coded, not recomputed.** The script holds `K`
addition records, one per grid point, and the fill path is a divined index into
the authenticated outputs and a scan of the output there against those `K`
constants. `k` never appears. Neither do `D₀`, `G`, `Y`, the reward lock script
hash, or the two randomnesses: the proposer folds all of them into the records
before the script is written, and the records are what the script compares
against.

This is §1.5's formulation taken literally — *path (b) asserts that at least one
member of an admissible set of addition records appears among the outputs* —
with the grid as a rule for building the set rather than as arithmetic the
verifier repeats. The general swap order is the same script with a one-element
set. A composer filling a SOFuN order still picks `k` by §4.6; it just picks it
by choosing which of the `K` records to pay, not by transmitting a number.

What this buys is that the script has no arithmetic to get wrong. What it costs
is `K` hard-coded digests and `K` comparisons in the fill path, and that cost is
not negligible. Measured (`fill_cost_by_output_count`), a fill against a
one-element set is 254 cycles and against the 26-element grid is 879 — 25 cycles
per extra member — which carries the padded height from 4096 to 16384, so the
grid costs about 4× the proving work of a general swap order. Output count is the
other axis and the cheaper one: authenticating the outputs field hashes it in
full, about 1.5 cycles per output, so 128 outputs adds 384. The grid dominates
until a transaction has some four hundred outputs.

That is the price of `K` payment dates on one order, and it is paid by the
composer, once per fill, on a proof they are already producing. Recomputing the
grid in the VM instead would replace `K` comparisons with `k`'s arithmetic and
one `commit`, which is cheaper; it is not taken, because the arithmetic is the
part that can be wrong and a spender is the one supplying its input.

**There is no path selector.** The preimage decides. A spender always divines
five words; if they hash to the post-image the hash lock has opened and the
script is done, and if they do not, the reward must be shown among the outputs.
Nobody chooses a branch, so there is no question of what a malicious prover
gains by choosing one, and no way to reach `halt` without having satisfied
exactly one of the two conditions — the fill check is skipped *only* by the hash
lock passing. A design with an explicit selector has to rule out a third
selector value falling through to `halt`; this one has nothing to rule out.

Two consequences worth knowing. Comparing digests as a *value* rather than
asserting costs about fifteen instructions instead of `assert_vector`'s one, and
every fill pays for one hash it does not need — both negligible. And a cancel
attempted with the wrong preimage does not fail as a cancel; it falls through
and fails as an unpaid fill, which is a confusing error message rather than a
soundness problem.

`authenticate_txk_field` already exists
(`neptune-consensus/src/transaction/validity/tasm/authenticate_txk_field.rs`);
the field is `TransactionKernelField::Outputs` (`transaction_kernel.rs:329`).
The grid needs no additional field authentication. The membership check is a
linear scan, so path (b) costs O(outputs), which dominates everything else here.

**The grid bound moved out of the script, so it must hold where the set is
built.** `Timestamp` is a single `BFieldElement`
(`neptune-primitives/src/timestamp.rs:48`) and its `Add` is that field's
addition, which wraps mod `p` in silence; its `Mul` panics rather than reports.
A `D₀` within half a year of the field bound would therefore give a grid whose
last points are wrapped-around dates in the distant past — release dates that
have already passed, on a reward the composer would be paying for nothing.

With no arithmetic in the script there are no braces, only the belt, so the
belt is where the check goes: the constructor rejects any `D₀` whose
`D_max = D₀ + (K−1)·G` reaches `2^63`, in `u64` and before any timestamp
arithmetic runs. Every `StandingSwapOrder<Sofun>` that exists has a grid that
fits, which is what makes the lock-script builder total, and an announcement
carrying an out-of-range `D₀` is rejected as malformed alongside one carrying a
nonzero `padding` (§4.3).

`2^63` is well under `p` and far past any date a time lock means anything on. It
is chosen so that `D₀ + k·G` is the same number in `u64` as it is in the field,
which makes the `u64` check the whole argument.

Note what path (b) does *not* constrain: it says nothing about where `X` goes,
what else the transaction does, what fee it pays, or who signed it. It insists
only that the reward be paid.

### 4.3 Announcement

The envelope is generic; the body has two readings of one fixed length. Three
elements name the market and the schema, and `pair_id` alone decides which
reading applies to the 28 that follow.

```
element 0   flag      STANDING_SWAP_ORDER_FLAG = 1000
element 1   pair_id   Hash(offered type scripts ‖ demanded type scripts)[0]
element 2   version   1 for the generic body, 0 for SOFuN
------------------------------------------------------- body, generic
StandingSwapOrderV1 {                                          elements
    offered_amount           NativeCurrencyAmount                    4
    demanded_amount          NativeCurrencyAmount                    4
    seed                     Digest                                  5
    cancel_post_image        Digest                                  5
    reward_lock_script_hash  Digest                                  5
    reward_receiver_digest   Digest                                  5
}                                                          total     28
--------------------------------------------------------- body, SOFuN
SofunBody {                                                    elements
    offered_amount           NativeCurrencyAmount                    4
    d_zero                   Timestamp                               1  \
    epoch                    u32                                     1   > 4
    padding                  u64                                     2  /
    seed                     Digest                                  5
    cancel_post_image        Digest                                  5
    reward_lock_script_hash  Digest                                  5
    reward_receiver_digest   Digest                                  5
}                                                          total     28
```

**SOFuN overloads the demanded-amount window.** `d_zero` is the origin of the
grid, and the grid exists only because SOFuN's demanded UTXO carries a release
date that is unknown when the order is written (§1.5). A general standing swap
order has a one-element admissible set, no grid, and no origin to publish, so
`d_zero` cannot go in the generic body without contradicting §1.5's requirement
that the primitive be specifiable without reference to time locks at all.

It does not need to. SOFuN's `demanded_amount` is not a free parameter: it is
`Y`, half the block subsidy (§4.1), and `epoch` says which halving's subsidy that
is, so the amount is determined rather than transmitted. Those four elements are
dead weight in a SOFuN order, and `d_zero` costs one of them. `epoch` takes a
second and `padding` fills the remaining two, which keeps both schemas at 28
elements and every shared field at the same offset.

**The three envelope elements are read, not decoded.** None of them belong in a
body, because all three are the key that chooses which body to decode: a reader
must know the version before it can pick a struct, and the same holds for the
flag and for `pair_id`. They are therefore a fixed-position prefix, assembled
and inspected element by element. That also matches how the node already treats
announcements — `Announcement::looks_like_lustration`
(`neptune-consensus/src/transaction/announcement.rs`) tests element 0 directly,
and `AnnouncementFlag` (`neptune-primitives/src/announcement_flag.rs`) is
defined as the first two elements, purpose and receiver id, with `pair_id`
standing in the second slot.

Do not be tempted to give the prefix a struct with a derived `BFieldCodec`. The
reversal noted below would write it as `[version, pair_id, flag]`, putting the
flag at element 2, where no existing scan looks for it.

Nothing further is needed to bind a body to its version. The prefix sits in the
same announcement as the body, under the same block commitment, so a reader that
has the body has the version. Repeating the version inside the body would add
nothing: against an honest reader it guards a bug that cannot occur, since a
reader has already touched elements 0 and 1 to find the announcement at all, and
against a dishonest proposer it guards nothing, since the same party writes both
copies. The requirement is on consumers instead, and it is the ordinary one —
read element 2, and reject a version you do not implement rather than assuming
the one you do.

**Both readings keep the derived codec.** The overload is one of whole typed
fields, not of bits inside a field, so each schema is an ordinary struct with a
derived `BFieldCodec` and neither needs an encoding of its own. Every field is
fixed-length, so a body is the struct's encoding and nothing else, and the
derived `decode` rejects a truncated record. Encoding an announcement is
`[flag, pair_id, version]` concatenated with `body.encode()`.

Two mechanical notes for anyone reading the wire format:

- **Fields are emitted in reverse declaration order**
  (`bfieldcodec_derive-0.7.1/src/lib.rs:197`). Read a body back to front: the
  four digests occupy elements 0 through 19, the overloaded window is 20 through
  23, and `offered_amount` is 24 through 27. Within the window the same
  reversal applies, so it is `padding`, then `epoch`, then `d_zero`.
- **Decoding is parsing, not recognition, and the asymmetry runs one way.**
  `NativeCurrencyAmount` is an `i128`, whose codec writes four 32-bit limbs and
  rejects any element above `u32::MAX` on decode. A timestamp in milliseconds is
  presently about 41 bits, so a generic decoder fed a SOFuN body errors out
  rather than reporting a nonsense price, and even that follows from real
  timestamps rather than from the layout: a `d_zero` small enough to pass would
  be a date before 1970-02-19. The reverse never fails. Every element of a
  generic order's overloaded window is below `u32::MAX` by construction, which
  is exactly what `epoch` and `padding` require and `d_zero` accepts anything,
  so a generic body always decodes as a `SofunBody`. The zero check on
  `padding` rejects some of those bodies but not all of them: a generic body
  whose two elements under `padding` are zero converts to a SOFuN order
  carrying a meaningless release date. Only `pair_id` separates the two
  schemas. Consult it before
  choosing a decoder, and never treat decoding success as evidence of which
  schema a body was written under.

**`padding` must be zero.** A `SofunBody` is a valid version 0 SOFuN order if
and only if its `padding` is zero. The derived codec accepts any value there, so
the check sits in the conversion from `SofunBody` to `StandingSwapOrder`, which
rejects a nonzero `padding`. Under that rule every order has exactly one
encoding, and anything that hashes, indexes or deduplicates announcements can
compare the raw elements.

The requirement costs no room for a later schema. The version is element 2 of
the envelope, outside the body, and a consumer rejects a version it does not
implement before it decodes anything. A version 0 SOFuN decoder therefore never
reads a version 1 SOFuN body, and version 1 may assign those two elements
whatever meaning it needs, whatever version 0 required of them.

The check does not change which UTXO an order describes. `padding` is not an
input to the lock script, so two announcements that differ only in `padding`
rebuild the same order UTXO and name the same AOCL leaf. An order announced with
a nonzero `padding` is still spendable on chain; a conforming consumer does not
list it. Only software that departs from this document writes one.

**The offered amount must not be negative.** An order is valid only if it
offers a non-negative amount, in every configuration, so the constructor of
each refuses a negative offer and decoding, which builds its result through the
constructor, refuses one too. No UTXO can hold a negative amount, so the UTXO
of such an order is never confirmed and no book would open the order; the rule
makes the order type say so, rather than leave it to consensus, and keeps a
fill from being computed from nonsense.

**The body carries only the differences.** Both sides' type scripts are fixed by
the pair, the release date is fixed by the grid, and both offered-side digests
are derived (below), so none of them are on the wire. What is left is two
amounts and four digests generically, and for SOFuN the same four digests, one
amount, and the grid origin in place of the second amount. The cost is that the
body is only decodable by a consumer who knows the pair's schema; an indexer that
does not can still bucket by `pair_id`, it just cannot read the terms. That is
the right trade — the alternative is paying for two `coins` lists in every order,
forever — but it means the version at element 2 is a *per-pair schema* version,
and what §1.5's generic core shares with SOFuN is the envelope, the length, and
the offsets of every field the two have in common, rather than the body itself.

**`G` and `K` are not negotiable, so they are not on the wire.** SOFuN version 0 fixes
`G` = 1 week and `K` = 26. `G` sets the proposer's overshoot: at most two weeks
on top of the three years, one step for quantization and one for §4.6's
headroom. `K` sets shelf life, because the grid is anchored at order creation —
the proposer takes `D₀` to be the first grid point at or after
`placement + 3 years`, and the order is fillable only while
`D_max ≥ t + 3 years` (§4.6), which is `(K−1)·G` ≈ six months from placement.
Six months is generous for the purpose. An order that has gone unfilled that
long is not waiting, it is mispriced, and re-placing it costs one transaction
and re-anchors the grid at a price the proposer has had six months of evidence
about. The wallet-side cost is 26 candidate addition records per open order.

Nothing enforces this at the consensus layer. A lock script is an arbitrary
program and nobody can stop a proposer from writing one on a grid of their own.
But nothing needs to, because the constants live in the accepter's
reconstruction of the lock script (§7.3): they rebuild the script from the
schema, hash it, build the order UTXO around that hash, derive the addition
record from `seed`, and look for it in the AOCL. An order built on a different
grid hashes differently, so its addition record is not the one being looked for,
so the order does not verify and nobody fills it. A deviant order is exactly as
fillable as no order at all. That is the whole of the enforcement, and it is
enough, because the only party who has to agree about the grid is the one
deciding whether to pay. Escaping the configuration means shipping a new SOFuN
schema version and convincing fillers to implement it — which is what
element 2 is for, and is governance rather than a hole in it.

**One seed, three public randomnesses.** The offered side's `sender_randomness`
and `receiver_preimage` and the demanded side's `sender_randomness*` are all
public by design, so publish one `seed` and derive them, after the pattern of
`derive_receiver_id` (`neptune-wallet/src/address/common.rs:29`):

```
offered.sender_randomness   =  H(seed ‖ 0)
offered.receiver_preimage   =  H(seed ‖ 1)
demanded.sender_randomness* =  H(seed ‖ 2)
```

The reward's `receiver_digest*` cannot come from the seed and is published
directly: the seed is public, so anything derived from it is spendable by
anyone, and that digest's preimage is exactly the proposer's custody of the
reward. Deriving the rest collapses §7.1's freshness requirement to a single
invariant — **one fresh seed per order** — which is a great deal easier for a
wallet to get right than three independent ones.

**Naming the pair.** The type of a UTXO is determined by the type scripts of its
coins, so a pair is `(offered type scripts, demanded type
scripts)`. SOFuN's pair is `{NativeCurrency} → {NativeCurrency, TimeLock}`.
`pair_id` is the first element of the hash of the two sets, the way a receiver
id is the first element of a hash of a seed: a filter, and an index. It is not
authenticated by the body — a consumer that knows the schema recomputes it from
the type scripts that schema names and checks the two agree.

**It commits to the type scripts and to nothing else.** The coins' `state` is
deliberately excluded, because `state` is exactly where the varying data lives:
`NativeCurrency`'s state is the amount and `TimeLock::until(D)`'s is the release
date (`time_lock.rs:39-42`). A pair id over state would change with `X`, with
`Y`, and with every grid point — one bucket per order, which is the opposite of
a market key.

The price is a coarser filter. Two assets that share a type script and differ
only in state — a future token type parameterized that way — land in the same
bucket, and a consumer of one sees the other's orders and discards them after
decoding. That is a false positive in an index, never a wrong fill: the lock
script commits to the exact demanded UTXO, state included, so an accepter who
reconstructs it cannot pay the wrong asset. If a market ever does need to be
finer than its type scripts, the place to say so is the schema at element 2,
which is outside the index by design — not the pair id, which would fragment it.

**Why name the pair at all, when the body already says it?** `AnnouncementFlag`
*is* the first two elements of an announcement and a query against
`RPC::block_heights_by_announcement_flags` must supply both. The question is
therefore never "pair id or nothing"; it is what occupies a slot the format
already has.

So `pair_id` is redundant *as data* — derivable from the body, and consumers
should derive it rather than trust it. It earns its element by being the only
part of the record the node can index on.

**The version is element 2, deliberately outside that prefix.** Elements 0
and 1 are the index, so anything put there becomes part of what consumers filter
*on*. A consumer subscribed to `(SWAP_ORDER, v1, pair)` would be blind to `v2`
orders in its own market. It would see an empty book rather than an unreadable
one. Keeping the version out of the index means every consumer of a pair sees
every order in it and can say "version 2, not understood, skipping". Version
skew becomes visible instead of silent.

*And do not mistake it for a full order book.* That index stores at most
`MAX_NUM_BLOCKS_IN_LOOKUP_LIST = 10_000` blocks per key
(`neptune-archive/src/rusty_utxo_index.rs:26`), and its own documentation frames
that as a per-wallet limit — a wallet with incoming UTXOs in more blocks than
that "cannot rely on the mapping". A pair id is shared by every order in its
market, so a market reaches the cap far sooner than any single recipient
would. It is a bootstrap and a coarse filter; anyone tracking a market
maintains their own index either way (§4.8).

**Preimage on one side, digest on the other.** The asymmetry is deliberate,
and getting it backwards loses funds either way:

- The **offered** side publishes `receiver_preimage`. Spending needs the
  preimage, and we want anybody to be able to spend this UTXO through path (b).
  Custody is enforced by the lock script, not by secrecy.
- The **demanded** side publishes only `receiver_digest*`. Creating an output
  needs just the digest — an addition record is
  `commit(item, sender_randomness, receiver_digest)`. Publishing that preimage
  would let anyone spend the proposer's payment.

**What is not in it.**
 - No order id: the UTXO is already confirmed, uniquely identifying the order
   already.
 - No price: both amounts are present, so any indexer computes the rate itself.
 - No lock script hash, on either side. The offered one is *derived* — see
   below — and the demanded one is the reward address, which is published.

**The announcement is a hint, not an authority.** The record is not a claim
about an order; it is enough material to rebuild the order and check it against
the chain. From the body an accepter reconstructs the lock script (`Y`, the
grid, the reward address, `sender_randomness*`, `receiver_digest*` and the
cancel post-image are all it hard-codes), hashes it, builds
`utxo = {that hash, [NativeCurrency(X)]}`, computes its addition record from the
seed-derived randomnesses, and looks for it in the AOCL. Every step is
verification against chain state, and there is no field left to take on trust.
An accepter who skips it can be induced to pay for nothing (§7.3).

Note what this requires of the announcement: the cancel post-image is in the
body precisely because path (a) hard-codes it, and a lock script that cannot be
rebuilt cannot be checked.

**SOFuN's instantiation.** `offered_amount = X` against a demanded
`[NativeCurrency(Y), TimeLock(D)]` whose release date the grid supplies. A
general swap over some other pair states its demanded coins concretely and needs
no grid — a one-element admissible set (§1.5) — which in this encoding means a
different pair, a different schema, and a body without the three grid fields.

**Filling requires no announcement at all.** This is the point of the grid.

### 4.4 Lifecycle

**Place.** Proposer builds a transaction spending `X` into the order UTXO and
attaches the order announcement. The proposer precomputes the `K` candidate
addition records `AR(D₀ + k·G)` and adds them to a watch set.

**Cancel.** Proposer spends the order UTXO via path (a). Costs a transaction fee.

**Fill.** A composer looks only at orders asking for exactly the time-locked
subsidy of the block they are building, and ignores the rest (§4.7). Among
those, they take the one offering the most `X`. They include, in the coinbase
transaction, the order UTXO as an input (satisfying path (b)) and `AR(D)` as an
output funded from the coinbase, choosing a small `k` whose reward output still
counts toward their own mandatory lock, with a margin (§4.6). They keep `X` as
liquid NPT.

**Claim.** The proposer's wallet matches a block's addition records against the
watch set, hits one, recovers `k` and hence the full reward UTXO, and registers
it as an `ExpectedUtxo` (`neptune-wallet/src/expected_utxo.rs`). A wallet that
has lost that state recovers the same thing from its seed (§4.5).

**Expire.** There is no expiry mechanism. Orders become uneconomic as `D_max`
approaches (§4.6) and can be cancelled at leisure.

### 4.5 Deriving an order, and recovering one from the seed alone

`ExpectedUtxo` is a convenience that is allowed to fail. It is wallet-local
state, and a wallet restored from its seed has none of it
(`neptune-wallet/src/expected_utxo.rs:26-31`). What is not allowed to fail is
recovery from the seed, which for ordinary incoming UTXOs means deterministic
key derivation plus a scan for announcements that a *future* key decrypts, the
counter advancing whenever one does
(`neptune-wallet/src/scan_mode_configuration.rs:5-14`). A reward has no address
and no encrypted notification, so that recogniser does not apply to it, and the
question is whether anything replaces it.

Something does, and it is simpler, because an order is *published*. **Everything
per-order comes from one derivation index.** The proposer takes a key at index
`i` the ordinary way — `Tip5::hash_varlen(secret_seed ‖ [FLAG, i])`,
`neptune-wallet/src/wallet_entropy.rs:98-110`, with a flag of its own — and that
one key supplies both secrets an order needs and the public seed of §4.3:

```
cancel_post_image        =  H(key_i's unlock preimage)
reward_lock_script_hash  =  key_i's lock script hash
reward_receiver_digest   =  H(key_i's receiver preimage)
seed                     =  H(key_i ‖ <public-seed domain>)
```

The reward is then an ordinary payment to key `i` that happens to carry a public
`sender_randomness*` and a published receiver digest, so nothing about holding
or spending it is new. The direction of the last derivation is the point: the
public seed comes from the key, never the key from the seed.

Recovery is a scan over public data.

1. Derive keys up to the last known index plus a lookahead and collect their
   cancel post-images into a set.
2. One pass over the chain's announcements — flag 1000, body decodes,
   `cancel_post_image` in the set. Each hit is one of the wallet's own orders,
   and advances the index counter exactly as an observed self-payment does
   today.
3. The announcement carries everything else, so the order UTXO can be rebuilt
   and cancelled, and the `K` candidate addition records recomputed.
4. One pass for those addition records: a hit gives `k`, hence `D`, hence the
   reward UTXO in full.

Step 3 is where fixing `G` and `K` in the schema (§4.3) pays a second time. A
grid whose step and count were the proposer's private choice would be per-order
state that the seed does not carry and the announcement does not have to state,
and recovery would need a durable record of it — which is precisely the kind of
state that is allowed to fail.

So `K` rows of `ExpectedUtxo` per open order is the right answer to the
watch-set question: 26 rows, written for speed, losable without consequence. No
lighter-weight index is needed, because the mechanism that must not fail is not
an index at all.

### 4.6 Which grid point the accepter picks

Let `t` be the timestamp of the filling transaction's kernel. The reward output
counts toward the composer's mandatory time-locked half only if
`D ≥ t + 3 years`. Below that it discharges nothing, and the composer has simply
handed over `Y` for `X`. So a fill takes the first grid point clearing
`t + 3 years`, and an order is fillable at all only while

```
D_max  =  D₀ + (K-1)·G  ≥  t + 3 years
```

The accepter knows `t` exactly — it is their own transaction's timestamp — but
it is not final. The plugin rebuilds the coinbase transaction whenever the tip
moves (§4.9), with a fresh timestamp each time, and a grid point sitting *just*
above `t + 3 years` may fail to clear `t' + 3 years` afterwards, forcing it to
bump `k` and re-prove path (b). So
the accepter takes a step of headroom rather than the tightest point that
clears: above the cliff it costs them nothing, and the proposer at most one
extra grid step.

### 4.7 One fill per block

A composer filling orders is spending block money on strangers. How much, and
how many at a time?

Fixing `Y` at the block's time-locked mint (§4.1) answers both at once. One
order consumes the whole of what one block can redirect, so a composer takes
**at most one order per block**. There is no packing problem, no ceiling to
tune, and no second lock-script proof to pay for.

**The composer ignores every order that asks for a different amount.** Not
prices it lower — ignores it. An order asking for less than the block's
time-locked subsidy would leave part of the slot unused, and one asking for more
cannot be paid out of the block at all, so neither is worth a moment's
attention. What remains is a set of orders that are identical except in price,
and the composer takes the one offering the largest `X`.

This also makes the first step of finding an order the cheapest possible one. An
order's `Y` is a field in its announcement (§4.3), so the filter is a single
comparison against a number the composer already knows, applied before any
lock script is rebuilt or any membership proof is fetched.

Consensus, for its part, imposes no limit of its own. Its only rule is that at
least half of everything the transaction pays out must be time-locked
(`native_currency.rs:925-931`), and a reward output *is* time-locked, so a fill
adds to the side of the ledger the rule wants larger. Filling never brings a
transaction closer to breaking the rule.

**A composer who intends to fill orders keeps the subsidy.** The guesser fee is
a fee, not an output: it is computed as the coinbase minus the composer's share
and handed to the transaction as its fee (`composer_parameters.rs:200-215`).
Since `total_input + coinbase = total_output + fee`, a guesser fraction `g`
leaves a total output of `(1-g)·C + X`, and the forced lock is half of that. The
reward `Y = C/2` does not shrink to match. The two meet at

```
X  ≥  g·C
```

Below that line the fill is still constructible — locking more than half is
always allowed — but part of the reward is then funded from coins the composer
was not forced to lock. Above it the reward is covered entirely by the forced
lock, and the forced lock exceeds the reward by `(X − g·C)/2`, which the
composer locks out of their own outputs. A composer keeping the whole subsidy
therefore locks half the offered amount on top of the reward. A composer keeping the whole subsidy is always above the line; one paying
half of it to a guesser is never above it, because that would need `X ≥ C/2`,
which is `Y`. So order-filling is for composers who guess their own blocks.

**An order carries no fee subsidy.** `X` is the whole of the compensation, paid
as a plain output to the composer. Routing part of it through the transaction's
fee field instead would not sweeten anything: a block's fee *is* the guesser's
reward (`block_body.rs:204-210`), so that money goes to the guesser rather than
to the filler. For the composers who actually fill orders, who guess their own
blocks, it would be the same pocket under a different name; for anyone else it
would be a leak.

What a fill costs the composer is not currency in the first place. It is one
removal record of kernel space and one more lock-script proof, and both are
bounded by taking at most one order per block. There is nothing for a fee to
reimburse. A proposer who wants to be filled sooner raises `X`, which is the one
number orders differ in.

**Where the policy lives: in the plugin.** The SOFuN plugin writes the whole
coinbase transaction of a block that fills an order (§4.9), so it applies the
rule itself, with `X` in the total it halves. The node's `CoinbaseDistribution`
is not consulted for that block.

### 4.8 The order index

Someone has to remember which orders are open. The question is who.

**The SOFuN plugin.** The node knows nothing about orders and must not: an
overlay protocol is a separate application, and the node's whole part in SOFuN
is to accept a coinbase transaction someone else built (§4.9). So the index
lives in the SOFuN plugin, a separate process that `neptune-defi` serves.
`neptune-defi` spawns the node, receives its notifications of new blocks,
mempool transactions and block proposals, and relays them to every plugin
connected to it. A plugin proves that it runs as the user who started
`neptune-defi` with a cookie that `neptune-defi` writes anew at every start,
next to the node's own RPC cookie in its data directory, where only that user
can read it. A plugin reads whatever else it needs from the node over
JSON-RPC. The two facts the index needs from a block are fields of its
transaction kernel: the announcements it carries, and the removal records that
tell which order UTXOs have just been spent. The plugin that fills orders is
also the one that consults the index, so the index sits where it is used.

**It is shaped like the mempool, not like the wallet.** It holds other people's
standing offers rather than the operator's own belongings, it is kept in step
with the tip, it is consulted when a block is built, and entries leave it when
the underlying UTXO is spent. So it is one row per open order, keyed by the
order UTXO's AOCL leaf index. The key is the leaf index rather than the
addition record because two orders with identical terms and identical
randomnesses commit to the same record and both can be confirmed — which the
node's own RPC documents, warning that a query by addition record can return
several blocks. A leaf index is assigned by the AOCL and is unique, and it is
also the last ingredient of the order UTXO's absolute index set, which is how
the book recognizes the block that spends it.

**The composer's query is a scan.** It asks for the largest `X` among the
orders demanding exactly this block's time-locked subsidy, and that amount is
an argument rather than a property of the book, since `epoch` is the proposer's
choice and orders naming the next generation's subsidy stand in the same book.
An ordering by `X` alone therefore answers a question nobody asks: the first
order under it may demand an amount the composer cannot pay. Answering from the
front of a queue means one queue per demanded amount, maintained on every
insert, every retirement and every rollback, and `demanding` (§4.10) does the
filter and the ranking in one pass instead. It is a few thousand comparisons
once per coinbase transaction the plugin builds. When that measurably notices,
bucket by demanded amount and keep a queue on `X` within each bucket.

**Verify on insert, not on query.** An announcement is a hint (§4.3, §7.3), so
admitting one to the index means rebuilding the lock script from it, computing
the order UTXO's addition record, and finding that record among the outputs of
the announcement's own block (§4.10). Done once
when the announcement is first seen, a row in the index is a verified order, and
the plugin building a coinbase transaction can take the best row without
checking it again.

**Verification runs outside the node.** Verifying an announcement is work an
attacker chooses: an announcement is a permissionless write, and checking one
means building a Triton program of `K` addition records and hashing it. The
plugin is a process of its own, so that work never sits inside the write that
sets the node's tip, and its cost falls on the plugin alone.

**The plugin learns of each new tip from a notification.** The node runs its
`--block-notify` command on every new tip, and `neptune-defi` relays it to the
plugin, whose driver fetches the block over JSON-RPC. If the block's parent is
the book's tip, the driver observes the block and applies the result. If it is
not, the chain reorganized: the driver walks the new branch back by parent hash
until it reaches a block it applied before, rolls the book back to that block,
and applies the new branch oldest first. To recognize such a block, the driver
keeps the identities of the blocks it applied, as deep as the book keeps closed
orders. Notifications can arrive faster than a plugin takes them in.
`neptune-defi` keeps up to 1024 for each plugin; past that it drops the oldest
and tells the plugin how many it dropped. The driver then follows the tip as if
it had been notified of it, and its walk back by parent hash brings in the
blocks it missed. So a dropped notification never becomes a dropped block,
which matters because a book that missed the block spending an order would go
on listing it.

The book therefore trails the node's tip by however long fetching and
verification take. An order confirmed in block *h* cannot be filled before
block *h+1* in any case, so a driver that keeps up with block time costs a
composer nothing, and one that falls behind costs it orders it would otherwise
have filled, never a wrong fill.

**On a reorg, roll back to the shared block.** The book only has to notice that
a reorganization happened, which it does because the new block's parent is not
its tip, and roll back to the last block the two branches share. Closed entries stay in the book for that
reason (§4.10). The mempool's answer to a reorg is to clear itself
(`neptune-mempool/src/mempool.rs:1746-1753`), which is fine for transactions that will be
re-broadcast, and wrong here: nothing re-broadcasts an order, and a book does
not replay history to find it again.

**A book knows only the orders placed after it was created.** A node that
starts a book does not go looking for older orders. The cost is that a freshly
started composer sees an order book that fills up over an order's shelf life of
six months rather than at once, and what it buys is that no part of the book
needs a block the plugin has not just been notified of.

**Everyone else is to ask the plugin.** A query for open orders, served through
`neptune-defi`, would keep explorers and third-party wallets from reimplementing
any of the above. It is not built yet (§9).

**Indexing needs no archival state.** Admitting an order needs its own block's
outputs, retiring one needs the inputs of the block that spends it, and both are
in the block the notification names. So a light node can index, as well as place
and cancel orders, which are ordinary wallet operations on its own UTXOs.

**Filling needs a membership proof, and the node restores it on demand.**
Spending the order UTXO needs a mutator-set membership proof for a UTXO the
composer does not own. Every ingredient is public — the item, both randomnesses
and the AOCL leaf index — so the order's absolute index set is public too, and
`wallet_restoreMembershipProof` returns the proof's chain-dependent parts for it,
relative to the tip's mutator set. The plugin asks once per coinbase transaction
it builds, and keeps nothing between blocks. The node answers from its archival
mutator set, so a composer that fills orders runs an archival node.

### 4.9 How a composer executes a fill

A fill is a coinbase transaction that spends the order UTXO through path (b) of
its lock script and pays the reward at a point of the order's grid. The SOFuN
plugin builds the whole transaction and hands it to the node with
`mining_setCoinbaseTx`, as a primitive witness. The node proves it and uses it
in place of the coinbase transaction it would have built. It knows nothing
about orders. Only the hard fork of §5 makes such a transaction valid.

**What the plugin builds.**

- *Input:* the order UTXO, with its lock script and the fill witness, and its
  membership proof restored as §4.8 describes.
- *Outputs:* the reward at the grid point §4.6 picks, and the composer's share,
  paid to an address of the node's own wallet, which the plugin asks
  `personal_generateAddress` for once, when it starts.
  The node registers no expected UTXOs for a transaction it did not build, so
  the composer's outputs carry on-chain notifications, which is how the wallet
  finds them.
- *Coinbase:* the block subsidy. *Fee:* none, so the composer keeps the
  guesser's share; filling pays only a composer who guesses their own blocks
  (§4.7).
- *Announcements:* a lustration announcement for the order input whenever the
  input's AOCL range requires one. On a young chain every input requires one.
  Lustration reveals the input's amount, `X`, which the order announcement made
  public already.

**The witness depends on the kernel, and the kernel does not depend on the
witness.** The fill witness contains the transaction's output list, its
authentication path against the kernel MAST hash (§4.2), and the index of the
reward among the outputs. The kernel's removal records are computed from each
input's UTXO and membership proof, never from its lock script witness. So the
plugin builds the transaction with any witness on the order input, takes the
kernel, computes the fill witness against it, and puts it in place. The node
has nothing to complete.

**The amounts.** Write `C` for the subsidy and `f` for the fee. By
`total_input + coinbase = total_output + fee`, the total output is
`C − f + X`, and the composer's outputs receive what the reward leaves of it:

```
own  =  C − f + X − Y
```

The time-lock rule (§5) requires at least half of the total output to be
time-locked, and the reward `Y = C/2` counts on the time-locked side. So the
composer's own outputs must lock

```
own_timelocked  ≥  (X − f) / 2
```

which with `f = g·C` is §4.7's excess. A composer keeping the whole subsidy pays
no fee and locks `⌈X/2⌉` of their own, rounded up because the rule compares
whole nau. The input raises the amount that must be locked; it never lowers it.

**What the plugin checks before setting the transaction.** The book verified the
order when it admitted it (§4.8), but a block may have arrived since. So the
plugin checks that the membership proof was restored against the current tip,
that `Y` equals this block's time-locked subsidy, and that `k` clears §4.6's
bound with its headroom, and it validates the primitive witness, which runs
every lock script and type script once. These checks are cheap next to
proving, and they are where the composer commits their own money to a
stranger's script.

**What the node checks, every time it composes.** It uses the transaction if and
only if the consensus rules at the block's height allow coinbase inputs, and
the transaction is valid, was built against the mutator set after the
predecessor, claims a non-negative coinbase no greater than the block subsidy,
pays a non-negative fee, is timestamped no earlier than the minimum block time
after the predecessor, and lustrates every input that must lustrate, by no more
than the lustration counter allows. A new block makes the transaction stale,
since its membership proof and mutator set hash belong to the old tip, so the
plugin builds a new one for every tip it is notified of.

**A fill must never stop a block.** If any check fails, the node composes the
block with its own coinbase transaction. The block subsidy is worth more than
any order, and no part of this may sit on the critical path in a way that can
block it.

**Before the fork.** `ConsensusRuleSet::allows_coinbase_inputs` decides whether
the node accepts the transaction. It holds on RegTest, where blocks carry mock
proofs and the rule the fork lifts never runs, and nowhere else until the fork
sets its activation heights. A fill is tested end to end on RegTest.


### 4.10 Replicating the book, and what the interface has to be

§4.8 puts the index in the SOFuN plugin, because the plugin both keeps it and
consults it. Other consumers — a wallet, a market-maker script, an explorer —
replicate the same book, so the book is written once, as a library, and
everything below is chosen so that any process can run it.

**The book is a container, not a chain consumer.** Split the work in two. A
*driver* touches the chain: it finds candidate announcements, decodes them under
the schema `pair_id` names, and performs §7.3's check. A *book* holds what survived and answers
questions about it. Only the driver reads blocks, and only the book needs to be
fast to query.

**An announcement names a UTXO in its own block.** The driver verifies against
the block it was handed and nothing else: it rebuilds the lock script from the
body, derives the order UTXO's addition record, and looks for that record among
that block's own outputs. The leaf index the row is keyed by is the AOCL's leaf
count before the block plus the record's position among its outputs, so the
identifier falls out of the verification, and no second lookup pays for it.

The rule costs a proposer nothing, because one transaction creates the order
UTXO and carries the announcement. What it buys is that the book is a function
of the blocks it is sent: a new block is an update, a reorg is a rollback, and
neither needs an index or a block from the past. The alternative — an
announcement free to name a UTXO confirmed at any earlier height — is a query
by addition record against the whole AOCL, which a light node cannot answer. An
announcement whose record is not among its block's outputs is not an order,
and a conforming consumer does not list it.

**Three types, not one, and each boundary adds information from its own
source.** An order is written once and read twice, and what it is called at each
stage is not a naming preference.

| stage | type | what it holds |
| --- | --- | --- |
| written | `StandingSwapOrderV1` or `SofunBody` | what varies from one order to the next |
| meant | `StandingSwapOrder<C>` | the full terms, the configuration's parameters, and the version; the asset pair is the book's |
| observed | `Order<C>` | the terms, plus confirming height and AOCL leaf index |

From body to logical order, the version comes from the envelope. The asset sets
come from the consumer's own table: it looked this pair up on purpose and
computed `pair_id` from those sets in order to query at all, so it already holds
them, and it hands them to the book once, when the book is created, since every
order in one book shares them. Nothing recovers them from the announcement, since `pair_id` is a one-way
hash of a single element — which is §4.3's point from the other side, that an
indexer ignorant of the pair can bucket by `pair_id` and still not read the
terms.

From logical order to row, the new information is observational and exists only
on the chain. That step *is* §7.3's check.

So the type boundary and the process boundary are one boundary. The driver is
precisely the part that turns a logical order into a row, and it is the only
part that reads blocks. Above the line is decoding, below it is storage
and queries, and that is why a book that performs no chain lookups is
nonetheless correct.

The whole interface follows from that split:

```rust
/// Identity of an order: the AOCL leaf index of its UTXO. Not the addition
/// record, which is not unique.
pub struct OrderId(pub u64);

/// An order in the book: one that has already passed §7.3, plus what only the
/// chain can say about it. Nothing here can be built from an announcement
/// alone, because the book performs no chain lookups.
pub struct Order<C: Swappable> {
    pub id: OrderId,
    /// The confirming block, set by `apply`.
    pub opened_in: BlockId,
    /// The block that spent the order UTXO, or `None` while open.
    pub closed_in: Option<BlockId>,
    /// The terms, and this order's own parameters of a type the configuration
    /// chooses: `SofunParams { d_zero, epoch }` for `Sofun`.
    pub order: StandingSwapOrder<C>,
}

/// A block, named by height for ordering and by hash for identity.
pub struct BlockId {
    pub height: BlockHeight,
    pub hash: Digest,
}

/// One block's worth of change, as the driver observed it.
pub struct BlockUpdate<C: Swappable> {
    pub block: BlockId,
    pub parent: Digest,
    pub opened: Vec<Order<C>>,
    pub closed: Vec<OrderId>,
}

impl<C: Swappable> OrderBook<C> {
    /// An empty book for one market. A closed entry is kept until its
    /// closing block lies `prune_depth` blocks below the tip.
    pub fn new(pair: AssetPair, prune_depth: u64) -> Self;

    /// The assets every order in this book offers and demands.
    pub fn pair(&self) -> &AssetPair;

    /// Admit and retire orders. Rejects an update that does not extend the
    /// tip; re-applying the tip itself is a no-op.
    pub fn apply(&mut self, update: BlockUpdate<C>) -> Result<(), Discontinuity>;

    /// Undo every change above `luca`, reopen whatever closed on the way
    /// there, and make `luca` the tip.
    pub fn roll_back_to(&mut self, luca: BlockId);

    /// Remove every order, open or closed, the predicate selects.
    pub fn prune(&mut self, prune: impl FnMut(&Order<C>) -> bool);

    /// The block this book reflects, if any.
    pub fn tip(&self) -> Option<BlockId>;

    /// Every open order, in no particular order.
    pub fn open_orders(&self) -> impl Iterator<Item = &Order<C>>;

    /// Open or retained closed; `closed_in` says which.
    pub fn get(&self, id: OrderId) -> Option<&Order<C>>;
}

/// Queries that depend on what an order means live with the configuration.
impl OrderBook<Sofun> {
    /// Open orders asking exactly this amount, richest offer first.
    pub fn demanding(&self, demanded: NativeCurrencyAmount)
        -> Vec<&Order<Sofun>>;
}
```

**A row holds a `StandingSwapOrder<C>`, it does not restate one.** The terms of an
order — both amounts and the four digests — already have a type, and the book
has no business owning a second copy of them. The asset pair is the exception
that goes the other way: it is identical for every order in the book, so the
book holds it once instead of every order holding a copy. That also leaves every
order the same fixed size, with no heap allocation of its own, so a limit on
the number of orders is a limit on memory. What it adds is
only what the order itself cannot know, because the chain assigns both rather
than the proposer choosing them: which block confirmed it, and which AOCL leaf
its UTXO became.

**`C::Params` is the additive divergence of §1.5, in memory rather than on
the wire.** `StandingSwapOrder<C>` holds the six fields every configuration
shares and one field of type `C::Params`, which is `SofunParams { d_zero,
epoch }` for SOFuN and `()` for a pair with no parameters. The generic struct
names no SOFuN field, for the same reason the generic body does not carry them
(§4.3): the type parameter is the only place the configuration enters.
Parameters and configuration are different things, and the types say so. A
configuration such as SOFuN is holistic, fixed for the whole book, so it is the
book's type parameter:

```rust
pub trait Swappable: Sized {
    type Params: Debug + Clone;
    type EncodingFormat: BFieldCodec
        + From<StandingSwapOrder<Self>>
        + TryInto<StandingSwapOrder<Self>>;
    fn version() -> u64;

    /// The UTXO holding the offered amount under the order's lock script.
    fn order_utxo(order: &StandingSwapOrder<Self>) -> UtxoTriple;

    /// Provided: checks flag, `pair_id` and version, in that order, then
    /// decodes the body.
    fn recognize(pair_id: BFieldElement, message: &[BFieldElement])
        -> Result<StandingSwapOrder<Self>, UnrecognizedOrder>;
}

pub enum UnrecognizedOrder {
    NotAnOrder,
    NotThisPair,
    UnknownVersion(BFieldElement),
    Malformed,
}

pub struct StandingSwapOrder<C: Swappable> {
    offered_amount: NativeCurrencyAmount,
    demanded_amount: NativeCurrencyAmount,
    seed: Digest,
    cancel_post_image: Digest,
    reward_lock_script_hash: Digest,
    reward_receiver_digest: Digest,
    params: C::Params,
}

pub struct Sofun;
impl Swappable for Sofun {
    type Params = SofunParams;
    type EncodingFormat = SofunBody;
    fn version() -> u64 { 0 }
    fn order_utxo(order: &StandingSwapOrder<Self>) -> UtxoTriple { … }
}
```

**Each configuration constructs its own orders, so encoding cannot fail.** The
fields of `StandingSwapOrder<C>` are private to its module, so a value exists
only if a constructor in that module or one of its children built it, and each
configuration supplies its own. `StandingSwapOrder<Sofun>::new` takes the
offered amount, the parameters and the four digests, and sets the demanded
amount to `Y` of the parameters' `epoch` (§4.1). Every SOFuN order therefore
demands exactly `Y(epoch)`, the conversion to `SofunBody` is total, and decoding
a body and encoding the result reproduces the body. Decoding is the direction
that can fail, on a nonzero `padding` or a negative offer (§4.3), and it builds
its result through `new` as well. Were the terms and the parameters two
separate values, a caller could pair the terms of one order with the parameters
of another, and encoding would write an order whose announced amount disagrees
with its lock script. A configuration with no relation between its terms and
its parameters, such as the `V1Swap` pair, takes both amounts as arguments, and
refuses only a negative offer.

The configuration chooses the parameter type, and each order carries its own
value of it — two SOFuN orders in one book have different `d_zero`. Keying the
book on the configuration rather than on the parameter type also means a query
that only makes sense for one configuration is written against that
configuration by name, as `demanding` is. No method of the generic book reads
`params`.

**Rejected: erasing the schema behind `Box<dyn Order>`.** A trait with `id`,
`offered`, `demanded` and `opened_in` as `&self` methods is object safe, so a
book of trait objects compiles. It solves a variation that cannot occur: a book
replicates one pair, `pair_id` fixes that pair's schema, and every order in it
was therefore decoded the same way. It also costs twice. The composer reads this
structure on every coinbase transaction it builds and wants a contiguous run ordered by offered
amount, not a vector of pointers into separate allocations. And a SOFuN consumer
holding `&dyn Order` cannot reach `d_zero`, so it either downcasts through `Any`,
turning a compile-time fact into a runtime failure, or the trait grows a release
date and the general primitive acquires the time lock §1.5 keeps out of it.

If one process ever serves many pairs, the erasure belongs a level up: a map from
pair to book, with the *book* behind the trait object. That is one indirection
per pair rather than per order, and the erased interface is then the query
surface, which really is uniform across pairs. Inside each book everything stays
concrete. The one place a trait object fits well is the driver, where choosing a
decoder from `pair_id` is dispatch over an open set with a uniform operation, and
the type parameter reappears on the far side once the schema is known.

**The query is a filter and then a maximum, in that order, and it belongs to
SOFuN.** A composer cannot fill an order whose demanded amount differs from half
its own block's subsidy (§4.1), so `demanding` takes that amount and yields the
rest in descending offered amount. There is no global best order, only a best
order for a given block, which is why the subsidy is an argument rather than a
property of the book. Both halves are SOFuN's: the exact-amount filter is its
constraint, and ranking by offered amount is ranking by price only because every
SOFuN order demands the same amount. A taker in a general pair can pay many
amounts and wants price across all of them. So `demanding` is defined on
`OrderBook<Sofun>` alone, built on the generic `open_orders`, and the
generic book encodes nothing about what makes one order better than another.

**Expiry is not in this interface, deliberately.** A standing swap order stands
until its UTXO is spent; it has no clock. SOFuN's shelf life comes from the grid
running out (§4.6), which is a fact about `d_zero` and `K`, not about the
primitive. So the caller skips orders whose grid no longer clears `t + 3 years`,
reading `params`. Putting a deadline on the row, or worse on
`StandingSwapOrder`, would be exactly the kind of SOFuN-shaped leak into the
general core that §1.5 rules out.

**Rollback orders by height; the hash is for identity.** A height names exactly
one block only on a single branch. The book holds one branch at a time, so
rollback and pruning can compare rows by height alone — and they must, since
hashes are unordered. A row nonetheless records the confirming block's hash as
well, so that the block can be named unambiguously by a consumer that does not
share the book's view of which branch is current. What a height cannot do is notice that the book has left its
branch. A driver that sees a reorganization but skips `roll_back_to` would
otherwise hand the book blocks at heights it has already passed, and a book
tracking only its height would either drop them as replays or stack the new
branch onto the orphaned one, silently either way. So every update names its
parent's hash, and `apply` accepts it only if that hash is the tip's and its
height is one more. A missed rollback then fails on the first block of the new
branch, which is what makes the single-branch assumption safe to rely on.

**`roll_back_to` is why closed entries are kept.** An order retired at height
*h* must come back if the chain abandons *h*, so closing an entry sets its
`closed_in` rather than removing it, and the entry stays in the book while a
rollback could still reach it. How deep that is belongs to the operator rather
than to this crate — a deeper book costs memory, a shallower one loses orders a
rollback would have reopened — so `prune_depth` is given when the book is built,
and `apply` drops every entry whose closing block has fallen that far below the
tip. `prune` remains for everything else: it takes an arbitrary predicate and
may remove open orders too, such as SOFuN orders whose grid has run out; that is
safe for the same reason eviction is, since removal can only make the book
incomplete, never wrong.
Open and closed entries share one map, which makes rollback two plain steps:
remove every entry opened above `luca`, then clear `closed_in` on every
entry closed above it. An entry opened and closed on the abandoned branch falls
to the first step regardless of the second.

**Two exits, and only one of them arrives as an announcement.** Orders enter on
a confirmed announcement and leave when the order UTXO is spent, which is a
removal record rather than an announcement, and covers a fill and a cancel
alike. A driver that watches only announcements builds a book that grows and
never shrinks.

**The driver runs in the plugin, and talks to the node through `neptune-defi`
and JSON-RPC.** A DeFi protocol layered on Neptune is a separate application,
and SOFuN is no exception: the fill reaches the composer's block through
`mining_setCoinbaseTx` (§4.9), so nothing about it needs to run inside the
node. Every plugin follows the chain the same way — a notification names a
block, the driver fetches it, and a parent other than the last block it applied
means a rollback first (§4.8) — so that loop is written once in
`neptune-defi`, and a protocol supplies only the state it keeps in step with the
chain. For standing swap orders that state is the book, and each arriving block
is turned into what the book reads and then passed to `observe` and `apply`:

```rust
// neptune_defi::chain

/// What an overlay protocol needs to know about one block.
pub struct ObservedBlock {
    pub id: BlockId,
    pub parent: Digest,
    pub first_leaf_index: u64,
    pub announcements: Vec<Announcement>,
    pub outputs: Vec<AdditionRecord>,
    pub spent: Vec<AbsoluteIndexSet>,
}

// neptune_defi::standing_swap_order::observe

impl<C: Swappable> OrderBook<C> {
    pub fn observe(&self, block: &ObservedBlock) -> BlockUpdate<C>;
}
```

**What is reversible, and what is not.** The process boundary is the cheapest
thing here: discovery, validation, `apply` and `roll_back_to` are the same logic
whichever process runs the driver, and only the channel that brings the blocks
differs. What is permanent is the wire format of §4.3 — the flag value,
how `pair_id` is derived, the 28 elements and their two readings, the reverse
field order, and `padding` being zero. Once orders exist on mainnet
under generic version 1 or SOFuN version 0, those cannot be changed without a
new version that fillers must adopt. Scrutiny belongs there rather than on which process runs the book.

**One rule keeps the rest reversible: dependency direction.** The
`neptune-defi` library depends on `neptune-consensus`, `neptune-mutator-set`,
`neptune-primitives`, `neptune-wallet`, `neptune-rpc-api` and
`neptune-rpc-client`, and on no part of the node, so any process can link it
unchanged; only its tests start a node, to fill an order end to end. The node
never depends on `neptune-defi`, which in particular means block processing
cannot call into the book. `apply` and `roll_back_to` take data, not a `Block`
and not a handle to node state, so the book never learns which process feeds
it.

**Build nothing for mempool yet.** Going from "an order is in the book" to "an
order has a state" is a mechanical change when the time comes, and a
single-variant status today is the dead weight this section exists to avoid. The
same goes for the query surface: return orders and let a market maker or a
wallet decide what to do with them, rather than offering to act on their behalf.


## 5. One consensus change

A fill spends the order UTXO in the composer's coinbase transaction, and
consensus forbids a coinbase transaction to have inputs:
RemovalRecordsIntegrity asserts `coinbase.is_none() || input_utxos.is_empty()`
(`removal_records_integrity.rs`). A hard fork lifts that rule, and SOFuN needs
it: before the fork activates, no fill is valid. Nothing else changes.

- Lock scripts are arbitrary Triton programs; a two-path script needs no new
  permission.
- The composer already chooses the recipients of coinbase outputs.
  `CoinbaseDistribution` (`neptune-wallet/src/coinbase_distribution.rs`) takes
  an arbitrary `ReceivingAddress` per output and is validated only for the
  fraction sums and the liquid/time-locked split.
- The mandatory-time-lock rule counts *amounts*, not recipients. It tallies
  outputs whose release date is at least `timestamp + 3 years` and requires that
  total to be at least **half of the transaction's total output** — the snippet
  is named `assert_half_output_amount_timelocked` (`native_currency.rs:180-209`;
  reference implementation at `:925-931`). A time-locked output paid to a third
  party counts exactly as much as one paid to the composer.

**Inputs cannot loosen the mandatory time lock.** A coinbase transaction with
inputs raises the question of whether they count toward the rule, and in either
sense they cannot help a composer escape it.

*As time-locked value.* The rule counts a UTXO as time-locked if and only if its
release date is at least `timestamp + 3 years`. The `TimeLock` type script lets a
transaction spend a time-locked input only if the input's release date is
earlier than the transaction's timestamp (`time_lock.rs`, reference
implementation at `:1076`). So every time-locked input is already released, its
release date lies before `timestamp`, and a fortiori before
`timestamp + 3 years`. A rule that counted inputs by the same test would find
none of them time-locked: counting them adds nothing to the time-locked side. A
merge cannot change this, since it raises the timestamp and never lowers it.

*As part of the base.* The rule asks for half of the total output, and by
`total_input + coinbase = total_output + fee` the total output includes what the
inputs bring. An input therefore raises the amount that must be time-locked,
never lowers it. For a fill, the order's `X` raises the total output to
`(1-g)·C + X`, which is what §4.7's analysis of the composer's lock starts from.

SOFuN is therefore, apart from the fork, a lock-script, announcement and
plugin feature. The node's part is one RPC, `mining_setCoinbaseTx`, which takes
a coinbase transaction and knows nothing about orders (§4.9).

## 6. Merging

The `Merge` operation is no problem for a fill. This section records why, since
the naive worry is wrong in an instructive way. (Skippable.)

The mandatory time-lock rule is checked by the native-currency type script
against a timestamp authenticated under *the kernel that type script is proving*.
Merging does **not** re-run type scripts. `MergeWitness::merge` verifies the two
sub-proofs against their own kernel MAST hashes and enforces coinbase-specific
structural rules; it never re-evaluates native currency against the merged
kernel. So *a fill that was valid when built stays valid after merging*. **There
is no failure mode here for the accepter.**

What the merged kernel does change is the timestamp: it becomes
`max(left, right)`, which may be later than the accepter's own. Since the
time-lock was proven against the earlier timestamp, the effective lock measured
against *block* time is shorter than three years by that difference. That is
exactly what `BoundTimeDiff::MAX_TIMESTAMP_DIFF = 12 hours` bounds, and the
comment there is explicit about the attack it prevents: without it, a composer
could back-date a coinbase transaction by three years, set release dates at
"now", and merge with a present-dated transaction to obtain immediately liquid
mining rewards.

Consequences for SOFuN:

- The proposer's guarantee is `D ≥ t + 3 years` for the accepter's `t`, but the
  proposer does not know that `t`. The best they can do is start scanning
  `≥ 3 years − 12 hours` measured against block time. That said, the greater the
  erosion, the sooner the funds will be liquid.
- This is a pre-existing property of the coinbase time lock, not something SOFuN
  introduces. Every composer's own time-locked reward is subject to the same
  bounded erosion today.


## 7. Security considerations

### 7.1 One output must not satisfy many orders — **must fix**

Path (b) (Fill) asserts membership of `AR(D)` in the outputs list. If two
orders can produce the same addition record, an accepter can spend **both**
order UTXOs while creating **one** reward output, pocketing the second `X` for
free. The same applies to `n` orders.

The grid widens this rather than narrowing it: two orders agreeing on `Y`,
reward lock script hash, `sender_randomness*` and `receiver_digest*` collide at
any grid point their grids share, and the accepter chooses `k`. Fixing `Y`
(§4.1), `G` and `K` (§4.3) narrows the gap further still — every order in the
market now agrees on three of those parameters by construction, and one wallet's
orders agree on the fourth. The seed is the only thing left keeping two of a
proposer's own orders apart.

Mitigation: every order must use a fresh seed, hence fresh
`sender_randomness*` (§4.3), which makes the commitments distinct for *every*
`k`. This is a hard wallet requirement, not a
convention. Cross-proposer collisions are not a concern — distinct proposers
have distinct receiver digests — but a single wallet placing many orders is
exactly the case where a naive implementation reuses randomness.

*Test to write: place two orders sharing reward parameters, confirm a
transaction spending both with one reward output is accepted by the lock script.
It should be, which is why the wallet must never construct that situation.*

### 7.2 Reorganizations

A fill can be reorganized away. Both the order UTXO and the reward UTXO revert;
the proposer must un-register the `ExpectedUtxo` and restore the order to its
watch set. Standard reorg handling applies; nothing SOFuN-specific, but it needs
a test.

### 7.3 The order announcement is unauthenticated

Anyone can publish an announcement claiming to be a SOFuN order. Accepters must
rebuild the lock script from the announced terms and check it against the order
UTXO's actual lock script hash before treating the order as real, which means
finding the rebuilt addition record among the outputs of the block that carries
the announcement (§4.10). An accepter who skips this check can be induced to
hand over `Y` for a UTXO that pays nothing.

### 7.4 Dust and spam

Orders are permissionless writes to a public index. Very small orders cost the
proposer a fee and cost every node the indexing work. Probably fine; worth a cap
or a minimum `X` in the indexer if it becomes a problem. Note that the fixed `Y`
already disposes of the cheapest kind of junk: an announcement asking for
anything other than the block's time-locked subsidy is discarded on one integer
comparison, before any lock script is rebuilt (§4.7).

---

## 8. Privacy

SOFuN is public by construction. An order reveals `X`, its grid origin `D₀`,
and the fact that some party wants to buy future NPT. `Y`, `G` and `K` are the
same for every order (§4.1, §4.3), so they reveal nothing about this one.

**Creation of the reward is fully public.** The grid is published, so anyone —
not just the proposer — can enumerate the `K` candidate addition records and
watch for one to land. Its amount, its release date and its association with the
order are all in the clear from the moment it exists.

**The spending of a reward is private.** A removal record is identified by
`AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage,
aocl_leaf_index)`. For the
reward UTXO an observer has the item, the sender randomness and the leaf index —
but not the **receiver preimage**, because §4.3 publishes only
`receiver_digest*` on the demanded side. Without it the index set cannot be
computed, so the proposer's eventual spend cannot be matched to the reward.
What remains is the generic mutator-set leak — the index set's `minimum`
constrains the spent UTXO's AOCL batch to a range — which is a property of the
mutator set, not of SOFuN, and is not order-specific.

The offered order UTXO is the deliberate opposite: its receiver preimage *is*
published, so anyone can compute its index set and see exactly when and where
the order was filled. That is the point — the whole design rests on anyone being
able to spend it.

What does leak on the receiving side is the reward's **lock script hash**, since
the announcement publishes it. That address is burned for the order: reuse it
elsewhere and the two are linked. Proposers should use a fresh key and fresh
randomness per order.


## 9. Progress

### Phase 0 — design
- [x] Core mechanism sketched
- [x] Established that a fill needs one consensus change, a coinbase
      transaction with inputs, now coming as a hard fork; and that inputs, in
      either sense, cannot loosen the mandatory time lock (§5)
- [x] Established that a fill pays for itself only inside a coinbase
      transaction (§4.6)
- [x] Discovery problem identified; design space enumerated (§2)
- [x] All code-referenced claims verified against the tree at `1d9d6dfda`
- [x] Fill interface settled: the plugin builds the whole coinbase transaction,
      and the node takes it through `mining_setCoinbaseTx` (§4.9)
- [x] Generalization goal recorded (§1.5)
- [x] Name chosen for the general primitive: **standing swap order** (§1.5)
- [x] Partial fills decided deliberately for the general case: out on grounds of
      cost and bookkeeping, with the upgrade path recorded (§1.5)
- [x] Grid chosen over fixed `D` and over an enforced payout announcement
- [x] Every open question resolved and written into the body
- [ ] Design reviewed by a second pair of eyes

### Phase 1 — lock script
- [x] Two-path lock script implemented, over a hard-coded admissible set
      (`SsoLockScript`)
- [x] Grid → admissible set builder, with `G` and `K` fixed and the grid bound
      enforced in the constructor (`StandingSwapOrder::<Sofun>::lock_script`)
- [x] Unit tests: path (a) accepts the proposer's preimage
- [x] Unit tests: a wrong preimage with no reward output fails, and the same
      wrong preimage with the reward present is a valid fill
- [x] Unit tests: path (b) accepts iff `AR(D₀ + k·G)` ∈ outputs
- [x] Unit tests: path (b) accepts every `k < K`, rejects `k >= K`
- [x] Negative test: a grid whose `D₀ + (K−1)·G` reaches the field bound (§4.2),
      rejected by the constructor and by `recognize`
- [x] Negative test: reward output present but with wrong `Y`, wrong reward
      lock script hash, or wrong receiver digest
- [x] Unit test: the reward UTXO is the one §4.1 specifies, coin by coin, so the
      addition records are not merely self-consistent
- [x] Negative test for §7.1 — one output, two orders; and its mitigation, that
      a fresh seed makes two orders' grids disjoint
- [x] `K = 1` degenerate case behaves as a fixed-`D` order (the general case
      of §1.5; not a reachable SOFuN configuration)
- [x] Proving cost measured against both output-list length and admissible-set
      size (§4.2)

### Phase 2 — announcement and discovery
- [x] `STANDING_SWAP_ORDER_FLAG` = 1000, defined beside the protocol that
      writes it, which is where every other announcement flag is defined (§4.3)
- [x] `G` = 1 week and `K` = 26 defined once, and used by both the lock-script
      builder and the order verifier (§4.3)
- [x] `StandingSwapOrderV1` and `SofunBody` with derived `BFieldCodec`; round-trip
      proptest over both announcements, envelope included, plus a truncation
      case and a check that both bodies are 28 elements with every shared field
      at the same offset
- [x] Schema chosen from `pair_id` before decoding, never from which decoder
      succeeds; test that a generic body decodes as `SofunBody` (§4.3)
- [x] Conversion from `SofunBody` rejects a nonzero `padding`, so every order
      has one encoding and consumers may deduplicate on raw elements (§4.3)
- [x] `pair_id` derived from an `AssetPair`, over sorted type script hashes, so
      that it does not depend on the order a consumer built the sets in; SOFuN's
      own pair stated once (§4.3)
- [x] Announcement generator: the envelope, then the body, read back by
      `recognize` in a round-trip proptest (§4.3)
- [x] Order-announcement / lock-script consistency check (§7.3) as a library
      function: `StandingSwapOrder::order_utxo`, whose addition record an
      accepter or a validator compares with the UTXO being spent
- [x] Order index: insert-time verification, and the composer's query by `Y`
      answered by a scan (§4.8)
- [x] The book takes `BlockUpdate` and performs no chain lookups; a row holds a
      `StandingSwapOrder` rather than repeating its fields (§4.10)
- [x] The driver, which is the other half of that split: candidate
      announcements, §7.3's check against the outputs of the announcement's own
      block, and the AOCL leaf index a row is keyed by (§4.10)
- [x] The node notifies on new blocks, mempool transactions and block proposals
      (`--block-notify`, `--tx-notify`, `--proposal-notify`)
- [x] The driver loop in `neptune-defi`, written once for every plugin
      (`Driver`): fetch each notified block, roll back on a parent the driver
      did not apply, and apply; a gap and a lag notice are followed alike, and
      a reorganization deeper than the driver remembers is an error the plugin
      handles (§4.8, §4.10)
- [x] Blocks read over JSON-RPC by hash (`RpcChain`, `archival_getBlockKernel`)
- [ ] A light node answers a block-by-hash query for recent blocks, so that a
      plugin can follow the chain without an archival node
- [x] No part of the book reads archival state; a book knows the orders placed
      after it was created (§4.8)
- [x] The order UTXO's membership proof restored on demand over JSON-RPC
      (`wallet_restoreMembershipProof`) (§4.8)
- [x] The `neptune-defi` binary: spawns the node, sets the flags it fixes and
      refuses them from the user, and reads the few flags whose values it needs
      as the node does
- [x] Notifications from the node taken in through `neptune-defi notify`, and
      relayed to the plugins that subscribed to them, with a notice to a plugin
      that fell behind (§4.8)
- [x] Plugins connect over TCP and speak JSON lines, authenticated by a cookie
      in the node's data directory that only the user can read; plugins use
      `plugin::connect` (§4.8)
- [x] A negative offered amount refused in every configuration (§4.3)
- [ ] `RpcChain` refuses a block whose AOCL leaf count is below its number of
      outputs, rather than underflowing
- [x] Orders retired on a spent order UTXO, not only admitted on an
      announcement (§4.10)
- [x] An order opened by its own block, closed by a block spending its UTXO,
      and reopened by a rollback abandoning that block, tested against observed
      blocks
- [x] A fill through the lock script, tested end to end on a RegTest node (§4.9)
- [ ] A cancel through the lock script, tested against chain data
- [x] Book rollback on reorg, and an update that does not extend the tip
      rejected rather than applied (§4.10)
- [x] Closed entries retained for rollback and pruned once their closing block
      lies deeper than a depth given when the book is built (§4.10)
- [ ] The `neptune-defi` library depends on no part of the node, checked in CI
      (§4.10)
- [ ] Plugin query exposing open orders

### Phase 2b — fill
- [x] `ConsensusRuleSet::allows_coinbase_inputs`: true on RegTest, false
      elsewhere until the fork (§4.9)
- [x] `mining_setCoinbaseTx`, honored by every composer, with a fallback to the
      node's own coinbase transaction whenever the set one does not fit (§4.9)
- [x] The SOFuN plugin, `neptune-sofun`: keeps the book, and builds,
      validates and sets the fill of the best order for every new tip, or
      unsets it when no order fits (§4.9)
- [x] Tests that a fill already mined is not used again, that a spoofed
      notification changes nothing, and that a plugin that missed too much
      starts its book over
- [ ] A fill merged with mempool transactions, proven with real proofs
- [ ] A fill refused by the node when its lustration would overdraw the
      counter, tested against a chain where lustration is in force
- [ ] The fork's activation heights, once known (§5)

### Phase 3 — proposer side (wallet / `neptune-cli`)
- [ ] Wallet API to place an order
- [ ] Order key derived at an index, with a flag of its own; freshness of the
      seed follows from the index rather than from an RNG (§4.5, §7.1)
- [ ] Randomnesses derived from the public seed, matching §4.3's three domains
- [ ] Recovery test: wipe the wallet database, restore from the seed, and
      recover both an open order and a filled one (§4.5)
- [ ] `K` candidate addition records computed and added to the watch set
- [ ] Watch-set hit recovers `k`, materializes the `ExpectedUtxo`, claims it
- [ ] Watch set restored on reorg (§7.2)
- [ ] Cancel path
- [ ] CLI / RPC surface

### Phase 4 — release
- [ ] User guide under `docs/src/user-guides/`
- [ ] Privacy warning in user-facing docs (§8)
- [ ] Mainnet-readiness review
