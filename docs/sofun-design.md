# SOFuN — Standing Orders for Future Neptune

Status: **design draft**. Nothing implemented yet.
Last updated: 2026-08-28.

---

## 1. Motivation

### 1.1 The composer's forced position

Consensus requires that, in any transaction bearing a coinbase, **at least half
of the total output** be time-locked for
`MINING_REWARD_TIME_LOCK_PERIOD = 3 years` (`block/mod.rs:100`; the check is
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

The two wants are exactly complementary. What is missing is a venue.

### 1.3 Why this does not undo the time-lock's purpose

The obvious objection is that letting composers sell their locked coins defeats
the reason the lock exists. It does not.

The time-lock exists to ensure that whoever is securing the chain today has a
stake in what the coin is worth in three years. SOFuN does not dissolve that
stake — the coins stay locked for the full period; not one NPT is released
early. What changes is *who holds it*. The three-year position is transferred,
intact, to a counterparty who bid for it voluntarily.

Arguably the alignment improves. Under the status quo, the position sits with
whoever happened to mine, regardless of their time preference, and its holder is
the party most motivated to find a way out. Under SOFuN it migrates to whoever
values three-year exposure most, at a price the market sets — and that price is
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
- **No new consensus rules.** See §5.

The cost is block space and privacy (§8).

### 1.5 The larger goal: this should generalize

SOFuN is the motivating instance, not the intended endpoint. The mechanism it
needs — a UTXO its owner can reclaim at any time, and that anyone else may take
provided the same transaction creates a specified output — is a general
**standing swap order**: *I offer this UTXO; whoever pays me that UTXO may have
it.* The book lives on-chain, the trade is atomic, and there is no escrow and no
counterparty risk. Nothing about that description mentions time locks, mining,
or native currency.

The intent is therefore that SOFuN be a *configuration* of that primitive rather
than a thing of its own, and that wherever the two diverge the divergence is
**additive** — a SOFuN layer over a general core, never a general mechanism bent
to SOFuN's needs. §9 audits the rest of this document against that intent.

**One divergence is already known, and it is the largest.** SOFuN's demanded
UTXO carries variable state: the release date `D` is not known when the order is
written. That is what forces the discovery problem of §2 and the grid that
answers it. Typical tokens have no variable state — the demanded UTXO is fully
determined at order creation, its addition record is a single constant, and
path (b) is one digest comparison with nothing to discover.

The clean way to say this is the one §9.3 (C4) argues for: path (b) asserts
that **at least one member of an admissible set of addition records** appears
among the transaction's outputs. A general swap order has a **one-element** set,
computed by the proposer when the order is written. SOFuN needs a **larger** one,
and the grid of §2 is a rule for constructing it — the one-element case is that
grid at `K = 1`, with its constants folded away.

Two things follow, and both are what we want. The wider-scope primitive uses the
*smaller* admissible set, so broadening scope never demands a more capable lock
script: the simplest form of path (b) already serves every ordinary swap. And
SOFuN sits as a construction rule layered over that core, rather than being the
thing the core has to be carved out of — so the general primitive can be
specified, implemented and audited without reference to time locks at all.

## 2. The Discovery Problem

Everything about the reward's shape follows from one constraint, so it is worth
stating before the mechanism rather than after.

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
| **C. `D` free, communicated by announcement** | Read from the announcement. | The announcement must be **enforced by the lock script**, since the accepter has no incentive to publish it. Costs a third kernel-field authentication, block space on every fill, and work for the accepter. |

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

---

## 3. Design decisions

| Decision | Choice | Why |
|---|---|---|
| Release date `D` | Chosen by the accepter from a **grid** `D ∈ {D₀ + k·G : 0 ≤ k < K}` named by the proposer | Makes the reward enumerable by the proposer (§2) while letting `D` track the actual fill time. Shelf life `K·G` and waiting time `≈3 years + G` are then **independent knobs**, which is what a single fixed date cannot give. |
| Payout announcement | **None** | Not needed once the reward is enumerable. Saves a field authentication, block space, and any reliance on accepter cooperation. |
| Partial fills | **Not supported** | One order = one UTXO = one fill. A proposer wanting granularity places several orders. Keeps the lock script free of arithmetic beyond `D₀ + k·G`. *Most likely of these to be reopened by generalization — see §9.3 (C3).* |
| Who may fill | **Anyone** | The lock script does not and should not care. The economics select composers on their own (§5); no restriction needs enforcing. |

---

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

where `commit` is `neptune-mutator-set/src/lib.rs:96`, i.e.
`hash_pair(hash_pair(item, sender_randomness), receiver_digest)`.

The proposer hard-codes into the lock script: `Y`, the reward lock script hash,
`sender_randomness*`, `receiver_digest*`, and the grid `(D₀, G, K)`. The
accepter divines only `k`, giving `D = D₀ + k·G` with `0 ≤ k < K` — it is
nondeterministic input to the lock script, not transaction data, and never
appears on-chain. Write `D_max = D₀ + (K−1)·G` for the last grid point.

There is deliberately **no lower bound beyond `D₀`**. A smaller `D` is strictly
better for the proposer and strictly more expensive for the accepter (§6.3), so
nothing needs to enforce one.

### 4.2 The lock script

A lock script sees exactly one public input: the transaction kernel MAST hash,
five words, delivered by `read_io 5`
(`neptune-consensus/src/transaction/validity/tasm/claims/generate_lock_script_claim_template.rs`).
Everything else must be divined and authenticated against that root.

Sketch:

```text
read_io 5                             // [txkmh]
divine 1                              // path selector
if selector == 0:
    // (a) cancel: standard hash lock
    divine 5; hash; assert_vector <proposer's after-image>
else:
    // (b) fill
    divine k
    assert k < K                      // K hard-coded
    D    := D0 + k*G                  // D0, G hard-coded
    utxo := [ NativeCurrency(Y), TimeLock(D) ]      // Y, lsh hard-coded
    ar   := commit(Hash(utxo), sr*, rd*)            // sr*, rd* hard-coded
    divine outputs list               // Vec<AdditionRecord>
    authenticate_txk_field(Outputs, txkmh)
    assert ar ∈ outputs
halt
```

`authenticate_txk_field` already exists
(`neptune-consensus/src/transaction/validity/tasm/authenticate_txk_field.rs`);
the field is `TransactionKernelField::Outputs` (`transaction_kernel.rs:312`).
The grid costs roughly six instructions — a range check on `k` and one
multiply-add — and no additional field authentication. The membership check is
a linear scan, so path (b) costs O(outputs).

> **Generalization note (§9.3, C4).** Read the above as the SOFuN instance of a
> general rule: *path (b) asserts that at least one member of an admissible set
> of addition records appears among the outputs.* The general case has one member
> and needs no arithmetic; the grid is a derivation rule for a larger set.

Note what path (b) does *not* constrain: it says nothing about where `X` goes,
what else the transaction does, what fee it pays, or who signed it. It insists
only that the reward be paid.

### 4.3 Announcement

The announcement is layered: a generic standing swap order record, plus a SOFuN
extension. The generic part carries no notion of currency or time.

```
element 0   flag      STANDING_SWAP_ORDER
element 1   pair_id   truncated Hash(offered assets ‖ demanded assets)
element 2   version
--------------------------------------------------------------- body
offered  { lock_script_hash, coins, sender_randomness, receiver_preimage }
demanded { lock_script_hash, coins, sender_randomness*, receiver_digest*,
           derivation }
```

**Naming the pair.** An asset's on-chain identity is the set of type script
hashes in its coins, so a pair is `(offered type scripts, demanded type
scripts)`. SOFuN's pair is `{NativeCurrency} → {NativeCurrency, TimeLock}` —
both sides are native currency, and the `TimeLock` is the whole trade.
`pair_id` is a truncated hash of the two sets: a filter, never an authority.
The full type script hashes are in the body, where they can be checked.

**Why name the pair at all, when the body already says it?** Because element 1
is indexed whether we use it or not. `AnnouncementFlag` *is* the first two
elements of an announcement — purpose, then receiver id
(`neptune-primitives/src/announcement_flag.rs`) — and a query against
`RPC::block_heights_by_announcement_flags` must supply both. The question is
therefore never "pair id or nothing"; it is what occupies a slot the format
already has. A constant would file every swap order in existence under one key.
The order's own identifier would make the index unqueryable by anyone who does
not already know what they are looking for. Partitioning by market is the best
available use of the slot, and a swap order has no receiver to name there.

So `pair_id` is redundant *as data* — derivable from the body, and consumers
should derive it rather than trust it. It earns its element by being the only
part of the record the node can index on.

**The version is element 2, deliberately outside that prefix.** Only elements 0
and 1 are indexed, so anything put there becomes part of what consumers filter
*on*. A consumer subscribed to `(SWAP_ORDER, v1, pair)` would be blind to `v2`
orders in its own market — it would see an empty book rather than an
unreadable one, which is the worse of the two failure modes. Keeping the
version one element further in means every consumer of a pair sees every order
in it and can say "version 2, not understood, skipping". Version skew becomes
visible instead of silent.

*And do not mistake it for an order book.* That index stores at most
`MAX_NUM_BLOCKS_IN_LOOKUP_LIST = 10_000` blocks per key
(`neptune-archive/src/rusty_utxo_index.rs:26`), and its own documentation frames
that as a per-wallet limit — a wallet with incoming UTXOs in more blocks than
that "cannot rely on the mapping". A pair id is shared by every order in its
market, so a market reaches the cap far sooner than any single recipient
would. It is a bootstrap and a coarse filter; anyone tracking a market
maintains their own index either way (§10).

**Preimage on one side, digest on the other.** The asymmetry is deliberate,
and getting it backwards loses funds either way:

- The **offered** side publishes `receiver_preimage`. Spending needs the
  preimage, and we want anybody to be able to spend this UTXO through path (b).
  Custody is enforced by the lock script, not by secrecy.
- The **demanded** side publishes only `receiver_digest*`. Creating an output
  needs just the digest — an addition record is
  `commit(item, sender_randomness, receiver_digest)`. Publishing that preimage
  would let anyone spend the proposer's payment.

**What is not in it.** No order id: the offered addition record is
`commit(Hash(offered utxo), sender_randomness, Hash(receiver_preimage))`, and
every input is already published, so it is derivable — and derivable identically
by everyone, which is what an id is for. No price either: both `coins` lists are
present, so any indexer computes the rate itself.

**The announcement is a hint, not an authority.** Every field is checkable:
rebuild the lock script from the published parameters, hash it, compare against
`offered.lock_script_hash`, and confirm that matches the UTXO actually on chain.
An accepter that skips this can be induced to pay for nothing (§7.5).

**SOFuN's instantiation.** `offered.coins = [NativeCurrency(X)]`;
`demanded.coins = [NativeCurrency(Y), TimeLock(·)]` with the release date left
open and `derivation = grid(D₀, G, K)` closing it. A general swap leaves
`derivation` empty and states `demanded.coins` concretely — a one-element
admissible set (§1.5).

**Filling requires no announcement at all.** This is the point of the grid.

### 4.4 Lifecycle

**Place.** Proposer builds a transaction spending `X` into the order UTXO and
attaches the order announcement. The proposer precomputes the `K` candidate
addition records `AR(D₀ + k·G)` and adds them to a watch set.

**Cancel.** Proposer spends the order UTXO via path (a). Costs a transaction fee.

**Fill.** A composer includes, in the coinbase transaction they are building,
the order UTXO as an input (satisfying path (b)) and `AR(D)` as an output funded
from the coinbase, choosing the smallest `k` for which the fill is free (§6.3).
They keep `X` as liquid NPT.

**Claim.** The proposer's wallet matches a block's addition records against the
watch set, hits one, recovers `k` and hence the full reward UTXO, and registers
it as an `ExpectedUtxo` (`neptune-wallet/src/expected_utxo.rs`).

**Expire.** There is no expiry mechanism. Orders become uneconomic as `D_max`
approaches (§6.3) and can be cancelled at leisure.

---

## 5. No consensus changes required

This is the strongest property of the design and worth stating plainly.

- Lock scripts are arbitrary Triton programs; a two-path script needs no new
  permission.
- The composer already chooses the recipients of coinbase outputs.
  `CoinbaseDistribution` (`neptune-wallet/src/coinbase_distribution.rs`) takes an
  arbitrary `ReceivingAddress` per output and is validated only for the fraction
  sums and the liquid/time-locked split.
- The mandatory-time-lock rule counts *amounts*, not recipients. It tallies
  outputs whose release date is at least `timestamp + 3 years` and requires that
  total to be at least **half of the transaction's total output** — the snippet
  is named `assert_half_output_amount_timelocked` (`native_currency.rs:180-209`;
  reference implementation at `:925-931`). A time-locked output paid to a third
  party counts exactly as much as one paid to the composer.

SOFuN is therefore entirely a wallet-, lock-script- and announcement-layer
feature. Nothing in `neptune-consensus` needs to change.

---

## 6. Economics

### 6.1 Filling is free for a composer, and — for SOFuN — only for a composer

> **Generalization note (§9.3, C1).** What follows is a property of what SOFuN
> *demands*, not of path (b). A general standing swap order demands a UTXO the
> accepter is happy to pay, and its accepters are ordinary.


Write the accepter's balance equation for an ordinary, non-coinbase transaction.
Accepter brings own inputs worth `Z`; the transaction spends the order UTXO
(`X`) and must create the reward output (`Y`):

```
X + Z = Y + change      =>   change = X + Z - Y
```

The accepter started with `Z` liquid and ends with `X + Z - Y` liquid, a net
change of `X - Y < 0`, and the reward UTXO belongs to the *proposer*, not to
them. A non-composer fill is a pure gift of `Y - X`. Nobody rational does it.

The balance equation is clean here because the mandatory-time-lock rule is
guarded by `if some_coinbase.is_positive()` (`native_currency.rs:927`). A
transaction without a coinbase carries no time-lock obligation at all.

Existing time-locked UTXOs cannot rescue this either: the time-lock type script
requires every time-locked input to have `release_date < timestamp`
(`time_lock.rs:1076`), so a would-be accepter cannot pay the reward out of coins
they already hold locked.

The composer is different only because they are *minting*. Consensus already
forces half of their output into a three-year lock; redirecting `Y` of that
forced-locked amount to the proposer costs them nothing they had a choice about.

It follows that **a fill is free only inside the transaction bearing the
coinbase**, because that is the only transaction the mandatory-time-lock rule
applies to (`native_currency.rs:927`), so it is the only place the reward output
can discharge an obligation the composer already had. The lock script binds the
order UTXO and the reward output to one kernel (§4.2), so they cannot be split
across a merge: the reward must be an output of whichever transaction spends the
order, and for the fill to be free that transaction must be the coinbase one.

A fill *can* be constructed elsewhere — this is worth knowing, because it is not
forbidden, merely pointless. A non-coinbase transaction may carry a **negative**
fee (`native_currency.rs:831`: `coinbase.is_none() || !fee.is_negative()`), so
an accepter can build a standalone transaction with input `X`, the reward output
`Y > X`, and fee `X - Y < 0`, to be merged as the left-hand side of some bundle
whose positive fees restore the block-level requirement that the fee be
non-negative (`block_program.rs:401`). But the reward then discharges nobody's
mandatory lock, and the `Y - X` comes out of fee revenue the guesser would
otherwise have received. It is §6.1's gift with a different payer, and a
composer selecting on fees will not carry it.

So filling profitably is not something an outside party can do by submitting a
transaction. It requires the composer's cooperation at the moment they build
their own.

### 6.2 The premium

`Y/X` is the price of three-year money, set by whatever proposers are willing to
offer and composers willing to accept. Nothing in the protocol constrains it.
A composer picks the best available rate among open orders it can fill for free
(§6.3), subject to block space and to its redirectable locked share.

### 6.3 Which grid point the accepter picks

Let `t` be the timestamp of the accepter's own transaction kernel. Their cost as
a function of `D`:

- **`D ≥ t + 3 years`** — the reward output counts toward the composer's
  mandatory time-locked half. The fill is free: a pure redirection of coins the
  composer was forced to lock anyway.
- **`D < t + 3 years`** — the reward output discharges none of the composer's
  mandatory lock, which leaves unchanged the only thing that made the trade
  work. They hand over `Y` of freely disposable output and receive `X < Y`
  back. That is not lending — nothing is repaid, the reward belongs to the
  proposer — it is the pure gift of §6.1, and **no premium redeems it.** The
  premium *is* `Y - X`; raising it deepens the loss.

So the second regime is empty of rational accepters, not merely expensive. Cost
is flat for every `D ≥ t + 3 years` and the trade simply ceases to exist below
it. The accepter is indifferent among the free choices and takes the smallest,
which is also the one the proposer prefers. That set is non-empty exactly when

```
D_max  =  D₀ + (K-1)·G  ≥  t + 3 years
```

and the accepter's chosen `D` then lies in `[t + 3y, t + 3y + G)`.

The accepter chooses `k` knowing `t` exactly — it is their own transaction's
timestamp — so this is a decision made with full information. Merging does not
disturb it; see §6.5.

### 6.4 What the accepter should leave headroom for

One operational caveat, and it is about proposal churn rather than merging. A
composer may rebuild or re-time the coinbase transaction — mempool contents
change, a stale proposal gets refreshed. If they re-time from `t` to `t' > t`, a
grid point chosen to sit *just* above `t + 3 years` may no longer clear
`t' + 3 years`, and they must bump `k` and re-prove path (b).

So an accepter should pick a grid point with a little headroom rather than the
tightest one that is free. The cost of headroom is nothing to them (cost is flat
above `t + 3 years`, §6.3) and at most one extra grid step to the proposer.

### 6.5 What merging does and does not do to the time lock

Worth recording, because the naive worry is wrong in an instructive way.

The mandatory-time-lock rule is checked by the native-currency type script
against a timestamp authenticated under *the kernel that type script is proving*
— the accepter's own (`native_currency.rs:346-380`, and the reference
implementation at `:901`, `release_date >= timestamp + MINING_REWARD_TIME_LOCK_PERIOD`).
Merging does **not** re-run type scripts. `MergeWitness::merge` verifies the two
sub-proofs against their own kernel MAST hashes and enforces coinbase-specific
structural rules; it never re-evaluates native currency against the merged
kernel. So a fill that was valid when built stays valid after merging. **There
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

Consequences for SOFuN, both benign:

- The proposer's guarantee is `D ≥ t + 3 years` for the accepter's `t`, hence
  `≥ 3 years − 12 hours` measured against block time. Twelve hours on a
  three-year horizon, and it runs in the proposer's favour.
- This is a pre-existing property of the coinbase time lock, not something SOFuN
  introduces. Every composer's own time-locked reward is subject to the same
  bounded erosion today.

### 6.6 The two knobs

This is what the grid buys, and it is the reason for preferring it to a single
fixed date:

| Knob | Set by | Controls |
|---|---|---|
| `G` (grid step) | proposer | How much longer than three years the proposer waits: `[3y, 3y + G)`. |
| `K·G` (grid span) | proposer | Shelf life — how long the order stays free-fillable. |

With a single fixed `D` these collapse into one. A proposer wanting six months of
shelf life would have to name a date six months further out and then wait the
full six months even if filled on day one — a 16% longer lock for shelf life
they did not consume. With the grid they set `G = 1 week`, `K = 26`, and get six
months of shelf life for at most a week of extra waiting.

The remaining cost is `K` digests in the proposer's watch set. At these numbers
that is nothing.

**Staleness.** As real time advances, `t + 3 years` climbs toward `D_max`; once
it passes, the free set is empty and the order is **dead** — not merely
unattractive, but unfillable by anyone who is not making a donation (§6.3).
Stale orders die of natural causes.

Wallet default: `D₀ = now + MINING_REWARD_TIME_LOCK_PERIOD + G`, with `G` and
`K` exposed as "how precisely do you want the release date" and "how long should
this order stand".

---

## 7. Security considerations

### 7.1 One output must not satisfy many orders — **must fix**

Path (b) asserts membership of `AR(D)` in the outputs list. If two orders can
produce the same addition record, an accepter can spend **both** order UTXOs
while creating **one** reward output, pocketing the second `X` for free. The
same applies to `n` orders.

The grid widens this rather than narrowing it: two orders agreeing on `Y`,
reward lock script hash, `sender_randomness*` and `receiver_digest*` collide at
any grid point their grids share, and the accepter chooses `k`.

Mitigation: every order must use fresh `sender_randomness*`, which makes the
commitments distinct for *every* `k`. This is a hard wallet requirement, not a
convention. Cross-proposer collisions are not a concern — distinct proposers have
distinct receiver digests — but a single wallet placing many orders is exactly
the case where a naive implementation reuses randomness.

*Test to write: place two orders sharing reward parameters, confirm a
transaction spending both with one reward output is accepted by the lock script.
It should be, which is why the wallet must never construct that situation.*

### 7.2 Fill races

Several composers may target the same order in competing block proposals. Only
one wins; the losers' proposals are wasted. Cost is bounded (the order was one
input among many) but wallets should prefer orders not already claimed in a
block proposal they have seen.

### 7.3 Reorganizations

A fill can be reorganized away. Both the order UTXO and the reward UTXO revert;
the proposer must un-register the `ExpectedUtxo` and restore the order to its watch
set. Standard reorg handling applies; nothing SOFuN-specific, but it needs a
test.

### 7.4 Cancel/fill race

A proposer cancelling and a composer filling can collide. Whichever confirms first
wins; the other transaction becomes invalid on a spent input. Acceptable — but a
proposer who cancels should not assume the cancel took effect until it confirms.

### 7.5 The order announcement is unauthenticated

Anyone can publish an announcement claiming to be a SOFuN order. Accepters must
rebuild the lock script from the announced terms and check it against the order
UTXO's actual lock script hash before treating the order as real. An accepter
who skips this check can be induced to hand over `Y` for a UTXO that pays
nothing.

Note that the proposer no longer depends on any announcement to be paid, so there
is no forged-announcement attack on the proposer's side. Removing the payout
announcement removed a trust surface as well as a cost.

### 7.6 Dust and spam

Orders are permissionless writes to a public index. Very small orders cost the
proposer a fee and cost every node the indexing work. Probably fine; worth a cap or
a minimum `X` in the indexer if it becomes a problem.

---

## 8. Privacy

SOFuN is public by construction. An order reveals `X`, `Y`, the grid
`(D₀, G, K)`, and the fact that some party wants to buy future NPT.

**Creation of the reward is fully public.** The grid is published, so anyone —
not just the proposer — can enumerate the `K` candidate addition records and
watch for one to land. Its amount, its release date and its association with the
order are all in the clear from the moment it exists.

**The later spend of it is not.** A removal record is identified by
`AbsoluteIndexSet::compute(item, sender_randomness, receiver_preimage,
aocl_leaf_index)`
(`neptune-mutator-set/src/removal_record/absolute_index_set.rs:84`). For the
reward UTXO an observer has the item, the sender randomness and the leaf index —
but not the **receiver preimage**, because §4.3 publishes only
`receiver_digest*` on the demanded side. Without it the index set cannot be
computed, so the proposer's eventual spend cannot be matched to the reward.
What remains is the generic mutator-set leak — the index set's `minimum`
constrains the spent UTXO's AOCL batch to a range — which is a property of the
mutator set, not of SOFuN, and is not order-specific.

The offered order UTXO is the deliberate opposite: its receiver preimage *is*
published, so anyone can compute its index set and see exactly when and where the
order was filled. That is the point — the whole design rests on anyone being able
to spend it.

So the §4.3 asymmetry is a privacy boundary as much as a security one: publish
the preimage on the side you are giving away, and the side you are receiving
keeps its unlinkability.

What does leak on the receiving side is the reward's **lock script hash**, since
the announcement publishes it. That address is burned for the order: reuse it
elsewhere and the two are linked. Proposers should use a fresh key and fresh
randomness per order.

Note that none of this is a cost of the grid. An enforced payout announcement
would have published the same creation-time link, and a single fixed `D` would
have published it too. Creation-time linkability is inherent to putting the
order book on-chain, and no variant of the reward encoding avoids it.

---

## 9. Generalization audit

Measuring this document against §1.5. Three verdicts: **carries** (already
general), **layers** (SOFuN-specific but additive, no action), **conflicts**
(states a SOFuN fact as a general property, or makes a choice the general case
would reopen).

### 9.1 What carries unchanged

The core is already the general primitive:

- The two-path lock script shape — owner reclaims, or anyone takes on payment.
  Nothing in it mentions currency or time.
- Cancel via path (a).
- Publishing the order UTXO's `sender_randomness` and `receiver_preimage` so
  anyone can build its removal record. Custody by lock script, not by secrecy.
- §5, no consensus changes — and *stronger* in the general case, which does not
  touch the coinbase machinery at all.
- §7 security and §8 privacy, essentially verbatim.
- Order discovery by scanning announcements; the on-chain book.

### 9.2 What layers cleanly

SOFuN-specific, but strictly additive. No action beyond keeping the seams
visible:

- §2 and the grid `(D₀, G, K)`. `K = 1` is the general form, so the general case
  is reached by *not* using a feature rather than by removing one.
- §6 in its entirety: the free-or-not-at-all regimes,
  staleness, the two knobs. All of it descends from the coinbase
  mandatory-time-lock rule and none of it applies to a token-for-token swap.

### 9.3 Conflicts

**C1 — §6.1's title claims too much.** "Filling is free for a composer, *and
only for a composer*" reads as a property of path (b). It is not; it is a
property of what SOFuN *demands*. A general swap demands a UTXO the accepter is
happy to pay, and the accepter is anyone who wants the trade. The mechanism is
indifferent. Scope the claim to SOFuN or it will be read as a limitation of the
primitive.

**C2 — how a fill is executed does not generalize, and this is the load-bearing
conflict.** A SOFuN fill is only free inside the coinbase transaction (§6.1), so
in practice only a composer can perform it, at the moment they build their
block, using a mechanism that does not exist today: nothing lets an outside
party place an *input* into the node's coinbase transaction.

A general swap fill has none of that. It is an ordinary mempool transaction —
build it, sign it, submit it — available to anyone, needing no privilege and no
new node interface.

So the two share a lock script and an order book but not an execution path.
Whatever eventually lets a composer fill a SOFuN order is a privileged surface
(it puts foreign inputs into the node's own transaction) and the general case
must not be built on top of it, or it inherits a danger it has no use for.

**C3 — partial fills.** "Not supported" is defensible for SOFuN: orders are
lumpy, proposers can place several, and it keeps the lock script free of
arithmetic. For a general A-for-B order book it is a much harder sell — a market
without partial fills is a poor market. This is the decision most likely to be
reopened by generalization, and it should be reopened deliberately rather than
inherited by accident.

**C4 — the lock script is described as a currency-and-timelock template.** §4.1
and §4.2 hard-code `[NativeCurrency(Y), TimeLock(D)]` and derive the admissible
commitments from the grid. The general form is one level up:

> Path (b) asserts that **at least one member of an admissible set of addition
> records** appears among the transaction's outputs.

The general case has `|set| = 1`; SOFuN's grid is one *derivation rule* for a
larger set. Framing it this way costs nothing today and means the general script
is not a rewrite of the SOFuN one.

**C5 — the announcement format was SOFuN-shaped. *Addressed.*** §4.3 now states
a generic order record — offered and demanded halves, a pair id, and a
`derivation` field that is empty in the general case and carries the grid for
SOFuN. What remains is encoding detail, in §10.

**C6 — `Y > X` is assumed in places.** SOFuN's premium makes the demanded side
worth more than the offered side, and several arguments lean on it quietly. A
general swap has no ordering between the two sides at all; they need not even be
the same asset. Any reasoning that leans on the premium must be marked as
SOFuN's.

**C7 — §4.1's "no lower bound" argument assumes a preference ordering.** It
holds because a smaller `D` is better for the proposer and worse for the
accepter, so nothing needs enforcing. A general admissible set has no such
ordering — the accepter picks by their own preference, not along an axis the
proposer can reason about. Nothing may depend on the accepter choosing the
"smallest" member.

**C8 — §7.1 gets worse, not better.** Two orders demanding an identical output
can be filled by one output, and generalization makes that *natural* rather than
a wallet bug: "pay me 10 NPT to this address" is exactly what a market maker
posts a hundred times. Fresh `sender_randomness*` per order remains the fix, but
in the general setting it protects against the common case rather than a corner
one. Treat it as a primitive-level invariant, not a SOFuN wallet rule.

### 9.4 Naming

If the general primitive is the goal it should have its own name, with SOFuN as
an instance of it — *"a standing swap order whose demanded UTXO is time-locked
native currency"*. Deciding that now is cheap; deciding it after the module
names are set is not.

---

## 10. Open questions

- [ ] **Announcement encoding.** Which `flag` constant, how versions are
  numbered, how `pair_id` is truncated, and how `coins` and `derivation` are
  serialized. Its own framing, not the address-notification one — a swap order
  is not addressed to anybody (§4.3).
- [ ] **Pair identity.** Is `(type script hashes, type script hashes)` the right
  notion of a pair, or should `pair_id` also commit to something in the coins'
  `state`? Two `NativeCurrency` amounts are the same asset; two distinct future
  token types sharing a type script would not be.
- [ ] **Lock script selector encoding.** How is the path selector supplied, and
  write down explicitly why a malicious prover choosing the branch is harmless
  (both branches are hard).
- [ ] **Grid arithmetic in the lock script.** `Timestamp` is a single
  `BFieldElement` of milliseconds. Confirm `D₀ + k·G` and the `k < K` range check
  are sound over the field with no wraparound reachable by a malicious `k` —
  this is the one place path (b) does arithmetic, so it is the one place an
  overflow would let an accepter name a `D` the proposer never offered.
- [ ] **Default `G` and `K`.** `G` trades the proposer's extra waiting time (up to
  one step) against watch-set size (`K = shelf life / G`). A week gives 26
  candidates for six months of shelf life. Is that the right default, and should
  `K` be capped so a proposer cannot build an unbounded watch set for their own
  wallet?
- [ ] **Watch-set mechanism.** `ExpectedUtxo` is one row per addition record.
  Is `K` rows per order acceptable, or does the wallet want a lighter-weight
  "candidate addition records" index that materializes an `ExpectedUtxo` only on
  a hit?
- [ ] **How a composer executes a fill.** A fill needs an input placed into the
  coinbase transaction (§6.1) and nothing today permits that. What is the
  narrowest mechanism that would, and what must it validate? Out of scope here,
  but the protocol is not usable without an answer.
- [ ] **Limits on redirection.** What ceiling on `Y` per block should a composer
  impose, and where does that policy live?
- [ ] **Indexing.** Does the order index live in the node or in whatever
  consumes it? Node-side avoids every consumer reimplementing reorg handling.
- [ ] **Composer selection policy.** Greedy by `Y/X`, subject to the free-regime
  filter (§6.3) and to total `Y` not exceeding the mandatory-locked half. Where
  does block space enter?
- [ ] **Interaction with `guesser_fee_fraction`.** The mandatory locked half is
  computed against the full subsidy; how much room is actually redirectable when
  the guesser fraction is high?
- [ ] **Fee.** Does the proposer's order need to carry a fee subsidy to be
  attractive at the margin, or is `X` itself sufficient compensation?

---

## 11. Progress

### Phase 0 — design
- [x] Core mechanism sketched
- [x] Confirmed no consensus changes needed
- [x] Economics: composer-only rationality argument
- [x] Discovery problem identified; design space enumerated (§2)
- [x] All code-referenced claims verified against the tree at `28ff10f86`
- [x] Existing `set_coinbase_distribution` latch found; §9.4 narrowed to inputs
- [x] Generalization goal recorded (§1.5) and audited against (§9)
- [ ] C1–C8 dispositioned: fixed, deferred, or accepted
- [ ] Name chosen for the general primitive (§9.4)
- [ ] Partial fills decided deliberately for the general case (§9.3, C3)
- [x] Grid chosen over fixed `D` and over an enforced payout announcement
- [ ] Remaining open questions in §10 resolved
- [ ] Design reviewed by a second pair of eyes

### Phase 1 — lock script
- [ ] Two-path lock script implemented
- [ ] Unit tests: path (a) accepts proposer, rejects others
- [ ] Unit tests: path (b) accepts iff `AR(D₀ + k·G)` ∈ outputs
- [ ] Unit tests: path (b) accepts every `k < K`, rejects `k >= K`
- [ ] Negative test: field-overflow attempt on `D₀ + k·G` (§10)
- [ ] Negative test: reward output present but with wrong `Y` or wrong reward
      lock script hash
- [ ] Negative test for §7.1 — one output, two orders
- [ ] `K = 1` degenerate case behaves as a fixed-`D` order
- [ ] Proving cost measured as a function of output-list length

### Phase 2 — announcement and discovery
- [ ] `AnnouncementFlag` value allocated
- [ ] Announcement encode/decode plus round-trip proptest
- [ ] Order-announcement / lock-script consistency check (§7.5) as a library
      function, usable by the accepter and by any validator of a fill
- [ ] Order index: build, query, reorg handling
- [ ] Index reorg test

### Phase 3 — proposer side (wallet / `neptune-cli`)
- [ ] Wallet API to place an order
- [ ] Fresh-randomness-per-order enforced and tested (§7.1)
- [ ] `K` candidate addition records computed and added to the watch set
- [ ] Watch-set hit recovers `k`, materializes the `ExpectedUtxo`, claims it
- [ ] Watch set restored on reorg (§7.3)
- [ ] Cancel path
- [ ] CLI / RPC surface

### Phase 4 — release
- [ ] User guide under `docs/src/user-guides/`
- [ ] Privacy warning in user-facing docs (§8)
- [ ] Mainnet-readiness review
