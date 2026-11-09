# The defi wallet, `neptune-defi-wallet`

Status: design, nothing implemented.
Last updated: 2026-11-09.

---

## 1. What it is

`neptune-defi-wallet` is a daemon that runs alongside `neptune-core`, as a
plugin of `neptune-defi`. It holds Neptune's native currency, NPT, and the
coins of smart contracts written for `neptune-defi`, such as vaulted NPT (vNPT)
or any other defi token. It follows the chain through `neptune-defi` as every
plugin does, builds its own transactions, proves them as far as a proof
collection, and submits them to `neptune-core` over JSON-RPC.

It reads `neptune-core` through namespaces that a node does not expose to the
internet: the UTXO index, and the unrestricted limits of `--unsafe-rpc`
(§3.3, §3.6). So it runs on the same host as `neptune-core`. It holds no user
interface of its own: graphical wallets talk to it over a JSON-RPC interface
of the kind through which they talk to `neptune-core` today (§6).

Its seed is a phrase of 18 or of 24 BIP-39 words, and it is defined by two
requirements, one for each length.

1. **Backward compatibility, for 18 words.** The wallet's seed is
   `neptune-core`'s, and every key of a type that `neptune-core` knows equals
   `neptune-core`'s key of that type and index. So the phrase unlocks in this
   wallet every UTXO that it unlocks in `neptune-core`'s built-in wallet and
   that can be recovered from the phrase. UTXOs notified off-chain cannot be, by
   either wallet; this wallet imports their randomness from `neptune-core`
   (§3.1).
2. **Industry standards, for 24 words.** The keys follow BIP-39, BIP-32,
   BIP-44 and SLIP-44 as closely as Neptune's keys allow (§2.2).

`neptune-core` knows nothing of this wallet, and its own wallet keeps working
unchanged. With an 18-word phrase the two wallets hold the same keys, so
running both duplicates the per-block scanning, and both can spend the same
UTXOs: a transaction of one wallet can spend a UTXO that the other is spending
too, and then only one of the two is confirmed. `neptune-core`'s wallet refuses
a UTXO with a type script it does not know, so a vNPT UTXO under a shared key
belongs to this wallet alone.

The wallet itself knows NPT and nothing of any smart contract. Every contract
plugs into it over the same JSON-RPC interface (§4): `neptune-sofun`, which
holds the vaults that issue vNPT as well as SOFuN's orders, and the token
contracts of third parties.

### 1.1 Terms

- **`neptune-defi`** runs `neptune-core`, relays its notifications of blocks,
  transactions and proposals, and serves *plugins*: separate processes that
  connect to it over a TCP socket on 127.0.0.1, authenticate with a cookie
  that only the user can read, and open with a *handshake*, their first message.
- **The driver** is the part of `neptune-defi`'s library that a plugin runs to
  follow the chain. It fetches every block that `neptune-core` reports, hands
  it to the plugin, and rolls the plugin back on a reorganization.
- **The mutator set** is Neptune's accumulator of UTXOs. A transaction's output
  is an *addition record*, a commitment to the UTXO's hash (its *item*), a
  *sender randomness* and a *receiver digest*, the hash of a *receiver
  preimage* that the owner keeps. Addition records are appended to the AOCL,
  and an output's position there is its *AOCL leaf index*. Spending a UTXO
  publishes a *removal record*, which contains the UTXO's *absolute index
  set*, a function of its item, both randomnesses and its leaf index. A
  *membership proof* shows that a UTXO is in the set and unspent.
- **A transaction's backing** is one of three. A *primitive witness* holds
  every secret of the transaction and never leaves its creator. A *proof
  collection* holds four fixed proofs (removal-records integrity, which is the
  expensive one, the collection of lock scripts, kernel to outputs, and the
  collection of type scripts), one proof per input's lock script and one per
  type script; it is cheap to make but cannot be mined, nor updated to a new
  mutator set. A *single proof*
  can be mined and can be updated to a new mutator set. *Raising* turns a proof
  collection into a single proof, which takes far more memory and time. An
  *upgrader* is a node that raises other people's transactions and takes part
  of their fee, the *gobbling fee*, in return. *Merging* combines two
  transactions backed by single proofs into one.
- **A vault** is a UTXO that holds NPT under the vault type script, which
  anyone may spend on that script's terms. **vNPT** is the token of
  `Vault(NativeCurrency, Bearer)`: depositing NPT into a vault mints as much
  vNPT, and any holder of vNPT may withdraw as much NPT from any vault by
  burning it. Every vault is announced on chain. `sofun-design.md` describes
  both in its section "Vaults, and vaulted NPT".
- **SOFuN**, Standing Orders for Future Neptune (`sofun-design.md`), lets the
  composer of a block fill an order that offers vNPT for the composer's
  time-locked reward. A *fill* pays the composer liquid NPT and the order's
  vNPT.

## 2. Keys

The *phrase* is the mnemonic of BIP-39 words that the wallet takes as input.
The *`SecretKeyMaterial`* is `neptune-core`'s secret, which `wallet.dat` stores
and an 18-word phrase encodes. The *BIP-39 seed* is the 64 bytes that BIP-39
computes from a phrase's text and a passphrase (§2.2).

The *seed manager* holds the wallet's *entropy* and derives every key from it.
For an 18-word phrase the entropy is a `WalletEntropy` (§2.1); for a 24-word
phrase it is the account entropy of the standard derivation (§2.2). Write `H`
for `Tip5::hash_varlen`, `e` for the encoding of the entropy as a sequence of
base-field elements, and `flag_t` for the flag of key type `t`. The key of type
`t` at index `i` is built by that type's constructor
(`GenerationSpendingKey::derive_from_seed`, `SymmetricKey::from_seed`,
`EcHybridKey::from_seed`, `ViewingAddressKey::from_seed`) from the *key seed*

- `H(e ‖ flag_t ‖ i)` for generation and symmetric keys;
- `H(encode(m_t) ‖ flag_t ‖ i)` with the master key `m_t = H(e ‖ flag_t)` for
  elliptic-curve hybrid and viewing keys.

These are `WalletEntropy`'s formulas. The key types that `neptune-core` does not
know, the SOFuN order key and the hardware wallet's signature key (§2.5) among
them, take flags of their own and the same formulas. The seed manager lives in
`neptune-defi`; `WalletEntropy` is not changed. Every key type exists at every
index for either entropy, and the scanning and spending code of §3 and §5,
which takes keys and not entropy, runs on either.

### 2.1 Eighteen words: `neptune-core`'s seed

`neptune-core`'s phrase is 18 BIP-39 words, the length BIP-39 gives to 192 bits
of entropy. `neptune-core` uses 192 bits because its secret is an
`XFieldElement`, three base-field elements of 64 bits each:
`SecretKeyMaterial::from_phrase` reads the entropy as three little-endian
`u64`s, the phrase's *limbs*, and reduces each modulo `p = 2^64 − 2^32 + 1`.
The result is the `SecretKeyMaterial` of a `WalletEntropy`
(`neptune-wallet/src/wallet_entropy.rs`). The key types of the built-in wallet
are generation, symmetric, elliptic-curve hybrid and viewing keys. No
passphrase enters, and no BIP-32 or SLIP-44 derivation.

For these key types the seed manager calls `WalletEntropy`'s own functions, so
compatibility holds by construction and not by a second implementation. For the
others it applies the formulas above to the `SecretKeyMaterial`'s encoding.

Generation key 0 receives `neptune-core`'s composer and guesser rewards, which
is why §3.1 recovers those rewards for an 18-word phrase only.

**An 18-word phrase takes no passphrase,** as in `neptune-core`, so that it
alone restores everything.

**An 18-word phrase comes from `wallet.dat` only.** The wallet reads the
`SecretKeyMaterial` from `neptune-core`'s `wallet.dat` directly. No RPC hands
out the phrase. `neptune-defi` runs `neptune-core`, which creates a random
`wallet.dat` when there is none, so a `wallet.dat` always exists, and a second
source of the 18-word phrase could only disagree with it and leave the two
wallets holding different keys. So the wallet refuses an 18-word phrase typed
in, and names `neptune-cli import-seed-phrase`, which a user restoring an
18-word phrase runs before `neptune-core`'s first start.

**The wallet takes no Shamir shares.** A user who split an 18-word phrase with
`neptune-core`'s Shamir secret sharing (`neptune-cli shamir-share`) recombines
the shares with `neptune-cli shamir-combine`, which writes `wallet.dat` and
refuses if one exists, before `neptune-core`'s first start. A share is
itself a valid 18-word phrase, so a share imported in its place opens an empty
wallet;
the wallet warns when its first scan of a new phrase, from the birthday to the
tip, finds no UTXO.

### 2.2 Twenty-four words: the standard derivation

The standard derivation follows a BIP-44 path, whose coin type is Neptune's
entry in the SLIP-44 registry (§2.4). Fix a passphrase `pw`, optional and by
default empty (§2.5), and an account number `a`, 0 by default. The *account
entropy* of `a` is computed in four steps.

1. `seed = PBKDF2-HMAC-SHA512(phrase, "mnemonic" ‖ pw, 2048 rounds, 64 bytes)`,
   the BIP-39 seed. A phrase typed in is first lowercased and its words joined
   by single spaces; then the phrase and `pw` are normalized to NFKD, as BIP-39
   requires, so a passphrase with non-ASCII characters gives the seed a
   hardware wallet gives.
2. `(k_0, c_0)` is `HMAC-SHA512("Bitcoin seed", seed)`, split into two halves
   of 32 bytes, BIP-32's master key and chain code.
3. For each index `j` of the path `44' / C' / a' / 0' / 0'`, where `C` is the
   coin type and `'` marks a hardened index, BIP-32's hardened child of
   `(k, c)`: `I = HMAC-SHA512(c, 0x00 ‖ ser256(k) ‖ ser32(j + 2^31))`, split
   into halves `IL` and `IR`, and the child is `(parse256(IL) + k mod n, IR)`,
   with `n` the order of secp256k1. If `parse256(IL) ≥ n` or the child key is
   0, which happens with probability below 2^-127, the wallet reports an error.
4. With `k` the last child key, let `b_0 … b_31` be the bytes of `ser256(k)`,
   and `l_m` the little-endian `u32` of `b_{4m} … b_{4m+3}`, for `m` from 0
   to 7. The account entropy is `Tip5::hash_varlen(l_0, …, l_7)`, a `Digest`
   of five base-field elements.

The seed manager derives the account's keys from the account entropy by the
formulas of §2. Every account is a complete Neptune wallet.

The wallet uses account 0 only. The account number stays in the path, and the
wallet's state is kept per account (§3.5), so that further accounts can be
added later without changing what exists: they would add discovery, scanning
account `a + 1` once account `a` has a history, and an account option to the
client's commands. UTXOs sent meanwhile to another account are announced on
chain, so a rescan finds them once accounts are added.

The account entropy is a `Digest` and not a `SecretKeyMaterial` so that it
keeps the phrase's entropy: a `SecretKeyMaterial` holds about 192 bits, and a
24-word phrase carries 256 (§2.5).

**SLIP-44 fixes only the coin type.** It is a registry of the constants that
fill the second component of a BIP-44 path, and says nothing about how a child
is derived. BIP-32 does, over secp256k1: a hardened child key is
`parse256(IL) + k mod n`, which needs the group order but no point, and a
non-hardened child needs the parent's public point.

**BIP-32 derives secrets and nothing else.** Every index is hardened, and the
only output is the last child key, which step 4 hashes into the account
entropy. No secp256k1 public key is computed, and no key of the wallet is a
secp256k1 key; the curve enters only through the addition modulo `n`.
Neptune's keys are lattice-KEM, symmetric and hybrid keys, so no public
derivation could serve them anyway; a watch-only wallet uses viewing keys
instead. SLIP-10's rules for ed25519 would avoid even the addition, by taking
the child key to be `IL` itself. BIP-32 is chosen for its published test
vectors and its audited implementations, against which steps 1 to 3 can be
checked; no outside tool computes step 4.

**The last two components are `0'`, hardened, unlike BIP-44.** In BIP-44 they
select the change chain and the address index, and are not hardened. Here the
account's own derivation selects keys by type and index, so both are fixed at
0, and hardened so that no public derivation is ever needed.

**A 24-word phrase takes an optional passphrase**, as BIP-39 allows and as
hardware wallets offer. The keys depend on the passphrase, so a wallet with one
asks for it at every start; it never stores the passphrase. Every string is a
valid passphrase and gives a valid BIP-39 seed, and nothing in the phrase
records which one was used, so a mistyped passphrase would silently open empty
accounts. The wallet's key file (§3.5) prevents that: it is encrypted under the
passphrase, so a wrong passphrase fails to decrypt it and is refused. When the
phrase is first entered, the wallet asks for the passphrase twice. A 24-word
phrase comes from the user.

### 2.3 Which keys it hands out

The wallet hands out generation addresses to receive payments from others, and
pays change to viewing-address keys, as `neptune-core` does; it never hands out
a symmetric key. With an 18-word phrase these are `neptune-core`'s keys too,
and each wallet advances its own index, so the two wallets can hand out the
same address. A payment to it reaches both wallets, and is spendable by both;
what it costs is that two payers of one address are linked on chain.

### 2.4 The coin type

Neptune has no entry yet in the SLIP-44 registry
(`satoshilabs/slips/slip-0044.md`). Coin type 1031 is requested in the
registry's [PR #2064](https://github.com/satoshilabs/slips/pull/2064), which is
open, and appears unassigned. The registry adds a coin type once a wallet
implements BIP-44 for the coin. This wallet uses BIP-44's path with its last
two components hardened (§2.2), and the registration says so. So `C` is 1031,
defined in one place, and is frozen at the coin type the registry assigns,
before any release.

### 2.5 Phrase lengths

The wallet accepts a phrase of 18 or of 24 BIP-39 words.

- A **24-word phrase** is the standard one. It has the standard derivation
  and an optional passphrase (§2.2). Its 256 bits of entropy fit no
  `SecretKeyMaterial`, so no `neptune-core` wallet has it.
- An **18-word phrase** exists for legacy use. It is the phrase of a
  `neptune-core` wallet, its entropy is that wallet's `WalletEntropy` (§2.1),
  and requirement 1 holds for it.

The 24-word phrase follows BIP-39, BIP-32, BIP-44 and SLIP-44 as closely as
Neptune's keys allow, so that a hardware wallet that knows Neptune can derive
its keys under coin type `C` from the same seed from which it derives BTC, ETH
and other coins. Every step of §2.2 is specified to the byte for that reason.

A hardware wallet spends without releasing a secret. Its key's lock script
takes as secret input a signature, possibly Falcon, on the transaction kernel's
MAST hash, which is the lock script's public input, under a public key that the
lock script's hash commits to. The hardware wallet signs the kernel's MAST
hash; the software wallet proves the lock script, so the proof shows knowledge
of a valid signature, not of a preimage. The host that proves learns the
signature, which authorizes this transaction only, and no key. This takes a key
type and lock script of the defi wallet's own, which the seed manager (§2)
derives as one more key type. They live in `neptune-defi`; `neptune-core`
neither knows nor needs them, since a lock script's proof names the script only
by its hash.

The wallet says of a 24-word phrase, when it is entered, that `neptune-core`
cannot open it. It refuses a typed 18-word phrase (§2.1) and every other
length. A 12-word phrase carries 128 bits, which Grover's algorithm searches in
about 2^64 steps.

A 24-word phrase is the one most holders of other coins already have, and the
one SLIP-44 serves: with it, an existing phrase holds Neptune's defi coins under
coin type `C` next to its other coins. Entering such a phrase into this wallet,
which is software, exposes every coin under it, on every chain, to whatever can
read this wallet's memory and files; a phrase that guards coins on a hardware
wallet is safer left there. And a 24-word phrase carries 256 bits, the usual
width for 128 bits of security against a quantum computer; 192 bits give about
96.

## 3. What the wallet tracks

### 3.1 UTXOs it can spend

The wallet finds the UTXOs that `neptune-core`'s wallet finds when it recovers
from a phrase:

- UTXOs announced on chain to a key whose index is at most the highest index
  at which a UTXO has been found, plus a look-ahead of future keys
  (`ScanModeConfiguration::num_future_keys`, 25 by default);
- for an 18-word phrase, the guesser-fee UTXOs of blocks that `neptune-core`
  guessed;
- for an 18-word phrase, the composer-reward UTXOs of blocks that
  `neptune-core` composed, which carry no notification and are found by
  computing them again from the guesser fraction the composer used
  (`ScanModeConfiguration::maybe_guesser_fraction`).

The last two need what the driver's `ObservedBlock` does not carry today: the
block's height, its `was_guessed_by` field, and the guesser's outputs with their
AOCL leaf indices. `ObservedBlock` gains these fields; the driver already
fetches the whole block, and the fields are added, so other plugins are
unaffected. The guesser fraction is the wallet's `--guesser-fraction` option
(§6), as it is in `neptune-core`'s recovery.

This logic lives in `neptune-core`'s `wallet_state.rs`. The library of
`neptune-defi` depends on no part of the node, so the logic moves to
`neptune-wallet`, unchanged in behaviour, and both wallets call it there.

UTXOs notified off-chain cannot be recovered from a phrase by either wallet.
`neptune-core` keeps their randomness in `incoming_randomness.dat`; this wallet
imports that file on request.

The wallet accepts a UTXO whose coins are NPT, `NativeCurrency` and
`TimeLock`, or of a type script that a plugged-in contract registered (§3.4).

### 3.2 Spends

A UTXO is spent when a block's removal records contain its absolute index set.
The driver reports every block's removal records, so the wallet checks each
tracked UTXO against them, as the SOFuN order book does for orders.

### 3.3 Membership proofs

The wallet stores, for each UTXO, its AOCL leaf index, its item, its sender
randomness and its receiver preimage, and no membership proof. When it spends
the UTXO, it computes the UTXO's absolute index set from these and restores the
membership proof with `wallet_restoreMembershipProof`, as the SOFuN plugin does
for an order. So a block costs the wallet a scan and no proof updates.
`wallet_restoreMembershipProof` reads `neptune-core`'s archival mutator set,
so spending requires an archival node, and catching up a node with the UTXO
index (§3.6). One request restores at most 256
membership proofs over the restricted RPC and at most 1,000 over the
unrestricted one, so the wallet batches its requests by that limit.

### 3.4 Coins of plugged-in contracts

A contract that plugs into the wallet (§4) registers its type scripts. The
wallet then tracks UTXOs under its own keys that carry their coins as it tracks
NPT: it finds them, notices when they are spent, and spends them. What the
coins mean is the contract's. A UTXO that carries a coin of no registered type
script is kept and reported, not spent, so that registering its contract later
makes it spendable without a rescan.

### 3.5 State

The wallet persists its UTXOs, the highest index at which a UTXO
has been found, its unconfirmed transactions, and the block it has applied, in
its own directory under `neptune-defi`'s data directory, per network. It
finds `wallet.dat` in `neptune-core`'s data directory for the same network
(`DataDirectory::wallet_directory_path`). UTXOs and indices are kept per
account and key type, an 18-word phrase having one account, so that adding
accounts (§2.2) needs no migration.

An 18-word phrase is read from `wallet.dat` at every start (§2.1). A 24-word
phrase is not stored. The wallet stores instead the BIP-32 node `m/44'/C'`, the
coin type's key and chain code, computed by steps 1 to 3 of §2.2 when the
phrase is entered; every account is a hardened child of it. A 24-word phrase
usually guards coins on other chains too, and hardened derivation cannot be
reversed, so a stolen file exposes Neptune's coins and no others. The wallet
therefore cannot show the phrase again; the user's written copy is the backup.

The node is kept in the *key file*, a file of its own in the wallet's
directory, never in `wallet.dat`, readable only by the user, as `wallet.dat`
is. Without a passphrase, the key file holds the node in plaintext. With one,
it holds the node encrypted with AES-256-GCM under a key derived from the
passphrase and a random 16-byte salt by PBKDF2-HMAC-SHA512 with 210,000
rounds. This key
derivation takes the passphrase alone; it is separate from the BIP-39 seed's,
which salts with the passphrase. The file is, byte for byte:

- a version byte, 1;
- a flag byte, 0 for plaintext and 1 for encrypted;
- if encrypted, the 16-byte salt and a random 12-byte nonce;
- the node's 32-byte key followed by its 32-byte chain code, or their
  AES-256-GCM ciphertext and 16-byte tag, with the version, flag and salt
  bytes as associated data.

The phrase, the passphrase, the BIP-39 seed, every BIP-32 node, the stored
one included, and the account entropy are zeroized when dropped, as
`WalletEntropy`'s secret is.

The wallet's state rolls back with the driver on a reorganization. A wallet
created from a phrase scans from a *birthday*, a height the user gives, by
default the genesis block.

### 3.6 Catching up

The driver applies the blocks it is notified of, and remembers at most `depth`
of them, so by itself it neither scans from a birthday nor resumes after a
restart. Two additions to it do. `Driver::resume(state, applied, depth)`
restores a driver from the blocks the plugin persisted, and
`Driver::catch_up(from_height, chain)` applies the blocks of interest from
`from_height` to the tip, oldest first, and then hands over to the
notifications. `Chain` gains `blocks(heights)`, backed by `wallet_getBlocks`.
Before applying a batch, `catch_up` checks that its first block descends from
the last one applied, and otherwise rolls back as for a reorganization. The
wallet catches up from its birthday on its first start and from the block it
applied last on every later one.

As `neptune-core`'s own rescan does, catching up requires a node with the UTXO
index, run with `--utxo-index`, which implies an archival node, as spending
does (§3.3). The index tells the wallet which blocks to fetch, so it fetches
those and not every block:

- **Announced UTXOs:** `utxoindex_blockHeightsByFlags` with the flag and
  receiver id of every key in the look-ahead window (§3.1). When a UTXO found
  raises the highest index used, the keys that come into the window are
  queried in turn, until no query finds a new block.
- **Spends:** `utxoindex_blockHeightsByAbsoluteIndexSets` for the UTXOs
  tracked.
- **Guesser fees and composer rewards** carry no announcement. The wallet scans
  for them by height range, as `neptune-core`'s `rescan_guesser_rewards` does,
  when `--guesser-fraction` is set or the user asks.

The index keeps at most 10,000 heights per flag and receiver id
(`MAX_NUM_BLOCKS_IN_LOOKUP_LIST`). For a key that reached the cap, the wallet
asks a new RPC, `utxoindex_blockHeightsByFlag(flag, receiver_id, from, to)`,
with the key's flag and receiver id, and warns. The index keys announcements
by flag and receiver id, the first two elements of an announcement. The new
RPC walks the index's per-block lists of flags and receiver ids
(`AnnouncementsByBlock`) over the range and returns the heights whose list
holds the flag, and the receiver id if one is given; it has no cap. It reads
no block, changes no part of the index's schema, and needs no migration. It
also serves any protocol that announces under one flag with varying second
elements, such as vaults (§4.1).

## 4. Contracts that plug into the wallet

Every smart contract is a process of its own, as `neptune-sofun` is, that plugs
into the defi wallet over its JSON-RPC interface (§6), and may also follow the
chain as a plugin of `neptune-defi`. `neptune-sofun` is the first: it holds
vaults (§4.1) and SOFuN's orders. The token contracts of third parties plug in
the same way. The wallet holds their coins and keys and proves and submits their
transactions; the contract knows what its coins mean, and what its transactions
must contain. Placing a SOFuN order, for instance, deposits NPT for the vNPT the
order offers, and the order's key is a key type of its own, which the seed
manager derives (§2). Without a defi wallet there are no SOFuN trades.

What a contract needs from the wallet is, at least:

- keys of a key type of its own, from the seed manager;
- a way to register its type scripts, so that the wallet accepts their coins
  (§3.4);
- requests from the wallet for the witnesses of those type scripts, which the
  wallet needs to build any transaction that carries their coins (§5.1), and
  which only the contract can compute;
- the UTXOs it owns;
- transactions built from the inputs and outputs it names, to which the wallet
  adds NPT inputs, change and the fee, and which it proves and submits.

The methods that serve these are open (§9). The wallet asks a contract for
witnesses, so a coin whose contract is not running cannot be spent until it runs
again.

### 4.1 Vaults, in `neptune-sofun`

Vaults are more general than SOFuN, but SOFuN is for now their only user, so
`neptune-sofun` holds them. It holds the vault type scripts,
`Vault(NativeCurrency, Bearer)` for vNPT among them, registers them with the
wallet, and answers the wallet's requests for their witnesses with
`Vault::type_script_and_witness`. Spending vNPT therefore needs `neptune-sofun`
running (§4). Should another contract come to use vaults, they move to a
contract of their own.

Every vault is announced on chain, with its UTXO and both randomnesses, so that
anyone can spend it. `neptune-sofun` records every vault announcement of its
type scripts, and drops a vault when it is spent. It catches up with
`utxoindex_blockHeightsByFlag` (§3.6), with the vault flag and no receiver id: a
vault announcement's second element is its sender randomness, so no receiver id
finds all vaults.

A deposit outputs a new vault holding NPT and a vNPT token of as much. A
withdrawal burns vNPT and takes as much NPT from a vault. vNPT is redeemable
against any vault, so a withdrawal may spend any vault holding enough.
`neptune-sofun` chooses one at random among them, so that withdrawals made at
the same time rarely spend the same vault, of which only one could be confirmed.
It excludes the vaults that its own unconfirmed transactions spend.

A transaction spends at most one vault and creates at most one, by the vault
type script's rules. So a withdrawal of less than the chosen vault holds
outputs a new vault with the rest, announced like every vault, and a
withdrawal of more than any one vault holds takes several transactions.

## 5. Transactions

### 5.1 Building

The wallet builds a primitive witness with
`PrimitiveWitness::generate_primitive_witness_with`, whose generator returns the
witness of every registered type script that the transaction's UTXOs name by
asking the contract that registered it (§4), which computes it, for vNPT with
`Vault::type_script_and_witness`. Lock scripts are the standard ones of each key
type. Inputs are chosen among the tracked UTXOs, besides those a contract names,
such as the vault of a withdrawal (§4.1). The wallet validates the primitive
witness before proving it.

The fee is the `--fee` given to the command or, by default, the least fee that
an upgrader and a relaying node take at `neptune-core`'s default settings. An
upgrader raises a transaction only if `fee · gobbling_fraction ≥
min_gobbling_fee`, and a node relays a proof collection only if
`fee ≥ n · min_relay_pctx_fee_per_input`, where `n` is the number of inputs.
The defaults are `gobbling_fraction = 0.6`, `min_gobbling_fee = 0.01` NPT and
`min_relay_pctx_fee_per_input = 0.0005` NPT, so the default fee is
`max(0.01 / 0.6, n · 0.0005)` NPT, rounded up to a whole nau. Other nodes'
settings are not published, so the wallet cannot do better than their
defaults; a user whose transaction waits raises the fee with `--fee`. The fee
is paid from the inputs, so it enters input selection.

An upgrader raises a proof collection of at most `--max-num-proofs` proofs, 16
by default (§5.2). A proof collection holds `4 + n + s` proofs for `n` inputs
and `s` type scripts, so a transaction takes at most `16 − 4 − s` inputs: about
10 for an NPT send and 9 for a vNPT send. The wallet selects the largest UTXOs
first, up to that cap. If they do not cover the amount and the fee, it refuses
and says how much one transaction can pay; the user then runs `consolidate`,
which pays the smallest UTXOs, up to the cap, to one viewing-address key of the
wallet, as `neptune-core`'s consolidation does.

### 5.2 Proving and submitting

The wallet proves a proof collection (§1.1) with `neptune-consensus`'s
prover and submits it with `wallet_submitTransaction`. Making one takes a
fraction of the memory and time of raising. The
wallet never sends a primitive witness: it reveals the transaction's secrets.

Everything after submission is `neptune-core`'s.

- **Upgrading.** `neptune-core` admits the transaction to its mempool at
  `UpgradePriority::Critical`, as it does every transaction submitted over
  RPC, and a node run with `--tx-proof-upgrading` raises it to a single proof
  with no gobbling fee. Any other upgrader of the network raises it only if its
  gobbling fraction of the fee is at least its minimum gobbling fee (§5.1).
  An upgrader raises only proof collections of at most `--max-num-proofs`
  proofs, 16 by default, which bounds the number of inputs (§5.1). Neither the
  mempool nor the upgrader asks whether a type script is known: the single
  proof verifies each type script's proof, which names the script only by its
  hash.
- **Blocks before the upgrade.** The mempool keeps a transaction until one of
  its inputs is spent, it expires, or it is evicted because the mempool is
  full; a block arriving before the transaction is raised is none of these.
  An upgrader raises a proof collection against the transaction's own mutator
  set, read from its archival state, and then updates the single proof to the
  tip. It looks back at most 100 blocks for that mutator set
  (`SEARCH_DEPTH_FOR_BLOCKS_FOR_MS_UPDATE`), so a proof collection more than 100
  blocks behind the tip is never raised.
- **Merging.** After raising, the upgrader looks for a merge partner in the
  mempool, as for every transaction it upgrades.

The wallet checks, at every block, whether its unconfirmed transactions are
still in the mempool, with `mempool_getTransactionsByAbsoluteIndexSets`. It
resubmits one whose inputs are unspent if it left the mempool unconfirmed,
because it expired, was evicted or never reached it, or if it is 100 blocks
behind the tip. It cannot update the primitive witness to the tip, since
`PrimitiveWitness::update_with_new_ms_data` refuses type scripts it does not
know, such as vNPT's. So it builds the transaction again: it restores the
inputs' membership proofs (§3.3), generates a primitive witness as in §5.1,
proves a new proof collection and submits it.

### 5.3 What it can do

- Send NPT to any address.
- Send the coins of a registered type script, such as vNPT, to any address.
- Build, prove and submit a contract's transaction, such as a deposit into a
  vault or a withdrawal from one (§4.1).
- Consolidate small UTXOs into one (§5.1).

## 6. Interface

The wallet daemon serves a JSON-RPC interface built like `neptune-core`'s, with
`neptune-rpc`'s transport and its convention of namespaced methods, on a port of
its configuration on 127.0.0.1, authenticated by a cookie in the wallet's
directory that only the user can read, as plugins authenticate to
`neptune-defi`. Graphical wallets are its clients, as they are `neptune-core`'s
today; `neptune-defi-wallet-cli` is one more.

The methods are `balance`, `receive`, `send`, `consolidate`, `history`,
`importRandomness` and `rescan`, and those through which contracts plug in (§4).
`send` and `consolidate` take an optional fee, which overrides the default fee
(§5.1). Depositing into a vault and withdrawing from one are `neptune-sofun`'s
operations (§4.1), not the wallet's; how a graphical wallet reaches a contract's
operations is open (§9). `receive` hands out the next unused generation address,
the key type for payments from others. The daemon itself takes
`--guesser-fraction`, the fraction of a composed block's reward that the user's
composer gave the guesser, for recovering composer rewards (§3.1).

The interface hands out no phrase, passphrase or key file, as `neptune-core`'s
hands out no seed. A 24-word phrase and its passphrase are entered through the
daemon's own terminal when the wallet is created, and the passphrase at every
start (§2.2).

## 7. Plugins asking each other, and SOFuN

A fill pays the composer two things, and they go to two places.

- The composer's share of NPT goes to `neptune-core`'s wallet, through
  `personal_generateAddress`, as it does today.
- The order's vNPT is a coin of a smart contract, which `neptune-core`'s
  wallet refuses, so it goes to an address this wallet hands out.

`neptune-sofun` asks this wallet for that address, and `neptune-defi` carries
the request. A plugin names, in its handshake, the requests it answers; this
wallet answers `receivingAddress`. A plugin sends a request to a name, and
`neptune-defi` relays it to the plugin that answers it and relays the response
back, or answers that no plugin does. Every plugin authenticates to
`neptune-defi` with the cookie that only the user can read, so a request comes
from the user's own software.

The answer to `receivingAddress` is a viewing address: the composer pays
themself, and `neptune-core` pays itself, its change and consolidation outputs,
to viewing-address keys too, because symmetric keys are deprecated. The wallet
answers with the same address until a UTXO under it is confirmed, and with the
next unused one after that. `neptune-sofun` asks before every fill, so a fill
pays an address no confirmed fill has paid, and fills that are never mined
cost no key. If no plugin answers, `neptune-sofun` fills no vNPT order for
that block, and the node composes with its own coinbase transaction.

## 8. Implementation plan

Each phase ends with its tests passing and is committed separately.

1. **Move recovery into `neptune-wallet`.** Move the scanning and recovery
   functions of §3.1 from `neptune-core`'s `wallet_state.rs` to
   `neptune-wallet`, behaviour unchanged, taking keys rather than a
   `WalletEntropy` wherever they need only keys. `neptune-core`'s wallet tests
   are the check.
2. **Keys.** `neptune-defi/src/wallet/keys.rs`: the seed manager, the BIP-39
   seed through `tiny-bip39`, BIP-32 hardened derivation with `hmac`, `sha2` and
   `k256` for the addition modulo `n`, the account entropy and its keys, reading
   the phrase from `wallet.dat`, and the key file of a 24-word phrase, with
   `aes-gcm` and `pbkdf2`. `hmac` and `pbkdf2` are in the tree only through
   other crates, so they become direct dependencies of `neptune-defi`, at pinned
   versions. Tests:
   - BIP-32's published test vectors for hardened children;
   - for an 18-word phrase, every key of a type `neptune-core` knows equals
     `WalletEntropy`'s, key for key;
   - distinct accounts give disjoint keys, and so do distinct passphrases of a
     24-word phrase;
   - the formulas of §2, given the encoding of a `SecretKeyMaterial` in place
     of a `Digest`'s, return `WalletEntropy`'s keys of every type, which shows
     the formulas are the same;
   - a key type of `neptune-defi`'s own gives keys distinct from those of every
     type `neptune-core` knows, for either phrase length;
   - a passphrase with non-ASCII characters gives BIP-39's seed for its NFKD
     form, and a phrase typed with capitals or extra spaces gives the seed of
     the same phrase written plainly;
   - a typed 18-word phrase is refused with a message naming
     `import-seed-phrase`, and so is every length but 24 typed in;
   - the key file of a 24-word phrase, without a passphrase, gives the same
     accounts as the phrase; with one, it gives them with the passphrase and
     is refused with any other, and a file whose version, flag or salt was
     altered is refused;
   - account `a` derived from the stored node equals account `a` derived from
     the phrase, for `a` = 0 and 1.
3. **Scanner.** First, `ObservedBlock` gains the height, `was_guessed_by`
   and the guesser's outputs with their leaf indices; test: on a RegTest
   block, they equal the block's own. Then, given a block update and the seed
   manager's keys, the UTXOs found and the UTXOs spent. Test: on the same
   blocks and 18-word phrase, the scanner finds exactly what `neptune-core`'s
   wallet finds, on a RegTest chain with on-chain, guesser-fee and
   composer-reward UTXOs.
4. **State and catching up.** Persistence, keyed by account, the birthday, and
   rollback with the driver; `utxoindex_blockHeightsByFlag` in `neptune-core`
   and `neptune-rpc`; `Driver::resume`, `Driver::catch_up` and `Chain::blocks`
   (§3.6). Tests: a reorganization restores the earlier state; a restart resumes
   where it stopped; `utxoindex_blockHeightsByFlag` returns exactly the heights
   in its range whose blocks announce under the flag, with any second element or
   the one given; catching up from a birthday on RegTest finds exactly the
   UTXOs and spends that following the chain block by block finds; a
   reorganization during the catch-up is followed.
5. **Building.** NPT sends and consolidation. Tests: both validate as a
   primitive witness; change goes to a viewing-address key; selection takes the
   largest UTXOs up to the input cap and refuses an amount beyond them;
   `consolidate` merges the smallest UTXOs into one; the default fee passes both
   thresholds at 1 input and at the most inputs a raisable proof collection
   allows, and `--fee` overrides it.
6. **Proving and submitting.** The proof collection, `wallet_submitTransaction`,
   and rebuilding and resubmitting a transaction that left the mempool
   unconfirmed or fell 100 blocks behind. Tests, on RegTest with
   `--tx-proof-upgrading`: two NPT sends are confirmed, the second after a block
   arrived before its upgrade, without a resubmission; a transaction that
   expired from the mempool is resubmitted and confirmed.
7. **Daemon and client.** The `neptune-defi-wallet` binary on the driver, its
   JSON-RPC interface and cookie, and `neptune-defi-wallet-cli`. Tests: every
   method end to end on RegTest through the command line; a request without
   the cookie is refused.
8. **Plugging in.** The methods of §4: a contract's key type, the registration
   of its type scripts, the wallet's requests for their witnesses, its UTXOs,
   and transactions built from the inputs and outputs it names. Tests, with a
   test contract on RegTest: its coins are accepted under the wallet's keys only
   once it has registered, a UTXO carrying them before then is kept and becomes
   spendable at registration, and a transaction it names is confirmed.
9. **Vaults in `neptune-sofun`** (§4.1). Vault tracking, catching up with
   `utxoindex_blockHeightsByFlag`, the random choice of vault, deposits,
   withdrawals and vNPT sends. Tests: every kind validates as a primitive
   witness; a partial withdrawal outputs a vault with the rest; a withdrawal
   never chooses a vault that an unconfirmed transaction of its own spends;
   catching up finds exactly the vaults that following the chain finds; on
   RegTest with `--tx-proof-upgrading`, a deposit and a withdrawal are
   confirmed.
10. **Requests between plugins.** The handshake's list of requests a plugin
    answers, and `neptune-defi` relaying a request and its response. Tests: a
    request reaches the plugin that answers it and the response returns; a
    request to a name no plugin answers is refused; a plugin that disconnects
    mid-request yields an error, not a hang.
11. **SOFuN.** `neptune-sofun` asks the wallet for its address, and the SOFuN
    proposer plugs into the wallet (§4), which takes the proposer side of
    `sofun-design.md` (its progress phase 3).
12. **Coin type.** Freeze `C` at the coin type the SLIP-44 registry assigns.

## 9. Open questions

- Whether importing `incoming_randomness.dat` is enough, or whether the wallet
  should read `neptune-core`'s wallet database for UTXOs notified off-chain.
- The signature scheme of the hardware-wallet key type (§2.5), Falcon or
  another, and the cost of verifying it in Triton VM.
- The JSON-RPC methods through which contracts plug into the wallet (§4):
  their namespace, how a contract registers its type scripts, how the wallet
  asks a contract for a witness, and how a
  graphical wallet reaches a contract's operations, such as a deposit.
