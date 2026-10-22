# Utxo Notification

When a sender creates a payment it is necessary to transfer some secrets to the recipient in order for the recipient to identify and claim the payment.

The secrets consist of a `Utxo` and a `Digest` that represents a random value created by the sender called `sender_randomness`.

It does not matter *how* these secrets are transferred between sender and receiver so long as it is done in a secure, private fashion.

There are two broad possibilities:
1. write the secrets to the blockchain, encrypted to the recipient
2. do not write secrets to the blockchain. Use some out-of-band method instead.

`neptune-core` supports both of these.  They are referred to as notification methods.  An enum `UtxoNotificationMethod` exists and provides variants `OnChain`, `OffChain`, and `None` (no notification intended). Where only the medium matters, the simpler enum `UtxoNotificationMedium` with variants `OnChain` and `OffChain` is used.

It is also important to recognize that sometimes the sender and receiver may be the same wallet or two wallets owned by the same person or organization.

## On-Chain Utxo Notifications

`OnChain` transfers are performed with the struct `Announcement`.  It is an opaque list of elements of type `BFieldElement` (its `message` field) that can hold arbitrary data.  A list of `Announcement`s is attached to each Neptune `Transaction` and stored on the blockchain.

The Neptune key types use `Announcement`s follows:
 - element `0`: `key_type` identifies which kind of secret spending key or public receiving address this announcement is for;
 - element `1`: `receiver_id` identifies the recipient's receiving address
 - elements `2..`: a ciphertext, decryptable only by the recipient's secret key, that holds `Utxo` and `sender_randomness`, which are necessary pieces of data to claim and spend the UTXO.

The first two elements are plaintext, so anyone can read them.

As of v0.2.1, all payments create on-chain notifications for the recipients by default. In order to avoid producing on-chain notifications, you must manually configure your client. While this default has drawbacks in terms of privacy, it has the benefit that all UTXOs can be recovered with not too much work from the wallet's secret seed.

### Identifying `Utxo` destined for our wallet

#### Illustrating the challenge.

Given that the notification secrets are encrypted there exists a problem.  How can a wallet identify which `Announcement` are intended for it?

The simplest and most obvious solution is to attempt to decrypt the ciphertext of each.  If the encryption succeeds then we can proceed with claiming the `Utxo`.  While this works it is very inefficient.  Each block may contain thousands of `Announcement`.  Further our wallet may have hundreds or even thousands of keys that must be checked against each announcement, making this an `n*m` operation.  While it may be feasible for a node to do this if it is online all the time it becomes very expensive to scan the entire blockchain as may be necessary when restoring an old wallet from a seed.

We can do better.

#### How `neptune-core` solves it.

This is where the `key-type` and `receiver_identifier` of the `Announcement` come into play.

Since these fields are plaintext we can use them to identify notifications intended for our wallet prior to attempting decryption.

Each `SpendingKey` has a `receiver_identifier` field that is derived from the secret-key.  This uniquely identifies the key without giving away the secret.  As such, it can be shared in the announcement.

The algorithm looks like:

```
index all known keys in our wallet by receiver_id
for each announcement in the block-transaction:
    look up the keys with receiver_id == announcement.receiver_id
    for each such key (almost always exactly one):
        filter by key-type
        filter by key.decrypt(announcement.ciphertext) result
```

The naive approach would loop over all known keys and, for each key, over all announcements, comparing receiver identifiers; these nested loops take time `O(keys × announcements)`. Building the index costs one pass over the keys, and each announcement then needs only a single lookup, so the algorithm above runs in time `O(keys + announcements)`.

#### Privacy warning

It is important to note that this scheme makes it possible to link together multiple payments that are made to the same key.  This mainly affects `Generation` keys as the address (public-key) is intended to be shared with 3rd parties and it is not possible to prevent 3rd parties from making multiple payments to the same address.

Wallet owners can mitigate this risk somewhat by generating a unique receiving address for each payment and avoid posting it in a public place.  Of course this is not feasible for some use-cases, eg posting an address in a forum for purpose of accepting donations.

Addressing this privacy concern is on the roadmap but not the highest priority.


## OffChain Utxo Notifications

Many types of OffChain transfers are possible.  examples:

1. Local state (never leaves source machine/wallet).

2. Neptune p2p network

3. External / Serialized  (proposed)

In the future `neptune-core` or a 3rd party wallet might support using a
decentralized storage mechanism such as IPFS.  Decentralized storage may provide a solution for ongoing wallet backups or primary wallet storage to minimize risk of funds loss, as discussed below.

### Warning! Risk of funds loss

It is important to recognize that all `OffChain` methods carry an extra risk of losing funds as compared to `OnChain` notification.  Since the secrets do not exist anywhere on the blockchain they can never be restored by the wallet if lost during or any time after the transfer.

For example Bob performs an off-chain utxo transfer to Sally.  Everything goes fine and Sally receives the notification and her wallet successfully identifies and validates the funds.  Six months later Sally's hard-drive crashes and she doesn't have any backup except for her seed-phrase.  She imports the seed-phrase into a new neptune-core wallet.  The wallet then scans the blockchain for `Utxo` that belong to Sally.   Unfortunately the wallet might not be able to recognize or claim the `Utxo` that she received via `OffChain` notification.

For this reason, it becomes crucial to maintain ongoing backups/redundancy of wallet data when receiving payments via OffChain notification.  And/or to ensure that the OffChain mechanism can reasonably provide data storage indefinitely into the future.

Wallet authors should have strategies in mind to help prevent funds loss for
recipients if providing off-chain send functionality.  Using decentralized cloud
storage for encrypted wallet files might be one such strategy.

With the scary stuff out of the way, let's look at some `OffChain` notification methods.

### Local state.

note: `neptune-core` already supports `OffChain` notifications via local state.

Local state transfers are useful when a wallet makes a payment to itself.
Self-payments occur for almost every transaction when a change output is
created.  Let's say that Bob has a single `Utxo` in his wallet worth 5 tokens.
Bob pays Sally 3 tokens so the 5-token `Utxo` gets split into two `Utxo` worth 3
and 2 respectively.  The 2-token `Utxo` is called the change output, and it must
be returned into Bob's wallet.

note: A wallet can send funds to itself for other reasons, but change outputs are predicted to be the most common use-case.

When a wallet is sending a `Utxo` to itself there is no strict need to announce this on
the public blockchain.  Instead the wallet can simply store a record, called an
`ExpectedUtxo` in local state (memory and disk) and once a block is mined that
contains the transaction, the wallet can recognize the `Utxo`, verify it can be
claimed, and add it to the list of wallet-owned `Utxo` called `monitored_utxos`.

Note, however, that by default change outputs *are* announced on-chain (`ChangePolicy::default()` uses on-chain notification to a `ViewingAddress` key), so that they can be recovered from the wallet's secret seed alone. Off-chain notification of change is available through `ChangePolicy::recover_to_next_unused_viewing_key_offchain()` and similar constructors; that saves blockchain space, but the change output is then lost if the wallet's local state is lost.

### Neptune p2p network

note: concept only. not yet supported in `neptune-core`.

`Utxo` secrets that are destined for 3rd party wallets can be distributed via the neptune P2P network. This would use the same p2p protocol that distributes transactions and blocks however the secrets would be stored in a separate `UtxoNotificationPool` inside each neptune-core node.

There are challenges with keeping the data around in perpetuity as this would place a great storage burden on p2p nodes. A solution outside the p2p network might be required for that.

### External / Serialized

note: steps 1–3 of this mechanism are supported by `neptune-core`; the optional step 4 is not implemented.

The idea here is that the transfer and ongoing storage takes place completely outside of `neptune-core`.

1. The sender creates a transaction with one or more `OffChain` outputs. With `neptune-cli`, this is done with

```
neptune-cli send <address> <amount> <fee> <receiver_tag> <notify_self> off-chain
```

   where the last argument selects off-chain notification for the recipient's output, and `<notify_self>` (`on-chain` or `off-chain`) does the same for the change output. For each off-chain output, `neptune-core` produces an `EncryptedUtxoNotification` containing the fields `flag` (the key type), `receiver_identifier`, and `ciphertext(utxo, sender_randomness)`.   Note that these are the same fields stored in an `Announcement` for on-chain notifications. Its standard serialization is a bech32m string. `neptune-cli` writes one utxo-transfer JSON file per off-chain output into the `utxo-transfer` directory under the data directory, and prints instructions for sender and receiver.

2. Some external process then transfers the serialized data to the intended recipient.

3. The recipient then invokes the `claim_utxo` RPC, for instance with `neptune-cli claim-utxo file <path>` or `neptune-cli claim-utxo raw <ciphertext>`, optionally with a maximum search depth for the case that the UTXO was already mined. `neptune-core` then attempts to recognize and claim it, just as if it had been found on the blockchain: on success, a new `ExpectedUtxo` is added to the wallet.

4. *(Optional; not implemented.)* The recipient could pass a flag to `claim_utxo` that would cause it to initiate a new `OnChain` payment into the recipient's wallet.  This could serve a couple purposes:
    * using `OnChain` notification minimizes future data-loss risk for recipient.
    * if the funds were sent with a symmetric-key this prevents the sender from spending (stealing) the funds later.
