# Utxo Notification

When a sender creates a payment it is necessary to transfer some secrets to the recipient in order for the recipient to identify and claim the payment.

The secrets consist of a `Utxo` and a `Digest` that represents a random value created by the sender called `sender_randomness`.

It does not matter *how* these secrets are transferred between sender and receiver so long as it is done in a secure, private fashion.

There are two broad possibilities:
1. write the secrets to the blockchain, encrypted to the recipient
2. do not write secrets to the blockchain. Use some out-of-band method instead.

`neptune-core` supports both of these.  They are referred to as notification methods.  An enum `UtxoNotifyMethod` exists and provides variant `OnChain` and `OffChain`.

It is also important to recognize that sometimes the sender and receiver may be the same wallet or two wallets owned by the same person or organization.

## OnChain Utxo transfers

`OnChain` transfers are performed with the struct `PublicAnnouncement`.  It is an opaque list of fields of type `BFieldElement` that can hold arbitrary data.  A list of `PublicAnnouncement` are attached to each neptune `Transaction` and stored on the blockchain.

The neptune key types leverage `PublicAnnouncement` to store the `key_type` in the first field and a unique `receiver_id` in the second field that is derived from the receiving address.  These fields are plaintext, so anyone can read them.

The remaining fields (variable length) are filled with encrypted ciphertext that holds `Utxo` and `sender_randomness` which are necessary to claim/spend the `Utxo`.

### Identifying `Utxo` destined for our wallet

#### Illustrating the challenge.

Given that the notification secrets are encrypted there exists a problem.  How can a wallet identify which `PublicAnnouncement` are intended for it?

The simplest and most obvious solution is to attempt to decrypt the ciphertext of each.  If the encryption succeeds then we can proceed with claiming the `Utxo`.  While this works it is very inefficient.  Each block may contain thousands of `PublicAnnouncement`.  Further our wallet may have hundreds or even thousands of keys that must be checked against each announcement, making this an `n*m` operation.  While it may be feasible for a node to do this if it is online all the time it becomes very expensive to scan the entire blockchain as may be necessary when restoring an old wallet from a seed.

We can do better.

#### How `neptune-core` solves it.

This is where the `key-type` and `receiver_identifier` of the `PublicAnnouncement` come into play.

Since these fields are plaintext we can use them to identify notifications intended for our wallet prior to attempting decryption.

Each `SpendingKeyType` has a `receiver_identifier` field that is derived from the secret-key.  This uniquely identifies the key without giving away the secret.  As such, it can be shared in the public-announcement.

The algorithm looks like:

```
for each key-type we support:
    for each known key in our wallet:
        for each public-announcement in the block-transaction:
            filter by key-type
            filter by key.receiver_id
            filter by key.decrypt(announcement.ciphertext) result
```

#### Privacy warning

It is important to note that this scheme makes it possible to link together multiple payments that are made to the same key.  This mainly affects `Generation` keys as the address (public-key) is intended to be shared with 3rd parties and it is not possible to prevent 3rd parties from making multiple payments to the same address.

Wallet owners can mitigate this risk somewhat by generating a unique receiving address for each payment and avoid posting it in a public place.  Of course this is not feasible for some use-cases, eg posting an address in a forum for purpose of accepting donations.

It is planned to address this privacy concern but it may not happen until after Neptune mainnet launches.


## OffChain Utxo transfers

Many types of OffChain transfers are possible.  `neptune-core` aims to support the following types at launch:

1. Local state (never leaves source machine/wallet)

2. Neptune p2p network

3. External / Serialized  (proposed)

In the future `neptune-core` or a 3rd party wallet might support using a
decentralized storage mechanism such as IPFS.  Decentralized storage may provide a solution for ongoing wallet backups or primary wallet storage to minimize risk of funds loss, as discussed below.

### Warning! Risk of funds loss

It is important to recognize that all `OffChain` methods carry an extra risk of losing funds as compared to `OnChain` notification.  Since the secrets do not exist anywhere on the blockchain they can never be restored by the wallet if lost during or any time after the transfer.

For example Bob performs an OffChain utxo transfer to Sally.  Everything goes fine and Sally receives the notification and her wallet successfully identifies and validates the funds.  Six months later Sally's hard-drive crashes and she doesn't have any backup except for her seed-phrase.  She imports the seed-phrase into a new neptune-core wallet.  The wallet then scans the blockchain for `Utxo` that belong to Sally.   Unfortunately the wallet will not be able to recognize or claim any `Utxo` that she received via `OffChain` notification.

For this reason, it becomes crucial to maintain ongoing backups/redundancy of wallet data when receiving payments via OffChain notification.  And/or to ensure that the OffChain mechanism can reasonably provide data storage indefinitely into the future.

Wallet authors should have strategies in mind to help prevent funds loss for recipients if providing off-chain send functionality.  Using decentralized storage for encrypted wallet files might be one such strategy.

With the scary stuff out of the way, let's look at some `OffChain` notification methods.

### Local state.

Local state transfers are useful when a wallet makes a payment to itself.
Self-payments occur for almost every transaction when a change output is
created.  Let's say that Bob has a single `Utxo` in his wallet worth 5 tokens.
Bob pays Sally 3 tokens so the 5-token `Utxo` gets split into two `Utxo` worth 3
and 2 respectively.  The 2-token `Utxo` is called the change output, and it must
be returned into Bob's wallet.

note: A wallet can send funds to itself for other reasons, but change outputs are predicted to be the most common use-case.

When a wallet is sending a `Utxo` to itself there is no need to announce this on
the public blockchain.  Instead the wallet simply stores a record, called an
`ExpectedUtxo` in local state (memory and disk) and once a block is mined that
contains the transaction, the wallet can recognize the `Utxo`, verify it can be
claimed, and add it to the list of wallet-owned `Utxo` called `monitored_utxos`.

### Neptune p2p network

`Utxo` secrets that are destined for 3rd party wallets can be distributed via the neptune P2P network. This would use the same p2p protocol that distributes transactions and blocks however the secrets would be stored in a separate `UtxoNotificationPool` inside each neptune-core node.

|alan or sword-smith, please flesh this out.|

### External / Serialized

note: this is a proposed mechanism.  It does not exist at time of writing.

The idea here is that the transfer takes place completely outside of `neptune-core`.

1. When a transaction is sent `neptune-core` would provide a serialized `PublicAnnouncement` for each `OffChain` output.

2. Some external process then transfers the `PublicAnnouncement` to the intended recipient.

3. The recipient then invokes the `claim_utxos()` RPC api and passes in a list of serialized `PublicAnnouncement`.  `neptune-core` then attempts to recognize and claim each `PublicAnnouncement`, just as if it had been found on the blockchain.

4. Optionally the recipient could pass a flag to `claim_utxos()` that would cause it to initiate a new OnChain payment into the recipient's wallet.  This could serve a couple purposes:
    * using OnChain notification minimizes future data-loss risk for recipient.
    * if the funds were sent with a symmetric-key this prevents the sender from spending (stealing) the funds later.
