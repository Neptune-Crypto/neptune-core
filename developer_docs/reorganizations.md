# How neptune-core handles reorganizations
Neptune is a blockchain which features recursive STARK proofs as part of its
consensus mechanism. This implies that participants can synchronize trustlessly
by simply downloading the latest block and verifying this. Unlike most other
blockchains, it is not necessary to download all historical blocks to get a
cryptographically verified view of the state of the blockchain.

It is possible, though, to run an archival node that downloads all historical
blocks. This archival node comes with additional functionality such as being
able to reconstruct transaction's membership proofs, provide some historical
transaction statistics, and allow other archival nodes to synchronize.

This document provides an overview of how different parts of the client's state
handle reorganizations.

## State overview
The client's state consists of the following parts:
- wallet
- light state
- archival state (optional)
- mempool

The wallet handles transactions that the client holds the spending keys for.
The light state contains the latest block which verifies the validity of the
entire history of the blockchain. The archival state is optional and allows,
among other things, the client to re-synchronize wallets that are no longer
up-to-date. The mempool keeps track of transactions that are not yet included
in blocks, thus allowing miners to confirm transactions by picking some from
the mempool to include in the next block.

### Wallet
The wallet can handle reorganizations that are up to `n` blocks deep, where `n`
can be controlled with the CLI argument `number_of_mps_per_utxo`.
Reorganizations that are deeper than this will make the membership proofs of
the transactions temporarily invalid until they can be recovered either through
the client's own archival state (if it exists), or through a peer's archival
state. This recovery process happens automatically.

### Light State
The light state only contains the latest block and thus can handle arbitrarily
deep reorganizations.

### Archival State
The archival state can handle arbitrarily deep reorganizations.

### Mempool
The mempool can *currently* not handle reorganizations. If a reorganization
occurs, all transactions in the mempool will be deleted, and the initiator of a
transaction will have to publish the transaction again. The transactions that
were included in blocks that are abandoned through this reorganization are not
added to the mempool again, they also have to be published again.
