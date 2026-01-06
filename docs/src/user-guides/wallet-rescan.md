# Rescanning Historical Blocks

When a new block is received, it is automatically checked for UTXOs that affect the balance. But in some circumstances, historical blocks may have to be rescanned for balance-affecting UTXOs. This can be required either because of data corruption in the wallet's database, or because an already-processed block contained a UTXO to an address managed by the wallet but the address was not registered when the block was originally parsed.

For full rescanning functionality, the client must be started with the `--utxo-index` CLI flag. With this flag set, all transaction inputs (spending of UTXOs) are registered with a digest (40 bytes), and all announcements are registered with two b-field elements (a total of 16 bytes). So maintaining this UTXO index adds a bit to the size of the databases managed by the client.

To rescan historical UTXOs, four CLI commands are provided:
- `neptune-cli rescan-announced <first> <last>` to rescan the specified range of blocks for UTXOs with associated announcements for any key registered to the wallet. This command requires the client to be started with the `--utxo-index` flag set.
- `neptune-cli rescan-expected <first> <last>` to rescan the specified range of blocks for UTXOs matching expected incoming UTXOs. This command works on all clients, regardless of whether the `--utxo-index` is set.
- `neptune-cli rescan-outgoing <first> <last>` to rescan the specified range of blocks for spent UTXOs. This can be useful if a precise wallet history needs to be constructed. This command requires the client to be started with the `--utxo-index` flag set.
- neptune-cli `rescan-guesser-rewards <first> <last>` to rescan the specified range of blocks for blocks that were guessed by the client. This command works on all clients, regardless of whether the `--utxo-index` is set.
