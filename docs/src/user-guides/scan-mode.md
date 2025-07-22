# Scan Mode

Scan mode is a configuration option for `neptune-core` in which it tries extra hard to find and recover lost UTXOs that belong to the wallet.

## Lost UTXOs

As of v0.2.1, `neptune-core`'s default configuration generates on-chain [UTXO notifications](../neptune-core/utxo_notification.md)s for all outgoing UTXOs. On-chain notifications were already generated for *transfer UTXOs* as well as *change UTXOs* at launch. Other UTXO types in need of special attention are proof-upgrader fee UTXOs, composer fee UTXOs, and guesser fee UTXOs.

You might have lost UTXOs if:
 - you backed up your `wallet.dat` file or have the secret seed phrase from which it can be reconstructed **and** you lost your `incoming_randomness.dat` file **and**:
   - someone sent UTXOs to you using off-chain UTXO notifications, or
   - you shared a receiving address but you were not online when the payment came in, or
   - you were composing or guessing prior to v0.2.1, or
   - you configured your client in a non-default way.

Note that if you have both `wallet.dat` and `incoming_randomness.dat` then standard timed jobs run by `neptune-core` will recover all UTXOs. (This fact is only true for *archival nodes* --- nodes that store all of history --- but presently `neptune-core` only supports that mode of operation.) Conversely, if you have *neither* `incoming_randomness.dat` nor `wallet.dat` (nor its corresponding seed phrase) then "your" UTXOs are lost and unrecoverable.

## What Scan Mode Does

If scan mode is active, `neptune-core` will execute an extra step whenever a new block is received. In this context, "new" means a block it sees for the first time, including blocks received in the course of syncing that are new for it but concretely old. Phrased differently, this extra step will not be re-executed on blocks that were already received. Consequently, if you want to run the scan mode step again on the same sequence of blocks, you need to engineer their receipt a second time, for instance by deleting the `blocks/` and `databases/` directories (both).

This extra scan mode step:
 - Reproduces the guesser UTXO as if your node had guessed the block.
 - Reproduces the composer UTXOs as if your node had composed the block. For the guesser fee fraction it takes whatever is set with the command-line argument (and so you had better make sure this command-line argument agrees with the argument you were using when you were composing[^1]).
 - Tries to decrypt the announcements using keys derived from *future* derivation indices, and bumps the derivation index according to any matches it finds.

Scan mode is not guaranteed to find all lost UTXOs. However, there are tunable parameters with which you can regulate the likelihood of catching lost UTXOs, exchanging speed for success probability.

## Enabling Scan Mode

There are three ways to enable scan mode[^2]. They can be used in any non-empty combination.

 1. Import the wallet. If you start `neptune-core` without any supporting state files beyond `wallet.dat` or after using `neptune-cli import-seed-phrase` (which has the same effect), `neptune-core` will infer that the wallet was imported and will automatically enter into scan mode.
 2. Set the command-line argument `--scan-blocks <range>`. The parameter `range` stipulates the range of block heights for which the scanning step will be executed. The default is all block heights. Ranges are valid in either rust or python-index formats.
 3. Set the command-line argument `--scan-keys <n>`. The parameter `n` regulates how many future keys to attempt the trial-decryption with. The default value is 25.

[^1]: An [outstanding issue](https://github.com/Neptune-Crypto/neptune-core/issues/535) proposes to infer the guesser fee fraction whenever possible. This improvement would make scanning for composer UTXOs more powerful.

[^2]: Actually, at the time of writing, scan mode is always on due to a [bug](https://github.com/Neptune-Crypto/neptune-core/issues/536). But this will be fixed soon.