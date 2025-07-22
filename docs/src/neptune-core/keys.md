# Keys and Addresses

`neptune-core` uses an extensible system of keys and addresses.  This is accomplished via an abstract type for each.  At present two types of keys are supported: `Generation` and `Symmetric`.

## Abstraction layer

Three `enum` are provided for working with keys and addresses:

| enum                   | description                                      |
|------------------------| -------------------------------------------------|
| `KeyType`              | enumerates available key/address implementations |
| `SpendingKey`      | enumerates key types and provides methods        |
| `ReceivingAddress` | enumerates address types and provides methods    |

note: It was decided to use `enum` rather than traits because the enums can be
used within our RPC layer while traits cannot.

Most public APIs use these types.  That provides flexibility and should also make it easy to add new implementations in the future if necessary.

## Root Wallet Seed

At present all supported key types are based on the same secret `seed`. The end-user can store/backup this seed using a bip39 style mnemonic.

## Key derivation

For each key-type, the neptune-core wallet keeps a counter which tracks the latest derived key.

To obtain the next unused address for a given key type call the rpc method `next_receiving_address(key_type)`.

(note: as of this writing it always returns the same address at index 0, but in the future it will work as described)

An equivalent API for obtaining the next unused spending key is available in the neptune-core crate, but is not (yet?) exposed as an rpc API.


## Available key types

`Generation` and `Symmetric` type keys are intended for different usages.

### `Generation` keys and addresses

`Generation` keys are asymmetric keys, meaning that they use public-key cryptography to separate a secret key from a public key.

They are primarily intended for sending funds to third party wallets.  They can also be used for sending funds back to the originating wallet but when used in this context they waste unnecessary space and incur unnecessary fees on the part of the transaction initiator.

`Generation` keys and addresses use the lattice-based public key encryption scheme described in Section 2.7 of [this paper](https://eprint.iacr.org/2022/1041.pdf). This choice of cryptosystem was made because of its native compatibility with the Oxfoi prime, $2^{64} - 2^{32} + 1$, which is the field into which Neptune encodes all blockchain data. (It does this, in turn, because Triton VM only works over this field.) Furthermore, according to current understanding, the parameters and underlying mathematics guarantee security long into the future and, in particular, even against attacks mounted on quantum computers.

The address encodes the public key using bech32m. The human readable prefix "nolga" stands for "Neptune oxfoi lattice-based generation address". The announcement encodes a ciphertext which, when decrypted with the correct key, yields the UTXO information.

#### Naming

These are called "Generation" keys because they are designed to be
quantum-secure and it is believed/hoped that the cryptography should be
unbreakable for at least a generation and hopefully many generations.  If
correct, it would be safe to put funds in a paper or metal wallet and ignore
them for decades, perhaps until they are transferred to the original owner's
children or grand-children.


### `Symmetric` keys and addresses

`Symmetric` keys are implemented with aes-256-gcm, a type of symmetric key,
meaning that a single key is used both for encrypting and decrypting.

Anyone holding the key can spend associated funds.  A symmetric key is equivalent to a private-key, and it has no equivalent to a public-key.

They are primarily intended for sending funds (such as change outputs) back to
the originating wallet.  However additional use-cases exist such as sending between separate wallets owned by the same person or organization.

Data encrypted with `Symmetric` keys is smaller than data encrypted with asymmetric keys such as `Generation`.  As such, it requires less blockchain space and should result in lower fees.

For this reason change output notifications are encrypted with a `Symmetric` key by default and it is desirable to do the same for all outputs destined for the
originating wallet.

Note that the `Symmetric` variant of abstract types `SpendingKey` and `ReceivingAddress` both use the same underlying `SymmetricKey`.  So they differ only in the methods available.  For this reason, it is important never to give an "address" of the `Symmetric` type to an untrusted third party, because it is also the spending key.
