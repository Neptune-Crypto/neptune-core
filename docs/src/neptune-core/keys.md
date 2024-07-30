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
used within our RPC layer while traits cannnot.

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

They are primarily intended for sending funds to third party wallets.  They can also be used for sending funds back to the originating wallet but they waste unnecessary space when the encrypted ciphertext is stored on the blockchain.

|alan todo: describe generation keys/addresses|

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