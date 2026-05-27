# Keys and Addresses

`neptune-core` uses an extensible system of keys and addresses.  This is accomplished via an abstract type for each.  At present four types of keys are supported: `Generation`, `Symmetric`, `EcHybrid`, and `Secret`.

## Abstraction layer

Three `enum` are provided for working with keys and addresses:

| enum               | description                                      |
| ------------------ | ------------------------------------------------ |
| `KeyType`          | enumerates available key/address implementations |
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

An equivalent API for obtaining the next unused spending key is available in the neptune-core crate.


## Available key types

### `Generation` keys and addresses

`Generation` keys are asymmetric keys, meaning that they use public-key cryptography to separate a secret key from a public key.

They are primarily intended for sending funds to third party wallets.  They can also be used for sending funds back to the originating wallet but when used in this context they waste unnecessary space and incur unnecessary fees on the part of the transaction initiator.

`Generation` keys and addresses use the lattice-based public key encryption scheme described in Section 2.7 of [this paper](https://eprint.iacr.org/2022/1041.pdf). This choice of cryptosystem was made because of its native compatibility with the Oxfoi prime, \\(2^{64} - 2^{32} + 1\\), which is the field into which Neptune encodes all blockchain data. (It does this, in turn, because Triton VM only works over this field.) Furthermore, according to current understanding, the parameters and underlying mathematics guarantee security long into the future and, in particular, even against attacks mounted on quantum computers.

The address encodes the public key using bech32m. The human readable prefix "nolga" stands for "Neptune oxfoi lattice-based generation address". The announcement encodes a ciphertext which, when decrypted with the correct key, yields the UTXO information.

#### Naming

These are called "Generation" keys because they are designed to be
quantum-secure and it is believed/hoped that the cryptography should be
unbreakable for at least a generation and hopefully many generations.  If
correct, it would be safe to put funds in a paper or metal wallet and ignore
them for decades, perhaps until they are transferred to the original owner's
children or grand-children.

### `Secret` keys and addresses

A secret address is both a viewing key and an address. This means that anyone with knowledge of the
address can decrypt all on-chain notifications of UTXOs sent to this address.

On-chain payment notifications are aes-256-gcm encrypted with a key that can be read directly from
the address. So anyone that sees the address can decrypt all UTXO notifications for this address.

For this reason, `Secret` addresses should never be shared with more than one other party, as this
would destroy privacy.

A bad way of using `Secret` keys would be to request donations sent to a `Secret` key. If that was
done, anyone would be able to see all amounts sent to this address, as long as on-chain payment
notifications are used.

`Secret` addresses are the shortest standard address format.

### `EcHybrid` keys and addresses

Elliptic curve hybrid keys are implemented with aes-256-gcm and EC Diffie-Hellman key exchange.

Like `Secret` addresses, ``EcHybrid` addresses should only be shared between two parties. For an
adversary in possession of a strong enough quantum computer, the address becomes a viewing key if it
is known to the attacker. In other words: knowledge of an address and possession of a powerful
quantum computer allows for the decryption of all on-chain payment notifications sent to an
`EcHybrid` address.

`EcHybrid` addresses offer post-quantum theft-prevention but confidentiality only against classical
adversaries, i.e. adversaries that do *not* possess a powerful quantum computer.

Like `Generation` addresses, EC hybrid addresses are post-quantum secure if used correctly. However,
unlike `Generation` addresses they stop being post-quantum secure if the address is published, or
shared between more parties than merely the sender and the receiver. In other words, an attacker that
possesses a quantum computer *and* knows an `EcHybrid` address can read the UTXO notifications for
that specific specific address and thus decrypt all amounts and UTXOs that were announced on-chain
for this address. This attacker still cannot steal funds from the address.

Concretely the AES key used for the encryption of the notification payload is the XOR of a value that
can be read from the address and a value chosen by the sender. This value chosen by the sender is then
shared with the receiver through an elliptic curve Diffie-Hellman key exchange protocol where the
public key in the exchange protocol is read from the address.

The selling point for `EcHybrid` addresses over `Generation` addresses is that `EcHybrid` addresses
are much shorter.

Their advantage over `Secret` addresses is that they require a quantum computer to deanonymize.


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
