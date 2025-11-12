# Neptune Coins

Neptune Coins refers to two things
 - the native currency coin type for Neptune Cash;
 - the unit in which quantities of the former are measured.

In the code, the struct `NativeCurrencyAmount` defines the unit. The native currency *type script* is encapsulated as a struct `NativeCurrency` implementing trait `ConsensusProgram` in `native_currency.rs`.

## The Unit

One Neptune Coin equals \\(10^{30} \times 2^2 \\) *nau*, which stands for Neptune Atomic Unit. The conversion factor is such that
 - The largest possible amount, corresponding to 42'000'000 Neptune Coins, can be represented in **127** bits.
 - It can represent a number of Neptune Coins with up to 30 decimal symbols after the point exactly.

The struct `NativeCurrencyAmount` is a wrapper around a `i128`.

## The Type Script

The Neptune Coins type script
 - computes the sum of all inputs, plus coinbase if it is set;
 - computes the sum of all outputs plus fee;
 - equates the two quantities.

## Additional Features

Transactions have two features that make the native currency type script special. The first is the *fee* field, which is the excess of the transaction balance that can be captured by the miner. The second is the option *coinbase* field, which stipulates by how much a transaction is allowed to exceed the sum of input amounts because it is the only transaction in a block.
