# Assertion Error IDs

Like [`tasm-lib`](https://github.com/TritonVM/tasm-lib/blob/master/tasm-lib/src/assertion_error_ids.md),
Neptune Core declares error IDs for Triton VM's instructions `assert` and `assert_vector`.
Use this file as the registry for Neptune Core's assertion error IDs.

Feel free to grab a multiple of 10 all at once.
This way, if your assembly snippet starts asserting more stuff, you don't have to come back here as
often.

## Registry

> ℹ️ Neptune Core's error IDs start at 1_000_000.
> For brevity, that offset is omitted below.

| Error IDs | Snippet                                                                                                                  |
|----------:|:-------------------------------------------------------------------------------------------------------------------------|
|     0..10 | [`RemovalRecordsIntegrity`](models/blockchain/transaction/validity/removal_records_integrity.rs)                         |
|    10..20 | [`AuditVmEndState`](models/proof_abstractions/tasm/audit_vm_end_state.rs)                                                |
|    20..30 | [`merge::AuthenticateCoinbaseFields`](models/blockchain/transaction/validity/tasm/merge/authenticate_coinbase_fields.rs) |
|    30..50 | [`NativeCurrency`](models/blockchain/type_scripts/native_currency.rs)                                                    |
|    50..70 | [`SingleProof`](models/blockchain/transaction/validity/single_proof.rs)                                                  |
|    70..80 | [`MergeBranch`](models/blockchain/transaction/validity/tasm/single_proof/merge_branch.rs)                                |
|  100..120 | [`Update`](models/blockchain/transaction/validity/update.rs)                                                             |
|  120..140 | [`Update`](models/blockchain/transaction/validity/update.rs)                                                             |
|  200..210 | [`CoinbaseAmount`](models/blockchain/transaction/validity/tasm/coinbase_amount.rs)                                       |
