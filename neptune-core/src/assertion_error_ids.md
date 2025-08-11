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

| Error IDs | Snippet(s)                                                                                                                     |
|----------:|:-------------------------------------------------------------------------------------------------------------------------------|
|     0..10 | [`RemovalRecordsIntegrity`](models/blockchain/transaction/validity/removal_records_integrity.rs)                               |
|    10..20 | `AuditVmEndState` (now deleted)                                                                                                |
|    20..30 | [`merge::AuthenticateCoinbaseFields`](models/blockchain/transaction/validity/tasm/merge/authenticate_coinbase_fields.rs)       |
|    30..50 | [`NativeCurrency`](models/blockchain/type_scripts/native_currency.rs)                                                          |
|    50..70 | [`SingleProof`](models/blockchain/transaction/validity/single_proof.rs)                                                        |
|    70..80 | [`MergeBranch`](models/blockchain/transaction/validity/tasm/single_proof/merge_branch.rs)                                      |
|  100..120 | [`UpdateBranch`](models/blockchain/transaction/validity/tasm/single_proof/update_branch.rs)                                    |
|  120..140 | [`Update`](models/blockchain/transaction/validity/update.rs)                                                                   |
|  200..210 | [`CoinbaseAmount`](models/blockchain/transaction/validity/tasm/coinbase_amount.rs)                                             |
|  210..250 | [`BlockProgram`](models/blockchain/block/validity/block_program.rs)                                                            |
|  250..260 | [`HashRemovalRecordIndexSets`](models/blockchain/transaction/validity/tasm/hash_removal_record_index_sets.rs)                  |
|  260..270 | [`CollectLockScripts`](models/blockchain/transaction/validity/collect_lock_scripts.rs)                                         |
|  270..280 | [`KernelToOutputs`](models/blockchain/transaction/validity/kernel_to_outputs.rs)                                               |
|  300..400 | [`LockScript`](models/blockchain/transaction/lock_script.rs)                                                                   |
|  400..500 | [`amount`](models/blockchain/type_scripts/amount/mod.rs)                                                                       |
|  500..510 | [`GenerateCollectTypeScriptsClaim`](models/blockchain/transaction/validity/tasm/claims/generate_collect_type_scripts_claim.rs) |
|  510..520 | [`CollectTypeScripts`](models/blockchain/transaction/validity/collect_type_scripts.rs)                                         |
