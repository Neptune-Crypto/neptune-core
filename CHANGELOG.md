# Changelog

All notable changes are documented in this file.
Lines marked “(!)” indicate a breaking change.

## [0.1.0](https://github.com/Neptune-Crypto/neptune-core/compare/c951cd1b2e92213e2866b87e9fe62686b9e30548..v0.1.0) – 2024-10-31

Initial release of Neptune Core.

## [0.0.10](https://github.com/Neptune-Crypto/neptune-core/compare/v0.0.5..v0.0.10) - 2024-11-23

### ✨ Features

- Global state lock, async leveldb, etc. ([fa89d041](https://github.com/Neptune-Crypto/neptune-core/commit/fa89d041))
- Display localtime in dashboard fields ([3626465f](https://github.com/Neptune-Crypto/neptune-core/commit/3626465f))
- Allow batch-queries of blocks with out-of-order starting points ([a99b16a9](https://github.com/Neptune-Crypto/neptune-core/commit/a99b16a9))
- Derandomize wallet generation ([4f3792a4](https://github.com/Neptune-Crypto/neptune-core/commit/4f3792a4))
- Reject blocks with timestamp in future ([0c0e2c5f](https://github.com/Neptune-Crypto/neptune-core/commit/0c0e2c5f))
- Time locks ([80552a81](https://github.com/Neptune-Crypto/neptune-core/commit/80552a81))
- Report on own UTXOs ([e36a6799](https://github.com/Neptune-Crypto/neptune-core/commit/e36a6799))
- Add CLI command for listing coins ([497f4462](https://github.com/Neptune-Crypto/neptune-core/commit/497f4462))
- Display time-locked balance in dashboard ([f3007d6d](https://github.com/Neptune-Crypto/neptune-core/commit/f3007d6d))
- Add ProofType and BlockType enums ([612a753e](https://github.com/Neptune-Crypto/neptune-core/commit/612a753e))
- Log duration of adding new block ([0869f4c3](https://github.com/Neptune-Crypto/neptune-core/commit/0869f4c3))
- Make duration macros more flexible ([e61ef788](https://github.com/Neptune-Crypto/neptune-core/commit/e61ef788))
- Add `tip_info()` RPC API ([678ede62](https://github.com/Neptune-Crypto/neptune-core/commit/678ede62))
- Adds rpcs: block_info, block_digest ([b433e0df](https://github.com/Neptune-Crypto/neptune-core/commit/b433e0df))
- Add utxo_digest RPC call ([b8e7c35b](https://github.com/Neptune-Crypto/neptune-core/commit/b8e7c35b))
- Improve block_info and fix block_digest rpc ([888a00d8](https://github.com/Neptune-Crypto/neptune-core/commit/888a00d8))
- Use rfc339 in Timestamp::standard_format() ([5a8ad635](https://github.com/Neptune-Crypto/neptune-core/commit/5a8ad635))
- Add block-info command to neptune-cli ([3e21a69e](https://github.com/Neptune-Crypto/neptune-core/commit/3e21a69e))
- Make block timestamp repr time block found ([5f9c9e83](https://github.com/Neptune-Crypto/neptune-core/commit/5f9c9e83))
- *(archival_state)* Add method to get parent block of tip ([99abbdc2](https://github.com/Neptune-Crypto/neptune-core/commit/99abbdc2))
- Add get_cpu_temps ([4eef2b7e](https://github.com/Neptune-Crypto/neptune-core/commit/4eef2b7e))
- Add CPU temp to dashboard overview ([2ca45587](https://github.com/Neptune-Crypto/neptune-core/commit/2ca45587))
- *(mutator-set)* Add function to get active window's chunk index interval ([384ca41f](https://github.com/Neptune-Crypto/neptune-core/commit/384ca41f))
- Add neptune-cli send-to-many command ([e4e8edd6](https://github.com/Neptune-Crypto/neptune-core/commit/e4e8edd6))
- Symmetric key notifications ([4182f7d3](https://github.com/Neptune-Crypto/neptune-core/commit/4182f7d3))
- Persist ExpectedUtxo to disk (db) ([232e8520](https://github.com/Neptune-Crypto/neptune-core/commit/232e8520))
- Add stub for `RemovalRecordsIntegrity` subprogram ([2525f13a](https://github.com/Neptune-Crypto/neptune-core/commit/2525f13a))
- Add tx consensus program `KernelToOutputs` ([cdeec086](https://github.com/Neptune-Crypto/neptune-core/commit/cdeec086))
- Add consensus program `CollectLockScripts` ([d2d34931](https://github.com/Neptune-Crypto/neptune-core/commit/d2d34931))
- Produce `ProofCollection` ([c4ef536c](https://github.com/Neptune-Crypto/neptune-core/commit/c4ef536c))
- Verify `ProofCollection` ([7fb3d6d7](https://github.com/Neptune-Crypto/neptune-core/commit/7fb3d6d7))
- Complete consensus program `KernelToOutputs` ([4f01d485](https://github.com/Neptune-Crypto/neptune-core/commit/4f01d485))
- *(consensus)* Add snippet for reading coinbase amount from memory ([914f06e6](https://github.com/Neptune-Crypto/neptune-core/commit/914f06e6))
- Add `Display` implementation of primitive witness ([5ab088d7](https://github.com/Neptune-Crypto/neptune-core/commit/5ab088d7))
- *(Tx)* (Verify capability to) produce `ProofCollection` ([dac7d9c6](https://github.com/Neptune-Crypto/neptune-core/commit/dac7d9c6))
- *(consensus)* Update transaction proofs (stub) ([e8eb336a](https://github.com/Neptune-Crypto/neptune-core/commit/e8eb336a))
- *(consensus)* Merge transaction proofs (stub) ([ee511924](https://github.com/Neptune-Crypto/neptune-core/commit/ee511924))
- Modify environment when invoking builtin `stark_verify` ([e3004806](https://github.com/Neptune-Crypto/neptune-core/commit/e3004806))
- Verify `KernelToOutputs` in `SingleProof` ([de1f930b](https://github.com/Neptune-Crypto/neptune-core/commit/de1f930b))
- Add snippet for storing RRI-claim in dyn memory ([72619d9e](https://github.com/Neptune-Crypto/neptune-core/commit/72619d9e))
- *(ProofCollection)* Store claim for kernel-to-outputs ([97846578](https://github.com/Neptune-Crypto/neptune-core/commit/97846578))
- *(proof_collection)* Store claim for collect-lockscripts ([b0b13d03](https://github.com/Neptune-Crypto/neptune-core/commit/b0b13d03))
- Add generic snippet for new claim ([08dfcbc4](https://github.com/Neptune-Crypto/neptune-core/commit/08dfcbc4))
- *(claim)* Add snippet for generating collect-lock-scripts claim ([2c0419b3](https://github.com/Neptune-Crypto/neptune-core/commit/2c0419b3))
- *(transaction_consensus)* Verify MSA against TXK ([65b9081e](https://github.com/Neptune-Crypto/neptune-core/commit/65b9081e))
- *(tx-update)* Authenticate both MSAs against respective txk-mhash ([f4e78c6d](https://github.com/Neptune-Crypto/neptune-core/commit/f4e78c6d))
- Continue on transaction's `Update` program ([7328794a](https://github.com/Neptune-Crypto/neptune-core/commit/7328794a))
- *(tx-consensus)* Add snippet to verify tx inputs against txk MAST hash ([8284c3e3](https://github.com/Neptune-Crypto/neptune-core/commit/8284c3e3))
- Make progress on tx's `update` program ([2fe3f592](https://github.com/Neptune-Crypto/neptune-core/commit/2fe3f592))
- Add snippet for authenticating generic field against txk mast hash ([5694640b](https://github.com/Neptune-Crypto/neptune-core/commit/5694640b))
- Integrate generic field authentication snippet into `Update` ([dcfd13bd](https://github.com/Neptune-Crypto/neptune-core/commit/dcfd13bd))
- *(update)* Also authenticate timestamps in `update` program ([bd832f12](https://github.com/Neptune-Crypto/neptune-core/commit/bd832f12))
- *(proof_abstractions)* Add snippet for verifying integrity of end-vm state ([d179a122](https://github.com/Neptune-Crypto/neptune-core/commit/d179a122))
- *(merge)* Add snippet for verifying coinbase amount rules ([25791088](https://github.com/Neptune-Crypto/neptune-core/commit/25791088))
- Add estimate of machine power to `networking_state` ([1702caa6](https://github.com/Neptune-Crypto/neptune-core/commit/1702caa6))
- Make salt for tx-proof-generation deterministic ([684dbb4a](https://github.com/Neptune-Crypto/neptune-core/commit/684dbb4a))
- Use host-machine power to pick tx-proof type ([cd9c7985](https://github.com/Neptune-Crypto/neptune-core/commit/cd9c7985))
- Application-level transaction merge ([617462f5](https://github.com/Neptune-Crypto/neptune-core/commit/617462f5))
- *(proofs)* Query proof-servers for proof ([af26c3fa](https://github.com/Neptune-Crypto/neptune-core/commit/af26c3fa))
- *(mempool)* Allow caller to cap num txs for block ([7fadf5cb](https://github.com/Neptune-Crypto/neptune-core/commit/7fadf5cb))
- *(main_loop)* Add scheduled task to upgrade tx-proofs in mempool ([701b1306](https://github.com/Neptune-Crypto/neptune-core/commit/701b1306))
- *(atomic_mutex)* Add synchronous `try_lock` method ([bd66d851](https://github.com/Neptune-Crypto/neptune-core/commit/bd66d851))
- Ensure max one instance of Triton VM's prover runs at all times ([b08c02e6](https://github.com/Neptune-Crypto/neptune-core/commit/b08c02e6))
- Wallet unconfirmed balance. ([3c605e40](https://github.com/Neptune-Crypto/neptune-core/commit/3c605e40))
- *(difficulty-control)* Implement advance difficulty correction ([1a4d34b1](https://github.com/Neptune-Crypto/neptune-core/commit/1a4d34b1))
- Display unconfirmed balance in clients ([203fb3ac](https://github.com/Neptune-Crypto/neptune-core/commit/203fb3ac))
- Add ScopeDurationLogger ([de96f98c](https://github.com/Neptune-Crypto/neptune-core/commit/de96f98c))
- Make log-slow-write-lock timeout configurable ([2d0be8f0](https://github.com/Neptune-Crypto/neptune-core/commit/2d0be8f0))
- Add guesser fee to mutator set ([551e9c71](https://github.com/Neptune-Crypto/neptune-core/commit/551e9c71))
- Record nonce-preimage ([9f7bfc78](https://github.com/Neptune-Crypto/neptune-core/commit/9f7bfc78))
- *(`Timestamp`)* Implement AddAssign ([640b9608](https://github.com/Neptune-Crypto/neptune-core/commit/640b9608))
- Add serial job-queue for triton-vm jobs ([d9b9dfa3](https://github.com/Neptune-Crypto/neptune-core/commit/d9b9dfa3))
- Fifo job ordering of same priority jobs ([439192ce](https://github.com/Neptune-Crypto/neptune-core/commit/439192ce))
- Two-Step Mining ([966db77b](https://github.com/Neptune-Crypto/neptune-core/commit/966db77b))
- Add CLI flag `--no-transaction-initiation` ([93f145be](https://github.com/Neptune-Crypto/neptune-core/commit/93f145be))
- Generate proofs out-of-process ([b7b70e0c](https://github.com/Neptune-Crypto/neptune-core/commit/b7b70e0c))
- Job cancellation of JobQueue jobs ([06ca5d83](https://github.com/Neptune-Crypto/neptune-core/commit/06ca5d83))
- Cli opt max_log2_padded_height_for_proofs ([7d3826aa](https://github.com/Neptune-Crypto/neptune-core/commit/7d3826aa))
- Reward peers for good behavior ([6e983cdd](https://github.com/Neptune-Crypto/neptune-core/commit/6e983cdd))
- Add JobResult::into_any(), owned downcast() ([b18f0d1c](https://github.com/Neptune-Crypto/neptune-core/commit/b18f0d1c))
- Pause mining if proof complexity limit hit ([e9a1c506](https://github.com/Neptune-Crypto/neptune-core/commit/e9a1c506))
- *(dashboard)* Show number of own mempool-transactions ([7b1426be](https://github.com/Neptune-Crypto/neptune-core/commit/7b1426be))
- *(dashboard)* Add mempool overview screen ([4b5b9d10](https://github.com/Neptune-Crypto/neptune-core/commit/4b5b9d10))
- Add log-slow-read-lock feature ([21319c9c](https://github.com/Neptune-Crypto/neptune-core/commit/21319c9c))
- Add location to slow scope log msg ([adcaeef4](https://github.com/Neptune-Crypto/neptune-core/commit/adcaeef4))
- *(dashboard)* Show proving capability ([a2dd0d9d](https://github.com/Neptune-Crypto/neptune-core/commit/a2dd0d9d))
- Log duration of VMState::run() in ProverJob ([556c3584](https://github.com/Neptune-Crypto/neptune-core/commit/556c3584))
- Add crate feature log-lock_events ([203e2d23](https://github.com/Neptune-Crypto/neptune-core/commit/203e2d23))
- Include location in log-lock-events feature ([a185aca3](https://github.com/Neptune-Crypto/neptune-core/commit/a185aca3))
- *(wallet)* Add support for offchain UTXO notifications ([8592bfdd](https://github.com/Neptune-Crypto/neptune-core/commit/8592bfdd))

### 🐛 Bug Fixes

- Prune_abandoned_monitored_utxos() RPC ([1a978991](https://github.com/Neptune-Crypto/neptune-core/commit/1a978991))
- Flush databases for RPC calls that mutate ([723b23a5](https://github.com/Neptune-Crypto/neptune-core/commit/723b23a5))
- Reduce dashboard CPU usage via fewer draws ([913a80c9](https://github.com/Neptune-Crypto/neptune-core/commit/913a80c9))
- Synchronize mast_hash trait with tasm snippets ([7d99673f](https://github.com/Neptune-Crypto/neptune-core/commit/7d99673f))
- `accumulate_transaction` ([2947dd0e](https://github.com/Neptune-Crypto/neptune-core/commit/2947dd0e))
- `wallet_state_constructor_with_genesis_block_test` ([a84a7c26](https://github.com/Neptune-Crypto/neptune-core/commit/a84a7c26))
- `get_ancestor_block_digests` ([4571d7c6](https://github.com/Neptune-Crypto/neptune-core/commit/4571d7c6))
- Mock blocks should have some proof ([c2b5656e](https://github.com/Neptune-Crypto/neptune-core/commit/c2b5656e))
- Index blocks by digest not header ([665a0dd6](https://github.com/Neptune-Crypto/neptune-core/commit/665a0dd6))
- `prune_abandoned_monitored_utxos` ([e4f77ccb](https://github.com/Neptune-Crypto/neptune-core/commit/e4f77ccb))
- Fix flaky mutator set test ([bd15ae7a](https://github.com/Neptune-Crypto/neptune-core/commit/bd15ae7a))
- *(mutator set)* Fix flaky test ([fcb306f7](https://github.com/Neptune-Crypto/neptune-core/commit/fcb306f7))
- Use locked `Cargo.lock` for installation ([94220272](https://github.com/Neptune-Crypto/neptune-core/commit/94220272))
- Disable lock_event tracing to fix tests leak ([5b81b100](https://github.com/Neptune-Crypto/neptune-core/commit/5b81b100))
- Clippy warning in a test ([44579900](https://github.com/Neptune-Crypto/neptune-core/commit/44579900))
- Potential overflow in `RootAndPaths` ([86df380d](https://github.com/Neptune-Crypto/neptune-core/commit/86df380d))
- Time lock tests ([e5734d44](https://github.com/Neptune-Crypto/neptune-core/commit/e5734d44))
- Remove double padding ([99843e46](https://github.com/Neptune-Crypto/neptune-core/commit/99843e46))
- *(Amounts)* Add non-negativity test for outputs ([f7206db6](https://github.com/Neptune-Crypto/neptune-core/commit/f7206db6))
- Get_batch_index_async() off-by-1, fixes 3 failing tests ([e71ad26d](https://github.com/Neptune-Crypto/neptune-core/commit/e71ad26d))
- Mutator set batch remove ([18bddc7d](https://github.com/Neptune-Crypto/neptune-core/commit/18bddc7d))
- Send syncing start/stop messages to miner ([b4a939c8](https://github.com/Neptune-Crypto/neptune-core/commit/b4a939c8))
- Build error.  u64 --> TimeStamp ([bc8ba6ad](https://github.com/Neptune-Crypto/neptune-core/commit/bc8ba6ad))
- Utxo_digest() must call count_leaves() ([5aabe432](https://github.com/Neptune-Crypto/neptune-core/commit/5aabe432))
- Use Block::hash() consistently ([bf4336e1](https://github.com/Neptune-Crypto/neptune-core/commit/bf4336e1))
- *(test)* Fix flaky timelock test ([0a540f8d](https://github.com/Neptune-Crypto/neptune-core/commit/0a540f8d))
- Loosen CPU temp test requirement because CI ([e651a294](https://github.com/Neptune-Crypto/neptune-core/commit/e651a294))
- Failing doctest example for new mempool ([ff19ec37](https://github.com/Neptune-Crypto/neptune-core/commit/ff19ec37))
- Docstring for creating a mempool instance ([108cfc46](https://github.com/Neptune-Crypto/neptune-core/commit/108cfc46))
- Adjust difficulty in the mining loop ([7fa9c694](https://github.com/Neptune-Crypto/neptune-core/commit/7fa9c694))
- Fix `RemovalRecordsIntegrity` and add tests ([6b7534ba](https://github.com/Neptune-Crypto/neptune-core/commit/6b7534ba))
- Verify AOCL membership in `RemovalRecordsIntegrity` ([bbab16c8](https://github.com/Neptune-Crypto/neptune-core/commit/bbab16c8))
- *(consensus)* Fix `CollectTypeScripts` ([53e3a430](https://github.com/Neptune-Crypto/neptune-core/commit/53e3a430))
- *(consensus)* Fix `CollectTypeScripts` and add test ([2b276944](https://github.com/Neptune-Crypto/neptune-core/commit/2b276944))
- Ensure valid total in arbitrary `PrimitiveWitness` ([6df97476](https://github.com/Neptune-Crypto/neptune-core/commit/6df97476))
- *(consensus)* Fix `NativeCurrency` type script ([fab234e2](https://github.com/Neptune-Crypto/neptune-core/commit/fab234e2))
- Make arbitrary for `PrimitiveWitness` deterministic ([c5079cb5](https://github.com/Neptune-Crypto/neptune-core/commit/c5079cb5))
- *(consensus)* Move authentication against kernel forward and fix it ([3b9fb920](https://github.com/Neptune-Crypto/neptune-core/commit/3b9fb920))
- *(consensus)* Make `RemovalRecordIntegrity` valid tasm ([3890af49](https://github.com/Neptune-Crypto/neptune-core/commit/3890af49))
- *(RemovalRecordsIntegrity)* Populate nd_digests with aocl auth paths ([12933daa](https://github.com/Neptune-Crypto/neptune-core/commit/12933daa))
- *(RemovalRecordsIntegrity)* Compute canonical commitment correctly ([656e80d9](https://github.com/Neptune-Crypto/neptune-core/commit/656e80d9))
- *(RemovalRecordsIntegrity)* Hash index sets correctly ([c6fa1ef4](https://github.com/Neptune-Crypto/neptune-core/commit/c6fa1ef4))
- *(RemovalRecordsIntegrity)* Hash chunk correctly ([0cb274ad](https://github.com/Neptune-Crypto/neptune-core/commit/0cb274ad))
- *(RemovalRecordsIntegrity)* Correct field getters for chunk dictionary entry ([a0e5b3bb](https://github.com/Neptune-Crypto/neptune-core/commit/a0e5b3bb))
- *(RemovalRecordsIntegrity)* Read leaf index from right memory location ([cebb5bd5](https://github.com/Neptune-Crypto/neptune-core/commit/cebb5bd5))
- *(RemovalRecordsIntegrity)* Fix stack arithmetic ([db752e45](https://github.com/Neptune-Crypto/neptune-core/commit/db752e45))
- *(consensus)* RemovalRecordIntegrity ([159ac807](https://github.com/Neptune-Crypto/neptune-core/commit/159ac807))
- *(`GenerationAddress`)* Fix `LockScriptAndWitness` generator ([18d3acff](https://github.com/Neptune-Crypto/neptune-core/commit/18d3acff))
- *(mutator set)* Fix `update_from_addition` ([f5b33e7a](https://github.com/Neptune-Crypto/neptune-core/commit/f5b33e7a))
- *(mutator_set)* Fix wrong index arithmetic ([a73a75ec](https://github.com/Neptune-Crypto/neptune-core/commit/a73a75ec))
- *(mutator_set)* Skip over new chunk index ([7d427f44](https://github.com/Neptune-Crypto/neptune-core/commit/7d427f44))
- *(mutator set)* Record indices of mps updated with append ([7771e89f](https://github.com/Neptune-Crypto/neptune-core/commit/7771e89f))
- *(mutator set)* Condition population of index map ([80fe1f6c](https://github.com/Neptune-Crypto/neptune-core/commit/80fe1f6c))
- *(mutator set)* Keep empty list up-to-date ([186cf822](https://github.com/Neptune-Crypto/neptune-core/commit/186cf822))
- *(removal_records_integrity)* Fix MMR auth path in Rust shadow ([c628924e](https://github.com/Neptune-Crypto/neptune-core/commit/c628924e))
- Names of snippet to be in line with that from `tasm-lib` ([6e11750d](https://github.com/Neptune-Crypto/neptune-core/commit/6e11750d))
- *(single_proof)* Fix RRI claim generation ([d1abb5cd](https://github.com/Neptune-Crypto/neptune-core/commit/d1abb5cd))
- *(`NewClaim`)* Bypass poor memory population manually ([774e11ac](https://github.com/Neptune-Crypto/neptune-core/commit/774e11ac))
- *(`GenerateRriClaim`)* Populate rust shadow stack correctly ([fc3d63e2](https://github.com/Neptune-Crypto/neptune-core/commit/fc3d63e2))
- *(Tx)* Fix production of nondeterminism in `Update` ([ae3e6e12](https://github.com/Neptune-Crypto/neptune-core/commit/ae3e6e12))
- Fix discrepancy in `Update`'s nondeterminism generator' ([e6b2185a](https://github.com/Neptune-Crypto/neptune-core/commit/e6b2185a))
- *(`Timelock`)* Update tasm code for `Timelock` ([a792bb75](https://github.com/Neptune-Crypto/neptune-core/commit/a792bb75))
- *(`PrimitiveWitness`)* Fix arbitrary primitive witness with timelocks ([7ff87142](https://github.com/Neptune-Crypto/neptune-core/commit/7ff87142))
- *(test)* Add missing assert in host-machine logic of MSA authentication ([dfcee576](https://github.com/Neptune-Crypto/neptune-core/commit/dfcee576))
- *(lints)* Fix or silence clippy warnings ([bf472cb2](https://github.com/Neptune-Crypto/neptune-core/commit/bf472cb2))
- *(primitive_witness)* Split arguments correctly ([0afa2161](https://github.com/Neptune-Crypto/neptune-core/commit/0afa2161))
- *(primitive_witness)* Arbitrary generator for two PWs ([ee86cdf2](https://github.com/Neptune-Crypto/neptune-core/commit/ee86cdf2))
- Correct `Map`'s input types ([71344d3f](https://github.com/Neptune-Crypto/neptune-core/commit/71344d3f))
- *(Update)* Make output empty ([466ef486](https://github.com/Neptune-Crypto/neptune-core/commit/466ef486))
- *(SingleProof)* Read txk digest once ([8e2d5eba](https://github.com/Neptune-Crypto/neptune-core/commit/8e2d5eba))
- Primitive witness generation on tx creation ([8b6effe5](https://github.com/Neptune-Crypto/neptune-core/commit/8b6effe5))
- State-related tests ([9d4bd1b2](https://github.com/Neptune-Crypto/neptune-core/commit/9d4bd1b2))
- *(test)* Allow_consumption_of_genesis_output_test ([1957886a](https://github.com/Neptune-Crypto/neptune-core/commit/1957886a))
- Fix deadlock in test-helper function ([f6ec10f9](https://github.com/Neptune-Crypto/neptune-core/commit/f6ec10f9))
- Blocking issue when fetching proofs for tests from proof server ([b63a27b7](https://github.com/Neptune-Crypto/neptune-core/commit/b63a27b7))
- Make announcement payload public again ([2ffaf6e8](https://github.com/Neptune-Crypto/neptune-core/commit/2ffaf6e8))
- Make tests in `state/mod.rs` compile ([4aea8999](https://github.com/Neptune-Crypto/neptune-core/commit/4aea8999))
- Make public announcement encryption deterministic ([e0f44818](https://github.com/Neptune-Crypto/neptune-core/commit/e0f44818))
- Make `send_to_many` test deterministic ([c7b1e997](https://github.com/Neptune-Crypto/neptune-core/commit/c7b1e997))
- Make RPC server's `send_to_many` test deterministic ([a61d4999](https://github.com/Neptune-Crypto/neptune-core/commit/a61d4999))
- Formatting errors for imports ([c721f8ea](https://github.com/Neptune-Crypto/neptune-core/commit/c721f8ea))
- Docstring test for mempool ([0987997a](https://github.com/Neptune-Crypto/neptune-core/commit/0987997a))
- *(wallet_state)* Don't use timelocked UTXOs as tx-inputs ([d6f5680a](https://github.com/Neptune-Crypto/neptune-core/commit/d6f5680a))
- *(mempool)* Remove all conflicting transactions ([96c4a3ae](https://github.com/Neptune-Crypto/neptune-core/commit/96c4a3ae))
- *(mine_loop)* Don't hold read-lock when generating coinbase transaction ([5c0242b5](https://github.com/Neptune-Crypto/neptune-core/commit/5c0242b5))
- *(ci-test)* Force CI machine to think it can generate SingleProofs ([1de32102](https://github.com/Neptune-Crypto/neptune-core/commit/1de32102))
- Relate block hash to predecessor difficulty ([bb339590](https://github.com/Neptune-Crypto/neptune-core/commit/bb339590))
- *(difficulty-control)* Simplify controller ([6407a300](https://github.com/Neptune-Crypto/neptune-core/commit/6407a300))
- Space blocks apart in tests ([0a6c30f0](https://github.com/Neptune-Crypto/neptune-core/commit/0a6c30f0))
- Conflicting implementations of Arbitrary ([201092ac](https://github.com/Neptune-Crypto/neptune-core/commit/201092ac))
- *(BlockProgram)* Fix implementation of Block's 1st claim: transaction_is_valid ([e57f4593](https://github.com/Neptune-Crypto/neptune-core/commit/e57f4593))
- Make proof producers async ([e36fdb86](https://github.com/Neptune-Crypto/neptune-core/commit/e36fdb86))
- *(test)* Restore_monitored_utxos_from_recovery_data_test ([cba9279a](https://github.com/Neptune-Crypto/neptune-core/commit/cba9279a))
- *(block_program)* Output all claim digests verified ([131365f3](https://github.com/Neptune-Crypto/neptune-core/commit/131365f3))
- *(test_helper)* Make_mock_block_with_valid_pow ([cff358f5](https://github.com/Neptune-Crypto/neptune-core/commit/cff358f5))
- *(Arbitrary)* Fix arbitrary impl of TransactionKernel ([74ed400d](https://github.com/Neptune-Crypto/neptune-core/commit/74ed400d))
- *(TxIsValidWitness)* Std-in is block body mast hash, not tx-kernel's ([0016fa93](https://github.com/Neptune-Crypto/neptune-core/commit/0016fa93))
- Drop block-verify asserts in mempool test ([d1b9939e](https://github.com/Neptune-Crypto/neptune-core/commit/d1b9939e))
- Use invalid block template in wallet test ([ffeaeea5](https://github.com/Neptune-Crypto/neptune-core/commit/ffeaeea5))
- *(peer_loop)* Fix test in peer loop ([40e4723d](https://github.com/Neptune-Crypto/neptune-core/commit/40e4723d))
- *(SingleProof)* Verify that discriminant has legal value in TASM program ([f9aeb505](https://github.com/Neptune-Crypto/neptune-core/commit/f9aeb505))
- Disable log-slow-write-lock for stable channel ([e3002a6a](https://github.com/Neptune-Crypto/neptune-core/commit/e3002a6a))
- Remove all futures::executor::block_on() ([85ebb168](https://github.com/Neptune-Crypto/neptune-core/commit/85ebb168))
- Shutdown even if prover is running. ([41b170d6](https://github.com/Neptune-Crypto/neptune-core/commit/41b170d6))
- Handle 'channel closed' err on ctrl-c ([5b721a31](https://github.com/Neptune-Crypto/neptune-core/commit/5b721a31))
- Await aborted tasks in graceful_shutdown() ([2cd9d1a5](https://github.com/Neptune-Crypto/neptune-core/commit/2cd9d1a5))
- Find triton-vm-prover in same dir as neptune-core ([9909e233](https://github.com/Neptune-Crypto/neptune-core/commit/9909e233))
- Ignore stderr when invoking triton-vm-prover ([18f2bef8](https://github.com/Neptune-Crypto/neptune-core/commit/18f2bef8))
- Stop queue when last JobQueue instance drops ([2eb6dff9](https://github.com/Neptune-Crypto/neptune-core/commit/2eb6dff9))
- *(mempool)* Prefer tx with higher proof quality ([2304ae7f](https://github.com/Neptune-Crypto/neptune-core/commit/2304ae7f))
- *(mutator_set)* Drop correction of removal records ([18e98e8a](https://github.com/Neptune-Crypto/neptune-core/commit/18e98e8a))
- Fixes a compile error on stable rustc ([430afd67](https://github.com/Neptune-Crypto/neptune-core/commit/430afd67))
- Avoid sending job-cancel if channel closed ([aa009d0d](https://github.com/Neptune-Crypto/neptune-core/commit/aa009d0d))
- *(mock_genesis_global_state)* Allow setting tx-prover capability ([f2beea8a](https://github.com/Neptune-Crypto/neptune-core/commit/f2beea8a))
- Scope duration logger was not working ([2888c480](https://github.com/Neptune-Crypto/neptune-core/commit/2888c480))
- *(dashboard)* Correct historical balance ([c0a6afff](https://github.com/Neptune-Crypto/neptune-core/commit/c0a6afff))
- Unused case in macro log_slow_scope() ([23b6de29](https://github.com/Neptune-Crypto/neptune-core/commit/23b6de29))
- Use wrapping add to avoid panic ([4a86c6e0](https://github.com/Neptune-Crypto/neptune-core/commit/4a86c6e0))
- Check emptiness, not absence, of SWBFI chunks ([a79b827c](https://github.com/Neptune-Crypto/neptune-core/commit/a79b827c))
- *(CLI-args)* Drop static variable in caching accessor ([ed38cf5f](https://github.com/Neptune-Crypto/neptune-core/commit/ed38cf5f))
- Avoid overflow ([2175b1e5](https://github.com/Neptune-Crypto/neptune-core/commit/2175b1e5))
- Fix `generate_collect_lock_scripts_claim` ([8750bed9](https://github.com/Neptune-Crypto/neptune-core/commit/8750bed9))
- Fix `generate_collect_type_scripts_claim` ([cd63a8ab](https://github.com/Neptune-Crypto/neptune-core/commit/cd63a8ab))
- Fix rust shadow of claim template generation ([94af1a2c](https://github.com/Neptune-Crypto/neptune-core/commit/94af1a2c))
- *(test)* Introduce assertion error IDs ([6bceec5e](https://github.com/Neptune-Crypto/neptune-core/commit/6bceec5e))
- Use canonical hash of claim to derive proof file name ([8ce6c761](https://github.com/Neptune-Crypto/neptune-core/commit/8ce6c761))
- *(SingleProof)* Bug in `claim` method ([d2e556ce](https://github.com/Neptune-Crypto/neptune-core/commit/d2e556ce))
- Un-pause mining if returning early in send() ([f2230d24](https://github.com/Neptune-Crypto/neptune-core/commit/f2230d24))
- Send no longer pause/unpause mining/composing. ([4ba22f7b](https://github.com/Neptune-Crypto/neptune-core/commit/4ba22f7b))
- Expand height of notice text and wrap text ([07721001](https://github.com/Neptune-Crypto/neptune-core/commit/07721001))
- *(mine_loop)* Flip logic of sleepy_guessing ([4316b8d3](https://github.com/Neptune-Crypto/neptune-core/commit/4316b8d3))

### 🚀 Performance

- Make archival_state file ops async/friendly ([e6031bf9](https://github.com/Neptune-Crypto/neptune-core/commit/e6031bf9))
- Use non-blocking I/O in wallet_state.rs ([1a6cdd1a](https://github.com/Neptune-Crypto/neptune-core/commit/1a6cdd1a))
- Add sync_atomic bench test ([636c53a9](https://github.com/Neptune-Crypto/neptune-core/commit/636c53a9))
- Add db/storage bench tests ([ae8c0c77](https://github.com/Neptune-Crypto/neptune-core/commit/ae8c0c77))
- Add benchmark for archival-MMR appned operations ([e98baa29](https://github.com/Neptune-Crypto/neptune-core/commit/e98baa29))
- Speedup AMMR append operation ([c2d7ee45](https://github.com/Neptune-Crypto/neptune-core/commit/c2d7ee45))
- Add benchmark of AMMR leaf mutations ([70f06c6e](https://github.com/Neptune-Crypto/neptune-core/commit/70f06c6e))
- Speed up archival-MMR's leaf mutation by removing auth path ([e282482a](https://github.com/Neptune-Crypto/neptune-core/commit/e282482a))
- Faster `count_leaves` and `prove_membership_async` for MMRA ([3adb0216](https://github.com/Neptune-Crypto/neptune-core/commit/3adb0216))
- Add benchmark of ArchivalMMR's `get_peaks` ([081acaa2](https://github.com/Neptune-Crypto/neptune-core/commit/081acaa2))
- Add spawn_blocking around script execution ([bf83e9ca](https://github.com/Neptune-Crypto/neptune-core/commit/bf83e9ca))
- Wrap mining loop with spawn_blocking() ([b17c8b32](https://github.com/Neptune-Crypto/neptune-core/commit/b17c8b32))
- Wrap tx prover with spawn_blocking ([b160e1d1](https://github.com/Neptune-Crypto/neptune-core/commit/b160e1d1))
- Optimize get_peaks_and_heights for archival MMR. ([e6f3e916](https://github.com/Neptune-Crypto/neptune-core/commit/e6f3e916))
- Optimize get_peaks_and_heights for archival MMR. ([e1bf9dda](https://github.com/Neptune-Crypto/neptune-core/commit/e1bf9dda))
- Make Block::hash() 0(1) via precompute ([20f4e0fa](https://github.com/Neptune-Crypto/neptune-core/commit/20f4e0fa))
- Only compute block digest if hash() called. ([b5ad29c6](https://github.com/Neptune-Crypto/neptune-core/commit/b5ad29c6))
- Use OnceLock for Block::digest field ([6b71f348](https://github.com/Neptune-Crypto/neptune-core/commit/6b71f348))
- Avoid holding write-lock across prove() ([10a95b6d](https://github.com/Neptune-Crypto/neptune-core/commit/10a95b6d))
- Avoid unneeded write-lock in send_to_many ([d177cca5](https://github.com/Neptune-Crypto/neptune-core/commit/d177cca5))
- Make scan_for_expected_utxos o(n)+o(m) ([90aaa942](https://github.com/Neptune-Crypto/neptune-core/commit/90aaa942))
- (!) Use iterator for receiver digests list, instead of list ([6b06a33a](https://github.com/Neptune-Crypto/neptune-core/commit/6b06a33a))
- *(RemovalRecordsIntegrity)* Use varlen hashing with static size ([9251326c](https://github.com/Neptune-Crypto/neptune-core/commit/9251326c))
- *(peer_loop)* Return batch of blocks based on 1st matching digest ([15970eb1](https://github.com/Neptune-Crypto/neptune-core/commit/15970eb1))
- *(test)* Speedup how blocks with valid PoWs are found for tests ([95156b03](https://github.com/Neptune-Crypto/neptune-core/commit/95156b03))
- *(test)* Make test_difficulty_control_matches faster by parallelization ([ae5a6359](https://github.com/Neptune-Crypto/neptune-core/commit/ae5a6359))
- *(test)* Parallelize block production in resync_ms_membership_proofs_across_stale_fork ([819047a8](https://github.com/Neptune-Crypto/neptune-core/commit/819047a8))
- *(test)* Don't rebuild block in `block_hash_relates_to_predecessor_difficulty` ([119a9691](https://github.com/Neptune-Crypto/neptune-core/commit/119a9691))
- Log_slow_scope(), better description when running vm program ([0ca21177](https://github.com/Neptune-Crypto/neptune-core/commit/0ca21177))
- Wrap VM::run() with spawn_blocking() ([621c7e69](https://github.com/Neptune-Crypto/neptune-core/commit/621c7e69))
- Acquire read-lock only once in dashboard rpc ([c1c78b22](https://github.com/Neptune-Crypto/neptune-core/commit/c1c78b22))
- Cache TimeLock and NativeCurrency hashes with OnceLock ([9a135d5d](https://github.com/Neptune-Crypto/neptune-core/commit/9a135d5d))
- Impl hash() with OnceLock for impl ConsensusProgram ([1b81397d](https://github.com/Neptune-Crypto/neptune-core/commit/1b81397d))
- Disable cpu temp in dashboard data. ([dd1e9fd8](https://github.com/Neptune-Crypto/neptune-core/commit/dd1e9fd8))
- Slow scope logging for dashboard_overview rpc ([de87a93f](https://github.com/Neptune-Crypto/neptune-core/commit/de87a93f))
- Avoid extra tip5 hash in Utxo::hash() ([9c75ffec](https://github.com/Neptune-Crypto/neptune-core/commit/9c75ffec))
- Avoid extra tip5 hash in TypeScript Hash impl ([6a430dc9](https://github.com/Neptune-Crypto/neptune-core/commit/6a430dc9))
- Cache CliArg::proving_capability() result ([576f1b36](https://github.com/Neptune-Crypto/neptune-core/commit/576f1b36))
- Lower cpu priority of triton-vm-prover ([60254645](https://github.com/Neptune-Crypto/neptune-core/commit/60254645))
- Remove extra rpc calls, fix notice display ([6328fee0](https://github.com/Neptune-Crypto/neptune-core/commit/6328fee0))

### 📚 Documentation

- Remove obsolete comment line ([e39186ad](https://github.com/Neptune-Crypto/neptune-core/commit/e39186ad))
- Add git_branches.md, update README.md ([39b3eba8](https://github.com/Neptune-Crypto/neptune-core/commit/39b3eba8))
- Add conventional commits and topic naming ([53999e4c](https://github.com/Neptune-Crypto/neptune-core/commit/53999e4c))
- Git branch workflow ([31514e19](https://github.com/Neptune-Crypto/neptune-core/commit/31514e19))
- Clarify validity of uncle blocks ([e8b858bb](https://github.com/Neptune-Crypto/neptune-core/commit/e8b858bb))
- Improve installation instructions ([bb435567](https://github.com/Neptune-Crypto/neptune-core/commit/bb435567))
- Document `NativeCurrency` and `NeptuneCoins` ([643bdb62](https://github.com/Neptune-Crypto/neptune-core/commit/643bdb62))
- Fix doctests. all tests now passing ([52f75c83](https://github.com/Neptune-Crypto/neptune-core/commit/52f75c83))
- Update DbSchema docs, remove unused files ([bde7172d](https://github.com/Neptune-Crypto/neptune-core/commit/bde7172d))
- Doc-comment tweak ([c4c32cc5](https://github.com/Neptune-Crypto/neptune-core/commit/c4c32cc5))
- Output which directory is used for MS init test ([d372d727](https://github.com/Neptune-Crypto/neptune-core/commit/d372d727))
- Comment lock usage in send rpc. ([a40aee0e](https://github.com/Neptune-Crypto/neptune-core/commit/a40aee0e))
- *(tip-updater)* Elaborate on comments in method to update tip ([65b283c7](https://github.com/Neptune-Crypto/neptune-core/commit/65b283c7))
- Improve error message on client startup ([167b452b](https://github.com/Neptune-Crypto/neptune-core/commit/167b452b))
- *(mempool)* Elaborate on mempool methods ([fe65beb8](https://github.com/Neptune-Crypto/neptune-core/commit/fe65beb8))
- Describe state element's tolerance to reorganizations ([1e788556](https://github.com/Neptune-Crypto/neptune-core/commit/1e788556))
- Apply feedback on documentation of reorganization ([d76d3a69](https://github.com/Neptune-Crypto/neptune-core/commit/d76d3a69))
- Create mdBook ([ec08ef13](https://github.com/Neptune-Crypto/neptune-core/commit/ec08ef13))
- Add consensus overview ([eb5fc0fe](https://github.com/Neptune-Crypto/neptune-core/commit/eb5fc0fe))
- Finish first draft of transaction validity ([bbc2c130](https://github.com/Neptune-Crypto/neptune-core/commit/bbc2c130))
- Add outline of block consensus ([c214af4c](https://github.com/Neptune-Crypto/neptune-core/commit/c214af4c))
- Clarify transaction and block consensus rules ([4b9fd578](https://github.com/Neptune-Crypto/neptune-core/commit/4b9fd578))
- Add diagram and table to clarify transaction validity ([1a0839f1](https://github.com/Neptune-Crypto/neptune-core/commit/1a0839f1))
- Address updating of removal records auth paths ([308ecbb2](https://github.com/Neptune-Crypto/neptune-core/commit/308ecbb2))
- Comment send-to-many outputs parsing ([a70adbcf](https://github.com/Neptune-Crypto/neptune-core/commit/a70adbcf))
- Danda's first read edits ([0c71a42f](https://github.com/Neptune-Crypto/neptune-core/commit/0c71a42f))
- Rewrite "Atomic writing to databases" ([c58be396](https://github.com/Neptune-Crypto/neptune-core/commit/c58be396))
- Clarify "Atomic writing to databases" ([7e64b1cc](https://github.com/Neptune-Crypto/neptune-core/commit/7e64b1cc))
- Fix cargo doc warnings ([ae49fa4a](https://github.com/Neptune-Crypto/neptune-core/commit/ae49fa4a))
- Fix clippy 1.80 doc-comment warning ([a111926f](https://github.com/Neptune-Crypto/neptune-core/commit/a111926f))
- Improve/fix doc-comments. ([48122030](https://github.com/Neptune-Crypto/neptune-core/commit/48122030))
- Add description of generation addresses ([67a20f4d](https://github.com/Neptune-Crypto/neptune-core/commit/67a20f4d))
- Add mdbook note re generation key naming ([340fb9c3](https://github.com/Neptune-Crypto/neptune-core/commit/340fb9c3))
- Update PeerLoopHandler doc-comment ([a59bae6b](https://github.com/Neptune-Crypto/neptune-core/commit/a59bae6b))
- Add comment about ignoring cost of reallocation ([40983b57](https://github.com/Neptune-Crypto/neptune-core/commit/40983b57))
- *(kernel_to_outputs)* More descriptive loop name ([c81a19ba](https://github.com/Neptune-Crypto/neptune-core/commit/c81a19ba))
- Verify AOCL membership in `RemovalRecordsIntegrity` ([b5f3de98](https://github.com/Neptune-Crypto/neptune-core/commit/b5f3de98))
- Fix diagram: show all inputs to `TypeScript` ([62d46175](https://github.com/Neptune-Crypto/neptune-core/commit/62d46175))
- Add docs for UTXO, scripts, Neptune Coins ([1e85e0ac](https://github.com/Neptune-Crypto/neptune-core/commit/1e85e0ac))
- *(consensus::transaction)* Add motivation for TX-validity ([68906d07](https://github.com/Neptune-Crypto/neptune-core/commit/68906d07))
- Update `transaction.md` ([e78e4caf](https://github.com/Neptune-Crypto/neptune-core/commit/e78e4caf))
- *(Tx)* Add fields of `PrimitiveWitness` ([935d7fd2](https://github.com/Neptune-Crypto/neptune-core/commit/935d7fd2))
- Update comment on `RegTest` variant ([e4ee8cd8](https://github.com/Neptune-Crypto/neptune-core/commit/e4ee8cd8))
- Add documentation on sharing proofs ([6f18665b](https://github.com/Neptune-Crypto/neptune-core/commit/6f18665b))
- Restrict suggested nginx server config for proof server ([3ebc8775](https://github.com/Neptune-Crypto/neptune-core/commit/3ebc8775))
- Update comment on whether to make test helper `async` ([4012b33a](https://github.com/Neptune-Crypto/neptune-core/commit/4012b33a))
- Add ASCII diagram to difficulty control mechanism ([08d6d192](https://github.com/Neptune-Crypto/neptune-core/commit/08d6d192))
- Add docstrings to `Difficulty` and `ProofOfWork` ([5cfe4a8a](https://github.com/Neptune-Crypto/neptune-core/commit/5cfe4a8a))
- Add proof server documentation to mdbook ([069637ca](https://github.com/Neptune-Crypto/neptune-core/commit/069637ca))
- Clarify possible error in return value ([355bbda1](https://github.com/Neptune-Crypto/neptune-core/commit/355bbda1))
- Update max_log2_padded_height_for_proofs description ([005c5fca](https://github.com/Neptune-Crypto/neptune-core/commit/005c5fca))
- Update README.md ([3465c8c4](https://github.com/Neptune-Crypto/neptune-core/commit/3465c8c4))

### 🔒️ Security

- *(Block)* Drop field `uncle_blocks` ([785b0ef4](https://github.com/Neptune-Crypto/neptune-core/commit/785b0ef4))

### ♻️ Refactor

- Add GlobalData::store_block() ([853affd3](https://github.com/Neptune-Crypto/neptune-core/commit/853affd3))
- No more LevelDB interior mutability ([4098dc78](https://github.com/Neptune-Crypto/neptune-core/commit/4098dc78))
- Require mutable access via monitored_utxos_mut() ([7f781ddf](https://github.com/Neptune-Crypto/neptune-core/commit/7f781ddf))
- No more interior mutability for RustyArchivalMutatorSet::ams ([4912ccd6](https://github.com/Neptune-Crypto/neptune-core/commit/4912ccd6))
- Make NeptuneLevelDb api take &mut self. ([150dd848](https://github.com/Neptune-Crypto/neptune-core/commit/150dd848))
- Add `prelude.rs` and simplify deps ([eda04be8](https://github.com/Neptune-Crypto/neptune-core/commit/eda04be8))
- *(consensus)* Introduce skeleton for block validation logic ([af4bb001](https://github.com/Neptune-Crypto/neptune-core/commit/af4bb001))
- Wip modify block structure ([5ac6e841](https://github.com/Neptune-Crypto/neptune-core/commit/5ac6e841))
- Make compile ([4a694c4c](https://github.com/Neptune-Crypto/neptune-core/commit/4a694c4c))
- `get_children_blocks` now takes `Digest` ([258fdf6a](https://github.com/Neptune-Crypto/neptune-core/commit/258fdf6a))
- *(block)* Drop body hash from header ([bc4e3c14](https://github.com/Neptune-Crypto/neptune-core/commit/bc4e3c14))
- *(block)* Drop mutator set hash ([7821efe1](https://github.com/Neptune-Crypto/neptune-core/commit/7821efe1))
- Simplify `HasDiscriminant` trait ([78b9793a](https://github.com/Neptune-Crypto/neptune-core/commit/78b9793a))
- *(amount)* `Amount` -> `NeptuneCoins` ([99e8da6d](https://github.com/Neptune-Crypto/neptune-core/commit/99e8da6d))
- Use fold() in indices_to_hash_map() ([2309850c](https://github.com/Neptune-Crypto/neptune-core/commit/2309850c))
- Move cli args out of RwLock ([89ef48c2](https://github.com/Neptune-Crypto/neptune-core/commit/89ef48c2))
- Rename `native_coin` -> `native_currency` ([c3e8c939](https://github.com/Neptune-Crypto/neptune-core/commit/c3e8c939))
- Add `type_scripts` directory ([ac0637b9](https://github.com/Neptune-Crypto/neptune-core/commit/ac0637b9))
- Finish renaming ([e1bc0455](https://github.com/Neptune-Crypto/neptune-core/commit/e1bc0455))
- *(consensus)* Simplify `PrimitiveTransactionWitness` ([dc1dfcf7](https://github.com/Neptune-Crypto/neptune-core/commit/dc1dfcf7))
- Factor out inputs and outputs generation ([e903689f](https://github.com/Neptune-Crypto/neptune-core/commit/e903689f))
- Factor out valid output amounts finding ([66a94149](https://github.com/Neptune-Crypto/neptune-core/commit/66a94149))
- Wrap witness UTXOs with salt ([eda0fa86](https://github.com/Neptune-Crypto/neptune-core/commit/eda0fa86))
- Expand trait `SecretWitness` ([88c26dc6](https://github.com/Neptune-Crypto/neptune-core/commit/88c26dc6))
- *(Amounts)* Switch to u128 ([79933279](https://github.com/Neptune-Crypto/neptune-core/commit/79933279))
- *(Amounts)* Use `safe_add` ([477c378c](https://github.com/Neptune-Crypto/neptune-core/commit/477c378c))
- Integrate time-lock logic ([aea112f8](https://github.com/Neptune-Crypto/neptune-core/commit/aea112f8))
- Update `Network` enum ([809817bb](https://github.com/Neptune-Crypto/neptune-core/commit/809817bb))
- Make genesis block relative to `Network` ([4bc8c6ac](https://github.com/Neptune-Crypto/neptune-core/commit/4bc8c6ac))
- Harmonize timestamps ([9e55a5b6](https://github.com/Neptune-Crypto/neptune-core/commit/9e55a5b6))
- Kill traits `Mmr` and `MutatorSet` ([5acf2073](https://github.com/Neptune-Crypto/neptune-core/commit/5acf2073))
- Drop `MutatorSetKernel` ([343209ef](https://github.com/Neptune-Crypto/neptune-core/commit/343209ef))
- Remove sync methods in ArchivalMmr ([72a9fa6b](https://github.com/Neptune-Crypto/neptune-core/commit/72a9fa6b))
- Remove MPs as input to `batch_mutate_leaf_and_update_mps` for archival-MMR ([ac8be915](https://github.com/Neptune-Crypto/neptune-core/commit/ac8be915))
- Don't return peaks when getting MMR auth path from AMMR ([cae4b55e](https://github.com/Neptune-Crypto/neptune-core/commit/cae4b55e))
- Polish RPC API ([587e9eb5](https://github.com/Neptune-Crypto/neptune-core/commit/587e9eb5))
- *(test)* Update state through `GlobalState`'s `set_new_tip_internal` ([c64b7905](https://github.com/Neptune-Crypto/neptune-core/commit/c64b7905))
- Change type of CPU temperature to f32 ([2e086c31](https://github.com/Neptune-Crypto/neptune-core/commit/2e086c31))
- Improve on/off chain notice handling ([448e0ec1](https://github.com/Neptune-Crypto/neptune-core/commit/448e0ec1))
- Sender can specify change notify method ([682b47cd](https://github.com/Neptune-Crypto/neptune-core/commit/682b47cd))
- Prepare for Symmetric Key notifications ([9d2091e1](https://github.com/Neptune-Crypto/neptune-core/commit/9d2091e1))
- Move change outside create_transaction ([d5f20fe0](https://github.com/Neptune-Crypto/neptune-core/commit/d5f20fe0))
- Separate create_raw_tx, create_tx ([0612210c](https://github.com/Neptune-Crypto/neptune-core/commit/0612210c))
- Create Address enum ([c4f65687](https://github.com/Neptune-Crypto/neptune-core/commit/c4f65687))
- Create_transaction, tests compile but 5 fail ([76f8335e](https://github.com/Neptune-Crypto/neptune-core/commit/76f8335e))
- Add privacy_preimage to UtxoReceiver ([9e48306e](https://github.com/Neptune-Crypto/neptune-core/commit/9e48306e))
- Abstract over spending key type ([6195fa7c](https://github.com/Neptune-Crypto/neptune-core/commit/6195fa7c))
- TxInput, TxOutput ([a42aa19f](https://github.com/Neptune-Crypto/neptune-core/commit/a42aa19f))
- Make from_bech32() take &str ([d6b5daef](https://github.com/Neptune-Crypto/neptune-core/commit/d6b5daef))
- Simplify keys and utxo notifications ([a37f5ef8](https://github.com/Neptune-Crypto/neptune-core/commit/a37f5ef8))
- Atomic_rw requires &mut self ([8a87902f](https://github.com/Neptune-Crypto/neptune-core/commit/8a87902f))
- *(Block)* Add variant `DummyProof` to `BlockProof` ([75dc4974](https://github.com/Neptune-Crypto/neptune-core/commit/75dc4974))
- Move `RemovalRecordsIntegrity` out of `tasm` folder ([daf8415a](https://github.com/Neptune-Crypto/neptune-core/commit/daf8415a))
- Hide field `dictionary` on `ChunkDictionary` ([db2e79dc](https://github.com/Neptune-Crypto/neptune-core/commit/db2e79dc))
- *(`chunk_dictionary`)* Hide type of internal field ([c0ff03c1](https://github.com/Neptune-Crypto/neptune-core/commit/c0ff03c1))
- Change internal representation of `ChunksDictionary` ([44aaf4fa](https://github.com/Neptune-Crypto/neptune-core/commit/44aaf4fa))
- Add commitment randomness fields to `PrimitiveWitness` ([b300b207](https://github.com/Neptune-Crypto/neptune-core/commit/b300b207))
- Use `From` to cast witnesses ([a398a091](https://github.com/Neptune-Crypto/neptune-core/commit/a398a091))
- Add tx consensus program `CollectTypeScripts` ([3b48ee85](https://github.com/Neptune-Crypto/neptune-core/commit/3b48ee85))
- Add const `MAST_HEIGHT` on trait `MastHash` ([8988478e](https://github.com/Neptune-Crypto/neptune-core/commit/8988478e))
- *(consensus)* Add tasm code for `CollectLockScripts` ([0c8d0e9d](https://github.com/Neptune-Crypto/neptune-core/commit/0c8d0e9d))
- *(consensus)* Link `CoinbaseAmount` with `NativeCurrency` ([6eb6ea2e](https://github.com/Neptune-Crypto/neptune-core/commit/6eb6ea2e))
- Remove all references to MMR's MP-leaf-index ([db8eb164](https://github.com/Neptune-Crypto/neptune-core/commit/db8eb164))
- *(removal_records_integrity)* Factor out TASM for MAST hash checks ([54691084](https://github.com/Neptune-Crypto/neptune-core/commit/54691084))
- Remove use of MMR-membership proof's leaf index from TASM ([a3add519](https://github.com/Neptune-Crypto/neptune-core/commit/a3add519))
- Separate `LockScript` from `Utxo` ([7f4d07ef](https://github.com/Neptune-Crypto/neptune-core/commit/7f4d07ef))
- Drop unused function ([24aed203](https://github.com/Neptune-Crypto/neptune-core/commit/24aed203))
- Introduce and use const `Digest`s for subprogram hashes ([c4813bfb](https://github.com/Neptune-Crypto/neptune-core/commit/c4813bfb))
- Wrap `ProofCollection` into variant of new enum `SingleProof` ([62d05162](https://github.com/Neptune-Crypto/neptune-core/commit/62d05162))
- *(Tx Update)* Anticipate verifying an MMR extension ([c7181885](https://github.com/Neptune-Crypto/neptune-core/commit/c7181885))
- *(removal_records_integrity)* Only initialize memory with needed fields ([27e2c123](https://github.com/Neptune-Crypto/neptune-core/commit/27e2c123))
- *(removal_records_integrity)* Read swbfa from ND-stream ([174d36a5](https://github.com/Neptune-Crypto/neptune-core/commit/174d36a5))
- *(`ArchivalMMR`)* Drop generic type argument `<H>` ([987373e0](https://github.com/Neptune-Crypto/neptune-core/commit/987373e0))
- *(Tx Update)* Include AOCL MMR successor proof ([17b3e8fe](https://github.com/Neptune-Crypto/neptune-core/commit/17b3e8fe))
- Use rust more idiomatically in `verify` ([e245f926](https://github.com/Neptune-Crypto/neptune-core/commit/e245f926))
- Drop reverse with `VecDeque` in emulated Triton environment ([d9375e0b](https://github.com/Neptune-Crypto/neptune-core/commit/d9375e0b))
- Factor out claim assemblers ([1a7fcf20](https://github.com/Neptune-Crypto/neptune-core/commit/1a7fcf20))
- Factor out dup-digest-from-stack-and-reverse ([d3e84419](https://github.com/Neptune-Crypto/neptune-core/commit/d3e84419))
- *(SingleProof)* Factor out common tasm blobs ([17e4716e](https://github.com/Neptune-Crypto/neptune-core/commit/17e4716e))
- *(SingleProof)* Factor out instance of `load_digest` ([7ed55d8f](https://github.com/Neptune-Crypto/neptune-core/commit/7ed55d8f))
- *(Tx Consensus)* Relativize `Update` and `Merge` wrt `SingleProof` ([f6c08676](https://github.com/Neptune-Crypto/neptune-core/commit/f6c08676))
- Integrate `NewClaim` into `GenerateRriClaim` ([e3cbecda](https://github.com/Neptune-Crypto/neptune-core/commit/e3cbecda))
- *(`SingleProof`)* Use `GenerateRriClaim` ([58d4b4e3](https://github.com/Neptune-Crypto/neptune-core/commit/58d4b4e3))
- *(K2O)* Integrate `NewClaim` into `GenerateK2oClaim` ([e98d16b8](https://github.com/Neptune-Crypto/neptune-core/commit/e98d16b8))
- *(claims)* Move helper snippet `new_claim` to claims dir ([8755e29e](https://github.com/Neptune-Crypto/neptune-core/commit/8755e29e))
- Use type script claim template generator in `SingleProof` ([3ed77bb8](https://github.com/Neptune-Crypto/neptune-core/commit/3ed77bb8))
- *(`Update`)* Fix tasm verification of `SingleProof` ([f1a5901e](https://github.com/Neptune-Crypto/neptune-core/commit/f1a5901e))
- *(`TimeLock`)* Generate primitive witnesses with expired or active time locks ([618e3f4a](https://github.com/Neptune-Crypto/neptune-core/commit/618e3f4a))
- Convert MSA authentication snippet to `MemPreserver` trait ([f7c1674b](https://github.com/Neptune-Crypto/neptune-core/commit/f7c1674b))
- Remove unused snippet to hash removal records ([d877d60d](https://github.com/Neptune-Crypto/neptune-core/commit/d877d60d))
- Extract snippet “single proof claim” ([8a487649](https://github.com/Neptune-Crypto/neptune-core/commit/8a487649))
- Split RR hashing from set equality check ([9a5ca304](https://github.com/Neptune-Crypto/neptune-core/commit/9a5ca304))
- *(merge)* Use `ChainMap` for inputs ([5a857f0c](https://github.com/Neptune-Crypto/neptune-core/commit/5a857f0c))
- *(compute_indices)* Remove obsolete snippet ([4ddd9717](https://github.com/Neptune-Crypto/neptune-core/commit/4ddd9717))
- *(msa_and_records)* Move `split_by` to tests ([1eef8993](https://github.com/Neptune-Crypto/neptune-core/commit/1eef8993))
- *(create_transaction)* Allow caller to specify proving capability ([7cc44ae3](https://github.com/Neptune-Crypto/neptune-core/commit/7cc44ae3))
- *(Tx)* Enable updating txs with new blocks ([f05a49f3](https://github.com/Neptune-Crypto/neptune-core/commit/f05a49f3))
- Allow insertion of pw-backed txs into mempool ([a0d20bba](https://github.com/Neptune-Crypto/neptune-core/commit/a0d20bba))
- Stronger types in proof-fetching logic ([fc3e5b67](https://github.com/Neptune-Crypto/neptune-core/commit/fc3e5b67))
- Make clippy happy ([e4751951](https://github.com/Neptune-Crypto/neptune-core/commit/e4751951))
- Rename function to `new_native_currency` ([c83da55e](https://github.com/Neptune-Crypto/neptune-core/commit/c83da55e))
- Add function to extract `ExpectedUtxo`s ([3e900073](https://github.com/Neptune-Crypto/neptune-core/commit/3e900073))
- Move some test-case generaters under test-flag ([b9cc3924](https://github.com/Neptune-Crypto/neptune-core/commit/b9cc3924))
- Make all proving-functions `async` ([200453d8](https://github.com/Neptune-Crypto/neptune-core/commit/200453d8))
- Wallet updates now atomic with mempool ([82a9fc7a](https://github.com/Neptune-Crypto/neptune-core/commit/82a9fc7a))
- Remove un-needed Result<()> in mempool ([2940ee05](https://github.com/Neptune-Crypto/neptune-core/commit/2940ee05))
- Modify fork choice rule ([64e53300](https://github.com/Neptune-Crypto/neptune-core/commit/64e53300))
- Require minimum block time ([be54cf80](https://github.com/Neptune-Crypto/neptune-core/commit/be54cf80))
- Modify interface of `difficulty_control` ([84c4db25](https://github.com/Neptune-Crypto/neptune-core/commit/84c4db25))
- Use `Timestamp` for time intervals ([cc00882f](https://github.com/Neptune-Crypto/neptune-core/commit/cc00882f))
- Move difficulty control to separate file ([a5152ed5](https://github.com/Neptune-Crypto/neptune-core/commit/a5152ed5))
- Rename `difficulty_to_digest_threshold` to `target` ([c8bfdf12](https://github.com/Neptune-Crypto/neptune-core/commit/c8bfdf12))
- *(difficulty-adjustment)* Make PID adjustment multiplicative ([26c7645e](https://github.com/Neptune-Crypto/neptune-core/commit/26c7645e))
- *(difficulty-control)* Clamp error ([5843fe41](https://github.com/Neptune-Crypto/neptune-core/commit/5843fe41))
- Use new types `Difficulty` and `ProofOfWork` ([ce2361ba](https://github.com/Neptune-Crypto/neptune-core/commit/ce2361ba))
- *(difficulty-control)* Factor out mul by fixed point rational ([9d1a426f](https://github.com/Neptune-Crypto/neptune-core/commit/9d1a426f))
- *(Block)* Encapsulate fork choice rule into function ([7ba0f85c](https://github.com/Neptune-Crypto/neptune-core/commit/7ba0f85c))
- Move block program into separate file ([78932e8b](https://github.com/Neptune-Crypto/neptune-core/commit/78932e8b))
- Pull `TransferBlock` into separate file ([1158cf16](https://github.com/Neptune-Crypto/neptune-core/commit/1158cf16))
- Drop block consensus program `TransactionIsValid` ([5707fed3](https://github.com/Neptune-Crypto/neptune-core/commit/5707fed3))
- Dedicate function to hash-lock ([30079632](https://github.com/Neptune-Crypto/neptune-core/commit/30079632))
- Supply guesser fee argument to state updaters ([ff04f020](https://github.com/Neptune-Crypto/neptune-core/commit/ff04f020))
- Split guesser fee into time-locked and no-lock ([9e2d854f](https://github.com/Neptune-Crypto/neptune-core/commit/9e2d854f))
- Pass current block to mempool update ([8c0cced6](https://github.com/Neptune-Crypto/neptune-core/commit/8c0cced6))
- Job-queue improvements. ([843aa42d](https://github.com/Neptune-Crypto/neptune-core/commit/843aa42d))
- Use `MiningStatus` to track and display mining status ([621bda88](https://github.com/Neptune-Crypto/neptune-core/commit/621bda88))
- *(`Block`)* Reduce visibility of `mutator_set_accumulator` ([2a54b5e8](https://github.com/Neptune-Crypto/neptune-core/commit/2a54b5e8))
- Make block mutator set implicit ([a6324acd](https://github.com/Neptune-Crypto/neptune-core/commit/a6324acd))
- Distinguish between block-body-MSA and MSA-after-block ([fc91b17f](https://github.com/Neptune-Crypto/neptune-core/commit/fc91b17f))
- Drop guesser fee records from update interface ([5989885f](https://github.com/Neptune-Crypto/neptune-core/commit/5989885f))
- Drop reward for transactions ([54ace0c2](https://github.com/Neptune-Crypto/neptune-core/commit/54ace0c2))
- *(peer-loop)* Distinguish positive from negative sanctions ([655865e2](https://github.com/Neptune-Crypto/neptune-core/commit/655865e2))
- Maybe future-date Tx timestamp in block proposal ([ed9df050](https://github.com/Neptune-Crypto/neptune-core/commit/ed9df050))
- Remove deprecated duration macros ([ad273c5a](https://github.com/Neptune-Crypto/neptune-core/commit/ad273c5a))
- *(`MainLoopHandler`)* Encapsulate channel to miner ([25495f17](https://github.com/Neptune-Crypto/neptune-core/commit/25495f17))
- Reduce visibility of CLI args on `GlobalState` ([50784249](https://github.com/Neptune-Crypto/neptune-core/commit/50784249))
- Make TransactionKernel immutable ([19b5ac54](https://github.com/Neptune-Crypto/neptune-core/commit/19b5ac54))
- *(mempool)* Do not update primitive witnesses transactions ([51b87dc1](https://github.com/Neptune-Crypto/neptune-core/commit/51b87dc1))
- *(`NetworkingState`)* Drop proving capability ([9c21222d](https://github.com/Neptune-Crypto/neptune-core/commit/9c21222d))
- *(ConsensusProgram)* Take owned argument ([b6e4aebe](https://github.com/Neptune-Crypto/neptune-core/commit/b6e4aebe))
- Set defailt `network` CLI arg to `beta` ([1b724b60](https://github.com/Neptune-Crypto/neptune-core/commit/1b724b60))

### ✅ Testing

- *(block mmr)* Can prove block ancestry ([696facde](https://github.com/Neptune-Crypto/neptune-core/commit/696facde))
- Make test case less timing sensisitive ([9b13d608](https://github.com/Neptune-Crypto/neptune-core/commit/9b13d608))
- Add manual integration test scripts ([bda1fd1e](https://github.com/Neptune-Crypto/neptune-core/commit/bda1fd1e))
- Implement Arbitrary for `RootAndPaths` ([76a3aab8](https://github.com/Neptune-Crypto/neptune-core/commit/76a3aab8))
- Add struct `MmraAndMembershipProofs` WIP ([37cfe4f1](https://github.com/Neptune-Crypto/neptune-core/commit/37cfe4f1))
- Add test for `RootAndPaths` reaching max tree height ([a7e7df65](https://github.com/Neptune-Crypto/neptune-core/commit/a7e7df65))
- Ensure `RootAndPaths` panics for too-large indices ([1d7ff91b](https://github.com/Neptune-Crypto/neptune-core/commit/1d7ff91b))
- Fix `arbitrary_with` for `MmraAndMembershipProofs` ([b51333f2](https://github.com/Neptune-Crypto/neptune-core/commit/b51333f2))
- Implement `arbitrary_with` for `PrimitiveWitness` ([ddfa13cc](https://github.com/Neptune-Crypto/neptune-core/commit/ddfa13cc))
- Implement `arbitrary_with` for `TimeLockWitness` ([cd05d828](https://github.com/Neptune-Crypto/neptune-core/commit/cd05d828))
- Implement `arbitrary_with` for `MsaAndRecords` ([7d27ba14](https://github.com/Neptune-Crypto/neptune-core/commit/7d27ba14))
- Fix `arbitrary_with` for `MsaAndRecords` ([5b60c624](https://github.com/Neptune-Crypto/neptune-core/commit/5b60c624))
- Fix arbitrary for `PrimitiveWitness` ([64434d29](https://github.com/Neptune-Crypto/neptune-core/commit/64434d29))
- Add tests for `NativeCurrency` ([e7fc923f](https://github.com/Neptune-Crypto/neptune-core/commit/e7fc923f))
- Test that released tokens can be spent ([dabedd89](https://github.com/Neptune-Crypto/neptune-core/commit/dabedd89))
- Fix failing test ([22a9c78d](https://github.com/Neptune-Crypto/neptune-core/commit/22a9c78d))
- Implement `arbitrary_between` for `Timestamp` ([990cf777](https://github.com/Neptune-Crypto/neptune-core/commit/990cf777))
- Fixes broken doctests ([147c524c](https://github.com/Neptune-Crypto/neptune-core/commit/147c524c))
- Reduce size of all tests running more than 20 seconds in Mjolnir ([ac9f61c9](https://github.com/Neptune-Crypto/neptune-core/commit/ac9f61c9))
- Add test of AMMR's batch leaf mutation ([91bb776b](https://github.com/Neptune-Crypto/neptune-core/commit/91bb776b))
- Add test mined_block_has_proof_of_work ([bcb56952](https://github.com/Neptune-Crypto/neptune-core/commit/bcb56952))
- Test block timestamp repr time block mined ([318b7a20](https://github.com/Neptune-Crypto/neptune-core/commit/318b7a20))
- Delete bad helper function from test lib ([4e0e75d6](https://github.com/Neptune-Crypto/neptune-core/commit/4e0e75d6))
- Add mining difficulty regression test ([0458d773](https://github.com/Neptune-Crypto/neptune-core/commit/0458d773))
- Add utxo_receiver tests ([5dbb38e6](https://github.com/Neptune-Crypto/neptune-core/commit/5dbb38e6))
- Add send_to_many_test() ([0b499333](https://github.com/Neptune-Crypto/neptune-core/commit/0b499333))
- Add mod global_state_tests::restore_wallet ([a8272ad1](https://github.com/Neptune-Crypto/neptune-core/commit/a8272ad1))
- Add failing test for #172: ExpectedUtxo ([0663c687](https://github.com/Neptune-Crypto/neptune-core/commit/0663c687))
- *(mine_loop)* Fix tests wrt dropped `accumulate_transaction` ([152598f4](https://github.com/Neptune-Crypto/neptune-core/commit/152598f4))
- Fix tests in `state/mod.rs` wrt `accumulate_transaction` ([c3bef8e2](https://github.com/Neptune-Crypto/neptune-core/commit/c3bef8e2))
- Fix tests in `mempool.rs` re dropped `accumulate_transaction` ([32d1a7fa](https://github.com/Neptune-Crypto/neptune-core/commit/32d1a7fa))
- Fix stalling tests ([57783e8e](https://github.com/Neptune-Crypto/neptune-core/commit/57783e8e))
- Fix complex wallet state update test ([723a2263](https://github.com/Neptune-Crypto/neptune-core/commit/723a2263))
- Harden `KernelToOutputs` test ([52f50215](https://github.com/Neptune-Crypto/neptune-core/commit/52f50215))
- Add case generator for `PrimitiveWitness` with time locks ([372c7d0a](https://github.com/Neptune-Crypto/neptune-core/commit/372c7d0a))
- Test validity of primitive witness with time locks ([d49dbe1d](https://github.com/Neptune-Crypto/neptune-core/commit/d49dbe1d))
- Fix test for `CollectTypeScripts` ([d69ca2b9](https://github.com/Neptune-Crypto/neptune-core/commit/d69ca2b9))
- Harden tests for `NativeCurrency` ([76da2a77](https://github.com/Neptune-Crypto/neptune-core/commit/76da2a77))
- *(consensus)* Do not reverse digests in output ([590dc130](https://github.com/Neptune-Crypto/neptune-core/commit/590dc130))
- *(`PrimitiveWitness`)* Set arbitrary AOCL size to less than 2^63 ([fff8991e](https://github.com/Neptune-Crypto/neptune-core/commit/fff8991e))
- Add test for `SingleProof` with time-locked transaction ([a5ad1ef5](https://github.com/Neptune-Crypto/neptune-core/commit/a5ad1ef5))
- *(update)* Factor out witness-generation function ([3ef0663e](https://github.com/Neptune-Crypto/neptune-core/commit/3ef0663e))
- *(`Update`)* Ensure that mutator set is updated too ([0c58e069](https://github.com/Neptune-Crypto/neptune-core/commit/0c58e069))
- *(tx-update)* Add negative tests of `update` program ([6c6d4e77](https://github.com/Neptune-Crypto/neptune-core/commit/6c6d4e77))
- *(tx-update)* Add negative test of manipulated index sets ([20e74436](https://github.com/Neptune-Crypto/neptune-core/commit/20e74436))
- *(primitive_witness)* Add generator for tuple with matching MSAs ([84be7af5](https://github.com/Neptune-Crypto/neptune-core/commit/84be7af5))
- Verify matching outputs ([318f9fba](https://github.com/Neptune-Crypto/neptune-core/commit/318f9fba))
- *(SingleProof)* Test `Update` pathway to `SingleProof` ([c61d2f85](https://github.com/Neptune-Crypto/neptune-core/commit/c61d2f85))
- *(collect_type_scripts)* Fix confusing test ([ec94a8e6](https://github.com/Neptune-Crypto/neptune-core/commit/ec94a8e6))
- *(mempool)* Fix monster test ([da4d85e1](https://github.com/Neptune-Crypto/neptune-core/commit/da4d85e1))
- *(mine_loop)* Fix difficulty-adjustment test ([65b65835](https://github.com/Neptune-Crypto/neptune-core/commit/65b65835))
- Fix test checking archival MS rollback ([55826919](https://github.com/Neptune-Crypto/neptune-core/commit/55826919))
- Fetch proofs from proof-server if not found locally ([0f142f83](https://github.com/Neptune-Crypto/neptune-core/commit/0f142f83))
- *(mine_loop)* Fix timestamps ([19dbfca9](https://github.com/Neptune-Crypto/neptune-core/commit/19dbfca9))
- Verify no crash on proving-power-estimator ([11acbe04](https://github.com/Neptune-Crypto/neptune-core/commit/11acbe04))
- *(proof_server)* Attempt to send test-name to server on requests ([d9c2a90f](https://github.com/Neptune-Crypto/neptune-core/commit/d9c2a90f))
- Don't create expensive SingleProofs in mempool test ([13207aae](https://github.com/Neptune-Crypto/neptune-core/commit/13207aae))
- Add a proof server ([e162e0a6](https://github.com/Neptune-Crypto/neptune-core/commit/e162e0a6))
- Fix tests in `mine_loop.rs` ([52004512](https://github.com/Neptune-Crypto/neptune-core/commit/52004512))
- Fix broken test: flaky_mutator_set_test ([885641b8](https://github.com/Neptune-Crypto/neptune-core/commit/885641b8))
- Fix test `block_template_is_valid` ([a12ecdf3](https://github.com/Neptune-Crypto/neptune-core/commit/a12ecdf3))
- Speed up test of mempool proof-maintanence through updates ([061070f1](https://github.com/Neptune-Crypto/neptune-core/commit/061070f1))
- Specify proving capability `SingleProof` ([2b618409](https://github.com/Neptune-Crypto/neptune-core/commit/2b618409))
- Set proving capability to `SingleProof` ([a3fd2375](https://github.com/Neptune-Crypto/neptune-core/commit/a3fd2375))
- Fix `restore_wallet` tests by setting proving capacity ([a62ecd1d](https://github.com/Neptune-Crypto/neptune-core/commit/a62ecd1d))
- *(peer_loop)* Introduce ability to mock time ([9afad221](https://github.com/Neptune-Crypto/neptune-core/commit/9afad221))
- Fix a couple failing doc-tests ([b3a0bf0f](https://github.com/Neptune-Crypto/neptune-core/commit/b3a0bf0f))
- Add more blocks to reorganization test ([a6b54a3d](https://github.com/Neptune-Crypto/neptune-core/commit/a6b54a3d))
- *(mempool)* Test new method `most_dense_proof_collection` ([7fc160bc](https://github.com/Neptune-Crypto/neptune-core/commit/7fc160bc))
- *(proof_upgrader)* Add test of main loop's scheduled task for proof upgrades ([214642f4](https://github.com/Neptune-Crypto/neptune-core/commit/214642f4))
- *(hash_removal_record_index_sets)* Fix flaky test ([4136cb4a](https://github.com/Neptune-Crypto/neptune-core/commit/4136cb4a))
- Space blocks apart by minimum block time ([c9b2eb90](https://github.com/Neptune-Crypto/neptune-core/commit/c9b2eb90))
- *(difficulty-control)* Verify no-overflow ([8d031034](https://github.com/Neptune-Crypto/neptune-core/commit/8d031034))
- *(mempool)* Fix wrong timestamps ([94e1a8bf](https://github.com/Neptune-Crypto/neptune-core/commit/94e1a8bf))
- *(`PrimitiveWitness`)* Add arbitrary impl for Merging into Blocks ([08a02903](https://github.com/Neptune-Crypto/neptune-core/commit/08a02903))
- Add arbitrary generator for `BlockPrimitiveWitness` ([d6481694](https://github.com/Neptune-Crypto/neptune-core/commit/d6481694))
- Implement first block validity program (!) ([d840745b](https://github.com/Neptune-Crypto/neptune-core/commit/d840745b))
- Test graceful halt of `BlockProgram` ([89c26a42](https://github.com/Neptune-Crypto/neptune-core/commit/89c26a42))
- Fix test `mine_10_blocks_in_10_seconds` ([0b87c4d8](https://github.com/Neptune-Crypto/neptune-core/commit/0b87c4d8))
- Estimate block preparation time ([840ea2c0](https://github.com/Neptune-Crypto/neptune-core/commit/840ea2c0))
- Factor out helper for sequence of blocks ([75522311](https://github.com/Neptune-Crypto/neptune-core/commit/75522311))
- Use block sequence helper function ([de1312d1](https://github.com/Neptune-Crypto/neptune-core/commit/de1312d1))
- Support multi-user 'cargo test' on same machine ([a2d80cb6](https://github.com/Neptune-Crypto/neptune-core/commit/a2d80cb6))
- Define and use helper `make_mock_transaction_with_mutator_set_hash` ([8251e193](https://github.com/Neptune-Crypto/neptune-core/commit/8251e193))
- Add spawned_tasks_live_as_long_as_jobqueue ([14c294ba](https://github.com/Neptune-Crypto/neptune-core/commit/14c294ba))
- Fix test `network_response_is_consistent` ([b359091a](https://github.com/Neptune-Crypto/neptune-core/commit/b359091a))
- Update jobquee test, remove #[should_panic] ([3caf807f](https://github.com/Neptune-Crypto/neptune-core/commit/3caf807f))
- Fix flaky job-queue test ([5b1a5f62](https://github.com/Neptune-Crypto/neptune-core/commit/5b1a5f62))
- Trigger sanity check with negative test ([ecbcbe8f](https://github.com/Neptune-Crypto/neptune-core/commit/ecbcbe8f))
- Fix nasty off-by-one error in arbitrary impl ([b33a7683](https://github.com/Neptune-Crypto/neptune-core/commit/b33a7683))
- Kill magic constant ([f211f25f](https://github.com/Neptune-Crypto/neptune-core/commit/f211f25f))
- Fix wallet-balance test after changing block subsidy ([2b012788](https://github.com/Neptune-Crypto/neptune-core/commit/2b012788))
- Fix mempool-related test in CI ([2d48dd66](https://github.com/Neptune-Crypto/neptune-core/commit/2d48dd66))
- Fix test failure in CI ([761be764](https://github.com/Neptune-Crypto/neptune-core/commit/761be764))
- *(claim_utxo)* Ensure double registration does not change balance ([c4288ee2](https://github.com/Neptune-Crypto/neptune-core/commit/c4288ee2))
- *(Block)* Add test that double-spending blocks are rejected ([4746a778](https://github.com/Neptune-Crypto/neptune-core/commit/4746a778))

### ⏱ Benchmark

- Remove now-unneeded step in AMMR benchmark ([56e3bc12](https://github.com/Neptune-Crypto/neptune-core/commit/56e3bc12))
- Add benchmark for batch-mutation of leafs in AMMR ([3cbf59c4](https://github.com/Neptune-Crypto/neptune-core/commit/3cbf59c4))
- Add benchmark for `KernelToOutputs` ([c6e3de65](https://github.com/Neptune-Crypto/neptune-core/commit/c6e3de65))
- *(consensus)* Add benchmarks for script collectors ([94873783](https://github.com/Neptune-Crypto/neptune-core/commit/94873783))
- *(transaction)* Factor out profile-generator for consensus programs ([97dbcb2d](https://github.com/Neptune-Crypto/neptune-core/commit/97dbcb2d))
- Update benchmarks ([c0175c5c](https://github.com/Neptune-Crypto/neptune-core/commit/c0175c5c))
- Update consensus-benchmark results ([a2d980d2](https://github.com/Neptune-Crypto/neptune-core/commit/a2d980d2))
- Add removal record index set hashing bench ([11cbbc52](https://github.com/Neptune-Crypto/neptune-core/commit/11cbbc52))
- Update benchmarks ([a61a2c4c](https://github.com/Neptune-Crypto/neptune-core/commit/a61a2c4c))

### 🎨 Styling

- Rename crate::locks::sync to std ([ab579295](https://github.com/Neptune-Crypto/neptune-core/commit/ab579295))
- Remove '_async' from ArchivalMmr methods ([e88c7155](https://github.com/Neptune-Crypto/neptune-core/commit/e88c7155))
- Add `.vscode/settings.json` to `.gitignore` ([f54c68ea](https://github.com/Neptune-Crypto/neptune-core/commit/f54c68ea))
- Rename receiver_preimage ([9f3df51f](https://github.com/Neptune-Crypto/neptune-core/commit/9f3df51f))
- Clippy, fmt, docs ([8195bf43](https://github.com/Neptune-Crypto/neptune-core/commit/8195bf43))
- Rename var: utxo_receiver -> tx_output ([336f1ef9](https://github.com/Neptune-Crypto/neptune-core/commit/336f1ef9))
- UtxoReceiver -> TxOutput in comments ([15835596](https://github.com/Neptune-Crypto/neptune-core/commit/15835596))
- Is_wallet_utxo() -> can_unlock() ([4f1f0261](https://github.com/Neptune-Crypto/neptune-core/commit/4f1f0261))
- Replace 'thread' with 'task' ([8d302dcd](https://github.com/Neptune-Crypto/neptune-core/commit/8d302dcd))
- *(kernel_to_outputs)* Make linter happy ([fe062493](https://github.com/Neptune-Crypto/neptune-core/commit/fe062493))
- Make linter happy about removal record integrity file ([59419c6f](https://github.com/Neptune-Crypto/neptune-core/commit/59419c6f))
- *(removal_record_integrity)* Refactor imports ([c11848e7](https://github.com/Neptune-Crypto/neptune-core/commit/c11848e7))
- *(removal_record_integrity)* Add explicit types to Rust-shadow ([9322badf](https://github.com/Neptune-Crypto/neptune-core/commit/9322badf))
- Simplify directory structure ([9f67c3fb](https://github.com/Neptune-Crypto/neptune-core/commit/9f67c3fb))
- Complete simplification of directory structure ([78b3573c](https://github.com/Neptune-Crypto/neptune-core/commit/78b3573c))
- *(genesis_block)* Avoid mutable tx variablk ([6b2d21f9](https://github.com/Neptune-Crypto/neptune-core/commit/6b2d21f9))
- Name players in tests ([86a695ba](https://github.com/Neptune-Crypto/neptune-core/commit/86a695ba))
- Reduce visibility ([0b6f038d](https://github.com/Neptune-Crypto/neptune-core/commit/0b6f038d))
- Make clippy 1.83.0 happy ([0ee4db22](https://github.com/Neptune-Crypto/neptune-core/commit/0ee4db22))
- Replace `print` with use of logger ([1f570ec3](https://github.com/Neptune-Crypto/neptune-core/commit/1f570ec3))
- Make many `pub` functions `pub(crate)` ([0624a4ba](https://github.com/Neptune-Crypto/neptune-core/commit/0624a4ba))
- *(main_loop)* Rename timers and intervals ([259bf73e](https://github.com/Neptune-Crypto/neptune-core/commit/259bf73e))
- *(lib.rs)* Change logic for opening p2p TCP-listener ([a6a812f1](https://github.com/Neptune-Crypto/neptune-core/commit/a6a812f1))
- Make linter happy ([85ff54f3](https://github.com/Neptune-Crypto/neptune-core/commit/85ff54f3))
- Declare variables in using match-branch ([64484cb3](https://github.com/Neptune-Crypto/neptune-core/commit/64484cb3))
- *(difficulty-control)* Multiply fixed-length u32 arrays directly ([6d918ec8](https://github.com/Neptune-Crypto/neptune-core/commit/6d918ec8))
- Use idiomatic `OnceLock` for caching ([6deeeb04](https://github.com/Neptune-Crypto/neptune-core/commit/6deeeb04))
- Add `stop` method to `JobQueue` ([4a36ec54](https://github.com/Neptune-Crypto/neptune-core/commit/4a36ec54))
- Prover job returns thiserror style error ([608d21ef](https://github.com/Neptune-Crypto/neptune-core/commit/608d21ef))
- Rename ConsensusProgramProverJob ([e41ccc1e](https://github.com/Neptune-Crypto/neptune-core/commit/e41ccc1e))
- *(dashboard)* Hide useless stack trace ([3ed0946a](https://github.com/Neptune-Crypto/neptune-core/commit/3ed0946a))
- Drop unnecessary closure ([038ef6a7](https://github.com/Neptune-Crypto/neptune-core/commit/038ef6a7))
- Remove un-needed trait bound from impls ([3884b0a7](https://github.com/Neptune-Crypto/neptune-core/commit/3884b0a7))
- *(`Transaction`)* Move test constructor to test module ([d9058529](https://github.com/Neptune-Crypto/neptune-core/commit/d9058529))
- Fix many style issues ([5c7e1cd8](https://github.com/Neptune-Crypto/neptune-core/commit/5c7e1cd8))
- Happify clippy ([18602898](https://github.com/Neptune-Crypto/neptune-core/commit/18602898))
- *(dashboard)* Fix clippy complaint ([fb07e336](https://github.com/Neptune-Crypto/neptune-core/commit/fb07e336))
- *(ConsensusProgram)* Return early on error ([400aa9fe](https://github.com/Neptune-Crypto/neptune-core/commit/400aa9fe))
- Prefer `display()` over `to_string_lossy()` ([87057cf3](https://github.com/Neptune-Crypto/neptune-core/commit/87057cf3))

### 🛠 Build

- Upgrade h2 to version 0.3.24 in Cargo.lock ([d9b48c3a](https://github.com/Neptune-Crypto/neptune-core/commit/d9b48c3a))
- Cargo update; fix tarpc/tokio_serde deps ([59b4eed5](https://github.com/Neptune-Crypto/neptune-core/commit/59b4eed5))
- *(deps)* Bump mio from 0.8.10 to 0.8.11 ([17dd186d](https://github.com/Neptune-Crypto/neptune-core/commit/17dd186d))
- Cargo update and fix breakage ([eea86e01](https://github.com/Neptune-Crypto/neptune-core/commit/eea86e01))
- Use major.minor for all deps ([015e4dbf](https://github.com/Neptune-Crypto/neptune-core/commit/015e4dbf))
- Fix build errors for rustc 1.80 ([7ec96932](https://github.com/Neptune-Crypto/neptune-core/commit/7ec96932))
- Set flags to make Triton VM compilation fast(ish) ([c19dfcad](https://github.com/Neptune-Crypto/neptune-core/commit/c19dfcad))
- Set up binary artifact distribution ([#216](https://github.com/Neptune-Crypto/neptune-core/issues/216)) ([5b74c61c](https://github.com/Neptune-Crypto/neptune-core/commit/5b74c61c))
- Bump version ([4a415531](https://github.com/Neptune-Crypto/neptune-core/commit/4a415531))

### ⚙️ Miscellaneous

- Update tasm-lib to current master ([bf2c77bd](https://github.com/Neptune-Crypto/neptune-core/commit/bf2c77bd))
- *(mutator set)* Drop generic type argument ([c85273fa](https://github.com/Neptune-Crypto/neptune-core/commit/c85273fa))
- Implement arbitrary ([df00fe0f](https://github.com/Neptune-Crypto/neptune-core/commit/df00fe0f))
- Moving storage from twenty-first ([db800e5e](https://github.com/Neptune-Crypto/neptune-core/commit/db800e5e))
- Fix clippy 1.77 errors ([a8a47690](https://github.com/Neptune-Crypto/neptune-core/commit/a8a47690))
- Clippy, remove needless casts ([1c5e6c9d](https://github.com/Neptune-Crypto/neptune-core/commit/1c5e6c9d))
- Replace emojihash of latest block with timestamp of latest block. ([83c56e22](https://github.com/Neptune-Crypto/neptune-core/commit/83c56e22))
- Update to t-vm 0.40 twenty-first 0.40 ([a00aa939](https://github.com/Neptune-Crypto/neptune-core/commit/a00aa939))
- Adapt to MMR::verify() return value change ([c6e76f3d](https://github.com/Neptune-Crypto/neptune-core/commit/c6e76f3d))
- Upgrade to latest tasm-lib ([d46dfcb2](https://github.com/Neptune-Crypto/neptune-core/commit/d46dfcb2))
- Block.kernel.mast_hash() --> block.hash() ([c94a02bf](https://github.com/Neptune-Crypto/neptune-core/commit/c94a02bf))
- Log info in PeerMessage::BlockNotification ([10761a70](https://github.com/Neptune-Crypto/neptune-core/commit/10761a70))
- Log timestamp when new block is mined. ([64c46e86](https://github.com/Neptune-Crypto/neptune-core/commit/64c46e86))
- Use block_selector in neptune-cli header ([e4276d80](https://github.com/Neptune-Crypto/neptune-core/commit/e4276d80))
- Use twenty-first compat with blockexplorer ([5ef24236](https://github.com/Neptune-Crypto/neptune-core/commit/5ef24236))
- Cli wallet-status outputs pretty json ([e215cb05](https://github.com/Neptune-Crypto/neptune-core/commit/e215cb05))
- Add doctests to Makefile recipe ([80b3b34f](https://github.com/Neptune-Crypto/neptune-core/commit/80b3b34f))
- Rename key types ([525d24de](https://github.com/Neptune-Crypto/neptune-core/commit/525d24de))
- Make NeptuneCoins more human friendly. ([7d2b89e8](https://github.com/Neptune-Crypto/neptune-core/commit/7d2b89e8))
- Canonicalize `use` statements ([733182a4](https://github.com/Neptune-Crypto/neptune-core/commit/733182a4))
- Cleanup consts, improve doc comments ([7ab26752](https://github.com/Neptune-Crypto/neptune-core/commit/7ab26752))
- *(consensus)* Progress on `NativeCurrency` ([674577d0](https://github.com/Neptune-Crypto/neptune-core/commit/674577d0))
- *(tasm-lib)* Update tasm-lib upstream to latest commit ([3b347659](https://github.com/Neptune-Crypto/neptune-core/commit/3b347659))
- Integrate reviewer feedback ([9fff18a5](https://github.com/Neptune-Crypto/neptune-core/commit/9fff18a5))
- Bump `tasm-lib` version ([90cfb1e4](https://github.com/Neptune-Crypto/neptune-core/commit/90cfb1e4))
- *(`SingleProof`)* Use claim generator snippets ([f56dc844](https://github.com/Neptune-Crypto/neptune-core/commit/f56dc844))
- *(`Update`)* Anticipate verifying an `MmrSuccessorProof` ([8c2b55cf](https://github.com/Neptune-Crypto/neptune-core/commit/8c2b55cf))
- Add makefile recipe for producing expensive proofs ([7e219529](https://github.com/Neptune-Crypto/neptune-core/commit/7e219529))
- Upgrade upstream tasm-lib ([715ed21c](https://github.com/Neptune-Crypto/neptune-core/commit/715ed21c))
- Upgrade upstream tasm-lib to get latest traits ([e384475e](https://github.com/Neptune-Crypto/neptune-core/commit/e384475e))
- Upgrade tasm-lib to fix bug in MMR successor proof snippet ([4478753d](https://github.com/Neptune-Crypto/neptune-core/commit/4478753d))
- Upgrade tasm-lib upstream ([bc130ef7](https://github.com/Neptune-Crypto/neptune-core/commit/bc130ef7))
- Update upstream `tasm-lib` ([38b507c2](https://github.com/Neptune-Crypto/neptune-core/commit/38b507c2))
- Update upstream tasm-lib to TVM 0.42-alpha10 ([28c87556](https://github.com/Neptune-Crypto/neptune-core/commit/28c87556))
- Upgrade upstream tasm-lib ([9a2af3f5](https://github.com/Neptune-Crypto/neptune-core/commit/9a2af3f5))
- Update upstream tasm-lib ([7dbd94fc](https://github.com/Neptune-Crypto/neptune-core/commit/7dbd94fc))
- Ignore proofs in `./test_data` ([1b288b6c](https://github.com/Neptune-Crypto/neptune-core/commit/1b288b6c))
- Audit preloaded data ([c446e7e7](https://github.com/Neptune-Crypto/neptune-core/commit/c446e7e7))
- Bump tasm-lib to TVM 0.42.1 ([35fc72b9](https://github.com/Neptune-Crypto/neptune-core/commit/35fc72b9))
- Delete `privacy` flag from CLI args ([f4ea5ec1](https://github.com/Neptune-Crypto/neptune-core/commit/f4ea5ec1))
- *(block)* Drop parameter `network` from `premine_distribution` ([0a12392b](https://github.com/Neptune-Crypto/neptune-core/commit/0a12392b))
- *(mutator-set)* Drop redundant bounds check ([a856b2f8](https://github.com/Neptune-Crypto/neptune-core/commit/a856b2f8))
- Update `Cargo.lock` ([26c83cad](https://github.com/Neptune-Crypto/neptune-core/commit/26c83cad))
- Change data model to allow non-standard lockscripts ([1c71167c](https://github.com/Neptune-Crypto/neptune-core/commit/1c71167c))
- Make latest rust version happy ([7b472ed3](https://github.com/Neptune-Crypto/neptune-core/commit/7b472ed3))
- Add field for tx-proof-upgrading timer ([e2abf6b1](https://github.com/Neptune-Crypto/neptune-core/commit/e2abf6b1))
- Skeleton for block proofs ([237ec263](https://github.com/Neptune-Crypto/neptune-core/commit/237ec263))
- Make linter happy ([926650f3](https://github.com/Neptune-Crypto/neptune-core/commit/926650f3))
- Skip load-dependent mining test ([b8b7f3ee](https://github.com/Neptune-Crypto/neptune-core/commit/b8b7f3ee))
- Disallow coinbase when tx has inputs ([#214](https://github.com/Neptune-Crypto/neptune-core/issues/214)) ([b08614c5](https://github.com/Neptune-Crypto/neptune-core/commit/b08614c5))
- Audit preloaded witness data ([ebdb760c](https://github.com/Neptune-Crypto/neptune-core/commit/ebdb760c))
- Add log-slow-write-lock crate feature ([76bafbb2](https://github.com/Neptune-Crypto/neptune-core/commit/76bafbb2))
- Change type of nonce to digest ([bbbc6caa](https://github.com/Neptune-Crypto/neptune-core/commit/bbbc6caa))
- Set guesser-fee fraction of block subsidy in coinbase tx ([1dff0fed](https://github.com/Neptune-Crypto/neptune-core/commit/1dff0fed))
- Accound for guesser-fee UTXOs when resyncing MS-MPs ([31322675](https://github.com/Neptune-Crypto/neptune-core/commit/31322675))
- Make linter happy ([ff2ca0fb](https://github.com/Neptune-Crypto/neptune-core/commit/ff2ca0fb))
- Make formatter happy ([8c3c77ac](https://github.com/Neptune-Crypto/neptune-core/commit/8c3c77ac))
- Only show whole seconds in Display ([40b2dfb4](https://github.com/Neptune-Crypto/neptune-core/commit/40b2dfb4))
- Log prover job start/end with random id. ([f173d30c](https://github.com/Neptune-Crypto/neptune-core/commit/f173d30c))
- Log job number in JobQueue ([6f4046df](https://github.com/Neptune-Crypto/neptune-core/commit/6f4046df))
- Log number of pending jobs in JobQueue ([93151447](https://github.com/Neptune-Crypto/neptune-core/commit/93151447))
- Include job duration field in log msg ([79ee090a](https://github.com/Neptune-Crypto/neptune-core/commit/79ee090a))
- Enable anyhow backtrace feature ([a8142d2e](https://github.com/Neptune-Crypto/neptune-core/commit/a8142d2e))
- Log job count when a job is added to queue ([2abf450c](https://github.com/Neptune-Crypto/neptune-core/commit/2abf450c))
- Change how queued jobs are counted ([5759cf20](https://github.com/Neptune-Crypto/neptune-core/commit/5759cf20))
- Spawn threads for proof-updates ([18467c40](https://github.com/Neptune-Crypto/neptune-core/commit/18467c40))
- `MutatorSetUpdateSequence` ([1edebfed](https://github.com/Neptune-Crypto/neptune-core/commit/1edebfed))
- SEt proving capability on CI machine ([9cd36164](https://github.com/Neptune-Crypto/neptune-core/commit/9cd36164))
- Use panic=abort for release and dev builds ([61db5d06](https://github.com/Neptune-Crypto/neptune-core/commit/61db5d06))
- Proving job returns anyhow::Result ([d9e3d317](https://github.com/Neptune-Crypto/neptune-core/commit/d9e3d317))
- Revert run-single-instance change ([8e45ee98](https://github.com/Neptune-Crypto/neptune-core/commit/8e45ee98))
- Rename script for parsing slow lock warnings ([a89c719d](https://github.com/Neptune-Crypto/neptune-core/commit/a89c719d))
- Run nodes with slow-locks features ([9ea13532](https://github.com/Neptune-Crypto/neptune-core/commit/9ea13532))
- Instrument Rpc::send_to_many_inner() ([c3d0b825](https://github.com/Neptune-Crypto/neptune-core/commit/c3d0b825))
- *(dashboard)* Show net balance delta for mempool transactions ([cff49534](https://github.com/Neptune-Crypto/neptune-core/commit/cff49534))
- Add script for logging lock events ([26e2fd02](https://github.com/Neptune-Crypto/neptune-core/commit/26e2fd02))
- Log duration when lock released ([1812a348](https://github.com/Neptune-Crypto/neptune-core/commit/1812a348))
- Log lock acquisition times ([5181f799](https://github.com/Neptune-Crypto/neptune-core/commit/5181f799))
- Log lock acquisition times ([0ec47ce6](https://github.com/Neptune-Crypto/neptune-core/commit/0ec47ce6))
- Allocate funds to premine recipients ([1981345b](https://github.com/Neptune-Crypto/neptune-core/commit/1981345b))
- Remove default impl of ConcensusProgram::hash() ([822ac7b1](https://github.com/Neptune-Crypto/neptune-core/commit/822ac7b1))
- Remove PartialEq - block_primitive_witness ([eb068b3a](https://github.com/Neptune-Crypto/neptune-core/commit/eb068b3a))
- Add option of claiming from raw string ([f2fcc925](https://github.com/Neptune-Crypto/neptune-core/commit/f2fcc925))
- Remove option to read ciphertext from stdin ([bc15bb2a](https://github.com/Neptune-Crypto/neptune-core/commit/bc15bb2a))
- Delete deprecated transaction_is_valid program ([236f9f1d](https://github.com/Neptune-Crypto/neptune-core/commit/236f9f1d))
- Return Result from send rpcs. ([53deffc1](https://github.com/Neptune-Crypto/neptune-core/commit/53deffc1))
- Upgrade to ratatui 0.29.0 and fix breakages ([90853e3d](https://github.com/Neptune-Crypto/neptune-core/commit/90853e3d))
- Simplify insufficient funds error message ([697d4cc1](https://github.com/Neptune-Crypto/neptune-core/commit/697d4cc1))

### ArchivalMutatorSet

- Fix get_mutator_set_update_to_tip ([#227](https://github.com/Neptune-Crypto/neptune-core/issues/227)) ([e506ea80](https://github.com/Neptune-Crypto/neptune-core/commit/e506ea80))

### ArchivalState

- Prevent block from being written to disk twice ([e356734d](https://github.com/Neptune-Crypto/neptune-core/commit/e356734d))
- Fix test of rollback-behavior ([70d281cf](https://github.com/Neptune-Crypto/neptune-core/commit/70d281cf))

### Block

- Improved error message on illegal coinbase amount ([f350bfc6](https://github.com/Neptune-Crypto/neptune-core/commit/f350bfc6))

### BlockPrimitiveWitness

- Disallow construction from inconsistent tx/predecessor block pair ([0c3faa7c](https://github.com/Neptune-Crypto/neptune-core/commit/0c3faa7c))

### CI

- Work-around for non-implemented TxProvingCapability::LockScript ([2dbbc7ab](https://github.com/Neptune-Crypto/neptune-core/commit/2dbbc7ab))

### ConsensusProgram

- Assert that all Merkle tree auth paths consumed ([e6d157f8](https://github.com/Neptune-Crypto/neptune-core/commit/e6d157f8))
- Require clean stack at halt ([0ad07f95](https://github.com/Neptune-Crypto/neptune-core/commit/0ad07f95))

### GlobalState

- Add test where same block is stored twice ([e7fd919d](https://github.com/Neptune-Crypto/neptune-core/commit/e7fd919d))
- Unwrap parent block on msmp-recovery ([3bd63de3](https://github.com/Neptune-Crypto/neptune-core/commit/3bd63de3))
- Move `shuffle_seed` function from mine_loop to global state ([ea8aa49d](https://github.com/Neptune-Crypto/neptune-core/commit/ea8aa49d))

### Makefile

- Don't overwrite tokio_unstable RUSTFLAGS value ([8453d243](https://github.com/Neptune-Crypto/neptune-core/commit/8453d243))

### Merge

- Add test of Merge with a coinbase transaction ([e5ceb4b9](https://github.com/Neptune-Crypto/neptune-core/commit/e5ceb4b9))

### PrimitiveWitness

- Fix missing field updates on update ([8881fa9e](https://github.com/Neptune-Crypto/neptune-core/commit/8881fa9e))
- Reduce AOCL leaf count in test-case generator ([6d921636](https://github.com/Neptune-Crypto/neptune-core/commit/6d921636))

### RPC-cli

- Add endpoint for number of expected UTXOs ([7f9ded9b](https://github.com/Neptune-Crypto/neptune-core/commit/7f9ded9b))

### SingleProof

- Add function to encapsulate proof production ([b53e17a7](https://github.com/Neptune-Crypto/neptune-core/commit/b53e17a7))
- Assign error IDs to some asserts ([9b5dd0f4](https://github.com/Neptune-Crypto/neptune-core/commit/9b5dd0f4))

### Transaction

- Move TransactionOutput from blockchain to wallet dir ([c685c6dc](https://github.com/Neptune-Crypto/neptune-core/commit/c685c6dc))

### TransactionProof

- Delete proof type invalid ([4dc9d653](https://github.com/Neptune-Crypto/neptune-core/commit/4dc9d653))

### TransferBlock

- Replace From<Block> into TryFrom<Block> ([a4157d39](https://github.com/Neptune-Crypto/neptune-core/commit/a4157d39))

### Update

- Expand on tests of tx-consensus program ([56742b01](https://github.com/Neptune-Crypto/neptune-core/commit/56742b01))
- Add error IDs to asserts ([4d0a21f6](https://github.com/Neptune-Crypto/neptune-core/commit/4d0a21f6))

### UtxoNotificationPayload

- Use dedicated structure in more fn interfaces ([b1ecdf7b](https://github.com/Neptune-Crypto/neptune-core/commit/b1ecdf7b))

### Add

- *(consensus)* Add rust source for `ProofCollection` validity ([b1301cfd](https://github.com/Neptune-Crypto/neptune-core/commit/b1301cfd))
- *(`SingleProof`)* Add claim template generator for lock scripts ([85b45d50](https://github.com/Neptune-Crypto/neptune-core/commit/85b45d50))
- Integrate lock script claim generator into `SingleProof` ([6da18240](https://github.com/Neptune-Crypto/neptune-core/commit/6da18240))
- Add type script claim template generator ([fbf25a32](https://github.com/Neptune-Crypto/neptune-core/commit/fbf25a32))
- Add builtin for verifying `MmrSuccessorProof`s ([2e50549d](https://github.com/Neptune-Crypto/neptune-core/commit/2e50549d))
- Verify 2 transactions in “merge” ([ba0fbee8](https://github.com/Neptune-Crypto/neptune-core/commit/ba0fbee8))
- Check integrity of to-be-merged inputs ([fec4bcf2](https://github.com/Neptune-Crypto/neptune-core/commit/fec4bcf2))
- *(Merge)* Verify new timestamp ([3f78bf7f](https://github.com/Neptune-Crypto/neptune-core/commit/3f78bf7f))
- *(Merge)* Verify mutator set hash agreement ([4fbef7dd](https://github.com/Neptune-Crypto/neptune-core/commit/4fbef7dd))
- *(merge)* Assert outputs are permuted merger ([dc81f9c0](https://github.com/Neptune-Crypto/neptune-core/commit/dc81f9c0))
- *(merge)* Assert announcements are merger ([37101d9a](https://github.com/Neptune-Crypto/neptune-core/commit/37101d9a))
- *(SingleProof)* Add support for Update -> SingleProof ([e685691b](https://github.com/Neptune-Crypto/neptune-core/commit/e685691b))
- *(SingleProof)* Write TASM for Update path ([9ae7ac6e](https://github.com/Neptune-Crypto/neptune-core/commit/9ae7ac6e))
- *(SingleProof)* Add support for `Merge` ([284d3eb8](https://github.com/Neptune-Crypto/neptune-core/commit/284d3eb8))
- Wrap fee into UTXO ([971d3754](https://github.com/Neptune-Crypto/neptune-core/commit/971d3754))

### Archival-mutator-set

- Read all chunks in one go ([43229280](https://github.com/Neptune-Crypto/neptune-core/commit/43229280))

### Archival-state

- Always set stored block as tip ([09b7f193](https://github.com/Neptune-Crypto/neptune-core/commit/09b7f193))

### Archival_mutator_set

- Verify initialized with correct AOCL leafs ([3d88d217](https://github.com/Neptune-Crypto/neptune-core/commit/3d88d217))

### Archival_state

- Fix failing test of MS-rollback ([3ddfa1c1](https://github.com/Neptune-Crypto/neptune-core/commit/3ddfa1c1))
- Derandomize test to reuse proofs ([6a5b0fac](https://github.com/Neptune-Crypto/neptune-core/commit/6a5b0fac))
- Add function to get ms-update data to tip ([0c7f8440](https://github.com/Neptune-Crypto/neptune-core/commit/0c7f8440))
- Handle guesser UTXOs in AMS updater ([55dc1baa](https://github.com/Neptune-Crypto/neptune-core/commit/55dc1baa))

### Claim_utxo

- Verify sender_randomness equality in wallet check ([2bacee41](https://github.com/Neptune-Crypto/neptune-core/commit/2bacee41))
- Handle scenario where UTXO is already spent ([18283238](https://github.com/Neptune-Crypto/neptune-core/commit/18283238))
- Add Raw option to sender documentation ([808876e6](https://github.com/Neptune-Crypto/neptune-core/commit/808876e6))

### Cleanup

- Remove old unused helper functions ([b36a5526](https://github.com/Neptune-Crypto/neptune-core/commit/b36a5526))

### Collect_lock_scripts

- Audit preloaded witness ([6c129f81](https://github.com/Neptune-Crypto/neptune-core/commit/6c129f81))

### Collect_type_scripts

- Audit preloaded data ([3562b6b1](https://github.com/Neptune-Crypto/neptune-core/commit/3562b6b1))

### Dashboard

- Remove unused test function, add Default impl ([06be015b](https://github.com/Neptune-Crypto/neptune-core/commit/06be015b))
- Show more information about mining process ([59d2a073](https://github.com/Neptune-Crypto/neptune-core/commit/59d2a073))

### Dashboard/mempool

- Show both negative and positive effect on balance ([13878e7c](https://github.com/Neptune-Crypto/neptune-core/commit/13878e7c))

### Debug

- Minimal failing example of Triton VM incompleteness ([a516db01](https://github.com/Neptune-Crypto/neptune-core/commit/a516db01))

### Deps

- Upgrade to latest version of `tasm-lib` ([d152de06](https://github.com/Neptune-Crypto/neptune-core/commit/d152de06))
- Point to newest version of `tasm-lib` ([ca0e1577](https://github.com/Neptune-Crypto/neptune-core/commit/ca0e1577))
- Point to new version of `tasm-lib` ([095aac4d](https://github.com/Neptune-Crypto/neptune-core/commit/095aac4d))
- Update `tasm-lib` rev ([5bed35c2](https://github.com/Neptune-Crypto/neptune-core/commit/5bed35c2))
- Bump dependency on `tasm-lib` ([5035629d](https://github.com/Neptune-Crypto/neptune-core/commit/5035629d))
- Bump `tasm-lib` rev ([6d4df6ca](https://github.com/Neptune-Crypto/neptune-core/commit/6d4df6ca))
- Update to new version of tasm-lib ([c6bba938](https://github.com/Neptune-Crypto/neptune-core/commit/c6bba938))
- Update version of `tasm-lib` ([73dc0e26](https://github.com/Neptune-Crypto/neptune-core/commit/73dc0e26))
- Update dependency on tasm-lib to 2024-09-06 ([df2954f0](https://github.com/Neptune-Crypto/neptune-core/commit/df2954f0))

### Devops

- Also lint tests in pre-commit hook ([40888890](https://github.com/Neptune-Crypto/neptune-core/commit/40888890))
- Ignore triton-tui artifacts ([152c9ae5](https://github.com/Neptune-Crypto/neptune-core/commit/152c9ae5))
- Use domain name for known proof server ([15d1f369](https://github.com/Neptune-Crypto/neptune-core/commit/15d1f369))
- `opt-level=3` for test profile ([8858abf2](https://github.com/Neptune-Crypto/neptune-core/commit/8858abf2))

### Devx

- *(`ArchivalState`)* Improve error message on block-file corruption ([e2d9b237](https://github.com/Neptune-Crypto/neptune-core/commit/e2d9b237))
- *(`main.rs`)* Return result of main's `block_on` ([abb754e0](https://github.com/Neptune-Crypto/neptune-core/commit/abb754e0))
- *(Makefile)* Remove unused stuff ([a9b4ed00](https://github.com/Neptune-Crypto/neptune-core/commit/a9b4ed00))
- Make failed VM run error readable ([28ce358f](https://github.com/Neptune-Crypto/neptune-core/commit/28ce358f))

### Drop

- Remove depracated source files ([677e985c](https://github.com/Neptune-Crypto/neptune-core/commit/677e985c))
- Deprecated variant of transaction `MultiClaimProof` ([abd7881f](https://github.com/Neptune-Crypto/neptune-core/commit/abd7881f))
- *(proof-abstractions)* Drop unused structs ([f4b91314](https://github.com/Neptune-Crypto/neptune-core/commit/f4b91314))

### Genesis_block

- Change RegTest time resolution to 7 days ([3f961355](https://github.com/Neptune-Crypto/neptune-core/commit/3f961355))

### Global_state

- Move function to add expected UTXOs to wallet state ([90bfb2d5](https://github.com/Neptune-Crypto/neptune-core/commit/90bfb2d5))

### Integration-test

- Only one client mines ([b8fdb6fa](https://github.com/Neptune-Crypto/neptune-core/commit/b8fdb6fa))

### Integration_tests

- Build before multiple `cargo run` ([d2690c23](https://github.com/Neptune-Crypto/neptune-core/commit/d2690c23))

### Log

- Make block-syncronization scheduled task less noisy ([55660978](https://github.com/Neptune-Crypto/neptune-core/commit/55660978))
- Implement `get_type` for MainToMiner messages ([bc9a09e0](https://github.com/Neptune-Crypto/neptune-core/commit/bc9a09e0))
- Inform user about which network they are on ([bceae04a](https://github.com/Neptune-Crypto/neptune-core/commit/bceae04a))

### Logs/integration-tests

- Don't delete timestamp from log msg ([a737335a](https://github.com/Neptune-Crypto/neptune-core/commit/a737335a))

### Main_loop

- Fix wrong task identifier ([741c4ddf](https://github.com/Neptune-Crypto/neptune-core/commit/741c4ddf))
- Run proof-upgrader in spawned task ([1892e4f1](https://github.com/Neptune-Crypto/neptune-core/commit/1892e4f1))
- Upgrade transaction-witnesses received from RPC server ([b0f6c617](https://github.com/Neptune-Crypto/neptune-core/commit/b0f6c617))
- Handle mempool tx-updating in spawned task ([ea83086c](https://github.com/Neptune-Crypto/neptune-core/commit/ea83086c))

### Mempool

- Clear all transactions on reorganizations ([11e12616](https://github.com/Neptune-Crypto/neptune-core/commit/11e12616))
- Add warning about caller-responsibility cf. future timestamps ([f5ce7f2c](https://github.com/Neptune-Crypto/neptune-core/commit/f5ce7f2c))
- Don't crash program on failure to update tx on new block ([91caa3fb](https://github.com/Neptune-Crypto/neptune-core/commit/91caa3fb))
- Allow insertion of proof collections ([a56f2e42](https://github.com/Neptune-Crypto/neptune-core/commit/a56f2e42))
- Change key used to identify transactions ([c17c31e7](https://github.com/Neptune-Crypto/neptune-core/commit/c17c31e7))
- Allow capping number of txs in mempool ([12c2a87b](https://github.com/Neptune-Crypto/neptune-core/commit/12c2a87b))
- Add methods to get proof-upgrade candidates ([9dd6a14e](https://github.com/Neptune-Crypto/neptune-core/commit/9dd6a14e))
- Allow caller to request only SingleProof-backed txs ([bce410eb](https://github.com/Neptune-Crypto/neptune-core/commit/bce410eb))
- Fix wrong answer about proof quality ([0eb613a0](https://github.com/Neptune-Crypto/neptune-core/commit/0eb613a0))
- Track which transaction are own ([8f866093](https://github.com/Neptune-Crypto/neptune-core/commit/8f866093))
- Always run update prover jobs with highest priority ([533f6dd4](https://github.com/Neptune-Crypto/neptune-core/commit/533f6dd4))
- Inform caller about update jobs, don't do them ([8dcd1eda](https://github.com/Neptune-Crypto/neptune-core/commit/8dcd1eda))

### Mine_loop

- Change mining-loop from while to do-while ([1d0603c9](https://github.com/Neptune-Crypto/neptune-core/commit/1d0603c9))
- Allow coinbase tx-fee to be non-zero ([8ced612c](https://github.com/Neptune-Crypto/neptune-core/commit/8ced612c))
- Spawn task for composing ([01eb7be9](https://github.com/Neptune-Crypto/neptune-core/commit/01eb7be9))
- Log more information from mined block ([e2cbc057](https://github.com/Neptune-Crypto/neptune-core/commit/e2cbc057))
- Use mpsc, not watch, channel from main_loop ([cfabe20a](https://github.com/Neptune-Crypto/neptune-core/commit/cfabe20a))
- Inject timestamp to `compose_block` ([4cfc7f96](https://github.com/Neptune-Crypto/neptune-core/commit/4cfc7f96))

### Mining_state

- Add unit to Display of duration ([df10a422](https://github.com/Neptune-Crypto/neptune-core/commit/df10a422))

### Mmr

- Add method `split_by_activity` to `AbsoluteIndexSet` ([71ea84cf](https://github.com/Neptune-Crypto/neptune-core/commit/71ea84cf))
- Use new method `split_by_activity` for MS-MP verification ([2d01f14a](https://github.com/Neptune-Crypto/neptune-core/commit/2d01f14a))
- Fix validation of removal records ([998ba577](https://github.com/Neptune-Crypto/neptune-core/commit/998ba577))

### Networking

- Use `--max-peers=0` to disallow all incoming peer connections ([b4d16236](https://github.com/Neptune-Crypto/neptune-core/commit/b4d16236))

### Peer_loop

- Use const boolean to indicate connection action ([eb702446](https://github.com/Neptune-Crypto/neptune-core/commit/eb702446))
- Use const booleans to indicate if connection should be closed ([3c413d7b](https://github.com/Neptune-Crypto/neptune-core/commit/3c413d7b))
- Add new type for p2p transaction communication ([87ed8515](https://github.com/Neptune-Crypto/neptune-core/commit/87ed8515))
- Prefer transactions of higher proof quality ([2a090723](https://github.com/Neptune-Crypto/neptune-core/commit/2a090723))
- Check if mempool contains tx with higher quality proof ([212d71ca](https://github.com/Neptune-Crypto/neptune-core/commit/212d71ca))
- Increase default tolerance to 1.000 ([8ef470ef](https://github.com/Neptune-Crypto/neptune-core/commit/8ef470ef))

### Peer_map

- Change field `last_seen` to `connection_established` ([a3a695d7](https://github.com/Neptune-Crypto/neptune-core/commit/a3a695d7))

### Peers

- Allow `max_peers` to be used to refuse incoming connections ([7bf999ec](https://github.com/Neptune-Crypto/neptune-core/commit/7bf999ec))

### Proof_abstractions

- Ensure dummy proof exists on server ([f751c0ea](https://github.com/Neptune-Crypto/neptune-core/commit/f751c0ea))

### Removal_records_integrity

- Audit preloaded data ([54be9c21](https://github.com/Neptune-Crypto/neptune-core/commit/54be9c21))

### Rename

- Directory `consensus` -> `proof_abstractions` ([512e13f8](https://github.com/Neptune-Crypto/neptune-core/commit/512e13f8))

### Rewrite

- *(removal_records_integrity)* Don't check for double-spend ([2023f6e8](https://github.com/Neptune-Crypto/neptune-core/commit/2023f6e8))

### Robustness

- Wrap update program in initand end state sanity check ([e2c8c201](https://github.com/Neptune-Crypto/neptune-core/commit/e2c8c201))

### Rpc_server

- Change return type of tx initiation to TransactionKernelId ([a9cdd724](https://github.com/Neptune-Crypto/neptune-core/commit/a9cdd724))

### Run-multiple-instances

- Adjust mining/composing roles ([33fbcfe6](https://github.com/Neptune-Crypto/neptune-core/commit/33fbcfe6))

### Security

- Stop replay attacks ([76ea5efb](https://github.com/Neptune-Crypto/neptune-core/commit/76ea5efb))

### Sub

- Put undetermined claims into appendix ([ecdf684a](https://github.com/Neptune-Crypto/neptune-core/commit/ecdf684a))

### Transaction

- Make single-proof updater take MsUpdate type, not block ([9055688d](https://github.com/Neptune-Crypto/neptune-core/commit/9055688d))

### Tx-consensus

- Add snippet for asserting RR index set equality ([c6efd7c2](https://github.com/Neptune-Crypto/neptune-core/commit/c6efd7c2))
- :merge: Fix recursive part of TASM-version ([a0f669f9](https://github.com/Neptune-Crypto/neptune-core/commit/a0f669f9))
- :merge: Validate fee ([f2d5275f](https://github.com/Neptune-Crypto/neptune-core/commit/f2d5275f))
- :merge: add coinbase-check to `merge` ([9d8b3dfa](https://github.com/Neptune-Crypto/neptune-core/commit/9d8b3dfa))
- Audit preloaded data of type scripts ([081d8a2c](https://github.com/Neptune-Crypto/neptune-core/commit/081d8a2c))

### Update

- Add more tests of the `update` tx-consensus program ([8a988df3](https://github.com/Neptune-Crypto/neptune-core/commit/8a988df3))

### Upstream

- Opt-level=3 for Triton VM ([6f6fbb25](https://github.com/Neptune-Crypto/neptune-core/commit/6f6fbb25))

### Ux

- Improve helpfulness of error message ([f879b7f0](https://github.com/Neptune-Crypto/neptune-core/commit/f879b7f0))
- *(export-seed-phrase)* Inform user about network and wallet file ([7f926709](https://github.com/Neptune-Crypto/neptune-core/commit/7f926709))

### Wallet

- Update wallet with block-induced mempool events ([19c76d22](https://github.com/Neptune-Crypto/neptune-core/commit/19c76d22))

### Wallet_state

- Avoid monitoring multiple copies of same UTXO ([f79ddda0](https://github.com/Neptune-Crypto/neptune-core/commit/f79ddda0))

### Wip

- Sync db writes by default, verify read checksums by default ([a667251b](https://github.com/Neptune-Crypto/neptune-core/commit/a667251b))
- Move more code into GlobalState, fix tests ([d9950363](https://github.com/Neptune-Crypto/neptune-core/commit/d9950363))
- Implement arbitrary for `PrimitiveWitness` for `Transaction` ([16c476f1](https://github.com/Neptune-Crypto/neptune-core/commit/16c476f1))
- Fix arbitrary for `PrimitiveWitness` ([b0d2cc8b](https://github.com/Neptune-Crypto/neptune-core/commit/b0d2cc8b))
- Test `arbitrary_with` for `TimeLockWitness` ([ec8dd094](https://github.com/Neptune-Crypto/neptune-core/commit/ec8dd094))
- Implement `NativeCurrency` type script ([d5008541](https://github.com/Neptune-Crypto/neptune-core/commit/d5008541))
- Make storage layer async. passes all tests except doctests ([698f6ad0](https://github.com/Neptune-Crypto/neptune-core/commit/698f6ad0))
- Remove util_types/sync ([ebce7b69](https://github.com/Neptune-Crypto/neptune-core/commit/ebce7b69))
- Add stub tasm code for `KernelToOutputs` ([df4665d9](https://github.com/Neptune-Crypto/neptune-core/commit/df4665d9))
- *(consensus)* Add stub tasm for `CollectTypeScripts` ([0f26b013](https://github.com/Neptune-Crypto/neptune-core/commit/0f26b013))
- *(consensus)* Make progress on `CollectTypeScripts` ([8660ff5e](https://github.com/Neptune-Crypto/neptune-core/commit/8660ff5e))
- *(consensus)* Finish tasm code for `NativeCurrency` ([be6323d5](https://github.com/Neptune-Crypto/neptune-core/commit/be6323d5))
- Add stub for `RemovalRecordsIntegrity` ([a4023e15](https://github.com/Neptune-Crypto/neptune-core/commit/a4023e15))
- *(consensus)* Make stub for `RemovalRecordsIntegrity` compile ([6dced985](https://github.com/Neptune-Crypto/neptune-core/commit/6dced985))
- *(consensus)* Advance `RemovalRecordIntegrity`; compute index set ([07b6d99d](https://github.com/Neptune-Crypto/neptune-core/commit/07b6d99d))
- *(consensus)* Add complete draft of `RemovalRecordsIntegrity` ([e32982b0](https://github.com/Neptune-Crypto/neptune-core/commit/e32982b0))
- *(RemovalRecordsIntegrity)* Use multiset eq from updated dependency ([d29097d6](https://github.com/Neptune-Crypto/neptune-core/commit/d29097d6))
- Track bug in `batch_update_from_addition` ([59b6e2c3](https://github.com/Neptune-Crypto/neptune-core/commit/59b6e2c3))
- Add case removal-records-integrity to single-proof tasm code ([a7d8f172](https://github.com/Neptune-Crypto/neptune-core/commit/a7d8f172))
- Debug `SingleProof` tasm stub ([4a022e56](https://github.com/Neptune-Crypto/neptune-core/commit/4a022e56))
- Determine "now" timestamp in arbitrary timelocked witness ([c7f4c9d6](https://github.com/Neptune-Crypto/neptune-core/commit/c7f4c9d6))

Note: (!) indicates a breaking change.
