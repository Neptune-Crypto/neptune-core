
## [0.1.2](https://github.com/Neptune-Crypto/neptune-core/compare/v0.1.1..v0.1.2) - 2025-02-12

### 🐛 Bug Fixes

- *(mempool)* Don't attempt to update tx with no inputs ([7601f08b](https://github.com/Neptune-Crypto/neptune-core/commit/7601f08b))

### ✅ Testing

- Verify that only 0.0.x versions are incompatible ([3fcc82ad](https://github.com/Neptune-Crypto/neptune-core/commit/3fcc82ad))

Note: (!) indicates a breaking change.

## [0.1.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.0.11..v0.1.0) - 2025-02-11

### ⚙️ Miscellaneous

- Set default CLI parameter network to "main" ([c551251f](https://github.com/Neptune-Crypto/neptune-core/commit/c551251f))

Note: (!) indicates a breaking change.

## [0.1.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.0.12..v0.1.0) - 2025-02-11

### ✨ Features

- Assert field pointer points into element ([171affda](https://github.com/Neptune-Crypto/neptune-core/commit/171affda))
- Record sent tx details in wallet ([96dd1f8d](https://github.com/Neptune-Crypto/neptune-core/commit/96dd1f8d))

### 🐛 Bug Fixes

- Descriptive error messages from send() rpc ([ac2597fc](https://github.com/Neptune-Crypto/neptune-core/commit/ac2597fc))
- Make trait `pub` to compile benchmarks again ([5b89d879](https://github.com/Neptune-Crypto/neptune-core/commit/5b89d879))
- *(`WalletState`)* Avoid unwrapping `None` ([c20b22f1](https://github.com/Neptune-Crypto/neptune-core/commit/c20b22f1))
- *(peer_loop)* Don't spam sync challenges ([e189f215](https://github.com/Neptune-Crypto/neptune-core/commit/e189f215))
- Import-seed-phrase check if wallet db exists ([09c3a2ca](https://github.com/Neptune-Crypto/neptune-core/commit/09c3a2ca))
- *(Update)* Fix update branch after interface change ([e584d0ea](https://github.com/Neptune-Crypto/neptune-core/commit/e584d0ea))

### ♻️ Refactor

- Set genesis header nonce to hash of Bitcoin block 883345
- *(`BlockProgram`)* Avoid reading same value from memory twice ([68687e17](https://github.com/Neptune-Crypto/neptune-core/commit/68687e17))
- *(RPC)* Abort send if machine too weak ([abec5e27](https://github.com/Neptune-Crypto/neptune-core/commit/abec5e27))
- *(BlockProgram)* Restrict size indicator of proofs ([35426fbc](https://github.com/Neptune-Crypto/neptune-core/commit/35426fbc))
- *(`Block`)* Cap number of claims in appendix ([f1adbb30](https://github.com/Neptune-Crypto/neptune-core/commit/f1adbb30))
- *(SingleProof)* Audit PC witness at end of program ([90a5f83a](https://github.com/Neptune-Crypto/neptune-core/commit/90a5f83a))
- Adjust some genesis parameters ([cae5e5d9](https://github.com/Neptune-Crypto/neptune-core/commit/cae5e5d9))
- *(`RemovalRecordsIntegrity`)* Harden security ([b886b66e](https://github.com/Neptune-Crypto/neptune-core/commit/b886b66e))
- *(CollectLockScripts)* Harden program ([786b5693](https://github.com/Neptune-Crypto/neptune-core/commit/786b5693))
- *(KernelToOutputs)* Harden program ([bad7e47e](https://github.com/Neptune-Crypto/neptune-core/commit/bad7e47e))

### ✅ Testing

- Reduce initial difficulty for tests ([83eb8e17](https://github.com/Neptune-Crypto/neptune-core/commit/83eb8e17))

### 🎨 Styling

- Fix comments in SingleProof ([c883bba8](https://github.com/Neptune-Crypto/neptune-core/commit/c883bba8))

### ⚙️ Miscellaneous

- Update release workflow files ([f7a5779d](https://github.com/Neptune-Crypto/neptune-core/commit/f7a5779d))
- Build benchmarks ([a955bc9b](https://github.com/Neptune-Crypto/neptune-core/commit/a955bc9b))
- Change premine addresses ([dc8c3192](https://github.com/Neptune-Crypto/neptune-core/commit/dc8c3192))
- Update `tasm-lib` dependency to 0.47.0 ([1f9fe03b](https://github.com/Neptune-Crypto/neptune-core/commit/1f9fe03b))
- Upgrade dependencies ([8d2b2c79](https://github.com/Neptune-Crypto/neptune-core/commit/8d2b2c79))
- Store Utxo instead of UnlockedUtxo ([b39eea3d](https://github.com/Neptune-Crypto/neptune-core/commit/b39eea3d))
- Include aocl_leaf_index in SentTransaction ([484c15a2](https://github.com/Neptune-Crypto/neptune-core/commit/484c15a2))
- Fix clippy warning after rebase ([ad3eadbb](https://github.com/Neptune-Crypto/neptune-core/commit/ad3eadbb))

### Log

- Reduce severity of duration-check log message ([86076b02](https://github.com/Neptune-Crypto/neptune-core/commit/86076b02))

Note: (!) indicates a breaking change.

## [0.0.12](https://github.com/Neptune-Crypto/neptune-core/compare/v0.0.11..v0.0.12) - 2025-02-09

### ✨ Features

- Lossless Display for `NativeCurrencyAmount` ([#373](https://github.com/Neptune-Crypto/neptune-core/issues/373)) ([520adf0d](https://github.com/Neptune-Crypto/neptune-core/commit/520adf0d))
- Add fee field to dashboard send screen ([8e223a22](https://github.com/Neptune-Crypto/neptune-core/commit/8e223a22))

### 🐛 Bug Fixes

- Catch panics and flush databases ([c5b0b82e](https://github.com/Neptune-Crypto/neptune-core/commit/c5b0b82e))
- Enable n-out-of-n Shamir secret sharing ([24c3d431](https://github.com/Neptune-Crypto/neptune-core/commit/24c3d431))
- Debug_assert_fails test, release build ([d5ae197b](https://github.com/Neptune-Crypto/neptune-core/commit/d5ae197b))
- Get_panics_when_out_of_bounds test, release build ([920df503](https://github.com/Neptune-Crypto/neptune-core/commit/920df503))
- Fixes clippy dead-code warning ([f64263be](https://github.com/Neptune-Crypto/neptune-core/commit/f64263be))
- Remove dashboard balance discrepancy ([065ea4a5](https://github.com/Neptune-Crypto/neptune-core/commit/065ea4a5))
- *(`NativeCurrencyAmount`)* Propagate rounding carry ([bd2e0a84](https://github.com/Neptune-Crypto/neptune-core/commit/bd2e0a84))
- *(wallet)* Don't create transaction using UTXOs present in mempool ([d9428673](https://github.com/Neptune-Crypto/neptune-core/commit/d9428673))

### 🚀 Performance

- Add option to maintain empty tx in mempool ([554b5b12](https://github.com/Neptune-Crypto/neptune-core/commit/554b5b12))

### 📚 Documentation

- Add user guides ([9df047f4](https://github.com/Neptune-Crypto/neptune-core/commit/9df047f4))
- Update tokio-console instructions ([df0fa623](https://github.com/Neptune-Crypto/neptune-core/commit/df0fa623))

### ♻️ Refactor

- *(rpc_server)* Exclude 1st mined block from intervals list ([c29822b6](https://github.com/Neptune-Crypto/neptune-core/commit/c29822b6))
- *(peer)* Reduce message size to 500MB ([49bc9e7c](https://github.com/Neptune-Crypto/neptune-core/commit/49bc9e7c))
- (!) Make trait `ConsensusProgram` private ([b62e26f2](https://github.com/Neptune-Crypto/neptune-core/commit/b62e26f2))
- (!) *(ConsensusProgram)* Create test trait ([f1999e5e](https://github.com/Neptune-Crypto/neptune-core/commit/f1999e5e))
- (!) *(ConsensusProgram)* Make trait private ([287c29a1](https://github.com/Neptune-Crypto/neptune-core/commit/287c29a1))
- *(`mutator_set`)* Drop unused `Result` wrapper ([cfebce80](https://github.com/Neptune-Crypto/neptune-core/commit/cfebce80))
- *(`wallet`)* Change determination of "spent" UTXOs ([6dd28b20](https://github.com/Neptune-Crypto/neptune-core/commit/6dd28b20))
- *(wallet)* Use MSMP validity for compiling balance history ([0500af9d](https://github.com/Neptune-Crypto/neptune-core/commit/0500af9d))
- *(RPC)* Filter out spent UTXOs smarter ([7493d58c](https://github.com/Neptune-Crypto/neptune-core/commit/7493d58c))
- (!) Increase target block interval back to 9.8 minutes ([51d3dc95](https://github.com/Neptune-Crypto/neptune-core/commit/51d3dc95))
- *(`mine_loop`)* Inspect mempool after creating coinbase transaction ([a63af7d0](https://github.com/Neptune-Crypto/neptune-core/commit/a63af7d0))
- *(RPC)* Disallow sending negative-fee transactions ([aee78c84](https://github.com/Neptune-Crypto/neptune-core/commit/aee78c84))
- *(`peer_loop`)* Punish peers who send negative-fee transactions ([c30496e9](https://github.com/Neptune-Crypto/neptune-core/commit/c30496e9))
- *(`Block`)* Return dedicated error type from block validation ([e92eaaea](https://github.com/Neptune-Crypto/neptune-core/commit/e92eaaea))

### ✅ Testing

- De-duplicate testing functionality ([fa81df30](https://github.com/Neptune-Crypto/neptune-core/commit/fa81df30))
- Fix tests invalidated by disallowing update of 0-input txs ([f1375125](https://github.com/Neptune-Crypto/neptune-core/commit/f1375125))
- Fix amounts related to increased block time ([d8d8a8a8](https://github.com/Neptune-Crypto/neptune-core/commit/d8d8a8a8))
- Allow spending of UTXOs spent in orphaned block ([cbf1020b](https://github.com/Neptune-Crypto/neptune-core/commit/cbf1020b))

### 🎨 Styling

- Happify clippy ([fe3f60a1](https://github.com/Neptune-Crypto/neptune-core/commit/fe3f60a1))
- *(intialize)* Improve declaration ordering ([94255bc6](https://github.com/Neptune-Crypto/neptune-core/commit/94255bc6))
- Make async fn sync ([ac1373c7](https://github.com/Neptune-Crypto/neptune-core/commit/ac1373c7))
- Use tokio::try_join instead of futures ([865f70e4](https://github.com/Neptune-Crypto/neptune-core/commit/865f70e4))

### 🛠 Build

- Add tokio-console feature flag. ([d5cd1842](https://github.com/Neptune-Crypto/neptune-core/commit/d5cd1842))

### ⚙️ Miscellaneous

- Improve run-multiple script ([f630e27e](https://github.com/Neptune-Crypto/neptune-core/commit/f630e27e))
- Improve run-multiple-instances.sh ([9381f9e6](https://github.com/Neptune-Crypto/neptune-core/commit/9381f9e6))
- Normalize --port arg between rpc clients ([#378](https://github.com/Neptune-Crypto/neptune-core/issues/378)) ([99bedc7f](https://github.com/Neptune-Crypto/neptune-core/commit/99bedc7f))
- Update scripts to use --port ([f70b159d](https://github.com/Neptune-Crypto/neptune-core/commit/f70b159d))
- Update release workflow files ([401f4c29](https://github.com/Neptune-Crypto/neptune-core/commit/401f4c29))

### UI

- Disallow sending negative-fee transactions ([b694b125](https://github.com/Neptune-Crypto/neptune-core/commit/b694b125))

### Trace

- *(ProverJob)* More info about job complexity ([#366](https://github.com/Neptune-Crypto/neptune-core/issues/366)) ([557688e1](https://github.com/Neptune-Crypto/neptune-core/commit/557688e1))

Note: (!) indicates a breaking change.

## [0.0.11](https://github.com/Neptune-Crypto/neptune-core/compare/v0.0.10..v0.0.11) - 2025-01-31

### ✨ Features

- *(rpc_server)* Add basic statistics for block intervals ([37bc71cb](https://github.com/Neptune-Crypto/neptune-core/commit/37bc71cb))
- *(rpc_server)* Add endpoint for block difficulties ([b9835d89](https://github.com/Neptune-Crypto/neptune-core/commit/b9835d89))
- Key derivation ([8682a1eb](https://github.com/Neptune-Crypto/neptune-core/commit/8682a1eb))
- Dashboard support for deriving keys ([24660ca9](https://github.com/Neptune-Crypto/neptune-core/commit/24660ca9))
- Display symmetric key hash to avoid leaking secret ([6d1c660b](https://github.com/Neptune-Crypto/neptune-core/commit/6d1c660b))
- *(RpcServer)* Show block digests by height ([f5ee1b04](https://github.com/Neptune-Crypto/neptune-core/commit/f5ee1b04))
- *(CLI)* Add command to get block digests by height ([e33d2edd](https://github.com/Neptune-Crypto/neptune-core/commit/e33d2edd))
- Add is_canonical to block_info() RPC result ([3995e39d](https://github.com/Neptune-Crypto/neptune-core/commit/3995e39d))
- Add sibling_blocks to /block_info rpc ([0f0871bf](https://github.com/Neptune-Crypto/neptune-core/commit/0f0871bf))
- *(native-currency)* Add time-lock check in rust source ([867a9ac0](https://github.com/Neptune-Crypto/neptune-core/commit/867a9ac0))
- *(native-currency)* Time-lock half of coinbase ([da724fa3](https://github.com/Neptune-Crypto/neptune-core/commit/da724fa3))
- Harden native currency ([ecfbefe9](https://github.com/Neptune-Crypto/neptune-core/commit/ecfbefe9))
- Add constructor for fee-gobbler transaction details ([71f1cf62](https://github.com/Neptune-Crypto/neptune-core/commit/71f1cf62))
- *(proof_upgrader)* Sort jobs by profitability ([077ddcc7](https://github.com/Neptune-Crypto/neptune-core/commit/077ddcc7))
- *(proof_upgrader)* Gobble fees ([9eb941f3](https://github.com/Neptune-Crypto/neptune-core/commit/9eb941f3))
- *(merge)* Allow negative fees ([17c4a841](https://github.com/Neptune-Crypto/neptune-core/commit/17c4a841))
- *(native-currency)* Disallow coinbase with negative fee ([94c897ce](https://github.com/Neptune-Crypto/neptune-core/commit/94c897ce))
- /block_info rpc returns actual block reward ([5d4de110](https://github.com/Neptune-Crypto/neptune-core/commit/5d4de110))
- *(SingleProof)* Ensure merge bit retained in update-branch ([6787d595](https://github.com/Neptune-Crypto/neptune-core/commit/6787d595))
- *(SingleProof)* Verify merge bit set after merge ([bf7e49d2](https://github.com/Neptune-Crypto/neptune-core/commit/bf7e49d2))
- *(BlockProgram)* Verify that merge bit is set ([ba89f056](https://github.com/Neptune-Crypto/neptune-core/commit/ba89f056))
- *(mine_loop)* Merge nop-gobbler if no other txs available ([996701de](https://github.com/Neptune-Crypto/neptune-core/commit/996701de))
- *(mine_loop)* Graceful shutdown on composition failure ([ea6188e7](https://github.com/Neptune-Crypto/neptune-core/commit/ea6188e7))
- *(dashboard)* Show max num peers ([f4a564af](https://github.com/Neptune-Crypto/neptune-core/commit/f4a564af))
- *(archival_mmr)* Add function to get latest leaf ([2049e1bb](https://github.com/Neptune-Crypto/neptune-core/commit/2049e1bb))
- *(archival_mmr)* Add function to prune MMR to specified num leafs ([50088a47](https://github.com/Neptune-Crypto/neptune-core/commit/50088a47))
- *(archival_mmr)* Add try-get for leafs ([66ae10d1](https://github.com/Neptune-Crypto/neptune-core/commit/66ae10d1))
- *(archival_state)* Add archival block MMR ([fd9a10aa](https://github.com/Neptune-Crypto/neptune-core/commit/fd9a10aa))
- *(archival_state)* Use block MMR to determine canonicity ([0477832e](https://github.com/Neptune-Crypto/neptune-core/commit/0477832e))
- *(CLI)* Add command `nth-receiving-address` ([611b16d4](https://github.com/Neptune-Crypto/neptune-core/commit/611b16d4))
- *(CLI)* Add command `premine-receiving-address` ([9c1c4438](https://github.com/Neptune-Crypto/neptune-core/commit/9c1c4438))
- *(mine_loop)* Restart guesser every 20 seconds ([37695fd4](https://github.com/Neptune-Crypto/neptune-core/commit/37695fd4))
- *(peer_loop)* Challenge block notifications before syncing ([22a7ba75](https://github.com/Neptune-Crypto/neptune-core/commit/22a7ba75))
- *(rpc)* Cookie based authentication ([65b67e98](https://github.com/Neptune-Crypto/neptune-core/commit/65b67e98))
- *(global_state)* Allow storing of block that's not tip ([0f61d6ab](https://github.com/Neptune-Crypto/neptune-core/commit/0f61d6ab))
- *(archival_mmr)* Get MPs relative to smaller MMRs ([8a7f5e8e](https://github.com/Neptune-Crypto/neptune-core/commit/8a7f5e8e))
- *(`main_loop`)* Tolerate arbitrarily deep reorganizations ([ebcd3ab0](https://github.com/Neptune-Crypto/neptune-core/commit/ebcd3ab0))
- *(main_loop)* Add global timeout for sync mode ([5eb8d2fa](https://github.com/Neptune-Crypto/neptune-core/commit/5eb8d2fa))
- Add RustyArchivalBlockMmr for schema-access ([89f5a1c2](https://github.com/Neptune-Crypto/neptune-core/commit/89f5a1c2))
- *(`difficulty_control`)* Estimate max pow after n blocks ([f56e669d](https://github.com/Neptune-Crypto/neptune-core/commit/f56e669d))
- *(`peer_loop`)* Reject fishy PoW evolutions ([1ab0beec](https://github.com/Neptune-Crypto/neptune-core/commit/1ab0beec))
- Add Shamir secret sharing maths ([27ca2f05](https://github.com/Neptune-Crypto/neptune-core/commit/27ca2f05))
- CLI commands for Shamir secret sharing ([e65f6bac](https://github.com/Neptune-Crypto/neptune-core/commit/e65f6bac))

### 🐛 Bug Fixes

- Store known keys in HashSet to ensure unique ([e15e228e](https://github.com/Neptune-Crypto/neptune-core/commit/e15e228e))
- Reserve key 0 for coinbase transactions ([4927b432](https://github.com/Neptune-Crypto/neptune-core/commit/4927b432))
- *(PrimitiveWitness/Arbitrary)* Pick one: coinbase or inputs ([203a18ac](https://github.com/Neptune-Crypto/neptune-core/commit/203a18ac))
- Use `checked_add_negative` for adding potentially negative fee ([0a92e9d5](https://github.com/Neptune-Crypto/neptune-core/commit/0a92e9d5))
- *(native_currency)* Adjust some test-case generators relating to amounts ([7c2cc2ac](https://github.com/Neptune-Crypto/neptune-core/commit/7c2cc2ac))
- *(`Merge`)* Compare fee not hash of fee against max amount ([9efdbd3e](https://github.com/Neptune-Crypto/neptune-core/commit/9efdbd3e))
- Test `upgrade_proof_collection_to_single_proof_foreign_tx` ([7f41efe9](https://github.com/Neptune-Crypto/neptune-core/commit/7f41efe9))
- *(block)* Adjust block parameters to match 42.000.000 limit ([a4a8f7f5](https://github.com/Neptune-Crypto/neptune-core/commit/a4a8f7f5))
- *(docs)* Fix wrong number in docs about target block interval ([2a0538a3](https://github.com/Neptune-Crypto/neptune-core/commit/2a0538a3))
- *(test)* Test that premine does not exceed promise ([2eab824e](https://github.com/Neptune-Crypto/neptune-core/commit/2eab824e))
- Add arbitrary for coinbase ([1a302055](https://github.com/Neptune-Crypto/neptune-core/commit/1a302055))
- *(AuthenticateTxkField)* Account for merge bit ([0f13fbae](https://github.com/Neptune-Crypto/neptune-core/commit/0f13fbae))
- *(test)* Account for merge bit in more tests ([b22200c5](https://github.com/Neptune-Crypto/neptune-core/commit/b22200c5))
- Temporarily exceed max num peers when bootstrapping ([a05b581e](https://github.com/Neptune-Crypto/neptune-core/commit/a05b581e))
- *(mine_loop)* Recheck for connections every 5 seconds ([517bd194](https://github.com/Neptune-Crypto/neptune-core/commit/517bd194))
- Deserializing GenerationSpendingKey with serde_json ([3f4ddd14](https://github.com/Neptune-Crypto/neptune-core/commit/3f4ddd14))
- Remove panic when deriving key index > 0 ([ac35685c](https://github.com/Neptune-Crypto/neptune-core/commit/ac35685c))
- *(`PeerStanding`)* Include lower bound in standing test ([5c35dc10](https://github.com/Neptune-Crypto/neptune-core/commit/5c35dc10))
- *(wallet_state)* Avoid adding duplicate MUTXOs from different blocks ([cbe6122b](https://github.com/Neptune-Crypto/neptune-core/commit/cbe6122b))
- *(`WalletState`)* Filter out unspendable UTXOs before monitoring ([226a371c](https://github.com/Neptune-Crypto/neptune-core/commit/226a371c))
- *(`WalletState`)* Filter UTXOs for state validity ([ff4dcb00](https://github.com/Neptune-Crypto/neptune-core/commit/ff4dcb00))
- *(`WalletState`)* Avoid duplicate `MonitoredUTXO`s ([a0eb24bf](https://github.com/Neptune-Crypto/neptune-core/commit/a0eb24bf))
- *(Block::is_valid)* Fix false negative ([4d6b7013](https://github.com/Neptune-Crypto/neptune-core/commit/4d6b7013))
- *(`mine_loop`)* Segregate rayon threadpool for guessing ([#315](https://github.com/Neptune-Crypto/neptune-core/issues/315)) ([a1baa425](https://github.com/Neptune-Crypto/neptune-core/commit/a1baa425))
- Spawn task for block proof verification ([17fd4737](https://github.com/Neptune-Crypto/neptune-core/commit/17fd4737))
- *(neptune-cli)* Catch failed connection gracefully ([0abca09e](https://github.com/Neptune-Crypto/neptune-core/commit/0abca09e))
- *(`WalletState`)* Receive premine at multiple addresses ([27ec3d36](https://github.com/Neptune-Crypto/neptune-core/commit/27ec3d36))
- *(wallet_state)* Remove unneeded `mut` for key-getter ([ef0c76c2](https://github.com/Neptune-Crypto/neptune-core/commit/ef0c76c2))
- *(native_currency)* Update hardcoded program hash ([a607d105](https://github.com/Neptune-Crypto/neptune-core/commit/a607d105))
- *(verify_mmr_successor)* Update non-determinism ([19001aee](https://github.com/Neptune-Crypto/neptune-core/commit/19001aee))
- Percolate rename of CLI argument ([6115692d](https://github.com/Neptune-Crypto/neptune-core/commit/6115692d))
- Add end-of-page margin for random memory pointers ([b856e36b](https://github.com/Neptune-Crypto/neptune-core/commit/b856e36b))
- *(difficulty_control)* Add epsilon to function for upper-bounds on difficulty evolution ([847fa714](https://github.com/Neptune-Crypto/neptune-core/commit/847fa714))
- Update TIME_LOCK_HASH value ([77728617](https://github.com/Neptune-Crypto/neptune-core/commit/77728617))
- *(Block)* Restrict spending of guesser-fee UTXO ([b97cda33](https://github.com/Neptune-Crypto/neptune-core/commit/b97cda33))
- *(wallet_state)* Only register *one* hash-lock key per PoW-mined block ([e83aae39](https://github.com/Neptune-Crypto/neptune-core/commit/e83aae39))
- *(peer_loop)* Don't grab read lock twice ([6a1c2fe1](https://github.com/Neptune-Crypto/neptune-core/commit/6a1c2fe1))
- Cancel proving job if composing stops ([44d503b4](https://github.com/Neptune-Crypto/neptune-core/commit/44d503b4))
- Kill prover process directly ([27726379](https://github.com/Neptune-Crypto/neptune-core/commit/27726379))
- *(PeerInfo)* Use string for peer's version, not ArrayString ([27fa206b](https://github.com/Neptune-Crypto/neptune-core/commit/27fa206b))

### 🚀 Performance

- Serialize only 'seed' field of GenerationSpendingKey ([f84c59c8](https://github.com/Neptune-Crypto/neptune-core/commit/f84c59c8))
- *(mine_loop)* Faster PoW guessing ([edbff181](https://github.com/Neptune-Crypto/neptune-core/commit/edbff181))
- *(peer_loop)* Use archival block-MMR for faster batch-response ([10c3f3a9](https://github.com/Neptune-Crypto/neptune-core/commit/10c3f3a9))
- *(peer_loop)* Faster response to block request by height ([8cfd801a](https://github.com/Neptune-Crypto/neptune-core/commit/8cfd801a))
- Faster PoW guessing by precalculating MT auth paths ([5c5650b1](https://github.com/Neptune-Crypto/neptune-core/commit/5c5650b1))

### 📚 Documentation

- Clarify docstring for mutxo-pruning ([6154e890](https://github.com/Neptune-Crypto/neptune-core/commit/6154e890))
- *(Block)* Synchronize comments in validity check function ([76f089e6](https://github.com/Neptune-Crypto/neptune-core/commit/76f089e6))
- *(main_loop)* Information about main loop's data ([1d9e4e7f](https://github.com/Neptune-Crypto/neptune-core/commit/1d9e4e7f))
- Add docs page about documentation ([5d201d70](https://github.com/Neptune-Crypto/neptune-core/commit/5d201d70))
- *(archival_state)* Add comment about duplicated data ([651bb5b9](https://github.com/Neptune-Crypto/neptune-core/commit/651bb5b9))
- *(peer_loop)* Fix log-msg for batch-response ([983a06fb](https://github.com/Neptune-Crypto/neptune-core/commit/983a06fb))
- *(mine_loop)* Log block height when constructing block proposal ([eefc4947](https://github.com/Neptune-Crypto/neptune-core/commit/eefc4947))
- Fix broken links in documentation ([bae89de0](https://github.com/Neptune-Crypto/neptune-core/commit/bae89de0))
- Trace-log MUTXO info in wallet-updater ([0bb00862](https://github.com/Neptune-Crypto/neptune-core/commit/0bb00862))
- Clarify deficiency on race-condition in sync-challenge-response ([87dc4cb6](https://github.com/Neptune-Crypto/neptune-core/commit/87dc4cb6))
- Fix typo in comment. ([5b254f53](https://github.com/Neptune-Crypto/neptune-core/commit/5b254f53))
- *(rpc)* Add token/cookie auth example ([c185f8c5](https://github.com/Neptune-Crypto/neptune-core/commit/c185f8c5))
- *(rpc)* Fix doc-comment example compile error ([3afe2838](https://github.com/Neptune-Crypto/neptune-core/commit/3afe2838))
- Fix `cargo doc` warnings ([a24b647c](https://github.com/Neptune-Crypto/neptune-core/commit/a24b647c))
- *(archival_state)* Clarify that `store_block` doesn't write to DB ([144af4f6](https://github.com/Neptune-Crypto/neptune-core/commit/144af4f6))
- *(wallet_state)* Comment on lack of wallet-persisting for genesis block ([acc0d6ca](https://github.com/Neptune-Crypto/neptune-core/commit/acc0d6ca))
- Fix comment on why no wallet action on MempoolEvent::UpdateTxMutatorSet ([e3d8f1f0](https://github.com/Neptune-Crypto/neptune-core/commit/e3d8f1f0))
- Add user guide to installation ([ca3c02fb](https://github.com/Neptune-Crypto/neptune-core/commit/ca3c02fb))
- Add user guide on Shamir secret sharing ([802c2769](https://github.com/Neptune-Crypto/neptune-core/commit/802c2769))
- Fix typo ([a70464ae](https://github.com/Neptune-Crypto/neptune-core/commit/a70464ae))
- Add comment about allowed minimum value for sync-threshold ([68b62644](https://github.com/Neptune-Crypto/neptune-core/commit/68b62644))
- Fix link to tokio::sync::RwLock ([46dc1e54](https://github.com/Neptune-Crypto/neptune-core/commit/46dc1e54))
- Add "Two-Step Mining" ([bc539624](https://github.com/Neptune-Crypto/neptune-core/commit/bc539624))
- Remove link to private code from public interfaces ([50dd91bc](https://github.com/Neptune-Crypto/neptune-core/commit/50dd91bc))
- Fix doc tests ([4f26919a](https://github.com/Neptune-Crypto/neptune-core/commit/4f26919a))

### ♻️ Refactor

- *(`PrimitiveWitness`)* Time-lock half of coinbase ([b6c08ec4](https://github.com/Neptune-Crypto/neptune-core/commit/b6c08ec4))
- Integrate time-locked coinbase into mine pipeline ([be2feb01](https://github.com/Neptune-Crypto/neptune-core/commit/be2feb01))
- Specify proving capability ([b48f9622](https://github.com/Neptune-Crypto/neptune-core/commit/b48f9622))
- *(NeptuneCoins)* Change inner type to `i128` ([93efd2c5](https://github.com/Neptune-Crypto/neptune-core/commit/93efd2c5))
- *(neptune_coins)* Remove manual implementation of BFieldCodec ([fb80ac19](https://github.com/Neptune-Crypto/neptune-core/commit/fb80ac19))
- *(native-currency)* Add support for negative fees ([c4729a91](https://github.com/Neptune-Crypto/neptune-core/commit/c4729a91))
- *(native-currency)* Assert non-negativity of coinbase ([b4cdb7a1](https://github.com/Neptune-Crypto/neptune-core/commit/b4cdb7a1))
- *(native_currency)* Assert UTXO-coin amount legality ([a97fe00a](https://github.com/Neptune-Crypto/neptune-core/commit/a97fe00a))
- *(native_currency)* Assert valid coinbase discriminant ([81af76c4](https://github.com/Neptune-Crypto/neptune-core/commit/81af76c4))
- *(BlockProgram)* Assert fee-legality ([e3fa6696](https://github.com/Neptune-Crypto/neptune-core/commit/e3fa6696))
- *(block_program)* Factor out fee legality verification ([9813c6b7](https://github.com/Neptune-Crypto/neptune-core/commit/9813c6b7))
- Make all generation key fields private ([9033bfb8](https://github.com/Neptune-Crypto/neptune-core/commit/9033bfb8))
- *(mine_loop)* Only mine when connected to peers ([34d0f570](https://github.com/Neptune-Crypto/neptune-core/commit/34d0f570))
- *(TransactionKernel)* Add `merge_bit` ([fb736546](https://github.com/Neptune-Crypto/neptune-core/commit/fb736546))
- *(transaction)* Delete deprecated snippet ([0f6a695d](https://github.com/Neptune-Crypto/neptune-core/commit/0f6a695d))
- *(mine_loop)* Create state-less versions of tx-generators ([db5435f9](https://github.com/Neptune-Crypto/neptune-core/commit/db5435f9))
- Add 'arbitrary-impl' feature-flag ([d7256533](https://github.com/Neptune-Crypto/neptune-core/commit/d7256533))
- *(`TransactionDetails`)* Add and use nop-tx constructor ([5faac406](https://github.com/Neptune-Crypto/neptune-core/commit/5faac406))
- *(`proof_upgrader`)* Log error on failure; don't panic ([2f403002](https://github.com/Neptune-Crypto/neptune-core/commit/2f403002))
- *(mine_loop)* Avoid mutable variable for latest block ([8fb1a1bf](https://github.com/Neptune-Crypto/neptune-core/commit/8fb1a1bf))
- *(archival_state)* Don't crash on canonicity-check of unknown block ([558539f0](https://github.com/Neptune-Crypto/neptune-core/commit/558539f0))
- *(archival_state)* Delete unused methods ([78629f1f](https://github.com/Neptune-Crypto/neptune-core/commit/78629f1f))
- *(archival_state)* Delete method ([eaa82d08](https://github.com/Neptune-Crypto/neptune-core/commit/eaa82d08))
- *(single_proof)* Disallow update of coinbase-transactions ([3fca68bf](https://github.com/Neptune-Crypto/neptune-core/commit/3fca68bf))
- *(mempool)* Add merge bit to tx-kernel-id ([8907bf4c](https://github.com/Neptune-Crypto/neptune-core/commit/8907bf4c))
- *(mine_loop)* Factor out generation of composer parameters ([212bcc7b](https://github.com/Neptune-Crypto/neptune-core/commit/212bcc7b))
- *(SingleProof)* Allow update of transaction's timestamp ([04e247de](https://github.com/Neptune-Crypto/neptune-core/commit/04e247de))
- *(wallet_state)* Don't consume input for empty tx ([d595f030](https://github.com/Neptune-Crypto/neptune-core/commit/d595f030))
- *(cli_args)* Restrict visibility of fields ([45cef88d](https://github.com/Neptune-Crypto/neptune-core/commit/45cef88d))
- *(cli_args)* Increase default reorganization tolerance ([e491b2e0](https://github.com/Neptune-Crypto/neptune-core/commit/e491b2e0))
- Simplify guessing step ([e6a63258](https://github.com/Neptune-Crypto/neptune-core/commit/e6a63258))
- *(peer_loop)* Limit block-batch size to 250 ([3ab413ca](https://github.com/Neptune-Crypto/neptune-core/commit/3ab413ca))
- *(models::peer)* Move PeerBlockNotification to separate file ([44260b5d](https://github.com/Neptune-Crypto/neptune-core/commit/44260b5d))
- Add wrapper for `triton_vm::verify` ([85a79d5d](https://github.com/Neptune-Crypto/neptune-core/commit/85a79d5d))
- Use wrapper for `triton_vm::verify` ([e170c925](https://github.com/Neptune-Crypto/neptune-core/commit/e170c925))
- *(`mine_loop`)* Factor out coinbase transaction preparation ([11bfca65](https://github.com/Neptune-Crypto/neptune-core/commit/11bfca65))
- Create valid blocks with bogus proofs ([9534287d](https://github.com/Neptune-Crypto/neptune-core/commit/9534287d))
- *(peer_loop)* Validate `SyncChallenge` ([3b33a742](https://github.com/Neptune-Crypto/neptune-core/commit/3b33a742))
- *(peer_loop)* Don't allow syncing mode from handshake data alone ([1af153d7](https://github.com/Neptune-Crypto/neptune-core/commit/1af153d7))
- Remove data_dir from GlobalStateLock ([b8c3d0ca](https://github.com/Neptune-Crypto/neptune-core/commit/b8c3d0ca))
- *(peer_loop)* Verify block before adding to fork-reconciliation list ([05a5d8b1](https://github.com/Neptune-Crypto/neptune-core/commit/05a5d8b1))
- *(archival_mmr)* Move module out of mutator-set directory ([a601150c](https://github.com/Neptune-Crypto/neptune-core/commit/a601150c))
- *(`peer_loop`)* Reject responses with fishy difficulties ([05ad1be6](https://github.com/Neptune-Crypto/neptune-core/commit/05ad1be6))
- Add `SpendingKey` variant `RawHashLock` ([11883ffc](https://github.com/Neptune-Crypto/neptune-core/commit/11883ffc))
- *(wallet_state)* Replace list with Option for nonce-preimage ([1b897818](https://github.com/Neptune-Crypto/neptune-core/commit/1b897818))
- *(wallet)* Delete duplicated type AnnouncedUtxo ([bfd7d8f6](https://github.com/Neptune-Crypto/neptune-core/commit/bfd7d8f6))
- *(`SecretKeyMaterial`)* Move logic to new file ([db391f8d](https://github.com/Neptune-Crypto/neptune-core/commit/db391f8d))
- *(NativeCurrency)* Rename NeptuneCoins to NativeCurrencyAmount ([a2038ef9](https://github.com/Neptune-Crypto/neptune-core/commit/a2038ef9))
- *(archival_state)* Add block-hash witness to BlockRecord ([a54f749d](https://github.com/Neptune-Crypto/neptune-core/commit/a54f749d))
- *(mine_loop)* Avoid hardcoded array-lengths for auth paths ([38d90c24](https://github.com/Neptune-Crypto/neptune-core/commit/38d90c24))
- *(mast_hash)* Use sequential Merkle tree builder ([e1fdb65c](https://github.com/Neptune-Crypto/neptune-core/commit/e1fdb65c))
- Halve target block interval ([89c04cb7](https://github.com/Neptune-Crypto/neptune-core/commit/89c04cb7))
- *(`Block`)* Drop unused testing premine recipients ([419dc812](https://github.com/Neptune-Crypto/neptune-core/commit/419dc812))
- (!) Add `guesser_digest` to `BlockHeader` ([03359d56](https://github.com/Neptune-Crypto/neptune-core/commit/03359d56))
- Reduce futuredating limit to 5 minutes ([5a107c04](https://github.com/Neptune-Crypto/neptune-core/commit/5a107c04))
- Drop needless variable binding ([99c24a51](https://github.com/Neptune-Crypto/neptune-core/commit/99c24a51))
- *(SyncChallenge)* Don't check difficulties if own tip is genesis ([6fcbf4e8](https://github.com/Neptune-Crypto/neptune-core/commit/6fcbf4e8))
- *(peer)* Move `HandshakeData` to separate file ([50752a1a](https://github.com/Neptune-Crypto/neptune-core/commit/50752a1a))
- *(peer)* Move `PeerInfo` to own file ([050071db](https://github.com/Neptune-Crypto/neptune-core/commit/050071db))
- *(peer)* Use fixed-size string for version in handshake ([41615578](https://github.com/Neptune-Crypto/neptune-core/commit/41615578))
- (!) Add own timestamp to peer handshake ([487e8b33](https://github.com/Neptune-Crypto/neptune-core/commit/487e8b33))
- *(`HashLock`)* Factor out related functions and structs ([adee45c8](https://github.com/Neptune-Crypto/neptune-core/commit/adee45c8))
- Make guesser key deterministic ([eaaa2c33](https://github.com/Neptune-Crypto/neptune-core/commit/eaaa2c33))
- *(`HashLock`)* Drop convenience `From` implementations ([dfec62fe](https://github.com/Neptune-Crypto/neptune-core/commit/dfec62fe))

### ✅ Testing

- Validate we can send to symmetric keys ([cbc37454](https://github.com/Neptune-Crypto/neptune-core/commit/cbc37454))
- Add negative tests ([f1798368](https://github.com/Neptune-Crypto/neptune-core/commit/f1798368))
- *(mine_loop)* Add test that coinbase tx has timelocked/liquid outputs ([0cbbffbc](https://github.com/Neptune-Crypto/neptune-core/commit/0cbbffbc))
- *(mine_loop)* Account fox timelocked coinbase output in test ([35954def](https://github.com/Neptune-Crypto/neptune-core/commit/35954def))
- Re-randomize former proptest ([f0cadb5c](https://github.com/Neptune-Crypto/neptune-core/commit/f0cadb5c))
- *(native_currency)* Assert that expected asserts are hit ([b3720787](https://github.com/Neptune-Crypto/neptune-core/commit/b3720787))
- *(primitive_witness)* Fix test-case generators after timelocking cb ([6f2ba0a5](https://github.com/Neptune-Crypto/neptune-core/commit/6f2ba0a5))
- Add positive and negative tests for negative fees ([4dbb0f42](https://github.com/Neptune-Crypto/neptune-core/commit/4dbb0f42))
- Arbitrary non-negative `NeptuneCoins` ([d0df57cd](https://github.com/Neptune-Crypto/neptune-core/commit/d0df57cd))
- Update error ID allocation ([f97275e1](https://github.com/Neptune-Crypto/neptune-core/commit/f97275e1))
- Add proptest for fee gobbler ([54ffdea5](https://github.com/Neptune-Crypto/neptune-core/commit/54ffdea5))
- *(native_currency)* Verify negative fee and set coinbase is disallowed ([0f74c71b](https://github.com/Neptune-Crypto/neptune-core/commit/0f74c71b))
- *(native_currency)* Add proptest variant of deterministic test ([83d184de](https://github.com/Neptune-Crypto/neptune-core/commit/83d184de))
- Estimate multi-threaded hash rate ([f1e26c22](https://github.com/Neptune-Crypto/neptune-core/commit/f1e26c22))
- *(rpc_server)* Add test of tx with 0-n transaction outputs ([c22cfe41](https://github.com/Neptune-Crypto/neptune-core/commit/c22cfe41))
- *(SingleProof)* Verify behavior of set/unset merge_bit ([73db2547](https://github.com/Neptune-Crypto/neptune-core/commit/73db2547))
- *(mine_loop)* Account for merge-bit in test case generator ([4a64fcab](https://github.com/Neptune-Crypto/neptune-core/commit/4a64fcab))
- *(neptune_coins)* Fix ranges in proptest ([7383c883](https://github.com/Neptune-Crypto/neptune-core/commit/7383c883))
- Add tests to verify key/addr format and derivation ([8447875e](https://github.com/Neptune-Crypto/neptune-core/commit/8447875e))
- Don't do PoW if not needed ([86a55cc8](https://github.com/Neptune-Crypto/neptune-core/commit/86a55cc8))
- Mimic real blocks better in mock_block generator ([a92ec31c](https://github.com/Neptune-Crypto/neptune-core/commit/a92ec31c))
- Add failing test of double-registration of MUTXOs ([4064bb4c](https://github.com/Neptune-Crypto/neptune-core/commit/4064bb4c))
- *(`WalletState`)* Allow repeated addition records ([783a817d](https://github.com/Neptune-Crypto/neptune-core/commit/783a817d))
- *(archival_mmr)* Add panicking test for leaf-getter ([c3dfc352](https://github.com/Neptune-Crypto/neptune-core/commit/c3dfc352))
- Test legacy addresses for premine recipients ([546e5e5a](https://github.com/Neptune-Crypto/neptune-core/commit/546e5e5a))
- *(block)* Fix negative test of block validity/bad block MMRA value ([814627b4](https://github.com/Neptune-Crypto/neptune-core/commit/814627b4))
- Fix mempool test of reorganization/tx-updates ([b8d0f781](https://github.com/Neptune-Crypto/neptune-core/commit/b8d0f781))
- *(Block)* Verify validity for blocks with 0-10 inputs ([6ffa24b4](https://github.com/Neptune-Crypto/neptune-core/commit/6ffa24b4))
- Fix test of double-spend illegality ([0506c9d9](https://github.com/Neptune-Crypto/neptune-core/commit/0506c9d9))
- *(archival_state)* Fix flaky test about block rollbacks ([a4bb80f4](https://github.com/Neptune-Crypto/neptune-core/commit/a4bb80f4))
- *(mine_loop)* Verify fast mast-hash agrees with trait function ([aead0424](https://github.com/Neptune-Crypto/neptune-core/commit/aead0424))
- Don't drop receiver before iterations are done ([8b69daf2](https://github.com/Neptune-Crypto/neptune-core/commit/8b69daf2))
- Produce valid transactions with bogus proofs ([e363c896](https://github.com/Neptune-Crypto/neptune-core/commit/e363c896))
- Add test of sync challenge ([950112b2](https://github.com/Neptune-Crypto/neptune-core/commit/950112b2))
- *(global_state)* Verify that never-tip blocks can bridge to new tip ([2b21f26c](https://github.com/Neptune-Crypto/neptune-core/commit/2b21f26c))
- *(archival_mmr)* Test `prove_membership_relative_to_smaller_mmr` ([625ce19f](https://github.com/Neptune-Crypto/neptune-core/commit/625ce19f))
- *(archival_state)* Verify expected bounds of archival_block_mmr ([2f149132](https://github.com/Neptune-Crypto/neptune-core/commit/2f149132))
- Annotate snippet names with sign-off status ([e1d16736](https://github.com/Neptune-Crypto/neptune-core/commit/e1d16736))
- Sanity checks on max-future pow estimator ([8ce167fa](https://github.com/Neptune-Crypto/neptune-core/commit/8ce167fa))
- Add sanity checks on max-future pow estimator ([2c450291](https://github.com/Neptune-Crypto/neptune-core/commit/2c450291))
- Avoid magic constants ([aa42608c](https://github.com/Neptune-Crypto/neptune-core/commit/aa42608c))
- Don't run same test multiple times ([36875586](https://github.com/Neptune-Crypto/neptune-core/commit/36875586))
- Fix tests of key-properties ([32e215da](https://github.com/Neptune-Crypto/neptune-core/commit/32e215da))
- Ensure guesser-fee UTXO addition records are consistent ([58299f4a](https://github.com/Neptune-Crypto/neptune-core/commit/58299f4a))
- *(wallet_state)* Check timelock registration of PoW UTXOs ([bc795563](https://github.com/Neptune-Crypto/neptune-core/commit/bc795563))
- More tests of wallet's handling of guesser-UTXOs ([4a13881e](https://github.com/Neptune-Crypto/neptune-core/commit/4a13881e))
- Fix off-by-one error in sync-test ([fa3dc860](https://github.com/Neptune-Crypto/neptune-core/commit/fa3dc860))
- Add faster test that mine-loop's fast-hash is correct ([1577b09a](https://github.com/Neptune-Crypto/neptune-core/commit/1577b09a))
- Fix failing test related to guesser-preimages ([42b7e6f4](https://github.com/Neptune-Crypto/neptune-core/commit/42b7e6f4))
- Fix hardcoded parameters from consensus-changes ([4581b1eb](https://github.com/Neptune-Crypto/neptune-core/commit/4581b1eb))

### 🎨 Styling

- Check sanity of size indicators ([bcbf96e9](https://github.com/Neptune-Crypto/neptune-core/commit/bcbf96e9))
- Add conversion method for `NativeCurrencyWitness` ([7277ba13](https://github.com/Neptune-Crypto/neptune-core/commit/7277ba13))
- Rename for better descriptiveness ([3ad22fff](https://github.com/Neptune-Crypto/neptune-core/commit/3ad22fff))
- *(merge_branch)* Fix error codes ([ea706be5](https://github.com/Neptune-Crypto/neptune-core/commit/ea706be5))
- *(native_currency)* Simplify and document check ([11f93b64](https://github.com/Neptune-Crypto/neptune-core/commit/11f93b64))
- *(`mine_loop`)* Factor out composer parameters ([d64257c1](https://github.com/Neptune-Crypto/neptune-core/commit/d64257c1))
- Reduce visibility of arbitrary implementations ([763f4ce4](https://github.com/Neptune-Crypto/neptune-core/commit/763f4ce4))
- Happify clippy (rust v. 1.83) ([1b4cce48](https://github.com/Neptune-Crypto/neptune-core/commit/1b4cce48))
- Avoid async closures ([f7c816b6](https://github.com/Neptune-Crypto/neptune-core/commit/f7c816b6))
- Remove bad whitespace from premine table ([913dc23f](https://github.com/Neptune-Crypto/neptune-core/commit/913dc23f))
- *(Block)* Change derivation of current block's ms-field ([4cf6e18e](https://github.com/Neptune-Crypto/neptune-core/commit/4cf6e18e))
- Avoid needless iteration ([c3f1a8fe](https://github.com/Neptune-Crypto/neptune-core/commit/c3f1a8fe))
- Make linter happy ([a1edbd4f](https://github.com/Neptune-Crypto/neptune-core/commit/a1edbd4f))
- Apply PR feedback ([09671d03](https://github.com/Neptune-Crypto/neptune-core/commit/09671d03))
- Happify clippy ([b17e295c](https://github.com/Neptune-Crypto/neptune-core/commit/b17e295c))
- *(`peer_loop`)* Arrange message handlers in order of sequence ([7c807673](https://github.com/Neptune-Crypto/neptune-core/commit/7c807673))
- *(`cli_args`)* Rename CLI argument about sync threshold ([e26ba392](https://github.com/Neptune-Crypto/neptune-core/commit/e26ba392))
- *(`GlobalState`)* Rename criterion function ([2dd639c2](https://github.com/Neptune-Crypto/neptune-core/commit/2dd639c2))
- *(`peer_loop`)* Improve `try_ensure_path` readability ([3e88e47f](https://github.com/Neptune-Crypto/neptune-core/commit/3e88e47f))
- *(archival_state)* Rename variable ([ea380e9d](https://github.com/Neptune-Crypto/neptune-core/commit/ea380e9d))
- *(`Block`)* Rename `genesis_block` to `genesis` ([fd4652d3](https://github.com/Neptune-Crypto/neptune-core/commit/fd4652d3))
- Rename `HashLock` -> `HashLockKey` ([b7166043](https://github.com/Neptune-Crypto/neptune-core/commit/b7166043))

### 🛠 Build

- Fix build script for Windows ([aff9423c](https://github.com/Neptune-Crypto/neptune-core/commit/aff9423c))

### ⚙️ Miscellaneous

- Add proof-server explorer.neptune.cash ([b6f49c33](https://github.com/Neptune-Crypto/neptune-core/commit/b6f49c33))
- Upgrade tasm-lib dependency ([6f90dd53](https://github.com/Neptune-Crypto/neptune-core/commit/6f90dd53))
- Cargo fmt ([1297fd5a](https://github.com/Neptune-Crypto/neptune-core/commit/1297fd5a))
- Clippy too-many-args lint ([bd7accfc](https://github.com/Neptune-Crypto/neptune-core/commit/bd7accfc))
- Neptune-cli offline cmds accept network ([5a70cc73](https://github.com/Neptune-Crypto/neptune-core/commit/5a70cc73))
- Update benchmarks ([eb09fde1](https://github.com/Neptune-Crypto/neptune-core/commit/eb09fde1))
- Run clippy on all code ([b65c2119](https://github.com/Neptune-Crypto/neptune-core/commit/b65c2119))
- Don't lint nightly-specific feature ([953a93c2](https://github.com/Neptune-Crypto/neptune-core/commit/953a93c2))
- *(connect_to_peers)* Reduce log-noise on failed outgoing connections ([8eb547cf](https://github.com/Neptune-Crypto/neptune-core/commit/8eb547cf))
- Allocate funds to premine recipients ([88db6fef](https://github.com/Neptune-Crypto/neptune-core/commit/88db6fef))
- Make arbitrary and proptest an optional dependency ([4e68232e](https://github.com/Neptune-Crypto/neptune-core/commit/4e68232e))
- Add comment in Cargo.toml ([2418e2a6](https://github.com/Neptune-Crypto/neptune-core/commit/2418e2a6))
- Reject if documentation builds with warnings ([55014685](https://github.com/Neptune-Crypto/neptune-core/commit/55014685))
- Make linter happy ([0a083d89](https://github.com/Neptune-Crypto/neptune-core/commit/0a083d89))
- Delete unused trait and implementation ([7178cb9d](https://github.com/Neptune-Crypto/neptune-core/commit/7178cb9d))
- Happify clippy ([31bf6db2](https://github.com/Neptune-Crypto/neptune-core/commit/31bf6db2))
- Happify clippy ([6ffa0ee1](https://github.com/Neptune-Crypto/neptune-core/commit/6ffa0ee1))
- Update benchmarks ([55142de3](https://github.com/Neptune-Crypto/neptune-core/commit/55142de3))
- Happify clippy ([7e499ac3](https://github.com/Neptune-Crypto/neptune-core/commit/7e499ac3))

### Block

- Verify coinbase is not negative ([c48acb70](https://github.com/Neptune-Crypto/neptune-core/commit/c48acb70))

### Devops

- Lint code behind feature flag in precommit hook ([8b28ac6c](https://github.com/Neptune-Crypto/neptune-core/commit/8b28ac6c))
- Add more rules to pre-commit hook ([466a5b89](https://github.com/Neptune-Crypto/neptune-core/commit/466a5b89))

### Log

- *(peer-loop)* Verbosify logging in block handler ([d7854b24](https://github.com/Neptune-Crypto/neptune-core/commit/d7854b24))
- Add peer address to peer-loop log messages ([2eb6e588](https://github.com/Neptune-Crypto/neptune-core/commit/2eb6e588))
- Add peer address to peer-loop log messages ([638926ea](https://github.com/Neptune-Crypto/neptune-core/commit/638926ea))
- *(peer_discovery)* Debug-log if no candidate can be found ([0d9da62a](https://github.com/Neptune-Crypto/neptune-core/commit/0d9da62a))
- *(mine_loop)* Warn if not mining because no connections ([4a1117f2](https://github.com/Neptune-Crypto/neptune-core/commit/4a1117f2))
- *(`BlockProposal`)* Readably print guesser fee ([e0c2318b](https://github.com/Neptune-Crypto/neptune-core/commit/e0c2318b))
- *(peer_loop)* More info on bad block-requests-by-height ([522a669f](https://github.com/Neptune-Crypto/neptune-core/commit/522a669f))

### Ui

- *(`neptune-cli`)* Avoid stack trace dump ([1e6833ac](https://github.com/Neptune-Crypto/neptune-core/commit/1e6833ac))

Note: (!) indicates a breaking change.
