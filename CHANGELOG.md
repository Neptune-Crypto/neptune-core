## [0.6.1](https://github.com/Neptune-Crypto/neptune-core/compare/v0.6.0..v0.6.1) - 2026-02-14

### ✨ Features

- *(CLI)* Add command: version ([af87a8af](https://github.com/Neptune-Crypto/neptune-core/commit/af87a8af))
- *(CLI)* Add command: consolidate ([b51d4c55](https://github.com/Neptune-Crypto/neptune-core/commit/b51d4c55))

### 🐛 Bug Fixes

- Consolidate ([b51d4c55](https://github.com/Neptune-Crypto/neptune-core/commit/b51d4c55))

### ♻️ Refactor

- *(sync-loop)!* Proactively push status instead of responding ([8a452cfc](https://github.com/Neptune-Crypto/neptune-core/commit/8a452cfc))
- *(CLI)* Split commands into subcategories ([05a24d4a](https://github.com/Neptune-Crypto/neptune-core/commit/05a24d4a))

### ⚙️ Miscellaneous

- Add MSI installer ([837627d3](https://github.com/Neptune-Crypto/neptune-core/commit/837627d3), [daccbc93](https://github.com/Neptune-Crypto/neptune-core/commit/daccbc93))

### 🪵 Log

- Reduce noise ([d59dac78](https://github.com/Neptune-Crypto/neptune-core/commit/d59dac78), [743403cc](https://github.com/Neptune-Crypto/neptune-core/commit/743403cc), [08f3b46c](https://github.com/Neptune-Crypto/neptune-core/commit/08f3b46c), [ad588094](https://github.com/Neptune-Crypto/neptune-core/commit/ad588094), [41752652](https://github.com/Neptune-Crypto/neptune-core/commit/41752652))
- Report on number of own txs confirmed by block proposal ([65064aac](https://github.com/Neptune-Crypto/neptune-core/commit/65064aac))

## [0.6.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.5.0..v0.6.0) - 2026-02-03

### 🔱 Fork

- (!) Upgrade Triton VM to v2.0.0, with checkpoint ([0da19139](https://github.com/Neptune-Crypto/neptune-core/commit/0da19139))

### ✨ Features

- Libp2p Network Stack ([cfed34aa](https://github.com/Neptune-Crypto/neptune-core/commit/cfed34aa))
- *(rapid-block-download)* Integrate sync loop into main loop ([5002c9db](https://github.com/Neptune-Crypto/neptune-core/commit/5002c9db))
- *(sync_loop)* Sync from syncing peers ([29aa946e](https://github.com/Neptune-Crypto/neptune-core/commit/29aa946e))
- *(CLI)* Add command `no-resume-sync` to avoid resuming a previous sync ([b7429a43](https://github.com/Neptune-Crypto/neptune-core/commit/b7429a43))
- Tolerate reorgs and warn user about undeletable corrupt data ([9f4e51bd](https://github.com/Neptune-Crypto/neptune-core/commit/9f4e51bd))
- *(sync_loop)* Sync across forks ([9e95169c](https://github.com/Neptune-Crypto/neptune-core/commit/9e95169c))
- *(archival_state)* Add UTXO index ([885c44ec](https://github.com/Neptune-Crypto/neptune-core/commit/885c44ec))
- *(json_rpc)* Client crate and macro ([41f5db8a](https://github.com/Neptune-Crypto/neptune-core/commit/41f5db8a))
- *(dashboard)* Add clear peer standing endpoint to dashboard rpc ([46f38738](https://github.com/Neptune-Crypto/neptune-core/commit/46f38738))
- *(json_rpc)* Add methods for off-node wallets ([#777](https://github.com/Neptune-Crypto/neptune-core/issues/777)) ([90698b66](https://github.com/Neptune-Crypto/neptune-core/commit/90698b66))
- *(json_rpc)* Add `getBlockTemplate` and `submitBlock` to `mining` namespace ([bd6e5126](https://github.com/Neptune-Crypto/neptune-core/commit/bd6e5126))
- DbtMap without `remove` functionality ([ca22a315](https://github.com/Neptune-Crypto/neptune-core/commit/ca22a315))
- Compute and show max, circulating, and burned supply ([f8d5544c](https://github.com/Neptune-Crypto/neptune-core/commit/f8d5544c))
- Add JSON-RPC endpoints for supply methods ([8e8a444c](https://github.com/Neptune-Crypto/neptune-core/commit/8e8a444c))
- *(wallet)* Allow rescanning for outgoing/spent UTXOs ([f975a781](https://github.com/Neptune-Crypto/neptune-core/commit/f975a781))
- *(wallet)* Rescan for all expected UTXOs ([9756739c](https://github.com/Neptune-Crypto/neptune-core/commit/9756739c))
- *(wallet)* Rescan for guesser rewards ([e22e586b](https://github.com/Neptune-Crypto/neptune-core/commit/e22e586b))
- Add wallet rescanning endpoints to JSON RPC server ([cce9664b](https://github.com/Neptune-Crypto/neptune-core/commit/cce9664b))
- *(utxo_index)* Get block digests from announcement flags ([a4c12c3f](https://github.com/Neptune-Crypto/neptune-core/commit/a4c12c3f))
- *(JSON-RPC)* Add mempool endpoints ([#823](https://github.com/Neptune-Crypto/neptune-core/issues/823)) ([70c5141c](https://github.com/Neptune-Crypto/neptune-core/commit/70c5141c))
- *(rpc)* Check if absolute index set was applied ([e371f607](https://github.com/Neptune-Crypto/neptune-core/commit/e371f607))
- *(rpc)* Add tx-priority-related mempool endpoints ([2689fa5e](https://github.com/Neptune-Crypto/neptune-core/commit/2689fa5e))
- Consolidate UTXOs ([f5c30468](https://github.com/Neptune-Crypto/neptune-core/commit/f5c30468))
- *(block_claims)* Dump testnet block claims and add checkpoint for testnet ([9931efa5](https://github.com/Neptune-Crypto/neptune-core/commit/9931efa5))
- Roll back to checkpoint if current tip is not valid ([65ff55db](https://github.com/Neptune-Crypto/neptune-core/commit/65ff55db))

### 🐛 Bug Fixes

- Make test case generator agree across Linux/MacOS ([3be538fe](https://github.com/Neptune-Crypto/neptune-core/commit/3be538fe))
- Avoid crash in pseudorandom sampler for `NegativePeerSection` ([aaf114a9](https://github.com/Neptune-Crypto/neptune-core/commit/aaf114a9))
- *(dashboard)* Mock RPC call `latest-address` ([fcfa8caf](https://github.com/Neptune-Crypto/neptune-core/commit/fcfa8caf))
- *(wallet)* Set sync label on wallet-DB recovery if DB is new ([cf9a6bb2](https://github.com/Neptune-Crypto/neptune-core/commit/cf9a6bb2))
- *(mine_loop)* Off-by-one error in coinbase production ([80ff054e](https://github.com/Neptune-Crypto/neptune-core/commit/80ff054e))
- Clippy rule name ([576e204d](https://github.com/Neptune-Crypto/neptune-core/commit/576e204d))

### 🚀 Performance

- *(archival_state)* Avoid recalculating mutator set after ([3502739c](https://github.com/Neptune-Crypto/neptune-core/commit/3502739c))
- *(wallet)* Avoid linear search through all expected UTXOs ([c3d247e9](https://github.com/Neptune-Crypto/neptune-core/commit/c3d247e9))
- *(rapid-block-download)* Prefer `VecDeque` for `pop_front` ([dedb14a9](https://github.com/Neptune-Crypto/neptune-core/commit/dedb14a9))

### 📚 Documentation

- Fix incorrect MathJaX delimiters ([e089f9dc](https://github.com/Neptune-Crypto/neptune-core/commit/e089f9dc))
- Fix formatting errors in README ([1a355c88](https://github.com/Neptune-Crypto/neptune-core/commit/1a355c88))
- Explain that transparent txs are more expensive ([5c1c6ef2](https://github.com/Neptune-Crypto/neptune-core/commit/5c1c6ef2))
- Document required size of static allocation ([92102593](https://github.com/Neptune-Crypto/neptune-core/commit/92102593))
- *(peer_loop)* Motivate punishment policy ([fe29f9ab](https://github.com/Neptune-Crypto/neptune-core/commit/fe29f9ab))
- Add documentation of wallet rescan and UTXO index ([9e43b9b9](https://github.com/Neptune-Crypto/neptune-core/commit/9e43b9b9))
- Fix wrong docstring on sender randomness derivation ([dbf554b8](https://github.com/Neptune-Crypto/neptune-core/commit/dbf554b8))
- *(README.md)* Update ([a0e20631](https://github.com/Neptune-Crypto/neptune-core/commit/a0e20631))
- *(`releasing.md`)* Specify where to find versions to bump ([a8f4eef0](https://github.com/Neptune-Crypto/neptune-core/commit/a8f4eef0))

### 🔒️ Security

- Upgrade to ratatui 0.30 ([cfff4d71](https://github.com/Neptune-Crypto/neptune-core/commit/cfff4d71))

### ♻️ Refactor

- *(dashboard)* Move mock data to state instead of generating it in rpc functions ([84f1bdee](https://github.com/Neptune-Crypto/neptune-core/commit/84f1bdee))
- Harden and scrutinize bisection search for confirming block ([fd766928](https://github.com/Neptune-Crypto/neptune-core/commit/fd766928))
- Move and clarify const for mempool/tx-relay policy ([3e5f7361](https://github.com/Neptune-Crypto/neptune-core/commit/3e5f7361))
- Define fork reconciliation policy const in terms of consensus const ([db28953a](https://github.com/Neptune-Crypto/neptune-core/commit/db28953a))
- Drop fork reconciliation memory limit ([5b1fd041](https://github.com/Neptune-Crypto/neptune-core/commit/5b1fd041))
- (!) *(wallet)* Fast lookup from AOCL leaf index to `MonitoredUtxo` ([83490f3f](https://github.com/Neptune-Crypto/neptune-core/commit/83490f3f))
- *(sync)* Add data structures for sync loop ([8bb0bea8](https://github.com/Neptune-Crypto/neptune-core/commit/8bb0bea8))
- Add functionalities for rapid block download ([018afce7](https://github.com/Neptune-Crypto/neptune-core/commit/018afce7))
- *(peer_loop)* Modify height-tracker only if block handling success ([de778fa2](https://github.com/Neptune-Crypto/neptune-core/commit/de778fa2))
- Delete newly unused main-to-peer message `RequestBlockBatch` ([15a5befa](https://github.com/Neptune-Crypto/neptune-core/commit/15a5befa))
- *(sync-loop)* Punish unresponsive peers ([513f6595](https://github.com/Neptune-Crypto/neptune-core/commit/513f6595))
- (!) Drop deprecated struct `ClaimedSynchronizationState` ([22a2d9e1](https://github.com/Neptune-Crypto/neptune-core/commit/22a2d9e1))
- *(CLI)* Ignore bad standing when peer is CLI argument ([8f450e20](https://github.com/Neptune-Crypto/neptune-core/commit/8f450e20))
- *(archival_state)* Pass cli args to constructor ([846c52b5](https://github.com/Neptune-Crypto/neptune-core/commit/846c52b5))
- *(archival_state)* Improve state-update encapsulation ([31bf9b14](https://github.com/Neptune-Crypto/neptune-core/commit/31bf9b14))
- *(rpc)* Use Rpc type for announcement flag ([65c22dad](https://github.com/Neptune-Crypto/neptune-core/commit/65c22dad))
- *(peer-loop)* Validate sync block proof prior to relay ([d7003648](https://github.com/Neptune-Crypto/neptune-core/commit/d7003648))
- Default consensus rule set to TVM proof version 1 ([e5885195](https://github.com/Neptune-Crypto/neptune-core/commit/e5885195))

### ✅ Testing

- *(native_currency)* Harden check on coinbase term ([b18872e4](https://github.com/Neptune-Crypto/neptune-core/commit/b18872e4))
- *(native_currency)* Add test explaining why neg fee-txs dont cause inflation ([19991f76](https://github.com/Neptune-Crypto/neptune-core/commit/19991f76))
- *(json_rpc)* Add `solve` utility from metadata ([6b90f5eb](https://github.com/Neptune-Crypto/neptune-core/commit/6b90f5eb))
- Remove a redundant test and test roundtrip of Diff and Pow ([0af13688](https://github.com/Neptune-Crypto/neptune-core/commit/0af13688))
- *(wallet)* Real v1->v2 migration data ([b5e4a738](https://github.com/Neptune-Crypto/neptune-core/commit/b5e4a738))
- *(DbtVec)* Harden some tests of `clear` and `persist` ([06233632](https://github.com/Neptune-Crypto/neptune-core/commit/06233632))
- Implement pseudorandom sampler for `Block` ([4fa5d0c8](https://github.com/Neptune-Crypto/neptune-core/commit/4fa5d0c8))
- *(rapid-block-download)* Can retrieve blocks iff stored ([4a1d2614](https://github.com/Neptune-Crypto/neptune-core/commit/4a1d2614))
- *(rapid-block-download)* Verify that receiving all blocks completes the task ([821486aa](https://github.com/Neptune-Crypto/neptune-core/commit/821486aa))
- *(rapid-block-download)* Verify that receiving the same block twice is ok ([d0d7bb9d](https://github.com/Neptune-Crypto/neptune-core/commit/d0d7bb9d))
- *(rapid-block-download)* Add test about updating tip while syncing ([6c7a339e](https://github.com/Neptune-Crypto/neptune-core/commit/6c7a339e))
- *(rapid-block-download)* Test sync loop for good peers ([23380a05](https://github.com/Neptune-Crypto/neptune-core/commit/23380a05))
- Fix test; avoid overlapping memory objects ([30e346d0](https://github.com/Neptune-Crypto/neptune-core/commit/30e346d0))
- *(wallet)* More tests of rescan ([6660f408](https://github.com/Neptune-Crypto/neptune-core/commit/6660f408))
- *(utxo_index)* Verify behavior of block indexing method ([3409c6e5](https://github.com/Neptune-Crypto/neptune-core/commit/3409c6e5))
- Fix false negative in test ([5f6413ac](https://github.com/Neptune-Crypto/neptune-core/commit/5f6413ac))
- *(utxo_index)* Test all indexing functions ([2633c01e](https://github.com/Neptune-Crypto/neptune-core/commit/2633c01e))
- *(utxo_index)* Verify properties of addition_records_to_block_height ([ea9a1462](https://github.com/Neptune-Crypto/neptune-core/commit/ea9a1462))
- *(utxo_index)* Test abs index set -> block height mapper ([81355ee9](https://github.com/Neptune-Crypto/neptune-core/commit/81355ee9))
- Fix tests related to hard fork tvm proof v1 ([da342a2d](https://github.com/Neptune-Crypto/neptune-core/commit/da342a2d))

### ⏳ Benchmark

- *(wallet)* Add bigger case for wallet state update ([749f4bd9](https://github.com/Neptune-Crypto/neptune-core/commit/749f4bd9))
- *(wallet)* Add benchmark of wallet rescanning ([cbf3c429](https://github.com/Neptune-Crypto/neptune-core/commit/cbf3c429))

### 🎨 Styling

- Run `cargo fmt` and `clippy` ([a0780dea](https://github.com/Neptune-Crypto/neptune-core/commit/a0780dea))
- *(rapid-block-download)* Sanitize log output ([fc49ab6c](https://github.com/Neptune-Crypto/neptune-core/commit/fc49ab6c))
- Clarify function contract of `process_inputs_and_outputs_maintain_mps` ([5512fc16](https://github.com/Neptune-Crypto/neptune-core/commit/5512fc16))

### ⚙️ Miscellaneous

- Limit bincode frame size ([c2a2a09d](https://github.com/Neptune-Crypto/neptune-core/commit/c2a2a09d))
- Track and limit memory consumption in fork reconciliation procedure ([6c9736d1](https://github.com/Neptune-Crypto/neptune-core/commit/6c9736d1))
- Merge PR #825: Use clang instead of gcc and other fixes ([4c015275](https://github.com/Neptune-Crypto/neptune-core/commit/4c015275))
- Move unused test helper functions to test module ([2e02e39c](https://github.com/Neptune-Crypto/neptune-core/commit/2e02e39c))
- Force use of clang compiler bc leveldb-sys ([a49401fd](https://github.com/Neptune-Crypto/neptune-core/commit/a49401fd))
- Cargo update ([a8aafd91](https://github.com/Neptune-Crypto/neptune-core/commit/a8aafd91))
- Major-version upgrade some dependencies ([60aa0f86](https://github.com/Neptune-Crypto/neptune-core/commit/60aa0f86))
- Update release workflow files ([0d441327](https://github.com/Neptune-Crypto/neptune-core/commit/0d441327))

### 🪵 Log

- Inform miners about guesser fee of new tips ([e9cd2e83](https://github.com/Neptune-Crypto/neptune-core/commit/e9cd2e83))
- *(mempool)* Inform user about tx-notification sent after Updates ([3c459302](https://github.com/Neptune-Crypto/neptune-core/commit/3c459302))
- Avoid scaring user with warning of safety ([e5b0d0af](https://github.com/Neptune-Crypto/neptune-core/commit/e5b0d0af))
- Fine-grained timing when setting new tip ([82689374](https://github.com/Neptune-Crypto/neptune-core/commit/82689374))

### 🚥 Developer Experience

- Add installation instructions for MacOS ([8be03de9](https://github.com/Neptune-Crypto/neptune-core/commit/8be03de9))

### CI

- Run parallelism-unfriendly tests in sequence ([60ec2e2c](https://github.com/Neptune-Crypto/neptune-core/commit/60ec2e2c))

### JSON-RPC

- Add UTXO-related calls and `--unsafe-rpc` ([#763](https://github.com/Neptune-Crypto/neptune-core/issues/763)) ([a97b1798](https://github.com/Neptune-Crypto/neptune-core/commit/a97b1798))

### Neptune-cli

- Add support for wallet rescan ([bba3eb22](https://github.com/Neptune-Crypto/neptune-core/commit/bba3eb22))

### Sec

- Limit announcement size ([ff9de0d5](https://github.com/Neptune-Crypto/neptune-core/commit/ff9de0d5))


## [0.5.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.4.0..v0.5.0) - 2025-10-31

### 🔱 Fork
- (!) Change PoW algorithm to make proposal-switching free, from block height 15.000 ([85e6799c](https://github.com/Neptune-Crypto/neptune-core/commit/85e6799c))

### ✨ Features

- Add `block-notify` CLI flag option ([79bf1883](https://github.com/Neptune-Crypto/neptune-core/commit/79bf1883))
- Allow ignoring foreign block proposals ([e7c1cee1](https://github.com/Neptune-Crypto/neptune-core/commit/e7c1cee1))
- Never overwrite own block proposal ([204dab7e](https://github.com/Neptune-Crypto/neptune-core/commit/204dab7e))
- *(rpc_server)* Allow overriding the default coinbase distribution ([87649308](https://github.com/Neptune-Crypto/neptune-core/commit/87649308))
- *(mutator_set)* Privacy-preserving membership recovery ([a384f655](https://github.com/Neptune-Crypto/neptune-core/commit/a384f655))
- *(dashboard)* Add UTXOs screen ([404d70ee](https://github.com/Neptune-Crypto/neptune-core/commit/404d70ee))
- *(RPC)* Add endpoint `list-utxos` ([ea1d3921](https://github.com/Neptune-Crypto/neptune-core/commit/ea1d3921))
- *(peer_loop)* Avoid local IPs in peer discovery ([620d86b0](https://github.com/Neptune-Crypto/neptune-core/commit/620d86b0))
- *(rpc_server)* Add endpoint to return latest address ([489853b6](https://github.com/Neptune-Crypto/neptune-core/commit/489853b6))
- Refuse connection on bad timestamp ([bc59aee1](https://github.com/Neptune-Crypto/neptune-core/commit/bc59aee1))
- HTTP-JSON RPC framework ([b5eb3f4d](https://github.com/Neptune-Crypto/neptune-core/commit/b5eb3f4d))
- *(json_rpc)* Use hex separately on BFEs and add more tests ([342e4a58](https://github.com/Neptune-Crypto/neptune-core/commit/342e4a58))
- (!) Simplify block_selector ([0582128c](https://github.com/Neptune-Crypto/neptune-core/commit/0582128c))
- *(cli_args)* Add min relay per input for pc-backed txs ([65a935c1](https://github.com/Neptune-Crypto/neptune-core/commit/65a935c1))

### 🐛 Bug Fixes

- *(dashboard)* Correct sign error in mempool transactions ([2f8d3dc6](https://github.com/Neptune-Crypto/neptune-core/commit/2f8d3dc6))
- Ensure block data written before db ([#703](https://github.com/Neptune-Crypto/neptune-core/issues/703)) ([85f62003](https://github.com/Neptune-Crypto/neptune-core/commit/85f62003))
- *(mutator_set)* Undo destruction of AMS' batch_remove ([7e4b0813](https://github.com/Neptune-Crypto/neptune-core/commit/7e4b0813))
- *(Mempool)* Cover edge case for initiating Update ([91b9a3d6](https://github.com/Neptune-Crypto/neptune-core/commit/91b9a3d6))
- *(dashboard)* Don't bump key index when opening dashboard ([9c351360](https://github.com/Neptune-Crypto/neptune-core/commit/9c351360))

### 🚀 Performance

- *(archival_mutator_set)* Use batch-removal method to update archival mutator set ([105969b6](https://github.com/Neptune-Crypto/neptune-core/commit/105969b6))

### 📚 Documentation

- Update release protocol ([1dc5d787](https://github.com/Neptune-Crypto/neptune-core/commit/1dc5d787))
- Fix links ([688a4db4](https://github.com/Neptune-Crypto/neptune-core/commit/688a4db4))
- Fix links ([478ae60e](https://github.com/Neptune-Crypto/neptune-core/commit/478ae60e))
- *(rpc_server)* Add motivation for `generate_tx_details` endpoint ([f7759d78](https://github.com/Neptune-Crypto/neptune-core/commit/f7759d78))
- Add docstring explaining function signature ([a8d999c1](https://github.com/Neptune-Crypto/neptune-core/commit/a8d999c1))
- Update install instructions for the CLI ([e6cf54ff](https://github.com/Neptune-Crypto/neptune-core/commit/e6cf54ff))
- *(cli_args)* Fix wrong documentation of `block_notify` CLI flag ([60bf5899](https://github.com/Neptune-Crypto/neptune-core/commit/60bf5899))

### ♻️ Refactor

- *(dashboard)* Simplify mempool screen ([27f8b236](https://github.com/Neptune-Crypto/neptune-core/commit/27f8b236))
- *(peer_loop)* Reduce block batch size ([7e7091ba](https://github.com/Neptune-Crypto/neptune-core/commit/7e7091ba))
- *(`GuesserBuffer`)* Exfiltrate field `mast_auth_paths` ([84103015](https://github.com/Neptune-Crypto/neptune-core/commit/84103015))
- *(mine_loop)* Allow mining without peers if not on main net ([0b073146](https://github.com/Neptune-Crypto/neptune-core/commit/0b073146))

### ✅ Testing

- Verify that custom coinbase distribution is caught by wallet ([38ab4fa3](https://github.com/Neptune-Crypto/neptune-core/commit/38ab4fa3))
- *(dashboard)* Mock RPC interface from dashboard ([3f1c4e5b](https://github.com/Neptune-Crypto/neptune-core/commit/3f1c4e5b))
- *(native_currency)* Snippet used in total amount calculation ([7f68176b](https://github.com/Neptune-Crypto/neptune-core/commit/7f68176b))
- Reduce timeout of proof fetching from server ([85c3cf21](https://github.com/Neptune-Crypto/neptune-core/commit/85c3cf21))
- Verify node can handle hardfork-alpha transition ([3b7164f6](https://github.com/Neptune-Crypto/neptune-core/commit/3b7164f6))
- *(peer_loop)* Add hardfork-alpha test to peer_loop ([d13dba57](https://github.com/Neptune-Crypto/neptune-core/commit/d13dba57))
- Ensure main loop does not do verification ([63e35dc7](https://github.com/Neptune-Crypto/neptune-core/commit/63e35dc7))
- Verify bitreverse algorithm ([90662142](https://github.com/Neptune-Crypto/neptune-core/commit/90662142))
- *(peer_loop)* Harden harfork-alpha-related test ([cb8cbe9d](https://github.com/Neptune-Crypto/neptune-core/commit/cb8cbe9d))
- *(peer_loop)* Add two negative pow-related tests ([591520a1](https://github.com/Neptune-Crypto/neptune-core/commit/591520a1))
- *(pow)* Make pow-solver for tests deterministic ([33f473c7](https://github.com/Neptune-Crypto/neptune-core/commit/33f473c7))
- Verify that transactions work on HF-a rule set ([02c6a6d4](https://github.com/Neptune-Crypto/neptune-core/commit/02c6a6d4))
- Verify sanity of `relay_transaction` check ([e195382a](https://github.com/Neptune-Crypto/neptune-core/commit/e195382a))

### 🎨 Styling

- Delete a few redundant `From` implementations ([fb6e4ec1](https://github.com/Neptune-Crypto/neptune-core/commit/fb6e4ec1))

### ⚙️ Miscellaneous

- Add script to graph difficulties ([c401db32](https://github.com/Neptune-Crypto/neptune-core/commit/c401db32))
- Restructure directories related to benchmarks (1/2) ([a3ba7758](https://github.com/Neptune-Crypto/neptune-core/commit/a3ba7758))
- Move directory `models/state/` out one level ([6d465773](https://github.com/Neptune-Crypto/neptune-core/commit/6d465773))
- Move `config_models/` to `application/config/` ([e8ac131d](https://github.com/Neptune-Crypto/neptune-core/commit/e8ac131d))
- Move `database/` to `application/database/` ([41cc1397](https://github.com/Neptune-Crypto/neptune-core/commit/41cc1397))
- Move `job_queue/` to `application/job_queue/` ([d9b38edf](https://github.com/Neptune-Crypto/neptune-core/commit/d9b38edf))
- Move `locks/` to `application/locks/` ([cb170028](https://github.com/Neptune-Crypto/neptune-core/commit/cb170028))
- Create directory `application/control/` ([01a86542](https://github.com/Neptune-Crypto/neptune-core/commit/01a86542))
- Move RPC-related files to `application/rpc/` ([73adf2cd](https://github.com/Neptune-Crypto/neptune-core/commit/73adf2cd))
- Move files related to mining state to `state/mining/` ([4c92d610](https://github.com/Neptune-Crypto/neptune-core/commit/4c92d610))
- Create directory `state/transaction/` ([b2cce022](https://github.com/Neptune-Crypto/neptune-core/commit/b2cce022))
- Rename directory `application/control/` to `application/loops/` ([14769d80](https://github.com/Neptune-Crypto/neptune-core/commit/14769d80))
- Rename `models/` to `protocol/` and `blockchain/` to `consensus/` ([d4c6f94e](https://github.com/Neptune-Crypto/neptune-core/commit/d4c6f94e))
- Kill type alias for `Tip5` ([85448e07](https://github.com/Neptune-Crypto/neptune-core/commit/85448e07))
- Move `database.rs` to `state/` ([1510ef6a](https://github.com/Neptune-Crypto/neptune-core/commit/1510ef6a))
- Move `channel.rs` to `application/loops/` ([ee7fce2e](https://github.com/Neptune-Crypto/neptune-core/commit/ee7fce2e))
- Git-ignore developer-specific config file ([c217991e](https://github.com/Neptune-Crypto/neptune-core/commit/c217991e))
- Make `was_guessed_by` pub ([b3f5c2ad](https://github.com/Neptune-Crypto/neptune-core/commit/b3f5c2ad))
- Fix cmake version problem ([f3ede9e0](https://github.com/Neptune-Crypto/neptune-core/commit/f3ede9e0))
- Make const for premine size public ([c6b9a502](https://github.com/Neptune-Crypto/neptune-core/commit/c6b9a502))
- Update `dist` version and settings ([57e56462](https://github.com/Neptune-Crypto/neptune-core/commit/57e56462))
- Update release workflow files ([de14b622](https://github.com/Neptune-Crypto/neptune-core/commit/de14b622))

### 🪵 Log

- Log IP on malformed handshake ([f80e1a8a](https://github.com/Neptune-Crypto/neptune-core/commit/f80e1a8a))

### 🚥 Developer Experience

- Only depend on unstable tokio behind feature flags ([877b2c01](https://github.com/Neptune-Crypto/neptune-core/commit/877b2c01))
- Faster compilation by lowering some `opt-level`s ([efac89bb](https://github.com/Neptune-Crypto/neptune-core/commit/efac89bb))
- Add Makefile target for rustc incremental compiler bug ([25e307cd](https://github.com/Neptune-Crypto/neptune-core/commit/25e307cd))

### Network-security

- Don't allocate error on bad incoming connections ([567ce562](https://github.com/Neptune-Crypto/neptune-core/commit/567ce562))
- Add timeout to handshake ([730b6498](https://github.com/Neptune-Crypto/neptune-core/commit/730b6498))
- Add DOS protection against many incoming connections ([c0169711](https://github.com/Neptune-Crypto/neptune-core/commit/c0169711))
- Check for banned peer before sending handshake ([aa3485c0](https://github.com/Neptune-Crypto/neptune-core/commit/aa3485c0))
- Prevent infinite sync challenges ([b2f10e37](https://github.com/Neptune-Crypto/neptune-core/commit/b2f10e37))


## [0.4.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.2.2..v0.4.0) - 2025-09-05

### ✨ Features

- *(mine)* Threshold value for guessing ([7e3c5909](https://github.com/Neptune-Crypto/neptune-core/commit/7e3c5909))
- *(guessing)* Only switch proposals when reward delta meets threshold ([f341f159](https://github.com/Neptune-Crypto/neptune-core/commit/f341f159))
- *(mine_loop)* Update tx if no synced in mempool ([ab781c2b](https://github.com/Neptune-Crypto/neptune-core/commit/ab781c2b))
- Padded height specific tvm env vars ([bbe04bc1](https://github.com/Neptune-Crypto/neptune-core/commit/bbe04bc1))
- *(rpc_server)* Add CLI command and endpoint for upgrading specified mempool-tx ([ebe4970f](https://github.com/Neptune-Crypto/neptune-core/commit/ebe4970f))
- *(rpc_server)* Add command to list all tx-ids in mempool ([c6f0ea58](https://github.com/Neptune-Crypto/neptune-core/commit/c6f0ea58))
- *(rpc_server)* Add endpoint for info about best block proposal ([d76fd76d](https://github.com/Neptune-Crypto/neptune-core/commit/d76fd76d))
- *(rpc_server)* Add an endpoint for broadcasting block proposal ([ce95b746](https://github.com/Neptune-Crypto/neptune-core/commit/ce95b746))
- *(mempool)* Add new mempool field for preserving merge-inputs ([2e2f649a](https://github.com/Neptune-Crypto/neptune-core/commit/2e2f649a))
- *(API)* Build infrastructure for transparent transactions ([9185b9c2](https://github.com/Neptune-Crypto/neptune-core/commit/9185b9c2))
- Add RPC endpoint for addition records with AOCL indices ([b89e7e69](https://github.com/Neptune-Crypto/neptune-core/commit/b89e7e69))
- Initiate transparent transactions ([48ece4b2](https://github.com/Neptune-Crypto/neptune-core/commit/48ece4b2))
- Add flag --restrict-peers-to-list ([185df933](https://github.com/Neptune-Crypto/neptune-core/commit/185df933))
- *(cli_args)* Whitelist composer IPs ([2015f11b](https://github.com/Neptune-Crypto/neptune-core/commit/2015f11b))
- *(rpc_server)* Allow pausing state updates ([4e12aee1](https://github.com/Neptune-Crypto/neptune-core/commit/4e12aee1))
- Set tip to stored block ([9b33ee42](https://github.com/Neptune-Crypto/neptune-core/commit/9b33ee42))
- *(rpc_server)* Allow full export of block/pow puzzle ([fedbb987](https://github.com/Neptune-Crypto/neptune-core/commit/fedbb987))
- Add tx filter for proof upgrading ([406167f1](https://github.com/Neptune-Crypto/neptune-core/commit/406167f1))

### 🐛 Bug Fixes

- *(RegTest)* Allow pow mocking ([d91ecbe4](https://github.com/Neptune-Crypto/neptune-core/commit/d91ecbe4))
- *(`mine_loop`)* Stop guessing task when aborted during preprocessing ([bdbb048a](https://github.com/Neptune-Crypto/neptune-core/commit/bdbb048a))
- *(wallet)* Announced UTXOs are never guesser fees ([4c75d0d4](https://github.com/Neptune-Crypto/neptune-core/commit/4c75d0d4))
- *(`Pow`)* Avoid out-of-bounds error when aborting preprocess ([672ec868](https://github.com/Neptune-Crypto/neptune-core/commit/672ec868))
- *(mempool)* Never return empty tx for update job ([67cc78df](https://github.com/Neptune-Crypto/neptune-core/commit/67cc78df))
- *(mempool)* Return removal event when insertion overwrites existing tx ([feb354ee](https://github.com/Neptune-Crypto/neptune-core/commit/feb354ee))
- Pack removal records list in bechmark helper function ([4b3df100](https://github.com/Neptune-Crypto/neptune-core/commit/4b3df100))
- *(scan_mode)* Bump known keys cache correctly ([ba680fe5](https://github.com/Neptune-Crypto/neptune-core/commit/ba680fe5))

### 🚀 Performance

- *(main_loop)* Don't hold lock when sending msg to peer loops ([d3fd60b0](https://github.com/Neptune-Crypto/neptune-core/commit/d3fd60b0))
- *(mempool)* Use hash map to track conflicts ([d444f36b](https://github.com/Neptune-Crypto/neptune-core/commit/d444f36b))
- *(wallet)* Don't clone transaction kernel needlessly ([b997e322](https://github.com/Neptune-Crypto/neptune-core/commit/b997e322))
- *(wallet)* Use hash map for spent UTXOs ([9611199b](https://github.com/Neptune-Crypto/neptune-core/commit/9611199b))
- Wallet updates without MSMP maintenance ([4fa3da4b](https://github.com/Neptune-Crypto/neptune-core/commit/4fa3da4b))

### 📚 Documentation

- Update to match rebooted network ([0d3eb5ad](https://github.com/Neptune-Crypto/neptune-core/commit/0d3eb5ad))
- *(`README.md`)* Drop mention of testnet ([ede59ba4](https://github.com/Neptune-Crypto/neptune-core/commit/ede59ba4))
- Fix some block-related doc strings ([42a552ff](https://github.com/Neptune-Crypto/neptune-core/commit/42a552ff))

### ♻️ Refactor

- *(main_loop)* Avoid relaying empty transactions ([5082dba5](https://github.com/Neptune-Crypto/neptune-core/commit/5082dba5))
- *(mine_loop)* Fix block timestamp ([c8004dc2](https://github.com/Neptune-Crypto/neptune-core/commit/c8004dc2))
- *(proof_upgrader)* Get 'update' job from global state ([5819905f](https://github.com/Neptune-Crypto/neptune-core/commit/5819905f))
- Factor out inner prove function for testability ([79f1cc67](https://github.com/Neptune-Crypto/neptune-core/commit/79f1cc67))
- Rename `listen_addr` to `peer_listen_addr` ([24cecab3](https://github.com/Neptune-Crypto/neptune-core/commit/24cecab3))
- Remove unfinished RPC endpoint ([c218ab42](https://github.com/Neptune-Crypto/neptune-core/commit/c218ab42))
- *(mempool)* Only transmit transaction kernels in mempool events ([4cc3262c](https://github.com/Neptune-Crypto/neptune-core/commit/4cc3262c))
- *(mempool)* Normalize mempool events ([76a519ef](https://github.com/Neptune-Crypto/neptune-core/commit/76a519ef))
- *(mempool)* Use MSA tip digest to check for MSA-updated txs ([c32cdafb](https://github.com/Neptune-Crypto/neptune-core/commit/c32cdafb))
- *(mempool)* Check conflict cache before accepting tx ([775e04fd](https://github.com/Neptune-Crypto/neptune-core/commit/775e04fd))
- Move transparency helper structs out of `api/` directory ([caefb469](https://github.com/Neptune-Crypto/neptune-core/commit/caefb469))
- Rename transparent-transaction struct -`Details` -> -`Info` ([5832e708](https://github.com/Neptune-Crypto/neptune-core/commit/5832e708))
- *(`OutputFormat`)* Add variant with time-lock ([060b747b](https://github.com/Neptune-Crypto/neptune-core/commit/060b747b))
- Make RegTest launch data constant ([92ecaed0](https://github.com/Neptune-Crypto/neptune-core/commit/92ecaed0))
- *(wallet)* Return potential duplicates from helper function ([8e5c9acd](https://github.com/Neptune-Crypto/neptune-core/commit/8e5c9acd))
- *(wallet)* Split helper function into two ([d9d9b705](https://github.com/Neptune-Crypto/neptune-core/commit/d9d9b705))
- *(connect_to_peers)* Perform pre-check on incoming connections ([c70131fc](https://github.com/Neptune-Crypto/neptune-core/commit/c70131fc))
- Change default gobbling fraction from 20 % to 60 % ([5f112c8f](https://github.com/Neptune-Crypto/neptune-core/commit/5f112c8f))

### ✅ Testing

- Re-enable test that first blk-file contains valid blocks ([a6ce30cb](https://github.com/Neptune-Crypto/neptune-core/commit/a6ce30cb))
- Add wallet-state update check ([7aae3166](https://github.com/Neptune-Crypto/neptune-core/commit/7aae3166))
- Restore state from two blk files ([fd17cd72](https://github.com/Neptune-Crypto/neptune-core/commit/fd17cd72))
- *(Block)* Fix generator for specified block height ([3e9d05b4](https://github.com/Neptune-Crypto/neptune-core/commit/3e9d05b4))
- Ensure deterministic STARK proofs ([2273b9a0](https://github.com/Neptune-Crypto/neptune-core/commit/2273b9a0))
- Verify setting tvm env vars works ([1a05f0ab](https://github.com/Neptune-Crypto/neptune-core/commit/1a05f0ab))
- Fix some flaky integration tests ([dec1f267](https://github.com/Neptune-Crypto/neptune-core/commit/dec1f267))
- *(mempool)* Ensure stability under insertions of merged txs ([65f6c870](https://github.com/Neptune-Crypto/neptune-core/commit/65f6c870))
- Validate transparent transaction ([bcc7153f](https://github.com/Neptune-Crypto/neptune-core/commit/bcc7153f))
- Add test suite for `TransparentTransactionInfo` ([9f513340](https://github.com/Neptune-Crypto/neptune-core/commit/9f513340))
- *(`GenerationReceivingAddress`)* Add regression test ([ec5ef875](https://github.com/Neptune-Crypto/neptune-core/commit/ec5ef875))
- Add integration test of time-locked expenditure ([9eeca034](https://github.com/Neptune-Crypto/neptune-core/commit/9eeca034))
- *(`TxOutput`)* Add test for `with_timelock` ([b0313a8f](https://github.com/Neptune-Crypto/neptune-core/commit/b0313a8f))
- Clean up `flaky_mutator_set` somewhat ([d744fb63](https://github.com/Neptune-Crypto/neptune-core/commit/d744fb63))
- Faster test-case generation for negative block validity tests ([1e2b260b](https://github.com/Neptune-Crypto/neptune-core/commit/1e2b260b))
- Add PoW-related integration test ([d7cfe931](https://github.com/Neptune-Crypto/neptune-core/commit/d7cfe931))
- Cover bump_derivation_counter by an existing test ([425dc231](https://github.com/Neptune-Crypto/neptune-core/commit/425dc231))
- Proper testing of scan mode-related function ([f305ed1b](https://github.com/Neptune-Crypto/neptune-core/commit/f305ed1b))
- *(wallet)* Verify no double-registration when not maintaining MSMPs ([3c95a9a9](https://github.com/Neptune-Crypto/neptune-core/commit/3c95a9a9))
- *(CLI)* Test parsing `HexDigest`s ([cae809bf](https://github.com/Neptune-Crypto/neptune-core/commit/cae809bf))
- *(peer_loop)* Harden check that blocks with invalid PoW are rejected ([bd1f0a98](https://github.com/Neptune-Crypto/neptune-core/commit/bd1f0a98))
- *(mempool)* Verify upgrade filter behavior on "raise" ([188103a6](https://github.com/Neptune-Crypto/neptune-core/commit/188103a6))

### 🎨 Styling

- Display digests as hex ([5610ff0a](https://github.com/Neptune-Crypto/neptune-core/commit/5610ff0a))

### ⚙️ Miscellaneous

- Skip flaky async tests ([a3b3ad2c](https://github.com/Neptune-Crypto/neptune-core/commit/a3b3ad2c))
- Upgrade dependencies ([acb0ec8f](https://github.com/Neptune-Crypto/neptune-core/commit/acb0ec8f))
- *(`release.yml`)* Fix syntax ([2dc409eb](https://github.com/Neptune-Crypto/neptune-core/commit/2dc409eb))
- Update tvm-benchmarks results ([48e37ee6](https://github.com/Neptune-Crypto/neptune-core/commit/48e37ee6))
- Display TVM-specific env variables at startup ([2d3cab77](https://github.com/Neptune-Crypto/neptune-core/commit/2d3cab77))
- *(neptune_cli)* Fix typo in "broadcast" ([a9dc965e](https://github.com/Neptune-Crypto/neptune-core/commit/a9dc965e))
- Export useful structs ([cfebda38](https://github.com/Neptune-Crypto/neptune-core/commit/cfebda38))
- Synchronize `bech32` dependency ([796d539b](https://github.com/Neptune-Crypto/neptune-core/commit/796d539b))
- Public nonce field ([5ad764a0](https://github.com/Neptune-Crypto/neptune-core/commit/5ad764a0))
- Make lossy_f64_fraction_mul pub ([aff0982f](https://github.com/Neptune-Crypto/neptune-core/commit/aff0982f))

### 🪵 Log

- Reduce number of `info` logs ([7e030db9](https://github.com/Neptune-Crypto/neptune-core/commit/7e030db9))
- Reduce number of `info` messages ([dd123c99](https://github.com/Neptune-Crypto/neptune-core/commit/dd123c99))
- Reduce severity of multiple messages ([fbabe6ad](https://github.com/Neptune-Crypto/neptune-core/commit/fbabe6ad))
- Use std-err for log purposes in spawned TVM prover ([143a7d93](https://github.com/Neptune-Crypto/neptune-core/commit/143a7d93))
- Better log on rejected block proposal ([1800bce2](https://github.com/Neptune-Crypto/neptune-core/commit/1800bce2))
- Less noisy rejection of incoming connection ([d6001758](https://github.com/Neptune-Crypto/neptune-core/commit/d6001758))

### 🚥 Developer Experience

- Report guesser fee fraction ([d4383a70](https://github.com/Neptune-Crypto/neptune-core/commit/d4383a70))
- Add two Makefile targets ([df0a59a3](https://github.com/Neptune-Crypto/neptune-core/commit/df0a59a3))

### Dx

- Remove husky ([0d7dc895](https://github.com/Neptune-Crypto/neptune-core/commit/0d7dc895))


## [0.3.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.2.2..v0.3.0) - 2025-08-05

### ✨ Features

- Make PoW preprocessing cancelable ([1b37599b](https://github.com/Neptune-Crypto/neptune-core/commit/1b37599b))
- *(`Pow`)* Make Merkle tree construction cancelable ([ed5f5ebc](https://github.com/Neptune-Crypto/neptune-core/commit/ed5f5ebc))

### 🐛 Bug Fixes

- *(`mine_loop`)* Stop guessing task when aborted during preprocessing ([bdbb048a](https://github.com/Neptune-Crypto/neptune-core/commit/bdbb048a))
- *(wallet)* Announced UTXOs are never guesser fees ([4c75d0d4](https://github.com/Neptune-Crypto/neptune-core/commit/4c75d0d4))

### 🚀 Performance

- *(`Pow`)* Unsafely avoid memory-copies in `preprocess` ([66522fb4](https://github.com/Neptune-Crypto/neptune-core/commit/66522fb4))
- *(`Pow`)* Free memory as soon as possible ([4094aef1](https://github.com/Neptune-Crypto/neptune-core/commit/4094aef1))
- Drop reliance on `twenty_first`'s Merkle tree ([0fdaa8be](https://github.com/Neptune-Crypto/neptune-core/commit/0fdaa8be))

### 📚 Documentation

- *(merge_branch)* Clarify two non-trivial things ([a7f5d995](https://github.com/Neptune-Crypto/neptune-core/commit/a7f5d995))
- *(`README.md`)* Correct CLI arg: `--peers` -> `--peer` ([5a7238e1](https://github.com/Neptune-Crypto/neptune-core/commit/5a7238e1))

### ♻️ Refactor

- *(HeaderToBlockHashWitness)* Add missing proof hash ([4a56f776](https://github.com/Neptune-Crypto/neptune-core/commit/4a56f776))
- Rename `peers` to `peer` when specifying through CLI ([284773b1](https://github.com/Neptune-Crypto/neptune-core/commit/284773b1))
- *(proof_upgrader)* Don't timelock half of gobbled fee ([e89645dc](https://github.com/Neptune-Crypto/neptune-core/commit/e89645dc))

### ✅ Testing

- Delete deprecated BlockKernel-hash test ([2a5f0de9](https://github.com/Neptune-Crypto/neptune-core/commit/2a5f0de9))
- Fix potential empty range error in proptest ([d7cad741](https://github.com/Neptune-Crypto/neptune-core/commit/d7cad741))
- Fix test related to new block hash definition ([9d34ae7c](https://github.com/Neptune-Crypto/neptune-core/commit/9d34ae7c))
- Verify that block hash depends on block proof ([21c01914](https://github.com/Neptune-Crypto/neptune-core/commit/21c01914))
- Fix test related to premine size check ([c08f2216](https://github.com/Neptune-Crypto/neptune-core/commit/c08f2216))
- *(coinbase_amount)* Verify crash on negative amount ([93b11f24](https://github.com/Neptune-Crypto/neptune-core/commit/93b11f24))
- *(native_currency)* Add two no-inflation violation tests ([e58dc806](https://github.com/Neptune-Crypto/neptune-core/commit/e58dc806))
- *(mutator_set)* Fix flaky test ([fee1b405](https://github.com/Neptune-Crypto/neptune-core/commit/fee1b405))
- Verify native currency hash always present in UTXO helper function ([df3086a7](https://github.com/Neptune-Crypto/neptune-core/commit/df3086a7))
- Fix hardcoded program hash ([26e6f566](https://github.com/Neptune-Crypto/neptune-core/commit/26e6f566))
- *(`Pow`)* Verify that `preprocess` can be canceled within 1 s ([5859879f](https://github.com/Neptune-Crypto/neptune-core/commit/5859879f))
- Fix proof-upgrader gobbling fee test ([e5a018ba](https://github.com/Neptune-Crypto/neptune-core/commit/e5a018ba))

### 🎨 Styling

- *(collect_type_scripts)* Rename variable ([d7249bf2](https://github.com/Neptune-Crypto/neptune-core/commit/d7249bf2))

### ⚙️ Miscellaneous

- Release v0.3.0-alpha.1 ([44c96540](https://github.com/Neptune-Crypto/neptune-core/commit/44c96540))
- *(`Block`)* Add UTXO redemption claim to genesis block ([079e730d](https://github.com/Neptune-Crypto/neptune-core/commit/079e730d))
- *(`Block`)* Add UTXO redemption claim to genesis ([821848e4](https://github.com/Neptune-Crypto/neptune-core/commit/821848e4))
- *(`Block`)* Add UTXO redemption to genesis ([d17edc5b](https://github.com/Neptune-Crypto/neptune-core/commit/d17edc5b))
- *(`Block`)* Add UTXO redemption claim to genesis ([4deaa961](https://github.com/Neptune-Crypto/neptune-core/commit/4deaa961))

### 🪵 Log

- Add an info message for each block on bootstrap ([c925263a](https://github.com/Neptune-Crypto/neptune-core/commit/c925263a))
- Add log message for preprocessing ([64d65f29](https://github.com/Neptune-Crypto/neptune-core/commit/64d65f29))
- Reduce number of `info` logs ([7e030db9](https://github.com/Neptune-Crypto/neptune-core/commit/7e030db9))
- Reduce number of `info` messages ([dd123c99](https://github.com/Neptune-Crypto/neptune-core/commit/dd123c99))
- Reduce severity of multiple messages ([fbabe6ad](https://github.com/Neptune-Crypto/neptune-core/commit/fbabe6ad))
- Reduce number of info log messages ([f0fc780a](https://github.com/Neptune-Crypto/neptune-core/commit/f0fc780a))
- Adjust some log messages ([e1c36d04](https://github.com/Neptune-Crypto/neptune-core/commit/e1c36d04))

### 🕵️ Privacy

- *(mine_loop)* Never add zero-valued composer outputs ([825a3b2f](https://github.com/Neptune-Crypto/neptune-core/commit/825a3b2f))

### Harden

- *(collect_type_scripts)* Ensure all pointer jumps are forward ([b87bc2cb](https://github.com/Neptune-Crypto/neptune-core/commit/b87bc2cb))
- *(PrimitiveWitness)* Verify not too many type script witnesses ([fa3fe55a](https://github.com/Neptune-Crypto/neptune-core/commit/fa3fe55a))
- *(collect_type_scripts)* Add extra check that witness lives in ND-memory region ([cfc13b6f](https://github.com/Neptune-Crypto/neptune-core/commit/cfc13b6f))
- *(collect_type_scripts)* Bound num inputs/outputs and num coins ([7c097730](https://github.com/Neptune-Crypto/neptune-core/commit/7c097730))
- Verify sane end-state after consensus program ([e9c5c0b8](https://github.com/Neptune-Crypto/neptune-core/commit/e9c5c0b8))
- *(kernel_to_outputs)* Add some extra checks ([8a25bb46](https://github.com/Neptune-Crypto/neptune-core/commit/8a25bb46))
- *(new_claim)* Ensure claim bound to one memory page ([57982703](https://github.com/Neptune-Crypto/neptune-core/commit/57982703))

### Joy

- Update genesis parameters to reboot ([8b155690](https://github.com/Neptune-Crypto/neptune-core/commit/8b155690))

### Ux

- *(`Pow`)* Check cancel channel periodically during `preprocess` ([be1d09d2](https://github.com/Neptune-Crypto/neptune-core/commit/be1d09d2))
- *(guess-preprocess)* Respect user-defined parallelism limit ([e5966931](https://github.com/Neptune-Crypto/neptune-core/commit/e5966931))


## [0.3.0-alpha.1](https://github.com/Neptune-Crypto/neptune-core/compare/v0.2.2..v0.3.0-alpha.1) - 2025-08-01

### ✨ Features

- Pub api layer, regtest mode, integration tests, ([69e28671](https://github.com/Neptune-Crypto/neptune-core/commit/69e28671))
- Handle panics in job-queue jobs ([d84c2162](https://github.com/Neptune-Crypto/neptune-core/commit/d84c2162))
- Implement mockable proofs for regtest mode ([811b0b06](https://github.com/Neptune-Crypto/neptune-core/commit/811b0b06))
- Add TritonVmProofJobOptionsBuilder ([cc737c88](https://github.com/Neptune-Crypto/neptune-core/commit/cc737c88))
- Backup wallet DB before migrating ([4cdce6ea](https://github.com/Neptune-Crypto/neptune-core/commit/4cdce6ea))
- *(ArchivalState)* Read blocks from file without db for indexing ([5708850c](https://github.com/Neptune-Crypto/neptune-core/commit/5708850c))
- *(GlobalState)* Restore state from block files ([1019ac46](https://github.com/Neptune-Crypto/neptune-core/commit/1019ac46))
- Bootstrap from directory of blocks ([8ada417d](https://github.com/Neptune-Crypto/neptune-core/commit/8ada417d))
- Add option to ignore block-validation on block-bootstrapping ([b898f33b](https://github.com/Neptune-Crypto/neptune-core/commit/b898f33b))
- Add RPC APIs for block kernel and mempool_tx ([c31ca08d](https://github.com/Neptune-Crypto/neptune-core/commit/c31ca08d))
- Add public TransactionKernel for BlockBody ([088d7ebf](https://github.com/Neptune-Crypto/neptune-core/commit/088d7ebf))
- Bootstrap flushing period ([#608](https://github.com/Neptune-Crypto/neptune-core/issues/608)) ([cf87679a](https://github.com/Neptune-Crypto/neptune-core/commit/cf87679a))
- *(mempool)* Track tip's mutator set digest ([7d82d3bd](https://github.com/Neptune-Crypto/neptune-core/commit/7d82d3bd))
- *(mempool)* Always preserve primitive witness if available ([5adddda5](https://github.com/Neptune-Crypto/neptune-core/commit/5adddda5))
- *(cli_args)* Add option `tx_proof_upgrading` ([70645311](https://github.com/Neptune-Crypto/neptune-core/commit/70645311))
- *(archival_state)* Add function to get historical MS data ([6fe9862e](https://github.com/Neptune-Crypto/neptune-core/commit/6fe9862e))
- *(mempool)* Get most valuable update job ([427ca211](https://github.com/Neptune-Crypto/neptune-core/commit/427ca211))
- *(mining)* Add CLI argument to set num merged transactions ([7f762b42](https://github.com/Neptune-Crypto/neptune-core/commit/7f762b42))
- Compressed encoding of `RemovalRecord`s ([65dc2166](https://github.com/Neptune-Crypto/neptune-core/commit/65dc2166))
- Version consensus programs ([73794cd9](https://github.com/Neptune-Crypto/neptune-core/commit/73794cd9))
- *(mutator_set)* New SWBF representation, with TASM snippet! ([15b78246](https://github.com/Neptune-Crypto/neptune-core/commit/15b78246))

### 🐛 Bug Fixes

- *(`PrimitiveWitness`)* Ensure presence of `NativeCurrency` hash ([f9c936be](https://github.com/Neptune-Crypto/neptune-core/commit/f9c936be))
- *(RemovalRecord)* Fix off-by-one error in `can_remove` ([33a23259](https://github.com/Neptune-Crypto/neptune-core/commit/33a23259))

### 🚀 Performance

- Only flush once when applying multiple blocks ([647c0224](https://github.com/Neptune-Crypto/neptune-core/commit/647c0224))
- *(mempool)* Early return on state update when mempool is empty ([fd02d4f6](https://github.com/Neptune-Crypto/neptune-core/commit/fd02d4f6))
- *(wallet)* Only do extra MSMP verification in debug mode ([ac85b228](https://github.com/Neptune-Crypto/neptune-core/commit/ac85b228))
- Use archival mutator set to resync wallet ([#616](https://github.com/Neptune-Crypto/neptune-core/issues/616)) ([c841cf51](https://github.com/Neptune-Crypto/neptune-core/commit/c841cf51))

### 📚 Documentation

- Expunge "caller" in src/api ([5a541c5c](https://github.com/Neptune-Crypto/neptune-core/commit/5a541c5c))
- Add work-in-progress note. ([b06094e5](https://github.com/Neptune-Crypto/neptune-core/commit/b06094e5))
- Improve docs in regtest_impl ([65507fb8](https://github.com/Neptune-Crypto/neptune-core/commit/65507fb8))
- Clarify ByUtxoSize means byte-size. ([69abb3f8](https://github.com/Neptune-Crypto/neptune-core/commit/69abb3f8))
- Add explanations in NativeCurrencyAmount ([03d943df](https://github.com/Neptune-Crypto/neptune-core/commit/03d943df))
- Add TransactionDetails diagram ([dee8fc30](https://github.com/Neptune-Crypto/neptune-core/commit/dee8fc30))
- Drop unnecessary explicit links ([23124e78](https://github.com/Neptune-Crypto/neptune-core/commit/23124e78))
- Fix docs re default notify medium ([5c6e6911](https://github.com/Neptune-Crypto/neptune-core/commit/5c6e6911))
- Add donation address ([d0b88f05](https://github.com/Neptune-Crypto/neptune-core/commit/d0b88f05))
- Clarify tx proof builder evaluation ([88d16a8a](https://github.com/Neptune-Crypto/neptune-core/commit/88d16a8a))
- Specify mock proofs disallowed on Mainnet ([010965e6](https://github.com/Neptune-Crypto/neptune-core/commit/010965e6))
- Clarify valid/invalid mock in builder ([955a6ef4](https://github.com/Neptune-Crypto/neptune-core/commit/955a6ef4))
- Clarify docs for primitive_witness method() ([806d542b](https://github.com/Neptune-Crypto/neptune-core/commit/806d542b))
- Fix cargo doc warnings and CI ([03d061de](https://github.com/Neptune-Crypto/neptune-core/commit/03d061de))
- Warn harder about using `master` branch ([b2698926](https://github.com/Neptune-Crypto/neptune-core/commit/b2698926))
- Add docstring to MSMP resync function ([5c6b30a8](https://github.com/Neptune-Crypto/neptune-core/commit/5c6b30a8))
- Correct obsolete comment ([c67037c8](https://github.com/Neptune-Crypto/neptune-core/commit/c67037c8))
- Add docstring to statistics test ([4a7cccff](https://github.com/Neptune-Crypto/neptune-core/commit/4a7cccff))
- Document bootstrapping from raw block data ([a841f2a0](https://github.com/Neptune-Crypto/neptune-core/commit/a841f2a0))
- Fix doctest for format_human_duration() ([57516c82](https://github.com/Neptune-Crypto/neptune-core/commit/57516c82))
- Add link to latest snapshot torrent ([e78ccf5b](https://github.com/Neptune-Crypto/neptune-core/commit/e78ccf5b))
- *(`GetSwbfIndicesNew`)* Explain mechanics of encoding step ([c7a5bf89](https://github.com/Neptune-Crypto/neptune-core/commit/c7a5bf89))
- *(mutator_set)* Clarify importance of `can_remove` ([77e8366a](https://github.com/Neptune-Crypto/neptune-core/commit/77e8366a))

### 🔒️ Security

- Pass network to proof verify function ([74084ea6](https://github.com/Neptune-Crypto/neptune-core/commit/74084ea6))

### ⏳ Benchmark

- Add a benchmark for wallet-state updating ([14a593de](https://github.com/Neptune-Crypto/neptune-core/commit/14a593de))

### 🎨 Styling

- Clarify function only intended for own transactions ([8630faab](https://github.com/Neptune-Crypto/neptune-core/commit/8630faab))
- *(`TransactionDetailsBuilder`)* Supply many, not one, `PublicAnnouncement`s ([0c9450a9](https://github.com/Neptune-Crypto/neptune-core/commit/0c9450a9))
- (!) Rename "public announcement" to "announcement" ([6e96c7d9](https://github.com/Neptune-Crypto/neptune-core/commit/6e96c7d9))

### ⚙️ Miscellaneous

- Restart network because of above bug fixes
- Add PrimitiveWitness::is_valid() -> bool ([70c0e8bc](https://github.com/Neptune-Crypto/neptune-core/commit/70c0e8bc))
- Add TxCreationArtifacts::is_valid() ([3ac62570](https://github.com/Neptune-Crypto/neptune-core/commit/3ac62570))
- Rename MockableProof to NeptuneProof ([c5524079](https://github.com/Neptune-Crypto/neptune-core/commit/c5524079))
- Add ProofBuilder doctest example ([75ecd10b](https://github.com/Neptune-Crypto/neptune-core/commit/75ecd10b))
- Rename is_vm_proof() --> executes_in_vm() ([080b81fc](https://github.com/Neptune-Crypto/neptune-core/commit/080b81fc))
- (!) Upgrade dependency “Triton VM” ([cd1aad2b](https://github.com/Neptune-Crypto/neptune-core/commit/cd1aad2b))
- *(peer)* Mark `PeerMessage` as non-exhaustive ([10112671](https://github.com/Neptune-Crypto/neptune-core/commit/10112671))
- Add UTXO redemption claim to genesis block ([9673abd5](https://github.com/Neptune-Crypto/neptune-core/commit/9673abd5))
- Hardcode genesis' `pow.root` to specific value ([c6508705](https://github.com/Neptune-Crypto/neptune-core/commit/c6508705))
- Update release workflow files ([3d21c9aa](https://github.com/Neptune-Crypto/neptune-core/commit/3d21c9aa))
- Upgrade version of twenty-first ([ec62f400](https://github.com/Neptune-Crypto/neptune-core/commit/ec62f400))

### 🚥 Developer Experience

- Report guesser fee fraction ([d4383a70](https://github.com/Neptune-Crypto/neptune-core/commit/d4383a70))

### 🕵️ Privacy

- *(mine_loop)* Never add zero-valued composer outputs ([825a3b2f](https://github.com/Neptune-Crypto/neptune-core/commit/825a3b2f))

### Harden

- *(collect_type_scripts)* Ensure all pointer jumps are forward ([b87bc2cb](https://github.com/Neptune-Crypto/neptune-core/commit/b87bc2cb))
- *(PrimitiveWitness)* Verify not too many type script witnesses ([fa3fe55a](https://github.com/Neptune-Crypto/neptune-core/commit/fa3fe55a))
- *(collect_type_scripts)* Add extra check that witness lives in ND-memory region ([cfc13b6f](https://github.com/Neptune-Crypto/neptune-core/commit/cfc13b6f))
- *(collect_type_scripts)* Bound num inputs/outputs and num coins ([7c097730](https://github.com/Neptune-Crypto/neptune-core/commit/7c097730))


## [0.2.2](https://github.com/Neptune-Crypto/neptune-core/compare/v0.2.1..v0.2.2) - 2025-04-01

### 🐛 Bug Fixes

- Add missing fields from Display impl of `BlockHeader` ([8f01e3a2](https://github.com/Neptune-Crypto/neptune-core/commit/8f01e3a2))
- Display impl of BlockHeader ([a33267b0](https://github.com/Neptune-Crypto/neptune-core/commit/a33267b0))
- *(peer_loop)* Don't hold read lock responding with transction ([3510716c](https://github.com/Neptune-Crypto/neptune-core/commit/3510716c))
- Avoid holding read-lock across peer.send() ([d37a5d77](https://github.com/Neptune-Crypto/neptune-core/commit/d37a5d77))
- *(proof_upgrader)* Check for double-spending ([1db6dc42](https://github.com/Neptune-Crypto/neptune-core/commit/1db6dc42))

### 📚 Documentation

- Add user guide about scan mode ([c3a187dc](https://github.com/Neptune-Crypto/neptune-core/commit/c3a187dc) / [a11fcd54](https://github.com/Neptune-Crypto/neptune-core/commit/a11fcd54))
- *(proof_upgrader)* Add some context to upgrade-handler ([8e8f368a](https://github.com/Neptune-Crypto/neptune-core/commit/8e8f368a))

### ♻️  Refactor

- Fix argument order in fee gobbler ([90abab4f](https://github.com/Neptune-Crypto/neptune-core/commit/90abab4f))
- Allow duplicated values in `incoming_randomness.dat` ([c97f29a4](https://github.com/Neptune-Crypto/neptune-core/commit/c97f29a4))

### ✅ Testing

- *(proof_upgrader)* Test merge-output being double-spender ([7e8bb13e](https://github.com/Neptune-Crypto/neptune-core/commit/7e8bb13e))


## [0.2.1](https://github.com/Neptune-Crypto/neptune-core/compare/v0.2.0..v0.2.1) - 2025-03-26

### ✨ Features

- Expand `BlockInfo` with `size` ([f67ac005](https://github.com/Neptune-Crypto/neptune-core/commit/f67ac005) / [9d490102](https://github.com/Neptune-Crypto/neptune-core/commit/9d490102))
- *(mempool)* Filter transactions for mutator set match ([8a3b7313](https://github.com/Neptune-Crypto/neptune-core/commit/8a3b7313))
- *(rpc_server)* Add command to clear mempool ([8cc1264e](https://github.com/Neptune-Crypto/neptune-core/commit/8cc1264e))
- *(`cli_args`)* `offchain_fee_notifications` ([bc2f73d1](https://github.com/Neptune-Crypto/neptune-core/commit/bc2f73d1))
- Scan blocks for lost composer UTXOs ([e322aa5a](https://github.com/Neptune-Crypto/neptune-core/commit/e322aa5a))

### 🐛 Bug Fixes

- Fix script for backing up randomness ([11e0616a](https://github.com/Neptune-Crypto/neptune-core/commit/11e0616a))
- *(proof_upgrader)* Don't upgrade for less than min gobbling fee ([94a84ca6](https://github.com/Neptune-Crypto/neptune-core/commit/94a84ca6))
- *(mempool)* Ignore conflictors with deprecated mutator sets ([e8fc2430](https://github.com/Neptune-Crypto/neptune-core/commit/e8fc2430))
- Don't return expected UTXOs for composition when policy is onchain ([e78d971d](https://github.com/Neptune-Crypto/neptune-core/commit/e78d971d))
- *(peer_loop)* Fix race condition on new connection ([2aca28b1](https://github.com/Neptune-Crypto/neptune-core/commit/2aca28b1))

### 📚 Documentation

- *(mempool)* Add docstring ([6dbe4ed3](https://github.com/Neptune-Crypto/neptune-core/commit/6dbe4ed3))
- *(peer_loop)* Justify holding write lock on new connection ([8f96f38e](https://github.com/Neptune-Crypto/neptune-core/commit/8f96f38e))

### ♻️  Refactor

- Make TransactionKernelId public ([266ba7d2](https://github.com/Neptune-Crypto/neptune-core/commit/266ba7d2))
- Make upgrader fee notifications conform to CLI policy ([d336bea2](https://github.com/Neptune-Crypto/neptune-core/commit/d336bea2))
- Default to on-chain composer fee notifications ([a8d635e1](https://github.com/Neptune-Crypto/neptune-core/commit/a8d635e1))
- Simplify interface wrt. guesser fee fraction ([c22f1dcd](https://github.com/Neptune-Crypto/neptune-core/commit/c22f1dcd))
- *(`cli_args`)* Generalize fee notification policy ([f5e61d28](https://github.com/Neptune-Crypto/neptune-core/commit/f5e61d28))
- *(`WalletState`)* Auto-generate symmetric key with index 0 ([e2522731](https://github.com/Neptune-Crypto/neptune-core/commit/e2522731))
- Factor out production of coinbase outputs ([68d587a7](https://github.com/Neptune-Crypto/neptune-core/commit/68d587a7))
- *(`mine_loop`)* Factor out extractor for `ExpectedUtxo`s ([c27e06a7](https://github.com/Neptune-Crypto/neptune-core/commit/c27e06a7))
- *(`mempool`)* Catch self-conflicts smarter ([6c1081c8](https://github.com/Neptune-Crypto/neptune-core/commit/6c1081c8))

### ✅ Testing

- *(mempool)* MS-filtering also works for SingleProof-backed txs ([16193bb1](https://github.com/Neptune-Crypto/neptune-core/commit/16193bb1))
- Wallet recovers unexpected composer UTXO ([908976a1](https://github.com/Neptune-Crypto/neptune-core/commit/908976a1))
- Expand composer and upgrader fee recovery tests ([be9ef7b3](https://github.com/Neptune-Crypto/neptune-core/commit/be9ef7b3))
- Recovery of unexpected off-chain composer UTXOs ([3a1e0367](https://github.com/Neptune-Crypto/neptune-core/commit/3a1e0367))
- Force `SingleProof` capability for block transactions ([395d0e36](https://github.com/Neptune-Crypto/neptune-core/commit/395d0e36))
- Explicitly bind and drop channel to nowhere ([b17a299e](https://github.com/Neptune-Crypto/neptune-core/commit/b17a299e))
- *(`FeeNotificationPolicy`)* Test parsing empty string ([6d99c118](https://github.com/Neptune-Crypto/neptune-core/commit/6d99c118))
- *(mempool)* Ensure MS-updated transaction always replaces progenitor ([#528](https://github.com/Neptune-Crypto/neptune-core/issues/528)) ([f8a4785e](https://github.com/Neptune-Crypto/neptune-core/commit/f8a4785e))

### 🎨 Styling

- Report guesser fee of rejected blocks ([cdc6e87b](https://github.com/Neptune-Crypto/neptune-core/commit/cdc6e87b) / [09b6ed8c](https://github.com/Neptune-Crypto/neptune-core/commit/09b6ed8c))
- Rename variable for better readability ([59cef21d](https://github.com/Neptune-Crypto/neptune-core/commit/59cef21d))
- Use `expect` to communicate assumptions ([225ee2fa](https://github.com/Neptune-Crypto/neptune-core/commit/225ee2fa))

### ⚙️  Miscellaneous

- Try to build when `Cargo.lock` is absent ([c6583346](https://github.com/Neptune-Crypto/neptune-core/commit/c6583346))
- Work around semver-breaking dependency ([187d28fd](https://github.com/Neptune-Crypto/neptune-core/commit/187d28fd))
- Synchronize pre-commit hook with CI ([3fe9300a](https://github.com/Neptune-Crypto/neptune-core/commit/3fe9300a))

### Devx

- Add script for tracking average RPC response time ([b23c3eaf](https://github.com/Neptune-Crypto/neptune-core/commit/b23c3eaf) / [13c163cc](https://github.com/Neptune-Crypto/neptune-core/commit/13c163cc))


## [0.2.0](https://github.com/Neptune-Crypto/neptune-core/compare/v0.1.3..v0.2.0) - 2025-03-20

### 🔱 Fork

- (!) Increase block size ([cbbd063d](https://github.com/Neptune-Crypto/neptune-core/commit/cbbd063d))

### ✨ Features

- *(CLI)* Show wallet status as table ([02a49e7a](https://github.com/Neptune-Crypto/neptune-core/commit/02a49e7a))
- Display peer version in dashboard ([c68ff066](https://github.com/Neptune-Crypto/neptune-core/commit/c68ff066))
- Make dashboard peers list scrollable ([89ce3fcd](https://github.com/Neptune-Crypto/neptune-core/commit/89ce3fcd))
- Add peer column sorting ([b2d705c2](https://github.com/Neptune-Crypto/neptune-core/commit/b2d705c2))
- Improve interactive peers sorting ([3e08e67c](https://github.com/Neptune-Crypto/neptune-core/commit/3e08e67c))
- Use canonical ip in dashboard peers screen ([76c3a8ec](https://github.com/Neptune-Crypto/neptune-core/commit/76c3a8ec))
- Mining status duration as human-time ([59304edc](https://github.com/Neptune-Crypto/neptune-core/commit/59304edc))
- *(`WalletState`)* Automatically detect own guesser UTXOs ([c46eebe0](https://github.com/Neptune-Crypto/neptune-core/commit/c46eebe0))
- Recognize own guesser UTXOs ([48c74077](https://github.com/Neptune-Crypto/neptune-core/commit/48c74077))
- (!) Refuse connections from recent disconnects ([7fd78443](https://github.com/Neptune-Crypto/neptune-core/commit/7fd78443))
- Add CLI subcommands for scan mode ([fffe51d4](https://github.com/Neptune-Crypto/neptune-core/commit/fffe51d4))
- Add functions to scan for UTXOs with future keys ([31f3c145](https://github.com/Neptune-Crypto/neptune-core/commit/31f3c145))
- Activate scanning with future keys ([0eb28311](https://github.com/Neptune-Crypto/neptune-core/commit/0eb28311))
- Scan Mode ([69fe29d6](https://github.com/Neptune-Crypto/neptune-core/commit/69fe29d6))
- *(rpc_server)* Support external PoW guesser programs ([dce5113b](https://github.com/Neptune-Crypto/neptune-core/commit/dce5113b))
- *(rpc_server)* Add endpoint for external guesser, with external key ([e87ae40d](https://github.com/Neptune-Crypto/neptune-core/commit/e87ae40d))
- *(PrimitiveWitness)* Allow updating wrt. MS update ([d145d367](https://github.com/Neptune-Crypto/neptune-core/commit/d145d367))
- *(proof_upgrader)* Handle block/upgrade race condition for PC proofs ([9f2ad8d0](https://github.com/Neptune-Crypto/neptune-core/commit/9f2ad8d0))
- *(rpc_server)* Add endpoint for sharing all txs in mempool ([dd345019](https://github.com/Neptune-Crypto/neptune-core/commit/dd345019))
- *(rpc_server)* Get all public announcements in block ([c45f4bcc](https://github.com/Neptune-Crypto/neptune-core/commit/c45f4bcc))
- Allow restricting num connections by IP ([d55ef2e4](https://github.com/Neptune-Crypto/neptune-core/commit/d55ef2e4))

### 🐛 Bug Fixes

- Report guessing time correctly ([da74d3ac](https://github.com/Neptune-Crypto/neptune-core/commit/da74d3ac))
- Display peers port in dashboard peers ([d44fa976](https://github.com/Neptune-Crypto/neptune-core/commit/d44fa976))
- Avoid holding locks across blocking send() ([4b9a2187](https://github.com/Neptune-Crypto/neptune-core/commit/4b9a2187))
- *(main_loop)* Respect `secret_compositions` flag ([1972e8da](https://github.com/Neptune-Crypto/neptune-core/commit/1972e8da))
- Potentially disconnect from multiple peers ([4a7cfe18](https://github.com/Neptune-Crypto/neptune-core/commit/4a7cfe18))
- *(primitive_witness)* Actually check TVM result in validation ([b031c82d](https://github.com/Neptune-Crypto/neptune-core/commit/b031c82d))
- *(Timestamp)* Ensure formatting cannot panic ([0a941348](https://github.com/Neptune-Crypto/neptune-core/commit/0a941348))
- *(peer_loop)* Race condition in transaction-handling ([bba442d2](https://github.com/Neptune-Crypto/neptune-core/commit/bba442d2))

### 🚀 Performance

- Only assemble SingleProof program once ([264fccc9](https://github.com/Neptune-Crypto/neptune-core/commit/264fccc9))
- Reduce time write-lock is held on new transaction ([c42e7cbf](https://github.com/Neptune-Crypto/neptune-core/commit/c42e7cbf))

### 📚 Documentation

- Update intra-doc links of private items ([26e52328](https://github.com/Neptune-Crypto/neptune-core/commit/26e52328))
- Explain seeming duplication ([35a9a1ff](https://github.com/Neptune-Crypto/neptune-core/commit/35a9a1ff))
- Fix docstring link ([14737085](https://github.com/Neptune-Crypto/neptune-core/commit/14737085))
- Update deprecated comment on proof-updating ([94200540](https://github.com/Neptune-Crypto/neptune-core/commit/94200540))
- Add various badges to README ([2240475f](https://github.com/Neptune-Crypto/neptune-core/commit/2240475f))

### ♻️  Refactor

- Improve PeerMessage::BlockProposal ([696a9cce](https://github.com/Neptune-Crypto/neptune-core/commit/696a9cce))
- Avoid passing guesser preimages ([f3476e9b](https://github.com/Neptune-Crypto/neptune-core/commit/f3476e9b))
- *(`Utxo`)* Remove confusing function ([fe94cd54](https://github.com/Neptune-Crypto/neptune-core/commit/fe94cd54))
- Reduce ways of setting new tip to one ([1f5b7e69](https://github.com/Neptune-Crypto/neptune-core/commit/1f5b7e69))
- Make `max_num_peers` a `usize` ([d6436cc6](https://github.com/Neptune-Crypto/neptune-core/commit/d6436cc6))
- Separate reconnecter from peer discovery ([6c115f30](https://github.com/Neptune-Crypto/neptune-core/commit/6c115f30))
- Track state for scan mode configuration ([c33a9b6d](https://github.com/Neptune-Crypto/neptune-core/commit/c33a9b6d))
- Separate `WalletSecret` -> `WalletEntropy` + `WalletFile` ([79f2eeb4](https://github.com/Neptune-Crypto/neptune-core/commit/79f2eeb4))
- Factor out `WalletConfiguration` ([07ab1ef7](https://github.com/Neptune-Crypto/neptune-core/commit/07ab1ef7))
- *(`ScanModeConfiguration`)* Allow commuting constructor-helpers ([4b317b37](https://github.com/Neptune-Crypto/neptune-core/commit/4b317b37))
- *(`WalletState`)* Improve scan mode logic and configuration ([68eca269](https://github.com/Neptune-Crypto/neptune-core/commit/68eca269))
- Add new type `AuthenticatedItem` ([cbfcd770](https://github.com/Neptune-Crypto/neptune-core/commit/cbfcd770))
- Remove redundant else for all features ([4066f753](https://github.com/Neptune-Crypto/neptune-core/commit/4066f753))
- Use `tokio::interval` over `sleep` ([56fc3d80](https://github.com/Neptune-Crypto/neptune-core/commit/56fc3d80))

### ✅ Testing

- Test guesser fee scanner in isolation ([c7bcef48](https://github.com/Neptune-Crypto/neptune-core/commit/c7bcef48))
- Only retrieve http response body if 2xx Ok. ([7131158a](https://github.com/Neptune-Crypto/neptune-core/commit/7131158a))
- Reduce scope of MMR mutability ([0aa6f569](https://github.com/Neptune-Crypto/neptune-core/commit/0aa6f569))
- Add test that genesis block is unchanged ([6ffd2d56](https://github.com/Neptune-Crypto/neptune-core/commit/6ffd2d56))
- Test seed recovery of UTXOs with scan mode ([8b2fb4c3](https://github.com/Neptune-Crypto/neptune-core/commit/8b2fb4c3))
- *(`WalletState`)* Add test of `scan_for_announced_utxos` ([5d2b8467](https://github.com/Neptune-Crypto/neptune-core/commit/5d2b8467))
- *(proof_upgrader)* Also test PW->SP path ([fb96630e](https://github.com/Neptune-Crypto/neptune-core/commit/fb96630e))
- *(Timestamp)* Add tests that constructors are sane and correct ([a2516ba4](https://github.com/Neptune-Crypto/neptune-core/commit/a2516ba4))
- Verify size of block subsidy ([2e941edb](https://github.com/Neptune-Crypto/neptune-core/commit/2e941edb))
- Link observed mining reward with expected block subsidy ([ac9d7454](https://github.com/Neptune-Crypto/neptune-core/commit/ac9d7454))

### ⏱ Benchmark

- Add PoW benchmark showing hash rate ([81e1264a](https://github.com/Neptune-Crypto/neptune-core/commit/81e1264a))

### ⚙️  Miscellaneous

- Simplify start_guessing check in mine-loop ([8f137255](https://github.com/Neptune-Crypto/neptune-core/commit/8f137255))
- Add a script to display unique log msgs by type ([5da0a73c](https://github.com/Neptune-Crypto/neptune-core/commit/5da0a73c))
- Do not log slow scope across peer.send() ([6546829f](https://github.com/Neptune-Crypto/neptune-core/commit/6546829f))
- Work around deprecation of ubuntu runner image ([d646753f](https://github.com/Neptune-Crypto/neptune-core/commit/d646753f))
- Skip flaky (on GitHub CI) test ([4b90018a](https://github.com/Neptune-Crypto/neptune-core/commit/4b90018a))
- Add new proof server to list ([5aea2770](https://github.com/Neptune-Crypto/neptune-core/commit/5aea2770))
- Report code coverage ([2433e25f](https://github.com/Neptune-Crypto/neptune-core/commit/2433e25f))
- Make clippy more pedantic ([61d8be47](https://github.com/Neptune-Crypto/neptune-core/commit/61d8be47))
- Make clippy more pedantic ([512c705e](https://github.com/Neptune-Crypto/neptune-core/commit/512c705e))
- Avoid `async fn`s without `await` points ([4d9c87a6](https://github.com/Neptune-Crypto/neptune-core/commit/4d9c87a6))
- Avoid `as` keyword for lossless casts ([46971c30](https://github.com/Neptune-Crypto/neptune-core/commit/46971c30))

### Devops

- Add script for backing up incoming/outgoing randomness ([f8c61c68](https://github.com/Neptune-Crypto/neptune-core/commit/f8c61c68))
- Add warning about also backing up `wallet.dat` ([a9d502a8](https://github.com/Neptune-Crypto/neptune-core/commit/a9d502a8))


## [0.1.3](https://github.com/Neptune-Crypto/neptune-core/compare/v0.1.2..v0.1.3) - 2025-02-17

### ✨ Features

- Show peer count in dashboard peer screen ([ad13f936](https://github.com/Neptune-Crypto/neptune-core/commit/ad13f936))

### 🐛 Bug Fixes

- Avoid screen corruption on dashboard panic ([5cce5c51](https://github.com/Neptune-Crypto/neptune-core/commit/5cce5c51))
- Improve dashboard peers display ([587f596c](https://github.com/Neptune-Crypto/neptune-core/commit/587f596c))
- Appears to resolve a deadlock in peer_loop ([9e0a1b7f](https://github.com/Neptune-Crypto/neptune-core/commit/9e0a1b7f))
- Leave raw mode before printing error msgs ([bf4ce45c](https://github.com/Neptune-Crypto/neptune-core/commit/bf4ce45c))

### 🚀 Performance

- Announce mined block to peers immediately. ([bae86981](https://github.com/Neptune-Crypto/neptune-core/commit/bae86981))

### 📚 Documentation

- Fix broken release isntructions ([6430d1a5](https://github.com/Neptune-Crypto/neptune-core/commit/6430d1a5))
- Fix comment typo ([d21c4272](https://github.com/Neptune-Crypto/neptune-core/commit/d21c4272))
- Turn regular comments into doc comments ([2d2038f7](https://github.com/Neptune-Crypto/neptune-core/commit/2d2038f7))
- Fix typos ([7e7e34fb](https://github.com/Neptune-Crypto/neptune-core/commit/7e7e34fb))

### ♻️ Refactor

- Drop indirection in early return ([3c80ea41](https://github.com/Neptune-Crypto/neptune-core/commit/3c80ea41))
- Check validity of own block proposal ([cdfc9a6c](https://github.com/Neptune-Crypto/neptune-core/commit/cdfc9a6c))
- *(peer_loop)* Extra check of double spending txs ([3ffa280a](https://github.com/Neptune-Crypto/neptune-core/commit/3ffa280a))

### 🛠 Build

- Regenerate Cargo.lock to avoid yanked crate ([af109071](https://github.com/Neptune-Crypto/neptune-core/commit/af109071))
- Restore deleted Cargo.lock ([a02fe9c9](https://github.com/Neptune-Crypto/neptune-core/commit/a02fe9c9))
- Lock-log_events depends track-lock-time ([1c649ece](https://github.com/Neptune-Crypto/neptune-core/commit/1c649ece))

### ⚙️ Miscellaneous

- Update benchmark results ([c0a7cec5](https://github.com/Neptune-Crypto/neptune-core/commit/c0a7cec5))
- Log when setting mining status ([6f8c24c1](https://github.com/Neptune-Crypto/neptune-core/commit/6f8c24c1))
- Reword log entry ([e0f26c24](https://github.com/Neptune-Crypto/neptune-core/commit/e0f26c24))
- Don't warn about equal fee proposals ([82c18567](https://github.com/Neptune-Crypto/neptune-core/commit/82c18567))
- Log mempool add/remove events ([42f58d13](https://github.com/Neptune-Crypto/neptune-core/commit/42f58d13))
- Reduce single-proof min RAM to 120Gb ([10ef6e9f](https://github.com/Neptune-Crypto/neptune-core/commit/10ef6e9f))
- Improve readability of early aborts ([eca5efc5](https://github.com/Neptune-Crypto/neptune-core/commit/eca5efc5))
- Set default RUST_LOG="info,tarpc=warn" ([87b8219a](https://github.com/Neptune-Crypto/neptune-core/commit/87b8219a))
- Add script for finding deadlocks in logs ([1595e072](https://github.com/Neptune-Crypto/neptune-core/commit/1595e072))
- Add php script to calculate block proposal durations ([8a763f93](https://github.com/Neptune-Crypto/neptune-core/commit/8a763f93))
- Improve block-proposal duration script ([0a0ab600](https://github.com/Neptune-Crypto/neptune-core/commit/0a0ab600))
- Report guessing times in interval script ([7abe2f2b](https://github.com/Neptune-Crypto/neptune-core/commit/7abe2f2b))
- Replace reqwest with clienter in tests ([d1391447](https://github.com/Neptune-Crypto/neptune-core/commit/d1391447))
- Update release workflow files ([da1e5877](https://github.com/Neptune-Crypto/neptune-core/commit/da1e5877))

### Trace

- *(mine_loop)* Show size of tx for merge ([0dc15ce6](https://github.com/Neptune-Crypto/neptune-core/commit/0dc15ce6))
- *(mine_loop)* Log fee or merged-in tx ([7b8df865](https://github.com/Neptune-Crypto/neptune-core/commit/7b8df865))

## [0.1.2](https://github.com/Neptune-Crypto/neptune-core/compare/v0.1.1..v0.1.2) - 2025-02-12

### 🐛 Bug Fixes

- *(mempool)* Don't attempt to update tx with no inputs ([7601f08b](https://github.com/Neptune-Crypto/neptune-core/commit/7601f08b))

### ✅ Testing

- Verify that only 0.0.x versions are incompatible ([3fcc82ad](https://github.com/Neptune-Crypto/neptune-core/commit/3fcc82ad))

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

- Set default CLI parameter network to "main" ([c551251f](https://github.com/Neptune-Crypto/neptune-core/commit/c551251f))
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
