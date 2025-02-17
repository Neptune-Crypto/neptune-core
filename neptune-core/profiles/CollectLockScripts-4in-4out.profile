CollectLockScripts-4in-4out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___CollectLockScriptsWitness              |         527 ( 57.0%) |         346 ( 50.4%) |          27 ( 18.9%) |           0 (  0.0%) |         189 ( 93.6%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         466 ( 50.4%) |         308 ( 44.9%) |          24 ( 16.8%) |           0 (  0.0%) |         120 ( 59.4%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         236 ( 25.5%) |         160 ( 23.3%) |          12 (  8.4%) |           0 (  0.0%) |          60 ( 29.7%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         206 ( 22.3%) |         153 ( 22.3%) |          85 ( 59.4%) |          61 ( 14.7%) |          13 (  6.4%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         192 ( 20.8%) |         138 ( 20.1%) |          85 ( 59.4%) |          54 ( 13.0%) |          13 (  6.4%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          54 (  5.8%) |          36 (  5.2%) |          80 ( 55.9%) |          48 ( 11.6%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |          50 (  5.4%) |          32 (  4.7%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          51 (  5.5%) |          29 (  4.2%) |           5 (  3.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                         |          16 (  1.7%) |           9 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests  |         134 ( 14.5%) |         140 ( 20.4%) |          28 ( 19.6%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                             |         924 (100.0%) |         686 (100.0%) |         143 (100.0%) |         415 (100.0%) |         202 (100.0%) |
