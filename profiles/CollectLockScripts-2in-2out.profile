CollectLockScripts-2in-2out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___CollectLockScriptsWitness              |         297 ( 49.0%) |         194 ( 43.1%) |          15 ( 19.5%) |           0 (  0.0%) |         188 ( 94.0%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         236 ( 38.9%) |         156 ( 34.7%) |          12 ( 15.6%) |           0 (  0.0%) |         120 ( 60.0%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         118 ( 19.5%) |          80 ( 17.8%) |           6 (  7.8%) |           0 (  0.0%) |          60 ( 30.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         182 ( 30.0%) |         137 ( 30.4%) |          45 ( 58.4%) |          37 (  9.5%) |          12 (  6.0%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         168 ( 27.7%) |         122 ( 27.1%) |          45 ( 58.4%) |          30 (  7.7%) |          12 (  6.0%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          30 (  5.0%) |          20 (  4.4%) |          40 ( 51.9%) |          24 (  6.1%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |          50 (  8.3%) |          32 (  7.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          51 (  8.4%) |          29 (  6.4%) |           5 (  6.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                         |          16 (  2.6%) |           9 (  2.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests  |          70 ( 11.6%) |          72 ( 16.0%) |          14 ( 18.2%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                             |         606 (100.0%) |         450 (100.0%) |          77 (100.0%) |         391 (100.0%) |         200 (100.0%) |
