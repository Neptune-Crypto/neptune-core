CollectTypeScripts-2in-2out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___CollectTypeScriptsWitness              |         792 ( 33.1%) |         524 ( 26.9%) |          42 (  9.7%) |           0 (  0.0%) |         250 ( 85.0%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         684 ( 28.6%) |         456 ( 23.4%) |          36 (  8.3%) |           0 (  0.0%) |         180 ( 61.2%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         448 ( 18.7%) |         304 ( 15.6%) |          24 (  5.5%) |           0 (  0.0%) |         120 ( 40.8%) |
| tasmlib_list_new___digest                                                         |          32 (  1.3%) |          25 (  1.3%) |           3 (  0.7%) |           0 (  0.0%) |          32 ( 10.9%) |
| ··tasmlib_memory_dyn_malloc                                                       |          25 (  1.0%) |          21 (  1.1%) |           2 (  0.5%) |           0 (  0.0%) |          32 ( 10.9%) |
| ····tasmlib_memory_dyn_malloc_initialize                                          |           4 (  0.2%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         396 ( 16.5%) |         298 ( 15.3%) |         126 ( 29.1%) |          98 ( 13.2%) |          12 (  4.1%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         368 ( 15.4%) |         268 ( 13.8%) |         126 ( 29.1%) |          84 ( 11.4%) |          12 (  4.1%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          84 (  3.5%) |          56 (  2.9%) |         120 ( 27.7%) |          72 (  9.7%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         144 (  6.0%) |          92 (  4.7%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          66 (  2.8%) |          38 (  2.0%) |           6 (  1.4%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                         |          32 (  1.3%) |          18 (  0.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_type_script_hashes_from_utxo                |        1010 ( 42.2%) |         950 ( 48.8%) |         244 ( 56.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ··neptune_consensus_transaction_collect_type_script_hashes_from_coin              |         866 ( 36.2%) |         830 ( 42.7%) |         232 ( 53.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_list_contains___digest                                                |         482 ( 20.1%) |         474 ( 24.4%) |         148 ( 34.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___digest_loop                                         |         354 ( 14.8%) |         338 ( 17.4%) |         100 ( 23.1%) |           0 (  0.0%) |           0 (  0.0%) |
| ····neptune_consensus_transaction_push_digest_to_list                             |          80 (  3.3%) |          76 (  3.9%) |          28 (  6.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___digest                                                  |          42 (  1.8%) |          40 (  2.1%) |          16 (  3.7%) |           0 (  0.0%) |           0 (  0.0%) |
| netpune_consensus_transaction_write_all_digests                                   |          34 (  1.4%) |          44 (  2.3%) |          10 (  2.3%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                             |        2394 (100.0%) |        1946 (100.0%) |         433 (100.0%) |         740 (100.0%) |         294 (100.0%) |
