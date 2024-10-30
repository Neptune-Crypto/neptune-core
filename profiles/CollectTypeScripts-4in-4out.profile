CollectTypeScripts-4in-4out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___CollectTypeScriptsWitness              |        1464 ( 35.5%) |         972 ( 28.8%) |          78 (  9.5%) |           0 (  0.0%) |         250 ( 84.7%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |        1356 ( 32.9%) |         904 ( 26.8%) |          72 (  8.8%) |           0 (  0.0%) |         180 ( 61.0%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         896 ( 21.7%) |         608 ( 18.0%) |          48 (  5.8%) |           0 (  0.0%) |         120 ( 40.7%) |
| tasmlib_list_new___digest                                                         |          32 (  0.8%) |          25 (  0.7%) |           3 (  0.4%) |           0 (  0.0%) |          32 ( 10.8%) |
| ··tasmlib_memory_dyn_malloc                                                       |          25 (  0.6%) |          21 (  0.6%) |           2 (  0.2%) |           0 (  0.0%) |          32 ( 10.8%) |
| ····tasmlib_memory_dyn_malloc_initialize                                          |           4 (  0.1%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         476 ( 11.5%) |         354 ( 10.5%) |         242 ( 29.5%) |         170 ( 20.9%) |          13 (  4.4%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         448 ( 10.9%) |         324 (  9.6%) |         242 ( 29.5%) |         156 ( 19.2%) |          13 (  4.4%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |         156 (  3.8%) |         104 (  3.1%) |         240 ( 29.2%) |         144 ( 17.7%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         188 (  4.6%) |         120 (  3.6%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          30 (  0.7%) |          18 (  0.5%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                         |          32 (  0.8%) |          18 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_type_script_hashes_from_utxo                |        1990 ( 48.2%) |        1878 ( 55.6%) |         480 ( 58.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ··neptune_consensus_transaction_collect_type_script_hashes_from_coin              |        1714 ( 41.5%) |        1646 ( 48.7%) |         456 ( 55.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_list_contains___digest                                                |        1026 ( 24.9%) |        1010 ( 29.9%) |         316 ( 38.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___digest_loop                                         |         770 ( 18.7%) |         738 ( 21.8%) |         220 ( 26.8%) |           0 (  0.0%) |           0 (  0.0%) |
| ····neptune_consensus_transaction_push_digest_to_list                             |          80 (  1.9%) |          76 (  2.2%) |          28 (  3.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___digest                                                  |          42 (  1.0%) |          40 (  1.2%) |          16 (  1.9%) |           0 (  0.0%) |           0 (  0.0%) |
| netpune_consensus_transaction_write_all_digests                                   |          34 (  0.8%) |          44 (  1.3%) |          10 (  1.2%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                             |        4126 (100.0%) |        3378 (100.0%) |         821 (100.0%) |         812 (100.0%) |         295 (100.0%) |
