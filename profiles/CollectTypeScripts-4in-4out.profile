CollectTypeScripts-4in-4out:
| Subroutine                                                             |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                              |          32 (  1.2%) |          25 (  1.0%) |           3 (  0.4%) |           0 (  0.0%) |          32 ( 16.4%) |
| ··tasmlib_memory_dyn_malloc                                            |          25 (  0.9%) |          21 (  0.9%) |           2 (  0.3%) |           0 (  0.0%) |          32 ( 16.4%) |
| ····tasmlib_memory_dyn_malloc_initialize                               |           4 (  0.2%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                           |         476 ( 17.9%) |         354 ( 14.7%) |         242 ( 32.6%) |         170 ( 29.4%) |          13 (  6.7%) |
| ··tasmlib_hashing_absorb_multiple                                      |         448 ( 16.8%) |         324 ( 13.5%) |         242 ( 32.6%) |         156 ( 27.0%) |          13 (  6.7%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks               |         156 (  5.9%) |         104 (  4.3%) |         240 ( 32.3%) |         144 ( 24.9%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                   |         188 (  7.1%) |         120 (  5.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                     |          30 (  1.1%) |          18 (  0.7%) |           2 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                              |          32 (  1.2%) |          18 (  0.7%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_type_script_hashes_from_utxo     |        1990 ( 74.8%) |        1878 ( 78.2%) |         480 ( 64.6%) |           0 (  0.0%) |          90 ( 46.2%) |
| ··neptune_consensus_transaction_collect_type_script_hashes_from_coin   |        1714 ( 64.5%) |        1646 ( 68.6%) |         456 ( 61.4%) |           0 (  0.0%) |          60 ( 30.8%) |
| ····tasmlib_list_contains___digest                                     |        1026 ( 38.6%) |        1010 ( 42.1%) |         316 ( 42.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___digest_loop                              |         770 ( 29.0%) |         738 ( 30.7%) |         220 ( 29.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ····neptune_consensus_transaction_push_digest_to_list                  |          80 (  3.0%) |          76 (  3.2%) |          28 (  3.8%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___digest                                       |          42 (  1.6%) |          40 (  1.7%) |          16 (  2.2%) |           0 (  0.0%) |           0 (  0.0%) |
| netpune_consensus_transaction_write_all_digests                        |          34 (  1.3%) |          44 (  1.8%) |          10 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                  |        2659 (100.0%) |        2401 (100.0%) |         743 (100.0%) |         578 (100.0%) |         195 (100.0%) |
