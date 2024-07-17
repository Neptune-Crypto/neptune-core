CollectTypeScripts-2in-2out:
| Subroutine                                                             |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                              |          28 (  1.8%) |          21 (  1.5%) |           3 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_memory_dyn_malloc                                            |          21 (  1.3%) |          17 (  1.2%) |           2 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_memory_dyn_malloc_initialize                               |           4 (  0.3%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                           |         396 ( 25.4%) |         298 ( 21.1%) |         126 ( 32.2%) |          98 ( 20.3%) |          12 (100.0%) |
| ··tasmlib_hashing_absorb_multiple                                      |         368 ( 23.6%) |         268 ( 19.0%) |         126 ( 32.2%) |          84 ( 17.4%) |          12 (100.0%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks               |          84 (  5.4%) |          56 (  4.0%) |         120 ( 30.7%) |          72 ( 14.9%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                   |         144 (  9.2%) |          92 (  6.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                     |          66 (  4.2%) |          38 (  2.7%) |           6 (  1.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                              |          32 (  2.1%) |          18 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_type_script_hashes_from_utxo     |         982 ( 63.1%) |         950 ( 67.2%) |         244 ( 62.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ··neptune_consensus_transaction_collect_type_script_hashes_from_coin   |         846 ( 54.3%) |         830 ( 58.7%) |         232 ( 59.3%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_list_contains___digest                                     |         482 ( 31.0%) |         474 ( 33.5%) |         148 ( 37.9%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___digest_loop                              |         354 ( 22.7%) |         338 ( 23.9%) |         100 ( 25.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ····neptune_consensus_transaction_push_digest_to_list                  |          76 (  4.9%) |          76 (  5.4%) |          28 (  7.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___digest                                       |          42 (  2.7%) |          40 (  2.8%) |          16 (  4.1%) |           0 (  0.0%) |           0 (  0.0%) |
| netpune_consensus_transaction_write_all_digests                        |          34 (  2.2%) |          44 (  3.1%) |          10 (  2.6%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                  |        1557 (100.0%) |        1413 (100.0%) |         391 (100.0%) |         482 (100.0%) |          12 (100.0%) |
