CollectTypeScripts-2in-2out:
| Subroutine                                                             |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                              |          32 (  2.0%) |          25 (  1.8%) |           3 (  0.8%) |           0 (  0.0%) |          32 ( 16.5%) |
| ··tasmlib_memory_dyn_malloc                                            |          25 (  1.6%) |          21 (  1.5%) |           2 (  0.5%) |           0 (  0.0%) |          32 ( 16.5%) |
| ····tasmlib_memory_dyn_malloc_initialize                               |           4 (  0.3%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                           |         396 ( 24.8%) |         298 ( 21.0%) |         126 ( 32.2%) |          98 ( 19.4%) |          12 (  6.2%) |
| ··tasmlib_hashing_absorb_multiple                                      |         368 ( 23.0%) |         268 ( 18.9%) |         126 ( 32.2%) |          84 ( 16.6%) |          12 (  6.2%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks               |          84 (  5.3%) |          56 (  4.0%) |         120 ( 30.7%) |          72 ( 14.2%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                   |         144 (  9.0%) |          92 (  6.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                     |          66 (  4.1%) |          38 (  2.7%) |           6 (  1.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                              |          32 (  2.0%) |          18 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_type_script_hashes_from_utxo     |        1010 ( 63.2%) |         950 ( 67.0%) |         244 ( 62.4%) |           0 (  0.0%) |          90 ( 46.4%) |
| ··neptune_consensus_transaction_collect_type_script_hashes_from_coin   |         866 ( 54.2%) |         830 ( 58.6%) |         232 ( 59.3%) |           0 (  0.0%) |          60 ( 30.9%) |
| ····tasmlib_list_contains___digest                                     |         482 ( 30.1%) |         474 ( 33.5%) |         148 ( 37.9%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___digest_loop                              |         354 ( 22.1%) |         338 ( 23.9%) |         100 ( 25.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ····neptune_consensus_transaction_push_digest_to_list                  |          80 (  5.0%) |          76 (  5.4%) |          28 (  7.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___digest                                       |          42 (  2.6%) |          40 (  2.8%) |          16 (  4.1%) |           0 (  0.0%) |           0 (  0.0%) |
| netpune_consensus_transaction_write_all_digests                        |          34 (  2.1%) |          44 (  3.1%) |          10 (  2.6%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                  |        1599 (100.0%) |        1417 (100.0%) |         391 (100.0%) |         506 (100.0%) |         194 (100.0%) |
