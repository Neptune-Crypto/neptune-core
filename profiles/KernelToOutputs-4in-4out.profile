KernelToOutputs-4in-4out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___KernelToOutputsWitnessMemory           |         569 ( 28.8%) |         378 ( 24.4%) |          31 ( 10.5%) |           0 (  0.0%) |         220 ( 65.9%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         466 ( 23.6%) |         308 ( 19.9%) |          24 (  8.1%) |           0 (  0.0%) |         120 ( 35.9%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         236 ( 12.0%) |         160 ( 10.3%) |          12 (  4.1%) |           0 (  0.0%) |          60 ( 18.0%) |
| tasmlib_list_new___digest                                                         |          32 (  1.6%) |          25 (  1.6%) |           3 (  1.0%) |           0 (  0.0%) |          32 (  9.6%) |
| ··tasmlib_memory_dyn_malloc                                                       |          25 (  1.3%) |          21 (  1.4%) |           2 (  0.7%) |           0 (  0.0%) |          32 (  9.6%) |
| ····tasmlib_memory_dyn_malloc_initialize                                          |           4 (  0.2%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| kernel_to_outputs_calculate_canonical_commitments                                 |         826 ( 41.8%) |         708 ( 45.7%) |         144 ( 48.8%) |         124 ( 15.8%) |          31 (  9.3%) |
| ··tasmlib_list_get_element___digest                                               |          56 (  2.8%) |          60 (  3.9%) |          20 (  6.8%) |           0 (  0.0%) |          20 (  6.0%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                                    |         624 ( 31.6%) |         468 ( 30.2%) |          76 ( 25.8%) |          76 (  9.7%) |          11 (  3.3%) |
| ····tasmlib_hashing_absorb_multiple                                               |         568 ( 28.8%) |         408 ( 26.3%) |          76 ( 25.8%) |          48 (  6.1%) |          11 (  3.3%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks                        |          48 (  2.4%) |          32 (  2.1%) |          40 ( 13.6%) |          24 (  3.1%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros                            |          24 (  1.2%) |          16 (  1.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder                              |         348 ( 17.6%) |         196 ( 12.6%) |          36 ( 12.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                                              |          16 (  0.8%) |          40 (  2.6%) |           0 (  0.0%) |          48 (  6.1%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         384 ( 19.5%) |         290 ( 18.7%) |         106 ( 35.9%) |          86 ( 10.9%) |          24 (  7.2%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         356 ( 18.0%) |         260 ( 16.8%) |         106 ( 35.9%) |          72 (  9.2%) |          24 (  7.2%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          72 (  3.6%) |          48 (  3.1%) |         100 ( 33.9%) |          60 (  7.6%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         144 (  7.3%) |          92 (  5.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          66 (  3.3%) |          38 (  2.5%) |           6 (  2.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                                     |          35 (  1.8%) |          28 (  1.8%) |           0 (  0.0%) |          18 (  2.3%) |          27 (  8.1%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero                           |          12 (  0.6%) |           2 (  0.1%) |           0 (  0.0%) |          18 (  2.3%) |          12 (  3.6%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                                   |           7 (  0.4%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  2.3%) |          12 (  3.6%) |
| Total                                                                             |        1974 (100.0%) |        1550 (100.0%) |         295 (100.0%) |         786 (100.0%) |         334 (100.0%) |
