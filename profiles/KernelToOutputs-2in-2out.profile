KernelToOutputs-2in-2out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___KernelToOutputsWitnessMemory           |         339 ( 26.0%) |         226 ( 22.0%) |          19 ( 11.8%) |           0 (  0.0%) |         189 ( 65.2%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         236 ( 18.1%) |         156 ( 15.2%) |          12 (  7.5%) |           0 (  0.0%) |          90 ( 31.0%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         118 (  9.0%) |          80 (  7.8%) |           6 (  3.7%) |           0 (  0.0%) |          30 ( 10.3%) |
| tasmlib_list_new___digest                                                         |          32 (  2.5%) |          25 (  2.4%) |           3 (  1.9%) |           0 (  0.0%) |          32 ( 11.0%) |
| ··tasmlib_memory_dyn_malloc                                                       |          25 (  1.9%) |          21 (  2.0%) |           2 (  1.2%) |           0 (  0.0%) |          32 ( 11.0%) |
| ····tasmlib_memory_dyn_malloc_initialize                                          |           4 (  0.3%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| kernel_to_outputs_calculate_canonical_commitments                                 |         416 ( 31.9%) |         356 ( 34.7%) |          72 ( 44.7%) |          62 (  8.9%) |          20 (  6.9%) |
| ··tasmlib_list_get_element___digest                                               |          28 (  2.1%) |          30 (  2.9%) |          10 (  6.2%) |           0 (  0.0%) |           9 (  3.1%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                                    |         312 ( 23.9%) |         234 ( 22.8%) |          38 ( 23.6%) |          38 (  5.5%) |          11 (  3.8%) |
| ····tasmlib_hashing_absorb_multiple                                               |         284 ( 21.8%) |         204 ( 19.9%) |          38 ( 23.6%) |          24 (  3.5%) |          11 (  3.8%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks                        |          24 (  1.8%) |          16 (  1.6%) |          20 ( 12.4%) |          12 (  1.7%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros                            |          12 (  0.9%) |           8 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder                              |         174 ( 13.3%) |          98 (  9.6%) |          18 ( 11.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                                              |           8 (  0.6%) |          20 (  1.9%) |           0 (  0.0%) |          24 (  3.5%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         354 ( 27.1%) |         270 ( 26.3%) |          56 ( 34.8%) |          56 (  8.1%) |          22 (  7.6%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         326 ( 25.0%) |         240 ( 23.4%) |          56 ( 34.8%) |          42 (  6.1%) |          22 (  7.6%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          42 (  3.2%) |          28 (  2.7%) |          50 ( 31.1%) |          30 (  4.3%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         144 ( 11.0%) |          92 (  9.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          66 (  5.1%) |          38 (  3.7%) |           6 (  3.7%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                                     |          35 (  2.7%) |          28 (  2.7%) |           0 (  0.0%) |          18 (  2.6%) |          27 (  9.3%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero                           |          12 (  0.9%) |           2 (  0.2%) |           0 (  0.0%) |          18 (  2.6%) |          12 (  4.1%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                                   |           7 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  2.6%) |          12 (  4.1%) |
| Total                                                                             |        1304 (100.0%) |        1026 (100.0%) |         161 (100.0%) |         694 (100.0%) |         290 (100.0%) |
