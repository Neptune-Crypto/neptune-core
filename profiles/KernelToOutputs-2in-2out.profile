KernelToOutputs-2in-2out:
| Subroutine                                                       |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                        |          28 (  2.9%) |          21 (  2.6%) |           3 (  2.1%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_memory_dyn_malloc                                      |          21 (  2.2%) |          17 (  2.1%) |           2 (  1.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_memory_dyn_malloc_initialize                         |           4 (  0.4%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| kernel_to_outputs_calculate_canonical_commitments                |         416 ( 43.1%) |         356 ( 44.3%) |          72 ( 49.7%) |          62 ( 13.3%) |          20 ( 40.0%) |
| ··tasmlib_list_get_element___digest                              |          28 (  2.9%) |          30 (  3.7%) |          10 (  6.9%) |           0 (  0.0%) |           9 ( 18.0%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                   |         312 ( 32.3%) |         234 ( 29.1%) |          38 ( 26.2%) |          38 (  8.2%) |          11 ( 22.0%) |
| ····tasmlib_hashing_absorb_multiple                              |         284 ( 29.4%) |         204 ( 25.4%) |          38 ( 26.2%) |          24 (  5.2%) |          11 ( 22.0%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks       |          24 (  2.5%) |          16 (  2.0%) |          20 ( 13.8%) |          12 (  2.6%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros           |          12 (  1.2%) |           8 (  1.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder             |         174 ( 18.0%) |          98 ( 12.2%) |          18 ( 12.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                             |           8 (  0.8%) |          20 (  2.5%) |           0 (  0.0%) |          24 (  5.2%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                     |         354 ( 36.7%) |         270 ( 33.6%) |          56 ( 38.6%) |          56 ( 12.0%) |          22 ( 44.0%) |
| ··tasmlib_hashing_absorb_multiple                                |         326 ( 33.8%) |         240 ( 29.9%) |          56 ( 38.6%) |          42 (  9.0%) |          22 ( 44.0%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks         |          42 (  4.4%) |          28 (  3.5%) |          50 ( 34.5%) |          30 (  6.4%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros             |         144 ( 14.9%) |          92 ( 11.4%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder               |          66 (  6.8%) |          38 (  4.7%) |           6 (  4.1%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                    |          36 (  3.7%) |          26 (  3.2%) |           0 (  0.0%) |          18 (  3.9%) |           8 ( 16.0%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero          |          12 (  1.2%) |           2 (  0.2%) |           0 (  0.0%) |          18 (  3.9%) |           0 (  0.0%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                  |           7 (  0.7%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  3.9%) |           0 (  0.0%) |
| Total                                                            |         965 (100.0%) |         804 (100.0%) |         145 (100.0%) |         466 (100.0%) |          50 (100.0%) |
