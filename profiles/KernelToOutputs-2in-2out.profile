KernelToOutputs-2in-2out:
| Subroutine                                                       |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                        |          32 (  3.2%) |          25 (  3.1%) |           3 (  2.1%) |           0 (  0.0%) |          32 ( 15.0%) |
| ··tasmlib_memory_dyn_malloc                                      |          25 (  2.5%) |          21 (  2.6%) |           2 (  1.4%) |           0 (  0.0%) |          32 ( 15.0%) |
| ····tasmlib_memory_dyn_malloc_initialize                         |           4 (  0.4%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| kernel_to_outputs_calculate_canonical_commitments                |         416 ( 42.1%) |         356 ( 44.1%) |          72 ( 49.7%) |          62 ( 12.5%) |          20 (  9.3%) |
| ··tasmlib_list_get_element___digest                              |          28 (  2.8%) |          30 (  3.7%) |          10 (  6.9%) |           0 (  0.0%) |           9 (  4.2%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                   |         312 ( 31.5%) |         234 ( 29.0%) |          38 ( 26.2%) |          38 (  7.7%) |          11 (  5.1%) |
| ····tasmlib_hashing_absorb_multiple                              |         284 ( 28.7%) |         204 ( 25.2%) |          38 ( 26.2%) |          24 (  4.8%) |          11 (  5.1%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks       |          24 (  2.4%) |          16 (  2.0%) |          20 ( 13.8%) |          12 (  2.4%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros           |          12 (  1.2%) |           8 (  1.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder             |         174 ( 17.6%) |          98 ( 12.1%) |          18 ( 12.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                             |           8 (  0.8%) |          20 (  2.5%) |           0 (  0.0%) |          24 (  4.8%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                     |         354 ( 35.8%) |         270 ( 33.4%) |          56 ( 38.6%) |          56 ( 11.3%) |          22 ( 10.3%) |
| ··tasmlib_hashing_absorb_multiple                                |         326 ( 33.0%) |         240 ( 29.7%) |          56 ( 38.6%) |          42 (  8.5%) |          22 ( 10.3%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks         |          42 (  4.2%) |          28 (  3.5%) |          50 ( 34.5%) |          30 (  6.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros             |         144 ( 14.6%) |          92 ( 11.4%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder               |          66 (  6.7%) |          38 (  4.7%) |           6 (  4.1%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                    |          36 (  3.6%) |          26 (  3.2%) |           0 (  0.0%) |          18 (  3.6%) |          20 (  9.3%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero          |          12 (  1.2%) |           2 (  0.2%) |           0 (  0.0%) |          18 (  3.6%) |          12 (  5.6%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                  |           7 (  0.7%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  3.6%) |          12 (  5.6%) |
| Total                                                            |         989 (100.0%) |         808 (100.0%) |         145 (100.0%) |         496 (100.0%) |         214 (100.0%) |
