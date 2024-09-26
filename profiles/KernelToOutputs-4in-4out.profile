KernelToOutputs-4in-4out:
| Subroutine                                                       |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_list_new___digest                                        |          32 (  2.2%) |          25 (  2.1%) |           3 (  1.1%) |           0 (  0.0%) |          32 ( 14.1%) |
| ··tasmlib_memory_dyn_malloc                                      |          25 (  1.7%) |          21 (  1.8%) |           2 (  0.7%) |           0 (  0.0%) |          32 ( 14.1%) |
| ····tasmlib_memory_dyn_malloc_initialize                         |           4 (  0.3%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| kernel_to_outputs_calculate_canonical_commitments                |         826 ( 57.8%) |         708 ( 60.0%) |         144 ( 53.9%) |         124 ( 21.1%) |          31 ( 13.7%) |
| ··tasmlib_list_get_element___digest                              |          56 (  3.9%) |          60 (  5.1%) |          20 (  7.5%) |           0 (  0.0%) |          20 (  8.8%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                   |         624 ( 43.7%) |         468 ( 39.7%) |          76 ( 28.5%) |          76 ( 12.9%) |          11 (  4.8%) |
| ····tasmlib_hashing_absorb_multiple                              |         568 ( 39.7%) |         408 ( 34.6%) |          76 ( 28.5%) |          48 (  8.2%) |          11 (  4.8%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks       |          48 (  3.4%) |          32 (  2.7%) |          40 ( 15.0%) |          24 (  4.1%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros           |          24 (  1.7%) |          16 (  1.4%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder             |         348 ( 24.4%) |         196 ( 16.6%) |          36 ( 13.5%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                             |          16 (  1.1%) |          40 (  3.4%) |           0 (  0.0%) |          48 (  8.2%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                     |         384 ( 26.9%) |         290 ( 24.6%) |         106 ( 39.7%) |          86 ( 14.6%) |          24 ( 10.6%) |
| ··tasmlib_hashing_absorb_multiple                                |         356 ( 24.9%) |         260 ( 22.0%) |         106 ( 39.7%) |          72 ( 12.2%) |          24 ( 10.6%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks         |          72 (  5.0%) |          48 (  4.1%) |         100 ( 37.5%) |          60 ( 10.2%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros             |         144 ( 10.1%) |          92 (  7.8%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder               |          66 (  4.6%) |          38 (  3.2%) |           6 (  2.2%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                    |          36 (  2.5%) |          26 (  2.2%) |           0 (  0.0%) |          18 (  3.1%) |          20 (  8.8%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero          |          12 (  0.8%) |           2 (  0.2%) |           0 (  0.0%) |          18 (  3.1%) |          12 (  5.3%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                  |           7 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  3.1%) |          12 (  5.3%) |
| Total                                                            |        1429 (100.0%) |        1180 (100.0%) |         267 (100.0%) |         588 (100.0%) |         227 (100.0%) |
