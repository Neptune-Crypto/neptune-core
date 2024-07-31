RemovalRecordsIntegrity-2in-2out:
| Subroutine                                                                               |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:-----------------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_mmr_bag_peaks                                                                    |         384 (  0.1%) |         664 (  0.3%) |         262 (  0.4%) |         300 (  0.6%) |          16 (  0.0%) |
| ··tasmlib_mmr_bag_peaks_length_is_not_zero                                               |         354 (  0.1%) |         638 (  0.3%) |         260 (  0.4%) |         300 (  0.6%) |           0 (  0.0%) |
| ····tasmlib_mmr_bag_peaks_length_is_not_zero_or_one                                      |         338 (  0.1%) |         626 (  0.2%) |         260 (  0.4%) |         300 (  0.6%) |           0 (  0.0%) |
| ······tasmlib_mmr_bag_peaks_loop                                                         |         302 (  0.1%) |         600 (  0.2%) |         250 (  0.4%) |         300 (  0.6%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                                            |          72 (  0.0%) |          52 (  0.0%) |           0 (  0.0%) |          36 (  0.1%) |          13 (  0.0%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero                                  |          24 (  0.0%) |           4 (  0.0%) |           0 (  0.0%) |          36 (  0.1%) |           0 (  0.0%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                                          |          14 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  0.1%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                             |       15816 (  4.4%) |       10574 (  4.2%) |       25852 ( 41.0%) |       15530 ( 31.2%) |          33 (  0.1%) |
| ··tasmlib_hashing_absorb_multiple                                                        |       15788 (  4.4%) |       10544 (  4.2%) |       25852 ( 41.0%) |       15516 ( 31.2%) |          33 (  0.1%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                                 |       15516 (  4.3%) |       10344 (  4.1%) |       25840 ( 41.0%) |       15504 ( 31.2%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                                     |          78 (  0.0%) |          50 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                       |         120 (  0.0%) |          68 (  0.0%) |          12 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_list_new___u64                                                                   |          28 (  0.0%) |          21 (  0.0%) |           3 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_memory_dyn_malloc                                                              |          21 (  0.0%) |          17 (  0.0%) |           2 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_memory_dyn_malloc_initialize                                                 |           4 (  0.0%) |           2 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| for_all_utxos                                                                            |      341496 ( 95.3%) |      240464 ( 95.3%) |       36851 ( 58.5%) |       31585 ( 63.5%) |       46502 ( 99.9%) |
| ··tasmlib_hashing_algebraic_hasher_hash_varlen                                           |         312 (  0.1%) |         234 (  0.1%) |          38 (  0.1%) |          38 (  0.1%) |          11 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple                                                      |         284 (  0.1%) |         204 (  0.1%) |          38 (  0.1%) |          24 (  0.0%) |          11 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_hash_all_full_chunks                               |          24 (  0.0%) |          16 (  0.0%) |          20 (  0.0%) |          12 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_pad_varnum_zeros                                   |          12 (  0.0%) |           8 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple_read_remainder                                     |         174 (  0.0%) |          98 (  0.0%) |          18 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_neptune_mutator_set_commit                                                     |           8 (  0.0%) |          20 (  0.0%) |           0 (  0.0%) |          24 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_mmr_verify_from_secret_in_leaf_index_on_stack                                  |        3862 (  1.1%) |        1996 (  0.8%) |          10 (  0.0%) |         756 (  1.5%) |        1846 (  4.0%) |
| ····tasmlib_mmr_leaf_index_to_mt_index_and_peak_index                                    |         250 (  0.1%) |         154 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |         720 (  1.5%) |
| ······tasmlib_arithmetic_u64_lt                                                          |          14 (  0.0%) |          10 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          66 (  0.1%) |
| ······tasmlib_arithmetic_u64_xor                                                         |          12 (  0.0%) |           4 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |         129 (  0.3%) |
| ······tasmlib_arithmetic_u64_log_2_floor                                                 |          32 (  0.0%) |          18 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          66 (  0.1%) |
| ········tasmlib_arithmetic_u64_log_2_floor_then                                          |          18 (  0.0%) |          10 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          66 (  0.1%) |
| ······tasmlib_arithmetic_u64_pow2                                                        |          10 (  0.0%) |           6 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          40 (  0.1%) |
| ······tasmlib_arithmetic_u64_decr                                                        |          40 (  0.0%) |          32 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_arithmetic_u64_decr_carry                                                |          24 (  0.0%) |          20 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_arithmetic_u64_and                                                         |          24 (  0.0%) |           8 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |         196 (  0.4%) |
| ······tasmlib_arithmetic_u64_add                                                         |          30 (  0.0%) |          16 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |         128 (  0.3%) |
| ······tasmlib_arithmetic_u64_popcount                                                    |          24 (  0.0%) |           4 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |          95 (  0.2%) |
| ····tasmlib_mmr_verify_from_secret_in_leaf_index_on_stack_auth_path_loop                 |        3556 (  1.0%) |        1780 (  0.7%) |           0 (  0.0%) |         756 (  1.5%) |        1122 (  2.4%) |
| ······tasmlib_arithmetic_u64_eq                                                          |         896 (  0.3%) |         384 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_merkle_step_u64_index                                              |        1890 (  0.5%) |         756 (  0.3%) |           0 (  0.0%) |         756 (  1.5%) |        1122 (  2.4%) |
| ····tasmlib_list_get_element___digest                                                    |          28 (  0.0%) |          30 (  0.0%) |          10 (  0.0%) |           0 (  0.0%) |           4 (  0.0%) |
| ··tasm_neptune_transaction_compute_indices                                               |        9446 (  2.6%) |        7074 (  2.8%) |         976 (  1.5%) |          86 (  0.2%) |        9058 ( 19.5%) |
| ····tasmlib_memory_push_ram_to_stack___u64                                               |          12 (  0.0%) |          10 (  0.0%) |           4 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_memory_push_ram_to_stack___digest                                            |          24 (  0.0%) |          32 (  0.0%) |          20 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_neptune_mutator_get_swbf_indices_1048576_45                                  |        9210 (  2.6%) |        6908 (  2.7%) |         938 (  1.5%) |          86 (  0.2%) |        9058 ( 19.5%) |
| ······tasmlib_arithmetic_u128_shift_right_static_3                                       |          50 (  0.0%) |          24 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |         128 (  0.3%) |
| ······tasmlib_arithmetic_u128_shift_left_static_12                                       |          46 (  0.0%) |          24 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |         128 (  0.3%) |
| ······tasmlib_hashing_algebraic_hasher_sample_indices                                    |        5534 (  1.5%) |        3978 (  1.6%) |         478 (  0.8%) |          60 (  0.1%) |        5799 ( 12.5%) |
| ········tasmlib_list_new___u32                                                           |          48 (  0.0%) |          38 (  0.0%) |           6 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··········tasmlib_memory_dyn_malloc                                                      |          68 (  0.0%) |          60 (  0.0%) |           8 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_hashing_algebraic_hasher_sample_indices_main_loop                        |        5470 (  1.5%) |        3932 (  1.6%) |         472 (  0.7%) |          60 (  0.1%) |        5799 ( 12.5%) |
| ··········tasmlib_list_length___u32                                                      |         448 (  0.1%) |         224 (  0.1%) |         112 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··········tasmlib_hashing_algebraic_hasher_sample_indices_then_reduce_and_save           |        3150 (  0.9%) |        1890 (  0.7%) |         360 (  0.6%) |           0 (  0.0%) |        5799 ( 12.5%) |
| ············tasmlib_list_push___u32                                                      |        1710 (  0.5%) |        1260 (  0.5%) |         360 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ··········tasmlib_hashing_algebraic_hasher_sample_indices_else_drop_tip                  |          60 (  0.0%) |          10 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_higher_order_u32_map_u32_to_u128_add_another_u128                     |        3530 (  1.0%) |        2788 (  1.1%) |         460 (  0.7%) |           0 (  0.0%) |        3003 (  6.4%) |
| ········tasmlib_list_new___u128                                                          |          48 (  0.0%) |          38 (  0.0%) |           6 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_list_higher_order_u32_map_u32_to_u128_add_another_u128_loop              |        3432 (  1.0%) |        2708 (  1.1%) |         450 (  0.7%) |           0 (  0.0%) |        3003 (  6.4%) |
| ··tasmlib_hashing_algebraic_hasher_hash_static_size_180                                  |         228 (  0.1%) |         188 (  0.1%) |         720 (  1.1%) |         484 (  1.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_static_size_180                                      |         168 (  0.0%) |         128 (  0.1%) |         720 (  1.1%) |         456 (  0.9%) |           0 (  0.0%) |
| ··tasmlib_list_contains___u64                                                            |          65 (  0.0%) |          54 (  0.0%) |          10 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_list_contains___u64_loop                                                     |          33 (  0.0%) |          26 (  0.0%) |           4 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··collect_aocl_index                                                                     |          80 (  0.0%) |          68 (  0.0%) |          16 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_list_push___u64                                                              |        1701 (  0.5%) |        1377 (  0.5%) |         405 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_list_new___u64                                                                 |          96 (  0.0%) |          76 (  0.0%) |          12 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_memory_dyn_malloc                                                            |          68 (  0.0%) |          60 (  0.0%) |           8 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··for_all_absolute_indices                                                               |       45699 ( 12.8%) |       38348 ( 15.2%) |        7789 ( 12.4%) |           0 (  0.0%) |        3054 (  6.6%) |
| ····tasmlib_arithmetic_u128_shift_right_static_12                                        |        2250 (  0.6%) |        1080 (  0.4%) |           0 (  0.0%) |           0 (  0.0%) |        2994 (  6.4%) |
| ····tasmlib_arithmetic_u64_lt_standard                                                   |         990 (  0.3%) |         810 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |          60 (  0.1%) |
| ······tasmlib_arithmetic_u64_lt_standard_aux                                             |         630 (  0.2%) |         450 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |          60 (  0.1%) |
| ····tasmlib_list_contains___u64                                                          |       37513 ( 10.5%) |       32080 ( 12.7%) |        7034 ( 11.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_contains___u64_loop                                                   |       36073 ( 10.1%) |       30820 ( 12.2%) |        6764 ( 10.7%) |           0 (  0.0%) |           0 (  0.0%) |
| ····collect_inactive_chunk_index                                                         |        2054 (  0.6%) |        1580 (  0.6%) |         395 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_push___u64                                                            |        1659 (  0.5%) |        1343 (  0.5%) |         395 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ··visit_all_chunks                                                                       |      278366 ( 77.7%) |      188818 ( 74.9%) |       26544 ( 42.1%) |       29941 ( 60.2%) |       32512 ( 69.8%) |
| ····tasmlib_hashing_algebraic_hasher_hash_varlen                                         |       13430 (  3.7%) |       10349 (  4.1%) |         948 (  1.5%) |        1501 (  3.0%) |          10 (  0.0%) |
| ······tasmlib_hashing_absorb_multiple                                                    |       12324 (  3.4%) |        9164 (  3.6%) |         948 (  1.5%) |         948 (  1.9%) |          10 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_hash_all_full_chunks                             |         948 (  0.3%) |         632 (  0.3%) |         790 (  1.3%) |         474 (  1.0%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_pad_varnum_zeros                                 |        6557 (  1.8%) |        4187 (  1.7%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_read_remainder                                   |        1896 (  0.5%) |        1106 (  0.4%) |         158 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_mmr_verify_from_memory                                                       |      256945 ( 71.7%) |      171114 ( 67.8%) |       24095 ( 38.2%) |       28440 ( 57.2%) |       32502 ( 69.8%) |
| ······tasmlib_mmr_leaf_index_to_mt_index_and_peak_index                                  |        9875 (  2.8%) |        6083 (  2.4%) |           0 (  0.0%) |           0 (  0.0%) |        8009 ( 17.2%) |
| ········tasmlib_arithmetic_u64_lt                                                        |         553 (  0.2%) |         395 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_arithmetic_u64_xor                                                       |         474 (  0.1%) |         158 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |        2549 (  5.5%) |
| ········tasmlib_arithmetic_u64_log_2_floor                                               |        1264 (  0.4%) |         711 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |          60 (  0.1%) |
| ··········tasmlib_arithmetic_u64_log_2_floor_then                                        |         711 (  0.2%) |         395 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |          60 (  0.1%) |
| ········tasmlib_arithmetic_u64_pow2                                                      |         395 (  0.1%) |         237 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |          37 (  0.1%) |
| ········tasmlib_arithmetic_u64_decr                                                      |        1580 (  0.4%) |        1264 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··········tasmlib_arithmetic_u64_decr_carry                                              |         948 (  0.3%) |         790 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_arithmetic_u64_and                                                       |         948 (  0.3%) |         316 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |        2728 (  5.9%) |
| ········tasmlib_arithmetic_u64_add                                                       |        1185 (  0.3%) |         632 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |        2549 (  5.5%) |
| ········tasmlib_arithmetic_u64_popcount                                                  |         948 (  0.3%) |         158 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |          86 (  0.2%) |
| ······tasmlib_mmr_verify_from_memory_loop                                                |      242725 ( 67.8%) |      161792 ( 64.1%) |       23700 ( 37.6%) |       28440 ( 57.2%) |       24493 ( 52.6%) |
| ········tasmlib_arithmetic_u64_div2                                                      |       71100 ( 19.8%) |       28440 ( 11.3%) |           0 (  0.0%) |           0 (  0.0%) |       11690 ( 25.1%) |
| ········tasmlib_hashing_swap_digest                                                      |       38115 ( 10.6%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_get_element___digest                                                  |        1106 (  0.3%) |        1185 (  0.5%) |         395 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_hashing_eq_digest                                                          |        1264 (  0.4%) |         711 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_list_multiset_equality_u64s                                                    |        2718 (  0.8%) |        2994 (  1.2%) |         652 (  1.0%) |         244 (  0.5%) |          21 (  0.0%) |
| ····tasmlib_list_multiset_equality_u64s_equal_length                                     |        2684 (  0.7%) |        2968 (  1.2%) |         648 (  1.0%) |         244 (  0.5%) |          21 (  0.0%) |
| ······tasmlib_hashing_algebraic_hasher_hash_varlen                                       |         812 (  0.2%) |         604 (  0.2%) |         320 (  0.5%) |         232 (  0.5%) |          21 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple                                                  |         756 (  0.2%) |         544 (  0.2%) |         320 (  0.5%) |         204 (  0.4%) |          21 (  0.0%) |
| ··········tasmlib_hashing_absorb_multiple_hash_all_full_chunks                           |         204 (  0.1%) |         136 (  0.1%) |         300 (  0.5%) |         180 (  0.4%) |           0 (  0.0%) |
| ··········tasmlib_hashing_absorb_multiple_pad_varnum_zeros                               |         200 (  0.1%) |         128 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··········tasmlib_hashing_absorb_multiple_read_remainder                                 |         204 (  0.1%) |         116 (  0.0%) |          20 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_list_multiset_equality_u64s_loop                                           |        1742 (  0.5%) |        2212 (  0.9%) |         316 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                                    |      358251 (100.0%) |      252217 (100.0%) |       63020 (100.0%) |       49708 (100.0%) |       46564 (100.0%) |