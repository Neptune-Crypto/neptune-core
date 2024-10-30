TimeLock-2in-2out:
| Subroutine                                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:--------------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| main                                                                                  |        1504 ( 99.9%) |        1188 (100.0%) |         179 (100.0%) |          80 ( 11.6%) |         730 (100.0%) |
| ··tasmlib_verifier_own_program_digest                                                 |           7 (  0.5%) |           5 (  0.4%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_io_read_stdin___digest                                                      |           9 (  0.6%) |          15 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_io_read_secin___bfe                                                         |           9 (  0.6%) |           3 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··encode_BField                                                                       |          33 (  2.2%) |          26 (  2.2%) |           4 (  2.2%) |           0 (  0.0%) |          32 (  4.4%) |
| ····tasmlib_memory_dyn_malloc                                                         |          25 (  1.7%) |          21 (  1.8%) |           2 (  1.1%) |           0 (  0.0%) |          32 (  4.4%) |
| ······tasmlib_memory_dyn_malloc_initialize                                            |           4 (  0.3%) |           2 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_langs_hash_varlen                                                              |         172 ( 11.4%) |         132 ( 11.1%) |           2 (  1.1%) |          13 (  1.9%) |           7 (  1.0%) |
| ····tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         364 ( 24.2%) |         278 ( 23.4%) |          64 ( 35.8%) |          62 (  9.0%) |          19 (  2.6%) |
| ······tasmlib_hashing_absorb_multiple                                                 |         336 ( 22.3%) |         248 ( 20.9%) |          64 ( 35.8%) |          48 (  6.9%) |          19 (  2.6%) |
| ········tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          48 (  3.2%) |          32 (  2.7%) |          60 ( 33.5%) |          36 (  5.2%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         166 ( 11.0%) |         106 (  8.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_read_remainder                                |          48 (  3.2%) |          28 (  2.4%) |           4 (  2.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_hashing_merkle_verify                                                       |          36 (  2.4%) |          26 (  2.2%) |           0 (  0.0%) |          18 (  2.6%) |          20 (  2.7%) |
| ····tasmlib_hashing_merkle_verify_tree_height_is_not_zero                             |          12 (  0.8%) |           2 (  0.2%) |           0 (  0.0%) |          18 (  2.6%) |          12 (  1.6%) |
| ······tasmlib_hashing_merkle_verify_traverse_tree                                     |           7 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  2.6%) |          12 (  1.6%) |
| ··tasmlib_structure_verify_nd_si_integrity___SaltedUtxos                              |         384 ( 25.5%) |         252 ( 21.2%) |          20 ( 11.2%) |           0 (  0.0%) |         218 ( 29.9%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo         |         342 ( 22.7%) |         228 ( 19.2%) |          18 ( 10.1%) |           0 (  0.0%) |         180 ( 24.7%) |
| ······tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin       |         224 ( 14.9%) |         152 ( 12.8%) |          12 (  6.7%) |           0 (  0.0%) |         120 ( 16.4%) |
| ··tasm_langs_hash_varlen_boxed_value___SaltedUtxos                                    |         222 ( 14.8%) |         164 ( 13.8%) |          64 ( 35.8%) |          49 (  7.1%) |          44 (  6.0%) |
| ··tasmlib_hashing_eq_digest                                                           |          16 (  1.1%) |           9 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··_binop_Lt__LboolR_bool_32_while_loop                                                |         546 ( 36.3%) |         438 ( 36.9%) |          62 ( 34.6%) |           0 (  0.0%) |         402 ( 55.1%) |
| ····tasm_langs_dynamic_list_element_finder                                            |          27 (  1.8%) |          18 (  1.5%) |           1 (  0.6%) |           0 (  0.0%) |          32 (  4.4%) |
| ····_binop_Lt__LboolR_bool_42_while_loop                                              |         442 ( 29.4%) |         360 ( 30.3%) |          58 ( 32.4%) |           0 (  0.0%) |         367 ( 50.3%) |
| ······tasm_langs_dynamic_list_element_finder                                          |          54 (  3.6%) |          36 (  3.0%) |           2 (  1.1%) |           0 (  0.0%) |          32 (  4.4%) |
| ······tasmlib_hashing_eq_digest                                                       |          64 (  4.3%) |          36 (  3.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······_binop_Eq__LboolR_bool_49_else                                                  |           4 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_arithmetic_u32_safeadd                                                  |          36 (  2.4%) |          28 (  2.4%) |           0 (  0.0%) |           0 (  0.0%) |           3 (  0.4%) |
| ······_binop_Eq__LboolR_bool_49_then                                                  |         102 (  6.8%) |          76 (  6.4%) |           6 (  3.4%) |           0 (  0.0%) |         262 ( 35.9%) |
| ········tasmlib_arithmetic_u64_lt                                                     |          26 (  1.7%) |          14 (  1.2%) |           0 (  0.0%) |           0 (  0.0%) |         131 ( 17.9%) |
| ····tasmlib_arithmetic_u32_safeadd                                                    |          18 (  1.2%) |          14 (  1.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                                 |        1505 (100.0%) |        1188 (100.0%) |         179 (100.0%) |         692 (100.0%) |         730 (100.0%) |
