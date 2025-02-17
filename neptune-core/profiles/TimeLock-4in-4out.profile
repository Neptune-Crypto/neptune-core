TimeLock-4in-4out:
| Subroutine                                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:--------------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| main                                                                                  |        2475 (100.0%) |        1910 (100.0%) |         320 (100.0%) |         116 ( 15.9%) |         920 (100.0%) |
| ··tasmlib_verifier_own_program_digest                                                 |           7 (  0.3%) |           5 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_io_read_stdin___digest                                                      |           9 (  0.4%) |          15 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_io_read_secin___bfe                                                         |           9 (  0.4%) |           3 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··encode_BField                                                                       |          33 (  1.3%) |          26 (  1.4%) |           4 (  1.2%) |           0 (  0.0%) |          32 (  3.5%) |
| ····tasmlib_memory_dyn_malloc                                                         |          25 (  1.0%) |          21 (  1.1%) |           2 (  0.6%) |           0 (  0.0%) |          32 (  3.5%) |
| ······tasmlib_memory_dyn_malloc_initialize                                            |           4 (  0.2%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_langs_hash_varlen                                                              |         172 (  6.9%) |         132 (  6.9%) |           2 (  0.6%) |          13 (  1.8%) |           7 (  0.8%) |
| ····tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         404 ( 16.3%) |         306 ( 16.0%) |         122 ( 38.1%) |          98 ( 13.5%) |          15 (  1.6%) |
| ······tasmlib_hashing_absorb_multiple                                                 |         376 ( 15.2%) |         276 ( 14.5%) |         122 ( 38.1%) |          84 ( 11.5%) |          15 (  1.6%) |
| ········tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          84 (  3.4%) |          56 (  2.9%) |         120 ( 37.5%) |          72 (  9.9%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         188 (  7.6%) |         120 (  6.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ········tasmlib_hashing_absorb_multiple_read_remainder                                |          30 (  1.2%) |          18 (  0.9%) |           2 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_hashing_merkle_verify                                                       |          36 (  1.5%) |          26 (  1.4%) |           0 (  0.0%) |          18 (  2.5%) |          20 (  2.2%) |
| ····tasmlib_hashing_merkle_verify_tree_height_is_not_zero                             |          12 (  0.5%) |           2 (  0.1%) |           0 (  0.0%) |          18 (  2.5%) |          12 (  1.3%) |
| ······tasmlib_hashing_merkle_verify_traverse_tree                                     |           7 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |          18 (  2.5%) |          12 (  1.3%) |
| ··tasmlib_structure_verify_nd_si_integrity___SaltedUtxos                              |         720 ( 29.1%) |         476 ( 24.9%) |          38 ( 11.9%) |           0 (  0.0%) |         219 ( 23.8%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo         |         678 ( 27.4%) |         452 ( 23.7%) |          36 ( 11.2%) |           0 (  0.0%) |         180 ( 19.6%) |
| ······tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin       |         448 ( 18.1%) |         304 ( 15.9%) |          24 (  7.5%) |           0 (  0.0%) |         120 ( 13.0%) |
| ··tasm_langs_hash_varlen_boxed_value___SaltedUtxos                                    |         262 ( 10.6%) |         192 ( 10.1%) |         122 ( 38.1%) |          85 ( 11.7%) |          40 (  4.3%) |
| ··tasmlib_hashing_eq_digest                                                           |          16 (  0.6%) |           9 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··_binop_Lt__LboolR_bool_32_while_loop                                                |        1141 ( 46.1%) |         908 ( 47.5%) |         127 ( 39.7%) |           0 (  0.0%) |         594 ( 64.6%) |
| ····tasm_langs_dynamic_list_element_finder                                            |         114 (  4.6%) |          76 (  4.0%) |           6 (  1.9%) |           0 (  0.0%) |          32 (  3.5%) |
| ····_binop_Lt__LboolR_bool_42_while_loop                                              |         884 ( 35.7%) |         720 ( 37.7%) |         116 ( 36.2%) |           0 (  0.0%) |         535 ( 58.2%) |
| ······tasm_langs_dynamic_list_element_finder                                          |         108 (  4.4%) |          72 (  3.8%) |           4 (  1.2%) |           0 (  0.0%) |          32 (  3.5%) |
| ······tasmlib_hashing_eq_digest                                                       |         128 (  5.2%) |          72 (  3.8%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······_binop_Eq__LboolR_bool_49_else                                                  |           8 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ······tasmlib_arithmetic_u32_safeadd                                                  |          72 (  2.9%) |          56 (  2.9%) |           0 (  0.0%) |           0 (  0.0%) |           3 (  0.3%) |
| ······_binop_Eq__LboolR_bool_49_then                                                  |         204 (  8.2%) |         152 (  8.0%) |          12 (  3.8%) |           0 (  0.0%) |         427 ( 46.4%) |
| ········tasmlib_arithmetic_u64_lt                                                     |          52 (  2.1%) |          28 (  1.5%) |           0 (  0.0%) |           0 (  0.0%) |         230 ( 25.0%) |
| ····tasmlib_arithmetic_u32_safeadd                                                    |          36 (  1.5%) |          28 (  1.5%) |           0 (  0.0%) |           0 (  0.0%) |           7 (  0.8%) |
| Total                                                                                 |        2476 (100.0%) |        1910 (100.0%) |         320 (100.0%) |         728 (100.0%) |         920 (100.0%) |
