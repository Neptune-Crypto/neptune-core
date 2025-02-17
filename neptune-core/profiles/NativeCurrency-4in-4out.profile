NativeCurrency-4in-4out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___NativeCurrencyWitnessMemory            |        1506 ( 36.1%) |        1000 ( 31.1%) |          80 ( 13.1%) |           0 (  0.0%) |         280 ( 30.6%) |
| ··tasmlib_tasmobject_size_verifier_option_none                                    |           4 (  0.1%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |        1356 ( 32.5%) |         904 ( 28.1%) |          72 ( 11.8%) |           0 (  0.0%) |         180 ( 19.7%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         896 ( 21.5%) |         608 ( 18.9%) |          48 (  7.9%) |           0 (  0.0%) |         120 ( 13.1%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         642 ( 15.4%) |         483 ( 15.0%) |         243 ( 39.8%) |         183 ( 16.8%) |          15 (  1.6%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         600 ( 14.4%) |         438 ( 13.6%) |         243 ( 39.8%) |         162 ( 14.9%) |          15 (  1.6%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |         162 (  3.9%) |         108 (  3.4%) |         240 ( 39.3%) |         144 ( 13.2%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         282 (  6.8%) |         180 (  5.6%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          45 (  1.1%) |          27 (  0.8%) |           3 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                                     |          70 (  1.7%) |          56 (  1.7%) |           0 (  0.0%) |          36 (  3.3%) |          44 (  4.8%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero                           |          24 (  0.6%) |           4 (  0.1%) |           0 (  0.0%) |          36 (  3.3%) |          24 (  2.6%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                                   |          14 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  3.3%) |          24 (  2.6%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                               |          38 (  0.9%) |          49 (  1.5%) |           4 (  0.7%) |          13 (  1.2%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                                   |          23 (  0.6%) |          34 (  1.1%) |           4 (  0.7%) |           6 (  0.6%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                                      |          25 (  0.6%) |          19 (  0.6%) |           1 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_no_coinbase                                        |           7 (  0.2%) |           5 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts                  |        1660 ( 39.8%) |        1400 ( 43.5%) |         264 ( 43.2%) |           0 (  0.0%) |         575 ( 62.9%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts                |        1320 ( 31.6%) |        1136 ( 35.3%) |         240 ( 39.3%) |           0 (  0.0%) |         575 ( 62.9%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount                 |         424 ( 10.2%) |         304 (  9.4%) |          48 (  7.9%) |           0 (  0.0%) |         575 ( 62.9%) |
| ······tasmlib_arithmetic_u128_safe_add                                            |         224 (  5.4%) |         128 (  4.0%) |           0 (  0.0%) |           0 (  0.0%) |         575 ( 62.9%) |
| Total                                                                             |        4173 (100.0%) |        3218 (100.0%) |         611 (100.0%) |        1090 (100.0%) |         914 (100.0%) |
