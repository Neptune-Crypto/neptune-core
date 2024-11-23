NativeCurrency-2in-2out:
| Subroutine                                                                        |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_structure_verify_nd_si_integrity___NativeCurrencyWitnessMemory            |         834 ( 32.1%) |         552 ( 27.4%) |          44 ( 13.5%) |           0 (  0.0%) |         280 ( 41.8%) |
| ··tasmlib_tasmobject_size_verifier_option_none                                    |           4 (  0.2%) |           2 (  0.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Utxo       |         684 ( 26.3%) |         456 ( 22.6%) |          36 ( 11.0%) |           0 (  0.0%) |         180 ( 26.9%) |
| ····tasmlib_structure_tasmobject_verify_size_indicators_dyn_elem_sizes___Coin     |         448 ( 17.3%) |         304 ( 15.1%) |          24 (  7.3%) |           0 (  0.0%) |         120 ( 17.9%) |
| tasmlib_hashing_algebraic_hasher_hash_varlen                                      |         562 ( 21.6%) |         427 ( 21.2%) |         127 ( 38.8%) |         111 ( 10.9%) |          19 (  2.8%) |
| ··tasmlib_hashing_absorb_multiple                                                 |         520 ( 20.0%) |         382 ( 18.9%) |         127 ( 38.8%) |          90 (  8.8%) |          19 (  2.8%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                          |          90 (  3.5%) |          60 (  3.0%) |         120 ( 36.7%) |          72 (  7.1%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                              |         238 (  9.2%) |         152 (  7.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                                |          81 (  3.1%) |          47 (  2.3%) |           7 (  2.1%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                                     |          70 (  2.7%) |          56 (  2.8%) |           0 (  0.0%) |          36 (  3.5%) |          44 (  6.6%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero                           |          24 (  0.9%) |           4 (  0.2%) |           0 (  0.0%) |          36 (  3.5%) |          24 (  3.6%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                                   |          14 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  3.5%) |          24 (  3.6%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                               |          38 (  1.5%) |          49 (  2.4%) |           4 (  1.2%) |          13 (  1.3%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                                   |          23 (  0.9%) |          34 (  1.7%) |           4 (  1.2%) |           6 (  0.6%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                                      |          25 (  1.0%) |          19 (  0.9%) |           1 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_no_coinbase                                        |           7 (  0.3%) |           5 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts                  |         836 ( 32.2%) |         704 ( 34.9%) |         132 ( 40.4%) |           0 (  0.0%) |         327 ( 48.8%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts                |         660 ( 25.4%) |         568 ( 28.1%) |         120 ( 36.7%) |           0 (  0.0%) |         327 ( 48.8%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount                 |         212 (  8.2%) |         152 (  7.5%) |          24 (  7.3%) |           0 (  0.0%) |         327 ( 48.8%) |
| ······tasmlib_arithmetic_u128_safe_add                                            |         112 (  4.3%) |          64 (  3.2%) |           0 (  0.0%) |           0 (  0.0%) |         327 ( 48.8%) |
| Total                                                                             |        2597 (100.0%) |        2018 (100.0%) |         327 (100.0%) |        1018 (100.0%) |         670 (100.0%) |
