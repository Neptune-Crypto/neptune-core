NativeCurrency-2in-2out:
| Subroutine                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                          |         562 ( 32.5%) |         427 ( 29.2%) |         127 ( 44.6%) |         111 ( 15.2%) |          19 (  5.4%) |
| ··tasmlib_hashing_absorb_multiple                                     |         520 ( 30.0%) |         382 ( 26.1%) |         127 ( 44.6%) |          90 ( 12.3%) |          19 (  5.4%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks              |          90 (  5.2%) |          60 (  4.1%) |         120 ( 42.1%) |          72 (  9.9%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                  |         238 ( 13.7%) |         152 ( 10.4%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                    |          81 (  4.7%) |          47 (  3.2%) |           7 (  2.5%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                         |          72 (  4.2%) |          52 (  3.6%) |           0 (  0.0%) |          36 (  4.9%) |          13 (  3.7%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero               |          24 (  1.4%) |           4 (  0.3%) |           0 (  0.0%) |          36 (  4.9%) |           0 (  0.0%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                       |          14 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  4.9%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                   |          38 (  2.2%) |          49 (  3.4%) |           4 (  1.4%) |          13 (  1.8%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                       |          23 (  1.3%) |          34 (  2.3%) |           4 (  1.4%) |           6 (  0.8%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                          |          25 (  1.4%) |          19 (  1.3%) |           1 (  0.4%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_no_coinbase                            |           7 (  0.4%) |           5 (  0.3%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts      |         804 ( 46.4%) |         704 ( 48.2%) |         132 ( 46.3%) |           0 (  0.0%) |         321 ( 90.9%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts    |         636 ( 36.7%) |         568 ( 38.9%) |         120 ( 42.1%) |           0 (  0.0%) |         321 ( 90.9%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount     |         204 ( 11.8%) |         152 ( 10.4%) |          24 (  8.4%) |           0 (  0.0%) |         321 ( 90.9%) |
| ······tasmlib_arithmetic_u128_safe_add                                |         112 (  6.5%) |          64 (  4.4%) |           0 (  0.0%) |           0 (  0.0%) |         321 ( 90.9%) |
| Total                                                                 |        1731 (100.0%) |        1462 (100.0%) |         285 (100.0%) |         730 (100.0%) |         353 (100.0%) |
