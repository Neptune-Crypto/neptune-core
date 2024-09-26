NativeCurrency-4in-4out:
| Subroutine                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                          |         634 ( 23.7%) |         475 ( 21.5%) |         247 ( 45.7%) |         183 ( 22.0%) |          22 (  2.8%) |
| ··tasmlib_hashing_absorb_multiple                                     |         592 ( 22.1%) |         430 ( 19.5%) |         247 ( 45.7%) |         162 ( 19.5%) |          22 (  2.8%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks              |         162 (  6.0%) |         108 (  4.9%) |         240 ( 44.4%) |         144 ( 17.3%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                  |         238 (  8.9%) |         152 (  6.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                    |          81 (  3.0%) |          47 (  2.1%) |           7 (  1.3%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                         |          72 (  2.7%) |          52 (  2.4%) |           0 (  0.0%) |          36 (  4.3%) |          37 (  4.7%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero               |          24 (  0.9%) |           4 (  0.2%) |           0 (  0.0%) |          36 (  4.3%) |          24 (  3.1%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                       |          14 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  4.3%) |          24 (  3.1%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                   |          38 (  1.4%) |          49 (  2.2%) |           4 (  0.7%) |          13 (  1.6%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                       |          23 (  0.9%) |          34 (  1.5%) |           4 (  0.7%) |           6 (  0.7%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                          |          26 (  1.0%) |          23 (  1.0%) |           5 (  0.9%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_has_coinbase                           |           8 (  0.3%) |           9 (  0.4%) |           4 (  0.7%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts      |        1660 ( 61.9%) |        1400 ( 63.3%) |         264 ( 48.8%) |           0 (  0.0%) |         604 ( 77.1%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts    |        1320 ( 49.3%) |        1136 ( 51.4%) |         240 ( 44.4%) |           0 (  0.0%) |         574 ( 73.3%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount     |         424 ( 15.8%) |         304 ( 13.8%) |          48 (  8.9%) |           0 (  0.0%) |         544 ( 69.5%) |
| ······tasmlib_arithmetic_u128_safe_add                                |         224 (  8.4%) |         128 (  5.8%) |           0 (  0.0%) |           0 (  0.0%) |         544 ( 69.5%) |
| Total                                                                 |        2680 (100.0%) |        2210 (100.0%) |         541 (100.0%) |         832 (100.0%) |         783 (100.0%) |
