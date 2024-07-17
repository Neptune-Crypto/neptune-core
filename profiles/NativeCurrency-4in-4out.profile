NativeCurrency-4in-4out:
| Subroutine                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                          |         642 ( 24.7%) |         483 ( 21.8%) |         243 ( 45.6%) |         183 ( 22.8%) |          15 (  2.2%) |
| ··tasmlib_hashing_absorb_multiple                                     |         600 ( 23.1%) |         438 ( 19.8%) |         243 ( 45.6%) |         162 ( 20.2%) |          15 (  2.2%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks              |         162 (  6.2%) |         108 (  4.9%) |         240 ( 45.0%) |         144 ( 18.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                  |         282 ( 10.8%) |         180 (  8.1%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                    |          45 (  1.7%) |          27 (  1.2%) |           3 (  0.6%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                         |          72 (  2.8%) |          52 (  2.3%) |           0 (  0.0%) |          36 (  4.5%) |          13 (  1.9%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero               |          24 (  0.9%) |           4 (  0.2%) |           0 (  0.0%) |          36 (  4.5%) |           0 (  0.0%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                       |          14 (  0.5%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  4.5%) |           0 (  0.0%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                   |          38 (  1.5%) |          49 (  2.2%) |           4 (  0.8%) |          13 (  1.6%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                       |          23 (  0.9%) |          34 (  1.5%) |           4 (  0.8%) |           6 (  0.7%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                          |          25 (  1.0%) |          19 (  0.9%) |           1 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_no_coinbase                            |           7 (  0.3%) |           5 (  0.2%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts      |        1596 ( 61.3%) |        1400 ( 63.2%) |         264 ( 49.5%) |           0 (  0.0%) |         647 ( 95.9%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts    |        1272 ( 48.9%) |        1136 ( 51.3%) |         240 ( 45.0%) |           0 (  0.0%) |         647 ( 95.9%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount     |         408 ( 15.7%) |         304 ( 13.7%) |          48 (  9.0%) |           0 (  0.0%) |         647 ( 95.9%) |
| ······tasmlib_arithmetic_u128_safe_add                                |         224 (  8.6%) |         128 (  5.8%) |           0 (  0.0%) |           0 (  0.0%) |         647 ( 95.9%) |
| Total                                                                 |        2603 (100.0%) |        2214 (100.0%) |         533 (100.0%) |         802 (100.0%) |         675 (100.0%) |
