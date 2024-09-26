NativeCurrency-2in-2out:
| Subroutine                                                            |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:----------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                          |         554 ( 31.2%) |         419 ( 28.7%) |         131 ( 44.7%) |         111 ( 14.6%) |          21 (  3.8%) |
| ··tasmlib_hashing_absorb_multiple                                     |         512 ( 28.8%) |         374 ( 25.7%) |         131 ( 44.7%) |          90 ( 11.8%) |          21 (  3.8%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks              |          90 (  5.1%) |          60 (  4.1%) |         120 ( 41.0%) |          72 (  9.5%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                  |         194 ( 10.9%) |         124 (  8.5%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                    |         117 (  6.6%) |          67 (  4.6%) |          11 (  3.8%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_merkle_verify                                         |          72 (  4.1%) |          52 (  3.6%) |           0 (  0.0%) |          36 (  4.7%) |          37 (  6.6%) |
| ··tasmlib_hashing_merkle_verify_tree_height_is_not_zero               |          24 (  1.4%) |           4 (  0.3%) |           0 (  0.0%) |          36 (  4.7%) |          24 (  4.3%) |
| ····tasmlib_hashing_merkle_verify_traverse_tree                       |          14 (  0.8%) |           0 (  0.0%) |           0 (  0.0%) |          36 (  4.7%) |          24 (  4.3%) |
| tasmlib_hashing_algebraic_hasher_hash_static_size_4                   |          38 (  2.1%) |          49 (  3.4%) |           4 (  1.4%) |          13 (  1.7%) |           0 (  0.0%) |
| ··tasmlib_hashing_absorb_multiple_static_size_4                       |          23 (  1.3%) |          34 (  2.3%) |           4 (  1.4%) |           6 (  0.8%) |           0 (  0.0%) |
| tasm_neptune_coinbase_amount                                          |          26 (  1.5%) |          23 (  1.6%) |           5 (  1.7%) |           0 (  0.0%) |           0 (  0.0%) |
| ··tasm_neptune_coinbase_amount_has_coinbase                           |           8 (  0.5%) |           9 (  0.6%) |           4 (  1.4%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_type_script_loop_utxos_add_amounts      |         836 ( 47.1%) |         704 ( 48.3%) |         132 ( 45.1%) |           0 (  0.0%) |         380 ( 68.1%) |
| ··neptune_consensus_transaction_type_script_loop_coins_add_amounts    |         660 ( 37.2%) |         568 ( 39.0%) |         120 ( 41.0%) |           0 (  0.0%) |         350 ( 62.7%) |
| ····neptune_consensus_transaction_type_script_read_and_add_amount     |         212 ( 11.9%) |         152 ( 10.4%) |          24 (  8.2%) |           0 (  0.0%) |         320 ( 57.3%) |
| ······tasmlib_arithmetic_u128_safe_add                                |         112 (  6.3%) |          64 (  4.4%) |           0 (  0.0%) |           0 (  0.0%) |         320 ( 57.3%) |
| Total                                                                 |        1776 (100.0%) |        1458 (100.0%) |         293 (100.0%) |         760 (100.0%) |         558 (100.0%) |
