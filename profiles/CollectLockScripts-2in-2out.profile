CollectLockScripts-2in-2out:
| Subroutine                                                                       |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:---------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                                     |         182 ( 59.5%) |         137 ( 55.0%) |          45 ( 72.6%) |          37 ( 17.5%) |          12 ( 11.8%) |
| ··tasmlib_hashing_absorb_multiple                                                |         168 ( 54.9%) |         122 ( 49.0%) |          45 ( 72.6%) |          30 ( 14.2%) |          12 ( 11.8%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                         |          30 (  9.8%) |          20 (  8.0%) |          40 ( 64.5%) |          24 ( 11.4%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                             |          50 ( 16.3%) |          32 ( 12.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                               |          51 ( 16.7%) |          29 ( 11.6%) |           5 (  8.1%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                        |          16 (  5.2%) |           9 (  3.6%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests |          70 ( 22.9%) |          72 ( 28.9%) |          14 ( 22.6%) |           0 (  0.0%) |          30 ( 29.4%) |
| Total                                                                            |         306 (100.0%) |         249 (100.0%) |          62 (100.0%) |         211 (100.0%) |         102 (100.0%) |
