CollectLockScripts-2in-2out:
| Subroutine                                                                       |            Processor |             Op Stack |                  RAM |                 Hash |                  U32 |
|:---------------------------------------------------------------------------------|---------------------:|---------------------:|---------------------:|---------------------:|---------------------:|
| tasmlib_hashing_algebraic_hasher_hash_varlen                                     |         182 ( 61.1%) |         137 ( 55.0%) |          45 ( 72.6%) |          37 ( 18.0%) |          12 (100.0%) |
| ··tasmlib_hashing_absorb_multiple                                                |         168 ( 56.4%) |         122 ( 49.0%) |          45 ( 72.6%) |          30 ( 14.6%) |          12 (100.0%) |
| ····tasmlib_hashing_absorb_multiple_hash_all_full_chunks                         |          30 ( 10.1%) |          20 (  8.0%) |          40 ( 64.5%) |          24 ( 11.7%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_pad_varnum_zeros                             |          50 ( 16.8%) |          32 ( 12.9%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| ····tasmlib_hashing_absorb_multiple_read_remainder                               |          51 ( 17.1%) |          29 ( 11.6%) |           5 (  8.1%) |           0 (  0.0%) |           0 (  0.0%) |
| tasmlib_hashing_eq_digest                                                        |          16 (  5.4%) |           9 (  3.6%) |           0 (  0.0%) |           0 (  0.0%) |           0 (  0.0%) |
| neptune_consensus_transaction_collect_lock_scripts_write_all_lock_script_digests |          66 ( 22.1%) |          72 ( 28.9%) |          14 ( 22.6%) |           0 (  0.0%) |           0 (  0.0%) |
| Total                                                                            |         298 (100.0%) |         249 (100.0%) |          62 (100.0%) |         205 (100.0%) |          12 (100.0%) |
