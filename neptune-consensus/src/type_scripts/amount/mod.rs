pub(crate) mod add_all_amounts_and_check_time_lock;
pub(crate) mod add_time_locked_amount;
pub mod get_total_and_timelocked_amounts;
pub(crate) mod read_and_add_amount;
pub(crate) mod test_time_lock_and_maybe_mark;
pub mod total_amount_main_loop;

const BAD_STATE_SIZE_ERROR: i128 = 1_000_400;
const UTXO_SIZE_TOO_LARGE_ERROR: i128 = 1_000_401;
const TOO_BIG_COIN_FIELD_SIZE_ERROR: i128 = 1_000_402;
const STATE_LENGTH_FOR_TIME_LOCK_NOT_ONE_ERROR: i128 = 1_000_403;

// Todo:
//  - support hardcoded digests for non-native-currency amount-like type
//    scripts.
