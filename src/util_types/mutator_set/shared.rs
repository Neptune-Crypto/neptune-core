use std::collections::HashMap;

pub const BITS_PER_U32: usize = 32;
pub const WINDOW_SIZE: usize = 32000;
pub const CHUNK_SIZE: usize = 1600;
pub const BATCH_SIZE: usize = 10;
pub const NUM_TRIALS: usize = 160;

pub fn bit_indices_to_hash_map(all_bit_indices: &[u128; NUM_TRIALS]) -> HashMap<u128, Vec<u128>> {
    let mut chunk_index_to_bit_indices: HashMap<u128, Vec<u128>> = HashMap::new();
    all_bit_indices
        .iter()
        .map(|bi| (bi / CHUNK_SIZE as u128, bi))
        .for_each(|(k, v)| {
            chunk_index_to_bit_indices
                .entry(k)
                .or_insert_with(Vec::new)
                .push(*v);
        });

    chunk_index_to_bit_indices
}
