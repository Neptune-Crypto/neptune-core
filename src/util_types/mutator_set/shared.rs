use std::collections::HashMap;

use super::set_commitment::{CHUNK_SIZE, NUM_TRIALS};

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
