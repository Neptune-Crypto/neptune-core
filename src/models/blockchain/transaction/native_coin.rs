use std::collections::VecDeque;

use anyhow::bail;
use num_traits::Zero;
use triton_opcodes::{program::Program, shortcuts::halt};
use triton_vm::bfield_codec::BFieldCodec;
use twenty_first::{
    shared_math::{b_field_element::BFieldElement, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher, merkle_tree::CpuParallel,
        merkle_tree_maker::MerkleTreeMaker,
    },
};

use crate::models::blockchain::{
    shared::Hash,
    transaction::{
        amount::Amount,
        utxo::{TypeScript, Utxo},
    },
};

use super::amount::AmountLike;

pub const NATIVE_COIN_TYPESCRIPT_DIGEST: Digest = Digest::new([
    BFieldElement::new(0xf00ba12u64),
    BFieldElement::new(0xdeadbeefu64),
    BFieldElement::new(0xb0000b5u64),
    BFieldElement::new(0xdeadbeefu64),
    BFieldElement::new(0xdeadbeefu64),
]);

pub fn native_coin_program() -> Program {
    // todo: insert inflation check logic here
    Program::new(&[halt()])
}

pub fn native_coin_reference(
    public_input: &mut VecDeque<BFieldElement>,
    secret_input: &mut VecDeque<BFieldElement>,
    _output: &mut [BFieldElement],
) -> anyhow::Result<()> {
    // public input is kernel mast hash

    // Kernel mast hash is the Merkle root whose leafs are
    //  - hash_varlen(input_sequence)
    //  - hash_varlen(output_sequence)
    //  - hash_varlen(pubscript_hashes_and_inputs_sequence)
    //  - hash_varlen(fee_sequence)
    //  - hash_varlen(coinbase_sequence)
    //  - hash_varlen(timestamp_sequence)
    //  - Digest::default()
    //  - Digest::default().
    // The sequences are provided through secret_in.

    // parse secret input
    let mut input_sequence = vec![secret_input.pop_front().unwrap()];
    let input_sequence_length = input_sequence[0].value() as u32;
    for _ in 0..input_sequence_length {
        input_sequence.push(secret_input.pop_front().unwrap());
    }

    let mut output_sequence = vec![secret_input.pop_front().unwrap()];
    let output_sequence_length = output_sequence[0].value() as u32;
    for _ in 0..output_sequence_length {
        output_sequence.push(secret_input.pop_front().unwrap());
    }

    let mut pubscript_sequence = vec![secret_input.pop_front().unwrap()];
    let pubscript_sequence_length = pubscript_sequence[0].value() as u32;
    for _ in 0..pubscript_sequence_length {
        pubscript_sequence.push(secret_input.pop_front().unwrap());
    }

    let mut fee_sequence = vec![secret_input.pop_front().unwrap()];
    let fee_sequence_length = fee_sequence[0].value() as u32;
    for _ in 0..fee_sequence_length {
        fee_sequence.push(secret_input.pop_front().unwrap());
    }

    let mut coinbase_sequence = vec![secret_input.pop_front().unwrap()];
    let coinbase_sequence_length = coinbase_sequence[0].value() as u32;
    for _ in 0..coinbase_sequence_length {
        coinbase_sequence.push(secret_input.pop_front().unwrap());
    }

    let mut timestamp_sequence = vec![secret_input.pop_front().unwrap()];
    let timestamp_sequence_length = timestamp_sequence[0].value() as u32;
    for _ in 0..timestamp_sequence_length {
        timestamp_sequence.push(secret_input.pop_front().unwrap());
    }

    // parse input sequence as UTXOs
    let _num_input_utxos = output_sequence[0].value();
    let mut input_utxos = vec![];
    let mut read_index = 1;
    while read_index < output_sequence.len() {
        let utxo_length = output_sequence[read_index].value() as usize;
        read_index += 1;
        let utxo = *Utxo::decode(&output_sequence[read_index..read_index + utxo_length])?;
        read_index += utxo_length;
        input_utxos.push(utxo);
    }

    // parse output sequence as UTXOs
    let _num_output_utxos = output_sequence[0].value();
    let mut output_utxos = vec![];
    read_index = 1;
    while read_index < output_sequence.len() {
        let utxo_length = output_sequence[read_index].value() as usize;
        read_index += 1;
        let utxo = *Utxo::decode(&output_sequence[read_index..read_index + utxo_length])?;
        read_index += utxo_length;
        output_utxos.push(utxo);
    }

    // parse fee sequence as amount
    let fee = Amount::from_bfes(&fee_sequence);

    // parse coinbase sequence as amount
    let coinbase = if coinbase_sequence[0].value() == 1 {
        Amount::from_bfes(&coinbase_sequence)
    } else {
        Amount::zero()
    };

    // calculate totals
    let total_inputs: Amount = input_utxos
        .iter()
        .flat_map(|utxo| {
            utxo.coins
                .iter()
                .filter(|coin| coin.type_script_hash == TypeScript::native_coin().hash())
                .map(|coin| Amount::from_bfes(&coin.state))
        })
        .sum();
    let total_outputs: Amount = output_utxos
        .iter()
        .flat_map(|utxo| {
            utxo.coins
                .iter()
                .filter(|coin| coin.type_script_hash == TypeScript::native_coin().hash())
                .map(|coin| Amount::from_bfes(&coin.state))
        })
        .sum();

    // assert non-inflation
    if total_inputs + coinbase > total_outputs + fee {
        bail!("Native coin logic error: transaction inflates money supply.")
    }

    // verify parsed secret input against digest provided in public input
    let leafs = [
        Hash::hash_varlen(&input_sequence),
        Hash::hash_varlen(&output_sequence),
        Hash::hash_varlen(&pubscript_sequence),
        Hash::hash_varlen(&fee_sequence),
        Hash::hash_varlen(&coinbase_sequence),
        Hash::hash_varlen(&timestamp_sequence),
        Digest::default(),
        Digest::default(),
    ];
    let root = <CpuParallel as MerkleTreeMaker<Hash>>::from_digests(&leafs).get_root();
    let public_input_hash = [
        public_input.pop_front().unwrap(),
        public_input.pop_front().unwrap(),
        public_input.pop_front().unwrap(),
        public_input.pop_front().unwrap(),
        public_input.pop_front().unwrap(),
    ];
    if root.values() != public_input_hash {
        bail!("Native coin logic error: supplied secret input does not match with public input.");
    }

    Ok(())
}
