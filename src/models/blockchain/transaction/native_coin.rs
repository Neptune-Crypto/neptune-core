use std::collections::VecDeque;

use anyhow::bail;
use num_traits::Zero;
use triton_opcodes::{program::Program, shortcuts::halt};
use triton_vm::bfield_codec::{decode_vec, BFieldCodec};
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
    _output: &mut VecDeque<BFieldElement>,
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

    // read secret input
    let mut read_secret_input = vec![secret_input.pop_front().unwrap()];
    let secret_input_length = read_secret_input[0].value() as usize;
    for _ in 0..secret_input_length {
        read_secret_input.push(secret_input.pop_front().unwrap());
    }

    // parse secret input
    let sequences: Vec<Vec<BFieldElement>> = *decode_vec(&read_secret_input)?;
    let input_sequence = &sequences[0];
    let output_sequence = &sequences[1];
    let pubscript_sequence = &sequences[2];
    let fee_sequence = &sequences[3];
    let coinbase_sequence = &sequences[4];
    let timestamp_sequence = &sequences[5];

    // parse utxos
    let input_utxos: Vec<Utxo> = *decode_vec(input_sequence)?;
    let output_utxos: Vec<Utxo> = *decode_vec(output_sequence)?;

    // parse amounts
    let fee = *Amount::decode(fee_sequence)?;
    let coinbase = if coinbase_sequence[0].value() == 1 {
        *Amount::decode(coinbase_sequence)?
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
    if total_inputs + coinbase < total_outputs + fee {
        bail!("Native coin logic error: transaction inflates money supply.")
    }

    // verify parsed secret input against digest provided in public input
    let leafs = [
        Hash::hash_varlen(input_sequence),
        Hash::hash_varlen(output_sequence),
        Hash::hash_varlen(pubscript_sequence),
        Hash::hash_varlen(fee_sequence),
        Hash::hash_varlen(coinbase_sequence),
        Hash::hash_varlen(timestamp_sequence),
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
