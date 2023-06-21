use std::collections::{HashSet, VecDeque};

use field_count::FieldCount;
use itertools::Itertools;
use tasm_lib::{
    io::load_struct_from_input::LoadStructFromInput, snippet::InputSource,
    snippet_state::SnippetState, structure::get_field::GetField, DIGEST_LENGTH,
};
use triton_opcodes::program::{self, Program};
use triton_vm::BFieldElement;
use twenty_first::{
    shared_math::{bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{algebraic_hasher::AlgebraicHasher, mmr::mmr_trait::Mmr},
};

use crate::{
    models::blockchain::{
        shared::Hash,
        transaction::validity::{
            removal_records_integrity::RemovalRecordsIntegrityWitness,
            tasm::transaction_kernel_mast_hash::TransactionKernelMastHash,
        },
    },
    util_types::mutator_set::{
        mutator_set_kernel::get_swbf_indices, mutator_set_trait::commit,
        removal_record::AbsoluteIndexSet,
    },
};

pub struct RemovalRecordsIntegrity;

pub trait CompiledProgram {
    fn rust_shadow(
        &self,
        public_input: VecDeque<BFieldElement>,
        secret_input: VecDeque<BFieldElement>,
    ) -> Vec<BFieldElement>;
    fn program(&self) -> Program;
    fn crash_conditions(&self) -> Vec<String>;
}

impl CompiledProgram for RemovalRecordsIntegrity {
    fn rust_shadow(
        &self,
        public_input: VecDeque<BFieldElement>,
        secret_input: VecDeque<BFieldElement>,
    ) -> Vec<BFieldElement> {
        let hash_of_kernel =
            *Digest::decode(&public_input.into_iter().take(DIGEST_LENGTH).collect_vec())
                .expect("Could not decode public input in Removal Records Integrity :: verify_raw");

        // 1. read and process witness data
        let witness =
            *RemovalRecordsIntegrityWitness::decode(&secret_input.into_iter().collect_vec())
                .unwrap();

        // 2. assert that the kernel from the witness matches the hash in the public input
        // now we can trust all data in kernel
        assert_eq!(hash_of_kernel, witness.kernel.mast_hash());

        // assert that the mutator set's MMRs in the witness match the kernel
        // now we can trust all data in these MMRs as well
        let mutator_set_hash = Hash::hash_pair(
            &Hash::hash_pair(&witness.aocl.bag_peaks(), &witness.swbfi.bag_peaks()),
            &Hash::hash_pair(&witness.swbfa_hash, &Digest::default()),
        );
        assert_eq!(witness.kernel.mutator_set_hash, mutator_set_hash);

        // How do we trust input UTXOs?
        // Because they generate removal records, and we can match
        // those against the removal records that are listed in the
        // kernel.
        let items = witness.input_utxos.iter().map(Hash::hash).collect_vec();

        // test that removal records listed in kernel match those derived from input utxos
        let digests_of_derived_index_sets = items
            .iter()
            .zip(witness.membership_proofs.iter())
            .map(|(utxo, msmp)| {
                AbsoluteIndexSet::new(&get_swbf_indices::<Hash>(
                    &Hash::hash(utxo),
                    &msmp.sender_randomness,
                    &msmp.receiver_preimage,
                    msmp.auth_path_aocl.leaf_index,
                ))
                .encode()
            })
            .map(|x| Hash::hash_varlen(&x))
            .collect::<HashSet<_>>();
        let digests_of_claimed_index_sets = witness
            .kernel
            .inputs
            .iter()
            .map(|input| input.absolute_indices.encode())
            .map(|e| Hash::hash_varlen(&e))
            .collect::<HashSet<_>>();
        assert_eq!(digests_of_derived_index_sets, digests_of_claimed_index_sets);

        // verify that all input utxos (mutator set items) live in the AOCL
        assert!(items
            .iter()
            .zip(witness.membership_proofs.iter())
            .map(|(item, msmp)| {
                (
                    commit::<Hash>(
                        item,
                        &msmp.sender_randomness,
                        &msmp.receiver_preimage.hash::<Hash>(),
                    ),
                    &msmp.auth_path_aocl,
                )
            })
            .all(|(cc, mp)| {
                mp.verify(
                    &witness.aocl.get_peaks(),
                    &cc.canonical_commitment,
                    witness.aocl.count_leaves(),
                )
                .0
            }));

        vec![]
    }

    fn program(&self) -> Program {
        let mut library = SnippetState::default();
        let num_fields_on_witness = RemovalRecordsIntegrityWitness::field_count();
        let get_field = library.import(Box::new(GetField));
        let transaction_kernel_mast_hash = library.import(Box::new(TransactionKernelMastHash));
        let load_struct_from_input = library.import(Box::new(LoadStructFromInput {
            input_source: InputSource::SecretIn,
        }));
        let read_input = "read_io\n".repeat(DIGEST_LENGTH);

        let code = format!(
            "
        // 1. read RemovalRecordsIntegrityWitness from secio
        push {num_fields_on_witness}
        call {load_struct_from_input} // _ *witness

        // 2. assert that witness kernel hash == public input
        dup 0 // _ *witness *witness
        push 5 // _ *witness *witness 5 (= field kernel)
        call {get_field} // _ *witness *kernel
        call {transaction_kernel_mast_hash} // _ *witness [witness_kernel_digest]
        {read_input} // _ *witness [witness_kernel_digest] [input_kernel_digest]
        assert_vector
        pop pop pop pop pop // _ *witness [kernel_digest]

        halt
        "
        );

        let mut src = code;
        let imports = library.all_imports();
        src.push_str(&imports);

        program::Program::from_code(&src).unwrap()
    }

    fn crash_conditions(&self) -> Vec<String> {
        vec![
            "the kernel from the witness does not match the hash in the public input".to_string(),
            "the mutator set's MMRs in the witness do not match the kernel".to_string(),
            "removal records listed in kernel do not match those derived from input utxos"
                .to_string(),
            "not all input utxos (mutator set items) live in the AOCL".to_string(),
        ]
    }
}

#[cfg(test)]

mod tests {
    use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};

    use super::*;
    use crate::tests::shared::pseudorandom_removal_record_integrity_witness;

    #[test]
    fn test_graceful_halt() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa0;
        seed[1] = 0xf1;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record_integrity_witness =
            pseudorandom_removal_record_integrity_witness(rng.gen());
        let program = RemovalRecordsIntegrity.program();
        let stdin: Vec<BFieldElement> = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values()
            .to_vec();
        let secret_in: Vec<BFieldElement> = removal_record_integrity_witness.encode();

        // assert!(triton_vm::vm::run(&program, stdin, secret_in).is_ok());
        let run_res = triton_vm::vm::debug_terminal_state(&program, stdin, secret_in);
        match run_res {
            Ok(_) => (),
            Err((state, msg)) => panic!("Failed: {msg}\n last state was: {state}"),
        };
    }
}
