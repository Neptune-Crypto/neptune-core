use crate::models::consensus::mast_hash::MastHash;
use crate::prelude::{triton_vm, twenty_first};

use std::collections::HashSet;

use crate::util_types::mmr::traits::*;
use crate::util_types::mmr::MmrAccumulator;
use itertools::Itertools;
use tasm_lib::data_type::DataType;
use tasm_lib::library::Library;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::traits::compiled_program::CompiledProgram;
use tasm_lib::{
    list::{
        contiguous_list::get_pointer_list::GetPointerList,
        higher_order::{all::All, inner_function::InnerFunction, map::Map, zip::Zip},
        multiset_equality::MultisetEquality,
    },
    mmr::bag_peaks::BagPeaks,
    DIGEST_LENGTH,
};
use triton_vm::instruction::LabelledInstruction;
use triton_vm::prelude::{triton_asm, BFieldElement, NonDeterminism, PublicInput};
use twenty_first::{
    shared_math::{bfield_codec::BFieldCodec, tip5::Digest},
    util_types::algebraic_hasher::AlgebraicHasher,
};

use crate::models::blockchain::transaction::validity::removal_records_integrity::{
    RemovalRecordsIntegrity, RemovalRecordsIntegrityWitness,
};
use crate::{
    models::blockchain::{
        shared::Hash,
        transaction::{
            transaction_kernel::TransactionKernel,
            validity::tasm::transaction_kernel_mast_hash::TransactionKernelMastHash,
        },
    },
    util_types::mutator_set::{
        mutator_set_kernel::get_swbf_indices, mutator_set_trait::commit,
        removal_record::AbsoluteIndexSet,
    },
};
use tasm_lib::memory::push_ram_to_stack::PushRamToStack;

use super::{
    compute_canonical_commitment::ComputeCanonicalCommitment, compute_indices::ComputeIndices,
    hash_index_list::HashIndexList, hash_removal_record_indices::HashRemovalRecordIndices,
    hash_utxo::HashUtxo, verify_aocl_membership::VerifyAoclMembership,
};

impl CompiledProgram for RemovalRecordsIntegrity {
    fn rust_shadow(
        public_input: &PublicInput,
        nondeterminism: &NonDeterminism<BFieldElement>,
    ) -> anyhow::Result<Vec<BFieldElement>> {
        // We must call async fn, but we cannot make this fn
        // async, as that would conflict with the trait, defined
        // in a non-async crate.
        //
        // The only way I know of to call an async fn inside a
        // sync fn is to create a new thread with new tokio runtime.
        // THis is of course fairly expensive.
        async fn rust_shadow_async(
            public_input: &PublicInput,
            nondeterminism: &NonDeterminism<BFieldElement>,
        ) -> anyhow::Result<Vec<BFieldElement>> {
            let hash_of_kernel = *Digest::decode(
                &public_input
                    .individual_tokens
                    .iter()
                    .copied()
                    .take(DIGEST_LENGTH)
                    .rev()
                    .collect_vec(),
            )
            .expect("Could not decode public input in Removal Records Integrity :: verify_raw");

            // 1. read and process witness data
            let removal_record_integrity_witness =
                *RemovalRecordsIntegrityWitness::decode_from_memory(
                    &nondeterminism.ram,
                    FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
                )
                .unwrap();

            println!(
                "first element of witness: {}",
                removal_record_integrity_witness.encode()[0]
            );
            println!(
                "first element of kernel: {}",
                removal_record_integrity_witness.kernel.encode()[0]
            );

            // 2. assert that the kernel from the witness matches the hash in the public input
            // now we can trust all data in kernel
            assert_eq!(
                hash_of_kernel,
                removal_record_integrity_witness.kernel.mast_hash(),
                "hash of kernel ({})\nwitness kernel ({})",
                hash_of_kernel,
                removal_record_integrity_witness.kernel.mast_hash()
            );

            // 3. assert that the mutator set's MMRs in the witness match the kernel
            // now we can trust all data in these MMRs as well
            let mutator_set_hash = Hash::hash_pair(
                Hash::hash_pair(
                    removal_record_integrity_witness.aocl.bag_peaks().await,
                    removal_record_integrity_witness.swbfi.bag_peaks().await,
                ),
                Hash::hash_pair(
                    removal_record_integrity_witness.swbfa_hash,
                    Digest::default(),
                ),
            );
            assert_eq!(
                removal_record_integrity_witness.kernel.mutator_set_hash,
                mutator_set_hash
            );

            // 4. derive index sets from inputs and match them against those listed in the kernel
            // How do we trust input UTXOs?
            // Because they generate removal records, and we can match
            // those against the removal records that are listed in the
            // kernel.
            let items = removal_record_integrity_witness
                .input_utxos
                .iter()
                .map(Hash::hash)
                .collect_vec();

            // test that removal records listed in kernel match those derived from input utxos
            let digests_of_derived_index_lists = items
                .iter()
                .zip(removal_record_integrity_witness.membership_proofs.iter())
                .map(|(&item, msmp)| {
                    AbsoluteIndexSet::new(&get_swbf_indices(
                        item,
                        msmp.sender_randomness,
                        msmp.receiver_preimage,
                        msmp.auth_path_aocl.leaf_index,
                    ))
                    .encode()
                })
                .map(|x| Hash::hash_varlen(&x))
                .collect::<HashSet<_>>();
            let digests_of_claimed_index_lists = removal_record_integrity_witness
                .kernel
                .inputs
                .iter()
                .map(|input| input.absolute_indices.encode())
                .map(|x| Hash::hash_varlen(&x))
                .collect::<HashSet<_>>();
            assert_eq!(
                digests_of_derived_index_lists,
                digests_of_claimed_index_lists
            );

            // 5. verify that all input utxos (mutator set items) live in the AOCL
            let peaks = removal_record_integrity_witness.aocl.get_peaks().await;
            let count_leaves = removal_record_integrity_witness.aocl.count_leaves().await;
            assert!(items
                .into_iter()
                .zip(removal_record_integrity_witness.membership_proofs.iter())
                .map(|(item, msmp)| {
                    (
                        commit(
                            item,
                            msmp.sender_randomness,
                            msmp.receiver_preimage.hash::<Hash>(),
                        ),
                        &msmp.auth_path_aocl,
                    )
                })
                .all(|(cc, mp)| { mp.verify(&peaks, cc.canonical_commitment, count_leaves,).0 }));

            Ok(vec![])
        }

        std::thread::scope(|s| {
            s.spawn(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                runtime.block_on(rust_shadow_async(public_input, nondeterminism))
            })
            .join()
            .unwrap()
        })
    }

    fn code() -> (Vec<LabelledInstruction>, Library) {
        let mut library = Library::new();
        let transaction_kernel_mast_hash = library.import(Box::new(TransactionKernelMastHash));
        let bag_peaks = library.import(Box::new(BagPeaks));
        let read_digest = library.import(Box::new(PushRamToStack {
            data_type: DataType::Digest,
        }));
        let map_hash_utxo = library.import(Box::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(HashUtxo)),
        }));
        let get_pointer_list = library.import(Box::new(GetPointerList {}));
        let zip_digest_with_void_pointer = library.import(Box::new(Zip {
            left_type: DataType::Digest,
            right_type: DataType::VoidPointer,
        }));
        let map_compute_indices = library.import(Box::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(ComputeIndices)),
        }));
        let map_hash_index_list = library.import(Box::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(HashIndexList)),
        }));
        let map_hash_removal_record_indices = library.import(Box::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(HashRemovalRecordIndices)),
        }));
        let multiset_equality = library.import(Box::new(MultisetEquality));

        let map_compute_canonical_commitment = library.import(Box::new(Map {
            f: InnerFunction::BasicSnippet(Box::new(ComputeCanonicalCommitment)),
        }));
        let all_verify_aocl_membership = library.import(Box::new(All {
            f: InnerFunction::BasicSnippet(Box::new(VerifyAoclMembership)),
        }));
        let _compute_indices = library.import(Box::new(ComputeIndices));

        // field getters
        let witness_to_kernel = tasm_lib::field!(RemovalRecordsIntegrityWitness::kernel);
        let witness_to_swbfa_hash = tasm_lib::field!(RemovalRecordsIntegrityWitness::swbfa_hash);
        let witness_to_swbfi = tasm_lib::field!(RemovalRecordsIntegrityWitness::swbfi);
        type MmraH = MmrAccumulator<Hash>;
        let swbfi_to_peaks = tasm_lib::field!(MmraH::peaks);
        let witness_to_aocl = tasm_lib::field!(RemovalRecordsIntegrityWitness::aocl);
        let kernel_to_mutator_set_hash = tasm_lib::field!(TransactionKernel::mutator_set_hash);
        let witness_to_utxos = tasm_lib::field!(RemovalRecordsIntegrityWitness::input_utxos);
        let witness_to_mps = tasm_lib::field!(RemovalRecordsIntegrityWitness::membership_proofs);
        let kernel_to_inputs = tasm_lib::field!(TransactionKernel::inputs);
        let aocl_to_leaf_count = tasm_lib::field!(MmraH::leaf_count);
        let aocl_to_peaks = tasm_lib::field!(MmraH::peaks);

        let code = triton_asm! {

        // 1. Witness was already loaded into memory, just point to it
        push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS} // _ *witness

        // 2. assert that witness kernel hash == public input
        dup 0                               // _ *witness *witness

        {&witness_to_kernel}                // _ *witness *kernel
        dup 0                               // _ *witness *kernel *kernel
        call {transaction_kernel_mast_hash} // _ *witness *kernel [witness_kernel_digest]
        read_io 5                           // _ *witness *kernel [witness_kernel_digest] [input_kernel_digest]
        assert_vector                       // _ *witness *kernel [witness_kernel_digest]
        pop 5                               // _ *witness *kernel

        // 3. assert that witness mutator set MMRs match those in kernel

        push 0 push 0 push 0 push 0 push 0 // _ *witness *kernel 0 0 0 0 0
        dup 6                              // _ *witness *kernel 0^5 *witness
        {&witness_to_swbfa_hash}           // _ *witness *kernel 0^5 *witness_swbfa_hash
        call {read_digest}

        hash // _ *witness *kernel [H(H(swbfaw)||0^5)]

        dup 6 // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness

        {&witness_to_swbfi} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi
        {&swbfi_to_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi_peaks
        call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash]

        dup 11 // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness
        {&witness_to_aocl} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl
        {&aocl_to_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl_peaks
        call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] [witness_aocl_hash]

        hash // _ *witness *kernel [H(H(swbfaw)||0^5)] [H(aocl||swbfi)]

        hash // _ *witness *kernel [Hw]

        dup 5 // _ *witness *kernel [Hw] *kernel
        {&kernel_to_mutator_set_hash} // _ *witness *kernel [Hw] *kernel_msh
        call {read_digest}
        // _ *witness *kernel [Hw] [Hk]

        assert_vector
        pop 5
        // _ *witness *kernel

        // 4. derive index sets and match them against kernel
        dup 1 // _ *witness *kernel *witness
        {&witness_to_utxos} // _ *witness *kernel *utxos
        call {get_pointer_list} // _ *witness *kernel *[*utxo]
        call {map_hash_utxo} // _ *witness *kernel *[item]

        dup 2 // _ *witness *kernel *[item] *witness
        {&witness_to_mps} //_ *witness *kernel *[items] *mps
        call {get_pointer_list} //_ *witness *kernel *[item] *[*mp]
        call {zip_digest_with_void_pointer} // _ *witness *kernel *[(item, *mp)]

        // store for later use
        dup 0  // _ *witness *kernel *[(item, *mp)] *[(item, *mp)]
        swap 3 // _  *[(item, *mp)] *kernel *[(item, *mp)] *witness
        swap 2 // _  *[(item, *mp)] *witness *[(item, *mp)] *kernel
        swap 1 // _  *[(item, *mp)] *witness *kernel *[(item, *mp)]

        call {map_compute_indices} // _  *[(item, *mp)] *witness *kernel *[*[index]]

        call {map_hash_index_list} // _  *[(item, *mp)] *witness *kernel *[index_list_hash]

        dup 1 // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *kernel
        {&kernel_to_inputs} // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *kernel_inputs
        call {get_pointer_list} // _  *[(item, *mp)] *witness *kernel *[index_list_hash] *[*tx_input]
        call {map_hash_removal_record_indices} // _  *[(item, *mp)] *witness *kernel *[witness_index_list_hash] *[kernel_index_list_hash]

        call {multiset_equality} // _  *[(item, *mp)] *witness *kernel witness_inputs==kernel_inputs

        assert // _  *[(item, *mp)] *witness *kernel

        // 5. verify that all items' commitments live in the aocl
        // get aocl leaf count
        dup 1 // _ *[(item, *mp)] *witness *kernel *witness
        {&witness_to_aocl}              // _ *[(item, *mp)] *witness *kernel *aocl
        dup 0                   // _ *[(item, *mp)] *witness *kernel *aocl *aocl
        {&aocl_to_leaf_count} // _ *[(item, *mp)] *witness *kernel *aocl *leaf_count
        push 1 add // _ *[(item, *mp)] *witness *kernel *aocl *leaf_count_last_word
        read_mem 2
        pop 1      // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo

        dup 2                   // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *aocl
        {&aocl_to_peaks}              // _ *[(item, *mp)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *peaks

        swap 6 // _ *peaks *witness *kernel *aocl leaf_count_hi leaf_count_lo *[(item, *mp)]
        swap 2 // _ *peaks *witness *kernel *aocl *[(item, *mp)] leaf_count_lo leaf_count_hi
        swap 5 // _ *peaks leaf_count_hi *kernel *aocl *[(item, *mp)] leaf_count_lo *witness
        pop  1 // _ *peaks leaf_count_hi *kernel *aocl *[(item, *mp)] leaf_count_lo
        swap 3 // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(item, *mp)] *kernel
        pop  1 // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(item, *mp)]
        swap 1 // _ *peaks leaf_count_hi leaf_count_lo *[(item, *mp)] *aocl
        pop  1 // _ *peaks leaf_count_hi leaf_count_lo *[(item, *mp)]

        call {map_compute_canonical_commitment}
               // _ *peaks leaf_count_hi leaf_count_lo *[(cc, *mp)]

        call {all_verify_aocl_membership}
               // _ *peaks leaf_count_hi leaf_count_lo all_live_in_aocl

        assert

        halt
        };

        (code, library)
    }

    fn crash_conditions() -> Vec<String> {
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
    use std::collections::HashMap;

    use super::*;
    use crate::tests::shared::pseudorandom_removal_record_integrity_witness;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::{memory::encode_to_memory, traits::compiled_program::test_rust_shadow};
    use triton_vm::prelude::{Claim, Stark};

    // #[test]
    // fn test_validation_logic() {
    //     let mut rng = thread_rng();
    //     let tx_kernel = &pseudorandom_transaction_kernel(rng.gen(), 2, 2, 2);
    //     let prrriw =
    //         pseudorandom_removal_record_integrity_witness(rng.gen());
    //     let input_utxos = prrriw.input_utxos;
    //     let input_lock_scripts = prrriw.input_utxos.iter().map(|x| x.)

    //     // pub struct PrimitiveWitness {
    //     // pub input_utxos: Vec<Utxo>,
    //     // pub input_lock_scripts: Vec<LockScript>,
    //     // pub lock_script_witnesses: Vec<Vec<BFieldElement>>,
    //     // pub input_membership_proofs: Vec<MsMembershipProof<Hash>>,
    //     // pub output_utxos: Vec<Utxo>,
    //     // pub pubscripts: Vec<PubScript>,
    //     // pub mutator_set_accumulator: MutatorSetAccumulator<Hash>,
    //     // }

    //     // let primitive_witness = pseudorandom_pri
    //     let rriw = RemovalRecordsIntegrity::new_from_witness(primitive_witness, tx_kernel);
    // }

    #[tokio::test]
    async fn test_graceful_halt() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa0;
        seed[1] = 0xf1;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record_integrity_witness =
            pseudorandom_removal_record_integrity_witness(rng.gen()).await;

        let stdin: Vec<BFieldElement> = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values()
            .to_vec();

        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            removal_record_integrity_witness,
        );
        let nondeterminism = NonDeterminism::new(vec![]).with_ram(memory);
        let program = RemovalRecordsIntegrity::program();
        let run_res = program.run(PublicInput::new(stdin.clone()), nondeterminism.clone());
        match run_res {
            Ok(_) => println!("Run successful."),
            Err(err) => panic!("Failed:\n last state was:\n{err}"),
        };

        if std::env::var("DYING_TO_PROVE").is_ok() {
            let claim: Claim = Claim {
                program_digest: program.hash::<Hash>(),
                input: stdin,
                output: vec![],
            };
            let maybe_proof = triton_vm::prove(Stark::default(), &claim, &program, nondeterminism);
            assert!(maybe_proof.is_ok());

            assert!(triton_vm::verify(
                Stark::default(),
                &claim,
                &maybe_proof.unwrap()
            ));
        }
    }

    #[test]
    fn program_is_deterministic() {
        let program = RemovalRecordsIntegrity::program();
        let other_program = RemovalRecordsIntegrity::program();
        assert_eq!(program, other_program);
    }

    #[tokio::test]
    async fn tasm_matches_rust() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa0;
        seed[1] = 0xf1;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record_integrity_witness =
            pseudorandom_removal_record_integrity_witness(rng.gen()).await;
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            removal_record_integrity_witness.clone(),
        );
        let nondeterminism = NonDeterminism::new(vec![]).with_ram(memory);
        let kernel_hash = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values();
        let public_input = PublicInput::new(kernel_hash.to_vec());

        test_rust_shadow::<RemovalRecordsIntegrity>(&public_input, &nondeterminism);
    }
}

#[cfg(test)]
mod bench {
    use std::collections::HashMap;

    use crate::{models::consensus::mast_hash::MastHash, prelude::triton_vm};

    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::{
        memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS},
        snippet_bencher::BenchmarkCase,
    };
    use triton_vm::prelude::{BFieldElement, NonDeterminism, PublicInput};

    use crate::tests::shared::pseudorandom_removal_record_integrity_witness;

    use super::RemovalRecordsIntegrity;
    use tasm_lib::traits::compiled_program::bench_and_profile_program;

    #[tokio::test]
    async fn benchmark() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa7;
        seed[1] = 0xf7;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record_integrity_witness =
            pseudorandom_removal_record_integrity_witness(rng.gen()).await;

        let stdin: Vec<BFieldElement> = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values()
            .to_vec();
        let public_input = PublicInput::new(stdin);
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            removal_record_integrity_witness,
        );
        let nondeterminism = NonDeterminism::default().with_ram(memory);

        bench_and_profile_program::<RemovalRecordsIntegrity>(
            "tasm_neptune_transaction_removal_records_integrity",
            BenchmarkCase::CommonCase,
            &public_input,
            &nondeterminism,
        );
    }
}
