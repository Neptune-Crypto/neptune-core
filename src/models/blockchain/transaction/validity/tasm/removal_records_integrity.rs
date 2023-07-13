use std::collections::HashSet;

use field_count::FieldCount;
use get_size::GetSize;
use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};
use tasm_lib::compiled_program::CompiledProgram;
use tasm_lib::library::Library;
use tasm_lib::{
    io::load_struct_from_input::LoadStructFromInput,
    list::{
        contiguous_list::get_pointer_list::GetPointerList,
        higher_order::{all::All, inner_function::InnerFunction, map::Map, zip::Zip},
        multiset_equality::MultisetEquality,
        unsafe_u32::get::UnsafeGet,
        ListType,
    },
    mmr::bag_peaks::BagPeaks,
    snippet::{DataType, InputSource},
    structure::get_field::GetField,
    DIGEST_LENGTH,
};
use tracing::{debug, warn};
use triton_vm::triton_asm;
use triton_vm::{instruction::LabelledInstruction, BFieldElement, StarkParameters};
use twenty_first::{
    shared_math::{bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{
        algebraic_hasher::AlgebraicHasher,
        mmr::{mmr_accumulator::MmrAccumulator, mmr_trait::Mmr},
    },
};

use crate::{
    models::blockchain::{
        shared::Hash,
        transaction::{
            transaction_kernel::TransactionKernel,
            utxo::Utxo,
            validity::{
                tasm::transaction_kernel_mast_hash::TransactionKernelMastHash, ClaimSupport,
                SupportedClaim, ValidationLogic,
            },
            PrimitiveWitness,
        },
    },
    util_types::mutator_set::{
        ms_membership_proof::MsMembershipProof, mutator_set_kernel::get_swbf_indices,
        mutator_set_trait::commit, removal_record::AbsoluteIndexSet,
    },
};
use tasm_lib::memory::push_ram_to_stack::PushRamToStack;

use super::{
    compute_canonical_commitment::ComputeCanonicalCommitment, compute_indices::ComputeIndices,
    hash_index_list::HashIndexList, hash_removal_record_indices::HashRemovalRecordIndices,
    hash_utxo::HashUtxo, verify_aocl_membership::VerifyAoclMembership,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, FieldCount)]
pub struct RemovalRecordsIntegrityWitness {
    pub input_utxos: Vec<Utxo>,
    pub membership_proofs: Vec<MsMembershipProof<Hash>>,
    pub aocl: MmrAccumulator<Hash>,
    pub swbfi: MmrAccumulator<Hash>,
    pub swbfa_hash: Digest,
    pub kernel: TransactionKernel,
}

impl RemovalRecordsIntegrityWitness {
    pub fn new(primitive_witness: &PrimitiveWitness, tx_kernel: &TransactionKernel) -> Self {
        Self {
            input_utxos: primitive_witness.input_utxos.clone(),
            membership_proofs: primitive_witness.input_membership_proofs.clone(),
            kernel: tx_kernel.to_owned(),
            aocl: primitive_witness
                .mutator_set_accumulator
                .kernel
                .aocl
                .clone(),
            swbfi: primitive_witness
                .mutator_set_accumulator
                .kernel
                .swbf_inactive
                .clone(),
            swbfa_hash: Hash::hash(&primitive_witness.mutator_set_accumulator.kernel.swbf_active),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount)]
pub struct RemovalRecordsIntegrity {
    pub supported_claim: SupportedClaim,
}

impl ValidationLogic for RemovalRecordsIntegrity {
    fn new_from_witness(
        primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::new(primitive_witness, tx_kernel);
        let witness_data = removal_records_integrity_witness.encode();

        Self {
            supported_claim: SupportedClaim {
                claim: triton_vm::Claim {
                    program_digest: Hash::hash_varlen(&Self::program().encode()),
                    input: tx_kernel.mast_hash().encode(),
                    output: vec![],
                },
                support: ClaimSupport::SecretWitness(witness_data, None),
            },
        }
    }

    fn prove(&mut self) -> anyhow::Result<()> {
        debug!(
            "rri program digest: ({})",
            Hash::hash_varlen(&Self::program().encode())
        );
        debug!(
            "rri program digest: ({})",
            Hash::hash_varlen(&Self::program().encode())
        );
        match &self.supported_claim.support {
            ClaimSupport::Proof(_) => {
                // nothing to do; proof already exists
                Ok(())
            }
            ClaimSupport::SecretWitness(witness, _program) => {
                debug!(
                    "program digest: ({})\nclaimed digest: ({})",
                    Hash::hash_varlen(&Self::program().encode()),
                    self.supported_claim.claim.program_digest
                );
                let proof = triton_vm::prove(
                    &StarkParameters::default(),
                    &self.supported_claim.claim,
                    &Self::program(),
                    witness,
                )
                .expect("Proving integrity of removal records must succeed.");
                self.supported_claim.support = ClaimSupport::Proof(proof);
                Ok(())
            }
            ClaimSupport::DummySupport => {
                // nothing to do
                warn!(
                    "Trying to prove removal record integrity for claim supported by dummy support"
                );
                Ok(())
            }
        }
    }

    fn verify(&self) -> bool {
        match &self.supported_claim.support {
            ClaimSupport::Proof(proof) => triton_vm::verify(
                &StarkParameters::default(),
                &self.supported_claim.claim,
                proof,
            ),
            ClaimSupport::SecretWitness(witness, _no_program) => {
                // let rust_output = Self::rust_shadow(
                //     self.supported_claim.claim.input.clone().into(),
                //     witness.clone().into(),
                // );
                let vm_result =
                    Self::program().run(self.supported_claim.claim.input.clone(), witness.to_vec());
                match vm_result {
                    Ok(observed_output) => {
                        let found_expected_output =
                            observed_output == self.supported_claim.claim.output;
                        if !found_expected_output {
                            warn!("Observed output does not match claimed output for RRI");
                            debug!("Got output: {found_expected_output}");
                        }

                        found_expected_output
                    }
                    Err(err) => {
                        warn!("VM execution for removal records integrity did not halt gracefully");
                        debug!("Last state was: {err}");
                        false
                    }
                }
            }
            ClaimSupport::DummySupport => {
                warn!("removal record integrity support must be supplied");
                false
            }
        }
    }
}

impl CompiledProgram for RemovalRecordsIntegrity {
    fn rust_shadow(
        public_input: &[BFieldElement],
        secret_input: &[BFieldElement],
    ) -> anyhow::Result<Vec<BFieldElement>> {
        let hash_of_kernel = *Digest::decode(
            &public_input
                .iter()
                .copied()
                .take(DIGEST_LENGTH)
                .rev()
                .collect_vec(),
        )
        .expect("Could not decode public input in Removal Records Integrity :: verify_raw");

        // 1. read and process witness data
        let witness =
            *RemovalRecordsIntegrityWitness::decode(&secret_input.iter().copied().collect_vec())
                .unwrap();

        // 2. assert that the kernel from the witness matches the hash in the public input
        // now we can trust all data in kernel
        assert_eq!(
            hash_of_kernel,
            witness.kernel.mast_hash(),
            "hash of kernel ({})\nwitness kernel ({})",
            hash_of_kernel,
            witness.kernel.mast_hash()
        );

        // 3. assert that the mutator set's MMRs in the witness match the kernel
        // now we can trust all data in these MMRs as well
        let mutator_set_hash = Hash::hash_pair(
            &Hash::hash_pair(&witness.aocl.bag_peaks(), &witness.swbfi.bag_peaks()),
            &Hash::hash_pair(&witness.swbfa_hash, &Digest::default()),
        );
        assert_eq!(witness.kernel.mutator_set_hash, mutator_set_hash);

        // 4. derive index sets from inputs and match them against those listed in the kernel
        // How do we trust input UTXOs?
        // Because they generate removal records, and we can match
        // those against the removal records that are listed in the
        // kernel.
        let items = witness.input_utxos.iter().map(Hash::hash).collect_vec();

        // test that removal records listed in kernel match those derived from input utxos
        let digests_of_derived_index_lists = items
            .iter()
            .zip(witness.membership_proofs.iter())
            .map(|(item, msmp)| {
                AbsoluteIndexSet::new(&get_swbf_indices::<Hash>(
                    item,
                    &msmp.sender_randomness,
                    &msmp.receiver_preimage,
                    msmp.auth_path_aocl.leaf_index,
                ))
                .encode()
            })
            .map(|x| Hash::hash_varlen(&x))
            .collect::<HashSet<_>>();
        let digests_of_claimed_index_lists = witness
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

        Ok(vec![])
    }

    fn code() -> (Vec<LabelledInstruction>, Library) {
        let mut library = Library::new();
        let num_fields_on_witness = RemovalRecordsIntegrityWitness::field_count();
        let get_field = library.import(Box::new(GetField));
        let transaction_kernel_mast_hash = library.import(Box::new(TransactionKernelMastHash));
        let load_struct_from_input = library.import(Box::new(LoadStructFromInput {
            input_source: InputSource::SecretIn,
        }));
        let bag_peaks = library.import(Box::new(BagPeaks));
        let read_input = "read_io\n".repeat(DIGEST_LENGTH);
        let read_digest = library.import(Box::new(PushRamToStack {
            output_type: DataType::Digest,
        }));
        let map_hash_utxo = library.import(Box::new(Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(HashUtxo)),
        }));
        let get_pointer_list = library.import(Box::new(GetPointerList {
            output_list_type: ListType::Unsafe,
        }));
        let zip_digest_with_void_pointer = library.import(Box::new(Zip {
            list_type: ListType::Unsafe,
            left_type: DataType::VoidPointer,
            right_type: DataType::Digest,
        }));
        let map_compute_indices = library.import(Box::new(Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(ComputeIndices)),
        }));
        let map_hash_index_list = library.import(Box::new(Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(HashIndexList)),
        }));
        let map_hash_removal_record_indices = library.import(Box::new(Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(HashRemovalRecordIndices)),
        }));
        let multiset_equality = library.import(Box::new(MultisetEquality(ListType::Unsafe)));

        let map_compute_canonical_commitment = library.import(Box::new(Map {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(ComputeCanonicalCommitment)),
        }));
        let all_verify_aocl_membership = library.import(Box::new(All {
            list_type: ListType::Unsafe,
            f: InnerFunction::Snippet(Box::new(VerifyAoclMembership)),
        }));

        let _get_element = library.import(Box::new(UnsafeGet(DataType::Digest)));
        let _compute_indices = library.import(Box::new(ComputeIndices));

        let code = triton_asm!(

        // 1. read RemovalRecordsIntegrityWitness from secio
        push {num_fields_on_witness}
        call {load_struct_from_input} // _ *witness

        // 2. assert that witness kernel hash == public input
        dup 0 // _ *witness *witness
        push 5 // _ *witness *witness 5 (= field kernel)
        call {get_field} // _ *witness *kernel_size_indicator

        push 1 add       // _ *witness *kernel
        dup 0 // _ *witness *kernel *kernel
        call {transaction_kernel_mast_hash} // _ *witness *kernel [witness_kernel_digest]
        {read_input} // _ *witness *kernel [witness_kernel_digest] [input_kernel_digest]
        assert_vector
        pop pop pop pop pop // _ *witness *kernel [kernel_digest]
        pop pop pop pop pop // _ *witness *kernel

        // 3. assert that witness mutator set MMRs match those in kernel

        push 0 push 0 push 0 push 0 push 0 // _ *witness *kernel 0 0 0 0 0
        dup 6 // _ *witness *kernel 0^5 *witness
        push 4 // _ *witness *kernel 0^5 *witness 4 (= field swbfa_hash)
        call {get_field} // _ *witness *kernel 0^5 *witness_swbfa_li
        push 1 add // _ *witness *kernel 0^5 *witness_swbfa_hash
        call {read_digest}

        hash // _ *witness *kernel [H(H(swbfaw)||0^5)] [garbage]
        pop pop pop pop pop // _ *witness *kernel [H(H(swbfaw)||0^5)]

        dup 6 // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness
        push 3 // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness 3 (= field swbfi)
        call {get_field} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi_li
        push 1 add // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi
        push 1 // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi 1 (= field peaks)
        call {get_field} // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi_peaks_li
        push 1 add // _ *witness *kernel [H(H(swbfaw)||0^5)] *witness_swbfi_peaks
        call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash]

        dup 11 // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness
        push 2 // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness 2 (= field aocl)
        call {get_field} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl_size_indicator
        push 1 add // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl
        push 1 // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl 1 (= field peaks)
        call {get_field} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl_peaks_li
        push 1 add // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] *witness_aocl_peaks
        call {bag_peaks} // _ *witness *kernel [H(H(swbfaw)||0^5)] [witness_swbfi_hash] [witness_aocl_hash]

        hash // _ *witness *kernel [H(H(swbfaw)||0^5)] [H(aocl||swbfi)] [garbage]
        pop pop pop pop pop // _ *witness *kernel [H(H(swbfaw)||0^5)] [H(aocl||swbfi)]

        hash // _ *witness *kernel [H(H(aocl||swbfi))||H(H(swbfaw)||0^5)] [garbage]
        pop pop pop pop pop // _ *witness *kernel [Hw]

        dup 5 // _ *witness *kernel [Hw] *kernel
        push 6 // _ *witness *kernel [Hw] *kernel 6 (= field mutator_set_hash)
        call {get_field} // _ *witness *kernel [Hw] *kernel_msh_li
        push 1 add // _ *witness *kernel [Hw] *kernel_msh
        call {read_digest}
        // _ *witness *kernel [Hw] [Hk]

        assert_vector
        pop pop pop pop pop
        pop pop pop pop pop
        // _ *witness *kernel

        // 4. derive index sets and match them against kernel
        dup 1 // _ *witness *kernel *witness
        push 0 call {get_field} // _ *witness *kernel *utxos_si
        push 1 add // _ *witness *kernel *utxos
        call {get_pointer_list} // _ *witness *kernel *[*utxo]
        call {map_hash_utxo} // _ *witness *kernel *[item]

        dup 2 // _ *witness *kernel *[item] *witness
        push 1 call {get_field} // _ *witness *kernel *[item] *mps_si
        push 1 add //_ *witness *kernel *[items] *mps
        call {get_pointer_list} //_ *witness *kernel *[item] *[*mp]
        swap 1 //_ *witness *kernel *[*mp] *[item]
        call {zip_digest_with_void_pointer} // _ *witness *kernel *[(*mp, item)]

        // store for later use
        dup 0  // _ *witness *kernel *[(*mp, item)] *[(*mp, item)]
        swap 3 // _  *[(*mp, item)] *kernel *[(*mp, item)] *witness
        swap 2 // _  *[(*mp, item)] *witness *[(*mp, item)] *kernel
        swap 1 // _  *[(*mp, item)] *witness *kernel *[(*mp, item)]

        call {map_compute_indices} // _  *[(*mp, item)] *witness *kernel *[*[index]]

        call {map_hash_index_list} // _  *[(*mp, item)] *witness *kernel *[index_list_hash]

        dup 1 // _  *[(*mp, item)] *witness *kernel *[index_list_hash] *kernel
        push 0 // _  *[(*mp, item)] *witness *kernel *[index_list_hash] *kernel 0 (= field inputs)
        call {get_field} // _  *[(*mp, item)] *witness *kernel *[index_list_hash] *kernel_inputs_si
        push 1 add // _  *[(*mp, item)] *witness *kernel *[index_list_hash] *kernel_inputs
        call {get_pointer_list} // _  *[(*mp, item)] *witness *kernel *[index_list_hash] *[*tx_input]
        call {map_hash_removal_record_indices} // _  *[(*mp, item)] *witness *kernel *[witness_index_list_hash] *[kernel_index_list_hash]

        call {multiset_equality} // _  *[(*mp, item)] *witness *kernel witness_inputs==kernel_inputs
        assert // _  *[(*mp, item)] *witness *kernel

        // 5. verify that all items' commitments live in the aocl
        // get aocl leaf count
        dup 1 // _ *[(*mp, item)] *witness *kernel *witness
        push 2 call {get_field} // _ *[(*mp, item)] *witness *kernel *aocl_si
        push 1 add              // _ *[(*mp, item)] *witness *kernel *aocl
        dup 0                   // _ *[(*mp, item)] *witness *kernel *aocl *aocl
        push 0 call {get_field} // _ *[(*mp, item)] *witness *kernel *aocl *leaf_count_si
        push 2 add // _ *[(*mp, item)] *witness *kernel *aocl *leaf_count+2
        read_mem swap 1 push -1 add // _ *[(*mp, item)] *witness *kernel *aocl leaf_count_hi *leaf_count+1
        read_mem swap 1 pop // _ *[(*mp, item)] *witness *kernel *aocl leaf_count_hi leaf_count_lo

        dup 2                   // _ *[(*mp, item)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *aocl
        push 1 call {get_field} // _ *[(*mp, item)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *peaks_si
        push 1 add              // _ *[(*mp, item)] *witness *kernel *aocl leaf_count_hi leaf_count_lo *peaks


        swap 6 // _ *peaks *witness *kernel *aocl leaf_count_hi leaf_count_lo *[(*mp, item)]
        swap 2 // _ *peaks *witness *kernel *aocl *[(*mp, item)] leaf_count_lo leaf_count_hi
        swap 5 // _ *peaks leaf_count_hi *kernel *aocl *[(*mp, item)] leaf_count_lo *witness
        pop    // _ *peaks leaf_count_hi *kernel *aocl *[(*mp, item)] leaf_count_lo
        swap 3 // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(*mp, item)] *kernel
        pop    // _ *peaks leaf_count_hi leaf_count_lo *aocl *[(*mp, item)]
        swap 1 // _ *peaks leaf_count_hi leaf_count_lo *[(*mp, item)] *aocl
        pop    // _ *peaks leaf_count_hi leaf_count_lo *[(*mp, item)]

        call {map_compute_canonical_commitment}
               // _ *peaks leaf_count_hi leaf_count_lo *[(cc, *mp)]

        call {all_verify_aocl_membership}
               // _ *peaks leaf_count_hi leaf_count_lo all_live_in_aocl

        assert

        halt
        );

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
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::compiled_program::test_rust_shadow;
    use triton_vm::{Claim, StarkParameters};
    use twenty_first::util_types::emojihash_trait::Emojihash;

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
        let aocl_leaf_count = removal_record_integrity_witness.aocl.count_leaves();
        println!("aocl leaf count: {aocl_leaf_count}",);
        let aocl_leaf_count_hi = (aocl_leaf_count >> 32) as u32;
        let aocl_leaf_count_lo = (aocl_leaf_count & u32::MAX as u64) as u32;
        println!("aocl_leaf_count_hi: {aocl_leaf_count_hi}",);
        println!("aocl_leaf_count_lo: {aocl_leaf_count_lo}",);
        println!(
            "number of peaks in AOCL: {}",
            removal_record_integrity_witness.aocl.get_peaks().len()
        );

        let program = RemovalRecordsIntegrity::program();
        let stdin: Vec<BFieldElement> = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values()
            .to_vec();
        let secret_in: Vec<BFieldElement> = removal_record_integrity_witness.encode();

        let witness_index_lists = removal_record_integrity_witness
            .input_utxos
            .iter()
            .zip_eq(removal_record_integrity_witness.membership_proofs.iter())
            .map(|(utxo, mp)| {
                (
                    Hash::hash(utxo),
                    mp.sender_randomness,
                    mp.receiver_preimage,
                    mp.auth_path_aocl.leaf_index,
                )
            })
            .map(|(item, sr, rp, li)| get_swbf_indices::<Hash>(&item, &sr, &rp, li))
            .map(|ais| AbsoluteIndexSet::new(&ais))
            .collect_vec();
        let very_first_index = witness_index_lists[0].to_array()[0];
        println!(
            "very first index: {} {} {} {}",
            very_first_index >> 96,
            (very_first_index >> 64) & u32::MAX as u128,
            (very_first_index >> 32) & u32::MAX as u128,
            very_first_index & u32::MAX as u128
        );
        let very_second_index = witness_index_lists[1].to_array()[0];
        println!(
            "very second index: {} {} {} {}",
            very_second_index >> 96,
            (very_second_index >> 64) & u32::MAX as u128,
            (very_second_index >> 32) & u32::MAX as u128,
            very_second_index & u32::MAX as u128
        );
        let mut witness_index_lists_hashes = witness_index_lists
            .iter()
            .map(|l| Hash::hash_varlen(&l.encode()[1..]))
            .collect_vec();
        witness_index_lists_hashes.sort();

        println!(
            "witness index set hashes: ({})",
            witness_index_lists_hashes
                .iter()
                .map(|wis| wis.emojihash())
                .join(", ")
        );
        println!(
            "as numbers: ({})-({})",
            witness_index_lists_hashes[0].values().iter().join(", "),
            witness_index_lists_hashes[1].values().iter().join(", ")
        );

        let kernel_index_lists = removal_record_integrity_witness
            .kernel
            .inputs
            .iter()
            .map(|rr| rr.absolute_indices.clone())
            .collect_vec();
        let mut kernel_index_lists_hashes = kernel_index_lists
            .iter()
            .map(|l| Hash::hash_varlen(&l.encode()[1..]))
            .collect_vec();
        kernel_index_lists_hashes.sort();

        println!(
            "kernel index set hashes: ({})",
            kernel_index_lists_hashes
                .iter()
                .map(|wis| wis.emojihash())
                .join(", ")
        );
        println!(
            "as numbers: ({})-({})",
            kernel_index_lists_hashes[0].values().iter().join(", "),
            kernel_index_lists_hashes[1].values().iter().join(", ")
        );

        let canonical_commitments = removal_record_integrity_witness
            .input_utxos
            .iter()
            .map(Hash::hash)
            .zip(removal_record_integrity_witness.membership_proofs.iter())
            .map(|(item, mp)| {
                commit::<Hash>(
                    &item,
                    &mp.sender_randomness,
                    &mp.receiver_preimage.hash::<Hash>(),
                )
            })
            .collect_vec();
        println!(
            "first canonical commitment: ({})",
            canonical_commitments[0].canonical_commitment
        );
        println!(
            "second canonical commitment: ({})",
            canonical_commitments[1].canonical_commitment
        );

        println!(
            "canonical commitments live in aocl? {}",
            removal_record_integrity_witness
                .membership_proofs
                .iter()
                .zip(canonical_commitments.iter())
                .all(|(mp, cc)| mp
                    .auth_path_aocl
                    .verify(
                        &removal_record_integrity_witness.aocl.get_peaks(),
                        &cc.canonical_commitment,
                        removal_record_integrity_witness.aocl.count_leaves()
                    )
                    .0)
        );

        // assert!(triton_vm::vm::run(&program, stdin, secret_in).is_ok());
        let run_res = program.debug_terminal_state(stdin.clone(), secret_in.clone(), None, None);
        match run_res {
            Ok(_) => (),
            Err((state, msg)) => panic!("Failed: {msg}\n last state was: {state}"),
        };

        let claim: Claim = Claim {
            program_digest: Hash::hash_varlen(&program.encode()),
            input: stdin,
            output: vec![],
        };

        if std::env::var("DYING_TO_PROVE").is_ok() {
            let maybe_proof =
                triton_vm::prove(&StarkParameters::default(), &claim, &program, &secret_in);
            assert!(maybe_proof.is_ok());

            assert!(triton_vm::verify(
                &StarkParameters::default(),
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

    #[test]
    fn tasm_matches_rust() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa0;
        seed[1] = 0xf1;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let witness = pseudorandom_removal_record_integrity_witness(rng.gen());
        let kernel_hash = witness.kernel.mast_hash().reversed().values();
        let public_input = kernel_hash.to_vec();
        let witness = witness.encode();

        test_rust_shadow::<RemovalRecordsIntegrity>(&public_input, &witness);
    }
}

#[cfg(test)]
mod bench {
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use tasm_lib::snippet_bencher::BenchmarkCase;
    use triton_vm::BFieldElement;
    use twenty_first::shared_math::bfield_codec::BFieldCodec;

    use crate::tests::shared::pseudorandom_removal_record_integrity_witness;

    use super::RemovalRecordsIntegrity;
    use tasm_lib::compiled_program::bench_program;

    #[test]
    fn benchmark() {
        let mut seed = [0u8; 32];
        seed[0] = 0xa7;
        seed[1] = 0xf7;
        let mut rng: StdRng = SeedableRng::from_seed(seed);
        let removal_record_integrity_witness =
            pseudorandom_removal_record_integrity_witness(rng.gen());

        let stdin: Vec<BFieldElement> = removal_record_integrity_witness
            .kernel
            .mast_hash()
            .reversed()
            .values()
            .to_vec();
        let secret_in: Vec<BFieldElement> = removal_record_integrity_witness.encode();

        bench_program::<RemovalRecordsIntegrity>(
            "tasm_neptune_transaction_removal_records_integrity".to_string(),
            BenchmarkCase::CommonCase,
            &stdin,
            &secret_in,
        );
    }
}
