use crate::prelude::{triton_vm, twenty_first};

use field_count::FieldCount;
use get_size::GetSize;
use itertools::Itertools;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use tasm_lib::memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS};
use tasm_lib::structure::tasm_object::TasmObject;
use tasm_lib::traits::compiled_program::CompiledProgram;
use triton_vm::prelude::{BFieldElement, Claim, NonDeterminism, Program};
use twenty_first::{
    shared_math::{bfield_codec::BFieldCodec, tip5::Digest},
    util_types::{algebraic_hasher::AlgebraicHasher, mmr::mmr_accumulator::MmrAccumulator},
};

use crate::models::blockchain::transaction::validity::SecretWitness;
use crate::{
    models::blockchain::{
        shared::Hash,
        transaction::{
            transaction_kernel::TransactionKernel,
            utxo::Utxo,
            validity::{ClaimSupport, SupportedClaim, ValidationLogic},
            PrimitiveWitness,
        },
    },
    util_types::mutator_set::ms_membership_proof::MsMembershipProof,
};

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    GetSize,
    BFieldCodec,
    FieldCount,
    TasmObject,
)]
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

impl SecretWitness for RemovalRecordsIntegrityWitness {
    fn nondeterminism(&self) -> NonDeterminism<BFieldElement> {
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );
        NonDeterminism::default().with_ram(memory)
    }

    fn subprogram(&self) -> Program {
        RemovalRecordsIntegrity::program()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, FieldCount, BFieldCodec)]
pub struct RemovalRecordsIntegrity {
    pub supported_claim: SupportedClaim<RemovalRecordsIntegrityWitness>,
}

impl ValidationLogic<RemovalRecordsIntegrityWitness> for RemovalRecordsIntegrity {
    fn new_from_primitive_witness(
        primitive_witness: &crate::models::blockchain::transaction::PrimitiveWitness,
        tx_kernel: &crate::models::blockchain::transaction::transaction_kernel::TransactionKernel,
    ) -> Self {
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::new(primitive_witness, tx_kernel);

        Self {
            supported_claim: SupportedClaim {
                claim: Claim {
                    program_digest: Hash::hash_varlen(&Self::program().encode()),
                    input: tx_kernel
                        .mast_hash()
                        .values()
                        .into_iter()
                        .rev()
                        .collect_vec(),
                    output: vec![],
                },
                support: ClaimSupport::SecretWitness(removal_records_integrity_witness),
            },
        }
    }

    fn subprogram(&self) -> Program {
        Self::program()
    }

    fn support(&self) -> ClaimSupport<RemovalRecordsIntegrityWitness> {
        self.supported_claim.support.clone()
    }

    fn claim(&self) -> Claim {
        self.supported_claim.claim.clone()
    }
}
