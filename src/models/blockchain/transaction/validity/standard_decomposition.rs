use std::collections::HashMap;

use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tasm_lib::{
    memory::{encode_to_memory, FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS},
    structure::tasm_object::TasmObject,
    triton_vm::{
        self,
        instruction::LabelledInstruction,
        prelude::BFieldCodec,
        program::{NonDeterminism, Program, PublicInput},
        proof::{Claim, Proof},
        stark::Stark,
    },
    twenty_first::util_types::algebraic_hasher::AlgebraicHasher,
    Digest,
};

use crate::models::proof_abstractions::SecretWitness;
use crate::models::{
    blockchain::shared::Hash, proof_abstractions::tasm::program::ConsensusProgram,
};
use crate::models::{
    blockchain::transaction::{
        primitive_witness::PrimitiveWitness,
        validity::{
            collect_lock_scripts::{CollectLockScripts, CollectLockScriptsWitness},
            collect_type_scripts::CollectTypeScripts,
            kernel_to_outputs::KernelToOutputs,
            removal_records_integrity::RemovalRecordsIntegrityWitness,
        },
    },
    proof_abstractions::mast_hash::MastHash,
};

use super::{
    kernel_to_outputs::KernelToOutputsWitness, removal_records_integrity::RemovalRecordsIntegrity,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec, TasmObject)]
pub struct ProofCollection {
    pub removal_records_integrity: Proof,
    pub collect_lock_scripts: Proof,
    pub lock_scripts_halt: Vec<Proof>,
    pub kernel_to_outputs: Proof,
    pub collect_type_scripts: Proof,
    pub type_scripts_halt: Vec<Proof>,
    pub lock_script_hashes: Vec<Digest>,
    pub type_script_hashes: Vec<Digest>,
    pub kernel_mast_hash: Digest,
    pub salted_inputs_hash: Digest,
    pub salted_outputs_hash: Digest,
}

impl ProofCollection {
    pub fn produce(primitive_witness: PrimitiveWitness) -> Self {
        // collect witnesses
        let removal_records_integrity_witness =
            RemovalRecordsIntegrityWitness::from(&primitive_witness);
        let collect_lock_scripts_witness = CollectLockScriptsWitness::from(&primitive_witness);
        let kernel_to_outputs_witness = KernelToOutputsWitness::from(&primitive_witness);
        let collect_type_scripts_witness = KernelToOutputsWitness::from(&primitive_witness);

        // verify graceful halts
        let removal_records_integrity_halts = RemovalRecordsIntegrity
            .run_rust(
                &removal_records_integrity_witness.standard_input(),
                removal_records_integrity_witness.nondeterminism(),
            )
            .is_ok();

        let collect_lock_scripts_halts = CollectLockScripts
            .run_rust(
                &collect_lock_scripts_witness.standard_input(),
                collect_lock_scripts_witness.nondeterminism(),
            )
            .is_ok();

        let kernel_to_outputs_halts = KernelToOutputs
            .run_rust(
                &kernel_to_outputs_witness.standard_input(),
                kernel_to_outputs_witness.nondeterminism(),
            )
            .is_ok();

        let collect_type_scripts_halts = CollectTypeScripts
            .run_rust(
                &collect_type_scripts_witness.standard_input(),
                collect_type_scripts_witness.nondeterminism(),
            )
            .is_ok();

        let txk_mast_hash = primitive_witness.kernel.mast_hash();
        let txk_mast_hash_as_input = PublicInput::new(txk_mast_hash.reversed().values().to_vec());
        let salted_inputs_hash = Hash::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Hash::hash(&primitive_witness.output_utxos);

        let all_lock_scripts_halt = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .all(|lsaw| lsaw.halts_gracefully(txk_mast_hash_as_input.clone()));
        let all_type_scripts_halt = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .all(|ts| ts.halts_gracefully(txk_mast_hash, salted_inputs_hash, salted_outputs_hash));

        if !removal_records_integrity_halts
            || !collect_lock_scripts_halts
            || !kernel_to_outputs_halts
            || !collect_type_scripts_halts
            || !all_lock_scripts_halt
            || !all_type_scripts_halt
        {
            panic!("cannot produce proof collection for transaction because one or more consensus programs fails to halt gracefully")
        }

        // prove
        let removal_records_integrity = RemovalRecordsIntegrity.prove(
            &removal_records_integrity_witness.claim(),
            removal_records_integrity_witness.nondeterminism(),
        );
        let collect_lock_scripts = CollectLockScripts.prove(
            &collect_lock_scripts_witness.claim(),
            collect_lock_scripts_witness.nondeterminism(),
        );
        let kernel_to_outputs = KernelToOutputs.prove(
            &kernel_to_outputs_witness.claim(),
            kernel_to_outputs_witness.nondeterminism(),
        );
        let collect_type_scripts = CollectTypeScripts.prove(
            &collect_type_scripts_witness.claim(),
            collect_type_scripts_witness.nondeterminism(),
        );
        let lock_scripts_halt = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.prove(txk_mast_hash_as_input.clone()))
            .collect_vec();
        let type_scripts_halt = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| tsaw.prove(txk_mast_hash, salted_inputs_hash, salted_outputs_hash))
            .collect_vec();

        // collect hashes
        let salted_inputs_hash = Hash::hash(&primitive_witness.input_utxos);
        let salted_outputs_hash = Hash::hash(&primitive_witness.output_utxos);
        let lock_script_hashes = primitive_witness
            .lock_scripts_and_witnesses
            .iter()
            .map(|lsaw| lsaw.program.hash::<Hash>())
            .collect_vec();
        let type_script_hashes = primitive_witness
            .type_scripts_and_witnesses
            .iter()
            .map(|tsaw| tsaw.program.hash::<Hash>())
            .collect_vec();

        // assemble data into struct and return
        ProofCollection {
            removal_records_integrity,
            collect_lock_scripts,
            lock_scripts_halt,
            kernel_to_outputs,
            collect_type_scripts,
            type_scripts_halt,
            lock_script_hashes,
            type_script_hashes,
            kernel_mast_hash: txk_mast_hash,
            salted_inputs_hash,
            salted_outputs_hash,
        }
    }

    pub fn verify(&self, txk_mast_hash: Digest) -> bool {
        // make sure we are talking about the same tx
        if self.kernel_mast_hash != txk_mast_hash {
            return false;
        }

        // compile claims
        let removal_records_integrity_claim = Claim {
            program_digest: RemovalRecordsIntegrity.program().hash::<Hash>(),
            input: self.kernel_mast_hash.reversed().values().to_vec(),
            output: self.salted_inputs_hash.values().to_vec(),
        };
        let kernel_to_outputs_claim = Claim {
            program_digest: KernelToOutputs.program().hash::<Hash>(),
            input: self.kernel_mast_hash.reversed().values().to_vec(),
            output: self.salted_outputs_hash.values().to_vec(),
        };
        let collect_lock_scripts_claim = Claim {
            program_digest: CollectLockScripts.program().hash::<Hash>(),
            input: self.salted_inputs_hash.reversed().values().to_vec(),
            output: self
                .lock_script_hashes
                .iter()
                .flat_map(|d| d.values())
                .collect_vec(),
        };
        let collect_type_scripts_claim = Claim {
            program_digest: CollectTypeScripts.program().hash::<Hash>(),
            input: [self.salted_inputs_hash, self.salted_outputs_hash]
                .into_iter()
                .flat_map(|d| d.reversed().values())
                .collect_vec(),
            output: self
                .type_script_hashes
                .iter()
                .flat_map(|d| d.reversed().values())
                .collect_vec(),
        };
        let lock_script_claims = self
            .lock_script_hashes
            .iter()
            .map(|lsh| Claim {
                program_digest: *lsh,
                input: self.kernel_mast_hash.reversed().values().to_vec(),
                output: vec![],
            })
            .collect_vec();
        let type_script_claims = self
            .type_script_hashes
            .iter()
            .map(|lsh| Claim {
                program_digest: *lsh,
                input: [
                    self.kernel_mast_hash,
                    self.salted_inputs_hash,
                    self.salted_outputs_hash,
                ]
                .into_iter()
                .flat_map(|d| d.reversed().values())
                .collect_vec(),
                output: vec![],
            })
            .collect_vec();

        // verify
        let rri = triton_vm::verify(
            Stark::default(),
            &removal_records_integrity_claim,
            &self.removal_records_integrity,
        );
        let k2o = triton_vm::verify(
            Stark::default(),
            &kernel_to_outputs_claim,
            &self.kernel_to_outputs,
        );
        let cls = triton_vm::verify(
            Stark::default(),
            &collect_lock_scripts_claim,
            &self.collect_lock_scripts,
        );
        let cts = triton_vm::verify(
            Stark::default(),
            &collect_type_scripts_claim,
            &self.collect_type_scripts,
        );
        let lsh = lock_script_claims
            .iter()
            .zip(self.lock_scripts_halt.iter())
            .all(|(cl, pr)| triton_vm::verify(Stark::default(), cl, pr));
        let tsh = type_script_claims
            .iter()
            .zip(self.type_scripts_halt.iter())
            .all(|(cl, pr)| triton_vm::verify(Stark::default(), cl, pr));

        // and all bits together and return
        rri && k2o && cls && cts && lsh && tsh
    }
}

impl SecretWitness for ProofCollection {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(self.kernel_mast_hash.reversed().values().to_vec())
    }

    fn program(&self) -> Program {
        StandardDecomposition.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        // set memory
        let mut memory = HashMap::default();
        encode_to_memory(
            &mut memory,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            self.clone(),
        );

        NonDeterminism::default().with_ram(memory)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct StandardDecomposition;

impl ConsensusProgram for StandardDecomposition {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}
