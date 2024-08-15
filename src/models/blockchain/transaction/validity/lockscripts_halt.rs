use get_size::GetSize;
use itertools::Itertools;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::instruction::LabelledInstruction;
use tasm_lib::triton_vm::program::Program;
use tasm_lib::triton_vm::program::PublicInput;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::Digest;
use triton_vm::prelude::BFieldElement;
use triton_vm::prelude::NonDeterminism;
use twenty_first::math::bfield_codec::BFieldCodec;

use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::utxo::LockScript;
use crate::models::consensus::mast_hash::MastHash;
use crate::models::consensus::tasm::program::ConsensusProgram;
use crate::models::consensus::RawWitness;
use crate::models::consensus::SecretWitness;
use crate::models::consensus::ValidationLogic;
use crate::models::consensus::ValidityAstType;
use crate::models::consensus::ValidityTree;
use crate::models::consensus::WhichProgram;
use crate::models::consensus::WitnessType;
use crate::prelude::triton_vm;
use crate::prelude::twenty_first;

pub struct LockScriptHalts {
    pub program: Program,
    pub claim: Claim,
    pub raw_witness: RawWitness,
}

impl From<LockScriptHaltsWitness> for LockScriptHalts {
    fn from(witness: LockScriptHaltsWitness) -> Self {
        Self {
            claim: Claim::new(witness.lock_script.hash()).with_input(
                witness
                    .transaction_kernel_mast_hash
                    .reversed()
                    .values()
                    .to_vec(),
            ),
            program: witness.clone().lock_script.program,
            raw_witness: witness.nondeterminism().into(),
        }
    }
}

impl ValidationLogic for LockScriptHalts {
    fn vast(&self) -> ValidityTree {
        ValidityTree::new(
            ValidityAstType::Atomic(
                Some(Box::new(self.program.clone())),
                self.claim.clone(),
                WhichProgram::LockScriptHalts,
            ),
            WitnessType::RawWitness(self.raw_witness.clone()),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, BFieldCodec)]
pub struct LockScriptHaltsWitness {
    lock_script: LockScript,
    nondeterministic_tokens: Vec<BFieldElement>,
    transaction_kernel_mast_hash: Digest,
}

impl SecretWitness for LockScriptHaltsWitness {
    fn nondeterminism(&self) -> NonDeterminism {
        NonDeterminism::new(
            self.nondeterministic_tokens
                .clone()
                .into_iter()
                .collect_vec(),
        )
    }

    fn standard_input(&self) -> PublicInput {
        PublicInput::new(
            self.transaction_kernel_mast_hash
                .reversed()
                .values()
                .to_vec(),
        )
    }

    fn program(&self) -> Program {
        self.lock_script.program.clone()
    }
}

impl ConsensusProgram for LockScriptHalts {
    fn source(&self) {
        todo!()
    }

    fn code(&self) -> Vec<LabelledInstruction> {
        todo!()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize, Default, BFieldCodec)]
pub struct LockScriptsHalt {
    pub witnesses: Vec<LockScriptHaltsWitness>,
}

impl From<transaction::PrimitiveWitness> for LockScriptsHalt {
    fn from(primitive_witness: transaction::PrimitiveWitness) -> Self {
        let program_and_program_digests_and_spending_keys = primitive_witness
            .input_lock_scripts
            .iter()
            .zip_eq(primitive_witness.lock_script_witnesses.iter())
            .map(|(lockscr, spendkey)| (lockscr, lockscr.hash(), spendkey));
        let tx_kernel_mast_hash = primitive_witness.kernel.mast_hash();

        Self {
            witnesses: program_and_program_digests_and_spending_keys
                .into_iter()
                .map(|(lockscript, _lockscript_digest, spendkey)| {
                    let mut nondeterministic_tokens = spendkey.to_owned();
                    nondeterministic_tokens.reverse();
                    LockScriptHaltsWitness {
                        lock_script: lockscript.to_owned(),
                        nondeterministic_tokens,
                        transaction_kernel_mast_hash: tx_kernel_mast_hash,
                    }
                })
                .collect(),
        }
    }
}

impl ValidationLogic for LockScriptsHalt {
    fn vast(&self) -> ValidityTree {
        ValidityTree::new(
            ValidityAstType::All(
                self.witnesses
                    .iter()
                    .cloned()
                    .map(|witness| LockScriptHalts::from(witness).vast())
                    .collect_vec(),
            ),
            WitnessType::Decomposition,
        )
    }
}
