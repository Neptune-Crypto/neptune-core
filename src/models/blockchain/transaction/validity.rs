pub mod compiled_program;
pub mod kernel_to_lock_scripts;
pub mod kernel_to_typescripts;
pub mod lockscripts_halt;
pub mod tasm;
pub mod typescripts_halt;

use crate::models::blockchain::shared::Hash;
use anyhow::{bail, Ok, Result};
use get_size::GetSize;
use itertools::Itertools;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use triton_opcodes::program::Program;
use triton_vm::{proof::Proof, Claim};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::{
    shared_math::b_field_element::BFieldElement, util_types::algebraic_hasher::AlgebraicHasher,
};

use self::{
    compiled_program::CompiledProgram,
    kernel_to_lock_scripts::KernelToLockScripts,
    kernel_to_typescripts::KernelToTypeScripts,
    lockscripts_halt::LockScriptsHalt,
    tasm::removal_records_integrity::{RemovalRecordsIntegrity, RemovalRecordsIntegrityWitness},
    typescripts_halt::TypeScriptsHalt,
};
use super::{transaction_kernel::TransactionKernel, PrimitiveWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub enum ClaimSupport {
    Proof(Proof),
    SecretWitness(Vec<BFieldElement>, Option<Program>),
    DummySupport, // TODO: Remove this when all claims are implemented
}

impl BFieldCodec for ClaimSupport {
    fn decode(sequence: &[BFieldElement]) -> Result<Box<Self>> {
        match sequence.first() {
            Some(val) => match val.value() {
                0 => {
                    let proof = *Proof::decode(&sequence[1..])?;
                    Ok(Box::new(ClaimSupport::Proof(proof)))
                }
                1 => {
                    let mut index = 1;
                    let secret_len: usize = match sequence.get(index) {
                        Some(inner_val) => inner_val.value().try_into()?,
                        None => bail!(
                            "ClaimSupport::decode: Invalid sequence length for secret witness secret_len!"
                        ),
                    };
                    index += 1;
                    let secret =
                        *Vec::<BFieldElement>::decode(&sequence[index..index + secret_len])?;
                    index += secret_len;

                    let program_len: usize = match sequence.get(index) {
                        Some(inner_val) => inner_val.value().try_into()?,
                        None => bail!(
                            "ClaimSupport::decode: Invalid sequence length for secret witness program_len!"
                        ),
                    };
                    index += 1;

                    let maybe_program = *Option::<triton_opcodes::program::Program>::decode(
                        &sequence[index..index + program_len],
                    )?;
                    index += program_len;

                    if index != sequence.len() {
                        bail!("ClaimSupport::decode: Invalid sequence length for secret witness! Too long.");
                    }
                    Ok(Box::new(ClaimSupport::SecretWitness(secret, maybe_program)))
                }
                2 => {
                    if sequence.len() != 1 {
                        bail!("ClaimSupport::decode: Invalid sequence length for dummy support!");
                    }
                    Ok(Box::new(ClaimSupport::DummySupport))
                }
                _ => bail!("ClaimSupport::decode: Invalid claim support type!"),
            },
            None => todo!(),
        }
    }

    fn encode(&self) -> Vec<BFieldElement> {
        match self {
            ClaimSupport::Proof(proof) => {
                vec![vec![BFieldElement::zero()], proof.encode()].concat()
            }
            ClaimSupport::SecretWitness(secret, maybe_program) => {
                let secret_encoded = secret.encode();
                let program_encoded = maybe_program.encode();
                vec![
                    vec![BFieldElement::one()],
                    vec![BFieldElement::new(secret_encoded.len() as u64)],
                    secret_encoded,
                    vec![BFieldElement::new(program_encoded.len() as u64)],
                    program_encoded,
                ]
                .concat()
            }
            ClaimSupport::DummySupport => vec![BFieldElement::new(2)],
        }
    }

    fn static_length() -> Option<usize> {
        None
    }
}

/// SupportedClaim is a helper struct for ValiditySequence. It
/// encodes a Claim with an optional witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct SupportedClaim {
    pub claim: triton_vm::Claim,
    pub support: ClaimSupport,
}

impl SupportedClaim {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy() -> SupportedClaim {
        let dummy_claim = triton_vm::Claim {
            input: Default::default(),
            output: Default::default(),
            program_digest: Default::default(),
        };

        Self {
            claim: dummy_claim,
            support: ClaimSupport::DummySupport,
        }
    }
}

/// ValidityConditions is a helper struct. It contains a sequence of
/// claims with optional witnesses. If all claims a true, then the
/// transaction is valid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct TransactionValidityLogic {
    // programs: [lock_script], input: hash of tx kernel (MAST hash), witness: secret spending key, output: []
    pub lock_scripts_halt: LockScriptsHalt,

    // program: todo, input: hash of tx kernel (MAST hash), witness: input utxos, utxo mast auth path, output: hashes of lock scripts
    pub kernel_to_lock_scripts: KernelToLockScripts,

    // program: recompute swbf indices, input: hash of kernel, witness: inputs + mutator set accumulator, output: []
    pub removal_records_integrity: RemovalRecordsIntegrity,

    // program: todo, input: hash of tx kernel (MAST hash), witness: outputs + kernel mast auth path + coins, output: type scripts
    pub kernel_to_typescripts: KernelToTypeScripts,

    // program: type script, input: hash of inputs + hash of outputs + coinbase + fee, witness: inputs + outputs + any, output: []
    pub type_scripts_halt: TypeScriptsHalt,
}

pub trait ValidationLogic {
    fn new_from_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self;
    fn prove(&mut self) -> Result<()>;
    fn verify(&self) -> bool;
}

impl ValidationLogic for TransactionValidityLogic {
    fn new_from_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let kernel_hash = tx_kernel.mast_hash().reversed().values().to_vec();
        let lock_scripts_halt = LockScriptsHalt {
            supported_claims: primitive_witness
                .input_utxos
                .iter()
                .zip(primitive_witness.input_lock_scripts.iter())
                .zip(primitive_witness.lock_script_witnesses.iter())
                .map(
                    |((_utxo, lock_script), lock_script_witness)| SupportedClaim {
                        claim: Claim {
                            program_digest: lock_script.hash(),
                            input: kernel_hash.clone(),
                            output: vec![],
                        },
                        support: ClaimSupport::SecretWitness(
                            lock_script_witness.clone(),
                            Some(lock_script.program.clone()),
                        ),
                    },
                )
                .collect_vec(),
        };
        let kernel_to_lock_scripts = KernelToLockScripts {
            supported_claim: SupportedClaim::dummy(),
        };
        debug!(
            "Removal Records Integrity program digest: ({})",
            Hash::hash_varlen(&RemovalRecordsIntegrity::program().encode())
        );
        let removal_records_integrity = RemovalRecordsIntegrity {
            supported_claim: SupportedClaim {
                claim: Claim {
                    program_digest: RemovalRecordsIntegrity::program().hash::<Hash>(),
                    input: kernel_hash,
                    output: vec![],
                },
                support: ClaimSupport::SecretWitness(
                    RemovalRecordsIntegrityWitness::new(primitive_witness, tx_kernel).encode(),
                    None,
                ),
            },
        };
        let kernel_to_typescripts = KernelToTypeScripts {
            supported_claim: SupportedClaim::dummy(),
        };
        let type_scripts_halt = TypeScriptsHalt {
            supported_claims: vec![SupportedClaim::dummy()],
        };
        Self {
            lock_scripts_halt,
            kernel_to_lock_scripts,
            removal_records_integrity,
            kernel_to_typescripts,
            type_scripts_halt,
        }
    }

    fn prove(&mut self) -> Result<()> {
        self.lock_scripts_halt.prove()?;

        self.removal_records_integrity.prove()?;

        // not supported yet:
        // self.kernel_to_lock_scripts.prove()?;
        // self.kernel_to_typescripts.prove()?;
        // self.type_scripts_halt.prove()?;
        Ok(())
    }

    fn verify(&self) -> bool {
        info!("validity logic for 'kernel_to_lock_scripts', 'kernel_to_type_scripts', 'type_scripts_halt' not implemented yet.");
        self.lock_scripts_halt.verify()
            // && self.kernel_to_lock_scripts.verify()
            && self.removal_records_integrity.verify()
        // && self.kernel_to_typescripts.verify()
        // && self.type_scripts_halt.verify()
    }
}
