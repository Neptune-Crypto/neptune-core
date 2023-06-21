pub mod inputs_to_lock_scripts;
pub mod kernel_to_inputs;
pub mod kernel_to_typescripts;
pub mod lockscript_halts;
pub mod removal_records_integrity;
pub mod tasm;
pub mod typescript_halts;

use anyhow::{bail, Ok, Result};
use get_size::GetSize;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use triton_vm::proof::Proof;
use twenty_first::shared_math::{b_field_element::BFieldElement, bfield_codec::BFieldCodec};

use self::{
    inputs_to_lock_scripts::InputsToLockScripts, kernel_to_inputs::KernelToInputs,
    kernel_to_typescripts::KernelToTypeScripts, lockscript_halts::LockScriptHalts,
    removal_records_integrity::RemovalRecordsIntegrity, typescript_halts::TypescriptHalts,
};
use super::{transaction_kernel::TransactionKernel, PrimitiveWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub enum ClaimSupport {
    Proof(Proof),
    SecretWitness(Vec<BFieldElement>, triton_opcodes::program::Program),
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

                    let program = *triton_opcodes::program::Program::decode(
                        &sequence[index..index + program_len],
                    )?;
                    index += program_len;

                    if index != sequence.len() {
                        bail!("ClaimSupport::decode: Invalid sequence length for secret witness! Too long.");
                    }
                    Ok(Box::new(ClaimSupport::SecretWitness(secret, program)))
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
            ClaimSupport::SecretWitness(secret, program) => {
                let secret_encoded = secret.encode();
                let program_encoded = program.encode();
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

/// WitnessableClaim is a helper struct for ValiditySequence. It
/// encodes a Claim with an optional witness.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct SupportedClaim {
    pub claim: triton_vm::Claim,
    pub support: ClaimSupport,
}

impl SupportedClaim {
    // TODO: REMOVE when all validity logic is implemented
    pub fn dummy_supported_claim() -> SupportedClaim {
        fn dummy_claim() -> triton_vm::Claim {
            triton_vm::Claim {
                input: Default::default(),
                output: Default::default(),
                program_digest: Default::default(),
            }
        }

        Self {
            claim: dummy_claim(),
            support: ClaimSupport::DummySupport,
        }
    }
}

/// ValidityConditions is a helper struct. It contains a sequence of
/// claims with optional witnesses. If all claims a true, then the
/// transaction is valid.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct ValidityLogic {
    // program: lock_script, input: hash of tx kernel (MAST hash), witness: secret spending key, output: []
    pub lock_script_halts: LockScriptHalts,

    // program: todo, input: encoding of all TX inputs (UTXOs), witness: input utxos, utxo mast auth path, output: lock scripts
    pub inputs_to_lock_scripts: InputsToLockScripts,

    // program: todo, input: hash of tx kernel (MAST hash), witness: kernel mast auth path, output: encoding of all TX inputs (UTXOs)
    pub kernel_to_inputs: KernelToInputs,

    // program: verify+drop, input: hash of kernel, witness: inputs + mutator set accumulator, output: []
    pub removal_records_integrity: RemovalRecordsIntegrity,

    // program: todo, input: hash of tx kernel (MAST hash), witness: outputs + kernel mast auth path + coins, output: type scripts
    pub kernel_to_typescripts: KernelToTypeScripts,

    // program: type script, input: hash of inputs + hash of outputs + coinbase + fee, witness: inputs + outputs + any, output: []
    pub type_script_halts: TypescriptHalts,
}

pub trait TxValidationLogic {
    fn unproven_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self;
    fn prove(&mut self) -> Result<()>;
    fn verify(&self, tx_kernel: &TransactionKernel) -> bool;
}

// Logic for generating ValidityLogic
impl ValidityLogic {
    // TODO: Consider implementing the `TxValidationLogic` trait here
    /// Generate validity logic for a transaction containing secret data as stand-in for proofs
    pub fn unproven_from_primitive_witness(
        primitive_witness: &PrimitiveWitness,
        tx_kernel: &TransactionKernel,
    ) -> Self {
        let lock_script_halts =
            LockScriptHalts::unproven_from_primitive_witness(primitive_witness, tx_kernel);

        // TODO: Generate all other fields correctly
        Self {
            lock_script_halts,
            inputs_to_lock_scripts: InputsToLockScripts::dummy(),
            kernel_to_inputs: KernelToInputs::dummy(),
            removal_records_integrity: RemovalRecordsIntegrity::dummy(),
            kernel_to_typescripts: KernelToTypeScripts::dummy(),
            type_script_halts: TypescriptHalts::dummy(),
        }
    }

    pub fn verify(&self, tx_kernel: &TransactionKernel) -> bool {
        self.lock_script_halts.verify(tx_kernel) // && ...

        // TODO: Add all other checks here
    }

    pub fn prove(&mut self) -> Result<()> {
        self.lock_script_halts.prove()?;

        // TODO: Prove all other fields here

        Ok(())
    }
}
