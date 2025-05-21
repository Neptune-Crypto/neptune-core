use std::fmt::Display;
use std::str::FromStr;

use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use sysinfo::System;

use crate::api::export::TransactionProofType;
use crate::models::state::Claim;
use crate::models::state::NonDeterminism;
use crate::models::state::Program;
use crate::models::state::VMState;
use crate::models::state::VM;

/// represents proving capability of a device.
///
/// The proving capability is represented as log2(padded_height) where
/// padded_height is an indicator of the execution complexity of the
/// (program, claim, nondeterminism) triple necessary for generating a
/// TritonVm `Proof`.
///
/// A rough indicator of a device's capability can be obtained via
/// the `auto_detect()` method.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VmProvingCapability {
    log2_padded_height: u8,
}

impl From<u8> for VmProvingCapability {
    fn from(log2_padded_height: u8) -> Self {
        Self { log2_padded_height }
    }
}

impl From<VmProvingCapability> for u8 {
    fn from(capability: VmProvingCapability) -> Self {
        capability.log2_padded_height
    }
}

impl From<VmProvingCapability> for u32 {
    fn from(capability: VmProvingCapability) -> Self {
        capability.log2_padded_height.into()
    }
}

impl VmProvingCapability {
    /// indicates if the device is capable of executing a program with the
    /// supplied padded height
    ///
    /// Examples:
    ///
    /// ```
    /// use neptune_cash::api::export::VmProvingCapability;
    /// use neptune_cash::api::export::TransactionProofType;
    ///
    /// let capability: VmProvingCapability = 16.into();
    ///
    /// assert!(capability.can_prove(15u32).is_ok());
    /// assert!(capability.can_prove(16u32).is_ok());
    /// assert!(!capability.can_prove(17u32).is_ok());
    ///
    /// assert!(capability.can_prove(TransactionProofType::PrimitiveWitness).is_ok());
    /// assert!(capability.can_prove(TransactionProofType::ProofCollection).is_ok());
    /// assert!(!capability.can_prove(TransactionProofType::SingleProof).is_ok());
    ///
    /// let single_proof_capability: VmProvingCapability = TransactionProofType::SingleProof.into();
    /// assert!(single_proof_capability.can_prove(TransactionProofType::SingleProof).is_ok());
    pub fn can_prove(&self, other: impl Into<u32>) -> Result<(), VmProvingCapabilityError> {
        let capability: u32 = (*self).into();
        let attempted: u32 = other.into();

        if capability >= attempted {
            Ok(())
        } else {
            Err(VmProvingCapabilityError::DeviceNotCapable {
                capability,
                attempted,
            })
        }
    }

    /// executes the supplied program triple to determine if device is capable
    /// of producing a TritonVM `Proof`.
    ///
    /// perf: this is an expensive operation; it may be under a second up to
    /// several seconds
    ///
    /// The program is executed inside spawn_blocking() so it will not block
    /// concurrent async tasks on the same thread.
    pub async fn check_if_capable_async(
        &self,
        program: Program,
        claim: Claim,
        nondeterminism: NonDeterminism,
    ) -> Result<(), VmProvingCapabilityError> {
        let copy = *self;
        tokio::task::spawn_blocking(move || copy.check_if_capable(program, claim, nondeterminism))
            .await
            .unwrap()
    }

    /// executes the supplied program triple to determine if device is capable
    /// of producing a TritonVM `Proof`.
    ///
    /// perf: this is an expensive operation; it may be under a second up to
    /// several seconds
    ///
    /// The program is executed in blocking fashion so it will block concurrent
    /// async tasks on the same thread.  async callers should use
    /// `check_if_capable_async()` instead.
    pub fn check_if_capable(
        &self,
        program: Program,
        claim: Claim,
        nondeterminism: NonDeterminism,
    ) -> Result<(), VmProvingCapabilityError> {
        let log2_padded_height = Self::obtain_log2_padded_height(program, claim, nondeterminism)?;
        self.can_prove(log2_padded_height)
    }

    /// executes the supplied program triple to obtain the log2(padded_height)
    ///
    /// perf: this is an expensive operation; it may be under a second up to
    /// several seconds
    ///
    /// The program is executed in blocking fashion so it will block concurrent
    /// async tasks on the same thread.  async callers should use
    /// `obtain_log2_padded_height_async()` instead.
    fn obtain_log2_padded_height(
        program: Program,
        claim: Claim,
        nondeterminism: NonDeterminism,
    ) -> Result<u32, VmProvingCapabilityError> {
        crate::macros::log_scope_duration!(crate::macros::fn_name!());

        let vmstate = VMState::new(program, claim.input.into(), nondeterminism);
        let (aet, _) = VM::trace_execution_of_state(vmstate)?;
        Ok(aet.padded_height().ilog2())
    }

    /// automatically detect the log2_padded_height for this device.
    ///
    /// for now this just:
    /// 1. obtains CPU core count and total mem for device.
    /// 2. compares against single-proof requirements
    /// 3. compares against proof-collection requirements
    /// 4. sets to min requirement of single-proof, proof-collection
    ///    or else primitive-witness depending on comparison results.
    ///
    /// in the future this method (or a similar one) may instead run
    /// some kind of proving test to calculate the log2_padded_height
    /// more accurately.
    //
    // see discussion:
    // <https://github.com/Neptune-Crypto/neptune-core/issues/576#issuecomment-2841509671>
    //
    // note: it would be nice if triton_vm would provide a method for this
    // that we can just call, eg: triton_vm::estimate_log2_padded_height();
    //
    // note: this is pub(crate) for now because it may change to async in the
    // future if we do a more involved stress test.
    pub(crate) fn auto_detect() -> Self {
        const SINGLE_PROOF_CORE_REQ: usize = 19;
        // see https://github.com/Neptune-Crypto/neptune-core/issues/426
        const SINGLE_PROOF_MEMORY_USAGE: u64 = (1u64 << 30) * 120;

        const PROOF_COLLECTION_CORE_REQ: usize = 2;
        const PROOF_COLLECTION_MEMORY_USAGE: u64 = (1u64 << 30) * 16;

        let s = System::new_all();
        let total_memory = s.total_memory();
        assert!(
            !total_memory.is_zero(),
            "Total memory reported illegal value of 0"
        );

        let physical_core_count = s.physical_core_count().unwrap_or(1);

        if total_memory > SINGLE_PROOF_MEMORY_USAGE && physical_core_count > SINGLE_PROOF_CORE_REQ {
            TransactionProofType::SingleProof.into()
        } else if total_memory > PROOF_COLLECTION_MEMORY_USAGE
            && physical_core_count > PROOF_COLLECTION_CORE_REQ
        {
            TransactionProofType::ProofCollection.into()
        } else {
            TransactionProofType::PrimitiveWitness.into()
        }
    }
}

impl Display for VmProvingCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.log2_padded_height)
    }
}

impl FromStr for VmProvingCapability {
    type Err = clap::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<u8>() {
            Ok(height) => Ok(VmProvingCapability {
                log2_padded_height: height,
            }),
            Err(e) => Err(clap::Error::raw(
                clap::error::ErrorKind::ValueValidation,
                format!("invalid log2_padded_height '{}': {}", s, e),
            )),
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum VmProvingCapabilityError {
    #[error("could not obtain padded-height due to program execution error")]
    VmExecutionFailed(#[from] tasm_lib::triton_vm::error::VMError),

    #[error("device capability {capability} is insufficient to generate proof that requires capability {attempted}")]
    DeviceNotCapable { capability: u32, attempted: u32 },
}
