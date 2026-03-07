use tasm_lib::triton_vm::prelude::Program;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::vm::NonDeterminism;

use crate::application::config::triton_vm_env_vars::TritonVmEnvVars;
use crate::protocol::proof_abstractions::tasm::prover_job::ProverJob;

/// A complete description of a prover task, tailored for inter-process
/// communication.
///
/// This struct contains the fields necessary for the external proving process
/// and only those fields. Phrased, differently, it codifies the input format.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TritonVMProverJob {
    pub program: Program,
    pub claim: Claim,
    pub non_determinism: NonDeterminism,
    pub max_log2_padded_height: Option<u8>,
    pub env_vars: TritonVmEnvVars,
}

impl From<ProverJob> for TritonVMProverJob {
    fn from(job: ProverJob) -> Self {
        Self {
            program: job.program,
            claim: job.claim,
            non_determinism: job.nondeterminism,
            max_log2_padded_height: job.job_settings.max_log2_padded_height_for_proofs,
            env_vars: job.job_settings.triton_vm_env_vars,
        }
    }
}
