use std::io::Write;
use std::path::PathBuf;

use crate::models::blockchain::shared::Hash as NeptuneHash;
use crate::triton_vm::prelude::Program;
use crate::triton_vm::proof::Claim;
use crate::triton_vm::vm::NonDeterminism;
use crate::triton_vm::vm::VMState;

/// enumerates types of proofs that can be logged.
///
/// this type facilitates offering distinct logging modes for:
///
/// 1. `MayContainWalletSecrets` (any kind of Proof)
/// 2. `DoesNotContainWalletSecrets`
///
/// The `MayContainWalletSecrets` mode is useful for logging inputs to every
/// single Proof that is generated.  These include proofs generated from
/// `PrimitiveWitness` meaning that the claims expose secrets and should not be
/// shared. This mode of logging is considered a security risk, but can be
/// useful for investigating or researching alone, or on testnet(s), etc.
///
/// The `DoesNotContainWalletSecrets` mode is useful when logging proof inputs for
/// purposes of sharing with others, eg neptune-core developers for debugging.
/// However it does not log any Proofs generated from a `PrimitiveWitness`
/// and thus does not leak wallet secrets.
pub enum LogProofInputsType {
    /// log proof inputs that may contain wallet secrets
    MayContainWalletSecrets,

    /// log proof inputs that do not contain wallet secrets
    DoesNotContainWalletSecrets,
}

impl LogProofInputsType {
    /// returns name of logging environment variable
    ///
    /// each variant has an environment variable that specifies the
    /// directory in which to write proof files.
    pub const fn env_var_name(&self) -> &str {
        match *self {
            Self::MayContainWalletSecrets => "NEPTUNE_VM_STATE_WITH_SECRETS_DIR",
            Self::DoesNotContainWalletSecrets => "NEPTUNE_VM_STATE_NO_SECRETS_DIR",
        }
    }

    /// returns file name prefix
    pub const fn file_prefix(&self) -> &str {
        match *self {
            Self::MayContainWalletSecrets => "vm_state.unsafe_to_share",
            Self::DoesNotContainWalletSecrets => "vm_state.safe_to_share",
        }
    }
}

/// If the environment variable specified by [LogProofInputsType::env_var_name()] is set,
/// write the initial VM state to file `<DIR>/<prefix>.<pid>.<claim>.json`.
///
/// where:
///  DIR = value of environment variable.
///  prefix = LogProofInputsType::file_prefix()
///  pid = process-id
///  claim = hex-encoded hash of input Claim
///
/// This file can be used to debug the program using the [Triton TUI]:
/// ```sh
/// triton-tui --initial-state <file>
/// ```
///
/// [Triton TUI]: https://crates.io/crates/triton-tui
///
/// Security:
///
/// Files of type [LogProofInputsType::MayContainWalletSecrets] should only be
/// used for debugging by the wallet owner as they may contain wallet secrets.
///
/// Files of type [LogProofInputsType::DoesNotContainWalletSecrets] can be shared
/// with others eg, neptune-core developers, for purposes of
/// debugging/assistance.
///
/// It is the *callers* responsibility to ensure that the provided claim matches
/// the `log_proof_inputs_type`
pub fn maybe_write<'a, F>(
    log_proof_inputs_type: LogProofInputsType,
    program: Program,
    claim: &Claim,
    nondeterminism: F,
) -> Result<Option<PathBuf>, LogVmStateError>
where
    F: FnOnce() -> NonDeterminism + Send + Sync + 'a,
{
    let Ok(dir) = std::env::var(log_proof_inputs_type.env_var_name()) else {
        return Ok(None);
    };
    let prefix = log_proof_inputs_type.file_prefix();

    write(&dir, prefix, program, claim, nondeterminism()).inspect_err(|e| tracing::warn!("{}", e))
}

fn write(
    dir: &str,
    file_prefix: &str,
    program: Program,
    claim: &Claim,
    nondeterminism: NonDeterminism,
) -> Result<Option<PathBuf>, LogVmStateError> {
    let vm_state = VMState::new(program, claim.input.clone().into(), nondeterminism);

    let filename = format!(
        "{}.{}.{}.json",
        file_prefix,
        std::process::id(),
        NeptuneHash::hash(claim).to_hex(),
    );

    let path = PathBuf::from(dir).join(filename);

    let mut state_file =
        std::fs::File::create(&path).map_err(|e| LogVmStateError::from((path.clone(), e)))?;
    let state = serde_json::to_string(&vm_state)?;
    write!(state_file, "{}", state).map_err(|e| LogVmStateError::from((path.clone(), e)))?;
    Ok(Some(path))
}

#[derive(Debug, thiserror::Error, strum::EnumIs)]
#[non_exhaustive]
pub enum LogVmStateError {
    #[error("could not obtain padded-height due to program execution error")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    SerializeError(#[from] serde_json::Error),
}

impl From<(PathBuf, std::io::Error)> for LogVmStateError {
    fn from(v: (PathBuf, std::io::Error)) -> Self {
        let (path, source) = v;
        Self::IoError { path, source }
    }
}
