use tasm_lib::prelude::Digest;

/// The consensus-relevant projection of a premine recipient: the two digests
/// genesis derives from a recipient address — the mutator-set receiver digest
/// and the lock-script hash.
#[derive(Debug, Clone, Copy)]
pub struct PremineReceiver {
    pub receiver_digest: Digest,
    pub lock_script_hash: Digest,
}
