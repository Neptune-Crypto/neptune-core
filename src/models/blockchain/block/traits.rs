//! traits for working with blocks

use tasm_lib::Digest;

use super::block_height::BlockHeight;

/// an interface for any type that provides data to
/// [BlockSelector](super::block_selector::BlockSelector) to read from the
/// blockchain.
///
/// note: this trait enables BlockSelector to abstract over BlockchainState and
/// &ArchivalState.  The latter is necessary for use in ArchivalState methods
/// which take &self.
pub trait BlockchainBlockSelector {
    /// returns the tip digest
    fn tip_digest(&self) -> Digest;

    /// returns the tip height
    fn tip_height(&self) -> BlockHeight;

    /// returns genesis digest.
    fn genesis_digest(&self) -> Digest;

    // returns digest of canonical block at the given height
    #[allow(async_fn_in_trait)]
    async fn height_to_canonical_digest(&self, h: BlockHeight) -> Option<Digest>;

    // returns height of canonical block with the given digest
    #[allow(async_fn_in_trait)]
    async fn digest_to_canonical_height(&self, d: Digest) -> Option<BlockHeight>;
}
