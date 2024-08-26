use tasm_lib::Digest;

use super::archival_state::ArchivalState;
use super::light_state::LightState;

use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::traits::BlockchainBlockSelector;

/// `BlockChainState` provides an `Archival` variant
/// for full nodes and a `Light` variant for light nodes.
///
/// It provides a bit of abstraction over the chain state.
/// In particular, one can call `light_state()` and get
/// the current tip for either variant.
///
/// It is intended to be forward thinking for when we
/// actually implement a light node.
///
// silence possible clippy bug / false positive.
// see: https://github.com/rust-lang/rust-clippy/issues/9798
#[derive(Debug)]
pub enum BlockchainState {
    /// represents a Archival blockchain state
    Archival(ArchivalState),
    /// represents Light node blockchain state (ie the current tip)
    Light(LightState),
}

impl BlockchainState {
    /// check if this is an archival node/state
    #[inline]
    pub fn is_archival_node(&self) -> bool {
        matches!(self, Self::Archival(_))
    }

    /// retrieve archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn archival_state(&self) -> &ArchivalState {
        match self {
            Self::Archival(a) => a,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve mutable archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn archival_state_mut(&mut self) -> &mut ArchivalState {
        match self {
            Self::Archival(a) => a,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve light state, ie the current tip.
    #[inline]
    pub fn light_state(&self) -> &LightState {
        match self {
            Self::Archival(a) => a.tip(),
            Self::Light(l) => l,
        }
    }

    /// retrieve mutable light state, ie the current tip.
    #[inline]
    pub fn light_state_mut(&mut self) -> &mut LightState {
        match self {
            Self::Archival(a) => a.tip_mut(),
            Self::Light(l) => l,
        }
    }
}

impl BlockchainBlockSelector for BlockchainState {
    // doc'ed in trait
    fn tip_digest(&self) -> Digest {
        self.light_state().hash()
    }

    // doc'ed in trait
    fn tip_height(&self) -> BlockHeight {
        self.light_state().header().height
    }

    // doc'ed in trait
    //
    // panics for light-state
    // Probably LightState should be modified to hold the genesis block
    // the way that ArchivalState does.
    fn genesis_digest(&self) -> Digest {
        match self {
            Self::Archival(a) => a.genesis_digest(),
            Self::Light(_) => todo!(),
        }
    }

    // doc'ed in trait
    //
    // panics for light-state as it does not have any history
    // the only way it could impl this would be to query peer(s)
    // or some decentralized data-storage layer.
    async fn height_to_canonical_digest(&self, h: BlockHeight) -> Option<Digest> {
        match self {
            Self::Archival(a) => a.height_to_canonical_digest(h).await,
            Self::Light(_) => unimplemented!(),
        }
    }

    // doc'ed in trait
    //
    // panics for light-state as it does not have any history
    // the only way it could impl this would be to query peer(s)
    // or some decentralized data-storage layer.
    async fn digest_to_canonical_height(&self, d: Digest) -> Option<BlockHeight> {
        match self {
            Self::Archival(a) => a.digest_to_canonical_height(d).await,
            Self::Light(_) => unimplemented!(),
        }
    }
}
