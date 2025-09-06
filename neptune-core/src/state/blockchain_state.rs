use super::archival_state::ArchivalState;
use super::light_state::LightState;
use crate::Block;

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
    Archival(Box<BlockchainArchivalState>),
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
    pub(crate) fn archival_state(&self) -> &ArchivalState {
        match self {
            Self::Archival(bac) => &bac.archival_state,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve blockchain archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn blockchain_archival_state(&self) -> &BlockchainArchivalState {
        match self {
            Self::Archival(bac) => bac,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve mutable archival state.
    ///
    /// panics if called by a light node.
    #[inline]
    pub fn archival_state_mut(&mut self) -> &mut ArchivalState {
        match self {
            Self::Archival(bac) => &mut bac.archival_state,
            Self::Light(_) => panic!("archival_state not available in LightState mode"),
        }
    }

    /// retrieve light state, ie the current tip.
    #[inline]
    pub fn light_state(&self) -> &Block {
        match self {
            Self::Archival(bac) => &bac.light_state,
            Self::Light(light_state) => light_state,
        }
    }

    #[inline]
    pub fn light_state_clone(&self) -> LightState {
        match self {
            Self::Archival(bac) => bac.light_state.clone(),
            Self::Light(light_state) => light_state.clone(),
        }
    }

    /// retrieve mutable light state, ie the current tip.
    #[inline]
    pub fn light_state_mut(&mut self) -> &mut LightState {
        match self {
            Self::Archival(bac) => &mut bac.light_state,
            Self::Light(light_state) => light_state,
        }
    }
}

/// The `BlockchainArchivalState` contains database access to block headers.
///
/// It is divided into `ArchivalState` and `LightState`.
#[derive(Debug)]
pub struct BlockchainArchivalState {
    /// Historical blockchain data, persisted
    pub(crate) archival_state: ArchivalState,

    /// The present tip.
    pub light_state: LightState,
}
