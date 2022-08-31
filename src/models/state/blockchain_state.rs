use super::{archival_state::ArchivalState, light_state::LightState};

/// The `BlockchainState` contains database access to block headers.
///
/// It is divided into `ArchivalState` and `LightState`.
#[derive(Debug, Clone)]
pub struct BlockchainState {
    /// The `archival_state` locks require an await to be taken, so archival_state
    /// locks must always be taken before light state locks. Due to the policy of
    /// taking locks in the order they are defined in terms of fields, archival_state
    /// must be listed before `light_state`.
    pub archival_state: Option<ArchivalState>,

    /// The `LightState` contains a lock from std::sync which may not be held
    /// across an await.
    pub light_state: LightState,
}
