use super::{archival_state::ArchivalState, light_state::LightState};

#[derive(Debug, Clone)]
pub struct BlockchainState {
    // The `LightState` contains a lock from std::sync which may no be held
    // across an await. The `archival_state` locks require an await to be taken,
    // so archival state locks must always be taken before light state locks. Due
    // to the policy of taking locks in the order they are defined in terms of
    // fields, archival_state must be listed before `light_state`.
    pub archival_state: Option<ArchivalState>,
    pub light_state: LightState,
}
