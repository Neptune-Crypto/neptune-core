use super::{archival_state::ArchivalState, light_state::LightState};

#[derive(Debug, Clone)]
pub struct BlockchainState {
    pub archival_state: Option<ArchivalState>,
    pub light_state: LightState,
}
