use std::fmt;
use std::net::IpAddr;

use neptune_database::NeptuneLevelDb;
use neptune_p2p::peer::PeerStanding;

#[derive(Clone)]
pub struct PeerDatabases {
    pub peer_standings_by_ip: NeptuneLevelDb<IpAddr, PeerStanding>,
}

impl fmt::Debug for PeerDatabases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("").finish()
    }
}
