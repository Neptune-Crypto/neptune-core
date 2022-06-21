use crate::models::blockchain::block::BlockHeight;
use crate::models::database::DatabaseUnit;
use crate::models::peer::Peer;
use crate::models::shared::LatestBlockInfo;
use crate::models::State;
use futures::executor;
use futures::future::{self, Ready};
use leveldb::kv::KV;
use leveldb::options::ReadOptions;
use std::net::SocketAddr;
use tarpc::context;

#[tarpc::service]
pub trait RPC {
    /// Returns the current block height.
    async fn block_height() -> BlockHeight;

    // Returns info about the peers we are connected to
    async fn get_peer_info() -> Vec<Peer>;
}

#[derive(Clone)]
pub struct NeptuneRPCServer {
    pub socket_address: SocketAddr,
    pub state: State,
}

impl RPC for NeptuneRPCServer {
    type BlockHeightFut = Ready<BlockHeight>;
    type GetPeerInfoFut = Ready<Vec<Peer>>;

    fn block_height(self, _: context::Context) -> Self::BlockHeightFut {
        let databases = executor::block_on(self.state.databases.lock());
        let lookup_res = databases
            .latest_block
            .get(ReadOptions::new(), DatabaseUnit())
            .expect("Failed to get latest block info on init");
        let block_info: Option<LatestBlockInfo> = lookup_res.map(|bytes| {
            bincode::deserialize(&bytes).expect("Failed to deserialize latest block info")
        });
        match block_info {
            Some(bh) => future::ready(bh.height),
            None => future::ready(0.into()),
        }
    }

    fn get_peer_info(self, _: context::Context) -> Self::GetPeerInfoFut {
        let peer_map = self
            .state
            .peer_map
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();

        future::ready(peer_map)
    }
}
