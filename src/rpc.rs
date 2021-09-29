use futures::future::{self, Ready};
use std::net::SocketAddr;
use tarpc::context;

#[tarpc::service]
pub trait RPC {
    /// Returns the current block height.
    async fn block_height() -> usize;
}

#[derive(Clone)]
pub struct NeptuneRPCServer(pub SocketAddr);

impl RPC for NeptuneRPCServer {
    type BlockHeightFut = Ready<usize>;

    fn block_height(self, _: context::Context) -> Self::BlockHeightFut {
        future::ready(42)
    }
}
