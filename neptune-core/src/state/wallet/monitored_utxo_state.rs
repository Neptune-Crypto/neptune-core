use neptune_primitives::block_height::BlockHeight;

pub(crate) enum MonitoredUtxoState {
    SyncedAndUnspent,
    Spent(Option<BlockHeight>),
    Unsynced,
}
