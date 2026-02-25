use crate::api::export::BlockHeight;

pub(crate) enum MonitoredUtxoState {
    SyncedAndUnspent,
    Spent(Option<BlockHeight>),
    Unsynced,
}
