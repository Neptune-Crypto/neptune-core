pub(crate) enum MonitoredUtxoState {
    SyncedAndUnspent,
    Spent,
    Unsynced,
}
