# Events

neptune-core can be seen as an event-driven program. Below is a list of all the events, and the messages that these events create.

## Events

| Description | Direct Task Messages | Indirect Task Messages | Spawned Network Messages |
| :--- | :--- | :--- | :--- |
| New block found locally | MinerToMain::NewBlockFound | MainToPeerTask::Block | PeerMessage::BlockNotificationWithPowWitness <br /> (PeerMessage::BlockNotification for older peers) |
| New block received from peer <br /> Got: PeerMessage::Block | PeerTaskToMain::NewBlocks | MainToMiner::NewBlock <br /> MainToPeerTask::Block | PeerMessage::BlockNotificationWithPowWitness <br /> (PeerMessage::BlockNotification for older peers) |
| Block notification received from peer <br /> Got: PeerMessage::BlockNotificationWithPowWitness or PeerMessage::BlockNotification | | | PeerMessage::BlockRequestByHeight if the block is new; <br /> PeerMessage::SyncChallenge instead if the sync-mode threshold is exceeded |
| New block proposal composed locally | MinerToMain::BlockProposal | MainToPeerTask::BlockProposalNotification (unless `--secret-compositions`) | PeerMessage::BlockProposalNotification |
| Block proposal notification received from peer <br /> Got: PeerMessage::BlockProposalNotification | | | PeerMessage::BlockProposalRequest if the proposal is of interest |
| Block proposal received from peer <br /> Got: PeerMessage::BlockProposal | PeerTaskToMain::BlockProposal | MainToPeerTask::BlockProposalNotification <br /> MainToMiner::NewBlockProposal if the proposal is more favorable and the node guesses | PeerMessage::BlockProposalNotification |
| Own transaction initiated <br /> (RPC) | RPCServerToMain::RecordAndBroadcastOwnTx or RPCServerToMain::BroadcastOwnTx | MainToPeerTask::TransactionNotification | PeerMessage::TransactionNotification |
| Transaction notification received from peer <br /> Got: PeerMessage::TransactionNotification | | | PeerMessage::TransactionRequest if the transaction is new |
| Transaction received from peer <br /> Got: PeerMessage::Transaction | PeerTaskToMain::Transaction | MainToPeerTask::TransactionNotification if inserting it changed the mempool | PeerMessage::TransactionNotification |
| Own chained transaction initiated <br /> (RPC) | RPCServerToMain::BroadcastOwnLinkTx | MainToPeerTask::LinkTxNotification | PeerMessage::LinkTxNotification |
| Chained transaction notification received from peer <br /> Got: PeerMessage::LinkTxNotification | | | PeerMessage::LinkTxRequest if the chained transaction is new |
| Chained transaction received from peer <br /> Got: PeerMessage::LinkTx | PeerTaskToMain::LinkTx | MainToPeerTask::LinkTxNotification | PeerMessage::LinkTxNotification |
| Mempool transactions updated after a new block | (internal mempool update job) | MainToPeerTask::TransactionNotification <br /> MainToPeerTask::LinkTxNotification | PeerMessage::TransactionNotification <br /> PeerMessage::LinkTxNotification |
