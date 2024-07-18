# Events

neptune-core can be seen as an event-driven program. Below is a list of all the events, and the messages that these events create.

## Events

| Description                                                                       | Direct Task Messages       | Indirect Task Messages                                                        | Spawned Network Messages       |
| :-------------------------------------------------------------------------------- | :------------------------- | :---------------------------------------------------------------------------- | :----------------------------- |
| New block found locally                                                           | FromMinerToMain::NewBlock  | MainToPeerTask::BlockFromMiner <br />  PeerMessage::Block                     | PeerMessage::Block             |
| New block received from peer <br /> Got: PeerMessage::Block                       | PeerTaskToMain::NewBlock   | ToMiner::NewBlock <br /> <span style="color:red">MainToPeerTask::Block</span> | PeerMessage::BlockNotification |
| Block notification received from peer <br /> Got:  PeerMessage::BlockNotification | MainToMiner::NewBlock      | <span style="color:red">MainToPeerTask::Block</span>                          | PeerMessage::BlockNotification |