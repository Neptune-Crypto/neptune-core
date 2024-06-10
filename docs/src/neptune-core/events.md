# Events

The Neptune Core client can be seen as an event-driven client. Below is a list of all the events, and the messages that
these events create.

## Events

| Description                                                                       | Direct Thread Messages     | Indirect Thread Messages                                                        | Spawned Network Messages       |
| :-------------------------------------------------------------------------------- | :------------------------- | :------------------------------------------------------------------------------ | :----------------------------- |
| New block found locally                                                           | FromMinerToMain::NewBlock  | MainToPeerThread::BlockFromMiner <br />  PeerMessage::Block                     | PeerMessage::Block             |
| New block received from peer <br /> Got: PeerMessage::Block                       | PeerThreadToMain::NewBlock | ToMiner::NewBlock <br /> <span style="color:red">MainToPeerThread::Block</span> | PeerMessage::BlockNotification |
| Block notification received from peer <br /> Got:  PeerMessage::BlockNotification | MainToMiner::NewBlock      | <span style="color:red">MainToPeerThread::Block</span>                          | PeerMessage::BlockNotification |