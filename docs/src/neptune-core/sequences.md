# Sequences

## New block received from peer (block not found by peer)

```text
 Miner task        Main task                   Peer task                     Peer
     │                 │                           │    BlockNotification*      │
     │                 │                           │◀───────────────────────────│
     │                 │                           │    BlockRequestByHeight    │
     │                 │                           │───────────────────────────▶│
     │                 │                           │    (if new)                │
     │                 │                           │    Block                   │
     │                 │                           │◀───────────────────────────│
     │                 │                           │ validate                   │
     │                 │  PeerTaskToMain::NewBlocks│                            │
     │                 │◀──────────────────────────│                            │
     │                 │ set_new_tip,              │                            │
     │                 │ flush databases           │                            │
     │                 │  MainToPeerTask::Block    │                            │
     │                 │  (broadcast to all        │                            │
     │                 │   peer tasks)             │                            │
     │                 │──────────────────────────▶│    BlockNotification*      │
     │ MainToMiner::   │                           │───────────────────────────▶│
     │ NewBlock        │                           │                            │
     │◀────────────────│                           │                            │
```

\* `PeerMessage::BlockNotificationWithPowWitness` for peers whose version supports it, `PeerMessage::BlockNotification` otherwise. All messages between the peer task and the peer are `PeerMessage`s.
