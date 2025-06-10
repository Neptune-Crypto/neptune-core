# Weighted Transitions for Peer Automaton Testing

## Problem
The original state automaton for peer testing was generating transitions with equal probability for all message types. This caused frequent peer banning because many message types trigger severe negative sanctions:

- `InvalidSyncChallengeResponse` = -500 points
- `InvalidSyncChallenge` = -50 points  
- `InvalidTransferBlock` = -50 points
- `InvalidBlock` = -10 points
- etc.

With a default peer tolerance of 1000, just 2-3 bad messages could ban a peer, making tests terminate prematurely.

## Solution
Implemented a weighted transition strategy that heavily favors "safe" messages while still including risky messages for comprehensive testing:

### Message Categories and Weights

#### Safe Messages (70% probability)
These messages typically don't cause negative sanctions:
- `PeerListRequest` (weight: 50)
- `BlockRequestByHeight` with valid height (weight: 40)
- `TransactionRequest` with valid tx id (weight: 40)
- `BlockNotificationRequest` without new blocks (weight: 30)
- Valid `BlockNotification` with new block (weight: 25)
- Valid `Block` with new block (weight: 25)
- Valid `BlockProposal` with new block (weight: 20)
- `BlockProposalRequest` with valid hash (weight: 15)

#### Moderate Messages (20% probability)
These might cause minor sanctions but are generally safe:
- `TransactionRequest` with random id (weight: 10)
- `BlockRequestByHash` with known hash (weight: 8)
- `BlockProposalRequest` with random hash (weight: 5)
- `BlockNotificationRequest` with new blocks (weight: 5)

#### Risky Messages (8% probability)
These are likely to cause sanctions but needed for testing:
- Random `BlockRequestByHash` (weight: 3)
- Random `BlockNotification` (weight: 3)
- Valid transactions (weight: 2 each)
- Random transfer blocks (weight: 2)
- Invalid blocks (weight: 1)

#### Very Risky Messages (2% probability)
These will likely cause severe sanctions:
- Random `SyncChallenge` (weight: 1) - can cause -50 points
- Random `SyncChallengeResponse` (weight: 1) - can cause -500 points

## Additional Changes

### Extended Test Sequence Length
- Increased from `1..20` to `1..50` transitions per test
- Allows for longer test runs to better exercise the system
- With weighted transitions, tests should now run longer before peer banning

### Conditional Logic
- Added proper handling for cases where `blocks_len <= 1`
- Ensures strategies work correctly even with minimal blockchain state

## Expected Benefits

1. **Reduced Peer Banning**: 90% of messages are now safe or moderately safe
2. **Longer Test Runs**: Tests can exercise more transitions before termination
3. **Better Coverage**: Still includes all message types but in realistic proportions
4. **More Realistic Testing**: Mimics real-world scenarios where most messages are valid

## Technical Implementation

The implementation uses Rust's `proptest` library with weighted `prop_oneof!` macros:

```rust
let mut the = prop_oneof![
    70 => safe_messages,      // 70% chance of safe messages
    20 => moderate_messages,  // 20% chance of moderate messages  
    8 => risky_messages,      // 8% chance of risky messages
    2 => very_risky_messages, // 2% chance of very risky messages
].boxed();
```

This approach maintains comprehensive test coverage while dramatically reducing the likelihood of premature test termination due to peer banning.