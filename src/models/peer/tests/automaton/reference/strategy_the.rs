use super::super::super::PeerMessage;
use super::utils::{self, block_new};
use super::{strategy_variants, Automaton, SyncStage, Transition};
use crate::config_models::network::Network;
use crate::models::blockchain::block::{block_height::BlockHeight, Block};
use crate::models::peer::peer_block_notifications::PeerBlockNotification;
use crate::models::peer::tests::automaton::reference::AssosiatedData;
use crate::models::peer::{BlockProposalRequest, SyncChallenge};
use crate::models::state::wallet::wallet_entropy::WalletEntropy;
use proptest::prelude::*;
use proptest::strategy::{Just, Strategy};
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;
use tokio::runtime::Runtime;

impl proptest_state_machine::strategy::ReferenceStateMachine for Automaton {
    type State = Self;
    type Transition = Transition;

    fn init_state() -> proptest::prelude::BoxedStrategy<Self::State> {
        use proptest::prelude::*;

        (
            any::<bool>(),
            // any::<u8>()
        )
            .prop_map(
                |(
                    is_inbound,
                    // distance
                )| {
                    Automaton {
                        blocks: [Block::genesis(Network::Main)].to_vec(),
                        // distance,
                        sync_stage: None,
                        is_inbound,
                    }
                },
            )
            .boxed()

        // TODO can it be also initialized with something like a mock genesis archival state? And does that make sense?
    }

    fn transitions(
        state: & /* 'transition */ Self::State,
    ) -> proptest::prelude::BoxedStrategy<Self::Transition> {
        // let rt = Runtime::new().unwrap();
        let blocks_len = state.blocks.len();
        let (blocks_tx_id, blocks_digests) = state
            .blocks
            .iter()
            .map(|b| (b.kernel.body.transaction_kernel.txid(), b.hash()))
            .collect::<(Vec<_>, Vec<_>)>();
        let current_tip = state
            .blocks
            .last()
            .expect("there should be at least genesis")
            .clone();

        /* TODO
        The only way to get a valid `SyncChallengeResponse` @skaunov found is via `response_to_sync_challenge`; which needs `&GlobalState` (and uses the following out of it). In turn,
        `Self::State` is bounded to be `Copy` and lock of the `GlobalState` isn't helpful here since state-machine test interleaves (and shrinks?) `Self::State` so that will become a useless mess.
        Seems like the best option is to refactor the response function out of the `GlobalState`
        method which would also make both better testable and maintainable. #noValidProp #SyncChallengeResponse

        ```rust
        let Some(child_digest) = self
                .chain
                .archival_state()
                .archival_block_mmr
                .ammr()
                .try_get_leaf(child_height.into())
                .await
        ``` */

        /* TODO is it possible to add a check here that the `Strategy` covers all the variants? */
        /* attempted to be sorted from simple to complex as the book recommends */
        let mut the = prop_oneof![
            /* Few variants are excluded from the strateegy.
            - Handshake: an existing peer can only punish for a `Handshake` hence it doesn't matter at all what's inside such a `PeerMessage` (TODO add a simple `Transition` for this)
            - nothing to test and `proptest` doesn't like finite automata
                - `Bye`
                - `ConnectionStatus`
            */
            // `PeerListRequest`
            Just(Transition(PeerMessage::PeerListRequest, None)),
            // `BlockRequestByHeight`
            Just(Transition(
                PeerMessage::BlockRequestByHeight(BlockHeight::from(blocks_len as u64)),
                None
            )),
            // `TransactionRequest`
            prop_oneof![
                (0..blocks_len).prop_map(move |i| Transition(
                    PeerMessage::TransactionRequest(blocks_tx_id[i]),
                    None
                )),
                arb::<crate::models::state::transaction_kernel_id::TransactionKernelId>()
                    .prop_map(|r| Transition(PeerMessage::TransactionRequest(r), None))
            ],
            // `BlockRequestByHash` random. #validChained
            arb::<Digest>()
                .prop_map(|digest| Transition(PeerMessage::BlockRequestByHash(digest), None)),
            // `BlockNotificationRequest`
            prop_oneof![
                Just(Transition(PeerMessage::BlockNotificationRequest, None)),
                strategy_variants::block_notif_req()
            ],
            // `SyncChallengeResponse`
            super::super::super::syncchallenge_response_prop_compose_random()
                .prop_map(|r| r.into()),
            // `SyncChallenge` random (a valid is chained based on the state in the end) #validChained
            proptest_arbitrary_interop::arb::<SyncChallenge>()
                .prop_map(|ch| Transition(ch.into(), None)),
            // `Transaction`
            strategy_variants::tx(false),
            // `TransactionNotification`
            strategy_variants::tx(true),
            // `BlockProposalRequest`
            prop_oneof![
                arb::<Digest>().prop_map(|d| Transition(
                    PeerMessage::BlockProposalRequest(BlockProposalRequest::new(d)),
                    None
                )),
                block_new(current_tip.clone()).prop_map(|b| Transition(
                    PeerMessage::BlockProposalRequest(BlockProposalRequest::new(b.hash())),
                    Some(AssosiatedData::NewBlock(b))
                ))
            ],
            // `Block`
            prop_oneof![
                crate::models::peer::transfer_block::block_transfer_prop_compose_random()
                    .prop_map(|tb| Transition(PeerMessage::Block(Box::new(tb)), None)),
                utils::block_new(current_tip.clone()).prop_map(|b| Transition(
                    PeerMessage::Block(Box::new(b.clone().try_into().unwrap())),
                    Some(AssosiatedData::NewBlock(b))
                )),
            ],
            // `BlockProposal`
            prop_oneof![
                utils::block_invalid()
                    .prop_map(|b| Transition(PeerMessage::BlockProposal(Box::new(b)), None)),
                utils::block_new(current_tip.clone()).prop_map(|b| Transition(
                    PeerMessage::BlockProposal(Box::new(b.clone())),
                    Some(AssosiatedData::NewBlock(b))
                ))
            ],
            // `BlockNotification`
            prop_oneof![
                utils::block_new(current_tip.clone()).prop_map(|b| Transition(
                    PeerMessage::BlockNotification(PeerBlockNotification::from(&b)),
                    Some(AssosiatedData::NewBlock(b))
                )),
                strategy_variants::block_notif()
            ],
            // `BlockRequestBatch`
            // TODO need an example of the MMR part
            //      look into `peer_loop_tests::sync_challenges`
            // (
            //     proptest::collection::vec(arb::<Digest>(), 0..crate::main_loop::MAX_NUM_DIGESTS_IN_BATCH_REQUEST),
            //     1u16..100u16,
            //     arb::<Digest>()
            // ).prop_map(|(known_blocks, max_response_len, anchor)|
            //     Transition(PeerMessage::BlockRequestBatch(
            //         crate::models::peer::BlockRequestBatch {
            //             known_blocks,
            //             max_response_len,
            //             anchor
            //         }
            //     ), None)
            // ),
        ]
        .boxed();
        // `BlockRequestByHash` from `blocks` except genesis
        // TODO add the `Just` strategy for genesis (as `blocks_digests[0]`) -- now the peer thread just panics on this, and it's not clear if that's an intended behaviour
        if blocks_len > 1 {
            the = the
                .prop_union(
                    (1..blocks_len)
                        .prop_map(move |i| {
                            Transition(PeerMessage::BlockRequestByHash(blocks_digests[i]), None)
                        })
                        .boxed(),
                )
                .boxed();
        }
        // `SyncChallenge` from `BlockNotification`
        if let Some(SyncStage::WaitingForChallenge(challenge_pre, tip_of_request)) =
            state.sync_stage.clone()
        {
            // let height_cloned = current_tip.header().height.clone();
            /* we only have `SyncChallenge::generate` for this, which `assert` 10 blocks difference between the tips */
            if current_tip.header().height - challenge_pre.height >= 10 {
                the = the
                    .prop_union(
                        any::<[u8; 32]>()
                            .prop_map(move |randomness| {
                                Transition(
                                    SyncChallenge::generate(
                                        &challenge_pre,
                                        tip_of_request.header().height,
                                        randomness,
                                    )
                                    .into(),
                                    // Some(AssosiatedData::Randomness(randomness)),
                                    Some(AssosiatedData::Valid),
                                )
                            })
                            .boxed(),
                    )
                    .boxed();
            }
        }
        the
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Transition(variant, Some(AssosiatedData::MakeNewBlocks(_ts, seed, digests))) => {
                let tip_at_request = state.blocks.last().unwrap().clone();
                // state.blocks.append(&mut Runtime::new().unwrap().block_on(
                //     crate::tests::shared::fake_valid_sequence_of_blocks_for_tests_dyn(
                //         &tip_at_request,
                //         *ts,
                //         *seed_the,
                //         super::super::BLOCKS_NEW_LEN,
                //     ),
                // ));
                let rt = Runtime::new().unwrap();
                for digest_a in digests {
                    state.blocks.push(
                        rt.block_on(crate::tests::shared::make_mock_block(
                            // previous_block: &Block,
                            state.blocks.last().unwrap(),
                            // block_timestamp: Option<Timestamp>,
                            None,
                            // composer_key: generation_address::GenerationSpendingKey,
                            WalletEntropy::new_pseudorandom(seed.to_owned())
                                .nth_generation_spending_key_for_tests(0),
                            digest_a.to_owned(),
                        ))
                        .0,
                    );
                }
                if &PeerMessage::BlockNotificationRequest == variant {
                    state.sync_stage = Some(SyncStage::WaitingForChallenge(
                        // a possible problem is a testing system will be responding with another block
                        state.blocks.last().unwrap().into(),
                        tip_at_request,
                    ));
                }
            }
            Transition(variant, Some(AssosiatedData::NewBlock(b))) => {
                state.blocks.push(b.clone());
                if let &PeerMessage::BlockNotification(_) = variant {
                    state.sync_stage = Some(SyncStage::WaitingForChallengeResponse);
                }
            }
            Transition(PeerMessage::SyncChallenge(_), Some(AssosiatedData::Valid)) => {
                state.sync_stage =
                    // Some(SyncStage::DoneWithRandomness(randomness.clone()));
                    None;
            }
            // #noValidProp #SyncChallengeResponse
            &Transition(PeerMessage::SyncChallengeResponse(_), _) => {
                // can't get a response without the notif
                if let Some(SyncStage::WaitingForChallengeResponse) = state.sync_stage {
                    state.sync_stage = None;
                    println! {"TODO. @skaunov would remove this leg until #noValidProp #SyncChallengeResponse ; but it's useful for previous messages (like `BlockNotification`). When this will be properly reachable add the block to `blocks`"}
                } else {
                    state.sync_stage = None;
                }
            }
            _ => {} // Other messages don't affect state
        }
        state
    }
}
