use super::super::super::PeerMessage;
use super::strategy_variants::block_notif_req;
use super::utils::block_new;
use super::{strategy_variants, Automaton, SyncStage, Transition};
use crate::config_models::network::Network;
use crate::models::blockchain::block::{block_height::BlockHeight, Block};
use crate::models::peer::peer_block_notifications::PeerBlockNotification;
use crate::models::peer::tests::automaton::reference::AssosiatedData;
use crate::models::peer::{BlockProposalRequest, SyncChallenge};
use proptest::prelude::*;
use proptest::strategy::{Just, Strategy};
use proptest_arbitrary_interop::arb;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;
use tasm_lib::twenty_first::bfe;
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
        /* the book recommends to have these from simple to complex */
        prop_oneof![
            // `BlockNotificationRequest`
            prop_oneof![
                Just(Transition(PeerMessage::BlockNotificationRequest, None)),
                block_notif_req()
            ],
            // `SyncChallengeResponse`
            crate::models::peer::syncchallenge_response_prop_compose_random().prop_map(|r| r.into()),
            // `SyncChallenge`
            {
                let syncchallenge_random_mapped =
                    proptest_arbitrary_interop::arb::<SyncChallenge>().prop_map(|ch| Transition(ch.into(), None)).boxed();
                /* we only have `SyncChallenge::generate` for this, which `assert` 10 blocks difference between the tips */
                let mut syncchallenge_is_generate = None;
                if let Some(SyncStage::WaitingForChallenge(challenge_pre, tip_of_request)) = state.sync_stage.clone() {
                    // let height_cloned = current_tip.header().height.clone();
                    if current_tip.header().height - challenge_pre.height >= 10 {
                        syncchallenge_is_generate = Some((challenge_pre, tip_of_request.header().height));
                    }
                }
                if let Some((challenge_pre, tip_of_request_height)) = syncchallenge_is_generate {
                    prop_oneof![
                        any::<[u8; 32]>().prop_map(move |randomness|
                            Transition(
                                SyncChallenge::generate(
                                    &challenge_pre, tip_of_request_height, randomness
                                ).into(),
                                Some(AssosiatedData::Randomness(/* randomness */))
                            )
                        ),
                        syncchallenge_random_mapped
                    ].boxed()
                } else {syncchallenge_random_mapped}
            },
            /* When you are in sync mode, you are asking for blocks from multiple peers 
            so that you can catch up as quickly as possible. You're not mining either 
            because what's the point. The issue is, what if a peer announces a block that 
            would send your node into sync mode? If they are honest, great! If not, they can 
            trick you into halting your mining operation while you figure out that 
            the announced block is bogus.

            So you can't enter into sync mode just based on the announced block. You first need 
            to verify that there really is a valid chain ending in that announced block. You 
            don't make 100% certain with the sync challenge, but you do make 99% certain. 
            Phrased differently, you're very likely to catch cheaters.

            So in the honest case, this is what happens:
            - you are on what you think is the tip, mining
            - a peer announces a block of a different height and more cumulative proof of work
            - you send them a sync challenge
            - they send a sync challenge response back
            - you validate the sync challenge response, and punish the peer if it does not go through
            - if valid, you enter into sync mode and halt miner and start requesting blocks from all peers that report knowledge of 
            the same tip */
            /* The difference between a block proposal and a block is the nonce, which makes the hash 
            of the block smaller than the target whereas the hash of the block proposal is not. */
            // mostly taken from `sync_challenges`
            prop_oneof![
                (
                    proptest::collection::vec(0..BFieldElement::P, Digest::LEN),
                    0..BFieldElement::P,
                    crate::models::blockchain::block::difficulty_control::propteststrategy::random()
                ).prop_map(|(digest_raw, height_u64, pow)| Transition(PeerMessage::BlockNotification(PeerBlockNotification {
                    hash: Digest(
                        digest_raw.into_iter().map(|limb| tasm_lib::twenty_first::bfe![limb]).collect::<Vec<BFieldElement>>().try_into()
                        .expect("the correct length is insured by the input `Strategy`")
                    ),
                    height: bfe![height_u64].into(),
                    cumulative_proof_of_work: pow
                }), None)),
                block_new(current_tip.clone()).prop_map(
                    |b| Transition(PeerMessage::BlockNotification(PeerBlockNotification::from(&b)), Some(AssosiatedData::NewBlock(b)))
                )
            ],
            /* Works:
            - BlockNotificationRequest
            - Transaction
            - TransactionRequest
            - BlockProposal
            - BlockNotification
            - PeerListRequest
            - Block
            - BlockRequestByHeight
            - TransactionRequest
            Excluded: 
            - `Bye`: nothing to test here and `proptest` doesn't like finite automata
            - Handshake: an existing peer can only punish for a `Handshake` hence it doesn't matter at all what's inside such a `PeerMessage` (TODO add a simplified `Transition` for this)
            - `ConnectionStatus`
            */

            strategy_variants::tx(false),
            strategy_variants::tx(true),

            prop_oneof![
                (0..state.blocks.len()).prop_map(move |i| Transition(
                    PeerMessage::TransactionRequest(blocks_tx_id[i]), None
                )),
                crate::models::state::transaction_kernel_id::propteststrategy::random_tx_kernelid()
                .prop_map(|r| Transition(
                    PeerMessage::TransactionRequest(r), None
                ))
            ],
            prop_oneof![
                super::utils::block_invalid().prop_map(|b| Transition(PeerMessage::BlockProposal(Box::new(b)), None)),
                block_new(current_tip.clone()).prop_map(|b| Transition(PeerMessage::BlockProposal(Box::new(b)), None))
            ],
            Just(Transition(PeerMessage::PeerListRequest, None)),
            // super::strategy_variants::block_response,
            Just(Transition(PeerMessage::BlockRequestByHeight(
                BlockHeight::from(state.blocks.len() as u64)
            ), None)),

            // from Sourcegraph
                // Block strategy
            prop_oneof![
                crate::models::peer::transfer_block::block_transfer_propcompose_random().prop_map(|tb|
                    Transition(PeerMessage::Block(Box::new(tb)), None)
                ),
                // TODO add this into `apply`
                block_new(current_tip.clone()).prop_map(|b| Transition(
                    PeerMessage::Block(Box::new(b.clone().try_into().unwrap())), Some(AssosiatedData::NewBlock(b))
                )),
            ],

            // BlockRequestByHash strategy
            // TODO add the `Just` strategy for genesis (as `blocks_digests[0]`) -- now the peer thread just panics on this, and it's not clear if that's an intended behaviour
            {
                let strategy_random = arb::<Digest>().prop_map(|digest| Transition(PeerMessage::BlockRequestByHash(digest), None));
                let len = state.blocks.len();
                if len > 1 {
                    prop_oneof![
                        strategy_random,
                        (1..len).prop_map(move |i| Transition(
                            PeerMessage::BlockRequestByHash(blocks_digests[i]), None
                        )),
                    ].boxed()
                } else {strategy_random.boxed()}
            },

            // BlockRequestBatch strategy
            // TODO need an example of the MMR part
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

            // BlockProposalRequest strategy
            prop_oneof![
                arb::<Digest>().prop_map(|d|
                    Transition(PeerMessage::BlockProposalRequest(BlockProposalRequest::new(d)), None)
                ),
                block_new(current_tip).prop_map(|b|
                    Transition(PeerMessage::BlockProposalRequest(BlockProposalRequest::new(b.hash())), Some(AssosiatedData::NewBlock(b)))
                )
            ],
        ].boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        match transition {
            Transition(PeerMessage::BlockNotificationRequest, news) => {
                let tip_on_request = state.blocks.last().unwrap().clone();
                if let Some(AssosiatedData::MakeNewBlocks(ts, seed_the)) = news {
                    state.blocks.append(&mut Runtime::new().unwrap().block_on(
                        crate::tests::shared::fake_valid_sequence_of_blocks_for_tests_dyn(
                            state.blocks.last().unwrap(),
                            *ts,
                            *seed_the,
                            11,
                        ),
                    ));
                }
                state.sync_stage = Some(SyncStage::WaitingForChallenge(
                    // a possible problem is a testing system will be responding with another block
                    state.blocks.last().unwrap().into(),
                    tip_on_request,
                ));
            }
            &Transition(PeerMessage::BlockNotification(_), None) => {}
            Transition(PeerMessage::BlockNotification(_), Some(AssosiatedData::NewBlock(new))) => {
                state.blocks.push(new.clone());
                state.sync_stage = Some(SyncStage::WaitingForChallengeResponse);
            }
            &Transition(PeerMessage::SyncChallenge(_), _) => {
                // TODO should we exclude the chance that our node just emited `BlockNotification`? I guees no.
                state.sync_stage = None;
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
