use crate::{
    api::export::Network,
    models::{
        blockchain::{
            block::{block_header::BlockHeader, Block},
            transaction::primitive_witness::PrimitiveWitness,
        },
        peer::SyncChallenge,
        proof_abstractions::timestamp::Timestamp,
    },
    tests::shared::Randomness,
};
use proptest::prelude::*;
use proptest_arbitrary_interop::arb;
use tasm_lib::{prelude::Digest, twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator};
use tokio::runtime::Runtime;

prop_compose! {
    pub fn blocks_new(predecessor: Block, network: Network) (
        timestamp in arb::<Timestamp>(),
        rness in arb::<[Randomness<2,2>; 10]>()
    ) -> ([Block; 10], [Randomness<2,2>; 10]) {
        (
            Runtime::new().unwrap().block_on(
                crate::tests::shared::fake_valid_sequence_of_blocks_for_tests::<10>(
                    &predecessor, timestamp, rness.clone(), network
                )
            ),
            rness
        )
    }
}

prop_compose! {
    // adaptation of `fake_valid_block_for_tests`
    pub fn block_new(current_tip: Block, network: Network)
    (rness in arb::<Randomness<2,2>>()) -> Block {
        tokio::runtime::Runtime::new().unwrap().block_on(
            crate::tests::shared::fake_valid_successor_for_tests(
                &current_tip,
                current_tip.header().timestamp + crate::models::proof_abstractions::timestamp::Timestamp::hours(1),
                rness,
                network
            )
        )
    }
}

// adaptation of `arbitrary_transaction_is_valid`
prop_compose! {
    pub fn block_invalid() (
        header in arb::<BlockHeader>(),
        // pw in any::<crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness>(),
        size_numbers in (1usize..3, 1usize..3, 0usize..3),
        mutatorsetacc in (arb::<Digest>(), any::<u64>(), arb::<Digest>()),
        // appendix in any::<crate::models::blockchain::block::block_appendix::BlockAppendix>()
    )
    // TODO why can't `pw` be in the first generation pack?
    (header in Just(header), pw in PrimitiveWitness::arbitrary_with_size_numbers(
        Some(size_numbers.0), size_numbers.1, size_numbers.2
    ), mutatorsetacc in Just(mutatorsetacc)) -> Block {
        Block::new(
            header,
            crate::models::blockchain::block::block_body::BlockBody::new(
                pw.into(), // #pw
                crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator::new(
                    &[mutatorsetacc.0], mutatorsetacc.1, &[mutatorsetacc.2],
                    &crate::util_types::mutator_set::active_window::ActiveWindow{sbf: Vec::new()}
                ),
                MmrAccumulator::new_from_leafs(Vec::new()),
                MmrAccumulator::new_from_leafs(Vec::new()),
            ),
            crate::models::blockchain::block::block_appendix::BlockAppendix::new(Vec::new()),
            crate::models::blockchain::block::BlockProof::Invalid
        )
    }
}

prop_compose! {
    pub fn syncchallenge_random() (
        tip_digest in arb::<Digest>(),
        challenges in prop::collection::vec(
            arb::<crate::models::blockchain::block::block_height::BlockHeight>(),
            crate::models::peer::SYNC_CHALLENGE_NUM_BLOCK_PAIRS
        )
    ) -> SyncChallenge {
        SyncChallenge{tip_digest, challenges: challenges.try_into().unwrap()}
    }
}

// Helper functions to generate complex message types
// impl RefAutomaton {
// proptest::prop_compose! {
//     pub fn sync_challenge_happy(state: &mut RefAutomaton, challenge_pre: _)
//     (r in [any::<u8>(); 32]) -> PeerMessage {
//         let output = PeerMessage::SyncChallenge(
//             crate::models::peer::SyncChallenge::generate(
//                 Runtime::new().block_on(crate::tests::shared::fake_valid_sequence_of_blocks_for_tests(
//                     // &genesis_block,
//                     &state.state.blocks[0]
//                     Timestamp::hours(1),
//                     [0u8; 32],
//                 )),
//                 r
//             )
//         );
//         state.sync_state = SyncStage(DoneWithRandomness(r));
//         output
//     }
// }
// }
