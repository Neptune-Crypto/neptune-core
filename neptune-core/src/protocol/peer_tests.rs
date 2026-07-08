//! Peer-type tests that depend on neptune-core's block-generation test helpers
//! (`fake_valid_sequence_of_blocks_for_tests`).

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use macro_rules_attr::apply;
    use neptune_consensus::block::block_header::BlockHeaderWithBlockHashWitness;
    use neptune_consensus::block::block_header::HeaderToBlockHashWitness;
    use neptune_consensus::block::Block;
    use neptune_p2p::peer::transfer_block::TransferBlock;
    use neptune_p2p::peer::SyncChallengeResponse;
    use neptune_p2p::peer::SYNC_CHALLENGE_POW_WITNESS_LENGTH;
    use neptune_primitives::network::Network;
    use neptune_primitives::timestamp::Timestamp;
    use rand::random;
    use rand::rngs::StdRng;
    use rand::Rng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    use crate::tests::shared::blocks::fake_valid_sequence_of_blocks_for_tests;
    use crate::tests::shared_tokio_runtime;

    #[apply(shared_tokio_runtime)]
    async fn sync_challenge_response_pow_witnesses_must_be_a_chain() {
        let network = Network::Testnet(42);
        let genesis = Block::genesis(network);
        let mut rng = rand::rng();
        let ten_blocks: [Block; SYNC_CHALLENGE_POW_WITNESS_LENGTH] =
            fake_valid_sequence_of_blocks_for_tests(
                &genesis,
                Timestamp::minutes(20),
                rng.random(),
                network,
            )
            .await;

        let to_pow_witness = |block: &Block| {
            BlockHeaderWithBlockHashWitness::new(
                *block.header(),
                HeaderToBlockHashWitness::from(block),
            )
        };

        let mut i = SYNC_CHALLENGE_POW_WITNESS_LENGTH;
        let mut block;
        let mut valid_pow_chain = vec![];
        while valid_pow_chain.len() < SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            i -= 1;
            block = &ten_blocks[i];
            valid_pow_chain.push(to_pow_witness(block));
        }

        let tip = &ten_blocks[SYNC_CHALLENGE_POW_WITNESS_LENGTH - 1];
        let valid_pow_chain: [BlockHeaderWithBlockHashWitness; SYNC_CHALLENGE_POW_WITNESS_LENGTH] =
            valid_pow_chain.try_into().unwrap();
        assert!(SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
            tip.hash(),
            &valid_pow_chain
        ));

        for j in 0..SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let mut invalid_pow_chain = valid_pow_chain.clone();
            invalid_pow_chain[j].header_mut().prev_block_digest = random();
            assert!(!SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
                tip.hash(),
                &invalid_pow_chain
            ));
        }

        for j in 0..SYNC_CHALLENGE_POW_WITNESS_LENGTH {
            let mut invalid_pow_chain = valid_pow_chain.clone();
            invalid_pow_chain[j].header_mut().set_nonce(random());
            assert!(!SyncChallengeResponse::pow_witnesses_form_chain_from_tip(
                tip.hash(),
                &invalid_pow_chain
            ));
        }
    }

    // verify digest is the same after conversion from TransferBlock and back.
    #[apply(shared_tokio_runtime)]
    #[traced_test]
    async fn from_transfer_block() {
        let network = Network::Testnet(42);
        // note: we have to generate a block because TransferBlock::into() will
        // panic if it encounters the genesis block.
        let genesis = Block::genesis(network);
        let [block1] = fake_valid_sequence_of_blocks_for_tests(
            &genesis,
            Timestamp::hours(1),
            StdRng::seed_from_u64(5550001).random(),
            network,
        )
        .await;

        let transfer_block = TransferBlock::try_from(block1.clone()).unwrap();
        let new_block = Block::try_from(transfer_block).unwrap();
        assert_eq!(block1.hash(), new_block.hash());
    }
}
