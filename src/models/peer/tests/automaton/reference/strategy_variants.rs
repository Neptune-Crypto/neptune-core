use proptest::{prelude::any, prop_compose};
use proptest_arbitrary_interop::arb;
use tasm_lib::{prelude::Digest, triton_vm::prelude::BFieldElement};
use tokio::runtime::Runtime;

use crate::models::{
    blockchain::block::Block, peer::PeerMessage,
    state::wallet::address::generation_address::GenerationSpendingKey,
};

use super::{AssosiatedData, Transition};

prop_compose! {
    pub fn block_notif() (
        hash in arb::<tasm_lib::prelude::Digest>(),
        height_u64 in 0..BFieldElement::P,
        pow in crate::models::blockchain::block::difficulty_control::propteststrategy::random()
    ) -> Transition {
        Transition(
            PeerMessage::BlockNotification(
                crate::models::peer::peer_block_notifications::PeerBlockNotification {
                    hash,
                    height: tasm_lib::twenty_first::bfe![height_u64].into(),
                    cumulative_proof_of_work: pow
                }
            ),
            None
        )
    }
}

prop_compose! {
    pub fn block_notif_req() (
        ts in arb::<crate::models::proof_abstractions::timestamp::Timestamp>(),
        // TODO change for the w itself?
        wallet_seed in any::<[u8; 32]>(),
        coinbase_vec in proptest::collection::vec(arb::<tasm_lib::prelude::Digest>(), crate::models::peer::tests::automaton::BLOCKS_NEW_LEN),
    ) -> Transition {
        Transition(
            PeerMessage::BlockNotificationRequest,
            Some(AssosiatedData::MakeNewBlocks(
                ts, wallet_seed,
                coinbase_vec.try_into().unwrap()
            ))
        )
    }
}

prop_compose! {
    pub fn tx(is_notif: bool) (
        // taken from `arbitrary_transaction_is_valid`
        size_numbers in (1usize..3, 1usize..3, 0usize..3),
    ) (
        pw in crate::models::blockchain::transaction::primitive_witness::
        PrimitiveWitness::arbitrary_with_size_numbers(
            Some(size_numbers.0), size_numbers.1, size_numbers.2
        ) // #pw
    ) -> Transition {
        let tx_instance = crate::models::blockchain::transaction::Transaction{
            kernel: pw.kernel,
            proof: crate::models::blockchain::transaction::TransactionProof::SingleProof(
                // crate::models::blockchain::transaction::TransactionProof::Witness(pw).into_single_proof()
                // tasm_lib::triton_vm::proof::Proof(Vec::new())
                crate::models::blockchain::transaction::validity::single_proof::SingleProof::produce_mock(true)
            )
        };
        if is_notif {Transition(PeerMessage::TransactionNotification((&tx_instance).try_into().unwrap()), None)}
        else {Transition(
            PeerMessage::Transaction(Box::new(crate::models::peer::transfer_transaction::TransferTransaction::try_from(&tx_instance).unwrap())), None
        )}
    }
}

prop_compose! {
    pub fn block_response(current_tip: Block) (
        coinbase_sender_randomness in arb::<Digest>(),
        k in arb::<Digest>(),
        claim in arb::<tasm_lib::triton_vm::proof::Claim>()
    ) -> Transition {
        /* S Kaunov, [11.02.2025 15:06]
        So, there's few PeerMessage variants which seems to be relevant.
        Am I correct that Block is used only with a BlockRequest...? Or is it more ubiquitous? (If so it would be a streamline to rename it to BlockResponse, btw.)

        ...

        Alan Szepieniec, [11.02.2025 16:13]
        BlockResponse seems like a better name. */
        // TODO add a valid block variant here
        let the = Runtime::new().unwrap().block_on(crate::tests::shared::make_mock_block(
            &current_tip,
            None,
            GenerationSpendingKey::derive_from_seed(k),
            coinbase_sender_randomness
        )).0;
        let content = Box::new(crate::models::peer::transfer_block::TransferBlock::from_random(&the, claim));
        Transition(PeerMessage::Block(content), None)
    }
}
