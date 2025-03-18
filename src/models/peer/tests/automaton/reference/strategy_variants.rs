use proptest::{prelude::any, prop_compose};
use proptest_arbitrary_interop::arb;
use tokio::runtime::Runtime;

use crate::models::{
    blockchain::block::Block, peer::PeerMessage,
    state::wallet::address::generation_address::GenerationSpendingKey,
};

use super::{AssosiatedData, Transition};

prop_compose! {
    pub fn block_notif_req() (
        ts in arb::<crate::models::proof_abstractions::timestamp::Timestamp>(),
        seed_an in any::<[u8; 32]>()
    ) -> Transition {
        Transition(
            PeerMessage::BlockNotificationRequest,
            Some(AssosiatedData::MakeNewBlocks(
                ts, seed_an
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
                tasm_lib::triton_vm::proof::Proof(Vec::new())
            )
        };
        if is_notif {Transition(PeerMessage::TransactionNotification((&tx_instance).try_into().unwrap()), None)}
        else {Transition(PeerMessage::Transaction(Box::new(crate::models::peer::transfer_transaction::TransferTransaction::try_from(&tx_instance).unwrap())), None)}
    }
}

prop_compose! {
    pub fn block_response(current_tip: Block) (
        seed in proptest::array::uniform32(any::<u8>()),
        k in arb::<tasm_lib::prelude::Digest>()
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
            // crate::models::state::wallet::WalletSecret::new_pseudorandom(seed) // #seedReused
            // .nth_generation_spending_key_for_tests(0),
            GenerationSpendingKey::derive_from_seed(k),
            seed
        )).0;
        let content = Box::new(crate::models::peer::transfer_block::TransferBlock::from_random(&the));
        Transition(PeerMessage::Block(content), None)
    }
}
