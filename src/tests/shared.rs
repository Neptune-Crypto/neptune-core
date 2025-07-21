use std::fmt::Debug;
use std::pin::Pin;

use anyhow::Result;
use bytes::Bytes;
use bytes::BytesMut;
use files::unit_test_data_directory;
use futures::sink;
use futures::stream;
use futures::task::Context;
use futures::task::Poll;
use mock_tx::fake_create_transaction_from_details_for_tests;
use num_traits::Zero;
use pin_project_lite::pin_project;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::Serializer;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;
use tracing::warn;

use crate::api::export::TransactionDetails;
use crate::api::export::TxOutputList;
use crate::config_models::network::Network;
use crate::database::storage::storage_vec::traits::StorageVecBase;
use crate::mine_loop::composer_parameters::ComposerParameters;
use crate::mine_loop::prepare_coinbase_transaction_stateless;
use crate::models::blockchain::block::block_transaction::BlockOrRegularTransaction;
use crate::models::blockchain::block::block_transaction::BlockTransaction;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::consensus_rule_set::ConsensusRuleSet;
use crate::models::blockchain::transaction::lock_script::LockScript;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::type_scripts::native_currency_amount::NativeCurrencyAmount;
use crate::models::peer::PeerMessage;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::util_types::mutator_set::addition_record::AdditionRecord;

pub mod archival;
pub mod blocks;
pub mod files;
pub mod globalstate;
pub mod mock_tx;
pub mod randomness_impl;
pub mod strategies;

/// Ubiquitous container holding any combination of randomness used in the test helpers; implements both
/// random and `proptest` generation. Useful when helper needs few random values and a call to it becomes
/// cluttered.
#[derive(arbitrary::Arbitrary, Debug, Clone, PartialEq, Eq)]
pub struct Randomness<const BA: usize, const D: usize> {
    pub bytes_arr: [[u8; 32]; BA],
    pub digests: [Digest; D],
}

pub(crate) fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formatting = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    transport.encode(Pin::new(&mut formatting).serialize(message)?, &mut buf)?;
    Ok(buf.freeze())
}

// Box<Vec<T>> is unnecessary because Vec<T> is already heap-allocated.
// However, Box<...> is used here because Pin<T> does not allow a &mut T,
// So a Box<T> (which also implements DerefMut) allows a pinned, mutable
// pointer.
type ActionList<Item> = Box<Vec<Action<Item>>>;

pin_project! {
#[derive(Debug)]
pub struct Mock<Item> {
    #[pin]
    actions: ActionList<Item>,
}
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MockError {
    WrongSend,
    UnexpectedSend,
    UnexpectedRead,
    ReadError,
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MockError::WrongSend => write!(f, "WrongSend"),
            MockError::UnexpectedSend => write!(f, "UnexpectedSend"),
            MockError::UnexpectedRead => write!(f, "UnexpectedRead"),
            MockError::ReadError => write!(f, "ReadError"),
        }
    }
}

impl std::error::Error for MockError {}

#[derive(Debug, Clone)]
pub enum Action<Item> {
    Read(Item),
    Write(Item),

    /// Simulates an error when reading the peer's message. Consider adding an
    /// error type here to better simulate e.g. a deserialization error.
    ReadError,
    // Todo: Some tests with these things
    // Wait(Duration),
    // ReadError(Option<Arc<io::Error>>),
    // WriteError(Option<Arc<io::Error>>),
}

impl<Item> Mock<Item> {
    pub fn new(actions: Vec<Action<Item>>) -> Mock<Item> {
        Mock {
            actions: Box::new(actions.into_iter().rev().collect()),
        }
    }
}

impl<Item: PartialEq> sink::Sink<Item> for Mock<Item> {
    type Error = MockError;

    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        match (self.actions.pop(), item) {
            (Some(Action::Write(a)), item) if item == a => Ok(()),
            (Some(Action::Write(_)), _) => Err(MockError::WrongSend),
            _ => Err(MockError::UnexpectedSend),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<Item> stream::Stream for Mock<Item> {
    type Item = Result<Item, MockError>;

    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.actions.pop() {
            Some(Action::Read(a)) => Poll::Ready(Some(Ok(a))),
            Some(Action::ReadError) => Poll::Ready(Some(Err(MockError::ReadError))),
            // Returning `Poll::Ready(None)` here would probably simulate better
            // a peer closing the connection. Otherwise, we have to close with a
            // `Bye` in all tests.
            _ => Poll::Ready(Some(Err(MockError::UnexpectedRead))),
        }
    }
}

pub(crate) fn dummy_expected_utxo() -> ExpectedUtxo {
    ExpectedUtxo {
        utxo: Utxo::new_native_currency(
            LockScript::anyone_can_spend().hash(),
            NativeCurrencyAmount::zero(),
        ),
        addition_record: AdditionRecord::new(Default::default()),
        sender_randomness: Default::default(),
        receiver_preimage: Default::default(),
        received_from: UtxoNotifier::Myself,
        notification_received: Timestamp::now(),
        mined_in_block: None,
    }
}

pub(crate) async fn mock_genesis_wallet_state(
    wallet_entropy: crate::models::state::wallet::wallet_entropy::WalletEntropy,
    cli_args: &crate::config_models::cli_args::Args,
) -> WalletState {
    let data_dir = unit_test_data_directory(cli_args.network).unwrap();
    WalletState::new_from_wallet_entropy(&data_dir, wallet_entropy, cli_args).await
}

/// Create a block-transaction with a bogus proof but such that `verify` passes.
pub(crate) async fn fake_create_block_transaction_for_tests(
    predecessor_block: &Block,
    composer_parameters: ComposerParameters,
    timestamp: Timestamp,
    shuffle_seed: [u8; 32],
    mut selected_mempool_txs: Vec<Transaction>,
    network: Network,
) -> Result<(BlockTransaction, TxOutputList)> {
    let (composer_txos, transaction_details) = prepare_coinbase_transaction_stateless(
        predecessor_block,
        composer_parameters,
        timestamp,
        network,
    );

    let block_height = predecessor_block.header().height;
    let consensus_rule_set = ConsensusRuleSet::infer_from(network, block_height.next());
    let coinbase_transaction =
        fake_create_transaction_from_details_for_tests(transaction_details, consensus_rule_set)
            .await;

    if selected_mempool_txs.is_empty() {
        // create the nop-tx and merge into the coinbase transaction to set the
        // merge bit to allow the tx to be included in a block.
        let nop_details = TransactionDetails::nop(
            predecessor_block.mutator_set_accumulator_after().unwrap(),
            timestamp,
            network,
        );
        let nop_transaction =
            fake_create_transaction_from_details_for_tests(nop_details, consensus_rule_set).await;

        selected_mempool_txs = vec![nop_transaction];
    }

    let mut block_transaction = BlockOrRegularTransaction::from(coinbase_transaction);
    for tx_to_include in selected_mempool_txs {
        block_transaction = mock_tx::fake_merge_block_transactions_for_tests(
            block_transaction,
            tx_to_include,
            shuffle_seed,
            consensus_rule_set,
        )
        .await
        .expect("Must be able to merge transactions in mining context")
        .into();
    }

    let block_transaction = BlockTransaction::try_from(block_transaction)
        .expect("we always merge at least once, with noptx if need be");

    Ok((block_transaction, composer_txos))
}

pub(crate) async fn wallet_state_has_all_valid_mps(
    wallet_state: &WalletState,
    tip_block: &Block,
) -> bool {
    let monitored_utxos = wallet_state.wallet_db.monitored_utxos();
    for monitored_utxo in &monitored_utxos.get_all().await {
        let current_mp = monitored_utxo.get_membership_proof_for_block(tip_block.hash());

        match current_mp {
            Some(mp) => {
                if !tip_block
                    .mutator_set_accumulator_after()
                    .unwrap()
                    .verify(Tip5::hash(&monitored_utxo.utxo), &mp)
                {
                    warn!("Invalid MSMP");
                    return false;
                }
            }
            None => {
                warn!("No MSMP");
                return false;
            }
        }
    }

    true
}

/// Waits for an async predicate to return true or a timeout.
///
/// # Arguments
///
/// * `predicate`: `async || -> bool` closure to evaluate.
/// * `timeout_secs`: Max seconds to wait (floating-point).
///
/// # Returns
///
/// `Ok(())` on success, `Err(_)` on timeout.
///
/// # Example
///
/// ```
/// async fn is_ready() -> bool { true }
///
/// #[tokio::main]
/// async fn main() -> Result<()> {
///     wait_until(async || is_ready().await, 1.5).await?;
///     Ok(())
/// }
/// ```
pub async fn wait_until<F, Fut>(
    timeout: std::time::Duration,
    mut predicate: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = bool> + Send + 'static,
{
    let start = std::time::Instant::now();
    loop {
        if predicate().await {
            break;
        }
        if start.elapsed() > timeout {
            anyhow::bail!(
                "timeout reached after {} seconds",
                start.elapsed().as_secs_f32()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}
