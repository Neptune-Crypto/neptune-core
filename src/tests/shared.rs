use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;
use std::time::SystemTime;

use anyhow::Result;
use bytes::Bytes;
use bytes::BytesMut;
use bytesize::ByteSize;
use futures::sink;
use futures::stream;
use futures::task::Context;
use futures::task::Poll;
use itertools::Itertools;
use num_traits::Zero;
use pin_project_lite::pin_project;
use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use rand::random;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_serde::formats::SymmetricalBincode;
use tokio_serde::Serializer;
use tokio_util::codec::Encoder;
use tokio_util::codec::LengthDelimitedCodec;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::digest::Digest;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;
use twenty_first::util_types::mmr::mmr_trait::Mmr;

use crate::config_models::cli_args;
use crate::config_models::data_directory::DataDirectory;
use crate::config_models::network::Network;
use crate::database::NeptuneLevelDb;
use crate::models::blockchain::block::block_body::BlockBody;
use crate::models::blockchain::block::block_header::BlockHeader;
use crate::models::blockchain::block::block_header::TARGET_BLOCK_INTERVAL;
use crate::models::blockchain::block::block_height::BlockHeight;
use crate::models::blockchain::block::Block;
use crate::models::blockchain::transaction;
use crate::models::blockchain::transaction::primitive_witness::PrimitiveWitness;
use crate::models::blockchain::transaction::primitive_witness::SaltedUtxos;
use crate::models::blockchain::transaction::transaction_kernel::pseudorandom_option;
use crate::models::blockchain::transaction::transaction_kernel::pseudorandom_public_announcement;
use crate::models::blockchain::transaction::transaction_kernel::pseudorandom_transaction_kernel;
use crate::models::blockchain::transaction::transaction_kernel::TransactionKernel;
use crate::models::blockchain::transaction::utxo::Utxo;
use crate::models::blockchain::transaction::validity::removal_records_integrity::RemovalRecordsIntegrityWitness;
use crate::models::blockchain::transaction::validity::TransactionValidationLogic;
use crate::models::blockchain::transaction::PublicAnnouncement;
use crate::models::blockchain::transaction::Transaction;
use crate::models::blockchain::transaction::TxInputList;
use crate::models::blockchain::transaction::TxOutputList;
use crate::models::blockchain::type_scripts::neptune_coins::pseudorandom_amount;
use crate::models::blockchain::type_scripts::neptune_coins::NeptuneCoins;
use crate::models::blockchain::type_scripts::TypeScript;
use crate::models::channel::MainToPeerTask;
use crate::models::channel::PeerTaskToMain;
use crate::models::consensus::timestamp::Timestamp;
use crate::models::consensus::ValidityTree;
use crate::models::database::BlockIndexKey;
use crate::models::database::BlockIndexValue;
use crate::models::database::PeerDatabases;
use crate::models::peer::HandshakeData;
use crate::models::peer::PeerInfo;
use crate::models::peer::PeerMessage;
use crate::models::peer::PeerStanding;
use crate::models::state::archival_state::ArchivalState;
use crate::models::state::blockchain_state::BlockchainState;
use crate::models::state::light_state::LightState;
use crate::models::state::mempool::Mempool;
use crate::models::state::networking_state::NetworkingState;
use crate::models::state::wallet::address::generation_address;
use crate::models::state::wallet::wallet_state::WalletState;
use crate::models::state::wallet::WalletSecret;
use crate::models::state::GlobalStateLock;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::pseudorandom_addition_record;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::chunk_dictionary::pseudorandom_chunk_dictionary;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::get_swbf_indices;
use crate::util_types::mutator_set::ms_membership_proof::pseudorandom_mutator_set_membership_proof;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::removal_record::AbsoluteIndexSet;
use crate::util_types::mutator_set::removal_record::RemovalRecord;
use crate::util_types::test_shared::mutator_set::pseudorandom_mmra;
use crate::util_types::test_shared::mutator_set::pseudorandom_mmra_with_mps;
use crate::Hash;
use crate::PEER_CHANNEL_CAPACITY;

/// Return an empty peer map
pub fn get_peer_map() -> HashMap<SocketAddr, PeerInfo> {
    HashMap::new()
}

// Return empty database objects, and root directory for this unit test instantiation's
/// data directory.
#[allow(clippy::type_complexity)]
pub async fn unit_test_databases(
    network: Network,
) -> Result<(
    NeptuneLevelDb<BlockIndexKey, BlockIndexValue>,
    PeerDatabases,
    DataDirectory,
)> {
    let data_dir: DataDirectory = unit_test_data_directory(network)?;

    // The returned future is not `Send` without block_on().
    use futures::executor::block_on;
    let block_db = block_on(ArchivalState::initialize_block_index_database(&data_dir))?;
    let peer_db = block_on(NetworkingState::initialize_peer_databases(&data_dir))?;

    Ok((block_db, peer_db, data_dir))
}

pub fn get_dummy_socket_address(count: u8) -> SocketAddr {
    std::net::SocketAddr::from_str(&format!("127.0.0.{}:8080", count)).unwrap()
}

pub fn get_dummy_peer(address: SocketAddr) -> PeerInfo {
    PeerInfo {
        connected_address: address,
        inbound: false,
        instance_id: rand::random(),
        last_seen: SystemTime::now(),
        standing: PeerStanding::default(),
        version: get_dummy_version(),
        port_for_incoming_connections: Some(8080),
        is_archival_node: true,
    }
}

pub fn get_dummy_version() -> String {
    "0.1.0".to_string()
}

/// Return a handshake object with a randomly set instance ID
pub async fn get_dummy_handshake_data_for_genesis(network: Network) -> HandshakeData {
    HandshakeData {
        instance_id: rand::random(),
        tip_header: Block::genesis_block(network).header().to_owned(),
        listen_port: Some(8080),
        network,
        version: get_dummy_version(),
        is_archival_node: true,
    }
}

pub fn to_bytes(message: &PeerMessage) -> Result<Bytes> {
    let mut transport = LengthDelimitedCodec::new();
    let mut formating = SymmetricalBincode::<PeerMessage>::default();
    let mut buf = BytesMut::new();
    transport.encode(Pin::new(&mut formating).serialize(message)?, &mut buf)?;
    Ok(buf.freeze())
}

pub async fn get_dummy_peer_connection_data_genesis(
    network: Network,
    id: u8,
) -> (HandshakeData, SocketAddr) {
    let handshake = get_dummy_handshake_data_for_genesis(network).await;
    let socket_address = get_dummy_socket_address(id);

    (handshake, socket_address)
}

/// Get a global state object for unit test purposes. This global state
/// populated with state from the genesis block, e.g. in the archival mutator
/// set and the wallet.
pub async fn mock_genesis_global_state(
    network: Network,
    peer_count: u8,
    wallet: WalletSecret,
) -> GlobalStateLock {
    let (archival_state, peer_db, _data_dir) = mock_genesis_archival_state(network).await;

    let syncing = false;
    let mut peer_map: HashMap<SocketAddr, PeerInfo> = get_peer_map();
    for i in 0..peer_count {
        let peer_address =
            std::net::SocketAddr::from_str(&format!("123.123.123.{}:8080", i)).unwrap();
        peer_map.insert(peer_address, get_dummy_peer(peer_address));
    }
    let networking_state = NetworkingState::new(peer_map, peer_db, syncing);
    let genesis_block = archival_state.tip();

    // Sanity check
    assert_eq!(archival_state.genesis_block().hash(), genesis_block.hash());

    let light_state: LightState = LightState::from(genesis_block.to_owned());
    println!(
        "Genesis light state MSA hash: {}",
        light_state.body().mutator_set_accumulator.hash()
    );
    let mempool = Mempool::new(ByteSize::gb(1), genesis_block.hash());
    let blockchain_state = BlockchainState::Archival(archival_state);
    let cli_args = cli_args::Args {
        network,
        ..Default::default()
    };

    let wallet_state = mock_genesis_wallet_state(wallet, network).await;

    GlobalStateLock::new(
        wallet_state,
        blockchain_state,
        networking_state,
        cli_args.clone(),
        mempool,
        cli_args.mine,
    )
}

/// Return a setup with empty databases, and with the genesis block in the
/// block header field of the state.
/// Returns:
/// (peer_broadcast_channel, from_main_receiver, to_main_transmitter, to_main_receiver, global state, peer's handshake data)
#[allow(clippy::type_complexity)]
pub async fn get_test_genesis_setup(
    network: Network,
    peer_count: u8,
) -> Result<(
    broadcast::Sender<MainToPeerTask>,
    broadcast::Receiver<MainToPeerTask>,
    mpsc::Sender<PeerTaskToMain>,
    mpsc::Receiver<PeerTaskToMain>,
    GlobalStateLock,
    HandshakeData,
)> {
    let (peer_broadcast_tx, mut _from_main_rx1) =
        broadcast::channel::<MainToPeerTask>(PEER_CHANNEL_CAPACITY);
    let (to_main_tx, mut _to_main_rx1) = mpsc::channel::<PeerTaskToMain>(PEER_CHANNEL_CAPACITY);
    let from_main_rx_clone = peer_broadcast_tx.subscribe();

    let devnet_wallet = WalletSecret::devnet_wallet();
    let state = mock_genesis_global_state(network, peer_count, devnet_wallet).await;
    Ok((
        peer_broadcast_tx,
        from_main_rx_clone,
        to_main_tx,
        _to_main_rx1,
        state,
        get_dummy_handshake_data_for_genesis(network).await,
    ))
}

pub async fn add_block_to_light_state(
    light_state: &mut LightState,
    new_block: Block,
) -> Result<()> {
    let previous_pow_family = light_state.kernel.header.proof_of_work_family;
    if previous_pow_family < new_block.kernel.header.proof_of_work_family {
        light_state.set_block(new_block);
    } else if new_block == *light_state {
        // no-op. light-state already has the block.
    } else {
        panic!("Attempted to add to light state an older block than the current light state block");
    }

    Ok(())
}

pub async fn add_block_to_archival_state(
    archival_state: &mut ArchivalState,
    new_block: Block,
) -> Result<()> {
    archival_state.write_block_as_tip(&new_block).await?;

    archival_state.update_mutator_set(&new_block).await.unwrap();

    Ok(())
}

/// Create a randomly named `DataDirectory` so filesystem-bound tests can run
/// in parallel. If this is not done, parallel execution of unit tests will
/// fail as they each hold a lock on the database.
///
/// For now we use databases on disk. In-memory databases would be nicer.
pub fn unit_test_data_directory(network: Network) -> Result<DataDirectory> {
    let mut rng = rand::thread_rng();
    let tmp_root: PathBuf = env::temp_dir()
        .join("neptune-unit-tests")
        .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

    DataDirectory::get(Some(tmp_root), network)
}

// Box<Vec<T>> is unnecessary because Vec<T> is already heap-allocated.
// However, Box<...> is used here because Pin<T> does not allow a &mut T,
// So a Box<T> (which also implements DerefMut) allows a pinned, mutable
// pointer.
//
// We suppress `clippy::box-collection` on a type alias because the can't
// easily place the pragma inside the `pin_project!` macro.
#[allow(clippy::box_collection)]
type ActionList<Item> = Box<Vec<Action<Item>>>;

pin_project! {
#[derive(Debug)]
pub struct Mock<Item> {
    #[pin]
    actions: ActionList<Item>,
}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockError {
    WrongSend,
    UnexpectedSend,
    UnexpectedRead,
}

impl std::fmt::Display for MockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MockError::WrongSend => write!(f, "WrongSend"),
            MockError::UnexpectedSend => write!(f, "UnexpectedSend"),
            MockError::UnexpectedRead => write!(f, "UnexpectedRead"),
        }
    }
}

impl std::error::Error for MockError {}

#[derive(Debug, Clone)]
pub enum Action<Item> {
    Read(Item),
    Write(Item),
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
        if let Some(Action::Read(a)) = self.actions.pop() {
            Poll::Ready(Some(Ok(a)))
        } else {
            // Returning `Poll::Ready(None)` here would probably simulate better
            // a peer closing the connection. Otherwise we have to close with a
            // `Bye` in all tests.
            Poll::Ready(Some(Err(MockError::UnexpectedRead)))
        }
    }
}

pub fn pseudorandom_utxo(seed: [u8; 32]) -> Utxo {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    Utxo {
        lock_script_hash: rng.gen(),
        coins: NeptuneCoins::new(rng.gen_range(0..42000000)).to_native_coins(),
    }
}

pub fn pseudorandom_removal_record_integrity_witness(
    seed: [u8; 32],
) -> RemovalRecordsIntegrityWitness {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let num_inputs = 2;
    let num_outputs = 2;
    let num_public_announcements = 1;

    let input_utxos = (0..num_inputs)
        .map(|_| pseudorandom_utxo(rng.gen::<[u8; 32]>()))
        .collect_vec();
    let mut membership_proofs = (0..num_inputs)
        .map(|_| pseudorandom_mutator_set_membership_proof(rng.gen::<[u8; 32]>()))
        .collect_vec();
    let addition_records = input_utxos
        .iter()
        .zip(membership_proofs.iter())
        .map(|(utxo, msmp)| {
            commit(
                Hash::hash(utxo),
                msmp.sender_randomness,
                msmp.receiver_preimage.hash::<Hash>(),
            )
        })
        .collect_vec();
    let canonical_commitments = addition_records
        .iter()
        .map(|ar| ar.canonical_commitment)
        .collect_vec();
    let (aocl, mmr_mps) = pseudorandom_mmra_with_mps(rng.gen::<[u8; 32]>(), &canonical_commitments);
    assert_eq!(num_inputs, mmr_mps.len());
    assert_eq!(num_inputs, canonical_commitments.len());

    for (mp, &cc) in mmr_mps.iter().zip_eq(canonical_commitments.iter()) {
        assert!(
            mp.verify(&aocl.get_peaks(), cc, aocl.count_leaves()),
            "Returned MPs must be valid for returned AOCL"
        );
    }

    for (ms_mp, mmr_mp) in membership_proofs.iter_mut().zip(mmr_mps.iter()) {
        ms_mp.auth_path_aocl = mmr_mp.clone();
    }
    let swbfi = pseudorandom_mmra(rng.gen::<[u8; 32]>());
    let swbfa_hash: Digest = rng.gen();
    let mut kernel = pseudorandom_transaction_kernel(
        rng.gen(),
        num_inputs,
        num_outputs,
        num_public_announcements,
    );
    kernel.mutator_set_hash = Hash::hash_pair(
        Hash::hash_pair(aocl.bag_peaks(), swbfi.bag_peaks()),
        Hash::hash_pair(swbfa_hash, Digest::default()),
    );
    kernel.inputs = input_utxos
        .iter()
        .zip(membership_proofs.iter())
        .map(|(utxo, msmp)| {
            (
                Hash::hash(utxo),
                msmp.sender_randomness,
                msmp.receiver_preimage,
                msmp.auth_path_aocl.leaf_index,
            )
        })
        .map(|(item, sr, rp, li)| get_swbf_indices(item, sr, rp, li))
        .map(|ais| RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new(&ais),
            target_chunks: pseudorandom_chunk_dictionary(rng.gen()),
        })
        .rev()
        .collect_vec();

    let mut kernel_index_set_hashes = kernel
        .inputs
        .iter()
        .map(|rr| Hash::hash(&rr.absolute_indices))
        .collect_vec();
    kernel_index_set_hashes.sort();

    RemovalRecordsIntegrityWitness {
        input_utxos,
        membership_proofs,
        aocl,
        swbfi,
        swbfa_hash,
        kernel,
    }
}

pub fn random_transaction_kernel() -> TransactionKernel {
    let mut rng = thread_rng();
    let num_inputs = 1 + (rng.next_u32() % 5) as usize;
    let num_outputs = 1 + (rng.next_u32() % 6) as usize;
    let num_public_announcements = (rng.next_u32() % 5) as usize;
    pseudorandom_transaction_kernel(rng.gen(), num_inputs, num_outputs, num_public_announcements)
}

pub fn random_addition_record() -> AdditionRecord {
    let mut rng = thread_rng();
    pseudorandom_addition_record(rng.gen::<[u8; 32]>())
}

pub fn random_public_announcement() -> PublicAnnouncement {
    let mut rng = thread_rng();
    pseudorandom_public_announcement(rng.gen::<[u8; 32]>())
}

pub fn random_amount() -> NeptuneCoins {
    let mut rng = thread_rng();
    pseudorandom_amount(rng.gen::<[u8; 32]>())
}

pub fn random_option<T>(thing: T) -> Option<T> {
    let mut rng = thread_rng();
    pseudorandom_option(rng.gen::<[u8; 32]>(), thing)
}

// pub fn add_output_to_block(block: &mut Block, utxo: Utxo) {
//     let tx = &mut block.body.transaction;
//     let output_randomness: Digest = Digest::new(random_elements_array());
//     let addition_record: AdditionRecord = block
//         .body
//         .previous_mutator_set_accumulator
//         .commit(&Hash::hash(&utxo), &output_randomness);
//     tx.outputs.push((utxo, output_randomness));

//     // Add addition record for this output
//     block
//         .body
//         .mutator_set_update
//         .additions
//         .push(addition_record);
//     let mut next_mutator_set_accumulator = block.body.previous_mutator_set_accumulator.clone();
//     block
//         .body
//         .mutator_set_update
//         .apply(&mut next_mutator_set_accumulator)
//         .expect("MS update application must work");
//     block.body.next_mutator_set_accumulator = next_mutator_set_accumulator;

//     // update header fields
//     block.header.mutator_set_hash = block.body.next_mutator_set_accumulator.hash();
//     block.header.block_body_merkle_root = Hash::hash(&block.body);
// }

/// Add an unsigned (incorrectly signed) devnet input to a transaction
/// Membership proofs and removal records must be valid against `previous_mutator_set_accumulator`,
/// not against `next_mutator_set_accumulator`.
// pub fn add_unsigned_dev_net_input_to_block_transaction(
//     block: &mut Block,
//     input_utxo: Utxo,
//     membership_proof: MsMembershipProof<Hash>,
//     removal_record: RemovalRecord<Hash>,
// ) {
//     let mut tx = block.body.transaction.clone();
//     let new_devnet_input = DevNetInput {
//         utxo: input_utxo,
//         membership_proof: membership_proof.into(),
//         removal_record: removal_record.clone(),
//         // We're just using a dummy signature here to type-check. The caller should apply a correct signature to the transaction
//         signature: Some(ecdsa::Signature::from_str("3044022012048b6ac38277642e24e012267cf91c22326c3b447d6b4056698f7c298fb36202201139039bb4090a7cfb63c57ecc60d0ec8b7483bf0461a468743022759dc50124").unwrap()),
//     };
//     tx.kernel.inputs.push(new_devnet_input);
//     block.body.transaction = tx;

//     // add removal record for this spending
//     block.body.mutator_set_update.removals.push(removal_record);

//     // Update block mutator set accumulator. We have to apply *all* elements in the `mutator_set_update`
//     // to the previous mutator set accumulator here, as the removal records need to be updated throughout
//     // this process. This means that the input membership proof and removal records are expected to be
//     // valid against `block.body.previous_mutator_set_accumulator`, not against
//     // `block.body.next_mutator_set_accumulator`
//     let mut next_mutator_set_accumulator = block.body.previous_mutator_set_accumulator.clone();
//     block
//         .body
//         .mutator_set_update
//         .apply(&mut next_mutator_set_accumulator)
//         .expect("MS update application must work");
//     block.body.next_mutator_set_accumulator = next_mutator_set_accumulator;

//     // update header fields
//     block.header.mutator_set_hash = block.body.next_mutator_set_accumulator.hash();
//     block.header.block_body_merkle_root = Hash::hash(&block.body);
// }

// pub fn add_unsigned_input_to_block(
//     block: &mut Block,
//     consumed_utxo: Utxo,
//     membership_proof: MsMembershipProof<Hash>,
// ) {
//     let item = Hash::hash(&consumed_utxo);
//     let input_removal_record = block
//         .body
//         .previous_mutator_set_accumulator
//         .drop(item, membership_proof);
//     add_unsigned_dev_net_input_to_block_transaction(
//         block,
//         consumed_utxo,
//         membership_proof,
//         input_removal_record,
//     );
// }

/// Helper function to add an unsigned input to a block's transaction
// pub async fn add_unsigned_input_to_block_ams(
//     block: &mut Block,
//     consumed_utxo: Utxo,
//     randomness: Digest,
//     ams: &Arc<tokio::sync::Mutex<RustyArchivalMutatorSet<Hash>>>,
//     aocl_leaf_index: u64,
// ) {
//     let item = Hash::hash(&consumed_utxo);
//     let input_membership_proof = ams
//         .lock()
//         .await
//         .ams
//         .restore_membership_proof(&item, &randomness, aocl_leaf_index)
//         .unwrap();

//     // Sanity check that restored membership proof agrees with AMS
//     assert!(
//         ams.lock().await.ams().verify(item, &input_membership_proof),
//         "Restored MS membership proof must validate against own AMS"
//     );

//     // Sanity check that restored membership proof agree with block
//     assert!(
//         block
//             .body
//             .previous_mutator_set_accumulator
//             .verify(item, &input_membership_proof),
//         "Restored MS membership proof must validate against input block"
//     );

//     let input_removal_record = ams
//         .lock()
//         .await
//         .ams
//         .kernel
//         .drop(item, &input_membership_proof);
//     add_unsigned_dev_net_input_to_block_transaction(
//         block,
//         consumed_utxo,
//         input_membership_proof,
//         input_removal_record,
//     );
// }

// /// Create a mock `DevNetInput`
// ///
// /// This mock currently contains a lot of things that don't pass block validation.
// pub fn make_mock_unsigned_devnet_input(amount: Amount, wallet: &WalletSecret) -> DevNetInput {
//     let mut rng = thread_rng();
//     let mock_mmr_membership_proof = MmrMembershipProof::new(0, vec![]);
//     let sender_randomness: Digest = rng.gen();
//     let receiver_preimage: Digest = rng.gen();
//     let mock_ms_membership_proof = MsMembershipProof {
//         sender_randomness,
//         receiver_preimage,
//         auth_path_aocl: mock_mmr_membership_proof,
//         target_chunks: ChunkDictionary::default(),
//     };
//     let mut mock_ms_acc = MutatorSetAccumulator::default();
//     let mock_removal_record = mock_ms_acc.drop(sender_randomness, &mock_ms_membership_proof);

//     let utxo = Utxo {
//         amount,
//         public_key: wallet.get_public_key(),
//     };

//     DevNetInput {
//         utxo,
//         membership_proof: mock_ms_membership_proof.into(),
//         removal_record: mock_removal_record,
//         // We're just using a dummy signature here to type-check. The caller should apply a correct signature to the transaction
//         signature: Some(ecdsa::Signature::from_str("3044022012048b6ac38277642e24e012267cf91c22326c3b447d6b4056698f7c298fb36202201139039bb4090a7cfb63c57ecc60d0ec8b7483bf0461a468743022759dc50124").unwrap()),
//     }
// }

// pub fn make_mock_signed_valid_tx() -> Transaction {
//     // Build a transaction
//     let wallet_1 = new_random_wallet();
//     let output_amount_1: Amount = 42.into();
//     let output_1 = Utxo {
//         amount: output_amount_1,
//         public_key: wallet_1.get_public_key(),
//     };
//     let randomness: Digest = Digest::new(random_elements_array());

//     let input_1 = make_mock_unsigned_devnet_input(42.into(), &wallet_1);
//     let mut transaction_1 = make_mock_transaction(vec![input_1], vec![(output_1, randomness)]);
//     transaction_1.sign(&wallet_1);

//     transaction_1
// }

// TODO: Consider moving this to to the appropriate place in global state,
// keep fn interface. Can be helper function to `create_transaction`.
pub async fn make_mock_transaction_with_generation_key(
    tx_inputs: TxInputList,
    tx_outputs: TxOutputList,
    fee: NeptuneCoins,
    tip_msa: MutatorSetAccumulator,
) -> Transaction {
    let timestamp = Timestamp::now();

    let kernel = TransactionKernel {
        inputs: tx_inputs.removal_records(&tip_msa),
        outputs: tx_outputs.addition_records(),
        public_announcements: tx_outputs.public_announcements(),
        fee,
        timestamp,
        coinbase: None,
        mutator_set_hash: tip_msa.hash(),
    };

    let type_scripts = vec![TypeScript::native_currency()];

    let primitive_witness = transaction::primitive_witness::PrimitiveWitness {
        input_utxos: SaltedUtxos::new(tx_inputs.utxos()),
        type_scripts,
        input_lock_scripts: tx_inputs.lock_scripts(),
        lock_script_witnesses: tx_inputs.lock_script_witnesses(),
        input_membership_proofs: tx_inputs.ms_membership_proofs(),
        output_utxos: SaltedUtxos::new(tx_outputs.utxos()),
        mutator_set_accumulator: tip_msa,
        kernel: kernel.clone(),
    };
    let validity_logic = TransactionValidationLogic::from(primitive_witness);

    Transaction {
        kernel,
        witness: validity_logic,
    }
}

// `make_mock_transaction`, in contrast to `make_mock_transaction2`, assumes you
// already have created `DevNetInput`s.
pub fn make_mock_transaction(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
) -> Transaction {
    let timestamp = Timestamp::now();

    Transaction {
        kernel: TransactionKernel {
            inputs,
            outputs,
            public_announcements: vec![],
            fee: NeptuneCoins::new(1),
            timestamp,
            coinbase: None,
            mutator_set_hash: random(),
        },
        witness: TransactionValidationLogic {
            vast: ValidityTree::axiom(),
            maybe_primitive_witness: None,
        },
    }
}

// TODO: Change this function into something more meaningful!
pub fn make_mock_transaction_with_wallet(
    inputs: Vec<RemovalRecord>,
    outputs: Vec<AdditionRecord>,
    fee: NeptuneCoins,
    _wallet_state: &WalletState,
    timestamp: Option<Timestamp>,
) -> Transaction {
    let timestamp = match timestamp {
        Some(ts) => ts,
        None => Timestamp::now(),
    };
    let kernel = TransactionKernel {
        inputs,
        outputs,
        public_announcements: vec![],
        fee,
        timestamp,
        coinbase: None,
        mutator_set_hash: random(),
    };

    Transaction {
        kernel,
        witness: TransactionValidationLogic {
            vast: ValidityTree::axiom(),
            maybe_primitive_witness: None,
        },
    }
}

/// Build a fake block with a random hash, containing *one* output UTXO in the form
/// of a coinbase output.
///
/// Returns (block, coinbase UTXO, Coinbase output randomness)
pub fn make_mock_block(
    previous_block: &Block,
    // target_difficulty: Option<U32s<TARGET_DIFFICULTY_U32_SIZE>>,
    block_timestamp: Option<Timestamp>,
    coinbase_beneficiary: generation_address::GenerationReceivingAddress,
    seed: [u8; 32],
) -> (Block, Utxo, Digest) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let new_block_height: BlockHeight = previous_block.kernel.header.height.next();

    // Build coinbase UTXO and associated data
    let lock_script = coinbase_beneficiary.lock_script();
    let coinbase_amount = Block::get_mining_reward(new_block_height);
    let coinbase_utxo = Utxo::new(lock_script, coinbase_amount.to_native_coins());
    let coinbase_output_randomness: Digest = rng.gen();
    let receiver_digest: Digest = coinbase_beneficiary.privacy_digest;

    let mut next_mutator_set = previous_block.kernel.body.mutator_set_accumulator.clone();
    let previous_mutator_set = next_mutator_set.clone();
    let mut block_mmr = previous_block.kernel.body.block_mmr_accumulator.clone();
    block_mmr.append(previous_block.hash());
    let coinbase_digest: Digest = Hash::hash(&coinbase_utxo);

    let coinbase_addition_record: AdditionRecord =
        commit(coinbase_digest, coinbase_output_randomness, receiver_digest);
    next_mutator_set.add(&coinbase_addition_record);

    let block_timestamp = match block_timestamp {
        Some(ts) => ts,
        None => previous_block.kernel.header.timestamp + Timestamp::millis(TARGET_BLOCK_INTERVAL),
    };

    let tx_kernel = TransactionKernel {
        inputs: vec![],
        outputs: vec![coinbase_addition_record],
        public_announcements: vec![],
        fee: NeptuneCoins::zero(),
        timestamp: block_timestamp,
        coinbase: Some(coinbase_amount),
        mutator_set_hash: previous_mutator_set.hash(),
    };

    let primitive_witness = PrimitiveWitness {
        input_utxos: SaltedUtxos::empty(),
        type_scripts: vec![TypeScript::native_currency()],
        lock_script_witnesses: vec![],
        input_membership_proofs: vec![],
        output_utxos: SaltedUtxos::new(vec![coinbase_utxo.clone()]),
        mutator_set_accumulator: previous_mutator_set.clone(),
        input_lock_scripts: vec![],
        kernel: tx_kernel.clone(),
    };
    let mut validation_logic = TransactionValidationLogic::from(primitive_witness);
    validation_logic.vast.prove();

    let transaction = Transaction {
        witness: validation_logic,
        kernel: tx_kernel,
    };

    let block_body: BlockBody = BlockBody {
        transaction,
        mutator_set_accumulator: next_mutator_set.clone(),
        lock_free_mmr_accumulator: MmrAccumulator::<Hash>::new(vec![]),
        block_mmr_accumulator: block_mmr,
        uncle_blocks: vec![],
    };

    let block_target_difficulty = previous_block.kernel.header.difficulty;
    let pow_line = previous_block.kernel.header.proof_of_work_line + block_target_difficulty;
    let pow_family = pow_line;
    let zero = BFieldElement::zero();
    let target_difficulty = Block::difficulty_control(previous_block, block_timestamp, None);
    let block_header = BlockHeader {
        version: zero,
        height: new_block_height,
        prev_block_digest: previous_block.hash(),
        timestamp: block_body.transaction.kernel.timestamp,
        nonce: [zero, zero, zero],
        max_block_size: 1_000_000,
        proof_of_work_line: pow_family,
        proof_of_work_family: pow_family,
        difficulty: target_difficulty,
    };

    (
        Block::new(block_header, block_body, Block::mk_std_block_type(None)),
        coinbase_utxo,
        coinbase_output_randomness,
    )
}

pub fn make_mock_block_with_valid_pow(
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    coinbase_beneficiary: generation_address::GenerationReceivingAddress,
    seed: [u8; 32],
) -> (Block, Utxo, Digest) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let (mut block, mut utxo, mut digest) = make_mock_block(
        previous_block,
        block_timestamp,
        coinbase_beneficiary,
        rng.gen(),
    );
    while !block.has_proof_of_work(previous_block) {
        let (block_new, utxo_new, digest_new) = make_mock_block(
            previous_block,
            block_timestamp,
            coinbase_beneficiary,
            rng.gen(),
        );
        block = block_new;
        utxo = utxo_new;
        digest = digest_new;
    }
    (block, utxo, digest)
}

pub fn make_mock_block_with_invalid_pow(
    previous_block: &Block,
    block_timestamp: Option<Timestamp>,
    coinbase_beneficiary: generation_address::GenerationReceivingAddress,
    seed: [u8; 32],
) -> (Block, Utxo, Digest) {
    let mut rng: StdRng = SeedableRng::from_seed(seed);
    let (mut block, mut utxo, mut digest) = make_mock_block(
        previous_block,
        block_timestamp,
        coinbase_beneficiary,
        rng.gen(),
    );
    while block.has_proof_of_work(previous_block) {
        let (block_new, utxo_new, digest_new) = make_mock_block(
            previous_block,
            block_timestamp,
            coinbase_beneficiary,
            rng.gen(),
        );
        block = block_new;
        utxo = utxo_new;
        digest = digest_new;
    }
    (block, utxo, digest)
}

/// Return a dummy-wallet used for testing. The returned wallet is populated with
/// whatever UTXOs are present in the genesis block.
pub async fn mock_genesis_wallet_state(
    wallet_secret: WalletSecret,
    network: Network,
) -> WalletState {
    let data_dir = unit_test_data_directory(network).unwrap();
    mock_genesis_wallet_state_with_data_dir(wallet_secret, network, &data_dir).await
}

pub async fn mock_genesis_wallet_state_with_data_dir(
    wallet_secret: WalletSecret,
    network: Network,
    data_dir: &DataDirectory,
) -> WalletState {
    let cli_args: cli_args::Args = cli_args::Args {
        number_of_mps_per_utxo: 30,
        network,
        ..Default::default()
    };
    WalletState::new_from_wallet_secret(data_dir, wallet_secret, &cli_args).await
}

/// Return an archival state populated with the genesis block
pub async fn mock_genesis_archival_state(
    network: Network,
) -> (ArchivalState, PeerDatabases, DataDirectory) {
    let (block_index_db, peer_db, data_dir) = unit_test_databases(network).await.unwrap();

    let ams = ArchivalState::initialize_mutator_set(&data_dir)
        .await
        .unwrap();

    let archival_state = ArchivalState::new(data_dir.clone(), block_index_db, ams, network).await;

    (archival_state, peer_db, data_dir)
}

// this will create and store the next block including any transactions
// presently in the mempool.  The coinbase will go to our own wallet.
//
// the stored block does NOT have valid proof-of-work.
pub async fn mine_block_to_wallet(global_state_lock: &mut GlobalStateLock) -> Result<Block> {
    let state = global_state_lock.lock_guard().await;
    let tip_block = state.chain.light_state();

    let timestamp = Timestamp::now();
    let (transaction, coinbase_expected_utxo) =
        crate::mine_loop::create_block_transaction(tip_block, &state, timestamp);

    let (header, body) =
        crate::mine_loop::make_block_template(tip_block, transaction, timestamp, None);
    let block = Block::new(header, body, Block::mk_std_block_type(None));
    drop(state);

    global_state_lock
        .store_coinbase_block(block.clone(), coinbase_expected_utxo)
        .await?;

    Ok(block)
}
