use itertools::Itertools;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;

use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtSingleton;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::Block;
use crate::state::wallet::address::announcement_flag::AnnouncementFlag;

/// The purpose of the UTXO index is to speed up the rescanning of historical
/// blocks, and to serve 3rd parties with information required to detect
/// incoming and outgoing UTXOs as quickly as possible. It assumes the presence
/// of an [`ArchivalState`]. Any decision about tables in the UTXO index should
/// be made in the light of allowing clients or 3rd parties to discover balance-
/// affecting input or output UTXOs in historical blocks as quickly as possible.
///
/// The tables of the UTXO index database. Does not include the addition records
/// in the block since those are included in the [`ArchivalMutatorSet`] which is
/// assumed to be part of the state of all nodes that also maintain a UTXO
/// index.
///
/// [`ArchivalMutatorSet`]: crate::util_types::mutator_set::archival_mutator_set::ArchivalMutatorSet
/// [`ArchivalState`]: crate::state::archival_state::ArchivalState
#[derive(Debug)]
struct UtxoIndexTables {
    #[allow(dead_code)]
    /// Schema version to be used in case this model changes, and data needs to
    /// be migrated or recreated.
    pub(super) schema_version: DbtSingleton<u16>,

    /// Mapping from block hash to the list of announcement flags contained in
    /// the block.
    ///
    /// Can be used to speed up the scanning for incoming, announced UTXOs.
    pub(super) announcements: DbtMap<Digest, Vec<AnnouncementFlag>>,

    /// Mapping from block hash to the list of digests of the absolute indices
    /// being set in the block.
    ///
    /// Can be used to speed up the scanning for used UTXOs, i.e. expenditures.
    pub(super) index_set_digests: DbtMap<Digest, Vec<Digest>>,

    /// Latest block handled by this database
    pub(super) sync_label: DbtSingleton<Digest>,
}

#[derive(Debug)]
pub(crate) struct RustyUtxoIndex {
    storage: SimpleRustyStorage,
    tables: UtxoIndexTables,
}

impl RustyUtxoIndex {
    pub(super) async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "RustyUtxoIndex-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        let schema_version = storage.schema.new_singleton::<u16>("schema_version").await;
        let announcements = storage.schema.new_map("announcements").await;
        let index_sets = storage.schema.new_map("index_sets").await;
        let sync_label = storage.schema.new_singleton::<Digest>("sync_label").await;

        let tables = UtxoIndexTables {
            schema_version,
            announcements,
            index_set_digests: index_sets,
            sync_label,
        };

        Self { storage, tables }
    }

    /// Return the announcement keys for the announcement in the specified
    /// block. Returns Some(vec![]) list if no compatible announcement (of
    /// minimum lenth 2) were mined in the block. Returns `None` if the block
    /// is not known to this index.
    pub(crate) async fn announcement_flags(
        &self,
        block_hash: Digest,
    ) -> Option<Vec<AnnouncementFlag>> {
        self.tables.announcements.get(&block_hash).await
    }

    /// Return the digests of all absolute index sets of the removal records in
    /// this block. Returns `None` if the block is not known to this index.
    pub(crate) async fn index_set_digests(&self, block_hash: Digest) -> Option<Vec<Digest>> {
        self.tables.index_set_digests.get(&block_hash).await
    }

    /// Add block to UTXO index. Adds all announcements, addition records, and
    /// index set digests to the UTXO index.
    ///
    /// This method is idempotent, meaning that it does not alter the index if
    /// the same block is indexed twice. The [`Self::sync_label`] always points
    /// to the latest blocks that was indexed.
    pub(crate) async fn index_block(&mut self, block: &Block) {
        let hash = block.hash();

        let tx_kernel = &block.body().transaction_kernel;

        let announcements = tx_kernel
            .announcements
            .iter()
            .filter_map(|ann| ann.try_into().ok())
            .collect_vec();
        self.tables.announcements.insert(hash, announcements).await;

        let index_set_digests = tx_kernel
            .inputs
            .iter()
            .map(|rr| Tip5::hash(&rr.absolute_indices))
            .collect_vec();
        self.tables
            .index_set_digests
            .insert(hash, index_set_digests)
            .await;

        self.tables.sync_label.set(hash).await;
    }

    pub(crate) fn sync_label(&self) -> Digest {
        self.tables.sync_label.get()
    }

    /// Returns true if the block was already indexed.
    pub(crate) async fn block_was_indexed(&self, block_hash: Digest) -> bool {
        self.tables.announcements.contains_key(&block_hash).await
    }
}

impl StorageWriter for RustyUtxoIndex {
    async fn persist(&mut self) {
        self.storage.persist().await;
    }

    async fn drop_unpersisted(&mut self) {
        unimplemented!("announcement index does not need it")
    }
}

#[cfg(test)]
mod tests {
    use macro_rules_attr::apply;
    use tasm_lib::twenty_first::bfe_vec;

    use super::*;
    use crate::api::export::Announcement;
    use crate::api::export::GenerationSpendingKey;
    use crate::api::export::Network;
    use crate::state::archival_state::ArchivalState;
    use crate::tests::shared::blocks::invalid_empty_block_with_announcements;
    use crate::tests::shared::blocks::make_mock_block_with_inputs_and_outputs;
    use crate::tests::shared_tokio_runtime;
    use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
    use crate::util_types::mutator_set::removal_record::chunk_dictionary::ChunkDictionary;
    use crate::util_types::mutator_set::removal_record::RemovalRecord;
    use crate::util_types::mutator_set::shared::NUM_TRIALS;
    use crate::BFieldElement;

    async fn test_utxo_index(network: Network) -> RustyUtxoIndex {
        let data_dir = crate::tests::shared::files::unit_test_data_directory(network).unwrap();
        ArchivalState::initialize_utxo_index(&data_dir)
            .await
            .unwrap()
    }

    fn announcements_length_0_to_3() -> Vec<Announcement> {
        let length0 = Announcement {
            message: bfe_vec![],
        };
        let length1 = Announcement {
            message: bfe_vec![22],
        };
        let length2 = Announcement {
            message: bfe_vec![22, 55],
        };
        let length3 = Announcement {
            message: bfe_vec![22, 55, 668],
        };
        vec![length0, length1, length2, length3]
    }

    #[apply(shared_tokio_runtime)]
    async fn block_index_is_idempotent() {
        let network = Network::Main;
        let mut utxo_index = test_utxo_index(network).await;
        let an_input = RemovalRecord {
            absolute_indices: AbsoluteIndexSet::new([(1u128 << 20); NUM_TRIALS as usize]),
            target_chunks: ChunkDictionary::default(),
        };

        let genesis = Block::genesis(network);
        let (block1, _) = make_mock_block_with_inputs_and_outputs(
            &genesis,
            vec![an_input],
            vec![],
            None,
            GenerationSpendingKey::derive_from_seed(Digest::default()),
            Digest::default(),
            network,
        )
        .await;
        let announcements = announcements_length_0_to_3();
        let block2 = invalid_empty_block_with_announcements(&block1, network, announcements);

        utxo_index.index_block(&block1).await;
        utxo_index.index_block(&block2).await;

        let expected_index_set_digests = utxo_index.index_set_digests(block1.hash()).await;
        let expected_announcement_flags = utxo_index.announcement_flags(block2.hash()).await;

        utxo_index.index_block(&block1).await;
        utxo_index.index_block(&block2).await;

        assert_eq!(
            expected_index_set_digests,
            utxo_index.index_set_digests(block1.hash()).await
        );
        assert_eq!(
            expected_announcement_flags,
            utxo_index.announcement_flags(block2.hash()).await
        );
        assert_eq!(block2.hash(), utxo_index.sync_label());
    }

    #[apply(shared_tokio_runtime)]
    async fn can_handle_short_announcements() {
        let network = Network::Main;
        let mut utxo_index = test_utxo_index(network).await;

        let announcements = announcements_length_0_to_3();
        let genesis = Block::genesis(network);
        let block1 = invalid_empty_block_with_announcements(&genesis, network, announcements);

        utxo_index.index_block(&block1).await;

        assert_eq!(
            2,
            utxo_index
                .announcement_flags(block1.hash())
                .await
                .unwrap()
                .len(),
            "Announcements of length 2 and above should be indexed"
        );
    }
}
