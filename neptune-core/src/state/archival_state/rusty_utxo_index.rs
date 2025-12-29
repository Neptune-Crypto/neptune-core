use itertools::Itertools;
use serde::Serialize;
use serde_derive::Deserialize;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::Announcement;
use crate::api::export::ReceivingAddress;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtMap;
use crate::application::database::storage::storage_schema::DbtSingleton;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;
use crate::protocol::consensus::block::Block;

/// Announcement meta-information, intended for use in combination with
/// [`ReceivingAddress`]. Can be used to quickly identify if the announcement
/// relates to a specific [`ReceivingAddress`].
///
/// [`ReceivingAddress`]: crate::api::export::ReceivingAddress
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct AnnouncementFlags {
    pub(crate) flag: BFieldElement,
    pub(crate) receiver_id: BFieldElement,
}

impl From<&ReceivingAddress> for AnnouncementFlags {
    fn from(value: &ReceivingAddress) -> Self {
        Self {
            flag: value.flag(),
            receiver_id: value.receiver_identifier(),
        }
    }
}

impl TryFrom<&Announcement> for AnnouncementFlags {
    // Only possible converstion error is that announcement message is too
    // short.
    type Error = ();

    fn try_from(value: &Announcement) -> Result<Self, Self::Error> {
        if value.message.len() < 2 {
            return Err(());
        }

        Ok(AnnouncementFlags {
            flag: value.message[0],
            receiver_id: value.message[1],
        })
    }
}

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
    pub(super) announcements: DbtMap<Digest, Vec<AnnouncementFlags>>,

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
    ) -> Option<Vec<AnnouncementFlags>> {
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
