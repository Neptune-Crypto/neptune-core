use tasm_lib::prelude::Digest;

use super::archival_mmr::ArchivalMmr;
use crate::application::database::storage::storage_schema::traits::*;
use crate::application::database::storage::storage_schema::DbtVec;
use crate::application::database::storage::storage_schema::RustyKey;
use crate::application::database::storage::storage_schema::RustyValue;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;
use crate::application::database::NeptuneLevelDb;

pub(crate) struct RustyArchivalBlockMmr {
    ammr: ArchivalMmr<DbtVec<Digest>>,
    storage: SimpleRustyStorage,
}

impl RustyArchivalBlockMmr {
    pub(crate) async fn connect(db: NeptuneLevelDb<RustyKey, RustyValue>) -> Self {
        let mut storage = SimpleRustyStorage::new_with_callback(
            db,
            "archival-block-mmr-Schema",
            crate::LOG_TOKIO_LOCK_EVENT_CB,
        );

        // We do not need a sync-label since the last leaf of the MMR will
        // be the sync-label, i.e., the block digest of the latest block added.
        let abmmr = storage.schema.new_vec::<Digest>("archival_block_mmr").await;
        let abmmr = ArchivalMmr::new(abmmr).await;

        Self {
            ammr: abmmr,
            storage,
        }
    }

    #[inline]
    pub fn ammr(&self) -> &ArchivalMmr<DbtVec<Digest>> {
        &self.ammr
    }

    #[inline]
    pub fn ammr_mut(&mut self) -> &mut ArchivalMmr<DbtVec<Digest>> {
        &mut self.ammr
    }
}

impl StorageWriter for RustyArchivalBlockMmr {
    async fn persist(&mut self) {
        self.storage.persist().await;
    }

    async fn drop_unpersisted(&mut self) {
        self.storage.drop_unpersisted().await;
    }
}
