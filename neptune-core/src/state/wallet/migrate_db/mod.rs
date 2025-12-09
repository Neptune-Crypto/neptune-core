mod migrate_db_impl;
mod v0_to_v1;
mod v1_to_v2;
pub(crate) use migrate_db_impl::migrate_range;

#[cfg(test)]
pub(super) mod worker {
    use std::path::PathBuf;

    use crate::application::config::data_directory::DataDirectory;
    use crate::application::database::storage::storage_schema::RustyKey;
    use crate::application::database::storage::storage_schema::RustyValue;
    use crate::application::database::NeptuneLevelDb;

    pub(super) fn crate_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    // opens wallet db
    pub(super) async fn open_db(
        data_dir: &DataDirectory,
    ) -> anyhow::Result<NeptuneLevelDb<RustyKey, RustyValue>> {
        let wallet_database_path = data_dir.wallet_database_dir_path();
        println!(
            "path {} exists: {}",
            wallet_database_path.display(),
            wallet_database_path.exists()
        );
        DataDirectory::create_dir_if_not_exists(&wallet_database_path).await?;
        NeptuneLevelDb::new(
            &wallet_database_path,
            &crate::application::database::create_db_if_missing(),
        )
        .await
    }
}
