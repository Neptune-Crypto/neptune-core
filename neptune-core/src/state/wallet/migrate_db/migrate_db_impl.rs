use super::v0_to_v1;
use crate::application::database::storage::storage_schema::traits::StorageWriter;
use crate::application::database::storage::storage_schema::SimpleRustyStorage;

// migrates a wallet db from a lower schema version to a higher version.
//
// this fn should be modified each time that WALLET_DB_SCHEMA_VERSION is
// incremented.
//
// each increment must have an accompanying migration module and function, eg
// v0_to_v1::migrate().
//
// When a database version is behind the code's version, then all migrations
// in the range are applied in sequence.
//
// Example: database is at v1, code is at v3. Migrations 2 and 3 get applied, in
// order.
//
// see description of `WalletDbTables` and `WALLET_DB_SCHEMA_VERSION`
//
// How to add a migration:
//
// let's say we are incrementing to SCHEMA_VERSION 2.
//
// 1. in the match statement of this fn, add:
//    v if v == 2 => {
//        log_apply_version(v);
//        v1_to_v2::migrate(storage).await?
//    }
//
// 2. create a module v1_to_v2 and implement the migrate() fn.
//    use v0_to_v1.rs as a template.
//
// 3. add a test for the migrate fn.
//    again, use v0_to_v1.rs as a template.
pub(crate) async fn migrate_range(
    storage: &mut SimpleRustyStorage,
    version_from: u16,
    version_to: u16,
) -> anyhow::Result<()> {
    assert!(version_from < version_to);

    tracing::info!(
        "wallet database is at schema version: v{}.  migrating to version: v{}",
        version_from,
        version_to
    );

    let log_apply_version = |version| {
        tracing::info!(
            "db migration. applying updates from v{} to v{}",
            version - 1,
            version
        )
    };

    // iterate schema versions and apply migrations, if available.
    // note that every schema version in the range must be known
    // (in the match) else a panic results.  This prevents incrementing
    // the schema version and accidentally forgetting to update this fn.
    for i in version_from..version_to {
        let apply_version = i + 1;

        match apply_version {
            v if v == 1 => {
                log_apply_version(v);
                v0_to_v1::migrate(storage).await?
            }
            _ => panic!("schema version {} is unknown", i),
        }

        storage.persist().await;
        tracing::debug!("persisted wallet db after migration to v{}", apply_version);
    }
    Ok(())
}
