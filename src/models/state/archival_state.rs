use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

use crate::{
    database::leveldb::LevelDB,
    models::{
        blockchain::{block::Block, digest::Digest},
        database::BlockDatabases,
    },
};

#[derive(Clone, Debug)]
pub struct ArchivalState {
    // Since this is a database, we use the tokio Mutex here.
    pub block_databases: Arc<TokioMutex<BlockDatabases>>,

    // The genesis block is stored on the heap, as we would otherwise get stack overflows whenever we instantiate
    // this object in a spawned worker thread.
    genesis_block: Box<Block>,
}

impl ArchivalState {
    pub fn new(initial_block_databases: Arc<TokioMutex<BlockDatabases>>) -> Self {
        Self {
            block_databases: initial_block_databases,
            genesis_block: Box::new(Block::genesis_block()),
        }
    }

    /// Return latest block from database, or genesis block if no other block
    /// is known.
    pub async fn get_latest_block(&self) -> Block {
        let mut dbs = self.block_databases.lock().await;
        let lookup_res_info: Option<Block> =
            BlockDatabases::get_latest_block(&mut dbs).expect("Failed to read from DB");

        match lookup_res_info {
            None => *self.genesis_block.clone(),
            Some(block) => block,
        }
    }

    // Return the block with a given block digest, iff it's available in state somewhere
    pub async fn get_block(&self, block_digest: Digest) -> Result<Option<Block>> {
        let maybe_block = self
            .block_databases
            .lock()
            .await
            .block_hash_to_block
            .get(block_digest)
            .or_else(move || {
                // If block was not found in database, check if the digest matches the genesis block
                if self.genesis_block.hash == block_digest {
                    Some(*self.genesis_block.clone())
                } else {
                    None
                }
            });

        Ok(maybe_block)
    }

    /// Return a list of digests of the ancestors to the requested digest. Does not include the input
    /// digest. If no ancestors can be found, returns the empty list. The count is the maximum length
    /// of the returned list. E.g. if the input digest corresponds to height 2 and count is 5, the
    /// returned list will contain the digests of block 1 and block 0 (the genesis block).
    /// The input block must correspond to a known block but it can be the genesis block in which case
    /// the empty list will be returned. The lock on the database must be free for this method to
    /// not end in a deadlock.
    pub async fn get_ancestor_block_digests(
        &self,
        block_digest: Digest,
        mut count: usize,
    ) -> Vec<Digest> {
        let input_block = self
            .get_block(block_digest)
            .await
            .expect("block lookup must succeed")
            .unwrap();
        let mut parent_digest = input_block.header.prev_block_digest;
        let mut ret = vec![];
        while let Some(parent) = self
            .get_block(parent_digest)
            .await
            .expect("block lookup must succeed")
        {
            ret.push(parent.hash);
            parent_digest = parent.header.prev_block_digest;
            count -= 1;
            if count == 0 {
                break;
            }
        }

        ret
    }
}

#[cfg(test)]
mod archival_state_tests {
    use super::*;

    use tracing_test::traced_test;

    use crate::{
        config_models::network::Network,
        models::state::{blockchain_state::BlockchainState, light_state::LightState},
        tests::shared::{databases, make_mock_block},
    };

    #[traced_test]
    #[tokio::test]
    async fn initialize_archival_state_test() -> Result<()> {
        // Ensure that the archival state can be initialized without overflowing the stack
        tokio::spawn(async move {
            let (block_databases, _) = databases(Network::Main).unwrap();
            let _archival_state0 = ArchivalState::new(block_databases);
            let (block_databases, _) = databases(Network::Main).unwrap();
            let _archival_state1 = ArchivalState::new(block_databases);
            let (block_databases, _) = databases(Network::Main).unwrap();
            let _archival_state2 = ArchivalState::new(block_databases);
            let b = Block::genesis_block();
            let blockchain_state = BlockchainState {
                archival_state: Some(_archival_state2),
                light_state: LightState::new(_archival_state1.genesis_block.header),
            };
            let block_1 = make_mock_block(b, None);
            let mut lock0 = blockchain_state
                .archival_state
                .as_ref()
                .unwrap()
                .block_databases
                .lock()
                .await;
            lock0.block_hash_to_block.put(block_1.hash, block_1.clone());
            let c = lock0.block_hash_to_block.get(block_1.hash).unwrap();
            println!("genesis digest = {}", c.hash);
            drop(lock0);

            let mut lock1 = blockchain_state
                .archival_state
                .as_ref()
                .unwrap()
                .block_databases
                .lock()
                .await;
            let c = lock1.block_hash_to_block.get(block_1.hash).unwrap();
            println!("genesis digest = {}", c.hash);
        })
        .await?;

        Ok(())
    }

    #[should_panic]
    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_panic_test() {
        let (block_databases, _) = databases(Network::Main).unwrap();
        let archival_state = ArchivalState::new(block_databases);
        let genesis = archival_state.genesis_block.clone();
        archival_state
            .get_ancestor_block_digests(genesis.header.prev_block_digest, 10)
            .await;
    }

    #[traced_test]
    #[tokio::test]
    async fn digest_of_ancestors_test() -> Result<()> {
        let (block_databases, _) = databases(Network::Main).unwrap();
        let archival_state = ArchivalState::new(block_databases);
        let genesis = *archival_state.genesis_block.clone();

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 1)
            .await
            .is_empty());

        // Insert blocks and verify that the same result is returned
        let mock_block_1 = make_mock_block(genesis.clone(), None);
        let mock_block_2 = make_mock_block(mock_block_1.clone(), None);
        let mock_block_3 = make_mock_block(mock_block_2.clone(), None);
        let mock_block_4 = make_mock_block(mock_block_3.clone(), None);

        let mut databases_locked = archival_state.block_databases.lock().await;
        databases_locked
            .block_hash_to_block
            .put(mock_block_1.hash, mock_block_1.clone());
        databases_locked
            .block_hash_to_block
            .put(mock_block_2.hash, mock_block_2.clone());
        databases_locked
            .block_hash_to_block
            .put(mock_block_3.hash, mock_block_3.clone());
        databases_locked
            .block_hash_to_block
            .put(mock_block_4.hash, mock_block_4.clone());
        drop(databases_locked); // drop lock because `get_ancestor_block_digests` acquires its own lock

        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 10)
            .await
            .is_empty());
        assert!(archival_state
            .get_ancestor_block_digests(genesis.hash, 1)
            .await
            .is_empty());

        // Check that ancestors of block 1 and 2 return the right values
        let ancestors_of_1 = archival_state
            .get_ancestor_block_digests(mock_block_1.hash, 10)
            .await;
        assert_eq!(1, ancestors_of_1.len());
        assert_eq!(genesis.hash, ancestors_of_1[0]);

        let ancestors_of_2 = archival_state
            .get_ancestor_block_digests(mock_block_2.hash, 10)
            .await;
        assert_eq!(2, ancestors_of_2.len());
        assert_eq!(mock_block_1.hash, ancestors_of_2[0]);
        assert_eq!(genesis.hash, ancestors_of_2[1]);

        // Verify that max length is respected
        let ancestors_of_4_long = archival_state
            .get_ancestor_block_digests(mock_block_4.hash, 10)
            .await;
        assert_eq!(4, ancestors_of_4_long.len());
        assert_eq!(mock_block_3.hash, ancestors_of_4_long[0]);
        assert_eq!(mock_block_2.hash, ancestors_of_4_long[1]);
        assert_eq!(mock_block_1.hash, ancestors_of_4_long[2]);
        assert_eq!(genesis.hash, ancestors_of_4_long[3]);
        let ancestors_of_4_short = archival_state
            .get_ancestor_block_digests(mock_block_4.hash, 2)
            .await;
        assert_eq!(2, ancestors_of_4_short.len());
        assert_eq!(mock_block_3.hash, ancestors_of_4_short[0]);
        assert_eq!(mock_block_2.hash, ancestors_of_4_short[1]);

        Ok(())
    }
}
