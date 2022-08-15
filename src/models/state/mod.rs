use anyhow::Result;
use memmap2::Mmap;
use serde::Serialize;
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    net::{IpAddr, SocketAddr},
    ops::DerefMut,
    path::{Path, PathBuf},
};

use self::{blockchain_state::BlockchainState, networking_state::NetworkingState};
use crate::{
    config_models::cli_args,
    database::{leveldb::LevelDB, rusty::RustyLevelDBIterator},
    models::{
        blockchain::block::Block,
        peer::{HandshakeData, PeerStanding},
    },
    VERSION,
};

use super::{
    blockchain::digest::Digest,
    database::{BlockIndexKey, BlockIndexValue, BlockRecord, FileLocation, FileRecord, LastRecord},
};

pub mod archival_state;
pub mod blockchain_state;
pub mod light_state;
pub mod networking_state;

pub const MAX_BLOCK_FILE_SIZE: u64 = 1024 * 1024 * 128; // 128 Mebibyte
pub const BLOCK_FILENAME_PREFIX: &str = "blk";
pub const BLOCK_FILENAME_EXTENSION: &str = "dat";
pub const DIR_NAME_FOR_BLOCKS: &str = "blocks";

/// State handles all state of the client that is shared across threads.
/// The policy used here is that only the main thread should update the
/// state, all other threads are only allowed to read from the state.
#[derive(Debug, Clone)]
pub struct State {
    // Only the main thread may update these values.
    pub chain: BlockchainState,

    // This contains values that both the peer threads and main thread may update
    pub net: NetworkingState,

    // This field is read-only as it's set at launch
    pub cli: cli_args::Args,
}

impl State {
    // Storing IP addresses is, according to this answer, not a violation of GDPR:
    // https://law.stackexchange.com/a/28609/45846
    // Wayback machine: https://web.archive.org/web/20220708143841/https://law.stackexchange.com/questions/28603/how-to-satisfy-gdprs-consent-requirement-for-ip-logging/28609
    pub async fn write_peer_standing_on_increase(&self, ip: IpAddr, standing: PeerStanding) {
        let mut peer_databases = self.net.peer_databases.lock().await;
        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_none() || old_standing.unwrap().standing < standing.standing {
            peer_databases.peer_standings.put(ip, standing)
        }
    }

    pub async fn get_peer_standing_from_database(&self, ip: IpAddr) -> Option<PeerStanding> {
        let mut peer_databases = self.net.peer_databases.lock().await;
        peer_databases.peer_standings.get(ip)
    }

    fn get_block_filename(last_record: LastRecord) -> PathBuf {
        let mut filename: String = BLOCK_FILENAME_PREFIX.to_owned();
        let index = last_record.last_file;
        filename.push_str(&index.to_string());
        let path = Path::new(&filename);
        let path = path.with_extension(BLOCK_FILENAME_EXTENSION);
        path.to_path_buf()
    }

    fn new_block_file_is_needed(file: &fs::File, bytes_to_store: u64) -> bool {
        file.metadata().unwrap().len() + bytes_to_store > MAX_BLOCK_FILE_SIZE
    }

    /// Return the file path of the file, and create any missing directories
    fn block_file_path(data_dir: PathBuf, last_record: LastRecord) -> PathBuf {
        let mut file_path = data_dir.clone();
        file_path.push(DIR_NAME_FOR_BLOCKS);

        // Create directory for blocks if it does not exist already
        std::fs::create_dir_all(file_path.clone()).unwrap_or_else(|_| {
            panic!(
                "Failed to create blocks directory in {}",
                file_path.to_string_lossy()
            )
        });

        // Create directory if it does not exist
        let block_fn = Self::get_block_filename(last_record);
        file_path.push(block_fn);

        file_path
    }

    /// Write a newly found block to database
    pub async fn update_latest_block(&self, new_block: Box<Block>) -> Result<()> {
        // Acquire both locks before updating
        let mut databases_locked = self
            .chain
            .archival_state
            .as_ref()
            .unwrap()
            .block_databases
            .lock()
            .await;
        let mut light_state_locked = self.chain.light_state.latest_block_header.lock().unwrap();

        // Perform the updates while holding both locks
        *light_state_locked = new_block.header.clone();

        // TODO: Multiple blocks can have the same height: fix!
        databases_locked
            .block_height_to_hash
            .put(new_block.header.height, new_block.hash);
        databases_locked
            .block_hash_to_block
            .put(new_block.hash, *new_block.clone());
        databases_locked
            .latest_block_header
            .put((), new_block.header.clone());

        // Write block to disk
        let mut last_rec: LastRecord = match databases_locked
            .block_index
            .get(BlockIndexKey::LastRecord)
            .map(|x| x.as_last_record())
        {
            Some(rec) => rec,
            None => LastRecord::default(),
        };

        // This file must exist on disk already, unless this is the first block
        // stored on disk.
        let data_dir = self.cli.get_data_directory().unwrap();
        let block_file_path = Self::block_file_path(data_dir, last_rec);
        let serialized_block: Vec<u8> = bincode::serialize(&new_block).unwrap();
        let serialized_block_size: u64 = serialized_block.len() as u64;
        let mut block_file: fs::File = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(block_file_path.clone())
            .unwrap();
        if Self::new_block_file_is_needed(&block_file, serialized_block_size) {
            last_rec = LastRecord {
                last_file: last_rec.last_file + 1,
            };
            block_file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(block_file_path)
                .unwrap();
        }

        // Get associated file record from database, otherwise create it
        let file_record_key: BlockIndexKey = BlockIndexKey::FileRecord(last_rec.last_file);
        let file_record_value: Option<FileRecord> = databases_locked
            .block_index
            .get(file_record_key)
            .map(|x| x.as_file_record());
        let file_record_value: FileRecord = match file_record_value {
            Some(record) => record.add(serialized_block_size, &new_block.header),
            None => FileRecord::new(serialized_block_size, &new_block.header),
        };

        // Make room in file for mmapping and record where block starts
        block_file
            .seek(SeekFrom::Current(serialized_block_size as i64 - 1))
            .unwrap();
        block_file.write_all(&[0]).unwrap();
        let file_offset: u64 = block_file
            .seek(SeekFrom::Current(-(serialized_block_size as i64)))
            .unwrap();

        let height_record_key = BlockIndexKey::HeightRecord(new_block.header.height);
        let mut blocks_at_same_height: Vec<Digest> =
            match databases_locked.block_index.get(height_record_key.clone()) {
                Some(rec) => rec.as_height_record(),
                None => vec![],
            };

        // Write to file with mmap
        let mmap = unsafe { Mmap::map(&block_file).unwrap() };
        let mut mmap = mmap.make_mut().unwrap();
        mmap.deref_mut().write_all(&serialized_block).unwrap();

        // Update block index database with newly stored block
        let mut block_index_entries: Vec<(BlockIndexKey, BlockIndexValue)> = vec![];
        let file_record_key: BlockIndexKey = BlockIndexKey::FileRecord(last_rec.last_file);
        let block_record_key: BlockIndexKey = BlockIndexKey::BlockRecord(new_block.hash);
        let block_record_value: BlockIndexValue = BlockIndexValue::BlockRecord(BlockRecord {
            block_header: new_block.header.clone(),
            file_location: FileLocation {
                file_index: last_rec.last_file,
                offset: file_offset,
            },
            tx_count: new_block.body.transactions.len() as u32,
        });

        block_index_entries.push((
            file_record_key,
            BlockIndexValue::FileRecord(file_record_value),
        ));
        block_index_entries.push((block_record_key, block_record_value));

        // Missing: height record and last record
        block_index_entries.push((
            BlockIndexKey::LastRecord,
            BlockIndexValue::LastRecord(last_rec),
        ));
        blocks_at_same_height.push(new_block.hash);
        block_index_entries.push((
            height_record_key,
            BlockIndexValue::HeightRecord(blocks_at_same_height),
        ));
        databases_locked
            .block_index
            .batch_write(&block_index_entries);

        // Release both locks
        Ok(())
    }

    pub async fn get_handshakedata(&self) -> HandshakeData {
        let listen_addr_socket = SocketAddr::new(self.cli.listen_addr, self.cli.peer_port);
        let latest_block_header = self.chain.light_state.get_latest_block_header();

        HandshakeData {
            tip_header: latest_block_header,
            listen_address: Some(listen_addr_socket),
            network: self.cli.network,
            instance_id: self.net.instance_id,
            version: VERSION.to_string(),
        }
    }

    pub async fn clear_ip_standing_in_database(&self, ip: IpAddr) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let old_standing = peer_databases.peer_standings.get(ip);

        if old_standing.is_some() {
            peer_databases
                .peer_standings
                .put(ip, PeerStanding::default())
        }
    }

    pub async fn clear_all_standings_in_database(&self) {
        let mut peer_databases = self.net.peer_databases.lock().await;

        let mut dbiterator: RustyLevelDBIterator<IpAddr, PeerStanding> =
            peer_databases.peer_standings.new_iter();

        for (ip, _v) in dbiterator.by_ref() {
            let old_standing = peer_databases.peer_standings.get(ip);

            if old_standing.is_some() {
                peer_databases
                    .peer_standings
                    .put(ip, PeerStanding::default())
            }
        }
    }
}
