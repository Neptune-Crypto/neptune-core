use tokio::fs;

pub const MAX_BLOCK_FILE_SIZE: u64 = 1024 * 1024 * 128; // 128 Mebibyte
pub const BLOCK_FILENAME_PREFIX: &str = "blk";
pub const BLOCK_FILENAME_EXTENSION: &str = "dat";
pub const DIR_NAME_FOR_BLOCKS: &str = "blocks";

/// Return a boolean indicating if a new file is needed or, in the negative sense, we can continue
/// writing to the current file.
pub(crate) async fn new_block_file_is_needed(file: &fs::File, bytes_to_store: u64) -> bool {
    file.metadata().await.unwrap().len() + bytes_to_store > MAX_BLOCK_FILE_SIZE
}
