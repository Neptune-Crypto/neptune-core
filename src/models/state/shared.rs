use std::{
    fs,
    path::{Path, PathBuf},
};

pub const MAX_BLOCK_FILE_SIZE: u64 = 1024 * 1024 * 128; // 128 Mebibyte
pub const BLOCK_FILENAME_PREFIX: &str = "blk";
pub const BLOCK_FILENAME_EXTENSION: &str = "dat";
pub const DIR_NAME_FOR_BLOCKS: &str = "blocks";

fn get_block_filename(file_index: u32) -> PathBuf {
    let mut filename: String = BLOCK_FILENAME_PREFIX.to_owned();
    filename.push_str(&file_index.to_string());
    let path = Path::new(&filename);

    path.with_extension(BLOCK_FILENAME_EXTENSION)
}

/// Return a boolean indicating if a new file is needed or, in the negative sense, we can continue
/// writing to the current file.
pub fn new_block_file_is_needed(file: &fs::File, bytes_to_store: u64) -> bool {
    file.metadata().unwrap().len() + bytes_to_store > MAX_BLOCK_FILE_SIZE
}

/// Return the file path of the file, and create any missing directories
pub fn get_block_file_path(data_dir: PathBuf, file_index: u32) -> PathBuf {
    let mut file_path = data_dir;
    file_path.push(DIR_NAME_FOR_BLOCKS);

    // Create directory for blocks if it does not exist already
    std::fs::create_dir_all(file_path.clone()).unwrap_or_else(|_| {
        panic!(
            "Failed to create blocks directory in {}",
            file_path.to_string_lossy()
        )
    });

    let block_fn = get_block_filename(file_index);
    file_path.push(block_fn);

    file_path
}
