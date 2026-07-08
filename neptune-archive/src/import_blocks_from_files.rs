use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use anyhow::bail;
use itertools::Itertools;
use memmap2::MmapOptions;
use neptune_consensus::block::Block;
use neptune_primitives::data_directory::BLOCK_FILENAME_EXTENSION;
use neptune_primitives::data_directory::BLOCK_FILENAME_PREFIX;
use regex::Regex;

use crate::archival_state::ArchivalState;

impl ArchivalState {
    /// Return a list of file names found in a directory, unsorted.
    fn file_names(directory: &Path) -> Result<Vec<String>> {
        let entries = directory.read_dir()?;
        let mut file_names = vec![];
        for entry in entries {
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(file_name) = entry.file_name().into_string() else {
                bail!("Could not convert {entry:?} to file name");
            };

            file_names.push(file_name);
        }

        Ok(file_names)
    }

    /// Return a sorted list of the paths of the files that store blocks in the
    /// specified directory.
    ///
    /// Returned list is sorted chronologically, assuming  normal operations,
    /// normal storage of blocks. Namely, `blk2.dat` comes before `blk10.dat` in
    /// the returned list.
    pub(crate) fn sorted_blk_file_names(entries: Vec<String>) -> Result<Vec<String>> {
        // Capture all indices from the block files, from the names
        // "blk(d+).dat".
        let blk_file_name_regex = Regex::new(&format!(
            "{BLOCK_FILENAME_PREFIX}(\\d+).{BLOCK_FILENAME_EXTENSION}"
        ))
        .unwrap();
        let mut block_file_indices = vec![];
        for entry in entries {
            if !blk_file_name_regex.is_match(&entry) {
                continue;
            }

            let caps = blk_file_name_regex.captures(&entry).unwrap();
            block_file_indices.push(caps[1].parse::<u32>()?);
        }

        // Sort to ensure blocks are applied in order, from file blk0.dat to
        // blk{N}.dat, while avoiding to process e.g. blk10.dat before
        // blk2.dat.
        block_file_indices.sort_unstable();

        Ok(block_file_indices
            .into_iter()
            .map(|blk_index| {
                format!("{BLOCK_FILENAME_PREFIX}{blk_index}.{BLOCK_FILENAME_EXTENSION}")
            })
            .collect())
    }

    /// Return a sorted list of the names of the files that store blocks in the
    /// specified directory.
    ///
    /// Returned list is sorted chronologically, assuming normal operations,
    /// normal storage of blocks. Specifically, `blk2.dat` will be returned before
    /// `blk10.dat`.
    pub fn read_block_file_names_from_directory(directory: &Path) -> Result<Vec<PathBuf>> {
        let file_names = Self::file_names(directory)?;
        let file_names = Self::sorted_blk_file_names(file_names)?;

        let directory = directory.to_path_buf();
        Ok(file_names
            .into_iter()
            .map(|file_name| {
                let mut file_path = directory.clone();
                file_path.push(file_name);
                file_path
            })
            .collect_vec())
    }

    /// Attempt to deserialize a list of blocks from a file, without access to
    /// a database to provide indexing and pointers into the file. Assumes the
    /// same file-encoding for blocks as is used in the rest of this module.
    ///
    /// Use this to extract a list of blocks from a file without having access
    /// to a database.
    ///
    /// Provides no validation that the blocks are valid, have enough PoW, or
    /// are stored in order in the file.
    pub async fn blocks_from_file_without_record(path: &PathBuf) -> Result<Vec<Block>> {
        let block_file = tokio::fs::OpenOptions::new().read(true).open(path).await?;
        let file_size = block_file.metadata().await?.len();

        let mut offset = 0;
        let mut blocks = vec![];
        while offset < file_size {
            let mmap = unsafe { MmapOptions::new().offset(offset).map(&block_file)? };
            let block: Block = bincode::deserialize(&mmap)?;
            offset += bincode::serialized_size(&block)?;

            blocks.push(block);
        }

        Ok(blocks)
    }
}
