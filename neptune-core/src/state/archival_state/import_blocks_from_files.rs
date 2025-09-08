use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use itertools::Itertools;
use memmap2::MmapOptions;
use regex::Regex;

use super::ArchivalState;
use crate::protocol::consensus::block::Block;
use crate::state::shared::BLOCK_FILENAME_EXTENSION;
use crate::state::shared::BLOCK_FILENAME_PREFIX;

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
    fn sorted_blk_file_names(entries: Vec<String>) -> Result<Vec<String>> {
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
    pub(crate) fn read_block_file_names_from_directory(directory: &Path) -> Result<Vec<PathBuf>> {
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
    pub(crate) async fn blocks_from_file_without_record(path: &PathBuf) -> Result<Vec<Block>> {
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

#[cfg(test)]
mod tests {
    use macro_rules_attr::apply;
    use tracing_test::traced_test;

    use super::*;
    use crate::api::export::Network;
    use crate::state::archival_state::tests::make_test_archival_state;
    use crate::tests::shared::blocks::invalid_empty_blocks;
    use crate::tests::shared_tokio_runtime;

    #[test]
    fn blk_file_names_sorted_correctly() {
        let input = [
            "blk10.dat",
            "blk2.dat",
            "blk3.dat",
            "blk4.dat",
            "blk5.dat",
            "blk0.dat",
            "blk99.dat",
            "not-parseable",
            ".",
            "..",
            "blk1.dat",
        ]
        .map(|x| x.to_owned())
        .to_vec();

        let expected = [
            "blk0.dat",
            "blk1.dat",
            "blk2.dat",
            "blk3.dat",
            "blk4.dat",
            "blk5.dat",
            "blk10.dat",
            "blk99.dat",
        ]
        .map(|x| x.to_owned())
        .to_vec();
        assert_eq!(
            expected,
            ArchivalState::sorted_blk_file_names(input).unwrap()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn get_blocks_directly_from_file_without_database() {
        let network = Network::Main;
        let mut archival_state = make_test_archival_state(network).await;
        let blocks = invalid_empty_blocks(&archival_state.genesis_block, 10, network);

        for i in 0..10 {
            archival_state
                .write_block_internal(&blocks[i], true)
                .await
                .unwrap();

            let assumed_block_file = archival_state.data_dir.block_file_path(0);
            let returned = ArchivalState::blocks_from_file_without_record(&assumed_block_file)
                .await
                .unwrap();

            assert_eq!(blocks[0..=i], returned[..]);
        }
    }
}
