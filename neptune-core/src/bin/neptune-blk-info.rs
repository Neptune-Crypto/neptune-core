//! neptune-blk-info
//!
//! Prints basic information about the blocks contained in `blk<n>.dat` files.

use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use neptune_cash::state::archival_state::ArchivalState;

#[derive(Parser, Debug, Clone)]
#[clap()]
struct CliArg {
    path: PathBuf,
}

fn main() -> Result<()> {
    async fn print_block_info(path: PathBuf) -> Result<()> {
        let blocks = ArchivalState::blocks_from_file_without_record(&path).await?;

        eprintln!(
            "Printing information about blocks contained in {}",
            path.to_string_lossy()
        );

        for block in blocks {
            println!(
                "hash: {:x}, height: {}",
                block.hash(),
                block.header().height
            );
        }

        Ok(())
    }

    let tokio_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("Could not create tokio runtime");

    let CliArg { path } = CliArg::parse();

    if !Path::exists(&path) {
        bail!(
            "Could not find file {}. Please ensure that this file exists,\
         and that the full path is provided.",
            path.to_string_lossy()
        )
    }

    tokio_runtime.block_on(print_block_info(path))
}
