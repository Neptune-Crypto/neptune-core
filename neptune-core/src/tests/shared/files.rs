use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use neptune_primitives::data_directory::DataDirectory;
use rand::distr::Alphanumeric;
use rand::distr::SampleString;
use tokio::time::sleep;
use tokio::time::timeout;

/// Create a randomly named `DataDirectory` so filesystem-bound tests can run
/// in parallel. If this is not done, parallel execution of unit tests will
/// fail as they each hold a lock on the database.
///
/// For now we use databases on disk. In-memory databases would be nicer.
pub(crate) fn unit_test_data_directory(
    network: neptune_primitives::network::Network,
) -> Result<DataDirectory> {
    let mut rng = rand::rng();
    let user = env::var("USER").unwrap_or_else(|_| "default".to_string());
    let pid = std::process::id();

    let tmp_root: PathBuf = env::temp_dir()
        .join(format!("neptune-unit-tests-{user}-{pid}"))
        .join(Path::new(&Alphanumeric.sample_string(&mut rng, 16)));

    DataDirectory::get(Some(tmp_root), network)
}

/// Waits until the file at `path` exists, or returns `Err` after 30 seconds.
pub(crate) async fn wait_for_file_to_exist(path: impl AsRef<Path>) -> Result<(), &'static str> {
    let path = path.as_ref().to_path_buf();

    // Wrap in timeout: returns error if 30s pass without success
    let res = timeout(Duration::from_secs(30), async {
        loop {
            if path.exists() {
                return Ok(());
            }
            sleep(Duration::from_millis(200)).await;
        }
    })
    .await;

    match res {
        Ok(inner) => inner,
        Err(_) => Err("Timed out"), // timeout triggered
    }
}

// recursively copy source dir to destination
pub fn copy_dir_recursive(source: &PathBuf, destination: &PathBuf) -> std::io::Result<()> {
    if !source.is_dir() {
        return Err(std::io::Error::other("Source is not a directory"));
    }
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let dest_path = &destination.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_recursive(&entry.path(), dest_path)?;
        } else {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}
