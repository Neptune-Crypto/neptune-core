use anyhow::{bail, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

use super::network::Network;

pub fn get_data_directory(network: Network) -> Result<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("org", "neptune", "neptune") {
        let mut path = proj_dirs.data_dir().to_path_buf();
        path.push(network.to_string());
        Ok(path)
    } else {
        bail!("Could not determine data directory")
    }
}
