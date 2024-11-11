use std::fmt::Display;
use std::time::Duration;
use std::time::SystemTime;

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MiningStatus {
    Guessing(SystemTime),
    Composing(SystemTime),
    Inactive,
}

impl Display for MiningStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let elapsed_time = match self {
            MiningStatus::Guessing(system_time) => Some(*system_time),
            MiningStatus::Composing(system_time) => Some(*system_time),
            MiningStatus::Inactive => None,
        }
        .map(|time| time.elapsed().unwrap_or(Duration::from_secs(0)));

        match self {
            MiningStatus::Guessing(_) => {
                write!(
                    f,
                    "guessing for {} seconds",
                    elapsed_time.unwrap().as_secs()
                )
            }
            MiningStatus::Composing(_) => {
                write!(
                    f,
                    "composing for {} seconds",
                    elapsed_time.unwrap().as_secs()
                )
            }
            MiningStatus::Inactive => write!(f, "inactive"),
        }
    }
}
