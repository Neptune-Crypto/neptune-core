use std::cmp::Ordering;

use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// Announcement meta-information, intended for use in combination with a
/// receiving address. Can be used to quickly identify if the announcement
/// relates to a specific receiving address. Contains the first two elements of
/// an announcement, as these are interpreted as purpose, receiver ID,
/// respectively.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AnnouncementFlag {
    /// Purpose of the announcement. E.g.: announcement for generational
    /// address, or for symmetric key address.
    pub flag: BFieldElement,

    /// An ID identifying the receiver.
    pub receiver_id: BFieldElement,
}

impl Ord for AnnouncementFlag {
    // Ordering is implemented to allow for idempotent and deterministic lookup
    // tables.
    fn cmp(&self, other: &Self) -> Ordering {
        match self.flag.value().cmp(&other.flag.value()) {
            Ordering::Equal => self.receiver_id.value().cmp(&other.receiver_id.value()),
            non_eq => non_eq,
        }
    }
}

impl PartialOrd for AnnouncementFlag {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
