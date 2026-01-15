use std::cmp::Ordering;

use serde::Serialize;
use serde_derive::Deserialize;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::Announcement;
use crate::api::export::ReceivingAddress;

/// Announcement meta-information, intended for use in combination with
/// [`ReceivingAddress`]. Can be used to quickly identify if the announcement
/// relates to a specific [`ReceivingAddress`]. Contains the first two elements
/// of an announcement, as these are interpreted as purpose, receiver ID,
/// respectively.
///
/// [`ReceivingAddress`]: crate::api::export::ReceivingAddress
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

impl From<&ReceivingAddress> for AnnouncementFlag {
    fn from(value: &ReceivingAddress) -> Self {
        Self {
            flag: value.flag(),
            receiver_id: value.receiver_identifier(),
        }
    }
}

impl TryFrom<&Announcement> for AnnouncementFlag {
    // Only possible converstion error is that announcement message is too
    // short.
    type Error = ();

    fn try_from(value: &Announcement) -> Result<Self, Self::Error> {
        if value.message.len() < 2 {
            return Err(());
        }

        Ok(AnnouncementFlag {
            flag: value.message[0],
            receiver_id: value.message[1],
        })
    }
}
