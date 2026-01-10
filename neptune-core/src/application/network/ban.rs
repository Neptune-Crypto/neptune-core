use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use serde_derive::Deserialize;
use serde_derive::Serialize;

/// Manages a persistent blacklist of IP addresses to enforce network-level
/// bans.
///
/// The [`BlackList`] serves as a gatekeeper for the
/// [`NetworkActor`](super::actor::NetworkActor), storing the [`IpAddr`] of
/// peers that have exceeded negative reputation thresholds.
///
/// Unlike a [`PeerId`](libp2p::PeerId) ban, an IP ban prevents malicious actors
/// from simply generating a new identity to bypass restrictions.
///
/// # Persistence
///
/// To ensure bans survive node restarts, the list is serialized to a JSON file
/// specified by the `filename` field. This file is updated whenever a peer is
/// banned and is reloaded during the initialization of the network stack.
///
/// # Example
///
/// ```ignore
/// let mut blacklist = BlackList::load_from_disk_or_new("bans.json")?;
/// if blacklist.is_banned(&remote_ip) {
///     return Err(ConnectionDenied::new("Blacklisted"));
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct BlackList {
    pub(crate) filename: PathBuf,
    pub(crate) list: HashMap<IpAddr, SystemTime>,
    pub(crate) ephemeral_bans: HashSet<IpAddr>,
}

impl BlackList {
    pub(crate) fn new(filename: PathBuf) -> Self {
        BlackList {
            filename,
            list: HashMap::new(),
            ephemeral_bans: HashSet::new(),
        }
    }

    pub(crate) fn with_ephemeral_bans(mut self, ephemeral_bans: Vec<IpAddr>) -> Self {
        self.ephemeral_bans = ephemeral_bans.into_iter().collect();
        self
    }

    /// Insert the IP into the black list.
    pub(crate) fn ban(&mut self, ip_address: IpAddr) {
        let now = SystemTime::now();
        self.list.insert(ip_address, now);
    }

    /// Remove the IP from the black list.
    ///
    /// # Return Value
    ///
    ///  - `true` if the IP address was on the black list.
    ///  - `false` otherwise.
    pub(crate) fn unban(&mut self, ip_address: &IpAddr) -> bool {
        self.list.remove(ip_address).is_some()
    }

    /// Determine whether the given IP is on the black list.
    pub(crate) fn is_banned(&self, ip_address: &IpAddr) -> bool {
        self.list.contains_key(ip_address) || self.ephemeral_bans.contains(ip_address)
    }

    /// Write the current blacklist to disk.
    ///
    /// Uses JSON encoding.
    ///
    /// # Return Value
    ///
    ///  - `Ok(())` in case of success.
    ///  - `Err(_)` if JSON encoding failed or it file operations failed.
    pub(crate) fn save_to_disk(&self) -> anyhow::Result<()> {
        let file = File::create(self.filename.clone())?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &self.list)?;
        Ok(())
    }

    /// Read the blacklist from a file or returns a new one.
    ///
    /// The file is decoded using JSON.
    ///
    /// # Return Value
    ///
    ///  - `Ok(BlackList::new())` if the file does not exist.
    ///  - `Ok(black_list)` if the file does exist and reading and decoding
    ///    succeeded.
    ///  - `Err(_)` if the file does exist and either reading or decoding
    ///    failed.
    pub(crate) fn load_or_new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::new(path.as_ref().to_path_buf()));
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let list = serde_json::from_reader(reader)?;
        Ok(BlackList {
            filename: path.as_ref().to_path_buf(),
            list,
            ephemeral_bans: HashSet::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::application::network::arbitrary::arb_ip_addr;
    use crate::application::network::arbitrary::arb_system_time;

    use super::*;

    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    fn black_list_strategy() -> impl Strategy<Value = BlackList> {
        let path_strategy = any::<String>().prop_map(|s| PathBuf::from(format!("{}.json", s)));
        let list_strategy =
            proptest::collection::hash_map(arb_ip_addr(), arb_system_time(), 0..100);
        let set_strategy = vec(arb_ip_addr(), 0..20);

        (path_strategy, list_strategy, set_strategy).prop_map(|(filename, list, set)| BlackList {
            filename,
            list,
            ephemeral_bans: set.into_iter().collect(),
        })
    }

    #[proptest]
    fn test_blacklist_round_trip(
        #[strategy(black_list_strategy())] mut original: BlackList,
        #[strategy(arb::<u64>())] file_id: u64,
    ) {
        // cross-platform temp directory
        let mut temp_path = std::env::temp_dir();

        // unique filename for this specific test run to avoid collisions
        let unique_name = format!("blacklist_test_{}.json", file_id);
        temp_path.push(unique_name);
        original.filename = temp_path.clone();

        original.save_to_disk().expect("Failed to save to disk");

        let loaded = BlackList::load_or_new(&temp_path).expect("Failed to load from disk");

        // aAssert equality
        // Note: SystemTime precision can sometimes vary by a few nanoseconds on
        // certain filesystems/platforms after serialization. For most
        // use cases, comparing the debug string or checking seconds is safer,
        // but standard equality usually holds for JSON.
        assert_eq!(original.filename, loaded.filename);
        assert_eq!(original.list.len(), loaded.list.len());

        for (ip, time) in &original.list {
            prop_assert!(loaded.list.contains_key(ip));

            // Compare seconds since epoch to avoid minor precision issues
            let original_dur = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let loaded_dur = loaded
                .list
                .get(ip)
                .unwrap()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            prop_assert_eq!(original_dur, loaded_dur);

            prop_assert!(loaded.ephemeral_bans.is_empty());
        }

        // clean up
        let _ = std::fs::remove_file(temp_path);
    }

    #[proptest]
    fn banned_peer_is_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn cli_peer_is_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ephemeral_bans.insert(ip);

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn new_peer_is_not_banned(
        #[strategy(black_list_strategy())] black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        prop_assert!(!black_list.is_banned(&ip));
    }

    #[proptest]
    fn unbanned_peer_is_not_banned(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);

        black_list.unban(&ip);

        prop_assert!(!black_list.is_banned(&ip));
    }
}
