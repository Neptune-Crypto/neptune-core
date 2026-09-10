use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::SystemTime;

use neptune_p2p::peer::STANDING_HALF_LIFE;
use serde::Deserialize;
use serde::Serialize;

/// How long a ban applies for.
const BAN_DURATION: Duration = STANDING_HALF_LIFE;

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

    /// Ephemeral bans are not persisted. They may correspond to bans specified
    /// as CLI arguments.
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
    ///
    /// A ban expires after [`BAN_DURATION`], so that a node sanctioned once, or
    /// sanctioned for behaviour it has since stopped, is not shut out of the
    /// network for the lifetime of the blacklist file. Bans given on the
    /// command line never expire.
    pub(crate) fn is_banned(&self, ip_address: &IpAddr) -> bool {
        if self.ephemeral_bans.contains(ip_address) {
            return true;
        }

        self.list
            .get(ip_address)
            .is_some_and(|banned_at| !Self::is_expired(*banned_at))
    }

    /// Whether a ban imposed at the given time no longer applies.
    fn is_expired(banned_at: SystemTime) -> bool {
        banned_at.elapsed().is_ok_and(|age| age >= BAN_DURATION)
    }

    /// Drop bans that have expired.
    ///
    /// Keeps the persisted file from growing without bound.
    fn forget_expired_bans(&mut self) {
        self.list
            .retain(|_ip, banned_at| !Self::is_expired(*banned_at));
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
        let mut black_list = BlackList {
            filename: path.as_ref().to_path_buf(),
            list,
            ephemeral_bans: HashSet::new(),
        };
        black_list.forget_expired_bans();

        Ok(black_list)
    }
}

#[cfg(test)]
mod tests {
    use neptune_p2p::peer::NegativePeerSanction;
    use neptune_p2p::peer::PeerStanding;
    use proptest::collection::vec;
    use proptest::prelude::any;
    use proptest::prelude::Strategy;
    use proptest::prop_assert;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::application::network::arbitrary::arb_ip_addr;
    use crate::application::network::arbitrary::tests::arb_system_time;

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

        original.forget_expired_bans();

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

    /// A standing that was sanctioned to exactly the ban threshold, `ago` in
    /// the past.
    fn standing_at_threshold(tolerance: u16, ago: Duration) -> PeerStanding {
        PeerStanding {
            standing: -i32::from(tolerance),
            latest_punishment: Some((
                NegativePeerSanction::DifferentGenesis,
                SystemTime::now() - ago,
            )),
            latest_reward: None,
            peer_tolerance: i32::from(tolerance),
        }
    }

    #[proptest]
    fn the_two_admission_gates_expire_together(
        #[strategy(1u16..=u16::MAX)] tolerance: u16,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        let margin = Duration::from_secs(60);
        let just_short = BAN_DURATION.checked_sub(margin).unwrap();
        let just_over = BAN_DURATION + margin;

        // Just before the deadline: both gates refuse.
        let mut before = BlackList::new(PathBuf::from("does-not-exist.json"));
        before.list.insert(ip, SystemTime::now() - just_short);
        let standing_before = standing_at_threshold(tolerance, just_short);

        prop_assert!(before.is_banned(&ip), "blacklist must still refuse");
        prop_assert!(standing_before.is_bad(), "standing must still be bad");

        // Just after: both gates admit.
        let mut after = BlackList::new(PathBuf::from("does-not-exist.json"));
        after.list.insert(ip, SystemTime::now() - just_over);
        let standing_after = standing_at_threshold(tolerance, just_over);

        prop_assert!(!after.is_banned(&ip), "blacklist must have expired");
        prop_assert!(!standing_after.is_bad(), "standing must no longer be bad");
    }

    #[proptest]
    fn ban_expires_after_the_ban_duration(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ban(ip);
        prop_assert!(black_list.is_banned(&ip));

        // Just short of the duration: still banned.
        let almost = SystemTime::now() - BAN_DURATION + Duration::from_secs(60);
        black_list.list.insert(ip, almost);
        prop_assert!(black_list.is_banned(&ip));

        // Past the duration: no longer banned.
        let expired = SystemTime::now() - BAN_DURATION - Duration::from_secs(60);
        black_list.list.insert(ip, expired);
        prop_assert!(!black_list.is_banned(&ip));
    }

    #[proptest]
    fn cli_bans_do_not_expire(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] ip: IpAddr,
    ) {
        black_list.ephemeral_bans.insert(ip);
        black_list.list.insert(
            ip,
            SystemTime::now() - BAN_DURATION - Duration::from_secs(60),
        );

        prop_assert!(black_list.is_banned(&ip));
    }

    #[proptest]
    fn forgetting_expired_bans_keeps_the_live_ones(
        #[strategy(black_list_strategy())] mut black_list: BlackList,
        #[strategy(arb_ip_addr())] live: IpAddr,
        #[strategy(arb_ip_addr())] expired: IpAddr,
    ) {
        black_list.list.insert(live, SystemTime::now());
        black_list.list.insert(
            expired,
            SystemTime::now() - BAN_DURATION - Duration::from_secs(60),
        );

        black_list.forget_expired_bans();

        prop_assert!(black_list.list.contains_key(&live));
        prop_assert!(!black_list.list.contains_key(&expired));
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
