//! Sharing the archival mutator set between peers: the proof-of-work ticket
//! a download is paid with, and the frames the set is streamed in.

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use libp2p_identity::PeerId;
use rayon::prelude::*;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::prelude::BFieldElement;
use tasm_lib::twenty_first::tip5::digest::Digest;

use crate::peer::InstanceId;

/// The most bytes of the archival mutator set stream that one
/// [`PeerMessage::ArchivalMutatorSet`](crate::peer::PeerMessage::ArchivalMutatorSet)
/// carries.
pub const ARCHIVAL_MUTATOR_SET_FRAME_BYTES: usize = 64 * 1024 * 1024;

/// One end of a request for an archival mutator set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AmsRequestParty {
    pub instance_id: InstanceId,
    pub peer_id: PeerId,
}

/// A request for one frame of the receiver's archival mutator set as of a
/// block, paid for with proof of work.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivalMutatorSetRequest {
    /// The block the set must be synced to.
    pub block_hash: Digest,

    /// Makes [`Self::work`] meet the receiver's target.
    pub nonce: Digest,

    /// Where in the stream the requested frame starts.
    pub offset: u64,
}

impl ArchivalMutatorSetRequest {
    /// The proof-of-work hash of a request.
    ///
    /// Binds both parties and the block hash such that a solution can never
    /// be reused. Does not bind the offset, meaning that a requestor only has
    /// to do this work once.
    pub fn work(&self, requester: AmsRequestParty, server: AmsRequestParty) -> Digest {
        let mut input = vec![];
        for party in [requester, server] {
            let id = party.instance_id;
            input.extend(
                [
                    id as u32,
                    (id >> 32) as u32,
                    (id >> 64) as u32,
                    (id >> 96) as u32,
                ]
                .map(u64::from)
                .map(BFieldElement::new),
            );
            input.extend(
                party
                    .peer_id
                    .to_bytes()
                    .into_iter()
                    .map(u64::from)
                    .map(BFieldElement::new),
            );
        }
        input.extend(self.block_hash.values());
        input.extend(self.nonce.values());
        Tip5::hash_varlen(&input)
    }

    /// Whether the work meets the target, as a proof of work does.
    pub fn meets(
        &self,
        requester: AmsRequestParty,
        server: AmsRequestParty,
        target: Digest,
    ) -> bool {
        self.work(requester, server) <= target
    }

    /// Solve the proof-of-work puzzle required to send a request for an
    /// archival mutator set.
    ///
    /// Multithreaded for performance reasons, leaving two threads of the
    /// pool free.
    pub fn solve(
        block_hash: Digest,
        offset: u64,
        requester: AmsRequestParty,
        server: AmsRequestParty,
        target: Digest,
        seed: Digest,
    ) -> Self {
        let found = AtomicBool::new(false);
        let threads = std::cmp::max(rayon::current_num_threads().saturating_sub(2), 1);
        (0..threads)
            .into_par_iter()
            .find_map_first(|thread| {
                let thread = Digest::new([BFieldElement::new(thread as u64); Digest::LEN]);
                let mut request = Self {
                    block_hash,
                    nonce: Tip5::hash_pair(seed, thread),
                    offset,
                };
                while !request.meets(requester, server, target) {
                    if found.load(Ordering::Relaxed) {
                        return None;
                    }
                    request.nonce = Tip5::hash(&request.nonce);
                }
                found.store(true, Ordering::Relaxed);
                Some(request)
            })
            .expect("one thread finds a nonce before the others give up")
    }

    /// The target that [`Self::work`] must meet after `log2_work` hashes
    /// on average. Digests compare by their last element first, so the
    /// target caps that element.
    pub fn target(log2_work: u8) -> Digest {
        let mut target = [BFieldElement::new(BFieldElement::MAX); Digest::LEN];
        target[Digest::LEN - 1] = BFieldElement::new(BFieldElement::MAX >> log2_work);
        Digest(target)
    }

    /// The number of frames a stream of `total_len` bytes takes.
    pub fn num_frames(total_len: u64) -> u64 {
        std::cmp::max(
            total_len.div_ceil(ARCHIVAL_MUTATOR_SET_FRAME_BYTES as u64),
            1,
        )
    }
}

/// State describing the downloading of an archival mutator set from another
/// peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchivalMutatorSetDownload {
    pub block_hash: Digest,
    pub nonce: Digest,
    pub next_offset: u64,
}

/// One frame of the receiver's archival mutator set stream: its AOCL leafs,
/// chunks, window and sync label, as the archive writes them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivalMutatorSetFrame {
    pub block_hash: Digest,
    pub total_len: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archival_mutator_set_request_work_is_bound_to_both_peers_and_block() {
        let everything = Digest([BFieldElement::new(BFieldElement::MAX); Digest::LEN]);
        let nothing = Digest::default();
        let block_hash = Digest([BFieldElement::new(7); Digest::LEN]);
        let requester = AmsRequestParty {
            instance_id: 42,
            peer_id: PeerId::random(),
        };
        let server = AmsRequestParty {
            instance_id: 43,
            peer_id: PeerId::random(),
        };

        let request =
            ArchivalMutatorSetRequest::solve(block_hash, 0, requester, server, everything, nothing);
        assert!(request.meets(requester, server, everything));
        assert!(!request.meets(requester, server, nothing));

        // Some work is needed for this target; the search finds it.
        let target = ArchivalMutatorSetRequest::target(12);
        let solved =
            ArchivalMutatorSetRequest::solve(block_hash, 0, requester, server, target, nothing);
        assert!(solved.meets(requester, server, target));

        // The same work serves every frame of one download, and no other
        // requester, server or block.
        let work = request.work(requester, server);
        let later_frame = ArchivalMutatorSetRequest {
            offset: 1,
            ..request
        };
        assert_eq!(work, later_frame.work(requester, server));
        let other_instance = |party: AmsRequestParty| AmsRequestParty {
            instance_id: party.instance_id + 1,
            ..party
        };
        let other_peer = |party: AmsRequestParty| AmsRequestParty {
            peer_id: PeerId::random(),
            ..party
        };
        assert_ne!(work, request.work(other_instance(requester), server));
        assert_ne!(work, request.work(requester, other_instance(server)));
        assert_ne!(work, request.work(other_peer(requester), server));
        assert_ne!(work, request.work(requester, other_peer(server)));
        assert_ne!(work, request.work(server, requester));
        let other_block = ArchivalMutatorSetRequest {
            block_hash: Digest::default(),
            ..request
        };
        assert_ne!(work, other_block.work(requester, server));
    }

    /// Time the ticket search on one thread and on all, for choosing the
    /// default work. Run with `cargo nextest run --release -p neptune-p2p
    /// --run-ignored only --no-capture -E 'test(ticket_solve_bench)'`.
    #[ignore = "benchmark"]
    #[test]
    fn ticket_solve_bench() {
        let block_hash = Digest([BFieldElement::new(7); Digest::LEN]);
        let target = ArchivalMutatorSetRequest::target(22);
        for threads in [1, rayon::current_num_threads()] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            let start = std::time::Instant::now();
            for seed in 0..4 {
                let seed = Digest([BFieldElement::new(seed); Digest::LEN]);
                let party = |instance_id| AmsRequestParty {
                    instance_id,
                    peer_id: PeerId::random(),
                };
                pool.install(|| {
                    ArchivalMutatorSetRequest::solve(
                        block_hash,
                        0,
                        party(1),
                        party(2),
                        target,
                        seed,
                    )
                });
            }
            println!(
                "2^22 work, pool of {threads}: {:?} per ticket",
                start.elapsed() / 4
            );
        }
    }

    #[test]
    fn archival_mutator_set_target_caps_the_last_digest_element() {
        let mut on_target = [BFieldElement::new(BFieldElement::MAX); Digest::LEN];
        on_target[Digest::LEN - 1] = BFieldElement::new(BFieldElement::MAX >> 26);
        let mut above_target = [BFieldElement::new(0); Digest::LEN];
        above_target[Digest::LEN - 1] = BFieldElement::new((BFieldElement::MAX >> 26) + 1);

        let target = ArchivalMutatorSetRequest::target(26);
        assert!(Digest(on_target) <= target);
        assert!(Digest(above_target) > target);
        let target = ArchivalMutatorSetRequest::target(0);
        assert!(Digest(above_target) <= target, "every digest meets it");
    }

    #[test]
    fn a_stream_takes_one_frame_per_started_frame_length() {
        let frame = ARCHIVAL_MUTATOR_SET_FRAME_BYTES as u64;
        assert_eq!(1, ArchivalMutatorSetRequest::num_frames(0));
        assert_eq!(1, ArchivalMutatorSetRequest::num_frames(frame));
        assert_eq!(2, ArchivalMutatorSetRequest::num_frames(frame + 1));
    }
}
