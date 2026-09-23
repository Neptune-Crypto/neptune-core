//! Bookkeeping of objects announced by peers that have been requested but not
//! yet received.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Duration;
use std::time::SystemTime;

use libp2p::PeerId;
use neptune_mempool::transaction_kernel_id::TransactionKernelId;
use neptune_mempool::transaction_proof_quality::TransactionProofQuality;
use neptune_primitives::block_height::BlockHeight;
use tasm_lib::prelude::Digest;

/// How long a request counts as pending. After this, the object is requested
/// from the next peer that announced it.
pub(crate) const PENDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How many requests may be in flight to one peer at a time. Further objects
/// the peer announced wait until earlier requests are answered or go stale.
const MAX_IN_FLIGHT_PER_PEER: usize = 20;

/// How many pending objects one peer may be involved in, as announcer or as
/// the peer a request is in flight to. Announcements beyond this are dropped.
const MAX_PENDING_PER_PEER: usize = 200;

/// An object that peers announce and that can then be requested from them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum AnnouncedObject {
    Block {
        hash: Digest,
        height: BlockHeight,
    },
    BlockProposal(Digest),
    Transaction {
        txid: TransactionKernelId,
        proof_quality: TransactionProofQuality,
        mutator_set_hash: Digest,
    },
}

/// A peer that announced an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Announcer {
    pub(crate) peer: PeerId,

    /// Whether the peer initiated the connection to the node.
    pub(crate) inbound: bool,
}

#[derive(Debug, Clone)]
struct PendingRequest {
    /// The peer the object was last requested from, and when. `None` if the
    /// peer disconnects without responding with the object, or if the object
    /// has not been requested yet.
    in_flight: Option<(PeerId, SystemTime)>,

    /// Peers that announced the object and have not been asked for it, most
    /// preferred first.
    announcers: VecDeque<Announcer>,
}

impl PendingRequest {
    /// Whether a request is expected to not be delivered on by already sent
    /// request.
    ///
    /// Returns true if no request is in flight, or one has not been delivered
    /// on within the timeout.
    fn is_stale(&self, now: SystemTime) -> bool {
        self.in_flight.is_none_or(|(_, since)| {
            now.duration_since(since)
                .is_ok_and(|elapsed| elapsed >= PENDING_REQUEST_TIMEOUT)
        })
    }

    fn involves(&self, peer: PeerId) -> bool {
        self.in_flight
            .is_some_and(|(in_flight, _)| in_flight == peer)
            || self
                .announcers
                .iter()
                .any(|announcer| announcer.peer == peer)
    }
}

/// How many pending objects a peer is involved in.
#[derive(Debug, Clone, Copy, Default)]
struct PeerLoad {
    in_flight: usize,
    pending: usize,
}

/// Requests for announced objects that have been sent to peers but not yet
/// answered.
///
/// Every peer announces the same new object, so without this bookkeeping, the
/// node would receive many copies of the same object. An object is requested
/// from the most preferred peer to announce it, either because it was first to
/// announce it, or because the peer that announced it is preferred for some
/// other reason. Later announcers are remembered as fallbacks and take over,
/// one at a time, if the request is not answered within
/// [`PENDING_REQUEST_TIMEOUT`].
///
/// Per peer, at most [`MAX_IN_FLIGHT_PER_PEER`] requests are in flight and at
/// most [`MAX_PENDING_PER_PEER`] objects are tracked, so that no peer can
/// grow this structure, or the number of requests sent to it, without bound.
#[derive(Debug, Clone, Default)]
pub(crate) struct PendingRequests {
    requests: HashMap<AnnouncedObject, PendingRequest>,
    loads: HashMap<PeerId, PeerLoad>,
}

impl PendingRequests {
    /// Record that `announcer` announced `object`. Returns `true` if the
    /// caller should request the object from the announcer now. Returns
    /// `false` if the request should wait, in which case the announcer is
    /// remembered and gets its turn through [`Self::due_requests`], or if the
    /// announcement was dropped because the announcer is involved in too many
    /// pending objects already.
    pub(crate) fn record_announcement(
        &mut self,
        object: AnnouncedObject,
        announcer: Announcer,
        now: SystemTime,
    ) -> bool {
        let Self { requests, loads } = self;
        let peer = announcer.peer;

        if loads
            .get(&peer)
            .is_some_and(|load| load.pending >= MAX_PENDING_PER_PEER)
        {
            return false;
        }

        let pending = requests.entry(object).or_insert_with(|| PendingRequest {
            in_flight: None,
            announcers: VecDeque::new(),
        });
        if pending.involves(peer) {
            // Don't request or re-record on repeated announcements
            return false;
        }

        loads.entry(peer).or_default().pending += 1;
        let position = if announcer.inbound {
            // Goes to the back of the queue
            pending.announcers.len()
        } else {
            // Goes to the last position for all outbound announcers
            pending
                .announcers
                .iter()
                .position(|queued| queued.inbound)
                .unwrap_or(pending.announcers.len())
        };
        pending.announcers.insert(position, announcer);

        Self::request_now(pending, loads, peer, now)
    }

    /// Every object that `peer` should request now: those it is the most
    /// preferred announcer of, and that are not in flight to a peer that is
    /// still expected to deliver, up to capacity.
    ///
    /// Stale requests without remaining announcers are forgotten.
    pub(crate) fn due_requests(&mut self, peer: PeerId, now: SystemTime) -> Vec<AnnouncedObject> {
        let Self { requests, loads } = self;
        let mut due = vec![];
        requests.retain(|object, pending| {
            if pending.is_stale(now) && pending.announcers.is_empty() {
                if let Some((stale_peer, _)) = pending.in_flight {
                    Self::release_in_flight(loads, stale_peer);
                }
                return false;
            }

            if Self::request_now(pending, loads, peer, now) {
                due.push(*object);
            }
            true
        });

        due
    }

    /// Record that an object was received.
    pub(crate) fn resolve(&mut self, object: &AnnouncedObject) {
        let Some(pending) = self.requests.remove(object) else {
            return;
        };

        if let Some((in_flight, _)) = pending.in_flight {
            Self::release_in_flight(&mut self.loads, in_flight);
        }
        for announcer in pending.announcers {
            Self::release_pending(&mut self.loads, announcer.peer);
        }
    }

    /// Forget peer because it disconnected. Requests in flight to it are
    /// left for the fallbacks to take over.
    pub(crate) fn forget_peer(&mut self, peer: PeerId) {
        self.loads.remove(&peer);
        self.requests.retain(|_, pending| {
            pending
                .announcers
                .retain(|announcer| announcer.peer != peer);
            if pending
                .in_flight
                .is_some_and(|(requested_from, _)| requested_from == peer)
            {
                pending.in_flight = None;
            }
            pending.in_flight.is_some() || !pending.announcers.is_empty()
        });
    }

    /// Return whether the peer is the most preferred announcer, whether it
    /// should request the object now. Marks the request for an object as in
    /// flight to this peer if that's the case.
    ///
    /// Returns false otherwise.
    fn request_now(
        pending: &mut PendingRequest,
        loads: &mut HashMap<PeerId, PeerLoad>,
        peer: PeerId,
        now: SystemTime,
    ) -> bool {
        if !pending.is_stale(now) {
            return false;
        }
        let Some(next) = pending.announcers.front() else {
            return false;
        };
        if next.peer != peer {
            return false;
        }
        if loads
            .get(&peer)
            .is_some_and(|load| load.in_flight >= MAX_IN_FLIGHT_PER_PEER)
        {
            return false;
        }

        if let Some((stale_peer, _)) = pending.in_flight.take() {
            Self::release_in_flight(loads, stale_peer);
        }
        pending.announcers.pop_front();
        pending.in_flight = Some((peer, now));
        loads.entry(peer).or_default().in_flight += 1;

        true
    }

    fn release_in_flight(loads: &mut HashMap<PeerId, PeerLoad>, peer: PeerId) {
        if let Some(load) = loads.get_mut(&peer) {
            load.in_flight = load.in_flight.saturating_sub(1);
        }
        Self::release_pending(loads, peer);
    }

    fn release_pending(loads: &mut HashMap<PeerId, PeerLoad>, peer: PeerId) {
        if let Some(load) = loads.get_mut(&peer) {
            load.pending = load.pending.saturating_sub(1);
            if load.pending == 0 {
                loads.remove(&peer);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::random;

    use super::*;

    /// A random block announcement
    fn block() -> AnnouncedObject {
        AnnouncedObject::Block {
            hash: random(),
            height: BlockHeight::from(random::<u64>()),
        }
    }

    fn outbound() -> Announcer {
        Announcer {
            peer: PeerId::random(),
            inbound: false,
        }
    }

    fn inbound() -> Announcer {
        Announcer {
            peer: PeerId::random(),
            inbound: true,
        }
    }

    #[test]
    fn same_object_is_requested_once_until_resolved() {
        let mut pending = PendingRequests::default();
        let (alice, bob) = (outbound(), outbound());
        let block = block();
        let now = SystemTime::now();

        assert!(pending.record_announcement(block, alice, now));
        assert!(!pending.record_announcement(block, bob, now));
        assert!(pending.due_requests(bob.peer, now).is_empty());

        pending.resolve(&block);
        assert!(pending.record_announcement(block, bob, now));
        assert!(pending.loads[&bob.peer].in_flight == 1);
        assert!(!pending.loads.contains_key(&alice.peer));
    }

    #[test]
    fn distinct_objects_do_not_block_each_other() {
        let mut pending = PendingRequests::default();
        let alice = outbound();
        let now = SystemTime::now();

        assert!(pending.record_announcement(block(), alice, now));
        assert!(pending.record_announcement(AnnouncedObject::BlockProposal(random()), alice, now));
    }

    #[test]
    fn fallbacks_take_over_stale_requests_one_at_a_time() {
        let mut pending = PendingRequests::default();
        let (alice, bob, carol) = (outbound(), outbound(), outbound());
        let proposal = AnnouncedObject::BlockProposal(random());
        let then = SystemTime::now();

        assert!(pending.record_announcement(proposal, alice, then));
        assert!(!pending.record_announcement(proposal, bob, then));
        assert!(!pending.record_announcement(proposal, carol, then));

        // Nothing is stale yet.
        let soon = then + PENDING_REQUEST_TIMEOUT / 2;
        assert!(pending.due_requests(bob.peer, soon).is_empty());
        assert!(pending.due_requests(carol.peer, soon).is_empty());

        // Bob announced first, so bob takes over; carol keeps waiting.
        let later = then + PENDING_REQUEST_TIMEOUT;
        assert!(pending.due_requests(carol.peer, later).is_empty());
        assert_eq!(vec![proposal], pending.due_requests(bob.peer, later));
        assert!(pending.due_requests(bob.peer, later).is_empty());
        assert!(!pending.loads.contains_key(&alice.peer));

        // Bob stalls too, so carol takes over.
        let latest = later + PENDING_REQUEST_TIMEOUT;
        assert_eq!(vec![proposal], pending.due_requests(carol.peer, latest));

        // Nobody is left to take over from carol; the request is forgotten.
        let end = latest + PENDING_REQUEST_TIMEOUT;
        assert!(pending.due_requests(alice.peer, end).is_empty());
        assert!(pending.requests.is_empty());
        assert!(pending.loads.is_empty());
    }

    #[test]
    fn stale_request_may_be_repeated_by_new_announcer() {
        let mut pending = PendingRequests::default();
        let (alice, bob) = (outbound(), outbound());
        let block = block();
        let then = SystemTime::now();

        assert!(pending.record_announcement(block, alice, then));
        assert!(!pending.record_announcement(block, bob, then + PENDING_REQUEST_TIMEOUT / 2));

        // Bob is a fallback already, so announcing again changes nothing, but
        // bob's turn comes on the tick.
        let later = then + PENDING_REQUEST_TIMEOUT;
        assert!(!pending.record_announcement(block, bob, later));
        assert_eq!(vec![block], pending.due_requests(bob.peer, later));
    }

    #[test]
    fn outbound_fallbacks_are_preferred_over_earlier_inbound_ones() {
        let mut pending = PendingRequests::default();
        let (alice, bob, carol) = (outbound(), inbound(), outbound());
        let block = block();
        let then = SystemTime::now();

        assert!(pending.record_announcement(block, alice, then));
        assert!(!pending.record_announcement(block, bob, then));
        assert!(!pending.record_announcement(block, carol, then));

        let later = then + PENDING_REQUEST_TIMEOUT;
        assert!(pending.due_requests(bob.peer, later).is_empty());
        assert_eq!(vec![block], pending.due_requests(carol.peer, later));
    }

    #[test]
    fn requests_in_flight_per_peer_are_capped_and_queued() {
        let mut pending = PendingRequests::default();
        let alice = outbound();
        let now = SystemTime::now();

        let blocks: Vec<_> = (0..MAX_IN_FLIGHT_PER_PEER + 2).map(|_| block()).collect();
        for block in &blocks[..MAX_IN_FLIGHT_PER_PEER] {
            assert!(pending.record_announcement(*block, alice, now));
        }

        // The cap is reached, so further announcements queue up.
        assert!(!pending.record_announcement(blocks[MAX_IN_FLIGHT_PER_PEER], alice, now));
        assert!(!pending.record_announcement(blocks[MAX_IN_FLIGHT_PER_PEER + 1], alice, now));
        assert!(pending.due_requests(alice.peer, now).is_empty());

        // Receiving one object frees one slot, filled on the next tick.
        pending.resolve(&blocks[0]);
        let due = pending.due_requests(alice.peer, now);
        assert_eq!(1, due.len());
        assert!(blocks[MAX_IN_FLIGHT_PER_PEER..].contains(&due[0]));

        // Stale requests free their slots too.
        let later = now + PENDING_REQUEST_TIMEOUT;
        let due_after_timeout = pending.due_requests(alice.peer, later);
        assert_eq!(1, due_after_timeout.len());
        assert!(blocks[MAX_IN_FLIGHT_PER_PEER..].contains(&due_after_timeout[0]));
        assert!(pending.loads[&alice.peer].in_flight <= MAX_IN_FLIGHT_PER_PEER);
    }

    #[test]
    fn announcements_beyond_the_pending_cap_are_dropped() {
        let mut pending = PendingRequests::default();
        let (alice, bob) = (outbound(), outbound());
        let now = SystemTime::now();

        for _ in 0..MAX_PENDING_PER_PEER {
            pending.record_announcement(block(), alice, now);
        }
        assert_eq!(MAX_PENDING_PER_PEER, pending.loads[&alice.peer].pending);

        let one_too_many = block();
        assert!(!pending.record_announcement(one_too_many, alice, now));
        assert!(!pending.requests.contains_key(&one_too_many));

        // Another peer is unaffected.
        assert!(pending.record_announcement(one_too_many, bob, now));
    }

    #[test]
    fn disconnected_peer_hands_over_to_fallback_immediately() {
        let mut pending = PendingRequests::default();
        let (alice, bob) = (outbound(), outbound());
        let block = block();
        let now = SystemTime::now();

        assert!(pending.record_announcement(block, alice, now));
        assert!(!pending.record_announcement(block, bob, now));

        pending.forget_peer(alice.peer);
        assert_eq!(vec![block], pending.due_requests(bob.peer, now));
        assert!(!pending.loads.contains_key(&alice.peer));
    }

    #[test]
    fn disconnected_peer_without_fallbacks_is_forgotten() {
        let mut pending = PendingRequests::default();
        let (alice, bob) = (outbound(), outbound());
        let block_from_alice = block();
        let block_from_bob = block();
        let now = SystemTime::now();

        assert!(pending.record_announcement(block_from_alice, alice, now));
        assert!(pending.record_announcement(block_from_bob, bob, now));

        pending.forget_peer(alice.peer);
        assert!(pending.record_announcement(block_from_alice, bob, now));
        assert!(!pending.record_announcement(block_from_bob, alice, now));
    }
}
