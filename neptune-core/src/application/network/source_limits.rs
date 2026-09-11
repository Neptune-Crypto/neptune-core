//! Per-source limits on inbound libp2p connections, enforced before any
//! cryptography runs.
//!
//! Three limits, each keyed on the address a connection actually arrives
//! from: how many connections one IP may hold, how many one prefix (`/24` for
//! IPv4, `/64` for IPv6) may hold, and how many attempts one IP may make per
//! minute.
//!
//! Relayed connections have no attributable address and pass untouched; the
//! global pending-connection cap covers those. A hole-punched connection has
//! one, and is counted on the side that acts as its listener.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt;
use std::net::IpAddr;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use libp2p::core::transport::PortUse;
use libp2p::core::Endpoint;
use libp2p::swarm::dummy;
use libp2p::swarm::ConnectionDenied;
use libp2p::swarm::ConnectionId;
use libp2p::swarm::FromSwarm;
use libp2p::swarm::NetworkBehaviour;
use libp2p::swarm::THandler;
use libp2p::swarm::THandlerInEvent;
use libp2p::swarm::THandlerOutEvent;
use libp2p::swarm::ToSwarm;
use libp2p::Multiaddr;
use libp2p::PeerId;

use super::observed_ips::attributable_ip;

const RATE_WINDOW: Duration = Duration::from_secs(60);

/// The limits to apply. `None` disables that limit.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SourceLimitsConfig {
    pub(crate) max_per_ip: Option<usize>,
    pub(crate) max_per_prefix: Option<usize>,
    pub(crate) max_attempts_per_minute: Option<usize>,
}

/// Why an inbound connection was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalReason {
    PerIp { ip: IpAddr, limit: usize },
    PerPrefix { ip: IpAddr, limit: usize },
    AttemptsPerMinute { ip: IpAddr, limit: usize },
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerIp { ip, limit } => write!(f, "{ip} already holds {limit} connections"),
            Self::PerPrefix { ip, limit } => {
                write!(f, "the prefix of {ip} already holds {limit} connections")
            }
            Self::AttemptsPerMinute { ip, limit } => {
                write!(f, "{ip} made {limit} connection attempts within a minute")
            }
        }
    }
}

impl std::error::Error for RefusalReason {}

/// A `/24` or `/64`, the granularity at which one operator usually controls
/// addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Prefix {
    V4([u8; 3]),
    V6([u8; 8]),
}

impl Prefix {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let [a, b, c, _] = v4.octets();
                Self::V4([a, b, c])
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                Self::V6(octets[..8].try_into().expect("eight of sixteen octets"))
            }
        }
    }
}

/// The counting behind [`SourceLimits`], kept free of libp2p so that it can be
/// tested in isolation.
#[derive(Debug)]
struct SourceCounts {
    config: SourceLimitsConfig,
    by_ip: HashMap<IpAddr, usize>,
    by_prefix: HashMap<Prefix, usize>,

    /// The IP each tracked connection is associated with: the canonical form of
    /// the one IP a direct address names. Relayed addresses name the relay's
    /// IP and are never counted.
    connections: HashMap<ConnectionId, IpAddr>,

    attempts: HashMap<IpAddr, VecDeque<Instant>>,
}

impl SourceCounts {
    fn new(config: SourceLimitsConfig) -> Self {
        Self {
            config,
            by_ip: HashMap::new(),
            by_prefix: HashMap::new(),
            connections: HashMap::new(),
            attempts: HashMap::new(),
        }
    }

    /// Admit a connection attributed to `ip`, or say why not. On success the
    /// connection is counted against the per-IP and per-prefix limits until
    /// [`Self::release`] is called with its id. Every attempt, admitted or not,
    /// counts toward the rate limit.
    fn admit(&mut self, id: ConnectionId, ip: IpAddr, now: Instant) -> Result<(), RefusalReason> {
        let ip = ip.to_canonical();

        let attempts = self.attempts.entry(ip).or_default();
        while attempts
            .front()
            .is_some_and(|&t| now.duration_since(t) >= RATE_WINDOW)
        {
            attempts.pop_front();
        }
        attempts.push_back(now);
        if let Some(limit) = self.config.max_attempts_per_minute {
            if attempts.len() > limit {
                return Err(RefusalReason::AttemptsPerMinute { ip, limit });
            }
        }

        if let Some(limit) = self.config.max_per_ip {
            if self.by_ip.get(&ip).copied().unwrap_or(0) >= limit {
                return Err(RefusalReason::PerIp { ip, limit });
            }
        }
        let prefix = Prefix::of(ip);
        if let Some(limit) = self.config.max_per_prefix {
            if self.by_prefix.get(&prefix).copied().unwrap_or(0) >= limit {
                return Err(RefusalReason::PerPrefix { ip, limit });
            }
        }

        *self.by_ip.entry(ip).or_default() += 1;
        *self.by_prefix.entry(prefix).or_default() += 1;
        self.connections.insert(id, ip);
        Ok(())
    }

    /// Stop counting a connection, whether it failed while pending or closed
    /// after being established. Unknown ids are ignored.
    fn release(&mut self, id: ConnectionId) {
        let Some(ip) = self.connections.remove(&id) else {
            return;
        };
        if let Some(count) = self.by_ip.get_mut(&ip) {
            *count -= 1;
            if *count == 0 {
                self.by_ip.remove(&ip);
            }
        }
        let prefix = Prefix::of(ip);
        if let Some(count) = self.by_prefix.get_mut(&prefix) {
            *count -= 1;
            if *count == 0 {
                self.by_prefix.remove(&prefix);
            }
        }
    }

    /// Forget attempt histories that have aged out of the window.
    fn prune(&mut self, now: Instant) {
        self.attempts.retain(|_, attempts| {
            attempts
                .back()
                .is_some_and(|&t| now.duration_since(t) < RATE_WINDOW)
        });
    }
}

/// A [`NetworkBehaviour`] that refuses inbound connections exceeding the
/// per-source limits, from `handle_pending_inbound_connection`, i.e. before
/// the transport upgrade.
#[derive(Debug)]
pub(crate) struct SourceLimits {
    counts: SourceCounts,
}

impl SourceLimits {
    pub(crate) fn new(config: SourceLimitsConfig) -> Self {
        Self {
            counts: SourceCounts::new(config),
        }
    }

    /// Drop stale rate-limit state; call periodically.
    pub(crate) fn prune(&mut self) {
        self.counts.prune(Instant::now());
    }
}

impl NetworkBehaviour for SourceLimits {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        let Some(ip) = attributable_ip(remote_addr) else {
            return Ok(());
        };

        self.counts
            .admit(connection_id, ip, Instant::now())
            .map_err(ConnectionDenied::new)
    }

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        _peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        // A hole punch is dialed from both sides. The side that ends up as
        // listener counts the connection, as it would have had the remote
        // connected directly.
        if role_override == Endpoint::Listener {
            if let Some(ip) = attributable_ip(addr) {
                self.counts
                    .admit(connection_id, ip, Instant::now())
                    .map_err(ConnectionDenied::new)?;
            }
        }

        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        match event {
            FromSwarm::ConnectionClosed(closed) => self.counts.release(closed.connection_id),
            FromSwarm::ListenFailure(failure) => self.counts.release(failure.connection_id),
            FromSwarm::DialFailure(failure) => self.counts.release(failure.connection_id),
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn counts(per_ip: usize, per_prefix: usize, per_minute: usize) -> SourceCounts {
        SourceCounts::new(SourceLimitsConfig {
            max_per_ip: Some(per_ip),
            max_per_prefix: Some(per_prefix),
            max_attempts_per_minute: Some(per_minute),
        })
    }

    fn id(n: usize) -> ConnectionId {
        ConnectionId::new_unchecked(n)
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4([203, 0, 113, last].into())
    }

    #[test]
    fn one_ip_is_capped_and_freed_by_release() {
        let mut counts = counts(2, 100, 100);
        let now = Instant::now();
        assert_eq!(Ok(()), counts.admit(id(1), ip(1), now));
        assert_eq!(Ok(()), counts.admit(id(2), ip(1), now));
        assert_eq!(
            Err(RefusalReason::PerIp {
                ip: ip(1),
                limit: 2
            }),
            counts.admit(id(3), ip(1), now)
        );
        assert_eq!(Ok(()), counts.admit(id(4), ip(2), now));

        counts.release(id(1));
        assert_eq!(Ok(()), counts.admit(id(5), ip(1), now));
    }

    #[test]
    fn a_prefix_is_capped_across_its_ips() {
        let mut counts = counts(100, 3, 100);
        let now = Instant::now();
        for n in 1..=3 {
            assert_eq!(Ok(()), counts.admit(id(n), ip(n as u8), now));
        }
        assert_eq!(
            Err(RefusalReason::PerPrefix {
                ip: ip(4),
                limit: 3
            }),
            counts.admit(id(4), ip(4), now)
        );
        let elsewhere = IpAddr::V4([198, 51, 100, 1].into());
        assert_eq!(Ok(()), counts.admit(id(5), elsewhere, now));
    }

    #[test]
    fn attempts_are_rate_limited_per_minute() {
        let mut counts = counts(100, 100, 3);
        let start = Instant::now();
        for n in 1..=3 {
            assert_eq!(Ok(()), counts.admit(id(n), ip(1), start));
            counts.release(id(n));
        }
        assert_eq!(
            Err(RefusalReason::AttemptsPerMinute {
                ip: ip(1),
                limit: 3
            }),
            counts.admit(id(4), ip(1), start + Duration::from_secs(30))
        );
        assert_eq!(Ok(()), counts.admit(id(5), ip(1), start + RATE_WINDOW));
    }

    #[test]
    fn refused_attempts_still_count_toward_the_rate() {
        let mut counts = counts(1, 100, 3);
        let now = Instant::now();
        assert_eq!(Ok(()), counts.admit(id(1), ip(1), now));
        assert!(counts.admit(id(2), ip(1), now).is_err());
        assert!(counts.admit(id(3), ip(1), now).is_err());
        assert_eq!(
            Err(RefusalReason::AttemptsPerMinute {
                ip: ip(1),
                limit: 3
            }),
            counts.admit(id(4), ip(1), now)
        );
    }

    #[test]
    fn a_disabled_limit_never_refuses() {
        let mut counts = SourceCounts::new(SourceLimitsConfig::default());
        let now = Instant::now();
        for n in 1..=50 {
            assert_eq!(Ok(()), counts.admit(id(n), ip(1), now));
        }
    }

    #[test]
    fn a_mapped_v4_address_counts_as_its_v4() {
        let mut counts = counts(1, 100, 100);
        let now = Instant::now();
        assert_eq!(Ok(()), counts.admit(id(1), ip(1), now));
        let mapped = IpAddr::V6(std::net::Ipv4Addr::new(203, 0, 113, 1).to_ipv6_mapped());
        assert_eq!(
            Err(RefusalReason::PerIp {
                ip: ip(1),
                limit: 1
            }),
            counts.admit(id(2), mapped, now)
        );
    }

    #[test]
    fn pruning_forgets_aged_attempt_histories() {
        let mut counts = counts(100, 100, 100);
        let start = Instant::now();
        assert_eq!(Ok(()), counts.admit(id(1), ip(1), start));
        counts.prune(start + Duration::from_secs(1));
        assert_eq!(1, counts.attempts.len());
        counts.prune(start + RATE_WINDOW);
        assert!(counts.attempts.is_empty());
    }

    #[test]
    fn releasing_an_unknown_id_is_harmless() {
        let mut counts = counts(1, 1, 1);
        counts.release(id(99));
    }
}
