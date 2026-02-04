use std::fmt::Display;
use std::ops::Deref;
use std::time::SystemTime;

use arraystring::typenum::U255;
use arraystring::typenum::U30;
use arraystring::ArrayString;
use serde::Deserialize;
use serde::Serialize;

use crate::application::config::network::Network;
use crate::application::loops::connect_to_peers::PEER_TIME_DIFFERENCE_THRESHOLD;
use crate::protocol::consensus::block::block_header::BlockHeader;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionString(ArrayString<U30>);

impl Deref for VersionString {
    type Target = ArrayString<U30>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for VersionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl VersionString {
    pub(crate) fn new_from_str(s: &str) -> Self {
        let array_string = ArrayString::<U30>::from_chars(s.chars());
        Self(array_string)
    }

    pub(crate) fn versions_are_compatible(own: Self, other: Self) -> bool {
        let own = semver::Version::parse(&own)
            .unwrap_or_else(|_| panic!("Must be able to parse own version string. Got: {own}"));
        let Ok(other) = semver::Version::parse(&other) else {
            return false;
        };

        // All alphanet and betanet versions are incompatible with each other.
        // Alpha and betanet have versions "0.0.n". Alpha and betanet are
        // incompatible with all other versions.
        if own.major == 0 && own.minor == 0 || other.major == 0 && other.minor == 0 {
            return own == other;
        }

        // Cannot connect two different versions on either side of 0.5.
        if own.major == 0 && other.major == 0 {
            let own_is_less = own.minor <= 5;
            let other_is_more = other.minor > 5;
            if own_is_less && other_is_more {
                return false;
            }

            let own_is_more = own.minor > 5;
            let other_is_less = other.minor <= 5;
            if own_is_more && other_is_less {
                return false;
            }
        }

        true
    }
}

pub type ExtraDataString = ArrayString<U255>;

/// Datastruct defining the handshake peers exchange when establishing a new
/// connection.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandshakeData {
    pub tip_header: BlockHeader,
    pub listen_port: Option<u16>,
    pub network: Network,
    pub instance_id: u128,
    pub version: VersionString,
    pub is_archival_node: bool,

    /// Indicates whether node acts as a bootstrapping node in a network
    /// context.
    pub is_bootstrapper_node: bool,

    /// Client's timestamp when the handshake was generated. Can be used to
    /// compare own timestamp to peer's or to a list of peers.
    pub timestamp: SystemTime,

    /// Use this field to add extra data in a backwards compatible manner. An
    /// encoding should be selected for this. Currently unused.
    pub extra_data: ExtraDataString,
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
pub(crate) enum HandshakeValidationError {
    #[error("connect to self")]
    SelfConnect,

    #[error("local network ({local}) =/= remote network {remote}")]
    NetworkMismatch { local: Network, remote: Network },

    #[error("local version ({local}) is incompatible with remote version ({remote})")]
    IncompatibleVersion {
        local: VersionString,
        remote: VersionString,
    },

    #[error("clock difference between local and remote too large")]
    ExcessiveClockDifference {
        local: SystemTime,
        remote: SystemTime,
    },
}

impl HandshakeData {
    /// Determine whether two handshakes are compatible.
    pub(crate) fn validate(
        local_handshake: &HandshakeData,
        remote_handshake: &HandshakeData,
    ) -> Result<(), HandshakeValidationError> {
        // Instance ID
        if local_handshake.instance_id == remote_handshake.instance_id {
            return Err(HandshakeValidationError::SelfConnect);
        }

        // Network
        if local_handshake.network != remote_handshake.network {
            return Err(HandshakeValidationError::NetworkMismatch {
                local: local_handshake.network,
                remote: remote_handshake.network,
            });
        }

        // Versions
        if !VersionString::versions_are_compatible(
            local_handshake.version,
            remote_handshake.version,
        ) {
            return Err(HandshakeValidationError::IncompatibleVersion {
                local: local_handshake.version,
                remote: remote_handshake.version,
            });
        }

        // Time difference
        let lag = remote_handshake
            .timestamp
            .duration_since(local_handshake.timestamp)
            .ok();
        let front = local_handshake
            .timestamp
            .duration_since(remote_handshake.timestamp)
            .ok();
        let absolute_time_delta = lag.unwrap_or_else(|| front.unwrap());
        if absolute_time_delta > PEER_TIME_DIFFERENCE_THRESHOLD {
            return Err(HandshakeValidationError::ExcessiveClockDifference {
                local: local_handshake.timestamp,
                remote: remote_handshake.timestamp,
            });
        }

        Ok(())
    }
}

// #[cfg(any(test, feature = "arbitrary-impls"))]
#[cfg(test)]
pub(crate) mod test {
    use std::time::Duration;

    use proptest::collection::vec;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest::prop_assert_eq;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;
    use crate::api::export::BlockHeight;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;

    impl VersionString {
        /// Generate a version string that is guaranteed to parse correctly.
        pub(crate) fn arbitrary_semver() -> BoxedStrategy<Self> {
            (0..5, 0..50, 0..200)
                .prop_map(|(major, minor, point)| {
                    Self::new_from_str(&format!("{major}.{minor}.{point}"))
                })
                .boxed()
        }
    }

    pub(crate) fn arbitrary_extra_data_string() -> BoxedStrategy<ExtraDataString> {
        vec(0u8..=u8::MAX, 256)
            .prop_map(|bytes| ExtraDataString::from_chars(bytes.into_iter().map(|b| b as char)))
            .boxed()
    }

    impl HandshakeData {
        pub(crate) fn arbitrary() -> BoxedStrategy<Self> {
            let height_strategy = arb::<BlockHeight>();
            let difficulty_strategy = arb::<Difficulty>();

            (height_strategy, difficulty_strategy)
                .prop_flat_map(|(height, difficulty)| {
                    let block_header_strategy =
                        BlockHeader::arbitrary_with_height_and_difficulty(height, difficulty);
                    let port_option_strategy = arb::<bool>();
                    let port_strategy = 0u16..=u16::MAX;
                    let network_strategy = Network::arbitrary();
                    let instance_id_strategy = 0u128..u128::MAX;
                    let version_string_strategy = VersionString::arbitrary_semver();
                    let is_archival_strategy = arb::<bool>();
                    let is_bootstrapper_strategy = arb::<bool>();
                    let timestamp_strategy = arb::<i64>().prop_map(|offset| {
                        let now = SystemTime::now();
                        if offset > 0 {
                            now + Duration::from_secs(offset as u64 % 315360000)
                        } else {
                            now - Duration::from_secs(offset.unsigned_abs() % 315360000)
                        }
                    });
                    let extra_data_strategy = arbitrary_extra_data_string();

                    (
                        block_header_strategy,
                        port_option_strategy,
                        port_strategy,
                        network_strategy,
                        instance_id_strategy,
                        version_string_strategy,
                        is_archival_strategy,
                        is_bootstrapper_strategy,
                        timestamp_strategy,
                        extra_data_strategy,
                    )
                        .prop_map(
                            |(
                                block_header,
                                port_option,
                                port,
                                network,
                                instance_id,
                                version_string,
                                is_archival,
                                is_bootstrapper,
                                timestamp,
                                extra_data,
                            )| {
                                HandshakeData {
                                    tip_header: block_header,
                                    listen_port: if port_option { Some(port) } else { None },
                                    network,
                                    instance_id,
                                    version: version_string,
                                    is_archival_node: is_archival,
                                    is_bootstrapper_node: is_bootstrapper,
                                    timestamp,
                                    extra_data,
                                }
                            },
                        )
                })
                .boxed()
        }
    }

    #[test]
    fn malformed_version_from_peer_doesnt_crash() {
        let version_numbers = ["potato", "&&&&"];
        for b in version_numbers {
            assert!(!VersionString::versions_are_compatible(
                VersionString::new_from_str("0.1.0"),
                VersionString::new_from_str(b)
            ));
        }
    }

    #[test]
    fn v0_5_0_and_0_6_0_are_incompatible() {
        assert!(!VersionString::versions_are_compatible(
            VersionString::new_from_str("0.6.0"),
            VersionString::new_from_str("0.5.0")
        ));
        assert!(!VersionString::versions_are_compatible(
            VersionString::new_from_str("0.5.0"),
            VersionString::new_from_str("0.6.0")
        ));
    }

    #[test]
    fn versions_are_compatible_for_all_versions_above_0_6_() {
        let version_numbers = [
            "0.6.0",
            "0.6.1",
            "0.6.99",
            "0.7.0",
            "1.2.0",
            "2.2.0",
            "3.2.0",
            "9999.99999.9999",
        ];
        for a in version_numbers {
            let a = VersionString::new_from_str(a);
            for b in version_numbers {
                let b = VersionString::new_from_str(b);
                assert!(VersionString::versions_are_compatible(a, b));
            }
        }
    }

    #[proptest(cases = 5)]
    fn handshake_with_self_fails_because_of_instance_id(
        #[strategy(HandshakeData::arbitrary())] handshake_data: HandshakeData,
    ) {
        let handshake_failure =
            HandshakeData::validate(&handshake_data, &handshake_data).unwrap_err();
        prop_assert_eq!(handshake_failure, HandshakeValidationError::SelfConnect,);

        let mut clone_up_to_instance_id = handshake_data;
        clone_up_to_instance_id.instance_id =
            u128::wrapping_add(clone_up_to_instance_id.instance_id, 1);
        let handshake_success = HandshakeData::validate(&handshake_data, &clone_up_to_instance_id);
        prop_assert_eq!(Ok(()), handshake_success);
    }
}
