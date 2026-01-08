use std::time::SystemTime;

use arraystring::typenum::U255;
use arraystring::typenum::U30;
use arraystring::ArrayString;
use serde::Deserialize;
use serde::Serialize;

use crate::application::config::network::Network;
use crate::protocol::consensus::block::block_header::BlockHeader;

pub type VersionString = ArrayString<U30>;
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

// #[cfg(any(test, feature = "arbitrary-impls"))]
#[cfg(test)]
pub(crate) mod arbitrary {
    use std::time::Duration;

    use proptest::collection::vec;
    use proptest::prelude::BoxedStrategy;
    use proptest::prelude::Strategy;
    use proptest_arbitrary_interop::arb;

    use crate::api::export::BlockHeight;
    use crate::protocol::consensus::block::difficulty_control::Difficulty;

    use super::*;

    pub(crate) fn arbitrary_version_string() -> BoxedStrategy<VersionString> {
        vec(0u8..=u8::MAX, 31)
            .prop_map(|bytes| VersionString::from_chars(bytes.into_iter().map(|b| b as char)))
            .boxed()
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
                    let version_string_strategy = arbitrary_version_string();
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
}
