pub(crate) mod swarmutil;

use std::time::Duration;

use libp2p::{gossipsub::{self, IdentTopic}, identify, kad::{self, store::MemoryStore}, multiaddr::Protocol, noise, ping, request_response::{self, cbor}, swarm::{NetworkBehaviour, SwarmEvent}, yamux, Multiaddr, Swarm};

use crate::application::loops::main_loop::p2p::{BLOCK_SIZE, TOPIC_BLOCK, TOPIC_PROPOSAL, TOPIC_TX_PROOFCOL_NOTIF, TOPIC_TX_SINGLEPROOF, TX_SINGLEPROOF_SIZE};

#[derive(libp2p::swarm::NetworkBehaviour)]
struct ComposedBehaviour {
    pub relay_client: libp2p::relay::client::Behaviour,
    pub dcutr: libp2p::dcutr::Behaviour,
    
    // TODO `connection_limits`? Actually some settings for bootstrapping (archival?) nodes would be better. #beefyConfig
    
    /* @skaunov don't understand why the <doc/libp2p/swarm/behaviour/trait.NetworkBehaviour.html#custom-networkbehaviour-with-the-derive-macro> 
    example puts `identify` before `ping` as I only can see how it can use the others result in the reversed order. */
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub autonat_client: libp2p::autonat::v2::client::Behaviour,

    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    // pub reqresp: request_response::cbor::Behaviour<PeerMessage, PeerMessage>,
    
    pub autonat_server: libp2p::autonat::v2::server::Behaviour,
    /// - the `Default` is so measle that it's ok to add to every node
    /// - hence it is incapable to transfer any Neptune message
    /// - but is still useful for
    ///   - DCUTR signalling
    ///   - Gossiping metadata about the messages
    ///   - peer discovery (TODO account for this in peer exchange) #libp2p_reqresp_px  
    pub relay_server: libp2p::relay::Behaviour,
}
impl ComposedBehaviour {
    pub const PROTOCOL_VERSION: &str = "/neptune/0.0.1";
    
    pub fn new_swarm(local_keypair: libp2p::identity::Keypair) -> Swarm<ComposedBehaviour> {
        libp2p::SwarmBuilder::with_existing_identity(local_keypair).with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        ).unwrap().with_quic().with_dns().unwrap().with_relay_client(noise::Config::new, yamux::Config::default).unwrap()
        .with_behaviour(|kp, relay_behaviour| {
            let local_id = kp.public().into();
            ComposedBehaviour {
                relay_client: relay_behaviour,
                dcutr: libp2p::dcutr::Behaviour::new(local_id),
                
                // black list
                // connection limit

                ping: ping::Behaviour::new(Default::default()),
                identify: identify::Behaviour::new(identify::Config::new_with_signed_peer_record(
                    Self::PROTOCOL_VERSION.to_owned(), 
                    kp // we don't want someone to impose punishment on another peer
                )),
                autonat_client: Default::default(),
                // don't forget about TTL if storing something in this layer
                kad: kad::Behaviour::with_config(local_id, MemoryStore::new(local_id), {
                    let mut c = kad::Config::default();
                    c.set_record_filtering(kad::StoreInserts::FilterBoth);
                    c.set_max_packet_size(super::TX_PROOFCOL_SIZE); // ~~TODO check this takes bytes~~
                    // @skaunov own euristic: I want to be sure that it won't be gone until a next block (~5 minutes), so it's improbable that in an hour a block won't be mined
                    c.set_record_ttl(Some(Duration::from_hours(1)));
                    c.set_publication_interval(None);
                    c.disjoint_query_paths(true);
                    let timeout_query = Duration::from_mins(5);
                    c.set_query_timeout(timeout_query);
                    c.set_replication_interval(None);
                    c.set_substreams_timeout(timeout_query / 20);
                    c
                }),
                gossipsub: {
                    let mut b = gossipsub::Behaviour::new(
                        /* The primary reason for this choice is that we will need to hide a tx author anyway. A secondary reason is that 
                        until we don't get back to the signer for anything on the message the sig isn't useful as it's as good as signing
                        with an ephemeral key. */
                        gossipsub::MessageAuthenticity::RandomAuthor, 

                        match gossipsub::ConfigBuilder::default().validate_messages().validation_mode(gossipsub::ValidationMode::Permissive)
                        .idontwant_on_publish(true)
                        .set_topic_max_transmit_size(IdentTopic::new(TOPIC_BLOCK).hash(), BLOCK_SIZE)
                        .set_topic_max_transmit_size(IdentTopic::new(TOPIC_PROPOSAL).hash(), BLOCK_SIZE)
                        .set_topic_max_transmit_size(IdentTopic::new(TOPIC_TX_SINGLEPROOF).hash(), TX_SINGLEPROOF_SIZE)
                        /* Block size limit is enourmous ~~but they're rare~~. Txs are frequent, but for now there's a hope Gossip-sub can pull it out. So it's logical to allow 
                        proof collection backed the max size of single proofs. At least as starting point as for single proofs that might be occassional but for proof collections
                        casual if not frequent; and that might make a lot of difference.
                                @skaunov just remembered proposals: so not so rare. Still significantly infrequent than txs. */
                        .set_topic_max_transmit_size(
                            IdentTopic::new(crate::application::loops::main_loop::p2p::TOPIC_TX_PROOFCOL_).hash(), 
                            TX_SINGLEPROOF_SIZE
                        )
                        .set_topic_max_transmit_size(
                            IdentTopic::new(TOPIC_TX_PROOFCOL_NOTIF).hash(), 
                            (8 * 5 + 8 * 5 + 1 + 16 + 8 + 8) * 10 // `* 10` just to be on a safe side and account for overheads as it's so small
                        ).build() {
                            Ok(conf) => conf,
                            Err(e) => {
                                tracing::error!("couldn't `build` correct configuration |{e}");
                                tracing::info!("falling back to the default one");
                                debug_assert!(false);
                                Default::default()
                            }
                        }
                    ).expect("`privacy` & `ValidationMode` are compatible");
                    b.with_peer_score(Default::default(), Default::default()).expect("scoring is default; `gossipsub::Behaviour` is just instantiated");
                    b
                },
                /* ~~[10 MiB](https://docs.rs/libp2p/latest/libp2p/request_response/cbor/type.Behaviour.html#default-size-limits) seems good even for a batch of the block~~ */
                // reqresp: request_response::cbor::Behaviour::<PeerMessage, PeerMessage>::new(
                //     [(libp2p::StreamProtocol::new("/nept-reqresp"), request_response::ProtocolSupport::Full)],
                //     request_response::Config::default().with_request_timeout(
                //         /* probably a bad choice; yet relies just because a challenge request is valid for 45 secs; 
                //         TODO also needs to carry the block (10 of them?) */
                //         Duration::from_mins(1)
                //     )
                // ),
                autonat_server: Default::default(),
                relay_server: libp2p::relay::Behaviour::new(local_id, Default::default()),
            }
        }).unwrap()
        .build()
    }
}

// pub(super) struct Peer {pub ping: Option<Duration>, pub info: identify::Info, pub legacy_sync: crate::protocol::peer::MutablePeerState}