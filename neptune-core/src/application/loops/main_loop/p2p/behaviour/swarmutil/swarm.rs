use std::collections::{HashMap, HashSet};

use futures::StreamExt;
use itertools::{Either, Itertools};
use libp2p::gossipsub::{IdentTopic, MessageAcceptance, PublishError};
use libp2p::identify;
use libp2p::identity::ed25519::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::ping;
use libp2p::swarm::SwarmEvent;
use libp2p::{Multiaddr, PeerId};
use tokio::{fs::File, io::AsyncWriteExt, sync::broadcast::error::RecvError};
use tracing::{debug, error, info, trace, warn};

use crate::application::loops::channel::MainToPeerTask;
use crate::application::loops::main_loop::p2p::behaviour::swarmutil::relay_connect_ifneeded;
use crate::application::loops::main_loop::p2p::behaviour::ComposedBehaviourEvent;
use crate::application::loops::main_loop::p2p::TOPIC_TX_PROOFCOL_;
use crate::application::loops::main_loop::p2p::TOPIC_TX_PROOFCOL_NOTIF;
use crate::application::loops::main_loop::p2p::{MSG_NOTALLOWED, TOPIC_TX_SINGLEPROOF};
use crate::application::loops::MSG_CONDIT;
use crate::protocol::{consensus::block::Block, peer::PeerSanction};
use crate::state::mining::mining_status::MiningStatus;

pub const FILE_NODEIDPERSISTANCE: &str = ".peer_sk";

pub(crate) async fn run(
    global_state_lock: crate::state::GlobalStateLock,
    mut command_chan_from_main: tokio::sync::broadcast::Receiver<
        crate::application::loops::channel::MainToPeerTask,
    >,
    to_main: tokio::sync::mpsc::Sender<crate::application::loops::channel::PeerTaskToMain>,
) {
    // ~~TODO~~ from `run_wrapper` adapt saving black-listed peers and other ratings in `NetworkingState::PeerDatabases`, and other relevant parts
    //      it's a whole issue tracked as #DB yet

    let mut swarm = super::super::ComposedBehaviour::new_swarm({
        /* ~~TODO~~ Add an `Args` and use it here for a persistent peer. This should include precausion about running a copy.
        I guess it'd be good to save the seed so that `persistant` argument would
        1) load the seed from the designated place,
        2) generate and save a seed if the place is empty,
        3) ~~if a value given to it then ignore the place,~~
        4) ~~document how to get the seed~~ */
        /*      After some consideration @skaunov intentionally dropped ## 3 and 4 from the list. Hence storing the key pair machine readable instead of hex.
        Rationale is that it only complicates things and potentially confuse this key with seed phrase and other block-chain keys. Gains from ability
        to get the key or generate it from a seed are questionable and I believe it's better to have this direct and simple which also ensure good random `PeerId`
        (as feeding in a trivial seed won't possible). */
        /* @skaunov struggle to grasp the (type) system. Initially I made that as the method of `DataDirectory` returing
        `Either<Keypair, std::io::Result<tokio::fs::File>>` but then I discovered that it will be callable only from
        an archival node (deep in `global_state_lock`). \
        I guess `.cli().data_dir` means basically the same; but there's significant chance that non archival node will
        need some storage and it will be ubiquitous. \
        Am still disappointed there's no roster for paths; `DataDirectory` seemed a fine candidate. */
        /*      just a great illustration (of @skaunov not grasping this): why a most suitable path (no pun intended) to get `Path` was via `wallet_state`?
        Why can't I just get that `root_dir_path`? (I was too naive to use `global_state_lock.cli().data_dir` initially, which is `None` at this point already.) */
        let mut kf = None;

        let file_path = global_state_lock
            .lock(|gs| {
                gs.wallet_state
                    .configuration
                    .data_directory()
                    .root_dir_path()
            })
            .await
            .join(std::path::Path::new(FILE_NODEIDPERSISTANCE));
        if global_state_lock.cli().persistent {
            if let Ok(mut f) = File::open(&file_path).await {
                let mut buf: [u8; 64] = [0; 64];
                if tokio::io::AsyncReadExt::read_exact(&mut f, &mut buf)
                    .await
                    .is_ok()
                {
                    if let Ok(k) = Keypair::try_from_bytes(&mut buf) {
                        kf = Some(Either::Left(k))
                    }
                }
            }
            if kf.is_none() {
                match File::create(file_path).await {
                    Ok(f) => kf = Some(Either::Right(f)),
                    Err(e) => warn!["{e}"],
                }
            }
        }
        match kf {
            Some(Either::Left(k)) => k,
            f => {
                let key = Keypair::generate();
                if let Some(Either::Right(mut file)) = f {
                    file.write_all(&key.to_bytes())
                        .await
                        .unwrap_or_else(|e| warn!["{e}"])
                }
                key
            }
        }
        .into()
    });

    // if no peers - return to the user to be restarted with some peers been indicated in the arguments
    //      IIRC it's not hard to catch a failed Kademlia bootstrapping
    //          it reports `warn!` but no event to catch when failed due to no peers; only for timeout. https://github.com/libp2p/rust-libp2p/blob/2fb2486d3c981f1931d6428ec7ec377ea21db5a4/protocols/kad/src/behaviour.rs#L2591
    for mut madr in global_state_lock.cli().peers.clone() {
        /* the idea here is that a successful `.dial` effectively does `.kad.add_address` but
        1) enriches an address with the current `PeerId` when it has no, and
        2) only adds currently reachable peers */
        swarm
            .dial(madr.clone())
            .unwrap_or_else(|e| tracing::debug!("{e}"));

        // still should try to add from the command though chances are they either don't have both address & id, either not reachable
        if let (Some(peer_id), _) =
            crate::application::loops::main_loop::p2p::tmp_utils_multiaddr::peerid_split(&mut madr)
        {
            swarm.behaviour_mut().kad.add_address(&peer_id, madr);
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id)
        }
    }
    // TODO #followUp ~~add the guys from the DB~~
    /*      The legacy #DB isn't useful now, so it makes more sense to develop the new one which would
    - hold only good peers,
    - hold the multiaddrs in addition to the standings,
    - hold also the ratings from the components like Gossip-sub, Kademlia */

    // we basically can't use the original remove methods anymore since...
    // ~~TODO eliminate their usage~~
    // https://github.com/Neptune-Crypto/neptune-core/pull/729#issuecomment-3382780123

    tracing::trace!("every node subscribes to the 'block' topic");
    let topic_block = IdentTopic::new(crate::application::loops::main_loop::p2p::TOPIC_BLOCK);
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&topic_block)
        .expect(MSG_NOTALLOWED);
    let topic_tx_singleproof = IdentTopic::new(TOPIC_TX_SINGLEPROOF);
    let topic_tx_proofcollection_notif = IdentTopic::new(TOPIC_TX_PROOFCOL_NOTIF);
    let topic_tx_proofcollection = IdentTopic::new(TOPIC_TX_PROOFCOL_);
    let topic_proposal = IdentTopic::new(crate::application::loops::main_loop::p2p::TOPIC_PROPOSAL);
    let topics_tx = [
        &topic_tx_singleproof,
        &topic_tx_proofcollection,
        &topic_tx_proofcollection_notif,
    ];
    // let topics_mining: [_; 4] = [topics_tx.as_slice(), [&topic_proposal].as_slice()].concat().try_into().expect("it's four of those now");

    let (mut height, mut cumul) = global_state_lock
        .lock(|gs| {
            let t = gs.chain.light_state().header();
            (t.height, t.cumulative_proof_of_work)
        })
        .await;
    // let mut peers_info = HashMap::<PeerId, crate::protocol::peer::MutablePeerState>::new(); // #libp2p_reqresp_Sync
    let mut peer_pings: HashMap<PeerId, Option<std::time::Duration>> = HashMap::new();
    let mut peer_infos: HashMap<PeerId, libp2p::identify::Info> = HashMap::new();

    // info!["If all listeners `Result::Err` -- we will continue using just outgoing connections and relays."];
    let mut swarm_listeners = [
        swarm.listen_on(
            Multiaddr::empty()
                .with(global_state_lock.cli().peer_listen_addr.into())
                .with(Protocol::Tcp(global_state_lock.cli().peer_port_tcp)),
        ),
        swarm.listen_on(
            Multiaddr::empty()
                .with(global_state_lock.cli().peer_listen_addr.into())
                .with(Protocol::Udp(global_state_lock.cli().peer_port_quic))
                .with(Protocol::QuicV1), // @SKaunov guess `...V1` is the only fine variant now. https://docs.libp2p.io/concepts/transports/quic/#distinguishing-multiple-quic-versions-in-libp2p
        ),
        //
        // swarm_listeners.push(swarm.listen_on(Multiaddr::empty().with(Protocol::Onion3(multiaddr::Onion3Addr::from(([0; 35], 0))))));
    ]
    .into_iter()
    .filter(|l| {
        if let Err(e) = l {
            debug!["{e}| the error an initial listener failed with"];
            false
        } else {
            true
        }
    })
    .map(|l| l.expect(MSG_CONDIT))
    .collect::<std::collections::HashSet<_>>();
    let mut multiaddrs_autonat = HashMap::<Multiaddr, Option<bool>>::new();

    /* TODO #followUp purge `libp2p::kad::store::MemoryStore` when a new tip received or published as that invalidates any proof collection backed tx

    @skaunov am not sure how to communicate the purge to `kad::Behaviour` and if that even a significant problem (obviously some requests would fail, but it's not significant)
    obviously, published records should be <https://docs.rs/libp2p/latest/libp2p/kad/struct.Behaviour.html#method.remove_record> first

    let mut publishedrecords = Vec::<Record>::with_capacity(0); */

    loop {
        tokio::select! {
            biased;
            // The broadcast will not good here after complete switching to `Swarm` as we can't afford the single consumer to lag. That's why `Lagged` isn't really processed here.
            msg = command_chan_from_main.recv() => if !global_state_lock.lock(|s| s.net.freeze).await || Ok(MainToPeerTask::Quit) == msg || Err(RecvError::Closed) == msg {
                // TODO #followUp why the main loop would even issue a message variant which should not be processed? =/ #ignoreOnConsumerInsteadOfIo
                // Currently `.ignore_on_freeze()` isn't used here because `Swarm` just introduced. When other things developed it will be needed if not optimized out by then.
                // `if frozen && main_msg.ignore_on_freeze() {warn!("Swarm loop ignores message from main loop because state updates have been paused"); //...`

                /* `SwarmEvent` branch dominates in volume/frequency so much it seems to monitor the mining status so well it could be ok to rely on `.topics()` here and not locking a lock.
                Still it's peanuts since obviously most of the locking happens exactly there and good sync would still straight the things up. #topicsSync */
                //      This assumes that no guesser would be not `.subscribe` to `TOPIC_PROPOSAL`. Without this assumption it's still can be well synced just not based on `.topics()`.

                if let Some(args) = match msg {
                    Ok(MainToPeerTask::Quit) | Err(RecvError::Closed) => break,
                    Err(er @ RecvError::Lagged(_)) => {
                        debug!["{er}"];
                        None
                    }
                    Ok(MainToPeerTask::Block(block)) => {
                        // TODO #followUp address #noDifferenceForBlock

                        if swarm.behaviour().gossipsub.topics().contains(&topic_proposal.hash()) {
                            if block.kernel.header.height > height || block.kernel.header.cumulative_proof_of_work > cumul {
                                (height, cumul) = (height.max(block.kernel.header.height), cumul.max(block.kernel.header.cumulative_proof_of_work));
                                Some((
                                    topic_block.hash(),
                                    // cbor4ii::serde::to_vec(, ).expect("")
                                    bincode::serialize(&block)
                                    // {
                                    //     let mut wr = Vec::with_capacity(block.size() * 8);
                                    //     ciborium::into_writer(, wr);
                                    //     wr
                                    // }
                                ))
                            } else {None} // Is there a better move when `block` isn't that good? Like should the main loop be notified for example?
                        } else {
                            trace!["the node isn't mining hence no need to *`publish`* `::Block`|{}", block.hash()]; // passing is done without `publish`
                            None
                        }
                    }
                    Ok(MainToPeerTask::BlockProposal(block)) => if topics_tx.iter().any(|t| swarm.behaviour().gossipsub.topics().contains(&t.hash())) {
                        if block.kernel.header.height > height || block.kernel.header.cumulative_proof_of_work > cumul {
                            // NO! (height, cumul) = (height.max(block.kernel.header.height), cumul.max(block.kernel.header.cumulative_proof_of_work));
                            Some((topic_proposal.hash(), bincode::serialize(&block)))
                        } else {None} // Should it even be checked for a proposal? Guess in legacy it allows not be punished, but here?
                        /*                      Basically it's the same thanks to inherited from the legacy acceptance: if it's not this good it's rejected hence score decreased.
                        And that's very probable to be the most sane approach when you start to really think about it. */
                    } else {
                        trace!["the node isn't composing hence no need to *`publish`* a proposal |{}", block.header()];
                        None
                    },
                    Ok(MainToPeerTask::RequestBlockBatch(_main_to_peer_task_batch_block_request)) => None, /* TODO #libp2p_reqresp_BatchBlock */
                    Ok(MainToPeerTask::MakePeerDiscoveryRequest) => None, // TODO #libp2p_reqresp_Sync
                    Ok(MainToPeerTask::MakeSpecificPeerDiscoveryRequest(_socket_addr)) => None, /* TODO #libp2p_reqresp_Sync */
                    Ok(MainToPeerTask::NewTransaction(transfer_transaction)) => {
                        // terrible, but still an estimation. TODO #followUp It's not that hard to make a method for a tx estimation.
                        //      not useful with `bincode` instead of CBOR
                        // let estimation = 16+45*4+8+16+4+4;

                        let tx_vecu8 = bincode::serialize(&transfer_transaction);
                        // ~~probably `handle_tx_from_peer` will be affected by this detailing too~~
                        match transfer_transaction.proof {
                            crate::protocol::peer::transfer_transaction::TransferTransactionProof::ProofCollection(_) => match tx_vecu8 {
                                Ok(tx_vecu8) if tx_vecu8.len() > crate::application::loops::main_loop::p2p::TX_SINGLEPROOF_SIZE => {
                                    // TODO #followUp needs <https://github.com/libp2p/rust-libp2p/pull/6176> to anonymize `Record`
                                    None
                                    // // TODO put it to all the mesh peers first so it would be harder to identify the actual source/sender of the tx
                                    // Some((topic_tx_proofcollection_notif.hash(), {
                                    //     let notification_vecu8 =
                                    //         cbor4ii::serde::to_vec(Vec::with_capacity(todo![]), &TransactionNotification::try_from(&transfer_transaction.into()).unwrap()).expect("TODO");
                                    //     match swarm.behaviour_mut().kad.put_record(
                                    //         libp2p::kad::Record::new(
                                    //             libp2p::kad::RecordKey::new(&notification_vecu8),
                                    //             cbor4ii::serde::to_vec(Vec::with_capacity(estimation), &transfer_transaction).expect("TODO")
                                    //         ),
                                    //         todo![]
                                    //     ) {
                                    //         Ok(_query_id) => notification_vecu8,
                                    //         Err(libp2p::kad::store::Error::MaxRecords) => todo!("check in advance, purge the store if needed, hence make this `unreachable!()`"),
                                    //         Err(libp2p::kad::store::Error::ValueTooLarge) => {
                                    //             error!["core sharing of a huge tx is currently limited to {} bytes; find another way to upgrade your tx, pls", todo!["make that `const`"]];
                                    //             todo!()
                                    //         }
                                    //         Err(libp2p::kad::store::Error::MaxProvidedKeys) => unreachable!(),
                                    //     }
                                    // }))
                                }
                                tx_vecu8 => Some((topic_tx_proofcollection.hash(), tx_vecu8))
                            },
                            crate::protocol::peer::transfer_transaction::TransferTransactionProof::SingleProof(_) => Some((
                                topic_tx_singleproof.hash(), tx_vecu8
                            )),
                        }
                    }
                    /* _________________
                    irrelevant to `swarm` */
                    Ok(MainToPeerTask::Disconnect(_socket_addr)) => None,
                    Ok(MainToPeerTask::BlockProposalNotification(_block_proposal_notification)) => None,
                    Ok(MainToPeerTask::TransactionNotification(_transaction_notification)) => None,
                    Ok(MainToPeerTask::PeerSynchronizationTimeout(_socket_addr)) => None,
                } {match swarm.behaviour_mut().gossipsub.publish(args.0, match args.1 {
                    Ok(r) => r,
                    Err(boxed) => {
                        warn!("{boxed}");
                        continue
                    }
                }) {
                    Ok(_) => {}
                    Err(PublishError::Duplicate) => {
                        debug_assert!(false, "this would be a reason to look closer at least for some time");
                        debug!["`PublishError::Duplicate` on `.publish`"] // to {}", args.0]
                    }
                    Err(PublishError::NoPeersSubscribedToTopic) => warn!["Something is wrong with your swarm (network) connection. `PublishError::NoPeersSubscribedToTopic`"],
                    Err(PublishError::MessageTooLarge) => {
                        debug_assert!(false, "the limits must be set correctly");
                        error!["`PublishError::MessageTooLarge` on `.publish`"] // to {}", args.0]
                    }
                    Err(PublishError::AllQueuesFull(peers_num)) => warn!["Please describe your case to the devs if you hit this. (`PublishError::AllQueuesFull({peers_num})`)"],
                    Err(PublishError::TransformFailed(_)) => unreachable![],
                    Err(PublishError::SigningError(_)) => unreachable![],
                }}

                // TODO #libp2p_reqresp_px
                    // MainToPeerTask::MakePeerDiscoveryRequest => todo!("easy to make if needed"),
                    // MainToPeerTask::MakeSpecificPeerDiscoveryRequest(socket_addr) => todo!("very doubtful this is needed"),
            },
            ev = futures::StreamExt::select_next_some(&mut swarm) => {
                /* TODO #followUp @skaunov think the best way to track the mining status here would be `swarm.behaviour().gossipsub.topics()`;
                all it takes is to well syncronize commands to `.gossipsub.subscribe` and this alone would ditch handful of `.await` in the module. #topicsSync */
                if global_state_lock.mining().await {
                    for interest in match global_state_lock.lock(|c| c.mining_state.mining_status).await {
                        MiningStatus::Guessing(_) => vec![&topic_proposal],
                        MiningStatus::Composing(_) => topics_tx.to_vec(),
                        MiningStatus::Inactive => unreachable!["{MSG_CONDIT}"]
                    } {if !swarm.behaviour().gossipsub.topics().contains(&interest.hash()) {swarm.behaviour_mut().gossipsub.subscribe(interest).expect(MSG_NOTALLOWED);}}
                } else {
                    let excessive = swarm.behaviour().gossipsub.topics().filter_map(|t| if *t != topic_block.hash() {Some(t.to_owned())} else {None}).collect::<Vec<_>>();
                    excessive.into_iter().for_each(|t| {swarm.behaviour_mut().gossipsub.unsubscribe(&IdentTopic::new(t.into_string()));})
                }
                // } else { if subscribed.next() != Some(&topic_block.hash()) && subscribed.next() != None {
                //     topics_mining.iter()
                // } }

                /* TODO identify if there's any need for `neptune_cash::protocol::peer::PeerSanction` outside of request-reponse layer
                (in Gossip-sub most likely which takes application score but doesn't give it back) \
                the standings are in `global_state_mut.net.peer_map` \
                #libp2p_reqresp */
                match ev {
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Ping(ping::Event{ peer, connection, result })) => {match result {
                        Err(ping::Failure::Timeout) => {swarm.close_connection(connection);}
                        Err(ping::Failure::Other { error }) => warn!(error),
                        result => {peer_pings.insert(peer, result.ok());}
                    }},
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Identify(identify::Event::Received{ peer_id, info, .. })) => {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        for a in info.listen_addrs.clone() {swarm.behaviour_mut().kad.add_address(&peer_id, a);}
                        peer_infos.insert(peer_id, info);
                    }
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Identify(identify::Event::Error{ connection_id, error, .. })) => match error {
                        libp2p::swarm::StreamUpgradeError::Timeout => {swarm.close_connection(connection_id);}
                        _ => warn!("{error}")
                    },
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::AutonatClient(libp2p::autonat::v2::client::Event{ tested_addr, result, .. })) => {
                        debug_assert![multiaddrs_autonat.keys().contains(&tested_addr)];
                        *multiaddrs_autonat.entry(tested_addr).or_default() = match result {
                            Ok(()) => {
                                // TODO #followUp do the same with `identify` observations from the several sources (as it's easy to lie there) in case `autonat` isn't around. @skaunov bet there ready solutions for this not hard to find.
                                swarm.add_external_address(tested_addr.clone());

                                Some(true)
                            }
                            Err(_) => Some(false),
                            // https://github.com/libp2p/rust-libp2p/pull/6168
                            #[allow(unreachable_patterns)]
                            Err(_) => None
                        };
                        relay_connect_ifneeded(&mut multiaddrs_autonat, &peer_infos, &peer_pings, &mut swarm_listeners, &mut swarm)
                    }
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Kad(libp2p::kad::Event::RoutingUpdated{ peer, is_new_peer: _is_new_peer, addresses: _addresses, old_peer, .. })) => {
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                        if let Some(old_peer) = old_peer {swarm.behaviour_mut().gossipsub.remove_explicit_peer(&old_peer)}
                    }
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Kad(libp2p::kad::Event::OutboundQueryProgressed{
                        result: libp2p::kad::QueryResult::Bootstrap(result), stats: _stats, ..
                    })) =>
                        if result.is_ok() {
                            let mut actual = peer_infos.keys().copied().collect::<HashSet<_>>();
                            // let mut collection = HashSet::with_capacity(1);
                            for b in swarm.behaviour_mut().kad.kbuckets() {
                                b.iter().map(|n| *n.node.key.preimage()).collect_into::<HashSet<PeerId>>(&mut actual);
                                // actual.extend(buf.drain().map(|p| &p))
                            }
                            // actual.extend(collection.iter());
                            let gossip = swarm.behaviour().gossipsub.all_peers().map(|x| x.0).copied().collect::<HashSet<_>>();
                            gossip.difference(&actual).for_each(|peer_id|
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(peer_id)
                                // gossip.remove(peer_id);
                            );
                            actual.difference(&gossip).for_each(|peer_id| swarm.behaviour_mut().gossipsub.add_explicit_peer(peer_id));
                        } else {
                            debug!["Kademlia bootstrap timeouted"];
                            let mut stillworks = false;
                            for b in swarm.behaviour_mut().kad.kbuckets() {if b.iter().next().is_some() {
                                stillworks = true;
                                break
                            }}
                            if !stillworks {warn!("Kademlia has no peers.")}
                        },
                    // TODO #followUp apply returned `PeerSanction` when #DB will be here?
                    SwarmEvent::Behaviour(ComposedBehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Message { propagation_source, message_id, message })) =>
                        if !swarm.behaviour_mut().gossipsub.report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            {
                                /* Ok, this ended up *much more* local than it was in the beginning, so while the following points I had are valid, they have so less impact and hence priority.
                                Also note that if `peer_message.ignore_...` setting were different it won't be this local. I mean from a design angle I still would like this to get another thought. */
                                /* @skaunov would prefer those to be processed as usual to
                                - not lock the lock each iteration,
                                - keep the swarm flowing,
                                - separate the concerns.

                                And deal with these states on the side of a further consumer of those messages. #ignoreOnConsumerInsteadOfIo
                                If that was introduced in <commit:4e12aee1e8a13593697cbc838d986c6ad5b9d5b6>
                                the rationale is totally reasonable for it to be baked into and not stubbed on the surface. */
                                let mut peermessageignore = false;
                                // Just taken from `PeerLoopHandler::run`. @skaunov don't want to tie `swarm` to `PeerMessage`, and want the taken code to be as recognizable as possible.
                                let (syncing, frozen) =
                                    global_state_lock.lock(|s| (s.net.sync_anchor.is_some(), s.net.freeze)).await;
                                // let message_type = peer_message.get_type();
                                if syncing // && peer_message.ignore_during_sync()
                                {
                                    debug!(
                                        "Ignoring {} message when syncing, from {propagation_source}", message.topic
                                    );
                                    peermessageignore = true;
                                }
                                // #libp2p_reqresp_Sync
                                // if peer_message.ignore_when_not_sync() && !syncing {
                                //     debug!(
                                //         "Ignoring {message_type} message when not syncing. |{peer_message}",
                                //     );
                                //     continue;
                                // }
                                // #libp2p_reqresp_pxs
                                if !peermessageignore &&
                                frozen // && peer_message.ignore_on_freeze()
                                {
                                    debug!("Ignoring message because state updates have been paused.");
                                    peermessageignore = true;
                                }

                                if peermessageignore {Ok(Box::pin(futures::future::ready(MessageAcceptance::Ignore)) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)}
                                else if topic_block.hash() == message.topic {bincode::deserialize(message.data.as_slice()).map(
                                    // fun fact: `#[serde(skip)]` in `Block` does the same here what documented for `TransferBlock`
                                    |block: Block| async {
                                        // @skaunov don't know how exactly this helps --- just repeatin the current/legacy implementation
                                        //      Just for fun @skaunov replaced that `TryFrom` for `From` which returns the genesis, and it seems to fly with the tests well.
                                        if block.kernel.header.height.is_genesis() {MessageAcceptance::Reject} else {
                                            match global_state_lock.lock_guard().await.chain.archival_state().get_block(block.header().prev_block_digest).await {
                                                Ok(Some(parent)) => {
                                                    // TODO #followUp an insignificant saving would be returning these things on success by the function
                                                    let (h, cu) = (block.kernel.header.height, block.kernel.header.cumulative_proof_of_work);
                                                    match crate::application::loops::peer_loop::PeerLoopHandler::handle_blocks(
                                                        global_state_lock.clone(),
                                                        to_main.clone(),
                                                        &crate::api::export::Timestamp::now(),
                                                        vec![block],
                                                        &parent
                                                    ).await.1 {
                                                        Some(PeerSanction::Positive(_)) => {
                                                            (height, cumul) = (height.max(h), cumul.max(cu));
                                                            MessageAcceptance::Accept
                                                        }
                                                        Some(PeerSanction::Negative(_)) => MessageAcceptance::Reject,
                                                        None => MessageAcceptance::Ignore
                                                    }
                                                }
                                                /* TODO #libp2p_reqresp_BatchBlock We can send our block digests and ask for the blocks leading to this one so we could `PeerLoopHandler::handle_blocks` the blocks this peer is ahead.
                                                Some kind of challenge would be nice for this so the peer could not be overwhelmed with the requests. */
                                                Ok(None) => MessageAcceptance::Ignore,
                                                Err(e) => {
                                                    warn!["{e}"];
                                                    MessageAcceptance::Ignore
                                                }
                                            }
                                        }
                                    }
                                ).map(|fut| Box::pin(fut) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)}
                                else if topic_tx_singleproof.hash() == message.topic || topic_tx_proofcollection.hash() == message.topic {
                                    bincode::deserialize(message.data.as_slice()).map(
                                        // crate::protocol::peer::transfer_transaction::TransferTransaction
                                        |tx| async {match crate::application::loops::handle_tx_from_peer::the(
                                            global_state_lock.clone(), to_main.clone(), crate::api::export::Timestamp::now(), tx
                                        ).await {
                                            Some(Some(_)) => MessageAcceptance::Reject,
                                            Some(None) => MessageAcceptance::Ignore,
                                            None => MessageAcceptance::Accept
                                        }}
                                    ).map(|fut| Box::pin(fut) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)
                                } else if topic_tx_proofcollection_notif.hash() == message.topic {
                                    debug_assert![false];
                                    debug!["someone mocking us sending 'tx_proofcollection_notification' topic which waits its implementation on the sending side"];
                                    Ok(Box::pin(futures::future::ready(MessageAcceptance::Ignore)) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)
                                } else if topic_proposal.hash() == message.topic {bincode::deserialize(message.data.as_slice()).map(|proposal| async {
                                    match super::super::super::super::super::handle_proposal_from_peer::the(
                                        global_state_lock.clone(), to_main.clone(), crate::api::export::Timestamp::now(), None, proposal
                                    ).await {
                                        Some(PeerSanction::Positive(_)) => MessageAcceptance::Accept,
                                        Some(PeerSanction::Negative(_)) => MessageAcceptance::Reject,
                                        None => MessageAcceptance::Ignore
                                    }
                                }).map(|fut| Box::pin(fut) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)}
                                else {
                                    debug!["an unrecognized topic was added to the network"];
                                    Ok(Box::pin(futures::future::ready(MessageAcceptance::Ignore)) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)
                                }
                            }.unwrap_or_else(|e| {
                                warn!["{e} |{} |{propagation_source} |{message_id}", message.topic];
                                Box::pin(futures::future::ready(MessageAcceptance::Reject)) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>
                            }).await
                        ) {warn!("Gossip-sub not catching up with the message validation |{} |{}", message_id, propagation_source)},
                    // SwarmEvent::Behaviour(ComposedBehaviourEvent::Reqresp(libp2p::request_response::Event::Message{ peer, connection_id: _, message })) => {
                    //     let (m, resp) = match message {
                    //         libp2p::request_response::Message::Request{ request_id: _, request, channel } => (request, Some(channel)),
                    //         libp2p::request_response::Message::Response{ request_id: _, response } => (response, None)
                    //     };
                    // }
                    SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause } => {
                        if let Some(e) = cause {warn!["`SwarmEvent::ConnectionClosed`|{e}|{peer_id}|{connection_id}|{endpoint:?}|{num_established}"]}
                        if num_established == 0 {
                            let _disconnected = (/* peers_info.remove(&peer_id), */ peer_pings.remove(&peer_id), peer_infos.remove(&peer_id));
                            // TODO #followUp spawn a task to save `_disconnected` to #DB (like standings)

                            if !swarm.behaviour_mut().kad.kbuckets().any(|b| b.iter().map(|n| n.node.key).contains(&libp2p::kad::KBucketKey::<PeerId>::from(peer_id))) {
                                swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id)
                            }
                        }
                    }
                    /* So, @skaunov current mental model is following. The listen addresses and the external addresses are coupled loosely. *External* are more important to us
                    as these are what other nodes actually use to communicate with us (even if these addresses aren't callable/dialabe but only "where we come from"). *Listen*
                    are what we advertise (mainly when `identify` info) with all the consequences (nodes probably would try those and it become confirmed when success; some
                    could be relevant only for a local net; etc).

                            actually a test how `identify` shares the listen addrs would still be a nice thing */
                    // ~~TODO~~ check/test that `identify` catches this
                    //      checked, @skaunov don't see a good test for it
                    SwarmEvent::NewListenAddr { listener_id, mut address } => {
                        info!["{address}| One of our listeners has reported a new local listening address."];
                        debug_assert!(swarm_listeners.contains(&listener_id));
                        if address.protocol_stack().contains(&Protocol::P2pCircuit.tag()) {
                            trace!["We started new listener on a relay. So let's `.dial` all the addresses which also listen on this relay to enhance a connection upgrade chance."];
                            let relay_id = {
                                let debug_pid = address.pop().expect("can't come without our own `PeerId`");
                                debug_assert_eq!(debug_pid, Protocol::P2p(*swarm.local_peer_id()));
                                let debug_circ = address.pop().expect("should be `Protocol::P2pCircuit`");
                                debug_assert_eq!(debug_circ, Protocol::P2pCircuit);
                                address.pop().expect("`Protocol::P2pCircuit` should have `Protocol::P2p(PeerId)` before it")
                            };
                            std::assert_matches::debug_assert_matches!(relay_id, Protocol::P2p(_), "check/test this well before removing");
                            if peer_infos.iter().filter(|(_, info)| info.listen_addrs.iter().any(|addr| {
                                let mut i = addr.iter();
                                i.contains(&relay_id) && i.contains(&Protocol::P2pCircuit)
                            })).flat_map(|(_, info)| info.listen_addrs.iter().cloned()).map(|adr| swarm.dial(adr)).all(|r| r.is_err()) {
                                trace!["We're not connected to anybody listening on this [relay]({relay_id}). Let's try to `.dial` all such addresses we have in Kademlia table then."];
                                if swarm.behaviour_mut().kad.kbuckets().flat_map(|bucket| bucket.iter().flat_map(
                                    |v| v.node.value
                                    // .iter().cloned()
                                    .clone().into_vec()
                                ).collect::<Vec<_>>()).filter(|addr| {addr.iter().contains(&relay_id) && addr.iter().contains(&Protocol::P2pCircuit)}).collect_vec().into_iter()
                                .map(|adr| swarm.dial(adr)).all(|r| r.is_err()) {debug!["We know no peers on our [relay]({relay_id}). Maybe our node is the first here."]}
                            }
                        }
                    }
                    SwarmEvent::ExpiredListenAddr { listener_id, address } => {
                        debug_assert![address.protocol_stack().contains(&Protocol::Ip6(std::net::Ipv6Addr::UNSPECIFIED).tag()),
                            "only IPv6 can expire: can it be done without new listen call, can it do this auto and just report the IPv6 change?"];

                        let debug_ = swarm_listeners.remove(&listener_id);
                        debug_assert!(debug_);

                        if address.iter().contains(&Protocol::P2pCircuit) {relay_connect_ifneeded(
                            &mut multiaddrs_autonat, &peer_infos, &peer_pings, &mut swarm_listeners, &mut swarm
                        )}
                        else {match swarm.listen_on(address.replace(
                            address.iter().position(|el| matches!(el, Protocol::Ip6(_))).unwrap(),
                            |_| Some(Protocol::Ip6(std::net::Ipv6Addr::UNSPECIFIED))
                        ).unwrap()) {
                            Ok(lid) => {swarm_listeners.insert(lid);}
                            Err(_) => relay_connect_ifneeded(&mut multiaddrs_autonat, &peer_infos, &peer_pings, &mut swarm_listeners, &mut swarm),
                        }}
                    }
                    SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                        // TODO #followUp ~~not here~~ (?) but would be nice to have listener crash #monitoring
                        let debug_ = swarm_listeners.remove(&listener_id);
                        debug_assert!(debug_, "all the listeners should be tracked in `swarm_listeners`");
                        reason.unwrap_or_else(|reason| {debug!["{listener_id}|{addresses:?}|{reason}"];})
                    }
                    SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                        // quite strange `kad` requires the call and Gossip picks up the event itself; chances are @skaunov just don't get this right yet
                        // indeed, that's why @skaunov added putting that into Gossip on new routable peer event which is even better than here
                        swarm.behaviour_mut().kad.add_address(&peer_id, address);
                    }
                    SwarmEvent::NewExternalAddrCandidate { address } => {multiaddrs_autonat.insert(address, None);}
                    SwarmEvent::ExternalAddrConfirmed { address } => if !swarm.listeners().contains(&address) {
                        match swarm.listen_on(address) {
                            Ok(lid) => {swarm_listeners.insert(lid);} // is there any reason not to? privacy maybe?
                            Err(er) => debug!("{er}"),
                        }
                    },
                    /* __________________________________________________________________________________________________________________
                    events which doesn't carry an interesting thing are commented here yet to be in front of the eyes at this early stage
                     */
                    // ev @ SwarmEvent::IncomingConnection { .. } => {dbg![ev];}
                    // ev @ SwarmEvent::ConnectionEstablished { .. } => {dbg![ev];}
                    // /* ~~why does this says 'a non-fatal'?~~
                    //         fatal will be the `reason` in `ListenerClosed` */
                    // ev @ SwarmEvent::ListenerError { .. } => debug![?ev],
                    // SwarmEvent::IncomingConnectionError { connection_id, local_addr, send_back_addr, error, peer_id } => {}
                    // SwarmEvent::OutgoingConnectionError { connection_id, peer_id, error } => {}
                    // ev @ SwarmEvent::Dialing { .. } => {dbg![ev];}
                    // SwarmEvent::ExternalAddrExpired { address } => {}

                    // SwarmEvent::Behaviour(ComposedBehaviourEvent::Dcutr(ev @ libp2p::dcutr::Event{ .. })) => {
                    //     println!["************** dcutr HOLE-PUNCHIN ************************"];
                    //     dbg![ev];
                    // }
                    // ev => {dbg![ev];}
                    _ => {}
                }
            }
            /* TODO #followUp it might be sensible to have here another branch of the least priority to feed the dashboard with data about the `swarm`
            (like peers, listening address, and whatever) #monitoring
                maybe send a "big" amount of this data once in awhile but only when all the other queues are exhausted */
        }
    }
    for l in swarm_listeners {
        swarm.remove_listener(l);
    }
    swarm
        .connected_peers()
        .copied()
        .collect_vec()
        .into_iter()
        .for_each(|p| {
            let _ = swarm.disconnect_peer_id(p);
        });
    tokio::spawn(async move {
        trace!("started the task to drive `swarm` to close everything it had");
        while 0 != swarm.connected_peers().count() + swarm.listeners().count() {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(_) => {}, // all peers disconnection should make errors from this irrelevant
                SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause } => match cause {
                    Some(er) => debug!("on quit error disconnecting a peer connection |{er} |{peer_id} |{connection_id} |{endpoint:?} |{num_established}"),
                    None => trace!("on quit successfully disconnected a peer connection |{peer_id} |{connection_id} |{endpoint:?} |{num_established}"),
                },
                SwarmEvent::ListenerClosed { listener_id, addresses, reason } => match reason {
                    Err(er) => warn!("on quit error closing a listener |{er} |{listener_id} |{addresses:?}"),
                    Ok(()) => trace!("on quit successfully closed a listener |{listener_id} |{addresses:?}"),
                },
                SwarmEvent::ListenerError { listener_id, error } => debug!{"while quiting a listener produced an error |{error} |{listener_id}"},
                // other events aren't relevant
                _ => {}
            }
        }
        trace!("`0 == swarm.connected_peers().count() + swarm.listeners().count()`");
    });

    // TODO #followUp save standings and addresses to a #DB
    /*      @skaunov am surprised that peer standings are just flushed and not persisted (see `flush_databases`). I'd say saving the top peers to disk
    would be beneficial. As well as prepopulating that DB, and also having centralized sources
    to download the first peers (block explorers and other public servers and RPC could serve this). */
    // https://github.com/Neptune-Crypto/neptune-core/pull/729#issuecomment-3381164924
}
