use std::collections::HashMap;

use cbor4ii::serde::DecodeError;
use futures::StreamExt;
use itertools::Itertools;
use libp2p::{gossipsub::{IdentTopic, MessageAcceptance, PublishError}, identify, multiaddr::Protocol, ping, swarm::SwarmEvent, Multiaddr, PeerId};
use tracing::{debug, error, info, trace, warn};

use crate::{application::loops::{channel::MainToPeerTask, main_loop::p2p::{behaviour::ComposedBehaviourEvent, TOPIC_TX_PROOFCOL_, TOPIC_TX_PROOFCOL_NOTIF, TOPIC_TX_SINGLEPROOF}, MSG_CONDIT}, protocol::{consensus::block::Block, peer::{transaction_notification::TransactionNotification, PeerSanction}}, state::mining::mining_status::MiningStatus};

pub(crate) async fn run(
    global_state_lock: crate::state::GlobalStateLock, 
    mut command_chan_from_main: tokio::sync::broadcast::Receiver<crate::application::loops::channel::MainToPeerTask>,
    to_main: tokio::sync::mpsc::Sender<crate::application::loops::channel::PeerTaskToMain>
) {
    // TODO from `run_wrapper` adapt saving black-listed peers and other ratings in `NetworkingState::PeerDatabases`, and other relevant parts
    
    // TODO Add an `Args` an use it here for a persistent peer. This should include precausion about running a copy. I guess it'd be good to save the seed so that `persistant` argument would 1) load the seed from the designated place, 2) generate and save a seed if the place is empty, 3) if a value given to it then ignore the place, 4) document how to get the seed
    let mut swarm = super::ComposedBehaviour::new_swarm(libp2p::identity::ed25519::Keypair::generate().into());

    /* TODO somewhere down the line of operation `kad.kbuckets()` should be checked to have some peers, and if not return to the user to be restarted with some peers been indicated in the arguments
            IIRC it's not hard to catch a failed Kademlia bootstrapping */
    for peer in global_state_lock.cli().peers.clone() {todo!("add explicitly to the each layer possible")}
    /* the idea here is that a successful `.dial` effectively does `.kad.add_address` but 1) enriches an address with the current `PeerId` when it has no, and 2) only adds currently reachable peers which is important too
            TODO wasn't a bad idea, but should be reversed as in the long run it will return to trying it  */
    global_state_lock.cli().peers.clone().into_iter().for_each(|a| swarm.dial(a).unwrap_or_else(|e| tracing::debug!("{e}")));
    /* TODO ~~add the guys from the DB~~
            The legacy DB isn't useful now, so it makes more sense to develop the new one which would 
            - hold only good peers,
            - hold the multiaddrs in addition to the standings,
            - hold also the ratings from the components like Gossip-sub, Kademlia */

    tracing::trace!("every node subscribes to the 'block' topic");
    let topic_block = IdentTopic::new(crate::application::loops::main_loop::p2p::TOPIC_BLOCK);
    swarm.behaviour_mut().gossipsub.subscribe(&topic_block);
    let topic_tx_singleproof = IdentTopic::new(TOPIC_TX_SINGLEPROOF);
    let topic_tx_proofcollection_notif = IdentTopic::new(TOPIC_TX_PROOFCOL_NOTIF);
    let topic_tx_proofcollection = IdentTopic::new(TOPIC_TX_PROOFCOL_);
    let topic_proposal = IdentTopic::new(crate::application::loops::main_loop::p2p::TOPIC_PROPOSAL);
    let topics_tx = [&topic_tx_singleproof, &topic_tx_proofcollection, &topic_tx_proofcollection_notif];
    // let topics_mining: [_; 4] = [topics_tx.as_slice(), [&topic_proposal].as_slice()].concat().try_into().expect("it's four of those now");

    /* TODO purge `libp2p::kad::store::MemoryStore` when a new `Block` received or published as that invalidates any proof collection backed tx
    @skaunov am not sure how to communicate the purge to `kad::Behaviour` and if that even a significant problem (obviously some request would fail, but they it's not significant)
    obviously published records should be <https://docs.rs/libp2p/latest/libp2p/kad/struct.Behaviour.html#method.remove_record> first */
    
    let (mut height, mut cumul) = global_state_lock.lock(|gs| {
        let t = gs.chain.light_state().header();
        (t.height, t.cumulative_proof_of_work)
    }).await;
    // let mut peers_info = HashMap::<PeerId, crate::protocol::peer::MutablePeerState>::new(); // #libp2p_reqresp_Sync
    let mut peer_pings: HashMap<PeerId, Option<std::time::Duration>> = HashMap::new();
    let mut peer_infos: HashMap<PeerId, libp2p::identify::Info> = HashMap::new();

    // info!["If all listeners `Result::Err` -- we will continue using just outgoing connections and relays."];
    let mut swarm_listeners = [
        swarm.listen_on(Multiaddr::empty().with(global_state_lock.cli().peer_listen_addr.into()).with(Protocol::Tcp(global_state_lock.cli().peer_port_tcp))),
        swarm.listen_on(Multiaddr::empty().with(global_state_lock.cli().peer_listen_addr.into())
        .with(Protocol::Udp(global_state_lock.cli().peer_port_quic)).with(Protocol::QuicV1)), // @SKaunov guess `...V1` is the only fine variant now. https://docs.libp2p.io/concepts/transports/quic/#distinguishing-multiple-quic-versions-in-libp2p

        // swarm_listeners.push(swarm.listen_on(Multiaddr::empty().with(Protocol::Onion3(multiaddr::Onion3Addr::from(([0; 35], 0))))));
    ].into_iter().filter(|l| if let Err(e) = l {
        debug!["{l:?}"];
        false
    } else {true}).map(|l| l.expect(MSG_CONDIT)).collect::<std::collections::HashSet<_>>();
    let mut swarm_listener_multiaddrs_autonat = HashMap::<Multiaddr, Option<bool>>::new();

    loop {tokio::select! {
        biased;
        // TODO broadcast will not good here anymore as we can't afford the single consumer to lag
        msg = command_chan_from_main.recv() => if !global_state_lock.lock(|s| s.net.freeze).await {
            // TODO why the main loop would even issue a message variant which should not be processed? =/ #ignoreOnConsumerInsteadOfIo
            // `if frozen && main_msg.ignore_on_freeze() {warn!("Swarm loop ignores message from main loop because state updates have been paused"); //...`

            /* TODO `SwarmEvent` branch seems to monitor the mining status so well it could be ok to rely on `.topics()` here and not locking a lock. 
            Still it's peanuts since obviously most of the locking happens exactly there and good sync would still straight the things up. */

            if let Some(args) = match msg.unwrap() {
                MainToPeerTask::Quit => break,
                MainToPeerTask::Block(block) => {
                    // TODO address #noDifferenceForBlock

                    // if crate::state::mining::mining_status::MiningStatus::Inactive != global_state_lock.lock(|c| c.mining_state.mining_status).await {
                    if global_state_lock.mining().await {
                        if block.kernel.header.height > height || block.kernel.header.cumulative_proof_of_work > cumul { 
                            // match swarm.behaviour_mut().gossipsub.publish(
                            //     topic_digest_block, 
                            //     cbor4ii::serde::to_vec(Vec::with_capacity(block.size()), &block).expect("TODO")
                            // ) {
                            //     Ok(_) => {}
                            //     Err(PublishError::Duplicate) => {
                            //         debug_assert!(false, "this would be a reason to look closer at least for some time");
                            //         debug!["`PublishError::Duplicate` on [block]({}) `.publish`", block.hash()]
                            //     }
                            //     Err(PublishError::NoPeersSubscribedToTopic) => warn!["Something is wrong with your swarm (network) connection. `PublishError::NoPeersSubscribedToTopic`"],
                            //     Err(PublishError::MessageTooLarge) => {
                            //         debug_assert!(false, "the limits must be set correctly");
                            //         error!["`PublishError::MessageTooLarge` on [block]({}) `.publish`", block.hash()]
                            //     }
                            //     Err(PublishError::AllQueuesFull(peers_num)) => warn!["Please describe your case to the devs if you hit this. (`PublishError::AllQueuesFull({peers_num})`)"],
                            //     Err(PublishError::TransformFailed(_)) => unreachable![],
                            //     Err(PublishError::SigningError(_)) => unreachable![],
                            // };
                            (height, cumul) = (height.max(block.kernel.header.height), cumul.max(block.kernel.header.cumulative_proof_of_work));
                            Some((topic_block.hash(), cbor4ii::serde::to_vec(Vec::with_capacity(block.size() * 8), &block).expect("TODO")))
                        } else {None} // TODO is there a better move when `block` isn't that good?
                    } else {
                        trace!["the node isn't mining hence no need to *`publish`* `Block`"]; // passing is done without `publish`
                        None
                    } 
                }
                MainToPeerTask::BlockProposal(block) => if let crate::state::mining::mining_status::MiningStatus::Composing(_) = global_state_lock.lock(|c| c.mining_state.mining_status).await {
                    if block.kernel.header.height > height || block.kernel.header.cumulative_proof_of_work > cumul { 
                        // NO! (height, cumul) = (height.max(block.kernel.header.height), cumul.max(block.kernel.header.cumulative_proof_of_work));
                        Some((topic_proposal.hash(), cbor4ii::serde::to_vec(Vec::with_capacity(8 * block.size()), &block).expect("TODO")))
                    } else {None} // TODO should it even be checked for a proposal?
                } else {
                    trace!["the node isn't composing hence no need to *`publish`* a proposal"];
                    None
                },
                MainToPeerTask::RequestBlockBatch(main_to_peer_task_batch_block_request) => None, /* TODO #libp2p_reqresp_BatchBlock */
                MainToPeerTask::MakePeerDiscoveryRequest => None, /* TODO #libp2p_reqresp_Sync */
                MainToPeerTask::MakeSpecificPeerDiscoveryRequest(socket_addr) => None, /* TODO #libp2p_reqresp_Sync */
                MainToPeerTask::NewTransaction(transfer_transaction) => {
                    let estimation = 16+45*4+8+16+4+4; // #terrible, but still an estimation. TODO It's not that hard to make a method for a tx estimation.
                    // ~~probably `handle_tx_from_peer` will be affected by this detailing too~~
                    match transfer_transaction.proof {
                        crate::protocol::peer::transfer_transaction::TransferTransactionProof::ProofCollection(_) => {
                            let tx_vecu8 = cbor4ii::serde::to_vec(Vec::with_capacity(estimation), &transfer_transaction).expect("TODO");
                            if tx_vecu8.len() < crate::application::loops::main_loop::p2p::TX_SINGLEPROOF_SIZE {Some((topic_tx_proofcollection.hash(), tx_vecu8))} 
                            else {
                                todo!["needs <https://github.com/libp2p/rust-libp2p/pull/6176> to anonymize `Record`"]
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
                                //             error!["peer-to-peer sharing of a huge tx is currently limited to {} bytes; find another way to upgrade your tx, pls", todo!["make that `const`"]];
                                //             todo!()
                                //         }
                                //         Err(libp2p::kad::store::Error::MaxProvidedKeys) => unreachable!(),
                                //     }
                                // }))
                            }
                        }
                        crate::protocol::peer::transfer_transaction::TransferTransactionProof::SingleProof(_) => Some((
                            topic_tx_singleproof.hash(), cbor4ii::serde::to_vec(Vec::with_capacity(estimation), &transfer_transaction).expect("TODO")
                        )),
                    }
                }
                /* _________________
                irrelevant to `swarm` */
                MainToPeerTask::Disconnect(socket_addr) => None, 
                MainToPeerTask::BlockProposalNotification(block_proposal_notification) => None, 
                MainToPeerTask::TransactionNotification(transaction_notification) => None, 
                MainToPeerTask::PeerSynchronizationTimeout(socket_addr) => None, 
            } {match swarm.behaviour_mut().gossipsub.publish(args.0, args.1) {
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
            // crate::application::loops::peer_loop::PeerLoopHandler::handle_main_task_message(
            //     msg.expect(), peers_info.0, &mut swarm, self.global_state_lock.clone(), self.peer_task_to_main_tx.clone()
            // ).await;
            
            // TODO #libp2p_reqresp_px
                // MainToPeerTask::MakePeerDiscoveryRequest => todo!("easy to make if needed"),
                // MainToPeerTask::MakeSpecificPeerDiscoveryRequest(socket_addr) => todo!("very doubtful this is needed"),
        },
        ev = futures::StreamExt::select_next_some(&mut swarm) => {
            
            // let peer_message = ev; // @skaunov don't want to tie `swarm` to `PeerMessage`, and want the taken code to be as recognizable as possible.
            // // TODO not this simple
            // // if !self.global_state_lock.lock(|s| s.net.freeze).await 
            // // ___________________________
            // /* Just taken from `PeerLoopHandler::run`. @skaunov would prefer those to be processed as usual to
            // - not lock the lock each iteration,
            // - keep the swarm flowing,
            // - separate the concerns.

            // And deal with these states on the side of a further consumer of those messages. #ignoreOnConsumerInsteadOfIo */
            // let (syncing, frozen) =
            //     global_state_lock.lock(|s| (s.net.sync_anchor.is_some(), s.net.freeze)).await;
            // let message_type = peer_message.get_type();
            // if syncing && peer_message.ignore_during_sync() {
            //     debug!(
            //         "Ignoring {message_type} message when syncing. |{peer_message}",
            //     );
            //     continue;
            // }
            // if peer_message.ignore_when_not_sync() && !syncing {
            //     debug!(
            //         "Ignoring {message_type} message when not syncing. |{peer_message}",
            //     );
            //     continue;
            // }
            // if frozen && peer_message.ignore_on_freeze() {
            //     debug!("Ignoring message because state updates have been paused. |{peer_message}");
            //     continue;
            // }

            /* TODO @skaunov think the best way to track the mining status here would be `swarm.behaviour().gossipsub.topics()`; 
            all it takes is to well syncronize commands to `.gossipsub.subscribe` and this alone would ditch handful of `.await` in the module. */
            /* `SwarmEvent` dominates in volume so much that the thing could never moved out that branch, 
            but @skaunov feel here it sparks better dicussion and it just more comfortable when I *can* reuse whenever I want. */
            if global_state_lock.mining().await { // ~~TODO @skaunov don't like this `.await` and guess it can be refactored out touching some deeper code~~
                // TODO proof upgrading?
                let interests = match global_state_lock.lock(|c| c.mining_state.mining_status).await {
                    MiningStatus::Guessing(_) => vec![&topic_proposal],
                    MiningStatus::Composing(_) => topics_tx.to_vec(),
                    MiningStatus::Inactive => unreachable!["{MSG_CONDIT}"]
                };
                for interest in interests {if !swarm.behaviour().gossipsub.topics().contains(&interest.hash()) {
                    swarm.behaviour_mut().gossipsub.subscribe(interest).err().into_iter().for_each(|e| error!("while `.subscribe` to {} |{e}", interest))
                }}
            } else {
                let excessive = swarm.behaviour().gossipsub.topics().filter_map(|t| if *t != topic_block.hash() {Some(t.to_owned())} else {None}).collect::<Vec<_>>();
                excessive.into_iter().for_each(|t| {swarm.behaviour_mut().gossipsub.unsubscribe(&IdentTopic::new(t.into_string()));})
            }
            // } else { if subscribed.next() != Some(&topic_block.hash()) && subscribed.next() != None {
            //     topics_mining.iter()
            // } }

            /* TODO identify if there's any need for `neptune_cash::protocol::peer::PeerSanction` outside of request-reponse layer (in Gossip-sub most likely which takes application score but doesn't give it back) \
            the standings are in `global_state_mut.net.peer_map` \
            #libp2p_reqresp */
            match ev {
                SwarmEvent::Behaviour(ComposedBehaviourEvent::Ping(ping::Event{ peer, connection, result })) => {match result {
                    Err(ping::Failure::Timeout) => {swarm.close_connection(connection);}
                    Err(ping::Failure::Other { error }) => warn!(error),
                    result => {peer_pings.insert(peer, result.ok());}
                }},
                SwarmEvent::Behaviour(ComposedBehaviourEvent::Identify(identify::Event::Received{ connection_id, peer_id, info })) => {peer_infos.insert(peer_id, info);}
                SwarmEvent::Behaviour(ComposedBehaviourEvent::Identify(identify::Event::Error{ connection_id, peer_id, error })) => match error {
                    libp2p::swarm::StreamUpgradeError::Timeout => {swarm.close_connection(connection_id);}
                    _ => warn!("{error}")
                },
                SwarmEvent::Behaviour(ComposedBehaviourEvent::AutonatClient(libp2p::autonat::v2::client::Event{ tested_addr, bytes_sent, server, result })) => {
                    if swarm_listener_multiaddrs_autonat.keys().into_iter().contains(&tested_addr) {
                        *swarm_listener_multiaddrs_autonat.get_mut(&tested_addr).expect(MSG_CONDIT) = match result {
                            Ok(()) => Some(true),
                            Err(_) => Some(false),
                            // TODO https://github.com/libp2p/rust-libp2p/pull/6168
                            Err(_) => None
                        };
                        if swarm_listener_multiaddrs_autonat.values().all(|s| s == &Some(false)) {
                            info!["`autonat` checked all the addresses we're listening onto, and all of them failed; hence we need to use a relay"];
                            let mut relays = peer_infos.iter().filter(|(_id, info)| info.protocols.contains(
                                    &libp2p::relay::HOP_PROTOCOL_NAME // TODO debug this to be sure this approach works
                                ) && info.listen_addrs.iter().any(|adr| {
                                    !adr.protocol_stack().contains(&Protocol::P2pCircuit.tag()) && adr.protocol_stack().contains(&Protocol::Tcp(0).tag()) // TODO make this a helper #relayMultiadr; or just filter those here
                                })) 
                                .map(|(id, _info)| (id, _info, peer_pings.get(&id).expect("TODO the only case @skaunov see yet is when `ping` `Timeout` and the peer caught disconnecting not yet `remove` from infos")))
                                .partition::<Vec<_>, _>(|(_, _, ping)| ping.is_some());
                            relays.0.sort_unstable_by(|a, b| b.2.cmp(&a.2));
                            relays.1.extend(relays.0);
                            let mut relays = relays.1;
                            dbg!["TODO check the order is from `None` to the smallest", &relays];
                            let mut listener_added = false;
                            while !listener_added && !relays.is_empty() {
                                for addr in relays.pop().expect(MSG_CONDIT).1.listen_addrs.iter().filter(|adr| {
                                    !adr.protocol_stack().contains(&Protocol::P2pCircuit.tag()) && adr.protocol_stack().contains(&Protocol::Tcp(0).tag()) // #relayMultiadr
                                }) {match swarm.listen_on(addr.clone()) { 
                                    Ok(value) => {
                                        swarm_listeners.insert(value);
                                        swarm_listener_multiaddrs_autonat.insert(addr.to_owned(), None);
                                        listener_added = true;
                                        break
                                    }
                                    Err(_) => todo!(),
                                }}
                            }
                            if listener_added {todo!["punish `None`"]} else {
                                // TODO Try the addresses from `kad` (any other useful component too?); it could be made as a helper to serve both here and dialing the relay neighbors. Note that's improbable, so double usage improves an implemetation chance.
                                trace!["we know no peers we can build a `P2pCircuit` on which"]
                            }
                        }
                    } else {trace!["`autonat` probed `FromSwarm::NewExternalAddrCandidate` which we never listened to"]}

                    // let MSG_TODO = "every listening address should be tracked via `multiaddrs_autonat`";

                    // let is_reachable = 
                    // let is_node_unreachable = {is_reachable == Some(false)}; 
                    // let mut inserted_result = false;
                    // let i = swarm_listeners.iter_mut();

                    // while is_node_unreachable || !inserted_result {
                    //     if let Some((l, adrs)) = i.next() {
                    //         if !inserted_result {if let Some(a) = adrs.get_mut(&tested_addr) {
                    //             *a = is_reachable;
                    //             inserted_result = true;
                    //         }}
                    //         if is_node_unreachable {is_node_unreachable = !adrs}

                    // }

                    // // *multiaddrs_autonat.get_mut(&tested_addr) = ;
                    // // swarm_listeners.iter().find(|p| p.1.contains(&tested_addr)).expect(MSG_TODO);
                    // // swarm_listeners.values_mut().flat_map(|ll| ll.entries());//.find(|ads| ads);

                    // if is_node_unreachable {todo!["listen on a relay"]}
                }
                // TODO apply returned `PeerSanction` when DB will be here?
                SwarmEvent::Behaviour(ComposedBehaviourEvent::Gossipsub(libp2p::gossipsub::Event::Message { propagation_source, message_id, message })) => 
                    // CBOR was chosen here just because it's used for `libp2p::request_response` anyway
                    if !swarm.behaviour_mut().gossipsub.report_message_validation_result(
                        &message_id, 
                        &propagation_source, 
                        {
                            if topic_block.hash() == message.topic {cbor4ii::serde::from_slice::<Block>(message.data.as_slice()).map(
                                // fun fact: `#[serde(skip)]` in `Block` does the same here what documented for `TransferBlock`
                                |block| async {
                                    // @skaunov don't know how exactly this helps --- just repeatin the current/legacy implementation
                                    //      Just for fun @skaunov replaced that `TryFrom` for `From` which returns the genesis, and it seems to fly with the tests well.
                                    if block.kernel.header.height.is_genesis() {MessageAcceptance::Reject} else {
                                        match global_state_lock.lock_guard().await.chain.archival_state().get_block(block.header().prev_block_digest).await {
                                            Ok(Some(parent)) => {
                                                // TODO an insignificant saving would be returning these things on success by the function
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
                            else if topic_tx_singleproof.hash() == message.topic {
                                cbor4ii::serde::from_slice::<crate::protocol::peer::transfer_transaction::TransferTransaction>(message.data.as_slice()).map(
                                    |tx| async {match crate::application::loops::handle_tx_from_peer::the(
                                        global_state_lock.clone(), to_main.clone(), crate::api::export::Timestamp::now(), tx
                                    ).await {
                                        Some(Some(_)) => MessageAcceptance::Reject,
                                        Some(None) => MessageAcceptance::Ignore,
                                        None => MessageAcceptance::Accept
                                    }}
                                ).map(|fut| Box::pin(fut) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>)
                            } else if topic_tx_proofcollection_notif.hash() == message.topic {
                                todo![]
                            } else if topic_proposal.hash() == message.topic {cbor4ii::serde::from_slice::<Block>(message.data.as_slice()).map(|proposal| async {
                                match super::super::super::super::handle_proposal_from_peer::the(
                                    global_state_lock.clone(), to_main.clone(), crate::api::export::Timestamp::now(), Protocol::P2p(propagation_source).into(), proposal
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
                        }.unwrap_or_else(|e| match e {
                            e @ DecodeError::Custom(_) => {
                                debug!["{e} |{} |{propagation_source} |{message_id}", message.topic];
                                Box::pin(futures::future::ready(MessageAcceptance::Reject)) as Pin<Box<dyn Future<Output = MessageAcceptance> + Send>>
                            }
                            DecodeError::Core(_) => unreachable!["`Infallible`"]
                        }).await
                    ) {
                        tracing::error!("Gossip-sub not catching up with the message validation |{} |{}", message_id, propagation_source)
                    },
                // SwarmEvent::Behaviour(ComposedBehaviourEvent::Reqresp(libp2p::request_response::Event::Message{ peer, connection_id: _, message })) => {
                //     let (m, resp) = match message {
                //         libp2p::request_response::Message::Request{ request_id: _, request, channel } => (request, Some(channel)),
                //         libp2p::request_response::Message::Response{ request_id: _, response } => (response, None)
                //     };
                // }
                SwarmEvent::ConnectionClosed { peer_id, connection_id, endpoint, num_established, cause } => {
                    if let Some(e) = cause {warn!["{e} |{peer_id} |{connection_id} |{endpoint:?} |{num_established}"]}
                    if num_established == 0 {
                        let _disconnected = (/* peers_info.remove(&peer_id), */ peer_pings.remove(&peer_id), peer_infos.remove(&peer_id));
                        // TODO spawn a task to save `_disconnected` to DB (like standings)
                    }
                }
                SwarmEvent::NewListenAddr { listener_id, mut address } => { //  TODO check/test that `identify` catches this 
                    info!["{address}| One of our listeners has reported a new local listening address."];
                    debug_assert!(swarm_listeners.contains(&listener_id));
                    swarm_listener_multiaddrs_autonat.insert(address.clone(), None);
                    if address.protocol_stack().contains(&Protocol::P2pCircuit.tag()) {
                        trace!["We started new listener on a relay. So let's `.dial` all the addresses which also listen on this relay to enhance a connection upgrade chance."];
                        let relay_id = {
                            let _debug = address.pop().expect("can't come without our own `PeerId`");
                            debug_assert_eq!(_debug, Protocol::P2p(swarm.local_peer_id().clone()));
                            let _debug = address.pop().expect("should be `Protocol::P2pCircuit`");
                            debug_assert_eq!(_debug, Protocol::P2pCircuit);
                            address.pop().expect("`Protocol::P2pCircuit` should have `Protocol::P2p(PeerId)` before it")
                        };
                        std::assert_matches::debug_assert_matches!(relay_id, Protocol::P2p(_), "TODO check/test this well");
                        if peer_infos.iter()
                        .filter(|(_, info)| info.listen_addrs.iter().any(|addr| {
                            let mut i = addr.iter();
                            i.contains(&relay_id) && i.contains(&Protocol::P2pCircuit)
                        })).map(|(_, info)| info.listen_addrs.iter().cloned()).flatten().map(|adr| swarm.dial(adr)).all(|r| r.is_err()) {
                            trace!["We're not connected to anybody listening on this [relay]({relay_id}). Let's try to `.dial` all such addresses we have in Kademlia table then."];
                            if swarm.behaviour_mut().kad.kbuckets().map(|bucket| bucket.iter().map(|v| v.node.value.iter().cloned()).flatten().collect::<Vec<_>>())
                            .flatten().filter(|addr| {addr.iter().contains(&relay_id) && addr.iter().contains(&Protocol::P2pCircuit)}).collect_vec().into_iter()
                            .map(|adr| swarm.dial(adr)).all(|r| r.is_err()) {debug!["We know no peers on our [relay]({relay_id}). Maybe our node is the first here."]}
                        }
                    }
                }
                ev @ SwarmEvent::ExpiredListenAddr { listener_id, address: _ } => {
                    debug![?ev];
                    // match listener_restart(&mut swarm) {
                    //     Ok(l) => {
                    //         trace!["listener restarted |{l}"];
                    //         listeners.push(l);
                    //     }
                    //     Err(e) => warn!("can continue using only outgoing connections |{e}")
                    // }
                    todo!["restart just the IPv6: can it be done without new listen call, can it do this auto and just report the IPv6 change?"];
                }
                SwarmEvent::ListenerClosed { listener_id, addresses, reason } => {
                    // TODO ~~not here~~ (?) but would be nice to have listener crash #monitoring
                    let _debug = swarm_listeners.remove(&listener_id);
                    debug_assert!(_debug, "all the listeners should be tracked in `swarm_listeners`");
                }
                SwarmEvent::NewExternalAddrOfPeer { peer_id, address } => {
                    // quite strange `kad` requires the call and Gossip picks up the event itself; chances are @skaunov just don't get this right yet
                    swarm.behaviour_mut().kad.add_address(&peer_id, address);
                } 
                /* __________________________________________________________________________________________________________________
                events which doesn't carry an interesting thing are commented here yet to be in front of the eyes at this early stage
                 */
                SwarmEvent::ExternalAddrConfirmed { address } => {/* `autonat` does this job now; without it @skaunov would `.listen_on(address)` the (in fact observed by `identify`) address to keep the listeners healthy */}
                SwarmEvent::IncomingConnection { connection_id, local_addr, send_back_addr } => {}
                SwarmEvent::ConnectionEstablished { peer_id, connection_id, endpoint, num_established, concurrent_dial_errors, established_in } => {}
                /* ~~why does this says 'a non-fatal'?~~
                        fatal will be the `reason` in `ListenerClosed` */
                ev @ SwarmEvent::ListenerError { .. } => debug![?ev],
                SwarmEvent::IncomingConnectionError { connection_id, local_addr, send_back_addr, error, peer_id } => {}
                SwarmEvent::OutgoingConnectionError { connection_id, peer_id, error } => {}
                SwarmEvent::Dialing { peer_id, connection_id } => {}
                SwarmEvent::NewExternalAddrCandidate { address } => {}
                SwarmEvent::ExternalAddrExpired { address } => {}

                ev => {dbg![ev];}
            }
        }
        /* TODO it might be sensible to have here another branch of the least priority to feed the dashboard with data about the `swarm` (like peers, listening address, and whatever) #monitoring
                maybe send the "big" amount of this data once in awhile but only when all the other queues are exhausted */
    }}
    swarm_listeners.into_iter().for_each(|l| {swarm.remove_listener(l);});
    swarm.connected_peers().cloned().collect_vec().into_iter().for_each(|p| {swarm.disconnect_peer_id(p);});
    tokio::spawn(async move {
        trace!("started the task to drive `swarm` to close everything it had");
        while 0 != swarm.connected_peers().count() + swarm.listeners().count() {match swarm.select_next_some().await {
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
        }}
        trace!("`0 == swarm.connected_peers().count() + swarm.listeners().count()`");
    });
    
    // todo!["save standings and addresses to a DB"]
    /* @skaunov am surprised that peer standings are just flushed and not persisted (see `flush_databases`). I'd say saving the top peers to disk would be beneficial.
    As well as prepopulating that DB, and also having centralized sources 
    to download the first peers (block explorers and other public servers and RPC could serve this). */
}