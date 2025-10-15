use std::collections::HashMap;

use libp2p::PeerId;

use crate::application::loops::main_loop::p2p::relay_maybe;

pub(crate) mod swarm;

fn relay_connect_ifneeded(
    swarm_listener_multiaddrs_autonat: &mut HashMap<libp2p::Multiaddr, Option<bool>>,
    peer_infos: &HashMap<PeerId, libp2p::identify::Info>,
    peer_pings: &HashMap<PeerId, Option<std::time::Duration>>,
    swarm_listeners: &mut std::collections::HashSet<libp2p::core::transport::ListenerId>,
    swarm: &mut libp2p::Swarm<super::ComposedBehaviour>,
) {
    if swarm_listener_multiaddrs_autonat
        .values()
        .all(|s| s == &Some(false))
    {
        tracing::info!["all the addresses of listeners were checked via `autonat`, and all failed; hence we need to use a relay"];
        let mut relays = peer_infos
            .iter()
            .filter(|(_id, info)| {
                info.protocols.contains(
                    &libp2p::relay::HOP_PROTOCOL_NAME, // ~~TODO~~ debug this to be sure this approach works
                ) && info.listen_addrs.iter().any(relay_maybe)
            })
            // ~~the only case @skaunov see yet when `peer_pings` can have no `&id` is `ping` `Timeout` and the peer caught disconnecting and to `remove` from infos; so it's ok to just filter him out~~
            //      hence the `expect` was changed for `filter_`
            .filter_map(|(id, info)| peer_pings.get(id).map(|ping| (id, info, ping)))
            .partition::<Vec<_>, _>(|(_, _, ping)| ping.is_some());
        relays.0.sort_unstable_by(|a, b| b.2.cmp(a.2));
        relays.1.extend(relays.0);
        let mut relays = relays.1;
        #[cfg(test)]
        dbg![
            "TODO check the order is from `None` to the smallest",
            &relays
        ];
        let mut listener_added = false;
        while !listener_added && !relays.is_empty() {
            let (relay_id, addrs, _) = relays.pop().expect(crate::application::loops::MSG_CONDIT);
            for addr in addrs.listen_addrs.iter().filter(|a| relay_maybe(a)) {
                match swarm.listen_on(
                    match addr.clone().with_p2p(*relay_id) {
                        Ok(inner) => inner,
                        Err(inner) => inner,
                    }
                    .with(multiaddr::Protocol::P2pCircuit)
                    .with_p2p(swarm.local_peer_id().to_owned())
                    .expect("just added `P2pCircuit` as the ending"),
                ) {
                    Ok(value) => {
                        swarm_listeners.insert(value);
                        swarm_listener_multiaddrs_autonat.insert(addr.to_owned(), None);
                        listener_added = true;
                        break;
                    }
                    Err(e) => tracing::debug!("{e}"),
                }
            }
        }
        if listener_added {
            // TODO #DB Punish the peers left in `relays` who has `None` for their ping for not following the protocol and adding the complexity here.
        } else {
            /* TODO #followUp Try the addresses from `kad` (any other useful component too?); it could be made as a helper to serve both here and dialing
            the relay neighbors. Note that's improbable, so double usage improves an implemetation chance. */
            tracing::debug!["we know no peers we can build a `P2pCircuit` on which"]
        }
    }
}
