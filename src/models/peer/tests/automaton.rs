// should be ok for tests
#![allow(clippy::large_enum_variant)]

use futures::SinkExt;
use proptest_state_machine::ReferenceStateMachine;
use reference::{AssosiatedData, Transition};
use tokio::runtime::Runtime;

use crate::{
    models::state::GlobalStateLock, peer_loop::PeerLoopHandler, MainToPeerTask, PeerTaskToMain,
};

pub mod reference;
mod stream_mock;

const BLOCKS_NEW_LEN: usize = 11;

struct TheSut {
    main_sim: crate::mpsc::Receiver<PeerTaskToMain>,
    // h: PeerLoopHandler,
    rt: Runtime,
    // counter: MutablePeerState,
    // sink: Mock<PeerMessage>,
    // dbg: u16
    sock: stream_mock::PeerMessageSocket,
    hold_the_end: tokio::sync::broadcast::Sender<MainToPeerTask>,
    g: GlobalStateLock,
    peer_address: std::net::SocketAddr,
    // h: PeerLoopHandler,
    stopped: bool,
}
impl proptest_state_machine::StateMachineTest for TheSut {
    type SystemUnderTest = Self;
    type Reference = reference::Automaton;

    fn init_test(
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
    ) -> Self::SystemUnderTest {
        let (sock_runner, sock_t) = stream_mock::create_peer_message_duplex();

        let rt = Runtime::new()
            .expect("Tokio should start for the `prop_state_machine!` state machine test");
        // let g = rt.block_on(
        //     crate::tests::shared::mock_genesis_global_state(Main, 2, todo!(), crate::config_models::cli_args::Args::default())
        // );

        let (peer_broadcast_tx, from_main_rx_clone, to_main_tx, to_main_rx1, g, hsd) = rt
            .block_on(crate::tests::shared::get_test_genesis_setup(
                crate::config_models::network::Network::Main,
                2,
                crate::config_models::cli_args::Args::default(),
            ))
            .unwrap();
        let peer_address = dbg!(crate::tests::shared::get_dummy_socket_address(2));
        // let from_main_rx_clone = peer_broadcast_tx.subscribe();
        let mut h = PeerLoopHandler::new(
            to_main_tx,
            g.clone(),
            peer_address,
            hsd,
            ref_state.is_inbound,
            1,
        );
        rt.spawn(async move {
            h.run_wrapper(sock_t, from_main_rx_clone).await.unwrap();
        });

        Self {
            main_sim: to_main_rx1,

            // h: PeerLoopHandler::new( //with_mocked_time(
            //     to_main_tx,
            //     alice.clone(),
            //     crate::tests::shared::get_dummy_socket_address(2),
            //     handshake_data,//.clone(),
            //     true,
            //     1,
            //     // now,
            // ), //.set_rng(_)
            rt,
            // counter: MutablePeerState::new(Default::default()),
            // sink: Mock::new(Vec::<crate::tests::shared::Action<PeerMessage>>::new()),
            // dbg: 0,
            sock: sock_runner,
            hold_the_end: peer_broadcast_tx,
            g: g.clone(),
            peer_address,
            // h
            stopped: false,
        }
    }

    fn apply(
        state: Self::SystemUnderTest,
        ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
        if state.stopped {
            return state;
        }
        let Self {
            // mut h,
            mut main_sim,
            rt,
            // mut counter,
            // mut sink,
            // dbg: mut dbg_c ,
            mut sock,
            hold_the_end,
            g,
            peer_address,
            // h
            mut stopped,
        } = state;

        let mut g_cloned = g.clone();
        let mut blocks_stuff = async |bs: Vec<crate::models::blockchain::block::Block>| {
            // let jq = g_cloned.vm_job_queue().clone();
            let mut g_guard = g_cloned.lock_guard_mut().await;
            for b in bs {
                dbg!(g_guard.set_new_tip(b).await.unwrap())
                    .into_iter()
                    .for_each(|j| {
                        rt.block_on(async {
                            j.upgrade(
                                crate::job_queue::triton_vm::vm_job_queue(),
                                Default::default(),
                            )
                            .await
                            .unwrap();
                        })
                    });
            }
        };
        // this gives a path problem
        // let mut g_cloned = g.clone();
        // let mut blocks_stuff_t = async |bs: Vec<crate::models::blockchain::block::Block>| {
        //     let mut g_guard = g_cloned.lock_guard_mut().await;
        //     let archival = g_guard.chain.archival_state_mut();
        //     for b in bs {
        //         crate::tests::shared::add_block_to_archival_state(archival, b).await.unwrap();
        //     }
        // };
        #[allow(clippy::shadow_unrelated)]
        let g_cloned = g.clone();

        rt.block_on(async {
            // dbg!(format!("{:?}", transition.0)
            //     .lines()
            //     .next()
            //     .unwrap_or_default());
            dbg!(&transition.1.is_some());
            match transition {
                Transition(_, Some(AssosiatedData::MakeNewBlocks(..))) => {
                    blocks_stuff(
                        ref_state.blocks[ref_state.blocks.len() - 1 - BLOCKS_NEW_LEN..].into(),
                    )
                    .await;

                    // let mut g_guard = g_cloned.lock_guard_mut().await;
                    // let l = ref_state.blocks.len();
                    // for i in BLOCKS_NEW_LEN..1 {
                    //     // let _ = g_guard.store_block_not_tip(ref_state.blocks[l-1 -i].clone());
                    // }
                    // // let _ = dbg!(g_guard.set_new_tip(ref_state.blocks[l-1].clone()).await);
                }
                Transition(_, Some(AssosiatedData::NewBlock(b))) => {
                    blocks_stuff(vec![b]).await;
                }
                _ => {}
            };

            // h.handle_peer_message_test(transition, &mut sink, &mut counter)
            sock.send(transition.0).await.unwrap();

            // reward/punishing behaviour can be defined here via `standing`; and signals to the `main`
            // assert_eq![ // TODO `prop_`?
            let _ = dbg!(main_sim.try_recv());
            dbg!(g_cloned
                .lock_guard()
                .await
                .net
                .peer_map
                .get(&state.peer_address));
            // .standing;
            // PeerTaskToMain::,
            // ];

            if let Some(crate::models::peer::peer_info::PeerInfo { standing, .. }) = g_cloned
                .lock_guard()
                .await
                .net
                .peer_map
                .get(&state.peer_address)
            {
                if standing.is_bad() {
                    stopped = true;
                }
            }
        });

        Self {
            main_sim,
            rt,
            sock,
            hold_the_end,
            g,
            peer_address,
            // h
            stopped,
        }
    }
}

/* Do you see the problem I got running `StateMachineTest for crate::peer_loop::PeerLoopHandler`?
Do you think it'd a good idea to start the `[#test]` with creating a new `Runtime` and `Mock` in it,
then create a separate system thread for the `Reference` and allow it to communitcate with
the `Mock`, then grab the result from the thread with the `Reference` and finish the `[#test]`? */
proptest_state_machine::prop_state_machine! {
    #![proptest_config(proptest::test_runner::Config::with_cases(1))]
    #[test]
    fn automaton(sequential 1..50 => TheSut);
}
