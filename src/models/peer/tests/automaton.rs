// should be ok for tests
#![allow(clippy::large_enum_variant)]

/*
After further progressing on the task I start to feel that making a `Strategy` for `Mock` would differ only in a facility to check invariants between sending a `PeerMessage`. But it would naturally work towards [test-case generating] since it would require to develop `Strategy` down the types used in `PeerMessage`

I mean the whole `proptest` state machine testing is basically a `Strategy` over transitions (which are literally `PeerMessage` here), feeding it into the system (which is `PeerLoopHandler` for us, probably after `run_wrapper` like `Mock` do), and then shrinking the strategy. Hence I found myself with implementations of both state machines and adapting `Mock` for their approach when it seems that just making (an equally complex) `Strategy` for `Mock` would be a cleaner and more maintainable solution.

I wonder how should I finish that

[test-case generating]: https://github.com/Neptune-Crypto/neptune-core/issues/110 */

use futures::SinkExt;
use proptest_state_machine::ReferenceStateMachine;
use tokio::runtime::Runtime;

use crate::{
    models::state::GlobalStateLock, peer_loop::PeerLoopHandler, MainToPeerTask, PeerTaskToMain,
};

pub mod reference;
mod stream_mock;

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
        }
    }

    fn apply(
        state: Self::SystemUnderTest,
        _ref_state: &<Self::Reference as ReferenceStateMachine>::State,
        transition: <Self::Reference as ReferenceStateMachine>::Transition,
    ) -> Self::SystemUnderTest {
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
        } = state;

        let g_cloned = g.clone();
        rt.block_on(async {
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
        });

        Self {
            main_sim,
            rt,
            sock,
            hold_the_end,
            g,
            peer_address,
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
    fn automaton(sequential 1..20 => TheSut);
}
