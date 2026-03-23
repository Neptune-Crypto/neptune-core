use anyhow::Result;
use macro_rules_attr::apply;
use num_traits::One;
use num_traits::Zero;
use proptest::prop_assume;
use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use strum::IntoEnumIterator;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::bfe;
use tracing_test::traced_test;

use super::*;
use crate::api::export::TxProvingCapability;
use crate::application::config::cli_args;
use crate::application::config::network::Network;
use crate::application::database::storage::storage_vec::traits::*;
use crate::application::rpc::server::NeptuneRPCServer;
use crate::protocol::consensus::block::block_selector::BlockSelectorLiteral;
use crate::protocol::peer::NegativePeerSanction;
use crate::protocol::peer::PeerSanction;
use crate::protocol::proof_abstractions::mast_hash::MastHash;
use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
use crate::state::wallet::address::generation_address::GenerationSpendingKey;
use crate::state::wallet::utxo_notification::UtxoNotificationMedium;
use crate::state::wallet::wallet_entropy::WalletEntropy;
use crate::tests::shared::blocks::invalid_block_with_transaction;
use crate::tests::shared::blocks::make_mock_block;
use crate::tests::shared::files::unit_test_data_directory;
use crate::tests::shared::globalstate::mock_genesis_global_state;
use crate::tests::shared::strategies::txkernel;
use crate::tests::shared_tokio_runtime;
use crate::util_types::mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use crate::BFieldElement;
use crate::Block;

const NUM_ANNOUNCEMENTS_BLOCK1: usize = 7;

async fn test_rpc_server(
    wallet_entropy: WalletEntropy,
    peer_count: u8,
    cli: cli_args::Args,
) -> NeptuneRPCServer {
    let global_state_lock =
        mock_genesis_global_state(peer_count, wallet_entropy, cli.clone()).await;

    let data_directory = unit_test_data_directory(cli.network).unwrap();

    let valid_tokens: Vec<auth::Token> =
        vec![auth::Cookie::try_new(&data_directory).await.unwrap().into()];

    let rpc_to_main_tx = global_state_lock.rpc_server_to_main_tx();

    NeptuneRPCServer::new(
        global_state_lock,
        rpc_to_main_tx,
        data_directory,
        valid_tokens,
    )
}

async fn cookie_token(server: &NeptuneRPCServer) -> auth::Token {
    auth::Cookie::try_load(server.data_directory())
        .await
        .unwrap()
        .into()
}

#[apply(shared_tokio_runtime)]
async fn network_response_is_consistent() -> Result<()> {
    for network in [Network::Main, Network::Testnet(0)] {
        let rpc_server = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        assert_eq!(network, rpc_server.network(context::current()).await?);
    }

    Ok(())
}

#[apply(shared_tokio_runtime)]
async fn verify_that_all_requests_leave_server_running() -> Result<()> {
    // Got through *all* request types and verify that server does not crash.
    // We don't care about the actual response data in this test, just that the
    // requests do not crash the server.

    let network = Network::Main;
    let mut rng = StdRng::seed_from_u64(123456789088u64);

    let rpc_server = test_rpc_server(
        WalletEntropy::new_pseudorandom(rng.random()),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let ctx = context::current();
    let _ = rpc_server.clone().network(ctx).await;
    let _ = rpc_server
        .clone()
        .own_listen_address_for_peers(ctx, token)
        .await;
    let _ = rpc_server.clone().own_instance_id(ctx, token).await;
    let _ = rpc_server.clone().block_height(ctx, token).await;
    let _ = rpc_server.clone().best_proposal(ctx, token).await;
    let _ = rpc_server
        .clone()
        .latest_address(ctx, token, KeyType::Generation)
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .latest_address(ctx, token, KeyType::Symmetric)
        .await
        .unwrap();
    let _ = rpc_server.clone().peer_info(ctx, token).await;
    let _ = rpc_server
        .clone()
        .block_digests_by_height(ctx, token, 42u64.into())
        .await;
    let _ = rpc_server
        .clone()
        .block_digests_by_height(ctx, token, 0u64.into())
        .await;
    let _ = rpc_server.clone().all_punished_peers(ctx, token).await;
    let _ = rpc_server.clone().latest_tip_digests(ctx, token, 2).await;
    let _ = rpc_server
        .clone()
        .header(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server
        .clone()
        .block_info(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server
        .clone()
        .block_kernel(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server
        .clone()
        .addition_record_indices_for_block(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server
        .clone()
        .restore_membership_proof_privacy_preserving(
            ctx,
            token,
            vec![AbsoluteIndexSet::compute(
                Digest::default(),
                Digest::default(),
                Digest::default(),
                444,
            )],
        )
        .await;
    let _ = rpc_server
        .clone()
        .announcements_in_block(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server
        .clone()
        .block_heights_by_announcement_flags(
            ctx,
            token,
            vec![AnnouncementFlag {
                flag: bfe!(0),
                receiver_id: bfe!(0),
            }],
        )
        .await;
    let _ = rpc_server
        .clone()
        .block_digest(ctx, token, BlockSelector::Digest(Digest::default()))
        .await;
    let _ = rpc_server.clone().utxo_digest(ctx, token, 0).await;
    let _ = rpc_server
        .clone()
        .confirmed_available_balance(ctx, token)
        .await;
    let _ = rpc_server.clone().history(ctx, token).await;
    let _ = rpc_server.clone().wallet_status(ctx, token).await;
    let own_receiving_address = rpc_server
        .clone()
        .next_receiving_address(ctx, token, KeyType::Generation)
        .await?;
    let _ = rpc_server.clone().mempool_tx_count(ctx, token).await;
    let _ = rpc_server.clone().mempool_size(ctx, token).await;
    let _ = rpc_server.clone().dashboard_overview_data(ctx, token).await;
    let _ = rpc_server
        .clone()
        .validate_address(
            ctx,
            token,
            "Not a valid address".to_owned(),
            Network::Testnet(0),
        )
        .await;
    let _ = rpc_server.clone().pow_puzzle_internal_key(ctx, token).await;
    let _ = rpc_server
        .clone()
        .pow_puzzle_external_key(ctx, token, own_receiving_address.clone())
        .await;
    let _ = rpc_server
        .clone()
        .provide_pow_solution(ctx, token, rng.random(), rng.random())
        .await;
    let _ = rpc_server
        .clone()
        .full_pow_puzzle_external_key(ctx, token, own_receiving_address.clone())
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .spendable_inputs(ctx, token)
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .select_spendable_inputs(
            ctx,
            token,
            InputSelectionPolicy::Random,
            NativeCurrencyAmount::coins(5),
        )
        .await;
    let _ = rpc_server
        .clone()
        .generate_tx_outputs(ctx, token, vec![])
        .await
        .unwrap();
    let tx_details = rpc_server
        .clone()
        .generate_tx_details(
            ctx,
            token,
            TxInputList::default(),
            TxOutputList::default(),
            ChangePolicy::default(),
            NativeCurrencyAmount::zero(),
        )
        .await
        .unwrap();
    let tx_proof = rpc_server
        .clone()
        .generate_witness_proof(ctx, token, tx_details.clone())
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .assemble_transaction(ctx, token, tx_details, tx_proof)
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .provide_new_tip(ctx, token, rng.random(), Block::genesis(network))
        .await
        .unwrap();
    let _ = rpc_server
        .clone()
        .block_intervals(
            ctx,
            token,
            BlockSelector::Special(BlockSelectorLiteral::Tip),
            None,
        )
        .await;
    let _ = rpc_server
        .clone()
        .block_difficulties(
            ctx,
            token,
            BlockSelector::Special(BlockSelectorLiteral::Tip),
            None,
        )
        .await;
    let _ = rpc_server
        .clone()
        .broadcast_all_mempool_txs(ctx, token)
        .await;
    let _ = rpc_server.clone().mempool_overview(ctx, token, 0, 20).await;
    let _ = rpc_server
        .clone()
        .mempool_tx_kernel(ctx, token, Default::default())
        .await;
    let _ = rpc_server.clone().clear_all_standings(ctx, token).await;
    let _ = rpc_server
        .clone()
        .clear_standing_by_ip(ctx, token, "127.0.0.1".parse().unwrap())
        .await;
    let output: OutputFormat = (
        own_receiving_address.clone(),
        NativeCurrencyAmount::one_nau(),
    )
        .into();
    let _ = rpc_server
        .clone()
        .rescan_announced(ctx, token, 0u64.into(), 14u64.into(), None)
        .await;
    let _ = rpc_server
        .clone()
        .rescan_expected(ctx, token, 0u64.into(), 14u64.into())
        .await;
    let _ = rpc_server
        .clone()
        .rescan_outgoing(ctx, token, 0u64.into(), 14u64.into())
        .await;
    let _ = rpc_server
        .clone()
        .rescan_guesser_rewards(ctx, token, 0u64.into(), 14u64.into())
        .await;
    let _ = rpc_server
        .clone()
        .send(
            ctx,
            token,
            vec![output],
            ChangePolicy::ExactChange,
            NativeCurrencyAmount::one_nau(),
        )
        .await;
    let _ = rpc_server
        .clone()
        .upgrade(ctx, token, TransactionKernelId::default())
        .await;
    let _ = rpc_server.clone().mempool_tx_ids(ctx, token).await;

    let my_output: OutputFormat = (own_receiving_address, NativeCurrencyAmount::one_nau()).into();
    let _ = rpc_server
        .clone()
        .send(
            ctx,
            token,
            vec![my_output],
            ChangePolicy::ExactChange,
            NativeCurrencyAmount::one_nau(),
        )
        .await;

    let _ = rpc_server.clone().pause_miner(ctx, token).await;
    let _ = rpc_server.clone().restart_miner(ctx, token).await;
    let _ = rpc_server
        .clone()
        .set_coinbase_distribution(ctx, token, vec![])
        .await;
    let _ = rpc_server
        .clone()
        .unset_coinbase_distribution(ctx, token)
        .await;
    let _ = rpc_server
        .clone()
        .prune_abandoned_monitored_utxos(ctx, token)
        .await;
    let _ = rpc_server.shutdown(ctx, token).await;

    Ok(())
}

#[apply(shared_tokio_runtime)]
async fn latest_address_and_get_new_address_are_consistent() {
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;

    for key_type in KeyType::iter() {
        let addr0 = rpc_server
            .clone()
            .latest_address(context::current(), token, key_type)
            .await
            .unwrap();
        let addr1 = rpc_server
            .clone()
            .next_receiving_address(context::current(), token, key_type)
            .await
            .unwrap();
        assert_ne!(addr0, addr1);

        let addr1_again = rpc_server
            .clone()
            .latest_address(context::current(), token, key_type)
            .await
            .unwrap();
        assert_eq!(addr1, addr1_again);

        let addr2 = rpc_server
            .clone()
            .next_receiving_address(context::current(), token, key_type)
            .await
            .unwrap();
        let addr2_again = rpc_server
            .clone()
            .latest_address(context::current(), token, key_type)
            .await
            .unwrap();
        assert_eq!(addr2, addr2_again);

        // Ensure endpoint is idempotent
        let addr2_again_again = rpc_server
            .clone()
            .latest_address(context::current(), token, key_type)
            .await
            .unwrap();
        assert_eq!(addr2, addr2_again_again);
    }
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn balance_is_zero_at_init() -> Result<()> {
    // Verify that a wallet not receiving a premine is empty at startup
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let balance = rpc_server
        .confirmed_available_balance(context::current(), token)
        .await?;
    assert!(balance.is_zero());

    Ok(())
}

#[apply(shared_tokio_runtime)]
async fn create_and_broadcast_valid_tx_through_rpc_endpoints() {
    // Go through a list of endpoints resulting in a valid
    // PrimitiveWitness-backed transaction. Uses the devnet premine UTXO to
    // fund the transaction.
    let network = Network::Main;
    let rpc_server = test_rpc_server(
        WalletEntropy::devnet_wallet(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let ctx = context::current();
    let spendable_inputs = rpc_server
        .clone()
        .spendable_inputs(ctx, token)
        .await
        .unwrap();
    assert_eq!(
        1,
        spendable_inputs.len(),
        "Devnet wallet on genesis block must have one spendable input (since timelock has passed)."
    );

    let third_party_address = GenerationReceivingAddress::derive_from_seed(Default::default());
    let inputs = rpc_server
        .clone()
        .select_spendable_inputs(
            ctx,
            token,
            InputSelectionPolicy::Random,
            NativeCurrencyAmount::coins(19),
        )
        .await
        .unwrap();

    let send_amt = NativeCurrencyAmount::coins(17);
    let outputs = rpc_server
        .clone()
        .generate_tx_outputs(
            ctx,
            token,
            vec![OutputFormat::AddressAndAmount(
                third_party_address.into(),
                send_amt,
            )],
        )
        .await
        .unwrap();
    let fee = NativeCurrencyAmount::coins(2);
    let tx_details = rpc_server
        .clone()
        .generate_tx_details(ctx, token, inputs, outputs, ChangePolicy::default(), fee)
        .await
        .unwrap();
    assert_eq!(1, tx_details.tx_inputs.len());
    assert_eq!(
        2,
        tx_details.tx_outputs.len(),
        "Must have recipient and change output"
    );
    assert_eq!(
        NativeCurrencyAmount::coins(18),
        tx_details.tx_outputs.total_native_coins(),
        "Total output must be balance - fee = 20 - 2 = 18 coins."
    );

    let tx_proof = rpc_server
        .clone()
        .generate_witness_proof(ctx, token, tx_details.clone())
        .await
        .unwrap();
    let tx = rpc_server
        .clone()
        .assemble_transaction(ctx, token, tx_details.clone(), tx_proof.clone())
        .await
        .unwrap();

    let consensus_rule_set = rpc_server.state.lock_guard().await.consensus_rule_set();
    assert!(
        tx.is_valid(network, consensus_rule_set).await,
        "Constructed tx must be valid"
    );

    assert_eq!(1, tx.kernel.inputs.len());
    assert_eq!(2, tx.kernel.outputs.len());
    assert_eq!(fee, tx.kernel.fee);

    let tx_artifacts = rpc_server
        .clone()
        .assemble_transaction_artifacts(ctx, token, tx_details.clone(), tx_proof.clone())
        .await
        .unwrap();
    let output_amount = tx_artifacts.details.tx_outputs.total_native_coins();
    assert_eq!(
        NativeCurrencyAmount::coins(18),
        output_amount,
        "Total output must be balance - fee = 20 - 2 = 18 coins. Got: {output_amount}"
    );

    // Broadcast transaction and verify insertion into mempool
    assert_eq!(0, rpc_server.state.lock_guard().await.mempool.len());
    rpc_server
        .clone()
        .record_and_broadcast_transaction(ctx, token, tx_artifacts)
        .await
        .unwrap();
    assert_eq!(1, rpc_server.state.lock_guard().await.mempool.len());
    assert!(rpc_server
        .state
        .lock_guard()
        .await
        .mempool
        .contains(tx.txid()));

    // Ensure `proof_type` endpoint finds the transaction in the mempool
    rpc_server.proof_type(ctx, token, tx.txid()).await.unwrap();
}

#[expect(clippy::shadow_unrelated)]
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn clear_ip_standing_test() -> Result<()> {
    let mut rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let rpc_request_context = context::current();
    let (peer_id0, peer_address0, peer_id1, peer_address1) = {
        let global_state = rpc_server.state.lock_guard().await;

        let entries = global_state.net.peer_map.iter().collect::<Vec<_>>();
        (
            *entries[0].0,
            entries[0].1.address(),
            *entries[1].0,
            entries[1].1.address(),
        )
    };

    // Verify that sanctions list is empty
    let punished_peers_startup = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert!(
        punished_peers_startup.is_empty(),
        "Sanctions list must be empty at startup"
    );

    // sanction both
    let (standing0, standing1) = {
        let mut global_state_mut = rpc_server.state.lock_guard_mut().await;

        global_state_mut
            .net
            .peer_map
            .entry(peer_id0)
            .and_modify(|p| {
                p.standing
                    .sanction(PeerSanction::Negative(
                        NegativePeerSanction::DifferentGenesis,
                    ))
                    .unwrap_err();
            });
        global_state_mut
            .net
            .peer_map
            .entry(peer_id1)
            .and_modify(|p| {
                p.standing
                    .sanction(PeerSanction::Negative(
                        NegativePeerSanction::DifferentGenesis,
                    ))
                    .unwrap_err();
            });
        let standing_0 = global_state_mut.net.peer_map[&peer_id0].standing;
        let standing_1 = global_state_mut.net.peer_map[&peer_id1].standing;
        (standing_0, standing_1)
    };

    // Verify expected sanctions reading
    let punished_peers_from_memory = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert_eq!(
        2,
        punished_peers_from_memory.len(),
        "Punished list must have two elements after sanctionings"
    );

    let ip0 = peer_address0
        .iter()
        .find_map(|component| match component {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .unwrap();
    let ip1 = peer_address1
        .iter()
        .find_map(|component| match component {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .unwrap();

    {
        let mut global_state_mut = rpc_server.state.lock_guard_mut().await;

        global_state_mut
            .net
            .write_peer_standing_on_decrease(ip0, standing0)
            .await;
        global_state_mut
            .net
            .write_peer_standing_on_decrease(ip1, standing1)
            .await;
    }

    // Verify expected sanctions reading, after DB-write
    let punished_peers_from_memory_and_db = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert_eq!(
        2,
        punished_peers_from_memory_and_db.len(),
        "Punished list must have to elements after sanctionings and after DB write"
    );

    // Verify expected initial conditions
    {
        let global_state = rpc_server.state.lock_guard().await;
        let standing0 = global_state.net.get_peer_standing_from_database(ip0).await;
        assert_ne!(0, standing0.unwrap().standing);
        assert_ne!(None, standing0.unwrap().latest_punishment);
        let peer_standing_1 = global_state.net.get_peer_standing_from_database(ip1).await;
        assert_ne!(0, peer_standing_1.unwrap().standing);
        assert_ne!(None, peer_standing_1.unwrap().latest_punishment);
        drop(global_state);

        // Clear standing of #0
        rpc_server
            .clone()
            .clear_standing_by_ip(rpc_request_context, token, ip0)
            .await?;
    }

    // Verify expected resulting conditions in database
    {
        let global_state = rpc_server.state.lock_guard().await;
        let standing0 = global_state.net.get_peer_standing_from_database(ip0).await;
        assert_eq!(0, standing0.unwrap().standing);
        assert_eq!(None, standing0.unwrap().latest_punishment);
        let standing1 = global_state.net.get_peer_standing_from_database(ip1).await;
        assert_ne!(0, standing1.unwrap().standing);
        assert_ne!(None, standing1.unwrap().latest_punishment);

        // Verify expected resulting conditions in peer map
        let standing0_from_memory = global_state.net.peer_map[&peer_id0].clone();
        assert_eq!(0, standing0_from_memory.standing.standing);
        let standing1_from_memory = global_state.net.peer_map[&peer_id1].clone();
        assert_ne!(0, standing1_from_memory.standing.standing);
    }

    // Verify expected sanctions reading, after one forgiveness
    let punished_list_after_one_clear = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert!(
        punished_list_after_one_clear.len().is_one(),
        "Punished list must have to elements after sanctionings and after DB write"
    );

    Ok(())
}

#[expect(clippy::shadow_unrelated)]
#[traced_test]
#[apply(shared_tokio_runtime)]
async fn clear_all_standings_test() -> Result<()> {
    // Create initial conditions
    let mut rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let mut state = rpc_server.state.lock_guard_mut().await;

    let (peer_id0, peer_address0, peer_id1, peer_address1) = {
        let entries = state.net.peer_map.iter().collect::<Vec<_>>();
        (
            *entries[0].0,
            entries[0].1.address(),
            *entries[1].0,
            entries[1].1.address(),
        )
    };

    let ip0 = peer_address0
        .iter()
        .find_map(|component| match component {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .unwrap();
    let ip1 = peer_address1
        .iter()
        .find_map(|component| match component {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        })
        .unwrap();

    // sanction both peers
    let (standing0, standing1) = {
        state.net.peer_map.entry(peer_id0).and_modify(|p| {
            p.standing
                .sanction(PeerSanction::Negative(
                    NegativePeerSanction::DifferentGenesis,
                ))
                .unwrap_err();
        });
        state.net.peer_map.entry(peer_id1).and_modify(|p| {
            p.standing
                .sanction(PeerSanction::Negative(
                    NegativePeerSanction::DifferentGenesis,
                ))
                .unwrap_err();
        });
        (
            state.net.peer_map[&peer_id0].standing,
            state.net.peer_map[&peer_id1].standing,
        )
    };

    state
        .net
        .write_peer_standing_on_decrease(ip0, standing0)
        .await;
    state
        .net
        .write_peer_standing_on_decrease(ip1, standing1)
        .await;

    drop(state);

    // Verify expected initial conditions
    {
        let peer_standing0 = rpc_server
            .state
            .lock_guard_mut()
            .await
            .net
            .get_peer_standing_from_database(ip0)
            .await;
        assert_ne!(0, peer_standing0.unwrap().standing);
        assert_ne!(None, peer_standing0.unwrap().latest_punishment);
    }

    {
        let peer_standing1 = rpc_server
            .state
            .lock_guard_mut()
            .await
            .net
            .get_peer_standing_from_database(ip1)
            .await;
        assert_ne!(0, peer_standing1.unwrap().standing);
        assert_ne!(None, peer_standing1.unwrap().latest_punishment);
    }

    // Verify expected reading through an RPC call
    let rpc_request_context = context::current();
    let after_two_sanctions = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert_eq!(2, after_two_sanctions.len());

    // Clear standing of both by clearing all standings
    rpc_server
        .clone()
        .clear_all_standings(rpc_request_context, token)
        .await?;

    let state = rpc_server.state.lock_guard().await;

    // Verify expected resulting conditions in database
    {
        let peer_standing_0 = state.net.get_peer_standing_from_database(ip0).await;
        assert_eq!(0, peer_standing_0.unwrap().standing);
        assert_eq!(None, peer_standing_0.unwrap().latest_punishment);
    }

    {
        let peer_still_standing_1 = state.net.get_peer_standing_from_database(ip1).await;
        assert_eq!(0, peer_still_standing_1.unwrap().standing);
        assert_eq!(None, peer_still_standing_1.unwrap().latest_punishment);
    }

    // Verify expected resulting conditions in peer map
    {
        let peer_standing_0_from_memory = state.net.peer_map[&peer_id0].clone();
        assert_eq!(0, peer_standing_0_from_memory.standing.standing);
    }

    {
        let peer_still_standing_1_from_memory = state.net.peer_map[&peer_id1].clone();
        assert_eq!(0, peer_still_standing_1_from_memory.standing.standing);
    }

    // Verify expected reading through an RPC call
    let after_global_forgiveness = rpc_server
        .clone()
        .all_punished_peers(rpc_request_context, token)
        .await?;
    assert!(after_global_forgiveness.is_empty());

    Ok(())
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn utxo_digest_test() {
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let aocl_leaves = rpc_server
        .state
        .lock_guard()
        .await
        .chain
        .archival_state()
        .archival_mutator_set
        .ams()
        .aocl
        .num_leafs()
        .await;

    debug_assert!(aocl_leaves > 0);

    assert!(rpc_server
        .clone()
        .utxo_digest(context::current(), token, aocl_leaves - 1)
        .await
        .unwrap()
        .is_some());

    assert!(rpc_server
        .utxo_digest(context::current(), token, aocl_leaves)
        .await
        .unwrap()
        .is_none());
}

#[traced_test]
#[test_strategy::proptest(async = "tokio", cases = 5)]
async fn utxo_origin_block_test(
    #[strategy(txkernel::with_lengths(0usize, 1usize, 0usize, false))]
    transaction_kernel: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
) {
    prop_assume!(!transaction_kernel.fee.is_negative());

    let network = Network::Main;
    let mut rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let transaction = Transaction {
        kernel: transaction_kernel,
        proof: TransactionProof::invalid(),
    };
    let block = invalid_block_with_transaction(&Block::genesis(network), transaction);
    rpc_server.state.set_new_tip(block.clone()).await.unwrap();

    let token = cookie_token(&rpc_server).await;
    let output = block.body().transaction_kernel().outputs[0];
    let origin_block = rpc_server
        .utxo_origin_block(context::current(), token, output, None)
        .await
        .unwrap();

    assert!(
        origin_block.is_some(),
        "Expected origin block for included UTXO"
    );
    assert_eq!(
        origin_block.unwrap(),
        block.hash(),
        "UTXOs inclusion digest should match the origin block"
    );
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn block_kernel_test() {
    let network = Network::Main;
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let ctx = context::current();

    assert!(
        rpc_server
            .clone()
            .block_kernel(ctx, token, BlockSelector::Digest(Digest::default()))
            .await
            .unwrap()
            .is_none(),
        "Must return none on bad digest"
    );
    assert_eq!(
        Block::genesis(network).kernel.mast_hash(),
        rpc_server
            .block_kernel(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Genesis)
            )
            .await
            .expect("RPC call must pass")
            .expect("Must find genesis block")
            .mast_hash(),
        "Must know genesis block and must match genesis hash"
    );
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn block_info_test() {
    let network = Network::RegTest;
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let global_state = rpc_server.state.lock_guard().await;
    let ctx = context::current();

    let genesis_hash = global_state.chain.archival_state().genesis_block().hash();
    let tip_hash = global_state.chain.light_state().hash();

    let genesis_block_info = BlockInfo::new(
        global_state.chain.archival_state().genesis_block(),
        genesis_hash,
        tip_hash,
        vec![],
        global_state
            .chain
            .archival_state()
            .block_belongs_to_canonical_chain(genesis_hash)
            .await,
    );

    assert!(
        genesis_block_info.num_announcements.is_zero(),
        "Genesis block contains no announcements. Block info must reflect that."
    );

    let tip_block_info = BlockInfo::new(
        global_state.chain.light_state(),
        genesis_hash,
        tip_hash,
        vec![],
        global_state
            .chain
            .archival_state()
            .block_belongs_to_canonical_chain(tip_hash)
            .await,
    );

    // should find genesis block by Genesis selector
    assert_eq!(
        genesis_block_info,
        rpc_server
            .clone()
            .block_info(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Genesis)
            )
            .await
            .unwrap()
            .unwrap()
    );

    // should find latest/tip block by Tip selector
    assert_eq!(
        tip_block_info,
        rpc_server
            .clone()
            .block_info(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Tip)
            )
            .await
            .unwrap()
            .unwrap()
    );

    // should find genesis block by Height selector
    assert_eq!(
        genesis_block_info,
        rpc_server
            .clone()
            .block_info(ctx, token, BlockSelector::Height(BlockHeight::from(0u64)))
            .await
            .unwrap()
            .unwrap()
    );

    // should find genesis block by Digest selector
    assert_eq!(
        genesis_block_info,
        rpc_server
            .clone()
            .block_info(ctx, token, BlockSelector::Digest(genesis_hash))
            .await
            .unwrap()
            .unwrap()
    );

    // should not find any block when Height selector is u64::Max
    assert!(rpc_server
        .clone()
        .block_info(
            ctx,
            token,
            BlockSelector::Height(BlockHeight::from(u64::MAX))
        )
        .await
        .unwrap()
        .is_none());

    // should not find any block when Digest selector is Digest::default()
    assert!(rpc_server
        .clone()
        .block_info(ctx, token, BlockSelector::Digest(Digest::default()))
        .await
        .unwrap()
        .is_none());
}

#[traced_test]
#[test_strategy::proptest(async = "tokio", cases = 5)]
async fn announcements_in_block_test(
    #[strategy(txkernel::with_lengths(0usize, 2usize, NUM_ANNOUNCEMENTS_BLOCK1, false))]
    tx_block1: crate::protocol::consensus::transaction::transaction_kernel::TransactionKernel,
) {
    let network = Network::Main;
    let mut rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let tx_block1 = Transaction {
        kernel: tx_block1,
        proof: TransactionProof::invalid(),
    };
    let fee = tx_block1.kernel.fee;
    let block1 = invalid_block_with_transaction(&Block::genesis(network), tx_block1);
    let set_new_tip_result = rpc_server.state.set_new_tip(block1.clone()).await;
    assert!(fee.is_negative() == set_new_tip_result.is_err());

    let token = cookie_token(&rpc_server).await;
    let ctx = context::current();

    let Some(block1_announcements) = rpc_server
        .clone()
        .announcements_in_block(ctx, token, BlockSelector::Height(1u64.into()))
        .await
        .unwrap()
    else {
        // If the fee was negative, the block was invalid and not stored.
        // So the RPC should return None.
        assert!(fee.is_negative());

        // And in this case we cannot proceed with the test.
        return Ok(());
    };

    assert_eq!(
        block1.body().transaction_kernel.announcements,
        block1_announcements,
        "Must return expected announcements"
    );
    assert_eq!(
        NUM_ANNOUNCEMENTS_BLOCK1,
        block1_announcements.len(),
        "Must return expected number of announcements"
    );

    let genesis_block_announcements = rpc_server
        .clone()
        .announcements_in_block(ctx, token, BlockSelector::Height(0u64.into()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        genesis_block_announcements.is_empty(),
        "Genesis block has no announements"
    );

    assert!(
        rpc_server
            .announcements_in_block(ctx, token, BlockSelector::Height(2u64.into()))
            .await
            .unwrap()
            .is_none(),
        "announcements in unknown block must return None"
    );
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn block_digest_test() {
    let network = Network::RegTest;
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(network),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let global_state = rpc_server.state.lock_guard().await;
    let ctx = context::current();

    let genesis_hash = Block::genesis(network).hash();

    // should find genesis block by Genesis selector
    assert_eq!(
        genesis_hash,
        rpc_server
            .clone()
            .block_digest(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Genesis)
            )
            .await
            .unwrap()
            .unwrap()
    );

    // should find latest/tip block by Tip selector
    assert_eq!(
        global_state.chain.light_state().hash(),
        rpc_server
            .clone()
            .block_digest(
                ctx,
                token,
                BlockSelector::Special(BlockSelectorLiteral::Tip)
            )
            .await
            .unwrap()
            .unwrap()
    );

    // should find genesis block by Height selector
    assert_eq!(
        genesis_hash,
        rpc_server
            .clone()
            .block_digest(ctx, token, BlockSelector::Height(BlockHeight::from(0u64)))
            .await
            .unwrap()
            .unwrap()
    );

    // should find genesis block by Digest selector
    assert_eq!(
        genesis_hash,
        rpc_server
            .clone()
            .block_digest(ctx, token, BlockSelector::Digest(genesis_hash))
            .await
            .unwrap()
            .unwrap()
    );

    // should not find any block when Height selector is u64::Max
    assert!(rpc_server
        .clone()
        .block_digest(
            ctx,
            token,
            BlockSelector::Height(BlockHeight::from(u64::MAX))
        )
        .await
        .unwrap()
        .is_none());

    // should not find any block when Digest selector is Digest::default()
    assert!(rpc_server
        .clone()
        .block_digest(ctx, token, BlockSelector::Digest(Digest::default()))
        .await
        .unwrap()
        .is_none());
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn getting_temperature_doesnt_crash_test() {
    // On your local machine, this should return a temperature but in CI,
    // the RPC call returns `None`, so we only verify that the call doesn't
    // crash the host machine, we don't verify that any value is returned.
    let rpc_server = test_rpc_server(
        WalletEntropy::new_random(),
        2,
        cli_args::Args::default_with_network(Network::Main),
    )
    .await;
    let token = cookie_token(&rpc_server).await;
    let _current_server_temperature = rpc_server
        .cpu_temp(context::current(), token)
        .await
        .unwrap();
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn cannot_initiate_transaction_if_notx_flag_is_set() {
    let network = Network::Main;
    let ctx = context::current();
    let mut rng = rand::rng();
    let address = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
    let amount = NativeCurrencyAmount::coins(rng.random_range(0..10));

    // set flag on, verify non-initiation
    let cli_on = cli_args::Args {
        no_transaction_initiation: true,
        network,
        ..Default::default()
    };

    let rpc_server = test_rpc_server(WalletEntropy::new_random(), 2, cli_on).await;
    let token = cookie_token(&rpc_server).await;

    let output: OutputFormat = (address.into(), amount).into();
    assert!(rpc_server
        .clone()
        .send(
            ctx,
            token,
            vec![output],
            ChangePolicy::ExactChange,
            NativeCurrencyAmount::zero()
        )
        .await
        .is_err());
}

#[traced_test]
#[apply(shared_tokio_runtime)]
async fn coinbase_distribution_happy_path() {
    let network = Network::Main;
    let ctx = context::current();
    let mut rng = rand::rng();
    let address0 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
    let output0 = CoinbaseOutputReadable::new(205, address0.to_bech32m(network).unwrap(), true);

    let address1 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
    let output1 = CoinbaseOutputReadable::new(300, address1.to_bech32m(network).unwrap(), true);

    let address2 = GenerationSpendingKey::derive_from_seed(rng.random()).to_address();
    let output2 = CoinbaseOutputReadable::new(495, address2.to_bech32m(network).unwrap(), false);

    let cli = cli_args::Args {
        network,
        compose: true,
        tx_proving_capability: Some(TxProvingCapability::SingleProof),
        ..Default::default()
    };
    let rpc_server = test_rpc_server(WalletEntropy::new_random(), 2, cli).await;
    let token = cookie_token(&rpc_server).await;
    assert!(rpc_server
        .state
        .lock_guard()
        .await
        .mining_state
        .overridden_coinbase_distribution()
        .is_none());
    assert!(rpc_server
        .clone()
        .set_coinbase_distribution(ctx, token, vec![output0, output1, output2])
        .await
        .is_ok());
    assert!(rpc_server
        .state
        .lock_guard()
        .await
        .mining_state
        .overridden_coinbase_distribution()
        .is_some());
    assert!(rpc_server
        .clone()
        .unset_coinbase_distribution(ctx, token)
        .await
        .is_ok());
    assert!(rpc_server
        .state
        .lock_guard()
        .await
        .mining_state
        .overridden_coinbase_distribution()
        .is_none());
}

#[apply(shared_tokio_runtime)]
async fn restore_membership_proof_privacy_preserving_devnet_wallet() {
    let network = Network::Main;
    let ctx = context::current();
    let rpc_server =
        test_rpc_server(WalletEntropy::devnet_wallet(), 2, cli_args::Args::default()).await;
    let token = cookie_token(&rpc_server).await;

    let utxo = rpc_server
        .state
        .lock_guard()
        .await
        .wallet_spendable_inputs(Timestamp::now())
        .await
        .into_iter()
        .collect_vec()[0]
        .clone();
    let msmp = utxo.mutator_set_mp().clone();

    let resp = rpc_server
        .clone()
        .restore_membership_proof_privacy_preserving(
            ctx,
            token,
            vec![msmp.compute_indices(Tip5::hash(&utxo.utxo))],
        )
        .await
        .unwrap();

    let genesis_block = Block::genesis(network);
    assert_eq!(BlockHeight::genesis(), resp.tip_height);
    assert_eq!(genesis_block.hash(), resp.tip_hash);
    assert_eq!(
        genesis_block.mutator_set_accumulator_after().unwrap(),
        resp.tip_mutator_set
    );
    assert_eq!(1, resp.membership_proofs.len());
    let restored_msmp_resp = resp.membership_proofs[0].clone();
    assert_eq!(
        msmp,
        restored_msmp_resp
            .extract_ms_membership_proof(
                msmp.aocl_leaf_index,
                msmp.sender_randomness,
                msmp.receiver_preimage
            )
            .unwrap()
    );

    // Ensure no crash on future AOCL items
    assert!(rpc_server
        .restore_membership_proof_privacy_preserving(
            ctx,
            token,
            vec![AbsoluteIndexSet::compute(
                Digest::default(),
                Digest::default(),
                Digest::default(),
                u64::from(u32::MAX)
            )],
        )
        .await
        .is_err());
}

mod pow_puzzle_tests {
    use rand::random;

    use super::*;
    use crate::protocol::consensus::block::block_header::BlockPow;
    use crate::protocol::consensus::block::pow::Pow;
    use crate::protocol::consensus::block::BlockProof;
    use crate::protocol::consensus::consensus_rule_set::ConsensusRuleSet;
    use crate::protocol::consensus::transaction::validity::neptune_proof::NeptuneProof;
    use crate::state::mining::block_proposal::BlockProposal;
    use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
    use crate::state::wallet::address::KeyType;
    use crate::tests::shared::blocks::fake_valid_deterministic_successor;
    use crate::tests::shared::blocks::invalid_empty_block;

    #[test]
    fn pow_puzzle_is_consistent_with_block_hash() {
        let network = Network::Main;
        let genesis = Block::genesis(network);
        let mut block1 = invalid_empty_block(&genesis, network);
        let mut rng = StdRng::seed_from_u64(3409875378456);
        let guesser_address = GenerationReceivingAddress::derive_from_seed(rng.random());
        block1.set_header_guesser_address(guesser_address.into());

        let guess_challenge = ProofOfWorkPuzzle::new(block1.clone(), genesis.header().difficulty);
        assert_eq!(guess_challenge.prev_block, genesis.hash());

        let pow: BlockPow = random();
        block1.set_header_pow(pow);

        let resulting_block_hash = block1.pow_mast_paths().fast_mast_hash(pow);

        assert_eq!(block1.hash(), resulting_block_hash);
    }

    #[apply(shared_tokio_runtime)]
    async fn provide_solution_when_no_proposal_known() {
        let network = Network::Main;
        let bob = test_rpc_server(
            WalletEntropy::new_random(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let bob_token = cookie_token(&bob).await;
        assert!(
            matches!(
                bob.state.lock_guard().await.mining_state.block_proposal,
                BlockProposal::None
            ),
            "Test assumption: no block proposal known"
        );
        let accepted = bob
            .clone()
            .provide_pow_solution(context::current(), bob_token, random(), random())
            .await
            .unwrap();
        assert!(
            !accepted,
            "Must reject PoW solution when no proposal exists"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn full_pow_puzzle_test() {
        let network = Network::Main;
        let bob = WalletEntropy::new_random();
        let mut bob = test_rpc_server(
            bob.clone(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;

        let genesis = Block::genesis(network);
        let block1 = fake_valid_deterministic_successor(&genesis, network).await;
        bob.state
            .lock_mut(|x| {
                x.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone())
            })
            .await;
        let guesser_address = bob
            .state
            .lock_guard_mut()
            .await
            .wallet_state
            .next_unused_spending_key(KeyType::Generation)
            .await
            .to_address();
        let bob_token = cookie_token(&bob).await;

        let (proposal_block1, puzzle) = bob
            .clone()
            .full_pow_puzzle_external_key(context::current(), bob_token, guesser_address)
            .await
            .unwrap()
            .unwrap();

        assert!(
            !bob.clone()
                .provide_new_tip(
                    context::current(),
                    bob_token,
                    Default::default(),
                    proposal_block1.clone()
                )
                .await
                .unwrap(),
            "Node must reject new tip with invalid PoW solution."
        );

        let solution = puzzle.solve(ConsensusRuleSet::Reboot);
        assert!(
            bob.clone()
                .provide_new_tip(
                    context::current(),
                    bob_token,
                    solution,
                    proposal_block1.clone()
                )
                .await
                .unwrap(),
            "Node must accept valid new tip."
        );

        let mut bad_proposal = proposal_block1;
        bad_proposal.set_proof(BlockProof::SingleProof(NeptuneProof::invalid()));
        assert!(
            !bob.clone()
                .provide_new_tip(
                    context::current(),
                    bob_token,
                    Default::default(),
                    bad_proposal
                )
                .await
                .unwrap(),
            "Node must reject new tip with invalid proof."
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn cached_exported_proposals_are_stored_correctly() {
        let network = Network::Main;
        let bob = WalletEntropy::new_random();
        let mut bob = test_rpc_server(
            bob.clone(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;

        let genesis = Block::genesis(network);
        let block1 = invalid_empty_block(&genesis, network);
        bob.state
            .lock_mut(|x| {
                x.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone())
            })
            .await;
        let bob_token = cookie_token(&bob).await;

        let num_exported_block_proposals = 6;

        let mut addresses = vec![];
        for _ in 0..num_exported_block_proposals {
            let address = bob
                .state
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await
                .to_address();
            addresses.push(address);
        }

        let mut pow_puzzle_ids = vec![];
        for guesser_address in addresses.clone() {
            let pow_puzzle = bob
                .clone()
                .pow_puzzle_external_key(context::current(), bob_token, guesser_address)
                .await
                .unwrap()
                .unwrap();
            assert!(!pow_puzzle_ids.contains(&pow_puzzle.id));
            pow_puzzle_ids.push(pow_puzzle.id);
        }

        assert_eq!(
            num_exported_block_proposals,
            bob.state
                .lock_guard()
                .await
                .mining_state
                .exported_block_proposals
                .len()
        );

        // Verify that the same exported puzzle is not added twice.
        for guesser_address in addresses {
            bob.clone()
                .pow_puzzle_external_key(context::current(), bob_token, guesser_address)
                .await
                .unwrap()
                .unwrap();
        }
        assert_eq!(
            num_exported_block_proposals,
            bob.state
                .lock_guard()
                .await
                .mining_state
                .exported_block_proposals
                .len()
        );
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn exported_pow_puzzle_is_consistent_with_block_hash() {
        let network = Network::Main;
        let bob = WalletEntropy::new_random();
        let mut bob = test_rpc_server(
            bob.clone(),
            2,
            cli_args::Args::default_with_network(network),
        )
        .await;
        let bob_token = cookie_token(&bob).await;

        let genesis = Block::genesis(network);
        let mut block1 = invalid_empty_block(&genesis, network);
        bob.state
            .lock_mut(|x| {
                x.mining_state.block_proposal = BlockProposal::ForeignComposition(block1.clone())
            })
            .await;

        let entropy_for_external_key = WalletEntropy::new_random();
        let external_guesser_key = entropy_for_external_key.guesser_fee_key();
        let external_guesser_address = external_guesser_key.to_address();
        let internal_guesser_address = bob
            .state
            .lock(|x| x.wallet_state.wallet_entropy.guesser_fee_key())
            .await
            .to_address();

        for use_internal_key in [true, false] {
            println!("use_internal_key: {use_internal_key}");
            let pow_puzzle = if use_internal_key {
                bob.clone()
                    .pow_puzzle_internal_key(context::current(), bob_token)
                    .await
                    .unwrap()
                    .unwrap()
            } else {
                bob.clone()
                    .pow_puzzle_external_key(
                        context::current(),
                        bob_token,
                        external_guesser_address.into(),
                    )
                    .await
                    .unwrap()
                    .unwrap()
            };

            let guesser_address = if use_internal_key {
                internal_guesser_address
            } else {
                external_guesser_address
            };

            assert!(
                bob.state
                    .lock_guard()
                    .await
                    .mining_state
                    .exported_block_proposals
                    .contains_key(&pow_puzzle.id),
                "Must have stored exported block proposal"
            );

            let pow: BlockPow = random();
            let resulting_block_hash = pow_puzzle.pow_mast_paths.fast_mast_hash(pow);

            block1.set_header_pow(pow);
            block1.set_header_guesser_address(guesser_address.into());
            assert_eq!(block1.hash(), resulting_block_hash);
            assert_eq!(
                block1.body().total_guesser_reward().unwrap(),
                pow_puzzle.total_guesser_reward
            );

            // Check that succesful guess is accepted by endpoint.
            let consensus_rule_set = ConsensusRuleSet::Reboot;
            let guesser_buffer = block1.guess_preprocess(None, None, consensus_rule_set);
            let mast_auth_paths = block1.pow_mast_paths();
            let index_picker_preimage = guesser_buffer.index_picker_preimage(&mast_auth_paths);
            let target = genesis.header().difficulty.target();
            let valid_pow = loop {
                if let Some(valid_pow) = Pow::guess(
                    &guesser_buffer,
                    &mast_auth_paths,
                    index_picker_preimage,
                    random(),
                    target,
                ) {
                    break valid_pow;
                }
            };

            block1.set_header_pow(valid_pow);
            let good_is_accepted = bob
                .clone()
                .provide_pow_solution(context::current(), bob_token, valid_pow, pow_puzzle.id)
                .await
                .unwrap();
            assert!(
                good_is_accepted,
                "Actual PoW-puzzle solution must be accepted by RPC endpoint."
            );

            // Check that bad guess is rejected by endpoint.
            let bad_pow: BlockPow = random();
            let bad_is_accepted = bob
                .clone()
                .provide_pow_solution(context::current(), bob_token, bad_pow, pow_puzzle.id)
                .await
                .unwrap();
            assert!(
                !bad_is_accepted,
                "Bad PoW solution must be rejected by RPC endpoint."
            );
        }
    }
}

mod claim_utxo_tests {
    use super::*;

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn claim_utxo_owned_before_confirmed() -> Result<()> {
        worker::claim_utxo_owned(false, false).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn claim_utxo_owned_after_confirmed() -> Result<()> {
        worker::claim_utxo_owned(true, false).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn claim_utxo_owned_after_confirmed_and_after_spent() -> Result<()> {
        worker::claim_utxo_owned(true, true).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn claim_utxo_unowned_before_confirmed() -> Result<()> {
        worker::claim_utxo_unowned(false).await
    }

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn claim_utxo_unowned_after_confirmed() -> Result<()> {
        worker::claim_utxo_unowned(true).await
    }

    mod worker {
        use cli_args::Args;

        use super::*;
        use crate::state::transaction::tx_proving_capability::TxProvingCapability;
        use crate::tests::shared::blocks::invalid_block_with_transaction;
        use crate::tests::shared::blocks::invalid_empty_block;

        pub(super) async fn claim_utxo_unowned(claim_after_confirmed: bool) -> Result<()> {
            let network = Network::Main;

            // bob's node
            let (pay_to_bob_outputs, bob_rpc_server, bob_token) = {
                let rpc_server = test_rpc_server(
                    WalletEntropy::new_random(),
                    2,
                    Args::default_with_network(network),
                )
                .await;
                let token = cookie_token(&rpc_server).await;

                let receiving_address_generation = rpc_server
                    .clone()
                    .next_receiving_address(context::current(), token, KeyType::Generation)
                    .await?;
                let receiving_address_symmetric = rpc_server
                    .clone()
                    .next_receiving_address(context::current(), token, KeyType::Symmetric)
                    .await?;

                let pay_to_bob_outputs: Vec<OutputFormat> = [
                    (
                        receiving_address_generation,
                        NativeCurrencyAmount::coins(1),
                        UtxoNotificationMedium::OffChain,
                    ),
                    (
                        receiving_address_symmetric,
                        NativeCurrencyAmount::coins(2),
                        UtxoNotificationMedium::OffChain,
                    ),
                ]
                .into_iter()
                .map(|o| o.into())
                .collect();

                (pay_to_bob_outputs, rpc_server, token)
            };

            // alice's node
            let (blocks, alice_to_bob_utxo_notifications, bob_amount) = {
                let wallet_entropy = WalletEntropy::new_random();
                let cli_args = cli_args::Args {
                    tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                    network,
                    ..Default::default()
                };
                let mut rpc_server = test_rpc_server(wallet_entropy.clone(), 2, cli_args).await;
                let token = cookie_token(&rpc_server).await;

                let genesis_block = Block::genesis(network);
                let mut blocks = vec![];

                let fee = NativeCurrencyAmount::zero();
                let bob_amount: NativeCurrencyAmount = pay_to_bob_outputs
                    .iter()
                    .map(|o| o.native_currency_amount())
                    .sum();

                // Mine block 1 to get some coins

                let cb_key = wallet_entropy.nth_generation_spending_key(0);
                let (block1, composer_expected_utxos) =
                    make_mock_block(&genesis_block, None, cb_key, Default::default(), network)
                        .await;
                blocks.push(block1.clone());

                rpc_server
                    .state
                    .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                    .await
                    .unwrap();

                let tx_artifacts = rpc_server
                    .clone()
                    .send(
                        context::current(),
                        token,
                        pay_to_bob_outputs,
                        ChangePolicy::recover_to_next_unused_key(
                            KeyType::Symmetric,
                            UtxoNotificationMedium::OffChain,
                        ),
                        fee,
                    )
                    .await
                    .unwrap();

                let block2 = invalid_block_with_transaction(
                    &block1,
                    tx_artifacts.transaction.clone().into(),
                );
                let block3 = invalid_empty_block(&block2, network);

                // mine two blocks, the first will include the transaction
                blocks.push(block2);
                blocks.push(block3);

                // note: change-policy uses off-chain, so alice will have an
                // off-chain notificatin also.  So it is important to use
                // unowned_offchain_notifications() when retrieving those
                // intended for bob.

                (
                    blocks,
                    tx_artifacts.unowned_offchain_notifications(),
                    bob_amount,
                )
            };

            // bob's node claims each utxo
            {
                let mut state = bob_rpc_server.state.clone();

                state.set_new_tip(blocks[0].clone()).await?;

                if claim_after_confirmed {
                    state.set_new_tip(blocks[1].clone()).await?;
                    state.set_new_tip(blocks[2].clone()).await?;
                }

                for utxo_notification in alice_to_bob_utxo_notifications {
                    // Register the same UTXO multiple times to ensure that this does not
                    // change the balance.
                    let claim_was_new0 = bob_rpc_server
                        .clone()
                        .claim_utxo(
                            context::current(),
                            bob_token,
                            utxo_notification.ciphertext.clone(),
                            None,
                        )
                        .await
                        .unwrap();
                    assert!(claim_was_new0);
                    let claim_was_new1 = bob_rpc_server
                        .clone()
                        .claim_utxo(
                            context::current(),
                            bob_token,
                            utxo_notification.ciphertext,
                            None,
                        )
                        .await
                        .unwrap();
                    assert!(!claim_was_new1);
                }

                assert_eq!(
                    vec![
                        NativeCurrencyAmount::coins(1), // claimed via generation addr
                        NativeCurrencyAmount::coins(2), // claimed via symmetric addr
                    ],
                    state
                        .lock_guard()
                        .await
                        .wallet_state
                        .wallet_db
                        .expected_utxos()
                        .get_all()
                        .await
                        .iter()
                        .map(|eu| eu.utxo.get_native_currency_amount())
                        .collect_vec()
                );

                if !claim_after_confirmed {
                    assert_eq!(
                        NativeCurrencyAmount::zero(),
                        bob_rpc_server
                            .clone()
                            .confirmed_available_balance(context::current(), bob_token)
                            .await?,
                    );
                    state.set_new_tip(blocks[1].clone()).await?;
                    state.set_new_tip(blocks[2].clone()).await?;
                }

                assert_eq!(
                    bob_amount,
                    bob_rpc_server
                        .confirmed_available_balance(context::current(), bob_token)
                        .await?,
                );
            }

            Ok(())
        }

        pub(super) async fn claim_utxo_owned(claim_after_mined: bool, spent: bool) -> Result<()> {
            assert!(
                !spent || claim_after_mined,
                "If UTXO is spent, it must also be mined"
            );
            let network = Network::Main;
            let bob_wallet = WalletEntropy::new_random();
            let cli_args = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                network,
                ..Default::default()
            };
            let mut bob = test_rpc_server(bob_wallet.clone(), 2, cli_args).await;
            let bob_token = cookie_token(&bob).await;

            let bob_key = bob_wallet.nth_generation_spending_key(0);
            let genesis_block = Block::genesis(network);
            let (block1, composer_expected_utxos) =
                make_mock_block(&genesis_block, None, bob_key, Default::default(), network).await;

            bob.state
                .set_new_self_composed_tip(block1.clone(), composer_expected_utxos)
                .await
                .unwrap();

            let bob_gen_addr = bob
                .clone()
                .next_receiving_address(context::current(), bob_token, KeyType::Generation)
                .await?;
            let bob_sym_addr = bob
                .clone()
                .next_receiving_address(context::current(), bob_token, KeyType::Symmetric)
                .await?;

            let pay_to_self_outputs: Vec<OutputFormat> = [
                (
                    bob_gen_addr,
                    NativeCurrencyAmount::coins(5),
                    UtxoNotificationMedium::OffChain,
                ),
                (
                    bob_sym_addr,
                    NativeCurrencyAmount::coins(6),
                    UtxoNotificationMedium::OffChain,
                ),
            ]
            .into_iter()
            .map(|o| o.into())
            .collect();

            let fee = NativeCurrencyAmount::coins(2);
            let tx_artifacts = bob
                .clone()
                .send(
                    context::current(),
                    bob_token,
                    pay_to_self_outputs.clone(),
                    ChangePolicy::recover_to_next_unused_key(
                        KeyType::Symmetric,
                        UtxoNotificationMedium::OffChain,
                    ),
                    fee,
                )
                .await
                .unwrap();

            // alice mines 2 more blocks.  block2 confirms the sent tx.
            let block2 =
                invalid_block_with_transaction(&block1, tx_artifacts.transaction.clone().into());
            let block3 = invalid_empty_block(&block2, network);

            if claim_after_mined {
                // bob applies the blocks before claiming utxos.
                bob.state.set_new_tip(block2.clone()).await?;
                bob.state.set_new_tip(block3.clone()).await?;

                if spent {
                    // Send entire liquid balance somewhere else
                    let another_address = WalletEntropy::new_random()
                        .nth_generation_spending_key(0)
                        .to_address();
                    let output: OutputFormat = (
                        another_address.into(),
                        NativeCurrencyAmount::coins(62),
                        UtxoNotificationMedium::OffChain,
                    )
                        .into();
                    let spending_tx_artifacts = bob
                        .clone()
                        .send(
                            context::current(),
                            bob_token,
                            vec![output],
                            ChangePolicy::exact_change(),
                            NativeCurrencyAmount::zero(),
                        )
                        .await
                        .unwrap();
                    let block4 = invalid_block_with_transaction(
                        &block3,
                        spending_tx_artifacts.transaction.clone().into(),
                    );
                    bob.state.set_new_tip(block4.clone()).await?;
                }
            }

            for offchain_notification in tx_artifacts.owned_offchain_notifications() {
                bob.clone()
                    .claim_utxo(
                        context::current(),
                        bob_token,
                        offchain_notification.ciphertext,
                        None,
                    )
                    .await?;
            }

            assert_eq!(
                vec![
                    NativeCurrencyAmount::coins(64), // liquid composer reward, block 1
                    NativeCurrencyAmount::coins(64), // illiquid composer reward, block 1
                    NativeCurrencyAmount::coins(5),  // claimed via generation addr
                    NativeCurrencyAmount::coins(6),  // claimed via symmetric addr
                    // 51 = (64 - 5 - 6 - 2 (fee))
                    NativeCurrencyAmount::coins(51) // change (symmetric addr)
                ],
                bob.state
                    .lock_guard()
                    .await
                    .wallet_state
                    .wallet_db
                    .expected_utxos()
                    .get_all()
                    .await
                    .iter()
                    .map(|eu| eu.utxo.get_native_currency_amount())
                    .collect_vec()
            );

            if !claim_after_mined {
                // bob hasn't applied blocks 2,3. liquid balance should be 64
                assert_eq!(
                    NativeCurrencyAmount::coins(64),
                    bob.clone()
                        .confirmed_available_balance(context::current(), bob_token)
                        .await?,
                );
                // bob applies the blocks after claiming utxos.
                bob.state.set_new_tip(block2).await?;
                bob.state.set_new_tip(block3).await?;
            }

            if spent {
                assert!(bob
                    .confirmed_available_balance(context::current(), bob_token)
                    .await?
                    .is_zero(),);
            } else {
                // final liquid balance should be 62.
                // +64 composer liquid
                // +64 composer timelocked (not counted)
                // -64 composer liquid spent
                // +5 self-send via Generation
                // +6 self-send via Symmetric
                // +51   change (less fee == 2)
                assert_eq!(
                    NativeCurrencyAmount::coins(62),
                    bob.confirmed_available_balance(context::current(), bob_token)
                        .await?,
                );
            }
            Ok(())
        }
    }
}

mod send_tests {
    use super::*;
    use crate::api::export::TxProvingCapability;
    use crate::application::rpc::server::error::RpcError;
    use crate::tests::shared::blocks::mine_block_to_wallet_invalid_block_proof;

    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn send_to_many_n_outputs() {
        let mut rng = StdRng::seed_from_u64(1815);
        let network = Network::Main;
        let cli_args = cli_args::Args {
            tx_proving_capability: Some(TxProvingCapability::ProofCollection),
            network,
            ..Default::default()
        };
        let rpc_server =
            test_rpc_server(WalletEntropy::new_pseudorandom(rng.random()), 2, cli_args).await;
        let token = cookie_token(&rpc_server).await;

        let ctx = context::current();
        // let timestamp = network.launch_date() + Timestamp::days(1);
        let own_address = rpc_server
            .clone()
            .next_receiving_address(ctx, token, KeyType::Generation)
            .await
            .unwrap();
        let elem: OutputFormat = (
            own_address.clone(),
            NativeCurrencyAmount::zero(),
            UtxoNotificationMedium::OffChain,
        )
            .into();
        let outputs = std::iter::repeat(elem);
        let fee = NativeCurrencyAmount::zero();

        // note: we can only perform 2 iters, else we bump into send rate-limit (per block)
        for i in 5..7 {
            let result = rpc_server
                .clone()
                .send(
                    ctx,
                    token,
                    outputs.clone().take(i).collect(),
                    ChangePolicy::ExactChange,
                    fee,
                )
                .await;
            assert!(result.is_ok());
        }
    }

    /// sends a tx with two outputs: one self, one external, for each key type
    /// that accepts incoming UTXOs.
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn send_to_many_test() -> Result<()> {
        for recipient_key_type in KeyType::all_types() {
            worker::send_to_many(recipient_key_type).await?;
        }
        Ok(())
    }

    /// checks that the sending rate limit kicks in after 2 tx are sent.
    /// note: rate-limit only applies below block 25000
    #[traced_test]
    #[apply(shared_tokio_runtime)]
    async fn send_rate_limit() -> Result<()> {
        let mut rng = StdRng::seed_from_u64(1815);
        let network = Network::Main;
        let cli_args = cli_args::Args {
            tx_proving_capability: Some(TxProvingCapability::SingleProof),
            network,
            ..Default::default()
        };
        let mut rpc_server = test_rpc_server(WalletEntropy::devnet_wallet(), 2, cli_args).await;

        let ctx = context::current();
        let token = cookie_token(&rpc_server).await;
        let timestamp = network.launch_date() + Timestamp::months(7);

        // obtain some funds, so we have two inputs available.
        mine_block_to_wallet_invalid_block_proof(&mut rpc_server.state, Some(timestamp)).await?;

        let address: ReceivingAddress = GenerationSpendingKey::derive_from_seed(rng.random())
            .to_address()
            .into();
        let amount = NativeCurrencyAmount::coins(rng.random_range(0..2));
        let fee = NativeCurrencyAmount::coins(1);

        let output: OutputFormat = (address, amount, UtxoNotificationMedium::OnChain).into();
        let outputs = vec![output];

        for i in 0..10 {
            let result = rpc_server
                .clone()
                .send(ctx, token, outputs.clone(), ChangePolicy::Burn, fee)
                .await;

            // any attempts after the 2nd send should result in RateLimit error.
            match i {
                0..2 => assert!(result.is_ok()),
                _ => assert!(matches!(
                    result,
                    Err(RpcError::SendError(s)) if s.contains("Send rate limit reached")
                )),
            }
        }

        Ok(())
    }

    mod worker {
        use super::*;
        use crate::state::wallet::address::generation_address::GenerationReceivingAddress;
        use crate::state::wallet::address::symmetric_key::SymmetricKey;
        use crate::state::wallet::address::SpendingKey;

        // sends a tx with two outputs: one self, one external.
        //
        // input: recipient_key_type: can be symmetric or generation.
        //
        // Steps:
        // --- Init.  Basics ---
        // --- Init.  get wallet spending key ---
        // --- Init.  generate a block, with coinbase going to our wallet ---
        // --- Init.  append the block to blockchain ---
        // --- Setup. generate an output that our wallet cannot claim. ---
        // --- Setup. generate an output that our wallet can claim. ---
        // --- Setup. assemble outputs and fee ---
        // --- Store: store num expected utxo before spend ---
        // --- Operation: perform send_to_many
        // --- Test: bech32m serialize/deserialize roundtrip.
        // --- Test: verify op returns a value.
        // --- Test: verify expected_utxos.len() has increased by 2.
        pub(super) async fn send_to_many(recipient_key_type: KeyType) -> Result<()> {
            info!("recipient_key_type: {}", recipient_key_type);

            // --- Init.  Basics ---
            let mut rng = StdRng::seed_from_u64(1814);
            let network = Network::Main;
            let cli_args = cli_args::Args {
                tx_proving_capability: Some(TxProvingCapability::ProofCollection),
                network,
                ..Default::default()
            };
            let mut rpc_server =
                test_rpc_server(WalletEntropy::new_pseudorandom(rng.random()), 2, cli_args).await;
            let token = cookie_token(&rpc_server).await;

            // --- Init.  get wallet spending key ---
            let genesis_block = Block::genesis(network);
            let wallet_spending_key = rpc_server
                .state
                .lock_guard_mut()
                .await
                .wallet_state
                .next_unused_spending_key(KeyType::Generation)
                .await;

            let SpendingKey::Generation(key) = wallet_spending_key else {
                // todo: make_mock_block should accept a SpendingKey.
                panic!("must be generation key");
            };

            // --- Init.  generate a block, with composer fee going to our
            // wallet ---
            let timestamp = network.launch_date() + Timestamp::days(1);
            let (block_1, composer_utxos) =
                make_mock_block(&genesis_block, Some(timestamp), key, rng.random(), network).await;

            {
                let state_lock = rpc_server.state.lock_guard().await;
                let wallet_status = state_lock.get_wallet_status_for_tip().await;
                let original_balance = wallet_status.available_confirmed(timestamp);
                assert!(original_balance.is_zero(), "Original balance assumed zero");
            };

            // --- Init.  append the block to blockchain ---
            rpc_server
                .state
                .set_new_self_composed_tip(block_1.clone(), composer_utxos)
                .await?;

            {
                let state_lock = rpc_server.state.lock_guard().await;
                let wallet_status = state_lock.get_wallet_status_for_tip().await;
                let new_balance = wallet_status.available_confirmed(timestamp);
                let mut expected_balance = Block::block_subsidy(block_1.header().height);
                expected_balance.div_two();
                assert_eq!(
                    expected_balance, new_balance,
                    "New balance must be exactly 1/2 mining reward bc timelock"
                );
            };

            // --- Setup. generate an output that our wallet cannot claim. ---
            let external_receiving_address: ReceivingAddress = match recipient_key_type {
                KeyType::Generation => {
                    GenerationReceivingAddress::derive_from_seed(rng.random()).into()
                }
                KeyType::Symmetric => SymmetricKey::from_seed(rng.random()).into(),
            };
            let output1: OutputFormat = (
                external_receiving_address.clone(),
                NativeCurrencyAmount::coins(5),
                UtxoNotificationMedium::OffChain,
            )
                .into();

            // --- Setup. generate an output that our wallet can claim. ---
            let output2: OutputFormat = {
                let spending_key = rpc_server
                    .state
                    .lock_guard_mut()
                    .await
                    .wallet_state
                    .next_unused_spending_key(recipient_key_type)
                    .await;
                (
                    spending_key.to_address(),
                    NativeCurrencyAmount::coins(25),
                    UtxoNotificationMedium::OffChain,
                )
            }
            .into();

            // --- Setup. assemble outputs and fee ---
            let outputs = vec![output1, output2];
            let fee = NativeCurrencyAmount::coins(1);

            // --- Store: store num expected utxo before spend ---
            let num_expected_utxo = rpc_server
                .state
                .lock_guard()
                .await
                .wallet_state
                .wallet_db
                .expected_utxos()
                .len()
                .await;

            // --- Operation: perform send_to_many
            // It's important to call a method where you get to inject the
            // timestamp. Otherwise, proofs cannot be reused, and CI will
            // fail. CI might also fail if you don't set an explicit proving
            // capability.
            let result = rpc_server
                .clone()
                .send(
                    context::current(),
                    token,
                    outputs,
                    ChangePolicy::recover_to_next_unused_key(
                        KeyType::Symmetric,
                        UtxoNotificationMedium::OffChain,
                    ),
                    fee,
                )
                .await;

            // --- Test: bech32m serialize/deserialize roundtrip.
            assert_eq!(
                external_receiving_address,
                ReceivingAddress::from_bech32m(
                    &external_receiving_address.to_bech32m(network)?,
                    network,
                )?
            );

            // --- Test: verify op returns a value.
            assert!(result.is_ok());

            // --- Test: verify expected_utxos.len() has increased by 2.
            //           (one off-chain utxo + one change utxo)
            assert_eq!(
                rpc_server
                    .state
                    .lock_guard()
                    .await
                    .wallet_state
                    .wallet_db
                    .expected_utxos()
                    .len()
                    .await,
                num_expected_utxo + 2
            );

            Ok(())
        }
    }
}
