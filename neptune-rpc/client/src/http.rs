use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use neptune_cash::application::json_rpc::core::api::client::transport::Transport;
use neptune_cash::application::json_rpc::core::model::json::JsonError;
use neptune_cash::application::json_rpc::core::model::json::JsonRequest;
use neptune_cash::application::json_rpc::core::model::json::JsonResponse;
use neptune_cash::application::json_rpc::core::model::json::JsonResult;
use reqwest::Client;

#[derive(Clone, Debug)]
pub struct HttpClient {
    url: String,
    client: Client,
    last_id: Arc<AtomicU64>,
}

impl HttpClient {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: Client::new(),
            last_id: Arc::new(AtomicU64::new(0)),
        }
    }
}

#[async_trait]
impl Transport for HttpClient {
    async fn call(&self, method: &str, params: serde_json::Value) -> JsonResult<serde_json::Value> {
        let request = JsonRequest {
            jsonrpc: Some("2.0".to_string()),
            method: method.to_string(),
            params,
            id: Some(self.last_id.fetch_add(1, Ordering::SeqCst).into()),
        };

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|_| JsonError::InternalError)?;
        if !response.status().is_success() {
            return Err(JsonError::InternalError);
        }

        let response: serde_json::Value =
            response.json().await.map_err(|_| JsonError::ParseError)?;
        let response: JsonResponse =
            serde_json::from_value(response).map_err(|_| JsonError::ParseError)?;

        match response {
            JsonResponse::Success { result, .. } => Ok(result),
            JsonResponse::Error { error, .. } => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::env;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::Duration;

    use neptune_cash::api::export::Args;
    use neptune_cash::api::export::BlockHeight;
    use neptune_cash::api::export::Digest;
    use neptune_cash::api::export::KeyType;
    use neptune_cash::api::export::NativeCurrencyAmount;
    use neptune_cash::api::export::Network;
    use neptune_cash::api::export::TransactionKernelId;
    use neptune_cash::api::export::TxProvingCapability;
    use neptune_cash::application::json_rpc::core::api::ops::Namespace;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcApi;
    use neptune_cash::application::json_rpc::core::api::rpc::RpcError;
    use neptune_cash::application::json_rpc::core::model::block::transaction_kernel::RpcAdditionRecord;
    use neptune_cash::application::json_rpc::core::model::json::JsonError;
    use neptune_cash::protocol::consensus::block::Block;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelector;
    use neptune_cash::protocol::consensus::block::block_selector::BlockSelectorLiteral;
    use neptune_cash::state::GlobalState;
    use neptune_cash::state::GlobalStateLock;
    use neptune_cash::state::wallet::address::generation_address::GenerationReceivingAddress;
    use neptune_cash::state::wallet::wallet_entropy::WalletEntropy;
    use num_traits::Zero;
    use rand::distr::Alphanumeric;
    use rand::distr::SampleString;

    use crate::http::HttpClient;

    /// Start a real neptune-core node with a specified port offset to allow
    /// tests to run in parallel.
    ///
    /// Don't use this real server to test all cornercases of inner workings of
    /// neptune-core. Think of this server as integration testing.
    async fn start_pseudo_real_server(
        network: Network,
        activated_namespaces: HashSet<Namespace>,
        unsafe_rpc: bool,
        port_offset: u16,
        injected_wallet_entropy: Option<WalletEntropy>,
    ) -> (HttpClient, GlobalStateLock) {
        let rpc_address = format!("127.0.0.1:{port_offset}");

        let mut cli_args = Args::default_with_network(network);
        cli_args.utxo_index = true;
        cli_args.tx_proving_capability = Some(TxProvingCapability::SingleProof);

        // allow run if instance is running, and don't overwrite
        // existing data dir.
        cli_args.peer_port = port_offset + 1;
        cli_args.rpc_port = port_offset + 2;
        cli_args.quic_port = port_offset + 3;
        cli_args.tcp_port = port_offset + 4;
        cli_args.rpc_modules = activated_namespaces.into_iter().collect();
        cli_args.unsafe_rpc = unsafe_rpc;
        let tmp_root: PathBuf = env::temp_dir()
            .join("neptune-unit-tests")
            .join(Path::new(&Alphanumeric.sample_string(&mut rand::rng(), 16)));

        cli_args.data_dir = Some(tmp_root);
        cli_args.listen_rpc = Some(rpc_address.parse::<SocketAddr>().unwrap());
        let mut main_loop = neptune_cash::initialize(cli_args, injected_wallet_entropy)
            .await
            .unwrap();

        let global_state_lock = main_loop.global_state_lock();

        tokio::spawn(async move {
            main_loop.run().await.unwrap();
        });

        // Wait a few seconds so node will fully initialize. Initializing
        // neptune-core spawns multiple loops. They might need a bit time to
        // be ready for responses.
        tokio::time::sleep(Duration::from_secs(1)).await;

        (
            HttpClient::new(format!("http://{}", rpc_address)),
            global_state_lock,
        )
    }

    #[tokio::test]
    async fn client_responds_in_real_world_scenario() {
        let unsafe_rpc = false;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Chain]),
            unsafe_rpc,
            40500,
            None,
        )
        .await;

        let tip_response = client.tip().await;
        assert!(tip_response.is_ok());

        // Archival is disabled by default.
        let block_response = client
            .get_block(BlockSelector::Special(BlockSelectorLiteral::Genesis))
            .await;
        assert!(block_response.is_err());
        assert_eq!(
            block_response.unwrap_err(),
            RpcError::Server(JsonError::MethodNotFound)
        );
    }

    #[tokio::test]
    async fn get_new_address_bumps_derivation_index() {
        let unsafe_rpc = true;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Chain, Namespace::Personal]),
            unsafe_rpc,
            40510,
            None,
        )
        .await;

        for key_type in [KeyType::Generation, KeyType::Symmetric] {
            let old_index = client.derivation_index(key_type).await.unwrap();
            let _ = client.generate_address(key_type).await.unwrap();
            let new_index = client.derivation_index(key_type).await.unwrap();
            assert_eq!(new_index.derivation_index, old_index.derivation_index + 1);
        }
    }

    #[tokio::test]
    async fn was_mined_on_genesis() {
        let unsafe_rpc = false;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Utxoindex]),
            unsafe_rpc,
            40520,
            None,
        )
        .await;

        let a_genesis_output = Block::genesis(Network::Main)
            .body()
            .transaction_kernel
            .outputs[0];
        assert_eq!(
            vec![BlockHeight::genesis()],
            client
                .was_mined(vec![], vec![a_genesis_output.into()])
                .await
                .unwrap()
                .block_heights
        );

        let unknown_output = RpcAdditionRecord(Digest::default());
        assert!(
            client
                .was_mined(vec![], vec![unknown_output])
                .await
                .unwrap()
                .block_heights
                .is_empty()
        );
        assert_eq!(
            RpcError::EmptyFilteringConditions,
            client.was_mined(vec![], vec![]).await.unwrap_err()
        );
    }

    #[tokio::test]
    async fn outgoing_history_empty_wallet_db() {
        let unsafe_rpc = true;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Personal]),
            unsafe_rpc,
            40530,
            None,
        )
        .await;

        assert!(
            client
                .outgoing_history(None, None, None, None, None, None, None)
                .await
                .unwrap()
                .matching_sent
                .is_empty()
        );
    }

    #[tokio::test]
    async fn count_sent_txs_empty_wallet_db() {
        let unsafe_rpc = true;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Personal]),
            unsafe_rpc,
            40540,
            None,
        )
        .await;

        assert_eq!(
            0,
            client
                .count_sent_transactions_at_block(BlockSelector::Special(
                    BlockSelectorLiteral::Genesis
                ))
                .await
                .unwrap()
                .count
        );
    }

    #[tokio::test]
    async fn validate_donation_address() {
        let unsafe_rpc = false;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Wallet]),
            unsafe_rpc,
            40550,
            None,
        )
        .await;

        let donation_address = "nolgam1tph26le2s8xct23j7cs7udj85q9uzlft8uezjc65ecxr8fpag5pm3x824pwngwpqanzta3x53vkwvzl9fw0lz60gnwf6nlgkak4rghf5als6xh60n7ameqen3a69jnz5wtyzkhmh69je867fpxqyf3cx4387fxjtggk47flg8v4e909qyzs0jv4mh3pn2rf7qe66aw3p9egx9ud2vnntw4su62cngga8zg4s5fv8khaws874ys48ut3wutxdrw4c2hpvq7fedg2u2lxdueuj39a252shahxn2ucf9smen7s5zv44k5tevnzmvq7gfwrylx6axlxhz3d37805rcwe7ct2snudsup93g0rgmneq0v6ge20whwjtr6fh9kgvkh0u8e70rmrz0j46wsfvfww6yszwtmck3tyxknklldqqx0mqs347mctur0pa3gz7crzksd4dym523mzzztr9e8ravr4p8aeptxzc43m4ls6xvwdfhj7x4sxyp0kv83xreldn8mshqpwguyw9wfxtpynszn8x2d2qj92aufg90fgq4l2lmwyjl822j4sn00gtuwh0we6rxeh50hytw0fa3qegqfu7tg3yahp6d82fq5wrcqflqdwt4y5h2yz5e4xd2upxuez8nm0naxt8t2vydr0ke6werkc6dfyhxppvqyz4aw0qrx4qffsx6kt4jtzsny5kd9qn2sk86qckfhexej4y0rtxurlg6ud6h2lcp3edvxxkehdyxt68e3q2cu6yn9wgvfaxacjtcly967g2zsx5tvye4zjvklt7uwny2h5z9mlyaeunfz54swnwfystk8t9enqugzm7yh9c40ldvzv385ev3fpuqhfdqdkm26sjt267nu7t3d62arlh885jhekk03aknykrd697xhugl75lrmcxyftagqh5gg885qqg2n65va890m9stfvx80t3eejvht77uww92yf9yy3epdty0250w82f5k7k9zhzqm945qrj3zrvgaplenrtq3jdzcwgx0wxxrel3fn7drjl050xr3h4zy6sf4hyledvmua9r209f4kr39hwgdy6g9yxhmwthnkyfzvvk4dupyeg0wjtgg9rxml7fu4quwfpel6exjm43q23jt9t9cvcny8rpljalpdjqjgq9whny8r0hpxk4h7g2luu3utzuyfl8n8au3rmlekzlkfssfjv4z7p4xf9vnqglha8rnand4fj2z2uedk04n9mv23dynumr32tcwcrr4f7vclppzs7r4tgwckhzh4t0gcn2h35f7payvg3mxruhz0pdgrktev4trlgqy5jqqnw48ee8yttyvxga9espcusfe7qz3althcz5yp8x4nm38rd26eajgjsftrm9kcen87z5lg47ddmv58tlq5fxq9rc2fx9y7ys55mpmjlm8ap9myyeq3y9cg0974hpzh8dqfx20vyya5tgyzwj53z4p4qecx04q7vzlutxqwlcm9uqurj6utsrds7dzj9zgurrqp7zrmjkh9vk5r9cmt0tenctkgd8llrvkwtklfnvd3wvl3wfeu5374s0jewjdnt6klyq73uasptwhldv2tucc9dvxe8z2n30kgmm0jvtjcturntr4saxlr7ujn33a05szfg7tlafuf7nzc64eqc52st3ncveg0v3dlvw2ndzk7cxtfrd8v6ng49jchd2v9mpm2ezlfuvnrpqtldhm50a6x47n6zk8hr6z9lt83pg7w9552j8tmghzrgkngupgymrxgc5dvwrwxnngyryfsdwnwelmlcehjlcxwstcdanrg05uxjt7pmr0253r876a0ne7zaz84vvleuw7ta7rtd9l6w8fctdtssd86lvu0yeawswnahc82kqu7cjsjs56nuzjh4anz9vggk0ngln6vajp54wccnmfgwa2vqy2skp62qwwyllwp0hmhela7zlt4wc4kdh29a0nt26tvu8z5j3p4g3nx82vex6xvm95rw00c8wy7fnrjl5hasukruu4hcyltmfwssggtc9d9x2he9f7088navqnkeld7deufem9a768yvj5mt2v8hm6cjfc0dyaj955tnaqupvur2h6lhwxzm8yqdksjn7h9p9yhxq7h8u30l7gl47esqnsu0hgml3zs6lrlh00ej2y2wumhskv6kzwnfez8xrpzg8zxvax9g5x3y6rd5p858hedhzxc0wpvje94vtgtk0awcx94g8e7vhgte3y4yee8lufesvzs8nll24xuvkeltvk70jt9057ejetagmweugmde5xennzg9vphmlmetpyzvjk3y3zlctmdt7uyreaus72wm6uyx735c5gqrktx3qe8sufukzxkrs5fq9q6me5g676u968lnf2yzsrjqld5dfgq5x0cer9ssujyhlxcnfcck8rxtx7ssshnqcqtwtcgnzshtzu7lp5k95kq0v78dv7u6prqjpnvm2w38kxevpfpv9yly7yvk5vhg9dwwteneztdtun42xp658m03waal3k3nmnjy98qrgplny708vwmjkznzkaluk5zr6vqqq708x27l0n2s3qamr84llp92v4avnpmn8fv3ekkvkm8m7pnkypqlxgy9l0d0kzk203v998agrtlj5tj5hp3sgw47czqprn8ythkm8m4e67j4a474c4dwg297yst6uqeuxv9qkykgt4cs0z2e66e6m0r470a7n7auud8mqyeylf845u9dxgfy840l3feqxhg5a7sgxy7pkwr7lm3cp3zja93nths4kzk2mal4w09ctkjf6656en2me68zj0tneqs26y45zxyy22lw90zfjcn5q0x4stzx6ptsudtnmqqtcp9fqcc46g9f7zltmk9ul6y2nylmj0eq69egfkca78k39fszs64ktl5dgke4u5j9m2qqvstcs3gjrgeeam0fymy9hk9detv7sfmq402pz57alkp64gjgdsgqmeeffh5sgyf6a0l2pl3yd28ynpernumm0899a8awtqeg6n7rqrsl9k307am5zjnf7wuedu3pg5mr7wxyltzkgucxtwf2dzh5ezsrsfm0k42l39lnjf3akatfqlqgr5aq2u2vzz9z3atxntke5zykv9xrehvfuw6lmkd39hk6j6klp77g9gys73cjqz2m8u55uswzcu9v4z8rqnpl7vaxuep5kqyt2f8ev7qx827az7n2gefp47gvlzuparqlpsuu6859cawfl7m73wtyx0kgt4ssm49cxlcn0cmnc6gu0l42erxkeewd9q24q3lz4sslw8t2080w2g9qthsshkyxfmtkdmnf367x2nsdjg7fc4f4r4z0eraqq5yyeh9x8xgf29h7dytkpzpl568rdxgus9k33602gmtheyldhuswumhlrvsa5ncvrt7w6yaxz3a2uxr33up4z3cx2mxe3sa8hf2zrh8f6q9vmphz6s";
        let good_resp = client
            .validate_address(donation_address.to_string())
            .await
            .unwrap();
        assert_eq!("generation".to_owned(), good_resp.address_type.unwrap());
        assert_eq!(
            good_resp.receiver_identifier.unwrap(),
            good_resp.announcement_flags.unwrap().receiver_id.value()
        );

        let bad_resp = client
            .validate_address("not_a_real_address".to_string())
            .await
            .unwrap();
        assert!(bad_resp.address_type.is_none());
        assert!(bad_resp.receiver_identifier.is_none());
        assert!(bad_resp.announcement_flags.is_none());
    }

    #[tokio::test]
    async fn unspent_utxos_call() {
        let unsafe_rpc = true;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Personal]),
            unsafe_rpc,
            40560,
            None,
        )
        .await;
        let unspent_utxos = client.unspent_utxos().await.unwrap().utxos;
        assert!(unspent_utxos.is_empty());
    }

    #[tokio::test]
    async fn send_from_premine_receiver() {
        let unsafe_rpc = true;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Personal, Namespace::Mempool, Namespace::Node]),
            unsafe_rpc,
            40570,
            Some(WalletEntropy::devnet_wallet()),
        )
        .await;

        let network = client
            .network()
            .await
            .unwrap()
            .network
            .parse::<Network>()
            .unwrap();
        let send_amt = NativeCurrencyAmount::coins(2).into();
        let fee = NativeCurrencyAmount::coins(2).into();
        let recipient = GenerationReceivingAddress::derive_from_seed(Digest::default())
            .to_bech32m(network)
            .unwrap();

        let key_counter_prior = client
            .derivation_index(KeyType::Symmetric)
            .await
            .unwrap()
            .derivation_index;
        let resp = client
            .send(
                send_amt,
                fee,
                recipient,
                None,
                None,
                Some("on-chain".to_string()),
                Some("on-chain".to_string()),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            2,
            resp.outputs.len(),
            "Tx must have two outputs. One send and one change"
        );
        assert_eq!(
            1,
            resp.inputs.len(),
            "Tx must have exactly one input, as premine recipient only has one UTXO."
        );

        // Sleep to allow transaction to find its way into the mempool.
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify tx is in mempool
        assert_eq!(
            1,
            client
                .get_transactions_by_addition_records(resp.outputs)
                .await
                .unwrap()
                .transactions
                .len()
        );

        assert_eq!(
            key_counter_prior + 1,
            client
                .derivation_index(KeyType::Symmetric)
                .await
                .unwrap()
                .derivation_index,
            "Derivation key counter must be bumped after successful 'send'"
        );
    }

    #[tokio::test]
    async fn send_and_register_from_offchain_notification() {
        // Alice sends coins to Bob with an offchain notification. Then Bob
        // registers the UTXO claim. Then the transaction is mined, and Bob's
        // wallet must register the mined UTXO.
        let unsafe_rpc = true;
        let network = Network::RegTest;
        let (alice_client, mut alice_gsl) = start_pseudo_real_server(
            network,
            HashSet::from([Namespace::Personal, Namespace::Mempool, Namespace::Archival]),
            unsafe_rpc,
            40580,
            Some(WalletEntropy::devnet_wallet()),
        )
        .await;
        let (bob_client, mut bob_gsl) = start_pseudo_real_server(
            network,
            HashSet::from([Namespace::Personal, Namespace::Mempool, Namespace::Node]),
            unsafe_rpc,
            40590,
            None,
        )
        .await;

        let send_amt = NativeCurrencyAmount::coins(5);
        let fee = NativeCurrencyAmount::coins(2).into();
        let bob_address = bob_client
            .generate_address(KeyType::Generation)
            .await
            .unwrap()
            .address;

        let send_resp = alice_client
            .send(
                send_amt.into(),
                fee,
                bob_address,
                None,
                None,
                Some("off-chain".to_owned()),
                Some("off-chain".to_owned()),
                None,
            )
            .await
            .unwrap();

        // Sleep to allow main loop to handle transaction
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Verify tx is in Alice's mempool
        assert_eq!(
            1,
            alice_client
                .get_transactions_by_addition_records(send_resp.outputs.clone())
                .await
                .unwrap()
                .transactions
                .len()
        );

        // Verify that Bob accepts offchain transaction notification
        assert_eq!(
            0,
            bob_gsl.api().wallet().num_expected_utxos().await,
            "Bob must have zero expected UTXOs prior to registering it"
        );
        let utxo_claim_ciphertext = send_resp.unowned_offchain_notifications[0]
            .ciphertext
            .clone();
        let claim_resp = bob_client
            .claim_utxo(utxo_claim_ciphertext, None)
            .await
            .unwrap();
        assert!(claim_resp.new, "Bob must accept claim response as new");

        // Verify that Bob now has an expected UTXO.
        assert_eq!(
            1,
            bob_gsl.api().wallet().num_expected_utxos().await,
            "Bob must have an expected UTXO after accepting an encrypted UTXO notification"
        );

        // Wait until Alice's tx has single proof type, so it can be mined.
        // Because RegTest network, no actual proof upgrading takes place here.
        {
            let alice = alice_gsl.lock_guard().await;
            wait_until_tx_in_mempool_has_single_proof(
                &alice,
                send_resp.transaction_kernel_id,
                Duration::from_secs(20),
            )
            .await;
        }

        // Mine the transaction
        alice_gsl
            .api_mut()
            .regtest_mut()
            .mine_blocks_to_wallet(3, true)
            .await
            .unwrap();

        // Verify tx no longer in Alice's mempool. Because it got mined.
        assert!(
            alice_client
                .get_transactions_by_addition_records(send_resp.outputs)
                .await
                .unwrap()
                .transactions
                .is_empty()
        );

        let prior_balance: NativeCurrencyAmount = bob_client
            .get_balance(1)
            .await
            .unwrap()
            .confirmed_available
            .into();
        assert!(
            prior_balance.is_zero(),
            "Bob must have no balance prior to getting transaction. Has: {prior_balance}",
        );

        // "Share" blocks with Bob
        for i in 1u64..=3 {
            let block = alice_client
                .get_block(BlockSelector::Height(i.into()))
                .await
                .unwrap()
                .block
                .unwrap();
            bob_gsl.set_new_tip(block.into()).await.unwrap();
        }

        let after_balance: NativeCurrencyAmount = bob_client
            .get_balance(1)
            .await
            .unwrap()
            .confirmed_available
            .into();
        assert_eq!(
            send_amt, after_balance,
            "Bob expected balance: {send_amt}. Was: {after_balance}",
        );
    }

    #[tokio::test]
    async fn personal_namespace_blocked_unless_unsafe_rpc_is_set() {
        let unsafe_rpc = false;
        let (client, _) = start_pseudo_real_server(
            Network::Main,
            HashSet::from([Namespace::Personal]),
            unsafe_rpc,
            40600,
            None,
        )
        .await;
        assert!(client.unspent_utxos().await.is_err());
    }

    async fn wait_until_tx_in_mempool_has_single_proof(
        gs: &GlobalState,
        txid: TransactionKernelId,
        timeout: Duration,
    ) {
        let start = std::time::Instant::now();
        loop {
            if let Some(tx) = gs.mempool.get(txid)
                && tx.proof.is_single_proof()
            {
                break;
            }
            assert!(
                start.elapsed() <= timeout,
                "tx not in mempool with single-proof after {} seconds",
                timeout.as_secs()
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
